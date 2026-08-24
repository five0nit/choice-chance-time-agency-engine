from __future__ import annotations

from hashlib import sha256
import multiprocessing
import os
from pathlib import Path
import stat
import sys
from typing import Any

import pytest

from cct_agent.commands import CommandSpec
from cct_agent.deployment import (
    DeploymentDenied,
    DeploymentRequest,
    DeploymentTarget,
    LocalFakeDeploymentAdapter,
)
from cct_agent.store import EventStore, canonical_json
from cct_agent.verification import (
    HostRegisteredVerifier,
    VerificationRequest,
    VerifierSpec,
)


PLAN_SHA256 = sha256(b"slice-9-private-plan").hexdigest()
ARTIFACT = b"fake deployment artifact\n"
ARTIFACT_SENTINEL = "DEPLOYMENT_PRIVATE_SENTINEL_762e1_not_for_ledger"


def verifier_spec(*, code: str = "raise SystemExit(0)") -> VerifierSpec:
    return VerifierSpec(
        id="fixture-build",
        kind="build",
        plan_id="plan-slice9-fixture",
        plan_sha256=PLAN_SHA256,
        stage_id="verify",
        command=CommandSpec(
            id="fixture-build-command",
            argv=(sys.executable, "-c", code),
            cwd=".",
            environment=(),
            timeout_ms=2000,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
        ),
        snapshot_paths=("dist/artifact.bin", "project.txt"),
        max_snapshot_file_bytes=4096,
        max_snapshot_total_bytes=8192,
    )


def target_spec(
    *,
    target_id: str = "fixture-local-deploy",
    sink_relative_path: str = "releases/artifact.bin",
    source_relative_path: str = "dist/artifact.bin",
) -> DeploymentTarget:
    return DeploymentTarget(
        id=target_id,
        kind="local_fake",
        source_relative_path=source_relative_path,
        sink_relative_path=sink_relative_path,
        verifier_id="fixture-build",
        max_artifact_bytes=4096,
    )


def build_fixture(
    tmp_path: Path,
    *,
    artifact: bytes = ARTIFACT,
    code: str = "raise SystemExit(0)",
    target: DeploymentTarget | None = None,
) -> tuple[
    LocalFakeDeploymentAdapter,
    HostRegisteredVerifier,
    EventStore,
    Path,
    Path,
    VerificationRequest,
]:
    workspace = tmp_path / "workspace"
    (workspace / "dist").mkdir(parents=True)
    (workspace / "dist" / "artifact.bin").write_bytes(artifact)
    (workspace / "project.txt").write_text("verified source\n")
    sink_root = tmp_path / "fake-sink"
    sink_root.mkdir()
    store = EventStore(tmp_path / "deployment.sqlite")
    spec = verifier_spec(code=code)
    verifier = HostRegisteredVerifier(
        store,
        workspace_root=workspace,
        verifiers=(spec,),
        allowed_executables=frozenset({sys.executable}),
    )
    snapshot = verifier.snapshot(spec.id)
    verification_request = VerificationRequest(
        id="slice9-verification",
        verifier_id=spec.id,
        plan_id=spec.plan_id,
        plan_sha256=spec.plan_sha256,
        stage_id=spec.stage_id,
        expected_snapshot_sha256=snapshot.sha256,
    )
    adapter = LocalFakeDeploymentAdapter(
        store,
        workspace_root=workspace,
        sink_root=sink_root,
        targets=(target or target_spec(),),
        verifier=verifier,
    )
    return adapter, verifier, store, workspace, sink_root, verification_request


def request_from_preview(
    adapter: LocalFakeDeploymentAdapter,
    verification_request_id: str,
    *,
    request_id: str = "local-deployment-1",
) -> DeploymentRequest:
    preview = adapter.preview(
        target_id="fixture-local-deploy",
        verification_request_id=verification_request_id,
    )
    return DeploymentRequest(
        id=request_id,
        target_id=preview.target_id,
        verification_request_id=preview.verification_request_id,
        expected_verification_event_id=preview.verification_event_id,
        expected_snapshot_sha256=preview.snapshot_sha256,
        expected_artifact_sha256=preview.artifact_sha256,
        expected_manifest_sha256=preview.manifest_sha256,
    )


def test_verified_artifact_deploys_once_with_exact_readback_and_hash_only_receipt(
    tmp_path: Path,
) -> None:
    artifact = ARTIFACT + ARTIFACT_SENTINEL.encode()
    adapter, verifier, store, _workspace, sink_root, verification_request = build_fixture(
        tmp_path,
        artifact=artifact,
    )
    passed = verifier.execute(verification_request)
    assert passed.status == "passed"
    preview = adapter.preview(
        target_id="fixture-local-deploy",
        verification_request_id=verification_request.id,
    )
    request = request_from_preview(adapter, verification_request.id)

    first = adapter.deploy(request)
    sink = sink_root / "releases" / "artifact.bin"
    inode = sink.stat().st_ino
    replay = adapter.deploy(request)
    required = adapter.require_deployed(request.id)

    assert sink.read_bytes() == artifact
    assert first.status == "deployed"
    assert first.target_id == request.target_id
    assert first.kind == "local_fake"
    assert first.verification_event_id == passed.terminal_event_id
    assert first.snapshot_sha256 == passed.snapshot_after_sha256
    assert first.artifact_sha256 == sha256(artifact).hexdigest()
    assert first.manifest_sha256 == preview.manifest_sha256
    assert first.sink_readback_sha256 == first.artifact_sha256
    assert first.sink_readback_verified is True
    assert first.public_action_eligible is True
    assert first.sink_mutation_count == 1
    assert first.replayed is False
    assert replay.replayed is True
    assert replay.terminal_event_id == first.terminal_event_id
    assert required.replayed is True
    assert sink.stat().st_ino == inode

    assert len(store.events("deployment.local_fake.claimed")) == 1
    assert len(store.events("deployment.local_fake.completed")) == 1
    persisted = canonical_json([event.payload for event in store.events()])
    assert ARTIFACT_SENTINEL not in persisted
    assert '"artifact"' not in persisted
    assert '"source_content"' not in persisted
    assert store.verify_chain()["valid"] is True
    assert stat.S_IMODE(sink_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(sink.stat().st_mode) == 0o600


def test_failed_verification_denies_without_claim_or_sink_effect(tmp_path: Path) -> None:
    adapter, verifier, store, _workspace, sink_root, verification_request = build_fixture(
        tmp_path,
        code="raise SystemExit(3)",
    )
    assert verifier.execute(verification_request).status == "failed"

    with pytest.raises(DeploymentDenied, match="VERIFICATION_NOT_PASSED"):
        adapter.preview(
            target_id="fixture-local-deploy",
            verification_request_id=verification_request.id,
        )

    assert not store.events("deployment.local_fake.claimed")
    assert list(sink_root.iterdir()) == [sink_root / ".deployment.lock"]


def test_source_or_verified_snapshot_drift_denies_before_deployment_claim(
    tmp_path: Path,
) -> None:
    adapter, verifier, store, workspace, sink_root, verification_request = build_fixture(tmp_path)
    verifier.execute(verification_request)
    request = request_from_preview(adapter, verification_request.id)
    (workspace / "dist" / "artifact.bin").write_bytes(b"changed after preview\n")

    with pytest.raises(DeploymentDenied, match="PROJECT_SNAPSHOT_STALE"):
        adapter.deploy(request)

    assert not store.events("deployment.local_fake.claimed")
    assert not (sink_root / "releases" / "artifact.bin").exists()


def test_request_hash_and_receipt_bindings_fail_closed_before_claim(tmp_path: Path) -> None:
    adapter, verifier, store, _workspace, sink_root, verification_request = build_fixture(tmp_path)
    verifier.execute(verification_request)
    preview = adapter.preview(
        target_id="fixture-local-deploy",
        verification_request_id=verification_request.id,
    )
    base = {
        "id": "bad-binding",
        "target_id": preview.target_id,
        "verification_request_id": preview.verification_request_id,
        "expected_verification_event_id": preview.verification_event_id,
        "expected_snapshot_sha256": preview.snapshot_sha256,
        "expected_artifact_sha256": preview.artifact_sha256,
        "expected_manifest_sha256": preview.manifest_sha256,
    }
    cases = (
        {**base, "expected_verification_event_id": "event-other"},
        {**base, "expected_snapshot_sha256": "f" * 64},
        {**base, "expected_artifact_sha256": "f" * 64},
        {**base, "expected_manifest_sha256": "f" * 64},
    )
    for index, values in enumerate(cases):
        values["id"] = f"bad-binding-{index}"
        with pytest.raises(DeploymentDenied, match="DEPLOYMENT_PREVIEW_MISMATCH"):
            adapter.deploy(DeploymentRequest(**values))

    assert not store.events("deployment.local_fake.claimed")
    assert not (sink_root / "releases" / "artifact.bin").exists()


def test_preexisting_sink_refuses_overwrite_even_when_bytes_match(tmp_path: Path) -> None:
    adapter, verifier, store, _workspace, sink_root, verification_request = build_fixture(tmp_path)
    verifier.execute(verification_request)
    request = request_from_preview(adapter, verification_request.id)
    sink = sink_root / "releases" / "artifact.bin"
    sink.parent.mkdir()
    sink.write_bytes(ARTIFACT)
    inode = sink.stat().st_ino

    with pytest.raises(DeploymentDenied, match="SINK_ALREADY_EXISTS"):
        adapter.deploy(request)

    assert sink.read_bytes() == ARTIFACT
    assert sink.stat().st_ino == inode
    assert not store.events("deployment.local_fake.claimed")


def test_crash_after_atomic_sink_write_adopts_without_second_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, verifier, store, _workspace, sink_root, verification_request = build_fixture(tmp_path)
    verifier.execute(verification_request)
    request = request_from_preview(adapter, verification_request.id, request_id="deploy-crash")
    original = adapter._record_completion

    def crash_before_receipt(*args: Any, **kwargs: Any) -> Any:
        raise SystemExit("simulated crash after sink write")

    monkeypatch.setattr(adapter, "_record_completion", crash_before_receipt)
    with pytest.raises(SystemExit, match="simulated crash"):
        adapter.deploy(request)
    sink = sink_root / "releases" / "artifact.bin"
    inode_after_crash = sink.stat().st_ino
    assert sink.read_bytes() == ARTIFACT
    assert not store.events("deployment.local_fake.completed")

    monkeypatch.setattr(adapter, "_record_completion", original)
    recovered = adapter.deploy(request)

    assert recovered.status == "deployed"
    assert recovered.replayed is True
    assert recovered.sink_mutation_count == 1
    assert sink.stat().st_ino == inode_after_crash
    assert len(store.events("deployment.local_fake.claimed")) == 1
    assert len(store.events("deployment.local_fake.completed")) == 1


def test_sink_mutation_after_success_blocks_replay_and_next_stage(tmp_path: Path) -> None:
    adapter, verifier, _store, _workspace, sink_root, verification_request = build_fixture(tmp_path)
    verifier.execute(verification_request)
    request = request_from_preview(adapter, verification_request.id)
    adapter.deploy(request)
    sink = sink_root / "releases" / "artifact.bin"
    sink.write_bytes(b"foreign mutation\n")

    with pytest.raises(DeploymentDenied, match="SINK_READBACK_STALE"):
        adapter.deploy(request)
    with pytest.raises(DeploymentDenied, match="SINK_READBACK_STALE"):
        adapter.require_deployed(request.id)
    assert sink.read_bytes() == b"foreign mutation\n"


def _concurrent_deploy_worker(
    store_path: str,
    workspace_path: str,
    sink_path: str,
    barrier: Any,
    queue: Any,
) -> None:
    store = EventStore(store_path)
    spec = verifier_spec()
    verifier = HostRegisteredVerifier(
        store,
        workspace_root=workspace_path,
        verifiers=(spec,),
        allowed_executables=frozenset({sys.executable}),
    )
    adapter = LocalFakeDeploymentAdapter(
        store,
        workspace_root=workspace_path,
        sink_root=sink_path,
        targets=(target_spec(),),
        verifier=verifier,
    )
    request = request_from_preview(adapter, "slice9-verification", request_id="concurrent-deploy")
    barrier.wait()
    try:
        result = adapter.deploy(request)
    except DeploymentDenied as error:
        queue.put(error.reason_code)
    else:
        queue.put("REPLAY" if result.replayed else "DEPLOYED")


def test_four_process_deploy_race_produces_one_atomic_sink_mutation(tmp_path: Path) -> None:
    adapter, verifier, _store, workspace, sink_root, verification_request = build_fixture(tmp_path)
    verifier.execute(verification_request)
    # Close setup handles before spawned processes open same ledger.
    del adapter
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(4)
    queue = context.Queue()
    workers = [
        context.Process(
            target=_concurrent_deploy_worker,
            args=(
                str(tmp_path / "deployment.sqlite"),
                str(workspace),
                str(sink_root),
                barrier,
                queue,
            ),
        )
        for _ in range(4)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0
    results = [queue.get(timeout=2) for _ in workers]

    assert results.count("DEPLOYED") == 1
    assert set(results) <= {"DEPLOYED", "REPLAY"}
    assert (sink_root / "releases" / "artifact.bin").read_bytes() == ARTIFACT
    store = EventStore(tmp_path / "deployment.sqlite")
    assert len(store.events("deployment.local_fake.claimed")) == 1
    assert len(store.events("deployment.local_fake.completed")) == 1
    assert store.verify_chain()["valid"] is True


def test_source_and_sink_symlinks_and_source_hardlink_fail_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "dist").mkdir(parents=True)
    source = workspace / "dist" / "artifact.bin"
    source.write_bytes(ARTIFACT)
    (workspace / "project.txt").write_text("source\n")
    outside = tmp_path / "outside.bin"
    outside.write_bytes(ARTIFACT)
    sink_root = tmp_path / "sink"
    sink_root.mkdir()
    store = EventStore(tmp_path / "unsafe.sqlite")
    spec = verifier_spec()
    verifier = HostRegisteredVerifier(
        store,
        workspace_root=workspace,
        verifiers=(spec,),
        allowed_executables=frozenset({sys.executable}),
    )

    source.unlink()
    source.symlink_to(outside)
    with pytest.raises(ValueError, match="deployment source"):
        LocalFakeDeploymentAdapter(
            store,
            workspace_root=workspace,
            sink_root=sink_root,
            targets=(target_spec(),),
            verifier=verifier,
        )

    source.unlink()
    os.link(outside, source)
    with pytest.raises(ValueError, match="deployment source"):
        LocalFakeDeploymentAdapter(
            store,
            workspace_root=workspace,
            sink_root=sink_root,
            targets=(target_spec(),),
            verifier=verifier,
        )

    source.unlink()
    source.write_bytes(ARTIFACT)
    safe_adapter = LocalFakeDeploymentAdapter(
        store,
        workspace_root=workspace,
        sink_root=sink_root,
        targets=(target_spec(),),
        verifier=verifier,
    )
    snapshot = verifier.snapshot(spec.id)
    verification_request = VerificationRequest(
        id="unsafe-sink-verification",
        verifier_id=spec.id,
        plan_id=spec.plan_id,
        plan_sha256=spec.plan_sha256,
        stage_id=spec.stage_id,
        expected_snapshot_sha256=snapshot.sha256,
    )
    verifier.execute(verification_request)
    request = request_from_preview(safe_adapter, verification_request.id)
    sink_parent = sink_root / "releases"
    sink_parent.mkdir()
    sink = sink_parent / "artifact.bin"
    sink.symlink_to(outside)

    with pytest.raises(DeploymentDenied, match="SINK_SYMLINK_DENIED"):
        safe_adapter.deploy(request)
    assert outside.read_bytes() == ARTIFACT
    assert not store.events("deployment.local_fake.claimed")


def test_target_and_request_schemas_reject_production_network_and_malformed_values() -> None:
    digest = "a" * 64
    request_values = {
        "id": "request",
        "target_id": "target",
        "verification_request_id": "verify-request",
        "expected_verification_event_id": "event-id",
        "expected_snapshot_sha256": digest,
        "expected_artifact_sha256": digest,
        "expected_manifest_sha256": digest,
    }
    factories = (
        lambda: DeploymentTarget(
            id="prod",
            kind="production",  # type: ignore[arg-type]
            source_relative_path="dist/app.bin",
            sink_relative_path="release/app.bin",
            verifier_id="verify",
            max_artifact_bytes=4096,
        ),
        lambda: DeploymentTarget(
            id="network",
            kind="local_fake",
            source_relative_path="https://example.com/app.bin",
            sink_relative_path="release/app.bin",
            verifier_id="verify",
            max_artifact_bytes=4096,
        ),
        lambda: DeploymentTarget(
            id="escape",
            kind="local_fake",
            source_relative_path="dist/app.bin",
            sink_relative_path="../production/app.bin",
            verifier_id="verify",
            max_artifact_bytes=4096,
        ),
        lambda: DeploymentTarget(
            id="boolean-limit",
            kind="local_fake",
            source_relative_path="dist/app.bin",
            sink_relative_path="release/app.bin",
            verifier_id="verify",
            max_artifact_bytes=True,  # type: ignore[arg-type]
        ),
        lambda: DeploymentRequest(**{**request_values, "id": "bad id"}),
        lambda: DeploymentRequest(
            **{**request_values, "expected_manifest_sha256": "BAD"}
        ),
    )
    for factory in factories:
        with pytest.raises(ValueError):
            factory()
