from __future__ import annotations

from hashlib import sha256
import multiprocessing
from pathlib import Path
import stat
import sys
from typing import Any

import pytest

from cct_agent.commands import CommandSpec
from cct_agent.deployment import (
    DeploymentRequest,
    DeploymentTarget,
    LocalFakeDeploymentAdapter,
)
from cct_agent.public_actions import (
    FakePublicActionRequest,
    FakePublicActionSpec,
    LocalFakePublicActionAdapter,
    PublicActionDenied,
)
from cct_agent.store import EventStore, canonical_json
from cct_agent.verification import (
    HostRegisteredVerifier,
    VerificationRequest,
    VerifierSpec,
)


PLAN_SHA256 = sha256(b"slice-10-private-plan").hexdigest()
ARTIFACT = b"fake public action deployment artifact\n"
PRIVATE_SENTINEL = "PUBLIC_ACTION_PRIVATE_SENTINEL_b03d8_not_for_ledger"


def verifier_spec() -> VerifierSpec:
    return VerifierSpec(
        id="fixture-build",
        kind="build",
        plan_id="plan-slice10-fixture",
        plan_sha256=PLAN_SHA256,
        stage_id="verify",
        command=CommandSpec(
            id="fixture-build-command",
            argv=(sys.executable, "-c", "raise SystemExit(0)"),
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


def deployment_target() -> DeploymentTarget:
    return DeploymentTarget(
        id="fixture-local-deploy",
        kind="local_fake",
        source_relative_path="dist/artifact.bin",
        sink_relative_path="releases/artifact.bin",
        verifier_id="fixture-build",
        max_artifact_bytes=4096,
    )


def action_spec(
    *,
    action_id: str = "fixture-publish",
    kind: str = "fake_sink",
    channel: str = "local_fake",
    action: str = "publish",
    template_id: str = "verified-deployment-v1",
    outbox_item_name: str = "fixture-publish.json",
) -> FakePublicActionSpec:
    return FakePublicActionSpec(
        id=action_id,
        kind=kind,  # type: ignore[arg-type]
        channel=channel,  # type: ignore[arg-type]
        action=action,  # type: ignore[arg-type]
        envelope_type="deployment_announcement",
        template_id=template_id,
        deployment_target_id="fixture-local-deploy",
        outbox_item_name=outbox_item_name,
        max_item_bytes=8192,
    )


def build_fixture(
    tmp_path: Path,
    *,
    artifact: bytes = ARTIFACT,
    action: FakePublicActionSpec | None = None,
) -> tuple[
    LocalFakePublicActionAdapter,
    LocalFakeDeploymentAdapter,
    HostRegisteredVerifier,
    EventStore,
    Path,
    Path,
    Path,
    VerificationRequest,
]:
    workspace = tmp_path / "workspace"
    (workspace / "dist").mkdir(parents=True)
    (workspace / "dist" / "artifact.bin").write_bytes(artifact)
    (workspace / "project.txt").write_text("verified source\n")
    deployment_sink = tmp_path / "deployment-sink"
    deployment_sink.mkdir()
    outbox_root = tmp_path / "fake-public-outbox"
    outbox_root.mkdir()
    store = EventStore(tmp_path / "public-action.sqlite")
    verifier = HostRegisteredVerifier(
        store,
        workspace_root=workspace,
        verifiers=(verifier_spec(),),
        allowed_executables=frozenset({sys.executable}),
    )
    snapshot = verifier.snapshot("fixture-build")
    verification_request = VerificationRequest(
        id="slice10-verification",
        verifier_id="fixture-build",
        plan_id="plan-slice10-fixture",
        plan_sha256=PLAN_SHA256,
        stage_id="verify",
        expected_snapshot_sha256=snapshot.sha256,
    )
    deployment = LocalFakeDeploymentAdapter(
        store,
        workspace_root=workspace,
        sink_root=deployment_sink,
        targets=(deployment_target(),),
        verifier=verifier,
    )
    adapter = LocalFakePublicActionAdapter(
        store,
        outbox_root=outbox_root,
        actions=(action or action_spec(),),
        deployment=deployment,
    )
    return (
        adapter,
        deployment,
        verifier,
        store,
        workspace,
        deployment_sink,
        outbox_root,
        verification_request,
    )


def deploy_fixture(
    deployment: LocalFakeDeploymentAdapter,
    verifier: HostRegisteredVerifier,
    verification_request: VerificationRequest,
    *,
    deployment_request_id: str = "slice10-deployment",
) -> DeploymentRequest:
    verifier.execute(verification_request)
    preview = deployment.preview(
        target_id="fixture-local-deploy",
        verification_request_id=verification_request.id,
    )
    request = DeploymentRequest(
        id=deployment_request_id,
        target_id=preview.target_id,
        verification_request_id=preview.verification_request_id,
        expected_verification_event_id=preview.verification_event_id,
        expected_snapshot_sha256=preview.snapshot_sha256,
        expected_artifact_sha256=preview.artifact_sha256,
        expected_manifest_sha256=preview.manifest_sha256,
    )
    deployment.deploy(request)
    return request


def request_from_preview(
    adapter: LocalFakePublicActionAdapter,
    deployment_request_id: str,
    *,
    request_id: str = "fake-public-action-1",
) -> FakePublicActionRequest:
    preview = adapter.preview(
        action_id="fixture-publish",
        deployment_request_id=deployment_request_id,
    )
    return FakePublicActionRequest(
        id=request_id,
        action_id=preview.action_id,
        deployment_request_id=preview.deployment_request_id,
        expected_deployment_event_id=preview.deployment_event_id,
        expected_sink_readback_sha256=preview.sink_readback_sha256,
        expected_envelope_sha256=preview.envelope_sha256,
        expected_preview_sha256=preview.preview_sha256,
    )


def test_exact_deployment_emits_one_typed_fake_action_with_readback_and_hash_only_receipt(
    tmp_path: Path,
) -> None:
    artifact = ARTIFACT + PRIVATE_SENTINEL.encode()
    (
        adapter,
        deployment,
        verifier,
        store,
        _workspace,
        _deployment_sink,
        outbox_root,
        verification_request,
    ) = build_fixture(tmp_path, artifact=artifact)
    deployment_request = deploy_fixture(deployment, verifier, verification_request)
    preview = adapter.preview(
        action_id="fixture-publish",
        deployment_request_id=deployment_request.id,
    )
    request = request_from_preview(adapter, deployment_request.id)

    first = adapter.execute(request)
    outbox_item = outbox_root / "fixture-publish.json"
    inode = outbox_item.stat().st_ino
    replay = adapter.execute(request)
    required = adapter.require_completed(request.id)
    payload = outbox_item.read_bytes()

    assert first.status == "sent"
    assert first.kind == "fake_sink"
    assert first.channel == "local_fake"
    assert first.action == "publish"
    assert first.deployment_request_id == deployment_request.id
    assert first.envelope_sha256 == preview.envelope_sha256
    assert first.preview_sha256 == preview.preview_sha256
    assert first.outbox_item_sha256 == sha256(payload).hexdigest()
    assert first.outbox_readback_sha256 == first.outbox_item_sha256
    assert first.outbox_readback_verified is True
    assert first.outbox_mutation_count == 1
    assert first.real_public_effect is False
    assert first.network_effect is False
    assert first.provider_effect is False
    assert first.credential_use is False
    assert first.production_effect is False
    assert first.replayed is False
    assert replay.replayed is True
    assert replay.terminal_event_id == first.terminal_event_id
    assert required.replayed is True
    assert outbox_item.stat().st_ino == inode
    assert stat.S_IMODE(outbox_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(outbox_item.stat().st_mode) == 0o600

    outbox = canonical_json(__import__("json").loads(payload))
    assert '"schema_version":"cct.public-action.fake-sink.outbox.v1"' in outbox
    assert '"template_id":"verified-deployment-v1"' in outbox
    assert PRIVATE_SENTINEL not in outbox
    persisted = canonical_json([event.payload for event in store.events()])
    assert PRIVATE_SENTINEL not in persisted
    assert "verified-deployment-v1" not in persisted
    assert len(store.events("public_action.fake_sink.claimed")) == 1
    assert len(store.events("public_action.fake_sink.completed")) == 1
    assert store.verify_chain()["valid"] is True


def test_action_requires_completed_current_deployment_before_claim(tmp_path: Path) -> None:
    adapter, _deployment, _verifier, store, *_rest = build_fixture(tmp_path)

    with pytest.raises(PublicActionDenied, match="DEPLOYMENT_NOT_COMPLETED"):
        adapter.preview(
            action_id="fixture-publish",
            deployment_request_id="missing-deployment",
        )

    assert not store.events("public_action.fake_sink.claimed")


def test_deployment_sink_or_source_drift_denies_before_action_claim(tmp_path: Path) -> None:
    (
        adapter,
        deployment,
        verifier,
        store,
        workspace,
        deployment_sink,
        outbox_root,
        verification_request,
    ) = build_fixture(tmp_path)
    deployment_request = deploy_fixture(deployment, verifier, verification_request)
    request = request_from_preview(adapter, deployment_request.id)
    (deployment_sink / "releases" / "artifact.bin").write_bytes(b"foreign mutation\n")

    with pytest.raises(PublicActionDenied, match="SINK_READBACK_STALE"):
        adapter.execute(request)
    assert not store.events("public_action.fake_sink.claimed")
    assert list(outbox_root.iterdir()) == [outbox_root / ".public-action.lock"]

    (deployment_sink / "releases" / "artifact.bin").write_bytes(ARTIFACT)
    (workspace / "project.txt").write_text("source drift\n")
    with pytest.raises(PublicActionDenied, match="PROJECT_SNAPSHOT_STALE"):
        adapter.execute(request)
    assert not store.events("public_action.fake_sink.claimed")


def test_action_preview_bindings_fail_closed_before_claim(tmp_path: Path) -> None:
    adapter, deployment, verifier, store, *_paths, verification_request = build_fixture(tmp_path)
    deployment_request = deploy_fixture(deployment, verifier, verification_request)
    preview = adapter.preview(
        action_id="fixture-publish",
        deployment_request_id=deployment_request.id,
    )
    base = {
        "id": "bad-action",
        "action_id": preview.action_id,
        "deployment_request_id": preview.deployment_request_id,
        "expected_deployment_event_id": preview.deployment_event_id,
        "expected_sink_readback_sha256": preview.sink_readback_sha256,
        "expected_envelope_sha256": preview.envelope_sha256,
        "expected_preview_sha256": preview.preview_sha256,
    }
    cases = (
        {**base, "expected_deployment_event_id": "event-other"},
        {**base, "expected_sink_readback_sha256": "f" * 64},
        {**base, "expected_envelope_sha256": "f" * 64},
        {**base, "expected_preview_sha256": "f" * 64},
    )
    for index, values in enumerate(cases):
        values["id"] = f"bad-action-{index}"
        with pytest.raises(PublicActionDenied, match="ACTION_PREVIEW_MISMATCH"):
            adapter.execute(FakePublicActionRequest(**values))
    assert not store.events("public_action.fake_sink.claimed")


def test_preexisting_outbox_item_refuses_adoption_before_claim(tmp_path: Path) -> None:
    (
        adapter,
        deployment,
        verifier,
        store,
        _workspace,
        _deployment_sink,
        outbox_root,
        verification_request,
    ) = build_fixture(tmp_path)
    deployment_request = deploy_fixture(deployment, verifier, verification_request)
    request = request_from_preview(adapter, deployment_request.id)
    item = outbox_root / "fixture-publish.json"
    item.write_text("foreign\n")
    inode = item.stat().st_ino

    with pytest.raises(PublicActionDenied, match="OUTBOX_ITEM_ALREADY_EXISTS"):
        adapter.execute(request)
    assert item.read_text() == "foreign\n"
    assert item.stat().st_ino == inode
    assert not store.events("public_action.fake_sink.claimed")


def test_crash_after_outbox_write_adopts_exact_item_without_second_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (
        adapter,
        deployment,
        verifier,
        store,
        _workspace,
        _deployment_sink,
        outbox_root,
        verification_request,
    ) = build_fixture(tmp_path)
    deployment_request = deploy_fixture(deployment, verifier, verification_request)
    request = request_from_preview(
        adapter,
        deployment_request.id,
        request_id="public-action-crash",
    )
    original = adapter._record_completion

    def crash_before_receipt(*args: Any, **kwargs: Any) -> Any:
        raise SystemExit("simulated crash after outbox write")

    monkeypatch.setattr(adapter, "_record_completion", crash_before_receipt)
    with pytest.raises(SystemExit, match="simulated crash"):
        adapter.execute(request)
    item = outbox_root / "fixture-publish.json"
    inode_after_crash = item.stat().st_ino
    assert not store.events("public_action.fake_sink.completed")

    monkeypatch.setattr(adapter, "_record_completion", original)
    recovered = adapter.execute(request)
    assert recovered.status == "sent"
    assert recovered.replayed is True
    assert recovered.outbox_mutation_count == 1
    assert item.stat().st_ino == inode_after_crash
    assert len(store.events("public_action.fake_sink.claimed")) == 1
    assert len(store.events("public_action.fake_sink.completed")) == 1


def test_outbox_mutation_after_success_blocks_replay_and_next_stage(tmp_path: Path) -> None:
    (
        adapter,
        deployment,
        verifier,
        _store,
        _workspace,
        _deployment_sink,
        outbox_root,
        verification_request,
    ) = build_fixture(tmp_path)
    deployment_request = deploy_fixture(deployment, verifier, verification_request)
    request = request_from_preview(adapter, deployment_request.id)
    adapter.execute(request)
    item = outbox_root / "fixture-publish.json"
    item.write_text("foreign mutation\n")

    with pytest.raises(PublicActionDenied, match="OUTBOX_READBACK_STALE"):
        adapter.execute(request)
    with pytest.raises(PublicActionDenied, match="OUTBOX_READBACK_STALE"):
        adapter.require_completed(request.id)
    assert item.read_text() == "foreign mutation\n"


def _concurrent_action_worker(
    store_path: str,
    workspace_path: str,
    deployment_sink_path: str,
    outbox_path: str,
    barrier: Any,
    queue: Any,
) -> None:
    store = EventStore(store_path)
    verifier = HostRegisteredVerifier(
        store,
        workspace_root=workspace_path,
        verifiers=(verifier_spec(),),
        allowed_executables=frozenset({sys.executable}),
    )
    deployment = LocalFakeDeploymentAdapter(
        store,
        workspace_root=workspace_path,
        sink_root=deployment_sink_path,
        targets=(deployment_target(),),
        verifier=verifier,
    )
    adapter = LocalFakePublicActionAdapter(
        store,
        outbox_root=outbox_path,
        actions=(action_spec(),),
        deployment=deployment,
    )
    request = request_from_preview(
        adapter,
        "slice10-deployment",
        request_id="concurrent-public-action",
    )
    barrier.wait()
    try:
        result = adapter.execute(request)
    except PublicActionDenied as error:
        queue.put(error.reason_code)
    else:
        queue.put("REPLAY" if result.replayed else "SENT")


def test_four_process_action_race_produces_one_atomic_outbox_item(tmp_path: Path) -> None:
    (
        adapter,
        deployment,
        verifier,
        _store,
        workspace,
        deployment_sink,
        outbox_root,
        verification_request,
    ) = build_fixture(tmp_path)
    deploy_fixture(deployment, verifier, verification_request)
    del adapter
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(4)
    queue = context.Queue()
    workers = [
        context.Process(
            target=_concurrent_action_worker,
            args=(
                str(tmp_path / "public-action.sqlite"),
                str(workspace),
                str(deployment_sink),
                str(outbox_root),
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

    assert results.count("SENT") == 1
    assert set(results) <= {"SENT", "REPLAY"}
    assert (outbox_root / "fixture-publish.json").is_file()
    store = EventStore(tmp_path / "public-action.sqlite")
    assert len(store.events("public_action.fake_sink.claimed")) == 1
    assert len(store.events("public_action.fake_sink.completed")) == 1
    assert store.verify_chain()["valid"] is True


def test_outbox_symlink_is_denied_without_touching_target(tmp_path: Path) -> None:
    (
        adapter,
        deployment,
        verifier,
        store,
        _workspace,
        _deployment_sink,
        outbox_root,
        verification_request,
    ) = build_fixture(tmp_path)
    deployment_request = deploy_fixture(deployment, verifier, verification_request)
    request = request_from_preview(adapter, deployment_request.id)
    outside = tmp_path / "outside.json"
    outside.write_text("outside\n")
    (outbox_root / "fixture-publish.json").symlink_to(outside)

    with pytest.raises(PublicActionDenied, match="OUTBOX_SYMLINK_DENIED"):
        adapter.execute(request)
    assert outside.read_text() == "outside\n"
    assert not store.events("public_action.fake_sink.claimed")


def test_outbox_root_overlap_and_generated_item_limit_fail_closed(
    tmp_path: Path,
) -> None:
    (
        adapter,
        deployment,
        verifier,
        store,
        workspace,
        _deployment_sink,
        _outbox_root,
        verification_request,
    ) = build_fixture(tmp_path)
    nested_outbox = workspace / "nested-outbox"
    nested_outbox.mkdir()
    with pytest.raises(ValueError, match="separate from deployment roots"):
        LocalFakePublicActionAdapter(
            store,
            outbox_root=nested_outbox,
            actions=(action_spec(action_id="overlap-action"),),
            deployment=deployment,
        )

    del adapter
    tiny_root = tmp_path / "tiny-outbox"
    tiny_root.mkdir()
    tiny = LocalFakePublicActionAdapter(
        store,
        outbox_root=tiny_root,
        actions=(
            FakePublicActionSpec(
                id="fixture-publish",
                kind="fake_sink",
                channel="local_fake",
                action="publish",
                envelope_type="deployment_announcement",
                template_id="verified-deployment-v1",
                deployment_target_id="fixture-local-deploy",
                outbox_item_name="fixture-publish.json",
                max_item_bytes=1,
            ),
        ),
        deployment=deployment,
    )
    deployment_request = deploy_fixture(deployment, verifier, verification_request)
    with pytest.raises(PublicActionDenied, match="OUTBOX_ITEM_TOO_LARGE"):
        tiny.preview(
            action_id="fixture-publish",
            deployment_request_id=deployment_request.id,
        )
    assert not store.events("public_action.fake_sink.claimed")


def test_specs_and_requests_reject_real_channels_credentials_paths_and_malformed_values() -> None:
    digest = "a" * 64
    request_values = {
        "id": "request",
        "action_id": "action",
        "deployment_request_id": "deployment",
        "expected_deployment_event_id": "event-id",
        "expected_sink_readback_sha256": digest,
        "expected_envelope_sha256": digest,
        "expected_preview_sha256": digest,
    }
    factories = (
        lambda: action_spec(kind="real"),
        lambda: action_spec(channel="telegram"),
        lambda: action_spec(action="email"),
        lambda: action_spec(template_id="https://example.com/payload"),
        lambda: action_spec(outbox_item_name="../public.json"),
        lambda: action_spec(outbox_item_name="token.json"),
        lambda: FakePublicActionSpec(
            id="bad-limit",
            kind="fake_sink",
            channel="local_fake",
            action="publish",
            envelope_type="deployment_announcement",
            template_id="template-v1",
            deployment_target_id="fixture-local-deploy",
            outbox_item_name="item.json",
            max_item_bytes=True,  # type: ignore[arg-type]
        ),
        lambda: FakePublicActionRequest(**{**request_values, "id": "bad id"}),
        lambda: FakePublicActionRequest(
            **{**request_values, "expected_preview_sha256": "BAD"}
        ),
    )
    for factory in factories:
        with pytest.raises(ValueError):
            factory()
