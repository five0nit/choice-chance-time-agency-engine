from __future__ import annotations

from hashlib import sha256
import multiprocessing
from pathlib import Path
import sys
from typing import Any

import pytest

from cct_agent.store import EventStore, canonical_json
from cct_agent.verification import (
    HostRegisteredVerifier,
    ProjectSnapshot,
    VerificationDenied,
    VerificationRequest,
    VerifierSpec,
)
from cct_agent.commands import CommandSpec


OUTPUT_SENTINEL = "VERIFIER_OUTPUT_SENTINEL_21b74_not_for_ledger"
PLAN_SHA256 = sha256(b"private-plan-payload").hexdigest()


def verifier_spec(
    workspace: Path,
    *,
    verifier_id: str = "fixture-tests",
    code: str,
    arguments: tuple[str, ...] = (),
    timeout_ms: int = 2000,
    max_stdout_bytes: int = 4096,
) -> VerifierSpec:
    return VerifierSpec(
        id=verifier_id,
        kind="test",
        plan_id="plan-slice8-fixture",
        plan_sha256=PLAN_SHA256,
        stage_id="verify",
        command=CommandSpec(
            id=f"command-{verifier_id}",
            argv=(sys.executable, "-c", code, *arguments),
            cwd=".",
            environment=(),
            timeout_ms=timeout_ms,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=4096,
        ),
        snapshot_paths=("project.txt",),
        max_snapshot_file_bytes=4096,
        max_snapshot_total_bytes=4096,
    )


def adapter_for(
    workspace: Path,
    store: EventStore,
    spec: VerifierSpec,
) -> HostRegisteredVerifier:
    return HostRegisteredVerifier(
        store,
        workspace_root=workspace,
        verifiers=(spec,),
        allowed_executables=frozenset({sys.executable}),
    )


def request_for(
    adapter: HostRegisteredVerifier,
    *,
    request_id: str = "verification-request-1",
    verifier_id: str = "fixture-tests",
) -> VerificationRequest:
    snapshot = adapter.snapshot(verifier_id)
    return VerificationRequest(
        id=request_id,
        verifier_id=verifier_id,
        plan_id="plan-slice8-fixture",
        plan_sha256=PLAN_SHA256,
        stage_id="verify",
        expected_snapshot_sha256=snapshot.sha256,
    )


def test_registered_verifier_passes_once_and_persists_hash_only_receipt(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "project.txt").write_text("verified source\n")
    effect = workspace / "effect.txt"
    code = (
        "from pathlib import Path; import sys; "
        "p=Path(sys.argv[1]); p.write_text(p.read_text()+'x' if p.exists() else 'x'); "
        f"sys.stdout.write('{OUTPUT_SENTINEL}'); sys.stderr.write('test-stderr')"
    )
    spec = verifier_spec(workspace, code=code, arguments=(str(effect),))
    store = EventStore(tmp_path / "verification.sqlite")
    adapter = adapter_for(workspace, store, spec)
    request = request_for(adapter)

    first = adapter.execute(request)
    replay = adapter.execute(request)
    gated = adapter.require_passed(request.id)

    assert effect.read_text() == "x"
    assert first.status == "passed"
    assert first.reason_code == "VERIFICATION_PASSED"
    assert first.stage_eligible is True
    assert first.plan_status == "verified"
    assert first.required_action == "advance"
    assert first.deployment_eligible is True
    assert first.public_action_eligible is True
    assert first.stdout == OUTPUT_SENTINEL.encode()
    assert first.stderr == b"test-stderr"
    assert first.snapshot_before_sha256 == request.expected_snapshot_sha256
    assert first.snapshot_after_sha256 == request.expected_snapshot_sha256
    assert first.replayed is False
    assert replay.replayed is True
    assert replay.stdout is None
    assert replay.stderr is None
    assert replay.terminal_event_id == first.terminal_event_id
    assert gated.replayed is True

    assert len(store.events("verification.run.claimed")) == 1
    assert len(store.events("command.execution.claimed")) == 1
    assert len(store.events("command.execution.completed")) == 1
    assert len(store.events("verification.run.completed")) == 1
    persisted = canonical_json([event.payload for event in store.events()])
    assert OUTPUT_SENTINEL not in persisted
    assert "verified source" not in persisted
    assert '"stdout"' not in persisted
    assert '"stderr"' not in persisted
    assert store.verify_chain()["valid"] is True


def test_nonzero_verifier_fails_plan_and_blocks_later_effect_stages(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "project.txt").write_text("broken\n")
    spec = verifier_spec(
        workspace,
        code="import sys; sys.stderr.write('failed details'); raise SystemExit(3)",
    )
    store = EventStore(tmp_path / "failed.sqlite")
    adapter = adapter_for(workspace, store, spec)
    request = request_for(adapter, request_id="failed-verification")

    result = adapter.execute(request)

    assert result.status == "failed"
    assert result.reason_code == "VERIFIER_EXIT_NONZERO"
    assert result.exit_status == 3
    assert result.stage_eligible is False
    assert result.plan_status == "failed"
    assert result.required_action == "rollback"
    assert result.deployment_eligible is False
    assert result.public_action_eligible is False
    with pytest.raises(VerificationDenied, match="VERIFICATION_NOT_PASSED"):
        adapter.require_passed(request.id)
    terminal = store.events("verification.run.completed")[0]
    assert terminal.payload["plan_transition"] == {
        "from": "verifying",
        "to": "failed",
    }
    assert terminal.payload["required_action"] == "rollback"


def test_snapshot_mismatch_denies_before_claim_or_subprocess(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "project.txt").write_text("source-v1\n")
    effect = workspace / "must-not-exist"
    spec = verifier_spec(
        workspace,
        code="from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ran')",
        arguments=(str(effect),),
    )
    store = EventStore(tmp_path / "mismatch.sqlite")
    adapter = adapter_for(workspace, store, spec)
    request = request_for(adapter, request_id="snapshot-mismatch")
    (workspace / "project.txt").write_text("source-v2\n")

    with pytest.raises(VerificationDenied, match="PROJECT_SNAPSHOT_MISMATCH"):
        adapter.execute(request)

    assert not effect.exists()
    assert not store.events()


def test_project_change_during_verification_fails_and_blocks_gating(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "project.txt"
    source.write_text("source-v1\n")
    code = "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('source-v2\\n')"
    spec = verifier_spec(workspace, code=code, arguments=(str(source),))
    store = EventStore(tmp_path / "changed.sqlite")
    adapter = adapter_for(workspace, store, spec)
    request = request_for(adapter, request_id="changed-during-verification")

    result = adapter.execute(request)

    assert result.status == "failed"
    assert result.reason_code == "PROJECT_CHANGED_DURING_VERIFICATION"
    assert result.snapshot_after_sha256 != result.snapshot_before_sha256
    assert result.stage_eligible is False
    with pytest.raises(VerificationDenied, match="VERIFICATION_NOT_PASSED"):
        adapter.require_passed(request.id)


def test_passed_receipt_becomes_ineligible_after_later_snapshot_drift(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "project.txt"
    source.write_text("source-v1\n")
    spec = verifier_spec(workspace, code="raise SystemExit(0)")
    store = EventStore(tmp_path / "stale.sqlite")
    adapter = adapter_for(workspace, store, spec)
    request = request_for(adapter, request_id="stale-after-pass")
    passed = adapter.execute(request)
    assert passed.status == "passed"
    source.write_text("source-v2\n")

    with pytest.raises(VerificationDenied, match="PROJECT_SNAPSHOT_STALE"):
        adapter.require_passed(request.id)
    with pytest.raises(VerificationDenied, match="PROJECT_SNAPSHOT_STALE"):
        adapter.execute(request)


def test_passed_receipt_fails_closed_after_host_verifier_registry_drift(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "project.txt").write_text("source-v1\n")
    original_spec = verifier_spec(workspace, code="raise SystemExit(0)")
    store = EventStore(tmp_path / "registry-drift.sqlite")
    original = adapter_for(workspace, store, original_spec)
    request = request_for(original, request_id="registry-drift")
    assert original.execute(request).status == "passed"

    changed_spec = verifier_spec(workspace, code="print('changed verifier')")
    changed = adapter_for(workspace, EventStore(store.path), changed_spec)

    with pytest.raises(VerificationDenied, match="VERIFIER_REGISTRY_DRIFT"):
        changed.require_passed(request.id)
    with pytest.raises(VerificationDenied, match="VERIFIER_REGISTRY_DRIFT"):
        changed.execute(request)


def test_request_must_match_host_registered_plan_stage_and_verifier(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "project.txt").write_text("source\n")
    spec = verifier_spec(workspace, code="raise SystemExit(0)")
    store = EventStore(tmp_path / "binding.sqlite")
    adapter = adapter_for(workspace, store, spec)
    snapshot = adapter.snapshot(spec.id)

    for request in (
        VerificationRequest(
            id="wrong-plan",
            verifier_id=spec.id,
            plan_id="other-plan",
            plan_sha256=PLAN_SHA256,
            stage_id=spec.stage_id,
            expected_snapshot_sha256=snapshot.sha256,
        ),
        VerificationRequest(
            id="wrong-hash",
            verifier_id=spec.id,
            plan_id=spec.plan_id,
            plan_sha256="f" * 64,
            stage_id=spec.stage_id,
            expected_snapshot_sha256=snapshot.sha256,
        ),
        VerificationRequest(
            id="wrong-stage",
            verifier_id=spec.id,
            plan_id=spec.plan_id,
            plan_sha256=PLAN_SHA256,
            stage_id="deploy",
            expected_snapshot_sha256=snapshot.sha256,
        ),
    ):
        with pytest.raises(VerificationDenied, match="REQUEST_BINDING_MISMATCH"):
            adapter.execute(request)

    with pytest.raises(VerificationDenied, match="VERIFIER_NOT_REGISTERED"):
        adapter.snapshot("unknown-verifier")
    assert not store.events()


def test_crash_after_command_receipt_recovers_without_second_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "project.txt").write_text("source\n")
    effect = workspace / "effect.txt"
    code = (
        "from pathlib import Path; import sys; "
        "p=Path(sys.argv[1]); p.write_text(p.read_text()+'x' if p.exists() else 'x')"
    )
    spec = verifier_spec(workspace, code=code, arguments=(str(effect),))
    store = EventStore(tmp_path / "crash.sqlite")
    adapter = adapter_for(workspace, store, spec)
    request = request_for(adapter, request_id="completion-crash")
    original = adapter._record_completion

    def crash_before_terminal(*args: Any, **kwargs: Any) -> Any:
        raise SystemExit("simulated crash after command receipt")

    monkeypatch.setattr(adapter, "_record_completion", crash_before_terminal)
    with pytest.raises(SystemExit, match="simulated crash"):
        adapter.execute(request)
    assert effect.read_text() == "x"
    assert len(store.events("command.execution.completed")) == 1
    assert not store.events("verification.run.completed")

    monkeypatch.setattr(adapter, "_record_completion", original)
    recovered = adapter.execute(request)

    assert effect.read_text() == "x"
    assert recovered.status == "passed"
    assert recovered.replayed is True
    assert len(store.events("command.execution.claimed")) == 1
    assert len(store.events("command.execution.completed")) == 1
    assert len(store.events("verification.run.completed")) == 1


def _concurrent_verifier_worker(
    store_path: str,
    workspace_path: str,
    effect_path: str,
    expected_snapshot_sha256: str,
    barrier: Any,
    queue: Any,
) -> None:
    workspace = Path(workspace_path)
    code = (
        "from pathlib import Path; import sys,time; "
        "p=Path(sys.argv[1]); p.open('a').write('one\\n'); time.sleep(0.15)"
    )
    spec = verifier_spec(workspace, code=code, arguments=(effect_path,))
    adapter = adapter_for(workspace, EventStore(store_path), spec)
    request = VerificationRequest(
        id="concurrent-verification",
        verifier_id=spec.id,
        plan_id=spec.plan_id,
        plan_sha256=spec.plan_sha256,
        stage_id=spec.stage_id,
        expected_snapshot_sha256=expected_snapshot_sha256,
    )
    barrier.wait()
    try:
        result = adapter.execute(request)
    except VerificationDenied as error:
        queue.put(error.reason_code)
    else:
        queue.put("REPLAY" if result.replayed else "EXECUTED")


def test_concurrent_verifier_requests_execute_one_process_only(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "project.txt").write_text("source\n")
    effect = workspace / "effect.txt"
    store_path = tmp_path / "concurrent.sqlite"
    store = EventStore(store_path)
    spec = verifier_spec(workspace, code="raise SystemExit(0)")
    expected = adapter_for(workspace, store, spec).snapshot(spec.id).sha256
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(4)
    queue = context.Queue()
    workers = [
        context.Process(
            target=_concurrent_verifier_worker,
            args=(
                str(store_path),
                str(workspace),
                str(effect),
                expected,
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

    assert results.count("EXECUTED") == 1
    assert set(results) <= {
        "EXECUTED",
        "REPLAY",
        "VERIFIER_EXECUTION_STATE_UNCERTAIN",
    }
    assert effect.read_text().splitlines() == ["one"]
    final_store = EventStore(store_path)
    assert len(final_store.events("verification.run.claimed")) == 1
    assert len(final_store.events("command.execution.claimed")) == 1
    assert len(final_store.events("command.execution.completed")) == 1
    assert len(final_store.events("verification.run.completed")) == 1
    assert final_store.verify_chain()["valid"] is True


def test_timeout_and_output_limit_become_failed_verification_receipts(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "project.txt").write_text("source\n")
    cases = (
        ("import time; time.sleep(1)", 50, 64, "VERIFIER_TIMEOUT"),
        (
            "import sys; sys.stdout.write('x'*100); sys.stdout.flush()",
            2000,
            16,
            "VERIFIER_STDOUT_LIMIT",
        ),
    )
    for index, (code, timeout_ms, output_limit, expected_reason) in enumerate(cases):
        spec = verifier_spec(
            workspace,
            verifier_id=f"limits-{index}",
            code=code,
            timeout_ms=timeout_ms,
            max_stdout_bytes=output_limit,
        )
        store = EventStore(tmp_path / f"limits-{index}.sqlite")
        adapter = adapter_for(workspace, store, spec)
        request = request_for(
            adapter,
            request_id=f"limits-request-{index}",
            verifier_id=spec.id,
        )
        result = adapter.execute(request)
        assert result.status == "failed"
        assert result.reason_code == expected_reason
        assert result.stdout_byte_count <= output_limit
        assert result.stage_eligible is False


def test_snapshot_requires_safe_owned_regular_single_link_files(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n")
    (workspace / "project.txt").symlink_to(outside)
    spec = verifier_spec(workspace, code="raise SystemExit(0)")
    with pytest.raises(ValueError, match="snapshot"):
        adapter_for(workspace, EventStore(tmp_path / "symlink.sqlite"), spec)

    (workspace / "project.txt").unlink()
    (workspace / "project.txt").hardlink_to(outside)
    with pytest.raises(ValueError, match="snapshot"):
        adapter_for(workspace, EventStore(tmp_path / "hardlink.sqlite"), spec)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: VerificationRequest(
            id="bad id",
            verifier_id="fixture",
            plan_id="plan",
            plan_sha256=PLAN_SHA256,
            stage_id="verify",
            expected_snapshot_sha256=PLAN_SHA256,
        ),
        lambda: VerificationRequest(
            id="request",
            verifier_id="fixture",
            plan_id="plan",
            plan_sha256="BAD",
            stage_id="verify",
            expected_snapshot_sha256=PLAN_SHA256,
        ),
        lambda: VerifierSpec(
            id="fixture",
            kind="test",
            plan_id="plan",
            plan_sha256=PLAN_SHA256,
            stage_id="verify",
            command="not-command",  # type: ignore[arg-type]
            snapshot_paths=("project.txt",),
            max_snapshot_file_bytes=4096,
            max_snapshot_total_bytes=4096,
        ),
        lambda: VerifierSpec(
            id="fixture",
            kind="test",
            plan_id="plan",
            plan_sha256=PLAN_SHA256,
            stage_id="verify",
            command=CommandSpec(
                id="command",
                argv=(sys.executable, "-c", "raise SystemExit(0)"),
                cwd=".",
                environment=(),
                timeout_ms=1000,
                max_stdout_bytes=64,
                max_stderr_bytes=64,
            ),
            snapshot_paths=["project.txt"],  # type: ignore[arg-type]
            max_snapshot_file_bytes=4096,
            max_snapshot_total_bytes=4096,
        ),
        lambda: VerifierSpec(
            id="fixture",
            kind="lint",  # type: ignore[arg-type]
            plan_id="plan",
            plan_sha256=PLAN_SHA256,
            stage_id="verify",
            command=CommandSpec(
                id="command",
                argv=(sys.executable, "-c", "raise SystemExit(0)"),
                cwd=".",
                environment=(),
                timeout_ms=1000,
                max_stdout_bytes=64,
                max_stderr_bytes=64,
            ),
            snapshot_paths=("project.txt",),
            max_snapshot_file_bytes=4096,
            max_snapshot_total_bytes=4096,
        ),
    ],
)
def test_verification_schemas_reject_malformed_values(factory: Any) -> None:
    with pytest.raises(ValueError):
        factory()


def test_snapshot_receipt_shape_is_bounded_and_deterministic(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    source = workspace / "project.txt"
    source.write_bytes(b"abc")
    spec = verifier_spec(workspace, code="raise SystemExit(0)")
    adapter = adapter_for(workspace, EventStore(tmp_path / "snapshot.sqlite"), spec)

    snapshot = adapter.snapshot(spec.id)

    assert isinstance(snapshot, ProjectSnapshot)
    assert snapshot.files == (
        {
            "relative_path": "project.txt",
            "byte_count": 3,
            "sha256": sha256(b"abc").hexdigest(),
        },
    )
    assert snapshot.sha256 == sha256(
        canonical_json(list(snapshot.files)).encode("utf-8")
    ).hexdigest()
