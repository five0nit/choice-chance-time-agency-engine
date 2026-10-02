from __future__ import annotations

from hashlib import sha256
import multiprocessing
from pathlib import Path
import stat
import sys
from typing import Any

import pytest

from cct_agent.commands import (
    BoundedCommandAdapter,
    CommandDenied,
    CommandRequest,
    CommandSpec,
)
from cct_agent.store import EventStore, canonical_json


OUTPUT_SENTINEL = "COMMAND_OUTPUT_SENTINEL_1ca89_not_for_ledger"


def command_spec(
    workspace: Path,
    *,
    command_id: str = "fixture-command",
    code: str,
    arguments: tuple[str, ...] = (),
    environment: tuple[tuple[str, str], ...] = (),
    cwd: str = ".",
    timeout_ms: int = 2000,
    max_stdout_bytes: int = 4096,
    max_stderr_bytes: int = 4096,
) -> CommandSpec:
    return CommandSpec(
        id=command_id,
        argv=(sys.executable, "-c", code, *arguments),
        cwd=cwd,
        environment=environment,
        timeout_ms=timeout_ms,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
    )


def adapter_for(
    workspace: Path,
    store: EventStore,
    spec: CommandSpec,
) -> BoundedCommandAdapter:
    return BoundedCommandAdapter(
        store,
        workspace_root=workspace,
        commands=(spec,),
        allowed_executables=frozenset({sys.executable}),
    )


def test_exact_registered_argv_runs_without_shell_or_ambient_environment_and_persists_hash_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = EventStore(tmp_path / "command.sqlite")
    monkeypatch.setenv("AMBIENT_SECRET", "must-not-reach-child")
    code = (
        "import os,sys; "
        f"sys.stdout.write('{OUTPUT_SENTINEL}|' + "
        "str(os.environ.get('AMBIENT_SECRET', 'absent')) + '|' + "
        "str(os.environ.get('CCT_EXPLICIT', 'missing'))); "
        "sys.stderr.write('stderr-receipt')"
    )
    spec = command_spec(
        workspace,
        code=code,
        environment=(("CCT_EXPLICIT", "present"),),
    )
    commands = adapter_for(workspace, store, spec)

    observation = commands.execute(
        CommandRequest(id="command-request-1", command_id="fixture-command")
    )

    expected_stdout = f"{OUTPUT_SENTINEL}|absent|present".encode()
    expected_stderr = b"stderr-receipt"
    expected_argv = (str(Path(sys.executable).resolve()), *spec.argv[1:])
    assert observation.replayed is False
    assert observation.stdout == expected_stdout
    assert observation.stderr == expected_stderr
    assert observation.termination_reason == "exited"
    assert observation.exit_status == 0
    assert observation.stdout_sha256 == sha256(expected_stdout).hexdigest()
    assert observation.stderr_sha256 == sha256(expected_stderr).hexdigest()
    assert observation.argv_sha256 == sha256(
        canonical_json(list(expected_argv)).encode()
    ).hexdigest()
    assert observation.cwd == "."

    claims = store.events("command.execution.claimed")
    receipts = store.events("command.execution.completed")
    assert len(claims) == 1
    assert len(receipts) == 1
    assert receipts[0].event_id == observation.receipt_event_id
    assert receipts[0].payload == {
        "schema_version": "cct.command.receipt.v1",
        "request_id": "command-request-1",
        "claim_event_id": claims[0].event_id,
        "command_id": "fixture-command",
        "argv_sha256": observation.argv_sha256,
        "cwd": ".",
        "environment_keys": ["CCT_EXPLICIT"],
        "exit_status": 0,
        "termination_reason": "exited",
        "stdout_byte_count": len(expected_stdout),
        "stdout_sha256": sha256(expected_stdout).hexdigest(),
        "stderr_byte_count": len(expected_stderr),
        "stderr_sha256": sha256(expected_stderr).hexdigest(),
        "duration_ms": observation.duration_ms,
        "shell": False,
        "ambient_environment_inherited": False,
        "output_persisted": False,
        "environment_values_persisted": False,
    }
    persisted = canonical_json([event.payload for event in store.events()])
    assert OUTPUT_SENTINEL not in persisted
    assert "must-not-reach-child" not in persisted
    assert "present" not in persisted
    assert store.verify_chain()["valid"] is True


def test_shell_metacharacters_are_passed_as_literal_argv_and_cannot_create_file(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = tmp_path / "must-not-exist"
    literal = f"$(touch {target}) ; echo exploited"
    spec = command_spec(
        workspace,
        code="import sys; sys.stdout.write(sys.argv[1])",
        arguments=(literal,),
    )
    store = EventStore(tmp_path / "literal.sqlite")

    observation = adapter_for(workspace, store, spec).execute(
        CommandRequest(id="literal-request", command_id=spec.id)
    )

    assert observation.stdout == literal.encode()
    assert not target.exists()
    assert store.events("command.execution.completed")[0].payload["shell"] is False


def test_exact_retry_returns_completed_hash_receipt_without_rerunning_or_raw_output(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    effect = workspace / "effect.txt"
    code = (
        "from pathlib import Path; import sys; "
        "p=Path(sys.argv[1]); p.write_text(p.read_text()+'x' if p.exists() else 'x'); "
        f"print('{OUTPUT_SENTINEL}', end='')"
    )
    spec = command_spec(workspace, code=code, arguments=(str(effect),))
    store = EventStore(tmp_path / "retry.sqlite")
    commands = adapter_for(workspace, store, spec)
    request = CommandRequest(id="retry-request", command_id=spec.id)

    first = commands.execute(request)
    retry = commands.execute(request)

    assert effect.read_text() == "x"
    assert first.replayed is False
    assert first.stdout == OUTPUT_SENTINEL.encode()
    assert retry.replayed is True
    assert retry.stdout is None
    assert retry.stderr is None
    assert retry.stdout_sha256 == first.stdout_sha256
    assert retry.receipt_event_id == first.receipt_event_id
    assert len(store.events("command.execution.claimed")) == 1
    assert len(store.events("command.execution.completed")) == 1


def test_claim_without_completion_fails_closed_and_never_reexecutes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    effect = workspace / "effect.txt"
    spec = command_spec(
        workspace,
        code="from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ran')",
        arguments=(str(effect),),
    )
    store = EventStore(tmp_path / "crash.sqlite")
    commands = adapter_for(workspace, store, spec)

    def crash_after_claim(*args: Any, **kwargs: Any) -> Any:
        raise SystemExit("simulated adapter crash")

    monkeypatch.setattr(commands, "_execute_claimed", crash_after_claim)
    request = CommandRequest(id="crash-request", command_id=spec.id)
    with pytest.raises(SystemExit, match="simulated adapter crash"):
        commands.execute(request)

    fresh_adapter = adapter_for(workspace, EventStore(store.path), spec)
    with pytest.raises(CommandDenied, match="EXECUTION_STATE_UNCERTAIN") as caught:
        fresh_adapter.execute(request)

    assert caught.value.reason_code == "EXECUTION_STATE_UNCERTAIN"
    assert not effect.exists()
    assert len(store.events("command.execution.claimed")) == 1
    assert not store.events("command.execution.completed")


def test_claimed_command_adopts_exact_host_readback_without_reexecution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace-readback"
    workspace.mkdir()
    effect = workspace / "effect.txt"
    spec = command_spec(
        workspace,
        code="from pathlib import Path; import sys; Path(sys.argv[1]).write_text('verified')",
        arguments=(str(effect),),
    )
    store = EventStore(tmp_path / "readback-crash.sqlite")
    request = CommandRequest(id="readback-crash-request", command_id=spec.id)
    commands = BoundedCommandAdapter(
        store,
        workspace_root=workspace,
        commands=(spec,),
        allowed_executables=frozenset({sys.executable}),
        recovery_probes={spec.id: lambda: effect.read_text() == "verified"},
    )

    def effect_then_crash(*args: Any, **kwargs: Any) -> Any:
        effect.write_text("verified", encoding="utf-8")
        raise SystemExit("crash-after-command-effect-before-receipt")

    monkeypatch.setattr(commands, "_execute_claimed", effect_then_crash)
    with pytest.raises(SystemExit, match="crash-after-command-effect-before-receipt"):
        commands.execute(request)

    resumed = BoundedCommandAdapter(
        EventStore(store.path),
        workspace_root=workspace,
        commands=(spec,),
        allowed_executables=frozenset({sys.executable}),
        recovery_probes={spec.id: lambda: effect.read_text() == "verified"},
    ).execute(request)

    assert resumed.replayed is True
    assert resumed.exit_status == 0
    assert resumed.termination_reason == "exited"
    assert effect.read_text() == "verified"
    assert len(store.events("command.execution.claimed")) == 1
    assert len(store.events("command.execution.readback_adopted")) == 1
    assert len(store.events("command.execution.completed")) == 1
    assert store.verify_chain()["valid"] is True


def _concurrent_worker(
    store_path: str,
    workspace_path: str,
    executable: str,
    effect_path: str,
    barrier: Any,
    queue: Any,
) -> None:
    workspace = Path(workspace_path)
    spec = CommandSpec(
        id="concurrent-command",
        argv=(
            executable,
            "-c",
            "from pathlib import Path; import sys,time; "
            "p=Path(sys.argv[1]); p.open('a').write('one\\n'); time.sleep(0.15)",
            effect_path,
        ),
        cwd=".",
        environment=(),
        timeout_ms=2000,
        max_stdout_bytes=64,
        max_stderr_bytes=64,
    )
    commands = BoundedCommandAdapter(
        EventStore(store_path),
        workspace_root=workspace,
        commands=(spec,),
        allowed_executables=frozenset({executable}),
    )
    barrier.wait()
    try:
        result = commands.execute(
            CommandRequest(id="concurrent-request", command_id=spec.id)
        )
    except CommandDenied as error:
        queue.put(error.reason_code)
    else:
        queue.put("REPLAY" if result.replayed else "EXECUTED")


def test_concurrent_requests_execute_one_process_only(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    effect = workspace / "effect.txt"
    store_path = tmp_path / "concurrent.sqlite"
    EventStore(store_path)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(4)
    queue = context.Queue()
    workers = [
        context.Process(
            target=_concurrent_worker,
            args=(
                str(store_path),
                str(workspace),
                sys.executable,
                str(effect),
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
    assert set(results) <= {"EXECUTED", "REPLAY", "EXECUTION_STATE_UNCERTAIN"}
    assert effect.read_text().splitlines() == ["one"]
    store = EventStore(store_path)
    assert len(store.events("command.execution.claimed")) == 1
    assert len(store.events("command.execution.completed")) == 1
    assert store.verify_chain()["valid"] is True


@pytest.mark.parametrize(
    ("code", "timeout_ms", "stdout_limit", "expected_reason"),
    [
        ("import time; time.sleep(1)", 50, 64, "timeout"),
        ("import sys; sys.stdout.write('x'*100); sys.stdout.flush()", 2000, 16, "stdout_limit"),
    ],
)
def test_timeout_and_output_limit_terminate_process_and_record_bounded_receipt(
    tmp_path: Path,
    code: str,
    timeout_ms: int,
    stdout_limit: int,
    expected_reason: str,
) -> None:
    workspace = tmp_path / expected_reason
    workspace.mkdir()
    spec = command_spec(
        workspace,
        command_id=f"command-{expected_reason}",
        code=code,
        timeout_ms=timeout_ms,
        max_stdout_bytes=stdout_limit,
        max_stderr_bytes=64,
    )
    store = EventStore(tmp_path / f"{expected_reason}.sqlite")

    result = adapter_for(workspace, store, spec).execute(
        CommandRequest(id=f"request-{expected_reason}", command_id=spec.id)
    )

    assert result.termination_reason == expected_reason
    assert result.stdout_byte_count <= stdout_limit
    assert result.stderr_byte_count <= 64
    assert len(store.events("command.execution.completed")) == 1
    assert store.events("command.execution.completed")[0].payload["termination_reason"] == expected_reason


def test_unregistered_request_and_unsafe_registry_values_fail_before_subprocess(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    safe = command_spec(workspace, code="print('safe')")
    store = EventStore(tmp_path / "denied.sqlite")
    commands = adapter_for(workspace, store, safe)

    with pytest.raises(CommandDenied, match="COMMAND_NOT_REGISTERED"):
        commands.execute(CommandRequest(id="unknown-request", command_id="not-registered"))
    assert not store.events()

    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ValueError, match="workspace"):
        BoundedCommandAdapter(
            store,
            workspace_root=workspace,
            commands=(command_spec(workspace, code="print('x')", cwd="../outside"),),
            allowed_executables=frozenset({sys.executable}),
        )
    escape_link = workspace / "escape-link"
    escape_link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="workspace"):
        BoundedCommandAdapter(
            store,
            workspace_root=workspace,
            commands=(command_spec(workspace, code="print('x')", cwd="escape-link"),),
            allowed_executables=frozenset({sys.executable}),
        )
    with pytest.raises(ValueError, match="allowlisted"):
        BoundedCommandAdapter(
            store,
            workspace_root=workspace,
            commands=(
                CommandSpec(
                    id="wrong-executable",
                    argv=("/bin/sh", "-c", "touch should-not-run"),
                    cwd=".",
                    environment=(),
                    timeout_ms=1000,
                    max_stdout_bytes=64,
                    max_stderr_bytes=64,
                ),
            ),
            allowed_executables=frozenset({sys.executable}),
        )
    assert not store.events()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: CommandRequest(id="bad id", command_id="command"),
        lambda: CommandSpec(
            id="command",
            argv=[sys.executable, "-c", "print(1)"],  # type: ignore[arg-type]
            cwd=".",
            environment=(),
            timeout_ms=1000,
            max_stdout_bytes=64,
            max_stderr_bytes=64,
        ),
        lambda: CommandSpec(
            id="command",
            argv=(sys.executable, "-c", "print(1)"),
            cwd=".",
            environment=(("BAD-NAME", "value"),),
            timeout_ms=1000,
            max_stdout_bytes=64,
            max_stderr_bytes=64,
        ),
        lambda: CommandSpec(
            id="command",
            argv=(sys.executable, "-c", "print(1)"),
            cwd=".",
            environment=(),
            timeout_ms=True,  # type: ignore[arg-type]
            max_stdout_bytes=64,
            max_stderr_bytes=64,
        ),
    ],
)
def test_request_and_command_spec_schemas_reject_malformed_values(factory: Any) -> None:
    with pytest.raises(ValueError):
        factory()


def test_command_receipt_database_is_private(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    spec = command_spec(workspace, code="print('ok', end='')")
    store = EventStore(tmp_path / "private" / "command.sqlite")
    commands = adapter_for(workspace, store, spec)
    commands.execute(CommandRequest(id="permission-request", command_id=spec.id))

    assert stat.S_IMODE(store.path.stat().st_mode) & 0o077 == 0
