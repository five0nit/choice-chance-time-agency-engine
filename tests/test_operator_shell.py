from __future__ import annotations

import base64
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any

import pytest

from operator_crash_matrix import race_same_ticket_recovery

from cct_agent.capabilities import (
    CapabilityLease,
    CapabilityRegistry,
    OperatorCapabilityCatalog,
)
from cct_agent.commands import (
    CommandDenied,
    OPERATOR_SHELL_VERIFIER_ID,
    OperatorShellAdapter,
    OwnedProjectShell,
    ShellManifest,
    ShellVerification,
)
from cct_agent.execution_tickets import (
    ExecutionTicket,
    ExecutionTicketAuthority,
    GlobalKillSwitch,
)
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-25T00:00:00+00:00"
FUTURE = "2026-08-26T00:00:00+00:00"


def configured(
    tmp_path: Path,
    *,
    project: OwnedProjectShell,
    verifier: Any,
) -> tuple[EventStore, OperatorShellAdapter, ExecutionTicketAuthority, str, str]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    installed = PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 1.0},
            directives=(
                PrincipalDirective(
                    id="operator-shell",
                    kind="preference",
                    statement="Prefer bounded verified shell work.",
                    tags=("domain:operator", "action:shell"),
                    priority=80,
                ),
            ),
        ),
        authority="operator",
        evidence=("operator://profile",),
    )
    catalog = OperatorCapabilityCatalog(store).install()
    shell_spec = catalog["shell"]
    CapabilityRegistry(store).grant(
        CapabilityLease(
            id="lease-shell-project-alpha",
            capability="operator.shell",
            principal_id="mike",
            scopes=("operator/shell/project-alpha",),
            expires_at=FUTURE,
            max_actions=8,
            max_bytes=65_536,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://lease/shell/project-alpha",),
        )
    )
    adapter = OperatorShellAdapter(
        store,
        projects=(project,),
        verifiers={"artifact-readback": verifier},
    )
    return (
        store,
        adapter,
        ExecutionTicketAuthority(store),
        installed["profile_digest"],
        shell_spec["spec_digest"],
    )


def issue(
    authority: ExecutionTicketAuthority,
    *,
    arguments: dict[str, Any],
    profile_digest: str,
    spec_digest: str,
) -> None:
    ticket_id = str(arguments["execution_ticket_id"])
    authority.issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name="operator_shell",
            arguments_sha256=sha256(canonical_json(arguments).encode("utf-8")).hexdigest(),
            goal_id="goal-cct-full-operator-effects",
            plan_id="plan-shell-project-alpha",
            plan_hash=sha256(b"plan:shell:project-alpha").hexdigest(),
            stage="execute-shell",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=profile_digest,
            capability="operator.shell",
            capability_spec_digest=spec_digest,
            lease_id="lease-shell-project-alpha",
            scope="operator/shell/project-alpha",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=int(arguments["max_stdout_bytes"])
            + int(arguments["max_stderr_bytes"]),
            value_budget_microunits=0,
        ),
        authority="operator",
        evidence=("operator://goal/shell-project-alpha",),
    )


def mediated(
    store: EventStore,
    adapter: OperatorShellAdapter,
    arguments: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    calls = 0

    def next_call() -> str:
        nonlocal calls
        calls += 1
        return adapter.execute(arguments)

    result = ToolExecutionMediator(
        store,
        frozenset({"operator_shell"}),
        outcome_verifiers=adapter.outcome_verifiers(),
    )(
        tool_name="operator_shell",
        args=arguments,
        original_args=arguments,
        next_call=next_call,
    )
    parsed = json.loads(result) if isinstance(result, str) else result
    assert isinstance(parsed, dict)
    return parsed, calls


def test_ticketed_registered_project_runs_arbitrary_argv_with_empty_environment_and_readback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_root = tmp_path / "owned-project"
    work = project_root / "work"
    work.mkdir(parents=True)
    artifact = work / "artifact.txt"
    expected = b"verified-shell-artifact\n"

    def verifier(root: Path, request: Any, observation: Any) -> ShellVerification:
        assert root == project_root.resolve()
        assert request.cwd == "work"
        payload = artifact.read_bytes()
        return ShellVerification(
            passed=payload == expected,
            code="ARTIFACT_MATCH" if payload == expected else "ARTIFACT_MISMATCH",
            evidence_sha256=sha256(payload).hexdigest(),
        )

    project = OwnedProjectShell(
        id="project-alpha",
        root=project_root,
        verifier_ids=("artifact-readback",),
        manifests=(),
    )
    store, adapter, authority, profile_digest, spec_digest = configured(
        tmp_path,
        project=project,
        verifier=verifier,
    )
    monkeypatch.setenv("AMBIENT_SECRET", "must-not-reach-shell")
    code = (
        "import os; from pathlib import Path; "
        f"Path('artifact.txt').write_bytes({expected!r}); "
        "print(os.environ.get('AMBIENT_SECRET', 'absent'), end='')"
    )
    arguments = {
        "execution_ticket_id": "ticket-shell-direct",
        "project_id": "project-alpha",
        "cwd": "work",
        "argv": [sys.executable, "-c", code],
        "verifier_id": "artifact-readback",
        "timeout_ms": 2_000,
        "max_stdout_bytes": 1_024,
        "max_stderr_bytes": 1_024,
    }
    issue(
        authority,
        arguments=arguments,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )

    result, calls = mediated(store, adapter, arguments)
    retry, retry_calls = mediated(store, adapter, arguments)

    assert result["success"] is True
    assert result["effect"]["idempotency_key"] == "ticket-shell-direct"
    assert result["shell"]["project_id"] == "project-alpha"
    assert result["shell"]["cwd"] == "work"
    assert result["shell"]["shell_mode"] == "direct_argv"
    assert result["shell"]["ambient_environment_inherited"] is False
    assert base64.b64decode(result["shell"]["stdout_base64"]) == b"absent"
    assert base64.b64decode(result["shell"]["stderr_base64"]) == b""
    assert result["verification"]["passed"] is True
    assert result["verification"]["evidence_sha256"] == sha256(expected).hexdigest()
    assert artifact.read_bytes() == expected
    assert calls == 1
    assert retry["success"] is True
    assert retry["mediation"]["recovered_after_restart"] is True
    assert retry_calls == 0

    claims = store.events("operator.shell.claimed")
    receipts = store.events("operator.shell.completed")
    assert len(claims) == len(receipts) == 1
    assert receipts[0].payload["ticket_id"] == "ticket-shell-direct"
    assert receipts[0].payload["project_id"] == "project-alpha"
    assert receipts[0].payload["cwd"] == "work"
    assert receipts[0].payload["ambient_environment_inherited"] is False
    assert receipts[0].payload["raw_argv_persisted"] is False
    assert receipts[0].payload["output_persisted"] is False
    persisted = canonical_json([event.payload for event in store.events()])
    assert code not in persisted
    assert "must-not-reach-shell" not in persisted
    assert str(project_root) not in persisted
    assert store.verify_chain()["valid"] is True


@pytest.mark.operator_crash_matrix
def test_post_effect_crash_adopts_verified_shell_receipt_without_second_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_root = tmp_path / "owned-project"
    project_root.mkdir()
    artifact = project_root / "artifact.txt"
    expected = b"verified-shell-crash-recovery\n"
    verifier_calls = 0

    def verifier(_root: Path, _request: Any, _observation: Any) -> ShellVerification:
        nonlocal verifier_calls
        verifier_calls += 1
        payload = artifact.read_bytes()
        return ShellVerification(
            passed=payload == expected,
            code="ARTIFACT_MATCH",
            evidence_sha256=sha256(payload).hexdigest(),
        )

    project = OwnedProjectShell(
        id="project-alpha",
        root=project_root,
        verifier_ids=("artifact-readback",),
        manifests=(),
    )
    store, adapter, authority, profile_digest, spec_digest = configured(
        tmp_path,
        project=project,
        verifier=verifier,
    )
    code = f"from pathlib import Path; Path('artifact.txt').write_bytes({expected!r})"
    arguments = {
        "execution_ticket_id": "ticket-shell-crash",
        "project_id": "project-alpha",
        "cwd": ".",
        "argv": [sys.executable, "-c", code],
        "verifier_id": "artifact-readback",
        "timeout_ms": 2_000,
        "max_stdout_bytes": 1_024,
        "max_stderr_bytes": 1_024,
    }
    issue(
        authority,
        arguments=arguments,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )

    def crash(*_args: Any, **_kwargs: Any) -> Any:
        raise SystemExit("simulated post-effect crash")

    monkeypatch.setattr(adapter, "_record_completion", crash)
    with pytest.raises(SystemExit, match="simulated post-effect crash"):
        mediated(store, adapter, arguments)
    assert artifact.read_bytes() == expected
    assert verifier_calls == 1
    assert len(store.events("operator.shell.effect_verified")) == 1
    assert not store.events("operator.shell.completed")

    restarted = OperatorShellAdapter(
        store,
        projects=(project,),
        verifiers={"artifact-readback": verifier},
    )
    recoveries = race_same_ticket_recovery(
        lambda: mediated(store, restarted, arguments)
    )

    assert all(recovered["success"] is True for recovered in recoveries)
    assert verifier_calls == 1
    assert artifact.read_bytes() == expected
    assert len(store.events("operator.shell.claimed")) == 1
    assert len(store.events("operator.shell.effect_verified")) == 1
    completions = store.events("operator.shell.completed")
    assert len(completions) == 1
    assert completions[0].payload["recovered_after_crash"] is True
    assert store.verify_chain()["valid"] is True


def test_private_manifest_bash_lc_executes_without_exposing_script_to_arguments_or_receipts(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "manifest-project"
    project_root.mkdir()
    script_sentinel = "PRIVATE_MANIFEST_SCRIPT_8e31"
    script = f"printf '{script_sentinel}' > manifest.txt"
    expected = script_sentinel.encode()

    def verifier(_root: Path, _request: Any, _observation: Any) -> ShellVerification:
        payload = (project_root / "manifest.txt").read_bytes()
        return ShellVerification(
            passed=payload == expected,
            code="MANIFEST_EFFECT_MATCH",
            evidence_sha256=sha256(payload).hexdigest(),
        )

    project = OwnedProjectShell(
        id="project-alpha",
        root=project_root,
        verifier_ids=("artifact-readback",),
        manifests=(ShellManifest(id="build-private", script=script),),
    )
    store, adapter, authority, profile_digest, spec_digest = configured(
        tmp_path,
        project=project,
        verifier=verifier,
    )
    arguments = {
        "execution_ticket_id": "ticket-shell-manifest",
        "project_id": "project-alpha",
        "cwd": ".",
        "manifest_id": "build-private",
        "verifier_id": "artifact-readback",
        "timeout_ms": 2_000,
        "max_stdout_bytes": 1_024,
        "max_stderr_bytes": 1_024,
    }
    assert script_sentinel not in canonical_json(arguments)
    issue(
        authority,
        arguments=arguments,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )

    result, calls = mediated(store, adapter, arguments)

    assert result["success"] is True
    assert result["shell"]["shell_mode"] == "private_manifest"
    assert result["shell"]["manifest_id"] == "build-private"
    assert (project_root / "manifest.txt").read_bytes() == expected
    assert calls == 1
    persisted = canonical_json([event.payload for event in store.events()])
    assert script_sentinel not in persisted
    assert script not in persisted
    assert store.events("operator.project_shell.registered")[0].payload[
        "manifest_content_persisted"
    ] is False


def test_unknown_project_traversal_and_direct_shell_command_are_denied_before_spawn(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "owned-project"
    project_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    effect = outside / "must-not-exist"

    def verifier(_root: Path, _request: Any, _observation: Any) -> ShellVerification:
        raise AssertionError("verifier must not run")

    project = OwnedProjectShell(
        id="project-alpha",
        root=project_root,
        verifier_ids=("artifact-readback",),
        manifests=(),
    )
    store, adapter, authority, profile_digest, spec_digest = configured(
        tmp_path,
        project=project,
        verifier=verifier,
    )
    base = {
        "execution_ticket_id": "ticket-denied",
        "project_id": "project-alpha",
        "cwd": ".",
        "argv": [sys.executable, "-c", f"from pathlib import Path; Path({str(effect)!r}).write_text('ran')"],
        "verifier_id": "artifact-readback",
        "timeout_ms": 1_000,
        "max_stdout_bytes": 64,
        "max_stderr_bytes": 64,
    }

    with pytest.raises(CommandDenied, match="TICKET_DISPATCH_CLAIM_REQUIRED"):
        adapter.execute(base)

    unknown = {
        **base,
        "execution_ticket_id": "ticket-unknown-project",
        "project_id": "unknown-project",
    }
    issue(
        authority,
        arguments=unknown,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )
    authority.claim_dispatch(
        ticket_id="ticket-unknown-project",
        tool_name="operator_shell",
        arguments_sha256=sha256(canonical_json(unknown).encode("utf-8")).hexdigest(),
        registered_verifier_ids=frozenset({OPERATOR_SHELL_VERIFIER_ID}),
    )
    with pytest.raises(CommandDenied, match="TICKET_DISPATCH_CLAIM_MISMATCH"):
        adapter.execute(unknown)
    with pytest.raises(ValueError, match="cwd"):
        adapter.execute({**base, "cwd": "../outside"})

    direct_shell = {
        **base,
        "execution_ticket_id": "ticket-direct-shell-denied",
        "argv": ["/bin/bash", "-lc", "touch escaped"],
    }
    issue(
        authority,
        arguments=direct_shell,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )
    authority.claim_dispatch(
        ticket_id="ticket-direct-shell-denied",
        tool_name="operator_shell",
        arguments_sha256=sha256(
            canonical_json(direct_shell).encode("utf-8")
        ).hexdigest(),
        registered_verifier_ids=frozenset({OPERATOR_SHELL_VERIFIER_ID}),
    )
    with pytest.raises(CommandDenied, match="DIRECT_SHELL_COMMAND_DENIED"):
        adapter.execute(direct_shell)

    assert not effect.exists()
    assert not store.events("operator.shell.claimed")
    assert not store.events("operator.shell.completed")


@pytest.mark.parametrize(
    ("case", "code", "timeout_ms", "stdout_limit", "expected_reason"),
    [
        ("timeout", "import time; time.sleep(1)", 50, 64, "timeout"),
        (
            "stdout-limit",
            "import sys; sys.stdout.write('x'*4096); sys.stdout.flush()",
            2_000,
            16,
            "stdout_limit",
        ),
    ],
)
def test_operator_shell_enforces_timeout_and_output_bounds(
    tmp_path: Path,
    case: str,
    code: str,
    timeout_ms: int,
    stdout_limit: int,
    expected_reason: str,
) -> None:
    project_root = tmp_path / "owned-project"
    project_root.mkdir()

    def verifier(_root: Path, _request: Any, _observation: Any) -> ShellVerification:
        raise AssertionError("verifier must not run for failed command")

    project = OwnedProjectShell(
        id="project-alpha",
        root=project_root,
        verifier_ids=("artifact-readback",),
        manifests=(),
    )
    store, adapter, authority, profile_digest, spec_digest = configured(
        tmp_path,
        project=project,
        verifier=verifier,
    )
    arguments = {
        "execution_ticket_id": f"ticket-shell-{case}",
        "project_id": "project-alpha",
        "cwd": ".",
        "argv": [sys.executable, "-c", code],
        "verifier_id": "artifact-readback",
        "timeout_ms": timeout_ms,
        "max_stdout_bytes": stdout_limit,
        "max_stderr_bytes": 64,
    }
    issue(
        authority,
        arguments=arguments,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )

    result, calls = mediated(store, adapter, arguments)

    assert result["success"] is False
    assert calls == 1
    receipts = store.events("operator.shell.completed")
    assert len(receipts) == 1
    assert receipts[0].payload["termination_reason"] == expected_reason
    assert receipts[0].payload["stdout_byte_count"] <= stdout_limit
    assert receipts[0].payload["stderr_byte_count"] <= 64
    assert receipts[0].payload["verification_passed"] is False
    assert store.verify_chain()["valid"] is True


def test_kill_switch_tripped_after_ticket_issue_denies_shell_before_subprocess(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "owned-project"
    project_root.mkdir()
    effect = project_root / "must-not-exist"

    def verifier(_root: Path, _request: Any, _observation: Any) -> ShellVerification:
        raise AssertionError("verifier must not run")

    project = OwnedProjectShell(
        id="project-alpha",
        root=project_root,
        verifier_ids=("artifact-readback",),
        manifests=(),
    )
    store, adapter, authority, profile_digest, spec_digest = configured(
        tmp_path,
        project=project,
        verifier=verifier,
    )
    arguments = {
        "execution_ticket_id": "ticket-shell-killed",
        "project_id": "project-alpha",
        "cwd": ".",
        "argv": [sys.executable, "-c", f"from pathlib import Path; Path({str(effect)!r}).write_text('ran')"],
        "verifier_id": "artifact-readback",
        "timeout_ms": 1_000,
        "max_stdout_bytes": 64,
        "max_stderr_bytes": 64,
    }
    issue(
        authority,
        arguments=arguments,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )
    GlobalKillSwitch(store).trip(
        trip_id="kill-before-shell",
        authority="operator",
        reason="Stop shell dispatch.",
    )

    result, calls = mediated(store, adapter, arguments)

    assert result["success"] is False
    assert result["error"]["reasons"] == ["GLOBAL_KILL_SWITCH_ACTIVE"]
    assert calls == 0
    assert not effect.exists()
    assert not store.events("operator.shell.claimed")
    assert not store.events("operator.shell.completed")
