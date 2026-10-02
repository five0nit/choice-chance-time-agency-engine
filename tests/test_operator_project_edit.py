from __future__ import annotations

import base64
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from typing import Any

import pytest

from operator_crash_matrix import race_same_ticket_recovery

from cct_agent.capabilities import CapabilityLease, CapabilityRegistry, OperatorCapabilityCatalog
from cct_agent.execution_tickets import ExecutionTicket, ExecutionTicketAuthority, GlobalKillSwitch
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.operator_project_edit import (
    OPERATOR_PROJECT_EDIT_VERIFIER_ID,
    OperatorProjectEditAdapter,
    OwnedProjectEdit,
    ProjectEditVerification,
)
from cct_agent.patching import PatchDenied
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-25T00:00:00+00:00"
FUTURE = "2026-08-26T00:00:00+00:00"
BEFORE = b"enabled = false\n"
AFTER = b"enabled = true\n"
PRIVATE_SENTINEL = "PROJECT_EDIT_PRIVATE_71f2"


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["/usr/bin/git", *args],
        cwd=root,
        env={"LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0", "HOME": "/nonexistent"},
        text=True,
    ).strip()


def configured(
    tmp_path: Path,
    projects: tuple[OwnedProjectEdit, ...],
    verifier: Any,
) -> tuple[EventStore, OperatorProjectEditAdapter, ExecutionTicketAuthority, str, str]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    installed = PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 1.0},
            directives=(
                PrincipalDirective(
                    id="operator-project-edit",
                    kind="preference",
                    statement="Prefer verified reversible owned-project edits.",
                    tags=("domain:operator", "action:project_edit"),
                    priority=80,
                ),
            ),
        ),
        authority="operator",
        evidence=("operator://profile",),
    )
    spec = OperatorCapabilityCatalog(store).install()["project_edit"]
    registry = CapabilityRegistry(store)
    for project in projects:
        registry.grant(
            CapabilityLease(
                id=f"lease-edit-{project.id}",
                capability="operator.project_edit",
                principal_id="mike",
                scopes=(f"operator/project_edit/{project.id}",),
                expires_at=FUTURE,
                max_actions=8,
                max_bytes=65_536,
                max_value_microunits=0,
                issued_by="operator",
                evidence=(f"operator://lease/project-edit/{project.id}",),
            )
        )
    adapter = OperatorProjectEditAdapter(
        store,
        state_root=tmp_path / "project-edit-state",
        projects=projects,
        verifiers={"readback": verifier},
        git_executable="/usr/bin/git",
    )
    return (
        store,
        adapter,
        ExecutionTicketAuthority(store),
        installed["profile_digest"],
        spec["spec_digest"],
    )


def arguments(ticket_id: str, project_id: str, replacement: bytes = AFTER) -> dict[str, Any]:
    return {
        "execution_ticket_id": ticket_id,
        "project_id": project_id,
        "relative_path": "config/settings.txt",
        "expected_before_sha256": sha256(BEFORE).hexdigest(),
        "replacement_base64": base64.b64encode(replacement).decode("ascii"),
        "verifier_id": "readback",
        "max_bytes": 4096,
    }


def issue(
    authority: ExecutionTicketAuthority,
    payload: dict[str, Any],
    profile_digest: str,
    spec_digest: str,
) -> None:
    ticket_id = str(payload["execution_ticket_id"])
    project_id = str(payload["project_id"])
    authority.issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name="operator_project_edit",
            arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
            goal_id="goal-cct-full-operator-effects",
            plan_id=f"plan-{ticket_id}",
            plan_hash=sha256(f"plan:{ticket_id}".encode()).hexdigest(),
            stage="execute-project-edit",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=profile_digest,
            capability="operator.project_edit",
            capability_spec_digest=spec_digest,
            lease_id=f"lease-edit-{project_id}",
            scope=f"operator/project_edit/{project_id}",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=int(payload["max_bytes"]),
            value_budget_microunits=0,
        ),
        authority="operator",
        evidence=(f"operator://goal/{ticket_id}",),
    )


def mediated(
    store: EventStore,
    adapter: OperatorProjectEditAdapter,
    payload: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    calls = 0

    def next_call() -> str:
        nonlocal calls
        calls += 1
        return adapter.execute(payload)

    result = ToolExecutionMediator(
        store,
        frozenset({"operator_project_edit"}),
        outcome_verifiers=adapter.outcome_verifiers(),
    )(
        tool_name="operator_project_edit",
        args=payload,
        original_args=payload,
        next_call=next_call,
    )
    parsed = json.loads(result) if isinstance(result, str) else result
    assert isinstance(parsed, dict)
    return parsed, calls


def test_any_registered_owned_project_gets_ticketed_cas_edit_readback_and_exact_retry(
    tmp_path: Path,
) -> None:
    roots = (tmp_path / "alpha", tmp_path / "beta")
    for root in roots:
        target = root / "config" / "settings.txt"
        target.parent.mkdir(parents=True)
        target.write_bytes(BEFORE)

    calls: list[str] = []

    def verifier(root: Path, request: Any, candidate: Any) -> ProjectEditVerification:
        calls.append(request.project_id)
        current = (root / request.relative_path).read_bytes()
        assert candidate.after_sha256 == sha256(current).hexdigest()
        return ProjectEditVerification(
            passed=current.startswith(AFTER.rstrip()),
            code="READBACK_MATCH",
            evidence_sha256=sha256(current).hexdigest(),
        )

    projects = tuple(
        OwnedProjectEdit(id=name, root=root, verifier_ids=("readback",), max_bytes=4096)
        for name, root in zip(("alpha", "beta"), roots, strict=True)
    )
    store, adapter, authority, profile_digest, spec_digest = configured(
        tmp_path, projects, verifier
    )

    for project_id, root in zip(("alpha", "beta"), roots, strict=True):
        replacement = AFTER + f"# {PRIVATE_SENTINEL}-{project_id}\n".encode()
        payload = arguments(f"ticket-edit-{project_id}", project_id, replacement)
        issue(authority, payload, profile_digest, spec_digest)
        result, call_count = mediated(store, adapter, payload)
        retry, retry_calls = mediated(store, adapter, payload)

        assert result["success"] is True
        assert result["effect"]["idempotency_key"] == f"ticket-edit-{project_id}"
        assert result["project_edit"]["project_id"] == project_id
        assert result["project_edit"]["relative_path"] == "config/settings.txt"
        assert result["project_edit"]["status"] == "verified"
        assert result["project_edit"]["replacement_persisted"] is False
        assert result["verification"]["passed"] is True
        assert (root / "config" / "settings.txt").read_bytes() == replacement
        assert call_count == 1
        assert retry["success"] is True
        assert retry["mediation"]["recovered_after_restart"] is True
        assert retry_calls == 0

    assert calls == ["alpha", "beta"]
    assert adapter.registered_project_ids == frozenset({"alpha", "beta"})
    persisted = canonical_json([event.payload for event in store.events()])
    assert PRIVATE_SENTINEL not in persisted
    assert str(roots[0]) not in persisted
    assert str(roots[1]) not in persisted
    assert len(store.events("operator.project_edit.completed")) == 2
    assert store.verify_chain()["valid"] is True


@pytest.mark.operator_crash_matrix
def test_post_write_crash_reconciles_verified_edit_without_second_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    target = root / "config" / "settings.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(BEFORE)
    verifier_calls = 0

    def verifier(root_path: Path, request: Any, candidate: Any) -> ProjectEditVerification:
        nonlocal verifier_calls
        verifier_calls += 1
        current = (root_path / request.relative_path).read_bytes()
        return ProjectEditVerification(
            passed=current == AFTER and candidate.after_sha256 == sha256(current).hexdigest(),
            code="READBACK_MATCH",
            evidence_sha256=sha256(current).hexdigest(),
        )

    project = OwnedProjectEdit(
        id="owned", root=root, verifier_ids=("readback",), max_bytes=4096
    )
    store, adapter, authority, profile_digest, spec_digest = configured(
        tmp_path, (project,), verifier
    )
    payload = arguments("ticket-edit-crash", "owned")
    issue(authority, payload, profile_digest, spec_digest)

    def crash(*_args: Any, **_kwargs: Any) -> Any:
        raise SystemExit("simulated post-write crash")

    monkeypatch.setattr(adapter, "_record_completion", crash)
    with pytest.raises(SystemExit, match="simulated post-write crash"):
        mediated(store, adapter, payload)
    assert target.read_bytes() == AFTER
    assert verifier_calls == 1
    assert not store.events("operator.project_edit.completed")

    restarted = OperatorProjectEditAdapter(
        store,
        state_root=tmp_path / "project-edit-state",
        projects=(project,),
        verifiers={"readback": verifier},
        git_executable="/usr/bin/git",
    )
    recoveries = race_same_ticket_recovery(lambda: mediated(store, restarted, payload))

    assert all(recovered["success"] is True for recovered in recoveries)
    assert verifier_calls == 1
    assert target.read_bytes() == AFTER
    assert len(store.events("patch.operation.applied")) == 1
    completions = store.events("operator.project_edit.completed")
    assert len(completions) == 1
    assert completions[0].payload["recovered_after_crash"] is True
    assert store.verify_chain()["valid"] is True


def test_git_project_checkpoint_and_explicit_rollback_restore_exact_prestate(
    tmp_path: Path,
) -> None:
    root = tmp_path / "git-project"
    target = root / "config" / "settings.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(BEFORE)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "cct@example.invalid")
    _git(root, "config", "user.name", "CCT Fixture")
    _git(root, "add", "config/settings.txt")
    _git(root, "commit", "-qm", "fixture baseline")
    before_head = _git(root, "rev-parse", "HEAD")
    before_status = _git(root, "status", "--porcelain=v1", "--", "config/settings.txt")

    def verifier(root_path: Path, request: Any, _candidate: Any) -> ProjectEditVerification:
        current = (root_path / request.relative_path).read_bytes()
        return ProjectEditVerification(
            passed=current == AFTER,
            code="READBACK_MATCH",
            evidence_sha256=sha256(current).hexdigest(),
        )

    project = OwnedProjectEdit(
        id="git-project", root=root, verifier_ids=("readback",), max_bytes=4096
    )
    store, adapter, authority, profile_digest, spec_digest = configured(
        tmp_path, (project,), verifier
    )
    payload = arguments("ticket-git-edit", "git-project")
    issue(authority, payload, profile_digest, spec_digest)

    result, calls = mediated(store, adapter, payload)
    rollback = adapter.rollback("ticket-git-edit")

    assert calls == 1
    assert result["success"] is True
    assert result["project_edit"]["git_repository"] is True
    assert result["project_edit"]["git_checkpoint_head"] == before_head
    assert target.read_bytes() == BEFORE
    assert _git(root, "rev-parse", "HEAD") == before_head
    assert _git(root, "status", "--porcelain=v1", "--", "config/settings.txt") == before_status
    assert rollback["status"] == "rolled_back"
    assert rollback["git_prestate_restored"] is True
    assert len(store.events("operator.project_edit.git_checkpoint")) == 1
    assert len(store.events("operator.project_edit.rollback.completed")) == 1


def test_failed_readback_auto_rolls_back_and_boundary_paths_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    target = root / "config" / "settings.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(BEFORE)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(BEFORE)
    (root / "escape.txt").symlink_to(outside)

    def verifier(_root: Path, _request: Any, candidate: Any) -> ProjectEditVerification:
        return ProjectEditVerification(
            passed=False,
            code="READBACK_FAILED",
            evidence_sha256=candidate.after_sha256,
        )

    project = OwnedProjectEdit(id="owned", root=root, verifier_ids=("readback",), max_bytes=4096)
    store, adapter, authority, profile_digest, spec_digest = configured(
        tmp_path, (project,), verifier
    )
    payload = arguments("ticket-failed-edit", "owned")
    issue(authority, payload, profile_digest, spec_digest)
    result, calls = mediated(store, adapter, payload)

    assert calls == 1
    assert result["success"] is False
    completed = store.events("operator.project_edit.completed")
    assert len(completed) == 1
    assert completed[0].payload["status"] == "rolled_back"
    assert completed[0].payload["git_prestate_restored"] is True
    assert target.read_bytes() == BEFORE

    with pytest.raises(ValueError, match="relative_path"):
        adapter.execute({**payload, "relative_path": "../outside.txt"})
    with pytest.raises(ValueError, match="sensitive"):
        adapter.execute({**payload, "relative_path": ".env"})

    escaped = {
        **payload,
        "execution_ticket_id": "ticket-symlink-edit",
        "relative_path": "escape.txt",
    }
    issue(authority, escaped, profile_digest, spec_digest)
    authority.claim_dispatch(
        ticket_id="ticket-symlink-edit",
        tool_name="operator_project_edit",
        arguments_sha256=sha256(canonical_json(escaped).encode()).hexdigest(),
        registered_verifier_ids=frozenset({OPERATOR_PROJECT_EDIT_VERIFIER_ID}),
    )
    with pytest.raises(PatchDenied, match="TARGET_SYMLINK_DENIED"):
        adapter.execute(escaped)
    assert outside.read_bytes() == BEFORE


def test_kill_switch_after_issue_blocks_project_edit_before_write(tmp_path: Path) -> None:
    root = tmp_path / "owned"
    target = root / "config" / "settings.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(BEFORE)

    def verifier(*_args: Any) -> ProjectEditVerification:
        raise AssertionError("verifier must not run")

    project = OwnedProjectEdit(id="owned", root=root, verifier_ids=("readback",), max_bytes=4096)
    store, adapter, authority, profile_digest, spec_digest = configured(
        tmp_path, (project,), verifier
    )
    payload = arguments("ticket-killed-edit", "owned")
    issue(authority, payload, profile_digest, spec_digest)
    GlobalKillSwitch(store).trip(
        trip_id="kill-before-project-edit",
        authority="operator",
        reason="Stop project editing.",
    )

    result, calls = mediated(store, adapter, payload)

    assert result["success"] is False
    assert result["error"]["reasons"] == ["GLOBAL_KILL_SWITCH_ACTIVE"]
    assert calls == 0
    assert target.read_bytes() == BEFORE
    assert not store.events("operator.project_edit.completed")
