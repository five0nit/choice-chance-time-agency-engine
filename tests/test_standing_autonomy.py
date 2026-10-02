from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import subprocess

import pytest

from cct_agent.capabilities import CapabilityRegistry
from cct_agent.commands import OwnedProjectShell
from cct_agent.execution_tickets import TicketAuthorityDenied
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.standing_autonomy import (
    StandingAutonomyPolicy,
    StandingAutonomyRunner,
    StandingShellAction,
)
from cct_agent.store import EventStore


NOW = "2026-09-03T00:00:00+00:00"
FUTURE = "2027-09-03T00:00:00+00:00"
EMPTY_SHA256 = sha256(b"").hexdigest()


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        env={
            "HOME": str(root),
            "GIT_AUTHOR_NAME": "CCT Test",
            "GIT_AUTHOR_EMAIL": "cct@example.invalid",
            "GIT_COMMITTER_NAME": "CCT Test",
            "GIT_COMMITTER_EMAIL": "cct@example.invalid",
        },
    ).stdout.strip()


def repository(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    git(root, "init", "-q")
    (root / "README.md").write_text("standing autonomy\n", encoding="utf-8")
    git(root, "add", "README.md")
    git(root, "commit", "-q", "-m", "Initial")
    return root


def installed_store(
    tmp_path: Path, *, clock: object | None = None
) -> EventStore:
    selected_clock = clock if callable(clock) else (lambda: NOW)
    store = EventStore(
        tmp_path / "state" / "agency.sqlite",
        clock=selected_clock,  # type: ignore[arg-type]
    )
    PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={
                "autonomy": 1.0,
                "competence": 1.0,
                "human_agency": 1.0,
                "truth": 1.0,
                "usefulness": 1.0,
            },
            directives=(
                PrincipalDirective(
                    id="standing-autonomy",
                    kind="grant",
                    statement="Allow bounded standing local autonomy under exact host policy.",
                    tags=("domain:operator", "action:shell"),
                    priority=100,
                ),
            ),
        ),
        authority="operator",
        evidence=("telegram://operator/standing-autonomy",),
    )
    return store


def policy(**overrides: object) -> StandingAutonomyPolicy:
    values: dict[str, object] = {
        "id": "mike-standing-autonomy-v1",
        "principal_id": "mike",
        "expires_at": FUTURE,
    }
    values.update(overrides)
    return StandingAutonomyPolicy(**values)  # type: ignore[arg-type]


def action(
    *,
    expected_exit_status: int = 0,
    expected_stdout_sha256: str | None = EMPTY_SHA256,
    action_class: str = "allowlisted_command",
    expected_utility: float = 0.9,
    uncertainty: float = 0.05,
    argv: tuple[str, ...] = ("/usr/bin/git", "status", "--porcelain=v1"),
) -> StandingShellAction:
    return StandingShellAction(
        id="project-health",
        action_class=action_class,
        project_id="project-alpha",
        cwd=".",
        argv=argv,
        verifier_id="project-health-readback",
        expected_utility=expected_utility,
        uncertainty=uncertainty,
        expected_exit_status=expected_exit_status,
        expected_stdout_sha256=expected_stdout_sha256,
    )


def runner(
    tmp_path: Path,
    *,
    action_spec: StandingShellAction | None = None,
) -> tuple[EventStore, StandingAutonomyRunner, Path]:
    root = repository(tmp_path)
    store = installed_store(tmp_path)
    configured = StandingAutonomyRunner(
        store,
        policy=policy(),
        projects=(
            OwnedProjectShell(
                id="project-alpha",
                root=root,
                verifier_ids=((action_spec or action()).verifier_id,),
                direct_argv_enabled=True,
            ),
        ),
        actions=(action_spec or action(),),
        authority_evidence=(
            "external:user:standing-autonomy-20260903",
            "receipt:brief2ship-preflight-cct-standing-autonomy-JNPYxY",
        ),
    )
    return store, configured, root


def test_policy_resolves_overlap_and_host_constraints_fail_closed() -> None:
    configured = policy(
        automatic_classes=(
            "allowlisted_command",
            "account_security_permission_change",
            "job_application_submission",
        ),
        earned_classes=(
            "account_security_permission_change",
            "bounded_spending_trading",
            "raw_password_mfa_recovery_secret_entry",
        ),
        per_operation_classes=(
            "account_security_permission_change",
            "legal_declaration",
            "raw_password_mfa_recovery_secret_entry",
        ),
    )

    assert configured.resolve("allowlisted_command") == "automatic"
    assert configured.resolve("job_application_submission") == "automatic"
    assert configured.resolve("bounded_spending_trading") == "earned"
    assert configured.resolve("account_security_permission_change") == "per_operation"
    assert configured.resolve("raw_password_mfa_recovery_secret_entry") == "per_operation"
    assert configured.resolve("unknown_effect") == "per_operation"
    assert "no_captcha_mfa_password_or_human_attestation_pending" in configured.conditions(
        "job_application_submission"
    )
    assert configured.as_payload()["self_grant_enabled"] is False


def test_registered_action_executes_without_fresh_approval_then_unchanged_trigger_noops(
    tmp_path: Path,
) -> None:
    store, configured, root = runner(tmp_path)

    first = configured.run_once(run_id="standing-run-1")
    second = configured.run_once(run_id="standing-run-2")

    assert first["status"] == "VERIFIED"
    assert first["fresh_user_approval_required"] is False
    assert first["external_effects"] == 0
    assert second["status"] == "NO_OP"
    assert second["reason"] == "UNCHANGED_TRIGGERS"
    assert git(root, "status", "--porcelain=v1") == ""
    assert len(store.events("capability.lease.granted")) == 1
    assert len(store.events("execution.ticket.issued")) == 1
    assert len(store.events("execution.ticket.consumed")) == 1
    assert len(store.events("operator.shell.completed")) == 1
    assert len(store.events("standing.autonomy.run.completed")) == 1
    assert (
        store.events("standing.autonomy.run.completed")[0].payload["effect_event_id"]
        == store.events("operator.shell.completed")[0].event_id
    )
    assert store.verify_chain()["valid"] is True
    status = configured.status()
    assert status["verified_runs"] == 1
    assert status["failed_runs"] == 0
    assert status["lease"]["expired"] is False
    assert status["self_grant_enabled"] is False


def test_same_run_is_idempotent_and_does_not_repeat_shell(tmp_path: Path) -> None:
    store, configured, _root = runner(tmp_path)

    first = configured.run_once(run_id="standing-run-same")
    replay = configured.run_once(run_id="standing-run-same")

    assert first["status"] == "VERIFIED"
    assert replay["status"] == "NO_OP"
    assert replay["reason"] == "UNCHANGED_TRIGGERS"
    assert len(store.events("operator.shell.completed")) == 1


def test_per_operation_action_cannot_enter_standing_runner(tmp_path: Path) -> None:
    root = repository(tmp_path)
    store = installed_store(tmp_path)
    protected = action(action_class="account_security_permission_change")

    with pytest.raises(ValueError, match="per-operation actions"):
        StandingAutonomyRunner(
            store,
            policy=policy(),
            projects=(
                OwnedProjectShell(
                    id="project-alpha",
                    root=root,
                    verifier_ids=(protected.verifier_id,),
                ),
            ),
            actions=(protected,),
            authority_evidence=("external:user:standing-autonomy-20260903",),
        )


def test_benefit_and_uncertainty_thresholds_reject_action_registration(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    store = installed_store(tmp_path)
    low_benefit = action(expected_utility=0.69)
    with pytest.raises(ValueError, match="below utility threshold"):
        StandingAutonomyRunner(
            store,
            policy=policy(),
            projects=(OwnedProjectShell("project-alpha", root, (low_benefit.verifier_id,)),),
            actions=(low_benefit,),
            authority_evidence=("external:user:standing-autonomy-20260903",),
        )

    high_uncertainty = action(uncertainty=0.21)
    with pytest.raises(ValueError, match="exceeds uncertainty threshold"):
        StandingAutonomyRunner(
            store,
            policy=policy(id="mike-standing-autonomy-v2"),
            projects=(OwnedProjectShell("project-alpha", root, (high_uncertainty.verifier_id,)),),
            actions=(high_uncertainty,),
            authority_evidence=("external:user:standing-autonomy-20260903",),
        )


def test_failed_readback_trips_global_kill_switch(tmp_path: Path) -> None:
    failing = action(
        argv=("/usr/bin/git", "rev-parse", "--verify", "refs/heads/not-present"),
        expected_exit_status=0,
        expected_stdout_sha256=None,
    )
    store, configured, _root = runner(tmp_path, action_spec=failing)

    result = configured.run_once(run_id="standing-run-fail")

    assert result["status"] == "FAILED"
    assert configured.status()["kill_switch"]["active"] is True
    with pytest.raises(TicketAuthorityDenied, match="GLOBAL_KILL_SWITCH_ACTIVE"):
        configured.run_once(run_id="standing-run-after-fail")
    assert store.verify_chain()["valid"] is True


def test_verified_history_promotes_within_operator_ceiling(tmp_path: Path) -> None:
    root = repository(tmp_path)
    store = installed_store(tmp_path)
    recurring = StandingShellAction(
        id="recurring-health",
        action_class="allowlisted_command",
        project_id="project-alpha",
        cwd=".",
        argv=("/usr/bin/git", "status", "--porcelain=v1"),
        verifier_id="recurring-health-readback",
        expected_utility=0.9,
        uncertainty=0.05,
        expected_stdout_sha256=EMPTY_SHA256,
        trigger_kind="always",
        required_tier=3,
    )
    configured = StandingAutonomyRunner(
        store,
        policy=policy(promotion_verified_runs=2),
        projects=(
            OwnedProjectShell(
                id="project-alpha",
                root=root,
                verifier_ids=(recurring.verifier_id,),
            ),
        ),
        actions=(recurring,),
        authority_evidence=("external:user:standing-autonomy-20260903",),
    )

    first = configured.run_once(run_id="promotion-run-1")
    second = configured.run_once(run_id="promotion-run-2")

    assert first["current_tier"] == 3
    assert second["current_tier"] == 4
    transitions = store.events("standing.autonomy.tier.changed")
    assert len(transitions) == 1
    assert transitions[0].payload["automatic_within_operator_ceiling"] is True
    assert transitions[0].payload["fresh_user_approval_required"] is False


def test_earned_action_requires_tier_four_registration(tmp_path: Path) -> None:
    root = repository(tmp_path)
    store = installed_store(tmp_path)
    earned = action(action_class="draft_pull_request")

    with pytest.raises(ValueError, match="earned standing actions require tier 4"):
        StandingAutonomyRunner(
            store,
            policy=policy(),
            projects=(
                OwnedProjectShell(
                    id="project-alpha",
                    root=root,
                    verifier_ids=(earned.verifier_id,),
                ),
            ),
            actions=(earned,),
            authority_evidence=("external:user:standing-autonomy-20260903",),
        )


def test_worker_drains_distinct_actions_once_per_git_state(tmp_path: Path) -> None:
    root = repository(tmp_path)
    store = installed_store(tmp_path)
    first_action = StandingShellAction(
        id="git-diff-check",
        action_class="allowlisted_command",
        project_id="project-alpha",
        cwd=".",
        argv=("/usr/bin/git", "diff", "--check"),
        verifier_id="git-diff-check-readback",
        expected_utility=0.95,
        uncertainty=0.03,
        expected_stdout_sha256=EMPTY_SHA256,
    )
    second_action = StandingShellAction(
        id="git-status-clean",
        action_class="allowlisted_command",
        project_id="project-alpha",
        cwd=".",
        argv=("/usr/bin/git", "status", "--porcelain=v1"),
        verifier_id="git-status-clean-readback",
        expected_utility=0.90,
        uncertainty=0.03,
        expected_stdout_sha256=EMPTY_SHA256,
    )
    configured = StandingAutonomyRunner(
        store,
        policy=policy(),
        projects=(
            OwnedProjectShell(
                id="project-alpha",
                root=root,
                verifier_ids=(first_action.verifier_id, second_action.verifier_id),
            ),
        ),
        actions=(first_action, second_action),
        authority_evidence=("external:user:standing-autonomy-20260903",),
    )

    first = configured.run_once(run_id="drain-run-1")
    second = configured.run_once(run_id="drain-run-2")
    third = configured.run_once(run_id="drain-run-3")

    assert first["action_id"] == "git-diff-check"
    assert second["action_id"] == "git-status-clean"
    assert third["status"] == "NO_OP"
    assert third["reason"] == "UNCHANGED_TRIGGERS"
    assert len(store.events("operator.shell.completed")) == 2


def test_daily_lease_renews_without_expanding_policy_ceiling(tmp_path: Path) -> None:
    root = repository(tmp_path)
    clock = ["2026-09-03T00:00:00+00:00"]
    store = installed_store(tmp_path, clock=lambda: clock[0])
    registered_action = action()
    project = OwnedProjectShell(
        id="project-alpha",
        root=root,
        verifier_ids=(registered_action.verifier_id,),
    )
    first = StandingAutonomyRunner(
        store,
        policy=policy(),
        projects=(project,),
        actions=(registered_action,),
        authority_evidence=("external:user:standing-autonomy-20260903",),
    )
    first_lease = first.lease_id

    clock[0] = "2026-09-04T00:00:00+00:00"
    second = StandingAutonomyRunner(
        store,
        policy=policy(),
        projects=(project,),
        actions=(registered_action,),
        authority_evidence=("external:user:standing-autonomy-20260903",),
    )

    assert first_lease.endswith("20260903")
    assert second.lease_id.endswith("20260904")
    assert second.lease_id != first_lease
    leases = CapabilityRegistry(store).status()["leases"]
    assert len(leases) == 2
    assert leases[first_lease]["max_actions"] == 24
    assert leases[second.lease_id]["max_actions"] == 24
