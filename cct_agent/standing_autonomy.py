"""Operator-endorsed standing autonomy for bounded local actions.

The operator approves one durable ceiling. Host code may then issue leases and
single-use tickets inside that ceiling without asking for every action. A model's
benefit estimate selects among already registered actions; it never creates
authority, commands, project roots, budgets, or verifiers.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Iterator, Literal, Mapping, Sequence

import fcntl

from .capabilities import CapabilityLease, CapabilityRegistry, OperatorCapabilityCatalog
from .commands import (
    OperatorShellAdapter,
    OwnedProjectShell,
    ShellInvocation,
    ShellVerification,
)
from .execution_tickets import ExecutionTicket, ExecutionTicketAuthority, GlobalKillSwitch
from .mediation import ToolExecutionMediator
from .store import Event, EventStore, canonical_json


StandingTier = Literal["automatic", "earned", "per_operation"]
TriggerKind = Literal["always", "git_state"]
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")

AUTOMATIC_ACTION_CLASSES = (
    "allowlisted_command",
    "authenticated_session_read_only",
    "durable_wake",
    "generate_artifact",
    "job_application_submission",
    "local_preview_service_control",
    "local_workspace_read",
    "prepare_external_commitment",
    "private_operator_notification",
    "project_file_create_modify",
    "public_web_read",
    "retry_reversible_failure",
    "rollback_own_change",
    "trusted_task_selection",
)

EARNED_ACTION_CLASSES = (
    "authenticated_account_read_only",
    "bounded_spending_trading",
    "draft_pull_request",
    "non_protected_branch_push",
    "preview_staging_deploy",
    "private_internal_record_update",
    "reversible_production_fix",
    "templated_public_post",
)

PER_OPERATION_ACTION_CLASSES = (
    "account_security_permission_change",
    "consequential_third_party_message",
    "high_consequence_financial_effect",
    "high_consequence_physical_effect",
    "irreversible_production_migration",
    "legal_declaration",
    "production_data_deletion",
    "raw_password_mfa_recovery_secret_entry",
)

SPECIAL_CONDITIONS: Mapping[str, tuple[str, ...]] = {
    "job_application_submission": (
        "exact_employer_role_and_application_package_bound",
        "all_required_facts_independently_verified",
        "no_unanswered_legal_declaration_or_protected_self_report",
        "no_captcha_mfa_password_or_human_attestation_pending",
        "authoritative_submission_receipt_required",
    ),
    "bounded_spending_trading": (
        "host_registered_venue_account_asset_and_side",
        "explicit_value_loss_slippage_fee_and_unwind_budgets",
        "wallet_pnl_truth_and_kill_switch_rechecked_each_leg",
        "authoritative_order_transaction_and_balance_readback",
    ),
    "raw_password_mfa_recovery_secret_entry": (
        "direct_model_or_computer_use_secret_entry_forbidden",
        "opaque_host_broker_or_authenticated_human_handoff_required",
    ),
}


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _timestamp(name: str, value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{name} must be ISO-8601") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include timezone")
    return parsed


def _finite(name: str, value: object, *, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    number = float(value)
    if not math.isfinite(number) or not low <= number <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return number


@dataclass(frozen=True, slots=True)
class StandingAutonomyPolicy:
    """Exact operator ceiling used by host-owned lease/ticket issuance."""

    id: str
    principal_id: str
    expires_at: str
    automatic_classes: tuple[str, ...] = AUTOMATIC_ACTION_CLASSES
    earned_classes: tuple[str, ...] = EARNED_ACTION_CLASSES
    per_operation_classes: tuple[str, ...] = PER_OPERATION_ACTION_CLASSES
    initial_tier: int = 3
    maximum_tier: int = 5
    promotion_verified_runs: int = 20
    min_expected_utility: float = 0.70
    max_uncertainty: float = 0.20
    max_actions: int = 24
    max_bytes: int = 262_144
    max_value_microunits: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("policy id", self.id))
        object.__setattr__(self, "principal_id", _identifier("principal id", self.principal_id))
        _timestamp("policy expires_at", self.expires_at)
        rows = {
            "automatic": tuple(sorted({_identifier("automatic class", row) for row in self.automatic_classes})),
            "earned": tuple(sorted({_identifier("earned class", row) for row in self.earned_classes})),
            "per_operation": tuple(sorted({_identifier("per-operation class", row) for row in self.per_operation_classes})),
        }
        for label, values in rows.items():
            if not values or len(values) > 64:
                raise ValueError(f"{label} classes must contain 1-64 values")
            object.__setattr__(self, f"{label}_classes", values)
        if not 0 <= self.initial_tier <= self.maximum_tier <= 5:
            raise ValueError("standing autonomy tiers must satisfy 0 <= initial <= maximum <= 5")
        if isinstance(self.promotion_verified_runs, bool) or self.promotion_verified_runs < 1:
            raise ValueError("promotion_verified_runs must be a positive integer")
        _finite("min_expected_utility", self.min_expected_utility, low=-1.0, high=1.0)
        _finite("max_uncertainty", self.max_uncertainty, low=0.0, high=1.0)
        for name, value, minimum in (
            ("max_actions", self.max_actions, 1),
            ("max_bytes", self.max_bytes, 0),
            ("max_value_microunits", self.max_value_microunits, 0),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                raise ValueError(f"{name} must be an integer >= {minimum}")

    def resolve(self, action_class: str) -> StandingTier:
        """Resolve conflicts deterministically: per-operation > earned > automatic."""

        action = _identifier("action class", action_class)
        if action in self.per_operation_classes:
            return "per_operation"
        if action in self.earned_classes:
            return "earned"
        if action in self.automatic_classes:
            return "automatic"
        return "per_operation"

    def conditions(self, action_class: str) -> tuple[str, ...]:
        return SPECIAL_CONDITIONS.get(action_class, ())

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "principal_id": self.principal_id,
            "expires_at": self.expires_at,
            "automatic_classes": list(self.automatic_classes),
            "earned_classes": list(self.earned_classes),
            "per_operation_classes": list(self.per_operation_classes),
            "special_conditions": {
                name: list(values) for name, values in sorted(SPECIAL_CONDITIONS.items())
            },
            "conflict_resolution": "per_operation_wins_then_earned_then_automatic",
            "initial_tier": self.initial_tier,
            "maximum_tier": self.maximum_tier,
            "promotion_verified_runs": self.promotion_verified_runs,
            "min_expected_utility": self.min_expected_utility,
            "max_uncertainty": self.max_uncertainty,
            "max_actions": self.max_actions,
            "max_bytes": self.max_bytes,
            "max_value_microunits": self.max_value_microunits,
            "self_grant_enabled": False,
        }


@dataclass(frozen=True, slots=True)
class StandingShellAction:
    """Host-registered exact action; callers select only its opaque ID."""

    id: str
    action_class: str
    project_id: str
    cwd: str
    argv: tuple[str, ...]
    verifier_id: str
    expected_utility: float
    uncertainty: float
    timeout_ms: int = 60_000
    max_stdout_bytes: int = 8_192
    max_stderr_bytes: int = 8_192
    expected_exit_status: int = 0
    expected_stdout_sha256: str | None = None
    trigger_kind: TriggerKind = "git_state"
    required_tier: int = 3
    reversible: bool = True

    def __post_init__(self) -> None:
        for name in ("id", "action_class", "project_id", "verifier_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        if not isinstance(self.cwd, str) or not self.cwd or len(self.cwd) > 512:
            raise ValueError("cwd must be a bounded relative path")
        if not isinstance(self.argv, tuple) or not 1 <= len(self.argv) <= 64:
            raise ValueError("argv must contain 1-64 exact strings")
        if any(not isinstance(value, str) or not value or "\x00" in value for value in self.argv):
            raise ValueError("argv values must be non-empty strings without NUL")
        _finite("expected_utility", self.expected_utility, low=-1.0, high=1.0)
        _finite("uncertainty", self.uncertainty, low=0.0, high=1.0)
        for name, value, minimum, maximum in (
            ("timeout_ms", self.timeout_ms, 1, 60_000),
            ("max_stdout_bytes", self.max_stdout_bytes, 0, 1_048_576),
            ("max_stderr_bytes", self.max_stderr_bytes, 0, 1_048_576),
            ("required_tier", self.required_tier, 0, 5),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
        if isinstance(self.expected_exit_status, bool) or not isinstance(self.expected_exit_status, int):
            raise ValueError("expected_exit_status must be an integer")
        if self.expected_stdout_sha256 is not None and not _DIGEST.fullmatch(self.expected_stdout_sha256):
            raise ValueError("expected_stdout_sha256 must be SHA-256")
        if self.trigger_kind not in {"always", "git_state"}:
            raise ValueError("trigger_kind must be always or git_state")
        if self.reversible is not True:
            raise ValueError("standing shell actions must be reversible")

    def public_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action_class": self.action_class,
            "project_id": self.project_id,
            "cwd": self.cwd,
            "argv_sha256": _digest(list(self.argv)),
            "verifier_id": self.verifier_id,
            "expected_utility": self.expected_utility,
            "uncertainty": self.uncertainty,
            "timeout_ms": self.timeout_ms,
            "max_stdout_bytes": self.max_stdout_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
            "expected_exit_status": self.expected_exit_status,
            "expected_stdout_sha256": self.expected_stdout_sha256,
            "trigger_kind": self.trigger_kind,
            "required_tier": self.required_tier,
            "reversible": True,
            "raw_argv_persisted": False,
        }


class StandingAutonomyRegistry:
    """Persist exact operator policy and host action registrations."""

    def __init__(self, store: EventStore) -> None:
        self.store = store

    def install_policy(
        self,
        policy: StandingAutonomyPolicy,
        *,
        authority: Literal["operator", "host_adapter"],
        evidence: Sequence[str],
    ) -> dict[str, Any]:
        if authority not in {"operator", "host_adapter"}:
            raise ValueError("policy authority must be operator or host_adapter")
        rows = tuple(str(value) for value in evidence)
        if not rows or len(rows) > 32 or any(not value or len(value) > 600 for value in rows):
            raise ValueError("policy evidence must contain 1-32 bounded values")
        policy_payload = policy.as_payload()
        payload = {
            "schema_version": "cct.standing_autonomy.policy.v1",
            "authority": authority,
            "evidence": list(rows),
            "policy": policy_payload,
            "policy_sha256": _digest(policy_payload),
            "raw_operator_message_persisted": False,
        }
        event, created = self.store.append_once_result(
            "standing.autonomy.policy.installed", policy.id, payload
        )
        if canonical_json(event.payload) != canonical_json(payload):
            raise ValueError("standing autonomy policy changed under the same ID")
        return {**event.payload, "event_id": event.event_id, "created": created}

    def register_action(self, action: StandingShellAction, *, policy_sha256: str) -> dict[str, Any]:
        if not _DIGEST.fullmatch(policy_sha256):
            raise ValueError("policy_sha256 must be SHA-256")
        payload = {
            "schema_version": "cct.standing_autonomy.action.v1",
            "authority": "host_adapter",
            "policy_sha256": policy_sha256,
            "action": action.public_payload(),
        }
        event, created = self.store.append_once_result(
            "standing.autonomy.action.registered", action.id, payload
        )
        if canonical_json(event.payload) != canonical_json(payload):
            raise ValueError("standing action changed under the same ID")
        return {**event.payload, "event_id": event.event_id, "created": created}


class StandingAutonomyRunner:
    """Select and execute registered local shell actions under standing authority."""

    def __init__(
        self,
        store: EventStore,
        *,
        policy: StandingAutonomyPolicy,
        projects: Sequence[OwnedProjectShell],
        actions: Sequence[StandingShellAction],
        authority_evidence: Sequence[str],
    ) -> None:
        if not projects or not actions:
            raise ValueError("standing runner requires projects and actions")
        self.store = store
        self.policy = policy
        self.actions = {action.id: action for action in actions}
        if len(self.actions) != len(actions):
            raise ValueError("standing action IDs must be unique")
        if len({action.verifier_id for action in actions}) != len(actions):
            raise ValueError("standing action verifier IDs must be unique")
        project_ids = {project.id for project in projects}
        if any(action.project_id not in project_ids for action in actions):
            raise ValueError("standing action references unknown project")
        if any(policy.resolve(action.action_class) == "per_operation" for action in actions):
            raise ValueError("per-operation actions cannot enter standing runner")
        if any(
            policy.resolve(action.action_class) == "earned" and action.required_tier < 4
            for action in actions
        ):
            raise ValueError("earned standing actions require tier 4 or higher")
        if any(action.expected_utility < policy.min_expected_utility for action in actions):
            raise ValueError("registered standing action is below utility threshold")
        if any(action.uncertainty > policy.max_uncertainty for action in actions):
            raise ValueError("registered standing action exceeds uncertainty threshold")

        latest_profile = self._latest("principal.profile.installed")
        if latest_profile is None:
            raise ValueError("principal profile must be installed before standing autonomy")
        profile = latest_profile.payload.get("profile", {})
        if profile.get("principal_id") != policy.principal_id:
            raise ValueError("standing policy principal does not match installed profile")
        self.profile_digest = str(latest_profile.payload.get("profile_digest"))
        if not _DIGEST.fullmatch(self.profile_digest):
            raise ValueError("installed principal profile digest is invalid")

        registry = StandingAutonomyRegistry(store)
        installed_policy = registry.install_policy(
            policy,
            authority="operator",
            evidence=authority_evidence,
        )
        self.policy_sha256 = str(installed_policy["policy_sha256"])
        for action in actions:
            registry.register_action(action, policy_sha256=self.policy_sha256)

        catalog = OperatorCapabilityCatalog(store).install()
        self.shell_spec_digest = str(catalog["shell"]["spec_digest"])
        self.capabilities = CapabilityRegistry(store)
        now = _timestamp("current time", self.store.clock()).astimezone(UTC)
        policy_expiry = _timestamp("policy expires_at", policy.expires_at).astimezone(UTC)
        next_day = now.date() + timedelta(days=1)
        daily_expiry = datetime.combine(next_day, time.min, tzinfo=UTC)
        lease_expiry = min(policy_expiry, daily_expiry)
        if lease_expiry <= now:
            raise ValueError("standing autonomy policy is expired")
        self.lease_expires_at = lease_expiry.isoformat()
        self.lease_id = (
            f"lease-{policy.id}-operator-shell-{now.strftime('%Y%m%d')}"
        )
        scopes = tuple(sorted(f"operator/shell/{project_id}" for project_id in project_ids))
        self.capabilities.grant(
            CapabilityLease(
                id=self.lease_id,
                capability="operator.shell",
                principal_id=policy.principal_id,
                scopes=scopes,
                expires_at=self.lease_expires_at,
                max_actions=policy.max_actions,
                max_bytes=policy.max_bytes,
                max_value_microunits=0,
                issued_by="host_adapter",
                evidence=(f"standing-policy:{self.policy_sha256}",),
            ),
            expected_principal_profile_digest=self.profile_digest,
        )
        verifier_map = {
            action.verifier_id: self._verifier_for(action)
            for action in actions
        }
        self.shell = OperatorShellAdapter(
            store,
            projects=tuple(projects),
            verifiers=verifier_map,
        )
        self.project_roots = {
            project.id: Path(project.root).resolve(strict=True) for project in projects
        }
        self.lock_path = store.path.parent / "standing-autonomy.lock"
        self.ticket_authority = ExecutionTicketAuthority(store)
        self.mediator = ToolExecutionMediator(
            store,
            frozenset({"operator_shell"}),
            outcome_verifiers=self.shell.outcome_verifiers(),
        )

    def _latest(self, kind: str) -> Event | None:
        rows = self.store.events(kind)
        return rows[-1] if rows else None

    @staticmethod
    def _verifier_for(action: StandingShellAction):
        def verifier(
            _root: Path,
            _request: ShellInvocation,
            observation: Any,
        ) -> ShellVerification:
            stdout_digest = sha256(observation.stdout).hexdigest()
            passed = (
                observation.termination_reason == "exited"
                and observation.exit_status == action.expected_exit_status
                and (
                    action.expected_stdout_sha256 is None
                    or stdout_digest == action.expected_stdout_sha256
                )
            )
            evidence = {
                "action_id": action.id,
                "exit_status": observation.exit_status,
                "termination_reason": observation.termination_reason,
                "stdout_sha256": stdout_digest,
                "stderr_sha256": sha256(observation.stderr).hexdigest(),
            }
            return ShellVerification(
                passed=passed,
                code="STANDING_ACTION_VERIFIED" if passed else "STANDING_ACTION_FAILED",
                evidence_sha256=_digest(evidence),
            )

        return verifier

    def current_tier(self) -> int:
        rows = self.store.events("standing.autonomy.tier.changed")
        if not rows:
            return self.policy.initial_tier
        value = rows[-1].payload.get("tier")
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("standing tier event is malformed")
        return value

    def _maybe_promote(self) -> int:
        completed = [
            event
            for event in self.store.events("standing.autonomy.run.completed")
            if event.payload.get("policy_sha256") == self.policy_sha256
        ]
        verified_runs = len(
            [event for event in completed if event.payload.get("verified") is True]
        )
        failed_runs = len(
            [event for event in completed if event.payload.get("verified") is not True]
        )
        current = self.current_tier()
        if failed_runs or GlobalKillSwitch(self.store).status()["active"]:
            return current
        earned_steps = verified_runs // self.policy.promotion_verified_runs
        target = min(
            self.policy.maximum_tier,
            self.policy.initial_tier + earned_steps,
        )
        if target <= current:
            return current
        payload = {
            "schema_version": "cct.standing_autonomy.tier.v1",
            "policy_id": self.policy.id,
            "policy_sha256": self.policy_sha256,
            "previous_tier": current,
            "tier": target,
            "verified_runs": verified_runs,
            "failed_runs": failed_runs,
            "automatic_within_operator_ceiling": True,
            "fresh_user_approval_required": False,
        }
        event, _created = self.store.append_once_result(
            "standing.autonomy.tier.changed",
            f"{self.policy.id}:{target}",
            payload,
        )
        if canonical_json(event.payload) != canonical_json(payload):
            raise ValueError("standing tier promotion changed under the same ID")
        return target

    @contextmanager
    def _run_lock(self) -> Iterator[None]:
        descriptor = os.open(
            self.lock_path,
            os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            metadata = os.fstat(descriptor)
            if not os.path.samestat(metadata, os.stat(self.lock_path, follow_symlinks=False)):
                raise RuntimeError("standing autonomy lock identity changed")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _trigger_sha256(self, action: StandingShellAction) -> str:
        if action.trigger_kind == "always":
            return _digest({"kind": "always", "action_id": action.id})
        project_root = self.project_roots[action.project_id]
        head = subprocess.run(
            ["/usr/bin/git", "-C", str(project_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={},
        ).stdout.strip()
        status = subprocess.run(
            ["/usr/bin/git", "-C", str(project_root), "status", "--porcelain=v1"],
            check=True,
            capture_output=True,
            timeout=30,
            env={},
        ).stdout
        return _digest(
            {
                "kind": "git_state",
                "head": head,
                "status_sha256": sha256(status).hexdigest(),
            }
        )

    def _already_completed(
        self, action_id: str, trigger_sha256: str, *, trigger_kind: TriggerKind
    ) -> Event | None:
        if trigger_kind == "always":
            return None
        return next(
            (
                event
                for event in reversed(self.store.events("standing.autonomy.run.completed"))
                if event.payload.get("action_id") == action_id
                and event.payload.get("trigger_sha256") == trigger_sha256
                and event.payload.get("verified") is True
            ),
            None,
        )

    def eligible_actions(self) -> tuple[StandingShellAction, ...]:
        tier = self.current_tier()
        rows = []
        for action in self.actions.values():
            policy_tier = self.policy.resolve(action.action_class)
            if policy_tier == "automatic" and action.required_tier <= tier:
                rows.append(action)
            elif policy_tier == "earned" and max(4, action.required_tier) <= tier:
                rows.append(action)
        return tuple(
            sorted(
                rows,
                key=lambda action: (
                    -(action.expected_utility - action.uncertainty),
                    action.id,
                ),
            )
        )

    def run_once(self, *, run_id: str, action_id: str | None = None) -> dict[str, Any]:
        with self._run_lock():
            return self._run_once_locked(run_id=run_id, action_id=action_id)

    def _run_once_locked(
        self, *, run_id: str, action_id: str | None = None
    ) -> dict[str, Any]:
        identifier = _identifier("run id", run_id)
        GlobalKillSwitch.ensure_clear(self.store.events())
        eligible = self.eligible_actions()
        selected: StandingShellAction | None = None
        trigger_sha256: str | None = None
        existing: Event | None = None
        if action_id is not None:
            chosen_id = _identifier("action id", action_id)
            selected = next((action for action in eligible if action.id == chosen_id), None)
            if selected is None:
                raise PermissionError("STANDING_ACTION_NOT_ELIGIBLE")
            trigger_sha256 = self._trigger_sha256(selected)
            existing = self._already_completed(
                selected.id,
                trigger_sha256,
                trigger_kind=selected.trigger_kind,
            )
        else:
            for candidate in eligible:
                candidate_trigger = self._trigger_sha256(candidate)
                candidate_existing = self._already_completed(
                    candidate.id,
                    candidate_trigger,
                    trigger_kind=candidate.trigger_kind,
                )
                if candidate_existing is None:
                    selected = candidate
                    trigger_sha256 = candidate_trigger
                    break
                existing = candidate_existing
        if selected is None:
            return {
                "status": "NO_OP",
                "reason": (
                    "UNCHANGED_TRIGGERS" if eligible else "NO_ELIGIBLE_STANDING_ACTION"
                ),
                "completion_event_id": existing.event_id if existing is not None else None,
                "external_effects": 0,
            }
        if trigger_sha256 is None:
            raise RuntimeError("standing action trigger missing")
        if existing is not None and action_id is not None:
            return {
                "status": "NO_OP",
                "reason": "UNCHANGED_TRIGGER",
                "action_id": selected.id,
                "trigger_sha256": trigger_sha256,
                "completion_event_id": existing.event_id,
                "external_effects": 0,
            }

        ticket_id = f"ticket-{identifier}"
        arguments = {
            "execution_ticket_id": ticket_id,
            "project_id": selected.project_id,
            "cwd": selected.cwd,
            "argv": list(selected.argv),
            "verifier_id": selected.verifier_id,
            "timeout_ms": selected.timeout_ms,
            "max_stdout_bytes": selected.max_stdout_bytes,
            "max_stderr_bytes": selected.max_stderr_bytes,
        }
        plan = {
            "policy_sha256": self.policy_sha256,
            "action_id": selected.id,
            "action_sha256": _digest(selected.public_payload()),
            "trigger_sha256": trigger_sha256,
        }
        ticket = ExecutionTicket(
            id=ticket_id,
            tool_name="operator_shell",
            arguments_sha256=_digest(arguments),
            goal_id="goal-cct-autonomous-local-work",
            plan_id=f"plan-{identifier}",
            plan_hash=_digest(plan),
            stage="execute-standing-action",
            attempt=1,
            principal_id=self.policy.principal_id,
            principal_profile_digest=self.profile_digest,
            capability="operator.shell",
            capability_spec_digest=self.shell_spec_digest,
            lease_id=self.lease_id,
            scope=f"operator/shell/{selected.project_id}",
            expires_at=self.lease_expires_at,
            action_budget=1,
            byte_budget=selected.max_stdout_bytes + selected.max_stderr_bytes,
            value_budget_microunits=0,
        )
        selected_payload = {
            "schema_version": "cct.standing_autonomy.selection.v1",
            "run_id": identifier,
            "action_id": selected.id,
            "action_class": selected.action_class,
            "policy_tier": self.policy.resolve(selected.action_class),
            "current_tier": self.current_tier(),
            "expected_utility": selected.expected_utility,
            "uncertainty": selected.uncertainty,
            "reversible": True,
            "trigger_sha256": trigger_sha256,
            "plan_hash": ticket.plan_hash,
            "fresh_user_approval_required": False,
            "standing_policy_sha256": self.policy_sha256,
        }
        selection, created = self.store.append_once_result(
            "standing.autonomy.run.selected", identifier, selected_payload
        )
        if canonical_json(selection.payload) != canonical_json(selected_payload):
            raise ValueError("standing run selection changed under the same ID")
        self.ticket_authority.issue(
            ticket,
            authority="host_adapter",
            evidence=(
                f"standing-policy:{self.policy_sha256}",
                f"selection-event:{selection.event_id}",
            ),
        )

        result = self.mediator(
            tool_name="operator_shell",
            args=arguments,
            original_args=arguments,
            next_call=lambda: self.shell.execute(arguments),
        )
        parsed = json.loads(result) if isinstance(result, str) else result
        if not isinstance(parsed, dict):
            raise RuntimeError("standing action returned malformed result")
        verified = parsed.get("success") is True and parsed.get("verification", {}).get("passed") is True
        completion_payload = {
            "schema_version": "cct.standing_autonomy.completion.v1",
            "run_id": identifier,
            "selection_event_id": selection.event_id,
            "policy_sha256": self.policy_sha256,
            "action_id": selected.id,
            "action_class": selected.action_class,
            "trigger_sha256": trigger_sha256,
            "ticket_id": ticket_id,
            "verified": verified,
            "effect_event_id": parsed.get("effect", {}).get("receipt_event_id"),
            "verification_code": parsed.get("verification", {}).get("code"),
            "stdout_sha256": parsed.get("shell", {}).get("stdout_sha256"),
            "stderr_sha256": parsed.get("shell", {}).get("stderr_sha256"),
            "raw_output_persisted": False,
            "fresh_user_approval_required": False,
        }
        completion, completion_created = self.store.append_once_result(
            "standing.autonomy.run.completed", identifier, completion_payload
        )
        if canonical_json(completion.payload) != canonical_json(completion_payload):
            raise ValueError("standing completion changed under the same ID")
        if not verified:
            GlobalKillSwitch(self.store).trip(
                trip_id=f"standing-failure-{identifier}",
                authority="host_adapter",
                reason="standing autonomy verifier failed",
            )
        current_tier = self._maybe_promote() if verified else self.current_tier()
        return {
            "status": "VERIFIED" if verified else "FAILED",
            "run_id": identifier,
            "action_id": selected.id,
            "trigger_sha256": trigger_sha256,
            "ticket_id": ticket_id,
            "selection_event_id": selection.event_id,
            "completion_event_id": completion.event_id,
            "idempotent": not (created and completion_created),
            "fresh_user_approval_required": False,
            "current_tier": current_tier,
            "external_effects": 0,
        }

    def status(self) -> dict[str, Any]:
        completed = [
            event
            for event in self.store.events("standing.autonomy.run.completed")
            if event.payload.get("policy_sha256") == self.policy_sha256
        ]
        verified = [event for event in completed if event.payload.get("verified") is True]
        failed = [event for event in completed if event.payload.get("verified") is not True]
        return {
            "policy": self.policy.as_payload(),
            "policy_sha256": self.policy_sha256,
            "current_tier": self.current_tier(),
            "eligible_action_ids": [action.id for action in self.eligible_actions()],
            "registered_actions": {
                action.id: action.public_payload() for action in sorted(self.actions.values(), key=lambda row: row.id)
            },
            "verified_runs": len(verified),
            "failed_runs": len(failed),
            "lease_id": self.lease_id,
            "lease": self.capabilities.status()["leases"][self.lease_id],
            "kill_switch": GlobalKillSwitch(self.store).status(),
            "self_grant_enabled": False,
            "raw_operator_message_persisted": False,
        }
