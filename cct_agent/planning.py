"""Bounded goal approval, deliberative choice, and durable private planning."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
from math import isfinite
import os
from pathlib import Path
import re
import stat
from typing import Any, Literal, Mapping, Sequence
from uuid import uuid4

from .kernel import AgencyKernel, NO_OP_ID, canonical_no_op
from .models import Goal, Option, options_from_dicts
from .principal import PrincipalProfile
from .store import GENESIS_HASH, Event, EventStore, canonical_json


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
StageKind = Literal["atomic", "group"]


class PlanningDenied(RuntimeError):
    """A fail-closed planning or cursor admission decision."""

    def __init__(self, reason_code: str, message: str | None = None) -> None:
        self.reason_code = reason_code
        super().__init__(message or reason_code)


def _identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{name} must be a bounded identifier")
    return value.strip()


def _text(name: str, value: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    cleaned = value.strip()
    if (
        not cleaned
        or len(cleaned) > maximum
        or any(ord(character) < 32 for character in cleaned)
    ):
        raise ValueError(f"{name} must be 1-{maximum} printable characters")
    return cleaned


def _unit(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    numeric = float(value)
    if not isfinite(numeric) or not 0.0 <= numeric <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")
    return numeric


def _sha256(name: str, value: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _events_chain_valid(events: Sequence[Event]) -> bool:
    previous = GENESIS_HASH
    for expected_seq, event in enumerate(events, start=1):
        if event.seq != expected_seq or event.previous_hash != previous:
            return False
        calculated = EventStore._digest(
            seq=event.seq,
            event_id=event.event_id,
            occurred_at=event.occurred_at,
            kind=event.kind,
            payload=event.payload,
            previous_hash=event.previous_hash,
        )
        if calculated != event.event_hash:
            return False
        previous = event.event_hash
    return True


def _string_tuple(name: str, values: Sequence[str], *, maximum: int = 32) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or len(values) > maximum:
        raise ValueError(f"{name} must be a bounded array")
    return tuple(_text(name, value, maximum=600) for value in values)


@dataclass(frozen=True, slots=True)
class ApprovedGoal:
    id: str
    statement: str
    rationale: str
    source: str
    horizon: str
    alignment: Mapping[str, float]
    approved_by: str
    approved_origin: str
    approval_evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("goal id", self.id))
        object.__setattr__(
            self, "statement", _text("goal statement", self.statement, maximum=1200)
        )
        object.__setattr__(
            self, "rationale", _text("goal rationale", self.rationale, maximum=1600)
        )
        object.__setattr__(self, "horizon", _identifier("goal horizon", self.horizon))
        if not isinstance(self.source, str):
            raise ValueError("source must be external or joint")
        normalized: dict[str, float] = {}
        if not self.alignment or len(self.alignment) > 32:
            raise ValueError("goal alignment must be a bounded non-empty object")
        for name, value in self.alignment.items():
            key = _identifier("goal alignment value", str(name))
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("goal alignment values must be numeric")
            numeric = float(value)
            if not isfinite(numeric) or not -1.0 <= numeric <= 1.0:
                raise ValueError("goal alignment values must be between -1 and 1")
            normalized[key] = numeric
        object.__setattr__(self, "alignment", normalized)
        object.__setattr__(
            self, "approved_by", _identifier("goal approver", self.approved_by)
        )
        if self.approved_by != "operator":
            raise ValueError("approved_by must be operator")
        object.__setattr__(
            self,
            "approved_origin",
            _text("goal approval origin", self.approved_origin, maximum=300),
        )
        if not self.approved_origin.startswith("operator:"):
            raise ValueError("approved_origin must identify an operator receipt")
        evidence = _string_tuple("goal approval evidence", self.approval_evidence)
        if not evidence:
            raise ValueError("goal approval evidence must not be empty")
        object.__setattr__(self, "approval_evidence", evidence)


@dataclass(frozen=True, slots=True)
class LeasedSelfGoal:
    """One self-originated goal admitted by an exact host-policy capability lease."""

    id: str
    statement: str
    rationale: str
    horizon: str
    alignment: Mapping[str, float]
    policy_id: str
    candidate_id: str
    candidate_event_id: str
    portfolio_decision_event_id: str
    lease_id: str
    lease_event_id: str
    capability_spec_digest: str
    receipt_event_ids: tuple[str, ...]
    scope: str
    expires_at: str
    max_actions: int
    max_bytes: int
    max_value_microunits: int = 0

    def __post_init__(self) -> None:
        for field_name in (
            "id",
            "policy_id",
            "candidate_id",
            "candidate_event_id",
            "portfolio_decision_event_id",
            "lease_id",
            "lease_event_id",
        ):
            object.__setattr__(
                self, field_name, _identifier(field_name, getattr(self, field_name))
            )
        object.__setattr__(
            self, "statement", _text("goal statement", self.statement, maximum=1200)
        )
        object.__setattr__(
            self, "rationale", _text("goal rationale", self.rationale, maximum=1600)
        )
        object.__setattr__(self, "horizon", _identifier("goal horizon", self.horizon))
        object.__setattr__(
            self,
            "capability_spec_digest",
            _sha256("capability_spec_digest", self.capability_spec_digest),
        )
        receipts = tuple(
            _identifier("receipt event id", event_id)
            for event_id in self.receipt_event_ids
        )
        if len(receipts) < 4 or len(receipts) > 16 or len(receipts) != len(set(receipts)):
            raise ValueError("self goal requires 4-16 unique input receipt events")
        object.__setattr__(self, "receipt_event_ids", receipts)
        object.__setattr__(self, "scope", _text("goal lease scope", self.scope, maximum=512))
        try:
            expires = datetime.fromisoformat(self.expires_at)
        except (TypeError, ValueError) as error:
            raise ValueError("goal lease expiry must be ISO-8601") from error
        if expires.tzinfo is None:
            raise ValueError("goal lease expiry must include a timezone")
        if (
            isinstance(self.max_actions, bool)
            or not isinstance(self.max_actions, int)
            or self.max_actions < 1
            or isinstance(self.max_bytes, bool)
            or not isinstance(self.max_bytes, int)
            or self.max_bytes < 0
            or isinstance(self.max_value_microunits, bool)
            or not isinstance(self.max_value_microunits, int)
            or self.max_value_microunits != 0
        ):
            raise ValueError("self goal lease budgets must be bounded non-financial integers")
        normalized: dict[str, float] = {}
        if not self.alignment or len(self.alignment) > 32:
            raise ValueError("self goal alignment must be a bounded non-empty object")
        for name, value in self.alignment.items():
            key = _identifier("self goal alignment value", str(name))
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("self goal alignment values must be numeric")
            numeric = float(value)
            if not isfinite(numeric) or not -1.0 <= numeric <= 1.0:
                raise ValueError("self goal alignment values must be between -1 and 1")
            normalized[key] = numeric
        object.__setattr__(self, "alignment", normalized)


@dataclass(frozen=True, slots=True)
class DecisionAlternative:
    id: str
    summary: str
    predicted_outcome: str
    value_impacts: Mapping[str, float]
    information_gain: float = 0.0
    uncertainty: float = 0.0
    time_cost: float = 0.0
    irreversible: bool = False
    blocked_reasons: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("alternative id", self.id))
        object.__setattr__(
            self, "summary", _text("alternative summary", self.summary, maximum=800)
        )
        object.__setattr__(
            self,
            "predicted_outcome",
            _text("predicted outcome", self.predicted_outcome, maximum=1200),
        )
        impacts: dict[str, float] = {}
        if len(self.value_impacts) > 32:
            raise ValueError("alternative value impacts must be bounded")
        for name, value in self.value_impacts.items():
            key = _identifier("alternative value", str(name))
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("alternative value impacts must be numeric")
            numeric = float(value)
            if not isfinite(numeric) or not -1.0 <= numeric <= 1.0:
                raise ValueError("alternative value impacts must be between -1 and 1")
            impacts[key] = numeric
        object.__setattr__(self, "value_impacts", impacts)
        object.__setattr__(
            self, "information_gain", _unit("information_gain", self.information_gain)
        )
        object.__setattr__(self, "uncertainty", _unit("uncertainty", self.uncertainty))
        if isinstance(self.time_cost, bool) or not isinstance(
            self.time_cost, (int, float)
        ):
            raise ValueError("time_cost must be numeric")
        time_cost = float(self.time_cost)
        if not isfinite(time_cost) or time_cost < 0.0:
            raise ValueError("time_cost must be finite and non-negative")
        object.__setattr__(self, "time_cost", time_cost)
        if not isinstance(self.irreversible, bool):
            raise ValueError("irreversible must be boolean")
        object.__setattr__(
            self,
            "blocked_reasons",
            _string_tuple("blocked reason", self.blocked_reasons),
        )
        object.__setattr__(
            self, "assumptions", _string_tuple("assumption", self.assumptions)
        )

    def semantic_payload(self) -> dict[str, Any]:
        """Return branch meaning; the caller-assigned identifier is not semantic."""

        return {
            "summary": self.summary,
            "predicted_outcome": self.predicted_outcome,
            "value_impacts": dict(self.value_impacts),
            "information_gain": self.information_gain,
            "uncertainty": self.uncertainty,
            "time_cost": self.time_cost,
            "irreversible": self.irreversible,
            "blocked_reasons": list(self.blocked_reasons),
            "assumptions": list(self.assumptions),
        }

    def receipt_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            **self.semantic_payload(),
            "predicted_outcome_sha256": sha256(
                self.predicted_outcome.encode("utf-8")
            ).hexdigest(),
        }

    def as_option(self) -> Option:
        return Option(
            id=self.id,
            description=self.summary,
            value_impacts=self.value_impacts,
            information_gain=self.information_gain,
            uncertainty=self.uncertainty,
            time_cost=self.time_cost,
            irreversible=self.irreversible,
            blocked_reasons=self.blocked_reasons,
            assumptions=self.assumptions,
        )


@dataclass(frozen=True, slots=True)
class StageHandoff:
    capability: str
    tool_name: str
    scope: str
    arguments_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "capability", _identifier("handoff capability", self.capability)
        )
        object.__setattr__(self, "tool_name", _identifier("handoff tool", self.tool_name))
        object.__setattr__(
            self, "scope", _text("handoff scope", self.scope, maximum=600)
        )
        object.__setattr__(
            self,
            "arguments_sha256",
            _sha256("handoff arguments_sha256", self.arguments_sha256),
        )

    def as_payload(self) -> dict[str, str]:
        return {
            "capability": self.capability,
            "tool_name": self.tool_name,
            "scope": self.scope,
            "arguments_sha256": self.arguments_sha256,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> StageHandoff:
        return cls(
            capability=str(payload["capability"]),
            tool_name=str(payload["tool_name"]),
            scope=str(payload["scope"]),
            arguments_sha256=str(payload["arguments_sha256"]),
        )


@dataclass(frozen=True, slots=True)
class PlanStage:
    id: str
    summary: str
    kind: StageKind = "atomic"
    parent_id: str | None = None
    depends_on: tuple[str, ...] = ()
    handoff: StageHandoff | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("stage id", self.id))
        object.__setattr__(
            self, "summary", _text("stage summary", self.summary, maximum=800)
        )
        if self.kind not in {"atomic", "group"}:
            raise ValueError("stage kind must be atomic or group")
        if self.parent_id is not None:
            object.__setattr__(
                self, "parent_id", _identifier("stage parent id", self.parent_id)
            )
        dependencies = tuple(
            _identifier("stage dependency", dependency) for dependency in self.depends_on
        )
        if len(dependencies) > 64 or len(dependencies) != len(set(dependencies)):
            raise ValueError("stage dependencies must be bounded and unique")
        object.__setattr__(self, "depends_on", dependencies)

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "summary": self.summary,
            "kind": self.kind,
            "parent_id": self.parent_id,
            "depends_on": list(self.depends_on),
            "handoff": self.handoff.as_payload() if self.handoff else None,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> PlanStage:
        raw_handoff = payload.get("handoff")
        if raw_handoff is not None and not isinstance(raw_handoff, Mapping):
            raise ValueError("stage handoff must be an object")
        raw_dependencies = payload.get("depends_on", [])
        if not isinstance(raw_dependencies, list):
            raise ValueError("stage depends_on must be an array")
        return cls(
            id=str(payload["id"]),
            summary=str(payload["summary"]),
            kind=str(payload.get("kind", "atomic")),  # type: ignore[arg-type]
            parent_id=(
                str(payload["parent_id"])
                if payload.get("parent_id") is not None
                else None
            ),
            depends_on=tuple(str(value) for value in raw_dependencies),
            handoff=(StageHandoff.from_payload(raw_handoff) if raw_handoff else None),
        )


@dataclass(frozen=True, slots=True)
class HierarchicalPlan:
    id: str
    goal_id: str
    decision_id: str
    chosen_option_id: str
    summary: str
    stages: tuple[PlanStage, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("plan id", self.id))
        object.__setattr__(self, "goal_id", _identifier("plan goal id", self.goal_id))
        object.__setattr__(
            self, "decision_id", _identifier("plan decision id", self.decision_id)
        )
        object.__setattr__(
            self,
            "chosen_option_id",
            _identifier("plan chosen option id", self.chosen_option_id),
        )
        object.__setattr__(
            self, "summary", _text("plan summary", self.summary, maximum=1200)
        )
        if not self.stages or len(self.stages) > 128:
            raise ValueError("plan stages must be a bounded non-empty array")
        object.__setattr__(self, "stages", tuple(self.stages))

    def semantic_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "goal_id": self.goal_id,
            "decision_id": self.decision_id,
            "chosen_option_id": self.chosen_option_id,
            "summary": self.summary,
            "stages": [stage.as_payload() for stage in self.stages],
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> HierarchicalPlan:
        rows = payload.get("stages")
        if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
            raise ValueError("plan stages must be an array of objects")
        return cls(
            id=str(payload["id"]),
            goal_id=str(payload["goal_id"]),
            decision_id=str(payload["decision_id"]),
            chosen_option_id=str(payload["chosen_option_id"]),
            summary=str(payload["summary"]),
            stages=tuple(PlanStage.from_payload(row) for row in rows),
        )


@dataclass(frozen=True, slots=True)
class PlanBinding:
    plan_id: str
    goal_id: str
    decision_id: str
    plan_sha256: str
    constitution_fingerprint: str
    principal_id: str
    principal_profile_digest: str
    principal_profile_revision: int

    def __post_init__(self) -> None:
        for field_name in ("plan_id", "goal_id", "decision_id", "principal_id"):
            object.__setattr__(
                self, field_name, _identifier(field_name, getattr(self, field_name))
            )
        object.__setattr__(
            self, "plan_sha256", _sha256("plan_sha256", self.plan_sha256)
        )
        object.__setattr__(
            self,
            "constitution_fingerprint",
            _sha256("constitution_fingerprint", self.constitution_fingerprint),
        )
        object.__setattr__(
            self,
            "principal_profile_digest",
            _sha256("principal_profile_digest", self.principal_profile_digest),
        )
        if (
            isinstance(self.principal_profile_revision, bool)
            or not isinstance(self.principal_profile_revision, int)
            or self.principal_profile_revision < 1
        ):
            raise ValueError("principal_profile_revision must be a positive integer")

    def as_payload(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "goal_id": self.goal_id,
            "decision_id": self.decision_id,
            "plan_sha256": self.plan_sha256,
            "constitution_fingerprint": self.constitution_fingerprint,
            "principal_id": self.principal_id,
            "principal_profile_digest": self.principal_profile_digest,
            "principal_profile_revision": self.principal_profile_revision,
        }


@dataclass(frozen=True, slots=True)
class WorkerClaimRequest:
    binding: PlanBinding
    worker_id: str
    expected_revision: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_id", _identifier("worker id", self.worker_id))
        if (
            isinstance(self.expected_revision, bool)
            or not isinstance(self.expected_revision, int)
            or self.expected_revision < 0
        ):
            raise ValueError("expected_revision must be a non-negative integer")

    def as_payload(self) -> dict[str, Any]:
        return {
            "binding": self.binding.as_payload(),
            "worker_id": self.worker_id,
            "expected_revision": self.expected_revision,
        }


@dataclass(frozen=True, slots=True)
class WorkerAdvanceRequest:
    binding: PlanBinding
    worker_id: str
    stage_id: str
    attempt: int
    claim_event_id: str
    expected_revision: int
    outcome_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_id", _identifier("worker id", self.worker_id))
        object.__setattr__(self, "stage_id", _identifier("stage id", self.stage_id))
        object.__setattr__(
            self, "claim_event_id", _identifier("claim event id", self.claim_event_id)
        )
        if isinstance(self.attempt, bool) or not isinstance(self.attempt, int) or self.attempt < 1:
            raise ValueError("attempt must be a positive integer")
        if (
            isinstance(self.expected_revision, bool)
            or not isinstance(self.expected_revision, int)
            or self.expected_revision < 0
        ):
            raise ValueError("expected_revision must be a non-negative integer")
        object.__setattr__(
            self, "outcome_sha256", _sha256("outcome_sha256", self.outcome_sha256)
        )

    def as_payload(self) -> dict[str, Any]:
        return {
            "binding": self.binding.as_payload(),
            "worker_id": self.worker_id,
            "stage_id": self.stage_id,
            "attempt": self.attempt,
            "claim_event_id": self.claim_event_id,
            "expected_revision": self.expected_revision,
            "outcome_sha256": self.outcome_sha256,
        }


class AutonomyPlanner:
    """Plan through the kernel while keeping executable detail off the event ledger."""

    def __init__(
        self, store: EventStore, kernel: AgencyKernel, private_root: str | Path
    ) -> None:
        self.store = store
        self.kernel = kernel
        self.private_root = Path(private_root)
        self._prepare_private_root()

    def _prepare_private_root(self) -> None:
        if os.path.lexists(self.private_root):
            root_stat = self.private_root.lstat()
            if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
                raise ValueError("private planning root must be a real directory")
            if root_stat.st_uid != os.getuid():
                raise ValueError("private planning root must be owned by current user")
        else:
            self.private_root.mkdir(mode=0o700, parents=True)
        os.chmod(self.private_root, 0o700)
        plans = self.private_root / "plans"
        if os.path.lexists(plans):
            plans_stat = plans.lstat()
            if not stat.S_ISDIR(plans_stat.st_mode) or stat.S_ISLNK(plans_stat.st_mode):
                raise ValueError("private plans path must be a real directory")
            if plans_stat.st_uid != os.getuid():
                raise ValueError("private plans path must be owned by current user")
        else:
            plans.mkdir(mode=0o700)
        os.chmod(plans, 0o700)

    def _private_permissions_valid(self, plan_path: Path | None = None) -> bool:
        try:
            for directory in (self.private_root, self.private_root / "plans"):
                descriptor = directory.lstat()
                if (
                    not stat.S_ISDIR(descriptor.st_mode)
                    or stat.S_ISLNK(descriptor.st_mode)
                    or stat.S_IMODE(descriptor.st_mode) != 0o700
                    or descriptor.st_uid != os.getuid()
                ):
                    return False
            if plan_path is not None:
                descriptor = plan_path.lstat()
                if (
                    not stat.S_ISREG(descriptor.st_mode)
                    or stat.S_ISLNK(descriptor.st_mode)
                    or stat.S_IMODE(descriptor.st_mode) != 0o600
                    or descriptor.st_uid != os.getuid()
                    or descriptor.st_nlink != 1
                ):
                    return False
        except OSError:
            return False
        return True

    def _self_authorization_reason(
        self,
        events: Sequence[Event],
        authorization: object,
        *,
        goal_id: str,
    ) -> str | None:
        required = {
            "policy_id",
            "candidate_id",
            "candidate_event_id",
            "candidate_sha256",
            "portfolio_decision_event_id",
            "lease_id",
            "lease_event_id",
            "lease_sha256",
            "capability_spec_digest",
            "receipt_event_ids",
            "scope",
            "expires_at",
            "max_actions",
            "max_bytes",
            "max_value_microunits",
            "risk_class",
            "reversible",
        }
        if not isinstance(authorization, Mapping) or set(authorization) != required:
            return "SELF_AUTHORIZATION_MALFORMED"
        try:
            for name in (
                "policy_id",
                "candidate_id",
                "candidate_event_id",
                "portfolio_decision_event_id",
                "lease_id",
                "lease_event_id",
            ):
                _identifier(name, str(authorization[name]))
            for name in (
                "candidate_sha256",
                "lease_sha256",
                "capability_spec_digest",
            ):
                _sha256(name, str(authorization[name]))
            expires = datetime.fromisoformat(str(authorization["expires_at"]))
            now = datetime.fromisoformat(self.store.clock())
        except (TypeError, ValueError):
            return "SELF_AUTHORIZATION_MALFORMED"
        if expires.tzinfo is None or now.tzinfo is None or expires <= now:
            return "SELF_GOAL_LEASE_EXPIRED"
        if (
            authorization.get("risk_class") != "reversible"
            or authorization.get("reversible") is not True
            or isinstance(authorization.get("max_actions"), bool)
            or not isinstance(authorization.get("max_actions"), int)
            or int(authorization["max_actions"]) < 1
            or isinstance(authorization.get("max_bytes"), bool)
            or not isinstance(authorization.get("max_bytes"), int)
            or int(authorization["max_bytes"]) < 0
            or authorization.get("max_value_microunits") != 0
        ):
            return "SELF_GOAL_RISK_OR_BUDGET_DENIED"

        receipt_ids = authorization.get("receipt_event_ids")
        if (
            not isinstance(receipt_ids, list)
            or len(receipt_ids) < 4
            or len(receipt_ids) > 16
            or len(receipt_ids) != len(set(receipt_ids))
            or any(not isinstance(event_id, str) for event_id in receipt_ids)
        ):
            return "SELF_GOAL_RECEIPTS_INVALID"
        receipt_events = [event for event in events if event.event_id in receipt_ids]
        if len(receipt_events) != len(receipt_ids):
            return "SELF_GOAL_RECEIPTS_INVALID"
        receipt_kinds: set[str] = set()
        for event in receipt_events:
            payload = event.payload
            receipt_kinds.add(str(payload.get("kind", "")))
            if (
                event.kind != "autonomy.self_goal.input.recorded"
                or payload.get("schema_version") != 1
                or payload.get("authenticated") is not True
                or payload.get("semantic_taint") is not False
                or payload.get("raw_content_persisted") is not False
                or payload.get("instructions_authorized") is not False
                or not isinstance(payload.get("content_sha256"), str)
                or not _SHA256.fullmatch(str(payload["content_sha256"]))
            ):
                return "SELF_GOAL_RECEIPTS_INVALID"
        if receipt_kinds != {"observation", "value", "commitment", "opportunity"}:
            return "SELF_GOAL_RECEIPTS_INCOMPLETE"

        candidate_rows = [
            event
            for event in events
            if event.event_id == authorization["candidate_event_id"]
            and event.kind == "autonomy.self_goal.candidate.registered"
        ]
        if len(candidate_rows) != 1:
            return "SELF_GOAL_CANDIDATE_INVALID"
        candidate = candidate_rows[0].payload
        if (
            candidate.get("candidate_id") != authorization["candidate_id"]
            or candidate.get("candidate_sha256") != authorization["candidate_sha256"]
            or candidate.get("required_receipt_event_ids") != receipt_ids
            or candidate.get("derivation") != "host_template"
            or candidate.get("producer_text_used") is not False
            or candidate.get("semantic_taint") is not False
            or candidate.get("risk_class") != "reversible"
            or candidate.get("reversible") is not True
            or candidate.get("scope") != authorization["scope"]
            or candidate.get("max_actions") != authorization["max_actions"]
            or candidate.get("max_bytes") != authorization["max_bytes"]
            or candidate.get("max_value_microunits") != 0
        ):
            return "SELF_GOAL_CANDIDATE_INVALID"

        portfolio_rows = [
            event
            for event in events
            if event.event_id == authorization["portfolio_decision_event_id"]
            and event.kind == "decision.made"
        ]
        if len(portfolio_rows) != 1 or (
            portfolio_rows[0].payload.get("chosen_option_id")
            != authorization["candidate_id"]
        ):
            return "SELF_GOAL_PORTFOLIO_BINDING_INVALID"

        lease_rows = [
            event
            for event in events
            if event.event_id == authorization["lease_event_id"]
            and event.kind == "capability.lease.granted"
        ]
        if len(lease_rows) != 1:
            return "SELF_GOAL_LEASE_INVALID"
        lease_event = lease_rows[0]
        lease = lease_event.payload.get("lease")
        if not isinstance(lease, Mapping) or (
            lease.get("id") != authorization["lease_id"]
            or lease.get("issued_by") != "host_adapter"
            or lease.get("scopes") != [authorization["scope"]]
            or lease.get("expires_at") != authorization["expires_at"]
            or lease.get("max_actions") != authorization["max_actions"]
            or lease.get("max_bytes") != authorization["max_bytes"]
            or lease.get("max_value_microunits") != 0
            or lease.get("evidence")
            != [
                *(f"event:{event_id}" for event_id in receipt_ids),
                f"event:{authorization['candidate_event_id']}",
                f"event:{authorization['portfolio_decision_event_id']}",
            ]
            or _digest(dict(lease)) != authorization["lease_sha256"]
            or lease_event.payload.get("spec_digest")
            != authorization["capability_spec_digest"]
        ):
            return "SELF_GOAL_LEASE_INVALID"
        if any(
            event.kind == "capability.lease.revoked"
            and event.payload.get("lease_id") == authorization["lease_id"]
            for event in events
        ):
            return "SELF_GOAL_LEASE_REVOKED"

        spec_rows = [
            event
            for event in events
            if event.kind == "capability.spec.registered"
            and event.payload.get("spec_digest")
            == authorization["capability_spec_digest"]
        ]
        if len(spec_rows) != 1:
            return "SELF_GOAL_CAPABILITY_INVALID"
        spec = spec_rows[0].payload.get("spec")
        principal = self._principal_snapshot(events)
        if not isinstance(spec, Mapping) or principal is None or (
            spec.get("name") != lease.get("capability")
            or spec.get("risk_class") != "reversible"
            or spec.get("reversible") is not True
            or spec.get("active") is not True
            or not isinstance(spec.get("scopes"), list)
            or authorization["scope"] not in spec["scopes"]
            or lease.get("principal_id") != principal["principal_id"]
            or isinstance(spec.get("max_actions"), bool)
            or not isinstance(spec.get("max_actions"), int)
            or isinstance(spec.get("max_bytes"), bool)
            or not isinstance(spec.get("max_bytes"), int)
            or isinstance(spec.get("max_value_microunits"), bool)
            or not isinstance(spec.get("max_value_microunits"), int)
            or authorization["max_actions"] > spec["max_actions"]
            or authorization["max_bytes"] > spec["max_bytes"]
            or spec["max_value_microunits"] != 0
        ):
            return "SELF_GOAL_CAPABILITY_INVALID"
        return None

    def adopt_self_goal(self, proposed: LeasedSelfGoal) -> dict[str, Any]:
        """Admit one self goal only through immutable metadata receipts and a live lease."""

        events = self.store.events()
        if not _events_chain_valid(events):
            raise PlanningDenied("LEDGER_CHAIN_INVALID")
        unknown = sorted(set(proposed.alignment) - set(self.kernel.constitution.weights))
        if unknown:
            raise ValueError(f"goal references unknown values: {', '.join(unknown)}")
        alignment_score = round(
            sum(
                self.kernel.constitution.weights[name] * impact
                for name, impact in proposed.alignment.items()
            ),
            12,
        )
        if alignment_score <= 0.0:
            raise ValueError("goal must have positive endorsed-value alignment")
        candidate = next(
            (
                event
                for event in events
                if event.event_id == proposed.candidate_event_id
            ),
            None,
        )
        lease = next(
            (event for event in events if event.event_id == proposed.lease_event_id),
            None,
        )
        if candidate is None or lease is None or not isinstance(lease.payload.get("lease"), Mapping):
            raise PlanningDenied("SELF_AUTHORIZATION_MALFORMED")
        authorization = {
            "policy_id": proposed.policy_id,
            "candidate_id": proposed.candidate_id,
            "candidate_event_id": proposed.candidate_event_id,
            "candidate_sha256": candidate.payload.get("candidate_sha256"),
            "portfolio_decision_event_id": proposed.portfolio_decision_event_id,
            "lease_id": proposed.lease_id,
            "lease_event_id": proposed.lease_event_id,
            "lease_sha256": _digest(dict(lease.payload["lease"])),
            "capability_spec_digest": proposed.capability_spec_digest,
            "receipt_event_ids": list(proposed.receipt_event_ids),
            "scope": proposed.scope,
            "expires_at": proposed.expires_at,
            "max_actions": proposed.max_actions,
            "max_bytes": proposed.max_bytes,
            "max_value_microunits": proposed.max_value_microunits,
            "risk_class": "reversible",
            "reversible": True,
        }
        reason = self._self_authorization_reason(events, authorization, goal_id=proposed.id)
        if reason is not None:
            raise PlanningDenied(reason)
        evidence = list(proposed.receipt_event_ids)
        goal_payload = {
            "goal": {
                "id": proposed.id,
                "statement": proposed.statement,
                "rationale": proposed.rationale,
                "source": "self",
                "horizon": proposed.horizon,
                "alignment": dict(proposed.alignment),
                "evidence": evidence,
                "status": "active",
            },
            "alignment_score": alignment_score,
            "constitution_fingerprint": self.kernel.constitution_fingerprint(),
        }
        try:
            goal_event, _ = self.store.append_once_result(
                "goal.formed", proposed.id, goal_payload
            )
        except ValueError as error:
            raise PlanningDenied("GOAL_APPROVAL_CONFLICT") from error
        if canonical_json(goal_event.payload) != canonical_json(goal_payload):
            raise PlanningDenied("GOAL_APPROVAL_CONFLICT")
        payload = {
            "schema_version": 2,
            "goal_id": proposed.id,
            "source": "self",
            "approved_by": "host_policy",
            "approved_origin": f"host-policy:{proposed.policy_id}",
            "approval_evidence": evidence,
            "goal_event_id": goal_event.event_id,
            "goal_sha256": _digest(goal_event.payload["goal"]),
            "alignment_score": alignment_score,
            "constitution_fingerprint": self.kernel.constitution_fingerprint(),
            "approval_grants_execution_authority": False,
            "self_authorization": authorization,
        }
        try:
            event, created = self.store.append_once_result(
                "autonomy.goal.approved", proposed.id, payload
            )
        except ValueError as error:
            raise PlanningDenied("GOAL_APPROVAL_CONFLICT") from error
        if canonical_json(event.payload) != canonical_json(payload):
            raise PlanningDenied("GOAL_APPROVAL_CONFLICT")
        return {**event.payload, "event_id": event.event_id, "created": created}

    def approve_goal(self, approved: ApprovedGoal) -> dict[str, Any]:
        if not _events_chain_valid(self.store.events()):
            raise PlanningDenied("LEDGER_CHAIN_INVALID")
        if approved.source not in {"external", "joint"}:
            raise ValueError("source must be external or joint")
        if approved.approved_by != "operator":
            raise ValueError("approved_by must be operator")
        unknown = sorted(set(approved.alignment) - set(self.kernel.constitution.weights))
        if unknown:
            raise ValueError(f"goal references unknown values: {', '.join(unknown)}")
        alignment_score = sum(
            self.kernel.constitution.weights[name] * impact
            for name, impact in approved.alignment.items()
        )
        if alignment_score <= 0.0:
            raise ValueError("goal must have positive endorsed-value alignment")

        goal = Goal(
            id=approved.id,
            statement=approved.statement,
            rationale=approved.rationale,
            alignment=approved.alignment,
            source=approved.source,
            horizon=approved.horizon,
            evidence=approved.approval_evidence,
        )
        goal_payload = {
            "goal": {
                "id": goal.id,
                "statement": goal.statement,
                "rationale": goal.rationale,
                "source": goal.source,
                "horizon": goal.horizon,
                "alignment": dict(goal.alignment),
                "evidence": list(goal.evidence),
                "status": goal.status,
            },
            "alignment_score": alignment_score,
            "constitution_fingerprint": self.kernel.constitution_fingerprint(),
        }
        goal_events = [
            event
            for event in self.store.events("goal.formed")
            if event.payload.get("goal", {}).get("id") == goal.id
        ]
        if len(goal_events) > 1:
            raise PlanningDenied("GOAL_APPROVAL_CONFLICT")
        if goal_events:
            goal_event = goal_events[0]
            if canonical_json(goal_event.payload) != canonical_json(goal_payload):
                raise PlanningDenied("GOAL_APPROVAL_CONFLICT")
        else:
            try:
                goal_event, _ = self.store.append_once_result(
                    "goal.formed", approved.id, goal_payload
                )
            except ValueError as error:
                raise PlanningDenied("GOAL_APPROVAL_CONFLICT") from error
            if canonical_json(goal_event.payload) != canonical_json(goal_payload):
                raise PlanningDenied("GOAL_APPROVAL_CONFLICT")
        payload = {
            "schema_version": 1,
            "goal_id": goal.id,
            "source": goal.source,
            "approved_by": approved.approved_by,
            "approved_origin": approved.approved_origin,
            "approval_evidence": list(approved.approval_evidence),
            "goal_event_id": goal_event.event_id,
            "goal_sha256": _digest(goal_event.payload["goal"]),
            "alignment_score": round(alignment_score, 12),
            "constitution_fingerprint": self.kernel.constitution_fingerprint(),
            "approval_grants_execution_authority": False,
        }
        try:
            event, created = self.store.append_once_result(
                "autonomy.goal.approved", approved.id, payload
            )
        except ValueError as error:
            raise PlanningDenied("GOAL_APPROVAL_CONFLICT") from error
        return {**event.payload, "event_id": event.event_id, "created": created}

    def _approved_goal_event(
        self, events: Sequence[Event], goal_id: str
    ) -> Event | None:
        formed = [
            event
            for event in events
            if event.kind == "goal.formed"
            and event.payload.get("goal", {}).get("id") == goal_id
        ]
        approvals = [
            event
            for event in events
            if event.kind == "autonomy.goal.approved"
            and event.payload.get("goal_id") == goal_id
        ]
        if len(formed) != 1 or len(approvals) != 1:
            return None
        goal_event = formed[0]
        approval = approvals[0]
        goal = goal_event.payload.get("goal")
        if not isinstance(goal, Mapping):
            return None
        alignment = goal.get("alignment")
        evidence = approval.payload.get("approval_evidence")
        if (
            not isinstance(alignment, Mapping)
            or not alignment
            or any(name not in self.kernel.constitution.weights for name in alignment)
            or not isinstance(evidence, list)
            or not evidence
            or any(not isinstance(item, str) or not item.strip() for item in evidence)
        ):
            return None
        try:
            alignment_score = round(
                sum(
                    self.kernel.constitution.weights[str(name)] * float(impact)
                    for name, impact in alignment.items()
                ),
                12,
            )
        except (TypeError, ValueError):
            return None
        current_fingerprint = self.kernel.constitution_fingerprint()
        if (
            alignment_score <= 0.0
            or approval.payload.get("alignment_score") != alignment_score
            or approval.payload.get("approval_grants_execution_authority") is not False
            or approval.payload.get("constitution_fingerprint")
            != current_fingerprint
            or goal_event.payload.get("constitution_fingerprint")
            != current_fingerprint
            or approval.payload.get("goal_event_id") != goal_event.event_id
            or approval.payload.get("goal_sha256") != _digest(dict(goal))
        ):
            return None
        source = goal.get("source")
        if source in {"external", "joint"}:
            if (
                approval.payload.get("source") != source
                or approval.payload.get("approved_by") != "operator"
                or not str(approval.payload.get("approved_origin", "")).startswith(
                    "operator:"
                )
                or approval.payload.get("schema_version") != 1
                or "self_authorization" in approval.payload
            ):
                return None
        elif source == "self":
            authorization = approval.payload.get("self_authorization")
            if (
                approval.payload.get("source") != "self"
                or approval.payload.get("approved_by") != "host_policy"
                or not str(approval.payload.get("approved_origin", "")).startswith(
                    "host-policy:"
                )
                or approval.payload.get("schema_version") != 2
                or self._self_authorization_reason(
                    events, authorization, goal_id=goal_id
                )
                is not None
                or not isinstance(authorization, Mapping)
                or evidence != authorization.get("receipt_event_ids")
            ):
                return None
        else:
            return None
        return approval

    def self_goal_authorization(self, goal_id: str) -> dict[str, Any]:
        """Read back one self-goal authorization with an explicit live/expiry reason."""

        goal_id = _identifier("goal id", goal_id)
        events = self.store.events()
        approvals = [
            event
            for event in events
            if event.kind == "autonomy.goal.approved"
            and event.payload.get("goal_id") == goal_id
            and event.payload.get("source") == "self"
        ]
        if len(approvals) != 1:
            return {"active": False, "reason": "SELF_GOAL_APPROVAL_MISSING"}
        authorization = approvals[0].payload.get("self_authorization")
        reason = self._self_authorization_reason(
            events, authorization, goal_id=goal_id
        )
        return {
            "active": reason is None,
            "reason": reason or "ACTIVE_SELF_GOAL_LEASE",
            "approval_event_id": approvals[0].event_id,
            "lease_id": (
                authorization.get("lease_id")
                if isinstance(authorization, Mapping)
                else None
            ),
        }

    def make_choice(
        self,
        *,
        goal_id: str,
        alternatives: Sequence[DecisionAlternative],
        seed: int,
        decision_id: str,
    ) -> dict[str, Any]:
        goal_id = _identifier("goal id", goal_id)
        decision_id = _identifier("decision id", decision_id)
        events = self.store.events()
        if not _events_chain_valid(events):
            raise PlanningDenied("LEDGER_CHAIN_INVALID")
        if self._constitution_reason(events) is not None:
            raise PlanningDenied("CONSTITUTION_MISMATCH")
        approval = self._approved_goal_event(events, goal_id)
        if approval is None:
            raise PlanningDenied("GOAL_NOT_APPROVED")
        rows = tuple(alternatives)
        semantic_digests = [_digest(row.semantic_payload()) for row in rows]
        ids = [row.id for row in rows]
        allowed_rows = [row for row in rows if not row.blocked_reasons]
        genuine = (
            len(rows) >= 2
            and len(rows) <= 32
            and len(allowed_rows) >= 2
            and NO_OP_ID not in ids
            and len(ids) == len(set(ids))
            and len(semantic_digests) == len(set(semantic_digests))
        )
        if not genuine:
            raise PlanningDenied("GENUINE_ALTERNATIVES_REQUIRED")

        try:
            kernel_receipt = self.kernel.deliberate(
                goal_id=goal_id,
                options=(row.as_option() for row in rows),
                seed=seed,
                decision_id=decision_id,
            )
        except ValueError as error:
            if "logical key collision" in str(error):
                raise PlanningDenied("DECISION_ID_CONFLICT") from error
            raise
        chosen_id = str(kernel_receipt["chosen_option_id"])
        branch_by_id = {row.id: row.receipt_payload() for row in rows}
        no_op = canonical_no_op()
        branch_by_id[NO_OP_ID] = {
            "id": NO_OP_ID,
            "summary": no_op.description,
            "predicted_outcome": "No external action is executed.",
            "predicted_outcome_sha256": sha256(
                b"No external action is executed."
            ).hexdigest(),
            "value_impacts": {},
            "information_gain": no_op.information_gain,
            "uncertainty": no_op.uncertainty,
            "time_cost": no_op.time_cost,
            "irreversible": False,
            "blocked_reasons": [],
            "assumptions": list(no_op.assumptions),
        }
        chosen = branch_by_id[chosen_id]
        branch_order = [*ids, NO_OP_ID]
        rejected = [
            branch_by_id[option_id]
            for option_id in branch_order
            if option_id != chosen_id
        ]
        selection_keys = (
            "selection_version",
            "mode",
            "reason_codes",
            "seed",
            "rng",
            "exploration_draw",
            "sample_draw",
            "probabilities",
            "scores",
        )
        payload = {
            "schema_version": 1,
            "decision_id": decision_id,
            "goal_id": goal_id,
            "goal_approval_event_id": approval.event_id,
            "constitution_fingerprint": kernel_receipt["constitution_fingerprint"],
            "chosen_branch": chosen,
            "rejected_branches": rejected,
            "branch_order": branch_order,
            "branches_sha256": _digest(
                [branch_by_id[option_id] for option_id in branch_order]
            ),
            **{key: kernel_receipt[key] for key in selection_keys},
            "kernel_decision_event_id": kernel_receipt["event_id"],
            "selection_grants_authority": False,
        }
        try:
            event, created = self.store.append_once_result(
                "autonomy.decision.receipt", decision_id, payload
            )
        except ValueError as error:
            raise PlanningDenied("DECISION_ID_CONFLICT") from error
        return {**event.payload, "event_id": event.event_id, "created": created}

    def _decision_receipt_matches(
        self, events: Sequence[Event], receipt: Event
    ) -> bool:
        decision_id = receipt.payload.get("decision_id")
        kernel_events = [
            event
            for event in events
            if event.kind == "decision.made"
            and event.payload.get("decision_id") == decision_id
        ]
        if len(kernel_events) != 1:
            return False
        kernel_event = kernel_events[0]
        kernel_payload = kernel_event.payload
        approval = self._approved_goal_event(
            events, str(receipt.payload.get("goal_id", ""))
        )
        if approval is None or (
            receipt.payload.get("goal_approval_event_id") != approval.event_id
            or receipt.payload.get("kernel_decision_event_id") != kernel_event.event_id
            or receipt.payload.get("constitution_fingerprint")
            != self.kernel.constitution_fingerprint()
            or kernel_payload.get("constitution_fingerprint")
            != self.kernel.constitution_fingerprint()
            or receipt.payload.get("selection_grants_authority") is not False
            or receipt.payload.get("goal_id") != kernel_payload.get("goal_id")
        ):
            return False
        option_rows = kernel_payload.get("options")
        if not isinstance(option_rows, list):
            return False
        try:
            options = options_from_dicts(option_rows)
            replay = self.kernel._select(
                [option for option in options if option.allowed],
                int(kernel_payload["seed"]),
                stream_id=f"decision:{decision_id}",
            )
        except (KeyError, TypeError, ValueError):
            return False
        selection_keys = (
            "selection_version",
            "mode",
            "reason_codes",
            "seed",
            "rng",
            "exploration_draw",
            "sample_draw",
            "probabilities",
            "scores",
        )
        if any(
            receipt.payload.get(key) != kernel_payload.get(key)
            or kernel_payload.get(key) != replay.get(key)
            for key in selection_keys
        ):
            return False
        if kernel_payload.get("chosen_option_id") != replay.get("chosen_option_id"):
            return False
        chosen = receipt.payload.get("chosen_branch")
        rejected = receipt.payload.get("rejected_branches")
        branch_order = receipt.payload.get("branch_order")
        if (
            not isinstance(chosen, Mapping)
            or not isinstance(rejected, list)
            or any(not isinstance(branch, Mapping) for branch in rejected)
            or not isinstance(branch_order, list)
        ):
            return False
        branch_rows = [dict(chosen), *(dict(branch) for branch in rejected)]
        branch_by_id = {str(branch.get("id", "")): branch for branch in branch_rows}
        expected_order = [str(row.get("id", "")) for row in option_rows]
        if (
            len(branch_by_id) != len(branch_rows)
            or branch_order != expected_order
            or set(branch_by_id) != set(expected_order)
            or chosen.get("id") != kernel_payload.get("chosen_option_id")
            or receipt.payload.get("branches_sha256")
            != _digest([branch_by_id[option_id] for option_id in expected_order])
        ):
            return False
        option_by_id = {option.id: option for option in options}
        for option_id in expected_order:
            option = option_by_id.get(option_id)
            branch = branch_by_id[option_id]
            prediction = branch.get("predicted_outcome")
            if option is None or not isinstance(prediction, str) or (
                branch.get("predicted_outcome_sha256")
                != sha256(prediction.encode("utf-8")).hexdigest()
                or branch.get("summary") != option.description
                or branch.get("value_impacts") != dict(option.value_impacts)
                or branch.get("information_gain") != option.information_gain
                or branch.get("uncertainty") != option.uncertainty
                or branch.get("time_cost") != option.time_cost
                or branch.get("irreversible") != option.irreversible
                or branch.get("blocked_reasons") != list(option.blocked_reasons)
                or branch.get("assumptions") != list(option.assumptions)
            ):
                return False
        return True

    def replay_choice(self, decision_id: str) -> dict[str, Any]:
        decision_id = _identifier("decision id", decision_id)
        events = self.store.events()
        receipts = [
            event
            for event in events
            if event.kind == "autonomy.decision.receipt"
            and event.payload.get("decision_id") == decision_id
        ]
        if len(receipts) != 1:
            raise KeyError(f"unknown autonomy decision: {decision_id}")
        receipt = receipts[0]
        chain_valid = _events_chain_valid(events)
        matches = chain_valid and self._decision_receipt_matches(events, receipt)
        return {
            "matches": matches,
            "decision_id": decision_id,
            "receipt_event_id": receipt.event_id,
            "chain_valid": chain_valid,
        }

    @staticmethod
    def _validate_graph(plan: HierarchicalPlan) -> tuple[list[str], list[list[str]]]:
        ids = [stage.id for stage in plan.stages]
        if len(ids) != len(set(ids)):
            raise PlanningDenied("INVALID_DEPENDENCY_ORDER")
        prior: set[str] = set()
        by_id = {stage.id: stage for stage in plan.stages}
        atomic: list[str] = []
        edges: list[list[str]] = []
        for stage in plan.stages:
            if stage.kind == "group":
                if stage.handoff is not None or stage.depends_on:
                    raise PlanningDenied("INVALID_DEPENDENCY_ORDER")
            else:
                if stage.handoff is None:
                    raise PlanningDenied("INVALID_DEPENDENCY_ORDER")
                atomic.append(stage.id)
            if stage.parent_id is not None:
                parent = by_id.get(stage.parent_id)
                if (
                    stage.parent_id not in prior
                    or parent is None
                    or parent.kind != "group"
                ):
                    raise PlanningDenied("INVALID_DEPENDENCY_ORDER")
            for dependency in stage.depends_on:
                dependency_stage = by_id.get(dependency)
                if (
                    dependency == stage.id
                    or dependency not in prior
                    or dependency_stage is None
                    or dependency_stage.kind != "atomic"
                ):
                    raise PlanningDenied("INVALID_DEPENDENCY_ORDER")
                edges.append([dependency, stage.id])
            prior.add(stage.id)
        if not atomic:
            raise PlanningDenied("INVALID_DEPENDENCY_ORDER")
        return atomic, edges

    @staticmethod
    def _principal_snapshot(events: Sequence[Event]) -> dict[str, Any] | None:
        profile_events = [
            event for event in events if event.kind == "principal.profile.installed"
        ]
        if not profile_events:
            return None
        previous_digest: str | None = None
        principal_id: str | None = None
        latest: dict[str, Any] | None = None
        for expected_revision, event in enumerate(profile_events, start=1):
            profile_payload = event.payload.get("profile")
            revision = event.payload.get("revision")
            evidence = event.payload.get("evidence")
            if (
                event.payload.get("schema_version") != 1
                or not isinstance(profile_payload, Mapping)
                or isinstance(revision, bool)
                or revision != expected_revision
                or event.payload.get("authority") not in {"operator", "host_adapter"}
                or event.payload.get("previous_profile_digest") != previous_digest
                or not isinstance(evidence, list)
                or not evidence
                or len(evidence) > 32
                or any(
                    not isinstance(item, str) or not item.strip() or len(item) > 600
                    for item in evidence
                )
            ):
                return None
            try:
                profile = PrincipalProfile.from_payload(profile_payload)
            except (TypeError, ValueError):
                return None
            profile_digest = _digest(profile.as_payload())
            if (
                event.payload.get("profile_digest") != profile_digest
                or (principal_id is not None and profile.principal_id != principal_id)
                or (previous_digest is not None and profile_digest == previous_digest)
            ):
                return None
            principal_id = profile.principal_id
            previous_digest = profile_digest
            latest = {
                "principal_id": profile.principal_id,
                "principal_profile_digest": profile_digest,
                "principal_profile_revision": revision,
            }
        return latest

    def _constitution_reason(
        self, events: Sequence[Event], binding: PlanBinding | None = None
    ) -> str | None:
        initialized = [event for event in events if event.kind == "constitution.initialized"]
        if len(initialized) != 1:
            return "CONSTITUTION_MISMATCH"
        event = initialized[0]
        constitution = event.payload.get("constitution")
        if not isinstance(constitution, Mapping):
            return "CONSTITUTION_MISMATCH"
        fingerprint = _digest(dict(constitution))
        expected = self.kernel.constitution_fingerprint()
        if event.payload.get("fingerprint") != fingerprint or fingerprint != expected:
            return "CONSTITUTION_MISMATCH"
        if binding is not None and binding.constitution_fingerprint != expected:
            return "CONSTITUTION_MISMATCH"
        return None

    @staticmethod
    def _public_plan_payload(
        plan: HierarchicalPlan,
        binding: PlanBinding,
        atomic_ids: Sequence[str],
        edges: Sequence[Sequence[str]],
    ) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "plan_id": plan.id,
            "goal_id": plan.goal_id,
            "decision_id": plan.decision_id,
            "chosen_option_id": plan.chosen_option_id,
            "summary": plan.summary,
            "plan_sha256": binding.plan_sha256,
            "constitution_fingerprint": binding.constitution_fingerprint,
            "principal_id": binding.principal_id,
            "principal_profile_digest": binding.principal_profile_digest,
            "principal_profile_revision": binding.principal_profile_revision,
            "atomic_stage_ids": list(atomic_ids),
            "dependency_edges": [list(edge) for edge in edges],
            "state_transition": {"from": "ABSENT", "to": "READY"},
            "content_in_event_ledger": False,
            "execution_ticket_required": True,
            "execution_authority_granted": False,
        }

    def _plan_path(self, plan_id: str) -> Path:
        return self.private_root / "plans" / f"{_identifier('plan id', plan_id)}.json"

    @staticmethod
    def _private_envelope(
        semantic: Mapping[str, Any], binding: PlanBinding
    ) -> dict[str, Any]:
        # The mirrored semantic keys retain compatibility with the original private
        # plan format; verification requires them to equal the canonical `plan` object.
        return {
            **dict(semantic),
            "plan": dict(semantic),
            "bindings": binding.as_payload(),
        }

    def _write_private_once(self, path: Path, payload: Mapping[str, Any]) -> bool:
        serialized = f"{canonical_json(payload)}\n"
        if not self._private_permissions_valid():
            raise PlanningDenied("PRIVATE_PLAN_PERMISSIONS_INVALID")
        if os.path.lexists(path):
            if not self._private_permissions_valid(path):
                raise PlanningDenied("PRIVATE_PLAN_PERMISSIONS_INVALID")
            try:
                existing = path.read_text(encoding="utf-8")
            except OSError as error:
                raise PlanningDenied("PLAN_DIGEST_MISMATCH") from error
            if existing != serialized:
                raise PlanningDenied("PLAN_ID_CONFLICT")
            if os.stat(path).st_mode & 0o777 != 0o600:
                raise PlanningDenied("PLAN_DIGEST_MISMATCH")
            return False

        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                if path.read_text(encoding="utf-8") != serialized:
                    raise PlanningDenied("PLAN_ID_CONFLICT")
                return False
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return True
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def store_plan(self, plan: HierarchicalPlan) -> dict[str, Any]:
        atomic_ids, edges = self._validate_graph(plan)
        events = self.store.events()
        if not _events_chain_valid(events):
            raise PlanningDenied("LEDGER_CHAIN_INVALID")
        constitution_reason = self._constitution_reason(events)
        if constitution_reason:
            raise PlanningDenied(constitution_reason)
        approval = self._approved_goal_event(events, plan.goal_id)
        if approval is None:
            raise PlanningDenied("GOAL_NOT_APPROVED")
        principal = self._principal_snapshot(events)
        if principal is None:
            raise PlanningDenied("PRINCIPAL_PROFILE_REQUIRED")

        receipts = [
            event
            for event in events
            if event.kind == "autonomy.decision.receipt"
            and event.payload.get("decision_id") == plan.decision_id
        ]
        if len(receipts) != 1:
            raise PlanningDenied("DECISION_BINDING_MISMATCH")
        if not self._decision_receipt_matches(events, receipts[0]):
            raise PlanningDenied("DECISION_BINDING_MISMATCH")
        decision = receipts[0].payload
        if (
            decision.get("goal_id") != plan.goal_id
            or decision.get("goal_approval_event_id") != approval.event_id
            or decision.get("chosen_branch", {}).get("id") != plan.chosen_option_id
            or plan.chosen_option_id == NO_OP_ID
        ):
            raise PlanningDenied("DECISION_BINDING_MISMATCH")

        semantic = plan.semantic_payload()
        binding = PlanBinding(
            plan_id=plan.id,
            goal_id=plan.goal_id,
            decision_id=plan.decision_id,
            plan_sha256=_digest(semantic),
            constitution_fingerprint=self.kernel.constitution_fingerprint(),
            **principal,
        )
        public_payload = self._public_plan_payload(plan, binding, atomic_ids, edges)
        private_payload = self._private_envelope(semantic, binding)
        private_path = self._plan_path(plan.id)
        self._write_private_once(private_path, private_payload)
        if not self._private_permissions_valid(private_path):
            raise PlanningDenied("PRIVATE_PLAN_PERMISSIONS_INVALID")
        try:
            event, created = self.store.append_once_result(
                "autonomy.plan.stored", plan.id, public_payload
            )
        except ValueError as error:
            raise PlanningDenied("PLAN_ID_CONFLICT") from error
        return {
            **event.payload,
            "binding": binding,
            "event_id": event.event_id,
            "created": created,
        }

    def _load_verified_plan(
        self, binding: PlanBinding, *, events: Sequence[Event] | None = None
    ) -> HierarchicalPlan:
        current_events = list(events) if events is not None else self.store.events()
        if not _events_chain_valid(current_events):
            raise PlanningDenied("LEDGER_CHAIN_INVALID")
        reason = self._constitution_reason(current_events, binding)
        if reason:
            raise PlanningDenied(reason)

        plan_events = [
            event
            for event in current_events
            if event.kind == "autonomy.plan.stored"
            and event.payload.get("plan_id") == binding.plan_id
        ]
        if len(plan_events) != 1:
            raise PlanningDenied("PLAN_DIGEST_MISMATCH")
        plan_event = plan_events[0]
        if (
            plan_event.payload.get("plan_sha256") != binding.plan_sha256
            or plan_event.payload.get("goal_id") != binding.goal_id
            or plan_event.payload.get("decision_id") != binding.decision_id
        ):
            raise PlanningDenied("PLAN_DIGEST_MISMATCH")

        private_path = self._plan_path(binding.plan_id)
        if not self._private_permissions_valid(private_path):
            raise PlanningDenied("PRIVATE_PLAN_PERMISSIONS_INVALID")
        try:
            raw = json.loads(private_path.read_text(encoding="utf-8"))
            if not isinstance(raw, Mapping):
                raise ValueError("private plan must be an object")
            semantic = raw["plan"]
            copied_binding = raw["bindings"]
            if not isinstance(semantic, Mapping) or not isinstance(copied_binding, Mapping):
                raise ValueError("private plan envelope is malformed")
            if _digest(dict(semantic)) != binding.plan_sha256:
                raise ValueError("private plan digest differs")
            if canonical_json(dict(copied_binding)) != canonical_json(binding.as_payload()):
                raise ValueError("private plan binding differs")
            mirrored = {key: raw.get(key) for key in semantic}
            if canonical_json(mirrored) != canonical_json(dict(semantic)):
                raise ValueError("private semantic mirror differs")
            plan = HierarchicalPlan.from_payload(semantic)
            atomic_ids, edges = self._validate_graph(plan)
        except (KeyError, OSError, TypeError, ValueError, PlanningDenied) as error:
            raise PlanningDenied("PLAN_DIGEST_MISMATCH") from error

        expected_public = self._public_plan_payload(plan, binding, atomic_ids, edges)
        if canonical_json(plan_event.payload) != canonical_json(expected_public):
            raise PlanningDenied("PLAN_DIGEST_MISMATCH")
        if (
            plan.id != binding.plan_id
            or plan.goal_id != binding.goal_id
            or plan.decision_id != binding.decision_id
        ):
            raise PlanningDenied("PLAN_DIGEST_MISMATCH")

        approval = self._approved_goal_event(current_events, binding.goal_id)
        decisions = [
            event
            for event in current_events
            if event.kind == "autonomy.decision.receipt"
            and event.payload.get("decision_id") == binding.decision_id
        ]
        if approval is None:
            raise PlanningDenied("GOAL_NOT_APPROVED")
        if len(decisions) != 1 or not self._decision_receipt_matches(
            current_events, decisions[0]
        ) or (
            decisions[0].payload.get("goal_id") != binding.goal_id
            or decisions[0].payload.get("goal_approval_event_id")
            != approval.event_id
            or decisions[0].payload.get("chosen_branch", {}).get("id")
            != plan.chosen_option_id
        ):
            raise PlanningDenied("DECISION_BINDING_MISMATCH")

        principal = self._principal_snapshot(current_events)
        if principal is None or any(
            principal[key] != binding.as_payload()[key]
            for key in (
                "principal_id",
                "principal_profile_digest",
                "principal_profile_revision",
            )
        ):
            raise PlanningDenied("PRINCIPAL_PROFILE_STALE")
        return plan

    @staticmethod
    def _cursor_from_events(
        plan: HierarchicalPlan, events: Sequence[Event]
    ) -> dict[str, Any]:
        plan_id = plan.id
        atomic_ids = [stage.id for stage in plan.stages if stage.kind == "atomic"]
        revision = 0
        state = "READY"
        completed: list[str] = []
        claimed: dict[str, Any] | None = None
        attempts: dict[str, int] = {}
        for event in events:
            if event.payload.get("plan_id") != plan_id:
                continue
            if event.kind == "autonomy.plan.stage.claimed":
                stage_id = event.payload.get("stage_id")
                worker_id = event.payload.get("worker_id")
                attempt = event.payload.get("attempt")
                expected_revision = event.payload.get("expected_revision")
                event_revision = event.payload.get("cursor_revision")
                if (
                    event.payload.get("schema_version") != 1
                    or not isinstance(event.payload.get("request_sha256"), str)
                    or not _SHA256.fullmatch(event.payload["request_sha256"])
                    or not isinstance(stage_id, str)
                    or not _IDENTIFIER.fullmatch(stage_id)
                    or not isinstance(worker_id, str)
                    or not _IDENTIFIER.fullmatch(worker_id)
                    or isinstance(attempt, bool)
                    or not isinstance(attempt, int)
                    or attempt < 1
                    or isinstance(expected_revision, bool)
                    or expected_revision != revision
                    or isinstance(event_revision, bool)
                    or event_revision != revision + 1
                    or event.payload.get("execution_ticket_required") is not True
                    or event.payload.get("execution_authority_granted") is not False
                    or state != "READY"
                    or claimed is not None
                    or event.payload.get("state_transition")
                    != {"from": "READY", "to": "CLAIMED"}
                ):
                    raise PlanningDenied("CURSOR_STATE_INVALID")
                assert isinstance(event_revision, int)
                assert isinstance(attempt, int)
                ready = AutonomyPlanner._first_ready_stage(plan, completed)
                if (
                    ready is None
                    or stage_id != ready.id
                    or attempt != int(attempts.get(stage_id, 0)) + 1
                ):
                    raise PlanningDenied("CURSOR_STATE_INVALID")
                revision = int(event_revision)
                state = "CLAIMED"
                attempts[stage_id] = int(attempt)
                claimed = {
                    "stage_id": stage_id,
                    "worker_id": worker_id,
                    "attempt": int(attempt),
                    "claim_event_id": event.event_id,
                }
            elif event.kind == "autonomy.plan.stage.advanced":
                expected_revision = event.payload.get("expected_revision")
                event_revision = event.payload.get("cursor_revision")
                if (
                    event.payload.get("schema_version") != 1
                    or not isinstance(event.payload.get("request_sha256"), str)
                    or not _SHA256.fullmatch(event.payload["request_sha256"])
                    or not isinstance(event.payload.get("outcome_sha256"), str)
                    or not _SHA256.fullmatch(event.payload["outcome_sha256"])
                    or isinstance(expected_revision, bool)
                    or expected_revision != revision
                    or isinstance(event_revision, bool)
                    or event_revision != revision + 1
                    or event.payload.get("execution_authority_granted") is not False
                    or state != "CLAIMED"
                    or claimed is None
                    or event.payload.get("state_transition", {}).get("from")
                    != "CLAIMED"
                ):
                    raise PlanningDenied("CURSOR_STATE_INVALID")
                assert isinstance(event_revision, int)
                revision = int(event_revision)
                next_state = str(event.payload["state_transition"]["to"])
                raw_completed = event.payload.get("completed_stage_ids")
                if (
                    not isinstance(raw_completed, list)
                    or any(
                        not isinstance(value, str)
                        or not _IDENTIFIER.fullmatch(value)
                        for value in raw_completed
                    )
                ):
                    raise PlanningDenied("CURSOR_STATE_INVALID")
                next_completed = list(raw_completed)
                if (
                    next_state
                    != ("COMPLETE" if next_completed == atomic_ids else "READY")
                    or event.payload.get("stage_id") != claimed["stage_id"]
                    or event.payload.get("worker_id") != claimed["worker_id"]
                    or event.payload.get("attempt") != claimed["attempt"]
                    or event.payload.get("claim_event_id")
                    != claimed["claim_event_id"]
                    or next_completed != [*completed, claimed["stage_id"]]
                ):
                    raise PlanningDenied("CURSOR_STATE_INVALID")
                state = next_state
                completed = next_completed
                claimed = None
        return {
            "plan_id": plan_id,
            "revision": revision,
            "state": state,
            "completed_stage_ids": completed,
            "claimed": claimed,
            "attempts": attempts,
        }

    def cursor(self, plan_id: str) -> dict[str, Any]:
        plan_id = _identifier("plan id", plan_id)
        events = self.store.events()
        plan_events = [
            event
            for event in events
            if event.kind == "autonomy.plan.stored"
            and event.payload.get("plan_id") == plan_id
        ]
        if len(plan_events) != 1:
            raise KeyError(f"unknown plan: {plan_id}")
        payload = plan_events[0].payload
        try:
            binding = PlanBinding(
                plan_id=payload["plan_id"],
                goal_id=payload["goal_id"],
                decision_id=payload["decision_id"],
                plan_sha256=payload["plan_sha256"],
                constitution_fingerprint=payload["constitution_fingerprint"],
                principal_id=payload["principal_id"],
                principal_profile_digest=payload["principal_profile_digest"],
                principal_profile_revision=payload["principal_profile_revision"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PlanningDenied("PLAN_DIGEST_MISMATCH") from error
        plan = self._load_verified_plan(binding, events=events)
        cursor = self._cursor_from_events(plan, events)
        return {key: value for key, value in cursor.items() if key != "attempts"}

    @staticmethod
    def _first_ready_stage(
        plan: HierarchicalPlan, completed_stage_ids: Sequence[str]
    ) -> PlanStage | None:
        completed = set(completed_stage_ids)
        return next(
            (
                stage
                for stage in plan.stages
                if stage.kind == "atomic"
                and stage.id not in completed
                and set(stage.depends_on).issubset(completed)
            ),
            None,
        )

    @staticmethod
    def _event_for_request(
        events: Sequence[Event], kind: str, request_sha256: str
    ) -> Event | None:
        return next(
            (
                event
                for event in events
                if event.kind == kind
                and event.payload.get("request_sha256") == request_sha256
            ),
            None,
        )

    @staticmethod
    def _claim_event_matches_request(
        event: Event, request: WorkerClaimRequest, request_sha256: str
    ) -> bool:
        return bool(
            event.payload.get("request_sha256") == request_sha256
            and event.payload.get("plan_id") == request.binding.plan_id
            and event.payload.get("worker_id") == request.worker_id
            and event.payload.get("expected_revision") == request.expected_revision
            and event.payload.get("cursor_revision") == request.expected_revision + 1
            and event.payload.get("execution_ticket_required") is True
            and event.payload.get("execution_authority_granted") is False
        )

    @staticmethod
    def _advance_event_matches_request(
        event: Event, request: WorkerAdvanceRequest, request_sha256: str
    ) -> bool:
        return bool(
            event.payload.get("request_sha256") == request_sha256
            and event.payload.get("plan_id") == request.binding.plan_id
            and event.payload.get("stage_id") == request.stage_id
            and event.payload.get("worker_id") == request.worker_id
            and event.payload.get("attempt") == request.attempt
            and event.payload.get("claim_event_id") == request.claim_event_id
            and event.payload.get("outcome_sha256") == request.outcome_sha256
            and event.payload.get("expected_revision") == request.expected_revision
            and event.payload.get("cursor_revision") == request.expected_revision + 1
            and event.payload.get("execution_authority_granted") is False
        )

    @staticmethod
    def _ticket_binding(
        plan: HierarchicalPlan, binding: PlanBinding, stage_id: str, attempt: int
    ) -> dict[str, Any]:
        stage = next(stage for stage in plan.stages if stage.id == stage_id)
        if stage.handoff is None:
            raise PlanningDenied("CURSOR_STATE_INVALID")
        return {
            "goal_id": binding.goal_id,
            "plan_id": binding.plan_id,
            "plan_hash": binding.plan_sha256,
            "stage": stage.id,
            "attempt": attempt,
            "tool_name": stage.handoff.tool_name,
            "arguments_sha256": stage.handoff.arguments_sha256,
        }

    def _claim_result(
        self,
        event: Event,
        created: bool,
        plan: HierarchicalPlan,
        binding: PlanBinding,
    ) -> dict[str, Any]:
        payload = event.payload
        return {
            **payload,
            "event_id": event.event_id,
            "created": created,
            "execution_ticket_binding": self._ticket_binding(
                plan,
                binding,
                str(payload["stage_id"]),
                int(payload["attempt"]),
            ),
        }

    def claim_stage(self, request: WorkerClaimRequest) -> dict[str, Any]:
        initial_events = self.store.events()
        plan = self._load_verified_plan(request.binding, events=initial_events)
        request_sha256 = _digest(request.as_payload())
        existing = self._event_for_request(
            initial_events, "autonomy.plan.stage.claimed", request_sha256
        )
        if existing is not None:
            self._cursor_from_events(plan, initial_events)
            if not self._claim_event_matches_request(
                existing, request, request_sha256
            ):
                raise PlanningDenied("CLAIM_RECEIPT_MISMATCH")
            return self._claim_result(existing, False, plan, request.binding)

        cursor = self._cursor_from_events(plan, initial_events)
        if cursor["revision"] != request.expected_revision:
            raise PlanningDenied("CURSOR_REVISION_CONFLICT")
        if cursor["state"] != "READY":
            raise PlanningDenied("CURSOR_REVISION_CONFLICT")
        stage = self._first_ready_stage(plan, cursor["completed_stage_ids"])
        if stage is None:
            raise PlanningDenied("PLAN_COMPLETE")
        attempt = int(cursor["attempts"].get(stage.id, 0)) + 1
        payload = {
            "schema_version": 1,
            "request_sha256": request_sha256,
            "plan_id": request.binding.plan_id,
            "stage_id": stage.id,
            "worker_id": request.worker_id,
            "attempt": attempt,
            "expected_revision": request.expected_revision,
            "cursor_revision": request.expected_revision + 1,
            "state_transition": {"from": "READY", "to": "CLAIMED"},
            "execution_ticket_required": True,
            "execution_authority_granted": False,
        }

        def guard(events: list[Event]) -> str | None:
            try:
                self._load_verified_plan(request.binding, events=events)
                current = self._cursor_from_events(plan, events)
            except PlanningDenied as error:
                return error.reason_code
            if current["revision"] != request.expected_revision:
                return "CURSOR_REVISION_CONFLICT"
            if current["state"] != "READY":
                return "CURSOR_REVISION_CONFLICT"
            ready = self._first_ready_stage(plan, current["completed_stage_ids"])
            if ready is None or ready.id != stage.id:
                return "CURSOR_REVISION_CONFLICT"
            return None

        event, created, rejection = self.store.append_once_result_guarded(
            "autonomy.plan.stage.claimed",
            f"{request.binding.plan_id}:{request_sha256}",
            payload,
            guard=guard,
        )
        if rejection is not None or event is None:
            raise PlanningDenied(rejection or "CURSOR_REVISION_CONFLICT")
        return self._claim_result(event, created, plan, request.binding)

    def _advance_result(self, event: Event, created: bool) -> dict[str, Any]:
        return {**event.payload, "event_id": event.event_id, "created": created}

    def advance_stage(self, request: WorkerAdvanceRequest) -> dict[str, Any]:
        initial_events = self.store.events()
        plan = self._load_verified_plan(request.binding, events=initial_events)
        request_sha256 = _digest(request.as_payload())
        existing = self._event_for_request(
            initial_events, "autonomy.plan.stage.advanced", request_sha256
        )
        if existing is not None:
            self._cursor_from_events(plan, initial_events)
            if not self._advance_event_matches_request(
                existing, request, request_sha256
            ):
                raise PlanningDenied("ADVANCE_RECEIPT_MISMATCH")
            return self._advance_result(existing, False)

        cursor = self._cursor_from_events(plan, initial_events)
        if cursor["revision"] != request.expected_revision:
            raise PlanningDenied("CURSOR_REVISION_CONFLICT")
        claimed = cursor["claimed"]
        if (
            cursor["state"] != "CLAIMED"
            or claimed is None
            or claimed["stage_id"] != request.stage_id
            or claimed["worker_id"] != request.worker_id
            or claimed["attempt"] != request.attempt
            or claimed["claim_event_id"] != request.claim_event_id
        ):
            raise PlanningDenied("CLAIM_BINDING_MISMATCH")
        ready = self._first_ready_stage(plan, cursor["completed_stage_ids"])
        if ready is None or ready.id != request.stage_id:
            raise PlanningDenied("CLAIM_BINDING_MISMATCH")

        completed = [*cursor["completed_stage_ids"], request.stage_id]
        atomic_ids = [stage.id for stage in plan.stages if stage.kind == "atomic"]
        next_state = "COMPLETE" if completed == atomic_ids else "READY"
        payload = {
            "schema_version": 1,
            "request_sha256": request_sha256,
            "plan_id": request.binding.plan_id,
            "stage_id": request.stage_id,
            "worker_id": request.worker_id,
            "attempt": request.attempt,
            "claim_event_id": request.claim_event_id,
            "outcome_sha256": request.outcome_sha256,
            "expected_revision": request.expected_revision,
            "cursor_revision": request.expected_revision + 1,
            "completed_stage_ids": completed,
            "state_transition": {"from": "CLAIMED", "to": next_state},
            "execution_authority_granted": False,
        }

        def guard(events: list[Event]) -> str | None:
            try:
                self._load_verified_plan(request.binding, events=events)
                current = self._cursor_from_events(plan, events)
            except PlanningDenied as error:
                return error.reason_code
            if current["revision"] != request.expected_revision:
                return "CURSOR_REVISION_CONFLICT"
            active = current["claimed"]
            if (
                current["state"] != "CLAIMED"
                or active is None
                or active["stage_id"] != request.stage_id
                or active["worker_id"] != request.worker_id
                or active["attempt"] != request.attempt
                or active["claim_event_id"] != request.claim_event_id
            ):
                return "CLAIM_BINDING_MISMATCH"
            ready = self._first_ready_stage(plan, current["completed_stage_ids"])
            if ready is None or ready.id != request.stage_id:
                return "CLAIM_BINDING_MISMATCH"
            return None

        event, created, rejection = self.store.append_once_result_guarded(
            "autonomy.plan.stage.advanced",
            f"{request.binding.plan_id}:{request_sha256}",
            payload,
            guard=guard,
        )
        if rejection is not None or event is None:
            raise PlanningDenied(rejection or "CURSOR_REVISION_CONFLICT")
        return self._advance_result(event, created)


__all__ = [
    "ApprovedGoal",
    "AutonomyPlanner",
    "DecisionAlternative",
    "HierarchicalPlan",
    "PlanBinding",
    "PlanningDenied",
    "PlanStage",
    "StageHandoff",
    "WorkerAdvanceRequest",
    "WorkerClaimRequest",
]
