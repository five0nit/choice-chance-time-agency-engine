"""Authenticated self-goal selection and leased full-stack episode coordination."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
from math import isfinite
import re
from typing import Literal, Mapping, Sequence

from .capabilities import CapabilityLease, CapabilityRegistry, CapabilitySpec
from .commands import BoundedCommandAdapter
from .deployment import LocalFakeDeploymentAdapter
from .full_stack import (
    FullStackEpisodeConfig,
    FullStackEpisodeResult,
    FullStackEpisodeRunner,
    FullStackEpisodeSpec,
)
from .kernel import AgencyKernel, NO_OP_ID
from .models import Option
from .patching import ExpectedHashPatchAdapter
from .planning import (
    AutonomyPlanner,
    DecisionAlternative,
    HierarchicalPlan,
    LeasedSelfGoal,
    PlanBinding,
    PlanStage,
    PlanningDenied,
    StageHandoff,
)
from .principal import PrincipalModel
from .public_actions import LocalFakePublicActionAdapter
from .research import BoundedResearchAdapter
from .store import EventStore, canonical_json
from .verification import HostRegisteredVerifier


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SCOPE_ROOT = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
ReceiptKind = Literal["observation", "value", "commitment", "opportunity"]


class SelfGoalDenied(RuntimeError):
    """A fail-closed self-goal admission or execution decision."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _bounded_text(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum or any(ord(char) < 32 for char in cleaned):
        raise ValueError(f"{name} must contain 1-{maximum} printable characters")
    return cleaned


@dataclass(frozen=True, slots=True)
class SelfGoalInputReceipt:
    """Signed metadata receipt; producer content stays outside the CCT ledger."""

    id: str
    kind: ReceiptKind
    subject_id: str
    content_sha256: str
    issued_by: Literal["host_adapter", "operator"]
    semantic_taint: bool
    signature: str
    raw_content_persisted: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("receipt id", self.id))
        object.__setattr__(self, "subject_id", _identifier("receipt subject", self.subject_id))
        if self.kind not in {"observation", "value", "commitment", "opportunity"}:
            raise ValueError("receipt kind is invalid")
        if not isinstance(self.content_sha256, str) or not _DIGEST.fullmatch(
            self.content_sha256
        ):
            raise ValueError("receipt content_sha256 must be a lowercase SHA-256")
        if self.issued_by not in {"host_adapter", "operator"}:
            raise ValueError("receipt issuer must be host_adapter or operator")
        if not isinstance(self.semantic_taint, bool):
            raise ValueError("receipt semantic_taint must be boolean")
        if not isinstance(self.signature, str) or not _DIGEST.fullmatch(self.signature):
            raise ValueError("receipt signature must be a lowercase HMAC-SHA256")
        if self.raw_content_persisted is not False:
            raise ValueError("self-goal input receipts must not persist raw content")

    def signed_payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "receipt_id": self.id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "content_sha256": self.content_sha256,
            "issued_by": self.issued_by,
            "semantic_taint": self.semantic_taint,
            "raw_content_persisted": False,
        }

    @classmethod
    def sign(
        cls,
        *,
        receipt_id: str,
        kind: ReceiptKind,
        subject_id: str,
        content_sha256: str,
        issued_by: Literal["host_adapter", "operator"],
        semantic_taint: bool,
        secret: bytes,
    ) -> SelfGoalInputReceipt:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("receipt authentication secret must contain at least 32 bytes")
        unsigned = {
            "schema_version": 1,
            "receipt_id": receipt_id,
            "kind": kind,
            "subject_id": subject_id,
            "content_sha256": content_sha256,
            "issued_by": issued_by,
            "semantic_taint": semantic_taint,
            "raw_content_persisted": False,
        }
        signature = hmac.new(
            secret,
            canonical_json(unsigned).encode("utf-8"),
            "sha256",
        ).hexdigest()
        return cls(
            id=receipt_id,
            kind=kind,
            subject_id=subject_id,
            content_sha256=content_sha256,
            issued_by=issued_by,
            semantic_taint=semantic_taint,
            signature=signature,
        )

    def verify(self, secret: bytes) -> bool:
        if not isinstance(secret, bytes) or len(secret) < 32:
            return False
        expected = hmac.new(
            secret,
            canonical_json(self.signed_payload()).encode("utf-8"),
            "sha256",
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)


@dataclass(frozen=True, slots=True)
class SelfGoalCandidate:
    """Immutable host template for one bounded candidate objective."""

    id: str
    statement: str
    rationale: str
    horizon: str
    alignment: Mapping[str, float]
    required_receipt_ids: tuple[str, ...]
    alternatives: tuple[DecisionAlternative, ...]
    config: FullStackEpisodeConfig
    scope_root: str
    expires_at: str
    max_actions: int
    max_bytes: int
    information_gain: float
    uncertainty: float
    time_cost: float
    risk_class: str = "reversible"
    reversible: bool = True
    semantic_taint: bool = False
    derivation: str = "host_template"
    producer_text_used: bool = False
    max_value_microunits: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("candidate id", self.id))
        object.__setattr__(
            self, "statement", _bounded_text("candidate statement", self.statement, 1200)
        )
        object.__setattr__(
            self, "rationale", _bounded_text("candidate rationale", self.rationale, 1600)
        )
        object.__setattr__(self, "horizon", _identifier("candidate horizon", self.horizon))
        if not isinstance(self.config, FullStackEpisodeConfig):
            raise ValueError("candidate config must be a FullStackEpisodeConfig")
        receipts = tuple(
            _identifier("required receipt id", receipt_id)
            for receipt_id in self.required_receipt_ids
        )
        if len(receipts) < 4 or len(receipts) > 16 or len(receipts) != len(set(receipts)):
            raise ValueError("candidate requires 4-16 unique receipt IDs")
        object.__setattr__(self, "required_receipt_ids", receipts)
        alternatives = tuple(self.alternatives)
        if len(alternatives) < 2 or len(alternatives) > 32:
            raise ValueError("candidate requires 2-32 plan alternatives")
        if NO_OP_ID in {alternative.id for alternative in alternatives}:
            raise ValueError("candidate alternatives must not redefine canonical NO_OP")
        object.__setattr__(self, "alternatives", alternatives)
        if not isinstance(self.scope_root, str) or not _SCOPE_ROOT.fullmatch(self.scope_root):
            raise ValueError("candidate scope_root must be a normalized relative path")
        if self.max_actions != len(self.config.stage_ids):
            raise ValueError("candidate action budget must exactly equal full-stack stage count")
        if (
            isinstance(self.max_bytes, bool)
            or not isinstance(self.max_bytes, int)
            or self.max_bytes < 1
            or self.max_value_microunits != 0
        ):
            raise ValueError("candidate byte/value budget is invalid")
        if not isinstance(self.reversible, bool) or not isinstance(self.semantic_taint, bool):
            raise ValueError("candidate risk flags must be boolean")
        if not isinstance(self.producer_text_used, bool):
            raise ValueError("producer_text_used must be boolean")
        normalized: dict[str, float] = {}
        if not self.alignment or len(self.alignment) > 32:
            raise ValueError("candidate alignment must be bounded and non-empty")
        for name, value in self.alignment.items():
            key = _identifier("candidate alignment value", str(name))
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("candidate alignment must be numeric")
            numeric = float(value)
            if not isfinite(numeric) or not -1.0 <= numeric <= 1.0:
                raise ValueError("candidate alignment must be between -1 and 1")
            normalized[key] = numeric
        object.__setattr__(self, "alignment", normalized)
        for name in ("information_gain", "uncertainty"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"candidate {name} must be numeric")
            if not isfinite(float(value)) or not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"candidate {name} must be between 0 and 1")
        if (
            isinstance(self.time_cost, bool)
            or not isinstance(self.time_cost, (int, float))
            or not isfinite(float(self.time_cost))
            or float(self.time_cost) < 0.0
        ):
            raise ValueError("candidate time_cost must be non-negative")

    @property
    def scope(self) -> str:
        return f"{self.scope_root}/**"

    @property
    def digest(self) -> str:
        return _digest(
            {
                "id": self.id,
                "statement": self.statement,
                "rationale": self.rationale,
                "horizon": self.horizon,
                "alignment": dict(self.alignment),
                "required_receipt_ids": list(self.required_receipt_ids),
                "alternatives": [row.receipt_payload() for row in self.alternatives],
                "configuration_sha256": self.config.digest,
                "scope": self.scope,
                "expires_at": self.expires_at,
                "max_actions": self.max_actions,
                "max_bytes": self.max_bytes,
                "max_value_microunits": self.max_value_microunits,
                "information_gain": self.information_gain,
                "uncertainty": self.uncertainty,
                "time_cost": self.time_cost,
                "risk_class": self.risk_class,
                "reversible": self.reversible,
                "semantic_taint": self.semantic_taint,
                "derivation": self.derivation,
                "producer_text_used": self.producer_text_used,
            }
        )


@dataclass(frozen=True, slots=True)
class SelfGoalPreparation:
    policy_id: str
    candidate: SelfGoalCandidate
    goal_id: str
    portfolio_decision_id: str
    portfolio_decision_event_id: str
    goal_decision_id: str
    lease_id: str
    lease_event_id: str
    approval_event_id: str
    receipt_event_ids: tuple[str, ...]
    binding: PlanBinding


@dataclass(frozen=True, slots=True)
class SelfGoalEpisodeResult:
    preparation: SelfGoalPreparation
    episode: FullStackEpisodeResult
    terminal_event_id: str
    replayed: bool


class SelfGoalEpisodeCoordinator:
    """Select, lease, plan, and execute one metadata-grounded reversible self goal."""

    CAPABILITY_NAME = "self-goal.full-stack-local-fake"

    def __init__(
        self,
        store: EventStore,
        *,
        kernel: AgencyKernel,
        planner: AutonomyPlanner,
        policy_id: str,
        principal_id: str,
        candidates: Sequence[SelfGoalCandidate],
        authentication_secret: bytes,
        capability_name: str | None = None,
    ) -> None:
        self.store = store
        self.kernel = kernel
        self.planner = planner
        self.policy_id = _identifier("policy id", policy_id)
        self.principal_id = _identifier("principal id", principal_id)
        self.capability_name = _identifier(
            "capability name", capability_name or self.CAPABILITY_NAME
        )
        self.candidates = tuple(candidates)
        self.authentication_secret = authentication_secret
        if len(self.candidates) < 2 or len(self.candidates) > 16:
            raise ValueError("self-goal portfolio requires 2-16 candidates")
        if len({candidate.id for candidate in self.candidates}) != len(self.candidates):
            raise ValueError("self-goal candidate IDs must be unique")
        if not isinstance(authentication_secret, bytes) or len(authentication_secret) < 32:
            raise ValueError("authentication_secret must contain at least 32 bytes")
        if store.path.resolve() != kernel.store.path.resolve() or (
            store.path.resolve() != planner.store.path.resolve()
        ):
            raise ValueError("self-goal coordinator components must share one event store")

    def _record_receipts(
        self, receipts: Sequence[SelfGoalInputReceipt]
    ) -> dict[str, str]:
        rows = tuple(receipts)
        if len(rows) < 4 or len(rows) > 32 or len({row.id for row in rows}) != len(rows):
            raise SelfGoalDenied("AUTHENTICATED_RECEIPT_SET_INVALID")
        event_ids: dict[str, str] = {}
        for receipt in rows:
            if not isinstance(receipt, SelfGoalInputReceipt) or not receipt.verify(
                self.authentication_secret
            ):
                raise SelfGoalDenied("INPUT_RECEIPT_AUTHENTICATION_FAILED")
            payload = {
                **receipt.signed_payload(),
                "authenticated": True,
                "authentication_scheme": "HMAC-SHA256",
                "signature": receipt.signature,
                "instructions_authorized": False,
            }
            try:
                event, _ = self.store.append_once_result(
                    "autonomy.self_goal.input.recorded", receipt.id, payload
                )
            except ValueError as error:
                raise SelfGoalDenied("INPUT_RECEIPT_CONFLICT") from error
            if canonical_json(event.payload) != canonical_json(payload):
                raise SelfGoalDenied("INPUT_RECEIPT_CONFLICT")
            event_ids[receipt.id] = event.event_id
        return event_ids

    def _register_candidates(self, receipt_events: Mapping[str, str]) -> dict[str, str]:
        result: dict[str, str] = {}
        for candidate in self.candidates:
            required_events = [
                receipt_events[receipt_id]
                for receipt_id in candidate.required_receipt_ids
                if receipt_id in receipt_events
            ]
            payload = {
                "schema_version": 1,
                "candidate_id": candidate.id,
                "candidate_sha256": candidate.digest,
                "required_receipt_event_ids": required_events,
                "derivation": candidate.derivation,
                "producer_text_used": candidate.producer_text_used,
                "semantic_taint": candidate.semantic_taint,
                "risk_class": candidate.risk_class,
                "reversible": candidate.reversible,
                "scope": candidate.scope,
                "max_actions": candidate.max_actions,
                "max_bytes": candidate.max_bytes,
                "max_value_microunits": candidate.max_value_microunits,
                "configuration_sha256": candidate.config.digest,
                "goal_text_source": "host_registered_template",
                "raw_producer_content_persisted": False,
            }
            try:
                event, _ = self.store.append_once_result(
                    "autonomy.self_goal.candidate.registered",
                    f"{self.policy_id}:{candidate.id}",
                    payload,
                )
            except ValueError as error:
                raise SelfGoalDenied("SELF_GOAL_CANDIDATE_CONFLICT") from error
            if canonical_json(event.payload) != canonical_json(payload):
                raise SelfGoalDenied("SELF_GOAL_CANDIDATE_CONFLICT")
            result[candidate.id] = event.event_id
        return result

    def _portfolio_goal(self, receipt_event_ids: Sequence[str]) -> str:
        goal_id = f"goal-self-portfolio-{self.policy_id}"
        existing = self.kernel.goal(goal_id)
        if existing is None:
            self.kernel.form_goal(
                goal_id=goal_id,
                statement="Select one useful low-risk reversible objective from authenticated metadata receipts.",
                rationale="Bounded self-originated work must convert trusted metadata into verified outcomes without importing producer instructions.",
                source="self",
                horizon="long",
                alignment={"truth": 0.9, "competence": 0.9, "autonomy": 0.9, "care": 0.5},
                evidence=tuple(receipt_event_ids),
            )
        elif existing.source != "self" or existing.status != "active":
            raise SelfGoalDenied("SELF_GOAL_PORTFOLIO_GOAL_INVALID")
        return goal_id

    def _candidate_blockers(
        self,
        candidate: SelfGoalCandidate,
        receipt_by_id: Mapping[str, SelfGoalInputReceipt],
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        if any(receipt_id not in receipt_by_id for receipt_id in candidate.required_receipt_ids):
            reasons.append("AUTHENTICATED_RECEIPTS_MISSING")
        linked = [
            receipt_by_id[receipt_id]
            for receipt_id in candidate.required_receipt_ids
            if receipt_id in receipt_by_id
        ]
        if (
            candidate.semantic_taint
            or candidate.derivation != "host_template"
            or candidate.producer_text_used
            or any(receipt.semantic_taint for receipt in linked)
        ):
            reasons.append("SEMANTIC_TAINT_REJECTED")
        if candidate.risk_class != "reversible" or not candidate.reversible:
            reasons.append("LOW_RISK_REVERSIBLE_ONLY")
        if candidate.max_value_microunits != 0:
            reasons.append("FINANCIAL_VALUE_DENIED")
        return tuple(reasons)

    def _register_capability(self, allowed: Sequence[SelfGoalCandidate]) -> dict[str, object]:
        registry = CapabilityRegistry(self.store)
        specification = CapabilitySpec(
            name=self.capability_name,
            description="Execute one leased source-only full-stack episode through registered local fake adapters.",
            effect_kind="full_stack_local_fake",
            intent_domain="autonomy",
            intent_action="execute",
            risk_class="reversible",
            scopes=tuple(sorted(candidate.scope for candidate in allowed)),
            verifier_id="registered-full-stack-verifier",
            reversible=True,
            max_actions=max(candidate.max_actions for candidate in allowed),
            max_bytes=max(candidate.max_bytes for candidate in allowed),
            max_value_microunits=0,
            default_mode="require_approval",
        )
        return registry.register(
            specification,
            authority="host_adapter",
            evidence=(f"host-policy:{self.policy_id}",),
        )

    def prepare(
        self,
        receipts: Sequence[SelfGoalInputReceipt],
        *,
        seed: int,
        expected_principal_profile_digest: str | None = None,
    ) -> SelfGoalPreparation:
        """Authenticate inputs, choose genuine alternatives, and store one leased exact plan."""

        if expected_principal_profile_digest is not None:
            if not _DIGEST.fullmatch(expected_principal_profile_digest):
                raise SelfGoalDenied("PRINCIPAL_PROFILE_DIGEST_INVALID")
            if (
                PrincipalModel(self.store).status().get("profile_digest")
                != expected_principal_profile_digest
            ):
                raise SelfGoalDenied("PRINCIPAL_PROFILE_CHANGED")
        receipt_by_id = {receipt.id: receipt for receipt in receipts}
        receipt_events = self._record_receipts(receipts)
        candidate_events = self._register_candidates(receipt_events)
        receipt_event_ids = tuple(receipt_events[receipt.id] for receipt in receipts)
        portfolio_goal = self._portfolio_goal(receipt_event_ids)
        options: list[Option] = []
        allowed: list[SelfGoalCandidate] = []
        for candidate in self.candidates:
            blockers = self._candidate_blockers(candidate, receipt_by_id)
            if not blockers:
                allowed.append(candidate)
            options.append(
                Option(
                    id=candidate.id,
                    description=candidate.statement,
                    value_impacts=candidate.alignment,
                    information_gain=candidate.information_gain,
                    uncertainty=candidate.uncertainty,
                    time_cost=candidate.time_cost,
                    irreversible=not candidate.reversible,
                    blocked_reasons=blockers,
                    assumptions=(
                        f"candidate_sha256={candidate.digest}",
                        "producer_text_used=false",
                    ),
                )
            )
        if len(allowed) < 2:
            raise SelfGoalDenied("GENUINE_SELF_GOAL_ALTERNATIVES_REQUIRED")
        portfolio_decision_id = f"self-portfolio-{self.policy_id}"
        selection = self.kernel.deliberate(
            goal_id=portfolio_goal,
            options=options,
            seed=seed,
            decision_id=portfolio_decision_id,
        )
        selected_id = str(selection["chosen_option_id"])
        if selected_id == NO_OP_ID:
            raise SelfGoalDenied("NO_OP_SELECTED")
        selected = next((candidate for candidate in allowed if candidate.id == selected_id), None)
        if selected is None:
            raise SelfGoalDenied("BLOCKED_SELF_GOAL_SELECTED")

        capability = self._register_capability(allowed)
        selected_receipts = tuple(
            receipt_events[receipt_id] for receipt_id in selected.required_receipt_ids
        )
        lease = CapabilityLease(
            id=f"lease-self-{selected.id}",
            capability=self.capability_name,
            principal_id=self.principal_id,
            scopes=(selected.scope,),
            expires_at=selected.expires_at,
            max_actions=selected.max_actions,
            max_bytes=selected.max_bytes,
            max_value_microunits=0,
            issued_by="host_adapter",
            evidence=(
                *(f"event:{event_id}" for event_id in selected_receipts),
                f"event:{candidate_events[selected.id]}",
                f"event:{selection['event_id']}",
            ),
        )
        try:
            lease_receipt = CapabilityRegistry(self.store).grant(
                lease,
                expected_principal_profile_digest=expected_principal_profile_digest,
            )
        except (KeyError, ValueError) as error:
            raise SelfGoalDenied("SELF_GOAL_LEASE_DENIED") from error
        if expected_principal_profile_digest is not None and (
            PrincipalModel(self.store).status().get("profile_digest")
            != expected_principal_profile_digest
        ):
            CapabilityRegistry(self.store).revoke(
                lease.id,
                authority="host_adapter",
                reason="Principal profile changed before self-goal adoption.",
            )
            raise SelfGoalDenied("PRINCIPAL_PROFILE_CHANGED")
        goal_id = f"goal-self-{selected.id}"
        proposed = LeasedSelfGoal(
            id=goal_id,
            statement=selected.statement,
            rationale=selected.rationale,
            horizon=selected.horizon,
            alignment=selected.alignment,
            policy_id=self.policy_id,
            candidate_id=selected.id,
            candidate_event_id=candidate_events[selected.id],
            portfolio_decision_event_id=str(selection["event_id"]),
            lease_id=lease.id,
            lease_event_id=str(lease_receipt["event_id"]),
            capability_spec_digest=str(capability["spec_digest"]),
            receipt_event_ids=selected_receipts,
            scope=selected.scope,
            expires_at=selected.expires_at,
            max_actions=selected.max_actions,
            max_bytes=selected.max_bytes,
        )
        try:
            approval = self.planner.adopt_self_goal(proposed)
        except PlanningDenied as error:
            raise SelfGoalDenied(error.reason_code) from error
        goal_decision_id = f"decision-self-{selected.id}"
        try:
            choice = self.planner.make_choice(
                goal_id=goal_id,
                alternatives=selected.alternatives,
                seed=seed,
                decision_id=goal_decision_id,
            )
        except PlanningDenied as error:
            raise SelfGoalDenied(error.reason_code) from error
        except ValueError as error:
            # A duplicate wake can arrive after the exact episode completed and
            # changed the goal out of active state. Replay the hash-validated
            # persisted choice; candidate append-once checks above already bind
            # the current alternatives/configuration to the original digest.
            if "goal is not active" not in str(error):
                raise
            try:
                replay = self.planner.replay_choice(goal_decision_id)
            except KeyError as replay_error:
                raise SelfGoalDenied("SELF_GOAL_DECISION_REPLAY_MISSING") from replay_error
            if replay.get("matches") is not True:
                raise SelfGoalDenied("SELF_GOAL_DECISION_REPLAY_INVALID") from error
            decision_event = self.store.event(str(replay["receipt_event_id"]))
            if decision_event is None:
                raise SelfGoalDenied("SELF_GOAL_DECISION_REPLAY_MISSING") from error
            choice = {
                **decision_event.payload,
                "event_id": decision_event.event_id,
                "created": False,
            }
        chosen_id = str(choice["chosen_branch"]["id"])
        if chosen_id == NO_OP_ID:
            raise SelfGoalDenied("SELF_GOAL_PLAN_NO_OP_SELECTED")
        config = selected.config
        stages: list[PlanStage] = []
        previous: str | None = None
        for stage_id in config.stage_ids:
            stages.append(
                PlanStage(
                    id=stage_id,
                    summary=f"Execute leased bounded {stage_id} stage.",
                    depends_on=((previous,) if previous else ()),
                    handoff=StageHandoff(
                        capability=f"self-goal.{stage_id}",
                        tool_name=config.tool_name(stage_id),
                        scope=f"{selected.scope_root}/{stage_id}",
                        arguments_sha256=config.arguments_sha256(stage_id),
                    ),
                )
            )
            previous = stage_id
        plan = HierarchicalPlan(
            id=f"plan-self-{selected.id}",
            goal_id=goal_id,
            decision_id=goal_decision_id,
            chosen_option_id=chosen_id,
            summary="Execute one leased metadata-grounded reversible full-stack episode.",
            stages=tuple(stages),
        )
        try:
            binding = self.planner.store_plan(plan)["binding"]
        except PlanningDenied as error:
            raise SelfGoalDenied(error.reason_code) from error
        return SelfGoalPreparation(
            policy_id=self.policy_id,
            candidate=selected,
            goal_id=goal_id,
            portfolio_decision_id=portfolio_decision_id,
            portfolio_decision_event_id=str(selection["event_id"]),
            goal_decision_id=goal_decision_id,
            lease_id=lease.id,
            lease_event_id=str(lease_receipt["event_id"]),
            approval_event_id=str(approval["event_id"]),
            receipt_event_ids=selected_receipts,
            binding=binding,
        )

    def run_prepared(
        self,
        preparation: SelfGoalPreparation,
        *,
        research: BoundedResearchAdapter,
        commands: BoundedCommandAdapter,
        patching: ExpectedHashPatchAdapter,
        verifier: HostRegisteredVerifier,
        deployment: LocalFakeDeploymentAdapter,
        public_actions: LocalFakePublicActionAdapter,
        claim_fault_hook=None,
        fault_hook=None,
    ) -> SelfGoalEpisodeResult:
        """Execute/replay one exact prepared plan through all registered adapters."""

        if preparation.policy_id != self.policy_id:
            raise SelfGoalDenied("SELF_GOAL_POLICY_MISMATCH")
        authorization = self.planner.self_goal_authorization(preparation.goal_id)
        if authorization["active"] is not True:
            if authorization["reason"] == "SELF_GOAL_LEASE_EXPIRED":
                expiry = self.store.append_once(
                    "autonomy.self_goal.lease.expired",
                    preparation.lease_id,
                    {
                        "schema_version": 1,
                        "policy_id": self.policy_id,
                        "candidate_id": preparation.candidate.id,
                        "goal_id": preparation.goal_id,
                        "lease_id": preparation.lease_id,
                        "expires_at": preparation.candidate.expires_at,
                        "adapter_effects": 0,
                    },
                )
                current = self.kernel.goal(preparation.goal_id)
                if current is not None and current.status == "active":
                    self.kernel.set_goal_status(
                        preparation.goal_id,
                        "paused",
                        f"Self-goal lease expired before adapter execution: {expiry.event_id}.",
                    )
            raise SelfGoalDenied(str(authorization["reason"]))
        if authorization.get("lease_id") != preparation.lease_id:
            raise SelfGoalDenied("SELF_GOAL_LEASE_MISMATCH")
        runner = FullStackEpisodeRunner(
            self.store,
            kernel=self.kernel,
            planner=self.planner,
            research=research,
            commands=commands,
            patching=patching,
            verifier=verifier,
            deployment=deployment,
            public_actions=public_actions,
            spec=FullStackEpisodeSpec(
                id=f"episode-self-{preparation.candidate.id}",
                binding=preparation.binding,
                worker_id="self-goal-worker",
                config=preparation.candidate.config,
            ),
            claim_fault_hook=claim_fault_hook,
            fault_hook=fault_hook,
        )
        try:
            episode = runner.run()
        except PlanningDenied as error:
            raise SelfGoalDenied(error.reason_code) from error
        payload = {
            "schema_version": 1,
            "policy_id": self.policy_id,
            "candidate_id": preparation.candidate.id,
            "goal_id": preparation.goal_id,
            "portfolio_decision_event_id": preparation.portfolio_decision_event_id,
            "goal_approval_event_id": preparation.approval_event_id,
            "lease_id": preparation.lease_id,
            "lease_event_id": preparation.lease_event_id,
            "plan_id": preparation.binding.plan_id,
            "plan_sha256": preparation.binding.plan_sha256,
            "episode_terminal_event_id": episode.terminal_event_id,
            "outcome_event_id": episode.outcome_event_id,
            "reflection_event_id": episode.reflection_event_id,
            "status": episode.status,
            "adapter_effects": len(episode.completed_stage_ids),
            "exact_scope": preparation.candidate.scope,
            "action_budget": preparation.candidate.max_actions,
            "byte_budget": preparation.candidate.max_bytes,
            "value_budget_microunits": 0,
            "external_effects": 0,
            "raw_producer_content_persisted": False,
        }
        try:
            terminal, created = self.store.append_once_result(
                "autonomy.self_goal.episode.terminal",
                preparation.candidate.id,
                payload,
            )
        except ValueError as error:
            raise SelfGoalDenied("SELF_GOAL_TERMINAL_CONFLICT") from error
        if canonical_json(terminal.payload) != canonical_json(payload):
            raise SelfGoalDenied("SELF_GOAL_TERMINAL_CONFLICT")
        return SelfGoalEpisodeResult(
            preparation=preparation,
            episode=episode,
            terminal_event_id=terminal.event_id,
            replayed=episode.replayed or not created,
        )
