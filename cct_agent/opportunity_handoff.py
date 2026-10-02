"""Bind authenticated operator interest to separately leased local execution.

Operator interest is conversational direction, never effect authority. This module only
hands an opportunity to the existing self-goal/full-stack runner when a host-signed
metadata receipt and an independently active reversible zero-value lease both bind the
same immutable opportunity presentation and feedback events.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Sequence

from .commands import BoundedCommandAdapter
from .deployment import LocalFakeDeploymentAdapter
from .patching import ExpectedHashPatchAdapter
from .principal import PrincipalModel
from .public_actions import LocalFakePublicActionAdapter
from .research import BoundedResearchAdapter
from .self_goals import (
    SelfGoalDenied,
    SelfGoalEpisodeCoordinator,
    SelfGoalEpisodeResult,
    SelfGoalInputReceipt,
    SelfGoalPreparation,
)
from .store import Event, EventStore, canonical_json
from .verification import HostRegisteredVerifier


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_INTEREST_DECISIONS = {"ACCEPT", "INTERESTED"}


class OpportunityTaskHandoffDenied(RuntimeError):
    """Fail-closed opportunity-to-task handoff decision."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class OpportunityInterestBinding:
    opportunity_id: str
    registration_event_id: str
    presentation_event_id: str
    feedback_event_id: str
    principal_id: str
    principal_profile_digest: str
    decision: str
    digest: str


@dataclass(frozen=True, slots=True)
class OpportunityTaskPreparation:
    interest: OpportunityInterestBinding
    self_goal: SelfGoalPreparation
    claim_event_id: str
    handoff_event_id: str


@dataclass(frozen=True, slots=True)
class OpportunityTaskResult:
    preparation: OpportunityTaskPreparation
    episode: SelfGoalEpisodeResult
    terminal_event_id: str
    replayed: bool


class OpportunityTaskHandoff:
    """Turn exact operator interest plus a separate host lease into one task run."""

    def __init__(self, store: EventStore, *, principal_id: str) -> None:
        self.store = store
        self.principal_id = _identifier("principal id", principal_id)

    @staticmethod
    def _opportunity(events: Sequence[Event], opportunity_id: str) -> tuple[Event, str]:
        registration: Event | None = None
        status = ""
        for event in events:
            if event.kind in {
                "autonomy.opportunity.registered",
                "opportunity.initiative.goal_candidate.created",
            } and event.payload.get("opportunity_id") == opportunity_id:
                registration = event
                status = str(event.payload.get("status", "open"))
            elif (
                event.kind == "autonomy.opportunity.status_changed"
                and event.payload.get("opportunity_id") == opportunity_id
            ):
                status = str(event.payload.get("to", ""))
        if registration is None:
            raise OpportunityTaskHandoffDenied("OPPORTUNITY_NOT_FOUND")
        return registration, status

    def inspect_interest(
        self, *, opportunity_id: str, feedback_event_id: str
    ) -> OpportunityInterestBinding:
        """Validate one immutable presented-interest receipt without granting authority."""

        opportunity_identifier = _identifier("opportunity id", opportunity_id)
        feedback_identifier = _identifier("feedback event id", feedback_event_id)
        events = self.store.events()
        registration, status = self._opportunity(events, opportunity_identifier)
        if status != "open":
            raise OpportunityTaskHandoffDenied("OPPORTUNITY_NOT_OPEN")
        feedback = self.store.event(feedback_identifier)
        if feedback is None or feedback.kind != "opportunity.initiative.feedback":
            raise OpportunityTaskHandoffDenied("INTEREST_FEEDBACK_NOT_FOUND")
        payload = feedback.payload
        if payload.get("opportunity_id") != opportunity_identifier:
            raise OpportunityTaskHandoffDenied("INTEREST_OPPORTUNITY_MISMATCH")
        decision = str(payload.get("decision", ""))
        if decision not in _INTEREST_DECISIONS or payload.get("operator_interest_recorded") is not True:
            raise OpportunityTaskHandoffDenied("OPERATOR_INTEREST_REQUIRED")
        if payload.get("source_authority") not in {"operator", "host_adapter"}:
            raise OpportunityTaskHandoffDenied("INTEREST_AUTHORITY_INVALID")
        if payload.get("principal_id") != self.principal_id:
            raise OpportunityTaskHandoffDenied("INTEREST_PRINCIPAL_MISMATCH")
        if (
            payload.get("execution_authority_granted") is not False
            or payload.get("capability_lease_changed") is not False
            or payload.get("opportunity_execution_status_changed") is not False
            or payload.get("external_effects") != 0
        ):
            raise OpportunityTaskHandoffDenied("INTEREST_RECEIPT_OVERCLAIMS_AUTHORITY")
        presentation_event_id = str(payload.get("presentation_event_id", ""))
        presentation = self.store.event(presentation_event_id)
        if (
            presentation is None
            or presentation.kind != "opportunity.initiative.completed"
            or presentation.payload.get("opportunity_id") != opportunity_identifier
            or presentation.payload.get("emitted") is not True
        ):
            raise OpportunityTaskHandoffDenied("INTEREST_PRESENTATION_INVALID")
        principal_status = PrincipalModel(self.store).status()
        profile = principal_status.get("profile")
        profile_digest = principal_status.get("profile_digest")
        presented_principal = presentation.payload.get("principal")
        if (
            not principal_status.get("profile_installed")
            or not isinstance(profile, dict)
            or profile.get("principal_id") != self.principal_id
            or not isinstance(profile_digest, str)
            or not isinstance(presented_principal, dict)
            or presented_principal.get("principal_id") != self.principal_id
            or presented_principal.get("profile_digest") != profile_digest
            or payload.get("principal_profile_digest") != profile_digest
        ):
            raise OpportunityTaskHandoffDenied("INTEREST_PRINCIPAL_PROFILE_STALE")
        binding_payload = {
            "schema_version": 1,
            "opportunity_id": opportunity_identifier,
            "registration_event_id": registration.event_id,
            "registration_sha256": _digest(registration.payload),
            "presentation_event_id": presentation.event_id,
            "feedback_event_id": feedback.event_id,
            "feedback_sha256": _digest(feedback.payload),
            "principal_id": self.principal_id,
            "principal_profile_digest": profile_digest,
            "decision": decision,
            "interest_grants_execution_authority": False,
            "producer_content_used": False,
        }
        return OpportunityInterestBinding(
            opportunity_id=opportunity_identifier,
            registration_event_id=registration.event_id,
            presentation_event_id=presentation.event_id,
            feedback_event_id=feedback.event_id,
            principal_id=self.principal_id,
            principal_profile_digest=profile_digest,
            decision=decision,
            digest=_digest(binding_payload),
        )

    def prepare(
        self,
        owner: SelfGoalEpisodeCoordinator,
        *,
        opportunity_id: str,
        feedback_event_id: str,
        receipts: Sequence[SelfGoalInputReceipt],
        seed: int,
    ) -> OpportunityTaskPreparation:
        """Require a host-signed interest binding before the owner can issue a lease."""

        if owner.store.path.resolve() != self.store.path.resolve():
            raise ValueError("opportunity handoff and self-goal owner must share one event store")
        interest = self.inspect_interest(
            opportunity_id=opportunity_id, feedback_event_id=feedback_event_id
        )
        rows = tuple(receipts)
        interest_receipts = tuple(
            receipt
            for receipt in rows
            if receipt.kind == "opportunity"
            and receipt.subject_id == interest.opportunity_id
            and receipt.content_sha256 == interest.digest
            and receipt.issued_by == "host_adapter"
            and receipt.semantic_taint is False
            and receipt.raw_content_persisted is False
            and receipt.verify(owner.authentication_secret)
        )
        if len(interest_receipts) != 1:
            raise OpportunityTaskHandoffDenied("HOST_INTEREST_BINDING_REQUIRED")
        interest_receipt = interest_receipts[0]
        allowed_candidates = tuple(
            candidate
            for candidate in owner.candidates
            if candidate.semantic_taint is False
            and candidate.derivation == "host_template"
            and candidate.producer_text_used is False
            and candidate.risk_class == "reversible"
            and candidate.reversible is True
            and candidate.max_value_microunits == 0
        )
        if len(allowed_candidates) < 2 or any(
            interest_receipt.id not in candidate.required_receipt_ids
            for candidate in allowed_candidates
        ):
            raise OpportunityTaskHandoffDenied("HOST_POLICY_NOT_BOUND_TO_INTEREST")
        claim_payload = {
            "schema_version": 1,
            "opportunity_id": interest.opportunity_id,
            "registration_event_id": interest.registration_event_id,
            "presentation_event_id": interest.presentation_event_id,
            "feedback_event_id": interest.feedback_event_id,
            "interest_binding_sha256": interest.digest,
            "principal_id": interest.principal_id,
            "principal_profile_digest": interest.principal_profile_digest,
            "policy_id": owner.policy_id,
            "capability_name": owner.capability_name,
            "candidate_portfolio_sha256": _digest(
                [
                    {"candidate_id": candidate.id, "candidate_sha256": candidate.digest}
                    for candidate in owner.candidates
                ]
            ),
            "receipt_set_sha256": _digest(
                [receipt.signed_payload() | {"signature": receipt.signature} for receipt in rows]
            ),
            "interest_receipt_id": interest_receipt.id,
            "interest_granted_execution_authority": False,
            "external_effects": 0,
            "raw_producer_content_persisted": False,
        }

        def claim_guard(events: list[Event]) -> str | None:
            principal = next(
                (
                    event
                    for event in reversed(events)
                    if event.kind == "principal.profile.installed"
                ),
                None,
            )
            if (
                principal is None
                or principal.payload.get("profile_digest")
                != interest.principal_profile_digest
            ):
                return "INTEREST_PRINCIPAL_PROFILE_STALE"
            try:
                registration, status = self._opportunity(events, interest.opportunity_id)
            except OpportunityTaskHandoffDenied:
                return "OPPORTUNITY_NOT_FOUND"
            if registration.event_id != interest.registration_event_id or status != "open":
                return "OPPORTUNITY_NOT_OPEN"
            feedback = next(
                (event for event in events if event.event_id == interest.feedback_event_id),
                None,
            )
            current_feedback = self.store.event(interest.feedback_event_id)
            if (
                feedback is None
                or current_feedback is None
                or feedback.kind != "opportunity.initiative.feedback"
                or _digest(feedback.payload) != _digest(current_feedback.payload)
            ):
                return "INTEREST_BINDING_CHANGED"
            return None

        try:
            claim, _, rejection = self.store.append_once_result_guarded(
                "opportunity.initiative.task_handoff.claimed",
                interest.feedback_event_id,
                claim_payload,
                guard=claim_guard,
                strict_existing_payload=True,
            )
        except ValueError as error:
            raise OpportunityTaskHandoffDenied("OPPORTUNITY_TASK_CLAIM_CONFLICT") from error
        if rejection is not None or claim is None:
            raise OpportunityTaskHandoffDenied(
                str(rejection or "OPPORTUNITY_TASK_CLAIM_DENIED")
            )
        try:
            self_goal = owner.prepare(
                rows,
                seed=seed,
                expected_principal_profile_digest=interest.principal_profile_digest,
            )
        except SelfGoalDenied as error:
            raise OpportunityTaskHandoffDenied(error.reason_code) from error
        current_interest = self.inspect_interest(
            opportunity_id=interest.opportunity_id,
            feedback_event_id=interest.feedback_event_id,
        )
        if current_interest.digest != interest.digest:
            raise OpportunityTaskHandoffDenied("INTEREST_BINDING_CHANGED")
        if interest_receipt.id not in self_goal.candidate.required_receipt_ids:
            raise OpportunityTaskHandoffDenied("SELECTED_GOAL_NOT_BOUND_TO_INTEREST")
        authorization = owner.planner.self_goal_authorization(self_goal.goal_id)
        if authorization.get("active") is not True or authorization.get("lease_id") != self_goal.lease_id:
            raise OpportunityTaskHandoffDenied("SEPARATE_CAPABILITY_LEASE_REQUIRED")
        interest_receipt_event = next(
            (
                event
                for event in reversed(
                    self.store.events("autonomy.self_goal.input.recorded")
                )
                if event.payload.get("receipt_id") == interest_receipt.id
            ),
            None,
        )
        if interest_receipt_event is None:
            raise OpportunityTaskHandoffDenied("HOST_INTEREST_RECEIPT_MISSING")
        handoff_id = "opportunity-task-" + interest.digest[:24]
        handoff_payload = {
            "schema_version": 1,
            "handoff_id": handoff_id,
            "opportunity_id": interest.opportunity_id,
            "registration_event_id": interest.registration_event_id,
            "presentation_event_id": interest.presentation_event_id,
            "feedback_event_id": interest.feedback_event_id,
            "claim_event_id": claim.event_id,
            "interest_binding_sha256": interest.digest,
            "interest_receipt_event_id": interest_receipt_event.event_id,
            "principal_id": interest.principal_id,
            "principal_profile_digest": interest.principal_profile_digest,
            "policy_id": self_goal.policy_id,
            "candidate_id": self_goal.candidate.id,
            "candidate_sha256": self_goal.candidate.digest,
            "goal_id": self_goal.goal_id,
            "lease_id": self_goal.lease_id,
            "lease_event_id": self_goal.lease_event_id,
            "plan_id": self_goal.binding.plan_id,
            "plan_sha256": self_goal.binding.plan_sha256,
            "interest_granted_execution_authority": False,
            "execution_authority_source": "separate_host_policy_capability_lease",
            "external_effects": 0,
            "raw_producer_content_persisted": False,
        }
        try:
            event, _ = self.store.append_once_result(
                "opportunity.initiative.task_handoff.prepared",
                interest.feedback_event_id,
                handoff_payload,
            )
        except ValueError as error:
            raise OpportunityTaskHandoffDenied("OPPORTUNITY_TASK_HANDOFF_CONFLICT") from error
        if canonical_json(event.payload) != canonical_json(handoff_payload):
            raise OpportunityTaskHandoffDenied("OPPORTUNITY_TASK_HANDOFF_CONFLICT")
        return OpportunityTaskPreparation(
            interest=interest,
            self_goal=self_goal,
            claim_event_id=claim.event_id,
            handoff_event_id=event.event_id,
        )

    def run_prepared(
        self,
        owner: SelfGoalEpisodeCoordinator,
        preparation: OpportunityTaskPreparation,
        *,
        research: BoundedResearchAdapter,
        commands: BoundedCommandAdapter,
        patching: ExpectedHashPatchAdapter,
        verifier: HostRegisteredVerifier,
        deployment: LocalFakeDeploymentAdapter,
        public_actions: LocalFakePublicActionAdapter,
        claim_fault_hook=None,
        fault_hook=None,
    ) -> OpportunityTaskResult:
        """Execute/replay only while interest and the separate lease remain exact."""

        from .recurrent import _AuthenticatedMetadataResearchAdapter

        if type(research) not in {
            BoundedResearchAdapter,
            _AuthenticatedMetadataResearchAdapter,
        }:
            raise OpportunityTaskHandoffDenied("RESEARCH_ADAPTER_NOT_EXACT_BOUNDED")
        if type(commands) is not BoundedCommandAdapter:
            raise OpportunityTaskHandoffDenied("COMMAND_ADAPTER_NOT_EXACT_BOUNDED")
        if type(patching) is not ExpectedHashPatchAdapter:
            raise OpportunityTaskHandoffDenied("PATCH_ADAPTER_NOT_EXACT_BOUNDED")
        if type(verifier) is not HostRegisteredVerifier:
            raise OpportunityTaskHandoffDenied("VERIFIER_NOT_EXACT_HOST_REGISTERED")
        if type(deployment) is not LocalFakeDeploymentAdapter:
            raise OpportunityTaskHandoffDenied("DEPLOYMENT_ADAPTER_NOT_LOCAL_FAKE")
        if type(public_actions) is not LocalFakePublicActionAdapter:
            raise OpportunityTaskHandoffDenied("PUBLIC_ACTION_ADAPTER_NOT_LOCAL_FAKE")
        current = self.inspect_interest(
            opportunity_id=preparation.interest.opportunity_id,
            feedback_event_id=preparation.interest.feedback_event_id,
        )
        if current.digest != preparation.interest.digest:
            raise OpportunityTaskHandoffDenied("INTEREST_BINDING_CHANGED")
        handoff = self.store.event(preparation.handoff_event_id)
        claim = self.store.event(preparation.claim_event_id)
        if (
            handoff is None
            or handoff.kind != "opportunity.initiative.task_handoff.prepared"
            or handoff.payload.get("interest_binding_sha256") != current.digest
            or claim is None
            or claim.kind != "opportunity.initiative.task_handoff.claimed"
            or handoff.payload.get("claim_event_id") != claim.event_id
            or claim.payload.get("interest_binding_sha256") != current.digest
        ):
            raise OpportunityTaskHandoffDenied("OPPORTUNITY_TASK_HANDOFF_INVALID")
        expected = {
            "policy_id": preparation.self_goal.policy_id,
            "candidate_id": preparation.self_goal.candidate.id,
            "candidate_sha256": preparation.self_goal.candidate.digest,
            "goal_id": preparation.self_goal.goal_id,
            "lease_id": preparation.self_goal.lease_id,
            "lease_event_id": preparation.self_goal.lease_event_id,
            "plan_id": preparation.self_goal.binding.plan_id,
            "plan_sha256": preparation.self_goal.binding.plan_sha256,
        }
        if any(handoff.payload.get(key) != value for key, value in expected.items()):
            raise OpportunityTaskHandoffDenied("OPPORTUNITY_TASK_PREPARATION_MISMATCH")
        authorization = owner.planner.self_goal_authorization(preparation.self_goal.goal_id)
        if (
            authorization.get("active") is not True
            or authorization.get("lease_id") != preparation.self_goal.lease_id
        ):
            raise OpportunityTaskHandoffDenied("SEPARATE_CAPABILITY_LEASE_REQUIRED")
        def guarded_claim_hook(stage_id: str, claim_event_id: str) -> None:
            if claim_fault_hook is not None:
                claim_fault_hook(stage_id, claim_event_id)
            stage_interest = self.inspect_interest(
                opportunity_id=preparation.interest.opportunity_id,
                feedback_event_id=preparation.interest.feedback_event_id,
            )
            if stage_interest.digest != preparation.interest.digest:
                raise OpportunityTaskHandoffDenied("INTEREST_BINDING_CHANGED")
            stage_authorization = owner.planner.self_goal_authorization(
                preparation.self_goal.goal_id
            )
            if (
                stage_authorization.get("active") is not True
                or stage_authorization.get("lease_id")
                != preparation.self_goal.lease_id
            ):
                raise OpportunityTaskHandoffDenied(
                    "SEPARATE_CAPABILITY_LEASE_REQUIRED"
                )

        episode = owner.run_prepared(
            preparation.self_goal,
            research=research,
            commands=commands,
            patching=patching,
            verifier=verifier,
            deployment=deployment,
            public_actions=public_actions,
            claim_fault_hook=guarded_claim_hook,
            fault_hook=fault_hook,
        )
        payload = {
            "schema_version": 1,
            "handoff_event_id": preparation.handoff_event_id,
            "opportunity_id": current.opportunity_id,
            "feedback_event_id": current.feedback_event_id,
            "interest_binding_sha256": current.digest,
            "goal_id": preparation.self_goal.goal_id,
            "lease_id": preparation.self_goal.lease_id,
            "episode_terminal_event_id": episode.terminal_event_id,
            "outcome_event_id": episode.episode.outcome_event_id,
            "reflection_event_id": episode.episode.reflection_event_id,
            "status": episode.episode.status,
            "adapter_effects": len(episode.episode.completed_stage_ids),
            "interest_granted_execution_authority": False,
            "execution_authority_source": "separate_host_policy_capability_lease",
            "external_effects": 0,
            "raw_producer_content_persisted": False,
        }
        try:
            terminal, created = self.store.append_once_result(
                "opportunity.initiative.task_handoff.completed",
                current.feedback_event_id,
                payload,
            )
        except ValueError as error:
            raise OpportunityTaskHandoffDenied("OPPORTUNITY_TASK_TERMINAL_CONFLICT") from error
        if canonical_json(terminal.payload) != canonical_json(payload):
            raise OpportunityTaskHandoffDenied("OPPORTUNITY_TASK_TERMINAL_CONFLICT")
        return OpportunityTaskResult(
            preparation=preparation,
            episode=episode,
            terminal_event_id=terminal.event_id,
            replayed=episode.replayed or not created,
        )


__all__ = [
    "OpportunityInterestBinding",
    "OpportunityTaskHandoff",
    "OpportunityTaskHandoffDenied",
    "OpportunityTaskPreparation",
    "OpportunityTaskResult",
]
