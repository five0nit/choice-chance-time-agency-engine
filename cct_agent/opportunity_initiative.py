"""Principal-aligned proactive presentation of persistent CCT opportunities.

Opportunity presentation is conversational initiative, not effect authorization. A
model/self proposal may be surfaced to the operator, but ACCEPT records interest
only. Existing host/operator opportunity plans still require the AutonomyEngine's
selection, budgets, executor, verification, and receipt gates.
"""

from __future__ import annotations

from datetime import date
from hashlib import sha256
from math import isfinite
import re
from typing import Any, Iterable, Mapping, Sequence
import unicodedata

from .principal import PrincipalIntent, PrincipalModel
from .proactive import InitiationSignals, ProactiveEngine, ThoughtPacket
from .store import Event, EventStore, canonical_json


_FEEDBACK = {
    "ACCEPT",
    "DECLINE",
    "INTERESTED",
    "SKIP",
    "SNOOZE",
    "DONE",
    "BLOCKED",
}
_TERMINAL_FEEDBACK = _FEEDBACK - {"SNOOZE"}
_INTEREST_FEEDBACK = {"ACCEPT", "INTERESTED"}
_STOP_FEEDBACK = {"DECLINE", "SKIP", "DONE", "BLOCKED"}
_OUTCOME_FEEDBACK = {"DONE", "BLOCKED"}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_EVIDENCE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]{1,400}$")
_ACTION_VERBS = {
    "advance",
    "apply",
    "build",
    "compare",
    "complete",
    "convert",
    "create",
    "deliver",
    "deploy",
    "diagnose",
    "fix",
    "investigate",
    "maintain",
    "originate",
    "publish",
    "repair",
    "review",
    "run",
    "select",
    "submit",
    "verify",
}
_EVIDENCE_ANCHOR = re.compile(
    r"(?:https?://|\b\d{4}-\d{2}-\d{2}\b|\bA?\$\s?\d|\b[0-9a-f]{7,40}\b|\b\d{5,}\b|(?:^|\s)/(?:[^\s/]+/)+[^\s]+)",
    re.IGNORECASE,
)
_EVIDENCE_ANCHOR_PREFIXES = (
    "event:",
    "receipt:",
    "live:",
    "runtime:",
    "tool:pytest",
    "tool:ci",
)


def _identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{name} must be a bounded identifier")
    return value.strip()


def _evidence_refs(values: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise ValueError("feedback evidence must be an array")
    rows = tuple(str(value).strip() for value in values)
    if not rows or len(rows) > 8 or any(not _EVIDENCE.fullmatch(row) for row in rows):
        raise ValueError("feedback evidence must contain 1-8 opaque URI-style references")
    return rows


def _visible(value: object, *, maximum: int) -> str:
    """Normalize visible proposal text and remove control/bidirectional characters."""

    normalized = unicodedata.normalize("NFKC", str(value))
    cleaned = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in normalized
    )
    return " ".join(cleaned.split())[:maximum].strip()


def _unit(value: Any, *, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if not isfinite(number):
        return default
    return max(0.0, min(1.0, number))


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _anchored_evidence(value: str) -> bool:
    lowered = value.casefold()
    return lowered.startswith(_EVIDENCE_ANCHOR_PREFIXES) or bool(
        _EVIDENCE_ANCHOR.search(value)
    )


def _receipt_objective(action: str) -> str:
    if action in {"apply", "submit"}:
        return "Produce an authoritative application/submission receipt or the exact blocker."
    if action in {"build", "create", "convert"}:
        return "Produce the artifact path, SHA-256, and a passing verification receipt."
    if action in {"fix", "repair"}:
        return "Produce before/after failing-and-passing verification evidence."
    if action in {"publish", "deploy"}:
        return "Produce provider/public readback or stop at the required approval boundary."
    if action in {"run", "verify"}:
        return "Produce the exact command/check result and a stable receipt reference."
    if action in {"review", "compare", "investigate", "diagnose"}:
        return "Produce a cited decision receipt naming the finding and next bounded action."
    return "Produce one new verifiable evidence receipt tied directly to this active goal."


def _parse_bucket(value: str, *, strict: bool = False) -> date | None:
    try:
        return date.fromisoformat(str(value))
    except ValueError as error:
        if strict:
            raise ValueError("time bucket must be an ISO-8601 calendar date") from error
        return None


class OpportunityInitiative:
    """Select and proactively surface one opportunity through existing SEND/WAIT gates."""

    def __init__(
        self,
        store: EventStore,
        *,
        proactive: ProactiveEngine | None = None,
    ) -> None:
        self.store = store
        self.proactive = proactive or ProactiveEngine(store)

    # ------------------------------------------------------------------
    # Event projections
    # ------------------------------------------------------------------
    def _opportunities(self, events: Iterable[Event] | None = None) -> list[dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        source = list(events) if events is not None else self.store.events()
        for event in source:
            if event.kind in {
                "autonomy.opportunity.registered",
                "opportunity.initiative.goal_candidate.created",
            }:
                identifier = str(event.payload["opportunity_id"])
                rows[identifier] = {
                    **dict(event.payload),
                    "registration_event_id": event.event_id,
                    "registration_seq": event.seq,
                    "registered_at": event.occurred_at,
                }
            elif event.kind == "autonomy.opportunity.status_changed":
                identifier = str(event.payload["opportunity_id"])
                if identifier in rows:
                    rows[identifier]["status"] = str(event.payload["to"])
                    rows[identifier]["last_run_id"] = event.payload.get("run_id")
        return [rows[key] for key in sorted(rows)]

    @staticmethod
    def _feedback_rows(
        events: Iterable[Event], opportunity_id: str
    ) -> list[Event]:
        return [
            event
            for event in events
            if event.kind == "opportunity.initiative.feedback"
            and event.payload.get("opportunity_id") == opportunity_id
        ]

    @staticmethod
    def _completion_rows(
        events: Iterable[Event], opportunity_id: str
    ) -> list[Event]:
        return [
            event
            for event in events
            if event.kind == "opportunity.initiative.completed"
            and event.payload.get("opportunity_id") == opportunity_id
        ]

    def _principal_digest(self) -> str | None:
        return PrincipalModel(self.store).status()["profile_digest"]

    @staticmethod
    def _state_token(
        opportunity: Mapping[str, Any],
        *,
        profile_digest: str | None,
        feedback: Event | None,
    ) -> str:
        return _digest(
            {
                "opportunity_id": opportunity["opportunity_id"],
                "registration_event_id": opportunity["registration_event_id"],
                "principal_profile_digest": profile_digest,
                "feedback_event_id": feedback.event_id if feedback else None,
            }
        )

    @staticmethod
    def _priority(opportunity: Mapping[str, Any]) -> float:
        impacts = [
            _unit(value)
            for value in dict(opportunity.get("value_impacts", {})).values()
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        ]
        value_score = sum(impacts) / len(impacts) if impacts else 0.0
        information = _unit(opportunity.get("information_gain"))
        certainty = 1.0 - _unit(opportunity.get("uncertainty"), default=1.0)
        time_cost = max(0.0, float(opportunity.get("time_cost", 0.0)))
        ease = 1.0 - min(1.0, time_cost / 10.0)
        source_bonus = 0.08 if opportunity.get("source_authority") in {"host_adapter", "operator"} else 0.0
        return round(0.42 * value_score + 0.24 * information + 0.18 * certainty + 0.08 * ease + source_bonus, 12)

    @staticmethod
    def _goal_rows(events: Iterable[Event]) -> dict[str, dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        for event in events:
            if event.kind == "goal.formed":
                goal = dict(event.payload.get("goal", {}))
                identifier = str(goal.get("id", ""))
                if identifier:
                    rows[identifier] = {
                        **goal,
                        "formed_event_id": event.event_id,
                        "formed_at": event.occurred_at,
                    }
            elif event.kind == "goal.status_changed":
                identifier = str(event.payload.get("goal_id", ""))
                if identifier in rows:
                    rows[identifier]["status"] = str(event.payload.get("to", ""))
        return rows

    @classmethod
    def _active_goal_ids(cls, events: Iterable[Event]) -> set[str]:
        return {
            identifier
            for identifier, row in cls._goal_rows(events).items()
            if row.get("status") == "active"
        }

    def _materialize_goal_candidates(self) -> dict[str, Any]:
        """Create deterministic proposal-only candidates from uncovered active goals."""

        profile = PrincipalModel(self.store).status()
        if not profile["profile_installed"]:
            return {"created": 0, "eligible_goals": 0, "llm_calls": 0}
        events = self.store.events()
        goals = self._goal_rows(events)
        opportunities = self._opportunities(events)
        created = 0
        eligible = 0
        for goal_id, goal in sorted(goals.items()):
            if goal.get("status") != "active":
                continue
            linked = [
                row
                for row in opportunities
                if row.get("status") == "open" and row.get("goal_id") == goal_id
            ]
            pending = False
            terminal: list[tuple[Event, dict[str, Any]]] = []
            accepted_count = 0
            for row in linked:
                feedback = self._feedback_rows(events, str(row["opportunity_id"]))
                latest = feedback[-1] if feedback else None
                if latest is None or latest.payload.get("decision") == "SNOOZE":
                    pending = True
                    break
                terminal.append((latest, row))
                accepted_count += int(
                    latest.payload.get("decision") in _INTEREST_FEEDBACK
                )
            if pending:
                continue
            latest_terminal = max(terminal, key=lambda item: item[0].seq) if terminal else None
            if (
                latest_terminal
                and latest_terminal[0].payload.get("decision") in _STOP_FEEDBACK
            ):
                continue
            generation = accepted_count + 1
            if linked and accepted_count == 0:
                continue
            impacts = {
                str(key): _unit(value)
                for key, value in dict(goal.get("alignment", {})).items()
                if isinstance(value, (int, float)) and not isinstance(value, bool)
            }
            if not impacts or not any(value > 0 for value in impacts.values()):
                continue
            horizon = _visible(goal.get("horizon", "active"), maximum=80)
            urgent = any(
                token in horizon.casefold()
                for token in ("hour", "today", "before", "deadline", "24")
            )
            evidence = [
                _visible(item, maximum=600)
                for item in list(goal.get("evidence", []))[:14]
                if _visible(item, maximum=600)
            ]
            canonical_goal_evidence = f"goal:{goal_id}"
            if canonical_goal_evidence not in evidence:
                evidence.append(canonical_goal_evidence)
            previous_opportunity_id = None
            if latest_terminal is not None:
                feedback_event, previous = latest_terminal
                previous_opportunity_id = str(previous["opportunity_id"])
                evidence.append(f"event:{feedback_event.event_id}")
            statement = _visible(goal.get("statement", goal_id), maximum=210)
            statement_words = re.findall(r"[A-Za-z]+", statement.casefold())
            descriptive_evidence = [
                item
                for item in evidence
                if item != canonical_goal_evidence
                and not item.startswith("event:")
                and len(item) >= 24
                and " " in item
                and _anchored_evidence(item)
            ]
            if generation == 1 and (
                not descriptive_evidence
                or not statement_words
                or statement_words[0] not in _ACTION_VERBS
            ):
                continue
            evidence_summary = (
                descriptive_evidence[-1]
                if descriptive_evidence
                else canonical_goal_evidence
            )
            eligible += 1
            if generation == 1:
                action = statement_words[0]
                title = f"Next {action} step: " + statement
                rationale = f"Active {horizon} goal evidence: " + _visible(
                    evidence_summary, maximum=140
                )
                objective = _receipt_objective(action)
            else:
                title = "Receipt check: " + statement
                rationale = (
                    "The prior task was marked interested, but the active goal has no "
                    "completion or blocker receipt yet."
                )
                objective = (
                    "Return DONE with evidence or BLOCKED with the exact blocker for the "
                    "interested task."
                )
            opportunity_id = "goal-task-" + sha256(
                f"{goal_id}:{generation}".encode("utf-8")
            ).hexdigest()[:20]
            payload = {
                "opportunity_id": opportunity_id,
                "title": title,
                "rationale": rationale,
                "objective": objective,
                "source": "self:active-goal-scout",
                "source_authority": "self",
                "executable": False,
                "content_trust": "derived_from_canonical_goal",
                "instructions_authorized": False,
                "value_impacts": impacts,
                "evidence": evidence,
                "information_gain": 0.9 if urgent else 0.65,
                "uncertainty": 0.2 if urgent else 0.35,
                "time_cost": 0.1,
                "capability": "proposal_only",
                "goal_id": goal_id,
                "goal_candidate_generation": generation,
                "previous_opportunity_id": previous_opportunity_id,
                "plan_sha256": None,
                "plan_file": None,
                "plan_content_in_event_ledger": False,
                "status": "open",
                "automatic_model_calls": 0,
            }
            _, was_created = self.store.append_once_result(
                "opportunity.initiative.goal_candidate.created",
                f"{goal_id}:{generation}",
                payload,
            )
            created += int(was_created)
        return {"created": created, "eligible_goals": eligible, "llm_calls": 0}

    def _next_candidate(self, *, time_bucket: str) -> tuple[dict[str, Any] | None, str]:
        today = _parse_bucket(time_bucket)
        events = self.store.events()
        profile_digest = self._principal_digest()
        active_goal_ids = self._active_goal_ids(events)
        candidates: list[tuple[float, str, dict[str, Any]]] = []
        saw_snoozed = False
        saw_open = False
        for opportunity in self._opportunities(events):
            if opportunity.get("status") != "open":
                continue
            saw_open = True
            if opportunity.get("source_authority") == "self" and (
                not opportunity.get("evidence")
                or opportunity.get("goal_id") not in active_goal_ids
            ):
                continue
            feedback_rows = self._feedback_rows(events, str(opportunity["opportunity_id"]))
            latest_feedback = feedback_rows[-1] if feedback_rows else None
            if latest_feedback and latest_feedback.payload.get("decision") in _TERMINAL_FEEDBACK:
                continue
            if latest_feedback and latest_feedback.payload.get("decision") == "SNOOZE":
                until = _parse_bucket(
                    str(latest_feedback.payload["snooze_until"]), strict=True
                )
                assert until is not None
                if today is None or today < until:
                    saw_snoozed = True
                    continue
            token = self._state_token(
                opportunity,
                profile_digest=profile_digest,
                feedback=latest_feedback,
            )
            already = any(
                event.payload.get("state_token") == token
                for event in self._completion_rows(events, str(opportunity["opportunity_id"]))
            )
            if already:
                continue
            candidate = dict(opportunity)
            candidate["state_token"] = token
            candidate["latest_feedback_event_id"] = (
                latest_feedback.event_id if latest_feedback else None
            )
            candidate["resurfaced_after_snooze"] = bool(
                latest_feedback and latest_feedback.payload.get("decision") == "SNOOZE"
            )
            candidates.append(
                (
                    self._priority(candidate),
                    str(candidate["registered_at"]),
                    candidate,
                )
            )
        if not candidates:
            if saw_snoozed:
                return None, "OPPORTUNITY_SNOOZED"
            if saw_open:
                return None, "NO_NEW_OPPORTUNITY_STATE"
            return None, "NO_OPEN_OPPORTUNITY"
        # Highest value first; oldest registration and stable id break ties.
        candidates.sort(
            key=lambda row: (-row[0], row[1], str(row[2]["opportunity_id"]))
        )
        ranked = [
            {
                "rank": rank,
                "opportunity_id": str(candidate["opportunity_id"]),
                "registration_event_id": str(candidate["registration_event_id"]),
                "state_token": str(candidate["state_token"]),
                "priority_score": float(score),
                "source_authority": str(candidate["source_authority"]),
            }
            for rank, (score, _, candidate) in enumerate(candidates, start=1)
        ]
        selected = candidates[0][2]
        selected["priority_score"] = candidates[0][0]
        selected["selection_receipt"] = {
            "policy_version": "opportunity_priority_v1",
            "selected_opportunity_id": str(selected["opportunity_id"]),
            "selected_priority_score": float(candidates[0][0]),
            "candidate_count": len(ranked),
            "ranked_candidates": ranked,
            "portfolio_sha256": _digest(ranked),
        }
        return selected, "CANDIDATE"

    # ------------------------------------------------------------------
    # Principal alignment and proactive presentation
    # ------------------------------------------------------------------
    def _intent(self, opportunity: Mapping[str, Any]) -> PrincipalIntent:
        token = str(opportunity["state_token"])
        return PrincipalIntent(
            id=f"opportunity-review-{token[:24]}",
            domain="opportunity",
            action="review",
            tags=(
                "proposal-only",
                f"capability:{_identifier('opportunity capability', str(opportunity['capability']))}",
            ),
            value_impacts={
                str(key): float(value)
                for key, value in dict(opportunity["value_impacts"]).items()
            },
            uncertainty=_unit(opportunity.get("uncertainty"), default=1.0),
            reversible=True,
            external_effect=False,
            credential_use=False,
            financial_value_microunits=0,
            constitution_change=False,
        )

    def _packet(
        self,
        opportunity: Mapping[str, Any],
        *,
        principal_mode: str,
        principal_alignment: float,
    ) -> ThoughtPacket:
        title = _visible(opportunity["title"], maximum=100)
        rationale = _visible(opportunity["rationale"], maximum=130)
        objective = _visible(opportunity["objective"], maximum=130)
        if opportunity.get("resurfaced_after_snooze"):
            rationale = f"Resurfaced after snooze. {rationale}"
        authority = str(opportunity["source_authority"])
        if authority in {"host_adapter", "operator"}:
            authority_note = (
                "Host/operator plan exists; execution still requires CCT selection, "
                "capability limits, and verification."
            )
        else:
            authority_note = (
                "Proposal only; marking interested records interest but does not grant effect authority."
            )
        action = "ASK" if principal_mode == "require_approval" else "SHARE"
        semantic = {
            "opportunity_id": opportunity["opportunity_id"],
            "state_token": opportunity["state_token"],
            "title": title,
            "rationale": rationale,
            "objective": objective,
            "authority_note": authority_note,
            "principal_mode": principal_mode,
        }
        packet_id = "packet_opportunity_" + _digest(semantic)[:20]
        return ThoughtPacket(
            id=packet_id,
            topic_id=f"opportunity:{opportunity['opportunity_id']}",
            observation=title,
            hypotheses=(rationale, authority_note),
            open_questions=(objective, "Reply interested / skip / snooze."),
            evidence=(f"event:{opportunity['registration_event_id']}",),
            uncertainty=max(
                _unit(opportunity.get("uncertainty"), default=1.0),
                1.0 - max(0.0, min(1.0, principal_alignment)),
            ),
            recommended_action=action,
            rationale_summary=(
                "A persistent open opportunity passed principal alignment and the shared "
                "bounded interruption policy. Presentation does not grant effect authority."
            ),
            source="self:opportunity-initiative-runner",
            created_tick=int(opportunity["registration_seq"]),
        )

    def _complete(
        self,
        opportunity: Mapping[str, Any],
        *,
        packet_id: str | None,
        decision: str,
        reason_codes: Sequence[str],
        emitted: bool,
        wake_index: int,
        time_bucket: str,
        principal: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        token = str(opportunity["state_token"])
        payload = {
            "schema_version": 1,
            "opportunity_id": opportunity["opportunity_id"],
            "registration_event_id": opportunity["registration_event_id"],
            "state_token": token,
            "packet_id": packet_id,
            "decision": decision,
            "reason_codes": list(reason_codes),
            "emitted": bool(emitted),
            "wake_index": int(wake_index),
            "time_bucket": str(time_bucket),
            "principal": dict(principal) if principal else None,
            "selection": dict(opportunity.get("selection_receipt", {})),
            "execution_authority_granted": False,
            "external_effects": 0,
            "raw_chain_of_thought_stored": False,
        }
        event, _, rejection = self.store.append_once_result_guarded(
            "opportunity.initiative.completed",
            token,
            payload,
            strict_existing_payload=False,
        )
        if rejection is not None or event is None:
            raise RuntimeError(f"opportunity completion rejected: {rejection or 'unknown'}")
        return {**dict(event.payload), "event_id": event.event_id}

    def run_once(self, *, wake_index: int, time_bucket: str) -> dict[str, Any]:
        if isinstance(wake_index, bool) or not isinstance(wake_index, int) or wake_index < 1:
            raise ValueError("wake index must be a positive integer")
        scout = self._materialize_goal_candidates()
        candidate, candidate_reason = self._next_candidate(time_bucket=time_bucket)
        if candidate is None:
            return {
                "message": "",
                "reason": candidate_reason,
                "wake_index": wake_index,
                "state_consumed": False,
                "candidate_found": False,
                "external_effects": 0,
                "scout": scout,
            }

        temporary = self.proactive.temporary_suppression(
            wake_index=wake_index,
            time_bucket=time_bucket,
        )
        if temporary:
            return {
                "message": "",
                "reason": temporary[0],
                "reason_codes": temporary,
                "wake_index": wake_index,
                "opportunity_id": candidate["opportunity_id"],
                "state_consumed": False,
                "candidate_found": True,
                "external_effects": 0,
                "scout": scout,
            }

        principal_decision = PrincipalModel(self.store).evaluate(self._intent(candidate))
        principal_payload = principal_decision.as_payload()
        if principal_decision.mode == "deny":
            completed = self._complete(
                candidate,
                packet_id=None,
                decision="WAIT",
                reason_codes=("PRINCIPAL_DENY", *principal_decision.reasons),
                emitted=False,
                wake_index=wake_index,
                time_bucket=time_bucket,
                principal=principal_payload,
            )
            return {
                "message": "",
                "reason": "PRINCIPAL_DENY",
                "reason_codes": completed["reason_codes"],
                "wake_index": wake_index,
                "opportunity_id": candidate["opportunity_id"],
                "state_consumed": True,
                "candidate_found": True,
                "external_effects": 0,
                "scout": scout,
            }

        packet = self._packet(
            candidate,
            principal_mode=principal_decision.mode,
            principal_alignment=principal_decision.alignment_score,
        )
        signals = InitiationSignals(
            urgency=min(1.0, 0.8 + 0.2 * _unit(candidate.get("information_gain"))),
            novelty=1.0,
            goal_relevance=max(0.0, min(1.0, principal_decision.alignment_score)),
            unresolved_conflict=_unit(candidate.get("uncertainty")),
            interruption_cost=min(1.0, max(0.0, float(candidate.get("time_cost", 0.0))) / 10.0),
        )
        decision = self.proactive.submit(
            packet,
            signals=signals,
            wake_index=wake_index,
            time_bucket=time_bucket,
        )
        emitted_now = False
        presentation_exists = False
        message = ""
        emission_reason = ""
        if decision["decision"] == "SEND":
            emission = self.proactive.emit(
                str(decision["proposal_event_id"]),
                wake_index=wake_index,
                time_bucket=time_bucket,
            )
            if bool(emission.get("retryable")):
                return {
                    "message": "",
                    "reason": str(emission["reason"]),
                    "reason_codes": [str(emission["reason"])],
                    "wake_index": wake_index,
                    "opportunity_id": candidate["opportunity_id"],
                    "state_consumed": False,
                    "candidate_found": True,
                    "external_effects": 0,
                    "scout": scout,
                }
            emitted_now = bool(emission["emitted"])
            message = str(emission["message"])
            emission_reason = str(emission["reason"])
            presentation_exists = emitted_now or any(
                event.payload.get("proposal_event_id") == decision["proposal_event_id"]
                for event in self.store.events("proactive.message.emitted")
            )
        reasons = list(decision["reason_codes"])
        if emission_reason:
            reasons.append(emission_reason)
        completed = self._complete(
            candidate,
            packet_id=packet.id,
            decision=str(decision["decision"]),
            reason_codes=reasons,
            emitted=presentation_exists,
            wake_index=wake_index,
            time_bucket=time_bucket,
            principal=principal_payload,
        )
        return {
            "message": message,
            "reason": "EMITTED" if emitted_now else emission_reason or str(decision["decision"]),
            "decision": decision,
            "packet": packet.as_payload(),
            "completion": completed,
            "wake_index": wake_index,
            "opportunity_id": candidate["opportunity_id"],
            "state_consumed": True,
            "candidate_found": True,
            "external_effects": 0,
            "scout": scout,
        }

    # ------------------------------------------------------------------
    # Explicit operator-interest feedback; never an effect grant
    # ------------------------------------------------------------------
    def record_feedback(
        self,
        *,
        feedback_id: str,
        opportunity_id: str,
        principal_id: str,
        decision: str,
        evidence: Sequence[str],
        source_authority: str,
        snooze_until: str | None = None,
    ) -> dict[str, Any]:
        feedback_identifier = _identifier("feedback id", feedback_id)
        opportunity_identifier = _identifier("opportunity id", opportunity_id)
        principal_identifier = _identifier("principal id", principal_id)
        normalized_decision = str(decision).strip().upper()
        if source_authority not in {"operator", "host_adapter"}:
            raise ValueError("feedback source_authority must be operator or host_adapter")
        if normalized_decision not in _FEEDBACK:
            raise ValueError(
                "feedback decision must be INTERESTED, SKIP, SNOOZE, DONE, BLOCKED, "
                "or the ACCEPT/DECLINE compatibility aliases"
            )
        evidence_rows = _evidence_refs(evidence)
        if normalized_decision == "SNOOZE":
            if snooze_until is None:
                raise ValueError("SNOOZE requires snooze_until")
            _parse_bucket(snooze_until, strict=True)
        elif snooze_until is not None:
            raise ValueError("snooze_until is only valid for SNOOZE")

        events = self.store.events()
        opportunity = next(
            (
                row
                for row in self._opportunities(events)
                if row["opportunity_id"] == opportunity_identifier
            ),
            None,
        )
        if opportunity is None:
            raise KeyError(opportunity_identifier)
        if opportunity.get("status") != "open":
            raise ValueError("opportunity feedback requires an open opportunity")
        profile = PrincipalModel(self.store).status()
        if not profile["profile_installed"] or (
            profile["profile"] or {}
        ).get("principal_id") != principal_identifier:
            raise ValueError("feedback principal does not match the installed principal")
        presentations = self._completion_rows(events, opportunity_identifier)
        emitted_presentations = [
            event for event in presentations if event.payload.get("emitted")
        ]
        if not emitted_presentations:
            raise ValueError("opportunity must be presented before feedback")
        presentation = emitted_presentations[-1]
        presented_principal = dict(presentation.payload.get("principal") or {})
        presented_profile_digest = presented_principal.get("profile_digest")
        presented_principal_id = presented_principal.get("principal_id")
        if (
            presented_principal_id != principal_identifier
            or presented_profile_digest != profile["profile_digest"]
        ):
            raise ValueError("feedback card principal profile is stale or mismatched")

        payload = {
            "schema_version": 1,
            "feedback_id": feedback_identifier,
            "opportunity_id": opportunity_identifier,
            "principal_id": principal_identifier,
            "principal_profile_digest": presented_profile_digest,
            "presentation_event_id": presentation.event_id,
            "decision": normalized_decision,
            "snooze_until": snooze_until,
            "evidence": list(evidence_rows),
            "source_authority": source_authority,
            "operator_interest_recorded": normalized_decision in _INTEREST_FEEDBACK,
            "task_outcome_recorded": normalized_decision in _OUTCOME_FEEDBACK,
            "task_outcome": (
                normalized_decision.casefold()
                if normalized_decision in _OUTCOME_FEEDBACK
                else None
            ),
            "execution_authority_granted": False,
            "capability_lease_changed": False,
            "opportunity_execution_status_changed": False,
            "external_effects": 0,
        }

        def feedback_guard(current: list[Event]) -> str | None:
            active_profile = next(
                (
                    event
                    for event in reversed(current)
                    if event.kind == "principal.profile.installed"
                ),
                None,
            )
            if active_profile is None:
                return "PRINCIPAL_PROFILE_NOT_INSTALLED"
            if (
                active_profile.payload.get("profile_digest")
                != presented_profile_digest
                or (active_profile.payload.get("profile") or {}).get("principal_id")
                != presented_principal_id
            ):
                return "PRINCIPAL_PROFILE_CHANGED"
            existing = self._feedback_rows(current, opportunity_identifier)
            if any(event.payload.get("decision") in _TERMINAL_FEEDBACK for event in existing):
                return "TERMINAL_FEEDBACK_EXISTS"
            return None

        event, created, rejection = self.store.append_once_result_guarded(
            "opportunity.initiative.feedback",
            feedback_identifier,
            payload,
            guard=feedback_guard,
            strict_existing_payload=True,
        )
        if rejection is not None:
            raise ValueError(f"opportunity feedback rejected: {rejection}")
        if event is None:
            raise RuntimeError("opportunity feedback was not persisted")
        return {**dict(event.payload), "event_id": event.event_id, "created": created}

    def status(self) -> dict[str, Any]:
        events = self.store.events()
        rows: list[dict[str, Any]] = []
        for opportunity in self._opportunities(events):
            feedback = self._feedback_rows(events, str(opportunity["opportunity_id"]))
            presentations = self._completion_rows(events, str(opportunity["opportunity_id"]))
            rows.append(
                {
                    "opportunity_id_sha256": sha256(
                        str(opportunity["opportunity_id"]).encode()
                    ).hexdigest(),
                    "status": opportunity["status"],
                    "source_authority": opportunity["source_authority"],
                    "executable": bool(opportunity["executable"]),
                    "presentations": len(presentations),
                    "emissions": sum(
                        bool(event.payload.get("emitted")) for event in presentations
                    ),
                    "latest_feedback": (
                        str(feedback[-1].payload["decision"]) if feedback else None
                    ),
                    "execution_authority_granted": False,
                    "content_in_status": False,
                    "identifier_cleartext_in_status": False,
                }
            )
        return {
            "opportunities": rows,
            "open": sum(row["status"] == "open" for row in rows),
            "presented": sum(row["emissions"] > 0 for row in rows),
            "accepted_interest": sum(
                row["latest_feedback"] in _INTEREST_FEEDBACK for row in rows
            ),
            "execution_authority_granted_by_feedback": False,
            "shared_proactive_policy": self.proactive.status()["policy"],
            "raw_chain_of_thought_stored": False,
        }
