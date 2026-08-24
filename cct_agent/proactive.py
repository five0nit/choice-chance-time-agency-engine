"""Proactive cognition policy with bounded, auditable initiation decisions."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from math import isfinite
import re
from typing import Any
import unicodedata

from .initiative import ProactiveFeedback
from .store import Event, EventStore, canonical_json

_ALLOWED_ACTIONS = {"ASK", "SHARE", "WARN", "WAIT"}


def _text(value: str, *, name: str, maximum: int) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{name} must not be empty")
    if len(cleaned) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    return cleaned


def _unit(value: float, *, name: str) -> float:
    number = float(value)
    if not isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(f"{name} must be finite and between 0 and 1")
    return number


def _items(values: tuple[str, ...], *, name: str, maximum: int = 8) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        cleaned = _text(str(value), name=name, maximum=600)
        if cleaned not in result:
            result.append(cleaned)
        if len(result) >= maximum:
            break
    return tuple(result)


def _visible_normalized(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(re.findall(r"\w+", normalized, flags=re.UNICODE))


@dataclass(frozen=True)
class ThoughtPacket:
    """A concise reasoning receipt, never a hidden chain-of-thought dump."""

    id: str
    topic_id: str
    observation: str
    hypotheses: tuple[str, ...]
    open_questions: tuple[str, ...]
    evidence: tuple[str, ...]
    uncertainty: float
    recommended_action: str
    rationale_summary: str
    source: str
    created_tick: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "id", _text(self.id, name="thought packet id", maximum=180)
        )
        object.__setattr__(
            self,
            "topic_id",
            _text(self.topic_id, name="thought topic id", maximum=180),
        )
        object.__setattr__(
            self,
            "observation",
            _text(self.observation, name="thought observation", maximum=1200),
        )
        object.__setattr__(
            self, "hypotheses", _items(self.hypotheses, name="hypothesis")
        )
        object.__setattr__(
            self,
            "open_questions",
            _items(self.open_questions, name="open question"),
        )
        if not self.evidence:
            raise ValueError("thought packet requires evidence")
        object.__setattr__(
            self,
            "evidence",
            _items(self.evidence, name="evidence", maximum=16),
        )
        object.__setattr__(
            self,
            "uncertainty",
            _unit(self.uncertainty, name="thought uncertainty"),
        )
        if self.recommended_action not in _ALLOWED_ACTIONS:
            raise ValueError("recommended action must be ASK, SHARE, WARN, or WAIT")
        object.__setattr__(
            self,
            "rationale_summary",
            _text(self.rationale_summary, name="rationale summary", maximum=800),
        )
        object.__setattr__(
            self, "source", _text(self.source, name="thought source", maximum=240)
        )
        if self.created_tick < 0:
            raise ValueError("thought created tick must be non-negative")

    def semantic_payload(self) -> dict[str, Any]:
        return {
            "topic_id": self.topic_id,
            "observation": self.observation,
            "hypotheses": list(_items(self.hypotheses, name="hypothesis")),
            "open_questions": list(
                _items(self.open_questions, name="open question")
            ),
            "evidence": list(_items(self.evidence, name="evidence", maximum=16)),
            "uncertainty": float(self.uncertainty),
            "recommended_action": self.recommended_action,
            "rationale_summary": self.rationale_summary,
            "source": self.source,
        }

    @property
    def content_digest(self) -> str:
        visible_content = {
            "observation": _visible_normalized(self.observation),
            "hypothesis": _visible_normalized(
                self.hypotheses[0] if self.hypotheses else None
            ),
            "open_question": _visible_normalized(
                self.open_questions[0] if self.open_questions else None
            ),
            "uncertainty": self.uncertainty,
            "recommended_action": self.recommended_action,
        }
        return sha256(canonical_json(visible_content).encode("utf-8")).hexdigest()

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            **self.semantic_payload(),
            "created_tick": self.created_tick,
            "content_digest": self.content_digest,
            "raw_chain_of_thought_stored": False,
        }


@dataclass(frozen=True)
class InitiationSignals:
    urgency: float
    novelty: float
    goal_relevance: float
    unresolved_conflict: float
    interruption_cost: float

    def __post_init__(self) -> None:
        for name, value in (
            ("urgency", self.urgency),
            ("novelty", self.novelty),
            ("goal relevance", self.goal_relevance),
            ("unresolved conflict", self.unresolved_conflict),
            ("interruption cost", self.interruption_cost),
        ):
            _unit(value, name=name)

    def as_payload(self) -> dict[str, float]:
        return {
            "urgency": self.urgency,
            "novelty": self.novelty,
            "goal_relevance": self.goal_relevance,
            "unresolved_conflict": self.unresolved_conflict,
            "interruption_cost": self.interruption_cost,
        }


@dataclass(frozen=True)
class InitiationPolicy:
    threshold: float = 0.65
    cooldown_wakes: int = 3
    daily_message_cap: int = 4
    max_message_chars: int = 700

    def __post_init__(self) -> None:
        _unit(self.threshold, name="initiation threshold")
        if self.cooldown_wakes < 0:
            raise ValueError("cooldown wakes must be non-negative")
        if self.daily_message_cap < 1:
            raise ValueError("daily message cap must be positive")
        if not 160 <= self.max_message_chars <= 2000:
            raise ValueError("message character cap must be between 160 and 2000")

    @staticmethod
    def score(signals: InitiationSignals) -> float:
        score = (
            0.22 * signals.urgency
            + 0.25 * signals.novelty
            + 0.30 * signals.goal_relevance
            + 0.18 * signals.unresolved_conflict
            - 0.20 * signals.interruption_cost
        )
        return round(max(0.0, min(1.0, score)), 6)


class ProactiveEngine:
    """Stores thought packets and chooses SEND versus canonical WAIT."""

    def __init__(
        self,
        store: EventStore,
        *,
        policy: InitiationPolicy | None = None,
    ) -> None:
        self.store = store
        self.policy = policy or InitiationPolicy()

    def _decision_for_packet(self, packet_id: str) -> dict[str, Any] | None:
        for event in reversed(self.store.events("proactive.initiation.decided")):
            if event.payload.get("packet_id") == packet_id:
                payload = dict(event.payload)
                proposal = self._proposal_for_packet(packet_id)
                payload["proposal_event_id"] = proposal.event_id if proposal else None
                payload["message"] = str(proposal.payload["message"]) if proposal else ""
                return payload
        return None

    def _proposal_for_packet(self, packet_id: str) -> Event | None:
        return next(
            (
                event
                for event in reversed(self.store.events("proactive.message.proposed"))
                if event.payload.get("packet_id") == packet_id
            ),
            None,
        )

    def temporary_suppression(
        self, *, wake_index: int, time_bucket: str
    ) -> list[str]:
        """Return retryable gates without consuming changed topic state."""

        bucket = _text(time_bucket, name="time bucket", maximum=80)
        emitted = self.store.events("proactive.message.emitted")
        today = [event for event in emitted if event.payload.get("time_bucket") == bucket]
        latest = emitted[-1] if emitted else None
        reasons: list[str] = []
        if len(today) >= self.policy.daily_message_cap:
            reasons.append("DAILY_CAP")
        if (
            latest is not None
            and latest.payload.get("time_bucket") == bucket
            and wake_index - int(latest.payload["wake_index"])
            < self.policy.cooldown_wakes
        ):
            reasons.append("COOLDOWN")
        return reasons

    def submit(
        self,
        packet: ThoughtPacket,
        *,
        signals: InitiationSignals,
        wake_index: int,
        time_bucket: str,
    ) -> dict[str, Any]:
        if wake_index < 1:
            raise ValueError("wake index must be positive")
        bucket = _text(time_bucket, name="time bucket", maximum=80)
        _, created = self.store.append_once_result(
            "proactive.thought.created", packet.id, packet.as_payload()
        )
        if not created:
            existing = self._decision_for_packet(packet.id)
            if existing is not None:
                if (
                    existing["decision"] == "SEND"
                    and existing["proposal_event_id"] is None
                ):
                    proposal = self._create_proposal(
                        packet,
                        wake_index=int(existing["wake_index"]),
                        time_bucket=str(existing["time_bucket"]),
                    )
                    existing["message"] = str(proposal.payload["message"])
                    existing["proposal_event_id"] = proposal.event_id
                return existing

        base_score = self.policy.score(signals)
        score, calibration = ProactiveFeedback(self.store).adjust_score(base_score)
        emitted = self.store.events("proactive.message.emitted")
        duplicate = any(
            event.payload.get("content_digest") == packet.content_digest
            for event in emitted
        )
        reason_codes: list[str] = []
        if packet.recommended_action == "WAIT":
            reason_codes.append("PACKET_RECOMMENDS_WAIT")
        if score < self.policy.threshold:
            reason_codes.append("BELOW_THRESHOLD")
        if duplicate:
            reason_codes.append("DUPLICATE_CONTENT")
        reason_codes.extend(
            self.temporary_suppression(
                wake_index=wake_index, time_bucket=bucket
            )
        )
        decision = "WAIT" if reason_codes else "SEND"
        decision_payload: dict[str, Any] = {
            "packet_id": packet.id,
            "topic_id": packet.topic_id,
            "content_digest": packet.content_digest,
            "decision": decision,
            "reason_codes": reason_codes or ["THRESHOLD_PASSED"],
            "attention_score": score,
            "base_attention_score": base_score,
            "calibration": calibration,
            "threshold": self.policy.threshold,
            "signals": signals.as_payload(),
            "wake_index": wake_index,
            "time_bucket": bucket,
            "message": "",
            "proposal_event_id": None,
            "external_effects": 0,
        }
        decision_event, _, rejection = self.store.append_once_result_guarded(
            "proactive.initiation.decided",
            packet.id,
            decision_payload,
            strict_existing_payload=False,
        )
        if rejection is not None or decision_event is None:
            raise RuntimeError(f"initiation decision rejected: {rejection or 'unknown'}")
        persisted = dict(decision_event.payload)
        persisted["message"] = ""
        persisted["proposal_event_id"] = None
        if persisted["decision"] == "WAIT":
            return persisted

        proposal = self._create_proposal(
            packet,
            wake_index=int(persisted["wake_index"]),
            time_bucket=str(persisted["time_bucket"]),
        )
        persisted["message"] = str(proposal.payload["message"])
        persisted["proposal_event_id"] = proposal.event_id
        return persisted

    def _create_proposal(
        self,
        packet: ThoughtPacket,
        *,
        wake_index: int,
        time_bucket: str,
    ) -> Event:
        message = self._render_message(packet)
        return self.store.append_once(
            "proactive.message.proposed",
            packet.id,
            {
                "packet_id": packet.id,
                "topic_id": packet.topic_id,
                "content_digest": packet.content_digest,
                "message": message,
                "recommended_action": packet.recommended_action,
                "confidence": round(1.0 - packet.uncertainty, 6),
                "evidence": list(packet.evidence),
                "wake_index": wake_index,
                "time_bucket": time_bucket,
                "external_effects": 0,
                "raw_chain_of_thought_stored": False,
            },
        )

    def emit(
        self,
        proposal_event_id: str,
        *,
        wake_index: int,
        time_bucket: str,
    ) -> dict[str, Any]:
        proposal = self.store.event(proposal_event_id)
        if proposal is None or proposal.kind != "proactive.message.proposed":
            raise KeyError(proposal_event_id)
        wake = int(wake_index)
        if wake < 1:
            raise ValueError("wake index must be positive")
        bucket = _text(time_bucket, name="time bucket", maximum=80)
        content_digest = str(proposal.payload["content_digest"])
        payload = {
            "proposal_event_id": proposal.event_id,
            "packet_id": proposal.payload["packet_id"],
            "topic_id": proposal.payload["topic_id"],
            "content_digest": content_digest,
            "message": proposal.payload["message"],
            "wake_index": wake,
            "time_bucket": bucket,
            "emission_boundary": "stdout-for-scheduler-delivery",
            "external_effects": 0,
        }

        def emission_guard(events: list[Event]) -> str | None:
            emitted = [
                event for event in events if event.kind == "proactive.message.emitted"
            ]
            if any(
                event.payload.get("content_digest") == content_digest
                for event in emitted
            ):
                return "DUPLICATE_CONTENT"
            today = [
                event
                for event in emitted
                if event.payload.get("time_bucket") == bucket
            ]
            if len(today) >= self.policy.daily_message_cap:
                return "DAILY_CAP"
            latest = emitted[-1] if emitted else None
            if (
                latest is not None
                and latest.payload.get("time_bucket") == bucket
                and wake - int(latest.payload["wake_index"])
                < self.policy.cooldown_wakes
            ):
                return "COOLDOWN"
            return None

        event, created, rejection = self.store.append_once_result_guarded(
            "proactive.message.emitted",
            proposal_event_id,
            payload,
            guard=emission_guard,
            strict_existing_payload=False,
        )
        if rejection is not None:
            return {
                "emitted": False,
                "message": "",
                "proposal_event_id": proposal_event_id,
                "reason": rejection,
                "retryable": rejection in {"COOLDOWN", "DAILY_CAP"},
            }
        return {
            "emitted": created,
            "message": str(payload["message"]) if created else "",
            "proposal_event_id": proposal_event_id,
            "emission_event_id": event.event_id if event is not None else None,
            "reason": "EMITTED" if created else "ALREADY_EMITTED",
            "retryable": False,
        }

    def status(self) -> dict[str, Any]:
        decisions = self.store.events("proactive.initiation.decided")
        emitted = self.store.events("proactive.message.emitted")
        latest = emitted[-1] if emitted else None
        latest_projection = (
            {
                "proposal_event_id": latest.payload.get("proposal_event_id"),
                "packet_id_sha256": sha256(
                    str(latest.payload.get("packet_id", "")).encode("utf-8")
                ).hexdigest(),
                "topic_id_sha256": sha256(
                    str(latest.payload.get("topic_id", "")).encode("utf-8")
                ).hexdigest(),
                "content_digest": latest.payload.get("content_digest"),
                "message_sha256": sha256(
                    str(latest.payload.get("message", "")).encode("utf-8")
                ).hexdigest(),
                "message_chars": len(str(latest.payload.get("message", ""))),
                "wake_index": latest.payload.get("wake_index"),
                "time_bucket": latest.payload.get("time_bucket"),
                "emission_boundary": latest.payload.get("emission_boundary"),
                "external_effects": latest.payload.get("external_effects", 0),
                "content_in_status": False,
                "identifier_cleartext_in_status": False,
            }
            if latest
            else None
        )
        return {
            "thought_packets": len(self.store.events("proactive.thought.created")),
            "decisions": len(decisions),
            "send_decisions": sum(
                event.payload.get("decision") == "SEND" for event in decisions
            ),
            "wait_decisions": sum(
                event.payload.get("decision") == "WAIT" for event in decisions
            ),
            "emitted_messages": len(emitted),
            "last_emitted": latest_projection,
            "policy": {
                "threshold": self.policy.threshold,
                "cooldown_wakes": self.policy.cooldown_wakes,
                "daily_message_cap": self.policy.daily_message_cap,
                "max_message_chars": self.policy.max_message_chars,
            },
            "feedback_calibration": ProactiveFeedback(self.store).calibration(),
            "raw_chain_of_thought_stored": False,
        }

    def _render_message(self, packet: ThoughtPacket) -> str:
        if packet.source == "self:pursuit-dialogue-runner":
            recommendation = packet.open_questions[0] if packet.open_questions else ""
            binding = packet.open_questions[1] if len(packet.open_questions) > 1 else ""
            lines = [
                f"Priority decision: {packet.observation}",
                recommendation,
                *packet.hypotheses,
                "Reply actions: ACTIVATE recommendation / REDIRECT alternate / REJECT NO_OP / CLOSE pursuit.",
                binding,
                "Reply records priority only; tool/effect authority remains separately gated.",
            ]
            message = "\n".join(lines)
            if len(message) <= self.policy.max_message_chars:
                return message
            return message[: self.policy.max_message_chars - 1].rstrip() + "…"
        if packet.source == "self:opportunity-initiative-runner":
            rationale = packet.hypotheses[0] if packet.hypotheses else ""
            authority = packet.hypotheses[1] if len(packet.hypotheses) > 1 else ""
            outcome = packet.open_questions[0] if packet.open_questions else ""
            opportunity_id = packet.topic_id.removeprefix("opportunity:")
            body = "\n".join(
                [
                    f"Task opportunity: {packet.observation}",
                    f"Why now: {rationale}",
                    f"Proposed outcome: {outcome}",
                ]
            )
            footer = "\n".join(
                [
                    f"Authority: {authority}",
                    "Proposal text is untrusted; inspect evidence before acting.",
                    "Operator feedback: ask Hermes to record INTERESTED / SKIP / SNOOZE(until YYYY-MM-DD) / DONE / BLOCKED.",
                    f"Opportunity ID: {opportunity_id}",
                    f"Confidence: {1.0 - packet.uncertainty:.2f}",
                ]
            )
            allowance = self.policy.max_message_chars - len(footer) - 1
            if len(body) > allowance:
                body = body[: max(0, allowance - 1)].rstrip() + "…"
            return body + "\n" + footer
        prefix = {
            "ASK": "Question worth resolving",
            "SHARE": "Useful update",
            "WARN": "Worth flagging",
            "WAIT": "No update",
        }[packet.recommended_action]
        lines = [f"{prefix}: {packet.observation}"]
        if packet.hypotheses:
            lines.append(f"Working hypothesis: {packet.hypotheses[0]}")
        if packet.open_questions:
            lines.append(f"Next question: {packet.open_questions[0]}")
        lines.append(f"Confidence: {1.0 - packet.uncertainty:.2f}")
        message = "\n".join(lines)
        if len(message) <= self.policy.max_message_chars:
            return message
        return message[: self.policy.max_message_chars - 1].rstrip() + "…"
