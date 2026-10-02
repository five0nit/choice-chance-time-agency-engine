"""Deterministic payload-safe human projection over the canonical event ledger."""

from __future__ import annotations

from hashlib import sha256
import re

from .store import Event, EventStore


_RESULT_CLASSES = {
    "VERIFIED",
    "FAILED",
    "ROLLED_BACK",
    "BLOCKED",
    "ACTION_REQUIRED",
    "RECORDED",
}
_ROUTINE_KINDS = {
    "cognition.tick.started",
    "cognition.cycle.completed",
    "interoception.sampled",
    "hermes.turn_observed",
}
_MAX_DIGEST_LIMIT = 50
_SAFE_TRACE_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{0,159}$")


class HumanNarrative:
    """Render bounded operator language without exposing arbitrary event payloads."""

    def __init__(self, store: EventStore) -> None:
        self.store = store

    @staticmethod
    def _safe_trace_identifier(value: str) -> str:
        if _SAFE_TRACE_IDENTIFIER.fullmatch(value):
            return value
        return "sha256:" + sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def _trace(cls, event: Event) -> dict[str, object]:
        return {
            "seq": event.seq,
            "event_id": cls._safe_trace_identifier(event.event_id),
            "kind": cls._safe_trace_identifier(event.kind),
            "event_hash": event.event_hash,
        }

    def _linked_completion_verified(self, event: Event) -> bool:
        evidence = event.payload.get("evidence", [])
        if not isinstance(evidence, list):
            return False
        for reference in evidence:
            if not isinstance(reference, str) or not reference.startswith("event:"):
                continue
            linked = self.store.event(reference.removeprefix("event:"))
            if linked is None:
                continue
            if linked.kind == "autonomy.run.executed" and (
                linked.payload.get("success") is True
                and linked.payload.get("verified") is True
                and isinstance(linked.payload.get("receipt_event_ids"), list)
                and bool(linked.payload["receipt_event_ids"])
            ):
                return True
            if linked.kind == "autonomy.run.completed":
                receipt_count = linked.payload.get("receipt_count", 0)
                if (
                    linked.payload.get("success") is True
                    and linked.payload.get("verified") is True
                    and isinstance(receipt_count, int)
                    and not isinstance(receipt_count, bool)
                    and receipt_count > 0
                ):
                    return True
            if (
                linked.kind.startswith("operator.")
                and linked.kind.endswith(".effect_verified")
            ):
                return True
        return False

    def _classify(self, event: Event) -> tuple[str, str, str]:
        kind = event.kind
        if kind.startswith("goal."):
            return (
                "RECORDED",
                "goal",
                "RECORDED: A goal-state event was recorded; no effect authority was granted.",
            )
        if kind == "decision.made" or kind.endswith(".decision.made"):
            return (
                "RECORDED",
                "decision",
                "RECORDED: A replayable decision was recorded; execution authority remains separate.",
            )
        if kind == "outcome.observed":
            realized = event.payload.get("realized_utility")
            non_negative = (
                isinstance(realized, (int, float))
                and not isinstance(realized, bool)
                and realized >= 0
            )
            if non_negative and self._linked_completion_verified(event):
                return (
                    "VERIFIED",
                    "outcome",
                    "VERIFIED: A non-negative outcome is linked to canonical completion evidence.",
                )
            if non_negative:
                return (
                    "RECORDED",
                    "outcome",
                    "RECORDED: A non-negative outcome was claimed without independent verification.",
                )
            return (
                "FAILED",
                "outcome",
                "FAILED: An observed negative outcome was linked to its decision evidence.",
            )
        if kind == "capability.control.state_changed" and isinstance(
            event.payload.get("control_receipt"), dict
        ):
            return (
                "RECORDED",
                "capability-control",
                "RECORDED: An authenticated host control changed configured capability state; no lease, ticket, or external effect was created.",
            )
        if kind.startswith("operator.") and kind.endswith(".effect_verified"):
            return (
                "VERIFIED",
                "effect",
                "VERIFIED: A typed effect passed its canonical verification boundary.",
            )
        if kind == "autonomy.episode.failed" or kind.endswith(".effect_failed"):
            return (
                "FAILED",
                "effect",
                "FAILED: A bounded execution episode ended without a verified effect.",
            )
        if kind.startswith("operator.") and kind.endswith(".rollback.completed"):
            return (
                "ROLLED_BACK",
                "effect",
                "ROLLED_BACK: A typed effect was reverted and the rollback was recorded.",
            )
        if kind == "mediation.tool.denied" or kind.endswith(".effect_blocked"):
            return (
                "BLOCKED",
                "effect",
                "BLOCKED: An effect was denied before downstream execution.",
            )
        if kind == "clarification.requested":
            return (
                "ACTION_REQUIRED",
                "clarification",
                "ACTION_REQUIRED: A bounded clarification awaits an authenticated operator answer.",
            )
        if kind.startswith("operator.kill_switch."):
            result = "BLOCKED" if event.payload.get("active", True) else "RECORDED"
            text = (
                "BLOCKED: The global effect kill switch is active."
                if result == "BLOCKED"
                else "RECORDED: A kill-switch state change was recorded."
            )
            return result, "kill-switch", text
        return (
            "RECORDED",
            "unknown-event",
            "RECORDED: An unclassified ledger event was recorded.",
        )

    def _row(self, event: Event) -> dict[str, object]:
        result, family, text = self._classify(event)
        if result not in _RESULT_CLASSES:  # defensive invariant
            raise RuntimeError("invalid human narrative result class")
        return {
            "result": result,
            "family": family,
            "text": text,
            "trace": self._trace(event),
        }

    def _significant_events(self) -> list[Event]:
        return [
            event for event in self.store.events() if event.kind not in _ROUTINE_KINDS
        ]

    @staticmethod
    def _unresolved_clarifications(events: list[Event]) -> int:
        latest: dict[str, Event] = {}
        for event in events:
            if event.kind != "clarification.requested":
                continue
            request_id = str(event.payload.get("request_id", event.event_id))
            revision = int(event.payload.get("revision", 0))
            current = latest.get(request_id)
            if current is None or revision >= int(current.payload.get("revision", 0)):
                latest[request_id] = event
        understandings = {
            str(event.payload.get("request_event_id")): event
            for event in events
            if event.kind == "clarification.answer.understood"
        }
        confirmations = {
            str(event.payload.get("request_event_id"))
            for event in events
            if event.kind == "clarification.answer.confirmed"
        }
        unresolved = 0
        for request in latest.values():
            answer = understandings.get(request.event_id)
            if answer is None:
                unresolved += 1
            elif (
                answer.payload.get("confirmation_required") is True
                and request.event_id not in confirmations
            ):
                unresolved += 1
        return unresolved

    def _invalid_view(
        self, view: str, chain: dict[str, object]
    ) -> dict[str, object]:
        return {
            "view": view,
            "text": "BLOCKED: Event-chain verification failed; success claims are suppressed.",
            "chain": chain,
            "rows": [],
        }

    def status(self) -> dict[str, object]:
        chain = self.store.verify_chain()
        if not chain["valid"]:
            return self._invalid_view("status", chain)
        events = self._significant_events()
        if not events:
            text = (
                "VERIFIED: Event chain is valid. "
                "No human-relevant activity has been recorded."
            )
            rows: list[dict[str, object]] = []
        else:
            latest = self._row(events[-1])
            non_clarification_actions = sum(
                self._classify(event)[0] == "ACTION_REQUIRED"
                and event.kind != "clarification.requested"
                for event in events
            )
            action_required = non_clarification_actions + self._unresolved_clarifications(
                events
            )
            text = (
                f"VERIFIED: Event chain is valid with {chain['event_count']} events. "
                f"Human-relevant events: {len(events)}; "
                f"unresolved action signals: {action_required}. "
                f"Latest: {latest['text']}"
            )
            rows = [latest]
        return {"view": "status", "text": text, "chain": chain, "rows": rows}

    def latest(self) -> dict[str, object]:
        chain = self.store.verify_chain()
        if not chain["valid"]:
            return self._invalid_view("latest", chain)
        events = self._significant_events()
        rows = [self._row(events[-1])] if events else []
        text = (
            str(rows[0]["text"])
            if rows
            else "VERIFIED: Event chain is valid. No human-relevant activity has been recorded."
        )
        return {"view": "latest", "text": text, "chain": chain, "rows": rows}

    def digest(self, *, limit: int = 8) -> dict[str, object]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_DIGEST_LIMIT
        ):
            raise ValueError("limit must be between 1 and 50")
        chain = self.store.verify_chain()
        if not chain["valid"]:
            return self._invalid_view("digest", chain)
        events = self._significant_events()
        rows = [self._row(event) for event in reversed(events[-limit:])]
        text = (
            "\n".join(str(row["text"]) for row in rows)
            if rows
            else "VERIFIED: Event chain is valid. No human-relevant activity has been recorded."
        )
        return {"view": "digest", "text": text, "chain": chain, "rows": rows}
