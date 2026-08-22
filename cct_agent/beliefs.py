"""Evidence-linked beliefs reconstructed from the temporal event ledger."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Any, Iterable

from .store import EventStore


@dataclass(frozen=True, slots=True)
class Belief:
    id: str
    proposition: str
    confidence: float
    source: str
    evidence: tuple[str, ...]
    created_tick: int
    last_verified_tick: int
    status: str = "active"
    refresh_condition: str = ""
    contradiction_of: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id.strip() or not self.proposition.strip() or not self.source.strip():
            raise ValueError("belief id, proposition, and source must not be empty")
        if len(self.proposition) > 2000:
            raise ValueError("belief proposition exceeds 2000 characters")
        if not isfinite(self.confidence) or not 0.0 <= self.confidence <= 1.0:
            raise ValueError("belief confidence must be between 0 and 1")
        if self.created_tick < 1 or self.last_verified_tick < self.created_tick:
            raise ValueError("belief ticks are invalid")
        if self.status not in {"active", "contested", "superseded", "expired"}:
            raise ValueError("invalid belief status")
        if not self.evidence:
            raise ValueError("belief requires evidence provenance")

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "proposition": self.proposition,
            "confidence": self.confidence,
            "source": self.source,
            "evidence": list(self.evidence),
            "created_tick": self.created_tick,
            "last_verified_tick": self.last_verified_tick,
            "status": self.status,
            "refresh_condition": self.refresh_condition,
            "contradiction_of": list(self.contradiction_of),
        }


class BeliefStore:
    def __init__(self, store: EventStore) -> None:
        self.store = store

    @staticmethod
    def _from_payload(payload: dict[str, Any]) -> Belief:
        return Belief(
            id=str(payload["id"]),
            proposition=str(payload["proposition"]),
            confidence=float(payload["confidence"]),
            source=str(payload["source"]),
            evidence=tuple(str(item) for item in payload["evidence"]),
            created_tick=int(payload["created_tick"]),
            last_verified_tick=int(payload["last_verified_tick"]),
            status=str(payload.get("status", "active")),
            refresh_condition=str(payload.get("refresh_condition", "")),
            contradiction_of=tuple(str(item) for item in payload.get("contradiction_of", [])),
        )

    def all(self, *, through_tick: int | None = None) -> list[Belief]:
        latest: dict[str, Belief] = {}
        for event in self.store.events("belief.updated"):
            event_tick = int(event.payload["logical_tick"])
            if through_tick is not None and event_tick > through_tick:
                continue
            belief = self._from_payload(dict(event.payload["belief"]))
            latest[belief.id] = belief
        return sorted(latest.values(), key=lambda belief: belief.id)

    def get(self, belief_id: str, *, through_tick: int | None = None) -> Belief | None:
        return next(
            (
                belief
                for belief in self.all(through_tick=through_tick)
                if belief.id == belief_id
            ),
            None,
        )

    def active(self, *, through_tick: int | None = None) -> list[Belief]:
        return [
            belief
            for belief in self.all(through_tick=through_tick)
            if belief.status in {"active", "contested"}
        ]

    def upsert(
        self,
        *,
        belief_id: str,
        proposition: str,
        confidence: float,
        source: str,
        evidence: Iterable[str],
        logical_tick: int,
        refresh_condition: str = "",
        contradiction_of: Iterable[str] = (),
        status: str = "active",
    ) -> Belief:
        previous = self.get(belief_id)
        merged_evidence = tuple(
            dict.fromkeys(
                [*(previous.evidence if previous else ()), *(str(item) for item in evidence)]
            )
        )
        belief = Belief(
            id=belief_id,
            proposition=proposition,
            confidence=round(float(confidence), 12),
            source=source,
            evidence=merged_evidence,
            created_tick=previous.created_tick if previous else logical_tick,
            last_verified_tick=logical_tick,
            status=status,
            refresh_condition=refresh_condition,
            contradiction_of=tuple(str(item) for item in contradiction_of),
        )
        self.store.append(
            "belief.updated",
            {
                "logical_tick": logical_tick,
                "operation": "upsert" if previous is None else "revise",
                "previous_confidence": previous.confidence if previous else None,
                "belief": belief.as_payload(),
            },
        )
        return belief

    def update_confidence(
        self,
        *,
        belief_id: str,
        supports: bool,
        weight: float,
        evidence: Iterable[str],
        logical_tick: int,
    ) -> Belief:
        if not isfinite(weight) or not 0.0 <= weight <= 1.0:
            raise ValueError("evidence weight must be between 0 and 1")
        previous = self.get(belief_id)
        if previous is None:
            raise KeyError(f"unknown belief: {belief_id}")
        evidence_rows = tuple(str(item) for item in evidence)
        if not any(item not in previous.evidence for item in evidence_rows):
            self.store.append(
                "belief.evidence.duplicate_ignored",
                {
                    "logical_tick": logical_tick,
                    "belief_id": belief_id,
                    "evidence": list(evidence_rows),
                    "confidence_unchanged": previous.confidence,
                },
            )
            return previous
        confidence = (
            previous.confidence + weight * (1.0 - previous.confidence)
            if supports
            else previous.confidence * (1.0 - weight)
        )
        return self.upsert(
            belief_id=previous.id,
            proposition=previous.proposition,
            confidence=confidence,
            source=previous.source,
            evidence=evidence_rows,
            logical_tick=logical_tick,
            refresh_condition=previous.refresh_condition,
            contradiction_of=previous.contradiction_of,
            status="active" if supports else "contested",
        )
