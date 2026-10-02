"""Limited-capacity global workspace with auditable broadcasts."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from math import isfinite
from typing import Any, Iterable, Mapping

from .store import EventStore, canonical_json


def _unit(name: str, value: float) -> None:
    numeric = float(value)
    if not isfinite(numeric) or not 0.0 <= numeric <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class WorkspaceItem:
    """One structured, source-tagged candidate for conscious access."""

    id: str
    kind: str
    summary: str
    source: str
    salience: float
    goal_relevance: float
    confidence: float
    novelty: float = 0.0
    urgency: float = 0.0
    unresolved_conflict: float = 0.0
    processing_cost: float = 0.0
    logical_tick: int = 0
    evidence: tuple[str, ...] = field(default_factory=tuple)
    content_digest: str = ""
    initiative_authority: str = "untrusted"

    def __post_init__(self) -> None:
        for name in ("id", "kind", "summary", "source"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"workspace {name} must not be empty")
        if len(self.summary) > 2000:
            raise ValueError("workspace summary exceeds 2000 characters")
        for name, maximum in (("id", 180), ("kind", 80), ("source", 200)):
            if len(str(getattr(self, name)).strip()) > maximum:
                raise ValueError(f"workspace {name} exceeds {maximum} characters")
        if self.initiative_authority not in {"untrusted", "trusted_producer"}:
            raise ValueError(
                "workspace initiative_authority must be untrusted or trusted_producer"
            )
        for name in (
            "salience",
            "goal_relevance",
            "confidence",
            "novelty",
            "urgency",
            "unresolved_conflict",
            "processing_cost",
        ):
            _unit(name, float(getattr(self, name)))
        if self.logical_tick < 0:
            raise ValueError("logical_tick must be non-negative")
        if not self.content_digest:
            material = canonical_json(
                {
                    "kind": self.kind,
                    "summary": self.summary,
                    "source": self.source,
                    "evidence": list(self.evidence),
                    "initiative_authority": self.initiative_authority,
                }
            )
            object.__setattr__(
                self,
                "content_digest",
                sha256(material.encode("utf-8")).hexdigest(),
            )

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "summary": self.summary,
            "source": self.source,
            "salience": self.salience,
            "goal_relevance": self.goal_relevance,
            "confidence": self.confidence,
            "novelty": self.novelty,
            "urgency": self.urgency,
            "unresolved_conflict": self.unresolved_conflict,
            "processing_cost": self.processing_cost,
            "logical_tick": self.logical_tick,
            "evidence": list(self.evidence),
            "content_digest": self.content_digest,
            "initiative_authority": self.initiative_authority,
        }


@dataclass(frozen=True, slots=True)
class AttendedItem:
    item: WorkspaceItem
    attention_score: float
    reason_codes: tuple[str, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            **self.item.as_payload(),
            "attention_score": self.attention_score,
            "attention_reason_codes": list(self.reason_codes),
        }


class GlobalWorkspace:
    """Persists small globally available frames instead of raw thought traces."""

    def __init__(
        self,
        store: EventStore,
        *,
        capacity: int = 8,
        char_budget: int = 6000,
    ) -> None:
        if capacity < 1:
            raise ValueError("workspace capacity must be positive")
        if char_budget < 128:
            raise ValueError("workspace char_budget must be at least 128")
        self.store = store
        self.capacity = capacity
        self.char_budget = char_budget

    def broadcast(
        self,
        attended: Iterable[AttendedItem],
        *,
        logical_tick: int,
        lesion: bool = False,
        attention_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if logical_tick < 1:
            raise ValueError("logical_tick must be positive")
        policy = dict(
            attention_policy
            or {
                "version": "attention-regulation-v1",
                "base_capacity": self.capacity,
                "effective_capacity": self.capacity,
                "base_char_budget": self.char_budget,
                "effective_char_budget": self.char_budget,
                "weights": {},
                "signals": {},
                "regulatory_event_id": None,
                "signals_are_control_variables_not_claimed_feelings": True,
            }
        )
        canonical_json(policy)
        effective_capacity = min(
            self.capacity, max(1, int(policy["effective_capacity"]))
        )
        effective_char_budget = min(
            self.char_budget, max(32, int(policy["effective_char_budget"]))
        )
        selected: list[AttendedItem] = []
        char_count = 0
        if not lesion:
            for candidate in attended:
                if len(selected) >= effective_capacity:
                    break
                size = len(candidate.item.summary)
                if char_count + size > effective_char_budget:
                    continue
                selected.append(candidate)
                char_count += size
        items = [candidate.as_payload() for candidate in selected]
        state_material = {
            "logical_tick": logical_tick,
            "items": items,
            "capacity": self.capacity,
            "char_budget": self.char_budget,
            "attention_policy": policy,
            "lesion": lesion,
        }
        state_hash = sha256(canonical_json(state_material).encode("utf-8")).hexdigest()
        payload: dict[str, Any] = {
            **state_material,
            "state_hash": state_hash,
            "char_count": char_count,
            "estimated_tokens": (char_count + 3) // 4,
            "raw_chain_of_thought_stored": False,
        }
        event = self.store.append("workspace.broadcast", payload)
        return {**payload, "event_id": event.event_id, "event_hash": event.event_hash}

    def latest_frame(self) -> dict[str, Any] | None:
        event = self.store.latest("workspace.broadcast")
        return dict(event.payload) if event else None

    def render_context(self, *, max_chars: int | None = None) -> str:
        frame = self.latest_frame()
        if not frame or not frame.get("items"):
            return ""
        limit = max_chars if max_chars is not None else self.char_budget
        lines = [
            f"Global workspace tick {frame['logical_tick']} "
            "(structured evidence; not hidden reasoning):"
        ]
        for row in frame["items"]:
            line = (
                f"- [{row['kind']}] {row['summary']} "
                f"(source={row['source']}, confidence={float(row['confidence']):.2f}, "
                f"attention={float(row['attention_score']):.3f})"
            )
            candidate = "\n".join([*lines, line])
            if len(candidate) > limit:
                break
            lines.append(line)
        rendered = "\n".join(lines)
        return rendered[:limit]
