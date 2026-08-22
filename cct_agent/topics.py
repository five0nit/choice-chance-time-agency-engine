"""Persistent conversation topics for bounded proactive cognition."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Any, Iterable

from .store import EventStore


def _clean_text(value: str, *, name: str, maximum: int) -> str:
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


def _unique(values: Iterable[str], *, maximum_items: int = 12) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        cleaned = _clean_text(str(value), name="topic list item", maximum=500)
        if cleaned not in result:
            result.append(cleaned)
        if len(result) >= maximum_items:
            break
    return tuple(result)


@dataclass(frozen=True)
class Topic:
    id: str
    title: str
    summary: str
    source: str
    status: str
    logical_tick: int
    revision: int
    questions: tuple[str, ...]
    hypotheses: tuple[str, ...]
    commitments: tuple[str, ...]
    urgency: float
    novelty: float
    goal_relevance: float
    unresolved_conflict: float

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "id", _clean_text(self.id, name="topic id", maximum=160)
        )
        object.__setattr__(
            self, "title", _clean_text(self.title, name="topic title", maximum=240)
        )
        object.__setattr__(
            self,
            "summary",
            _clean_text(self.summary, name="topic summary", maximum=1200),
        )
        object.__setattr__(
            self,
            "source",
            _clean_text(self.source, name="topic source", maximum=240),
        )
        if self.status not in {"open", "paused", "closed"}:
            raise ValueError("topic status must be open, paused, or closed")
        if self.logical_tick < 0 or self.revision < 1:
            raise ValueError("topic tick and revision must be non-negative")
        object.__setattr__(self, "questions", _unique(self.questions))
        object.__setattr__(self, "hypotheses", _unique(self.hypotheses))
        object.__setattr__(self, "commitments", _unique(self.commitments))
        object.__setattr__(self, "urgency", _unit(self.urgency, name="topic urgency"))
        object.__setattr__(self, "novelty", _unit(self.novelty, name="topic novelty"))
        object.__setattr__(
            self,
            "goal_relevance",
            _unit(self.goal_relevance, name="topic goal relevance"),
        )
        object.__setattr__(
            self,
            "unresolved_conflict",
            _unit(self.unresolved_conflict, name="topic unresolved conflict"),
        )

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "source": self.source,
            "status": self.status,
            "logical_tick": self.logical_tick,
            "revision": self.revision,
            "questions": list(self.questions),
            "hypotheses": list(self.hypotheses),
            "commitments": list(self.commitments),
            "urgency": self.urgency,
            "novelty": self.novelty,
            "goal_relevance": self.goal_relevance,
            "unresolved_conflict": self.unresolved_conflict,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "Topic":
        return cls(
            id=str(payload["id"]),
            title=str(payload["title"]),
            summary=str(payload["summary"]),
            source=str(payload["source"]),
            status=str(payload["status"]),
            logical_tick=int(payload["logical_tick"]),
            revision=int(payload["revision"]),
            questions=tuple(str(item) for item in payload.get("questions", [])),
            hypotheses=tuple(str(item) for item in payload.get("hypotheses", [])),
            commitments=tuple(str(item) for item in payload.get("commitments", [])),
            urgency=float(payload.get("urgency", 0.0)),
            novelty=float(payload.get("novelty", 0.0)),
            goal_relevance=float(payload.get("goal_relevance", 0.0)),
            unresolved_conflict=float(payload.get("unresolved_conflict", 0.0)),
        )


class TopicStore:
    """Profile-scoped topic continuity; never automatically captures transcripts."""

    def __init__(self, store: EventStore) -> None:
        self.store = store

    def all(self, *, status: str | None = None) -> list[Topic]:
        latest: dict[str, Topic] = {}
        for event in self.store.events("proactive.topic.updated"):
            topic = Topic.from_payload(dict(event.payload["topic"]))
            latest[topic.id] = topic
        rows = sorted(latest.values(), key=lambda item: (item.logical_tick, item.id))
        if status is not None:
            rows = [item for item in rows if item.status == status]
        return rows

    def get(self, topic_id: str) -> Topic | None:
        return next((topic for topic in self.all() if topic.id == topic_id), None)

    def upsert(
        self,
        *,
        topic_id: str,
        title: str,
        summary: str,
        source: str,
        logical_tick: int,
        questions: Iterable[str] = (),
        hypotheses: Iterable[str] = (),
        commitments: Iterable[str] = (),
        urgency: float = 0.0,
        novelty: float = 0.0,
        goal_relevance: float = 0.0,
        unresolved_conflict: float = 0.0,
        status: str = "open",
    ) -> Topic:
        existing = self.get(topic_id)
        tick = int(logical_tick)
        if existing is not None and tick < existing.logical_tick:
            raise ValueError("topic revision cannot move logical time backward")
        topic = Topic(
            id=_clean_text(topic_id, name="topic id", maximum=160),
            title=_clean_text(title, name="topic title", maximum=240),
            summary=_clean_text(summary, name="topic summary", maximum=1200),
            source=_clean_text(source, name="topic source", maximum=240),
            status=status,
            logical_tick=tick,
            revision=(existing.revision + 1) if existing else 1,
            questions=_unique((*existing.questions, *questions) if existing else questions),
            hypotheses=_unique(
                (*existing.hypotheses, *hypotheses) if existing else hypotheses
            ),
            commitments=_unique(
                (*existing.commitments, *commitments) if existing else commitments
            ),
            urgency=_unit(urgency, name="topic urgency"),
            novelty=_unit(novelty, name="topic novelty"),
            goal_relevance=_unit(goal_relevance, name="topic goal relevance"),
            unresolved_conflict=_unit(
                unresolved_conflict, name="topic unresolved conflict"
            ),
        )
        self.store.append(
            "proactive.topic.updated",
            {
                "topic": topic.as_payload(),
                "previous_revision": existing.revision if existing else None,
                "continuity_scope": "profile",
                "content_mode": "caller_supplied_structured_summary",
                "automatic_raw_conversation_capture": False,
                "raw_chain_of_thought_stored": False,
            },
        )
        return topic

    def close(self, topic_id: str, *, source: str, logical_tick: int) -> Topic:
        topic = self.get(topic_id)
        if topic is None:
            raise KeyError(topic_id)
        return self.upsert(
            topic_id=topic.id,
            title=topic.title,
            summary=topic.summary,
            source=source,
            logical_tick=logical_tick,
            questions=topic.questions,
            hypotheses=topic.hypotheses,
            commitments=topic.commitments,
            urgency=topic.urgency,
            novelty=0.0,
            goal_relevance=topic.goal_relevance,
            unresolved_conflict=0.0,
            status="closed",
        )
