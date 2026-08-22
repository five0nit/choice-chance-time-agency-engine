"""Bounded structured memory consolidation and deterministic retrieval."""

from __future__ import annotations

from typing import Any

from .beliefs import BeliefStore
from .store import EventStore


class MemoryManager:
    """Consolidates receipts; never stores raw private chain-of-thought."""

    def __init__(self, store: EventStore, *, char_budget: int = 4000) -> None:
        if char_budget < 256:
            raise ValueError("memory char_budget must be at least 256")
        self.store = store
        self.char_budget = char_budget

    def consolidate(self, *, logical_tick: int) -> dict[str, Any]:
        entries: list[dict[str, Any]] = []
        workspace = self.store.latest("workspace.broadcast")
        if workspace:
            for row in workspace.payload.get("items", []):
                entries.append(
                    {
                        "kind": "workspace",
                        "summary": str(row["summary"]),
                        "source": str(row["source"]),
                        "evidence": list(row.get("evidence", [])),
                    }
                )
        for belief in BeliefStore(self.store).active():
            entries.append(
                {
                    "kind": "belief",
                    "summary": belief.proposition,
                    "source": belief.source,
                    "confidence": belief.confidence,
                    "evidence": list(belief.evidence),
                }
            )
        recent_outcomes = self.store.events("outcome.observed")[-3:]
        for event in recent_outcomes:
            entries.append(
                {
                    "kind": "outcome",
                    "summary": str(event.payload["observation"]),
                    "source": "outcome.observed",
                    "evidence": list(event.payload.get("evidence", [])),
                }
            )

        bounded: list[dict[str, Any]] = []
        chars = 0
        seen: set[tuple[str, str]] = set()
        for entry in entries:
            key = (str(entry["kind"]), str(entry["summary"]))
            if key in seen:
                continue
            seen.add(key)
            remaining = self.char_budget - chars
            if remaining <= 0:
                break
            summary = str(entry["summary"])
            if len(summary) > remaining:
                summary = summary[: max(0, remaining - 1)] + "…"
            if not summary:
                break
            bounded.append({**entry, "summary": summary})
            chars += len(summary)

        payload: dict[str, Any] = {
            "logical_tick": logical_tick,
            "entries": bounded,
            "entry_count": len(bounded),
            "char_count": chars,
            "estimated_tokens": (chars + 3) // 4,
            "raw_chain_of_thought_stored": False,
            "memory_types": ["episodic", "semantic", "identity", "prospective"],
        }
        event = self.store.append("memory.consolidated", payload)
        return {**payload, "event_id": event.event_id, "event_hash": event.event_hash}

    def latest(self) -> dict[str, Any] | None:
        event = self.store.latest("memory.consolidated")
        return dict(event.payload) if event else None

    def retrieve(self, query: str, *, limit: int = 5) -> list[dict[str, Any]]:
        terms = {term.casefold() for term in query.split() if term.strip()}
        scored: list[tuple[int, int, dict[str, Any]]] = []
        for event in self.store.events("memory.consolidated"):
            for row in event.payload.get("entries", []):
                text = str(row["summary"]).casefold()
                score = sum(term in text for term in terms)
                if score:
                    scored.append((score, event.seq, dict(row)))
        scored.sort(key=lambda item: (-item[0], -item[1], str(item[2]["summary"])))
        return [row for _, _, row in scored[:limit]]
