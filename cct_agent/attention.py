"""Deterministic limited-capacity attention selection."""

from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from .workspace import AttendedItem, WorkspaceItem


class AttentionPolicy:
    """Ranks source-tagged content without invoking an LLM."""

    def __init__(self, *, capacity: int = 8, char_budget: int = 6000) -> None:
        if capacity < 1:
            raise ValueError("attention capacity must be positive")
        if char_budget < 32:
            raise ValueError("attention char_budget must be at least 32")
        self.capacity = capacity
        self.char_budget = char_budget

    @staticmethod
    def score(item: WorkspaceItem) -> float:
        value = (
            0.25 * item.salience
            + 0.25 * item.goal_relevance
            + 0.18 * item.urgency
            + 0.12 * item.novelty
            + 0.15 * item.unresolved_conflict
            + 0.10 * item.confidence
            - 0.15 * item.processing_cost
        )
        return round(value, 12)

    @staticmethod
    def reasons(item: WorkspaceItem) -> tuple[str, ...]:
        reasons: list[str] = []
        if item.goal_relevance >= 0.5:
            reasons.append("GOAL_RELEVANT")
        if item.salience >= 0.5:
            reasons.append("SALIENT")
        if item.urgency >= 0.5:
            reasons.append("URGENT")
        if item.novelty >= 0.5:
            reasons.append("NOVEL")
        if item.unresolved_conflict >= 0.5:
            reasons.append("UNRESOLVED_CONFLICT")
        if item.confidence < 0.5:
            reasons.append("LOW_CONFIDENCE")
        return tuple(reasons or ["CAPACITY_ADMISSION"])

    def select(self, candidates: Iterable[WorkspaceItem]) -> list[AttendedItem]:
        ranked = sorted(candidates, key=lambda item: (-self.score(item), item.id))
        selected: list[AttendedItem] = []
        chars = 0
        for item in ranked:
            if len(selected) >= self.capacity:
                break
            remaining = self.char_budget - chars
            if remaining <= 0:
                break
            candidate = item
            if len(candidate.summary) > remaining:
                if selected:
                    continue
                suffix = "…" if remaining > 1 else ""
                candidate = replace(candidate, summary=candidate.summary[: remaining - len(suffix)] + suffix)
            selected.append(
                AttendedItem(
                    item=candidate,
                    attention_score=self.score(candidate),
                    reason_codes=self.reasons(candidate),
                )
            )
            chars += len(candidate.summary)
        return selected
