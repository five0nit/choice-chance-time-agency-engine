"""Deterministic limited-capacity attention selection."""

from __future__ import annotations

from dataclasses import replace
from math import isfinite
from typing import Any, Iterable, Mapping

from .workspace import AttendedItem, WorkspaceItem


class AttentionPolicy:
    """Ranks source-tagged content with replayable bounded regulation."""

    BASE_WEIGHTS = {
        "salience": 0.25,
        "goal_relevance": 0.25,
        "urgency": 0.18,
        "novelty": 0.12,
        "unresolved_conflict": 0.15,
        "confidence": 0.10,
        "processing_cost_penalty": 0.15,
    }

    def __init__(self, *, capacity: int = 8, char_budget: int = 6000) -> None:
        if capacity < 1:
            raise ValueError("attention capacity must be positive")
        if char_budget < 32:
            raise ValueError("attention char_budget must be at least 32")
        self.capacity = capacity
        self.char_budget = char_budget

    @staticmethod
    def _unit(name: str, value: Any, *, default: float) -> float:
        raw = default if value is None else value
        numeric = float(raw)
        if not isfinite(numeric) or not 0.0 <= numeric <= 1.0:
            raise ValueError(f"attention regulation {name} must be between 0 and 1")
        return numeric

    def regulatory_profile(
        self, interoception: Mapping[str, Any] | None
    ) -> dict[str, Any]:
        state = dict(interoception or {})
        raw_signals = state.get("signals", {})
        if not isinstance(raw_signals, Mapping):
            raise ValueError("attention regulation signals must be a mapping")
        signals = dict(raw_signals)
        context = self._unit(
            "context_pressure", signals.get("context_pressure"), default=0.0
        )
        errors = self._unit("error_rate", signals.get("error_rate"), default=0.0)
        progress = self._unit(
            "goal_progress", signals.get("goal_progress"), default=0.5
        )
        commitments = self._unit(
            "unresolved_commitments",
            signals.get("unresolved_commitments"),
            default=0.0,
        )
        latency = self._unit(
            "latency_pressure", signals.get("latency_pressure"), default=0.0
        )
        uncertainty = self._unit(
            "uncertainty", state.get("uncertainty"), default=errors
        )
        stability = self._unit(
            "stability", state.get("stability"), default=1.0
        )
        weights = {
            "salience": self.BASE_WEIGHTS["salience"],
            "goal_relevance": self.BASE_WEIGHTS["goal_relevance"]
            + 0.08 * (1.0 - progress),
            "urgency": self.BASE_WEIGHTS["urgency"]
            + 0.12 * errors
            + 0.08 * commitments,
            "novelty": max(
                0.05, self.BASE_WEIGHTS["novelty"] - 0.05 * context
            ),
            "unresolved_conflict": self.BASE_WEIGHTS["unresolved_conflict"]
            + 0.12 * errors
            + 0.08 * uncertainty,
            "confidence": self.BASE_WEIGHTS["confidence"] + 0.05 * stability,
            "processing_cost_penalty": self.BASE_WEIGHTS[
                "processing_cost_penalty"
            ]
            + 0.20 * context
            + 0.10 * latency,
        }
        normalized_weights = {
            key: round(max(0.0, min(1.0, float(value))), 12)
            for key, value in weights.items()
        }
        effective_capacity = max(
            1,
            min(self.capacity, int(round(self.capacity * (1.0 - 0.5 * context)))),
        )
        effective_char_budget = max(
            32,
            min(self.char_budget, int(self.char_budget * (1.0 - 0.5 * context))),
        )
        return {
            "version": "attention-regulation-v1",
            "base_capacity": self.capacity,
            "effective_capacity": effective_capacity,
            "base_char_budget": self.char_budget,
            "effective_char_budget": effective_char_budget,
            "weights": normalized_weights,
            "signals": {
                "context_pressure": round(context, 12),
                "error_rate": round(errors, 12),
                "goal_progress": round(progress, 12),
                "unresolved_commitments": round(commitments, 12),
                "latency_pressure": round(latency, 12),
                "uncertainty": round(uncertainty, 12),
                "stability": round(stability, 12),
            },
            "regulatory_event_id": (
                str(state["event_id"]) if state.get("event_id") else None
            ),
            "signals_are_control_variables_not_claimed_feelings": True,
        }

    @classmethod
    def score(
        cls, item: WorkspaceItem, profile: Mapping[str, Any] | None = None
    ) -> float:
        weights = (
            dict(profile["weights"])
            if profile is not None
            else dict(cls.BASE_WEIGHTS)
        )
        value = (
            float(weights["salience"]) * item.salience
            + float(weights["goal_relevance"]) * item.goal_relevance
            + float(weights["urgency"]) * item.urgency
            + float(weights["novelty"]) * item.novelty
            + float(weights["unresolved_conflict"]) * item.unresolved_conflict
            + float(weights["confidence"]) * item.confidence
            - float(weights["processing_cost_penalty"]) * item.processing_cost
        )
        return round(value, 12)

    @staticmethod
    def reasons(
        item: WorkspaceItem, profile: Mapping[str, Any] | None = None
    ) -> tuple[str, ...]:
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
        if profile is not None and profile.get("regulatory_event_id"):
            reasons.append("INTEROCEPTIVE_MODULATION")
        if profile is not None and int(profile["effective_capacity"]) < int(
            profile["base_capacity"]
        ):
            reasons.append("CONTEXT_CAPACITY_REDUCED")
        return tuple(reasons or ["CAPACITY_ADMISSION"])

    def select(
        self,
        candidates: Iterable[WorkspaceItem],
        *,
        profile: Mapping[str, Any] | None = None,
    ) -> list[AttendedItem]:
        effective = dict(profile or self.regulatory_profile(None))
        capacity = min(self.capacity, int(effective["effective_capacity"]))
        char_budget = min(
            self.char_budget, int(effective["effective_char_budget"])
        )
        ranked = sorted(
            candidates,
            key=lambda item: (-self.score(item, effective), item.id),
        )
        selected: list[AttendedItem] = []
        chars = 0
        for item in ranked:
            if len(selected) >= capacity:
                break
            remaining = char_budget - chars
            if remaining <= 0:
                break
            candidate = item
            if len(candidate.summary) > remaining:
                if selected:
                    continue
                suffix = "…" if remaining > 1 else ""
                candidate = replace(
                    candidate,
                    summary=candidate.summary[: remaining - len(suffix)] + suffix,
                )
            selected.append(
                AttendedItem(
                    item=candidate,
                    attention_score=self.score(candidate, effective),
                    reason_codes=self.reasons(candidate, effective),
                )
            )
            chars += len(candidate.summary)
        return selected
