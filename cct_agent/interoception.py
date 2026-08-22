"""Computational interoception: bounded internal regulatory signals."""

from __future__ import annotations

from math import isfinite
from typing import Any, Mapping

from .store import EventStore


class InteroceptiveState:
    KNOWN_SIGNALS = {
        "context_pressure",
        "error_rate",
        "goal_progress",
        "memory_integrity",
        "unresolved_commitments",
        "tool_availability",
        "prediction_error",
        "latency_pressure",
    }

    def __init__(self, store: EventStore) -> None:
        self.store = store

    def sample(
        self,
        signals: Mapping[str, float],
        *,
        logical_tick: int,
    ) -> dict[str, Any]:
        normalized: dict[str, float] = {}
        for name, value in signals.items():
            if not name.strip():
                raise ValueError("interoceptive signal name must not be empty")
            numeric = float(value)
            if not isfinite(numeric) or not 0.0 <= numeric <= 1.0:
                raise ValueError(f"interoceptive signal {name} must be between 0 and 1")
            normalized[name] = round(numeric, 12)

        context = normalized.get("context_pressure", 0.0)
        errors = normalized.get("error_rate", 0.0)
        progress = normalized.get("goal_progress", 0.5)
        integrity = normalized.get("memory_integrity", 1.0)
        commitments = normalized.get("unresolved_commitments", 0.0)
        prediction_error = normalized.get("prediction_error", errors)
        latency = normalized.get("latency_pressure", 0.0)
        availability = normalized.get("tool_availability", 1.0)

        arousal = min(1.0, 0.30 * context + 0.30 * errors + 0.20 * commitments + 0.20 * latency)
        valence = max(-1.0, min(1.0, 2.0 * progress - 1.0 - 0.5 * errors))
        uncertainty = min(1.0, 0.6 * prediction_error + 0.4 * (1.0 - availability))
        stability = max(0.0, min(1.0, 0.6 * integrity + 0.4 * (1.0 - errors)))
        regulatory = {
            "arousal": round(arousal, 12),
            "valence": round(valence, 12),
            "uncertainty": round(uncertainty, 12),
            "stability": round(stability, 12),
            "signals_are_control_variables_not_claimed_feelings": True,
        }
        payload = {
            "logical_tick": logical_tick,
            "signals": normalized,
            "regulatory": regulatory,
        }
        event = self.store.append("interoception.sampled", payload)
        return {**regulatory, "signals": normalized, "event_id": event.event_id}

    def latest(self) -> dict[str, Any] | None:
        event = self.store.latest("interoception.sampled")
        return dict(event.payload) if event else None
