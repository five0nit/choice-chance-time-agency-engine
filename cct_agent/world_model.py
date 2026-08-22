"""Counterfactual world-model receipts derived from CCT score components."""

from __future__ import annotations

from typing import Any, Iterable

from .kernel import AgencyKernel
from .models import Option
from .store import EventStore


class CounterfactualWorldModel:
    def __init__(self, store: EventStore, kernel: AgencyKernel) -> None:
        self.store = store
        self.kernel = kernel

    def predict(
        self,
        options: Iterable[Option],
        *,
        logical_tick: int,
    ) -> dict[str, dict[str, Any]]:
        option_list = list(options)
        ids = [option.id for option in option_list]
        if len(ids) != len(set(ids)):
            raise ValueError("counterfactual option ids must be unique")
        predictions: dict[str, dict[str, Any]] = {}
        for option in sorted(option_list, key=lambda item: item.id):
            score = self.kernel.score_option(option)
            predictions[option.id] = {
                "option_id": option.id,
                "description": option.description,
                "predicted_utility": score["total"],
                "confidence": round(1.0 - option.uncertainty, 12),
                "allowed": option.allowed,
                "blocked_reasons": list(option.blocked_reasons),
                "assumptions": list(option.assumptions),
                "score_components": score,
                "time_horizon_cost": option.time_cost,
            }
        event = self.store.append(
            "world.predicted",
            {
                "logical_tick": logical_tick,
                "predictions": predictions,
                "counterfactual_count": len(predictions),
                "selected_option_id": None,
            },
        )
        return {
            option_id: {**row, "prediction_event_id": event.event_id}
            for option_id, row in predictions.items()
        }

    def latest(self) -> dict[str, Any] | None:
        event = self.store.latest("world.predicted")
        return dict(event.payload) if event else None
