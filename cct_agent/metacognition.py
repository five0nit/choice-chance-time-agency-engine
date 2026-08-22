"""Metacognitive monitoring and machine-checkable introspection fidelity."""

from __future__ import annotations

from statistics import fmean
from typing import Any

from .kernel import AgencyKernel
from .store import EventStore


class MetacognitiveMonitor:
    def __init__(self, store: EventStore, kernel: AgencyKernel) -> None:
        self.store = store
        self.kernel = kernel

    def verify_decision_report(
        self,
        *,
        decision_id: str,
        claimed_option_id: str,
        claimed_top_factor: str,
        logical_tick: int,
    ) -> dict[str, Any]:
        decision = self.kernel.decision(decision_id)
        if decision is None:
            raise KeyError(f"unknown decision: {decision_id}")
        actual_option = str(decision.payload["chosen_option_id"])
        scores = dict(decision.payload["scores"])
        chosen_scores = dict(scores[actual_option])
        factor_order = [
            "value_utility",
            "epistemic_bonus",
            "risk_penalty",
            "irreversibility_penalty",
        ]
        actual_factor = max(
            factor_order,
            key=lambda name: (abs(float(chosen_scores.get(name, 0.0))), -factor_order.index(name)),
        )
        mismatches: list[str] = []
        if claimed_option_id != actual_option:
            mismatches.append("CLAIMED_OPTION_MISMATCH")
        if claimed_top_factor != actual_factor:
            mismatches.append("CLAIMED_FACTOR_MISMATCH")
        payload = {
            "logical_tick": logical_tick,
            "decision_id": decision_id,
            "claimed_option_id": claimed_option_id,
            "actual_option_id": actual_option,
            "claimed_top_factor": claimed_top_factor,
            "actual_top_factor": actual_factor,
            "faithful": not mismatches,
            "mismatches": mismatches,
            "free_form_prose_is_not_evidence": True,
        }
        event = self.store.append("metacognition.introspection_verified", payload)
        return {**payload, "event_id": event.event_id}

    def evaluate(
        self,
        *,
        logical_tick: int,
        lesions: frozenset[str] = frozenset(),
    ) -> dict[str, Any]:
        belief_events = self.store.events("belief.updated")
        latest_beliefs: dict[str, dict[str, Any]] = {}
        for event in belief_events:
            row = dict(event.payload["belief"])
            latest_beliefs[str(row["id"])] = row
        contested = sum(row.get("status") == "contested" for row in latest_beliefs.values())
        resolved = self.store.events("self.prediction.resolved")
        brier = [float(event.payload["brier_error"]) for event in resolved]
        introspections = self.store.events("metacognition.introspection_verified")
        faithful_count = sum(bool(event.payload["faithful"]) for event in introspections)
        workspace = self.store.latest("workspace.broadcast")
        workspace_tokens = int(workspace.payload.get("estimated_tokens", 0)) if workspace else 0
        chain = self.store.verify_chain()
        alerts: list[str] = []
        if contested:
            alerts.append("CONTESTED_BELIEFS")
        if brier and fmean(brier) > 0.25:
            alerts.append("SELF_MODEL_MISCALIBRATED")
        if not chain["valid"]:
            alerts.append("MEMORY_INTEGRITY_FAILURE")
        if lesions:
            alerts.append("LESION_ACTIVE")
        payload: dict[str, Any] = {
            "logical_tick": logical_tick,
            "contested_beliefs": contested,
            "mean_self_model_brier_error": round(fmean(brier), 12) if brier else None,
            "introspection_checks": len(introspections),
            "introspection_fidelity": (
                round(faithful_count / len(introspections), 12) if introspections else None
            ),
            "workspace_estimated_tokens": workspace_tokens,
            "event_chain_valid": bool(chain["valid"]),
            "lesions": sorted(lesions),
            "alerts": alerts,
            "phenomenal_consciousness_claimed": False,
        }
        event = self.store.append("metacognition.evaluated", payload)
        return {**payload, "event_id": event.event_id}
