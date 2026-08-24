#!/usr/bin/env python3
"""Deterministic Phase 12 proactive-opportunity acceptance episode."""

from __future__ import annotations

import argparse
from pathlib import Path
import json
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cct_agent import (  # noqa: E402
    AgencyKernel,
    AutonomyEngine,
    EventStore,
    Opportunity,
    OpportunityInitiative,
    PrincipalDirective,
    PrincipalModel,
    PrincipalProfile,
    ProactiveRunner,
    default_constitution,
)


VERSION = "0.9.0a1"


def proposal(identifier: str, title: str, rationale: str, objective: str) -> Opportunity:
    return Opportunity(
        id=identifier,
        title=title,
        rationale=rationale,
        objective=objective,
        source="self:phase12-demo",
        source_authority="self",
        value_impacts={
            "truth": 0.85,
            "competence": 0.85,
            "autonomy": 0.8,
            "usefulness": 0.9,
        },
        plan={"steps": [], "final_verify": []},
        evidence=(f"demo:{identifier}",),
        information_gain=0.8,
        uncertainty=0.1,
        time_cost=0.1,
        capability="proposal_only",
        goal_id=identifier,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    args = parser.parse_args()

    store = EventStore(args.db)
    kernel = AgencyKernel(store, default_constitution("phase12-demo"))
    kernel.initialize()
    PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={
                "truth": 1.0,
                "competence": 0.95,
                "autonomy": 0.95,
                "usefulness": 0.95,
            },
            directives=(
                PrincipalDirective(
                    id="prefer-receipt-backed-opportunities",
                    kind="preference",
                    statement="Prefer concrete reversible receipt-backed opportunities.",
                    tags=("domain:opportunity", "action:review"),
                    priority=95,
                ),
            ),
            uncertainty_threshold=0.35,
        ),
        authority="operator",
        evidence=("operator://phase12-demo-principal",),
    )
    engine = AutonomyEngine(store, kernel, args.workspace, state_root=args.state_root)
    try:
        for goal_id in ("phase12-first-task", "phase12-second-task"):
            kernel.form_goal(
                goal_id=goal_id,
                statement=f"Advance {goal_id} through one bounded operator decision.",
                rationale="A real active goal grounds each proactive task proposal.",
                source="joint",
                horizon="short",
                alignment={"truth": 0.85, "competence": 0.85, "autonomy": 0.8},
                evidence=(f"demo:goal-{goal_id}",),
            )
        first = engine.register_opportunity(
            proposal(
                "phase12-first-task",
                "Review the highest-value bounded task",
                "An active goal has a concrete next action with a verifiable receipt.",
                "Choose whether CCT should begin the bounded task.",
            )
        )
        first_run = ProactiveRunner(store).run_once(time_bucket="2026-08-23")
        if not first_run["message"]:
            raise RuntimeError("Phase 12 first opportunity was not presented")
        accepted = OpportunityInitiative(store).record_feedback(
            feedback_id="phase12-first-task-accept",
            opportunity_id="phase12-first-task",
            principal_id="mike",
            decision="INTERESTED",
            evidence=("demo:explicit-operator-accept",),
            source_authority="operator",
        )
        second = engine.register_opportunity(
            proposal(
                "phase12-second-task",
                "Inspect a second useful opportunity",
                "A second distinct task demonstrates cooldown-preserving deferred initiative.",
                "Return the second task card only after the shared cooldown expires.",
            )
        )
        deferred_one = ProactiveRunner(store).run_once(time_bucket="2026-08-23")
        deferred_two = ProactiveRunner(store).run_once(time_bucket="2026-08-23")
        second_run = ProactiveRunner(store).run_once(time_bucket="2026-08-23")
        if second_run.get("opportunity_id") != "phase12-second-task":
            raise RuntimeError("Phase 12 second opportunity was not selected after cooldown")
        kernel.form_goal(
            goal_id="phase12-scouted-task",
            statement="Originate one task from an uncovered active canonical goal.",
            rationale="The Phase 12 scout must find useful goal work without a model proposal.",
            source="joint",
            horizon="short",
            alignment={"truth": 0.9, "competence": 0.9, "autonomy": 0.8},
            evidence=("receipt: Uncovered active goal requires a model-free receipt task.",),
        )
        scout = OpportunityInitiative(store)._materialize_goal_candidates()
        scouted = store.events("opportunity.initiative.goal_candidate.created")
        if scout["created"] != 1 or not scouted:
            raise RuntimeError("Phase 12 active-goal scout did not originate one task")
        status = OpportunityInitiative(store).status()
        result = {
            "status": "pass",
            "version": VERSION,
            "first_registration": {
                "opportunity_id": first["opportunity_id"],
                "executable": first["executable"],
                "content_trust": first["content_trust"],
                "instructions_authorized": first["instructions_authorized"],
            },
            "first_presentation": {
                "initiative_kind": first_run["initiative_kind"],
                "message": first_run["message"],
                "external_effects": first_run["external_effects"],
            },
            "acceptance": {
                "decision": accepted["decision"],
                "operator_interest_recorded": accepted["operator_interest_recorded"],
                "execution_authority_granted": accepted["execution_authority_granted"],
                "capability_lease_changed": accepted["capability_lease_changed"],
                "opportunity_execution_status_changed": accepted[
                    "opportunity_execution_status_changed"
                ],
            },
            "second_registration": {
                "opportunity_id": second["opportunity_id"],
                "executable": second["executable"],
            },
            "cooldown": {
                "first_reason": deferred_one["reason"],
                "second_reason": deferred_two["reason"],
                "state_consumed": [
                    deferred_one["state_consumed"],
                    deferred_two["state_consumed"],
                ],
            },
            "second_presentation": {
                "message": second_run["message"],
                "external_effects": second_run["external_effects"],
            },
            "goal_scout": {
                **scout,
                "candidate_event_id": scouted[-1].event_id,
                "goal_id": scouted[-1].payload["goal_id"],
                "content_trust": scouted[-1].payload["content_trust"],
                "executable": scouted[-1].payload["executable"],
            },
            "initiative_status": status,
            "authority_side_effects": {
                "capability_leases": len(store.events("capability.lease.granted")),
                "opportunity_status_changes": len(
                    store.events("autonomy.opportunity.status_changed")
                ),
                "autonomy_runs": len(store.events("autonomy.run.completed")),
            },
            "proactive_emissions": len(store.events("proactive.message.emitted")),
            "event_chain": store.verify_chain(),
            "raw_chain_of_thought_stored": False,
        }
        if result["authority_side_effects"] != {
            "capability_leases": 0,
            "opportunity_status_changes": 0,
            "autonomy_runs": 0,
        }:
            raise RuntimeError("operator interest changed effect authority")
        if result["proactive_emissions"] != 2:
            raise RuntimeError("Phase 12 emission count mismatch")
        if not result["event_chain"]["valid"]:
            raise RuntimeError("Phase 12 event chain is invalid")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    finally:
        engine.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
