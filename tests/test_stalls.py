from __future__ import annotations

import json
from pathlib import Path

from cct_agent.cognitive_cycle import CognitiveCycle, Observation
from cct_agent.kernel import AgencyKernel, NO_OP_ID, default_constitution
from cct_agent.models import Option
from cct_agent.stalls import StallDetector
from cct_agent.store import EventStore


HOSTILE = "HOSTILE_STALL_PRODUCER_TEXT_never_persist_in_stall_receipt"


def fixture(tmp_path: Path) -> tuple[EventStore, CognitiveCycle, str]:
    store = EventStore(tmp_path / "agency.sqlite")
    kernel = AgencyKernel(store, default_constitution("stall-test"))
    kernel.initialize()
    goal = kernel.form_goal(
        goal_id="goal-stall-test",
        statement="Escape repeated blocked reasoning without weakening authority.",
        rationale="Repeated identical NO_OP outcomes need one governed exploration request.",
        source="joint",
        alignment={"truth": 0.9, "competence": 0.8, "autonomy": 0.7},
        evidence=("test:stall-contract",),
    )
    return store, CognitiveCycle(kernel), goal.id


def blocked_option() -> Option:
    return Option(
        id="blocked-effect",
        description=HOSTILE,
        value_impacts={"autonomy": 1.0},
        blocked_reasons=(HOSTILE,),
    )


def conflict_observation(identifier: str, evidence: str) -> Observation:
    return Observation(
        id=identifier,
        kind="unresolved_conflict",
        summary=HOSTILE,
        source="tool:verified-stall-fixture",
        confidence=0.9,
        salience=0.8,
        goal_relevance=1.0,
        novelty=0.2,
        urgency=0.7,
        unresolved_conflict=1.0,
        evidence=(evidence,),
    )


def test_repeated_identical_noop_emits_one_proposal_only_exploration_request(
    tmp_path: Path,
) -> None:
    store, cycle, goal_id = fixture(tmp_path)
    first = cycle.run(
        observations=[conflict_observation("same-conflict", "test:evidence-v1")],
        goal_id=goal_id,
        options=[blocked_option()],
        seed=1,
    )
    second = cycle.run(
        observations=[conflict_observation("same-conflict", "test:evidence-v1")],
        goal_id=goal_id,
        options=[blocked_option()],
        seed=2,
    )
    third = cycle.run(
        observations=[conflict_observation("same-conflict", "test:evidence-v1")],
        goal_id=goal_id,
        options=[blocked_option()],
        seed=3,
    )

    assert first["decision"]["chosen_option_id"] == NO_OP_ID
    assert first["stall"]["repeat_count"] == 1
    assert first["stall"]["exploration_requested"] is False
    assert second["stall"]["repeat_count"] == 2
    assert second["stall"]["detected"] is True
    assert second["stall"]["exploration_requested"] is True
    assert (
        "Proposal-only exploration requested for goal goal-stall-test"
        in cycle.context()
    )
    assert "does not grant effect authority" in cycle.context()
    assert third["stall"]["exploration_request_event_id"] == second["stall"][
        "exploration_request_event_id"
    ]
    assert len(store.events("cognition.stall.detected")) == 1
    assert len(store.events("cognition.exploration.requested")) == 1
    request = store.events("cognition.exploration.requested")[0]
    assert request.payload["proposal_only"] is True
    assert request.payload["effect_authority_granted"] is False
    assert request.payload["external_effects"] == 0
    assert request.payload["required_fields"] == [
        "provenance",
        "assumptions",
        "uncertainty",
        "falsifiable_discriminator",
    ]
    stall_payloads = [
        event.payload
        for event in store.events()
        if event.kind.startswith("cognition.stall")
        or event.kind == "cognition.exploration.requested"
    ]
    assert HOSTILE not in json.dumps(stall_payloads, sort_keys=True)
    assert store.verify_chain()["valid"] is True


def test_new_evidence_changes_fingerprint_and_requires_its_own_repeat(
    tmp_path: Path,
) -> None:
    store, cycle, goal_id = fixture(tmp_path)
    for seed in (1, 2):
        cycle.run(
            observations=[conflict_observation("conflict-v1", "test:evidence-v1")],
            goal_id=goal_id,
            options=[blocked_option()],
            seed=seed,
        )
    changed = cycle.run(
        observations=[conflict_observation("conflict-v2", "test:evidence-v2")],
        goal_id=goal_id,
        options=[blocked_option()],
        seed=3,
    )

    assert changed["stall"]["repeat_count"] == 1
    assert changed["stall"]["exploration_requested"] is False
    assert len(store.events("cognition.exploration.requested")) == 1

    repeated = cycle.run(
        observations=[conflict_observation("conflict-v2", "test:evidence-v2")],
        goal_id=goal_id,
        options=[blocked_option()],
        seed=4,
    )
    assert repeated["stall"]["repeat_count"] == 2
    assert repeated["stall"]["exploration_requested"] is True
    assert len(store.events("cognition.exploration.requested")) == 2
    status = StallDetector(store).status()
    assert status["detected"] == 2
    assert status["exploration_requests"] == 2
    assert status["external_effects"] == 0
