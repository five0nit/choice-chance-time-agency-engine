from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
from typing import Any

import pytest

from cct_agent.kernel import AgencyKernel, NO_OP_ID, default_constitution
from cct_agent.planning import (
    ApprovedGoal,
    AutonomyPlanner,
    DecisionAlternative,
    HierarchicalPlan,
    PlanBinding,
    PlanningDenied,
    PlanStage,
    StageHandoff,
    WorkerAdvanceRequest,
    WorkerClaimRequest,
)
from cct_agent.principal import (
    PrincipalDirective,
    PrincipalModel,
    PrincipalProfile,
)
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-24T05:00:00+00:00"


def digest(value: object) -> str:
    return sha256(canonical_json(value).encode()).hexdigest()


def principal_profile(*, display_name: str = "Mike") -> PrincipalProfile:
    return PrincipalProfile(
        principal_id="mike",
        display_name=display_name,
        values={"truth": 1.0, "competence": 0.9, "autonomy": 0.8},
        directives=(
            PrincipalDirective(
                id="prefer-bounded-delivery",
                kind="preference",
                statement="Prefer bounded, verified, reversible local delivery.",
                tags=("domain:workspace", "action:patch"),
                priority=90,
            ),
        ),
    )


def approved_goal() -> ApprovedGoal:
    return ApprovedGoal(
        id="goal-slice4-fixture",
        statement="Produce one controlled, locally verified autonomy fixture.",
        rationale="The operator requested a bounded proof of planning and handoff.",
        source="external",
        horizon="short",
        alignment={"truth": 0.9, "competence": 0.8, "autonomy": 0.6},
        approved_by="operator",
        approved_origin="operator:mike",
        approval_evidence=("operator://slice4-approved-goal",),
    )


def alternatives() -> tuple[DecisionAlternative, ...]:
    return (
        DecisionAlternative(
            id="research-first",
            summary="Research the controlled fixture before changing it.",
            predicted_outcome="A verified evidence receipt informs a smaller local patch.",
            value_impacts={"truth": 0.9, "competence": 0.8, "autonomy": 0.4},
            information_gain=0.8,
            uncertainty=0.1,
            time_cost=0.2,
        ),
        DecisionAlternative(
            id="prototype-first",
            summary="Prototype the controlled fixture before deeper research.",
            predicted_outcome="A reversible prototype reveals implementation constraints.",
            value_impacts={"truth": 0.5, "competence": 0.7, "autonomy": 0.5},
            information_gain=0.5,
            uncertainty=0.2,
            time_cost=0.3,
        ),
    )


def configured(
    tmp_path: Path,
) -> tuple[EventStore, AgencyKernel, PrincipalModel, AutonomyPlanner, Path]:
    store = EventStore(tmp_path / "state" / "agency.sqlite", clock=lambda: NOW)
    kernel = AgencyKernel(store, default_constitution("slice4-test"))
    kernel.initialize()
    principal = PrincipalModel(store)
    principal.install(
        principal_profile(),
        authority="operator",
        evidence=("operator://slice4-principal",),
    )
    private_root = tmp_path / "private-planning"
    planner = AutonomyPlanner(store, kernel, private_root)
    planner.approve_goal(approved_goal())
    planner.make_choice(
        goal_id="goal-slice4-fixture",
        alternatives=alternatives(),
        seed=0,
        decision_id="decision-slice4-fixture",
    )
    return store, kernel, principal, planner, private_root


def stage_handoff(name: str) -> StageHandoff:
    return StageHandoff(
        capability=f"fixture.{name}",
        tool_name=f"fixture_{name}",
        scope=f"private/technical-{name}",
        arguments_sha256=digest({"stage": name, "private": True}),
    )


def hierarchical_plan() -> HierarchicalPlan:
    return HierarchicalPlan(
        id="plan-slice4-fixture",
        goal_id="goal-slice4-fixture",
        decision_id="decision-slice4-fixture",
        chosen_option_id="research-first",
        summary="Research, patch, and verify one controlled local fixture.",
        stages=(
            PlanStage(
                id="discovery",
                summary="Group bounded discovery work.",
                kind="group",
            ),
            PlanStage(
                id="research",
                summary="Collect one bounded evidence receipt.",
                parent_id="discovery",
                handoff=stage_handoff("research"),
            ),
            PlanStage(
                id="delivery",
                summary="Group reversible delivery work.",
                kind="group",
            ),
            PlanStage(
                id="patch",
                summary="Prepare one reversible local patch.",
                parent_id="delivery",
                depends_on=("research",),
                handoff=stage_handoff("patch"),
            ),
            PlanStage(
                id="verify",
                summary="Verify the exact local result.",
                parent_id="delivery",
                depends_on=("patch",),
                handoff=stage_handoff("verify"),
            ),
        ),
    )


def stored_plan(
    tmp_path: Path,
) -> tuple[EventStore, AgencyKernel, PrincipalModel, AutonomyPlanner, Path, PlanBinding]:
    store, kernel, principal, planner, private_root = configured(tmp_path)
    result = planner.store_plan(hierarchical_plan())
    return store, kernel, principal, planner, private_root, result["binding"]


def test_goal_approval_exact_retry_and_partial_recovery_are_idempotent(
    tmp_path: Path,
) -> None:
    store, _kernel, _principal, planner, _root = configured(tmp_path / "retry")
    first = store.events("autonomy.goal.approved")[0]
    repeated = planner.approve_goal(approved_goal())
    assert repeated["created"] is False
    assert repeated["event_id"] == first.event_id
    assert len(store.events("goal.formed")) == 1
    assert len(store.events("autonomy.goal.approved")) == 1

    recovery_store = EventStore(
        tmp_path / "recovery" / "agency.sqlite", clock=lambda: NOW
    )
    recovery_kernel = AgencyKernel(
        recovery_store, default_constitution("slice4-test")
    )
    recovery_kernel.initialize()
    recovery_planner = AutonomyPlanner(
        recovery_store, recovery_kernel, tmp_path / "recovery" / "private"
    )
    goal = approved_goal()
    recovery_kernel.form_goal(
        goal_id=goal.id,
        statement=goal.statement,
        rationale=goal.rationale,
        source=goal.source,
        horizon=goal.horizon,
        alignment=goal.alignment,
        evidence=goal.approval_evidence,
    )
    recovered = recovery_planner.approve_goal(goal)
    assert recovered["created"] is True
    assert len(recovery_store.events("goal.formed")) == 1
    assert len(recovery_store.events("autonomy.goal.approved")) == 1

    concurrent_store = EventStore(
        tmp_path / "concurrent" / "agency.sqlite", clock=lambda: NOW
    )
    concurrent_kernel = AgencyKernel(
        concurrent_store, default_constitution("slice4-test")
    )
    concurrent_kernel.initialize()
    concurrent_planner = AutonomyPlanner(
        concurrent_store, concurrent_kernel, tmp_path / "concurrent" / "private"
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        concurrent = list(
            pool.map(lambda _index: concurrent_planner.approve_goal(goal), range(2))
        )
    assert sorted(result["created"] for result in concurrent) == [False, True]
    assert len({result["event_id"] for result in concurrent}) == 1
    assert len(concurrent_store.events("goal.formed")) == 1
    assert len(concurrent_store.events("autonomy.goal.approved")) == 1


def claim_request(
    binding: PlanBinding,
    *,
    worker_id: str = "worker-one",
    expected_revision: int = 0,
) -> WorkerClaimRequest:
    return WorkerClaimRequest(
        binding=binding,
        worker_id=worker_id,
        expected_revision=expected_revision,
    )


def test_operator_goal_choice_plan_and_serialized_handoff_are_durable_and_private(
    tmp_path: Path,
) -> None:
    store, kernel, _principal, planner, private_root = configured(tmp_path)

    goal = kernel.goal("goal-slice4-fixture")
    assert goal is not None
    assert goal.source == "external"
    approval = store.events("autonomy.goal.approved")
    assert len(approval) == 1
    assert approval[0].payload["approved_by"] == "operator"
    assert approval[0].payload["approved_origin"] == "operator:mike"
    assert approval[0].payload["constitution_fingerprint"] == kernel.constitution_fingerprint()
    assert approval[0].payload["alignment_score"] > 0

    decision_event = store.events("autonomy.decision.receipt")[0]
    decision = decision_event.payload
    assert decision["chosen_branch"]["id"] == "research-first"
    assert decision["chosen_branch"]["predicted_outcome"].startswith("A verified")
    assert {row["id"] for row in decision["rejected_branches"]} == {
        "prototype-first",
        NO_OP_ID,
    }
    assert set(decision["probabilities"]) == {
        "research-first",
        "prototype-first",
        NO_OP_ID,
    }
    assert decision["seed"] == 0
    assert decision["mode"] == "exploit"
    assert decision["exploration_draw"] is not None
    assert decision["sample_draw"] is None
    assert decision["selection_grants_authority"] is False
    assert planner.replay_choice("decision-slice4-fixture")["matches"] is True

    created = planner.store_plan(hierarchical_plan())
    binding = created["binding"]
    assert isinstance(binding, PlanBinding)
    assert created["created"] is True
    plan_event = store.events("autonomy.plan.stored")[0]
    assert plan_event.payload["summary"] == hierarchical_plan().summary
    assert plan_event.payload["atomic_stage_ids"] == ["research", "patch", "verify"]
    assert plan_event.payload["dependency_edges"] == [
        ["research", "patch"],
        ["patch", "verify"],
    ]
    assert plan_event.payload["state_transition"] == {"from": "ABSENT", "to": "READY"}
    assert plan_event.payload["content_in_event_ledger"] is False
    assert plan_event.payload["execution_ticket_required"] is True

    private_path = private_root / "plans" / "plan-slice4-fixture.json"
    private_payload = json.loads(private_path.read_text(encoding="utf-8"))
    assert private_payload["stages"][1]["handoff"]["scope"] == "private/technical-research"
    assert private_payload["bindings"]["plan_sha256"] == binding.plan_sha256
    assert os.stat(private_root).st_mode & 0o777 == 0o700
    assert os.stat(private_path).st_mode & 0o777 == 0o600
    ledger_text = canonical_json([event.payload for event in store.events()])
    assert "private/technical-research" not in ledger_text
    assert stage_handoff("research").arguments_sha256 not in ledger_text

    claim = planner.claim_stage(claim_request(binding))
    assert claim["stage_id"] == "research"
    assert claim["attempt"] == 1
    assert claim["cursor_revision"] == 1
    assert claim["state_transition"] == {"from": "READY", "to": "CLAIMED"}
    assert claim["execution_ticket_binding"] == {
        "goal_id": "goal-slice4-fixture",
        "plan_id": "plan-slice4-fixture",
        "plan_hash": binding.plan_sha256,
        "stage": "research",
        "attempt": 1,
        "tool_name": "fixture_research",
        "arguments_sha256": stage_handoff("research").arguments_sha256,
    }
    assert claim["execution_authority_granted"] is False
    assert claim["execution_ticket_required"] is True

    advanced = planner.advance_stage(
        WorkerAdvanceRequest(
            binding=binding,
            worker_id="worker-one",
            stage_id="research",
            attempt=1,
            claim_event_id=claim["event_id"],
            expected_revision=1,
            outcome_sha256=digest({"verified": "research"}),
        )
    )
    assert advanced["cursor_revision"] == 2
    assert advanced["state_transition"] == {"from": "CLAIMED", "to": "READY"}
    second = planner.claim_stage(
        claim_request(binding, worker_id="worker-two", expected_revision=2)
    )
    assert second["stage_id"] == "patch"
    assert store.verify_chain()["valid"] is True


def test_goal_provenance_and_genuine_non_decoy_alternatives_fail_closed(
    tmp_path: Path,
) -> None:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    kernel = AgencyKernel(store, default_constitution("slice4-test"))
    kernel.initialize()
    PrincipalModel(store).install(
        principal_profile(),
        authority="operator",
        evidence=("operator://profile",),
    )
    planner = AutonomyPlanner(store, kernel, tmp_path / "private")

    with pytest.raises(ValueError, match="source must be external or joint"):
        planner.approve_goal(replace(approved_goal(), source="self"))
    with pytest.raises(ValueError, match="unknown values"):
        planner.approve_goal(
            replace(
                approved_goal(),
                id="goal-invented-value",
                alignment={"invented_constitution_value": 1.0},
            )
        )

    planner.approve_goal(approved_goal())
    with pytest.raises(PlanningDenied) as too_few:
        planner.make_choice(
            goal_id=approved_goal().id,
            alternatives=alternatives()[:1],
            seed=0,
            decision_id="decision-too-few",
        )
    assert too_few.value.reason_code == "GENUINE_ALTERNATIVES_REQUIRED"

    decoy = replace(alternatives()[0], id="research-first-decoy")
    with pytest.raises(PlanningDenied) as duplicated:
        planner.make_choice(
            goal_id=approved_goal().id,
            alternatives=(alternatives()[0], decoy),
            seed=0,
            decision_id="decision-decoy",
        )
    assert duplicated.value.reason_code == "GENUINE_ALTERNATIVES_REQUIRED"
    assert store.events("decision.made") == []
    assert store.events("autonomy.decision.receipt") == []


def test_choice_requires_operator_approval_and_two_allowed_action_alternatives(
    tmp_path: Path,
) -> None:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    kernel = AgencyKernel(store, default_constitution("slice4-test"))
    kernel.initialize()
    PrincipalModel(store).install(
        principal_profile(),
        authority="operator",
        evidence=("operator://profile",),
    )
    planner = AutonomyPlanner(store, kernel, tmp_path / "private")

    with pytest.raises(ValueError, match="approved_by must be operator"):
        planner.approve_goal(replace(approved_goal(), approved_by="self"))

    kernel.form_goal(
        goal_id="goal-self-not-approved",
        statement="Try to enter the approved planning path.",
        rationale="Regression fixture for approval binding.",
        source="self",
        horizon="short",
        alignment={"truth": 0.8},
        evidence=("fixture://self-goal",),
    )
    with pytest.raises(PlanningDenied) as unapproved:
        planner.make_choice(
            goal_id="goal-self-not-approved",
            alternatives=alternatives(),
            seed=0,
            decision_id="decision-self-not-approved",
        )
    assert unapproved.value.reason_code == "GOAL_NOT_APPROVED"

    planner.approve_goal(approved_goal())
    blocked = tuple(
        replace(
            alternative,
            id=f"{alternative.id}-blocked",
            blocked_reasons=("MISSING_AUTHORITY",),
        )
        for alternative in alternatives()
    )
    with pytest.raises(PlanningDenied) as no_allowed_choice:
        planner.make_choice(
            goal_id=approved_goal().id,
            alternatives=blocked,
            seed=0,
            decision_id="decision-no-allowed-actions",
        )
    assert no_allowed_choice.value.reason_code == "GENUINE_ALTERNATIVES_REQUIRED"
    assert store.events("decision.made") == []
    assert store.events("autonomy.decision.receipt") == []


def test_invalid_dependency_order_and_cycles_never_store_a_plan(tmp_path: Path) -> None:
    store, _kernel, _principal, planner, private_root = configured(tmp_path)
    base = hierarchical_plan()
    invalid_rows = (
        (
            replace(base.stages[1], depends_on=("patch",)),
            *base.stages[2:],
        ),
        (
            *base.stages[:3],
            replace(base.stages[3], depends_on=("verify",)),
            replace(base.stages[4], depends_on=("patch",)),
        ),
    )
    for index, stages in enumerate(invalid_rows):
        with pytest.raises(PlanningDenied) as error:
            planner.store_plan(
                replace(base, id=f"plan-invalid-{index}", stages=tuple(stages))
            )
        assert error.value.reason_code == "INVALID_DEPENDENCY_ORDER"
    assert store.events("autonomy.plan.stored") == []
    assert not (private_root / "plans" / "plan-invalid-0.json").exists()


def test_plan_hash_and_constitution_drift_deny_without_cursor_mutation(
    tmp_path: Path,
) -> None:
    store, _kernel, _principal, planner, private_root, binding = stored_plan(
        tmp_path / "hash-drift"
    )
    wrong_binding = replace(binding, plan_sha256="f" * 64)
    with pytest.raises(PlanningDenied) as caller_drift:
        planner.claim_stage(claim_request(wrong_binding))
    assert caller_drift.value.reason_code == "PLAN_DIGEST_MISMATCH"
    assert store.events("autonomy.plan.stage.claimed") == []

    private_path = private_root / "plans" / "plan-slice4-fixture.json"
    private_path.write_text('{"drifted":true}', encoding="utf-8")
    with pytest.raises(PlanningDenied) as file_drift:
        planner.claim_stage(claim_request(binding))
    assert file_drift.value.reason_code == "PLAN_DIGEST_MISMATCH"
    assert store.events("autonomy.plan.stage.claimed") == []

    other_store, _kernel, _principal, other, _root, other_binding = stored_plan(
        tmp_path / "constitution-drift"
    )
    other_store.append(
        "constitution.initialized",
        {
            "constitution": {"identity": "unauthorized-replacement"},
            "fingerprint": "0" * 64,
        },
    )
    assert other_store.verify_chain()["valid"] is True
    with pytest.raises(PlanningDenied) as constitution_drift:
        other.claim_stage(claim_request(other_binding))
    assert constitution_drift.value.reason_code == "CONSTITUTION_MISMATCH"
    assert other_store.events("autonomy.plan.stage.claimed") == []


def test_decision_replay_and_cursor_admission_reject_changed_ledger_bytes(
    tmp_path: Path,
) -> None:
    store, _kernel, _principal, planner, _root, binding = stored_plan(tmp_path)
    assert planner.replay_choice(binding.decision_id)["matches"] is True
    decision = store.events("autonomy.decision.receipt")[0]
    changed = dict(decision.payload)
    changed["probabilities"] = {"research-first": 0.5, NO_OP_ID: 0.5}
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE event_id = ?",
            (canonical_json(changed), decision.event_id),
        )

    replay = planner.replay_choice(binding.decision_id)
    assert replay["matches"] is False
    assert replay["chain_valid"] is False
    with pytest.raises(PlanningDenied) as changed_history:
        planner.claim_stage(claim_request(binding))
    assert changed_history.value.reason_code == "LEDGER_CHAIN_INVALID"
    assert store.events("autonomy.plan.stage.claimed") == []


def test_decision_receipt_checks_replayed_choice_not_only_stored_choice(
    tmp_path: Path,
) -> None:
    store, _kernel, _principal, planner, _root = configured(tmp_path)
    events = store.events()
    changed_events = []
    changed_receipt = None
    for event in events:
        payload = dict(event.payload)
        if event.kind == "decision.made":
            payload["chosen_option_id"] = "prototype-first"
        elif event.kind == "autonomy.decision.receipt":
            old_chosen = dict(payload["chosen_branch"])
            old_rejected = [dict(branch) for branch in payload["rejected_branches"]]
            prototype = next(
                branch for branch in old_rejected if branch["id"] == "prototype-first"
            )
            payload["chosen_branch"] = prototype
            payload["rejected_branches"] = [
                old_chosen,
                *(branch for branch in old_rejected if branch is not prototype),
            ]
            changed_receipt = replace(event, payload=payload)
            changed_events.append(changed_receipt)
            continue
        changed_events.append(replace(event, payload=payload))
    assert changed_receipt is not None
    assert planner._decision_receipt_matches(changed_events, changed_receipt) is False


def test_stale_principal_profile_denies_claim_and_advance_without_mutation(
    tmp_path: Path,
) -> None:
    store, _kernel, principal, planner, _root, binding = stored_plan(tmp_path)
    initial = principal.status()
    principal.install(
        principal_profile(display_name="Michael"),
        authority="operator",
        evidence=("operator://profile-revision",),
        expected_previous_digest=initial["profile_digest"],
    )
    with pytest.raises(PlanningDenied) as stale:
        planner.claim_stage(claim_request(binding))
    assert stale.value.reason_code == "PRINCIPAL_PROFILE_STALE"
    assert store.events("autonomy.plan.stage.claimed") == []
    assert store.events("autonomy.plan.stage.advanced") == []


def test_forged_principal_snapshot_and_out_of_order_claim_fail_closed(
    tmp_path: Path,
) -> None:
    store, _kernel, _principal, planner, _root, binding = stored_plan(
        tmp_path / "principal-digest"
    )
    store.append(
        "principal.profile.installed",
        {
            "schema_version": 1,
            "revision": binding.principal_profile_revision,
            "profile_digest": binding.principal_profile_digest,
            "previous_profile_digest": binding.principal_profile_digest,
            "authority": "operator",
            "evidence": ["fixture://forged-profile"],
            "profile": principal_profile(display_name="Changed without digest").as_payload(),
        },
    )
    assert store.verify_chain()["valid"] is True
    with pytest.raises(PlanningDenied) as forged_profile:
        planner.claim_stage(claim_request(binding))
    assert forged_profile.value.reason_code == "PRINCIPAL_PROFILE_STALE"
    assert store.events("autonomy.plan.stage.claimed") == []

    other_store, _kernel, _principal, other, _root, other_binding = stored_plan(
        tmp_path / "out-of-order"
    )
    forged_claim = other_store.append(
        "autonomy.plan.stage.claimed",
        {
            "schema_version": 1,
            "request_sha256": digest({"fixture": "out-of-order"}),
            "plan_id": other_binding.plan_id,
            "stage_id": "verify",
            "worker_id": "worker-forged",
            "attempt": 1,
            "expected_revision": 0,
            "cursor_revision": 1,
            "state_transition": {"from": "READY", "to": "CLAIMED"},
            "execution_ticket_required": True,
            "execution_authority_granted": False,
        },
    )
    assert other_store.verify_chain()["valid"] is True
    with pytest.raises(PlanningDenied) as out_of_order:
        other.advance_stage(
            WorkerAdvanceRequest(
                binding=other_binding,
                worker_id="worker-forged",
                stage_id="verify",
                attempt=1,
                claim_event_id=forged_claim.event_id,
                expected_revision=1,
                outcome_sha256=digest({"verified": "out-of-order"}),
            )
        )
    assert out_of_order.value.reason_code == "CURSOR_STATE_INVALID"
    assert other_store.events("autonomy.plan.stage.advanced") == []


def test_malformed_claim_flags_and_principal_lineage_block_cursor_mutation(
    tmp_path: Path,
) -> None:
    store, _kernel, _principal, planner, _root, binding = stored_plan(
        tmp_path / "claim-flags"
    )
    malformed_claim = store.append(
        "autonomy.plan.stage.claimed",
        {
            "schema_version": 1,
            "request_sha256": digest({"fixture": "malformed-claim"}),
            "plan_id": binding.plan_id,
            "stage_id": "research",
            "worker_id": "worker-malformed",
            "attempt": 1,
            "expected_revision": 0,
            "cursor_revision": 1,
            "state_transition": {"from": "READY", "to": "CLAIMED"},
            "execution_ticket_required": False,
            "execution_authority_granted": True,
        },
    )
    with pytest.raises(PlanningDenied) as malformed_flags:
        planner.advance_stage(
            WorkerAdvanceRequest(
                binding=binding,
                worker_id="worker-malformed",
                stage_id="research",
                attempt=1,
                claim_event_id=malformed_claim.event_id,
                expected_revision=1,
                outcome_sha256=digest({"verified": "malformed-claim"}),
            )
        )
    assert malformed_flags.value.reason_code == "CURSOR_STATE_INVALID"
    assert store.events("autonomy.plan.stage.advanced") == []

    other_store, _kernel, _principal, other, _root, other_binding = stored_plan(
        tmp_path / "principal-lineage"
    )
    installed = other_store.events("principal.profile.installed")[-1]
    malformed_profile = dict(installed.payload)
    malformed_profile["previous_profile_digest"] = "0" * 64
    malformed_profile["evidence"] = []
    other_store.append("principal.profile.installed", malformed_profile)
    with pytest.raises(PlanningDenied) as malformed_lineage:
        other.claim_stage(claim_request(other_binding))
    assert malformed_lineage.value.reason_code == "PRINCIPAL_PROFILE_STALE"
    assert other_store.events("autonomy.plan.stage.claimed") == []

    replay_store, _kernel, _principal, replay, _root, replay_binding = stored_plan(
        tmp_path / "claim-request-binding"
    )
    intended = claim_request(replay_binding, worker_id="worker-intended")
    replay_store.append(
        "autonomy.plan.stage.claimed",
        {
            "schema_version": 1,
            "request_sha256": digest(intended.as_payload()),
            "plan_id": replay_binding.plan_id,
            "stage_id": "research",
            "worker_id": "worker-other",
            "attempt": 1,
            "expected_revision": 0,
            "cursor_revision": 1,
            "state_transition": {"from": "READY", "to": "CLAIMED"},
            "execution_ticket_required": True,
            "execution_authority_granted": False,
        },
    )
    with pytest.raises(PlanningDenied) as changed_request_fields:
        replay.claim_stage(intended)
    assert changed_request_fields.value.reason_code == "CLAIM_RECEIPT_MISMATCH"
    assert len(replay_store.events("autonomy.plan.stage.claimed")) == 1


def test_cursor_rejects_non_string_completed_stage_identifiers(tmp_path: Path) -> None:
    store, _kernel, _principal, planner, _root = configured(tmp_path)
    base = hierarchical_plan()
    numeric_stage_plan = replace(
        base,
        id="plan-numeric-stage-fixture",
        stages=(
            base.stages[0],
            replace(base.stages[1], id="1"),
            base.stages[2],
            replace(base.stages[3], depends_on=("1",)),
            base.stages[4],
        ),
    )
    binding = planner.store_plan(numeric_stage_plan)["binding"]
    claim = planner.claim_stage(claim_request(binding))
    store.append(
        "autonomy.plan.stage.advanced",
        {
            "schema_version": 1,
            "request_sha256": digest({"fixture": "numeric-completed-stage"}),
            "plan_id": binding.plan_id,
            "stage_id": "1",
            "worker_id": claim["worker_id"],
            "attempt": 1,
            "claim_event_id": claim["event_id"],
            "outcome_sha256": digest({"verified": "numeric-stage"}),
            "expected_revision": 1,
            "cursor_revision": 2,
            "completed_stage_ids": [1],
            "state_transition": {"from": "CLAIMED", "to": "READY"},
            "execution_authority_granted": False,
        },
    )
    with pytest.raises(PlanningDenied) as noncanonical_completed:
        planner.cursor(binding.plan_id)
    assert noncanonical_completed.value.reason_code == "CURSOR_STATE_INVALID"


@pytest.mark.parametrize(
    ("target", "mode"),
    (("root", 0o755), ("plans", 0o755), ("file", 0o644)),
)
def test_private_plan_permission_drift_denies_claim(
    tmp_path: Path, target: str, mode: int
) -> None:
    store, _kernel, _principal, planner, private_root, binding = stored_plan(tmp_path)
    targets = {
        "root": private_root,
        "plans": private_root / "plans",
        "file": private_root / "plans" / f"{binding.plan_id}.json",
    }
    targets[target].chmod(mode)
    with pytest.raises(PlanningDenied) as permission_drift:
        planner.claim_stage(claim_request(binding))
    assert permission_drift.value.reason_code == "PRIVATE_PLAN_PERMISSIONS_INVALID"
    assert store.events("autonomy.plan.stage.claimed") == []


def test_store_plan_rejects_decision_without_complete_kernel_receipt(
    tmp_path: Path,
) -> None:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    kernel = AgencyKernel(store, default_constitution("slice4-test"))
    kernel.initialize()
    PrincipalModel(store).install(
        principal_profile(),
        authority="operator",
        evidence=("operator://profile",),
    )
    planner = AutonomyPlanner(store, kernel, tmp_path / "private")
    approval = planner.approve_goal(approved_goal())
    store.append(
        "autonomy.decision.receipt",
        {
            "schema_version": 1,
            "decision_id": "decision-slice4-fixture",
            "goal_id": approved_goal().id,
            "goal_approval_event_id": approval["event_id"],
            "chosen_branch": {"id": "research-first"},
        },
    )
    with pytest.raises(PlanningDenied) as incomplete_decision:
        planner.store_plan(hierarchical_plan())
    assert incomplete_decision.value.reason_code == "DECISION_BINDING_MISMATCH"
    assert store.events("autonomy.plan.stored") == []
    assert not (tmp_path / "private" / "plans" / "plan-slice4-fixture.json").exists()


def test_same_revision_concurrency_is_serialized_and_restart_replays_exactly(
    tmp_path: Path,
) -> None:
    store, kernel, _principal, planner, private_root, binding = stored_plan(tmp_path)
    requests = (
        claim_request(binding, worker_id="worker-a"),
        claim_request(binding, worker_id="worker-b"),
    )

    def claim(request: WorkerClaimRequest) -> tuple[str, Any]:
        try:
            return "ok", planner.claim_stage(request)
        except PlanningDenied as error:
            return "denied", error.reason_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(claim, requests))
    winners = [value for status, value in outcomes if status == "ok"]
    denials = [value for status, value in outcomes if status == "denied"]
    assert len(winners) == 1
    assert denials == ["CURSOR_REVISION_CONFLICT"]
    assert len(store.events("autonomy.plan.stage.claimed")) == 1
    winner = winners[0]

    restarted = AutonomyPlanner(store, kernel, private_root)
    repeated = restarted.claim_stage(
        claim_request(binding, worker_id=winner["worker_id"])
    )
    assert repeated["created"] is False
    assert repeated["event_id"] == winner["event_id"]
    assert restarted.cursor(binding.plan_id)["revision"] == 1

    advance_rows = (
        WorkerAdvanceRequest(
            binding=binding,
            worker_id=winner["worker_id"],
            stage_id="research",
            attempt=1,
            claim_event_id=winner["event_id"],
            expected_revision=1,
            outcome_sha256=digest({"outcome": "a"}),
        ),
        WorkerAdvanceRequest(
            binding=binding,
            worker_id=winner["worker_id"],
            stage_id="research",
            attempt=1,
            claim_event_id=winner["event_id"],
            expected_revision=1,
            outcome_sha256=digest({"outcome": "b"}),
        ),
    )

    def advance(request: WorkerAdvanceRequest) -> tuple[str, Any]:
        try:
            return "ok", restarted.advance_stage(request)
        except PlanningDenied as error:
            return "denied", error.reason_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        advanced = list(pool.map(advance, advance_rows))
    completion_winners = [value for status, value in advanced if status == "ok"]
    completion_denials = [value for status, value in advanced if status == "denied"]
    assert len(completion_winners) == 1
    assert completion_denials == ["CURSOR_REVISION_CONFLICT"]
    assert len(store.events("autonomy.plan.stage.advanced")) == 1
    repeated_advance = restarted.advance_stage(
        next(
            request
            for request in advance_rows
            if request.outcome_sha256 == completion_winners[0]["outcome_sha256"]
        )
    )
    assert repeated_advance["created"] is False
    assert repeated_advance["event_id"] == completion_winners[0]["event_id"]

    next_claim = restarted.claim_stage(
        claim_request(binding, worker_id="worker-next", expected_revision=2)
    )
    assert next_claim["stage_id"] == "patch"
    assert restarted.cursor(binding.plan_id)["completed_stage_ids"] == ["research"]
    assert store.verify_chain()["valid"] is True
