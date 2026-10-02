from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from cct_agent.autonomy import AutonomyEngine, Opportunity
from cct_agent.capabilities import CapabilityRegistry
from cct_agent.opportunity_handoff import (
    OpportunityTaskHandoff,
    OpportunityTaskHandoffDenied,
)
from cct_agent.opportunity_initiative import OpportunityInitiative
from cct_agent.principal import PrincipalModel
from cct_agent.runner import ProactiveRunner
from cct_agent.self_goals import SelfGoalEpisodeCoordinator, SelfGoalInputReceipt
from tests.test_full_stack_episode import ARTIFACT, build_episode, research_server
from tests.test_self_generated_goal_episode import (
    SECRET,
    candidates,
    runtime_adapters,
)


def interest_receipts(
    *, opportunity_id: str, interest_sha256: str
) -> tuple[SelfGoalInputReceipt, ...]:
    rows = []
    for kind, character in zip(
        ("observation", "value", "commitment"), ("a", "b", "c"), strict=True
    ):
        rows.append(
            SelfGoalInputReceipt.sign(
                receipt_id=f"receipt-{kind}",
                kind=kind,
                subject_id=f"fixture-{kind}",
                content_sha256=character * 64,
                issued_by="host_adapter",
                semantic_taint=False,
                secret=SECRET,
            )
        )
    rows.append(
        SelfGoalInputReceipt.sign(
            receipt_id="receipt-opportunity",
            kind="opportunity",
            subject_id=opportunity_id,
            content_sha256=interest_sha256,
            issued_by="host_adapter",
            semantic_taint=False,
            secret=SECRET,
        )
    )
    return tuple(rows)


def accepted_interest(source, store, tmp_path: Path, *, decision: str = "INTERESTED"):
    opportunity_id = "accepted-local-task"
    if source.kernel.goal(opportunity_id) is None:
        source.kernel.form_goal(
            goal_id=opportunity_id,
            statement="Advance one operator-interested local task with exact receipts.",
            rationale="Operator interest plus separate host authority should unlock bounded work.",
            source="joint",
            horizon="short",
            alignment={"truth": 0.8, "competence": 0.8, "autonomy": 0.7},
            evidence=("test:accepted-local-task",),
        )
    engine = AutonomyEngine(
        store,
        source.kernel,
        tmp_path / "opportunity-workspace",
        state_root=tmp_path / "opportunity-state",
    )
    try:
        engine.register_opportunity(
            Opportunity(
                id=opportunity_id,
                title="Review accepted local task",
                rationale="A bounded verified result would advance an active goal.",
                objective="Complete one bounded local task and return its receipt.",
                source="self:fixture",
                source_authority="self",
                value_impacts={"truth": 0.8, "competence": 0.8, "autonomy": 0.7},
                plan={},
                evidence=(f"goal:{opportunity_id}",),
                information_gain=0.8,
                uncertainty=0.1,
                time_cost=0.1,
                capability="proposal_only",
                goal_id=opportunity_id,
            )
        )
    finally:
        engine.close()
    presented = ProactiveRunner(store).run_once(time_bucket="2026-08-23")
    assert presented["message"]
    feedback = OpportunityInitiative(store).record_feedback(
        feedback_id="feedback-accepted-local-task",
        opportunity_id=opportunity_id,
        principal_id="mike",
        decision=decision,
        evidence=("operator:accepted-local-task",),
        source_authority="operator",
    )
    return opportunity_id, str(feedback["event_id"])


def owner_for_interest(
    source,
    store,
    opportunity_receipt_id: str,
    *,
    policy_id: str = "accepted-opportunity-task",
):
    bound_candidates = tuple(
        replace(
            candidate,
            required_receipt_ids=tuple(
                opportunity_receipt_id if row == "receipt-opportunity" else row
                for row in candidate.required_receipt_ids
            ),
        )
        for candidate in candidates(source.spec.config)
    )
    return SelfGoalEpisodeCoordinator(
        store,
        kernel=source.kernel,
        planner=source.planner,
        policy_id=policy_id,
        principal_id="mike",
        candidates=bound_candidates,
        authentication_secret=SECRET,
    )


def prepared_handoff(tmp_path: Path, base_url: str):
    source, store, _planner, workspace, sink, outbox = build_episode(
        tmp_path, base_url, verifier_passes=True
    )
    opportunity_id, feedback_event_id = accepted_interest(source, store, tmp_path)
    handoff = OpportunityTaskHandoff(store, principal_id="mike")
    interest = handoff.inspect_interest(
        opportunity_id=opportunity_id, feedback_event_id=feedback_event_id
    )
    receipts = interest_receipts(
        opportunity_id=opportunity_id, interest_sha256=interest.digest
    )
    owner = owner_for_interest(source, store, "receipt-opportunity")
    preparation = handoff.prepare(
        owner,
        opportunity_id=opportunity_id,
        feedback_event_id=feedback_event_id,
        receipts=receipts,
        seed=0,
    )
    adapters = runtime_adapters(
        store=store,
        preparation=preparation.self_goal,
        source_runner=source,
        workspace=workspace,
        deployment_sink=sink,
        outbox=outbox,
    )
    return (
        source,
        store,
        handoff,
        owner,
        preparation,
        receipts,
        adapters,
    )


def test_operator_interest_plus_separate_host_lease_executes_full_stack_once(
    tmp_path: Path,
) -> None:
    with research_server() as base_url:
        source, store, _planner, workspace, sink, outbox = build_episode(
            tmp_path, base_url, verifier_passes=True
        )
        opportunity_id, feedback_event_id = accepted_interest(source, store, tmp_path)
        handoff = OpportunityTaskHandoff(store, principal_id="mike")
        interest = handoff.inspect_interest(
            opportunity_id=opportunity_id, feedback_event_id=feedback_event_id
        )
        receipts = interest_receipts(
            opportunity_id=opportunity_id, interest_sha256=interest.digest
        )
        owner = owner_for_interest(source, store, "receipt-opportunity")
        preparation = handoff.prepare(
            owner,
            opportunity_id=opportunity_id,
            feedback_event_id=feedback_event_id,
            receipts=receipts,
            seed=0,
        )
        adapters = runtime_adapters(
            store=store,
            preparation=preparation.self_goal,
            source_runner=source,
            workspace=workspace,
            deployment_sink=sink,
            outbox=outbox,
        )
        first = handoff.run_prepared(
            owner,
            preparation,
            research=adapters[0],
            commands=adapters[1],
            patching=adapters[2],
            verifier=adapters[3],
            deployment=adapters[4],
            public_actions=adapters[5],
        )
        duplicate = handoff.run_prepared(
            owner,
            preparation,
            research=adapters[0],
            commands=adapters[1],
            patching=adapters[2],
            verifier=adapters[3],
            deployment=adapters[4],
            public_actions=adapters[5],
        )

    assert first.episode.episode.status == "completed"
    assert first.replayed is False
    assert duplicate.replayed is True
    assert duplicate.terminal_event_id == first.terminal_event_id
    assert len(store.events("opportunity.initiative.task_handoff.claimed")) == 1
    assert len(store.events("opportunity.initiative.task_handoff.prepared")) == 1
    assert len(store.events("opportunity.initiative.task_handoff.completed")) == 1
    assert len(store.events("deployment.local_fake.completed")) == 1
    assert len(store.events("public_action.fake_sink.completed")) == 1
    assert (sink / "releases" / "artifact.bin").read_bytes() == ARTIFACT
    terminal = store.events("opportunity.initiative.task_handoff.completed")[0].payload
    assert terminal["interest_granted_execution_authority"] is False
    assert terminal["execution_authority_source"] == (
        "separate_host_policy_capability_lease"
    )
    assert terminal["adapter_effects"] == 6
    assert terminal["external_effects"] == 0
    assert terminal["raw_producer_content_persisted"] is False
    assert store.events("autonomy.self_goal.episode.terminal")[0].payload[
        "adapter_effects"
    ] == 6
    assert store.verify_chain()["valid"] is True


def test_execution_rejects_substituted_preparation_and_nonlocal_adapter(
    tmp_path: Path,
) -> None:
    with research_server() as base_url:
        (
            _source,
            store,
            handoff,
            owner,
            preparation,
            _receipts,
            adapters,
        ) = prepared_handoff(tmp_path, base_url)
        substituted = replace(
            preparation,
            self_goal=replace(preparation.self_goal, policy_id="substituted-policy"),
        )
        with pytest.raises(
            OpportunityTaskHandoffDenied,
            match="OPPORTUNITY_TASK_PREPARATION_MISMATCH",
        ):
            handoff.run_prepared(
                owner,
                substituted,
                research=adapters[0],
                commands=adapters[1],
                patching=adapters[2],
                verifier=adapters[3],
                deployment=adapters[4],
                public_actions=adapters[5],
            )
        with pytest.raises(
            OpportunityTaskHandoffDenied, match="DEPLOYMENT_ADAPTER_NOT_LOCAL_FAKE"
        ):
            handoff.run_prepared(
                owner,
                preparation,
                research=adapters[0],
                commands=adapters[1],
                patching=adapters[2],
                verifier=adapters[3],
                deployment=object(),  # type: ignore[arg-type]
                public_actions=adapters[5],
            )

    assert not store.events("research.observation.recorded")
    assert not store.events("deployment.local_fake.completed")


def test_second_policy_conflicts_before_minting_another_lease(tmp_path: Path) -> None:
    with research_server() as base_url:
        (
            source,
            store,
            handoff,
            _owner,
            preparation,
            receipts,
            _adapters,
        ) = prepared_handoff(tmp_path, base_url)
        second = owner_for_interest(
            source,
            store,
            "receipt-opportunity",
            policy_id="different-opportunity-policy",
        )
        leases_before = len(store.events("capability.lease.granted"))
        with pytest.raises(
            OpportunityTaskHandoffDenied, match="OPPORTUNITY_TASK_CLAIM_CONFLICT"
        ):
            handoff.prepare(
                second,
                opportunity_id=preparation.interest.opportunity_id,
                feedback_event_id=preparation.interest.feedback_event_id,
                receipts=receipts,
                seed=0,
            )

    assert len(store.events("capability.lease.granted")) == leases_before
    assert not any(
        event.payload.get("policy_id") == "different-opportunity-policy"
        for event in store.events("autonomy.goal.approved")
    )


def test_profile_revision_before_owner_prepare_denies_before_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with research_server() as base_url:
        source, store, _planner, _workspace, _sink, _outbox = build_episode(
            tmp_path, base_url, verifier_passes=True
        )
        opportunity_id, feedback_event_id = accepted_interest(source, store, tmp_path)
        handoff = OpportunityTaskHandoff(store, principal_id="mike")
        interest = handoff.inspect_interest(
            opportunity_id=opportunity_id, feedback_event_id=feedback_event_id
        )
        receipts = interest_receipts(
            opportunity_id=opportunity_id, interest_sha256=interest.digest
        )
        owner = owner_for_interest(source, store, "receipt-opportunity")
        original = owner.prepare

        def revise_then_prepare(*args, **kwargs):
            model = PrincipalModel(store)
            profile = model.profile()
            assert profile is not None
            digest = model.status()["profile_digest"]
            model.install(
                replace(profile, display_name="Michael"),
                authority="operator",
                evidence=("operator:handoff-profile-revision",),
                expected_previous_digest=digest,
            )
            return original(*args, **kwargs)

        monkeypatch.setattr(owner, "prepare", revise_then_prepare)
        leases_before = len(store.events("capability.lease.granted"))
        approvals_before = len(store.events("autonomy.goal.approved"))
        with pytest.raises(
            OpportunityTaskHandoffDenied, match="PRINCIPAL_PROFILE_CHANGED"
        ):
            handoff.prepare(
                owner,
                opportunity_id=opportunity_id,
                feedback_event_id=feedback_event_id,
                receipts=receipts,
                seed=0,
            )

    assert len(store.events("capability.lease.granted")) == leases_before
    assert len(store.events("autonomy.goal.approved")) == approvals_before


def test_lease_revocation_after_stage_claim_denies_before_adapter_effect(
    tmp_path: Path,
) -> None:
    with research_server() as base_url:
        (
            _source,
            store,
            handoff,
            owner,
            preparation,
            _receipts,
            adapters,
        ) = prepared_handoff(tmp_path, base_url)

        def revoke_after_claim(stage_id: str, _claim_event_id: str) -> None:
            if stage_id == "research":
                CapabilityRegistry(store).revoke(
                    preparation.self_goal.lease_id,
                    authority="host_adapter",
                    reason="Deterministic post-claim revocation probe.",
                )

        with pytest.raises(
            OpportunityTaskHandoffDenied,
            match="SEPARATE_CAPABILITY_LEASE_REQUIRED",
        ):
            handoff.run_prepared(
                owner,
                preparation,
                research=adapters[0],
                commands=adapters[1],
                patching=adapters[2],
                verifier=adapters[3],
                deployment=adapters[4],
                public_actions=adapters[5],
                claim_fault_hook=revoke_after_claim,
            )

    assert not store.events("research.observation.recorded")
    assert not store.events("command.execution.completed")
    assert not store.events("deployment.local_fake.completed")


def test_interest_without_exact_host_binding_denies_before_goal_or_lease(
    tmp_path: Path,
) -> None:
    with research_server() as base_url:
        source, store, _planner, _workspace, _sink, _outbox = build_episode(
            tmp_path, base_url, verifier_passes=True
        )
        opportunity_id, feedback_event_id = accepted_interest(source, store, tmp_path)
        handoff = OpportunityTaskHandoff(store, principal_id="mike")
        owner = owner_for_interest(source, store, "receipt-opportunity")
        wrong = interest_receipts(
            opportunity_id=opportunity_id, interest_sha256="f" * 64
        )
        before_approvals = len(store.events("autonomy.goal.approved"))
        before_leases = len(store.events("capability.lease.granted"))

        with pytest.raises(
            OpportunityTaskHandoffDenied, match="HOST_INTEREST_BINDING_REQUIRED"
        ):
            handoff.prepare(
                owner,
                opportunity_id=opportunity_id,
                feedback_event_id=feedback_event_id,
                receipts=wrong,
                seed=0,
            )

    assert len(store.events("autonomy.goal.approved")) == before_approvals
    assert len(store.events("capability.lease.granted")) == before_leases
    assert not store.events("opportunity.initiative.task_handoff.prepared")
    assert not store.events("command.execution.completed")
    assert not store.events("deployment.local_fake.completed")


def test_skip_feedback_cannot_enter_task_handoff(tmp_path: Path) -> None:
    with research_server() as base_url:
        source, store, _planner, _workspace, _sink, _outbox = build_episode(
            tmp_path, base_url, verifier_passes=True
        )
        opportunity_id, feedback_event_id = accepted_interest(
            source, store, tmp_path, decision="SKIP"
        )
        handoff = OpportunityTaskHandoff(store, principal_id="mike")

        with pytest.raises(
            OpportunityTaskHandoffDenied, match="OPERATOR_INTEREST_REQUIRED"
        ):
            handoff.inspect_interest(
                opportunity_id=opportunity_id, feedback_event_id=feedback_event_id
            )

    assert not store.events("opportunity.initiative.task_handoff.prepared")
    assert not store.events("capability.lease.granted")
