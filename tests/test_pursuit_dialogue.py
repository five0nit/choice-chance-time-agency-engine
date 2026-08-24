from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path

import pytest

from cct_agent.kernel import AgencyKernel, NO_OP_ID, default_constitution
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.pursuit_dialogue import (
    Pursuit,
    PursuitDialogue,
    PursuitDialogueDenied,
    PursuitPortfolio,
    PursuitReply,
)
from cct_agent.runner import ProactiveRunner
from cct_agent.store import EventStore


NOW = "2026-08-24T12:30:00+00:00"
SECRET = b"priority-negotiation-auth-secret-32-bytes-minimum"


def make_store(tmp_path: Path) -> EventStore:
    return EventStore(tmp_path / "state" / "agency.sqlite", clock=lambda: NOW)


def install_principal(store: EventStore) -> None:
    PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 0.95, "autonomy": 0.95},
            directives=(
                PrincipalDirective(
                    id="negotiate-close-priorities",
                    kind="escalation",
                    statement="Ask one bounded concrete question when priorities are close.",
                    tags=("domain:pursuit", "action:prioritize", "uncertain"),
                    priority=100,
                ),
            ),
            uncertainty_threshold=0.35,
        ),
        authority="operator",
        evidence=("operator:priority-negotiation-mandate",),
    )


def install_goals(store: EventStore) -> AgencyKernel:
    kernel = AgencyKernel(store, default_constitution("pursuit-dialogue-test"))
    kernel.initialize()
    for goal_id, status in (
        ("goal-release", "paused"),
        ("goal-research", "active"),
        ("goal-review", "paused"),
        ("goal-qa", "paused"),
        ("goal-docs", "paused"),
    ):
        kernel.form_goal(
            goal_id=goal_id,
            statement=f"Advance {goal_id} through one bounded receipt.",
            rationale="Priority negotiation fixture needs genuine attributable goals.",
            source="joint",
            horizon="short",
            alignment={"truth": 0.8, "competence": 0.8, "autonomy": 0.7},
            evidence=(f"receipt:{goal_id}",),
        )
        if status != "active":
            kernel.set_goal_status(goal_id, status, "Await exact ranked operator priority.")
    return kernel


def pursuits(*, count: int = 2) -> tuple[Pursuit, ...]:
    rows = (
        Pursuit(
            id="ship-release",
            goal_id="goal-release",
            summary="Ship exact reviewed candidate",
            payoff=0.88,
            cost=0.24,
            uncertainty=0.18,
            required_authority="operator",
            evidence=("receipt:release-candidate",),
            consequential=True,
        ),
        Pursuit(
            id="research-gap",
            goal_id="goal-research",
            summary="Resolve highest-impact evidence gap",
            payoff=0.85,
            cost=0.22,
            uncertainty=0.20,
            required_authority="operator",
            evidence=("receipt:research-gap",),
        ),
        Pursuit(
            id="review-state",
            goal_id="goal-review",
            summary="Review state and crash semantics",
            payoff=0.78,
            cost=0.18,
            uncertainty=0.16,
            required_authority="host_adapter",
            evidence=("receipt:state-review",),
        ),
        Pursuit(
            id="qa-runtime",
            goal_id="goal-qa",
            summary="Exercise runtime canary",
            payoff=0.74,
            cost=0.20,
            uncertainty=0.15,
            required_authority="operator",
            evidence=("receipt:runtime-canary",),
        ),
        Pursuit(
            id="write-docs",
            goal_id="goal-docs",
            summary="Record exact release receipt",
            payoff=0.66,
            cost=0.12,
            uncertainty=0.08,
            required_authority="host_adapter",
            evidence=("receipt:release-docs",),
        ),
    )
    return rows[:count]


def register(
    dialogue: PursuitDialogue,
    *,
    proposal_id: str = "priority-20260824",
    revision: int = 1,
    count: int = 2,
) -> dict[str, object]:
    return dialogue.register(
        PursuitPortfolio(
            id=proposal_id,
            revision=revision,
            question="Which bounded pursuit should CCT own next?",
            pursuits=pursuits(count=count),
            expires_at="2026-08-25T12:30:00+00:00",
            ambiguous=True,
        )
    )


def signed_reply(
    proposal: dict[str, object],
    *,
    reply_id: str,
    decision: str,
    selected_pursuit_id: str,
    semantic_taint: bool = False,
) -> PursuitReply:
    return PursuitReply.sign(
        reply_id=reply_id,
        proposal_id=str(proposal["proposal_id"]),
        proposal_revision=int(proposal["revision"]),
        portfolio_sha256=str(proposal["portfolio_sha256"]),
        principal_id="mike",
        principal_profile_digest=str(proposal["principal_profile_digest"]),
        decision=decision,
        selected_pursuit_id=selected_pursuit_id,
        evidence=(f"telegram:{reply_id}",),
        source_authority="operator",
        semantic_taint=semantic_taint,
        secret=SECRET,
    )


def setup_dialogue(tmp_path: Path) -> tuple[EventStore, AgencyKernel, PursuitDialogue, dict[str, object]]:
    store = make_store(tmp_path)
    install_principal(store)
    kernel = install_goals(store)
    dialogue = PursuitDialogue(store)
    proposal = register(dialogue)
    return store, kernel, dialogue, proposal


def test_ranked_priority_question_contains_required_decision_fields_and_no_op(
    tmp_path: Path,
) -> None:
    store, _kernel, _dialogue, proposal = setup_dialogue(tmp_path)
    result = ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    message = result["message"]

    assert result["initiative_kind"] == "pursuit_dialogue"
    assert result["proposal_id"] == "priority-20260824"
    assert "Which bounded pursuit should CCT own next?" in message
    assert "Recommendation: ship-release" in message
    assert "1. ship-release" in message and "2. research-gap" in message
    assert "payoff=" in message and "cost=" in message and "uncertainty=" in message
    assert "authority=operator" in message
    assert "evidence=receipt:release-candidate" in message
    assert "NO_OP" in message
    assert "priority-20260824 r1" in message
    assert str(proposal["portfolio_sha256"]) in message
    assert len(message) <= 1800

    event = store.events("pursuit.dialogue.proposed")[0]
    assert event.payload["trigger_reasons"] == [
        "AMBIGUOUS_PRIORITY",
        "CLOSE_RANKED",
        "CONSEQUENTIAL",
        "MISSING_AUTHORITY",
    ]
    assert event.payload["ranked_pursuits"][-1]["id"] == NO_OP_ID
    assert event.payload["ranked_pursuits"][-1]["canonical"] is True
    assert event.payload["recommended_pursuit_id"] == "ship-release"
    assert event.payload["raw_producer_content_persisted"] is False
    assert store.verify_chain()["valid"] is True


def test_portfolio_requires_two_to_five_untainted_real_pursuits(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    install_principal(store)
    install_goals(store)
    dialogue = PursuitDialogue(store)
    with pytest.raises(ValueError, match="2-5"):
        dialogue.register(
            PursuitPortfolio(
                id="too-small",
                revision=1,
                question="Choose?",
                pursuits=pursuits(count=1),
                expires_at="2026-08-25T12:30:00+00:00",
                ambiguous=True,
            )
        )
    tainted = replace(pursuits(count=2)[0], semantic_taint=True)
    with pytest.raises(PursuitDialogueDenied, match="SEMANTIC_TAINT_REJECTED"):
        dialogue.register(
            PursuitPortfolio(
                id="tainted-portfolio",
                revision=1,
                question="Choose?",
                pursuits=(tainted, pursuits(count=2)[1]),
                expires_at="2026-08-25T12:30:00+00:00",
                ambiguous=True,
            )
        )
    assert not store.events("pursuit.dialogue.proposed")


@pytest.mark.parametrize(
    ("decision", "selected", "expected_statuses", "expected_transition_count"),
    (
        ("ACTIVATE", "ship-release", {"goal-release": "active", "goal-research": "active"}, 1),
        ("REDIRECT", "research-gap", {"goal-release": "paused", "goal-research": "active"}, 0),
        ("REJECT", NO_OP_ID, {"goal-release": "paused", "goal-research": "active"}, 0),
        ("CLOSE", "research-gap", {"goal-release": "paused", "goal-research": "completed"}, 1),
    ),
)
def test_authenticated_reply_applies_activation_redirection_rejection_or_closure_once(
    tmp_path: Path,
    decision: str,
    selected: str,
    expected_statuses: dict[str, str],
    expected_transition_count: int,
) -> None:
    store, kernel, dialogue, proposal = setup_dialogue(tmp_path)
    assert ProactiveRunner(store).run_once(time_bucket="2026-08-24")["message"]
    reply = signed_reply(
        proposal,
        reply_id=f"reply-{decision.casefold()}",
        decision=decision,
        selected_pursuit_id=selected,
    )
    result = dialogue.record_reply(reply, secret=SECRET)
    duplicate = PursuitDialogue(EventStore(store.path, clock=lambda: NOW)).record_reply(
        reply, secret=SECRET
    )

    assert result["applied"] is True
    assert result["decision"] == decision
    assert result["selected_pursuit_id"] == selected
    assert result["execution_authority_granted"] is False
    assert result["external_effects"] == 0
    assert duplicate["applied"] is False
    assert duplicate["reason"] == "DUPLICATE_REPLY"
    assert duplicate["goal_transition_count"] == 0
    assert len(store.events("pursuit.dialogue.reply.authenticated")) == 1
    assert len(store.events("pursuit.dialogue.reply.applied")) == 1
    transitions = [
        event
        for event in store.events("goal.status_changed")
        if event.payload.get("pursuit_reply_id") == reply.id
    ]
    assert len(transitions) == expected_transition_count
    for goal_id, status in expected_statuses.items():
        assert kernel.goal(goal_id).status == status


def test_redirect_from_recommended_goal_pauses_old_focus_and_activates_selected(
    tmp_path: Path,
) -> None:
    store, kernel, dialogue, proposal = setup_dialogue(tmp_path)
    kernel.set_goal_status("goal-release", "active", "Fixture starts recommended goal active.")
    kernel.set_goal_status("goal-research", "paused", "Fixture starts alternate goal paused.")
    ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    reply = signed_reply(
        proposal,
        reply_id="reply-real-redirection",
        decision="REDIRECT",
        selected_pursuit_id="research-gap",
    )
    result = dialogue.record_reply(reply, secret=SECRET)
    assert result["goal_transition_count"] == 2
    assert kernel.goal("goal-release").status == "paused"
    assert kernel.goal("goal-research").status == "active"


def test_stale_tainted_tampered_and_wrong_binding_replies_fail_closed(tmp_path: Path) -> None:
    store, _kernel, dialogue, first = setup_dialogue(tmp_path)
    ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    second = register(dialogue, revision=2)

    stale = signed_reply(
        first,
        reply_id="reply-stale",
        decision="ACTIVATE",
        selected_pursuit_id="ship-release",
    )
    with pytest.raises(PursuitDialogueDenied, match="STALE_PROPOSAL_REVISION"):
        dialogue.record_reply(stale, secret=SECRET)

    # Present current revision after cooldown advances.
    ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    current = ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    assert current["proposal_revision"] == 2

    tainted = signed_reply(
        second,
        reply_id="reply-tainted",
        decision="ACTIVATE",
        selected_pursuit_id="ship-release",
        semantic_taint=True,
    )
    with pytest.raises(PursuitDialogueDenied, match="SEMANTIC_TAINT_REJECTED"):
        dialogue.record_reply(tainted, secret=SECRET)

    valid = signed_reply(
        second,
        reply_id="reply-valid-base",
        decision="ACTIVATE",
        selected_pursuit_id="ship-release",
    )
    with pytest.raises(PursuitDialogueDenied, match="REPLY_AUTHENTICATION_FAILED"):
        dialogue.record_reply(replace(valid, signature="0" * 64), secret=SECRET)
    wrong_binding = PursuitReply.sign(
        reply_id="reply-wrong-binding",
        proposal_id=str(second["proposal_id"]),
        proposal_revision=int(second["revision"]),
        portfolio_sha256="f" * 64,
        principal_id="mike",
        principal_profile_digest=str(second["principal_profile_digest"]),
        decision="ACTIVATE",
        selected_pursuit_id="ship-release",
        evidence=("telegram:wrong-binding",),
        source_authority="operator",
        semantic_taint=False,
        secret=SECRET,
    )
    with pytest.raises(PursuitDialogueDenied, match="PROPOSAL_BINDING_MISMATCH"):
        dialogue.record_reply(wrong_binding, secret=SECRET)

    assert not store.events("pursuit.dialogue.reply.authenticated")
    assert not store.events("pursuit.dialogue.reply.applied")
    assert not [
        event
        for event in store.events("goal.status_changed")
        if event.payload.get("pursuit_reply_id")
    ]


def test_reply_recovers_after_crash_without_duplicate_transition(tmp_path: Path) -> None:
    store, kernel, dialogue, proposal = setup_dialogue(tmp_path)
    ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    reply = signed_reply(
        proposal,
        reply_id="reply-crash-recovery",
        decision="ACTIVATE",
        selected_pursuit_id="ship-release",
    )

    def crash(stage: str) -> None:
        if stage == "after_reply_recorded":
            raise RuntimeError("simulated reply crash")

    with pytest.raises(RuntimeError, match="simulated reply crash"):
        dialogue.record_reply(reply, secret=SECRET, fault_hook=crash)
    assert len(store.events("pursuit.dialogue.reply.authenticated")) == 1
    assert not store.events("pursuit.dialogue.reply.applied")
    store.clock = lambda: "2026-08-25T12:30:01+00:00"

    restarted = PursuitDialogue(
        EventStore(store.path, clock=lambda: "2026-08-25T12:30:02+00:00")
    )
    recovered = restarted.record_reply(reply, secret=SECRET)
    duplicate = restarted.record_reply(reply, secret=SECRET)
    assert recovered["applied"] is True
    assert recovered["recovered"] is True
    assert duplicate["reason"] == "DUPLICATE_REPLY"
    assert kernel.goal("goal-release").status == "active"
    transitions = [
        event
        for event in store.events("goal.status_changed")
        if event.payload.get("pursuit_reply_id") == reply.id
    ]
    assert len(transitions) == 1
    assert len(store.events("pursuit.dialogue.reply.applied")) == 1
    assert store.verify_chain()["valid"] is True


def test_redirect_recovers_from_half_committed_goal_transitions(tmp_path: Path) -> None:
    store, kernel, dialogue, proposal = setup_dialogue(tmp_path)
    kernel.set_goal_status("goal-release", "active", "Recommended pursuit starts active.")
    kernel.set_goal_status("goal-research", "paused", "Alternate pursuit starts paused.")
    ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    reply = signed_reply(
        proposal,
        reply_id="reply-half-transition",
        decision="REDIRECT",
        selected_pursuit_id="research-gap",
    )

    def crash(stage: str) -> None:
        if stage == "after_goal_transition:goal-release":
            raise RuntimeError("simulated half-transition crash")

    with pytest.raises(RuntimeError, match="half-transition crash"):
        dialogue.record_reply(reply, secret=SECRET, fault_hook=crash)
    assert kernel.goal("goal-release").status == "paused"
    assert kernel.goal("goal-research").status == "paused"
    assert not store.events("pursuit.dialogue.reply.applied")

    recovered = PursuitDialogue(
        EventStore(store.path, clock=lambda: NOW)
    ).record_reply(reply, secret=SECRET)
    assert recovered["recovered"] is True
    assert recovered["goal_transition_count"] == 2
    assert kernel.goal("goal-release").status == "paused"
    assert kernel.goal("goal-research").status == "active"
    transitions = [
        event
        for event in store.events("goal.status_changed")
        if event.payload.get("pursuit_reply_id") == reply.id
    ]
    assert len(transitions) == 2
    assert store.verify_chain()["valid"] is True


def test_concurrent_exact_replies_converge_on_one_transition(tmp_path: Path) -> None:
    store, kernel, _dialogue, proposal = setup_dialogue(tmp_path)
    ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    reply = signed_reply(
        proposal,
        reply_id="reply-concurrent",
        decision="ACTIVATE",
        selected_pursuit_id="ship-release",
    )

    def apply(_: int) -> dict[str, object]:
        return PursuitDialogue(
            EventStore(store.path, clock=lambda: NOW)
        ).record_reply(reply, secret=SECRET)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(apply, (1, 2)))
    assert sum(result["applied"] is True for result in results) == 1
    assert sum(result["reason"] == "DUPLICATE_REPLY" for result in results) == 1
    assert kernel.goal("goal-release").status == "active"
    transitions = [
        event
        for event in store.events("goal.status_changed")
        if event.payload.get("pursuit_reply_id") == reply.id
    ]
    assert len(transitions) == 1
    assert len(store.events("pursuit.dialogue.reply.applied")) == 1
    assert store.verify_chain()["valid"] is True


def test_foreign_goal_mutation_after_authenticated_reply_fails_closed(
    tmp_path: Path,
) -> None:
    store, kernel, dialogue, proposal = setup_dialogue(tmp_path)
    ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    reply = signed_reply(
        proposal,
        reply_id="reply-foreign-drift",
        decision="ACTIVATE",
        selected_pursuit_id="ship-release",
    )

    def crash(stage: str) -> None:
        if stage == "after_reply_recorded":
            raise RuntimeError("simulated pre-transition crash")

    with pytest.raises(RuntimeError, match="pre-transition crash"):
        dialogue.record_reply(reply, secret=SECRET, fault_hook=crash)
    kernel.set_goal_status(
        "goal-research",
        "paused",
        "Foreign mutation after authenticated reply snapshot.",
    )
    with pytest.raises(PursuitDialogueDenied, match="GOAL_STATE_DRIFT"):
        PursuitDialogue(EventStore(store.path, clock=lambda: NOW)).record_reply(
            reply, secret=SECRET
        )
    assert kernel.goal("goal-release").status == "paused"
    assert not [
        event
        for event in store.events("goal.status_changed")
        if event.payload.get("pursuit_reply_id") == reply.id
    ]
    assert not store.events("pursuit.dialogue.reply.applied")


def test_dialogue_restart_duplicate_wake_cooldown_and_global_daily_cap(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    install_principal(store)
    install_goals(store)
    dialogue = PursuitDialogue(store)
    for index in range(1, 6):
        register(dialogue, proposal_id=f"priority-{index}")

    runner = ProactiveRunner(store)
    first = runner.run_once(time_bucket="2026-08-24")
    restarted = ProactiveRunner(EventStore(store.path, clock=lambda: NOW))
    cooldown_one = restarted.run_once(time_bucket="2026-08-24")
    cooldown_two = restarted.run_once(time_bucket="2026-08-24")
    second = restarted.run_once(time_bucket="2026-08-24")
    assert first["message"]
    assert cooldown_one["reason"] == "COOLDOWN"
    assert cooldown_one["state_consumed"] is False
    assert cooldown_two["reason"] == "COOLDOWN"
    assert second["message"]

    # Deliver proposals 3 and 4 at shared cooldown spacing.
    for expected in ("priority-3", "priority-4"):
        assert restarted.run_once(time_bucket="2026-08-24")["reason"] == "COOLDOWN"
        assert restarted.run_once(time_bucket="2026-08-24")["reason"] == "COOLDOWN"
        delivered = restarted.run_once(time_bucket="2026-08-24")
        assert delivered["proposal_id"] == expected and delivered["message"]

    # Fifth remains unconsumed under shared daily cap, then emits next day.
    capped = restarted.run_once(time_bucket="2026-08-24")
    assert capped["reason"] == "DAILY_CAP"
    assert "COOLDOWN" in capped["reason_codes"]
    assert capped["state_consumed"] is False
    next_day = restarted.run_once(time_bucket="2026-08-25")
    assert next_day["proposal_id"] == "priority-5"
    assert next_day["message"]

    assert len(store.events("proactive.message.emitted")) == 5
    assert len(store.events("pursuit.dialogue.presentation.completed")) == 5
    messages = [event.payload["message"] for event in store.events("proactive.message.emitted")]
    assert len(messages) == len(set(messages))
    assert store.verify_chain()["valid"] is True


def test_expired_unanswered_proposal_closes_once_without_goal_or_external_effect(
    tmp_path: Path,
) -> None:
    store, kernel, dialogue, proposal = setup_dialogue(tmp_path)
    presented = ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    assert presented["proposal_id"] == proposal["proposal_id"]
    baseline = {
        goal_id: kernel.goal(goal_id).status
        for goal_id in ("goal-release", "goal-research")
    }
    store.clock = lambda: "2026-08-25T12:30:01+00:00"

    first = dialogue.run_once(wake_index=10, time_bucket="2026-08-25")
    restarted = PursuitDialogue(
        EventStore(store.path, clock=lambda: "2026-08-25T12:30:02+00:00")
    )
    duplicate = restarted.run_once(wake_index=11, time_bucket="2026-08-25")

    assert first["message"] == ""
    assert first["reason"] == "PRIORITY_DIALOGUE_EXPIRED"
    assert first["expired_count"] == 1
    assert first["state_consumed"] is True
    assert first["external_effects"] == 0
    assert duplicate["reason"] == "NO_PRIORITY_DIALOGUE"
    assert duplicate["expired_count"] == 0
    expirations = store.events("pursuit.dialogue.expired")
    assert len(expirations) == 1
    assert expirations[0].payload == {
        "schema_version": 1,
        "proposal_event_id": proposal["event_id"],
        "proposal_id": proposal["proposal_id"],
        "proposal_revision": proposal["revision"],
        "portfolio_sha256": proposal["portfolio_sha256"],
        "expires_at": proposal["expires_at"],
        "terminal_reason": "UNANSWERED_EXPIRED",
        "goal_transition_count": 0,
        "execution_authority_granted": False,
        "external_effects": 0,
        "raw_reply_text_persisted": False,
    }
    assert {
        goal_id: kernel.goal(goal_id).status
        for goal_id in ("goal-release", "goal-research")
    } == baseline
    assert restarted.status()["open_latest_revisions"] == 0
    assert restarted.status()["expired_proposals"] == 1

    late = signed_reply(
        proposal,
        reply_id="reply-after-expiry",
        decision="ACTIVATE",
        selected_pursuit_id="ship-release",
    )
    with pytest.raises(PursuitDialogueDenied, match="PROPOSAL_EXPIRED"):
        restarted.record_reply(late, secret=SECRET)
    assert not store.events("pursuit.dialogue.reply.authenticated")
    assert not store.events("pursuit.dialogue.reply.applied")
    assert store.verify_chain()["valid"] is True


def test_reply_persists_hashes_and_structured_summary_not_raw_message(tmp_path: Path) -> None:
    store, _kernel, dialogue, proposal = setup_dialogue(tmp_path)
    ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    sentinel = "PRIVATE RAW REPLY SENTINEL MUST NEVER PERSIST"
    reply = PursuitReply.sign(
        reply_id="reply-privacy",
        proposal_id=str(proposal["proposal_id"]),
        proposal_revision=int(proposal["revision"]),
        portfolio_sha256=str(proposal["portfolio_sha256"]),
        principal_id="mike",
        principal_profile_digest=str(proposal["principal_profile_digest"]),
        decision="ACTIVATE",
        selected_pursuit_id="ship-release",
        evidence=("telegram:privacy-receipt",),
        source_authority="operator",
        semantic_taint=False,
        secret=SECRET,
    )
    dialogue.record_reply(reply, secret=SECRET)
    serialized = json.dumps([event.payload for event in store.events()])
    assert sentinel not in serialized
    receipt = store.events("pursuit.dialogue.reply.authenticated")[0].payload
    assert receipt["raw_reply_text_persisted"] is False
    assert receipt["signature_scheme"] == "HMAC-SHA256"
    assert len(receipt["reply_sha256"]) == 64
