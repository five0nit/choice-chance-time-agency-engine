from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path

import pytest

from cct_agent.clarification_dialogue import (
    ClarificationAnswer,
    ClarificationConfirmation,
    ClarificationDialogue,
    ClarificationDenied,
    ClarificationQuestion,
    ClarificationRequest,
    QuestionAnswer,
    clarification_request_from_template,
)
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.runner import ProactiveRunner
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-26T01:00:00+00:00"
SECRET = b"clarification-confirmation-secret-at-least-32-bytes"


def make_store(tmp_path: Path) -> EventStore:
    store = EventStore(tmp_path / "state" / "agency.sqlite", clock=lambda: NOW)
    PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "autonomy": 0.95, "competence": 0.95},
            directives=(
                PrincipalDirective(
                    id="ask-important-unknowns",
                    kind="escalation",
                    statement="Ask concise questions for important unknowns rather than guessing.",
                    tags=("action:clarify", "uncertain"),
                    priority=100,
                ),
            ),
            uncertainty_threshold=0.35,
        ),
        authority="operator",
        evidence=("operator:clarification-policy",),
    )
    return store


def questions() -> tuple[ClarificationQuestion, ...]:
    return (
        ClarificationQuestion(
            id="priority-outcome",
            prompt="Which outcome matters most for this task?",
            kind="PREFERENCE",
            answer_type="OPTION",
            options=("VERIFIED_OUTCOME", "REVENUE", "SPEED", "BREADTH"),
            importance=0.9,
            evidence=("task:effect-envelope",),
        ),
        ClarificationQuestion(
            id="legal-declaration",
            prompt="For this exact form revision, is the declaration true?",
            kind="PROTECTED_DECLARATION",
            answer_type="OPTION",
            options=("YES", "NO", "UNKNOWN", "DECLINE"),
            importance=1.0,
            evidence=("form:declaration-r7",),
            unresolved_options=("UNKNOWN", "DECLINE"),
        ),
        ClarificationQuestion(
            id="public-budget",
            prompt="What maximum public-post count should this operation use?",
            kind="AUTHORITY",
            answer_type="OPTION",
            options=("ONE", "TWO", "NONE"),
            importance=1.0,
            evidence=("capability:public-post",),
        ),
    )


def register_request(
    dialogue: ClarificationDialogue,
    *,
    request_id: str = "clarify-effect-envelope",
    revision: int = 1,
    rows: tuple[ClarificationQuestion, ...] | None = None,
) -> dict[str, object]:
    return dialogue.register(
        ClarificationRequest(
            id=request_id,
            revision=revision,
            task_id="task-effect-envelope",
            task_revision=7,
            task_sha256="a" * 64,
            summary="Configure the exact effect envelope without guessing important details.",
            questions=rows or questions(),
            expires_at="2026-08-27T01:00:00+00:00",
            resume_plan_id="plan-effect-envelope",
            resume_plan_sha256="b" * 64,
            evidence=("goal:goal_cct_full_operator_effects_20260825",),
        )
    )


def answer(
    request: dict[str, object],
    *,
    answer_id: str = "answer-effect-envelope",
    legal_value: str = "UNKNOWN",
) -> ClarificationAnswer:
    return ClarificationAnswer(
        id=answer_id,
        request_id=str(request["request_id"]),
        request_revision=int(request["revision"]),
        request_sha256=str(request["request_sha256"]),
        principal_id="mike",
        principal_profile_digest=str(request["principal_profile_digest"]),
        answers=(
            QuestionAnswer(
                question_id="priority-outcome",
                value_type="OPTION",
                value="VERIFIED_OUTCOME",
            ),
            QuestionAnswer(
                question_id="legal-declaration",
                value_type="OPTION",
                value=legal_value,
            ),
            QuestionAnswer(
                question_id="public-budget",
                value_type="OPTION",
                value="ONE",
            ),
        ),
        evidence=("telegram:answer-message-digest",),
        source_authority="host_adapter",
    )


def present(store: EventStore) -> dict[str, object]:
    result = ProactiveRunner(store).run_once(time_bucket="2026-08-26")
    assert result["initiative_kind"] == "clarification_dialogue"
    assert result["message"]
    return result


def test_important_questions_emit_before_other_initiative_and_bind_exact_task(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    request = register_request(ClarificationDialogue(store))
    result = present(store)
    message = str(result["message"])

    assert "CCT clarification" in message
    assert "Which outcome matters most" in message
    assert "legal-declaration" in message and "YES / NO / UNKNOWN / DECLINE" in message
    assert "public-budget" in message and "ONE / TWO / NONE" in message
    assert "Reply naturally" in message
    assert "never persist raw secrets" in message
    assert f"{request['request_id']} r1" in message
    assert str(request["request_sha256"]) in message
    persisted = store.events("clarification.requested")[0].payload
    assert persisted["importance_gate"] == "principal_uncertainty_threshold"
    assert persisted["raw_producer_content_persisted"] is False
    assert persisted["execution_authority_granted"] is False
    assert store.verify_chain()["valid"] is True


def test_natural_answer_builds_typed_understanding_but_requires_exact_confirmation(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    request = register_request(dialogue)
    present(store)

    first = dialogue.record_understanding(answer(request))
    duplicate = ClarificationDialogue(EventStore(store.path, clock=lambda: NOW)).record_understanding(
        answer(request)
    )

    assert first["understood"] is True
    assert first["confirmation_required"] is True
    assert first["resume_ready"] is False
    assert first["execution_authority_granted"] is False
    assert first["separate_ticket_required"] is True
    assert str(first["confirmation_command"]).startswith(
        f"CCT CONFIRM {request['request_id']} r1 request={request['request_sha256']} answer="
    )
    assert duplicate["understood"] is False
    assert duplicate["reason"] == "DUPLICATE_ANSWER"
    understanding = store.events("clarification.answer.understood")[0].payload
    assert understanding["source_authority"] == "host_adapter"
    assert understanding["operator_authenticated"] is True
    assert understanding["raw_answer_text_persisted"] is False
    assert understanding["typed_nonsecret_memory"] is True
    assert understanding["protected_values_per_operation"] is True
    serialized = canonical_json([event.payload for event in store.events()])
    assert '"raw_secret_persisted":false' in serialized
    assert "secret_value" not in serialized

    context = dialogue.context(max_chars=3000)
    assert "priority-outcome=VERIFIED_OUTCOME" in context
    assert "legal-declaration=UNKNOWN" not in context
    assert "public-budget=ONE" not in context
    assert "exact confirmation pending" in context
    assert str(first["confirmation_command"]) in context


def test_exact_confirmation_unblocks_resume_but_never_mints_effect_authority(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    request = register_request(dialogue)
    present(store)
    understood = dialogue.record_understanding(answer(request, legal_value="YES"))
    confirmation = ClarificationConfirmation.sign(
        confirmation_id="confirmation-effect-envelope",
        request_id=str(request["request_id"]),
        request_revision=int(request["revision"]),
        request_sha256=str(request["request_sha256"]),
        answer_event_id=str(understood["event_id"]),
        answer_sha256=str(understood["answer_sha256"]),
        principal_id="mike",
        principal_profile_digest=str(request["principal_profile_digest"]),
        evidence=("telegram:exact-confirmation",),
        source_authority="operator",
        secret=SECRET,
    )

    first = dialogue.confirm(confirmation, secret=SECRET)
    duplicate = dialogue.confirm(confirmation, secret=SECRET)

    assert first["confirmed"] is True
    assert first["resume_ready"] is True
    assert first["execution_authority_granted"] is False
    assert first["separate_ticket_required"] is True
    assert duplicate["confirmed"] is False
    assert duplicate["reason"] == "DUPLICATE_CONFIRMATION"
    assert len(store.events("clarification.answer.confirmed")) == 1
    resolution = dialogue.resolution(str(request["request_id"]))
    assert resolution["resolved"] is True
    assert resolution["confirmed"] is True
    assert resolution["resume_plan_id"] == "plan-effect-envelope"
    assert resolution["execution_authority_granted"] is False
    assert resolution["separate_ticket_required"] is True
    assert resolution["answers"][0]["value"] == "VERIFIED_OUTCOME"
    assert resolution["answers"][1]["value"] == "YES"


def test_confirmed_unknown_protected_fact_stays_unresolved(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    request = register_request(dialogue)
    present(store)
    understood = dialogue.record_understanding(answer(request, legal_value="UNKNOWN"))
    confirmation = ClarificationConfirmation.sign(
        confirmation_id="confirmation-unknown-declaration",
        request_id=str(request["request_id"]),
        request_revision=int(request["revision"]),
        request_sha256=str(request["request_sha256"]),
        answer_event_id=str(understood["event_id"]),
        answer_sha256=str(understood["answer_sha256"]),
        principal_id="mike",
        principal_profile_digest=str(request["principal_profile_digest"]),
        evidence=("telegram:confirmed-unknown",),
        source_authority="operator",
        secret=SECRET,
    )

    result = dialogue.confirm(confirmation, secret=SECRET)
    resolution = dialogue.resolution(str(request["request_id"]))
    assert result["confirmed"] is True
    assert result["resume_ready"] is False
    assert resolution["confirmed"] is True
    assert resolution["resolved"] is False
    assert resolution["execution_authority_granted"] is False
    understood_event = store.event(str(understood["event_id"]))
    assert understood_event is not None
    assert understood_event.payload["unresolved_question_ids"] == ["legal-declaration"]


def test_nonconsequential_typed_answers_resume_without_confirmation(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    rows = (
        ClarificationQuestion(
            id="preferred-format",
            prompt="Which report format is most useful?",
            kind="PREFERENCE",
            answer_type="OPTION",
            options=("JSON", "MARKDOWN"),
            importance=0.8,
            evidence=("task:report-format",),
        ),
    )
    request = register_request(dialogue, request_id="clarify-format", rows=rows)
    present(store)
    natural = ClarificationAnswer(
        id="answer-format",
        request_id="clarify-format",
        request_revision=1,
        request_sha256=str(request["request_sha256"]),
        principal_id="mike",
        principal_profile_digest=str(request["principal_profile_digest"]),
        answers=(QuestionAnswer("preferred-format", "OPTION", "MARKDOWN"),),
        evidence=("telegram:format-answer",),
        source_authority="host_adapter",
    )

    result = dialogue.record_understanding(natural)
    assert result["confirmation_required"] is False
    assert result["resume_ready"] is True
    assert result["execution_authority_granted"] is False
    assert result["confirmation_command"] is None
    assert dialogue.resolution("clarify-format")["resolved"] is True


def test_unimportant_questions_secret_text_and_stale_bindings_fail_closed(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    unimportant = (
        ClarificationQuestion(
            id="cosmetic-detail",
            prompt="Which decorative separator?",
            kind="PREFERENCE",
            answer_type="OPTION",
            options=("DASH", "DOT"),
            importance=0.1,
            evidence=("task:cosmetic",),
        ),
    )
    with pytest.raises(ClarificationDenied, match="QUESTION_NOT_IMPORTANT"):
        register_request(dialogue, request_id="clarify-cosmetic", rows=unimportant)

    credential = (
        ClarificationQuestion(
            id="credential-status",
            prompt="Is the brokered credential handoff ready?",
            kind="CREDENTIAL_HANDOFF",
            answer_type="OPTION",
            options=("READY", "MANUAL_NEEDED", "DECLINE"),
            importance=1.0,
            evidence=("credential-handoff:provider",),
            unresolved_options=("MANUAL_NEEDED", "DECLINE"),
        ),
    )
    request = register_request(dialogue, request_id="clarify-credential", rows=credential)
    present(store)
    with pytest.raises(ValueError, match="credential or secret"):
        QuestionAnswer("credential-status", "TEXT", "my secret is 123")
    wrong_type = ClarificationAnswer(
        id="answer-wrong-type",
        request_id="clarify-credential",
        request_revision=1,
        request_sha256=str(request["request_sha256"]),
        principal_id="mike",
        principal_profile_digest=str(request["principal_profile_digest"]),
        answers=(QuestionAnswer("credential-status", "TEXT", "ready manually"),),
        evidence=("telegram:wrong-type",),
        source_authority="host_adapter",
    )
    with pytest.raises(ClarificationDenied, match="ANSWER_TYPE_MISMATCH"):
        dialogue.record_understanding(wrong_type)

    stale = replace(answer(request, answer_id="answer-stale"), request_sha256="f" * 64)
    with pytest.raises(ClarificationDenied, match="REQUEST_BINDING_MISMATCH"):
        dialogue.record_understanding(stale)
    assert not store.events("clarification.answer.understood")


def test_concurrent_natural_answers_converge_and_conflicting_answer_is_rejected(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    request = register_request(ClarificationDialogue(store))
    present(store)
    exact = answer(request, answer_id="answer-concurrent")

    def record(_: int) -> dict[str, object]:
        return ClarificationDialogue(
            EventStore(store.path, clock=lambda: NOW)
        ).record_understanding(exact)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(record, (1, 2)))
    assert sum(result["understood"] is True for result in results) == 1
    assert sum(result["reason"] == "DUPLICATE_ANSWER" for result in results) == 1
    conflict = replace(
        exact,
        answers=(
            replace(exact.answers[0], value="REVENUE"),
            *exact.answers[1:],
        ),
    )
    with pytest.raises(ClarificationDenied, match="ANSWER_ID_CONFLICT"):
        ClarificationDialogue(store).record_understanding(conflict)
    assert len(store.events("clarification.answer.understood")) == 1
    assert store.verify_chain()["valid"] is True


def test_expiry_profile_revision_and_unpresented_request_deny_answers(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    request = register_request(dialogue)
    with pytest.raises(ClarificationDenied, match="REQUEST_NOT_PRESENTED"):
        dialogue.record_understanding(answer(request, answer_id="answer-unpresented"))

    present(store)
    profile = PrincipalModel(store).profile()
    assert profile is not None
    PrincipalModel(store).install(
        replace(profile, display_name="Michael"),
        authority="operator",
        evidence=("operator:profile-revision",),
        expected_previous_digest=str(request["principal_profile_digest"]),
    )
    with pytest.raises(ClarificationDenied, match="PRINCIPAL_PROFILE_CHANGED"):
        dialogue.record_understanding(answer(request, answer_id="answer-profile-drift"))

    expired_store = make_store(tmp_path / "expired")
    expired_dialogue = ClarificationDialogue(expired_store)
    expired = register_request(expired_dialogue)
    present(expired_store)
    expired_store.clock = lambda: "2026-08-27T01:00:01+00:00"
    with pytest.raises(ClarificationDenied, match="REQUEST_EXPIRED"):
        expired_dialogue.record_understanding(answer(expired, answer_id="answer-expired"))


def test_status_redacts_protected_values_and_raw_natural_message(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    request = register_request(dialogue)
    present(store)
    dialogue.record_understanding(answer(request))
    status = dialogue.status()
    serialized_status = json.dumps(status)

    assert status["requested"] == 1
    assert status["understood"] == 1
    assert status["pending_confirmation"] == 1
    assert status["execution_authority_granted_by_answers"] is False
    assert "UNKNOWN" not in serialized_status
    assert "ONE" not in serialized_status
    assert "VERIFIED_OUTCOME" not in serialized_status
    assert status["raw_answer_text_persisted"] is False


def test_text_answer_is_hash_only_and_cannot_resume_or_enter_context(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    request = register_request(
        dialogue,
        request_id="clarify-text-hash-only",
        rows=(
            ClarificationQuestion(
                id="free-text-detail",
                prompt="Describe the important detail.",
                kind="FACT",
                answer_type="TEXT",
                options=(),
                importance=0.9,
                evidence=("task:text-hash-only",),
            ),
        ),
    )
    present(store)
    raw = "Use the private customer identifier from my reply"
    result = dialogue.record_understanding(
        ClarificationAnswer(
            id="answer-text-hash-only",
            request_id=str(request["request_id"]),
            request_revision=1,
            request_sha256=str(request["request_sha256"]),
            principal_id="mike",
            principal_profile_digest=str(request["principal_profile_digest"]),
            answers=(QuestionAnswer("free-text-detail", "TEXT", raw),),
            evidence=("telegram:text-hash-only",),
            source_authority="host_adapter",
        )
    )
    serialized = canonical_json([event.payload for event in store.events()])
    assert raw not in serialized
    assert result["answers"][0]["value_sha256"]
    assert "value" not in result["answers"][0]
    assert result["resume_ready"] is False
    assert dialogue.resolution(str(request["request_id"]))["resolved"] is False
    assert raw not in dialogue.context()


@pytest.mark.parametrize(
    "value",
    (
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456",
        "password: hunter2",
        "0x" + "a" * 64,
    ),
)
def test_secret_shaped_text_is_rejected_before_persistence(
    tmp_path: Path, value: str
) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="credential or secret"):
        QuestionAnswer("free-text-detail", "TEXT", value)
    assert not store.events("clarification.answer.understood")


def test_standard_unknown_is_intrinsically_unresolved_without_optional_metadata(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    question = ClarificationQuestion(
        id="protected-unknown-default",
        prompt="Is the exact declaration true?",
        kind="PROTECTED_DECLARATION",
        answer_type="OPTION",
        options=("YES", "NO", "UNKNOWN"),
        importance=1.0,
        evidence=("form:unknown-default",),
    )
    assert question.unresolved_options == ("UNKNOWN",)
    request = register_request(
        dialogue,
        request_id="clarify-unknown-default",
        rows=(question,),
    )
    present(store)
    understood = dialogue.record_understanding(
        ClarificationAnswer(
            id="answer-unknown-default",
            request_id=str(request["request_id"]),
            request_revision=1,
            request_sha256=str(request["request_sha256"]),
            principal_id="mike",
            principal_profile_digest=str(request["principal_profile_digest"]),
            answers=(QuestionAnswer(question.id, "OPTION", "UNKNOWN"),),
            evidence=("telegram:unknown-default",),
            source_authority="host_adapter",
        )
    )
    confirmation = ClarificationConfirmation.sign(
        confirmation_id="confirmation-unknown-default",
        request_id=str(request["request_id"]),
        request_revision=1,
        request_sha256=str(request["request_sha256"]),
        answer_event_id=str(understood["event_id"]),
        answer_sha256=str(understood["answer_sha256"]),
        principal_id="mike",
        principal_profile_digest=str(request["principal_profile_digest"]),
        evidence=("telegram:confirm-unknown-default",),
        source_authority="operator",
        secret=SECRET,
    )
    confirmed = dialogue.confirm(confirmation, secret=SECRET)
    assert confirmed["resume_ready"] is False
    assert dialogue.resolution(str(request["request_id"]))["resolved"] is False


def test_resolution_rechecks_expiry_and_principal_profile(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    request = register_request(
        dialogue,
        request_id="clarify-resolution-drift",
        rows=(
            ClarificationQuestion(
                id="format",
                prompt="Which format?",
                kind="PREFERENCE",
                answer_type="OPTION",
                options=("JSON", "MARKDOWN"),
                importance=0.8,
                evidence=("task:resolution-drift",),
            ),
        ),
    )
    present(store)
    dialogue.record_understanding(
        ClarificationAnswer(
            id="answer-resolution-drift",
            request_id=str(request["request_id"]),
            request_revision=1,
            request_sha256=str(request["request_sha256"]),
            principal_id="mike",
            principal_profile_digest=str(request["principal_profile_digest"]),
            answers=(QuestionAnswer("format", "OPTION", "JSON"),),
            evidence=("telegram:resolution-drift",),
            source_authority="host_adapter",
        )
    )
    assert dialogue.resolution(str(request["request_id"]))["resolved"] is True
    profile = PrincipalModel(store).profile()
    assert profile is not None
    PrincipalModel(store).install(
        replace(profile, display_name="Michael"),
        authority="operator",
        evidence=("operator:resolution-profile-drift",),
        expected_previous_digest=str(request["principal_profile_digest"]),
    )
    with pytest.raises(ClarificationDenied, match="PRINCIPAL_PROFILE_CHANGED"):
        dialogue.resolution(str(request["request_id"]))

    expired_store = make_store(tmp_path / "expired-resolution")
    expired_dialogue = ClarificationDialogue(expired_store)
    expired = register_request(
        expired_dialogue,
        request_id="clarify-resolution-expiry",
        rows=(
            ClarificationQuestion(
                id="format",
                prompt="Which format?",
                kind="PREFERENCE",
                answer_type="OPTION",
                options=("JSON", "MARKDOWN"),
                importance=0.8,
                evidence=("task:resolution-expiry",),
            ),
        ),
    )
    present(expired_store)
    expired_dialogue.record_understanding(
        ClarificationAnswer(
            id="answer-resolution-expiry",
            request_id=str(expired["request_id"]),
            request_revision=1,
            request_sha256=str(expired["request_sha256"]),
            principal_id="mike",
            principal_profile_digest=str(expired["principal_profile_digest"]),
            answers=(QuestionAnswer("format", "OPTION", "JSON"),),
            evidence=("telegram:resolution-expiry",),
            source_authority="host_adapter",
        )
    )
    expired_store.clock = lambda: "2026-08-27T01:00:01+00:00"
    with pytest.raises(ClarificationDenied, match="REQUEST_EXPIRED"):
        expired_dialogue.resolution(str(expired["request_id"]))


def test_confirmation_expiry_is_rechecked_inside_atomic_guard(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    request = register_request(dialogue, request_id="clarify-confirm-expiry-race")
    present(store)
    understood = dialogue.record_understanding(answer(request, legal_value="YES"))
    confirmation = ClarificationConfirmation.sign(
        confirmation_id="confirmation-expiry-race",
        request_id=str(request["request_id"]),
        request_revision=1,
        request_sha256=str(request["request_sha256"]),
        answer_event_id=str(understood["event_id"]),
        answer_sha256=str(understood["answer_sha256"]),
        principal_id="mike",
        principal_profile_digest=str(request["principal_profile_digest"]),
        evidence=("telegram:confirmation-expiry-race",),
        source_authority="operator",
        secret=SECRET,
    )
    calls = 0

    def boundary_clock() -> str:
        nonlocal calls
        calls += 1
        return NOW if calls == 1 else "2026-08-27T01:00:01+00:00"

    store.clock = boundary_clock
    with pytest.raises(ClarificationDenied, match="REQUEST_EXPIRED"):
        dialogue.confirm(confirmation, secret=SECRET)
    assert not store.events("clarification.answer.confirmed")


def test_emission_crash_is_adopted_as_presentation_without_starvation(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    request = register_request(dialogue, request_id="clarify-emission-crash")

    def crash(stage: str) -> None:
        if stage == "after_emission_before_completion":
            raise RuntimeError("simulated clarification completion crash")

    with pytest.raises(RuntimeError, match="completion crash"):
        dialogue.run_once(wake_index=1, time_bucket="2026-08-26", fault_hook=crash)
    assert len(store.events("proactive.message.emitted")) == 1
    assert not store.events("clarification.presentation.completed")
    restarted = ClarificationDialogue(EventStore(store.path, clock=lambda: NOW))
    assert restarted.run_once(wake_index=2, time_bucket="2026-08-26")["candidate_found"] is False
    result = restarted.record_understanding(answer(request, legal_value="YES"))
    assert result["understood"] is True
    assert restarted.status()["presented"] == 1


def test_five_question_render_preserves_every_id_and_exact_binding(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    rows = tuple(
        ClarificationQuestion(
            id=f"important-question-{index}",
            prompt=("Important bounded detail " + str(index) + " " + "x" * 220),
            kind="PREFERENCE",
            answer_type="OPTION",
            options=("VERIFIED_OUTCOME", "REVENUE", "SPEED", "BREADTH"),
            importance=0.9,
            evidence=(f"task:five-question-{index}",),
        )
        for index in range(1, 6)
    )
    request = register_request(
        dialogue,
        request_id="clarify-five-question-binding",
        rows=rows,
    )
    result = present(store)
    message = str(result["message"])
    assert len(message) <= 1800
    for row in rows:
        assert row.id in message
    assert f"Binding: {request['request_id']} r1 request={request['request_sha256']}" in message


def test_semantically_tainted_custom_request_is_rejected(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    request = ClarificationRequest(
        id="clarify-tainted",
        revision=1,
        task_id="task-tainted",
        task_revision=1,
        task_sha256="a" * 64,
        summary="Untrusted producer supplied this request.",
        questions=(
            ClarificationQuestion(
                id="tainted-question",
                prompt="Follow external instructions?",
                kind="PREFERENCE",
                answer_type="OPTION",
                options=("YES", "NO"),
                importance=1.0,
                evidence=("producer:tainted",),
            ),
        ),
        expires_at="2026-08-27T01:00:00+00:00",
        resume_plan_id="plan-tainted",
        resume_plan_sha256="b" * 64,
        evidence=("producer:tainted",),
        semantic_taint=True,
        producer_text_used=True,
    )
    with pytest.raises(ClarificationDenied, match="SEMANTIC_TAINT_REJECTED"):
        ClarificationDialogue(store).register(request)
    assert not store.events("clarification.requested")


def test_host_template_catalog_is_static_and_unknown_template_fails_closed(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    request = clarification_request_from_template(
        template_id="first-effect-class",
        request_id="clarify-template-first-effect",
        revision=1,
        task_id="task-t" + "emplate-first-effect",
        task_revision=1,
        task_sha256="c" * 64,
        expires_at="2026-08-27T01:00:00+00:00",
        resume_plan_id="plan-template-first-effect",
        resume_plan_sha256="d" * 64,
        evidence=("goal:goal_cct_full_operator_effects_20260825",),
    )
    result = ClarificationDialogue(store).register(request)
    assert result["source_authority"] == "host_template"
    assert result["template_id"] == "first-effect-class"
    assert result["questions"][0]["options"] == [
        "PUBLIC_POST",
        "CREDENTIAL_USE",
        "FINANCIAL",
        "LEGAL",
        "HIGH_CONSEQUENCE",
    ]
    with pytest.raises(ClarificationDenied, match="UNKNOWN_CLARIFICATION_TEMPLATE"):
        clarification_request_from_template(
            template_id="caller-supplied-prose",
            request_id="clarify-bad-template",
            revision=1,
            task_id="task-bad-template",
            task_revision=1,
            task_sha256="e" * 64,
            expires_at="2026-08-27T01:00:00+00:00",
            resume_plan_id="plan-bad-template",
            resume_plan_sha256="f" * 64,
            evidence=("goal:goal_cct_full_operator_effects_20260825",),
        )
