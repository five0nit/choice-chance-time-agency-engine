from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from cct_agent.clarification_dialogue import (
    ClarificationDialogue,
    clarification_request_from_template,
)
from cct_agent.gateway_replies import GatewayPursuitReplyAdapter
from cct_agent.principal import PrincipalModel
from cct_agent.runner import ProactiveRunner
from cct_agent.store import EventStore, canonical_json
import hermes_plugin
from tests.test_clarification_dialogue import NOW, answer, make_store, register_request
from tests.test_gateway_pursuit_reply import Gateway, source


class PluginContext:
    def __init__(self) -> None:
        self.hooks: dict[str, Callable[..., Any]] = {}
        self.tools: dict[str, dict[str, Any]] = {}

    def register_tool(self, **kwargs: Any) -> None:
        self.tools[str(kwargs["name"])] = kwargs

    def register_hook(self, name: str, handler: Callable[..., Any]) -> None:
        self.hooks[name] = handler

    def register_middleware(self, middleware_type: str, callback: object) -> None:
        del middleware_type, callback


def clarification_event(
    text: str,
    *,
    quoted: str | None,
    event_source: object | None = None,
    message_id: str = "clarification-message-1",
    reply_to_message_id: str | None = "outbound-clarification-1",
    reply_to_is_own_message: bool = True,
) -> object:
    return SimpleNamespace(
        text=text,
        source=event_source or source(),
        message_id=message_id,
        media_urls=[],
        reply_to_text=quoted,
        reply_to_message_id=reply_to_message_id,
        reply_to_is_own_message=reply_to_is_own_message,
    )


def setup_confirmation(tmp_path: Path):
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    request = register_request(dialogue)
    presentation = ProactiveRunner(store).run_once(time_bucket="2026-08-26")
    message = str(presentation["message"])
    understood = dialogue.record_understanding(answer(request, legal_value="YES"))
    secret_path = store.path.parent / "pursuit-reply-auth.key"
    secret_path.write_bytes(b"gateway-clarification-confirmation-secret-32-bytes")
    secret_path.chmod(0o600)
    return store, request, understood, secret_path, message


def confirmation_command(request: dict[str, object], understood: dict[str, object]) -> str:
    return (
        f"CCT CONFIRM {request['request_id']} r{request['revision']} "
        f"request={request['request_sha256']} answer={understood['answer_sha256']}"
    )


def test_exact_private_confirmation_applies_once_without_granting_effect_authority(
    tmp_path: Path,
) -> None:
    store, request, understood, secret_path, message = setup_confirmation(tmp_path)
    adapter = GatewayPursuitReplyAdapter(store, secret_path=secret_path)
    command = confirmation_command(request, understood)
    inbound = clarification_event(
        command,
        quoted=message,
        message_id="clarification-confirmation-1",
    )

    first = adapter.handle(event=inbound, gateway=Gateway())
    second = GatewayPursuitReplyAdapter(
        EventStore(store.path, clock=lambda: NOW), secret_path=secret_path
    ).handle(event=inbound, gateway=Gateway())

    assert first == {
        "action": "skip",
        "reason": "CCT_CLARIFICATION_CONFIRMATION_APPLIED",
    }
    assert second == {
        "action": "skip",
        "reason": "CCT_CLARIFICATION_CONFIRMATION_DUPLICATE",
    }
    confirmations = store.events("clarification.answer.confirmed")
    assert len(confirmations) == 1
    assert confirmations[0].payload["operator_authenticated"] is True
    assert confirmations[0].payload["execution_authority_granted"] is False
    assert confirmations[0].payload["separate_ticket_required"] is True
    resolution = ClarificationDialogue(store).resolution(str(request["request_id"]))
    assert resolution["resolved"] is True
    assert resolution["execution_authority_granted"] is False
    serialized = canonical_json([row.payload for row in store.events()])
    assert command not in serialized
    # Match the raw identifier, not a chance substring inside random event hashes.
    assert not re.search(r"\b4242\b", serialized)
    assert store.verify_chain()["valid"] is True


def test_confirmation_requires_exact_own_message_reply_and_authorized_private_source(
    tmp_path: Path,
) -> None:
    store, request, understood, secret_path, message = setup_confirmation(tmp_path)
    adapter = GatewayPursuitReplyAdapter(store, secret_path=secret_path)
    command = confirmation_command(request, understood)

    no_reply = adapter.handle(
        event=clarification_event(command, quoted=None, reply_to_message_id=None),
        gateway=Gateway(),
    )
    wrong_quote = adapter.handle(
        event=clarification_event(command, quoted=message + " changed"),
        gateway=Gateway(),
    )
    unauthorized = adapter.handle(
        event=clarification_event(command, quoted=message),
        gateway=Gateway(authorized=False),
    )
    group = adapter.handle(
        event=clarification_event(
            command,
            quoted=message,
            event_source=source(chat_type="group"),
        ),
        gateway=Gateway(),
    )
    malformed = adapter.handle(
        event=clarification_event(command + " extra", quoted=message),
        gateway=Gateway(),
    )

    assert no_reply == {
        "action": "skip",
        "reason": "CCT_CLARIFICATION_CONFIRMATION_RECIPIENT_MISMATCH",
    }
    assert wrong_quote == {
        "action": "skip",
        "reason": "CCT_CLARIFICATION_CONFIRMATION_RECIPIENT_MISMATCH",
    }
    assert unauthorized == {
        "action": "skip",
        "reason": "CCT_PURSUIT_REPLY_UNAUTHORIZED",
    }
    assert group == {
        "action": "skip",
        "reason": "CCT_PURSUIT_REPLY_PRIVATE_DM_REQUIRED",
    }
    assert malformed == {
        "action": "skip",
        "reason": "CCT_CLARIFICATION_CONFIRMATION_MALFORMED",
    }
    assert not store.events("clarification.answer.confirmed")


def test_natural_private_reply_maps_only_host_allowlisted_option_and_reaches_agent(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    expires = (datetime.fromisoformat(NOW) + timedelta(days=1)).isoformat()
    request = dialogue.register(
        clarification_request_from_template(
            template_id="important-outcome",
            request_id="clarify-natural-outcome",
            revision=1,
            task_id="task-natural-outcome",
            task_revision=1,
            task_sha256="c" * 64,
            expires_at=expires,
            resume_plan_id="plan-natural-outcome",
            resume_plan_sha256="d" * 64,
            evidence=("goal:goal_cct_full_operator_effects_20260825",),
        )
    )
    presentation = ProactiveRunner(store).run_once(time_bucket="2026-08-26")
    message = str(presentation["message"])
    secret_path = store.path.parent / "pursuit-reply-auth.key"
    secret_path.write_bytes(b"gateway-natural-answer-secret-at-least-32-bytes")
    secret_path.chmod(0o600)
    inbound = clarification_event("verified outcome", quoted=message)

    result = GatewayPursuitReplyAdapter(store, secret_path=secret_path).handle(
        event=inbound,
        gateway=Gateway(),
    )

    assert result is None
    understanding = store.events("clarification.answer.understood")
    assert len(understanding) == 1
    assert understanding[0].payload["source_authority"] == "host_adapter"
    assert understanding[0].payload["operator_authenticated"] is True
    assert understanding[0].payload["answers"] == [
        {
            "question_id": "important-outcome",
            "question_kind": "PREFERENCE",
            "value_type": "OPTION",
            "value": "VERIFIED_OUTCOME",
            "visibility": "typed_nonsecret_memory",
        }
    ]
    resolution = dialogue.resolution(str(request["request_id"]))
    assert resolution["resolved"] is True
    assert resolution["execution_authority_granted"] is False
    serialized = canonical_json([row.payload for row in store.events()])
    assert "verified outcome" not in serialized
    assert "VERIFIED_OUTCOME" in dialogue.context()


def test_natural_reply_must_quote_exact_emitted_message_and_match_closed_options(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    dialogue = ClarificationDialogue(store)
    request = dialogue.register(
        clarification_request_from_template(
            template_id="first-effect-class",
            request_id="clarify-first-effect",
            revision=1,
            task_id="task-first-effect",
            task_revision=1,
            task_sha256="e" * 64,
            expires_at="2026-08-27T01:00:00+00:00",
            resume_plan_id="plan-first-effect",
            resume_plan_sha256="f" * 64,
            evidence=("goal:goal_cct_full_operator_effects_20260825",),
        )
    )
    message = str(ProactiveRunner(store).run_once(time_bucket="2026-08-26")["message"])
    secret_path = store.path.parent / "pursuit-reply-auth.key"
    secret_path.write_bytes(b"gateway-natural-answer-secret-at-least-32-bytes")
    secret_path.chmod(0o600)
    adapter = GatewayPursuitReplyAdapter(store, secret_path=secret_path)

    assert adapter.handle(
        event=clarification_event("public post", quoted=message + " changed"),
        gateway=Gateway(),
    ) == {
        "action": "skip",
        "reason": "CCT_CLARIFICATION_NATURAL_REQUEST_MISMATCH",
    }
    assert adapter.handle(
        event=clarification_event("invented option", quoted=message),
        gateway=Gateway(),
    ) is None
    assert not store.events("clarification.answer.understood")
    assert request["request_id"] == "clarify-first-effect"


def test_plugin_registers_host_template_request_tool_and_same_nonmodel_reply_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("CCT_IDENTITY", "clarification-plugin-test")
    context = PluginContext()
    hermes_plugin.register(context)
    fixture_profile = PrincipalModel(make_store(tmp_path / "principal-fixture")).profile()
    assert fixture_profile is not None
    PrincipalModel(
        EventStore(tmp_path / "cct-agency" / "agency.sqlite")
    ).install(
        fixture_profile,
        authority="operator",
        evidence=("operator:clarification-plugin-test",),
    )
    context.tools["cct_form_goal"]["handler"](
        {
            "goal_id": "goal-plugin-first-effect",
            "statement": "Choose the first real effect class for a bounded canary.",
            "rationale": "Mike asked CCT to ask important questions instead of guessing.",
            "source": "joint",
            "horizon": "short",
            "alignment": {"truth": 0.9, "autonomy": 0.9, "competence": 0.9},
            "evidence": ["operator:clarification-plugin-test"],
        }
    )

    assert "cct_clarification_request" in context.tools
    assert "cct_clarification_answer" not in context.tools
    handler = context.tools["cct_clarification_request"]["handler"]
    result = handler(
        {
            "template_id": "first-effect-class",
            "request_id": "clarify-plugin-first-effect",
            "request_revision": 1,
            "task_id": "goal-plugin-first-effect",
            "task_revision": 1,
            "task_sha256": "a" * 64,
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(days=1)
            ).isoformat(),
            "resume_plan_id": "plan-plugin-first-effect",
            "resume_plan_sha256": "b" * 64,
            "evidence": ["goal:goal_cct_full_operator_effects_20260825"],
        }
    )
    parsed = __import__("json").loads(result)
    assert parsed["success"] is True
    assert parsed["question_content_source"] == "immutable_host_template"
    assert parsed["execution_authority_granted"] is False
    questions = parsed["clarification"]["questions"]
    assert [row["id"] for row in questions] == ["first-effect-class"]
    assert questions[0]["prompt"] == (
        "Which real effect class should CCT activate and canary first?"
    )
    assert parsed["clarification"]["source_authority"] == "host_template"
    assert set(context.hooks) == {
        "pre_gateway_dispatch",
        "pre_llm_call",
        "post_llm_call",
    }
