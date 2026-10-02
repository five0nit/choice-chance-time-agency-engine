from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from cct_agent.gateway_replies import GatewayPursuitReplyAdapter
from cct_agent.kernel import AgencyKernel, default_constitution
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.pursuit_dialogue import Pursuit, PursuitDialogue, PursuitPortfolio
from cct_agent.runner import ProactiveRunner
from cct_agent.store import EventStore, canonical_json
from hashlib import sha256
import hermes_plugin


NOW = "2026-08-24T18:30:00+00:00"


class Gateway:
    def __init__(self, *, authorized: bool = True) -> None:
        self.authorized = authorized
        self.auth_calls = 0

    def _is_user_authorized(self, source: object) -> bool:
        del source
        self.auth_calls += 1
        return self.authorized


class PluginContext:
    def __init__(self) -> None:
        self.hooks: dict[str, Callable[..., Any]] = {}

    def register_tool(self, **kwargs: object) -> None:
        del kwargs

    def register_hook(self, name: str, handler: Callable[..., Any]) -> None:
        self.hooks[name] = handler

    def register_middleware(self, middleware_type: str, callback: object) -> None:
        del middleware_type, callback


def setup_store(tmp_path: Path) -> tuple[EventStore, dict[str, object], Path]:
    state_root = tmp_path / "cct-agency"
    store = EventStore(state_root / "agency.sqlite", clock=lambda: NOW)
    kernel = AgencyKernel(store, default_constitution("gateway-reply-test"))
    kernel.initialize()
    PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 0.95, "autonomy": 0.95},
            directives=(
                PrincipalDirective(
                    id="choose-release-priority",
                    kind="escalation",
                    statement="Choose one exact bounded release priority.",
                    tags=("domain:release", "action:prioritize", "uncertain"),
                    priority=100,
                ),
            ),
            uncertainty_threshold=0.35,
        ),
        authority="operator",
        evidence=("operator:gateway-reply-test",),
    )
    for goal_id, status in (("goal-release", "paused"), ("goal-hold", "active")):
        kernel.form_goal(
            goal_id=goal_id,
            statement=f"Advance {goal_id} through one bounded receipt.",
            rationale="Gateway reply fixture requires two attributable goals.",
            source="joint",
            horizon="short",
            alignment={"truth": 0.8, "competence": 0.8, "autonomy": 0.7},
            evidence=(f"receipt:{goal_id}",),
        )
        if status != "active":
            kernel.set_goal_status(goal_id, status, "Await exact operator reply.")
    proposal = PursuitDialogue(store).register(
        PursuitPortfolio(
            id="cct-release-choice-20260825",
            revision=1,
            question="Freeze exact candidate or hold for another bounded slice?",
            pursuits=(
                Pursuit(
                    id="freeze-review-candidate",
                    goal_id="goal-release",
                    summary="Freeze and review exact candidate",
                    payoff=0.9,
                    cost=0.2,
                    uncertainty=0.1,
                    required_authority="operator",
                    evidence=("receipt:release-candidate",),
                    consequential=True,
                ),
                Pursuit(
                    id="hold-candidate",
                    goal_id="goal-hold",
                    summary="Hold candidate for one bounded slice",
                    payoff=0.82,
                    cost=0.18,
                    uncertainty=0.12,
                    required_authority="operator",
                    evidence=("receipt:hold-candidate",),
                ),
            ),
            expires_at="2026-08-26T18:30:00+00:00",
            ambiguous=True,
        )
    )
    presented = ProactiveRunner(store).run_once(time_bucket="2026-08-24")
    assert presented["proposal_id"] == proposal["proposal_id"]

    secret_path = state_root / "pursuit-reply-auth.key"
    secret_path.write_bytes(b"gateway-pursuit-reply-secret-at-least-32-bytes")
    secret_path.chmod(0o600)
    return store, proposal, secret_path


def source(*, chat_id: str = "4242", user_id: str = "4242", chat_type: str = "dm") -> object:
    return SimpleNamespace(
        platform=SimpleNamespace(value="telegram"),
        chat_id=chat_id,
        chat_type=chat_type,
        user_id=user_id,
        profile="generalist2",
    )


def recipient_binding(*, chat_id: str = "4242", user_id: str = "4242") -> str:
    return sha256(
        canonical_json(
            {
                "profile_name": "generalist2",
                "platform": "telegram",
                "chat_type": "private",
                "principal_id": "mike",
                "chat_id": chat_id,
                "user_id": user_id,
            }
        ).encode("utf-8")
    ).hexdigest()


def record_delivery(store: EventStore, proposal: dict[str, object], *, binding: str) -> None:
    store.append(
        "canary.telegram.delivery.completed",
        {
            "schema_version": "cct.canary.telegram-delivery.receipt.v1",
            "proposal_event_id": proposal["event_id"],
            "proposal_id": proposal["proposal_id"],
            "proposal_revision": proposal["revision"],
            "portfolio_sha256": proposal["portfolio_sha256"],
            "principal_id": "mike",
            "profile_name": "generalist2",
            "service_name": "hermes-gateway-generalist2.service",
            "platform": "telegram",
            "chat_type": "private",
            "recipient_binding_sha256": binding,
            "delivery_readback_verified": True,
            "status": "delivered",
            "external_effect_count": 1,
            "raw_message_persisted": False,
            "raw_chat_id_persisted": False,
        },
    )


def event(text: str, *, event_source: object | None = None, message_id: str = "9001") -> object:
    return SimpleNamespace(
        text=text,
        source=event_source or source(),
        message_id=message_id,
        media_urls=[],
        reply_to_text=None,
    )


def command(proposal: dict[str, object], *, decision: str = "ACTIVATE", selected: str = "freeze-review-candidate") -> str:
    return (
        f"CCT REPLY {proposal['proposal_id']} r{proposal['revision']} "
        f"portfolio={proposal['portfolio_sha256']} {decision} {selected}"
    )


def test_authorized_private_exact_reply_applies_once_and_never_reaches_agent(
    tmp_path: Path,
) -> None:
    store, proposal, secret_path = setup_store(tmp_path)
    record_delivery(store, proposal, binding=recipient_binding())
    adapter = GatewayPursuitReplyAdapter(store, secret_path=secret_path)
    inbound = event(command(proposal))

    first = adapter.handle(event=inbound, gateway=Gateway())
    restarted = GatewayPursuitReplyAdapter(
        EventStore(store.path, clock=lambda: NOW), secret_path=secret_path
    )
    second = restarted.handle(event=inbound, gateway=Gateway())

    assert first == {"action": "skip", "reason": "CCT_PURSUIT_REPLY_APPLIED"}
    assert second == {"action": "skip", "reason": "CCT_PURSUIT_REPLY_DUPLICATE"}
    assert len(store.events("pursuit.dialogue.reply.authenticated")) == 1
    assert len(store.events("pursuit.dialogue.reply.applied")) == 1
    assert len(
        [
            row
            for row in store.events("goal.status_changed")
            if row.payload.get("pursuit_reply_id")
        ]
    ) == 1
    goal = AgencyKernel(store, default_constitution("gateway-reply-test")).goal(
        "goal-release"
    )
    assert goal is not None and goal.status == "active"
    serialized = canonical_json([row.payload for row in store.events()])
    assert command(proposal) not in serialized
    assert "4242" not in serialized
    assert store.verify_chain()["valid"] is True


def test_unrelated_text_passes_without_reading_reply_secret(tmp_path: Path) -> None:
    store, _proposal, secret_path = setup_store(tmp_path)
    secret_path.unlink()
    adapter = GatewayPursuitReplyAdapter(store, secret_path=secret_path)

    assert adapter.handle(event=event("ordinary user request"), gateway=Gateway()) is None
    assert not store.events("pursuit.dialogue.reply.authenticated")


def test_plugin_registers_non_model_gateway_hook_and_consumes_exact_reply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("CCT_IDENTITY", "gateway-reply-test")
    store, proposal, _secret_path = setup_store(tmp_path)
    record_delivery(store, proposal, binding=recipient_binding())
    monkeypatch.setattr(
        hermes_plugin,
        "EventStore",
        lambda path: EventStore(path, clock=lambda: NOW),
    )
    context = PluginContext()
    hermes_plugin.register(context)

    assert set(context.hooks) == {
        "pre_gateway_dispatch",
        "pre_llm_call",
        "post_llm_call",
    }
    hook = context.hooks["pre_gateway_dispatch"]
    result = hook(event=event(command(proposal)), gateway=Gateway(), session_store=None)

    assert result == {"action": "skip", "reason": "CCT_PURSUIT_REPLY_APPLIED"}
    assert len(store.events("pursuit.dialogue.reply.applied")) == 1


def test_malformed_unauthorized_group_or_wrong_recipient_binding_fail_closed(
    tmp_path: Path,
) -> None:
    store, proposal, secret_path = setup_store(tmp_path)
    record_delivery(store, proposal, binding=recipient_binding())
    adapter = GatewayPursuitReplyAdapter(store, secret_path=secret_path)
    exact = command(proposal)

    malformed = adapter.handle(event=event(exact + " extra"), gateway=Gateway())
    unauthorized = adapter.handle(event=event(exact), gateway=Gateway(authorized=False))
    group = adapter.handle(
        event=event(exact, event_source=source(chat_type="group")), gateway=Gateway()
    )
    wrong_binding = adapter.handle(
        event=event(exact, event_source=source(chat_id="9999", user_id="9999")),
        gateway=Gateway(),
    )

    assert malformed == {"action": "skip", "reason": "CCT_PURSUIT_REPLY_MALFORMED"}
    assert unauthorized == {"action": "skip", "reason": "CCT_PURSUIT_REPLY_UNAUTHORIZED"}
    assert group == {"action": "skip", "reason": "CCT_PURSUIT_REPLY_PRIVATE_DM_REQUIRED"}
    assert wrong_binding == {"action": "skip", "reason": "CCT_PURSUIT_REPLY_RECIPIENT_MISMATCH"}
    assert not store.events("pursuit.dialogue.reply.authenticated")
    assert not store.events("pursuit.dialogue.reply.applied")
    assert store.verify_chain()["valid"] is True


def test_stale_portfolio_and_insecure_secret_fail_closed(tmp_path: Path) -> None:
    store, proposal, secret_path = setup_store(tmp_path)
    record_delivery(store, proposal, binding=recipient_binding())
    adapter = GatewayPursuitReplyAdapter(store, secret_path=secret_path)
    stale = command({**proposal, "portfolio_sha256": "0" * 64})

    stale_result = adapter.handle(event=event(stale), gateway=Gateway())
    secret_path.chmod(0o644)
    secret_result = adapter.handle(event=event(command(proposal)), gateway=Gateway())

    assert stale_result == {"action": "skip", "reason": "CCT_PURSUIT_REPLY_PROPOSAL_MISMATCH"}
    assert secret_result == {"action": "skip", "reason": "CCT_PURSUIT_REPLY_SECRET_INVALID"}
    assert not store.events("pursuit.dialogue.reply.authenticated")
