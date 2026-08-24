from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import hermes_plugin
from cct_agent.canary_mediation import (
    PROFILE_DEPLOY_TOOL,
    PROFILE_DEPLOY_VERIFIER,
    PRIVATE_TELEGRAM_TOOL,
    PRIVATE_TELEGRAM_VERIFIER,
    build_canary_outcome_registry,
    private_telegram_tool_result,
    profile_deployment_tool_result,
)
from cct_agent.capabilities import CapabilityLease, CapabilityRegistry, CapabilitySpec
from cct_agent.execution_tickets import ExecutionTicket, ExecutionTicketAuthority
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-25T02:00:00+00:00"
FUTURE = "2026-08-26T02:00:00+00:00"


class Context:
    def __init__(self) -> None:
        self.middlewares: list[tuple[str, Any]] = []

    @staticmethod
    def get_config(key: str, default: object = None) -> object:
        if key == "mediated_tools":
            return [PROFILE_DEPLOY_TOOL, PRIVATE_TELEGRAM_TOOL]
        return default

    @staticmethod
    def register_tool(**_kwargs: object) -> None:
        return None

    @staticmethod
    def register_hook(_name: str, _handler: Any) -> None:
        return None

    def register_middleware(self, kind: str, callback: Any) -> None:
        self.middlewares.append((kind, callback))


class DefaultContext(Context):
    @staticmethod
    def get_config(key: str, default: object = None) -> object:
        del key
        return default


def configured_store(tmp_path: Path) -> tuple[EventStore, str, str, str]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    installed = PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 1.0},
            directives=(
                PrincipalDirective(
                    id="prefer-bounded-canaries",
                    kind="preference",
                    statement="Prefer reversible receipt-backed release canaries.",
                    tags=("domain:runtime", "action:deploy"),
                    priority=90,
                ),
            ),
        ),
        authority="operator",
        evidence=("operator://live-canary-mediation",),
    )
    registry = CapabilityRegistry(store)
    deploy = registry.register(
        CapabilitySpec(
            name="generalist2.profile-deploy",
            description="Deploy one exact CCT artifact to Generalist2.",
            effect_kind="generalist2_profile_deployment",
            intent_domain="runtime",
            intent_action="deploy",
            risk_class="reversible",
            scopes=("generalist2/cct-agency",),
            verifier_id=PROFILE_DEPLOY_VERIFIER,
            reversible=True,
            max_actions=1,
            max_bytes=67_108_864,
            max_value_microunits=0,
        ),
        authority="host_adapter",
        evidence=("host://generalist2-profile-deploy",),
    )
    telegram = registry.register(
        CapabilitySpec(
            name="generalist2.private-telegram",
            description="Deliver one proposal-bound private Telegram DM.",
            effect_kind="private_telegram_delivery",
            intent_domain="messaging",
            intent_action="deliver",
            risk_class="reversible",
            scopes=("telegram/mike/private",),
            verifier_id=PRIVATE_TELEGRAM_VERIFIER,
            reversible=True,
            max_actions=1,
            max_bytes=1800,
            max_value_microunits=0,
        ),
        authority="host_adapter",
        evidence=("host://private-telegram-delivery",),
    )
    registry.grant(
        CapabilityLease(
            id="lease-live-profile-deploy",
            capability="generalist2.profile-deploy",
            principal_id="mike",
            scopes=("generalist2/cct-agency",),
            expires_at=FUTURE,
            max_actions=1,
            max_bytes=67_108_864,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://live-profile-deploy-lease",),
        )
    )
    registry.grant(
        CapabilityLease(
            id="lease-live-private-telegram",
            capability="generalist2.private-telegram",
            principal_id="mike",
            scopes=("telegram/mike/private",),
            expires_at=FUTURE,
            max_actions=1,
            max_bytes=1800,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://live-private-telegram-lease",),
        )
    )
    return (
        store,
        str(installed["profile_digest"]),
        str(deploy["spec_digest"]),
        str(telegram["spec_digest"]),
    )


def invoke(
    callback: Any,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    downstream: object,
) -> tuple[object, int]:
    calls = 0

    def next_call() -> object:
        nonlocal calls
        calls += 1
        return downstream() if callable(downstream) else downstream

    return (
        callback(
            tool_name=tool_name,
            args=arguments,
            original_args=arguments,
            next_call=next_call,
        ),
        calls,
    )


def test_registered_live_canary_effect_requires_ticket_and_replays_without_second_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, profile_digest, capability_digest, _telegram_digest = configured_store(
        tmp_path
    )
    outcome_registry = build_canary_outcome_registry(store)
    assert outcome_registry.registered_ids == frozenset(
        {PROFILE_DEPLOY_VERIFIER, PRIVATE_TELEGRAM_VERIFIER}
    )
    monkeypatch.setattr(hermes_plugin, "_kernel", lambda: SimpleNamespace(store=store))
    context = Context()
    hermes_plugin.register(context)
    callback = context.middlewares[0][1]

    denied, denied_calls = invoke(
        callback,
        tool_name=PRIVATE_TELEGRAM_TOOL,
        arguments={"request_id": "telegram-without-ticket"},
        downstream="must-not-run",
    )
    assert denied_calls == 0
    assert json.loads(str(denied))["error"]["reasons"] == ["TICKET_REQUIRED"]

    ticket_id = "ticket-live-profile-deploy"
    arguments = {
        "execution_ticket_id": ticket_id,
        "request_id": ticket_id,
        "target_id": "generalist2-cct-plugin",
    }
    ExecutionTicketAuthority(store).issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name=PROFILE_DEPLOY_TOOL,
            arguments_sha256=sha256(canonical_json(arguments).encode("utf-8")).hexdigest(),
            goal_id="goal-cct-release",
            plan_id="plan-cct-release",
            plan_hash="a" * 64,
            stage="deploy",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=profile_digest,
            capability="generalist2.profile-deploy",
            capability_spec_digest=capability_digest,
            lease_id="lease-live-profile-deploy",
            scope="generalist2/cct-agency",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=1024,
            value_budget_microunits=0,
        ),
        authority="operator",
        evidence=("operator://exact-cct-release",),
    )
    raw_results: list[str] = []

    def deploy_effect() -> str:
        event, _created = store.append_once_result(
            "canary.profile.deployment.completed",
            ticket_id,
            {
                "schema_version": "cct.canary.profile-deployment.receipt.v1",
                "request_id": ticket_id,
                "claim_event_id": "evt-profile-claim",
                "target_id": "generalist2-cct-plugin",
                "profile_name": "generalist2",
                "service_name": "hermes-gateway-generalist2.service",
                "artifact_sha256": "b" * 64,
                "manifest_sha256": "c" * 64,
                "before_runtime_sha256": "d" * 64,
                "after_runtime_sha256": "e" * 64,
                "state_db_logical_sha256": "f" * 64,
                "sqlite_backup_sha256": "1" * 64,
                "artifact_readback_verified": True,
                "sqlite_backup_verified": True,
                "profile_mutation_count": 1,
                "state_db_restored": False,
                "ambient_credentials_used": False,
                "network_effect": False,
                "service_reload_effect": False,
                "status": "deployed",
            },
        )
        result = profile_deployment_tool_result(
            request_id=ticket_id,
            target_id="generalist2-cct-plugin",
            artifact_sha256="b" * 64,
            manifest_sha256="c" * 64,
            before_runtime_sha256="d" * 64,
            after_runtime_sha256="e" * 64,
            state_db_logical_sha256="f" * 64,
            sqlite_backup_sha256="1" * 64,
            terminal_event_id=event.event_id,
        )
        raw_results.append(result)
        return result

    allowed, allowed_calls = invoke(
        callback,
        tool_name=PROFILE_DEPLOY_TOOL,
        arguments=arguments,
        downstream=deploy_effect,
    )
    assert allowed == raw_results[0]
    assert allowed_calls == 1
    assert len(store.events("execution.ticket.consumed")) == 1
    assert len(store.events("mediation.tool.outcome")) == 1
    assert len(store.events("mediation.tool.completed")) == 1

    restarted = Context()
    hermes_plugin.register(restarted)
    replayed, replay_calls = invoke(
        restarted.middlewares[0][1],
        tool_name=PROFILE_DEPLOY_TOOL,
        arguments=arguments,
        downstream="must-not-run-again",
    )
    assert replay_calls == 0
    replay = json.loads(str(replayed))
    assert replay["success"] is True
    assert replay["mediation"]["recovered_after_restart"] is True
    assert len(store.events("mediation.tool.outcome")) == 1
    assert len(store.events("mediation.tool.completed")) == 1

    read_result, read_calls = invoke(
        restarted.middlewares[0][1],
        tool_name="read_file",
        arguments={"path": "README.md"},
        downstream={"success": True, "content": "bounded read"},
    )
    assert read_calls == 1
    assert read_result == {"success": True, "content": "bounded read"}
    assert store.verify_chain()["valid"] is True


def test_missing_profile_override_keeps_exact_real_canary_effects_mediated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _profile_digest, _deploy_digest, _telegram_digest = configured_store(
        tmp_path
    )
    monkeypatch.setattr(hermes_plugin, "_kernel", lambda: SimpleNamespace(store=store))
    context = DefaultContext()
    hermes_plugin.register(context)

    for tool_name in (PROFILE_DEPLOY_TOOL, PRIVATE_TELEGRAM_TOOL):
        denied, calls = invoke(
            context.middlewares[0][1],
            tool_name=tool_name,
            arguments={"request_id": f"missing-ticket-{tool_name}"},
            downstream="must-not-run",
        )
        assert calls == 0
        assert json.loads(str(denied))["error"]["reasons"] == ["TICKET_REQUIRED"]

    read, read_calls = invoke(
        context.middlewares[0][1],
        tool_name="read_file",
        arguments={"path": "README.md"},
        downstream="read-result",
    )
    assert read == "read-result"
    assert read_calls == 1


def test_private_telegram_ticket_requires_canonical_private_delivery_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, profile_digest, _deploy_digest, telegram_digest = configured_store(tmp_path)
    monkeypatch.setattr(hermes_plugin, "_kernel", lambda: SimpleNamespace(store=store))
    context = Context()
    hermes_plugin.register(context)
    callback = context.middlewares[0][1]
    ticket_id = "ticket-live-private-telegram"
    arguments = {
        "execution_ticket_id": ticket_id,
        "request_id": ticket_id,
        "target_id": "generalist2-mike-private-dm",
        "proposal_id": "priority-release",
        "proposal_revision": 1,
    }
    ExecutionTicketAuthority(store).issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name=PRIVATE_TELEGRAM_TOOL,
            arguments_sha256=sha256(canonical_json(arguments).encode("utf-8")).hexdigest(),
            goal_id="goal-cct-priority",
            plan_id="plan-cct-priority",
            plan_hash="2" * 64,
            stage="private-delivery",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=profile_digest,
            capability="generalist2.private-telegram",
            capability_spec_digest=telegram_digest,
            lease_id="lease-live-private-telegram",
            scope="telegram/mike/private",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=812,
            value_budget_microunits=0,
        ),
        authority="operator",
        evidence=("operator://proposal-bound-private-delivery",),
    )
    effect_calls = 0

    def deliver_effect() -> str:
        nonlocal effect_calls
        effect_calls += 1
        event, _created = store.append_once_result(
            "canary.telegram.delivery.completed",
            ticket_id,
            {
                "schema_version": "cct.canary.telegram-delivery.receipt.v1",
                "request_id": ticket_id,
                "claim_event_id": "evt-telegram-claim",
                "target_id": "generalist2-mike-private-dm",
                "profile_name": "generalist2",
                "service_name": "hermes-gateway-generalist2.service",
                "platform": "telegram",
                "chat_type": "private",
                "principal_id": "mike",
                "proposal_event_id": "evt-priority-release",
                "proposal_id": "priority-release",
                "proposal_revision": 1,
                "portfolio_sha256": "3" * 64,
                "recipient_binding_sha256": "4" * 64,
                "message_sha256": "5" * 64,
                "message_byte_count": 812,
                "preview_sha256": "6" * 64,
                "provider_receipt_sha256": "7" * 64,
                "provider_message_id_sha256": "8" * 64,
                "delivery_readback_verified": True,
                "external_effect_count": 1,
                "ambient_credentials_used": False,
                "host_managed_delivery": True,
                "message_content_persisted": False,
                "raw_producer_content_persisted": False,
                "status": "delivered",
            },
        )
        return private_telegram_tool_result(event)

    delivered, calls = invoke(
        callback,
        tool_name=PRIVATE_TELEGRAM_TOOL,
        arguments=arguments,
        downstream=deliver_effect,
    )
    decoded = json.loads(str(delivered))
    assert calls == effect_calls == 1
    assert decoded["success"] is True
    assert decoded["effect"]["chat_type"] == "private"
    assert decoded["effect"]["external_effect_count"] == 1

    restarted = Context()
    hermes_plugin.register(restarted)
    replayed, replay_calls = invoke(
        restarted.middlewares[0][1],
        tool_name=PRIVATE_TELEGRAM_TOOL,
        arguments=arguments,
        downstream="must-not-send-again",
    )
    assert replay_calls == 0
    assert effect_calls == 1
    replay = json.loads(str(replayed))
    assert replay["success"] is True
    assert replay["mediation"]["recovered_after_restart"] is True
    assert len(store.events("canary.telegram.delivery.completed")) == 1
    assert len(store.events("mediation.tool.outcome")) == 1
    assert len(store.events("mediation.tool.completed")) == 1
    assert store.verify_chain()["valid"] is True
