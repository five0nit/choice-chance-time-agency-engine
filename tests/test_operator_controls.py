from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

from cct_agent.capabilities import (
    OPERATOR_EFFECT_CLASSES,
    CapabilityLease,
    CapabilityRegistry,
    OperatorCapabilityCatalog,
)
from cct_agent.execution_tickets import (
    ExecutionTicket,
    ExecutionTicketAuthority,
    GlobalKillSwitch,
    TicketAuthorityDenied,
)
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-25T00:00:00+00:00"
FUTURE = "2026-08-26T00:00:00+00:00"


def configured(
    tmp_path: Path,
) -> tuple[
    EventStore,
    ExecutionTicketAuthority,
    GlobalKillSwitch,
    str,
    dict[str, dict[str, Any]],
]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    installed = PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 1.0},
            directives=(
                PrincipalDirective(
                    id="operator-effects",
                    kind="preference",
                    statement="Prefer bounded verified operator effects.",
                    tags=("domain:operator",),
                    priority=80,
                ),
            ),
        ),
        authority="operator",
        evidence=("operator://profile",),
    )
    catalog = OperatorCapabilityCatalog(store).install()
    registry = CapabilityRegistry(store)
    for effect_class in OPERATOR_EFFECT_CLASSES:
        spec = catalog[effect_class]["spec"]
        value_budget = 1 if spec["max_value_microunits"] else 0
        registry.grant(
            CapabilityLease(
                id=f"lease-{effect_class}",
                capability=spec["name"],
                principal_id="mike",
                scopes=(f"operator/{effect_class}/**",),
                expires_at=FUTURE,
                max_actions=16,
                max_bytes=1_048_576,
                max_value_microunits=value_budget,
                issued_by="operator",
                evidence=(f"operator://lease/{effect_class}",),
            )
        )
    return (
        store,
        ExecutionTicketAuthority(store),
        GlobalKillSwitch(store),
        installed["profile_digest"],
        catalog,
    )


def invocation(
    effect_class: str,
    *,
    suffix: str,
    profile_digest: str,
    catalog: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], ExecutionTicket]:
    ticket_id = f"ticket-{effect_class}-{suffix}"
    arguments = {
        "execution_ticket_id": ticket_id,
        "target_id": f"target-{effect_class}",
    }
    spec = catalog[effect_class]
    value_budget = 1 if spec["spec"]["max_value_microunits"] else 0
    ticket = ExecutionTicket(
        id=ticket_id,
        tool_name=f"operator_{effect_class}",
        arguments_sha256=sha256(canonical_json(arguments).encode()).hexdigest(),
        goal_id="goal-cct-full-operator-effects",
        plan_id=f"plan-{effect_class}",
        plan_hash=sha256(f"plan:{effect_class}".encode()).hexdigest(),
        stage=f"execute-{effect_class}",
        attempt=1,
        principal_id="mike",
        principal_profile_digest=profile_digest,
        capability=spec["spec"]["name"],
        capability_spec_digest=spec["spec_digest"],
        lease_id=f"lease-{effect_class}",
        scope=f"operator/{effect_class}/target",
        expires_at=FUTURE,
        action_budget=1,
        byte_budget=64,
        value_budget_microunits=value_budget,
    )
    return arguments, ticket


def test_host_catalog_covers_exact_operator_effect_classes_without_granting_authority(
    tmp_path: Path,
) -> None:
    store = EventStore(tmp_path / "catalog.sqlite", clock=lambda: NOW)

    installed = OperatorCapabilityCatalog(store).install()

    assert tuple(installed) == OPERATOR_EFFECT_CLASSES
    assert set(installed) == {
        "shell",
        "web",
        "project_edit",
        "deploy",
        "public",
        "credential",
        "financial",
        "high_consequence",
    }
    for effect_class, row in installed.items():
        assert row["created"] is True
        assert row["spec"]["effect_kind"] == effect_class
        assert row["spec"]["name"] == f"operator.{effect_class}"
        assert row["spec"]["default_mode"] == "deny"
        assert row["spec"]["verifier_id"] == f"operator-{effect_class}-readback"
        assert row["spec"]["scopes"] == [f"operator/{effect_class}/**"]
    registered = store.events("capability.spec.registered")
    assert len(registered) == 8
    assert all(event.payload["authority"] == "host_adapter" for event in registered)
    assert not store.events("capability.lease.granted")
    assert CapabilityRegistry(store).status()["self_grant_enabled"] is False
    assert store.verify_chain()["valid"] is True


def test_active_global_kill_switch_denies_issue_and_dispatch_for_all_effect_classes(
    tmp_path: Path,
) -> None:
    store, authority, kill_switch, profile_digest, catalog = configured(tmp_path)
    issued_before_trip: dict[str, dict[str, Any]] = {}
    for effect_class in OPERATOR_EFFECT_CLASSES:
        arguments, ticket = invocation(
            effect_class,
            suffix="before-trip",
            profile_digest=profile_digest,
            catalog=catalog,
        )
        authority.issue(
            ticket,
            authority="operator",
            evidence=(f"operator://approval/{effect_class}",),
        )
        issued_before_trip[effect_class] = arguments

    tripped = kill_switch.trip(
        trip_id="kill-all-effects",
        authority="operator",
        reason="Operator emergency stop.",
    )
    assert tripped["active"] is True
    assert kill_switch.status()["active_trip_event_id"] == tripped["event_id"]

    mediated_tools = frozenset(
        f"operator_{effect_class}" for effect_class in OPERATOR_EFFECT_CLASSES
    )
    mediator = ToolExecutionMediator(store, mediated_tools)
    for effect_class, arguments in issued_before_trip.items():
        downstream_calls = 0

        def next_call() -> str:
            nonlocal downstream_calls
            downstream_calls += 1
            return "must-not-run"

        result = json.loads(
            mediator(
                tool_name=f"operator_{effect_class}",
                args=arguments,
                original_args=arguments,
                next_call=next_call,
            )
        )
        assert result["error"]["reasons"] == ["GLOBAL_KILL_SWITCH_ACTIVE"]
        assert downstream_calls == 0

        _new_arguments, new_ticket = invocation(
            effect_class,
            suffix="after-trip",
            profile_digest=profile_digest,
            catalog=catalog,
        )
        with pytest.raises(ValueError, match="GLOBAL_KILL_SWITCH_ACTIVE"):
            authority.issue(
                new_ticket,
                authority="operator",
                evidence=(f"operator://approval/{effect_class}",),
            )

    assert len(store.events("execution.ticket.issued")) == 8
    assert not store.events("execution.ticket.consumed")
    assert len(store.events("mediation.tool.denied")) == 8
    assert store.verify_chain()["valid"] is True


def test_kill_switch_is_durable_model_cannot_clear_and_stale_clear_fails(
    tmp_path: Path,
) -> None:
    store = EventStore(tmp_path / "durable.sqlite", clock=lambda: NOW)
    kill_switch = GlobalKillSwitch(store)
    first = kill_switch.trip(
        trip_id="kill-first",
        authority="host_adapter",
        reason="Host detected unsafe state.",
    )
    assert first["created"] is True

    reopened = GlobalKillSwitch(EventStore(store.path, clock=lambda: NOW))
    assert reopened.status()["active"] is True
    with pytest.raises(ValueError, match="authority must be operator or host_adapter"):
        reopened.clear(
            clear_id="clear-by-model",
            authority="model",
            active_trip_event_id=first["event_id"],
            evidence="model requested resume",
        )

    second = reopened.trip(
        trip_id="kill-second",
        authority="operator",
        reason="Operator confirms stop remains required.",
    )
    with pytest.raises(TicketAuthorityDenied) as stale:
        reopened.clear(
            clear_id="clear-stale",
            authority="operator",
            active_trip_event_id=first["event_id"],
            evidence="operator://clear/stale",
        )
    assert stale.value.reason_code == "KILL_SWITCH_STATE_CHANGED"
    assert reopened.status()["active_trip_event_id"] == second["event_id"]

    cleared = reopened.clear(
        clear_id="clear-current",
        authority="operator",
        active_trip_event_id=second["event_id"],
        evidence="operator://clear/current",
    )
    assert cleared["active"] is False
    assert reopened.status()["active"] is False
    idempotent_old_trip = reopened.trip(
        trip_id="kill-first",
        authority="host_adapter",
        reason="Host detected unsafe state.",
    )
    assert idempotent_old_trip["created"] is False
    assert idempotent_old_trip["active"] is False
    assert store.verify_chain()["valid"] is True


def test_between_step_checkpoint_stops_remaining_multi_step_effect(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "steps.sqlite", clock=lambda: NOW)
    kill_switch = GlobalKillSwitch(store)

    first = kill_switch.checkpoint(
        checkpoint_id="effect-one-step-one",
        effect_id="effect-one",
        step="step-one",
    )
    assert first["clear"] is True
    kill_switch.trip(
        trip_id="kill-between-steps",
        authority="host_adapter",
        reason="Host stopped remaining legs.",
    )
    with pytest.raises(TicketAuthorityDenied) as blocked:
        kill_switch.checkpoint(
            checkpoint_id="effect-one-step-two",
            effect_id="effect-one",
            step="step-two",
        )
    assert blocked.value.reason_code == "GLOBAL_KILL_SWITCH_ACTIVE"
    assert len(store.events("operator.kill_switch.checkpoint")) == 1
    assert store.verify_chain()["valid"] is True


def test_trip_racing_ticket_issue_always_blocks_later_dispatch(tmp_path: Path) -> None:
    store, authority, kill_switch, profile_digest, catalog = configured(tmp_path)
    arguments, pending_ticket = invocation(
        "shell",
        suffix="race",
        profile_digest=profile_digest,
        catalog=catalog,
    )
    barrier = Barrier(2)

    def issue_ticket() -> str:
        barrier.wait(timeout=10)
        try:
            authority.issue(
                pending_ticket,
                authority="operator",
                evidence=("operator://approval/race",),
            )
            return "issued"
        except ValueError as error:
            return str(error)

    def trip_switch() -> str:
        barrier.wait(timeout=10)
        kill_switch.trip(
            trip_id="kill-race",
            authority="host_adapter",
            reason="Concurrent host stop.",
        )
        return "tripped"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [pool.submit(issue_ticket), pool.submit(trip_switch)]
        results = [future.result() for future in outcomes]
    assert "tripped" in results
    assert results[0] in {"issued", "GLOBAL_KILL_SWITCH_ACTIVE"}

    calls = 0

    def next_call() -> str:
        nonlocal calls
        calls += 1
        return "must-not-run"

    denied = json.loads(
        ToolExecutionMediator(store, frozenset({"operator_shell"}))(
            tool_name="operator_shell",
            args=arguments,
            original_args=arguments,
            next_call=next_call,
        )
    )
    assert denied["error"]["reasons"] == ["GLOBAL_KILL_SWITCH_ACTIVE"]
    assert calls == 0
    assert not store.events("execution.ticket.consumed")
    assert store.verify_chain()["valid"] is True
