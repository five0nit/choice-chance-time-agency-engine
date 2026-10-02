from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Callable

import pytest

from cct_agent.execution_tickets import ExecutionTicket, ExecutionTicketAuthority
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.operator_authenticated_access import OperatorAuthenticatedAccessScaffold
from cct_agent.operator_authenticated_session_bridge import (
    OPERATOR_AUTHENTICATED_SESSION_TOOL,
    AuthenticatedSessionBridgeDenied,
    HermesAuthenticatedSessionDriver,
    OperatorAuthenticatedSessionBridge,
)
from cct_agent.store import canonical_json
from tests.test_operator_authenticated_access import (
    FUTURE,
    SECRET,
    access_arguments,
    configured,
    issue_and_use_credential,
)


def bridge_fixture(
    tmp_path: Path,
    *,
    ticket_id: str,
    dispatch: Callable[[str, dict[str, Any]], object],
    browser_real_profile_enabled: bool = True,
    native: bool = False,
) -> dict[str, Any]:
    fixture = configured(tmp_path)
    target = fixture["target"]
    if native:
        target = replace(
            target,
            id="windows-native-session",
            target_kind="native",
            route="computer_use_existing_session",
            app_id="windows-native-app",
        )
    credential = issue_and_use_credential(
        fixture, f"credential-before-{ticket_id}"
    )
    scaffold = OperatorAuthenticatedAccessScaffold(
        fixture["store"], targets=(target,)
    )
    access = access_arguments(
        scaffold,
        str(credential["effect"]["receipt_event_id"]),
        ticket_id,
        target_id=target.id,
    )
    prepared = json.loads(scaffold.prepare(access))["prepared"]
    driver = HermesAuthenticatedSessionDriver(
        dispatch,
        browser_real_profile_enabled=browser_real_profile_enabled,
    )
    bridge = OperatorAuthenticatedSessionBridge(
        fixture["store"], scaffold, driver
    )
    preview = bridge.preview(prepared_event_id=str(prepared["prepared_event_id"]))
    arguments = bridge.arguments(preview)
    ExecutionTicketAuthority(fixture["store"]).issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name=OPERATOR_AUTHENTICATED_SESSION_TOOL,
            arguments_sha256=sha256(canonical_json(arguments).encode()).hexdigest(),
            goal_id="goal-cct-authenticated-session",
            plan_id=f"plan-{ticket_id}",
            plan_hash=sha256(f"plan:{ticket_id}".encode()).hexdigest(),
            stage="attach-authenticated-session",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=fixture["profile_digest"],
            capability="operator.credential",
            capability_spec_digest=fixture["spec_digest"],
            lease_id="lease-authenticated-access",
            scope=f"operator/credential/{fixture['handle'].id}",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=0,
            value_budget_microunits=0,
        ),
        authority="operator",
        evidence=(f"operator://authenticated-session/{ticket_id}",),
    )
    return {
        **fixture,
        "target": target,
        "scaffold": scaffold,
        "bridge": bridge,
        "prepared": prepared,
        "preview": preview,
        "arguments": arguments,
    }


def mediated(fixture: dict[str, Any]) -> tuple[dict[str, Any], int]:
    calls = 0

    def next_call() -> str:
        nonlocal calls
        calls += 1
        return fixture["bridge"].execute(fixture["arguments"])

    value = ToolExecutionMediator(
        fixture["store"],
        frozenset({OPERATOR_AUTHENTICATED_SESSION_TOOL}),
        outcome_verifiers=fixture["bridge"].outcome_verifiers(),
    )(
        tool_name=OPERATOR_AUTHENTICATED_SESSION_TOOL,
        args=fixture["arguments"],
        original_args=fixture["arguments"],
        next_call=next_call,
    )
    parsed = json.loads(value) if isinstance(value, str) else value
    assert isinstance(parsed, dict)
    return parsed, calls


def test_ticketed_browser_bridge_dispatches_fixed_probe_and_replays_once(
    tmp_path: Path,
) -> None:
    dispatches: list[tuple[str, dict[str, Any]]] = []

    def dispatch(name: str, arguments: dict[str, Any]) -> str:
        dispatches.append((name, arguments))
        assert name == "browser_exec"
        assert set(arguments) == {"code", "session", "timeout_s"}
        assert "CCT_BROWSER_SESSION_READY_V1" in arguments["code"]
        assert "http" not in arguments["code"].lower()
        return json.dumps(
            {
                "success": True,
                "exit_code": 0,
                "output": "CCT_BROWSER_SESSION_READY_V1\n",
                "session": arguments["session"],
            }
        )

    fixture = bridge_fixture(
        tmp_path,
        ticket_id="authenticated-browser-ticket",
        dispatch=dispatch,
    )
    ready, calls = mediated(fixture)
    replay, replay_calls = mediated(fixture)

    assert ready["success"] is True
    assert ready["authenticated_session"]["route"] == "browser_real_profile_snapshot"
    assert ready["authenticated_session"]["status"] == "READY"
    assert ready["authenticated_session"]["dispatch_tool_name"] == "browser_exec"
    assert ready["authenticated_session"]["dispatch_count"] == 1
    assert ready["authenticated_session"]["ui_action_count"] == 0
    assert ready["credential_use"]["raw_secret_exposed"] is False
    assert ready["credential_use"]["secret_input_performed"] is False
    assert calls == 1
    assert replay["success"] is True
    assert replay["mediation"]["recovered_after_restart"] is True
    assert replay_calls == 0
    assert len(dispatches) == 1
    assert fixture["store"].verify_chain()["valid"] is True


def test_native_bridge_dispatches_app_inventory_and_discards_raw_ui_text(
    tmp_path: Path,
) -> None:
    private_label = "private-native-window-label-8821"
    dispatches: list[tuple[str, dict[str, Any]]] = []

    def dispatch(name: str, arguments: dict[str, Any]) -> str:
        dispatches.append((name, arguments))
        assert name == "computer_use"
        assert arguments == {
            "action": "list_apps",
        }
        return json.dumps(
            {
                "apps": [
                    {
                        "name": "windows-native-app",
                        "pid": 4242,
                        "window_count": 1,
                        "private_label": private_label,
                    }
                ],
                "count": 1,
            }
        )

    fixture = bridge_fixture(
        tmp_path,
        ticket_id="authenticated-native-ticket",
        dispatch=dispatch,
        native=True,
    )
    ready, calls = mediated(fixture)

    assert ready["success"] is True
    assert ready["authenticated_session"]["route"] == "computer_use_existing_session"
    assert ready["authenticated_session"]["status"] == "READY"
    assert ready["authenticated_session"]["dispatch_tool_name"] == "computer_use"
    assert calls == 1
    assert len(dispatches) == 1
    persisted = canonical_json([event.payload for event in fixture["store"].events()])
    response = canonical_json(ready)
    assert private_label not in persisted
    assert private_label not in response
    assert SECRET.decode() not in persisted
    assert SECRET.decode() not in response
    assert fixture["store"].verify_chain()["valid"] is True


def test_disabled_real_profile_returns_verified_user_handoff_without_dispatch(
    tmp_path: Path,
) -> None:
    dispatches = 0

    def dispatch(_name: str, _arguments: dict[str, Any]) -> object:
        nonlocal dispatches
        dispatches += 1
        raise AssertionError("disabled browser profile must not dispatch")

    fixture = bridge_fixture(
        tmp_path,
        ticket_id="authenticated-browser-handoff",
        dispatch=dispatch,
        browser_real_profile_enabled=False,
    )
    handoff, calls = mediated(fixture)

    assert handoff["success"] is True
    assert handoff["authenticated_session"]["status"] == "AUTH_HANDOFF_REQUIRED"
    assert handoff["authenticated_session"]["existing_session_ready"] is False
    assert handoff["authenticated_session"]["auth_handoff_required"] is True
    assert handoff["authenticated_session"]["dispatch_tool_name"] == "none"
    assert handoff["authenticated_session"]["dispatch_count"] == 0
    assert calls == 1
    assert dispatches == 0


def test_bridge_requires_mediator_claim_and_rejects_caller_tool_payload(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path)
    credential = issue_and_use_credential(fixture, "credential-direct-denial")
    scaffold = OperatorAuthenticatedAccessScaffold(
        fixture["store"], targets=(fixture["target"],)
    )
    prepared = json.loads(
        scaffold.prepare(
            access_arguments(
                scaffold,
                str(credential["effect"]["receipt_event_id"]),
                "direct-session-denial",
            )
        )
    )["prepared"]
    bridge = OperatorAuthenticatedSessionBridge(
        fixture["store"],
        scaffold,
        HermesAuthenticatedSessionDriver(
            lambda _name, _args: "must-not-run",
            browser_real_profile_enabled=True,
        ),
    )
    arguments = bridge.arguments(
        bridge.preview(prepared_event_id=str(prepared["prepared_event_id"]))
    )

    with pytest.raises(
        AuthenticatedSessionBridgeDenied, match="TICKET_DISPATCH_CLAIM_REQUIRED"
    ):
        bridge.execute(arguments)
    with pytest.raises(ValueError, match="require exact fields"):
        bridge.execute({**arguments, "code": "print('caller supplied')"})
    assert not fixture["store"].events("operator.authenticated_session.claimed")


def test_post_readback_crash_reconciles_without_second_host_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host_dispatches = 0

    def dispatch(_name: str, arguments: dict[str, Any]) -> str:
        nonlocal host_dispatches
        host_dispatches += 1
        return json.dumps(
            {
                "success": True,
                "exit_code": 0,
                "output": "CCT_BROWSER_SESSION_READY_V1\n",
                "session": arguments["session"],
            }
        )

    fixture = bridge_fixture(
        tmp_path,
        ticket_id="authenticated-session-crash",
        dispatch=dispatch,
    )
    original = fixture["bridge"]._record_completion
    completion_attempts = 0

    def crash_once(*args: Any, **kwargs: Any) -> str:
        nonlocal completion_attempts
        completion_attempts += 1
        if completion_attempts == 1:
            raise RuntimeError("simulated post-readback crash")
        return original(*args, **kwargs)

    monkeypatch.setattr(fixture["bridge"], "_record_completion", crash_once)
    recovered, calls = mediated(fixture)

    assert recovered["success"] is True
    assert recovered["authenticated_session"]["recovered_after_readback"] is True
    assert host_dispatches == 1
    assert calls == 1
    assert completion_attempts == 2
    assert len(fixture["store"].events("operator.authenticated_session.completed")) == 1
    assert fixture["store"].verify_chain()["valid"] is True
