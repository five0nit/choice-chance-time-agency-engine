from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Callable

import pytest

import hermes_plugin
from cct_agent.execution_tickets import ExecutionTicket, ExecutionTicketAuthority
from cct_agent.operator_authenticated_session_bridge import (
    OPERATOR_AUTHENTICATED_SESSION_TOOL,
)
from cct_agent.store import canonical_json
from tests.test_operator_authenticated_access import (
    ACTION_SCOPE_SHA256,
    FUTURE,
    configured,
    issue_and_use_credential,
)


class PluginContext:
    def __init__(self, config: dict[str, object]) -> None:
        self.config = config
        self.tools: dict[str, Callable[..., str]] = {}
        self.schemas: dict[str, dict[str, Any]] = {}
        self.middlewares: list[tuple[str, Callable[..., Any]]] = []
        self.hooks: dict[str, Callable[..., Any]] = {}
        self.dispatches: list[tuple[str, dict[str, Any]]] = []

    def get_config(self, key: str, default: object = None) -> object:
        return self.config.get(key, default)

    def register_tool(
        self, *, name: str, handler: Callable[..., str], **kwargs: object
    ) -> None:
        self.tools[name] = handler
        self.schemas[name] = dict(kwargs["schema"])  # type: ignore[arg-type]

    def register_middleware(
        self, kind: str, callback: Callable[..., Any]
    ) -> None:
        self.middlewares.append((kind, callback))

    def register_hook(self, name: str, handler: Callable[..., Any]) -> None:
        self.hooks[name] = handler

    def dispatch_tool(self, name: str, arguments: dict[str, Any], **_kwargs: Any) -> str:
        self.dispatches.append((name, arguments))
        if name != "browser_exec":
            raise AssertionError(f"unexpected dispatched tool: {name}")
        return json.dumps(
            {
                "success": True,
                "exit_code": 0,
                "output": "CCT_BROWSER_SESSION_READY_V1\n",
                "session": arguments["session"],
            }
        )


def target_config() -> dict[str, object]:
    return {
        "id": "chrome-real-profile",
        "target_kind": "web",
        "route": "browser_real_profile_snapshot",
        "app_id": "chrome",
        "consumer_id": "browser-real-profile",
        "owner_principal_id": "mike",
        "allowed_purposes": ["resume-browser-session"],
    }


def test_plugin_registers_and_executes_ticketed_authenticated_browser_bridge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hermes_home = tmp_path / "hermes"
    state_root = hermes_home / "cct-agency"
    state_root.mkdir(parents=True)
    fixture = configured(state_root)
    credential = issue_and_use_credential(fixture, "plugin-credential-use")
    receipt_event_id = str(credential["effect"]["receipt_event_id"])
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    context = PluginContext(
        {
            "identity": "Plugin-Authenticated-Access",
            "mediated_tools": [OPERATOR_AUTHENTICATED_SESSION_TOOL],
            "authenticated_access_targets": [target_config()],
            "authenticated_access_browser_real_profile_enabled": True,
        }
    )

    hermes_plugin.register(context)

    assert {
        "cct_authenticated_access_preview",
        "cct_authenticated_access_prepare",
        "cct_authenticated_session_preview",
        OPERATOR_AUTHENTICATED_SESSION_TOOL,
    }.issubset(context.tools)
    assert context.schemas[OPERATOR_AUTHENTICATED_SESSION_TOOL]["parameters"][
        "additionalProperties"
    ] is False

    access_preview = json.loads(
        context.tools["cct_authenticated_access_preview"](
            {
                "target_id": "chrome-real-profile",
                "credential_receipt_event_id": receipt_event_id,
                "purpose": "resume-browser-session",
                "action_scope_sha256": ACTION_SCOPE_SHA256,
            }
        )
    )
    ticket_id = "plugin-authenticated-session"
    prepared = json.loads(
        context.tools["cct_authenticated_access_prepare"](
            {
                "operation_id": ticket_id,
                "target_id": access_preview["target_id"],
                "credential_receipt_event_id": access_preview[
                    "credential_receipt_event_id"
                ],
                "purpose": access_preview["purpose"],
                "action_scope_sha256": access_preview["action_scope_sha256"],
                "expected_target_spec_sha256": access_preview[
                    "target_spec_sha256"
                ],
                "expected_credential_receipt_sha256": access_preview[
                    "credential_receipt_sha256"
                ],
                "expected_preview_sha256": access_preview["preview_sha256"],
            }
        )
    )["prepared"]
    session_preview = json.loads(
        context.tools["cct_authenticated_session_preview"](
            {"prepared_event_id": prepared["prepared_event_id"]}
        )
    )
    session_arguments = {
        "execution_ticket_id": session_preview["ticket_id"],
        "prepared_event_id": session_preview["prepared_event_id"],
        "expected_prepared_sha256": session_preview["prepared_sha256"],
        "expected_target_spec_sha256": session_preview["target_spec_sha256"],
        "expected_action_scope_sha256": session_preview["action_scope_sha256"],
        "expected_preview_sha256": session_preview["preview_sha256"],
        "verifier_id": session_preview["verifier_id"],
    }
    ExecutionTicketAuthority(fixture["store"]).issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name=OPERATOR_AUTHENTICATED_SESSION_TOOL,
            arguments_sha256=sha256(
                canonical_json(session_arguments).encode()
            ).hexdigest(),
            goal_id="goal-plugin-authenticated-session",
            plan_id="plan-plugin-authenticated-session",
            plan_hash=sha256(b"plan:plugin-authenticated-session").hexdigest(),
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
        evidence=("operator://plugin/authenticated-session",),
    )

    middleware = context.middlewares[0][1]
    raw = middleware(
        tool_name=OPERATOR_AUTHENTICATED_SESSION_TOOL,
        args=session_arguments,
        original_args=session_arguments,
        next_call=lambda: context.tools[OPERATOR_AUTHENTICATED_SESSION_TOOL](
            session_arguments
        ),
    )
    result = json.loads(raw)

    assert result["success"] is True
    assert result["authenticated_session"]["status"] == "READY"
    assert result["authenticated_session"]["route"] == "browser_real_profile_snapshot"
    assert result["authenticated_session"]["dispatch_count"] == 1
    assert len(context.dispatches) == 1
    assert context.dispatches[0][0] == "browser_exec"
    assert "CCT_BROWSER_SESSION_READY_V1" in context.dispatches[0][1]["code"]
    assert fixture["store"].verify_chain()["valid"] is True


def test_plugin_does_not_expose_effect_tool_when_not_explicitly_mediated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hermes_home = tmp_path / "hermes"
    state_root = hermes_home / "cct-agency"
    state_root.mkdir(parents=True)
    configured(state_root)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    context = PluginContext(
        {
            "mediated_tools": [],
            "authenticated_access_targets": [target_config()],
            "authenticated_access_browser_real_profile_enabled": True,
        }
    )

    hermes_plugin.register(context)

    assert "cct_authenticated_access_preview" in context.tools
    assert "cct_authenticated_access_prepare" in context.tools
    assert "cct_authenticated_session_preview" in context.tools
    assert OPERATOR_AUTHENTICATED_SESSION_TOOL not in context.tools


def test_invalid_target_config_keeps_middleware_fail_closed_without_bridge_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hermes_home = tmp_path / "hermes"
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    context = PluginContext(
        {
            "mediated_tools": [OPERATOR_AUTHENTICATED_SESSION_TOOL],
            "authenticated_access_targets": [
                {**target_config(), "unexpected": "field"}
            ],
            "authenticated_access_browser_real_profile_enabled": True,
        }
    )

    hermes_plugin.register(context)

    assert OPERATOR_AUTHENTICATED_SESSION_TOOL not in context.tools
    denied = json.loads(
        context.middlewares[0][1](
            tool_name=OPERATOR_AUTHENTICATED_SESSION_TOOL,
            args={"execution_ticket_id": "missing"},
            original_args={"execution_ticket_id": "missing"},
            next_call=lambda: "must-not-run",
        )
    )
    assert denied["success"] is False
    assert "POLICY_CONFIGURATION_INVALID" in denied["error"]["reasons"]
