from __future__ import annotations

from hashlib import sha256
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

import hermes_plugin
from cct_agent.store import EventStore, canonical_json


class MiddlewareContext:
    def __init__(self, config: dict[str, object] | None = None) -> None:
        self.config = dict(config or {})
        self.tools: dict[str, Callable[..., str]] = {}
        self.hooks: dict[str, Callable[..., Any]] = {}
        self.middlewares: list[tuple[str, Callable[..., Any]]] = []

    def get_config(self, key: str, default: object = None) -> object:
        return self.config.get(key, default)

    def register_tool(
        self, *, name: str, handler: Callable[..., str], **kwargs: object
    ) -> None:
        del kwargs
        self.tools[name] = handler

    def register_hook(self, name: str, handler: Callable[..., Any]) -> None:
        self.hooks[name] = handler

    def register_middleware(
        self, middleware_type: str, callback: Callable[..., Any]
    ) -> None:
        self.middlewares.append((middleware_type, callback))


def register_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, object] | None = None,
) -> MiddlewareContext:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    context = MiddlewareContext(config)
    hermes_plugin.register(context)
    return context


def execute(
    callback: Callable[..., Any],
    *,
    tool_name: object,
    args: object,
    original_args: object,
    downstream_result: object,
) -> tuple[Any, int]:
    downstream_calls = 0

    def next_call() -> object:
        nonlocal downstream_calls
        downstream_calls += 1
        return downstream_result

    result = callback(
        tool_name=tool_name,
        args=args,
        original_args=original_args,
        next_call=next_call,
        telemetry_schema_version="1",
        middleware_schema_version="1",
        session_id="session-private-runtime-id",
        request_id="request-private-runtime-id",
    )
    return result, downstream_calls


def test_plugin_registers_exactly_one_tool_execution_middleware(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = register_context(tmp_path, monkeypatch)

    assert len(context.tools) == 21
    assert set(context.hooks) == {
        "pre_gateway_dispatch",
        "pre_llm_call",
        "post_llm_call",
    }
    assert [kind for kind, _callback in context.middlewares] == ["tool_execution"]
    assert not inspect.iscoroutinefunction(context.middlewares[0][1])


def test_packaged_manifest_matches_directory_manifest_and_declares_mediation() -> None:
    project_root = Path(__file__).parents[1]
    directory_manifest = (project_root / "plugin.yaml").read_bytes()
    packaged_manifest = (project_root / "hermes_plugin" / "plugin.yaml").read_bytes()

    assert packaged_manifest == directory_manifest
    assert b"\n  mediated_tools:\n" in packaged_manifest


def test_selected_tool_is_denied_without_downstream_and_receipt_omits_raw_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = register_context(
        tmp_path, monkeypatch, {"mediated_tools": ["workspace_write"]}
    )
    callback = context.middlewares[0][1]
    private_marker = "raw-private-argument-3fe8d4"
    arguments = {"path": "artifact.txt", "content": private_marker}
    expected_digest = sha256(canonical_json(arguments).encode("utf-8")).hexdigest()

    result, downstream_calls = execute(
        callback,
        tool_name="workspace_write",
        args=arguments,
        original_args={"content": private_marker, "unvalidated": True},
        downstream_result="must-not-run",
    )

    assert downstream_calls == 0
    assert json.loads(result) == {
        "success": False,
        "blocked": True,
        "error": {
            "code": "CCT_MEDIATION_DENIED",
            "reasons": ["TICKET_REQUIRED"],
        },
        "mediation": {
            "schema_version": "cct.tool_execution.v1",
            "selected": True,
            "tool_name": "workspace_write",
            "arguments_sha256": expected_digest,
            "receipt_persisted": True,
            "raw_arguments_persisted": False,
        },
    }
    events = EventStore(
        tmp_path / "hermes" / "cct-agency" / "agency.sqlite"
    ).events("mediation.tool.denied")
    assert len(events) == 1
    assert events[0].payload == {
        "schema_version": "cct.tool_execution.denial.v1",
        "tool_name": "workspace_write",
        "arguments_sha256": expected_digest,
        "reason_codes": ["TICKET_REQUIRED"],
        "blocked": True,
        "downstream_called": False,
        "raw_arguments_persisted": False,
    }
    serialized_receipt = canonical_json(events[0].payload)
    assert private_marker not in serialized_receipt
    assert "session-private-runtime-id" not in serialized_receipt
    assert "request-private-runtime-id" not in serialized_receipt


@pytest.mark.parametrize(
    "config",
    [None, {"mediated_tools": []}, {"mediated_tools": ["workspace_write"]}],
)
def test_unselected_tool_passes_through_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, object] | None,
) -> None:
    context = register_context(tmp_path, monkeypatch, config)
    callback = context.middlewares[0][1]
    downstream_result = object()

    result, downstream_calls = execute(
        callback,
        tool_name="weather_lookup",
        args={"city": "Brisbane"},
        original_args={"city": "Brisbane"},
        downstream_result=downstream_result,
    )

    assert result is downstream_result
    assert downstream_calls == 1
    assert not EventStore(
        tmp_path / "hermes" / "cct-agency" / "agency.sqlite"
    ).events("mediation.tool.denied")


def test_malformed_selected_call_is_denied_without_throwing_or_downstream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = register_context(
        tmp_path, monkeypatch, {"mediated_tools": ["workspace_write"]}
    )
    callback = context.middlewares[0][1]

    result, downstream_calls = execute(
        callback,
        tool_name="workspace_write",
        args=["not", "a", "dictionary", "raw-private-argument-a71c"],
        original_args="raw-original-argument-77a2",
        downstream_result="must-not-run",
    )

    assert downstream_calls == 0
    denial = json.loads(result)
    assert denial["error"] == {
        "code": "CCT_MEDIATION_DENIED",
        "reasons": ["TICKET_REQUIRED", "MALFORMED_CALL"],
    }
    assert denial["mediation"]["arguments_sha256"] is None
    events = EventStore(
        tmp_path / "hermes" / "cct-agency" / "agency.sqlite"
    ).events("mediation.tool.denied")
    assert len(events) == 1
    assert events[0].payload["arguments_sha256"] is None
    assert "raw-private-argument-a71c" not in canonical_json(events[0].payload)
    assert "raw-original-argument-77a2" not in canonical_json(events[0].payload)


def test_malformed_tool_identity_is_denied_when_mediation_is_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = register_context(
        tmp_path, monkeypatch, {"mediated_tools": ["workspace_write"]}
    )

    result, downstream_calls = execute(
        context.middlewares[0][1],
        tool_name=["workspace_write"],
        args={"path": "artifact.txt"},
        original_args={"path": "artifact.txt"},
        downstream_result="must-not-run",
    )

    assert downstream_calls == 0
    denial = json.loads(result)
    assert denial["error"] == {
        "code": "CCT_MEDIATION_DENIED",
        "reasons": ["MALFORMED_CALL"],
    }
    assert denial["mediation"]["tool_name"] is None


def test_selected_tool_stays_denied_when_receipt_persistence_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FailingStore:
        def append(self, kind: str, payload: object) -> None:
            del kind, payload
            raise OSError("simulated persistence failure")

    monkeypatch.setattr(
        hermes_plugin, "_kernel", lambda: SimpleNamespace(store=FailingStore())
    )
    context = MiddlewareContext({"mediated_tools": ["workspace_write"]})
    hermes_plugin.register(context)

    result, downstream_calls = execute(
        context.middlewares[0][1],
        tool_name="workspace_write",
        args={"path": "artifact.txt"},
        original_args={"path": "artifact.txt"},
        downstream_result="must-not-run",
    )

    assert downstream_calls == 0
    denial = json.loads(result)
    assert denial["blocked"] is True
    assert denial["error"] == {
        "code": "CCT_MEDIATION_DENIED",
        "reasons": ["TICKET_REQUIRED", "RECEIPT_PERSISTENCE_FAILED"],
    }
    assert denial["mediation"]["receipt_persisted"] is False


@pytest.mark.parametrize(
    "configured",
    ["workspace_write", ["workspace write"], ["workspace_write", "workspace_write"]],
)
def test_explicit_malformed_mediated_tools_configuration_keeps_denying_middleware(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    configured: object,
) -> None:
    context = register_context(
        tmp_path,
        monkeypatch,
        {"mediated_tools": configured},
    )

    assert len(context.tools) == 21
    assert set(context.hooks) == {
        "pre_gateway_dispatch",
        "pre_llm_call",
        "post_llm_call",
    }
    assert [kind for kind, _callback in context.middlewares] == ["tool_execution"]
    result, downstream_calls = execute(
        context.middlewares[0][1],
        tool_name="workspace_write",
        args={"path": "artifact.txt"},
        original_args={"path": "artifact.txt"},
        downstream_result="must-not-run",
    )
    denial = json.loads(result)
    assert downstream_calls == 0
    assert denial["error"] == {
        "code": "CCT_MEDIATION_DENIED",
        "reasons": ["POLICY_CONFIGURATION_INVALID"],
    }
    assert denial["mediation"]["configuration_valid"] is False


def test_real_plugin_manager_keeps_fail_closed_middleware_after_mixed_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugins_runtime = pytest.importorskip("hermes_cli.plugins")
    middleware_runtime = pytest.importorskip("hermes_cli.middleware")
    config_runtime = pytest.importorskip("hermes_cli.config")
    home = tmp_path / "real-hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(
        config_runtime,
        "load_config_readonly",
        lambda: {
            "plugins": {
                "entries": {
                    "cct-agency": {
                        "settings": {
                            "mediated_tools": ["workspace_write", "invalid name"]
                        }
                    }
                }
            }
        },
    )
    manager = plugins_runtime.PluginManager(scope_key=str(home.resolve()))
    manifest = plugins_runtime.PluginManifest(
        name="cct-agency",
        key="cct-agency",
        source="user",
        path=str(Path(hermes_plugin.__file__).parent),
    )
    monkeypatch.setattr(
        manager,
        "_load_directory_module",
        lambda _manifest, module_name: hermes_plugin,
    )
    downstream_calls = 0

    def downstream(_args: dict[str, Any]) -> str:
        nonlocal downstream_calls
        downstream_calls += 1
        return "must-not-run"

    try:
        manager._load_plugin(manifest)
        loaded = manager._plugins["cct-agency"]
        assert loaded.enabled is True
        assert loaded.error is None
        assert loaded.middleware_registered == ["tool_execution"]
        monkeypatch.setattr(plugins_runtime, "get_plugin_manager", lambda: manager)
        denial = json.loads(
            middleware_runtime.run_tool_execution_middleware(
                "workspace_write",
                {"path": "artifact.txt"},
                downstream,
            )
        )
        assert downstream_calls == 0
        assert denial["error"]["reasons"] == ["POLICY_CONFIGURATION_INVALID"]
    finally:
        manager.unload()


def test_callback_runs_inside_real_hermes_execution_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    middleware_runtime = pytest.importorskip("hermes_cli.middleware")
    context = register_context(
        tmp_path, monkeypatch, {"mediated_tools": ["workspace_write"]}
    )
    callback = context.middlewares[0][1]
    monkeypatch.setattr(
        middleware_runtime,
        "_get_middleware_callbacks",
        lambda kind: [callback] if kind == "tool_execution" else [],
    )
    downstream_calls = 0

    def downstream(effective_args: dict[str, Any]) -> str:
        nonlocal downstream_calls
        downstream_calls += 1
        return canonical_json({"success": True, "args": effective_args})

    denied = middleware_runtime.run_tool_execution_middleware(
        "workspace_write",
        {"path": "artifact.txt", "content": "blocked"},
        downstream,
        session_id="real-chain-session",
    )
    assert not inspect.isawaitable(denied)
    assert json.loads(denied)["error"]["code"] == "CCT_MEDIATION_DENIED"
    assert downstream_calls == 0

    allowed = middleware_runtime.run_tool_execution_middleware(
        "weather_lookup",
        {"city": "Brisbane"},
        downstream,
        session_id="real-chain-session",
    )
    assert json.loads(allowed) == {
        "success": True,
        "args": {"city": "Brisbane"},
    }
    assert downstream_calls == 1