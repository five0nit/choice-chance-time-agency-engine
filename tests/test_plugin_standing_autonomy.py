from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest

import hermes_plugin
from tests.test_standing_worker import fixture


class PluginContext:
    def __init__(self, config: dict[str, object]) -> None:
        self.config = config
        self.tools: dict[str, Callable[..., str]] = {}
        self.schemas: dict[str, dict[str, Any]] = {}
        self.middlewares: list[tuple[str, Callable[..., Any]]] = []
        self.hooks: dict[str, Callable[..., Any]] = {}

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


def test_plugin_conditionally_registers_and_runs_standing_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, config_path, project, _authority = fixture(tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(profile))
    context = PluginContext(
        {
            "identity": "Standing-Autonomy-Test",
            "standing_autonomy_config": str(config_path),
        }
    )

    hermes_plugin.register(context)

    assert "cct_standing_autonomy_status" in context.tools
    assert "cct_standing_autonomy_run" in context.tools
    status = json.loads(context.tools["cct_standing_autonomy_status"]({}))
    result = json.loads(
        context.tools["cct_standing_autonomy_run"](
            {"run_id": "plugin-standing-run"}
        )
    )
    retry = json.loads(
        context.tools["cct_standing_autonomy_run"](
            {"run_id": "plugin-standing-retry"}
        )
    )

    assert status["current_tier"] == 3
    assert status["eligible_action_ids"] == ["project-health"]
    assert result["status"] == "VERIFIED"
    assert result["fresh_user_approval_required"] is False
    assert retry["status"] == "NO_OP"
    assert retry["reason"] == "UNCHANGED_TRIGGERS"
    assert subprocess_status(project) == ""
    schema = context.schemas["cct_standing_autonomy_run"]["parameters"]
    assert schema["additionalProperties"] is False
    with pytest.raises(ValueError, match="unknown parameter: argv"):
        context.tools["cct_standing_autonomy_run"](
            {
                "run_id": "plugin-standing-injected",
                "argv": ["/bin/sh", "-c", "whoami"],
            }
        )


def subprocess_status(project: Path) -> str:
    import subprocess

    return subprocess.run(
        ["/usr/bin/git", "status", "--porcelain=v1"],
        cwd=project,
        check=True,
        capture_output=True,
        text=True,
        env={},
    ).stdout.strip()


def test_invalid_standing_config_suppresses_only_conditional_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    profile.mkdir()
    invalid = profile / "standing.json"
    invalid.write_text("{}\n", encoding="utf-8")
    invalid.chmod(0o600)
    monkeypatch.setenv("HERMES_HOME", str(profile))
    context = PluginContext(
        {
            "identity": "Standing-Autonomy-Invalid",
            "standing_autonomy_config": str(invalid),
        }
    )

    hermes_plugin.register(context)

    assert "cct_status" in context.tools
    assert "cct_standing_autonomy_status" not in context.tools
    assert "cct_standing_autonomy_run" not in context.tools
    assert len(context.middlewares) == 1
