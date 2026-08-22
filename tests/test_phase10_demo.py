from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


def test_phase10_demo_end_to_end(tmp_path):
    root = Path(__file__).resolve().parents[1]
    receipt = tmp_path / "receipt"
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "cct_phase10_demo.py"),
            "--db",
            str(receipt / "agency.sqlite"),
            "--workspace",
            str(receipt / "workspace"),
            "--state-root",
            str(receipt / "autonomy"),
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    assert payload["first_run"]["opportunity_id"] == "fragile-first"
    assert payload["first_run"]["recovered_steps"] == 1
    assert payload["learned_second_choice"]["opportunity_id"] == "stable-first"
    assert payload["second_run"]["verified"] is True
    assert payload["rollback_run"]["success"] is False
    assert payload["rollback_run"]["rollback_complete"] is True
    assert payload["verification"]["rollback_temp_absent"] is True
    assert payload["verification"]["plan_content_found_in_event_ledger"] is False
    assert payload["chain"]["valid"] is True


def test_host_wake_noop_is_silent_in_message_mode(tmp_path):
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "cct_autonomy_tick.py"),
            "--db",
            str(tmp_path / "agency.sqlite"),
            "--workspace",
            str(tmp_path / "workspace"),
            "--state-root",
            str(tmp_path / "autonomy"),
            "--seed",
            "0",
            "--message-only",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout == ""


def test_autonomy_tick_private_adapter_detects_and_executes(tmp_path):
    root = Path(__file__).resolve().parents[1]
    state = tmp_path / "autonomy"
    state.mkdir()
    adapter = state / "artifact-adapters.json"
    adapter.write_text(
        json.dumps(
            [
                {
                    "opportunity_id": "private-adapter",
                    "relative_path": "private-adapter.md",
                    "content": "private adapter artifact\n",
                    "title": "Create private adapter artifact",
                    "rationale": "Host-owned configuration declares a missing artifact.",
                    "objective": "Create and verify private-adapter.md.",
                    "value_impacts": {
                        "truth": 0.8,
                        "competence": 0.8,
                        "autonomy": 0.7,
                    },
                }
            ]
        )
    )
    adapter.chmod(0o600)
    command = [
        sys.executable,
        str(root / "scripts" / "cct_autonomy_tick.py"),
        "--db",
        str(tmp_path / "agency.sqlite"),
        "--workspace",
        str(tmp_path / "workspace"),
        "--state-root",
        str(state),
        "--adapter-file",
        str(adapter),
        "--seed",
        "0",
        "--run-id",
        "adapter-wake-1",
    ]
    completed = subprocess.run(command, cwd=root, check=True, capture_output=True, text=True)
    payload = json.loads(completed.stdout)
    assert payload["success"] is True
    assert payload["observations"][0]["registered"] is True
    assert (tmp_path / "workspace" / "private-adapter.md").read_text() == "private adapter artifact\n"

    second = subprocess.run(
        [*command[:-2], "--run-id", "adapter-wake-2", "--message-only"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    assert second.stdout == ""


def test_autonomy_tick_rejects_group_readable_adapter(tmp_path):
    root = Path(__file__).resolve().parents[1]
    state = tmp_path / "autonomy"
    state.mkdir()
    adapter = state / "artifact-adapters.json"
    adapter.write_text("[]")
    adapter.chmod(0o640)
    completed = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "cct_autonomy_tick.py"),
            "--db",
            str(tmp_path / "agency.sqlite"),
            "--workspace",
            str(tmp_path / "workspace"),
            "--state-root",
            str(state),
            "--adapter-file",
            str(adapter),
            "--seed",
            "0",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "group/world accessible" in completed.stderr
