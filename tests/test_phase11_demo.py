from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


def test_phase11_personal_agency_demo_end_to_end(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "cct_phase11_demo.py"),
            "--db",
            str(tmp_path / "agency.sqlite"),
            "--workspace",
            str(tmp_path / "workspace"),
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert result["version"] == "0.8.0a1"
    assert result["principal"]["id"] == "operator"
    assert result["principal"]["self_ratification_enabled"] is False
    assert result["principal"]["revision_proposal_auto_apply"] is False
    assert result["capability"]["name"] == "workspace.inspect"
    assert result["capability"]["used"]["actions"] == 2
    assert result["capability"]["remaining"]["actions"] == 0
    assert result["capability"]["third_request_blocked"] is True
    assert "LEASE_ACTION_BUDGET_EXHAUSTED" in result["capability"][
        "third_request_reason"
    ]
    assert result["safe_inspection"] == {
        "authorized": "allow",
        "content_matches": True,
        "content_trust": "untrusted_workspace_content",
        "instructions_authorized": False,
        "taint_flags": [],
    }
    assert result["tainted_inspection"]["instructions_authorized"] is False
    assert result["tainted_inspection"]["taint_flags"] == [
        "PROMPT_OVERRIDE_LANGUAGE",
        "TOOL_INSTRUCTION_LANGUAGE",
    ]
    assert result["privacy"] == {
        "safe_content_persisted": False,
        "tainted_content_persisted": False,
    }
    assert all(value is False for value in result["high_power_executors"].values())
    assert result["chain"]["valid"] is True
