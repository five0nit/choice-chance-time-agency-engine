from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


def test_phase12_demo_proves_proactive_tasks_without_authority_expansion(
    tmp_path: Path,
) -> None:
    script = Path(__file__).parents[1] / "scripts" / "cct_phase12_demo.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--db",
            str(tmp_path / "state" / "agency.sqlite"),
            "--workspace",
            str(tmp_path / "workspace"),
            "--state-root",
            str(tmp_path / "autonomy"),
        ],
        cwd=script.parents[1],
        text=True,
        capture_output=True,
        check=True,
    )
    result = json.loads(completed.stdout)
    assert result["status"] == "pass"
    assert result["version"] == "0.9.0a1"
    assert result["first_registration"] == {
        "opportunity_id": "phase12-first-task",
        "executable": False,
        "content_trust": "self_generated_untrusted_proposal",
        "instructions_authorized": False,
    }
    assert result["first_presentation"]["initiative_kind"] == "opportunity"
    assert "ask Hermes to record INTERESTED / SKIP / SNOOZE" in result[
        "first_presentation"
    ]["message"]
    assert result["acceptance"]["operator_interest_recorded"] is True
    assert result["acceptance"]["execution_authority_granted"] is False
    assert result["acceptance"]["capability_lease_changed"] is False
    assert result["acceptance"]["opportunity_execution_status_changed"] is False
    assert result["cooldown"] == {
        "first_reason": "COOLDOWN",
        "second_reason": "COOLDOWN",
        "state_consumed": [False, False],
    }
    assert "second useful opportunity" in result["second_presentation"]["message"]
    assert result["authority_side_effects"] == {
        "capability_leases": 0,
        "opportunity_status_changes": 0,
        "autonomy_runs": 0,
    }
    assert result["proactive_emissions"] == 2
    assert result["goal_scout"]["created"] == 1
    assert result["goal_scout"]["eligible_goals"] == 1
    assert result["goal_scout"]["llm_calls"] == 0
    assert result["goal_scout"]["goal_id"] == "phase12-scouted-task"
    assert result["goal_scout"]["content_trust"] == "derived_from_canonical_goal"
    assert result["goal_scout"]["executable"] is False
    assert result["event_chain"]["valid"] is True
    assert result["raw_chain_of_thought_stored"] is False
