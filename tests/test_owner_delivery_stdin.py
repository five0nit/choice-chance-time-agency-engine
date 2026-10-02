"""Stdin-only artifacts: real sandbox/SQLite, explicit offline model/cloud doubles.

No generated code imports in the host process. Examples contain hypothetical
metadata; acceptance expectations are separately authored host-owned inputs.
"""

import copy
from hashlib import sha256
import json
from pathlib import Path

import pytest

from cct_agent.owner_delivery import OwnerDelivery
from cct_agent.owner_delivery_local import (
    DeliveryError,
    LocalDeliveryDriver,
    validate_acceptance,
)
from cct_agent.owner_delivery_model import validate
from tests.test_owner_delivery import environment as environment  # noqa: F401


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def inputs():
    return tuple(
        json.loads((EXAMPLES / ("pyproject-inspector." + suffix + ".json")).read_text())
        for suffix in ("bundle", "acceptance")
    )


def test_stdin_only_acceptance_is_valid_and_snapshotted():
    _, plan = inputs()
    original = copy.deepcopy(plan)
    validated = validate(plan, {"stage": "acceptance"})
    plan["cases"][0]["stdin"] = "changed caller data"
    assert validated == original


@pytest.mark.parametrize("text", ["", " ", "\n\t", "\x00", "x" * 8001])
def test_stdin_only_empty_or_invalid_input_stays_denied(text):
    _, plan = inputs()
    plan["cases"][0]["stdin"] = text
    with pytest.raises(DeliveryError, match="INVALID_ACCEPTANCE_CASE"):
        validate_acceptance(plan)


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("duplicate", "DUPLICATE_ACCEPTANCE_INPUT"),
        ("constant", "VACUOUS_ACCEPTANCE_PLAN"),
        ("help", "INVALID_ACCEPTANCE_CASE"),
    ],
)
def test_stdin_only_retains_nonvacuous_oracle_guards(mutation, reason):
    _, plan = inputs()
    if mutation == "duplicate":
        plan["cases"][1]["stdin"] = plan["cases"][0]["stdin"]
    elif mutation == "constant":
        for case in plan["cases"][:2]:
            case.pop("jsonChecks")
            case["stdout"] = "unchanging label\n"
    else:
        plan["cases"][0]["argv"] = ["--help"]
    with pytest.raises(DeliveryError, match=reason):
        validate_acceptance(plan)


def test_real_stdin_only_delivery_completes_and_survives_restart(
    environment, monkeypatch
):
    w, gateway, evidence, _, services, _, clock = environment
    value, plan = inputs()
    calls = []

    def model(payload):
        calls.append(copy.deepcopy(payload))
        if payload["stage"] == "select":
            return {
                "action": "BUILD",
                "ideaId": payload["candidates"][0]["ideaId"],
                "objective": "Inspect declared Python project metadata from stdin, without installs/imports.",
                "doneWhen": "Exact metadata/counts; unknown version stays null; invalid TOML rejected.",
                "why": "Offline hypothetical acceptance demonstration.",
                "reportIds": [],
            }
        if payload["stage"] == "build":
            return copy.deepcopy(value)
        if payload["stage"] == "acceptance":
            return copy.deepcopy(plan)
        assert payload["stage"] == "review"
        assert payload["execution"]["verification"]["independentBehavior"] is True
        return {
            "accepted": True,
            "issues": [],
        }  # Offline review double, not provider proof.

    w.model_override = model
    w.driver = LocalDeliveryDriver(w.home / "stdin-artifacts")
    result = w.tick()
    assert result["phase"] == "COMPLETE", result
    job = w.jobs()[0]
    receipt = job["execution"]
    assert job["attempts"] == 1 and w.chain_valid()
    assert receipt["testCount"] == len(plan["cases"]) == 5
    assert receipt["verification"]["generatedTestsVerified"] is False
    assert receipt["verification"]["semanticCompletion"] is False
    assert all(case["passed"] for case in receipt["verification"]["acceptanceEvidence"])
    assert [call["stage"] for call in calls] == [
        "select",
        "build",
        "acceptance",
        "review",
    ]
    assert services.calls == [job["id"]]
    for item in receipt["manifest"]:
        data = (Path(receipt["artifactRoot"]) / item["path"]).read_bytes()
        assert len(data) == item["bytes"] and sha256(data).hexdigest() == item["sha256"]
    logs = {item["stage"]: item for item in receipt["logs"]}
    observed = json.loads(logs["acceptance-declared-metadata"]["stdout"])
    assert observed["dependencies"] == ["alpha", "zeta>=1"]
    assert observed["scripts"] == ["doc-tool"]
    assert json.loads(logs["acceptance-unknown-version"]["stdout"])["version"] is None

    restarted = LocalDeliveryDriver(w.driver.root)
    monkeypatch.setattr(
        restarted,
        "_sandbox",
        lambda *a, **k: pytest.fail("cached run must not execute"),
    )
    assert restarted.run(receipt["jobId"], value, acceptance=plan) == receipt
    changed = copy.deepcopy(plan)
    changed["cases"][0]["stdin"] += "# changed commitment\n"
    assert (
        restarted.run(receipt["jobId"], value, acceptance=changed)["reason"]
        == "JOB_ID_BUNDLE_MISMATCH"
    )
    resumed = OwnerDelivery(
        w.home,
        gateway=gateway,
        evidence=evidence,
        driver=restarted,
        services=services,
        model=model,
        clock=lambda: clock[0],
    )
    try:
        assert resumed.jobs()[0] == job and resumed.chain_valid()
        gateway.workspace["learningEnabled"] = False
        assert resumed.tick()["phase"] == "PAUSED"
        assert len(calls) == 4 and services.calls == [job["id"]]
    finally:
        resumed.close()


def test_stdin_only_wrong_computation_cannot_pass_real_sandbox(tmp_path):
    value, plan = inputs()
    app = next(item for item in value["files"] if item["path"] == "app.py")
    app["content"] = app["content"].replace(
        "'dependency_count': len(dependencies)", "'dependency_count': 99"
    )
    # Remove self-authored assertions, proving independent expectations remain decisive.
    next(item for item in value["files"] if item["path"] == "test_app.py")[
        "content"
    ] = "import unittest\nclass T(unittest.TestCase):\n def test_claim(self): self.assertTrue(True)\n"
    receipt = LocalDeliveryDriver(tmp_path / "wrong-artifact").run(
        "wrong-count", value, acceptance=plan
    )
    assert receipt["status"] == "blocked", receipt
    assert receipt["reason"] == "INDEPENDENT_BEHAVIOR_FAILED"
    assert receipt["verification"]["independentBehavior"] is False
    assert "/quarantine/" in receipt["artifactRoot"]
