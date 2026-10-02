"""Full continuation with real SQLite, ticketed transport and Bubblewrap.

Model outputs, public server bodies, owner gateway and notification are explicit
fixtures. No real provider/accounts or Internet; generated Python runs only in
the credential-free, networkless host sandbox, never in this test interpreter.
"""

import copy
import json

from cct_agent.owner_continuation import Continuation
from cct_agent.owner_delivery import OwnerDelivery
from cct_agent.owner_delivery_local import LocalDeliveryDriver
from tests.test_owner_delivery import environment as environment, bundle, acceptance
from tests.test_owner_delivery_research import (
    network as network,
    prohibit_real_network as prohibit_real_network,
)


def enable(w):
    path = w.home / "config/cct-owner-continuation.json"
    path.write_text(
        json.dumps(
            {
                "schemaVersion": "cct.owner_continuation.config.v1",
                "ownerUid": w.config["ownerUid"],
                "projectId": w.config["projectId"],
                "authorization": "operator://test/continuation-fixture",
                "enabled": True,
            }
        )
    )
    path.chmod(0o600)
    w.continuation = Continuation(w)


class CycleModel:
    def __init__(self):
        self.calls = []

    def __call__(self, p):
        self.calls.append(copy.deepcopy(p))
        stage = p["stage"]
        if stage in {"continuation_plan", "continuation_decide"}:
            parents = p["parents"]
            done = len(p["actualOutcomes"]) >= 2
            action = (
                "WAIT"
                if done
                else "UPGRADE"
                if parents
                else ("RESEARCH" if stage == "continuation_plan" else "NEW")
            )
            idea = "" if done or parents else p["candidates"][0]["ideaId"]
            parent = parents[0]["buildId"] if parents and not done else ""
            anchor = "candidate:" + idea if idea else "outcome:" + parent
            return {
                "action": action,
                "ideaId": idea,
                "parentBuildId": parent,
                "objective": ""
                if done
                else "Fixture: double integer and add one"
                if parents
                else "Fixture: double integer",
                "doneWhen": ""
                if done
                else "2 gives 5 and -3 gives -5"
                if parents
                else "2 gives 4 and -3 gives -6",
                "why": "Fixture alternatives: observed parent allows one observable change; otherwise verify a source before starting.",
                "reportIds": [],
                "sourceIds": [p["sourceCatalog"][0]["id"]]
                if action == "RESEARCH"
                else [],
                "evidenceIds": [] if done else [anchor],
                "alternatives": [
                    {
                        "action": "WAIT",
                        "reason": "No new evidence or useful untried follow-up.",
                    },
                    {
                        "action": action if action != "WAIT" else "NEW",
                        "reason": "Observable bounded fixture behavior.",
                    },
                ],
            }
        if stage == "continuation_novelty":
            prop = p["proposal"]
            return {
                "accepted": True,
                "objectiveKey": "fixture-double-plus-one"
                if prop["parentBuildId"]
                else "fixture-double",
                "comparedIds": p["comparisonIds"],
                "evidenceIds": prop["evidenceIds"],
                "improvement": prop["doneWhen"],
                "issues": [],
            }
        if stage == "build":
            value = bundle()
            if p.get("parentBuild"):
                value["files"][1]["content"] = value["files"][1]["content"].replace(
                    "int(sys.argv[1])*2", "int(sys.argv[1])*2+1"
                )
                value["summary"] = (
                    "Fixture-only double-plus-one child; not production research."
                )
            return value
        if stage == "acceptance":
            value = acceptance()
            if p.get("parentBuild"):
                value["cases"][0]["stdout"] = "5\n"
                value["cases"][1]["stdout"] = "-5\n"
            return value
        assert stage == "review"
        return {"accepted": True, "issues": []}


def test_discovery_real_sandbox_outcome_and_independent_child_no_promote(
    environment, network
):
    w, g, e, d, s, m, clock = environment
    enable(w)
    w.driver = LocalDeliveryDriver(w.home / "sandbox-fixture")
    model = CycleModel()
    w.model_override = model
    first = w.tick()
    assert first["phase"] == "COMPLETE", first
    parent = w.jobs()[0]
    assert parent["execution"]["sandbox"] == "bubblewrap-no-network"
    assert parent["verification"]["independentBehavior"] is True
    assert parent["verification"]["generatedTestsVerified"] is False
    assert w.continuation.status()["research"]["verified"] == 1
    assert len(network.calls) == 1
    clock[0] += 1
    second = w.tick()
    assert second["phase"] == "COMPLETE", second
    child = next(j for j in w.jobs() if j["id"] != parent["id"])
    assert child["parentBuild"]["jobId"] == parent["id"]
    assert child["parentBuild"]["bundle"] == parent["bundle"]
    assert child["parentBuild"]["execution"] == parent["execution"]
    assert child["bundle"] != parent["bundle"]
    assert child["verification"]["testCount"] == 2
    assert "ownerRequest" not in child and "requestId" not in child
    assert child["maxArtifactAttempts"] == 2
    assert len(s.calls) == 2 and w.chain_valid()
    assert w.db.execute("SELECT count(*) FROM continuation_outcomes").fetchone()[0] == 2
    assert all(j["phase"] == "COMPLETE" for j in w.jobs())
    waiting = w.tick()
    assert waiting["continuation"]["state"] == "WAIT", waiting
    calls = len(model.calls)
    for _ in range(3):
        assert w.tick()["continuation"]["state"] == "WAIT"
    assert len(model.calls) == calls == 12
    w2 = OwnerDelivery(
        w.home,
        gateway=g,
        evidence=e,
        driver=w.driver,
        services=s,
        model=model,
        clock=lambda: clock[0],
    )
    try:
        assert w2.tick()["continuation"]["state"] == "WAIT"
        assert len(model.calls) == calls and len(w2.jobs()) == 2
    finally:
        w2.close()


def test_real_research_resumes_after_global_cap_without_duplicate_dispatch(
    environment, network
):
    w, g, e, d, s, m, clock = environment
    enable(w)
    research = w.continuation.research
    ids = [entry["id"] for entry in research.catalog()]
    assert research.fetch("fixture-old-cycle", ids[0])["ok"]
    assert research.fetch("fixture-old-cycle", ids[1])["ok"]
    model = CycleModel()
    w.model_override = model
    status = w.tick()
    assert status["continuation"]["state"] == "DAILY_CAP", status
    assert status["continuation"]["blocker"] == "DELIVERY_RESEARCH_DAILY_CAP"
    for _ in range(2):
        w.tick()
    assert len(network.calls) == 2 and len(model.calls) == 1
    clock[0] += 86401
    resumed = w.tick()
    assert resumed["phase"] == "COMPLETE", resumed
    assert len(network.calls) == 3
    assert sum(p["stage"] == "continuation_plan" for p in model.calls) == 1
