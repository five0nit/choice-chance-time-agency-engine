"""Continuation on real OwnerDelivery/SQLite with explicit, offline test doubles.

The fixture driver cases test orchestration, not independent execution or facts.
Real sandbox coverage lives in test_owner_continuation_fullcycle.py.
"""

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json


import pytest

from cct_agent.owner_continuation import (
    Continuation,
    COOLDOWN,
    digest,
    objective_fingerprint,
)
from cct_agent.owner_delivery import OwnerDelivery
from cct_agent.owner_delivery_model import validate
from tests.test_owner_delivery import environment as environment, acceptance, bundle
from tests.test_owner_continuation_model import decision, novelty


class ProcessCrash(BaseException):
    """Simulate process loss without invoking normal Exception recovery."""


class StagedModel:
    """No permissive fallback: unexpected stages and invalid replies fail the test."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.calls = []

    def __call__(self, payload):
        self.calls.append(deepcopy(payload))
        assert self.steps, f"Unexpected model call: {payload['stage']}"
        stage, result = self.steps.pop(0)
        assert payload["stage"] == stage
        result = result(deepcopy(payload)) if callable(result) else deepcopy(result)
        return validate(result, payload)


class DeterministicResearch:
    """Labelled reference fixtures; never open a socket or imply a live GET."""

    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.receipts = {}
        self.after_fetch = None
        self.failure: BaseException | None = None
        self.sources = [
            {
                "id": "fixture-reference",
                "title": "Offline integer CLI fixture",
                "url": "https://example.invalid/fixture/integer-cli",
            }
        ]

    def catalog(self):
        return deepcopy(self.sources)

    def fetch(self, cycle_id, source_id):
        key = (cycle_id, source_id)
        assert key not in self.receipts, (
            "Continuation replayed an already saved research effect"
        )
        self.calls.append(key)
        if self.failure:
            raise self.failure
        source = next(item for item in self.sources if item["id"] == source_id)
        text = "OFFLINE TEST FIXTURE: explicit signed integer inputs support deterministic CLI tests."
        receipt = {
            "id": source_id,
            "url": source["url"],
            "sha256": sha256(text.encode()).hexdigest(),
            "text": text,
            "fetchedAt": datetime.fromtimestamp(
                self.clock[0], timezone.utc
            ).isoformat(),
            "receipt": {"kind": "offline-fixture-only", "verified": True},
        }
        self.receipts[key] = deepcopy(receipt)
        if self.after_fetch:
            self.after_fetch()
        return receipt

    def usage(self):
        return {
            "attempted": len(self.calls),
            "verified": len(self.receipts),
            "maxPer24h": 2,
        }


def continuation_config(worker, **changes):
    value = {
        "schemaVersion": "cct.owner_continuation.config.v1",
        "ownerUid": worker.config["ownerUid"],
        "projectId": worker.config["projectId"],
        "authorization": "operator://fixture/bounded-continuation",
        "enabled": True,
    }
    value.update(changes)
    path = worker.home / "config/cct-owner-continuation.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def attach(environment, model):
    worker, gateway, evidence, driver, services, _, clock = environment
    continuation_config(worker)
    research = DeterministicResearch(clock)
    worker.model_override = model
    worker.continuation = Continuation(worker, research=research)
    return worker.continuation, research


@contextmanager
def restart(environment, model, research):
    worker, gateway, evidence, driver, services, _, clock = environment
    # Inject before construction so no real researcher/config dependency is loaded.
    resumed = OwnerDelivery(
        worker.home,
        gateway=gateway,
        evidence=evidence,
        driver=worker.driver,
        services=services,
        model=model,
        continuation=object(),
        clock=lambda: clock[0],
    )
    try:
        resumed.continuation = Continuation(resumed, research=research)
        yield resumed
    finally:
        resumed.close()


def tick_loop(worker, snapshot):
    with worker.lock():
        return worker.continuation.tick(snapshot)


def rows(worker, table):
    return [
        tuple(row) for row in worker.db.execute(f"SELECT * FROM {table} ORDER BY rowid")
    ]


def frozen_state(worker):
    return {
        table: rows(worker, table)
        for table in (
            "continuation_cycles",
            "continuation_outcomes",
            "continuation_objectives",
            "jobs",
            "attempts",
            "tool_attempts",
            "events",
            "meta",
        )
    }


def new_steps():
    return [
        ("continuation_plan", lambda p: decision(p)),
        ("continuation_novelty", lambda p: novelty(p)),
    ]


def upgrade_bundle(payload):
    parent = payload["parentBuild"]
    assert parent["phase"] == "COMPLETE"
    assert parent["bundleDigest"] == digest(parent["bundle"])
    assert parent["execution"]["status"] == "completed"
    assert parent["verification"]["acceptanceDigest"] == digest(parent["acceptance"])
    assert parent["review"] == {"accepted": True, "issues": []}
    assert "int(sys.argv[1])*2" in next(
        f["content"] for f in parent["bundle"]["files"] if f["path"] == "app.py"
    )
    result = deepcopy(parent["bundle"])
    result["summary"] = "Fixture-only integer doubler with optional absolute output"
    content = {
        "README.md": "OFFLINE TEST FIXTURE. Example: python app.py --absolute -3 prints 6.\n",
        "app.py": (
            "import argparse\n"
            "def double(value, absolute=False):\n"
            "    result = value * 2\n"
            "    return abs(result) if absolute else result\n"
            "def main():\n"
            "    parser = argparse.ArgumentParser(description='Fixture integer doubler')\n"
            "    parser.add_argument('--absolute', action='store_true')\n"
            "    parser.add_argument('value', nargs='?', type=int)\n"
            "    args = parser.parse_args()\n"
            "    if args.value is None:\n"
            "        parser.print_help()\n"
            "    else:\n"
            "        print(double(args.value, args.absolute))\n"
            "if __name__ == '__main__':\n"
            "    main()\n"
        ),
        "test_app.py": (
            "import unittest\nfrom app import double\n"
            "class FixtureTests(unittest.TestCase):\n"
            "    def test_signed(self):\n        self.assertEqual(double(-3), -6)\n"
            "    def test_absolute(self):\n        self.assertEqual(double(-3, True), 6)\n"
            "    def test_zero(self):\n        self.assertEqual(double(0, True), 0)\n"
        ),
    }
    result["files"] = [
        {"path": name, "content": value} for name, value in content.items()
    ]
    return result


def upgrade_acceptance(payload):
    assert payload["bundle"] != payload["parentBuild"]["bundle"]
    return {
        "schemaVersion": "cct.cli_acceptance.v1",
        "cases": [
            {
                "id": "signed-default",
                "argv": ["-3"],
                "stdin": "",
                "exitCode": 0,
                "stdout": "-6\n",
            },
            {
                "id": "absolute-option",
                "argv": ["--absolute", "-3"],
                "stdin": "",
                "exitCode": 0,
                "stdout": "6\n",
            },
        ],
    }


def cycle_steps():
    return [
        *new_steps(),
        ("build", bundle()),
        ("acceptance", acceptance()),
        ("review", {"accepted": True, "issues": []}),
        ("continuation_plan", lambda p: decision(p, "UPGRADE")),
        ("continuation_novelty", lambda p: novelty(p, key="fixture-absolute-output")),
        ("build", upgrade_bundle),
        ("acceptance", upgrade_acceptance),
        ("review", {"accepted": True, "issues": []}),
    ]


def test_new_complete_upgrade_uses_actual_parent_then_waits_without_churn(environment):
    worker, gateway, evidence, driver, services, _, clock = environment
    model = StagedModel(
        *cycle_steps(), ("continuation_plan", lambda p: decision(p, "WAIT"))
    )
    continuation, research = attach(environment, model)
    budgets = deepcopy(worker.builds.effective())

    first = worker.tick()
    assert first["phase"] == "COMPLETE", first
    root = worker.jobs()[0]
    immutable_root = deepcopy(root["bundle"])
    observed_root = continuation.observe(root)
    assert observed_root is not None
    assert first["continuation"]["state"] == "LEARNED"
    assert first["lastOutcome"]["revenueDelta"] is None
    assert root["maxArtifactAttempts"] == 2 and root["attempts"] == 1
    assert root["rootBuildId"] == root["id"]
    assert "ownerRequest" not in root and "requestId" not in root
    clock[0] += 1
    with restart(environment, model, research) as resumed:
        second = resumed.tick()
        assert second["phase"] == "COMPLETE", second
        child = next(job for job in resumed.jobs() if job.get("parentBuildId"))
        assert child["parentBuild"] == observed_root
        assert child["rootBuildId"] == root["id"]
        assert child["parentBuildId"] == observed_root["buildId"]
        assert child["bundle"] != immutable_root
        assert (
            next(job for job in resumed.jobs() if job["id"] == root["id"])["bundle"]
            == immutable_root
        )
        child_contexts = [call for call in model.calls if call.get("parentBuild")]
        assert [call["stage"] for call in child_contexts] == [
            "build",
            "acceptance",
            "review",
        ]
        assert all(call["parentBuild"] == observed_root for call in child_contexts)
        assert all(
            call.get("continuationContext") and "ownerRequest" not in call
            for call in child_contexts
        )
        assert resumed.tick()["phase"] == "WAIT"
        assert model.calls[-1]["parents"] == []
        assert {outcome["jobId"] for outcome in model.calls[-1]["actualOutcomes"]} == {
            root["id"],
            child["id"],
        }
        before = frozen_state(resumed)
        for _ in range(3):
            clock[0] += 60
            assert tick_loop(resumed, evidence.snapshot()) is None
        assert frozen_state(resumed) == before
        assert resumed.builds.effective() == budgets
        assert len(resumed.jobs()) == 2
        assert len(rows(resumed, "attempts")) == len(model.calls) == 11
        assert len(rows(resumed, "tool_attempts")) == 2
        assert resumed.chain_valid()

    assert not research.calls and not model.steps
    assert len(set(services.calls)) == 2


def test_unchanged_wait_survives_restart_without_any_sql_or_model_churn(environment):
    worker, _, evidence, driver, services, _, clock = environment
    model = StagedModel(("continuation_plan", lambda p: decision(p, "WAIT")))
    continuation, research = attach(environment, model)
    assert tick_loop(worker, evidence.snapshot()) is None
    assert continuation.status()["state"] == "WAIT"
    with restart(environment, model, research) as resumed:
        before = frozen_state(resumed)
        changes = resumed.db.total_changes
        for delta in (60, 3600, 86401):
            clock[0] += delta
            assert tick_loop(resumed, evidence.snapshot()) is None
        assert frozen_state(resumed) == before
        assert resumed.db.total_changes == changes
    assert len(model.calls) == 1
    assert (
        not research.calls
        and not worker.jobs()
        and not driver.calls
        and not services.calls
    )


@pytest.mark.parametrize("checkpoint", ["plan", "research", "decision", "novelty"])
def test_restart_resumes_each_saved_checkpoint_once(
    environment, monkeypatch, checkpoint
):
    worker, _, evidence, driver, services, _, _ = environment
    model = StagedModel(
        ("continuation_plan", lambda p: decision(p, "RESEARCH")),
        ("continuation_decide", lambda p: decision(p)),
        ("continuation_novelty", lambda p: novelty(p)),
    )
    continuation, research = attach(environment, model)
    original = continuation._save
    crashed = []

    def crash_after_save(cycle):
        original(cycle)
        if checkpoint in cycle and not crashed:
            crashed.append(cycle["id"])
            raise ProcessCrash()

    monkeypatch.setattr(continuation, "_save", crash_after_save)
    with pytest.raises(ProcessCrash):
        tick_loop(worker, evidence.snapshot())
    assert crashed
    with restart(environment, model, research) as resumed:
        job = tick_loop(resumed, evidence.snapshot())
        assert job and job["phase"] == "QUEUED"
        assert resumed.continuation.authorize(job)
        assert job["continuationContext"]["research"] == list(
            research.receipts.values()
        )
        assert tick_loop(resumed, evidence.snapshot()) is None
        assert len(resumed.jobs()) == 1
        assert len(rows(resumed, "continuation_cycles")) == 1
    assert [call["stage"] for call in model.calls] == [
        "continuation_plan",
        "continuation_decide",
        "continuation_novelty",
    ]
    decided = model.calls[1]
    assert decided["research"] == list(research.receipts.values())
    assert "source:fixture-reference" in decided["evidenceIds"]
    assert len(research.calls) == 1 and not driver.calls and not services.calls


def test_crash_after_atomic_enqueue_does_not_emit_second_job(environment, monkeypatch):
    worker, _, evidence, _, _, _, _ = environment
    model = StagedModel(*new_steps())
    continuation, research = attach(environment, model)
    original = continuation._gate

    def crash_after_commit():
        original()
        if worker.jobs():
            raise ProcessCrash()

    monkeypatch.setattr(continuation, "_gate", crash_after_commit)
    with pytest.raises(ProcessCrash):
        tick_loop(worker, evidence.snapshot())
    saved = worker.jobs()[0]
    with restart(environment, model, research) as resumed:
        assert tick_loop(resumed, evidence.snapshot()) is None
        assert resumed.jobs() == [saved]
        assert resumed.continuation.authorize(saved)
        assert resumed.continuation.status()["childBuildId"] == saved["id"]
    assert len(model.calls) == 2


def test_semantic_duplicate_survives_restart_even_with_new_wording_and_fingerprint(
    environment,
):
    worker, _, evidence, driver, services, _, clock = environment
    model = StagedModel(
        ("continuation_plan", lambda p: decision(p)),
        ("continuation_novelty", lambda p: novelty(p, accepted=False)),
        (
            "continuation_plan",
            lambda p: decision(
                p,
                objective="Rename the same integer doubling utility",
                done_when="Equivalent signed integer multiplication results",
            ),
        ),
        ("continuation_novelty", lambda p: novelty(p)),
    )
    continuation, research = attach(environment, model)
    snapshot = evidence.snapshot()
    assert tick_loop(worker, snapshot) is None
    assert continuation.status()["blocker"] == "CONTINUATION_NOVELTY_REJECTED"
    changed = deepcopy(snapshot)
    changed["candidates"][0]["idea"]["title"] = "Rephrased canonical fixture evidence"
    clock[0] += 1
    with restart(environment, model, research) as resumed:
        assert tick_loop(resumed, changed) is None
        status = resumed.continuation.status()
        assert status["state"] == "REJECTED"
        assert status["blocker"] == "CONTINUATION_SEMANTIC_DUPLICATE"
        identities = [
            json.loads(row[-1]) for row in rows(resumed, "continuation_objectives")
        ]
        assert len({item["fingerprint"] for item in identities}) == 2
        assert len({item["objectiveKey"] for item in identities}) == 1
        assert all(item["accepted"] is False for item in identities)
        assert model.calls[-1]["comparisonIds"]
        before = frozen_state(resumed)
        assert tick_loop(resumed, changed) is None
        assert frozen_state(resumed) == before
    assert (
        not worker.jobs()
        and not driver.calls
        and not services.calls
        and not research.calls
    )
    assert not model.steps


def test_structural_duplicate_ignores_case_whitespace_and_wrapper_changes(environment):
    worker, _, evidence, _, _, _, clock = environment
    model = StagedModel(
        ("continuation_plan", lambda p: decision(p)),
        ("continuation_novelty", lambda p: novelty(p, accepted=False)),
        (
            "continuation_plan",
            lambda p: decision(
                p,
                objective="  BUILD A PRIVATE FIXTURE INTEGER DOUBLER  ",
                done_when="Explicit  positive and NEGATIVE integers produce their doubles",
            ),
        ),
    )
    continuation, _ = attach(environment, model)
    snapshot = evidence.snapshot()
    tick_loop(worker, snapshot)
    snapshot["candidates"][0]["idea"]["title"] = "Changed title, same objective"
    clock[0] += 1
    assert tick_loop(worker, snapshot) is None
    assert continuation.status()["blocker"] == "CONTINUATION_STRUCTURAL_DUPLICATE"
    assert continuation.status()["state"] == "BLOCKED"
    assert len(model.calls) == 3 and not worker.jobs()
    first = decision(model.calls[0])
    second = decision(
        model.calls[-1],
        objective="  BUILD A PRIVATE FIXTURE INTEGER DOUBLER  ",
        done_when="Explicit  positive and NEGATIVE integers produce their doubles",
    )
    assert objective_fingerprint(first) == objective_fingerprint(second)


@pytest.mark.parametrize("cap", ["provider", "jobs", "tool"])
def test_existing_rolling_caps_resume_saved_stage_without_replanning(environment, cap):
    worker, _, evidence, driver, services, _, clock = environment
    path = worker.home / "config/cct-owner-delivery.json"
    config = json.loads(path.read_text())
    if cap == "jobs":
        assert worker.tick()["phase"] == "COMPLETE"
        config["maxDailyJobs"] = 1
    elif cap == "provider":
        config["maxDailyModelCalls"] = 1
    else:
        for _ in range(worker.builds.effective()["maxDailyToolCalls"]):
            worker.builds.charge("tool", "fixture-reserved-sandbox-slot")
    path.write_text(json.dumps(config))
    model = StagedModel(*new_steps())
    continuation, research = attach(environment, model)
    snapshot = evidence.snapshot()
    if cap == "jobs":
        snapshot["candidates"] = snapshot["candidates"][1:]
    previous_jobs = len(worker.jobs())
    previous_driver_calls = len(driver.calls)
    previous_notifications = len(services.calls)
    assert tick_loop(worker, snapshot) is None
    status = continuation.status()
    assert status["state"] == "DAILY_CAP"
    assert (
        status["blocker"]
        == {
            "provider": "DELIVERY_MODEL_DAILY_CAP",
            "jobs": "DELIVERY_JOB_DAILY_CAP",
            "tool": "DELIVERY_TOOL_DAILY_CAP",
        }[cap]
    )
    assert status["nextEligibleAt"]
    calls_before = len(model.calls)
    with restart(environment, model, research) as resumed:
        for _ in range(3):
            assert tick_loop(resumed, snapshot) is None
        assert len(model.calls) == calls_before
        assert len(resumed.jobs()) == previous_jobs
        clock[0] += 86401
        queued = tick_loop(resumed, snapshot)
        assert queued and queued["phase"] == "QUEUED"
        assert resumed.continuation.status()["cycleId"] == status["cycleId"]
        assert len(resumed.jobs()) == previous_jobs + 1
        assert tick_loop(resumed, snapshot) is None
    assert [call["stage"] for call in model.calls] == [
        "continuation_plan",
        "continuation_novelty",
    ]
    assert (
        len(driver.calls) == previous_driver_calls
        and len(services.calls) == previous_notifications
    )
    assert not research.calls


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("disable", "CONTINUATION_DISABLED"),
        ("remove", "CONTINUATION_CONFIG_MISSING"),
        ("authorization", "CONTINUATION_BINDING_CHANGED"),
        ("ownerUid", "CONTINUATION_CONFIG_IDENTITY"),
        ("projectId", "CONTINUATION_CONFIG_IDENTITY"),
    ],
)
def test_revoked_authority_blocks_queued_job_before_model_sandbox_or_notification(
    environment, mutation, code
):
    worker, _, evidence, driver, services, _, _ = environment
    model = StagedModel(*new_steps())
    continuation, research = attach(environment, model)
    job = tick_loop(worker, evidence.snapshot())
    path = worker.home / "config/cct-owner-continuation.json"
    config = json.loads(path.read_text())
    if mutation == "remove":
        path.unlink()
    else:
        config["enabled" if mutation == "disable" else mutation] = (
            False
            if mutation == "disable"
            else "operator://changed"
            if mutation == "authorization"
            else "foreign"
        )
        path.write_text(json.dumps(config))
    with pytest.raises((ValueError, RuntimeError), match=code):
        continuation.authorize(job)
    before = len(model.calls)
    result = worker.execute(job)
    assert result["reason"] == code
    assert len(model.calls) == before
    assert not driver.calls and not services.calls and not research.calls


@pytest.mark.parametrize("gate_number", [1, 2])
@pytest.mark.parametrize(
    "stage", ["continuation_plan", "continuation_decide", "continuation_novelty"]
)
@pytest.mark.parametrize(
    "mutation,code",
    [
        ("disable", "CONTINUATION_DISABLED"),
        ("remove", "CONTINUATION_CONFIG_MISSING"),
        ("authorization", "CONTINUATION_BINDING_CHANGED"),
        ("ownerUid", "CONTINUATION_CONFIG_IDENTITY"),
        ("projectId", "CONTINUATION_CONFIG_IDENTITY"),
    ],
)
def test_revocation_during_final_provider_gate_prevents_charge_and_dispatch(
    environment, monkeypatch, stage, mutation, code, gate_number
):
    worker, gateway, evidence, driver, services, _, _ = environment
    steps = [
        ("continuation_plan", lambda p: decision(p, "RESEARCH")),
        ("continuation_decide", lambda p: decision(p)),
        ("continuation_novelty", lambda p: novelty(p)),
    ]
    model = StagedModel(*steps)
    continuation, research = attach(environment, model)
    original_model, original_read = worker.model, gateway.read
    dispatching = []
    revoked = []
    reads = []

    def model_boundary(current_stage, payload, job_id):
        dispatching.append(current_stage)
        try:
            return original_model(current_stage, payload, job_id)
        finally:
            dispatching.pop()

    def revoke_during_read(collection, *args):
        result = original_read(collection, *args)
        if collection == "cct_workspace" and dispatching == [stage]:
            reads.append(True)
        if len(reads) == gate_number and not revoked:
            revoked.append(True)
            path = worker.home / "config/cct-owner-continuation.json"
            if mutation == "remove":
                path.unlink()
            else:
                changes = (
                    {"enabled": False}
                    if mutation == "disable"
                    else {
                        mutation: "operator://changed"
                        if mutation == "authorization"
                        else "foreign"
                    }
                )
                continuation_config(worker, **changes)
        return result

    monkeypatch.setattr(worker, "model", model_boundary)
    monkeypatch.setattr(gateway, "read", revoke_during_read)
    assert tick_loop(worker, evidence.snapshot()) is None
    assert revoked and continuation.status()["blocker"] == code
    stages = [name for name, _ in steps]
    expected = stages[: stages.index(stage)]
    assert [call["stage"] for call in model.calls] == expected
    assert [
        row[0] for row in worker.db.execute("SELECT stage FROM attempts ORDER BY id")
    ] == expected
    assert len(research.calls) == (0 if stage == "continuation_plan" else 1)
    assert not worker.jobs() and not driver.calls and not services.calls


def test_revocation_after_model_return_retains_checkpoint_and_resumes_after_reenable(
    environment,
):
    worker, _, evidence, driver, services, _, clock = environment

    def pause_after_plan(payload):
        result = decision(payload)
        continuation_config(worker, enabled=False)
        return result

    model = StagedModel(
        ("continuation_plan", pause_after_plan),
        ("continuation_novelty", lambda p: novelty(p)),
    )
    continuation, research = attach(environment, model)
    assert tick_loop(worker, evidence.snapshot()) is None
    saved = json.loads(rows(worker, "continuation_cycles")[0][-1])
    assert saved["plan"]["action"] == "NEW"
    assert saved["blocker"] == "CONTINUATION_DISABLED" and saved["state"] == "COOLDOWN"
    assert tick_loop(worker, evidence.snapshot()) is None
    assert len(model.calls) == 1 and not worker.jobs()
    continuation_config(worker)
    clock[0] += COOLDOWN + 1
    with restart(environment, model, research) as resumed:
        assert tick_loop(resumed, evidence.snapshot())["phase"] == "QUEUED"
    assert len(model.calls) == 2 and not driver.calls and not services.calls


@pytest.mark.parametrize(
    "mutation",
    [
        "objective",
        "candidate",
        "novelty",
        "reports",
        "authority",
        "attemptLimit",
        "ownerRequest",
        "requestId",
    ],
)
def test_frozen_job_context_rejects_tampering_without_any_effect(environment, mutation):
    worker, _, evidence, driver, services, _, _ = environment
    model = StagedModel(*new_steps())
    continuation, _ = attach(environment, model)
    original = tick_loop(worker, evidence.snapshot())
    job = deepcopy(original)
    if mutation == "objective":
        job["continuationContext"]["proposal"]["objective"] = "Mutated task"
    elif mutation == "candidate":
        job["continuationContext"]["candidate"]["idea"]["title"] = "Forged source"
    elif mutation == "novelty":
        job["continuationContext"]["novelty"]["improvement"] = "Invented result"
    elif mutation == "reports":
        job["reports"] = [{"id": "foreign", "text": "Unbound evidence"}]
    elif mutation == "authority":
        job["authority"] = "operator://forged"
    elif mutation == "attemptLimit":
        job["maxArtifactAttempts"] = 999
    else:
        job[mutation] = (
            {"instructions": "Forged owner instruction"}
            if mutation == "ownerRequest"
            else "forged-request"
        )
    with pytest.raises(ValueError, match="CONTINUATION_(JOB_MUTATED|FORGED_REQUEST)"):
        continuation.authorize(job)
    assert worker.jobs() == [original]
    assert len(model.calls) == 2 and not driver.calls and not services.calls


def test_observe_uses_durable_outcome_not_caller_claim_and_rejects_later_mutation(
    environment,
):
    worker, _, evidence, _, _, _, _ = environment
    model = StagedModel(*cycle_steps()[:5])
    continuation, _ = attach(environment, model)
    queued = tick_loop(worker, evidence.snapshot())
    assert (
        continuation.observe({**queued, "phase": "COMPLETE", "bundle": bundle()})
        is None
    )
    with pytest.raises(ValueError, match="CONTINUATION_OUTCOME_MISSING"):
        continuation.observe({"id": "not-a-durable-job", "phase": "COMPLETE"})
    assert worker.tick()["phase"] == "COMPLETE"
    saved = worker.jobs()[0]
    outcome = continuation.observe(saved)
    before = rows(worker, "continuation_outcomes")
    assert (
        continuation.observe({"id": saved["id"], "phase": "BLOCKED", "bundle": {}})
        == outcome
    )
    assert rows(worker, "continuation_outcomes") == before
    saved["bundle"]["summary"] = "Tampered durable source"
    worker.save(saved)
    with pytest.raises(ValueError, match="CONTINUATION_OUTCOME_MUTATED"):
        continuation.observe(saved)
    assert rows(worker, "continuation_outcomes") == before


@pytest.mark.parametrize(
    "field", ["acceptance", "review", "execution", "verification", "acceptanceDigest"]
)
def test_completion_without_bound_host_evidence_cannot_become_a_parent(
    environment, field
):
    worker, _, evidence, driver, _, _, _ = environment
    model = StagedModel(*new_steps())
    continuation, _ = attach(environment, model)
    job = tick_loop(worker, evidence.snapshot())
    plan = acceptance()
    execution = driver.run("fixture-receipt-only", bundle(), acceptance=plan)
    job.update(
        phase="COMPLETE",
        bundle=bundle(),
        acceptance=plan,
        execution=execution,
        verification=deepcopy(execution["verification"]),
        review={"accepted": True, "issues": []},
    )
    if field == "acceptanceDigest":
        job["verification"][field] = "0" * 64
    else:
        job.pop(field)
    worker.save(job)
    with pytest.raises(ValueError, match="CONTINUATION_OUTCOME_EVIDENCE"):
        continuation.observe(job)
    assert not rows(worker, "continuation_outcomes")


def test_research_crash_after_started_marker_is_not_permission_to_repeat_get(
    environment,
):
    worker, _, evidence, driver, services, _, clock = environment
    model = StagedModel(("continuation_plan", lambda p: decision(p, "RESEARCH")))
    continuation, research = attach(environment, model)
    research.failure = ProcessCrash()
    with pytest.raises(ProcessCrash):
        tick_loop(worker, evidence.snapshot())
    research.failure = None
    with restart(environment, model, research) as resumed:
        assert tick_loop(resumed, evidence.snapshot()) is None
        assert resumed.continuation.status()["state"] == "BLOCKED"
        assert (
            resumed.continuation.status()["blocker"]
            == "CONTINUATION_RESEARCH_INTERRUPTED"
        )
        clock[0] += 86401
        assert tick_loop(resumed, evidence.snapshot()) is None
    assert len(research.calls) == 1 and len(model.calls) == 1
    assert not worker.jobs() and not driver.calls and not services.calls


@pytest.mark.parametrize(
    "cloud_status,delay", [("QUOTA_BACKOFF", 300), ("TRANSIENT_BACKOFF", 30)]
)
def test_cloud_cooldown_resumes_saved_plan_at_circuit_deadline(
    environment, cloud_status, delay
):
    from cct_agent.cloud_backoff import CloudCircuit, CloudErrorPolicy

    worker, gateway, evidence, driver, services, _, clock = environment
    model = StagedModel(*cycle_steps()[:5])
    continuation, research = attach(environment, model)
    budgets = deepcopy(worker.builds.effective())

    class OfflineCloudFailure(Exception):
        pass

    errors = CloudErrorPolicy(
        (OfflineCloudFailure,) if cloud_status == "QUOTA_BACKOFF" else (),
        (OfflineCloudFailure,) if cloud_status == "TRANSIENT_BACKOFF" else (),
        (),
    )
    circuit_path = worker.home / "cloud-fixture" / "backoff.json"
    gateway.circuit = CloudCircuit(circuit_path, errors, clock=lambda: clock[0])
    read = gateway.read
    failed = []
    operations = []

    def guarded_read(collection, document="current"):
        def operation():
            operations.append((collection, document))
            # Real circuit, offline gateway: fail after the returned plan is saved.
            if collection == "cct_workspace" and model.calls and not failed:
                failed.append(clock[0])
                raise OfflineCloudFailure("offline cloud fixture")
            return read(collection, document)

        return gateway.circuit.call(operation)

    gateway.read = guarded_read
    result = worker.tick()
    deadline = clock[0] + delay
    assert result["reason"] == "FIRESTORE_" + cloud_status
    assert result["projection"] == "UNAVAILABLE"
    assert not gateway.projections
    saved = continuation._latest()
    assert saved is not None
    assert saved["state"] == "COOLDOWN"
    assert saved["plan"]["action"] == "NEW"
    assert saved["retryAt"] == deadline
    assert continuation.status()["nextEligibleAt"] == result["retryAt"]
    assert continuation.status()["blocker"] == result["reason"]
    assert len(model.calls) == 1 and not worker.jobs()
    attempts = rows(worker, "attempts")
    before_operations = list(operations)

    # New circuit and worker prove that both checkpoints survive restart.
    gateway.circuit = CloudCircuit(circuit_path, errors, clock=lambda: clock[0])
    with restart(environment, model, research) as resumed:
        clock[0] = deadline - 1
        assert resumed.tick()["retrySeconds"] == 1
        assert rows(resumed, "attempts") == attempts
        assert operations == before_operations
        assert resumed.continuation.status()["nextEligibleAt"] == result["retryAt"]
        clock[0] = deadline
        recovered = resumed.tick()
        assert recovered["phase"] == "COMPLETE", recovered
        assert recovered["continuation"]["nextEligibleAt"] is None
        assert recovered["continuation"]["blocker"] is None
        assert resumed.builds.effective() == budgets
        assert resumed.chain_valid()
        assert len(rows(resumed, "attempts")) == 5
    assert [p["stage"] for p in model.calls] == [
        "continuation_plan",
        "continuation_novelty",
        "build",
        "acceptance",
        "review",
    ]
    assert len(driver.calls) == 1 and len(services.calls) == 1 and not research.calls


def test_cloud_backoff_after_enqueue_preserves_atomic_job_link(environment):
    from cct_agent.cloud_backoff import CloudCircuit, CloudErrorPolicy

    worker, gateway, evidence, driver, services, _, clock = environment
    model = StagedModel(*cycle_steps()[:5])
    continuation, research = attach(environment, model)

    class OfflineQuota(Exception):
        pass

    gateway.circuit = CloudCircuit(
        worker.home / "cloud-fixture" / "backoff.json",
        CloudErrorPolicy((OfflineQuota,), (), ()),
        clock=lambda: clock[0],
    )
    read = gateway.read
    failed = []

    def guarded_read(collection, document="current"):
        def operation():
            if collection == "cct_workspace" and worker.jobs() and not failed:
                failed.append(True)
                raise OfflineQuota()
            return read(collection, document)

        return gateway.circuit.call(operation)

    gateway.read = guarded_read
    assert worker.tick()["reason"] == "FIRESTORE_QUOTA_BACKOFF"
    saved = continuation._latest()
    assert saved is not None
    assert saved["state"] == "QUEUED"
    assert saved["childBuildId"] == worker.jobs()[0]["id"]
    assert saved["nextEligibleAt"] is None
    assert len(model.calls) == 2 and not driver.calls
    with restart(environment, model, research) as resumed:
        assert resumed.tick()["reason"] == "FIRESTORE_QUOTA_BACKOFF"
        assert len(resumed.jobs()) == 1
        clock[0] += 300
        assert resumed.tick()["phase"] == "COMPLETE"
        assert len(resumed.jobs()) == 1
        assert resumed.continuation.status()["state"] == "LEARNED"
        assert resumed.chain_valid()
    assert len(model.calls) == 5 and len(driver.calls) == 1 and len(services.calls) == 1


def test_cloud_backoff_before_cycle_propagates_without_generic_error(environment):
    from cct_agent.cloud_backoff import CloudBackoff

    worker, gateway, evidence, driver, services, _, clock = environment
    model = StagedModel(*new_steps())
    continuation, _ = attach(environment, model)
    error = CloudBackoff(
        {
            "cloudStatus": "QUOTA_BACKOFF",
            "retrySeconds": 300,
            "retryAt": datetime.fromtimestamp(clock[0] + 300, timezone.utc).isoformat(),
        }
    )

    def unavailable(*args, **kwargs):
        raise error

    gateway.read = unavailable
    with pytest.raises(CloudBackoff) as raised:
        tick_loop(worker, evidence.snapshot())
    assert raised.value is error
    assert continuation._latest() is None
    assert worker.meta("continuationError") is None
    assert not model.calls and not driver.calls and not services.calls


def test_failed_plan_is_cooled_down_and_lifetime_bounded_across_days(environment):
    worker, _, evidence, driver, services, _, clock = environment

    def fail(_):
        raise TimeoutError("offline fixture provider unavailable")

    model = StagedModel(("continuation_plan", fail), ("continuation_plan", fail))
    continuation, research = attach(environment, model)
    assert tick_loop(worker, evidence.snapshot()) is None
    assert continuation.status()["state"] == "COOLDOWN"
    for _ in range(3):
        assert tick_loop(worker, evidence.snapshot()) is None
    assert len(model.calls) == 1
    clock[0] += 86401
    with restart(environment, model, research) as resumed:
        assert tick_loop(resumed, evidence.snapshot()) is None
        clock[0] += 86401
        assert tick_loop(resumed, evidence.snapshot()) is None
        assert resumed.continuation.status()["state"] == "BLOCKED"
        assert resumed.continuation.status()["blocker"] == "CONTINUATION_LIFETIME_LIMIT"
        assert len(rows(resumed, "attempts")) == 2
    assert (
        len(model.calls) == 2
        and not worker.jobs()
        and not driver.calls
        and not services.calls
    )


def test_one_automatic_child_per_root_rejects_stale_parent_even_with_new_objective(
    environment,
):
    worker, _, evidence, driver, services, _, clock = environment
    model = StagedModel(*cycle_steps())
    continuation, research = attach(environment, model)
    assert worker.tick()["phase"] == "COMPLETE"
    root = continuation.observe(worker.jobs()[0])
    assert root is not None
    clock[0] += 1
    assert worker.tick()["phase"] == "COMPLETE"
    children = [job for job in worker.jobs() if job.get("parentBuildId")]
    assert len(children) == 1 and children[0]["rootBuildId"] == root["rootBuildId"]

    def stale_upgrade(payload):
        assert payload["parents"] == []
        return decision(
            {**payload, "parents": [root]},
            "UPGRADE",
            objective="Attempt a second automatic child with a different name",
            done_when="Another unsupported behavior change",
        )

    model.steps.append(("continuation_plan", stale_upgrade))
    clock[0] += 1
    with restart(environment, model, research) as resumed:
        assert tick_loop(resumed, evidence.snapshot()) is None
        assert (
            resumed.continuation.status()["blocker"] == "CONTINUATION_DECISION_ANCHOR"
        )
        assert tick_loop(resumed, evidence.snapshot()) is None
        assert len(resumed.jobs()) == 2
    assert len(driver.calls) == 2 and len(set(services.calls)) == 2
    assert len(model.calls) == 11


@pytest.mark.parametrize(
    "change",
    [
        {"enabled": "true"},
        {"enabled": 1},
        {"schemaVersion": "other"},
        {"authorization": "https://example.invalid/not-authority"},
        {"authorization": "operator://contains space"},
        {"extra": "producer authority"},
    ],
)
def test_host_continuation_config_is_closed_and_strict(environment, change):
    worker = environment[0]
    continuation_config(worker, **change)
    research = DeterministicResearch(environment[-1])
    with pytest.raises(ValueError, match="CONTINUATION_CONFIG_INVALID"):
        Continuation(worker, research=research)
    assert not research.calls and not worker.meta("continuationBinding")


def test_missing_initial_config_is_disabled_without_provider_or_research(environment):
    worker, _, evidence, driver, services, model, clock = environment
    research = DeterministicResearch(clock)
    continuation = Continuation(worker, research=research)
    assert continuation.enabled is False
    assert continuation.tick(evidence.snapshot()) is None
    assert continuation.status()["state"] == "DISABLED"
    assert not worker.meta("continuationBinding")
    assert (
        not model.calls
        and not research.calls
        and not driver.calls
        and not services.calls
    )
