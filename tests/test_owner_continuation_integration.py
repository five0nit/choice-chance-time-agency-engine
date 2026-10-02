"""Worker-boundary fixture tests; real engine/network/sandbox have separate tests."""

import copy


from tests.test_owner_delivery import environment as environment


class LoopFixture:
    enabled = True

    def __init__(self, worker):
        self.worker = worker
        self.observed = {}
        self.allow = True
        self.fail_observe = False
        self.selections = 0
        self.prepared = None

    def authorize(self, job):
        if not self.allow:
            raise RuntimeError("CONTINUATION_DISABLED")

    def tick(self, snapshot):
        self.selections += 1
        if self.prepared:
            return None
        job = self.worker.select(snapshot)
        if job:
            job["continuationContext"] = {
                "objective": "Fixture boundary continuation",
                "cycleId": "fixture-cycle",
            }
            job["maxArtifactAttempts"] = 2
            self.worker.save(job)
            self.prepared = job["id"]
        return job

    def observe(self, job):
        if self.fail_observe:
            raise RuntimeError("FIXTURE_PROJECTION_FAILURE")
        self.observed[job["id"]] = copy.deepcopy(job)

    def status(self):
        return {
            "schemaVersion": "cct.owner_continuation.v1",
            "enabled": True,
            "state": "WAITING",
            "objective": "Fixture only",
            "whatHappened": "Fixture boundary exercised.",
            "whatImproved": "",
            "nextAction": "Wait for new evidence.",
            "blocker": "",
            "nextEligibleAt": None,
            "cycleId": "fixture-cycle",
            "parentBuildId": "",
            "childBuildId": self.prepared or "",
            "research": {"attempted": 0, "verified": 0, "maxPer24h": 2},
            "updatedAt": "2026-09-15T00:00:00+00:00",
        }


def attach(environment):
    worker, *rest = environment
    loop = LoopFixture(worker)
    worker.continuation = loop
    return (worker, loop, *rest)


def test_tick_routes_new_work_through_continuation_and_records_completed_outcome(
    environment,
):
    worker, loop, gateway, evidence, driver, services, model, clock = attach(
        environment
    )
    result = worker.tick()
    assert result["phase"] == "COMPLETE"
    assert loop.selections == 1
    assert loop.observed[result["job"]["id"]]["phase"] == "COMPLETE"
    assert result["continuation"]["schemaVersion"] == "cct.owner_continuation.v1"
    assert all(
        p.get("continuationContext") for p in model.calls if p["stage"] != "select"
    )
    assert not any("ownerRequest" in p for p in model.calls)
    assert worker.chain_valid()


def test_auto_artifact_failure_gets_exactly_one_repair(environment):
    worker, loop, gateway, evidence, driver, services, model, clock = attach(
        environment
    )
    driver.fail = True
    assert worker.tick()["phase"] == "RETRY"
    clock[0] += 2
    assert worker.tick()["phase"] == "BLOCKED"
    clock[0] += 2
    worker.tick()
    assert len(driver.calls) == 2
    assert len([p for p in model.calls if p["stage"] == "build"]) == 2
    assert len(worker.jobs()) == 1
    assert worker.jobs()[0]["attempts"] == 2
    assert worker.jobs()[0]["phase"] == "BLOCKED"


def test_revoked_continuation_blocks_saved_job_before_provider_or_driver(environment):
    worker, loop, gateway, evidence, driver, services, model, clock = attach(
        environment
    )
    job = loop.tick(evidence.snapshot())
    before = len(model.calls)
    loop.allow = False
    result = worker.execute(job)
    assert result["reason"] == "CONTINUATION_DISABLED"
    assert len(model.calls) == before
    assert not driver.calls and not services.calls


def test_revocation_during_projection_rechecked_before_next_effect(environment):
    worker, loop, gateway, evidence, driver, services, model, clock = attach(
        environment
    )
    publish = gateway.publish

    def revoke(collection, document, value):
        publish(collection, document, value)
        if collection == "cct_owner_delivery" and value["phase"] == "BUILDING":
            loop.allow = False

    gateway.publish = revoke
    result = worker.tick()
    assert result["reason"] == "CONTINUATION_DISABLED"
    assert [p["stage"] for p in model.calls] == ["select"]
    assert not driver.calls and not services.calls


def test_learning_failure_cannot_invalidate_complete_artifact(environment):
    worker, loop, gateway, evidence, driver, services, model, clock = attach(
        environment
    )
    loop.fail_observe = True
    result = worker.tick()
    assert result["phase"] == "COMPLETE"
    assert result["continuation"]["state"] == "UNAVAILABLE"
    assert worker.jobs()[0]["phase"] == "COMPLETE"
    assert len(driver.calls) == 1
    worker.tick()
    assert len(driver.calls) == 1
    assert worker.jobs()[0]["phase"] == "COMPLETE"


def test_pending_job_precedes_new_automatic_selection(environment):
    worker, loop, gateway, evidence, driver, services, model, clock = attach(
        environment
    )
    loop.tick(evidence.snapshot())
    assert loop.selections == 1
    assert worker.tick()["phase"] == "COMPLETE"
    assert loop.selections == 1


def test_workspace_pause_holds_loop_without_calls(environment):
    worker, loop, gateway, evidence, driver, services, model, clock = attach(
        environment
    )
    gateway.workspace["learningEnabled"] = False
    result = worker.tick()
    assert result["phase"] == "PAUSED"
    assert result["continuation"]["state"] == "PAUSED"
    assert loop.selections == 0
    assert not model.calls and not driver.calls and not services.calls


def test_followup_context_preserves_provenance_not_forged_owner_request(environment):
    worker = environment[0]
    job = {
        "parentBuild": {"bundleDigest": "a" * 64},
        "continuationContext": {"cycleId": "test"},
        "untrusted": "ignored",
    }
    assert worker.followup_context(job) == {
        k: job[k] for k in ("parentBuild", "continuationContext")
    }
