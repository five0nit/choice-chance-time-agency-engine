"""Real durable cloud circuit/SQLite; all external services are offline doubles."""

from copy import deepcopy
from datetime import datetime

import pytest

from cct_agent.cloud_backoff import CloudCircuit, CloudErrorPolicy
from cct_agent.owner_delivery import OwnerDelivery
from tests.test_owner_delivery import environment as environment


@pytest.mark.parametrize(
    "cloud_status,delay", [("QUOTA_BACKOFF", 300), ("TRANSIENT_BACKOFF", 30)]
)
@pytest.mark.parametrize(
    "checkpoint", ["bundle", "acceptance", "execution", "review", "complete"]
)
@pytest.mark.parametrize("prior_recoveries", [0, 2])
def test_cloud_failure_preserves_delivery_checkpoint_and_recovery_budget(
    environment, checkpoint, cloud_status, delay, prior_recoveries
):
    worker, gateway, evidence, driver, services, model, clock = environment
    budgets = deepcopy(worker.builds.effective())
    execute = worker.execute

    def execute_with_prior_recoveries(job):
        # Model an already-used recovery allowance; the cloud must not reset or
        # consume it. This is local test state, not a live budget adjustment.
        if prior_recoveries:
            job["recoveryAttempts"] = prior_recoveries
            worker.save(job)
        return execute(job)

    worker.execute = execute_with_prior_recoveries

    class OfflineCloudFailure(Exception):
        pass

    errors = CloudErrorPolicy(
        (OfflineCloudFailure,) if cloud_status == "QUOTA_BACKOFF" else (),
        (OfflineCloudFailure,) if cloud_status == "TRANSIENT_BACKOFF" else (),
        (),
    )
    circuit_path = worker.home / "cloud-fixture" / "backoff.json"
    gateway.circuit = CloudCircuit(circuit_path, errors, clock=lambda: clock[0])
    read, publish = gateway.read, gateway.publish
    operations, failures = [], []

    def reached(job):
        return {
            "bundle": bool(job.get("bundle")) and not job.get("acceptance"),
            "acceptance": bool(job.get("acceptance")) and not job.get("execution"),
            "execution": bool(job.get("execution")) and not job.get("review"),
            "review": job.get("phase") == "NOTIFY",
            "complete": job.get("phase") == "COMPLETE",
        }[checkpoint]

    def operation(kind, collection, document, value=None):
        operations.append((kind, collection, document))
        jobs = worker.jobs()
        boundary = (
            kind == "read"
            and collection == "cct_workspace"
            and checkpoint != "complete"
        ) or (
            kind == "publish"
            and collection == "cct_owner_builds"
            and checkpoint == "complete"
        )
        if boundary and jobs and reached(jobs[0]) and not failures:
            failures.append(deepcopy(jobs[0]))
            raise OfflineCloudFailure("offline cloud fixture")
        if kind == "read":
            return read(collection, document)
        return publish(collection, document, value)

    gateway.read = lambda collection, document="current": gateway.circuit.call(
        lambda: operation("read", collection, document)
    )
    gateway.publish = lambda collection, document, value: gateway.circuit.call(
        lambda: operation("publish", collection, document, value)
    )

    result = worker.tick()
    assert result["reason"] == "FIRESTORE_" + cloud_status
    assert result["projection"] == "UNAVAILABLE"
    deadline = clock[0] + delay
    assert datetime.fromisoformat(result["retryAt"]).timestamp() == deadline
    assert len(failures) == 1
    saved = worker.jobs()[0]
    assert saved == failures[0], (
        "A typed cloud outage must not rewrite the committed job checkpoint"
    )
    assert saved.get("recoveryAttempts", 0) == prior_recoveries
    assert not worker.db.execute(
        "SELECT 1 FROM events WHERE kind='STAGE_FAILED'"
    ).fetchone()
    attempts = [
        tuple(row) for row in worker.db.execute("SELECT * FROM attempts ORDER BY id")
    ]
    before_operations = list(operations)
    before_effects = (len(model.calls), len(driver.calls), len(services.calls))
    before_projections = len(gateway.projections)

    # No follow-on automatic job: isolate projection recovery of the completed job.
    if checkpoint == "complete":
        snapshot = evidence.snapshot()
        evidence.snapshot = lambda: {**snapshot, "candidates": []}
    gateway.circuit = CloudCircuit(circuit_path, errors, clock=lambda: clock[0])
    resumed = OwnerDelivery(
        worker.home,
        gateway=gateway,
        evidence=evidence,
        driver=driver,
        services=services,
        model=model,
        clock=lambda: clock[0],
    )
    try:
        clock[0] = deadline - 1
        assert resumed.tick()["retrySeconds"] == 1
        assert resumed.jobs() == [saved]
        assert operations == before_operations
        assert len(gateway.projections) == before_projections
        assert (
            len(model.calls),
            len(driver.calls),
            len(services.calls),
        ) == before_effects
        assert [
            tuple(row)
            for row in resumed.db.execute("SELECT * FROM attempts ORDER BY id")
        ] == attempts
        clock[0] = deadline
        recovered = resumed.tick()
        assert recovered["phase"] == (
            "WAITING" if checkpoint == "complete" else "COMPLETE"
        )
        assert recovered["projection"] == "VERIFIED"
        complete = resumed.jobs()[0]
        assert complete["phase"] == "COMPLETE" and complete["attempts"] == 1
        assert complete.get("recoveryAttempts", 0) == prior_recoveries
        assert complete.get("retryAt") is None
        assert complete["bundle"] == saved["bundle"]
        assert resumed.builds.effective() == budgets
        assert resumed.chain_valid()
        assert (
            resumed.db.execute(
                "SELECT count(*) FROM events WHERE kind='OUTCOME'"
            ).fetchone()[0]
            == 1
        )
        assert (
            resumed.db.execute("SELECT count(*) FROM tool_attempts").fetchone()[0] == 1
        )
        assert len(resumed.jobs()) == 1
    finally:
        resumed.close()
    assert [call["stage"] for call in model.calls] == [
        "select",
        "build",
        "acceptance",
        "review",
    ]
    assert len(driver.calls) == len(services.calls) == 1
