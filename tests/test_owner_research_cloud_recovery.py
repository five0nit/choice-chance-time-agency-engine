"""Offline DNS/socket fixtures with real research mediation, SQLite and cloud circuit."""

from copy import deepcopy
from datetime import datetime

import pytest

from cct_agent.cloud_backoff import CloudBackoff, CloudCircuit, CloudErrorPolicy
from cct_agent.owner_continuation import Continuation
from cct_agent.owner_delivery_research import DeliveryResearch, ResearchDeferred
from tests.test_owner_delivery import environment as environment, acceptance, bundle
from tests.test_owner_continuation import (
    StagedModel,
    attach,
    continuation_config,
    restart,
    rows,
    tick_loop,
)
from tests.test_owner_continuation_model import decision, novelty
from tests.test_owner_delivery_research import (
    network as network,
    prohibit_real_network as prohibit_real_network,
    worker as worker,
)


@pytest.mark.parametrize(
    "cloud_status,delay", [("QUOTA_BACKOFF", 300), ("TRANSIENT_BACKOFF", 30)]
)
@pytest.mark.parametrize(
    "boundary", ["unclaimed", "charged", "after_get", "before_commit"]
)
def test_research_cloud_gate_defers_only_unclaimed_attempts(
    environment, network, monkeypatch, cloud_status, delay, boundary
):
    worker, gateway, evidence, driver, services, _, clock = environment
    continuation_config(worker)
    research = DeliveryResearch(worker)
    worker.continuation = Continuation(worker, research=research)
    model = StagedModel(
        ("continuation_plan", lambda p: decision(p, "RESEARCH")),
        ("continuation_decide", lambda p: decision(p)),
        ("continuation_novelty", lambda p: novelty(p)),
        ("build", bundle()),
        ("acceptance", acceptance()),
        ("review", {"accepted": True, "issues": []}),
    )
    worker.model_override = model
    budgets = deepcopy(worker.builds.effective())

    class OfflineCloudFailure(Exception):
        pass

    errors = CloudErrorPolicy(
        (OfflineCloudFailure,) if cloud_status == "QUOTA_BACKOFF" else (),
        (OfflineCloudFailure,) if cloud_status == "TRANSIENT_BACKOFF" else (),
        (),
    )
    circuit_path = worker.home / "cloud-fixture/backoff.json"
    gateway.circuit = CloudCircuit(circuit_path, errors, clock=lambda: clock[0])
    read = gateway.read
    armed, operations = [], []

    def guarded_read(collection, document="current"):
        def operation():
            operations.append((collection, document))
            if armed and armed.pop():
                raise OfflineCloudFailure("offline research authority fixture")
            return read(collection, document)

        return gateway.circuit.call(operation)

    gateway.read = guarded_read
    publish = gateway.publish
    gateway.publish = lambda collection, document, value: gateway.circuit.call(
        lambda: publish(collection, document, value)
    )
    gate = research._gate
    gates = []
    fail_at = {"unclaimed": 1, "charged": 2, "after_get": 3, "before_commit": 4}[
        boundary
    ]

    def guarded_gate(expected=None):
        gates.append(expected)
        if len(gates) == fail_at:
            armed.append(True)
        return gate(expected)

    monkeypatch.setattr(research, "_gate", guarded_gate)
    result = worker.tick()
    saved = worker.continuation._latest()
    assert len(gates) == fail_at, (result, saved)
    assert saved is not None and saved["plan"]["action"] == "RESEARCH"
    assert result["cloudStatus"] == cloud_status
    assert result["projection"] == "UNAVAILABLE"
    deadline = clock[0] + delay
    assert datetime.fromisoformat(result["retryAt"]).timestamp() == deadline
    source = saved["plan"]["sourceIds"][0]
    calls_before = len(network.calls)
    assert calls_before == (0 if boundary in {"unclaimed", "charged"} else 1)
    assert len(model.calls) == 1 and not driver.calls and not services.calls
    if boundary == "unclaimed":
        assert saved["state"] == "COOLDOWN"
        assert result["reason"] == "FIRESTORE_" + cloud_status
        assert saved["retryAt"] == deadline
        assert saved["nextEligibleAt"] == result["retryAt"]
        assert source not in saved["researchStarted"]
        assert research.usage() == {"attempted": 0, "verified": 0, "maxPer24h": 2}
    else:
        assert saved["state"] == "BLOCKED"
        assert research.usage() == {"attempted": 1, "verified": 0, "maxPer24h": 2}
    before_operations = list(operations)
    before_attempts = rows(worker, "attempts")
    gateway.circuit = CloudCircuit(circuit_path, errors, clock=lambda: clock[0])
    with restart(environment, model, research) as resumed:
        # Recreate the actual adapter on the reopened worker DB, not a stale connection.
        resumed_research = DeliveryResearch(resumed)
        resumed.continuation = Continuation(resumed, research=resumed_research)
        clock[0] = deadline - 1
        assert resumed.tick()["retrySeconds"] == 1
        assert operations == before_operations
        assert rows(resumed, "attempts") == before_attempts
        assert len(network.calls) == calls_before
        assert resumed.continuation._latest() == saved
        clock[0] = deadline
        recovered = resumed.tick()
        assert isinstance(recovered["continuation"], dict)
        if boundary == "unclaimed":
            assert recovered["phase"] == "COMPLETE", recovered
            assert recovered["continuation"]["nextEligibleAt"] is None
            assert recovered["continuation"]["blocker"] is None
            assert resumed_research.usage() == {
                "attempted": 1,
                "verified": 1,
                "maxPer24h": 2,
            }
            assert len(network.calls) == 1
            assert len(driver.calls) == len(services.calls) == 1
            assert [p["stage"] for p in model.calls] == [
                "continuation_plan",
                "continuation_decide",
                "continuation_novelty",
                "build",
                "acceptance",
                "review",
            ]
            assert resumed_research._store is not None
            assert resumed_research._store.verify_chain()["valid"] is True
            assert len(resumed_research._store.events("execution.ticket.consumed")) == 1
            assert (
                resumed.jobs()[0]["continuationContext"]["research"][0]["provenance"]
                == "external_untrusted"
            )
        else:
            assert recovered["continuation"]["state"] == "BLOCKED"
            assert not resumed.jobs() and len(model.calls) == 1
            assert (
                resumed_research.fetch(saved["id"], source)["error"]
                == "DELIVERY_RESEARCH_GATE_UNAVAILABLE"
            )
            clock[0] += 86401
            assert (
                resumed_research.fetch(saved["id"], source)["error"]
                == "DELIVERY_RESEARCH_GATE_UNAVAILABLE"
            )
            assert len(network.calls) == calls_before
        assert resumed.builds.effective() == budgets
        assert resumed.chain_valid()


@pytest.mark.parametrize("cached", [False, True])
def test_deferred_cloud_gate_preserves_adapter_attempts_and_cached_evidence(
    worker, network, cached
):
    adapter = DeliveryResearch(worker)
    source = adapter.catalog()[0]["id"]
    original = adapter.fetch("deferred-fixture", source) if cached else None
    before = [
        tuple(row)
        for row in worker.db.execute("SELECT * FROM delivery_research_attempts")
    ]
    error = CloudBackoff(
        {
            "cloudStatus": "TRANSIENT_BACKOFF",
            "retrySeconds": 30,
            "retryAt": "2033-05-18T03:33:50+00:00",
        }
    )
    fail_at = worker.gates + (2 if cached else 1)

    def outage():
        if worker.gates == fail_at:
            raise error

    worker.gate_hook = outage
    with pytest.raises(ResearchDeferred) as raised:
        adapter.fetch("deferred-fixture", source)
    assert raised.value.receipt == error.receipt
    assert [
        tuple(row)
        for row in worker.db.execute("SELECT * FROM delivery_research_attempts")
    ] == before
    assert len(network.calls) == int(cached)
    worker.gate_hook = None
    # Current pause remains authoritative even when there is no claimed attempt.
    worker.paused = True
    assert (
        DeliveryResearch(worker).fetch("deferred-fixture", source)["error"]
        == "DELIVERY_RESEARCH_PAUSED"
    )
    assert len(network.calls) == int(cached)
    worker.paused = False
    result = DeliveryResearch(worker).fetch("deferred-fixture", source)
    assert result["ok"] is True
    if cached:
        assert result == original
    assert len(network.calls) == 1
    assert adapter.usage() == {"attempted": 1, "verified": 1, "maxPer24h": 2}


def test_generic_cloud_error_is_not_proof_of_unclaimed_research(environment):
    worker, _, evidence, driver, services, _, clock = environment
    model = StagedModel(("continuation_plan", lambda p: decision(p, "RESEARCH")))
    continuation, research = attach(environment, model)
    research.failure = CloudBackoff(
        {
            "cloudStatus": "TRANSIENT_BACKOFF",
            "retrySeconds": 30,
            "retryAt": datetime.fromtimestamp(clock[0] + 30).astimezone().isoformat(),
        }
    )
    with pytest.raises(CloudBackoff):
        tick_loop(worker, evidence.snapshot())
    saved = continuation._latest()
    assert saved is not None
    assert saved["researchStarted"] == [research.sources[0]["id"]]
    research.failure = None
    with restart(environment, model, research) as resumed:
        clock[0] += 30
        assert tick_loop(resumed, evidence.snapshot()) is None
        assert (
            resumed.continuation.status()["blocker"]
            == "CONTINUATION_RESEARCH_INTERRUPTED"
        )
        assert resumed.continuation.status()["state"] == "BLOCKED"
    assert len(research.calls) == len(model.calls) == 1
    assert not driver.calls and not services.calls and not worker.jobs()
