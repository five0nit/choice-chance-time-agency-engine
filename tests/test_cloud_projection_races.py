"""Deterministic cache/backoff interleavings; no real cloud or credentials."""
from copy import deepcopy
import subprocess
import sys
from types import SimpleNamespace

import pytest

from cct_agent.cloud_backoff import CloudBackoff, CloudCircuit, CloudErrorPolicy
from cct_agent.cloud_projection import ProjectionCache, publish_projection


class Failure(Exception):
    pass


def _pair(tmp_path, monkeypatch, status="quota"):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o700)
    monkeypatch.setenv("CCT_CLOUD_RECOVERY_DIR", str(shared))
    monkeypatch.setenv("CCT_CLOUD_PROJECTION_HEARTBEAT_SECONDS", "1800")
    now = [1_700_000_000.0]
    policy = CloudErrorPolicy((Failure,) if status == "quota" else (),
                              (Failure,) if status == "transient" else (), ())
    first = CloudCircuit.for_project("demo-cache-race", tmp_path / "profile-a.json",
                                     policy, clock=lambda: now[0])
    sibling = CloudCircuit.for_project("demo-cache-race", tmp_path / "profile-b.json",
                                       policy, clock=lambda: now[0])
    return first, sibling, now


def _fail(circuit):
    def rpc():
        raise Failure("synthetic transport only")
    with pytest.raises(CloudBackoff):
        circuit.call(rpc)


def _lock_available_in_child(circuit):
    """Check the exact process lock at a deterministic boundary, without sleeps."""
    script = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_NOFOLLOW)
try:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print('LOCKED')
    else:
        print('AVAILABLE')
finally:
    os.close(fd)
"""
    result = subprocess.run([sys.executable, "-c", script, str(circuit.path) + ".lock"],
                            capture_output=True, text=True, timeout=10, check=True)
    assert result.stdout.strip() in {"LOCKED", "AVAILABLE"}
    return result.stdout.strip() == "AVAILABLE"


@pytest.mark.parametrize("status,delay", [("quota", 300), ("transient", 30)])
@pytest.mark.parametrize("expired", [False, True])
def test_sibling_failure_at_cache_entry_never_returns_old_success(
        tmp_path, monkeypatch, status, delay, expired):
    circuit, sibling, now = _pair(tmp_path, monkeypatch, status)
    writes = []
    cache = ProjectionCache(clock=lambda: 0.0)

    def publish(collection, name, value):
        circuit.call(lambda: writes.append(deepcopy(value)))
        return deepcopy(value)

    gateway = SimpleNamespace(circuit=circuit, _projection_cache=cache, publish=publish)
    first = {"updatedAt": "original", "phase": "WAIT"}
    assert publish_projection(gateway, "cct_owner_work", "current", first) == first
    original = cache.publish

    def fail_before_lookup(*args, **kwargs):
        # Ancestor code checked the circuit before entering cache.publish.
        _fail(sibling)
        if expired:
            now[0] += delay
        return original(*args, **kwargs)

    monkeypatch.setattr(cache, "publish", fail_before_lookup)
    next_value = {**first, "updatedAt": "fresh-write-required"}
    if expired:
        assert publish_projection(gateway, "cct_owner_work", "current", next_value) == next_value
        assert writes == [first, next_value]
        # Successful publication alone does not clear a worker-cycle failure.
        assert circuit.status()["retrySeconds"] == 0
    else:
        with pytest.raises(CloudBackoff):
            publish_projection(gateway, "cct_owner_work", "current", next_value)
        assert writes == [first]
        assert circuit.status()["retrySeconds"] == delay


@pytest.mark.parametrize("boundary", ["lookup", "copy"])
def test_cache_decision_holds_process_lock_but_gateway_rpc_does_not(
        tmp_path, monkeypatch, boundary):
    import cct_agent.cloud_projection as projection

    circuit, sibling, _ = _pair(tmp_path, monkeypatch)
    cache, writes, observations = ProjectionCache(clock=lambda: 0.0), [], []

    def publish(collection, name, value):
        assert _lock_available_in_child(circuit), "cache guard leaked into gateway RPC"
        circuit.call(lambda: writes.append(deepcopy(value)))
        return deepcopy(value)

    gateway = SimpleNamespace(circuit=circuit, _projection_cache=cache, publish=publish)
    value = {"updatedAt": "verified", "phase": "WAIT"}
    assert publish_projection(gateway, "cct_owner_work", "current", value) == value
    saved_receipt = cache.entries[("cct_owner_work", "current")][2]

    def assert_locked():
        available = _lock_available_in_child(sibling)
        observations.append(available)
        assert not available, "sibling can persist failure inside cache decision"

    if boundary == "lookup":
        class Entries(dict):
            def get(self, key, default=None):
                assert_locked()
                return super().get(key, default)
        cache.entries = Entries(cache.entries)
    else:
        def checked_copy(obj):
            if obj is saved_receipt:
                assert_locked()
            return deepcopy(obj)
        monkeypatch.setattr(projection, "deepcopy", checked_copy)

    assert publish_projection(gateway, "cct_owner_work", "current", value) == value
    assert observations == [False]
    assert writes == [value]
    assert _lock_available_in_child(circuit)
    _fail(sibling)
    with pytest.raises(CloudBackoff):
        publish_projection(gateway, "cct_owner_work", "current", value)
    assert writes == [value]


def test_local_cache_exception_releases_lock_without_classifying_cloud_failure(tmp_path, monkeypatch):
    circuit, _, _ = _pair(tmp_path, monkeypatch)
    cache = ProjectionCache()

    class Entries(dict):
        def get(self, key, default=None):
            raise Failure("local cache failure, not RPC quota")

    cache.entries = Entries()
    with pytest.raises(Failure):
        cache.publish("cct_owner_work", "current", {"phase": "WAIT"},
                      lambda: pytest.fail("unexpected RPC"), circuit=circuit)
    assert _lock_available_in_child(circuit)
    assert circuit.status() == {}
