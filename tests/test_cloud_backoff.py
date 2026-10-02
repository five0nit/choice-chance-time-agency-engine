"""Offline regression tests for durable shared cloud cooldowns."""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from unittest.mock import Mock

import pytest

from cct_agent.cloud_backoff import CloudBackoff, CloudCircuit, CloudErrorPolicy
from cct_agent.owner_connection import tick_services


class QuotaError(Exception):
    pass


class TransientError(Exception):
    pass


class RetryError(Exception):
    pass


@dataclass
class FakeClock:
    now: float = 1_700_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def circuit_parts(tmp_path):
    # CloudCircuit creates this private directory itself (tmp_path mode varies).
    path = tmp_path / "private-cloud" / "backoff.json"
    policy = CloudErrorPolicy(
        quota=(QuotaError,), transient=(TransientError,), retry=(RetryError,)
    )
    return path, policy, FakeClock()


def test_quota_cooldown_survives_restart_and_suppresses_sibling_rpcs(circuit_parts):
    path, policy, clock = circuit_parts
    original = CloudCircuit(path, policy, clock=clock)
    sibling = CloudCircuit(path, policy, clock=clock)
    rpc = Mock(side_effect=QuotaError("private upstream details"))

    with pytest.raises(CloudBackoff) as first:
        original.call(rpc)
    assert first.value.reason_code == "FIRESTORE_QUOTA_BACKOFF"
    assert first.value.receipt["retrySeconds"] == 300
    assert "private upstream details" not in str(first.value)
    deadline = first.value.receipt["retryAt"]
    assert json.loads(path.read_text()) == {
        "status": "QUOTA_BACKOFF", "delay": 300, "until": clock.now + 300,
    }
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700

    del original
    restarted = CloudCircuit(path, policy, clock=clock)
    for elapsed in (0, 1, 298):
        clock.now += elapsed
        for instance in (sibling, restarted):
            for _ in range(3):
                with pytest.raises(CloudBackoff) as blocked:
                    instance.call(rpc)
                assert blocked.value.receipt["retryAt"] == deadline
                assert blocked.value.receipt["retrySeconds"] > 0
            with pytest.raises(CloudBackoff):
                instance.check()
    assert rpc.call_count == 1
    assert restarted.status()["retrySeconds"] == 1

    clock.now += 1
    restarted.check()
    rpc.side_effect = None
    rpc.return_value = "fresh remote result"
    assert sibling.call(rpc) == "fresh remote result"
    assert rpc.call_count == 2


def test_transient_escalates_to_cap_without_successful_read_reset(circuit_parts):
    path, policy, clock = circuit_parts
    failing_rpc = Mock(side_effect=TransientError())
    successful_read = Mock(return_value="fresh read")

    for expected_delay in (30, 60, 120, 240, 300, 300):
        # Each retry uses a new instance: escalation is persisted, not in memory.
        circuit = CloudCircuit(path, policy, clock=clock)
        assert circuit.call(successful_read) == "fresh read"
        with pytest.raises(CloudBackoff) as failed:
            circuit.call(failing_rpc)
        assert failed.value.reason_code == "FIRESTORE_TRANSIENT_BACKOFF"
        assert failed.value.receipt["retrySeconds"] == expected_delay
        with pytest.raises(CloudBackoff):
            circuit.call(failing_rpc)
        clock.now += expected_delay
    assert failing_rpc.call_count == 6
    assert successful_read.call_count == 6

    circuit.recovered()
    assert circuit.status() == {}
    assert json.loads(path.read_text()) == {"status": "CLOSED", "delay": 0, "until": 0}
    restarted = CloudCircuit(path, policy, clock=clock)
    assert restarted.status() == {}
    with pytest.raises(CloudBackoff) as reset:
        restarted.call(failing_rpc)
    assert reset.value.receipt["retrySeconds"] == 30
    assert failing_rpc.call_count == 7


def test_recovered_does_not_clear_active_sibling_failure(circuit_parts):
    path, policy, clock = circuit_parts
    worker = CloudCircuit(path, policy, clock=clock)
    sibling = CloudCircuit(path, policy, clock=clock)
    assert worker.call(lambda: "completed read") == "completed read"
    rpc = Mock(side_effect=QuotaError())
    with pytest.raises(CloudBackoff) as failed:
        sibling.call(rpc)

    worker.recovered()
    assert worker.status() == failed.value.receipt
    with pytest.raises(CloudBackoff):
        worker.call(rpc)
    assert rpc.call_count == 1


@pytest.mark.parametrize("error_type", [QuotaError, TransientError])
def test_tick_services_skips_executor_on_new_and_known_backoff(circuit_parts, error_type):
    path, policy, clock = circuit_parts
    circuit = CloudCircuit(path, policy, clock=clock)
    rpc = Mock(side_effect=error_type())
    connection = Mock()
    connection.tick.side_effect = lambda now: circuit.call(rpc)
    executor = Mock(transport_failed=False)
    now = datetime.fromtimestamp(clock.now, timezone.utc)

    with pytest.raises(CloudBackoff) as initial:
        tick_services(connection, executor, now)
    # Repeated ticks, including a restarted circuit, must not invoke either RPC
    # or executor once the shared dependency failure is known.
    circuit = CloudCircuit(path, policy, clock=clock)
    for _ in range(3):
        with pytest.raises(CloudBackoff) as suppressed:
            tick_services(connection, executor, now)
        assert suppressed.value.receipt == initial.value.receipt
    assert rpc.call_count == 1
    assert connection.tick.call_count == 4
    connection.tick.assert_called_with(now)
    executor.tick.assert_not_called()


def test_tick_services_still_observes_executor_after_non_cloud_failure():
    connection = Mock()
    connection.tick.side_effect = ValueError("local messaging failure")
    executor = Mock(transport_failed=False)
    with pytest.raises(RuntimeError, match="^OWNER_SERVICES_UNAVAILABLE$"):
        tick_services(connection, executor, datetime(2026, 1, 1, tzinfo=timezone.utc))
    executor.tick.assert_called_once_with()
