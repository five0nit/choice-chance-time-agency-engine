"""Display-only coalescing preserves authority and exact-readback boundaries."""
from copy import deepcopy
from unittest.mock import Mock
import pytest
from cct_agent.cloud_projection import ProjectionCache, publish_projection
from cct_agent.cloud_backoff import CloudBackoff, CloudCircuit, CloudErrorPolicy


def test_idle_heartbeats_coalesce_but_semantic_change_is_immediate():
    clock = [0.0]
    cache = ProjectionCache(clock=lambda: clock[0])
    write = Mock()
    first = {'updatedAt': 'old', 'revision': 1, 'phase': 'WAITING'}
    assert cache.publish('cct_discovery', 'current', first, write) == first
    clock[0] = 60
    changed = {**first, 'updatedAt': 'new', 'revision': 2}
    assert cache.publish('cct_discovery', 'current', changed, write) == first
    assert write.call_count == 1
    assert cache.publish('cct_discovery', 'current', {**changed, 'phase': 'READY'}, write)['phase'] == 'READY'
    assert write.call_count == 2
    clock[0] = 180
    cache.publish('cct_discovery', 'current', {**changed, 'phase': 'READY'}, write)
    assert write.call_count == 3


def test_authority_control_status_never_coalesces():
    cache, write = ProjectionCache(), Mock()
    for _ in range(3):
        cache.publish('cct_owner_build_controls_status', 'current', {'revision': 3}, write)
    assert write.call_count == 3


def test_failure_never_enters_cache():
    cache, write = ProjectionCache(), Mock(side_effect=[RuntimeError('unverified'), None])
    with pytest.raises(RuntimeError):
        cache.publish('cct_owner_work', 'current', {'updatedAt': 'x'}, write)
    cache.publish('cct_owner_work', 'current', {'updatedAt': 'x'}, write)
    assert write.call_count == 2


def test_cached_payload_cannot_be_mutated_by_caller():
    cache = ProjectionCache()
    value = {'updatedAt': 'x', 'nested': {'state': 1}}
    cache.publish('cct_owner_work', 'current', value, lambda: None)
    result = cache.publish('cct_owner_work', 'current', value, lambda: None)
    result['nested']['state'] = 8
    assert cache.publish('cct_owner_work', 'current', value, lambda: None) == value


def test_legacy_gateway_requires_readback():
    gateway = Mock()
    gateway.publish.return_value = None
    gateway.read.return_value = {'wrong': True}
    with pytest.raises(RuntimeError, match='CLOUD_PROJECTION_READBACK_MISMATCH'):
        publish_projection(gateway, 'cct_owner_work', 'current', {'phase': 'WAITING'})
    assert not gateway._projection_cache.entries


def test_known_outage_cannot_be_hidden_by_cached_projection(tmp_path):
    class Quota(Exception):
        pass
    circuit = CloudCircuit(tmp_path / 'private' / 'backoff.json',
                           CloudErrorPolicy((Quota,), (), ()))
    class Gateway:
        def __init__(self):
            self.circuit = circuit
            self.writes = 0
        def publish(self, collection, name, value):
            self.writes += 1
            return deepcopy(value)
    gateway = Gateway()
    payload = {'updatedAt': 'old', 'phase': 'WAITING'}
    publish_projection(gateway, 'cct_owner_work', 'current', payload)
    with pytest.raises(CloudBackoff):
        circuit.call(lambda: (_ for _ in ()).throw(Quota()))
    with pytest.raises(CloudBackoff):
        publish_projection(gateway, 'cct_owner_work', 'current', payload)
    assert gateway.writes == 1


@pytest.mark.parametrize('value', ['', '0', '119', '1801', '60.0', 'true', ' 600', '600 ', '-600', '６００'])
def test_invalid_explicit_heartbeat_fails_closed(monkeypatch, value):
    monkeypatch.setenv('CCT_CLOUD_PROJECTION_HEARTBEAT_SECONDS', value)
    with pytest.raises(ValueError, match='^CLOUD_PROJECTION_HEARTBEAT_INVALID$'):
        ProjectionCache()


@pytest.mark.parametrize('value', [None, '120', '600', '1800'])
def test_heartbeat_configuration_is_bounded_and_only_display_coalesces(monkeypatch, value):
    if value is None:
        monkeypatch.delenv('CCT_CLOUD_PROJECTION_HEARTBEAT_SECONDS', raising=False)
    else:
        monkeypatch.setenv('CCT_CLOUD_PROJECTION_HEARTBEAT_SECONDS', value)
    clock = [0]
    cache = ProjectionCache(clock=lambda: clock[0])
    assert cache.heartbeat_seconds == (int(value) if value else 120)
    writes, authority = Mock(), Mock()
    for second in range(0, 3600, 60):
        clock[0] = second
        cache.publish('cct_owner_work', 'current', {'updatedAt': second, 'phase': 'WAIT'}, writes)
        cache.publish('cct_owner_build_controls_status', 'current', {'revision': 1}, authority)
    assert writes.call_count == 3600 // cache.heartbeat_seconds
    assert authority.call_count == 3600 // 60
    clock[0] += 1
    cache.publish('cct_owner_work', 'current', {'updatedAt': clock[0], 'phase': 'READY'}, writes)
    assert writes.call_count == 3600 // cache.heartbeat_seconds + 1


@pytest.mark.parametrize('status,delay', [('quota', 300), ('transient', 30)])
def test_expired_circuit_requires_fresh_verified_display_not_cached_recovery(tmp_path, monkeypatch, status, delay):
    monkeypatch.setenv('CCT_CLOUD_PROJECTION_HEARTBEAT_SECONDS', '1800')
    class Failure(Exception):
        pass
    policy = CloudErrorPolicy((Failure,) if status == 'quota' else (),
                              (Failure,) if status == 'transient' else (), ())
    clock = [1_700_000_000.0]
    path = tmp_path / 'private' / 'backoff.json'
    first = CloudCircuit(path, policy, clock=lambda: clock[0])
    sibling = CloudCircuit(path, policy, clock=lambda: clock[0])
    rpc = Mock(return_value=None)
    class Gateway:
        circuit = first
        _projection_cache = ProjectionCache(clock=lambda: clock[0])
        def publish(self, collection, name, value):
            self.circuit.call(rpc)
            return deepcopy(value)
    gateway = Gateway()
    before = {'updatedAt': 'before', 'phase': 'WAIT'}
    assert publish_projection(gateway, 'cct_owner_work', 'current', before) == before
    with pytest.raises(CloudBackoff):
        sibling.call(lambda: (_ for _ in ()).throw(Failure()))
    with pytest.raises(CloudBackoff):
        publish_projection(gateway, 'cct_owner_work', 'current', before)
    assert rpc.call_count == 1
    clock[0] += delay
    rpc.side_effect = Failure()
    with pytest.raises(CloudBackoff):
        publish_projection(gateway, 'cct_owner_work', 'current', before)
    assert rpc.call_count == 2
    assert first.status()['retrySeconds'] == delay * 2
    clock[0] += delay * 2
    rpc.side_effect = None
    after = {**before, 'updatedAt': 'actual fresh write'}
    assert publish_projection(gateway, 'cct_owner_work', 'current', after) == after
    assert rpc.call_count == 3
    first.recovered()
    assert sibling.status() == {}
    assert publish_projection(gateway, 'cct_owner_work', 'current', {**after, 'updatedAt': 'not written'}) == after
    assert rpc.call_count == 3


def test_long_display_heartbeat_never_caches_owner_authority_reads(tmp_path, monkeypatch):
    from cct_agent.owner_connection import FirebaseOwnerGateway
    monkeypatch.setenv('CCT_CLOUD_PROJECTION_HEARTBEAT_SECONDS', '1800')
    now = [0]
    gateway = FirebaseOwnerGateway.__new__(FirebaseOwnerGateway)
    gateway.circuit = CloudCircuit(tmp_path / 'private' / 'backoff.json', CloudErrorPolicy((), (), ()))
    gateway.db = Mock()
    ref = gateway.db.collection.return_value.document.return_value
    ref.get.return_value.to_dict.side_effect = [{'enabled': True}, {'enabled': False}, {'enabled': False}]
    gateway.publish = Mock(side_effect=lambda collection, name, value: deepcopy(value))
    gateway._projection_cache = ProjectionCache(clock=lambda: now[0])
    payload = {'updatedAt': 'first', 'phase': 'WAIT'}
    for expected in (True, False, False):
        assert gateway.read('cct_workspace')['enabled'] is expected
        publish_projection(gateway, 'cct_owner_work', 'current', payload)
        now[0] += 60
    assert ref.get.call_count == 3
    assert all(call.kwargs == {'retry': None, 'timeout': 15} for call in ref.get.call_args_list)
    assert gateway.publish.call_count == 1
