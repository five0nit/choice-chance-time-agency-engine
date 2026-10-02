import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cct_agent.reliability_observer import digest, ledger_snapshot, run


@pytest.fixture
def config(tmp_path):
    home = tmp_path / 'home'
    folder = home / 'owner-delivery'
    folder.mkdir(parents=True)
    with sqlite3.connect(folder / 'delivery.sqlite') as c:
        c.executescript('''CREATE TABLE events(id INTEGER PRIMARY KEY, at TEXT, kind TEXT, data TEXT, previous TEXT, hash TEXT);
CREATE TABLE jobs(id TEXT PRIMARY KEY, created REAL, payload TEXT);
CREATE TABLE continuation_cycles(id TEXT PRIMARY KEY, state TEXT, created REAL);
CREATE TABLE attempts(id INTEGER PRIMARY KEY);
CREATE TABLE tool_attempts(id INTEGER PRIMARY KEY);''')
    return {'home': str(home), 'stateDirectory': str(tmp_path / 'observations'),
            'startedAt': 1000, 'endsAt': 1000 + 3*86400, 'units': []}


def test_missing_database_is_error_not_success(config):
    Path(config['home'], 'owner-delivery/delivery.sqlite').unlink()
    assert 'OBSERVER_ERROR' in run(config, now=1001, services={})
    assert not Path(config['home'], 'owner-delivery/delivery.sqlite').exists()


def test_silence_deadline_and_restart(config):
    assert '0 fresh verified deliveries' in run(config, now=1001, services={})
    assert run(config, now=1002, services={}) == ''
    assert 'running' in run(config, now=1001+86400, services={})
    assert 'window ended' in run(config, now=config['endsAt'], services={})
    assert run(config, now=config['endsAt']+1, services={}) == ''
    assert len(list(Path(config['stateDirectory']).glob('sample-*.json'))) == 4


def test_changed_config_fails(config):
    run(config, now=1001, services={})
    config['endsAt'] += 1
    with pytest.raises(ValueError, match='OBSERVER_CONFIG_CHANGED'):
        run(config, now=1002, services={})


def add_job(config, created=999):
    root = Path(config['home'], 'owner-delivery/artifacts/job')
    root.mkdir(parents=True)
    p = root / 'app.py'
    p.write_text('print(1)')
    import hashlib
    job = {'id': 'test-job', 'created': created, 'phase': 'COMPLETE', 'artifactRoot': str(root),
           'execution': {'manifest': [{'path': 'app.py', 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}]},
           'verification': {'status': 'passed'}, 'review': {'accepted': True},
           'notification': {'readVerified': True, 'messageId': 'fixture-only'}}
    with sqlite3.connect(Path(config['home'], 'owner-delivery/delivery.sqlite')) as c:
        c.execute('INSERT INTO jobs VALUES(?,?,?)', (job['id'], created, json.dumps(job)))
    return p


def test_past_deliveries_not_fresh(config):
    add_job(config)
    assert '0 fresh verified deliveries' in run(config, now=1001, services={})
    snap = ledger_snapshot(config['home'], 1000)
    assert snap['jobs'][0]['artifactVerifiedNow'] is True


def test_corruption_and_service_failure(config):
    p = add_job(config, created=1001)
    assert '1 fresh verified deliveries' in run(config, now=1002, services={})
    p.write_text('tampered')
    assert 'FAILURE' in run(config, now=1003, services={})
    assert ledger_snapshot(config['home'], 1000)['jobs'][0]['artifactVerifiedNow'] is False


def test_chain_and_duplicate_detection(config):
    db = Path(config['home'], 'owner-delivery/delivery.sqlite')
    previous = '0'*64
    with sqlite3.connect(db) as c:
        for i in range(2):
            value = {'at': 'test-fixture', 'kind': 'OUTCOME', 'data': {'jobId': 'j'}, 'previous': previous}
            hashed = digest(value)
            c.execute('INSERT INTO events VALUES(?,?,?,?,?,?)', (i, value['at'], value['kind'], json.dumps(value['data']), previous, hashed))
            previous = hashed
    snap = ledger_snapshot(config['home'], 1000)
    assert snap['chainValid'] is True
    assert snap['duplicateLocalOutcomes'] == 1
    with sqlite3.connect(db) as c:
        c.execute("UPDATE events SET hash='bad' WHERE id=1")
    assert ledger_snapshot(config['home'], 1000)['chainValid'] is False


def test_circuit_failure_remains_failure_after_deadline_until_recovery(config):
    path = Path(config['home']) / 'circuit.json'
    config['circuitFiles'] = [str(path)]
    path.write_text(json.dumps({'status': 'QUOTA_BACKOFF', 'until': 999}))
    assert 'FAILURE' in run(config, now=1001, services={})
    path.write_text(json.dumps({'status': 'CLOSED', 'until': 0}))
    assert 'LOCAL_CHECKS_OK' in run(config, now=1002, services={})


def test_overlapping_wakes_serialize(config):
    def call(_):
        try:
            return run(config, now=1001, services={})
        except BlockingIOError:
            return ''
    with ThreadPoolExecutor(max_workers=5) as pool:
        messages = list(pool.map(call, range(5)))
    assert sum(bool(m) for m in messages) == 1
    state = json.loads(Path(config['stateDirectory'], 'state.json').read_text())
    assert state['samples'] >= 1
