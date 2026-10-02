"""Bounded executor tests: cloud is explicitly a MOCK; artifacts are real files."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path

import pytest

from cct_agent.owner_executor import (
    BoundedExecutor,
    CONTROL_SCHEMA,
    load_executor_config,
)

NOW = datetime(2026, 9, 13, 1, tzinfo=timezone.utc)
UID = "owner-test"


def control(**changes):
    return {
        "schemaVersion": CONTROL_SCHEMA,
        "ownerUid": UID,
        "revision": 1,
        "updatedAt": NOW,
        "enabled": True,
        "runNonce": "activation-test-0001",
        "task": "project-audit",
        "maxRuns": 1,
        "intervalSeconds": 60,
        **changes,
    }


class MockGateway:
    """No real Firebase access. publish intentionally does NOT verify itself."""

    def __init__(self):
        self.control = control()
        self.docs = {}
        self.events = []
        self.fail_read = False
        self.fail_publish = False
        self.tamper = False
        self.on_read = None
        self.on_publish = None

    def read(self, collection, name="current"):
        self.events.append(("read", collection, name))
        if self.on_read:
            self.on_read(collection, name)
        if self.fail_read and collection == "cct_executor_control":
            raise OSError("SECRET MUST NOT APPEAR")
        value = (
            self.control
            if collection == "cct_executor_control"
            else self.docs.get((collection, name))
        )
        result = deepcopy(value)
        if self.tamper and result and collection == "cct_executor_runtime":
            result["ownerUid"] = "wrong-owner"
        return result

    def publish(self, collection, name, value):
        self.events.append(("publish", collection, name, deepcopy(value)))
        if self.fail_publish:
            raise OSError("SECRET MUST NOT APPEAR")
        self.docs[collection, name] = deepcopy(value)
        if self.on_publish:
            self.on_publish(collection, name, value)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home = tmp_path / "profile"
    project = tmp_path / "pinned-project"
    home.mkdir()
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname="test-project"\nversion="1.0"\ndependencies=[]\n'
    )
    (project / "README.md").write_text(
        "# Fixture project\nThis is real test input, not simulated audit output.\n"
    )
    (project / "LICENSE").write_text("MIT License\n")
    (project / "firestore.rules").write_text(
        "rules_version = '2';\nallow read: if request.auth != null;\n"
    )
    (project / ".gitignore").write_text(".env\n*.sqlite\n")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr("cct_agent.owner_executor.PINNED_PROJECT_ROOT", project)
    config = {
        "projectId": "demo-owner",
        "ownerUid": UID,
        "hostEnabled": True,
        "projectRoot": str(project),
        "outputRoot": str(home / "owner-connection" / "executor"),
    }
    path = home / "config" / "cct-owner-executor.json"
    path.parent.mkdir()
    path.write_text(json.dumps(config))
    gateway = MockGateway()
    clock = [NOW]
    executor = BoundedExecutor(
        path, gateway, owner_uid=UID, project_id="demo-owner", clock=lambda: clock[0]
    )
    yield executor, gateway, clock, config, path, project
    executor.close()


def runs(gateway):
    return [
        value
        for (collection, _), value in gateway.docs.items()
        if collection == "cct_executor_runs"
    ]


def test_real_artifact_exact_readback_and_no_replay(setup):
    executor, gateway, _, config, _, project = setup
    result = executor.tick()
    assert result["state"] == "COMPLETED"
    assert result["scope"] == "BOUNDED_TEST_EXECUTOR"
    assert result["completedRuns"] == 1
    assert gateway.docs["cct_executor_runtime", "current"] == result
    (run,) = runs(gateway)
    assert run["state"] == "COMPLETED"
    artifact = Path(config["outputRoot"]) / (run["runId"] + ".txt")
    assert artifact.read_text() == run["reportText"]
    assert sha256(artifact.read_bytes()).hexdigest() == run["artifactSha256"]
    assert "Bounded project audit" in run["reportText"]
    assert str(project) not in run["reportText"]
    assert "Fixture project" not in run["reportText"]
    assert artifact.stat().st_mode & 0o777 == 0o600
    before = len(runs(gateway))
    executor.tick()
    assert len(runs(gateway)) == before
    events = gateway.events
    ack = next(
        i
        for i, e in enumerate(events)
        if e[0] == "publish"
        and e[1] == "cct_executor_runtime"
        and e[3]["state"] == "RUNNING"
    )
    assert events[ack + 1][:2] == ("read", "cct_executor_runtime")
    assert any(e[:2] == ("read", "cct_executor_control") for e in events[ack + 2 :])


@pytest.mark.parametrize(
    "changes",
    [
        {"ownerUid": "other"},
        {"extra": True},
        {"revision": True},
        {"revision": 0},
        {"revision": 2147483648},
        {"enabled": "true"},
        {"maxRuns": True},
        {"maxRuns": 4},
        {"intervalSeconds": 59},
        {"intervalSeconds": 3601},
        {"task": "shell"},
        {"runNonce": "bad nonce"},
        {"updatedAt": NOW.isoformat()},
        {"updatedAt": NOW + timedelta(seconds=1)},
        {"updatedAt": NOW - timedelta(hours=2)},
    ],
)
def test_invalid_control_never_runs(setup, changes):
    executor, gateway, *_ = setup
    gateway.control = control(**changes)
    result = executor.tick()
    assert result["state"] == "INVALID"
    assert not runs(gateway)
    assert len(json.dumps(result)) < 2000


def test_read_error_never_uses_cached_control(setup):
    executor, gateway, clock, *_ = setup
    gateway.control = control(maxRuns=3)
    assert executor.tick()["state"] == "READY"
    clock[0] += timedelta(seconds=61)
    gateway.fail_read = True
    result = executor.tick()
    assert result["state"] == "UNAVAILABLE"
    assert len(runs(gateway)) == 1
    assert "SECRET" not in json.dumps(result)


def test_ack_mismatch_blocks_effect_and_counts_attempt(setup):
    executor, gateway, *_ = setup
    gateway.tamper = True
    assert executor.tick()["state"] == "UNAVAILABLE"
    gateway.tamper = False
    executor.tick()
    values = runs(gateway)
    assert len(values) == 1
    assert values[0]["state"] in {"BLOCKED", "UNKNOWN"}
    assert not values[0]["reportText"]


def test_nonce_cannot_reactivate_at_later_revision(setup):
    executor, gateway, *_ = setup
    assert executor.tick()["state"] == "COMPLETED"
    gateway.control = control(revision=2)
    assert executor.tick()["state"] == "INVALID"
    assert len(runs(gateway)) == 1


def test_off_revokes_and_same_nonce_cannot_restart(setup):
    executor, gateway, *_ = setup
    gateway.control = control(maxRuns=3)
    executor.tick()
    gateway.control = control(revision=2, enabled=False)
    assert executor.tick()["state"] == "OFF"
    gateway.control = control(revision=3)
    assert executor.tick()["state"] == "INVALID"
    assert len(runs(gateway)) == 1


def test_activation_interval_and_six_per_utc_day(setup):
    executor, gateway, clock, *_ = setup
    gateway.control = control(maxRuns=3)
    assert executor.tick()["state"] == "READY"
    executor.tick()
    assert len(runs(gateway)) == 1
    for _ in range(2):
        clock[0] += timedelta(seconds=61)
        executor.tick()
    assert len(runs(gateway)) == 3
    gateway.control = control(revision=2, runNonce="activation-test-0002", maxRuns=3)
    for _ in range(3):
        clock[0] += timedelta(seconds=61)
        executor.tick()
    assert len(runs(gateway)) == 6
    gateway.control = control(revision=3, runNonce="activation-test-0003")
    assert executor.tick()["reasonCode"] == "EXECUTOR_DAILY_BUDGET"
    assert len(runs(gateway)) == 6


def test_mid_work_revoke_suppresses_artifact_and_completion(setup, monkeypatch):
    executor, gateway, _, config, *_ = setup

    def work(task, checkpoint):
        checkpoint()
        gateway.control = control(revision=2, enabled=False)
        return "must never be published"

    monkeypatch.setattr(executor, "perform_task", work)
    result = executor.tick()
    assert result["state"] == "STOPPED"
    (run,) = runs(gateway)
    assert run["state"] == "STOPPED"
    assert run["reportText"] == ""
    assert run["artifactSha256"] is None
    assert not list(Path(config["outputRoot"]).glob("run-*.txt"))


def test_config_requires_pinned_profile_identity_and_root(setup):
    _, _, _, config, path, _ = setup
    assert load_executor_config(path, owner_uid=UID, project_id="demo-owner") == config
    for changes in (
        {"hostEnabled": "true"},
        {"ownerUid": "wrong"},
        {"projectRoot": "/tmp"},
        {"outputRoot": "/tmp"},
        {"taskTimeout": 999},
    ):
        path.write_text(json.dumps({**config, **changes}))
        with pytest.raises(ValueError):
            load_executor_config(path, owner_uid=UID, project_id="demo-owner")


def test_off_does_not_expire(setup):
    executor, gateway, clock, *_ = setup
    gateway.control = control(enabled=False)
    clock[0] += timedelta(days=2)
    assert executor.tick()["state"] == "OFF"
    assert runs(gateway) == []


def test_restart_marks_claim_unknown_and_does_not_replay(setup, monkeypatch):
    executor, gateway, clock, config, path, _ = setup

    def crash(task, checkpoint):
        raise SystemExit("simulated process crash")

    monkeypatch.setattr(executor, "perform_task", crash)
    with pytest.raises(SystemExit):
        executor.tick()
    fresh = BoundedExecutor(
        path, gateway, owner_uid=UID, project_id="demo-owner", clock=lambda: clock[0]
    )
    try:
        assert fresh.tick()["state"] == "STOPPED"
        (run,) = runs(gateway)
        assert run["state"] == "UNKNOWN"
        assert run["reportText"] == ""
        assert run["artifactSha256"] is None
    finally:
        fresh.close()


def test_locked_finalization_halts_before_next_daemon_tick(setup, monkeypatch):
    import sqlite3
    from types import SimpleNamespace

    from cct_agent.owner_connection import tick_services
    from cct_agent.owner_executor import ExecutorStop

    executor, gateway, clock, config, *_ = setup
    gateway.control = control(maxRuns=3)
    executor.db.execute("PRAGMA busy_timeout=1")
    reader = sqlite3.connect(
        Path(config["outputRoot"]) / "executor.sqlite", isolation_level=None
    )
    connection = SimpleNamespace(tick=lambda now: {})
    perform_task = executor.perform_task

    def fail(task, checkpoint):
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM runs").fetchall()
        raise ExecutorStop("EXECUTOR_TASK_FAILED", "BLOCKED")

    monkeypatch.setattr(executor, "perform_task", fail)
    try:
        with pytest.raises(RuntimeError, match="OWNER_SERVICES_UNAVAILABLE"):
            tick_services(connection, executor, clock[0])
        activation = executor._activation(gateway.control["runNonce"])
        assert (activation["attempts"], activation["halted"]) == (1, 0)
        assert (
            json.loads(executor.db.execute("SELECT payload FROM runs").fetchone()[0])[
                "state"
            ]
            == "RUNNING"
        )
        clock[0] += timedelta(seconds=61)
        with pytest.raises(RuntimeError, match="OWNER_SERVICES_UNAVAILABLE"):
            tick_services(connection, executor, clock[0])
    finally:
        reader.close()
    monkeypatch.setattr(executor, "perform_task", perform_task)
    _, status = tick_services(connection, executor, clock[0])
    assert status is not None and status["state"] == "STOPPED"
    activation = executor._activation(gateway.control["runNonce"])
    assert (activation["attempts"], activation["completed"], activation["halted"]) == (
        1,
        0,
        1,
    )
    (row,) = runs(gateway)
    assert row["state"] == "UNKNOWN" and not row["reportText"]
    gateway.control = control(
        revision=2, runNonce="activation-fresh-0002", updatedAt=clock[0]
    )
    _, status = tick_services(connection, executor, clock[0])
    assert status is not None and status["state"] == "COMPLETED"


@pytest.mark.parametrize(
    "phase,state",
    [
        ("recover", "UNKNOWN"),
        ("finish", "UNKNOWN"),
        ("finish", "BLOCKED"),
        ("finish", "STOPPED"),
    ],
)
@pytest.mark.parametrize("boundary", ["run_saved", "halt_written", "committed"])
def test_terminal_halt_is_atomic_across_process_death(setup, phase, state, boundary):
    import subprocess
    import sys

    executor, gateway, clock, _, path, project = setup
    gateway.control = control(maxRuns=3)
    if phase == "recover":
        current, digest = executor._read_control()
        executor._observe(current, digest)
        executor._claim(current)
    # os._exit skips Python cleanup: SQLite must recover the actual journal.
    script = """
import os, runpy, sqlite3, sys
from pathlib import Path
import cct_agent.owner_executor as module
helpers = runpy.run_path(sys.argv[1])
path, project = map(Path, sys.argv[2:4])
phase, state, boundary = sys.argv[4:]
module.PINNED_PROJECT_ROOT = project
armed = phase == "recover"
class CrashConnection(sqlite3.Connection):
    def execute(self, sql, parameters=()):
        result = super().execute(sql, parameters)
        if armed and (
            boundary == "run_saved" and sql.startswith("UPDATE runs SET payload=")
            or boundary == "halt_written" and sql == "UPDATE activations SET halted=1 WHERE nonce=?"
            or boundary == "committed" and sql == "COMMIT"
        ):
            os._exit(73)
        return result
connect = sqlite3.connect
module.sqlite3.connect = lambda *a, **kw: connect(*a, factory=CrashConnection, **kw)
gateway = helpers["MockGateway"]()
gateway.control = helpers["control"](maxRuns=3)
executor = module.BoundedExecutor(path, gateway, owner_uid=helpers["UID"],
                                  project_id="demo-owner", clock=lambda: helpers["NOW"])
if phase == "finish":
    current, digest = executor._read_control()
    executor._observe(current, digest)
    row = executor._claim(current)
    armed = True
    executor._finish_failed(row, state, "EXECUTOR_TASK_FAILED")
executor.close()
"""
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(Path(__file__).resolve()),
            str(path),
            str(project),
            phase,
            state,
            boundary,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert child.returncode == 73, child.stderr
    before = json.loads(executor.db.execute("SELECT payload FROM runs").fetchone()[0])
    halted = executor._activation(gateway.control["runNonce"])["halted"]
    clock[0] += timedelta(seconds=61)
    fresh = BoundedExecutor(
        path, gateway, owner_uid=UID, project_id="demo-owner", clock=lambda: clock[0]
    )
    try:
        assert fresh.tick()["state"] == "STOPPED"
        activation = fresh._activation(gateway.control["runNonce"])
        assert (
            activation["attempts"],
            activation["completed"],
            activation["halted"],
        ) == (1, 0, 1)
        (run,) = runs(gateway)
        assert run["state"] == (state if boundary == "committed" else "UNKNOWN")
        assert not run["reportText"] and run["artifactSha256"] is None
        assert (before["state"], halted) == (
            (state, 1) if boundary == "committed" else ("RUNNING", 0)
        )
        gateway.control = control(
            revision=2, runNonce="activation-fresh-0002", updatedAt=clock[0]
        )
        assert fresh.tick()["state"] == "COMPLETED"
        assert len(runs(gateway)) == 2
    finally:
        fresh.close()


@pytest.mark.parametrize("state", ["UNKNOWN", "BLOCKED", "STOPPED"])
def test_recovery_halts_legacy_terminal_activation(setup, state):
    executor, gateway, clock, _, path, _ = setup
    gateway.control = control(maxRuns=3)
    current, digest = executor._read_control()
    executor._observe(current, digest)
    row = executor._claim(current)
    # Simulate a journal left by the old autocommit ordering, not a new run.
    row.update(state=state, reasonCode="EXECUTOR_INTERRUPTED")
    executor._save_run(row)
    assert executor._activation(current["runNonce"])["halted"] == 0
    clock[0] += timedelta(seconds=61)
    fresh = BoundedExecutor(
        path, gateway, owner_uid=UID, project_id="demo-owner", clock=lambda: clock[0]
    )
    try:
        assert fresh.tick()["state"] == "STOPPED"
        assert fresh._activation(current["runNonce"])["attempts"] == 1
        (run,) = runs(gateway)
        assert run["state"] == state
    finally:
        fresh.close()


def test_symlink_input_is_rejected_not_read(setup):
    executor, gateway, _, _, _, project = setup
    target = project.parent / "private.txt"
    target.write_text("do not export me")
    (project / "README.md").unlink()
    (project / "README.md").symlink_to(target)
    assert executor.tick()["state"] == "COMPLETED"
    (run,) = runs(gateway)
    assert "Readme: REJECTED" in run["reportText"]
    assert "do not export me" not in run["reportText"]


def test_host_revocation_during_work(setup, monkeypatch):
    executor, gateway, _, config, path, _ = setup

    def work(task, checkpoint):
        path.write_text(json.dumps({**config, "hostEnabled": False}))
        checkpoint()
        return "never"

    monkeypatch.setattr(executor, "perform_task", work)
    assert executor.tick()["reasonCode"] == "EXECUTOR_HOST_DISABLED"
    (run,) = runs(gateway)
    assert run["state"] == "BLOCKED"
    assert not run["reportText"]


def test_public_http_real_socket_bounded_no_redirects(monkeypatch):
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    import cct_agent.owner_executor as module

    body = b"<title>Local fixture, not a production result</title>"

    class Handler(BaseHTTPRequestHandler):
        status = 200
        payload = body

        def do_GET(self):
            self.send_response(self.status)
            self.send_header("Content-Length", str(len(self.payload)))
            self.end_headers()
            self.wfile.write(self.payload)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(
        module.http.client,
        "HTTPSConnection",
        lambda host, timeout: http.client.HTTPConnection(
            "127.0.0.1", server.server_port, timeout=timeout
        ),
    )
    try:
        result = module.fetch_public_document(module.PUBLIC_DOC_URLS[0], lambda: None)
        assert result["sha256"] == sha256(body).hexdigest()
        assert result["bytes"] == len(body)
        Handler.status = 302
        assert (
            module.fetch_public_document(module.PUBLIC_DOC_URLS[0], lambda: None)[
                "result"
            ]
            == "REDIRECT_BLOCKED"
        )
        Handler.status = 200
        monkeypatch.setattr(module, "MAX_HTTP_BYTES", 10)
        with pytest.raises(
            module.ExecutorStop, match="EXECUTOR_HTTP_RESPONSE_TOO_LARGE"
        ):
            module.fetch_public_document(module.PUBLIC_DOC_URLS[0], lambda: None)
        with pytest.raises(module.ExecutorStop, match="EXECUTOR_URL_NOT_ALLOWED"):
            module.fetch_public_document("http://127.0.0.1/", lambda: None)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
