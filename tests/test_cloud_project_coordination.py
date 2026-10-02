"""Offline shared-project coordination, including independent OS processes."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import multiprocessing
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from cct_agent.cloud_backoff import CloudBackoff, CloudCircuit, CloudErrorPolicy


PROJECT = "demo-cctae-control"
NOW = 1_700_000_000.0


class QuotaError(Exception):
    pass


POLICY = CloudErrorPolicy((QuotaError,), (), ())


@pytest.fixture
def shared(tmp_path, monkeypatch):
    directory = tmp_path / "shared"
    directory.mkdir(mode=0o700)
    monkeypatch.setenv("CCT_CLOUD_RECOVERY_DIR", str(directory))
    monkeypatch.delenv("CCT_CLOUD_PROJECTION_HEARTBEAT_SECONDS", raising=False)
    return directory


def test_unset_retains_each_exact_legacy_path(tmp_path, monkeypatch):
    monkeypatch.delenv("CCT_CLOUD_RECOVERY_DIR", raising=False)
    legacy = [tmp_path / "profile-a" / "cloud-recovery" / (sha256(PROJECT.encode()).hexdigest() + ".json"),
              tmp_path / "profile-b" / "runtime" / "cloud-backoff.json"]
    for path in legacy:
        assert CloudCircuit.for_project(PROJECT, path, POLICY).path == path
    assert not any(path.exists() for path in legacy)


def test_shared_project_key_ignores_profile_but_not_project(tmp_path, shared):
    first = CloudCircuit.for_project(PROJECT, tmp_path / "profile-a" / "a.json", POLICY)
    second = CloudCircuit.for_project(PROJECT, tmp_path / "profile-b" / "b.json", POLICY)
    other = CloudCircuit.for_project("demo-other-project", tmp_path / "other.json", POLICY)
    assert first.path == second.path == shared / (sha256(PROJECT.encode()).hexdigest() + ".json")
    assert other.path != first.path
    assert other.call(lambda: "fresh") == "fresh"
    assert not (tmp_path / "profile-a").exists()
    assert not (tmp_path / "profile-b").exists()


@pytest.mark.parametrize("kind", ["empty", "relative", "parent", "missing", "file", "public",
                                  "group", "symlink", "linked-ancestor", "writable-ancestor", "root"])
def test_explicit_unsafe_directory_fails_closed_without_fallback(tmp_path, monkeypatch, kind):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    configured = str(private)
    if kind == "empty":
        configured = ""
    elif kind == "relative":
        configured = "relative/cloud"
    elif kind == "parent":
        configured = str(private / ".." / "private")
    elif kind == "missing":
        configured = str(tmp_path / "not-provisioned")
    elif kind == "file":
        file = tmp_path / "not-directory"
        file.write_text("not a directory")
        configured = str(file)
    elif kind in ("public", "group"):
        private.chmod(0o777 if kind == "public" else 0o750)
    elif kind == "symlink":
        link = tmp_path / "link"
        link.symlink_to(private, target_is_directory=True)
        configured = str(link)
    elif kind in ("linked-ancestor", "writable-ancestor"):
        leaf = private / "leaf"
        leaf.mkdir(mode=0o700)
        if kind == "linked-ancestor":
            link = tmp_path / "link"
            link.symlink_to(private, target_is_directory=True)
            configured = str(link / "leaf")
        else:
            private.chmod(0o777)
            configured = str(leaf)
    elif kind == "root":
        configured = "/"
    monkeypatch.setenv("CCT_CLOUD_RECOVERY_DIR", configured)
    fallback = tmp_path / "fallback" / "backoff.json"
    with pytest.raises(ValueError, match="^CLOUD_RECOVERY_DIRECTORY_UNSAFE$"):
        CloudCircuit.for_project(PROJECT, fallback, POLICY)
    assert not fallback.parent.exists()


def test_shared_directory_revalidated_after_construction_and_rpc_uses_open_descriptor(tmp_path, shared):
    circuit = CloudCircuit.for_project(PROJECT, tmp_path / "unused", POLICY, clock=lambda: NOW)
    moved = tmp_path / "moved"
    target = tmp_path / "target"
    target.mkdir(mode=0o700)

    def failing_rpc():
        shared.rename(moved)
        shared.symlink_to(target, target_is_directory=True)
        raise QuotaError()

    with pytest.raises(CloudBackoff):
        circuit.call(failing_rpc)
    assert json.loads((moved / circuit.path.name).read_text())["until"] == NOW + 300
    assert not list(target.iterdir())
    rpc = Mock()
    with pytest.raises(ValueError, match="^CLOUD_RECOVERY_DIRECTORY_UNSAFE$"):
        circuit.call(rpc)
    rpc.assert_not_called()


@pytest.mark.parametrize("artifact", ["state", "lock"])
@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "public", "fifo"])
def test_unsafe_shared_artifact_never_calls_rpc(tmp_path, shared, artifact, unsafe):
    circuit = CloudCircuit.for_project(PROJECT, tmp_path / "unused", POLICY)
    path = circuit.path if artifact == "state" else Path(str(circuit.path) + ".lock")
    if unsafe == "symlink":
        target = tmp_path / "target.json"
        target.write_text("{}")
        path.symlink_to(target)
    elif unsafe == "fifo":
        os.mkfifo(path, mode=0o600)
    else:
        path.write_text("{}")
        path.chmod(0o666 if unsafe == "public" else 0o600)
        if unsafe == "hardlink":
            os.link(path, tmp_path / "alias")
    rpc = Mock()
    with pytest.raises((ValueError, OSError)):
        circuit.call(rpc)
    rpc.assert_not_called()


def _process_worker(kind, profile, project, now, fail, counter, ready, entered, release, output):
    """Spawn target: actual adapters, fake SDK transport; no network or credentials."""
    from google.api_core.exceptions import ResourceExhausted
    from cct_agent.cloud_backoff import firestore_error_policy
    from cct_agent.firebase_bridge import run_bridge_loop
    from cct_agent.owner_connection import FirebaseOwnerGateway

    os.environ["HERMES_HOME"] = str(profile)
    profile.mkdir(mode=0o700, parents=True, exist_ok=True)

    def rpc():
        with counter.get_lock():
            counter.value += 1
        if entered is not None:
            entered.set()
        if release is not None:
            assert release.wait(20), "failure release barrier timed out"
        if fail:
            raise ResourceExhausted("synthetic quota only")
        return {"fresh": True}

    try:
        if kind == "owner":
            db = Mock()
            db.collection.return_value.document.return_value.get.side_effect = lambda **_: SimpleNamespace(to_dict=rpc)
            with patch("google.auth.default", return_value=(None, None)), patch("google.cloud.firestore.Client", return_value=db):
                gateway = FirebaseOwnerGateway(project)
            gateway.circuit.clock = lambda: now
            ready.set()
            try:
                value = gateway.read("cct_workspace")
                gateway.circuit.recovered()
                result = {"status": "ONLINE", "value": value}
            except CloudBackoff as error:
                result = error.receipt
        else:
            runtime = profile / "runtime"
            runtime.mkdir(mode=0o700, exist_ok=True)
            config = SimpleNamespace(project_id=project, runtime_directory=runtime, poll_seconds=60)
            ready.set()
            code = run_bridge_loop(SimpleNamespace(config=config, run_once=rpc), once=True,
                                   errors=firestore_error_policy(),
                                   clock=lambda: datetime.fromtimestamp(now, timezone.utc))
            result = json.loads((runtime / "bridge-health.json").read_text())
            result["exit_code"] = code
        output.put(result)
    except BaseException as error:
        output.put({"unexpected": type(error).__name__, "detail": str(error)})
        raise


@pytest.mark.parametrize("first_kind,sibling_kind", [("owner", "bridge"), ("bridge", "owner")])
def test_cross_process_failure_blocks_distinct_profiles_restart_and_recovers(tmp_path, shared, first_kind, sibling_kind):
    pytest.importorskip("google.cloud.firestore")
    ctx = multiprocessing.get_context("spawn")
    counter, entered, release = ctx.Value("i", 0), ctx.Event(), ctx.Event()
    processes = []

    def start(kind, profile, *, fail=False, at=NOW, project=PROJECT, hold=False):
        ready, output = ctx.Event(), ctx.Queue()
        process = ctx.Process(target=_process_worker, args=(
            kind, tmp_path / profile, project, at, fail, counter, ready,
            entered if hold else None, release if hold else None, output))
        processes.append(process)
        process.start()
        assert ready.wait(20), "adapter initialization timed out"
        return process, output

    def finish(worker):
        process, output = worker
        result = output.get(timeout=20)
        process.join(timeout=20)
        assert process.exitcode == 0, result
        assert "unexpected" not in result
        output.close()
        return result

    try:
        first = start(first_kind, "profile-a", fail=True, hold=True)
        assert entered.wait(20)
        sibling = start(sibling_kind, "profile-b")
        release.set()
        a, b = finish(first), finish(sibling)
        assert a.get("cloudStatus", a.get("status")) == "QUOTA_BACKOFF"
        assert b.get("cloudStatus", b.get("status")) == "QUOTA_BACKOFF"
        assert a["retrySeconds"] == b["retrySeconds"] == 300
        assert counter.value == 1
        restarted = finish(start(first_kind, "profile-a", at=NOW + 299))
        assert restarted.get("cloudStatus", restarted.get("status")) == "QUOTA_BACKOFF"
        assert counter.value == 1
        assert finish(start("owner", "profile-other", project="demo-other-project"))["status"] == "ONLINE"
        assert counter.value == 2
        assert finish(start(sibling_kind, "profile-b", at=NOW + 300))["status"] == "ONLINE"
        assert counter.value == 3
        failed_again = finish(start(first_kind, "profile-a", fail=True, at=NOW + 301))
        assert failed_again["retrySeconds"] == 300
        assert counter.value == 4
        state = shared / (sha256(PROJECT.encode()).hexdigest() + ".json")
        assert json.loads(state.read_text())["until"] == NOW + 601
        assert state.stat().st_mode & 0o777 == 0o600
        assert not list(shared.glob(".cloud-circuit-*"))
    finally:
        release.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=5)


def test_three_day_quota_outage_has_one_project_probe_per_deadline_across_restarts(tmp_path, shared):
    now = [NOW]
    probes, workers = [], []

    def fail():
        probes.append(now[0])
        raise QuotaError()

    # Three independent workers wake each minute; reconstruct each hour, not
    # just once, to prove exponential state persists throughout a finite outage.
    for elapsed in range(0, 3 * 86400, 60):
        now[0] = NOW + elapsed
        if elapsed % 3600 == 0:
            workers = [CloudCircuit.for_project(PROJECT, tmp_path / str(i) / "unused", POLICY,
                                               clock=lambda: now[0]) for i in range(3)]
        for worker in workers:
            with pytest.raises(CloudBackoff):
                worker.call(fail)
    gaps = [b - a for a, b in zip(probes, probes[1:])]
    assert gaps[:3] == [300, 600, 1200]
    assert set(gaps[3:]) == {1800}
    assert len(probes) <= 3 * 48 + 4
    state = json.loads(workers[0].path.read_text())
    now[0] = state["until"]
    assert workers[0].call(lambda: "fresh recovery") == "fresh recovery"
    workers[0].recovered()
    assert workers[1].status() == {}
    with pytest.raises(CloudBackoff) as reset:
        workers[2].call(fail)
    assert reset.value.receipt["retrySeconds"] == 300
