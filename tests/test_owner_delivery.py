"""Isolated orchestration/model contracts; no real accounts/model calls."""

import copy
import json
from pathlib import Path
from datetime import datetime, timezone
from cct_agent.owner_workspace import ANSWER_CHOICES, PERMISSION_KEYS

import pytest

from cct_agent.owner_delivery import OwnerDelivery, digest, regular
from cct_agent.owner_delivery_model import validate


def config(home):
    (home / "config").mkdir(parents=True, exist_ok=True)
    value = {
        "schemaVersion": "cct.owner_delivery.config.v1",
        "ownerUid": "fixture-owner",
        "projectId": "fixture-project",
        "conversationId": "fixture-conversation",
        "sourceHome": str(home.parent / "source"),
        "enabled": True,
        "authorization": "operator://test/local-only",
        "maxDailyJobs": 2,
        "maxDailyModelCalls": 12,
        "maxAttempts": 3,
        "retrySeconds": 1,
        "services": {},
    }
    (home / "config/cct-owner-delivery.json").write_text(json.dumps(value))
    (home / "config/cct-owner-delivery.json").chmod(0o600)
    return value


class Gateway:
    def __init__(self):
        self.workspace = {
            "ownerUid": "fixture-owner",
            "learningEnabled": True,
            "autonomyMode": "full",
            "autonomyAcknowledged": True,
            "schemaVersion": "cct.owner_workspace.v1",
            "revision": 1,
            "updatedAt": datetime(2026, 9, 14, tzinfo=timezone.utc),
            "permissions": {k: True for k in PERMISSION_KEYS},
            "answers": {k: "" for k in ANSWER_CHOICES},
            "decisions": {},
        }
        self.projections = []
        self.documents = {}

    def list_build_requests(self, *, owner_uid, after, limit):
        return sorted(
            [
                (name, copy.deepcopy(value))
                for (col, name), value in self.documents.items()
                if col == "cct_owner_build_requests"
                and value.get("ownerUid") == owner_uid
                and name > after
            ]
        )[:limit]

    def read(self, collection, document="current"):
        if collection == "cct_owner_delivery":
            return copy.deepcopy(self.projections[-1]) if self.projections else None
        if collection == "cct_workspace":
            return copy.deepcopy(self.workspace)
        return copy.deepcopy(self.documents.get((collection, document)))

    def publish(self, collection, document, value):
        if collection == "cct_owner_delivery" and document == "current":
            self.projections.append(copy.deepcopy(value))
        else:
            self.documents[(collection, document)] = copy.deepcopy(value)


class Evidence:
    def snapshot(self):
        return {
            "turnId": "q-" + "a" * 32,
            "candidates": [
                {
                    "ideaId": f"promote-{'a' * 32}-{i}",
                    "turnId": "q-" + "a" * 32,
                    "ideaIndex": i,
                    "idea": {
                        "title": f"Fixture utility {i}",
                        "firstStep": "Build private test tool",
                    },
                    "fingerprint": digest(["fixture", i]),
                }
                for i in range(3)
            ],
            "reports": [],
        }


def bundle():
    return {
        "summary": "Fixture-only bundle",
        "files": [
            {"path": p, "content": c}
            for p, c in [
                ("README.md", "Test fixture, not a real artifact."),
                (
                    "app.py",
                    "import sys\nif __name__ == '__main__':\n print(int(sys.argv[1])*2 if len(sys.argv)>1 and sys.argv[1]!='--help' else 'Double an integer')",
                ),
                (
                    "test_app.py",
                    "import unittest\nclass T(unittest.TestCase):\n def test_fixture(self): self.assertTrue(True)",
                ),
            ]
        ],
        "testCommand": "python-unittest",
    }


def acceptance():
    return {
        "schemaVersion": "cct.cli_acceptance.v1",
        "cases": [
            {
                "id": "positive",
                "argv": ["2"],
                "stdin": "",
                "exitCode": 0,
                "stdout": "4\n",
            },
            {
                "id": "negative",
                "argv": ["-3"],
                "stdin": "",
                "exitCode": 0,
                "stdout": "-6\n",
            },
        ],
    }


class Model:
    def __init__(self):
        self.calls = []
        self.reject = False
        self.noop = False
        self.fail_build = False

    def __call__(self, p):
        self.calls.append(copy.deepcopy(p))
        if p["stage"] == "select":
            return {
                "action": "NO_OP" if self.noop else "BUILD",
                "ideaId": "" if self.noop else p["candidates"][0]["ideaId"],
                "objective": "Build fixture utility",
                "doneWhen": "Fixture behavior passes",
                "why": "Test selection",
                "reportIds": [],
            }
        if p["stage"] == "build":
            if self.fail_build:
                raise RuntimeError("FIXTURE_MODEL_FAILED")
            return bundle()
        if p["stage"] == "acceptance":
            return acceptance()
        return {
            "accepted": not self.reject,
            "issues": ["Fixture review rejection"] if self.reject else [],
        }


class Driver:
    def __init__(self):
        self.calls = []
        self.fail = False

    def run(self, job_id, value, *, acceptance=None):
        self.calls.append((job_id, value))
        return {
            "schemaVersion": "cct-local-delivery/v2",
            "artifactRoot": "/fixture/artifact",
            "status": "blocked" if self.fail else "completed",
            "testCount": 2,
            "private": True,
            "sandbox": "bubblewrap-no-network",
            "manifest": [{"path": "app.py"}],
            "verification": {
                "status": "blocked" if self.fail else "passed",
                "testCount": 2,
                "compile": True,
                "tests": True,
                "cli": True,
                "readback": True,
                "semanticCompletion": False,
                "independentBehavior": True,
                "generatedTestsVerified": False,
                "acceptanceDigest": digest(acceptance),
            },
        }


class Services:
    def __init__(self):
        self.calls = []
        self.fail = False

    def capabilities(self):
        return [
            {
                "id": "fixture",
                "implemented": True,
                "configured": True,
                "authorized": True,
                "readVerified": False,
                "reason": "Isolated fixture",
            }
        ]

    def notify_owner(self, job):
        self.calls.append(job["id"])
        return {
            "state": "FAILED" if self.fail else "VERIFIED",
            "readVerified": not self.fail,
            "documentId": job["id"],
        }


@pytest.fixture
def environment(tmp_path):
    home = tmp_path / "home"
    config(home)
    g, e, d, s, m = Gateway(), Evidence(), Driver(), Services(), Model()
    clock = [1_800_000_000.0]
    worker = OwnerDelivery(
        home,
        gateway=g,
        evidence=e,
        driver=d,
        services=s,
        model=m,
        clock=lambda: clock[0],
    )
    yield worker, g, e, d, s, m, clock
    worker.close()


def test_real_auto_selection_lineage_delivery_followup_and_daily_cap(environment):
    w, g, e, d, s, m, clock = environment
    first = w.tick()
    assert first["phase"] == "COMPLETE"
    assert w.jobs()[0]["ideaId"] == e.snapshot()["candidates"][0]["ideaId"]
    assert [c["stage"] for c in m.calls] == ["select", "build", "acceptance", "review"]
    assert "NO_OP" in m.calls[0]["alternatives"]
    assert first["lastOutcome"]["revenueDelta"] is None
    assert w.tick()["phase"] == "COMPLETE"
    assert len(set(s.calls)) == 2
    assert w.tick()["phase"] == "DAILY_CAP"
    assert len(m.calls) == 8
    assert w.chain_valid()
    clock[0] += 86401
    assert w.tick()["phase"] == "COMPLETE"
    assert len(set(s.calls)) == 3
    before = len(m.calls)
    assert w.tick()["phase"] == "WAITING"
    assert len(m.calls) == before


def test_noop_idle_has_no_model_spam(environment):
    w, g, e, d, s, m, clock = environment
    m.noop = True
    assert w.tick()["phase"] == "WAITING"
    for _ in range(3):
        assert w.tick()["phase"] == "WAITING"
    assert len(m.calls) == 1
    assert not w.jobs() and not d.calls and not s.calls


@pytest.mark.parametrize(
    "mutation",
    [
        lambda g: g.workspace.update(autonomyMode="supervised"),
        lambda g: g.workspace.update(learningEnabled=False),
        lambda g: g.workspace.update(autonomyAcknowledged=False),
        lambda g: g.workspace["permissions"].update(workspaceWrite=False),
    ],
)
def test_full_switch_is_necessary_not_sufficient(environment, mutation):
    w, g, e, d, s, m, clock = environment
    mutation(g)
    expected = (
        "ERROR"
        if g.workspace["autonomyMode"] == "full"
        and not g.workspace["autonomyAcknowledged"]
        else "PAUSED"
    )
    assert w.tick()["phase"] == expected
    assert not m.calls and not d.calls


def test_wrong_owner_and_authority_drift_fail_closed(environment):
    w, g, e, d, s, m, clock = environment
    g.workspace["ownerUid"] = "different-owner"
    assert w.tick()["reason"] == "DELIVERY_DASHBOARD_IDENTITY"
    assert not m.calls
    g.workspace["ownerUid"] = "fixture-owner"
    path = w.home / "config/cct-owner-delivery.json"
    c = json.loads(path.read_text())
    c["authorization"] = "operator://changed"
    path.write_text(json.dumps(c))
    assert w.tick()["reason"] == "DELIVERY_IDENTITY_CHANGED"
    assert not m.calls


def test_pause_between_model_and_effect(environment):
    w, g, e, d, s, m, clock = environment
    original = m.__call__

    def pause(p):
        value = original(p)
        if p["stage"] == "build":
            g.workspace["learningEnabled"] = False
        return value

    w.model_override = pause
    assert w.tick()["phase"] == "PAUSED"
    assert not d.calls and w.jobs()[0]["bundle"]
    g.workspace["learningEnabled"] = True
    assert w.tick()["phase"] == "COMPLETE"
    assert len([c for c in m.calls if c["stage"] == "build"]) == 1


@pytest.mark.parametrize("revoke_at", ["publish", "readback"])
def test_pause_during_execution_projection_retains_bundle_without_effect(
    environment, monkeypatch, revoke_at
):
    w, g, e, d, s, m, clock = environment
    original_publish, original_read = g.publish, g.read

    def publish(collection, document, value):
        original_publish(collection, document, value)
        if revoke_at == "publish" and value.get("phase") == "EXECUTING":
            g.workspace["learningEnabled"] = False

    def read(collection, document="current"):
        value = original_read(collection, document)
        if (
            revoke_at == "readback"
            and collection == "cct_owner_delivery"
            and value.get("phase") == "EXECUTING"
        ):
            g.workspace["learningEnabled"] = False
        return value

    monkeypatch.setattr(g, "publish", publish)
    monkeypatch.setattr(g, "read", read)
    assert w.tick()["phase"] == "PAUSED"
    saved = w.jobs()[0]
    assert saved["bundle"] and saved["acceptance"] and saved["attempts"] == 1
    assert not d.calls and not s.calls
    monkeypatch.setattr(g, "publish", original_publish)
    monkeypatch.setattr(g, "read", original_read)
    g.workspace["learningEnabled"] = True
    assert w.tick()["phase"] == "COMPLETE"
    assert len(d.calls) == 1
    assert [c["stage"] for c in m.calls] == ["select", "build", "acceptance", "review"]


def test_failed_execution_replans_with_evidence_then_converges(environment):
    w, g, e, d, s, m, clock = environment
    d.fail = True
    assert w.tick()["phase"] == "RETRY"
    assert w.tick()["phase"] == "WAITING_RETRY"
    d.fail = False
    clock[0] += 2
    assert w.tick()["phase"] == "COMPLETE"
    builds = [c for c in m.calls if c["stage"] == "build"]
    assert builds[1]["previousFailure"]["code"] == "DELIVERY_LOCAL_VERIFICATION_FAILED"
    assert w.jobs()[0]["attempts"] == 2


def test_review_is_independent_and_bounded(environment):
    w, g, e, d, s, m, clock = environment
    m.reject = True
    assert w.tick()["phase"] == "RETRY"
    clock[0] += 4
    assert w.tick()["phase"] == "RETRY"
    clock[0] += 4
    assert w.tick()["phase"] == "BLOCKED"
    assert not s.calls
    assert len([x for x in m.calls if x["stage"] == "build"]) == 3


def test_notification_failure_does_not_rebuild(environment):
    w, g, e, d, s, m, clock = environment
    s.fail = True
    assert w.tick()["phase"] == "NOTIFY"
    assert len(d.calls) == 1
    s.fail = False
    clock[0] += 2
    assert w.tick()["phase"] == "COMPLETE"
    assert len(d.calls) == 1 and len(m.calls) == 4


def test_resume_persisted_job_without_reselection(environment):
    w, g, e, d, s, m, clock = environment
    with w.lock():
        job = w.select(e.snapshot())
    assert job["phase"] == "QUEUED"
    w2 = OwnerDelivery(
        w.home,
        gateway=g,
        evidence=e,
        driver=d,
        services=s,
        model=m,
        clock=lambda: clock[0],
    )
    try:
        assert w2.tick()["phase"] == "COMPLETE"
        assert len([c for c in m.calls if c["stage"] == "select"]) == 1
    finally:
        w2.close()


def test_overlapping_runners_cannot_duplicate_effects(environment):
    w, g, e, d, s, m, clock = environment
    with w.lock():
        w2 = OwnerDelivery(
            w.home,
            gateway=g,
            evidence=e,
            driver=d,
            services=s,
            model=m,
            clock=lambda: clock[0],
        )
        try:
            assert w2.tick()["phase"] == "BUSY"
        finally:
            w2.close()
    assert not m.calls and not s.calls


def test_event_chain_tamper_blocks_next_execution(environment):
    w, g, e, d, s, m, clock = environment
    assert w.tick()["phase"] == "COMPLETE"
    with w.db:
        w.db.execute("UPDATE events SET data='{}' WHERE id=1")
    count = len(m.calls)
    assert w.tick()["reason"] == "DELIVERY_EVENT_CHAIN_INVALID"
    assert len(m.calls) == count


def test_daily_model_cap_is_durable_and_holds_saved_stage(environment):
    w, g, e, d, s, m, clock = environment
    c = json.loads((w.home / "config/cct-owner-delivery.json").read_text())
    c["maxDailyModelCalls"] = 1
    (w.home / "config/cct-owner-delivery.json").write_text(json.dumps(c))
    assert w.tick()["phase"] == "DAILY_CAP"
    assert len(m.calls) == 1
    assert w.jobs()[0]["phase"] == "QUEUED" and w.jobs()[0]["attempts"] == 0
    assert w.tick()["phase"] == "DAILY_CAP"
    assert len(m.calls) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"action": "PUBLISH"},
        {"ideaId": "foreign"},
        {"reportIds": ["forged"]},
        {"why": ""},
        {"extra": "authority"},
    ],
)
def test_model_selection_contract_rejects_authority_and_lineage_invention(change):
    evidence = Evidence().snapshot()
    p = {"stage": "select", **evidence}
    value = Model()(p)
    value.update(change)
    with pytest.raises(ValueError):
        validate(value, p)


@pytest.mark.parametrize(
    "result",
    [
        {"accepted": True, "issues": ["bad"]},
        {"accepted": False, "issues": []},
        {"accepted": 1, "issues": []},
    ],
)
def test_review_cannot_claim_success_with_issues(result):
    with pytest.raises(ValueError):
        validate(result, {"stage": "review"})


def test_projection_outage_preserves_completed_job_and_outcome(environment):
    w, g, e, d, s, m, clock = environment
    publish = g.publish

    def unavailable(collection, document, value):
        if collection == "cct_owner_delivery":
            raise OSError("fixture delivery-status outage")
        return publish(collection, document, value)

    g.publish = unavailable
    result = w.tick()
    assert result["phase"] == "COMPLETE" and result["projection"] == "UNAVAILABLE"
    assert w.jobs()[0]["phase"] == "COMPLETE"
    assert w.meta("lastOutcome")["jobId"] == w.jobs()[0]["id"]
    assert w.chain_valid() and len(d.calls) == 1


@pytest.mark.parametrize(
    "invalid",
    [
        {"verification": "VERIFIED"},
        {"verification": {"status": "VERIFIED"}},
        {"verification": {"status": "passed", "testCount": 0}},
    ],
)
def test_incomplete_local_receipt_cannot_complete(environment, invalid):
    w, g, e, d, s, m, clock = environment
    d.run = lambda *args, **kwargs: invalid
    assert w.tick()["phase"] == "RETRY"
    assert not s.calls


def test_real_local_and_service_driver_integration(tmp_path):
    """Real sandbox + SQLite services; fixture model and in-memory Firestore only."""
    from cct_agent.owner_delivery_services import ServiceDispatcher
    from cct_agent.owner_delivery_local import LocalDeliveryDriver
    from cct_agent.owner_workspace import ANSWER_CHOICES, PERMISSION_KEYS

    home = tmp_path / "home"
    c = config(home)
    c["services"] = {"ownerNotificationsEnabled": True}
    (home / "config/cct-owner-delivery.json").write_text(json.dumps(c))
    g = Gateway()
    g.project_id = c["projectId"]
    g.workspace.update(
        schemaVersion="cct.owner_workspace.v1",
        revision=1,
        updatedAt=datetime(2026, 9, 14, tzinfo=timezone.utc),
        permissions={k: True for k in PERMISSION_KEYS},
        answers={k: "" for k in ANSWER_CHOICES},
        decisions={},
    )
    documents = {("cct_workspace", "current"): g.workspace}
    g.read = lambda collection, document="current": copy.deepcopy(
        documents.get((collection, document))
    )
    g.publish = lambda collection, document, value: documents.update(
        {(collection, document): copy.deepcopy(value)}
    )
    m = Model()
    w = OwnerDelivery(home, gateway=g, evidence=Evidence(), model=m)
    try:
        assert isinstance(w.driver, LocalDeliveryDriver) and isinstance(
            w.services, ServiceDispatcher
        )
        result = w.tick()
        assert result["phase"] == "COMPLETE", result
        assert result["projection"] == "VERIFIED"
        job = w.jobs()[0]
        assert Path(job["artifactRoot"], "app.py").is_file()
        assert job["verification"]["testCount"] > 0
        assert job["notification"]["readVerified"] is True
        assert len([key for key in documents if key[0] == "cct_owner_messages"]) == 1
        assert w.chain_valid()
    finally:
        w.close()


def test_regular_file_rejects_unsafe_paths_and_modes(tmp_path):
    source = tmp_path / "source"
    source.write_text("fixture")
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="SYMLINK"):
        regular(link)
    source.chmod(0o666)
    with pytest.raises(ValueError, match="WRITABLE"):
        regular(source)


@pytest.mark.parametrize("checkpoint", ["EXECUTING", "REVIEWING"])
@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("control read timed out"),
        PermissionError("control denied"),
        RuntimeError("DELIVERY_DASHBOARD_IDENTITY"),
        RuntimeError("DELIVERY_PAUSED"),
    ],
)
def test_control_failure_retains_checkpoint_and_resumes_after_restart(
    environment, checkpoint, error
):
    w, g, e, d, s, m, clock = environment
    original_gate = w.gate
    failed = False

    def gate():
        nonlocal failed
        if not failed and w.jobs() and w.jobs()[0]["phase"] == checkpoint:
            failed = True
            raise error
        return original_gate()

    w.gate = gate
    result = w.tick()
    assert failed
    assert result["phase"] == (
        "PAUSED" if str(error) == "DELIVERY_PAUSED" else checkpoint
    )
    saved = w.jobs()[0]
    assert saved["phase"] == checkpoint and saved["bundle"] == bundle()
    assert saved["attempts"] == 1 and not s.calls
    if checkpoint == "REVIEWING":
        assert saved["execution"]["status"] == "completed"
        assert saved["verification"]["status"] == "passed"
        assert len(d.calls) == 1
    else:
        assert not d.calls
    clock[0] += 4
    resumed = OwnerDelivery(
        w.home,
        gateway=g,
        evidence=e,
        driver=d,
        services=s,
        model=m,
        clock=lambda: clock[0],
    )
    try:
        assert resumed.tick()["phase"] == "COMPLETE"
        assert [p["stage"] for p in m.calls] == [
            "select",
            "build",
            "acceptance",
            "review",
        ]
        assert len(d.calls) == 1 and len(s.calls) == 1
        assert resumed.jobs()[0]["attempts"] == 1
        assert resumed.chain_valid()
    finally:
        resumed.close()


@pytest.mark.parametrize("failure", ["timeout", "invalid_response"])
def test_review_dependency_retries_are_bounded_without_rebuild(environment, failure):
    w, g, e, d, s, m, clock = environment
    original_model = w.model_override
    review_calls = []

    def model(payload):
        if payload["stage"] == "review":
            review_calls.append(payload)
            if failure == "timeout":
                raise TimeoutError("review unavailable")
            return {"accepted": "invalid", "issues": []}
        return original_model(payload)

    w.model_override = model
    for phase in ["REVIEWING", "REVIEWING", "BLOCKED"]:
        assert w.tick()["phase"] == phase
        saved = w.jobs()[0]
        assert (
            saved["bundle"] == bundle() and saved["execution"]["status"] == "completed"
        )
        assert saved["attempts"] == 1
        if phase != "BLOCKED":
            assert w.tick()["phase"] == "WAITING_RETRY"
        clock[0] += 4
    assert saved["recoveryAttempts"] == w.config["maxAttempts"]
    assert len(review_calls) == 3 and len(d.calls) == 1 and not s.calls
    assert [p["stage"] for p in m.calls] == ["select", "build", "acceptance"]


def test_control_failure_recovery_budget_retains_verified_artifact(environment):
    w, g, e, d, s, m, clock = environment
    original_gate = w.gate

    def gate():
        if w.jobs() and w.jobs()[0]["phase"] == "REVIEWING":
            raise TimeoutError("control read timed out")
        return original_gate()

    w.gate = gate
    assert w.tick()["phase"] == "REVIEWING"
    # Exercise the execute entry gate independently of tick's read-only preflight.
    for phase in ["REVIEWING", "BLOCKED"]:
        clock[0] += 4
        assert w.execute(w.jobs()[0])["phase"] == phase
    saved = w.jobs()[0]
    assert saved["bundle"] == bundle() and saved["execution"]["status"] == "completed"
    assert saved["recoveryAttempts"] == 3 and saved["attempts"] == 1
    assert len(d.calls) == 1 and not s.calls


@pytest.mark.parametrize(
    "reason",
    [
        "SANDBOX_UNAVAILABLE",
        "LOCAL_IO_OR_STATE_ERROR",
        "UNSAFE_LOCK",
        "UNKNOWN_DEPENDENCY_DENIAL",
    ],
)
def test_driver_dependency_receipt_retains_bundle_and_bounds_retry(environment, reason):
    w, g, e, d, s, m, clock = environment
    original_run = d.run

    def unavailable(*args, **kwargs):
        result = original_run(*args, **kwargs)
        result.update(status="blocked", reason=reason)
        result["verification"]["status"] = "blocked"
        return result

    d.run = unavailable
    for phase in ["EXECUTING", "EXECUTING", "BLOCKED"]:
        assert w.tick()["phase"] == phase
        clock[0] += 4
    saved = w.jobs()[0]
    assert saved["bundle"] == bundle() and saved["attempts"] == 1
    assert len({job_id for job_id, _ in d.calls}) == 1
    assert len(d.calls) == 3 and not s.calls
    assert [p["stage"] for p in m.calls] == ["select", "build", "acceptance"]


def test_acceptance_failure_discards_only_failed_attempt_evidence(environment):
    w, g, e, d, s, m, clock = environment
    m.reject = True
    assert w.tick()["phase"] == "RETRY"
    saved = w.jobs()[0]
    assert all(
        field not in saved
        for field in ("bundle", "execution", "review", "verification", "artifactRoot")
    )
    assert saved["previousFailure"]["review"]["accepted"] is False
    m.reject = False
    clock[0] += 4
    assert w.tick()["phase"] == "COMPLETE"
    assert [p["stage"] for p in m.calls] == [
        "select",
        "build",
        "acceptance",
        "review",
        "build",
        "acceptance",
        "review",
    ]
    assert len(d.calls) == 2 and len(s.calls) == 1


def test_persisted_accepted_review_resumes_without_driver_or_model_even_at_cap(
    environment,
):
    w, g, e, d, s, m, clock = environment
    job = w.select(e.snapshot())
    value = w.model(
        "build",
        {"selection": job["selection"], "idea": job["idea"], "reports": job["reports"]},
        job["id"],
    )
    plan = w.model(
        "acceptance", {"selection": job["selection"], "bundle": value}, job["id"]
    )
    execution = d.run(job["id"] + "-a1", value, acceptance=plan)
    review = w.model(
        "review",
        {
            "selection": job["selection"],
            "idea": job["idea"],
            "bundle": value,
            "execution": execution,
            "reports": job["reports"],
        },
        job["id"],
    )
    job.update(
        phase="REVIEWING",
        attempts=1,
        bundle=value,
        acceptance=plan,
        execution=execution,
        verification=execution["verification"],
        artifactRoot=execution["artifactRoot"],
        review=review,
    )
    w.save(job)
    path = w.home / "config/cct-owner-delivery.json"
    c = json.loads(path.read_text())
    c["maxDailyModelCalls"] = 4
    path.write_text(json.dumps(c))
    assert w.tick()["phase"] == "COMPLETE"
    assert len(m.calls) == 4 and len(d.calls) == 1 and len(s.calls) == 1


def test_build_provider_failure_is_bounded_without_driver_effects(environment):
    w, g, e, d, s, m, clock = environment
    m.fail_build = True
    for phase in ["BUILDING", "BUILDING", "BLOCKED"]:
        assert w.tick()["phase"] == phase
        clock[0] += 4
    assert w.jobs()[0]["attempts"] == 3
    assert len([p for p in m.calls if p["stage"] == "build"]) == 3
    assert not d.calls and not s.calls
