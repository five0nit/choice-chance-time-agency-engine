"""Focused promotion checks; isolated SQLite, no owner/cloud/model/web effects."""

from datetime import timedelta
from unittest.mock import Mock

import pytest

from cct_agent import owner_work as work
from cct_agent.owner_work_model import validate


@pytest.fixture
def worker(tmp_path, monkeypatch):
    monkeypatch.setattr(
        work,
        "load_config",
        lambda _: {"ownerUid": "owner", "projectId": "demo-promotions"},
    )
    monkeypatch.setattr(
        work,
        "dialogue_config",
        lambda _: {"conversationId": "conversation", "enabled": True},
    )
    monkeypatch.setattr(work, "FirebaseOwnerGateway", lambda _: Mock())
    instance = work.OwnerWork(tmp_path)
    documents = {}
    instance.gateway.publish.side_effect = lambda collection, name, value: (
        documents.update({(collection, name): value})
    )
    instance.gateway.read.side_effect = lambda collection, name="current": (
        documents.get((collection, name))
    )
    instance.gate = lambda: {"authorization": "operator://isolated-fixture"}
    instance.ingest_promotions = lambda config: None
    instance.snapshot = lambda turn_id=None: {
        "turnId": turn_id or "q-" + "a" * 32,
        "turnCreatedAt": work.stamp(work.now() - timedelta(hours=1)),
        "history": [{"questionId": "q-" + "f" * 32, "answer": "isolated test fixture"}],
        "workIdeas": [
            {
                "title": "Exact idea",
                "firstStep": "Research this exact objective",
                "sourceAnswerIds": ["q-" + "f" * 32],
                "readiness": "DRAFT_ONLY",
            }
        ],
    }
    yield instance
    instance.close()


def request(worker, digit="a"):
    turn = "q-" + digit * 32
    return "promote-" + digit * 32 + "-0", {
        "schemaVersion": "cct.work_request.v1",
        "ownerUid": "owner",
        "conversationId": "conversation",
        "turnId": turn,
        "ideaIndex": 0,
        "idea": worker.snapshot(turn)["workIdeas"][0],
        "scope": "PUBLIC_RESEARCH_PRIVATE_REPORT",
        "state": "PENDING",
        "createdAt": work.now(),
    }


def test_exact_idea_dedup_and_same_day_serial_launch(worker):
    key, value = request(worker)
    first = worker.accept_promotion(key, value, worker.gate())
    assert worker.accept_promotion(key, value, worker.gate())["id"] == first["id"]
    key2, value2 = request(worker, "b")
    second = worker.accept_promotion(key2, value2, worker.gate())
    launched = []

    def finish(job, _):
        launched.append(job)
        job.update(
            phase="COMPLETE", reason="Isolated trigger check; no research executed"
        )
        worker.save(job)
        return job

    worker.execute = finish
    assert worker.tick()["id"] == first["id"]
    assert worker.tick()["id"] == second["id"]
    worker.tick()
    assert [j["discovery"]["workIdeas"] for j in launched] == [
        [value["idea"]],
        [value2["idea"]],
    ]
    assert (
        len(launched)
        == worker.db.execute("SELECT count(*) FROM jobs").fetchone()[0]
        == 2
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("ownerUid", "other"),
        ("scope", "TRADE"),
        ("ideaIndex", True),
        ("idea", {"title": "Changed"}),
        ("createdAt", "not a server timestamp"),
    ],
)
def test_changed_request_is_rejected(worker, field, value):
    key, payload = request(worker)
    with pytest.raises(ValueError):
        worker.accept_promotion(key, {**payload, field: value}, worker.gate())
    assert worker.db.execute("SELECT count(*) FROM jobs").fetchone()[0] == 0


def test_restart_preserves_queue_but_does_not_replay_uncertain_effect(worker):
    key, value = request(worker)
    queued = worker.accept_promotion(key, value, worker.gate())
    key2, value2 = request(worker, "b")
    active = worker.accept_promotion(key2, value2, worker.gate())
    active.update(phase="FETCHING", reason="uncertain effect")
    worker.save(active)
    restarted = work.OwnerWork(worker.home)
    try:
        phases = dict(restarted.db.execute("SELECT id,phase FROM jobs"))
        assert phases == {queued["id"]: "QUEUED", active["id"]: "BLOCKED"}
    finally:
        restarted.close()


def test_publication_failure_retries_only_receipt(worker):
    key, value = request(worker)
    worker.accept_promotion(key, value, worker.gate())
    worker.gateway.publish.side_effect = RuntimeError("network")
    with pytest.raises(RuntimeError):
        worker.flush_receipts()
    assert not worker.db.execute(
        "SELECT 1 FROM meta WHERE key LIKE 'receipt:%'"
    ).fetchone()
    worker.gateway.publish.side_effect = None
    worker.flush_receipts()
    worker.flush_receipts()
    assert worker.gateway.publish.call_count == 2


def test_model_cannot_substitute_objective(worker):
    idea = worker.snapshot()["workIdeas"][0]
    data = {
        "stage": "select",
        "discovery": worker.snapshot(),
        "catalog": [{"id": "source"}],
        "promotedIdea": idea,
    }
    selected = {
        "title": idea["title"],
        "objective": idea["firstStep"],
        "sourceAnswerIds": idea["sourceAnswerIds"],
        "sourceIds": ["source"],
        "doneWhen": "Concrete cited report",
    }
    validate(selected, data)
    with pytest.raises(ValueError, match="WORK_PROMOTED_IDEA_CHANGED"):
        validate({**selected, "objective": "Unrelated task"}, data)


def test_pause_does_not_dequeue(worker):
    key, value = request(worker)
    worker.accept_promotion(key, value, worker.gate())
    worker.gate = Mock(side_effect=RuntimeError("WORK_PAUSED"))
    worker.publish = Mock()
    worker.tick()
    assert worker.publish.call_args.args[2] == "PAUSED"
    assert worker.db.execute("SELECT phase FROM jobs").fetchone()[0] == "QUEUED"
