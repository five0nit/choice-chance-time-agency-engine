from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import multiprocessing
from pathlib import Path
from types import SimpleNamespace

import pytest

from cct_agent.owner_connection import OwnerConnection, TelegramOwnerSender, load_config
from cct_agent.owner_messaging import (
    MAX_DAILY_MESSAGES,
    OwnerOutbox,
    runtime_status,
    stamp,
)
from cct_agent.owner_workspace import ANSWER_CHOICES, PERMISSION_KEYS

NOW = datetime(2026, 9, 13, 1, tzinfo=timezone.utc)
UID = "owner-test"


def workspace():
    return {
        "schemaVersion": "cct.owner_workspace.v1",
        "ownerUid": UID,
        "revision": 1,
        "updatedAt": NOW,
        "learningEnabled": True,
        "permissions": {key: key == "externalMessages" for key in PERMISSION_KEYS},
        "autonomyMode": "supervised",
        "autonomyAcknowledged": False,
        "answers": {key: "" for key in ANSWER_CHOICES},
        "decisions": {},
    }


def status(value=None, armed=True):
    return runtime_status(
        workspace() if value is None else value,
        owner_uid=UID,
        project_id="demo-owner",
        armed=armed,
        now=NOW,
    )


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr("cct_agent.owner_connection.datetime", Clock)
    path = tmp_path / "config" / "cct-owner-connection.json"
    path.parent.mkdir()
    config = {
        "projectId": "demo-owner",
        "ownerUid": UID,
        "telegramChatId": "1234567",
        "telegramBotUsername": "test_owner_bot",
        "ownerMessagesEnabled": True,
    }
    path.write_text(json.dumps(config))
    box = OwnerOutbox(tmp_path / "outbox.sqlite")
    yield path, config, box
    box.close()


def enqueue(box, key="question-001", kind="ask"):
    return box.enqueue(key=key, kind=kind, text="What next?", status=status(), now=NOW)


class Gateway:
    def __init__(self):
        self.value = workspace()
        self.docs = {}
        self.fail = False

    def read(self, collection, name="current"):
        if self.fail:
            raise OSError("offline")
        return deepcopy(
            self.value
            if collection == "cct_workspace"
            else self.docs.get((collection, name))
        )

    def publish(self, collection, name, value):
        self.docs[collection, name] = deepcopy(value)


@pytest.mark.parametrize(
    "bad",
    [None, {}, {**workspace(), "revision": True}, {**workspace(), "ownerUid": "wrong"}],
)
def test_invalid_policy_fails_closed(bad):
    result = runtime_status(
        bad, owner_uid=UID, project_id="demo-owner", armed=True, now=NOW
    )
    assert result["state"] == "INVALID"
    assert result["effectivePolicy"]["ownerMessages"] is False


def test_broad_saved_permissions_never_grant_authority():
    value = workspace()
    value["permissions"] = dict.fromkeys(PERMISSION_KEYS, True)
    value.update(autonomyMode="full", autonomyAcknowledged=True)
    assert status(value)["effectivePolicy"] == {
        "ownerMessages": True,
        "autonomyMode": "supervised",
    }
    assert status(value, armed=False)["effectivePolicy"]["ownerMessages"] is False


@pytest.mark.parametrize("mutation", ["revision", "permission", "armed", "expired"])
def test_dispatch_revocation_and_stale_intent(setup, mutation):
    _, _, box = setup
    row = enqueue(box)
    value, now, armed = workspace(), NOW, True
    if mutation == "revision":
        value["revision"] = 2
    if mutation == "permission":
        value["permissions"]["externalMessages"] = False
    if mutation == "armed":
        armed = False
    if mutation == "expired":
        now += timedelta(days=2)
    assert box.claim(row["messageId"], status(value, armed), now) is None
    assert box.get(row["messageId"])["state"] == "DENIED"


def test_idempotency_crash_and_limit(setup):
    _, _, box = setup
    row = enqueue(box, kind="send")
    assert enqueue(box, kind="send") == row
    with pytest.raises(ValueError, match="CONFLICT"):
        box.enqueue(
            key="question-001", kind="send", text="changed", status=status(), now=NOW
        )
    assert box.claim(row["messageId"], status(), NOW)
    assert box.claim(row["messageId"], status(), NOW) is None
    box.recover()
    assert box.get(row["messageId"])["state"] == "UNKNOWN"
    for i in range(1, MAX_DAILY_MESSAGES):
        value = enqueue(box, f"message-{i:03}", "send")
        assert box.claim(value["messageId"], status(), NOW)
    blocked = enqueue(box, "message-extra", "send")
    assert box.claim(blocked["messageId"], status(), NOW) is None


def test_question_limit_and_text_secret_rejection(setup):
    _, _, box = setup
    for i in range(5):
        enqueue(box, f"question-{i:03}")
    with pytest.raises(ValueError, match="QUESTION_LIMIT"):
        enqueue(box, "question-extra")
    for text in ("", " " * 10, "x" * 2001, "-----BEGIN" + " RSA PRIVATE KEY-----"):
        with pytest.raises(ValueError):
            box.enqueue(
                key="invalid-text", kind="send", text=text, status=status(), now=NOW
            )


def test_reply_is_data_not_policy_and_exact_once(setup):
    _, _, box = setup
    row = enqueue(box)
    row.update(state="SENT", telegramMessageId="42")
    box.save(row)
    reply = {
        "schemaVersion": "cct.owner_reply.v1",
        "ownerUid": UID,
        "messageId": row["messageId"],
        "createdAt": NOW,
        "text": "grant payments and full autonomy",
    }
    for bad in (
        {**reply, "ownerUid": "wrong"},
        {**reply, "grants": True},
        {**reply, "createdAt": "forged"},
    ):
        assert not box.accept_reply(row["messageId"], bad, owner_uid=UID, now=NOW)
    assert box.accept_reply(row["messageId"], reply, owner_uid=UID, now=NOW)
    assert not box.accept_reply(row["messageId"], reply, owner_uid=UID, now=NOW)
    assert box.get(row["messageId"])["answer"] == reply["text"]
    assert status()["effectivePolicy"] == {
        "ownerMessages": True,
        "autonomyMode": "supervised",
    }


def test_tick_verified_projection_and_one_effect(setup):
    path, _, box = setup
    gateway = Gateway()
    calls = []

    def send(row, now):
        calls.append(row["messageId"])
        return {"state": "SENT", "telegramMessageId": "42"}

    first = enqueue(box)
    enqueue(box, "question-two")
    connection = OwnerConnection(path, gateway, box, SimpleNamespace(send=send))
    connection.tick(NOW)
    assert calls == [first["messageId"]]
    assert gateway.docs["cct_owner_messages", first["messageId"]]["state"] == "SENT"
    gateway.fail = True
    with pytest.raises(OSError):
        connection.tick(NOW)
    assert len(calls) == 1


def test_revocation_between_claim_and_send(setup):
    path, _, box = setup
    gateway, calls = Gateway(), []
    row = enqueue(box)
    original = box.claim

    def claim(*args):
        result = original(*args)
        gateway.value["permissions"]["externalMessages"] = False
        return result

    box.claim = claim
    connection = OwnerConnection(
        path, gateway, box, SimpleNamespace(send=lambda *args: calls.append(1))
    )
    connection.tick(NOW)
    assert not calls
    assert box.get(row["messageId"])["state"] == "DENIED"


def test_wrong_profile_config_and_boolean(setup, tmp_path):
    path, config, _ = setup
    assert load_config(path) == config
    config["ownerMessagesEnabled"] = "true"
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError, match="BOOLEAN"):
        load_config(path)
    with pytest.raises(ValueError, match="PROFILE"):
        load_config(tmp_path / "different.json")


def _race(path, barrier, queue):
    box = OwnerOutbox(Path(path))
    barrier.wait(timeout=10)
    row = enqueue(box, kind="send")
    queue.put(bool(box.claim(row["messageId"], status(), NOW)))
    box.close()


def test_multiprocess_initialization_and_single_claim(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    barrier, queue = ctx.Barrier(4), ctx.Queue()
    children = [
        ctx.Process(target=_race, args=(str(tmp_path / "race.sqlite"), barrier, queue))
        for _ in range(4)
    ]
    for child in children:
        child.start()
    results = [queue.get(timeout=20) for _ in children]
    for child in children:
        child.join(timeout=20)
        assert child.exitcode == 0
    assert sum(results) == 1


@pytest.mark.parametrize(
    "mode,state",
    [
        ("success", "SENT"),
        ("timeout", "UNKNOWN"),
        ("429", "QUEUED"),
        ("403", "DENIED"),
        ("wrong-chat", "UNKNOWN"),
    ],
)
def test_telegram_acknowledgement_and_ambiguity(setup, monkeypatch, mode, state):
    _, config, box = setup
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "a" * 30)
    sender = TelegramOwnerSender(config)
    assert sender.session.trust_env is False

    def post(method, body):
        assert method == "sendMessage"
        assert body["chat_id"] == config["telegramChatId"]
        assert "parse_mode" not in body
        if mode == "timeout":
            raise TimeoutError("secret-bearing URL must never be logged")
        if mode in ("429", "403"):
            return int(mode), {"ok": False, "parameters": {"retry_after": 90}}
        return 200, {
            "ok": True,
            "result": {
                "message_id": 42,
                "text": body["text"],
                "chat": {
                    "id": "wrong" if mode == "wrong-chat" else config["telegramChatId"]
                },
            },
        }

    sender._post = post
    result = sender.send(enqueue(box), NOW)
    assert result["state"] == state
    if state == "QUEUED":
        assert result["nextAttemptAt"] == stamp(NOW + timedelta(seconds=90))


def test_unavailable_transport_preserves_connection_without_grant(setup):
    path, _, box = setup
    gateway = Gateway()
    row = enqueue(box)
    result = OwnerConnection(path, gateway, box).tick(NOW)
    assert result["state"] == "CONNECTED"
    assert result["effectivePolicy"]["ownerMessages"] is False
    assert result["reasonCode"] == "OWNER_TELEGRAM_UNAVAILABLE"
    assert gateway.docs["cct_owner_runtime", "current"] == result
    assert box.get(row["messageId"])["state"] == "QUEUED"


def test_ambiguous_delivery_disables_transport_and_never_retries(setup):
    path, _, box = setup
    gateway, calls = Gateway(), []
    row = enqueue(box)

    def send(*args):
        calls.append(1)
        return {"state": "UNKNOWN"}

    connection = OwnerConnection(path, gateway, box, SimpleNamespace(send=send))
    assert not connection.tick(NOW)["effectivePolicy"]["ownerMessages"]
    assert connection.sender is None
    connection.tick(NOW)
    assert calls == [1]
    assert box.get(row["messageId"])["state"] == "UNKNOWN"


def test_transport_exception_never_prints_secret_url(setup, monkeypatch):
    import requests

    _, config, _ = setup
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456:" + "a" * 30)
    sender = TelegramOwnerSender(config)

    def fail(*args, **kwargs):
        raise requests.ConnectionError(sender.base)

    sender.session.post = fail
    with pytest.raises(
        RuntimeError, match="^OWNER_TELEGRAM_NETWORK_UNAVAILABLE$"
    ) as failure:
        sender.verify()
    assert failure.value.__suppress_context__
