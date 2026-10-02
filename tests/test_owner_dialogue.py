"""Isolated interview fixtures: no live model, Firebase, Telegram or owner replies."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from io import StringIO
import json
import sys
from types import ModuleType, SimpleNamespace

import pytest

from cct_agent import owner_dialogue as dialogue
from cct_agent import owner_dialogue_model as model
from cct_agent.owner_connection import OwnerConnection
from cct_agent.owner_workspace import ANSWER_CHOICES, PERMISSION_KEYS

NOW = datetime(2026, 9, 13, 1, tzinfo=timezone.utc)
UID = "owner-test"


@pytest.fixture
def interview(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(dialogue, "now", lambda: NOW)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr("cct_agent.owner_connection.datetime", Clock)
    config = tmp_path / "config"
    config.mkdir()
    (tmp_path / "owner-connection").mkdir()
    (config / "cct-owner-connection.json").write_text(
        json.dumps(
            {
                "projectId": "demo-owner",
                "ownerUid": UID,
                "telegramChatId": "1234567",
                "telegramBotUsername": "test_owner_bot",
                "ownerMessagesEnabled": True,
            }
        )
    )
    (config / "cct-owner-dialogue.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "conversationId": "fixture-discovery",
                "modelPython": sys.executable,
            }
        )
    )
    state = SimpleNamespace(
        home=tmp_path,
        calls=[],
        decisions=[],
        sent=[],
        docs={},
        workspace={
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
        },
    )

    def read(collection, name="current"):
        return deepcopy(
            state.workspace
            if collection == "cct_workspace"
            else state.docs.get((collection, name))
        )

    def publish(collection, name, value):
        state.docs[collection, name] = deepcopy(value)

    state.gateway = SimpleNamespace(read=read, publish=publish)
    monkeypatch.setattr(dialogue, "FirebaseOwnerGateway", lambda project: state.gateway)

    def generate(command, **kwargs):
        assert command[0] == sys.executable
        assert kwargs["env"]["HERMES_HOME"] == str(tmp_path)
        assert kwargs["timeout"] == 150
        state.calls.append(json.loads(kwargs["input"]))
        decision = (
            state.decisions.pop(0)
            if state.decisions
            else {"kind": "ask", "text": "Fixture: which customer?"}
        )
        if callable(decision):
            decision = decision()
        return SimpleNamespace(returncode=0, stdout=json.dumps(decision))

    monkeypatch.setattr(dialogue.subprocess, "run", generate)
    state.worker = dialogue.OwnerDialogue(tmp_path)

    def send(row, now):
        state.sent.append(row["messageId"])
        return {"state": "SENT", "telegramMessageId": str(len(state.sent))}

    state.connection = OwnerConnection(
        config / "cct-owner-connection.json",
        state.gateway,
        state.worker.outbox,
        SimpleNamespace(send=send),
    )
    yield state
    state.worker.close()


def answer(state, message_id, text="Fixture only: I can serve an existing customer."):
    state.docs["cct_owner_replies", message_id] = {
        "schemaVersion": "cct.owner_reply.v1",
        "ownerUid": UID,
        "messageId": message_id,
        "createdAt": NOW,
        "text": text,
    }
    state.connection.tick(NOW)


def test_answer_advances_once_then_proposal_waits(interview):
    s = interview
    first = s.worker.tick()
    assert first["state"] == "AWAITING_DELIVERY"
    assert s.worker.tick()["messageId"] == first["messageId"]
    s.connection.tick(NOW)
    assert s.worker.tick()["state"] == "AWAITING_REPLY"
    assert len(s.calls) == 1
    answer(s, first["messageId"])
    s.decisions.append(
        {
            "kind": "propose",
            "text": "Fixture draft: offer the existing customer a paid service.",
        }
    )
    second = s.worker.tick()
    assert second["answersConsumed"] == 1
    assert s.calls[-1]["conversation"] == [
        {
            "question": "Fixture: which customer?",
            "answer": "Fixture only: I can serve an existing customer.",
        }
    ]
    s.connection.tick(NOW)
    for _ in range(2):
        result = s.worker.tick()
        assert result["state"] == "AWAITING_APPROVAL"
        assert result["executionEnabled"] is False
    assert len(s.calls) == len(s.sent) == 2
    assert (
        "Nothing has been started." in s.worker.outbox.get(second["messageId"])["text"]
    )


@pytest.mark.parametrize("gate", ["learning", "permission", "host"])
def test_pause_does_not_call_model_or_enqueue(interview, gate):
    s = interview
    if gate == "learning":
        s.workspace["learningEnabled"] = False
    elif gate == "permission":
        s.workspace["permissions"]["externalMessages"] = False
    else:
        path = s.home / "config/cct-owner-dialogue.json"
        value = json.loads(path.read_text())
        path.write_text(json.dumps({**value, "enabled": False}))
    assert s.worker.tick()["state"] == "PAUSED"
    assert s.calls == s.worker.outbox.rows() == []


def test_workspace_change_during_model_call_discards_output(interview):
    s = interview

    def changed():
        s.workspace["revision"] += 1
        return {"kind": "ask", "text": "Fixture stale output"}

    s.decisions.append(changed)
    assert (
        s.worker.tick()["reason"]
        == "OWNER_DIALOGUE_WORKSPACE_CHANGED_DURING_GENERATION"
    )
    assert s.worker.outbox.rows() == []
    assert s.worker.db.execute("SELECT count(*) FROM turns").fetchone()[0] == 0


def test_current_ambiguous_delivery_blocks_but_new_revision_supersedes(interview):
    s = interview
    first = s.worker.tick()
    row = s.worker.outbox.get(first["messageId"])
    row.update(state="UNKNOWN", reasonCode="FIXTURE_AMBIGUOUS")
    s.worker.outbox.save(row)
    assert s.worker.tick()["state"] == "BLOCKED"
    assert len(s.calls) == 1
    s.workspace["revision"] += 1
    second = s.worker.tick()
    assert second["messageId"] != first["messageId"]
    assert second["answersConsumed"] == 0
    assert s.calls[-1]["conversation"] == []
    assert s.worker.outbox.get(first["messageId"])["state"] == "UNKNOWN"


def test_restart_recovers_persisted_output_without_second_model_call(
    interview, monkeypatch
):
    s = interview

    def failed_enqueue(**kwargs):
        raise OSError("fixture crash after durable model output")

    monkeypatch.setattr(s.worker.outbox, "enqueue", failed_enqueue)
    with pytest.raises(OSError):
        s.worker.tick()
    s.worker.close()
    s.worker = dialogue.OwnerDialogue(s.home)
    assert s.worker.tick()["state"] == "AWAITING_DELIVERY"
    assert len(s.calls) == len(s.worker.outbox.rows()) == 1


@pytest.mark.parametrize(
    "decision",
    [
        {"kind": "execute", "text": "bad"},
        {"kind": "ask", "text": ""},
        {"kind": "ask", "text": "question", "tools": ["terminal"]},
    ],
)
def test_invalid_model_output_never_enqueues(interview, decision):
    s = interview
    s.decisions.append(decision)
    with pytest.raises(ValueError):
        s.worker.tick()
    assert s.worker.outbox.rows() == []


def test_failed_turn_attempt_budget_persists(interview):
    s = interview
    for _ in range(3):
        s.decisions.append({"kind": "execute", "text": "fixture invalid"})
        with pytest.raises(ValueError):
            s.worker.tick()
    s.worker.close()
    s.worker = dialogue.OwnerDialogue(s.home)
    assert s.worker.tick()["reason"] == "OWNER_DIALOGUE_MODEL_ATTEMPT_LIMIT"
    assert len(s.calls) == 3


def test_expired_question_does_not_trigger_more_generation(interview, monkeypatch):
    s = interview
    first = s.worker.tick()
    s.connection.tick(NOW)
    monkeypatch.setattr(dialogue, "now", lambda: NOW + timedelta(days=2))
    assert s.worker.tick()["reason"] == "OWNER_DIALOGUE_QUESTION_EXPIRED"
    assert len(s.calls) == 1
    assert s.worker.outbox.get(first["messageId"])["answer"] is None


@pytest.mark.parametrize("tool_calls", [None, [{"name": "terminal"}]])
def test_model_adapter_uses_own_config_without_tools(
    tmp_path, monkeypatch, capsys, tool_calls
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        json.dumps({"model": {"provider": "fixture", "default": "fixture-model"}})
    )
    monkeypatch.setattr(sys, "stdin", StringIO('{"conversation":[]}'))
    requests = []
    module = ModuleType("agent.auxiliary_client")

    def call_llm(**kwargs):
        requests.append(kwargs)
        message = SimpleNamespace(
            tool_calls=tool_calls, content='{"kind":"ask","text":"Fixture question"}'
        )
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    setattr(module, "call_llm", call_llm)
    monkeypatch.setitem(sys.modules, "agent", ModuleType("agent"))
    monkeypatch.setitem(sys.modules, "agent.auxiliary_client", module)
    if tool_calls:
        with pytest.raises(ValueError, match="MODEL_OUTPUT_INVALID"):
            model.main()
    else:
        model.main()
        assert json.loads(capsys.readouterr().out)["text"] == "Fixture question"
    assert requests[0]["tools"] == []
    assert requests[0]["provider"] == "fixture"
    assert requests[0]["model"] == "fixture-model"
