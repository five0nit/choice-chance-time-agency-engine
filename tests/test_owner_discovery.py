"""Isolated discovery regressions: no live owner data, services or model calls."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
import socket
import sys
from types import ModuleType, SimpleNamespace

import pytest

from cct_agent import owner_discovery as discovery
from cct_agent import owner_discovery_model as model
from cct_agent.owner_workspace import ANSWER_CHOICES, PERMISSION_KEYS

NOW = datetime(2026, 9, 13, 12, tzinfo=timezone.utc)
UID = "owner-test"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Discovery tests must not access the network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def response(source):
    return {
        "question": {"text": "Fixture: which boundary matters next?"},
        "learning": {
            **discovery.empty_learning(),
            "wants": [
                {"text": "Fixture observation", "sourceAnswerIds": [source]},
            ],
        },
        "unknowns": ["Fixture owner-only boundary"],
        "workIdeas": [
            {
                "title": "Fixture research brief",
                "why": "Fixture supported direction",
                "firstStep": "Compare sources; finish when evidence gaps are recorded.",
                "sourceAnswerIds": [source],
                "readiness": "DRAFT_ONLY",
            }
        ],
    }


@pytest.fixture
def interview(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
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
                "ownerMessagesEnabled": False,
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
        now=NOW,
        calls=[],
        docs={},
        error=None,
        fail_projection=False,
        workspace={
            "schemaVersion": "cct.owner_workspace.v1",
            "ownerUid": UID,
            "revision": 1,
            "updatedAt": NOW,
            "learningEnabled": True,
            "permissions": dict.fromkeys(PERMISSION_KEYS, False),
            "autonomyMode": "supervised",
            "autonomyAcknowledged": False,
            "answers": dict.fromkeys(ANSWER_CHOICES, ""),
            "decisions": {},
        },
    )
    monkeypatch.setattr(discovery, "now", lambda: state.now)

    def read(collection, name="current"):
        return deepcopy(
            state.workspace
            if collection == "cct_workspace"
            else state.docs.get((collection, name))
        )

    def publish(collection, name, value):
        if state.fail_projection and value["phase"] == "AWAITING_INPUT":
            raise OSError("Fixture projection failure after durable save")
        state.docs[collection, name] = deepcopy(value)

    state.gateway = SimpleNamespace(read=read, publish=publish)
    monkeypatch.setattr(
        discovery, "FirebaseOwnerGateway", lambda project: state.gateway
    )

    def invoke(worker, turn):
        request = json.loads(turn["input_json"])
        state.calls.append(request)
        if state.error:
            raise state.error
        return discovery.dumps(response(request["newAnswerId"]))

    monkeypatch.setattr(discovery.OwnerDiscovery, "invoke", invoke)
    state.worker = discovery.OwnerDiscovery(tmp_path)
    yield state
    state.worker.close()


def reply(state, text="Fixture-only answer"):
    question = state.worker.latest()["question_id"]
    state.docs["cct_discovery_answers", question] = {
        "schemaVersion": "cct.discovery_answer.v1",
        "ownerUid": UID,
        "questionId": question,
        "text": text,
        "createdAt": state.now,
    }
    return question


def restart(state):
    state.worker.close()
    state.worker = discovery.OwnerDiscovery(state.home)


def seed_attempts(state, outcome, count):
    with state.worker.db:
        state.worker.db.executemany(
            "INSERT INTO attempts(turn_key,created_at,outcome) VALUES(?,?,?)",
            [
                (
                    f"fixture-{outcome}-{i}",
                    discovery.stamp(NOW - timedelta(hours=23 - i)),
                    outcome,
                )
                for i in range(count)
            ],
        )


def test_successful_answers_continue_beyond_ten_and_idle_does_not_regenerate(interview):
    s = interview
    assert s.worker.tick()["phase"] == "AWAITING_INPUT"
    assert not s.calls  # The starter does not need a model.
    for index in range(12):
        exact = f"  Fixture answer {index}\nwith preserved whitespace.\t"
        source = reply(s, exact)
        value = s.worker.tick()
        assert value["phase"] == "AWAITING_INPUT"
        assert value["answersConsumed"] == index + 1
        assert value["executionEnabled"] is False
        history = {row["questionId"]: row["answer"] for row in s.calls[-1]["history"]}
        assert history[source] == exact
        assert value["workIdeas"][0]["sourceAnswerIds"] == [source]
        assert s.worker.tick()["question"] == value["question"]
    restart(s)
    assert s.worker.tick()["answersConsumed"] == 12
    assert len(s.calls) == 12
    assert (
        s.worker.db.execute(
            "SELECT count(*) FROM attempts WHERE outcome='SAVED'"
        ).fetchone()[0]
        == 12
    )
    assert (
        s.worker.db.execute("SELECT count(*) FROM answers WHERE consumed=0").fetchone()[
            0
        ]
        == 0
    )


@pytest.mark.parametrize("failures", [9, 10, 12])
def test_daily_breaker_counts_only_failures_and_reports_exact_release(
    interview, failures
):
    s = interview
    seed_attempts(s, "SAVED", 15)
    seed_attempts(s, "FAILED", failures)
    blocked = s.worker.budget({"key": "fixture-new-turn"})
    if failures < 10:
        assert blocked is None
    else:
        reason, retry_at = blocked
        assert "ten unsuccessful model attempts" in reason
        release = NOW + timedelta(hours=failures - 9)
        assert retry_at == discovery.stamp(release)
        s.now = release - timedelta(microseconds=1)
        assert s.worker.budget({"key": "fixture-new-turn"}) is not None
        s.now = release
        assert s.worker.budget({"key": "fixture-new-turn"}) is None


def test_blocked_answer_is_saved_then_consumed_once_when_failures_expire(interview):
    s = interview
    s.worker.tick()
    seed_attempts(s, "FAILED", 10)
    source = reply(s)
    assert s.worker.tick()["phase"] == "BLOCKED"
    row = s.worker.db.execute("SELECT * FROM answers WHERE id=?", (source,)).fetchone()
    assert row["answer"] == "Fixture-only answer" and row["consumed"] == 0
    assert not s.calls
    s.now += timedelta(hours=1)
    assert s.worker.tick()["answersConsumed"] == 1
    assert s.worker.tick()["phase"] == "AWAITING_INPUT"
    assert len(s.calls) == 1


def test_backoff_and_three_attempt_limit_survive_restart(interview):
    s = interview
    s.worker.tick()
    reply(s)
    s.error = RuntimeError("Fixture model unavailable")
    assert s.worker.tick()["phase"] == "BLOCKED"
    assert s.worker.tick()["retryAt"] == discovery.stamp(NOW + timedelta(seconds=300))
    assert len(s.calls) == 1
    for _ in range(2):
        s.now += timedelta(seconds=300)
        assert s.worker.tick()["phase"] == "BLOCKED"
    restart(s)
    assert "three-attempt model limit" in s.worker.tick()["reason"]
    assert len(s.calls) == 3
    assert (
        s.worker.db.execute("SELECT count(*) FROM answers WHERE consumed=0").fetchone()[
            0
        ]
        == 1
    )


@pytest.mark.parametrize("outcome", ["UNKNOWN", "IN_FLIGHT"])
def test_unresolved_attempt_is_never_replayed_after_restart(interview, outcome):
    s = interview
    s.worker.tick()
    question = reply(s)
    s.worker.accept_answer(s.worker.latest(), s.docs["cct_discovery_answers", question])
    answer = s.worker.db.execute(
        "SELECT * FROM answers WHERE id=?", (question,)
    ).fetchone()
    turn = s.worker.prepare(answer, s.workspace)
    with s.worker.db:
        s.worker.db.execute(
            "INSERT INTO attempts(turn_key,created_at,outcome) VALUES(?,?,?)",
            (turn["key"], discovery.stamp(), outcome),
        )
    restart(s)
    value = s.worker.tick()
    assert value["phase"] == "BLOCKED"
    assert "Operator recovery is required" in value["reason"]
    assert "retryAt" not in value
    assert not s.calls


def test_projection_failure_preserves_durable_output_without_second_model_call(
    interview,
):
    s = interview
    s.worker.tick()
    reply(s)
    s.fail_projection = True
    assert s.worker.tick()["phase"] == "BLOCKED"
    durable = json.loads(s.worker.latest()["response_json"])
    restart(s)
    s.fail_projection = False
    value = s.worker.tick()
    assert value["phase"] == "AWAITING_INPUT"
    assert value["learning"] == durable["learning"]
    assert value["workIdeas"] == durable["workIdeas"]
    assert value == s.docs["cct_discovery", "current"]
    assert value == json.loads(
        s.worker.db.execute("SELECT payload FROM status WHERE id=1").fetchone()[0]
    )
    assert value["executionEnabled"] is False
    assert len(s.calls) == 1


@pytest.mark.parametrize("field", ["tool_calls", "function_call", None])
def test_adapter_sends_current_prompt_without_tools_or_retry_ladder(
    tmp_path, monkeypatch, capsys, field
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        json.dumps(
            {
                "model": {"provider": "fixture", "default": "fixture-model"},
            }
        )
    )
    source = "q-" + "a" * 32
    payload = {"history": [{"questionId": source, "answer": "Fixture-only evidence"}]}
    monkeypatch.setattr(
        sys, "stdin", SimpleNamespace(buffer=BytesIO(json.dumps(payload).encode()))
    )
    raw = json.dumps(response(source), indent=2)
    message = SimpleNamespace(content=raw, tool_calls=None, function_call=None)
    if field:
        setattr(message, field, {"name": "fixture-forbidden-tool"})
    requests, formats, resolutions = [], [], []

    def create(**kwargs):
        requests.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    def resolve(**kwargs):
        resolutions.append(kwargs)
        return SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        ), "fixture-model"

    def build(provider, name, messages, **kwargs):
        formats.append((provider, name, messages, kwargs))
        return {"model": name, "messages": messages, "tools": ["fixture-default-tool"]}

    module = ModuleType("agent.auxiliary_client")
    setattr(module, "resolve_provider_client", resolve)
    setattr(module, "_build_call_kwargs", build)
    monkeypatch.setitem(sys.modules, "agent", ModuleType("agent"))
    monkeypatch.setitem(sys.modules, "agent.auxiliary_client", module)
    if field:
        with pytest.raises(ValueError, match="DISCOVERY_MODEL_OUTPUT_INVALID"):
            model.main()
        assert capsys.readouterr().out == ""
    else:
        model.main()
        assert capsys.readouterr().out == raw
    assert len(requests) == len(resolutions) == 1
    assert requests[0]["tools"] == formats[0][3]["tools"] == []
    assert requests[0]["messages"][0] == {"role": "system", "content": model.PROMPT}
    assert resolutions[0]["provider"] == "fixture"


@pytest.mark.parametrize("violation", ["authority", "citation"])
def test_drafts_reject_execution_authority_and_invented_evidence(violation):
    source = "q-" + "b" * 32
    value = response(source)
    if violation == "authority":
        value["workIdeas"][0]["readiness"] = "EXECUTE"
    else:
        value["workIdeas"][0]["sourceAnswerIds"] = ["q-" + "c" * 32]
    with pytest.raises(
        ValueError, match="DISCOVERY_(EXECUTION_FORBIDDEN|CITATION_INVALID)"
    ):
        model.validate_response(value, [{"questionId": source}])
