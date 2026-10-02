from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

import pytest

import hermes_plugin
from cct_agent.cli import main as cli_main
from cct_agent.narrative import HumanNarrative
from cct_agent.store import Event, EventStore, GENESIS_HASH


NOW = "2026-08-27T00:00:00+00:00"
HOSTILE_SENTINEL = "HOSTILE_PRODUCER_SENTINEL_a16_never_render"
MAX_DIGEST_LIMIT = 50
TRACE_FIELDS = {"seq", "event_id", "kind", "event_hash"}
VOCABULARY = {
    "VERIFIED",
    "FAILED",
    "ROLLED_BACK",
    "BLOCKED",
    "ACTION_REQUIRED",
    "RECORDED",
}


def make_store(tmp_path: Path) -> EventStore:
    return EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)


def append(
    store: EventStore,
    kind: str,
    payload: dict[str, Any],
    event_id: str,
) -> Event:
    return store.append(
        kind,
        payload,
        occurred_at=NOW,
        event_id=event_id,
    )


def trace(event: Event) -> dict[str, object]:
    return {
        "seq": event.seq,
        "event_id": event.event_id,
        "kind": event.kind,
        "event_hash": event.event_hash,
    }


def assert_no_payload_key(value: object) -> None:
    if isinstance(value, dict):
        assert "payload" not in value
        for item in value.values():
            assert_no_payload_key(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            assert_no_payload_key(item)


def assert_safe_view(view: dict[str, object]) -> None:
    assert set(view) == {"view", "text", "chain", "rows"}
    assert isinstance(view["text"], str)
    assert isinstance(view["chain"], dict)
    assert isinstance(view["rows"], list)
    assert_no_payload_key(view)
    serialized = json.dumps(view, sort_keys=True, ensure_ascii=False)
    assert HOSTILE_SENTINEL not in serialized
    for row in view["rows"]:
        assert isinstance(row, dict)
        assert set(row) == {"result", "family", "text", "trace"}
        assert row["result"] in VOCABULARY
        assert isinstance(row["text"], str)
        assert str(row["text"]).startswith(f"{row['result']}:")
        assert isinstance(row["trace"], dict)
        assert set(row["trace"]) == TRACE_FIELDS


def test_empty_store_has_human_status_without_creating_an_event(tmp_path: Path) -> None:
    store = make_store(tmp_path)

    result = HumanNarrative(store).status()

    assert result == {
        "view": "status",
        "text": (
            "VERIFIED: Event chain is valid. "
            "No human-relevant activity has been recorded."
        ),
        "chain": {
            "valid": True,
            "event_count": 0,
            "head_hash": GENESIS_HASH,
            "errors": [],
        },
        "rows": [],
    }
    assert store.count() == 0
    assert_safe_view(result)


def test_known_event_families_use_fixed_operator_vocabulary_and_exact_traces(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    fixtures = [
        (
            append(
                store,
                "goal.formed",
                {
                    "goal": {
                        "id": "goal-a16",
                        "statement": HOSTILE_SENTINEL,
                        "status": "active",
                    }
                },
                "evt_goal",
            ),
            "goal",
            "RECORDED",
        ),
        (
            append(
                store,
                "decision.made",
                {
                    "decision_id": "decision-a16",
                    "chosen_option_id": "bounded-option",
                    "mode": "exploit",
                    "producer_note": HOSTILE_SENTINEL,
                },
                "evt_decision",
            ),
            "decision",
            "RECORDED",
        ),
        (
            append(
                store,
                "outcome.observed",
                {
                    "decision_id": "decision-a16",
                    "realized_utility": 1.0,
                    "evidence": ["sha256:" + "a" * 64],
                    "observation": HOSTILE_SENTINEL,
                },
                "evt_outcome_verified",
            ),
            "outcome",
            "RECORDED",
        ),
        (
            append(
                store,
                "outcome.observed",
                {
                    "decision_id": "decision-a16-negative",
                    "realized_utility": -1.0,
                    "evidence": ["test:failed"],
                    "observation": HOSTILE_SENTINEL,
                },
                "evt_outcome_failed",
            ),
            "outcome",
            "FAILED",
        ),
        (
            append(
                store,
                "operator.web.effect_verified",
                {"verified": True, "producer_summary": HOSTILE_SENTINEL},
                "evt_effect_verified",
            ),
            "effect",
            "VERIFIED",
        ),
        (
            append(
                store,
                "autonomy.episode.failed",
                {"reason": HOSTILE_SENTINEL},
                "evt_effect_failed",
            ),
            "effect",
            "FAILED",
        ),
        (
            append(
                store,
                "operator.project_edit.rollback.completed",
                {"reason": HOSTILE_SENTINEL},
                "evt_effect_rolled_back",
            ),
            "effect",
            "ROLLED_BACK",
        ),
        (
            append(
                store,
                "mediation.tool.denied",
                {"reason": HOSTILE_SENTINEL},
                "evt_effect_blocked",
            ),
            "effect",
            "BLOCKED",
        ),
        (
            append(
                store,
                "clarification.requested",
                {
                    "request_id": "clarify-a16",
                    "summary": HOSTILE_SENTINEL,
                    "questions": [{"prompt": HOSTILE_SENTINEL}],
                },
                "evt_clarification",
            ),
            "clarification",
            "ACTION_REQUIRED",
        ),
        (
            append(
                store,
                "operator.kill_switch.tripped",
                {"active": True, "reason": HOSTILE_SENTINEL},
                "evt_kill_switch",
            ),
            "kill-switch",
            "BLOCKED",
        ),
        (
            append(
                store,
                "producer.private.story",
                {
                    "summary": HOSTILE_SENTINEL,
                    "nested": {"arbitrary": [HOSTILE_SENTINEL]},
                },
                "evt_unknown",
            ),
            "unknown-event",
            "RECORDED",
        ),
    ]

    result = HumanNarrative(store).digest(limit=MAX_DIGEST_LIMIT)

    assert result["view"] == "digest"
    assert result["chain"] == store.verify_chain()
    assert len(result["rows"]) == len(fixtures)
    by_event_id = {row["trace"]["event_id"]: row for row in result["rows"]}
    assert set(by_event_id) == {event.event_id for event, _, _ in fixtures}
    for event, family, expected_result in fixtures:
        row = by_event_id[event.event_id]
        assert row["family"] == family
        assert row["result"] == expected_result
        assert row["trace"] == trace(event)
    assert {row["result"] for row in result["rows"]} == VOCABULARY
    assert_safe_view(result)


def test_unknown_event_fallback_is_generic_and_never_renders_arbitrary_payload(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    event = append(
        store,
        "future.producer.event.v999",
        {
            "title": HOSTILE_SENTINEL,
            "message": HOSTILE_SENTINEL,
            "raw": {"secret": HOSTILE_SENTINEL},
        },
        "evt_future_unknown",
    )

    result = HumanNarrative(store).latest()

    assert result["rows"] == [
        {
            "result": "RECORDED",
            "family": "unknown-event",
            "text": "RECORDED: An unclassified ledger event was recorded.",
            "trace": trace(event),
        }
    ]
    assert HOSTILE_SENTINEL not in result["text"]
    assert_safe_view(result)


def test_outcome_requires_linked_independent_completion_before_verified(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    claimed = append(
        store,
        "outcome.observed",
        {
            "decision_id": "decision-claimed",
            "realized_utility": 1.0,
            "evidence": ["caller:asserted-success"],
            "observation": HOSTILE_SENTINEL,
        },
        "evt_claimed_outcome",
    )
    execution = append(
        store,
        "autonomy.run.executed",
        {
            "run_id": "verified-run",
            "success": True,
            "verified": True,
            "receipt_event_ids": ["evt_effect_receipt"],
        },
        "evt_verified_execution",
    )
    verified = append(
        store,
        "outcome.observed",
        {
            "decision_id": "decision-verified",
            "realized_utility": 1.0,
            "evidence": [f"event:{execution.event_id}"],
            "observation": HOSTILE_SENTINEL,
        },
        "evt_verified_outcome",
    )

    result = HumanNarrative(store).digest(limit=10)
    result_rows = result["rows"]
    assert isinstance(result_rows, list)
    rows = {row["trace"]["seq"]: row for row in result_rows}

    assert rows[claimed.seq]["result"] == "RECORDED"
    assert "without independent verification" in rows[claimed.seq]["text"]
    assert rows[verified.seq]["result"] == "VERIFIED"
    assert HOSTILE_SENTINEL not in json.dumps(result, sort_keys=True)


def test_answered_clarification_is_not_counted_as_unresolved_action(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    request = append(
        store,
        "clarification.requested",
        {
            "request_id": "clarification-resolved",
            "revision": 1,
            "questions": [],
        },
        "evt_clarification_resolved",
    )
    append(
        store,
        "clarification.answer.understood",
        {
            "request_event_id": request.event_id,
            "confirmation_required": False,
            "answers": [],
        },
        "evt_clarification_answer",
    )

    status = HumanNarrative(store).status()

    assert "unresolved action signals: 0" in str(status["text"])


def test_unsafe_caller_metadata_is_hashed_in_trace(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    event = append(
        store,
        f"future.{HOSTILE_SENTINEL}",
        {"safe": True},
        HOSTILE_SENTINEL,
    )

    result = HumanNarrative(store).latest()
    result_rows = result["rows"]
    assert isinstance(result_rows, list)
    trace_row = result_rows[0]["trace"]

    assert trace_row["seq"] == event.seq
    assert trace_row["event_hash"] == event.event_hash
    assert str(trace_row["event_id"]).startswith("sha256:")
    assert str(trace_row["kind"]).startswith("sha256:")
    assert HOSTILE_SENTINEL not in json.dumps(result, sort_keys=True)


def test_routine_events_are_suppressed_from_latest_and_digest(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    meaningful = append(
        store,
        "goal.status_changed",
        {
            "goal_id": "goal-a16",
            "from": "active",
            "to": "completed",
            "reason": HOSTILE_SENTINEL,
        },
        "evt_meaningful",
    )
    routine = [
        append(
            store,
            "cognition.tick.started",
            {"producer_note": HOSTILE_SENTINEL},
            "evt_routine_tick",
        ),
        append(
            store,
            "interoception.sampled",
            {"producer_note": HOSTILE_SENTINEL},
            "evt_routine_sample",
        ),
        append(
            store,
            "cognition.cycle.completed",
            {"producer_note": HOSTILE_SENTINEL},
            "evt_routine_cycle",
        ),
    ]

    latest = HumanNarrative(store).latest()
    digest = HumanNarrative(store).digest(limit=10)

    assert [row["trace"]["event_id"] for row in latest["rows"]] == [
        meaningful.event_id
    ]
    assert [row["trace"]["event_id"] for row in digest["rows"]] == [
        meaningful.event_id
    ]
    rendered = json.dumps([latest, digest], sort_keys=True)
    for event in routine:
        assert event.event_id not in rendered
    assert latest["chain"]["event_count"] == 4
    assert digest["chain"]["event_count"] == 4
    assert_safe_view(latest)
    assert_safe_view(digest)


def test_digest_is_newest_first_and_enforces_its_limit(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    events = [
        append(
            store,
            "future.event",
            {"ordinal": ordinal, "producer_note": HOSTILE_SENTINEL},
            f"evt_digest_{ordinal}",
        )
        for ordinal in range(6)
    ]
    narrative = HumanNarrative(store)

    result = narrative.digest(limit=3)

    assert [row["trace"]["event_id"] for row in result["rows"]] == [
        event.event_id for event in reversed(events[-3:])
    ]
    assert len(result["rows"]) == 3
    with pytest.raises(ValueError, match="limit must be between 1 and 50"):
        narrative.digest(limit=0)
    with pytest.raises(ValueError, match="limit must be between 1 and 50"):
        narrative.digest(limit=MAX_DIGEST_LIMIT + 1)
    assert_safe_view(result)


def test_repeated_rendering_is_deterministic_and_does_not_mutate_store(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    append(
        store,
        "goal.formed",
        {
            "goal": {
                "id": "goal-deterministic",
                "statement": HOSTILE_SENTINEL,
                "status": "active",
            }
        },
        "evt_deterministic_goal",
    )
    append(
        store,
        "operator.shell.effect_verified",
        {"verified": True, "stdout": HOSTILE_SENTINEL},
        "evt_deterministic_effect",
    )
    before_events = list(store.export())
    before_chain = store.verify_chain()
    narrative = HumanNarrative(store)

    first = {
        "status": narrative.status(),
        "latest": narrative.latest(),
        "digest": narrative.digest(limit=10),
    }
    second = {
        "status": narrative.status(),
        "latest": narrative.latest(),
        "digest": narrative.digest(limit=10),
    }

    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert list(store.export()) == before_events
    assert store.verify_chain() == before_chain
    for view in first.values():
        assert_safe_view(view)


def test_chain_invalid_state_fails_closed_without_any_success_claim(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    event = append(
        store,
        "operator.shell.effect_verified",
        {"verified": True, "producer_note": "original"},
        "evt_tampered_success",
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE events SET payload_json = ? WHERE event_id = ?",
            (
                json.dumps(
                    {"verified": True, "producer_note": HOSTILE_SENTINEL},
                    sort_keys=True,
                ),
                event.event_id,
            ),
        )

    assert store.verify_chain()["valid"] is False
    narrative = HumanNarrative(store)
    views = [
        narrative.status(),
        narrative.latest(),
        narrative.digest(limit=10),
    ]

    for view in views:
        assert view["chain"]["valid"] is False
        assert str(view["text"]).startswith("BLOCKED:")
        assert "VERIFIED" not in view["text"]
        assert view["rows"] == []
        assert_safe_view(view)


def test_cli_human_views_are_plain_by_default_and_json_on_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = make_store(tmp_path)
    append(
        store,
        "operator.shell.effect_verified",
        {"verified": True, "stdout": HOSTILE_SENTINEL},
        "evt_cli_verified",
    )
    before = store.count()

    assert cli_main(["--db", str(store.path), "human-status"]) == 0
    plain = capsys.readouterr().out
    assert plain.startswith("VERIFIED:")
    assert HOSTILE_SENTINEL not in plain

    assert cli_main(["--db", str(store.path), "explain-latest", "--json"]) == 0
    latest = json.loads(capsys.readouterr().out)
    assert latest["view"] == "latest"
    assert latest["rows"][0]["trace"]["event_id"] == "evt_cli_verified"

    assert cli_main(["--db", str(store.path), "digest", "--limit", "1", "--json"]) == 0
    digest = json.loads(capsys.readouterr().out)
    assert digest["view"] == "digest"
    assert len(digest["rows"]) == 1
    assert store.count() == before
    assert_safe_view(latest)
    assert_safe_view(digest)


class NarrativePluginContext:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}
        self.schemas: dict[str, dict[str, Any]] = {}

    @staticmethod
    def get_config(_key: str, default: object = None) -> object:
        return default

    def register_tool(
        self,
        *,
        name: str,
        schema: dict[str, Any],
        handler: Any,
        **_kwargs: object,
    ) -> None:
        self.tools[name] = handler
        self.schemas[name] = schema

    @staticmethod
    def register_hook(_name: str, _handler: Any) -> None:
        return None

    @staticmethod
    def register_middleware(_kind: str, _handler: Any) -> None:
        return None


def test_hermes_human_summary_is_bounded_payload_safe_and_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    context = NarrativePluginContext()
    hermes_plugin.register(context)
    store = EventStore(home / "cct-agency" / "agency.sqlite")
    append(
        store,
        "future.hostile.event",
        {"summary": HOSTILE_SENTINEL, "secret": HOSTILE_SENTINEL},
        "evt_plugin_hostile",
    )
    before_events = list(store.export())

    result = json.loads(
        context.tools["cct_human_summary"]({"view": "digest", "limit": 8})
    )

    assert result["success"] is True
    safe_view = {key: result[key] for key in ("view", "text", "chain", "rows")}
    assert_safe_view(safe_view)
    assert HOSTILE_SENTINEL not in json.dumps(result, sort_keys=True)
    assert list(store.export()) == before_events
    parameters = context.schemas["cct_human_summary"]["parameters"]
    assert parameters["additionalProperties"] is False
    assert parameters["properties"]["limit"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 50,
    }
    with pytest.raises(ValueError, match="not an allowed value"):
        context.tools["cct_human_summary"]({"view": "raw"})
    with pytest.raises(ValueError, match="exceeds its maximum"):
        context.tools["cct_human_summary"]({"view": "digest", "limit": 51})
