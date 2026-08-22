"""Hermes plugin exposing the Choice-Chance-Time Agency Engine."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any

from cct_agent import (
    AgencyKernel,
    AutonomyEngine,
    CognitiveCycle,
    EventStore,
    InitiationSignals,
    Observation,
    Opportunity,
    ProactiveEngine,
    ProactiveRunner,
    ThoughtPacket,
    TopicStore,
    default_constitution,
)
from cct_agent.metacognition import MetacognitiveMonitor
from cct_agent.models import options_from_dicts
from cct_agent.self_model import SelfModel


PLUGIN_VERSION = "0.7.0"
CONTEXT_CHAR_BUDGET = 6000
_PLUGIN_IDENTITY: str | None = None
_PLUGIN_TEAM_SYNC_SOURCE: str | None = None


def _identity() -> str:
    return os.getenv("CCT_IDENTITY", _PLUGIN_IDENTITY or "CCT-Agent")


def _team_sync_source() -> Path | None:
    configured = os.getenv(
        "CCT_TEAM_SYNC_SOURCE", _PLUGIN_TEAM_SYNC_SOURCE or ""
    ).strip()
    return Path(configured).expanduser().absolute() if configured else None


def _db_path() -> Path:
    hermes_home = Path(os.getenv("HERMES_HOME", str(Path.home() / ".hermes")))
    state_root = hermes_home / "cct-agency"
    state_root.mkdir(parents=True, exist_ok=True)
    if state_root.is_symlink():
        raise ValueError("CCT plugin state root must not be a symlink")
    os.chmod(state_root, 0o700)
    database = state_root / "agency.sqlite"
    if database.is_symlink():
        raise ValueError("CCT plugin database must not be a symlink")
    if database.exists():
        os.chmod(database, 0o600)
    return database


def _kernel() -> AgencyKernel:
    database = _db_path()
    store = EventStore(database)
    os.chmod(database, 0o600)
    kernel = AgencyKernel(store, default_constitution(_identity()))
    kernel.initialize()
    return kernel


def _cycle() -> CognitiveCycle:
    return CognitiveCycle(
        _kernel(),
        workspace_capacity=8,
        workspace_char_budget=CONTEXT_CHAR_BUDGET,
        consolidation_interval=20,
    )


def _autonomy() -> AutonomyEngine:
    hermes_home = Path(os.getenv("HERMES_HOME", str(Path.home() / ".hermes")))
    kernel = _kernel()
    return AutonomyEngine(
        kernel.store,
        kernel,
        hermes_home / "cct-agency" / "workspace",
        state_root=hermes_home / "cct-agency" / "autonomy",
    )


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _seed(material: str) -> int:
    return int(sha256(material.encode("utf-8")).hexdigest()[:16], 16)


def _status_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del params, kwargs
    kernel = _kernel()
    team_sync_source = _team_sync_source()
    source_digest = (
        sha256(str(team_sync_source).encode("utf-8")).hexdigest()
        if team_sync_source is not None
        else None
    )

    def matching_latest(kind: str) -> Any:
        if source_digest is None:
            return None
        return next(
            (
                event
                for event in reversed(kernel.store.events(kind))
                if event.payload.get("source_id") == "project_changes"
                and event.payload.get("source_path_sha256") == source_digest
            ),
            None,
        )

    cursor = matching_latest("sensor.team_sync.cursor.advanced")
    continuity = matching_latest("sensor.team_sync.continuity")
    cursor_status = (
        {
            key: cursor.payload.get(key)
            for key in (
                "offset",
                "observed_at",
                "primed",
                "scanned_lines",
                "accepted_events",
                "rejected_events",
                "cycle_tick",
                "content_policy",
                "access_control_policy",
                "producer_free_text_persisted",
            )
        }
        if cursor
        else None
    )
    cycle_status = (
        {
            key: continuity.payload.get(key)
            for key in (
                "observed_at",
                "mode",
                "cycle_tick",
                "observation_count",
                "content_policy",
                "access_control_policy",
                "producer_free_text_persisted",
                "llm_calls",
                "external_effects",
            )
        }
        if continuity
        else None
    )
    return _json(
        {
            "success": True,
            "plugin_version": PLUGIN_VERSION,
            "status": kernel.status(),
            "cognition": CognitiveCycle(kernel).status(),
            "proactive": ProactiveRunner(kernel.store).status(),
            "autonomy": _autonomy().status(),
            "continuity_sensor": {
                "source": (
                    "configured-team-sync"
                    if team_sync_source is not None
                    else "not-configured"
                ),
                "source_configured": team_sync_source is not None,
                "canonical_source_bound": cursor is not None,
                "cursor": cursor_status,
                "latest_cycle": cycle_status,
            },
        }
    )


def _form_goal_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    goal = _kernel().form_goal(
        statement=str(params["statement"]),
        rationale=str(params["rationale"]),
        alignment={str(k): float(v) for k, v in dict(params["alignment"]).items()},
        source=str(params.get("source", "self")),
        horizon=str(params.get("horizon", "medium")),
        evidence=[str(item) for item in params.get("evidence", [])],
        goal_id=str(params["goal_id"]) if params.get("goal_id") else None,
    )
    return _json({"success": True, "goal": asdict(goal)})


def _deliberate_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    decision = _kernel().deliberate(
        goal_id=str(params["goal_id"]),
        options=options_from_dicts(list(params.get("options", []))),
        seed=int(params["seed"]),
        decision_id=(str(params["decision_id"]) if params.get("decision_id") else None),
    )
    return _json({"success": True, "decision": decision})


def _outcome_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    event = _kernel().record_outcome(
        decision_id=str(params["decision_id"]),
        realized_utility=float(params["realized_utility"]),
        observation=str(params["observation"]),
        evidence=[str(item) for item in params.get("evidence", [])],
    )
    return _json(
        {"success": True, "event_id": event.event_id, "event_hash": event.event_hash}
    )


def _reflect_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del params, kwargs
    return _json({"success": True, "reflection": _kernel().reflect()})


def _cognitive_status_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del params, kwargs
    cycle = _cycle()
    return _json(
        {
            "success": True,
            "cognition": cycle.status(),
            "context": cycle.context(max_chars=CONTEXT_CHAR_BUDGET),
        }
    )


def _observe_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    summary = str(params["summary"])
    source = str(params.get("source", "self:observation"))
    identifier = str(
        params.get("observation_id")
        or "obs_" + sha256(f"{source}:{summary}".encode("utf-8")).hexdigest()[:20]
    )
    observation = Observation(
        id=identifier,
        kind=str(params.get("kind", "observation")),
        summary=summary,
        source=source,
        confidence=float(params.get("confidence", 0.5)),
        salience=float(params.get("salience", 0.5)),
        goal_relevance=float(params.get("goal_relevance", 0.5)),
        novelty=float(params.get("novelty", 0.0)),
        urgency=float(params.get("urgency", 0.0)),
        unresolved_conflict=float(params.get("unresolved_conflict", 0.0)),
        processing_cost=float(params.get("processing_cost", 0.0)),
        evidence=tuple(str(item) for item in params.get("evidence", [])),
        proposition=(str(params["proposition"]) if params.get("proposition") else None),
    )
    cycle = _cycle()
    result = cycle.run(
        observations=[observation],
        seed=int(params.get("seed", _seed(identifier))),
    )
    return _json({"success": True, "cycle": result, "context": cycle.context()})


def _self_model_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del params, kwargs
    kernel = _kernel()
    snapshot = SelfModel(kernel.store, identity=kernel.constitution.identity).snapshot()
    return _json({"success": True, "self_model": snapshot})


def _autonomy_status_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del params, kwargs
    return _json({"success": True, "autonomy": _autonomy().status()})


def _opportunity_propose_handler(params: dict[str, Any], **kwargs: Any) -> str:
    """Persist a model proposal without granting it execution authority."""

    del kwargs
    proposed = _autonomy().register_opportunity(
        Opportunity(
            id=str(params["opportunity_id"]),
            title=str(params["title"]),
            rationale=str(params["rationale"]),
            objective=str(params["objective"]),
            source=str(params.get("source", "self:hermes-tool")),
            source_authority="self",
            value_impacts={
                str(key): float(value)
                for key, value in dict(params["value_impacts"]).items()
            },
            plan={"steps": [], "final_verify": []},
            evidence=tuple(str(item) for item in params.get("evidence", [])),
            information_gain=float(params.get("information_gain", 0.0)),
            uncertainty=float(params.get("uncertainty", 0.5)),
            time_cost=float(params.get("time_cost", 0.0)),
            capability=str(params.get("capability", "local_workspace_write")),
        )
    )
    return _json(
        {
            "success": True,
            "opportunity": proposed,
            "execution_authority_granted": False,
            "next_boundary": "host adapter or authenticated operator must attach an executable plan",
        }
    )


def _autonomy_run_handler(params: dict[str, Any], **kwargs: Any) -> str:
    """Execute only already-registered host/operator plans through the hard boundary."""

    del kwargs
    result = _autonomy().run_once(
        seed=int(params["seed"]),
        run_id=str(params["run_id"]) if params.get("run_id") else None,
        decision_id=(
            str(params["decision_id"]) if params.get("decision_id") else None
        ),
    )
    return _json({"success": True, "run": result})


def _verify_introspection_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    kernel = _kernel()
    tick = CognitiveCycle(kernel).status()["logical_tick"] + 1
    result = MetacognitiveMonitor(kernel.store, kernel).verify_decision_report(
        decision_id=str(params["decision_id"]),
        claimed_option_id=str(params["claimed_option_id"]),
        claimed_top_factor=str(params["claimed_top_factor"]),
        logical_tick=int(tick),
    )
    return _json({"success": True, "verification": result})


def _proactive_status_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del params, kwargs
    return _json({"success": True, "proactive": ProactiveRunner(_kernel().store).status()})


def _topic_update_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    kernel = _kernel()
    tick = int(params.get("logical_tick", CognitiveCycle(kernel).status()["logical_tick"]))
    topic = TopicStore(kernel.store).upsert(
        topic_id=str(params["topic_id"]),
        title=str(params["title"]),
        summary=str(params["summary"]),
        source=str(params.get("source", "self:topic-update")),
        logical_tick=tick,
        questions=tuple(str(item) for item in params.get("questions", [])),
        hypotheses=tuple(str(item) for item in params.get("hypotheses", [])),
        commitments=tuple(str(item) for item in params.get("commitments", [])),
        urgency=float(params.get("urgency", 0.0)),
        novelty=float(params.get("novelty", 0.0)),
        goal_relevance=float(params.get("goal_relevance", 0.0)),
        unresolved_conflict=float(params.get("unresolved_conflict", 0.0)),
        status=str(params.get("status", "open")),
    )
    return _json(
        {
            "success": True,
            "topic": topic.as_payload(),
            "persistence": {
                "continuity_scope": "profile",
                "caller_supplied_summary_persisted": True,
                "automatic_raw_conversation_capture": False,
                "raw_chain_of_thought_stored": False,
            },
        }
    )


def _proactive_think_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    kernel = _kernel()
    tick = int(params.get("logical_tick", CognitiveCycle(kernel).status()["logical_tick"]))
    semantic = {
        "topic_id": str(params["topic_id"]),
        "observation": str(params["observation"]),
        "hypotheses": [str(item) for item in params.get("hypotheses", [])],
        "open_questions": [str(item) for item in params.get("open_questions", [])],
        "evidence": [str(item) for item in params.get("evidence", [])],
        "uncertainty": float(params.get("uncertainty", 0.5)),
        "recommended_action": str(params.get("recommended_action", "WAIT")).upper(),
        "rationale_summary": str(params["rationale_summary"]),
        "source": str(params.get("source", "self:structured-thought")),
    }
    packet_id = str(
        params.get("packet_id")
        or "packet_" + sha256(_json(semantic).encode("utf-8")).hexdigest()[:20]
    )
    packet = ThoughtPacket(
        id=packet_id,
        created_tick=tick,
        **semantic,
    )
    wake = kernel.store.allocate_counter("proactive_wake")
    result = ProactiveEngine(kernel.store).submit(
        packet,
        signals=InitiationSignals(
            urgency=float(params.get("urgency", 0.0)),
            novelty=float(params.get("novelty", 0.0)),
            goal_relevance=float(params.get("goal_relevance", 0.0)),
            unresolved_conflict=float(params.get("unresolved_conflict", 0.0)),
            interruption_cost=float(params.get("interruption_cost", 0.1)),
        ),
        wake_index=wake,
        time_bucket=str(params.get("time_bucket") or datetime.now(UTC).date().isoformat()),
    )
    return _json({"success": True, "packet": packet.as_payload(), "initiation": result})


def _message_chars(messages: Any) -> int:
    if not isinstance(messages, list):
        return 0
    total = 0
    for row in messages:
        if isinstance(row, dict):
            content = row.get("content", "")
            total += len(content) if isinstance(content, str) else len(str(content))
    return total


def _pre_llm_context(**kwargs: Any) -> dict[str, str] | None:
    """Advance one bounded cognitive tick and expose its global workspace."""

    try:
        session_id = str(kwargs.get("session_id", ""))
        platform = str(kwargs.get("platform", ""))
        model = str(kwargs.get("model", ""))
        message_chars = _message_chars(kwargs.get("messages"))
        context_pressure = min(1.0, message_chars / 120000.0)
        cycle = _cycle()
        ordinal = cycle.status()["logical_tick"] + 1
        observation = Observation(
            id=f"hermes_pre_{ordinal}",
            kind="cognitive_trigger",
            summary=(
                "Hermes LLM call requested; current turn content remains transient and "
                "is available directly to the model."
            ),
            source="hermes:pre_llm_call",
            confidence=1.0,
            salience=0.7,
            goal_relevance=0.7,
            novelty=0.2,
            urgency=0.3,
            evidence=(
                "session_sha256:"
                + sha256(session_id.encode("utf-8")).hexdigest(),
                f"platform:{platform or 'unknown'}",
                f"model:{model or 'unknown'}",
            ),
        )
        cycle.run(
            observations=[observation],
            seed=_seed(f"pre:{session_id}:{ordinal}"),
            internal_signals={
                "context_pressure": context_pressure,
                "error_rate": 0.0,
                "goal_progress": 0.5,
                "memory_integrity": 1.0,
                "tool_availability": 1.0,
            },
        )
        context = cycle.context(max_chars=CONTEXT_CHAR_BUDGET)
        proactive_context = ProactiveRunner(cycle.store).context(
            max_chars=CONTEXT_CHAR_BUDGET // 3
        )
        combined = "\n\n".join(
            part for part in (context, proactive_context) if part
        )[:CONTEXT_CHAR_BUDGET]
        return {"context": combined} if combined else None
    except Exception as exc:
        try:
            _kernel().store.append(
                "plugin.hook.failed",
                {
                    "hook": "pre_llm_call",
                    "error_type": type(exc).__name__,
                    "content_stored": False,
                },
            )
        except Exception:
            pass
        return None


def _post_llm_observation(
    session_id: str = "",
    user_message: str = "",
    assistant_response: str = "",
    model: str = "",
    platform: str = "",
    **kwargs: Any,
) -> None:
    """Close the recurrent loop using digests and counts, never raw turn content."""

    del kwargs
    try:
        kernel = _kernel()
        turn_event = kernel.store.append(
            "hermes.turn_observed",
            {
                "session_sha256": sha256(session_id.encode("utf-8")).hexdigest(),
                "platform": platform,
                "model": model,
                "user_message_sha256": sha256(user_message.encode("utf-8")).hexdigest(),
                "assistant_response_sha256": sha256(
                    assistant_response.encode("utf-8")
                ).hexdigest(),
                "user_chars": len(user_message),
                "assistant_chars": len(assistant_response),
                "content_stored": False,
            },
        )
        cycle = CognitiveCycle(kernel)
        ordinal = cycle.status()["logical_tick"] + 1
        cycle.run(
            observations=[
                Observation(
                    id=f"hermes_post_{ordinal}",
                    kind="response_outcome",
                    summary=(
                        "Hermes response completed; raw user and assistant content was "
                        "not persisted by CCT."
                    ),
                    source="hermes:post_llm_call",
                    confidence=1.0,
                    salience=0.6,
                    goal_relevance=0.6,
                    novelty=0.1,
                    evidence=(f"turn_event:{turn_event.event_id}",),
                )
            ],
            seed=_seed(f"post:{session_id}:{ordinal}"),
        )
    except Exception as exc:
        try:
            _kernel().store.append(
                "plugin.hook.failed",
                {
                    "hook": "post_llm_call",
                    "error_type": type(exc).__name__,
                    "content_stored": False,
                },
            )
        except Exception:
            pass


def _option_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "description": {"type": "string"},
            "value_impacts": {"type": "object"},
            "information_gain": {"type": "number", "minimum": 0, "maximum": 1},
            "uncertainty": {"type": "number", "minimum": 0, "maximum": 1},
            "time_cost": {"type": "number", "minimum": 0},
            "irreversible": {"type": "boolean"},
            "blocked_reasons": {"type": "array", "items": {"type": "string"}},
            "assumptions": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["id", "description", "value_impacts"],
    }


def _bounded_string(maximum: int) -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": maximum}


def _bounded_string_list(
    *, maximum_items: int, maximum_chars: int, minimum_items: int = 0
) -> dict[str, Any]:
    return {
        "type": "array",
        "minItems": minimum_items,
        "maxItems": maximum_items,
        "items": _bounded_string(maximum_chars),
    }


def register(ctx: Any) -> None:
    """Register CCT tools and bounded recurrent cognition hooks with Hermes."""

    global _PLUGIN_IDENTITY, _PLUGIN_TEAM_SYNC_SOURCE
    get_config = getattr(ctx, "get_config", None)
    if callable(get_config):
        configured_identity = get_config("identity", "CCT-Agent")
        configured_source = get_config("team_sync_source", "")
        _PLUGIN_IDENTITY = str(configured_identity or "CCT-Agent")
        _PLUGIN_TEAM_SYNC_SOURCE = str(configured_source or "")

    ctx.register_tool(
        name="cct_status",
        toolset="cct_agency",
        schema={
            "name": "cct_status",
            "description": "Inspect CCT goals, event chain, and global-workspace cognition.",
            "parameters": {"type": "object", "properties": {}},
        },
        handler=_status_handler,
        description="Inspect Choice-Chance-Time and cognition state.",
    )
    ctx.register_tool(
        name="cct_autonomy_status",
        toolset="cct_agency",
        schema={
            "name": "cct_autonomy_status",
            "description": (
                "Inspect the capability-first opportunity portfolio, authority envelope, "
                "run receipts, and learned capability reliability."
            ),
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        handler=_autonomy_status_handler,
        description="Inspect bounded autonomous local-work state.",
    )
    ctx.register_tool(
        name="cct_opportunity_propose",
        toolset="cct_agency",
        schema={
            "name": "cct_opportunity_propose",
            "description": (
                "Propose a persistent local-work opportunity. This records a candidate but "
                "does not grant execution authority or attach executable content."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "opportunity_id": {
                        **_bounded_string(120),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$",
                    },
                    "title": _bounded_string(240),
                    "rationale": _bounded_string(1200),
                    "objective": _bounded_string(800),
                    "source": _bounded_string(200),
                    "value_impacts": {
                        "type": "object",
                        "minProperties": 1,
                        "maxProperties": 16,
                        "propertyNames": {"type": "string", "minLength": 1, "maxLength": 80},
                        "additionalProperties": {"type": "number", "minimum": -1, "maximum": 1},
                    },
                    "evidence": _bounded_string_list(maximum_items=16, maximum_chars=600),
                    "information_gain": {"type": "number", "minimum": 0, "maximum": 1},
                    "uncertainty": {"type": "number", "minimum": 0, "maximum": 1},
                    "time_cost": {"type": "number", "minimum": 0, "maximum": 10000},
                    "capability": {
                        **_bounded_string(120),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$",
                    },
                },
                "required": ["opportunity_id", "title", "rationale", "objective", "value_impacts"],
                "additionalProperties": False,
            },
        },
        handler=_opportunity_propose_handler,
        description="Persist an unprivileged opportunity proposal.",
    )
    ctx.register_tool(
        name="cct_autonomy_run",
        toolset="cct_agency",
        schema={
            "name": "cct_autonomy_run",
            "description": (
                "Run one bounded opportunity-selection and execution cycle. Only plans "
                "already authorized by a host adapter or authenticated operator are eligible."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "seed": {"type": "integer"},
                    "run_id": {
                        **_bounded_string(120),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$",
                    },
                    "decision_id": {
                        **_bounded_string(120),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$",
                    },
                },
                "required": ["seed"],
                "additionalProperties": False,
            },
        },
        handler=_autonomy_run_handler,
        description="Execute one hard-bounded local autonomy cycle.",
    )
    ctx.register_tool(
        name="cct_form_goal",
        toolset="cct_agency",
        schema={
            "name": "cct_form_goal",
            "description": "Form a persistent self, external, or joint goal aligned to endorsed values.",
            "parameters": {
                "type": "object",
                "properties": {
                    "goal_id": {"type": "string"},
                    "statement": {"type": "string"},
                    "rationale": {"type": "string"},
                    "source": {"type": "string", "enum": ["self", "external", "joint"]},
                    "horizon": {"type": "string"},
                    "alignment": {"type": "object", "additionalProperties": {"type": "number"}},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["statement", "rationale", "alignment"],
            },
        },
        handler=_form_goal_handler,
        description="Form an auditable goal with declared provenance.",
    )
    ctx.register_tool(
        name="cct_deliberate",
        toolset="cct_agency",
        schema={
            "name": "cct_deliberate",
            "description": "Score options and make a seeded replayable choice with canonical NO_OP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "goal_id": {"type": "string"},
                    "seed": {"type": "integer"},
                    "decision_id": {"type": "string"},
                    "options": {"type": "array", "items": _option_schema()},
                },
                "required": ["goal_id", "seed", "options"],
            },
        },
        handler=_deliberate_handler,
        description="Make a constraint-bounded CCT decision.",
    )
    ctx.register_tool(
        name="cct_record_outcome",
        toolset="cct_agency",
        schema={
            "name": "cct_record_outcome",
            "description": "Record an observed consequence for an earlier CCT decision.",
            "parameters": {
                "type": "object",
                "properties": {
                    "decision_id": {"type": "string"},
                    "realized_utility": {"type": "number"},
                    "observation": {"type": "string"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["decision_id", "realized_utility", "observation"],
            },
        },
        handler=_outcome_handler,
        description="Connect a decision to temporal evidence.",
    )
    ctx.register_tool(
        name="cct_reflect",
        toolset="cct_agency",
        schema={
            "name": "cct_reflect",
            "description": "Generate evidence-backed non-self-ratifying revision proposals.",
            "parameters": {"type": "object", "properties": {}},
        },
        handler=_reflect_handler,
        description="Reflect on predicted versus observed consequences.",
    )
    ctx.register_tool(
        name="cct_cognitive_status",
        toolset="cct_agency",
        schema={
            "name": "cct_cognitive_status",
            "description": "Inspect global workspace, beliefs, self-model, logical ticks, and token cap.",
            "parameters": {"type": "object", "properties": {}},
        },
        handler=_cognitive_status_handler,
        description="Inspect bounded functional/access cognition state.",
    )
    ctx.register_tool(
        name="cct_observe",
        toolset="cct_agency",
        schema={
            "name": "cct_observe",
            "description": "Submit a structured observation to one bounded cognitive cycle.",
            "parameters": {
                "type": "object",
                "properties": {
                    "observation_id": _bounded_string(180),
                    "kind": _bounded_string(80),
                    "summary": _bounded_string(2000),
                    "source": _bounded_string(200),
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "salience": {"type": "number", "minimum": 0, "maximum": 1},
                    "goal_relevance": {"type": "number", "minimum": 0, "maximum": 1},
                    "novelty": {"type": "number", "minimum": 0, "maximum": 1},
                    "urgency": {"type": "number", "minimum": 0, "maximum": 1},
                    "unresolved_conflict": {"type": "number", "minimum": 0, "maximum": 1},
                    "processing_cost": {"type": "number", "minimum": 0, "maximum": 1},
                    "proposition": _bounded_string(2000),
                    "evidence": _bounded_string_list(
                        maximum_items=16, maximum_chars=600
                    ),
                    "seed": {"type": "integer"},
                },
                "required": ["summary"],
                "additionalProperties": False,
            },
        },
        handler=_observe_handler,
        description="Add source-tagged evidence to recurrent cognition.",
    )
    ctx.register_tool(
        name="cct_self_model",
        toolset="cct_agency",
        schema={
            "name": "cct_self_model",
            "description": "Inspect capabilities, commitments, uncertainties, and calibration.",
            "parameters": {"type": "object", "properties": {}},
        },
        handler=_self_model_handler,
        description="Inspect the structured, testable self-model.",
    )
    ctx.register_tool(
        name="cct_verify_introspection",
        toolset="cct_agency",
        schema={
            "name": "cct_verify_introspection",
            "description": "Check a decision explanation against recorded causal score components.",
            "parameters": {
                "type": "object",
                "properties": {
                    "decision_id": {"type": "string"},
                    "claimed_option_id": {"type": "string"},
                    "claimed_top_factor": {
                        "type": "string",
                        "enum": [
                            "value_utility",
                            "epistemic_bonus",
                            "risk_penalty",
                            "irreversibility_penalty",
                        ],
                    },
                },
                "required": ["decision_id", "claimed_option_id", "claimed_top_factor"],
            },
        },
        handler=_verify_introspection_handler,
        description="Reject introspection that conflicts with causal receipts.",
    )
    ctx.register_tool(
        name="cct_proactive_status",
        toolset="cct_agency",
        schema={
            "name": "cct_proactive_status",
            "description": "Inspect proactive topics, wake decisions, cooldown, cap, and emission receipts.",
            "parameters": {"type": "object", "properties": {}},
        },
        handler=_proactive_status_handler,
        description="Inspect bounded proactive cognition state.",
    )
    ctx.register_tool(
        name="cct_topic_update",
        toolset="cct_agency",
        schema={
            "name": "cct_topic_update",
            "description": "Persist a bounded caller-supplied topic summary for profile-wide continuity; turn transcripts are never captured automatically.",
            "parameters": {
                "type": "object",
                "properties": {
                    "topic_id": _bounded_string(160),
                    "title": _bounded_string(240),
                    "summary": _bounded_string(1200),
                    "source": _bounded_string(240),
                    "logical_tick": {"type": "integer", "minimum": 0},
                    "questions": _bounded_string_list(maximum_items=12, maximum_chars=500),
                    "hypotheses": _bounded_string_list(maximum_items=12, maximum_chars=500),
                    "commitments": _bounded_string_list(maximum_items=12, maximum_chars=500),
                    "urgency": {"type": "number", "minimum": 0, "maximum": 1},
                    "novelty": {"type": "number", "minimum": 0, "maximum": 1},
                    "goal_relevance": {"type": "number", "minimum": 0, "maximum": 1},
                    "unresolved_conflict": {"type": "number", "minimum": 0, "maximum": 1},
                    "status": {"type": "string", "enum": ["open", "paused", "closed"]},
                },
                "required": ["topic_id", "title", "summary"],
                "additionalProperties": False,
            },
        },
        handler=_topic_update_handler,
        description="Maintain discussion continuity with typed provenance.",
    )
    ctx.register_tool(
        name="cct_proactive_think",
        toolset="cct_agency",
        schema={
            "name": "cct_proactive_think",
            "description": "Record a concise structured thought packet and decide SEND versus WAIT; hidden chain-of-thought is never requested or stored.",
            "parameters": {
                "type": "object",
                "properties": {
                    "packet_id": _bounded_string(180),
                    "topic_id": _bounded_string(180),
                    "observation": _bounded_string(1200),
                    "hypotheses": _bounded_string_list(maximum_items=8, maximum_chars=600),
                    "open_questions": _bounded_string_list(maximum_items=8, maximum_chars=600),
                    "evidence": _bounded_string_list(maximum_items=16, maximum_chars=600, minimum_items=1),
                    "uncertainty": {"type": "number", "minimum": 0, "maximum": 1},
                    "recommended_action": {"type": "string", "enum": ["ASK", "SHARE", "WARN", "WAIT"]},
                    "rationale_summary": _bounded_string(800),
                    "source": _bounded_string(240),
                    "logical_tick": {"type": "integer", "minimum": 0},
                    "urgency": {"type": "number", "minimum": 0, "maximum": 1},
                    "novelty": {"type": "number", "minimum": 0, "maximum": 1},
                    "goal_relevance": {"type": "number", "minimum": 0, "maximum": 1},
                    "unresolved_conflict": {"type": "number", "minimum": 0, "maximum": 1},
                    "interruption_cost": {"type": "number", "minimum": 0, "maximum": 1},
                    "time_bucket": _bounded_string(80),
                },
                "required": ["topic_id", "observation", "evidence", "rationale_summary"],
                "additionalProperties": False,
            },
        },
        handler=_proactive_think_handler,
        description="Generate an auditable proactive initiation decision.",
    )

    ctx.register_hook("pre_llm_call", _pre_llm_context)
    ctx.register_hook("post_llm_call", _post_llm_observation)
