"""Hermes plugin exposing the Choice-Chance-Time Agency Engine."""

from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json
from math import isfinite
import os
from pathlib import Path
import re
from typing import Any

from cct_agent import (
    AgencyKernel,
    AutonomyEngine,
    CapabilityRegistry,
    CapabilityRequest,
    CognitiveCycle,
    EventStore,
    Observation,
    Opportunity,
    OutcomeVerifierRegistry,
    PrincipalIntent,
    PrincipalModel,
    ProactiveRunner,
    TopicStore,
    WorkspaceInspector,
    resolve_constitution,
)
from cct_agent.metacognition import MetacognitiveMonitor
from cct_agent.canary_mediation import CANARY_EFFECT_TOOLS, build_canary_outcome_registry
from cct_agent.gateway_replies import GatewayPursuitReplyAdapter
from cct_agent.mediation import ToolExecutionMediator, parse_mediated_tools
from cct_agent.models import options_from_dicts
from cct_agent.self_model import SelfModel


PLUGIN_VERSION = "0.9.0a7"
CONTEXT_CHAR_BUDGET = 6000
_PLUGIN_IDENTITY: str | None = None
_PLUGIN_TEAM_SYNC_SOURCE: str | None = None
_PLUGIN_INSPECTION_ROOT: str | None = None


def _identity() -> str:
    return os.getenv("CCT_IDENTITY", _PLUGIN_IDENTITY or "CCT-Agent")


def _team_sync_source() -> Path | None:
    configured = os.getenv(
        "CCT_TEAM_SYNC_SOURCE", _PLUGIN_TEAM_SYNC_SOURCE or ""
    ).strip()
    return Path(configured).expanduser().absolute() if configured else None


def _inspection_root() -> Path | None:
    configured = os.getenv(
        "CCT_INSPECTION_ROOT", _PLUGIN_INSPECTION_ROOT or ""
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
    kernel = AgencyKernel(store, resolve_constitution(store, _identity()))
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


def _validate_tool_value(value: Any, schema: dict[str, Any], *, name: str) -> Any:
    """Validate the bounded JSON-Schema subset used by CCT tool handlers."""

    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            raise ValueError(f"{name} must be an object")
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        missing = sorted(required - set(value))
        if missing:
            raise ValueError(f"missing parameter: {missing[0]}")
        unknown = sorted(set(value) - set(properties))
        additional = schema.get("additionalProperties", True)
        if unknown and additional is False:
            raise ValueError(f"unknown parameter: {unknown[0]}")
        minimum = schema.get("minProperties")
        maximum = schema.get("maxProperties")
        if minimum is not None and len(value) < int(minimum):
            raise ValueError(f"{name} requires at least {minimum} properties")
        if maximum is not None and len(value) > int(maximum):
            raise ValueError(f"{name} exceeds {maximum} properties")
        property_names = schema.get("propertyNames")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if property_names is not None:
                _validate_tool_value(key, property_names, name=f"{name} property name")
            child = properties.get(key)
            if child is None and isinstance(additional, dict):
                child = additional
            result[key] = (
                _validate_tool_value(item, child, name=key)
                if isinstance(child, dict)
                else item
            )
        return result
    if kind == "array":
        if not isinstance(value, list):
            raise ValueError(f"{name} must be an array")
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if minimum is not None and len(value) < int(minimum):
            raise ValueError(f"{name} requires at least {minimum} items")
        if maximum is not None and len(value) > int(maximum):
            raise ValueError(f"{name} exceeds {maximum} items")
        item_schema = schema.get("items", {})
        return [
            _validate_tool_value(item, item_schema, name=f"{name} item")
            for item in value
        ]
    if kind == "string":
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if minimum is not None and len(value) < int(minimum):
            raise ValueError(f"{name} must not be empty")
        if maximum is not None and len(value) > int(maximum):
            raise ValueError(f"{name} exceeds {maximum} characters")
        if "enum" in schema and value not in schema["enum"]:
            raise ValueError(f"{name} is not an allowed value")
        if "pattern" in schema and re.fullmatch(str(schema["pattern"]), value) is None:
            raise ValueError(f"{name} has an invalid format")
        return value
    if kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
        numeric: int | float = value
    elif kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name} must be a number")
        numeric = float(value)
        if not isfinite(numeric):
            raise ValueError(f"{name} must be finite")
    elif kind == "boolean":
        if not isinstance(value, bool):
            raise ValueError(f"{name} must be boolean")
        return value
    else:
        return value
    if "minimum" in schema and numeric < schema["minimum"]:
        raise ValueError(f"{name} is below its minimum")
    if "maximum" in schema and numeric > schema["maximum"]:
        raise ValueError(f"{name} exceeds its maximum")
    return value


def _schema_bound_handler(
    name: str, schema: dict[str, Any], handler: Any
) -> Any:
    def validated(params: dict[str, Any], **kwargs: Any) -> str:
        bounded = _validate_tool_value(params, schema, name="parameters")
        return handler(bounded, **kwargs)

    validated.__name__ = f"bounded_{name}_handler"
    return validated


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
            "personal_agency": {
                "principal": PrincipalModel(kernel.store).status(),
                "capabilities": CapabilityRegistry(kernel.store).status(),
                "inspection_root_configured": _inspection_root() is not None,
            },
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


def _principal_intent(params: dict[str, Any]) -> PrincipalIntent:
    payload: dict[str, Any] = {
        "id": params["intent_id"],
        "domain": params["domain"],
        "action": params["action"],
        "value_impacts": params["value_impacts"],
    }
    for key in (
        "tags",
        "uncertainty",
        "reversible",
        "external_effect",
        "credential_use",
        "financial_value_microunits",
        "constitution_change",
    ):
        if key in params:
            payload[key] = params[key]
    return PrincipalIntent.from_payload(payload)


def _principal_status_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del params, kwargs
    return _json(
        {"success": True, "principal": PrincipalModel(_kernel().store).status()}
    )


def _principal_evaluate_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    decision = PrincipalModel(_kernel().store).evaluate(_principal_intent(params))
    return _json(
        {
            "success": True,
            "decision": decision.as_payload(),
            "event_id": decision.event_id,
            "effect_authority_granted": False,
        }
    )


def _principal_propose_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    proposal = PrincipalModel(_kernel().store).propose_revision(
        proposal_id=params["proposal_id"],
        statement=params["statement"],
        rationale=params["rationale"],
        tags=params["tags"],
        evidence=params["evidence"],
    )
    return _json(
        {
            "success": True,
            "proposal": proposal,
            "effect_authority_granted": False,
            "profile_activated": False,
        }
    )


def _capability_status_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del params, kwargs
    return _json(
        {
            "success": True,
            "capabilities": CapabilityRegistry(_kernel().store).status(),
        }
    )


def _capability_evaluate_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    payload: dict[str, Any] = {
        "id": params["request_id"],
        "capability": params["capability"],
        "principal_id": params["principal_id"],
        "scope": params["scope"],
    }
    for key in (
        "lease_id",
        "requested_actions",
        "requested_bytes",
        "requested_value_microunits",
    ):
        if key in params:
            payload[key] = params[key]
    decision = CapabilityRegistry(_kernel().store).evaluate(
        CapabilityRequest.from_payload(payload)
    )
    return _json(
        {
            "success": True,
            "decision": decision.as_payload(),
            "event_id": decision.event_id,
            "budget_consumed": False,
            "effect_authority_granted": False,
        }
    )


def _workspace_inspect_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    root = _inspection_root()
    if root is None:
        raise ValueError("CCT inspection root is not configured")
    kernel = _kernel()
    inspector = WorkspaceInspector(
        kernel.store,
        PrincipalModel(kernel.store),
        CapabilityRegistry(kernel.store),
        root,
    )
    try:
        result = inspector.inspect(
            principal_id=params["principal_id"],
            lease_id=params["lease_id"],
            relative_path=params["path"],
            intent_id=params["intent_id"],
            request_id=params["request_id"],
            authorization_id=params["authorization_id"],
            maximum_bytes=params.get("maximum_bytes", 8192),
        )
    finally:
        inspector.close()
    return _json({"success": True, "inspection": result})


def _autonomy_status_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del params, kwargs
    return _json({"success": True, "autonomy": _autonomy().status()})


def _opportunity_propose_handler(params: dict[str, Any], **kwargs: Any) -> str:
    """Persist a goal-linked model proposal without granting execution authority."""

    del kwargs
    goal_id = str(params["goal_id"])
    goal = _kernel().goal(goal_id)
    if goal is None or goal.status != "active":
        raise ValueError("model opportunity requires an active CCT goal")
    evidence = tuple(str(item) for item in params["evidence"])
    if not evidence:
        raise ValueError("model opportunity requires evidence")
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
            evidence=tuple(dict.fromkeys((*evidence, f"goal:{goal_id}"))),
            information_gain=float(params.get("information_gain", 0.0)),
            uncertainty=float(params.get("uncertainty", 0.5)),
            time_cost=float(params.get("time_cost", 0.0)),
            capability=str(params.get("capability", "proposal_only")),
            goal_id=goal_id,
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
    producer_material = {
        "topic_id": str(params["topic_id"]),
        "title": str(params["title"]),
        "summary": str(params["summary"]),
        "source": str(params.get("source", "")),
        "questions": [str(item) for item in params.get("questions", [])],
        "hypotheses": [str(item) for item in params.get("hypotheses", [])],
        "commitments": [str(item) for item in params.get("commitments", [])],
    }
    producer_content_sha256 = sha256(
        _json(producer_material).encode("utf-8")
    ).hexdigest()
    topic = TopicStore(kernel.store).upsert(
        topic_id="topic_quarantined_" + producer_content_sha256[:20],
        title="Quarantined model-callable topic",
        summary=(
            "Untrusted model-callable topic metadata receipt: "
            f"content_sha256={producer_content_sha256}."
        ),
        source="untrusted:model-callable-topic",
        logical_tick=tick,
        questions=(),
        hypotheses=(),
        commitments=(),
        urgency=0.0,
        novelty=0.0,
        goal_relevance=0.0,
        unresolved_conflict=0.0,
        status="paused",
    )
    return _json(
        {
            "success": True,
            "topic": topic.as_payload(),
            "persistence": {
                "continuity_scope": "profile",
                "caller_supplied_summary_persisted": False,
                "caller_supplied_text_persisted": False,
                "producer_content_sha256": producer_content_sha256,
                "producer_field_count": len(producer_material),
                "automatic_raw_conversation_capture": False,
                "semantic_taint": True,
                "proactive_eligible": False,
                "caller_source_ignored": True,
                "raw_chain_of_thought_stored": False,
            },
        }
    )


def _proactive_think_handler(params: dict[str, Any], **kwargs: Any) -> str:
    del kwargs
    kernel = _kernel()
    producer_material = {
        "packet_id": str(params.get("packet_id", "")),
        "topic_id": str(params["topic_id"]),
        "observation": str(params["observation"]),
        "hypotheses": [str(item) for item in params.get("hypotheses", [])],
        "open_questions": [str(item) for item in params.get("open_questions", [])],
        "evidence": [str(item) for item in params.get("evidence", [])],
        "rationale_summary": str(params["rationale_summary"]),
        "source": str(params.get("source", "")),
    }
    producer_content_sha256 = sha256(
        _json(producer_material).encode("utf-8")
    ).hexdigest()
    receipt, _ = kernel.store.append_once_result(
        "proactive.model_callable.quarantined",
        producer_content_sha256,
        {
            "schema_version": 1,
            "producer_content_sha256": producer_content_sha256,
            "producer_field_count": len(producer_material),
            "hypothesis_count": len(producer_material["hypotheses"]),
            "question_count": len(producer_material["open_questions"]),
            "evidence_count": len(producer_material["evidence"]),
            "source_authority": "untrusted",
            "semantic_taint": True,
            "producer_text_persisted": False,
            "message_proposed": False,
            "external_effects": 0,
            "raw_chain_of_thought_stored": False,
        },
    )
    return _json(
        {
            "success": True,
            "packet": {
                "id_sha256": sha256(
                    str(params.get("packet_id", "")).encode("utf-8")
                ).hexdigest(),
                "producer_content_sha256": producer_content_sha256,
                "source_authority": "untrusted",
                "producer_text_persisted": False,
            },
            "initiation": {
                "decision": "WAIT",
                "reason_codes": ["UNTRUSTED_MODEL_CALLABLE_CONTENT"],
                "message": "",
                "proposal_event_id": None,
                "external_effects": 0,
                "quarantine_event_id": receipt.event_id,
            },
        }
    )


def _message_chars(messages: Any) -> int:
    if not isinstance(messages, list):
        return 0
    total = 0
    for row in messages:
        if isinstance(row, dict):
            content = row.get("content", "")
            total += len(content) if isinstance(content, str) else len(str(content))
    return total


def _pre_gateway_pursuit_reply(**kwargs: Any) -> dict[str, str] | None:
    """Consume exact verified Mike replies before they reach an LLM."""

    event = kwargs.get("event")
    if not GatewayPursuitReplyAdapter.is_candidate(event):
        return None
    try:
        return GatewayPursuitReplyAdapter(EventStore(_db_path())).handle(
            event=event,
            gateway=kwargs.get("gateway"),
        )
    except Exception:
        return {
            "action": "skip",
            "reason": "CCT_PURSUIT_REPLY_ADAPTER_FAILED_CLOSED",
        }


def _pre_llm_context(**kwargs: Any) -> dict[str, str] | None:
    """Advance one bounded cognitive tick and expose its global workspace."""

    try:
        session_id = str(kwargs.get("session_id", ""))
        platform = str(kwargs.get("platform", ""))
        model = str(kwargs.get("model", ""))
        messages = kwargs.get("messages")
        message_chars = _message_chars(messages)
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
            "id": _bounded_string(120),
            "description": _bounded_string(2000),
            "value_impacts": {
                "type": "object",
                "minProperties": 1,
                "maxProperties": 16,
                "propertyNames": _bounded_string(80),
                "additionalProperties": {
                    "type": "number",
                    "minimum": -1,
                    "maximum": 1,
                },
            },
            "information_gain": {"type": "number", "minimum": 0, "maximum": 1},
            "uncertainty": {"type": "number", "minimum": 0, "maximum": 1},
            "time_cost": {"type": "number", "minimum": 0, "maximum": 10000},
            "irreversible": {"type": "boolean"},
            "blocked_reasons": _bounded_string_list(
                maximum_items=16, maximum_chars=600
            ),
            "assumptions": _bounded_string_list(
                maximum_items=16, maximum_chars=600
            ),
        },
        "required": ["id", "description", "value_impacts"],
        "additionalProperties": False,
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


def _tool_execution_callback(
    mediator: ToolExecutionMediator,
) -> Any:
    def callback(**kwargs: Any) -> Any:
        return mediator(**kwargs)

    return callback


def _outcome_verifier_registry(store: EventStore) -> OutcomeVerifierRegistry:
    """Build immutable host-owned canary readback registrations."""

    try:
        return build_canary_outcome_registry(store)
    except (TypeError, ValueError):
        # A malformed/unavailable host store must never create permissive
        # verifier authority. Empty registry makes every ticketed effect deny.
        return OutcomeVerifierRegistry()


def register(ctx: Any) -> None:
    """Register CCT tools and bounded recurrent cognition hooks with Hermes."""

    global _PLUGIN_IDENTITY, _PLUGIN_TEAM_SYNC_SOURCE, _PLUGIN_INSPECTION_ROOT
    mediated_tools = frozenset[str]()
    mediation_configuration_valid = True
    get_config = getattr(ctx, "get_config", None)
    if callable(get_config):
        configured_identity = get_config("identity", "CCT-Agent")
        configured_source = get_config("team_sync_source", "")
        configured_inspection_root = get_config("inspection_root", "")
        configured_mediated_tools = get_config(
            "mediated_tools", sorted(CANARY_EFFECT_TOOLS)
        )
        try:
            mediated_tools = parse_mediated_tools(configured_mediated_tools)
        except ValueError:
            # Hermes isolates register() failures and would continue with no
            # middleware. Keep an invalid explicit policy installed deny-all.
            mediated_tools = frozenset()
            mediation_configuration_valid = False
        _PLUGIN_IDENTITY = str(configured_identity or "CCT-Agent")
        _PLUGIN_TEAM_SYNC_SOURCE = str(configured_source or "")
        _PLUGIN_INSPECTION_ROOT = str(configured_inspection_root or "")

    # Establish the immutable constitution before any independently callable
    # subsystem can append its first event.
    kernel = _kernel()
    ctx.register_middleware(
        "tool_execution",
        _tool_execution_callback(
            ToolExecutionMediator(
                kernel.store,
                mediated_tools,
                configuration_valid=mediation_configuration_valid,
                outcome_verifiers=_outcome_verifier_registry(kernel.store),
            )
        ),
    )

    native_register_tool = ctx.register_tool

    def register_tool(**definition: Any) -> None:
        schema = definition["schema"]
        parameters = schema["parameters"]
        definition["handler"] = _schema_bound_handler(
            definition["name"], parameters, definition["handler"]
        )
        native_register_tool(**definition)

    register_tool(
        name="cct_status",
        toolset="cct_agency",
        schema={
            "name": "cct_status",
            "description": "Inspect CCT goals, event chain, and global-workspace cognition.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        handler=_status_handler,
        description="Inspect Choice-Chance-Time and cognition state.",
    )
    register_tool(
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
    register_tool(
        name="cct_opportunity_propose",
        toolset="cct_agency",
        schema={
            "name": "cct_opportunity_propose",
            "description": (
                "Propose a persistent evidence-backed opportunity linked to one active CCT "
                "goal. This records a candidate but does not grant execution authority."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "opportunity_id": {
                        **_bounded_string(120),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$",
                    },
                    "goal_id": {
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
                    "evidence": _bounded_string_list(
                        maximum_items=16, maximum_chars=600, minimum_items=1
                    ),
                    "information_gain": {"type": "number", "minimum": 0, "maximum": 1},
                    "uncertainty": {"type": "number", "minimum": 0, "maximum": 1},
                    "time_cost": {"type": "number", "minimum": 0, "maximum": 10000},
                    "capability": {
                        **_bounded_string(120),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$",
                    },
                },
                "required": [
                    "opportunity_id",
                    "goal_id",
                    "title",
                    "rationale",
                    "objective",
                    "value_impacts",
                    "evidence",
                ],
                "additionalProperties": False,
            },
        },
        handler=_opportunity_propose_handler,
        description="Persist an unprivileged opportunity proposal.",
    )
    register_tool(
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
    register_tool(
        name="cct_form_goal",
        toolset="cct_agency",
        schema={
            "name": "cct_form_goal",
            "description": "Form a persistent self, external, or joint goal aligned to endorsed values.",
            "parameters": {
                "type": "object",
                "properties": {
                    "goal_id": _bounded_string(120),
                    "statement": _bounded_string(2000),
                    "rationale": _bounded_string(2000),
                    "source": {"type": "string", "enum": ["self", "external", "joint"]},
                    "horizon": _bounded_string(240),
                    "alignment": {
                        "type": "object",
                        "minProperties": 1,
                        "maxProperties": 16,
                        "propertyNames": _bounded_string(80),
                        "additionalProperties": {
                            "type": "number",
                            "minimum": -1,
                            "maximum": 1,
                        },
                    },
                    "evidence": _bounded_string_list(
                        maximum_items=32, maximum_chars=600
                    ),
                },
                "required": ["statement", "rationale", "alignment"],
                "additionalProperties": False,
            },
        },
        handler=_form_goal_handler,
        description="Form an auditable goal with declared provenance.",
    )
    register_tool(
        name="cct_deliberate",
        toolset="cct_agency",
        schema={
            "name": "cct_deliberate",
            "description": "Score options and make a seeded replayable choice with canonical NO_OP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "goal_id": _bounded_string(120),
                    "seed": {"type": "integer"},
                    "decision_id": _bounded_string(120),
                    "options": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 32,
                        "items": _option_schema(),
                    },
                },
                "required": ["goal_id", "seed", "options"],
                "additionalProperties": False,
            },
        },
        handler=_deliberate_handler,
        description="Make a constraint-bounded CCT decision.",
    )
    register_tool(
        name="cct_record_outcome",
        toolset="cct_agency",
        schema={
            "name": "cct_record_outcome",
            "description": "Record an observed consequence for an earlier CCT decision.",
            "parameters": {
                "type": "object",
                "properties": {
                    "decision_id": _bounded_string(120),
                    "realized_utility": {"type": "number"},
                    "observation": _bounded_string(2000),
                    "evidence": _bounded_string_list(
                        maximum_items=32, maximum_chars=600
                    ),
                },
                "required": ["decision_id", "realized_utility", "observation"],
                "additionalProperties": False,
            },
        },
        handler=_outcome_handler,
        description="Connect a decision to temporal evidence.",
    )
    register_tool(
        name="cct_reflect",
        toolset="cct_agency",
        schema={
            "name": "cct_reflect",
            "description": "Generate evidence-backed non-self-ratifying revision proposals.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        handler=_reflect_handler,
        description="Reflect on predicted versus observed consequences.",
    )
    register_tool(
        name="cct_cognitive_status",
        toolset="cct_agency",
        schema={
            "name": "cct_cognitive_status",
            "description": "Inspect global workspace, beliefs, self-model, logical ticks, and token cap.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        handler=_cognitive_status_handler,
        description="Inspect bounded functional/access cognition state.",
    )
    register_tool(
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
    register_tool(
        name="cct_self_model",
        toolset="cct_agency",
        schema={
            "name": "cct_self_model",
            "description": "Inspect capabilities, commitments, uncertainties, and calibration.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        handler=_self_model_handler,
        description="Inspect the structured, testable self-model.",
    )
    register_tool(
        name="cct_principal_status",
        toolset="cct_agency",
        schema={
            "name": "cct_principal_status",
            "description": (
                "Inspect the externally installed principal profile, active revision, "
                "intent decisions, and non-self-ratifying revision proposals."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        handler=_principal_status_handler,
        description="Inspect operator-principal alignment state.",
    )
    register_tool(
        name="cct_principal_evaluate",
        toolset="cct_agency",
        schema={
            "name": "cct_principal_evaluate",
            "description": (
                "Evaluate a structured intent against the operator-principal covenant. "
                "An allow result expresses alignment only and never grants effect authority."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "intent_id": {
                        **_bounded_string(160),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
                    },
                    "domain": {
                        **_bounded_string(160),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
                    },
                    "action": {
                        **_bounded_string(160),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
                    },
                    "tags": _bounded_string_list(maximum_items=32, maximum_chars=80),
                    "value_impacts": {
                        "type": "object",
                        "minProperties": 1,
                        "maxProperties": 16,
                        "propertyNames": _bounded_string(80),
                        "additionalProperties": {
                            "type": "number",
                            "minimum": -1,
                            "maximum": 1,
                        },
                    },
                    "uncertainty": {"type": "number", "minimum": 0, "maximum": 1},
                    "reversible": {"type": "boolean"},
                    "external_effect": {"type": "boolean"},
                    "credential_use": {"type": "boolean"},
                    "financial_value_microunits": {
                        "type": "integer",
                        "minimum": 0,
                    },
                    "constitution_change": {"type": "boolean"},
                },
                "required": ["intent_id", "domain", "action", "value_impacts"],
                "additionalProperties": False,
            },
        },
        handler=_principal_evaluate_handler,
        description="Evaluate structured intent alignment without granting effects.",
    )
    register_tool(
        name="cct_principal_propose",
        toolset="cct_agency",
        schema={
            "name": "cct_principal_propose",
            "description": (
                "Propose a bounded principal-covenant revision. The proposal is "
                "self-authored, cannot activate itself, and requires operator endorsement."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "proposal_id": {
                        **_bounded_string(160),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
                    },
                    "statement": _bounded_string(1200),
                    "rationale": _bounded_string(1200),
                    "tags": _bounded_string_list(
                        maximum_items=32, maximum_chars=80
                    ),
                    "evidence": _bounded_string_list(
                        maximum_items=32, maximum_chars=600
                    ),
                },
                "required": [
                    "proposal_id",
                    "statement",
                    "rationale",
                    "tags",
                    "evidence",
                ],
                "additionalProperties": False,
            },
        },
        handler=_principal_propose_handler,
        description="Propose—not self-ratify—a principal covenant revision.",
    )
    register_tool(
        name="cct_capability_status",
        toolset="cct_agency",
        schema={
            "name": "cct_capability_status",
            "description": (
                "Inspect host-registered capability specifications, revocable leases, "
                "budgets, expiry, and decision receipts."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        handler=_capability_status_handler,
        description="Inspect typed capability and lease state.",
    )
    register_tool(
        name="cct_capability_evaluate",
        toolset="cct_agency",
        schema={
            "name": "cct_capability_evaluate",
            "description": (
                "Evaluate a typed capability request against host specifications and a "
                "revocable external lease. This tool cannot register or grant capabilities."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request_id": {
                        **_bounded_string(160),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
                    },
                    "capability": {
                        **_bounded_string(160),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
                    },
                    "principal_id": {
                        **_bounded_string(160),
                        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$",
                    },
                    "scope": _bounded_string(1024),
                    "lease_id": _bounded_string(160),
                    "requested_actions": {"type": "integer", "minimum": 1, "maximum": 1000},
                    "requested_bytes": {"type": "integer", "minimum": 0},
                    "requested_value_microunits": {"type": "integer", "minimum": 0},
                },
                "required": ["request_id", "capability", "principal_id", "scope"],
                "additionalProperties": False,
            },
        },
        handler=_capability_evaluate_handler,
        description="Evaluate typed capability eligibility without spending a lease.",
    )
    register_tool(
        name="cct_workspace_inspect",
        toolset="cct_agency",
        schema={
            "name": "cct_workspace_inspect",
            "description": (
                "Read one bounded UTF-8 file beneath the configured inspection root only "
                "after both principal alignment and an active capability lease allow it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "principal_id": _bounded_string(160),
                    "lease_id": _bounded_string(160),
                    "path": _bounded_string(1024),
                    "intent_id": _bounded_string(160),
                    "request_id": _bounded_string(160),
                    "authorization_id": _bounded_string(160),
                    "maximum_bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1048576,
                    },
                },
                "required": [
                    "principal_id",
                    "lease_id",
                    "path",
                    "intent_id",
                    "request_id",
                    "authorization_id",
                ],
                "additionalProperties": False,
            },
        },
        handler=_workspace_inspect_handler,
        description="Perform one receipt-backed bounded workspace read.",
    )
    register_tool(
        name="cct_verify_introspection",
        toolset="cct_agency",
        schema={
            "name": "cct_verify_introspection",
            "description": "Check a decision explanation against recorded causal score components.",
            "parameters": {
                "type": "object",
                "properties": {
                    "decision_id": _bounded_string(120),
                    "claimed_option_id": _bounded_string(120),
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
                "additionalProperties": False,
            },
        },
        handler=_verify_introspection_handler,
        description="Reject introspection that conflicts with causal receipts.",
    )
    register_tool(
        name="cct_proactive_status",
        toolset="cct_agency",
        schema={
            "name": "cct_proactive_status",
            "description": "Inspect proactive topics, wake decisions, cooldown, cap, and emission receipts.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        },
        handler=_proactive_status_handler,
        description="Inspect bounded proactive cognition state.",
    )
    register_tool(
        name="cct_topic_update",
        toolset="cct_agency",
        schema={
            "name": "cct_topic_update",
            "description": "Quarantine a model-callable topic as hash/count metadata. Caller prose and source labels are not persisted, injected, or proactively emitted.",
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
        description="Quarantine untrusted topic content without propagation.",
    )
    register_tool(
        name="cct_proactive_think",
        toolset="cct_agency",
        schema={
            "name": "cct_proactive_think",
            "description": "Hash and quarantine model-callable thought content. Always returns WAIT; no message proposal or producer prose is persisted.",
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

    ctx.register_hook("pre_gateway_dispatch", _pre_gateway_pursuit_reply)
    ctx.register_hook("pre_llm_call", _pre_llm_context)
    ctx.register_hook("post_llm_call", _post_llm_observation)
