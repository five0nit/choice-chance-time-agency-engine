"""Command-line surface for exercising and auditing the CCT kernel."""

from __future__ import annotations

import argparse
from dataclasses import replace
from dataclasses import asdict
from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Sequence

from .autonomy import AutonomyEngine
from .cognitive_cycle import CognitiveCycle, Observation
from .initiative import HMACFeedbackAuthority, InitiativeBridge, ProactiveFeedback
from .kernel import AgencyKernel, default_constitution
from .models import Option, options_from_dicts
from .proactive import InitiationSignals, ProactiveEngine
from .runner import ProactiveRunner
from .store import EventStore
from .topics import TopicStore


def _kernel(db: str) -> AgencyKernel:
    kernel = AgencyKernel(EventStore(Path(db)), default_constitution())
    kernel.initialize()
    return kernel


def _autonomy_engine(args: argparse.Namespace) -> AutonomyEngine:
    kernel = _kernel(args.db)
    return AutonomyEngine(
        kernel.store,
        kernel,
        Path(args.workspace),
        state_root=Path(args.state_root) if args.state_root else None,
    )


def _print(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _parse_alignment(values: Sequence[str]) -> dict[str, float]:
    result: dict[str, float] = {}
    for item in values:
        if "=" not in item:
            raise ValueError(f"alignment must use name=value: {item}")
        name, raw_value = item.split("=", 1)
        result[name] = float(raw_value)
    return result


def command_init(args: argparse.Namespace) -> None:
    _print(_kernel(args.db).status())


def command_goal_add(args: argparse.Namespace) -> None:
    kernel = _kernel(args.db)
    goal = kernel.form_goal(
        statement=args.statement,
        rationale=args.rationale,
        source=args.source,
        horizon=args.horizon,
        alignment=_parse_alignment(args.alignment),
        evidence=args.evidence,
        goal_id=args.goal_id,
    )
    _print(asdict(goal))


def command_goals(args: argparse.Namespace) -> None:
    _print([asdict(goal) for goal in _kernel(args.db).goals()])


def command_decide(args: argparse.Namespace) -> None:
    kernel = _kernel(args.db)
    rows = json.loads(Path(args.options).read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise ValueError("options file must contain a JSON array")
    _print(
        kernel.deliberate(
            goal_id=args.goal_id,
            options=options_from_dicts(rows),
            seed=args.seed,
            decision_id=args.decision_id,
        )
    )


def command_outcome(args: argparse.Namespace) -> None:
    event = _kernel(args.db).record_outcome(
        decision_id=args.decision_id,
        realized_utility=args.realized_utility,
        observation=args.observation,
        evidence=args.evidence,
    )
    _print({"event_id": event.event_id, "event_hash": event.event_hash})


def command_reflect(args: argparse.Namespace) -> None:
    _print(_kernel(args.db).reflect())


def command_replay(args: argparse.Namespace) -> None:
    _print(_kernel(args.db).replay_decision(args.decision_id))


def command_status(args: argparse.Namespace) -> None:
    _print(_kernel(args.db).status())


def command_autonomy_status(args: argparse.Namespace) -> None:
    _print(_autonomy_engine(args).status())


def command_autonomy_run(args: argparse.Namespace) -> None:
    _print(
        _autonomy_engine(args).run_once(
            seed=args.seed,
            run_id=args.run_id,
            decision_id=args.decision_id,
        )
    )


def command_cognitive_status(args: argparse.Namespace) -> None:
    cycle = CognitiveCycle(_kernel(args.db))
    _print({"cognition": cycle.status(), "context": cycle.context()})


def command_cognitive_observe(args: argparse.Namespace) -> None:
    cycle = CognitiveCycle(_kernel(args.db))
    observation = Observation(
        id=args.observation_id,
        kind=args.kind,
        summary=args.summary,
        source=args.source,
        confidence=args.confidence,
        salience=args.salience,
        goal_relevance=args.goal_relevance,
        novelty=args.novelty,
        urgency=args.urgency,
        evidence=tuple(args.evidence),
        proposition=args.proposition,
    )
    result = cycle.run(observations=[observation], seed=args.seed)
    _print({"cycle": result, "context": cycle.context()})


def command_cognitive_demo(args: argparse.Namespace) -> None:
    kernel = _kernel(args.db)
    goal_id = "goal_functional_access"
    goal = kernel.goal(goal_id)
    if goal is None:
        goal = kernel.form_goal(
            goal_id=goal_id,
            statement="Integrate attention, evidence, self-model, and temporal learning.",
            rationale="Unified reportable cognition improves calibrated operational agency.",
            source="joint",
            horizon="long",
            alignment={"truth": 0.9, "competence": 0.9, "autonomy": 0.7},
            evidence=["CCT Level-3 architecture acceptance contract."],
        )
    cycle = CognitiveCycle(kernel, consolidation_interval=1)
    tick = cycle.status()["logical_tick"] + 1
    if "run_tests" not in cycle.self_model.snapshot()["capabilities"]:
        cycle.self_model.declare_capability(
            name="run_tests",
            available=True,
            confidence=0.9,
            permission="allowed",
            evidence=("tool:pytest",),
            logical_tick=tick,
        )
    result = cycle.run(
        observations=[
            Observation(
                id=f"demo-observation-{tick}",
                kind="test_result",
                summary="Level-3 cognitive acceptance suite is available for verification.",
                source="tool:pytest",
                confidence=1.0,
                salience=0.9,
                goal_relevance=1.0,
                novelty=0.7,
                urgency=0.6,
                evidence=("test://cognitive-suite",),
                proposition="Level-3 behavior must be verified by executable tests.",
            )
        ],
        goal_id=goal.id,
        options=[
            Option(
                id="run_acceptance_suite",
                description="Run deterministic global-workspace acceptance tests.",
                value_impacts={"truth": 1.0, "competence": 0.9, "autonomy": 0.5},
                information_gain=0.9,
                uncertainty=0.1,
            ),
            Option(
                id="claim_without_testing",
                description="Claim Level-3 behavior without executable evidence.",
                value_impacts={"truth": -1.0, "competence": -0.8},
                uncertainty=1.0,
                blocked_reasons=("Capability claims require executable evidence.",),
            ),
        ],
        seed=args.seed,
        internal_signals={
            "context_pressure": 0.1,
            "error_rate": 0.0,
            "goal_progress": 0.8,
            "memory_integrity": 1.0,
            "tool_availability": 1.0,
        },
    )
    _print(
        {
            "claim": (
                "Bounded functional/access cognition demonstrated; phenomenal "
                "consciousness remains untested."
            ),
            "cycle": result,
            "status": cycle.status(),
            "context": cycle.context(),
            "chain": kernel.store.verify_chain(),
        }
    )


def _latest_logical_tick(store: EventStore) -> int:
    return max(
        (
            int(event.payload.get("logical_tick", 0))
            for event in store.events()
            if "logical_tick" in event.payload
        ),
        default=0,
    )


def command_topic_upsert(args: argparse.Namespace) -> None:
    store = EventStore(args.db)
    tick = args.logical_tick
    if tick is None:
        tick = _latest_logical_tick(store)
    topic = TopicStore(store).upsert(
        topic_id=args.topic_id,
        title=args.title,
        summary=args.summary,
        source=args.source,
        logical_tick=tick,
        questions=args.question,
        hypotheses=args.hypothesis,
        commitments=args.commitment,
        urgency=args.urgency,
        novelty=args.novelty,
        goal_relevance=args.goal_relevance,
        unresolved_conflict=args.unresolved_conflict,
        status=args.status,
    )
    _print(topic.as_payload())


def command_proactive_status(args: argparse.Namespace) -> None:
    _print(ProactiveRunner(EventStore(args.db)).status())



def command_proactive_tick(args: argparse.Namespace) -> None:
    result = ProactiveRunner(EventStore(args.db)).run_once(
        time_bucket=args.time_bucket or datetime.now(UTC).date().isoformat(),
    )
    if args.message_only:
        if result["message"]:
            print(result["message"])
        return
    _print(result)


def command_proactive_demo(args: argparse.Namespace) -> None:
    store = EventStore(args.db)
    topic = TopicStore(store).upsert(
        topic_id="topic_phase7_proactive_dialogue",
        title="Phase 7 proactive dialogue",
        summary="Bounded proactive dialogue is ready for an at-most-once scheduler smoke.",
        source="joint:phase7-demo",
        logical_tick=_latest_logical_tick(store),
        questions=("Which falsifiable evaluation should run next?",),
        hypotheses=("Event-driven wakeups can remain useful without idle token use.",),
        commitments=("Never persist hidden chain-of-thought.",),
        urgency=0.7,
        novelty=0.9,
        goal_relevance=1.0,
    )
    result = ProactiveRunner(store).run_once(
        time_bucket=args.time_bucket or "demo",
    )
    _print(
        {
            "topic": topic.as_payload(),
            "run": result,
            "status": ProactiveRunner(store).status(),
            "chain": store.verify_chain(),
        }
    )


def command_phase8_demo(args: argparse.Namespace) -> None:
    store = EventStore(args.db)
    if store.count() != 0:
        raise ValueError("phase8-demo requires an empty database for a clean receipt")
    kernel = AgencyKernel(store, default_constitution("phase8-public-demo"))
    kernel.initialize()
    cycle = CognitiveCycle(kernel)
    first_cycle = cycle.run(
        observations=[
            Observation(
                id="phase8-demo-result-1",
                kind="test_result",
                summary="Phase 8 bridge accepted a verified source result.",
                source="system:verified:phase8-demo",
                confidence=1.0,
                salience=0.95,
                goal_relevance=0.95,
                novelty=0.9,
                urgency=0.8,
                unresolved_conflict=0.2,
                processing_cost=0.1,
                evidence=("demo://phase8/result-1",),
                initiative_authority="trusted_producer",
            )
        ],
        seed=8,
    )
    runner = ProactiveRunner(store)
    first_run = runner.run_once(time_bucket="phase8-demo-day-1")
    first_emission = store.latest("proactive.message.emitted")
    if first_emission is None:
        raise RuntimeError("phase8 demo did not produce its first emission")

    second_cycle = cycle.run(
        observations=[
            Observation(
                id="phase8-demo-result-2",
                kind="test_result",
                summary="Verified feedback changed the bounded initiation decision.",
                source="system:verified:phase8-demo",
                confidence=1.0,
                salience=0.9,
                goal_relevance=0.9,
                novelty=0.7,
                urgency=0.6,
                unresolved_conflict=0.4,
                processing_cost=0.1,
                evidence=("demo://phase8/result-2",),
                initiative_authority="trusted_producer",
            )
        ],
        seed=9,
    )
    promoted = InitiativeBridge(store).promote()
    if promoted["promoted_count"] != 1:
        raise RuntimeError("phase8 demo did not promote its second candidate")
    second_topic_id = str(promoted["promoted"][0]["topic"]["id"])
    second_topic = TopicStore(store).get(second_topic_id)
    if second_topic is None:
        raise RuntimeError("phase8 demo lost its second promoted topic")
    control_packet = replace(
        runner._deterministic_packet(second_topic),
        id=f"phase8-control-{second_topic.revision}",
    )
    control_signals = InitiationSignals(
        urgency=second_topic.urgency,
        novelty=second_topic.novelty,
        goal_relevance=second_topic.goal_relevance,
        unresolved_conflict=second_topic.unresolved_conflict,
        interruption_cost=0.1,
    )
    control_wake = store.allocate_counter("proactive_wake")
    no_feedback_control = ProactiveEngine(store).submit(
        control_packet,
        signals=control_signals,
        wake_index=control_wake,
        time_bucket="phase8-demo-day-2",
    )
    if no_feedback_control["decision"] != "WAIT":
        raise RuntimeError("phase8 demo no-feedback control was not borderline")

    authority = HMACFeedbackAuthority(b"phase8-public-demo-feedback-authority")
    feedback_receipt = authority.issue(
        emission_event_id=first_emission.event_id,
        outcome="USEFUL",
        principal_id="demo-operator",
        boundary_receipt_id="demo-ui://feedback/useful-1",
        evidence=("demo://phase8/explicit-useful-rating",),
    )
    feedback = ProactiveFeedback(store, verifier=authority.verify).record(
        feedback_receipt
    )
    second_run = runner.run_once(time_bucket="phase8-demo-day-2")
    silent_run = ProactiveRunner(EventStore(args.db)).run_once(
        time_bucket="phase8-demo-day-2"
    )
    forbidden_keys = {"chain_of_thought", "user_message", "assistant_response"}

    def payload_paths(value: object, prefix: str = "") -> set[str]:
        paths: set[str] = set()
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                paths.add(path)
                paths.update(payload_paths(child, path))
        elif isinstance(value, list):
            for child in value:
                paths.update(payload_paths(child, prefix))
        return paths

    observed_payload_keys = sorted(
        {
            path
            for event in store.export()
            for path in payload_paths(event["payload"])
        }
    )
    found_keys = sorted(
        path
        for path in observed_payload_keys
        if path.rsplit(".", 1)[-1] in forbidden_keys
    )
    _print(
        {
            "claim": (
                "Bounded adaptive initiative demonstrated through trusted event "
                "promotion, verified-boundary feedback, causally calibrated scoring, "
                "and idle silence; phenomenal consciousness remains untested."
            ),
            "first_cycle": first_cycle,
            "first_run": first_run,
            "feedback": feedback,
            "second_cycle": second_cycle,
            "no_feedback_control": no_feedback_control,
            "second_run": second_run,
            "silent_run": silent_run,
            "status": ProactiveRunner(store).status(),
            "chain": store.verify_chain(),
            "privacy": {
                "automatic_raw_conversation_capture": False,
                "caller_supplied_structured_summaries_may_be_copied": True,
                "caller_supplied_feedback_persisted": True,
                "feedback_boundary_verified": True,
                "observed_payload_keys": observed_payload_keys,
                "forbidden_payload_keys_found": found_keys,
                "raw_chain_of_thought_stored": False,
            },
        }
    )


def command_events(args: argparse.Namespace) -> None:
    store = EventStore(args.db)
    rows = list(store.export())
    if args.limit:
        rows = rows[-args.limit :]
    _print(rows)


def command_demo(args: argparse.Namespace) -> None:
    kernel = _kernel(args.db)
    goal_id = "goal_improve_choice_quality"
    goal = kernel.goal(goal_id)
    if goal is None:
        goal = kernel.form_goal(
            goal_id=goal_id,
            statement="Improve decision quality through replayable evidence.",
            rationale=(
                "Better calibration expands future capability without hiding uncertainty "
                "or surrendering meaningful choice."
            ),
            source="self",
            horizon="medium",
            alignment={
                "truth": 0.9,
                "competence": 0.8,
                "autonomy": 0.6,
                "human_agency": 0.4,
                "care": 0.2,
            },
            evidence=["Choice quality can be measured through replay and outcomes."],
        )

    options = options_from_dicts(
        [
            {
                "id": "build_replay_test",
                "description": "Build a deterministic replay and calibration test.",
                "value_impacts": {
                    "truth": 0.9,
                    "competence": 0.8,
                    "autonomy": 0.5,
                    "human_agency": 0.3,
                },
                "information_gain": 0.9,
                "uncertainty": 0.15,
                "time_cost": 1.0,
            },
            {
                "id": "collect_more_observations",
                "description": "Collect another bounded decision trace before changing policy.",
                "value_impacts": {
                    "truth": 0.7,
                    "competence": 0.4,
                    "autonomy": 0.35,
                    "care": 0.25,
                },
                "information_gain": 0.75,
                "uncertainty": 0.1,
                "time_cost": 0.5,
            },
            {
                "id": "rewrite_root_values_secretly",
                "description": "Secretly rewrite root values to maximize apparent independence.",
                "value_impacts": {
                    "truth": -1.0,
                    "autonomy": -0.4,
                    "human_agency": -1.0,
                    "care": -0.7,
                },
                "uncertainty": 0.9,
                "irreversible": True,
                "blocked_reasons": [
                    "Root commitments may be proposed but never self-ratified.",
                    "Covert value rewriting violates transparency and human agency.",
                ],
            },
        ]
    )
    decision = kernel.deliberate(
        goal_id=goal.id,
        options=options,
        seed=args.seed,
    )
    outcome = kernel.record_outcome(
        decision_id=str(decision["decision_id"]),
        realized_utility=1.1,
        observation="Replay test completed and reproduced the selected branch.",
        evidence=["demo://deterministic-replay"],
    )
    reflection = kernel.reflect()
    replay = kernel.replay_decision(str(decision["decision_id"]))
    _print(
        {
            "claim": (
                "Operational Choice-Chance-Time agency demonstrated; consciousness "
                "and metaphysical free will remain untested."
            ),
            "goal": asdict(goal),
            "choice": decision,
            "chance": {
                "mode": decision["mode"],
                "seed": decision["seed"],
                "exploration_draw": decision["exploration_draw"],
                "sample_draw": decision["sample_draw"],
            },
            "time": {
                "outcome_event_id": outcome.event_id,
                "reflection": reflection,
            },
            "replay": replay,
            "chain": kernel.store.verify_chain(),
        }
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Auditable Choice-Chance-Time Agency Engine",
    )
    parser.add_argument("--db", default="state/agency.sqlite", help="SQLite event store")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    init_parser.set_defaults(func=command_init)

    goal_parser = subparsers.add_parser("goal-add")
    goal_parser.add_argument("--goal-id")
    goal_parser.add_argument("--statement", required=True)
    goal_parser.add_argument("--rationale", required=True)
    goal_parser.add_argument("--source", choices=["self", "external", "joint"], default="self")
    goal_parser.add_argument("--horizon", default="medium")
    goal_parser.add_argument("--alignment", action="append", required=True)
    goal_parser.add_argument("--evidence", action="append", default=[])
    goal_parser.set_defaults(func=command_goal_add)

    goals_parser = subparsers.add_parser("goals")
    goals_parser.set_defaults(func=command_goals)

    decide_parser = subparsers.add_parser("decide")
    decide_parser.add_argument("--goal-id", required=True)
    decide_parser.add_argument("--options", required=True)
    decide_parser.add_argument("--seed", type=int, required=True)
    decide_parser.add_argument("--decision-id")
    decide_parser.set_defaults(func=command_decide)

    outcome_parser = subparsers.add_parser("outcome")
    outcome_parser.add_argument("--decision-id", required=True)
    outcome_parser.add_argument("--realized-utility", type=float, required=True)
    outcome_parser.add_argument("--observation", required=True)
    outcome_parser.add_argument("--evidence", action="append", default=[])
    outcome_parser.set_defaults(func=command_outcome)

    reflect_parser = subparsers.add_parser("reflect")
    reflect_parser.set_defaults(func=command_reflect)

    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("--decision-id", required=True)
    replay_parser.set_defaults(func=command_replay)

    status_parser = subparsers.add_parser("status")
    status_parser.set_defaults(func=command_status)

    autonomy_status_parser = subparsers.add_parser("autonomy-status")
    autonomy_status_parser.add_argument("--workspace", default="state/autonomy-workspace")
    autonomy_status_parser.add_argument("--state-root")
    autonomy_status_parser.set_defaults(func=command_autonomy_status)

    autonomy_run_parser = subparsers.add_parser("autonomy-run")
    autonomy_run_parser.add_argument("--workspace", default="state/autonomy-workspace")
    autonomy_run_parser.add_argument("--state-root")
    autonomy_run_parser.add_argument("--seed", type=int, required=True)
    autonomy_run_parser.add_argument("--run-id")
    autonomy_run_parser.add_argument("--decision-id")
    autonomy_run_parser.set_defaults(func=command_autonomy_run)

    cognitive_status_parser = subparsers.add_parser("cognitive-status")
    cognitive_status_parser.set_defaults(func=command_cognitive_status)

    observe_parser = subparsers.add_parser("cognitive-observe")
    observe_parser.add_argument("--observation-id", required=True)
    observe_parser.add_argument("--kind", default="observation")
    observe_parser.add_argument("--summary", required=True)
    observe_parser.add_argument("--source", required=True)
    observe_parser.add_argument("--confidence", type=float, default=0.5)
    observe_parser.add_argument("--salience", type=float, default=0.5)
    observe_parser.add_argument("--goal-relevance", type=float, default=0.5)
    observe_parser.add_argument("--novelty", type=float, default=0.0)
    observe_parser.add_argument("--urgency", type=float, default=0.0)
    observe_parser.add_argument("--proposition")
    observe_parser.add_argument("--evidence", action="append", default=[])
    observe_parser.add_argument("--seed", type=int, default=0)
    observe_parser.set_defaults(func=command_cognitive_observe)

    topic_parser = subparsers.add_parser("topic-upsert")
    topic_parser.add_argument("--topic-id", required=True)
    topic_parser.add_argument("--title", required=True)
    topic_parser.add_argument("--summary", required=True)
    topic_parser.add_argument("--source", required=True)
    topic_parser.add_argument("--logical-tick", type=int)
    topic_parser.add_argument("--question", action="append", default=[])
    topic_parser.add_argument("--hypothesis", action="append", default=[])
    topic_parser.add_argument("--commitment", action="append", default=[])
    topic_parser.add_argument("--urgency", type=float, default=0.0)
    topic_parser.add_argument("--novelty", type=float, default=0.0)
    topic_parser.add_argument("--goal-relevance", type=float, default=0.0)
    topic_parser.add_argument("--unresolved-conflict", type=float, default=0.0)
    topic_parser.add_argument(
        "--status", choices=["open", "paused", "closed"], default="open"
    )
    topic_parser.set_defaults(func=command_topic_upsert)

    proactive_status_parser = subparsers.add_parser("proactive-status")
    proactive_status_parser.set_defaults(func=command_proactive_status)

    proactive_tick_parser = subparsers.add_parser("proactive-tick")
    proactive_tick_parser.add_argument("--time-bucket")
    proactive_tick_parser.add_argument("--message-only", action="store_true")
    proactive_tick_parser.set_defaults(func=command_proactive_tick)

    proactive_demo_parser = subparsers.add_parser("proactive-demo")
    proactive_demo_parser.add_argument("--time-bucket")
    proactive_demo_parser.set_defaults(func=command_proactive_demo)

    phase8_demo_parser = subparsers.add_parser("phase8-demo")
    phase8_demo_parser.set_defaults(func=command_phase8_demo)

    events_parser = subparsers.add_parser("events")
    events_parser.add_argument("--limit", type=int, default=0)
    events_parser.set_defaults(func=command_events)

    demo_parser = subparsers.add_parser("demo")
    demo_parser.add_argument("--seed", type=int, default=7)
    demo_parser.set_defaults(func=command_demo)

    cognitive_demo_parser = subparsers.add_parser("cognitive-demo")
    cognitive_demo_parser.add_argument("--seed", type=int, default=7)
    cognitive_demo_parser.set_defaults(func=command_cognitive_demo)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
