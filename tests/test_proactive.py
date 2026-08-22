from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from threading import Barrier

from cct_agent import AgencyKernel, EventStore, default_constitution
from cct_agent.proactive import (
    InitiationPolicy,
    InitiationSignals,
    ProactiveEngine,
    ThoughtPacket,
)
from cct_agent.runner import ProactiveRunner
from cct_agent.topics import TopicStore


class ProactiveTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Path(self.tempdir.name) / "phase7.sqlite"
        self.store = EventStore(self.db)
        self.kernel = AgencyKernel(self.store, default_constitution("phase7-test"))
        self.kernel.initialize()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def packet(
        *,
        identifier: str = "packet-1",
        action: str = "SHARE",
        tick: int = 1,
    ) -> ThoughtPacket:
        return ThoughtPacket(
            id=identifier,
            topic_id="topic-phase7",
            observation="Phase 7 needs one falsifiable next step.",
            hypotheses=("A structured wake policy can remain bounded.",),
            open_questions=("Which result would disprove the current approach?",),
            evidence=("test://phase7",),
            uncertainty=0.2,
            recommended_action=action,
            rationale_summary="Novel goal-relevant evidence justifies one concise update.",
            source="self:proactive-runner",
            created_tick=tick,
        )

    @staticmethod
    def strong_signals() -> InitiationSignals:
        return InitiationSignals(
            urgency=0.7,
            novelty=0.9,
            goal_relevance=1.0,
            unresolved_conflict=0.6,
            interruption_cost=0.1,
        )

    def test_thought_packet_is_structured_and_has_no_raw_chain(self) -> None:
        packet = self.packet()
        payload = packet.as_payload()
        self.assertEqual(payload["recommended_action"], "SHARE")
        self.assertNotIn("chain_of_thought", payload)
        self.assertFalse(payload["raw_chain_of_thought_stored"])
        self.assertTrue(payload["content_digest"])
        with self.assertRaises(ValueError):
            ThoughtPacket(
                id="bad",
                topic_id="topic",
                observation="Bad.",
                hypotheses=(),
                open_questions=(),
                evidence=("test://bad",),
                uncertainty=float("nan"),
                recommended_action="SHARE",
                rationale_summary="Bad.",
                source="test",
                created_tick=1,
            )

    def test_thought_packet_normalizes_all_bounded_collections(self) -> None:
        packet = replace(
            self.packet(identifier="bounded"),
            hypotheses=tuple(f"hypothesis-{index}" for index in range(12)),
            open_questions=tuple(f"question-{index}" for index in range(12)),
            evidence=tuple(f"evidence-{index}" for index in range(20)),
        )
        self.assertEqual(len(packet.hypotheses), 8)
        self.assertEqual(len(packet.open_questions), 8)
        self.assertEqual(len(packet.evidence), 16)
        result = ProactiveEngine(self.store).submit(
            packet,
            signals=self.strong_signals(),
            wake_index=1,
            time_bucket="bounded",
        )
        proposal = self.store.event(str(result["proposal_event_id"]))
        assert proposal is not None
        self.assertEqual(len(proposal.payload["evidence"]), 16)
        with self.assertRaisesRegex(ValueError, "600"):
            replace(self.packet(identifier="oversized"), evidence=("x" * 601,))

    def test_topics_merge_continuity_and_survive_restart(self) -> None:
        topics = TopicStore(self.store)
        first = topics.upsert(
            topic_id="topic-phase7",
            title="Proactive cognition",
            summary="Build bounded proactive dialogue.",
            source="external:user",
            logical_tick=1,
            questions=("How should wake conditions work?",),
            hypotheses=("Event-driven wakeups reduce waste.",),
            commitments=("Never persist hidden chain-of-thought.",),
            urgency=0.6,
            novelty=0.9,
            goal_relevance=1.0,
        )
        revised = topics.upsert(
            topic_id=first.id,
            title=first.title,
            summary="Build and test bounded proactive dialogue.",
            source="joint",
            logical_tick=2,
            questions=("How should new evidence revise the topic?",),
            hypotheses=("Event-driven wakeups reduce waste.",),
            commitments=("Use NO_OP when nothing is worth saying.",),
            urgency=0.7,
            novelty=0.8,
            goal_relevance=1.0,
        )
        self.assertEqual(len(revised.questions), 2)
        self.assertEqual(len(revised.hypotheses), 1)
        self.assertEqual(len(revised.commitments), 2)
        restarted = TopicStore(EventStore(self.db)).get(first.id)
        self.assertEqual(restarted, revised)
        topic_event = self.store.latest("proactive.topic.updated")
        assert topic_event is not None
        self.assertEqual(topic_event.payload["continuity_scope"], "profile")
        self.assertTrue(topic_event.payload["content_mode"].startswith("caller_supplied"))
        self.assertFalse(topic_event.payload["automatic_raw_conversation_capture"])
        with self.assertRaisesRegex(ValueError, "backward"):
            topics.upsert(
                topic_id=first.id,
                title=first.title,
                summary="Stale revision.",
                source="test:stale",
                logical_tick=1,
            )

    def test_policy_threshold_wait_and_send(self) -> None:
        policy = InitiationPolicy(threshold=0.65)
        weak = InitiationSignals(0.1, 0.1, 0.1, 0.0, 0.8)
        self.assertLess(policy.score(weak), policy.threshold)
        self.assertGreaterEqual(policy.score(self.strong_signals()), policy.threshold)

        engine = ProactiveEngine(self.store, policy=policy)
        weak_result = engine.submit(
            self.packet(identifier="weak"),
            signals=weak,
            wake_index=1,
            time_bucket="2026-08-21",
        )
        strong_result = engine.submit(
            self.packet(identifier="strong"),
            signals=self.strong_signals(),
            wake_index=2,
            time_bucket="2026-08-21",
        )
        self.assertEqual(weak_result["decision"], "WAIT")
        self.assertEqual(strong_result["decision"], "SEND")
        self.assertTrue(strong_result["message"])

    def test_wait_packet_never_proposes_message(self) -> None:
        result = ProactiveEngine(self.store).submit(
            self.packet(action="WAIT"),
            signals=self.strong_signals(),
            wake_index=1,
            time_bucket="2026-08-21",
        )
        self.assertEqual(result["decision"], "WAIT")
        self.assertEqual(result["message"], "")
        self.assertIsNone(self.store.latest("proactive.message.proposed"))

    def test_emit_is_at_most_once_across_restart(self) -> None:
        engine = ProactiveEngine(self.store)
        result = engine.submit(
            self.packet(),
            signals=self.strong_signals(),
            wake_index=1,
            time_bucket="2026-08-21",
        )
        first = engine.emit(
            proposal_event_id=result["proposal_event_id"],
            wake_index=1,
            time_bucket="2026-08-21",
        )
        second = ProactiveEngine(EventStore(self.db)).emit(
            proposal_event_id=result["proposal_event_id"],
            wake_index=1,
            time_bucket="2026-08-21",
        )
        self.assertTrue(first["emitted"])
        self.assertFalse(second["emitted"])
        self.assertEqual(second["message"], "")
        self.assertEqual(second["reason"], "ALREADY_EMITTED")
        self.assertEqual(len(self.store.events("proactive.message.emitted")), 1)

    def test_identical_visible_content_is_not_reemitted(self) -> None:
        engine = ProactiveEngine(
            self.store, policy=InitiationPolicy(cooldown_wakes=0)
        )
        first_packet = self.packet(identifier="visible-first")
        first = engine.submit(
            first_packet,
            signals=self.strong_signals(),
            wake_index=1,
            time_bucket="day-one",
        )
        engine.emit(
            str(first["proposal_event_id"]), wake_index=1, time_bucket="day-one"
        )
        same_visible_content = replace(
            first_packet,
            id="visible-second",
            evidence=("different://provenance",),
            hypotheses=(*first_packet.hypotheses, "Unrendered alternate."),
            open_questions=(*first_packet.open_questions, "Unrendered follow-up?"),
            source="different:source",
            created_tick=2,
        )
        self.assertEqual(
            first_packet.content_digest, same_visible_content.content_digest
        )
        duplicate = engine.submit(
            same_visible_content,
            signals=self.strong_signals(),
            wake_index=2,
            time_bucket="day-two",
        )
        self.assertEqual(duplicate["decision"], "WAIT")
        self.assertIn("DUPLICATE_CONTENT", duplicate["reason_codes"])

        punctuation_variant = replace(
            first_packet,
            id="visible-punctuation",
            observation=first_packet.observation.rstrip(".") + "!",
            created_tick=3,
        )
        self.assertEqual(first_packet.content_digest, punctuation_variant.content_digest)
        punctuation_duplicate = engine.submit(
            punctuation_variant,
            signals=self.strong_signals(),
            wake_index=3,
            time_bucket="day-three",
        )
        self.assertEqual(punctuation_duplicate["decision"], "WAIT")
        self.assertIn("DUPLICATE_CONTENT", punctuation_duplicate["reason_codes"])

    def test_concurrent_emission_cannot_overshoot_daily_cap(self) -> None:
        policy = InitiationPolicy(cooldown_wakes=0, daily_message_cap=1)
        proposals: list[str] = []
        for identifier, observation, wake in (
            ("race-a", "First concurrent update.", 1),
            ("race-b", "Second concurrent update.", 2),
        ):
            packet = replace(
                self.packet(identifier=identifier, tick=wake),
                observation=observation,
            )
            decision = ProactiveEngine(self.store, policy=policy).submit(
                packet,
                signals=self.strong_signals(),
                wake_index=wake,
                time_bucket="race-day",
            )
            self.assertEqual(decision["decision"], "SEND")
            proposals.append(str(decision["proposal_event_id"]))

        barrier = Barrier(2)

        def emit(proposal: str, wake: int) -> dict[str, object]:
            barrier.wait()
            return ProactiveEngine(EventStore(self.db), policy=policy).emit(
                proposal, wake_index=wake, time_bucket="race-day"
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(emit, proposals, (1, 2)))
        self.assertEqual(sum(bool(result["emitted"]) for result in results), 1)
        self.assertEqual(
            {str(result["reason"]) for result in results}, {"EMITTED", "DAILY_CAP"}
        )
        self.assertEqual(len(self.store.events("proactive.message.emitted")), 1)

    def test_submit_recovers_after_packet_only_crash_boundary(self) -> None:
        packet = self.packet(identifier="packet-only-crash")
        self.store.append_once(
            "proactive.thought.created", packet.id, packet.as_payload()
        )
        result = ProactiveEngine(EventStore(self.db)).submit(
            packet,
            signals=self.strong_signals(),
            wake_index=1,
            time_bucket="2026-08-21",
        )
        self.assertEqual(result["decision"], "SEND")
        self.assertTrue(result["proposal_event_id"])

    def test_concurrent_submit_recovers_after_packet_only_crash_boundary(self) -> None:
        packet = self.packet(identifier="packet-only-concurrent-crash")
        self.store.append_once(
            "proactive.thought.created", packet.id, packet.as_payload()
        )
        barrier = Barrier(2)
        original = ProactiveEngine._decision_for_packet

        def synchronized_decision(engine: ProactiveEngine, packet_id: str):
            decision = original(engine, packet_id)
            if decision is None:
                barrier.wait()
            return decision

        def submit(wake_index: int) -> dict[str, object]:
            return ProactiveEngine(EventStore(self.db)).submit(
                packet,
                signals=self.strong_signals(),
                wake_index=wake_index,
                time_bucket="packet-only-race",
            )

        with patch.object(
            ProactiveEngine, "_decision_for_packet", synchronized_decision
        ):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(submit, (1, 2)))
        self.assertEqual({result["decision"] for result in results}, {"SEND"})
        self.assertEqual(len(self.store.events("proactive.initiation.decided")), 1)
        self.assertEqual(len(self.store.events("proactive.message.proposed")), 1)

    def test_submit_recovers_after_decision_before_proposal_crash(self) -> None:
        packet = self.packet(identifier="proposal-crash")
        engine = ProactiveEngine(self.store)
        original = self.store.append_once

        def crash_before_proposal(kind: str, key: str, payload: dict[str, object]):
            if kind == "proactive.message.proposed":
                raise RuntimeError("simulated proposal crash")
            return original(kind, key, payload)

        with patch.object(self.store, "append_once", side_effect=crash_before_proposal):
            with self.assertRaisesRegex(RuntimeError, "simulated proposal crash"):
                engine.submit(
                    packet,
                    signals=self.strong_signals(),
                    wake_index=1,
                    time_bucket="2026-08-21",
                )
        recovered = ProactiveEngine(EventStore(self.db)).submit(
            packet,
            signals=self.strong_signals(),
            wake_index=2,
            time_bucket="2026-08-21",
        )
        self.assertEqual(recovered["decision"], "SEND")
        self.assertTrue(recovered["proposal_event_id"])
        self.assertEqual(len(self.store.events("proactive.message.proposed")), 1)

    def test_cooldown_and_daily_cap_suppress_interruptions(self) -> None:
        policy = InitiationPolicy(cooldown_wakes=3, daily_message_cap=2)
        engine = ProactiveEngine(self.store, policy=policy)
        first = engine.submit(
            self.packet(identifier="first"),
            signals=self.strong_signals(),
            wake_index=1,
            time_bucket="2026-08-21",
        )
        engine.emit(first["proposal_event_id"], wake_index=1, time_bucket="2026-08-21")
        cooldown = engine.submit(
            self.packet(identifier="cooldown", tick=2),
            signals=self.strong_signals(),
            wake_index=2,
            time_bucket="2026-08-21",
        )
        self.assertEqual(cooldown["decision"], "WAIT")
        self.assertIn("COOLDOWN", cooldown["reason_codes"])

        second = engine.submit(
            replace(
                self.packet(identifier="second", tick=4),
                observation="A second distinct high-value update is ready.",
            ),
            signals=self.strong_signals(),
            wake_index=4,
            time_bucket="2026-08-21",
        )
        engine.emit(second["proposal_event_id"], wake_index=4, time_bucket="2026-08-21")
        capped = engine.submit(
            replace(
                self.packet(identifier="capped", tick=7),
                observation="A third distinct update exceeds the daily cap.",
            ),
            signals=self.strong_signals(),
            wake_index=7,
            time_bucket="2026-08-21",
        )
        self.assertEqual(capped["decision"], "WAIT")
        self.assertIn("DAILY_CAP", capped["reason_codes"])

    def test_runner_sends_once_then_stays_silent_until_topic_changes(self) -> None:
        topics = TopicStore(self.store)
        topics.upsert(
            topic_id="topic-phase7",
            title="Proactive cognition",
            summary="Build bounded proactive dialogue.",
            source="external:user",
            logical_tick=1,
            questions=("What should be tested next?",),
            hypotheses=("A wake policy can remain quiet when idle.",),
            commitments=("Use structured receipts.",),
            urgency=0.7,
            novelty=0.9,
            goal_relevance=1.0,
        )
        runner = ProactiveRunner(self.store)
        first = runner.run_once(time_bucket="2026-08-21")
        second = ProactiveRunner(EventStore(self.db)).run_once(
            time_bucket="2026-08-21"
        )
        self.assertTrue(first["message"])
        self.assertEqual(second["message"], "")
        self.assertEqual(second["reason"], "NO_NEW_STATE")

        topics.upsert(
            topic_id="topic-phase7",
            title="Proactive cognition",
            summary="New decision-relevant evidence became available.",
            source="tool:evidence-refresh",
            logical_tick=2,
            questions=("Which measurement should be checked first?",),
            hypotheses=("A changed topic revision should permit one fresh update.",),
            commitments=(),
            urgency=0.7,
            novelty=1.0,
            goal_relevance=1.0,
        )
        third = runner.run_once(time_bucket="2026-08-22")
        self.assertTrue(third["message"])

    def test_runner_without_topics_is_silent_and_token_free(self) -> None:
        result = ProactiveRunner(self.store).run_once(time_bucket="2026-08-21")
        self.assertEqual(result["message"], "")
        self.assertEqual(result["reason"], "NO_OPEN_TOPIC")
        self.assertEqual(result["llm_calls"], 0)

    def test_runner_retries_changed_topic_after_cooldown(self) -> None:
        topics = TopicStore(self.store)
        common = {
            "topic_id": "retry-topic",
            "title": "Retry after cooldown",
            "source": "test:cooldown",
            "questions": ("Will temporary deferral preserve the revision?",),
            "hypotheses": ("Cooldown should defer rather than consume state.",),
            "commitments": (),
            "urgency": 0.8,
            "novelty": 0.9,
            "goal_relevance": 1.0,
        }
        topics.upsert(
            **common,
            summary="First topic state.",
            logical_tick=1,
        )
        runner = ProactiveRunner(self.store)
        self.assertTrue(runner.run_once(time_bucket="same-day")["message"])
        topics.upsert(
            **common,
            summary="Second topic state arrived during cooldown.",
            logical_tick=2,
        )
        deferred_one = runner.run_once(time_bucket="same-day")
        deferred_two = runner.run_once(time_bucket="same-day")
        retried = runner.run_once(time_bucket="same-day")
        self.assertEqual(deferred_one["reason"], "COOLDOWN")
        self.assertFalse(deferred_one["state_consumed"])
        self.assertEqual(deferred_two["reason"], "COOLDOWN")
        self.assertTrue(retried["message"])
        self.assertEqual(len(self.store.events("proactive.runner.completed")), 2)

    def test_scheduler_script_emits_once_then_is_silent(self) -> None:
        hermes_home = Path(self.tempdir.name) / "hermes-home"
        store = EventStore(hermes_home / "cct-agency" / "agency.sqlite")
        TopicStore(store).upsert(
            topic_id="script-topic",
            title="Scheduler smoke",
            summary="A scheduler-visible topic changed.",
            source="test:scheduler",
            logical_tick=1,
            questions=("Does the second run stay silent?",),
            hypotheses=("At-most-once emission prevents duplicate output.",),
            urgency=0.8,
            novelty=0.9,
            goal_relevance=1.0,
        )
        script = Path(__file__).parents[1] / "scripts" / "cct_proactive_tick.py"
        environment = dict(os.environ, HERMES_HOME=str(hermes_home))
        first = subprocess.run(
            [sys.executable, str(script)],
            cwd=script.parents[1],
            env=environment,
            text=True,
            capture_output=True,
            check=True,
        )
        second = subprocess.run(
            [sys.executable, str(script)],
            cwd=script.parents[1],
            env=environment,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("scheduler-visible topic changed", first.stdout.lower())
        self.assertEqual(second.stdout, "")
        self.assertTrue(store.verify_chain()["valid"])


if __name__ == "__main__":
    unittest.main()
