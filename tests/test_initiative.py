from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch

from cct_agent import AgencyKernel, EventStore, default_constitution
from cct_agent.cognitive_cycle import CognitiveCycle, Observation
from cct_agent.initiative import (
    HMACFeedbackAuthority,
    InitiativeBridge,
    ProactiveFeedback,
    PromotionPolicy,
)
from cct_agent.proactive import InitiationPolicy, InitiationSignals, ProactiveEngine, ThoughtPacket
from cct_agent.runner import ProactiveRunner
from cct_agent.topics import TopicStore


class InitiativeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Path(self.tempdir.name) / "phase8.sqlite"
        self.store = EventStore(self.db)
        self.kernel = AgencyKernel(self.store, default_constitution("phase8-test"))
        self.kernel.initialize()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def observation(
        identifier: str,
        summary: str,
        *,
        kind: str = "test_result",
        source: str = "system:verified:phase8-test",
        initiative_authority: str = "trusted_producer",
        salience: float = 0.95,
        goal_relevance: float = 0.95,
        novelty: float = 0.9,
        urgency: float = 0.8,
    ) -> Observation:
        return Observation(
            id=identifier,
            kind=kind,
            summary=summary,
            source=source,
            confidence=1.0,
            salience=salience,
            goal_relevance=goal_relevance,
            novelty=novelty,
            urgency=urgency,
            evidence=(f"test://{identifier}",),
            initiative_authority=initiative_authority,
        )

    @staticmethod
    def feedback_authority() -> HMACFeedbackAuthority:
        return HMACFeedbackAuthority(b"phase8-test-feedback-key-32bytes")

    @staticmethod
    def workspace_item(
        identifier: str,
        summary: str,
        *,
        source: str = "system:verified:phase8-test",
        content_digest: str | None = None,
    ) -> dict[str, object]:
        return {
            "id": identifier,
            "kind": "test_result",
            "summary": summary,
            "source": source,
            "salience": 0.95,
            "goal_relevance": 0.95,
            "confidence": 1.0,
            "novelty": 0.9,
            "urgency": 0.8,
            "unresolved_conflict": 0.2,
            "processing_cost": 0.1,
            "logical_tick": 1,
            "evidence": [f"test://{identifier}"],
            "content_digest": content_digest
            or sha256(f"{identifier}|{summary}".encode("utf-8")).hexdigest(),
            "attention_score": 0.84,
            "attention_reason_codes": ["GOAL_RELEVANT", "SALIENT", "NOVEL"],
            "initiative_authority": "trusted_producer",
        }

    @staticmethod
    def packet(identifier: str, observation: str) -> ThoughtPacket:
        return ThoughtPacket(
            id=identifier,
            topic_id="topic-feedback",
            observation=observation,
            hypotheses=("Explicit feedback can calibrate interruption policy.",),
            open_questions=("Does bounded calibration improve message selection?",),
            evidence=(f"test://{identifier}",),
            uncertainty=0.2,
            recommended_action="SHARE",
            rationale_summary="New source-backed evidence crossed the fixed initiation gate.",
            source="test:phase8",
            created_tick=1,
        )

    @staticmethod
    def strong_signals() -> InitiationSignals:
        return InitiationSignals(
            urgency=0.8,
            novelty=0.9,
            goal_relevance=0.95,
            unresolved_conflict=0.2,
            interruption_cost=0.1,
        )

    def test_runner_promotes_high_value_workspace_item_and_emits(self) -> None:
        CognitiveCycle(self.kernel).run(
            observations=[
                self.observation(
                    "acceptance-pass",
                    "Phase 8 acceptance evidence became available.",
                )
            ],
            seed=8,
        )
        result = ProactiveRunner(self.store).run_once(time_bucket="phase8-day-1")
        self.assertIn("Phase 8 acceptance evidence", result["message"])
        self.assertEqual(result["promotion"]["promoted_count"], 1)
        topic_event = self.store.latest("proactive.topic.updated")
        assert topic_event is not None
        self.assertTrue(topic_event.payload["automatic_structured_workspace_promotion"])
        self.assertFalse(topic_event.payload["automatic_raw_conversation_capture"])
        self.assertFalse(topic_event.payload["raw_chain_of_thought_stored"])
        self.assertTrue(topic_event.payload["promotion"]["source_event_id"])

        restarted = ProactiveRunner(EventStore(self.db)).run_once(
            time_bucket="phase8-day-1"
        )
        self.assertEqual(restarted["message"], "")
        self.assertEqual(restarted["reason"], "NO_NEW_STATE")
        self.assertEqual(len(self.store.events("proactive.topic.updated")), 1)

    def test_bridge_ignores_generic_hermes_and_low_value_items(self) -> None:
        CognitiveCycle(self.kernel).run(
            observations=[
                self.observation(
                    "generic-trigger",
                    "Hermes model call requested.",
                    kind="cognitive_trigger",
                    source="hermes:pre_llm_call",
                ),
                self.observation(
                    "low-result",
                    "Low-value background result.",
                    salience=0.2,
                    goal_relevance=0.2,
                    novelty=0.1,
                    urgency=0.0,
                ),
            ],
            seed=9,
        )
        result = InitiativeBridge(self.store).promote()
        self.assertEqual(result["promoted_count"], 0)
        self.assertEqual(self.store.events("proactive.topic.updated"), [])
        self.assertGreaterEqual(result["rejected_by_reason"]["KIND_NOT_ALLOWED"], 1)
        self.assertGreaterEqual(result["rejected_by_reason"]["LOW_ATTENTION"], 1)

    def test_bridge_rejects_caller_asserted_provenance(self) -> None:
        CognitiveCycle(self.kernel).run(
            observations=[
                self.observation(
                    "spoofed-source",
                    "Caller asserted a passing test result.",
                    source="external:untrusted",
                    initiative_authority="untrusted",
                )
            ],
            seed=91,
        )
        result = ProactiveRunner(self.store).run_once(time_bucket="spoof-day")
        self.assertEqual(result["message"], "")
        self.assertEqual(result["promotion"]["promoted_count"], 0)
        self.assertEqual(
            result["promotion"]["rejected_by_reason"]["SOURCE_NOT_ALLOWED"], 1
        )
        self.assertEqual(self.store.events("proactive.topic.updated"), [])

    def test_promotion_is_restart_idempotent_and_concurrency_safe(self) -> None:
        CognitiveCycle(self.kernel).run(
            observations=[
                self.observation("race-a", "First concurrent source result."),
                self.observation("race-b", "Second concurrent source result."),
            ],
            seed=10,
        )
        barrier = Barrier(2)

        def promote(_: int) -> dict[str, object]:
            barrier.wait()
            return InitiativeBridge(
                EventStore(self.db), policy=PromotionPolicy(max_promotions_per_run=8)
            ).promote()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(promote, (1, 2)))
        events = self.store.events("proactive.topic.updated")
        self.assertEqual(len(events), 2)
        topics = [event.payload["topic"] for event in events]
        self.assertEqual({topic["revision"] for topic in topics}, {1, 2})
        self.assertEqual(len({topic["id"] for topic in topics}), 1)
        self.assertEqual(
            len({event.payload["promotion"]["promotion_key"] for event in events}), 2
        )
        self.assertEqual(sum(int(result["promoted_count"]) for result in results), 2)
        self.assertTrue(self.store.verify_chain()["valid"])

        retry = InitiativeBridge(EventStore(self.db)).promote()
        self.assertEqual(retry["promoted_count"], 0)
        self.assertEqual(len(self.store.events("proactive.topic.updated")), 2)

    def test_auto_promoted_summary_and_metadata_are_bounded(self) -> None:
        CognitiveCycle(self.kernel).run(
            observations=[
                self.observation(
                    "long",
                    "x" * 2000,
                )
            ],
            seed=11,
        )
        result = InitiativeBridge(self.store).promote()
        topic = result["promoted"][0]["topic"]
        self.assertLessEqual(len(topic["summary"]), 1200)
        self.assertTrue(topic["summary"].endswith("…"))
        self.assertLessEqual(len(topic["source"]), 240)
        event = self.store.latest("proactive.topic.updated")
        assert event is not None
        self.assertEqual(
            event.payload["content_mode"], "automatic_structured_workspace_promotion"
        )
        self.assertTrue(event.payload["source_summary_already_persisted"])
        self.assertTrue(event.payload["caller_supplied_summary_may_be_copied"])

    def test_rebroadcast_identity_and_bounded_backlog_cursor_do_not_lose_work(self) -> None:
        duplicate = self.workspace_item(
            "stable-item", "Stable producer item.", content_digest="a" * 64
        )
        for tick in (1, 2):
            item = dict(duplicate)
            item["logical_tick"] = tick
            self.store.append("workspace.broadcast", {"logical_tick": tick, "items": [item]})
        bridge = InitiativeBridge(
            self.store,
            policy=PromotionPolicy(max_source_events_scan=1, max_promotions_per_run=1),
        )
        bridge.promote()
        bridge.promote()
        self.assertEqual(len(self.store.events("proactive.topic.updated")), 1)

        for index in range(4):
            item = self.workspace_item(f"backlog-{index}", f"Backlog item {index}.")
            item["logical_tick"] = index + 3
            self.store.append(
                "workspace.broadcast",
                {"logical_tick": index + 3, "items": [item]},
            )
        for _ in range(8):
            bridge.promote()
        promotions = self.store.events("proactive.topic.updated")
        promoted_ids = {
            event.payload["promotion"]["source_item_id"] for event in promotions
        }
        self.assertEqual(
            promoted_ids,
            {"stable-item", "backlog-0", "backlog-1", "backlog-2", "backlog-3"},
        )
        self.assertEqual(len(promotions), 5)

    def test_malformed_frame_cursor_does_not_starve_later_backlog(self) -> None:
        self.store.append(
            "workspace.broadcast",
            {"logical_tick": 1, "items": {"not": "a-list"}},
        )
        valid = self.workspace_item("after-bad-frame", "Later valid frame.")
        self.store.append(
            "workspace.broadcast",
            {"logical_tick": 2, "items": [valid]},
        )
        bridge = InitiativeBridge(
            self.store,
            policy=PromotionPolicy(max_source_events_scan=1),
        )
        first = bridge.promote()
        second = bridge.promote()
        self.assertEqual(first["rejected_by_reason"]["MALFORMED_FRAME"], 1)
        self.assertEqual(second["promoted_count"], 1)
        self.assertEqual(
            second["promoted"][0]["source_item_id"], "after-bad-frame"
        )

    def test_missing_content_digest_fails_closed_without_duplicate_revisions(self) -> None:
        for tick in (1, 2):
            item = self.workspace_item("missing-digest", "Missing producer digest.")
            item.pop("content_digest")
            item["logical_tick"] = tick
            self.store.append(
                "workspace.broadcast",
                {"logical_tick": tick, "items": [item]},
            )
        bridge = InitiativeBridge(
            self.store,
            policy=PromotionPolicy(max_source_events_scan=1),
        )
        results = [bridge.promote(), bridge.promote()]
        self.assertEqual(sum(result["promoted_count"] for result in results), 0)
        self.assertEqual(len(self.store.events("proactive.topic.updated")), 0)
        self.assertEqual(
            sum(
                result["rejected_by_reason"].get("MALFORMED_ITEM", 0)
                for result in results
            ),
            2,
        )

    def test_malformed_item_isolated_while_later_valid_item_emits(self) -> None:
        malformed = self.workspace_item(
            "malformed", "Malformed producer item.", source="x" * 241
        )
        valid = self.workspace_item("valid-after-malformed", "Valid later producer item.")
        self.store.append(
            "workspace.broadcast",
            {"logical_tick": 1, "items": [malformed, valid]},
        )
        result = ProactiveRunner(self.store).run_once(time_bucket="malformed-day")
        self.assertIn("Valid later producer item", result["message"])
        self.assertEqual(result["promotion"]["promoted_count"], 1)
        self.assertEqual(
            result["promotion"]["rejected_by_reason"]["MALFORMED_ITEM"], 1
        )

    def test_automatic_promotion_preserves_closed_and_paused_status(self) -> None:
        for status in ("closed", "paused"):
            with self.subTest(status=status):
                db = Path(self.tempdir.name) / f"{status}.sqlite"
                store = EventStore(db)
                kernel = AgencyKernel(store, default_constitution(f"phase8-{status}"))
                kernel.initialize()
                source = f"system:verified:{status}"
                CognitiveCycle(kernel).run(
                    observations=[self.observation(f"{status}-1", "First state.", source=source)],
                    seed=1,
                )
                first = InitiativeBridge(store).promote()["promoted"][0]["topic"]
                topics = TopicStore(store)
                if status == "closed":
                    topics.close(first["id"], logical_tick=2, source="external:test")
                else:
                    current = topics.get(first["id"])
                    assert current is not None
                    topics.upsert(
                        topic_id=current.id,
                        title=current.title,
                        summary=current.summary,
                        source="external:test",
                        status="paused",
                        logical_tick=2,
                        questions=current.questions,
                        hypotheses=current.hypotheses,
                        commitments=current.commitments,
                        urgency=current.urgency,
                        novelty=current.novelty,
                        goal_relevance=current.goal_relevance,
                        unresolved_conflict=current.unresolved_conflict,
                    )
                CognitiveCycle(kernel).run(
                    observations=[self.observation(f"{status}-2", "New state.", source=source)],
                    seed=2,
                )
                result = ProactiveRunner(store).run_once(time_bucket=f"{status}-day")
                self.assertEqual(result["message"], "")
                final_topic = topics.get(first["id"])
                assert final_topic is not None
                self.assertEqual(final_topic.status, status)

    def test_concurrent_runners_process_one_revision_without_collision(self) -> None:
        TopicStore(self.store).upsert(
            topic_id="runner-race",
            title="Runner race",
            summary="Only one concurrent runner may emit this revision.",
            source="external:test",
            status="open",
            logical_tick=1,
            questions=("Did exactly one runner emit?",),
            hypotheses=("Atomic emission and idempotent completion prevent duplicates.",),
            commitments=(),
            goal_relevance=0.95,
            urgency=0.8,
            novelty=0.9,
            unresolved_conflict=0.2,
        )
        barrier = Barrier(2)
        original = ProactiveRunner._next_topic

        def synchronized_next(runner: ProactiveRunner):
            topic = original(runner)
            barrier.wait()
            return topic

        def run(_: int) -> dict[str, object]:
            return ProactiveRunner(EventStore(self.db)).run_once(time_bucket="race-day")

        with patch.object(ProactiveRunner, "_next_topic", synchronized_next):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(run, (1, 2)))
        self.assertEqual(sum(bool(result["message"]) for result in results), 1)
        self.assertEqual(len(self.store.events("proactive.message.emitted")), 1)
        self.assertEqual(len(self.store.events("proactive.runner.completed")), 1)

    def _emit(self, identifier: str, observation: str, *, wake: int) -> str:
        engine = ProactiveEngine(
            self.store, policy=InitiationPolicy(cooldown_wakes=0, daily_message_cap=20)
        )
        decision = engine.submit(
            self.packet(identifier, observation),
            signals=self.strong_signals(),
            wake_index=wake,
            time_bucket="feedback-day",
        )
        emission = engine.emit(
            str(decision["proposal_event_id"]),
            wake_index=wake,
            time_bucket="feedback-day",
        )
        self.assertTrue(emission["emitted"])
        return str(emission["emission_event_id"])

    def test_feedback_is_idempotent_and_calibrates_bounded_score(self) -> None:
        emission_id = self._emit("feedback-first", "First feedback candidate.", wake=1)
        authority = self.feedback_authority()
        envelope = authority.issue(
            emission_event_id=emission_id,
            outcome="USEFUL",
            principal_id="operator-1",
            boundary_receipt_id="ui://feedback/1",
            evidence=("user://explicit-rating",),
        )
        barrier = Barrier(2)

        def record(_: int) -> dict[str, object]:
            barrier.wait()
            verifier = self.feedback_authority()
            return ProactiveFeedback(
                EventStore(self.db), verifier=verifier.verify
            ).record(envelope)

        with ThreadPoolExecutor(max_workers=2) as pool:
            receipts = list(pool.map(record, (1, 2)))
        self.assertEqual(sum(bool(receipt["created"]) for receipt in receipts), 1)
        self.assertEqual(len(self.store.events("proactive.feedback.recorded")), 1)

        calibration = ProactiveFeedback(self.store).calibration()
        self.assertGreater(calibration["score_adjustment"], 0.0)
        self.assertLessEqual(abs(calibration["score_adjustment"]), 0.12)
        engine = ProactiveEngine(
            self.store, policy=InitiationPolicy(cooldown_wakes=0, daily_message_cap=20)
        )
        decision = engine.submit(
            self.packet("feedback-second", "Second distinct feedback candidate."),
            signals=self.strong_signals(),
            wake_index=2,
            time_bucket="feedback-day",
        )
        self.assertAlmostEqual(
            decision["attention_score"],
            decision["base_attention_score"] + calibration["score_adjustment"],
        )
        self.assertEqual(decision["calibration"]["sample_count"], 1)

    def test_feedback_rejects_non_emission_and_conflicting_retry(self) -> None:
        authority = self.feedback_authority()
        feedback = ProactiveFeedback(self.store, verifier=authority.verify)
        constitution = self.store.latest("constitution.initialized")
        assert constitution is not None
        non_emission = authority.issue(
            emission_event_id=constitution.event_id,
            outcome="USEFUL",
            principal_id="operator-1",
            boundary_receipt_id="ui://feedback/non-emission",
        )
        with self.assertRaises(KeyError):
            feedback.record(non_emission)

        emission_id = self._emit("conflict", "Feedback conflict candidate.", wake=1)
        useful = authority.issue(
            emission_event_id=emission_id,
            outcome="USEFUL",
            principal_id="operator-1",
            boundary_receipt_id="ui://feedback/conflict",
        )
        with self.assertRaisesRegex(PermissionError, "verified feedback boundary"):
            ProactiveFeedback(self.store).record(useful)
        with self.assertRaisesRegex(PermissionError, "signature"):
            feedback.record(replace(useful, signature="0" * 64))
        feedback.record(useful)
        disruptive = authority.issue(
            emission_event_id=emission_id,
            outcome="DISRUPTIVE",
            principal_id="operator-1",
            boundary_receipt_id="ui://feedback/conflict-correction",
        )
        with self.assertRaisesRegex(ValueError, "logical key collision"):
            feedback.record(disruptive)

    def test_disruptive_feedback_can_defer_borderline_send_without_changing_hard_gates(self) -> None:
        authority = self.feedback_authority()
        feedback = ProactiveFeedback(self.store, verifier=authority.verify)
        for index in range(3):
            emission_id = self._emit(
                f"disruptive-{index}",
                f"Distinct candidate rated disruptive {index}.",
                wake=index + 1,
            )
            feedback.record(authority.issue(
                emission_event_id=emission_id,
                outcome="DISRUPTIVE",
                principal_id="operator-1",
                boundary_receipt_id=f"ui://feedback/disruptive-{index}",
                evidence=(f"user://disruptive-{index}",),
            ))

        policy = InitiationPolicy(cooldown_wakes=0, daily_message_cap=20)
        engine = ProactiveEngine(self.store, policy=policy)
        decision = engine.submit(
            self.packet("deferred-after-feedback", "A borderline candidate after feedback."),
            signals=self.strong_signals(),
            wake_index=4,
            time_bucket="feedback-day",
        )
        self.assertEqual(decision["decision"], "WAIT")
        self.assertIn("BELOW_THRESHOLD", decision["reason_codes"])
        self.assertLess(decision["calibration"]["score_adjustment"], 0.0)
        self.assertEqual(decision["threshold"], 0.65)
        self.assertFalse(decision["calibration"]["root_policy_changed"])
        self.assertFalse(decision["calibration"]["hard_safety_gates_changed"])

    def test_phase8_cli_demo_proves_bridge_feedback_and_silence(self) -> None:
        demo_db = Path(self.tempdir.name) / "public-demo.sqlite"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "cct_agent.cli",
                "--db",
                str(demo_db),
                "phase8-demo",
            ],
            cwd=Path(__file__).parents[1],
            text=True,
            capture_output=True,
            check=True,
        )
        receipt = json.loads(completed.stdout)
        self.assertTrue(receipt["first_run"]["message"])
        self.assertEqual(receipt["no_feedback_control"]["decision"], "WAIT")
        self.assertLess(
            receipt["second_run"]["decision"]["base_attention_score"],
            receipt["second_run"]["decision"]["threshold"],
        )
        self.assertGreaterEqual(
            receipt["second_run"]["decision"]["attention_score"],
            receipt["second_run"]["decision"]["threshold"],
        )
        self.assertTrue(receipt["second_run"]["message"])
        self.assertEqual(receipt["silent_run"]["message"], "")
        self.assertEqual(receipt["silent_run"]["reason"], "NO_NEW_STATE")
        self.assertGreater(receipt["feedback"]["calibration"]["score_adjustment"], 0.0)
        self.assertTrue(receipt["chain"]["valid"])
        self.assertFalse(receipt["privacy"]["automatic_raw_conversation_capture"])
        self.assertFalse(receipt["privacy"]["raw_chain_of_thought_stored"])
        self.assertTrue(
            any("." in path for path in receipt["privacy"]["observed_payload_keys"])
        )
        exported = list(EventStore(demo_db).export())

        def keys(value: object) -> set[str]:
            if isinstance(value, dict):
                return set(value) | {
                    nested
                    for child in value.values()
                    for nested in keys(child)
                }
            if isinstance(value, list):
                return {nested for child in value for nested in keys(child)}
            return set()

        payload_keys = keys(exported)
        self.assertNotIn("chain_of_thought", payload_keys)
        self.assertNotIn("user_message", payload_keys)
        self.assertNotIn("assistant_response", payload_keys)


if __name__ == "__main__":
    unittest.main()
