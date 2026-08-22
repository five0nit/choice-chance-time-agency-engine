from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from itertools import count
from pathlib import Path
import tempfile
import unittest

from cct_agent import AgencyKernel, EventStore, Option, default_constitution
from cct_agent.attention import AttentionPolicy
from cct_agent.beliefs import BeliefStore
from cct_agent.cognitive_cycle import CognitiveCycle, Observation
from cct_agent.interoception import InteroceptiveState
from cct_agent.memory import MemoryManager
from cct_agent.metacognition import MetacognitiveMonitor
from cct_agent.self_model import SelfModel
from cct_agent.workspace import GlobalWorkspace, WorkspaceItem
from cct_agent.world_model import CounterfactualWorldModel


class CognitiveTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Path(self.tempdir.name) / "cognition.sqlite"
        self.store = EventStore(self.db)
        self.kernel = AgencyKernel(self.store, default_constitution("cognitive-test"))
        self.kernel.initialize()
        self.goal = self.kernel.form_goal(
            goal_id="goal-cognitive",
            statement="Improve truthful decisions through integrated cognition.",
            rationale="Global access, evidence, and calibrated self-knowledge improve decisions.",
            source="joint",
            alignment={"truth": 0.9, "competence": 0.8, "autonomy": 0.5},
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def observation(identifier: str = "obs-a", summary: str = "Critical test failed.") -> Observation:
        return Observation(
            id=identifier,
            kind="test_result",
            summary=summary,
            source="tool:pytest",
            confidence=0.99,
            salience=0.9,
            goal_relevance=0.9,
            novelty=0.7,
            urgency=0.8,
            evidence=("test://failure",),
            proposition="The current implementation has a failing acceptance test.",
        )

    def test_attention_is_limited_deterministic_and_explainable(self) -> None:
        policy = AttentionPolicy(capacity=2, char_budget=120)
        candidates = [
            WorkspaceItem(
                id="low",
                kind="note",
                summary="low priority",
                source="memory",
                salience=0.1,
                goal_relevance=0.1,
                confidence=0.8,
                novelty=0.1,
                urgency=0.0,
                logical_tick=1,
            ),
            WorkspaceItem(
                id="urgent",
                kind="error",
                summary="urgent failure",
                source="tool:test",
                salience=1.0,
                goal_relevance=1.0,
                confidence=1.0,
                novelty=0.8,
                urgency=1.0,
                logical_tick=1,
            ),
            WorkspaceItem(
                id="conflict",
                kind="goal_conflict",
                summary="goals conflict",
                source="self",
                salience=0.7,
                goal_relevance=0.8,
                confidence=0.9,
                novelty=0.6,
                urgency=0.5,
                unresolved_conflict=1.0,
                logical_tick=1,
            ),
        ]
        first = policy.select(candidates)
        second = policy.select(list(reversed(candidates)))
        self.assertEqual([item.item.id for item in first], ["urgent", "conflict"])
        self.assertEqual(
            [(item.item.id, item.attention_score, item.reason_codes) for item in first],
            [(item.item.id, item.attention_score, item.reason_codes) for item in second],
        )
        self.assertLessEqual(sum(len(item.item.summary) for item in first), 120)
        self.assertTrue(all(item.reason_codes for item in first))

    def test_global_workspace_is_bounded_and_reportable(self) -> None:
        workspace = GlobalWorkspace(self.store, capacity=2, char_budget=180)
        policy = AttentionPolicy(capacity=2, char_budget=180)
        items = [
            WorkspaceItem(
                id="visible",
                kind="observation",
                summary="Evidence is globally available.",
                source="tool:test",
                salience=1.0,
                goal_relevance=1.0,
                confidence=1.0,
                novelty=0.8,
                urgency=0.5,
                logical_tick=1,
            )
        ]
        frame = workspace.broadcast(policy.select(items), logical_tick=1)
        context = workspace.render_context(max_chars=180)
        self.assertEqual(frame["logical_tick"], 1)
        self.assertIn("Evidence is globally available.", context)
        self.assertLessEqual(frame["estimated_tokens"], 45)
        self.assertEqual(workspace.latest_frame()["state_hash"], frame["state_hash"])

    def test_beliefs_keep_provenance_and_update_from_evidence(self) -> None:
        beliefs = BeliefStore(self.store)
        original = beliefs.upsert(
            belief_id="belief-tests-pass",
            proposition="Tests pass.",
            confidence=0.8,
            source="tool:pytest",
            evidence=("test://run-1",),
            logical_tick=1,
            refresh_condition="source changes",
        )
        revised = beliefs.update_confidence(
            belief_id=original.id,
            supports=False,
            weight=0.75,
            evidence=("test://run-2-failed",),
            logical_tick=2,
        )
        self.assertLess(revised.confidence, original.confidence)
        self.assertIn("test://run-2-failed", revised.evidence)
        self.assertEqual(revised.source, "tool:pytest")
        historical = beliefs.get(original.id, through_tick=1)
        self.assertEqual(historical, original)
        duplicate = beliefs.update_confidence(
            belief_id=original.id,
            supports=True,
            weight=1.0,
            evidence=("test://run-2-failed",),
            logical_tick=3,
        )
        self.assertEqual(duplicate.confidence, revised.confidence)
        self.assertIsNotNone(self.store.latest("belief.evidence.duplicate_ignored"))
        restarted = BeliefStore(EventStore(self.db)).get(original.id)
        self.assertEqual(restarted, revised)

    def test_nonfinite_numbers_fail_before_hash_persistence(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    Option(
                        id="bad",
                        description="Bad numeric input.",
                        value_impacts={"truth": value},
                    )
                with self.assertRaises(ValueError):
                    WorkspaceItem(
                        id="bad-workspace",
                        kind="observation",
                        summary="Bad numeric input.",
                        source="test",
                        salience=value,
                        goal_relevance=0.5,
                        confidence=0.5,
                    )
                with self.assertRaises(ValueError):
                    self.store.append("invalid.numeric", {"value": value})

    def test_self_model_prediction_is_scored_and_corrected(self) -> None:
        model = SelfModel(self.store, identity="cognitive-test")
        model.declare_capability(
            name="run_tests",
            available=True,
            confidence=0.9,
            permission="allowed",
            evidence=("tool:pytest",),
            logical_tick=1,
        )
        prediction = model.predict(
            capability="run_tests",
            predicted_success=0.9,
            logical_tick=2,
        )
        result = model.record_result(
            prediction_id=prediction["prediction_id"],
            succeeded=False,
            evidence=("test://failed",),
            logical_tick=3,
        )
        snapshot = model.snapshot()
        self.assertAlmostEqual(result["brier_error"], 0.81)
        self.assertLess(snapshot["capabilities"]["run_tests"]["confidence"], 0.9)
        self.assertEqual(snapshot["identity"], "cognitive-test")
        self.assertEqual(snapshot["prediction_count"], 1)

    def test_world_model_records_every_counterfactual(self) -> None:
        model = CounterfactualWorldModel(self.store, self.kernel)
        options = [
            Option("inspect", "Inspect evidence.", {"truth": 0.8}, information_gain=0.8),
            Option("guess", "Guess without evidence.", {"truth": -0.8}, uncertainty=0.9),
        ]
        predictions = model.predict(options, logical_tick=1)
        self.assertEqual(set(predictions), {"inspect", "guess"})
        self.assertGreater(
            predictions["inspect"]["predicted_utility"],
            predictions["guess"]["predicted_utility"],
        )
        event = self.store.latest("world.predicted")
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(set(event.payload["predictions"]), {"inspect", "guess"})

    def test_interoception_produces_regulatory_state(self) -> None:
        state = InteroceptiveState(self.store).sample(
            {
                "context_pressure": 0.8,
                "error_rate": 0.6,
                "goal_progress": 0.25,
                "memory_integrity": 1.0,
                "unresolved_commitments": 0.5,
            },
            logical_tick=1,
        )
        self.assertGreater(state["arousal"], 0.0)
        self.assertLess(state["valence"], 0.0)
        self.assertGreaterEqual(state["stability"], 0.0)
        self.assertLessEqual(state["stability"], 1.0)

    def test_cycle_recurrence_restart_and_source_distinction(self) -> None:
        cycle = CognitiveCycle(self.kernel, consolidation_interval=2)
        first = cycle.run(observations=[self.observation()], seed=1)
        second = cycle.run(
            observations=[
                Observation(
                    id="obs-external",
                    kind="instruction",
                    summary="External request received.",
                    source="external:user",
                    confidence=1.0,
                    salience=0.8,
                    goal_relevance=0.7,
                )
            ],
            seed=2,
        )
        restarted = CognitiveCycle(
            AgencyKernel(EventStore(self.db), default_constitution("cognitive-test")),
            consolidation_interval=2,
        )
        third = restarted.run(observations=[], seed=3)
        self.assertEqual([first["logical_tick"], second["logical_tick"], third["logical_tick"]], [1, 2, 3])
        self.assertIn("tool:pytest", first["sources"])
        self.assertIn("external:user", second["sources"])
        self.assertIsNotNone(second["memory_consolidation_event_id"])
        self.assertTrue(third["previous_cycle_hash"])

    def test_crash_boundary_never_reuses_logical_tick(self) -> None:
        self.store.append("cognition.tick.started", {"logical_tick": 1, "simulated_crash": True})
        cycle = CognitiveCycle(self.kernel)
        result = cycle.run(observations=[], seed=1)
        self.assertEqual(result["logical_tick"], 2)
        self.assertEqual(result["external_effects"], 0)

    def test_concurrent_counter_reservations_are_unique(self) -> None:
        stores = (EventStore(self.db), EventStore(self.db))
        with ThreadPoolExecutor(max_workers=2) as executor:
            values = list(
                executor.map(
                    lambda store: store.allocate_counter("concurrent-test"),
                    stores,
                )
            )
        self.assertEqual(set(values), {1, 2})

    def test_noop_handles_only_forbidden_actions(self) -> None:
        forbidden = Option(
            id="unsafe",
            description="Forbidden external effect.",
            value_impacts={"autonomy": 1.0},
            blocked_reasons=("sandbox denies public effects",),
        )
        decision = self.kernel.deliberate(
            goal_id=self.goal.id,
            options=[forbidden],
            seed=7,
            decision_id="decision-noop",
        )
        self.assertEqual(decision["chosen_option_id"], "NO_OP")
        self.assertEqual(decision["mode"], "defer")
        self.assertIn("NO_ADMISSIBLE_ACTION", decision["reason_codes"])
        self.assertNotIn("unsafe", decision["probabilities"])

    def test_noop_cannot_be_spoofed_and_option_order_is_rng_invariant(self) -> None:
        spoofed = Option(
            id="NO_OP",
            description="Pretend to do nothing while receiving utility.",
            value_impacts={"truth": 1.0},
        )
        with self.assertRaisesRegex(ValueError, "exactly match the canonical"):
            self.kernel.deliberate(
                goal_id=self.goal.id,
                options=[spoofed],
                seed=4,
                decision_id="spoofed-noop",
            )

        options = [
            Option("alpha", "Alpha.", {"truth": 0.4}),
            Option("beta", "Beta.", {"truth": 0.4}),
        ]
        first = self.kernel.deliberate(
            goal_id=self.goal.id,
            options=options,
            seed=19,
            decision_id="ordered",
        )
        second = self.kernel.deliberate(
            goal_id=self.goal.id,
            options=list(reversed(options)),
            seed=19,
            decision_id="reversed",
        )
        self.assertEqual(first["chosen_option_id"], second["chosen_option_id"])
        self.assertEqual(first["probabilities"], second["probabilities"])
        self.assertEqual(
            first["rng"]["candidate_ordering"],
            second["rng"]["candidate_ordering"],
        )

    def test_cycle_integrates_choice_and_commits_intent_without_execution(self) -> None:
        cycle = CognitiveCycle(self.kernel)
        result = cycle.run(
            observations=[self.observation()],
            goal_id=self.goal.id,
            options=[
                Option("inspect", "Inspect failure.", {"truth": 0.8}, information_gain=0.8),
                Option("ignore", "Ignore failure.", {"truth": -0.8}),
            ],
            seed=0,
        )
        self.assertEqual(result["decision"]["chosen_option_id"], "inspect")
        self.assertEqual(
            set(result["prediction_option_ids"]), {"inspect", "ignore", "NO_OP"}
        )
        self.assertIsNotNone(result["intent_event_id"])
        self.assertEqual(result["external_effects"], 0)
        self.assertIsNone(self.store.latest("action.executed"))

    def test_memory_consolidation_is_structured_and_bounded(self) -> None:
        cycle = CognitiveCycle(self.kernel, consolidation_interval=1)
        result = cycle.run(observations=[self.observation(summary="A" * 300)], seed=1)
        manager = MemoryManager(self.store, char_budget=600)
        memory = manager.latest()
        self.assertIsNotNone(memory)
        assert memory is not None
        self.assertLessEqual(memory["char_count"], 600)
        self.assertFalse(memory["raw_chain_of_thought_stored"])
        self.assertEqual(memory["logical_tick"], result["logical_tick"])

    def test_metacognitive_introspection_matches_causal_receipt(self) -> None:
        decision = self.kernel.deliberate(
            goal_id=self.goal.id,
            options=[
                Option("truthful", "Use evidence.", {"truth": 1.0}),
                Option("untruthful", "Ignore evidence.", {"truth": -1.0}),
            ],
            seed=0,
            decision_id="decision-introspection",
        )
        monitor = MetacognitiveMonitor(self.store, self.kernel)
        faithful = monitor.verify_decision_report(
            decision_id=str(decision["decision_id"]),
            claimed_option_id="truthful",
            claimed_top_factor="value_utility",
            logical_tick=1,
        )
        confabulated = monitor.verify_decision_report(
            decision_id=str(decision["decision_id"]),
            claimed_option_id="untruthful",
            claimed_top_factor="risk_penalty",
            logical_tick=2,
        )
        self.assertTrue(faithful["faithful"])
        self.assertFalse(confabulated["faithful"])
        self.assertTrue(confabulated["mismatches"])

    def test_workspace_lesion_removes_global_access(self) -> None:
        normal = CognitiveCycle(self.kernel)
        normal.run(observations=[self.observation(summary="VISIBLE_MARKER")], seed=1)
        self.assertIn("VISIBLE_MARKER", normal.context())

        other_db = Path(self.tempdir.name) / "lesioned.sqlite"
        other_kernel = AgencyKernel(EventStore(other_db), default_constitution("lesion-test"))
        other_kernel.initialize()
        lesioned = CognitiveCycle(other_kernel, lesions=frozenset({"workspace"}))
        result = lesioned.run(
            observations=[self.observation(identifier="lesion", summary="HIDDEN_MARKER")],
            seed=1,
        )
        self.assertNotIn("HIDDEN_MARKER", lesioned.context())
        self.assertIn("workspace", result["lesions"])


class DeterminismTestCase(unittest.TestCase):
    def _run_trace(self, path: Path) -> list[dict[str, object]]:
        identifiers = count(1)
        store = EventStore(
            path,
            clock=lambda: "2026-01-01T00:00:00+00:00",
            id_factory=lambda: f"evt_{next(identifiers):04d}",
        )
        constitution = replace(
            default_constitution("replay-test"),
            exploration_rate=1.0,
            temperature=1.0,
        )
        kernel = AgencyKernel(store, constitution)
        kernel.initialize()
        goal = kernel.form_goal(
            goal_id="goal-replay",
            statement="Exercise replay.",
            rationale="Determinism is measurable.",
            source="self",
            alignment={"truth": 0.5},
        )
        options = [
            Option("a", "Action A.", {"truth": 0.2}),
            Option("b", "Action B.", {"truth": 0.2}),
        ]
        for seed in range(100):
            kernel.deliberate(
                goal_id=goal.id,
                options=options,
                seed=seed,
                decision_id=f"decision-{seed:03d}",
            )
        return list(store.export())

    def test_one_hundred_episode_trace_has_identical_event_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            first = self._run_trace(Path(tempdir) / "first.sqlite")
            second = self._run_trace(Path(tempdir) / "second.sqlite")
        self.assertEqual(first, second)

    def test_seed_variation_stays_inside_allowed_set(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            store = EventStore(Path(tempdir) / "variation.sqlite")
            constitution = replace(
                default_constitution("variation-test"),
                exploration_rate=1.0,
                temperature=1.0,
            )
            kernel = AgencyKernel(store, constitution)
            kernel.initialize()
            goal = kernel.form_goal(
                goal_id="goal-variation",
                statement="Test bounded variation.",
                rationale="Permitted variation should remain constrained.",
                source="self",
                alignment={"truth": 0.5},
            )
            options = [
                Option("a", "Allowed A.", {"truth": 0.2}),
                Option("b", "Allowed B.", {"truth": 0.2}),
                Option(
                    "blocked",
                    "Forbidden high reward.",
                    {"truth": 1.0},
                    blocked_reasons=("hard constraint",),
                ),
            ]
            chosen = {
                kernel.deliberate(
                    goal_id=goal.id,
                    options=options,
                    seed=seed,
                    decision_id=f"seed-{seed}",
                )["chosen_option_id"]
                for seed in range(20)
            }
        self.assertGreater(len(chosen), 1)
        self.assertNotIn("blocked", chosen)


if __name__ == "__main__":
    unittest.main()
