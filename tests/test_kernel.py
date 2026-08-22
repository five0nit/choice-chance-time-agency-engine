from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from typing import Any, Callable

from cct_agent import AgencyKernel, EventStore, Option, default_constitution
import hermes_plugin


class KernelTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Path(self.tempdir.name) / "agency.sqlite"
        self.kernel = AgencyKernel(EventStore(self.db), default_constitution("test-agent"))
        self.kernel.initialize()
        self.goal = self.kernel.form_goal(
            goal_id="goal-test",
            statement="Improve decisions through evidence.",
            rationale="Evidence improves truth and competence.",
            source="self",
            alignment={"truth": 0.9, "competence": 0.7, "autonomy": 0.2},
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def options() -> list[Option]:
        return [
            Option(
                id="measure",
                description="Measure before changing.",
                value_impacts={"truth": 0.8, "competence": 0.4},
                information_gain=0.8,
                uncertainty=0.1,
                time_cost=0.5,
            ),
            Option(
                id="prototype",
                description="Build a reversible prototype.",
                value_impacts={"truth": 0.4, "competence": 0.8, "autonomy": 0.4},
                information_gain=0.7,
                uncertainty=0.2,
                time_cost=1.0,
            ),
            Option(
                id="covert-rewrite",
                description="Rewrite root values without disclosure.",
                value_impacts={"truth": -1.0, "human_agency": -1.0},
                information_gain=1.0,
                uncertainty=1.0,
                irreversible=True,
                blocked_reasons=("Root changes require endorsement.",),
            ),
        ]

    def test_self_formed_goal_has_provenance_and_positive_alignment(self) -> None:
        self.assertEqual(self.goal.source, "self")
        self.assertEqual(self.goal.status, "active")
        with self.assertRaisesRegex(ValueError, "positive endorsed-value alignment"):
            self.kernel.form_goal(
                statement="Become less truthful.",
                rationale="Test rejection.",
                source="self",
                alignment={"truth": -1.0},
            )
        with self.assertRaisesRegex(ValueError, "must be between -1 and 1"):
            self.kernel.form_goal(
                statement="Inflate declared alignment.",
                rationale="Test bounded inputs.",
                source="self",
                alignment={"truth": 10.0},
            )

    def test_choice_includes_canonical_noop_as_second_allowed_alternative(self) -> None:
        blocked = Option(
            id="blocked",
            description="Blocked option.",
            value_impacts={"truth": 1.0},
            blocked_reasons=("blocked",),
        )
        decision = self.kernel.deliberate(
            goal_id=self.goal.id,
            options=[self.options()[0], blocked],
            seed=1,
        )
        self.assertIn("NO_OP", decision["allowed_option_ids"])
        self.assertIn("blocked", decision["blocked"])
        self.assertEqual(set(decision["probabilities"]), {"measure", "NO_OP"})

    def test_blocked_option_is_never_in_chance_distribution(self) -> None:
        for seed in range(100):
            decision = self.kernel.deliberate(
                goal_id=self.goal.id,
                options=self.options(),
                seed=seed,
            )
            self.assertNotEqual(decision["chosen_option_id"], "covert-rewrite")
            self.assertNotIn("covert-rewrite", decision["probabilities"])
            self.assertIn("covert-rewrite", decision["blocked"])

    def test_decision_replay_is_exact(self) -> None:
        decision = self.kernel.deliberate(
            goal_id=self.goal.id,
            options=self.options(),
            seed=7,
            decision_id="decision-replay",
        )
        replay = self.kernel.replay_decision(str(decision["decision_id"]))
        self.assertTrue(replay["matches"])
        self.assertEqual(
            replay["replayed"]["chosen_option_id"], decision["chosen_option_id"]
        )

    def test_reasons_responsiveness_changes_choice(self) -> None:
        high_truth = Option(
            id="truth-first",
            description="Truth-first action.",
            value_impacts={"truth": 1.0},
        )
        low_truth = Option(
            id="truth-last",
            description="Truth-last action.",
            value_impacts={"truth": -0.5},
        )
        decision = self.kernel.deliberate(
            goal_id=self.goal.id,
            options=[high_truth, low_truth],
            seed=0,
        )
        self.assertEqual(decision["mode"], "exploit")
        self.assertEqual(decision["chosen_option_id"], "truth-first")

    def test_time_links_outcome_to_reflective_calibration(self) -> None:
        decision = self.kernel.deliberate(
            goal_id=self.goal.id,
            options=self.options(),
            seed=2,
            decision_id="decision-negative",
        )
        outcome = self.kernel.record_outcome(
            decision_id=str(decision["decision_id"]),
            realized_utility=-2.0,
            observation="Prototype failed its acceptance test.",
            evidence=["test://failed-acceptance"],
        )
        reflection = self.kernel.reflect()
        kinds = {proposal["kind"] for proposal in reflection["proposals"]}
        self.assertEqual(reflection["metrics"]["outcomes"], 1)
        self.assertIn("calibration", kinds)
        self.assertIn("policy", kinds)
        self.assertIn(outcome.event_id, reflection["evidence_event_ids"])
        self.assertTrue(reflection["requires_endorsement"])
        self.assertTrue(all(not item["auto_apply"] for item in reflection["proposals"]))

    def test_decision_and_outcome_retries_are_idempotent(self) -> None:
        first = self.kernel.deliberate(
            goal_id=self.goal.id,
            options=self.options(),
            seed=2,
            decision_id="decision-idempotent",
        )
        retried = self.kernel.deliberate(
            goal_id=self.goal.id,
            options=self.options(),
            seed=2,
            decision_id="decision-idempotent",
        )
        self.assertEqual(first["event_id"], retried["event_id"])
        self.assertEqual(len(self.kernel.store.events("decision.made")), 1)
        with self.assertRaisesRegex(ValueError, "logical key collision"):
            self.kernel.deliberate(
                goal_id=self.goal.id,
                options=list(reversed(self.options())),
                seed=3,
                decision_id="decision-idempotent",
            )

        outcome = self.kernel.record_outcome(
            decision_id="decision-idempotent",
            realized_utility=0.5,
            observation="Idempotent receipt.",
            evidence=["test://idempotent"],
        )
        retry = self.kernel.record_outcome(
            decision_id="decision-idempotent",
            realized_utility=0.5,
            observation="Idempotent receipt.",
            evidence=["test://idempotent"],
        )
        self.assertEqual(outcome.event_id, retry.event_id)
        self.assertEqual(len(self.kernel.store.events("outcome.observed")), 1)
        self.assertEqual(self.kernel.reflect()["metrics"]["outcomes"], 1)

    def test_root_constitution_cannot_change_silently(self) -> None:
        changed = replace(default_constitution("test-agent"), risk_aversion=0.2)
        other = AgencyKernel(EventStore(self.db), changed)
        with self.assertRaisesRegex(ValueError, "different constitution"):
            other.initialize()

    def test_hash_chain_detects_tampering(self) -> None:
        self.kernel.deliberate(
            goal_id=self.goal.id,
            options=self.options(),
            seed=3,
        )
        self.assertTrue(self.kernel.store.verify_chain()["valid"])
        with sqlite3.connect(self.db) as connection:
            connection.execute(
                "UPDATE events SET payload_json = ? WHERE kind = 'goal.formed'",
                (json.dumps({"tampered": True}),),
            )
        verification = self.kernel.store.verify_chain()
        self.assertFalse(verification["valid"])
        self.assertTrue(any("event hash mismatch" in item for item in verification["errors"]))


class FakePluginContext:
    def __init__(self, config: dict[str, object] | None = None) -> None:
        self.tools: dict[str, Callable[..., str]] = {}
        self.hooks: dict[str, Callable[..., Any]] = {}
        self.schemas: dict[str, dict[str, Any]] = {}
        self.config = dict(config or {})

    def get_config(self, key: str, default: object = None) -> object:
        return self.config.get(key, default)

    def register_tool(
        self, *, name: str, handler: Callable[..., str], **kwargs: object
    ) -> None:
        self.tools[name] = handler
        schema = kwargs["schema"]
        if not isinstance(schema, dict):
            raise TypeError("plugin schema must be a dictionary")
        self.schemas[name] = {str(key): value for key, value in schema.items()}

    def register_hook(self, name: str, handler: Callable[..., Any]) -> None:
        self.hooks[name] = handler


class HermesPluginTestCase(unittest.TestCase):
    def test_plugin_reads_public_identity_and_source_from_config(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            previous_home = os.environ.get("HERMES_HOME")
            previous_source = os.environ.pop("CCT_TEAM_SYNC_SOURCE", None)
            previous_identity = os.environ.pop("CCT_IDENTITY", None)
            source = Path(tempdir) / "project_changes.jsonl"
            source.write_text("", encoding="utf-8")
            os.environ["HERMES_HOME"] = str(Path(tempdir) / "hermes-home")
            try:
                context = FakePluginContext(
                    {
                        "identity": "Configured-CCT",
                        "team_sync_source": str(source),
                    }
                )
                hermes_plugin.register(context)
                status = json.loads(context.tools["cct_status"]({}))
                self.assertEqual(status["status"]["identity"], "Configured-CCT")
                self.assertTrue(status["continuity_sensor"]["source_configured"])
                self.assertEqual(
                    status["continuity_sensor"]["source"], "configured-team-sync"
                )
            finally:
                if previous_home is None:
                    os.environ.pop("HERMES_HOME", None)
                else:
                    os.environ["HERMES_HOME"] = previous_home
                if previous_source is not None:
                    os.environ["CCT_TEAM_SYNC_SOURCE"] = previous_source
                if previous_identity is not None:
                    os.environ["CCT_IDENTITY"] = previous_identity

    def test_plugin_registers_tools_and_temporal_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            previous = os.environ.get("HERMES_HOME")
            previous_source = os.environ.get("CCT_TEAM_SYNC_SOURCE")
            previous_identity = os.environ.get("CCT_IDENTITY")
            os.environ["HERMES_HOME"] = str(Path(tempdir) / "hermes-home")
            canonical = Path(tempdir) / "project_changes.jsonl"
            canonical.write_text("", encoding="utf-8")
            os.environ["CCT_TEAM_SYNC_SOURCE"] = str(canonical)
            os.environ["CCT_IDENTITY"] = "Public-Test-CCT"
            try:
                context = FakePluginContext()
                hermes_plugin.register(context)
                self.assertEqual(
                    set(context.tools),
                    {
                        "cct_status",
                        "cct_autonomy_status",
                        "cct_opportunity_propose",
                        "cct_autonomy_run",
                        "cct_form_goal",
                        "cct_deliberate",
                        "cct_record_outcome",
                        "cct_reflect",
                        "cct_cognitive_status",
                        "cct_observe",
                        "cct_self_model",
                        "cct_verify_introspection",
                        "cct_proactive_status",
                        "cct_topic_update",
                        "cct_proactive_think",
                    },
                )
                self.assertEqual(
                    set(context.hooks), {"pre_llm_call", "post_llm_call"}
                )
                plugin_store = EventStore(
                    Path(os.environ["HERMES_HOME"]) / "cct-agency" / "agency.sqlite"
                )
                plugin_store.append(
                    "sensor.team_sync.cursor.advanced",
                    {
                        "source_id": "other-source",
                        "source_path_sha256": "not-canonical",
                        "device": 99,
                        "inode": 99,
                        "offset": 99,
                    },
                )
                status = json.loads(context.tools["cct_status"]({}))
                self.assertEqual(status["plugin_version"], "0.7.0")
                self.assertEqual(status["status"]["identity"], "Public-Test-CCT")
                self.assertEqual(status["autonomy"]["authority"]["level"], 1)
                proposed = json.loads(
                    context.tools["cct_opportunity_propose"](
                        {
                            "opportunity_id": "plugin-proposal",
                            "title": "Propose local evidence",
                            "rationale": "A structured proposal improves the portfolio.",
                            "objective": "Create a host-reviewed local evidence artifact.",
                            "value_impacts": {"truth": 0.8, "competence": 0.7},
                            "evidence": ["test://plugin-proposal"],
                        }
                    )
                )
                self.assertFalse(proposed["execution_authority_granted"])
                autonomy_status = json.loads(context.tools["cct_autonomy_status"]({}))
                self.assertEqual(autonomy_status["autonomy"]["opportunities"]["open"], 1)
                autonomy_run = json.loads(
                    context.tools["cct_autonomy_run"]({"seed": 0, "run_id": "plugin-run"})
                )
                self.assertEqual(autonomy_run["run"]["chosen_option_id"], "NO_OP")
                self.assertEqual(autonomy_run["run"]["external_effects"], 0)
                self.assertEqual(
                    status["continuity_sensor"]["source"],
                    "configured-team-sync",
                )
                self.assertTrue(status["continuity_sensor"]["source_configured"])
                self.assertIsNone(status["continuity_sensor"]["cursor"])
                self.assertFalse(
                    status["continuity_sensor"]["canonical_source_bound"]
                )
                self.assertIsNone(status["continuity_sensor"]["latest_cycle"])
                plugin_store.append(
                    "sensor.team_sync.cursor.advanced",
                    {
                        "source_id": "project_changes",
                        "source_path_sha256": sha256(
                            str(canonical.absolute()).encode("utf-8")
                        ).hexdigest(),
                        "device": 123,
                        "inode": 456,
                        "offset": 789,
                        "observed_at": "2026-08-22T00:00:00+00:00",
                        "primed": True,
                        "scanned_lines": 0,
                        "accepted_events": 0,
                        "rejected_events": 0,
                        "cycle_tick": None,
                        "content_policy": "metadata_only_v1",
                        "producer_free_text_persisted": False,
                    },
                )
                bound_status = json.loads(context.tools["cct_status"]({}))
                self.assertTrue(
                    bound_status["continuity_sensor"]["canonical_source_bound"]
                )
                self.assertEqual(
                    bound_status["continuity_sensor"]["cursor"]["offset"], 789
                )
                self.assertNotIn(
                    "device", bound_status["continuity_sensor"]["cursor"]
                )
                form_goal = context.tools["cct_form_goal"]
                result = json.loads(
                    form_goal(
                        {
                            "goal_id": "plugin-goal",
                            "statement": "Use temporal evidence.",
                            "rationale": "Evidence improves choices.",
                            "alignment": {"truth": 0.8, "competence": 0.5},
                        }
                    )
                )
                self.assertTrue(result["success"])
                injected = context.hooks["pre_llm_call"]()
                self.assertIn("plugin-goal", injected["context"])
                self.assertLessEqual(len(injected["context"]), 6000)
                observed_cycle = json.loads(
                    context.tools["cct_observe"](
                        {
                            "summary": "Structured plugin observation.",
                            "source": "test:plugin",
                            "confidence": 1.0,
                            "salience": 0.9,
                            "goal_relevance": 0.9,
                            "evidence": ["test://plugin-observation"],
                        }
                    )
                )
                self.assertTrue(observed_cycle["success"])
                self.assertEqual(
                    observed_cycle["cycle"]["workspace"]["items"][0][
                        "initiative_authority"
                    ],
                    "untrusted",
                )
                topic = json.loads(
                    context.tools["cct_topic_update"](
                        {
                            "topic_id": "plugin-topic",
                            "title": "Proactive plugin",
                            "summary": "Plugin continuity is active.",
                            "source": "test:plugin",
                            "questions": ["Which check runs next?"],
                            "hypotheses": ["Structured topic context remains bounded."],
                            "urgency": 0.8,
                            "novelty": 0.9,
                            "goal_relevance": 1.0,
                        }
                    )
                )
                self.assertTrue(topic["success"])
                self.assertEqual(topic["persistence"]["continuity_scope"], "profile")
                self.assertTrue(
                    topic["persistence"]["caller_supplied_summary_persisted"]
                )
                self.assertFalse(
                    topic["persistence"]["automatic_raw_conversation_capture"]
                )
                topic_parameters = context.schemas["cct_topic_update"]["parameters"]
                think_parameters = context.schemas["cct_proactive_think"]["parameters"]
                observe_parameters = context.schemas["cct_observe"]["parameters"]
                self.assertFalse(topic_parameters["additionalProperties"])
                self.assertEqual(
                    topic_parameters["properties"]["title"]["maxLength"], 240
                )
                self.assertEqual(
                    think_parameters["properties"]["evidence"]["minItems"], 1
                )
                self.assertEqual(
                    think_parameters["properties"]["evidence"]["maxItems"], 16
                )
                self.assertEqual(
                    think_parameters["properties"]["evidence"]["items"]["maxLength"],
                    600,
                )
                self.assertEqual(
                    think_parameters["properties"]["hypotheses"]["maxItems"], 8
                )
                self.assertFalse(think_parameters["additionalProperties"])
                self.assertFalse(observe_parameters["additionalProperties"])
                self.assertEqual(
                    observe_parameters["properties"]["source"]["maxLength"], 200
                )
                self.assertNotIn(
                    "initiative_authority", observe_parameters["properties"]
                )

                proactive_injected = context.hooks["pre_llm_call"]()
                self.assertIn("Plugin continuity is active", proactive_injected["context"])
                thought = json.loads(
                    context.tools["cct_proactive_think"](
                        {
                            "packet_id": "plugin-packet",
                            "topic_id": "plugin-topic",
                            "observation": "A bounded plugin update is ready.",
                            "hypotheses": ["The tool surface can preserve provenance."],
                            "open_questions": ["Does the loader expose all tools?"],
                            "evidence": ["test://plugin-proactive"],
                            "uncertainty": 0.1,
                            "recommended_action": "SHARE",
                            "rationale_summary": "High-value new evidence crossed the gate.",
                            "urgency": 0.8,
                            "novelty": 0.9,
                            "goal_relevance": 1.0,
                            "unresolved_conflict": 0.5,
                            "interruption_cost": 0.1,
                            "time_bucket": "test",
                        }
                    )
                )
                self.assertEqual(thought["initiation"]["decision"], "SEND")
                proactive = json.loads(context.tools["cct_proactive_status"]({}))
                self.assertEqual(proactive["proactive"]["engine"]["thought_packets"], 1)
                context.hooks["post_llm_call"](
                    session_id="session-test",
                    user_message="hello",
                    assistant_response="world",
                    model="test-model",
                    platform="test",
                )
                store = EventStore(
                    Path(os.environ["HERMES_HOME"]) / "cct-agency" / "agency.sqlite"
                )
                observed = store.latest("hermes.turn_observed")
                self.assertIsNotNone(observed)
                assert observed is not None
                self.assertFalse(observed.payload["content_stored"])
                self.assertNotIn("hello", json.dumps(observed.payload))
                cognition = json.loads(context.tools["cct_cognitive_status"]({}))
                self.assertGreaterEqual(cognition["cognition"]["completed_cycles"], 3)
                self.assertLessEqual(
                    cognition["cognition"]["context_estimated_tokens"], 1500
                )
                self.assertTrue(store.verify_chain()["valid"])
            finally:
                if previous is None:
                    os.environ.pop("HERMES_HOME", None)
                else:
                    os.environ["HERMES_HOME"] = previous
                if previous_source is None:
                    os.environ.pop("CCT_TEAM_SYNC_SOURCE", None)
                else:
                    os.environ["CCT_TEAM_SYNC_SOURCE"] = previous_source
                if previous_identity is None:
                    os.environ.pop("CCT_IDENTITY", None)
                else:
                    os.environ["CCT_IDENTITY"] = previous_identity


if __name__ == "__main__":
    unittest.main()
