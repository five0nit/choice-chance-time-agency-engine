"""Recurrent bounded cognitive cycle integrating the Level-3 components."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Iterable, Mapping

from .attention import AttentionPolicy
from .beliefs import BeliefStore
from .interoception import InteroceptiveState
from .kernel import AgencyKernel, NO_OP_ID, canonical_no_op
from .memory import MemoryManager
from .metacognition import MetacognitiveMonitor
from .models import Option
from .self_model import SelfModel
from .stalls import StallDetector
from .store import canonical_json
from .workspace import GlobalWorkspace, WorkspaceItem
from .world_model import CounterfactualWorldModel


@dataclass(frozen=True, slots=True)
class Observation:
    id: str
    kind: str
    summary: str
    source: str
    confidence: float
    salience: float
    goal_relevance: float
    novelty: float = 0.0
    urgency: float = 0.0
    unresolved_conflict: float = 0.0
    processing_cost: float = 0.0
    evidence: tuple[str, ...] = field(default_factory=tuple)
    proposition: str | None = None
    initiative_authority: str = "untrusted"

    def __post_init__(self) -> None:
        for name in ("id", "kind", "summary", "source"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"observation {name} must not be empty")
        if len(self.summary) > 2000:
            raise ValueError("observation summary exceeds 2000 characters")
        for name, maximum in (("id", 180), ("kind", 80), ("source", 200)):
            if len(str(getattr(self, name)).strip()) > maximum:
                raise ValueError(f"observation {name} exceeds {maximum} characters")
        if self.initiative_authority not in {"untrusted", "trusted_producer"}:
            raise ValueError(
                "observation initiative_authority must be untrusted or trusted_producer"
            )
        for name in (
            "confidence",
            "salience",
            "goal_relevance",
            "novelty",
            "urgency",
            "unresolved_conflict",
            "processing_cost",
        ):
            value = float(getattr(self, name))
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"observation {name} must be between 0 and 1")


class CognitiveCycle:
    """A deterministic global-access loop; never executes external effects itself."""

    ALLOWED_LESIONS = {
        "attention",
        "workspace",
        "beliefs",
        "self_model",
        "world_model",
        "memory",
        "metacognition",
        "interoception",
    }

    def __init__(
        self,
        kernel: AgencyKernel,
        *,
        workspace_capacity: int = 8,
        workspace_char_budget: int = 6000,
        consolidation_interval: int = 20,
        lesions: frozenset[str] = frozenset(),
    ) -> None:
        unknown = set(lesions) - self.ALLOWED_LESIONS
        if unknown:
            raise ValueError(f"unknown cognitive lesions: {sorted(unknown)}")
        if consolidation_interval < 1:
            raise ValueError("consolidation_interval must be positive")
        self.kernel = kernel
        self.kernel.initialize()
        self.store = kernel.store
        self.attention = AttentionPolicy(
            capacity=workspace_capacity,
            char_budget=workspace_char_budget,
        )
        self.workspace = GlobalWorkspace(
            self.store,
            capacity=workspace_capacity,
            char_budget=workspace_char_budget,
        )
        self.beliefs = BeliefStore(self.store)
        self.self_model = SelfModel(
            self.store,
            identity=self.kernel.constitution.identity,
        )
        self.world_model = CounterfactualWorldModel(self.store, self.kernel)
        self.interoception = InteroceptiveState(self.store)
        self.memory = MemoryManager(self.store)
        self.metacognition = MetacognitiveMonitor(self.store, self.kernel)
        self.stalls = StallDetector(self.store)
        self.consolidation_interval = consolidation_interval
        self.lesions = lesions

    def _next_tick(self) -> int:
        starts = self.store.events("cognition.tick.started")
        floor = max(
            (int(event.payload["logical_tick"]) for event in starts),
            default=0,
        )
        return self.store.allocate_counter("cognitive_tick", floor=floor)

    def _previous_cycle_hash(self) -> str:
        previous = self.store.latest("cognition.cycle.completed")
        return str(previous.payload["cycle_hash"]) if previous else ""

    @staticmethod
    def _observation_digest(observation: Observation) -> str:
        return sha256(
            canonical_json(
                {
                    "id": observation.id,
                    "kind": observation.kind,
                    "summary": observation.summary,
                    "source": observation.source,
                    "evidence": list(observation.evidence),
                    "initiative_authority": observation.initiative_authority,
                }
            ).encode("utf-8")
        ).hexdigest()

    @classmethod
    def _observation_item(
        cls, observation: Observation, *, logical_tick: int
    ) -> WorkspaceItem:
        return WorkspaceItem(
            id=observation.id,
            kind=observation.kind,
            summary=observation.summary,
            source=observation.source,
            salience=observation.salience,
            goal_relevance=observation.goal_relevance,
            confidence=observation.confidence,
            novelty=observation.novelty,
            urgency=observation.urgency,
            unresolved_conflict=observation.unresolved_conflict,
            processing_cost=observation.processing_cost,
            logical_tick=logical_tick,
            evidence=observation.evidence,
            content_digest=cls._observation_digest(observation),
            initiative_authority=observation.initiative_authority,
        )

    def run(
        self,
        *,
        observations: Iterable[Observation],
        seed: int,
        goal_id: str | None = None,
        options: Iterable[Option] = (),
        internal_signals: Mapping[str, float] | None = None,
    ) -> dict[str, Any]:
        tick = self._next_tick()
        observation_list = list(observations)
        sources = sorted({observation.source for observation in observation_list})
        previous_cycle_hash = self._previous_cycle_hash()
        started = self.store.append(
            "cognition.tick.started",
            {
                "logical_tick": tick,
                "seed": seed,
                "observation_digests": [
                    self._observation_digest(observation)
                    for observation in observation_list
                ],
                "sources": sources,
                "lesions": sorted(self.lesions),
                "previous_cycle_hash": previous_cycle_hash,
            },
        )

        interoception_payload: dict[str, Any] | None = None
        if "interoception" not in self.lesions:
            signals = dict(
                internal_signals
                or {
                    "context_pressure": 0.0,
                    "error_rate": 0.0,
                    "goal_progress": 0.5,
                    "memory_integrity": 1.0
                    if self.store.verify_chain()["valid"]
                    else 0.0,
                    "tool_availability": 1.0,
                    "unresolved_commitments": min(
                        1.0,
                        len(self.self_model.snapshot()["commitments"]) / 10.0,
                    ),
                }
            )
            interoception_payload = self.interoception.sample(signals, logical_tick=tick)

        attention_profile = self.attention.regulatory_profile(interoception_payload)
        workspace_candidates: list[WorkspaceItem] = []
        for observation in observation_list:
            digest = self._observation_digest(observation)
            workspace_candidates.append(
                self._observation_item(observation, logical_tick=tick)
            )
            if observation.proposition and "beliefs" not in self.lesions:
                belief_id = "belief_" + sha256(
                    observation.proposition.encode("utf-8")
                ).hexdigest()[:20]
                evidence = observation.evidence or (f"observation:{digest}",)
                self.beliefs.upsert(
                    belief_id=belief_id,
                    proposition=observation.proposition,
                    confidence=observation.confidence,
                    source=observation.source,
                    evidence=evidence,
                    logical_tick=tick,
                    refresh_condition="new contradictory evidence",
                )

        attended = (
            []
            if "attention" in self.lesions
            else self.attention.select(
                workspace_candidates, profile=attention_profile
            )
        )
        workspace_frame = self.workspace.broadcast(
            attended,
            logical_tick=tick,
            lesion="workspace" in self.lesions,
            attention_policy=attention_profile,
        )

        option_list = list(options)
        predictions: dict[str, dict[str, Any]] = {}
        decision: dict[str, Any] | None = None
        intent_event_id: str | None = None
        if option_list or goal_id is not None:
            if goal_id is None:
                raise ValueError("goal_id is required when options are supplied")
            if not any(option.id == NO_OP_ID for option in option_list):
                option_list.append(canonical_no_op())
            if "world_model" not in self.lesions:
                predictions = self.world_model.predict(option_list, logical_tick=tick)
            decision = self.kernel.deliberate(
                goal_id=goal_id,
                options=option_list,
                seed=seed,
                decision_id=f"decision_tick_{tick}",
            )
            intent = self.store.append(
                "intent.committed",
                {
                    "logical_tick": tick,
                    "decision_id": decision["decision_id"],
                    "chosen_option_id": decision["chosen_option_id"],
                    "external_execution_authorized": False,
                    "external_effects": 0,
                },
            )
            intent_event_id = intent.event_id

        stall = self.stalls.observe(
            goal_id=goal_id,
            decision=decision,
            options=option_list,
            candidates=workspace_candidates,
            logical_tick=tick,
        )

        memory_event_id: str | None = None
        if tick % self.consolidation_interval == 0 and "memory" not in self.lesions:
            memory_event_id = self.memory.consolidate(logical_tick=tick)["event_id"]

        self_snapshot = (
            {}
            if "self_model" in self.lesions
            else self.self_model.snapshot()
        )
        metacognitive: dict[str, Any] | None = None
        if "metacognition" not in self.lesions:
            metacognitive = self.metacognition.evaluate(
                logical_tick=tick,
                lesions=self.lesions,
            )

        state_material = {
            "logical_tick": tick,
            "workspace_state_hash": workspace_frame["state_hash"],
            "belief_ids": [belief.id for belief in self.beliefs.active()],
            "self_model": self_snapshot,
            "decision_id": decision["decision_id"] if decision else None,
            "chosen_option_id": decision["chosen_option_id"] if decision else None,
            "intent_event_id": intent_event_id,
            "stall_sample_event_id": stall.get("sample_event_id"),
            "stall_event_id": stall.get("stall_event_id"),
            "exploration_request_event_id": stall.get(
                "exploration_request_event_id"
            ),
            "memory_consolidation_event_id": memory_event_id,
            "previous_cycle_hash": previous_cycle_hash,
            "lesions": sorted(self.lesions),
            "external_effects": 0,
        }
        cycle_hash = sha256(canonical_json(state_material).encode("utf-8")).hexdigest()
        completed_payload: dict[str, Any] = {
            **state_material,
            "cycle_hash": cycle_hash,
            "started_event_id": started.event_id,
            "sources": sources,
            "prediction_option_ids": sorted(predictions),
            "metacognition_event_id": (
                metacognitive["event_id"] if metacognitive else None
            ),
        }
        completed = self.store.append("cognition.cycle.completed", completed_payload)
        return {
            **completed_payload,
            "event_id": completed.event_id,
            "decision": decision,
            "workspace": workspace_frame,
            "interoception": interoception_payload,
            "stall": stall,
        }

    def context(self, *, max_chars: int = 6000) -> str:
        if max_chars < 256:
            raise ValueError("context max_chars must be at least 256")
        sections: list[str] = []
        workspace = self.workspace.render_context(max_chars=max_chars)
        if workspace:
            sections.append(workspace)
        goals = self.kernel.active_goals()[:5]
        if goals:
            sections.append(
                "Active goals:\n"
                + "\n".join(
                    f"- [{goal.source}] {goal.id}: {goal.statement}" for goal in goals
                )
            )
        exploration = self.store.latest("cognition.exploration.requested")
        if exploration is not None:
            goal_id_sha256 = str(exploration.payload.get("goal_id_sha256", ""))
            target = next(
                (
                    goal
                    for goal in goals
                    if sha256(canonical_json(goal.id).encode("utf-8")).hexdigest()
                    == goal_id_sha256
                ),
                None,
            )
            if target is not None:
                sections.append(
                    "Cognitive exploration request:\n"
                    f"- Proposal-only exploration requested for goal {target.id}. "
                    "Return structured provenance, assumptions, uncertainty, and a "
                    "falsifiable discriminator; this does not grant effect authority."
                )
        beliefs = self.beliefs.active()[:8]
        if beliefs:
            sections.append(
                "Evidence-linked beliefs:\n"
                + "\n".join(
                    f"- {belief.proposition} (confidence={belief.confidence:.2f}, "
                    f"source={belief.source})"
                    for belief in beliefs
                )
            )
        if "self_model" not in self.lesions:
            snapshot = self.self_model.snapshot()
            capability_lines = [
                f"- {name}: available={row['available']}, "
                f"confidence={float(row['confidence']):.2f}, permission={row['permission']}"
                for name, row in sorted(snapshot["capabilities"].items())[:8]
            ]
            if capability_lines:
                sections.append("Self-model capabilities:\n" + "\n".join(capability_lines))
        boundary = (
            "Boundary: this is bounded functional/access-cognition state, not evidence "
            "of phenomenal consciousness or felt experience."
        )
        sections.append(boundary)
        rendered = "\n\n".join(sections)
        return rendered[:max_chars]

    def status(self) -> dict[str, Any]:
        starts = self.store.events("cognition.tick.started")
        completed = self.store.events("cognition.cycle.completed")
        completed_ticks = {int(event.payload["logical_tick"]) for event in completed}
        started_ticks = {int(event.payload["logical_tick"]) for event in starts}
        context = self.context()
        latest = completed[-1] if completed else None
        return {
            "logical_tick": int(latest.payload["logical_tick"]) if latest else 0,
            "completed_cycles": len(completed),
            "incomplete_ticks": sorted(started_ticks - completed_ticks),
            "latest_cycle_hash": str(latest.payload["cycle_hash"]) if latest else "",
            "workspace": self.workspace.latest_frame(),
            "active_belief_count": len(self.beliefs.active()),
            "self_model": self.self_model.snapshot(),
            "stalls": self.stalls.status(),
            "context_chars": len(context),
            "context_estimated_tokens": (len(context) + 3) // 4,
            "context_token_budget": 1500,
            "lesions": sorted(self.lesions),
            "external_effects": 0,
            "phenomenal_consciousness_claimed": False,
        }
