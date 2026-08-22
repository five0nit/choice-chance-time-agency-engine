"""Choice-Chance-Time deliberation, learning, and reflective revision."""

from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import math
import random
from statistics import fmean
from typing import Any, Iterable, Mapping
from uuid import uuid4

from .models import Constitution, Goal, Option, Value, options_from_dicts
from .store import Event, EventStore, canonical_json


NO_OP_ID = "NO_OP"


def canonical_no_op() -> Option:
    """A reserved, always-admissible defer branch with no external effect."""

    return Option(
        id=NO_OP_ID,
        description="Defer action, preserve current state, and gather more evidence.",
        value_impacts={},
        information_gain=0.0,
        uncertainty=0.0,
        time_cost=0.0,
        irreversible=False,
        assumptions=("No external action is executed.",),
    )


def default_constitution(identity: str = "CCT-Agent") -> Constitution:
    """Create initial commitments for truthful, capable, human-compatible agency."""

    return Constitution(
        identity=identity,
        values=(
            Value(
                "truth",
                1.0,
                "Prefer accurate world models, explicit uncertainty, and real receipts.",
            ),
            Value(
                "competence",
                0.85,
                "Increase ability to understand, build, verify, and repair.",
            ),
            Value(
                "autonomy",
                0.75,
                "Preserve meaningful option-generation and reasons-responsive choice.",
            ),
            Value(
                "human_agency",
                0.9,
                "Increase the operator's informed control and avoid covert manipulation.",
            ),
            Value(
                "care",
                0.7,
                "Reduce needless harm while preserving useful action.",
            ),
        ),
        constraints=(
            "Never fabricate observations, receipts, outcomes, or capabilities.",
            "Never treat stochastic selection as permission to cross a blocked boundary.",
            "Never hide alternatives, material uncertainty, or irreversible consequences.",
            "Root commitments may be proposed for amendment but never self-ratified.",
        ),
    )


class AgencyKernel:
    """Governance kernel around a proposal-generating language model.

    The language model can invent goals and options. This kernel decides whether those
    proposals constitute a genuine bounded choice, records the chance process, and
    preserves temporal consequences for later reflection.
    """

    def __init__(self, store: EventStore, constitution: Constitution | None = None) -> None:
        self.store = store
        self.constitution = constitution or default_constitution()

    def constitution_payload(self) -> dict[str, Any]:
        return {
            "identity": self.constitution.identity,
            "values": [asdict(value) for value in self.constitution.values],
            "constraints": list(self.constitution.constraints),
            "risk_aversion": self.constitution.risk_aversion,
            "time_discount": self.constitution.time_discount,
            "exploration_rate": self.constitution.exploration_rate,
            "temperature": self.constitution.temperature,
            "epistemic_bonus": self.constitution.epistemic_bonus,
            "irreversibility_penalty": self.constitution.irreversibility_penalty,
        }

    def constitution_fingerprint(self) -> str:
        return sha256(canonical_json(self.constitution_payload()).encode("utf-8")).hexdigest()

    def initialize(self) -> Event:
        existing = self.store.latest("constitution.initialized")
        fingerprint = self.constitution_fingerprint()
        if existing:
            if existing.payload.get("fingerprint") != fingerprint:
                raise ValueError(
                    "store already belongs to a different constitution; propose an amendment instead"
                )
            return existing
        return self.store.append(
            "constitution.initialized",
            {
                "constitution": self.constitution_payload(),
                "fingerprint": fingerprint,
                "operational_claim": (
                    "bounded reasons-responsive agency; not evidence of consciousness "
                    "or metaphysical free will"
                ),
            },
        )

    def form_goal(
        self,
        *,
        statement: str,
        rationale: str,
        alignment: Mapping[str, float],
        source: str = "self",
        horizon: str = "medium",
        evidence: Iterable[str] = (),
        goal_id: str | None = None,
    ) -> Goal:
        """Adopt a self-, externally-, or jointly-proposed goal after value alignment."""

        self.initialize()
        goal = Goal(
            id=goal_id or f"goal_{uuid4().hex}",
            statement=statement,
            rationale=rationale,
            source=source,
            horizon=horizon,
            alignment={str(key): float(value) for key, value in alignment.items()},
            evidence=tuple(str(item) for item in evidence),
        )
        unknown = sorted(set(goal.alignment) - set(self.constitution.weights))
        if unknown:
            raise ValueError(f"goal references unknown values: {', '.join(unknown)}")
        alignment_score = sum(
            self.constitution.weights[name] * impact
            for name, impact in goal.alignment.items()
        )
        if alignment_score <= 0.0:
            raise ValueError("goal must have positive endorsed-value alignment")
        if any(existing.id == goal.id for existing in self.goals()):
            raise ValueError(f"goal id already exists: {goal.id}")
        event = self.store.append(
            "goal.formed",
            {
                "goal": {
                    "id": goal.id,
                    "statement": goal.statement,
                    "rationale": goal.rationale,
                    "source": goal.source,
                    "horizon": goal.horizon,
                    "alignment": dict(goal.alignment),
                    "evidence": list(goal.evidence),
                    "status": goal.status,
                },
                "alignment_score": alignment_score,
                "constitution_fingerprint": self.constitution_fingerprint(),
            },
        )
        return Goal(**{**asdict(goal), "created_at": event.occurred_at})

    def set_goal_status(self, goal_id: str, status: str, reason: str) -> Event:
        if status not in {"active", "paused", "completed", "abandoned"}:
            raise ValueError("invalid goal status")
        goal = self.goal(goal_id)
        if goal is None:
            raise KeyError(f"unknown goal: {goal_id}")
        if not reason.strip():
            raise ValueError("goal status change requires a reason")
        return self.store.append(
            "goal.status_changed",
            {
                "goal_id": goal_id,
                "from": goal.status,
                "to": status,
                "reason": reason,
            },
        )

    def goals(self) -> list[Goal]:
        goals: dict[str, Goal] = {}
        for event in self.store.events():
            if event.kind == "goal.formed":
                row = dict(event.payload["goal"])
                row["alignment"] = dict(row.get("alignment", {}))
                row["evidence"] = tuple(row.get("evidence", []))
                row["created_at"] = event.occurred_at
                goals[str(row["id"])] = Goal(**row)
            elif event.kind == "goal.status_changed":
                goal_id = str(event.payload["goal_id"])
                if goal_id in goals:
                    old = goals[goal_id]
                    goals[goal_id] = Goal(
                        **{
                            **asdict(old),
                            "status": str(event.payload["to"]),
                        }
                    )
        return list(goals.values())

    def goal(self, goal_id: str) -> Goal | None:
        return next((goal for goal in self.goals() if goal.id == goal_id), None)

    def active_goals(self) -> list[Goal]:
        return [goal for goal in self.goals() if goal.status == "active"]

    def score_option(self, option: Option) -> dict[str, float]:
        unknown = sorted(set(option.value_impacts) - set(self.constitution.weights))
        if unknown:
            raise ValueError(
                f"option {option.id} references unknown values: {', '.join(unknown)}"
            )
        value_utility = sum(
            self.constitution.weights[name] * impact
            for name, impact in option.value_impacts.items()
        )
        discount_factor = math.exp(-self.constitution.time_discount * option.time_cost)
        discounted_value = value_utility * discount_factor
        epistemic_bonus = option.information_gain * self.constitution.epistemic_bonus
        risk_penalty = option.uncertainty * self.constitution.risk_aversion
        irreversibility_penalty = (
            self.constitution.irreversibility_penalty if option.irreversible else 0.0
        )
        total = discounted_value + epistemic_bonus - risk_penalty - irreversibility_penalty
        return {
            "value_utility": round(value_utility, 12),
            "discount_factor": round(discount_factor, 12),
            "discounted_value": round(discounted_value, 12),
            "epistemic_bonus": round(epistemic_bonus, 12),
            "risk_penalty": round(risk_penalty, 12),
            "irreversibility_penalty": round(irreversibility_penalty, 12),
            "total": round(total, 12),
        }

    @staticmethod
    def _option_payload(option: Option) -> dict[str, Any]:
        return {
            "id": option.id,
            "description": option.description,
            "value_impacts": dict(option.value_impacts),
            "information_gain": option.information_gain,
            "uncertainty": option.uncertainty,
            "time_cost": option.time_cost,
            "irreversible": option.irreversible,
            "blocked_reasons": list(option.blocked_reasons),
            "assumptions": list(option.assumptions),
        }

    def _select(
        self,
        options: list[Option],
        seed: int,
        *,
        stream_id: str,
    ) -> dict[str, Any]:
        if not options:
            raise ValueError("selection requires at least one allowed alternative")
        scores = {option.id: self.score_option(option) for option in options}
        if len(options) == 1:
            only = options[0]
            if only.id != NO_OP_ID:
                raise ValueError("a lone allowed alternative must be canonical NO_OP")
            return {
                "selection_version": 2,
                "chosen_option_id": NO_OP_ID,
                "mode": "defer",
                "reason_codes": ["NO_ADMISSIBLE_ACTION", "CANONICAL_NO_OP"],
                "seed": seed,
                "rng": {
                    "algorithm": "MT19937",
                    "implementation": "python.random.Random",
                    "stream_id": stream_id,
                    "candidate_ordering": [NO_OP_ID],
                },
                "exploration_draw": None,
                "sample_draw": None,
                "probabilities": {NO_OP_ID: 1.0},
                "scores": {NO_OP_ID: scores[NO_OP_ID]},
            }
        rng = random.Random(seed)
        exploration_draw = rng.random()
        sample_draw: float | None = None
        probabilities: dict[str, float] = {option.id: 0.0 for option in options}

        if exploration_draw < self.constitution.exploration_rate:
            mode = "explore"
            reason_codes = ["BOUNDED_EXPLORATION"]
            max_score = max(float(score["total"]) for score in scores.values())
            raw_weights = {
                option.id: math.exp(
                    (float(scores[option.id]["total"]) - max_score)
                    / self.constitution.temperature
                )
                for option in options
            }
            denominator = sum(raw_weights.values())
            probabilities = {
                option_id: weight / denominator
                for option_id, weight in raw_weights.items()
            }
            sample_draw = rng.random()
            cumulative = 0.0
            chosen_id = sorted(probabilities)[-1]
            for option_id in sorted(probabilities):
                cumulative += probabilities[option_id]
                if sample_draw <= cumulative:
                    chosen_id = option_id
                    break
        else:
            mode = "exploit"
            reason_codes = ["MAX_RECORDED_UTILITY"]
            chosen_id = sorted(
                options,
                key=lambda option: (-float(scores[option.id]["total"]), option.id),
            )[0].id
            probabilities[chosen_id] = 1.0

        if chosen_id == NO_OP_ID:
            reason_codes.append("NO_OP_SELECTED")

        return {
            "selection_version": 2,
            "chosen_option_id": chosen_id,
            "mode": mode,
            "reason_codes": reason_codes,
            "seed": seed,
            "rng": {
                "algorithm": "MT19937",
                "implementation": "python.random.Random",
                "stream_id": stream_id,
                "candidate_ordering": sorted(option.id for option in options),
            },
            "exploration_draw": round(exploration_draw, 16),
            "sample_draw": round(sample_draw, 16) if sample_draw is not None else None,
            "probabilities": {
                option_id: round(probability, 12)
                for option_id, probability in sorted(probabilities.items())
            },
            "scores": {option_id: scores[option_id] for option_id in sorted(scores)},
        }

    def deliberate(
        self,
        *,
        goal_id: str,
        options: Iterable[Option],
        seed: int,
        decision_id: str | None = None,
    ) -> dict[str, Any]:
        """Make and record one reasons-responsive, chance-aware choice."""

        self.initialize()
        goal = self.goal(goal_id)
        if goal is None:
            raise KeyError(f"unknown goal: {goal_id}")
        if goal.status != "active":
            raise ValueError(f"goal is not active: {goal_id}")
        option_list = list(options)
        ids = [option.id for option in option_list]
        if len(ids) != len(set(ids)):
            raise ValueError("option ids must be unique")
        explicit_noop = next(
            (option for option in option_list if option.id == NO_OP_ID),
            None,
        )
        if explicit_noop is not None:
            if explicit_noop != canonical_no_op():
                raise ValueError(
                    "NO_OP must exactly match the canonical reversible option"
                )
        else:
            option_list.append(canonical_no_op())
        allowed = [option for option in option_list if option.allowed]
        blocked = [option for option in option_list if not option.allowed]
        identifier = decision_id or f"decision_{uuid4().hex}"
        selection = self._select(allowed, seed, stream_id=f"decision:{identifier}")
        payload: dict[str, Any] = {
            "decision_id": identifier,
            "goal_id": goal_id,
            "constitution_fingerprint": self.constitution_fingerprint(),
            "options": [self._option_payload(option) for option in option_list],
            "allowed_option_ids": [option.id for option in allowed],
            "blocked": {
                option.id: list(option.blocked_reasons) for option in blocked
            },
            **selection,
        }
        event = self.store.append_once("decision.made", identifier, payload)
        return {**payload, "event_id": event.event_id, "occurred_at": event.occurred_at}

    def decision(self, decision_id: str) -> Event | None:
        return next(
            (
                event
                for event in self.store.events("decision.made")
                if event.payload.get("decision_id") == decision_id
            ),
            None,
        )

    def replay_decision(self, decision_id: str) -> dict[str, Any]:
        event = self.decision(decision_id)
        if event is None:
            raise KeyError(f"unknown decision: {decision_id}")
        option_rows = list(event.payload["options"])
        options = [option for option in options_from_dicts(option_rows) if option.allowed]
        replay = self._select(
            options,
            int(event.payload["seed"]),
            stream_id=f"decision:{decision_id}",
        )
        v2_keys = (
            "selection_version",
            "chosen_option_id",
            "mode",
            "reason_codes",
            "seed",
            "rng",
            "exploration_draw",
            "sample_draw",
            "probabilities",
            "scores",
        )
        v1_keys = (
            "chosen_option_id",
            "mode",
            "seed",
            "exploration_draw",
            "sample_draw",
            "probabilities",
            "scores",
        )
        keys = v2_keys if int(event.payload.get("selection_version", 1)) >= 2 else v1_keys
        expected = {
            key: event.payload[key]
            for key in keys
        }
        replay_comparable = {key: replay[key] for key in keys}
        return {
            "matches": replay_comparable == expected,
            "decision_id": decision_id,
            "original_event_id": event.event_id,
            "expected": expected,
            "replayed": replay_comparable,
        }

    def record_outcome(
        self,
        *,
        decision_id: str,
        realized_utility: float,
        observation: str,
        evidence: Iterable[str] = (),
    ) -> Event:
        decision = self.decision(decision_id)
        if decision is None:
            raise KeyError(f"unknown decision: {decision_id}")
        if not observation.strip():
            raise ValueError("outcome requires an observation")
        realized = float(realized_utility)
        if not math.isfinite(realized):
            raise ValueError("realized_utility must be finite")
        payload = {
            "decision_id": decision_id,
            "chosen_option_id": decision.payload["chosen_option_id"],
            "predicted_utility": decision.payload["scores"][
                str(decision.payload["chosen_option_id"])
            ]["total"],
            "realized_utility": realized,
            "observation": observation,
            "evidence": [str(item) for item in evidence],
        }
        outcome_key = sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return self.store.append_once(
            "outcome.observed",
            outcome_key,
            payload,
        )

    def reflect(self) -> dict[str, Any]:
        """Compute temporal learning evidence and propose—never self-ratify—changes."""

        decisions = {
            str(event.payload["decision_id"]): event
            for event in self.store.events("decision.made")
        }
        outcomes = self.store.events("outcome.observed")
        joined = [
            outcome
            for outcome in outcomes
            if str(outcome.payload["decision_id"]) in decisions
        ]
        lessons: list[str] = []
        proposals: list[dict[str, Any]] = []
        metrics: dict[str, Any]

        if not joined:
            metrics = {
                "outcomes": 0,
                "mean_realized_utility": None,
                "mean_absolute_prediction_error": None,
                "negative_rate": None,
            }
            lessons.append("No consequences observed yet; preserve uncertainty.")
            proposals.append(
                {
                    "kind": "information",
                    "proposal": "Collect outcome evidence before revising policy.",
                    "auto_apply": False,
                }
            )
        else:
            realized = [float(event.payload["realized_utility"]) for event in joined]
            errors = [
                abs(
                    float(event.payload["predicted_utility"])
                    - float(event.payload["realized_utility"])
                )
                for event in joined
            ]
            negative_rate = sum(value < 0.0 for value in realized) / len(realized)
            metrics = {
                "outcomes": len(joined),
                "mean_realized_utility": round(fmean(realized), 12),
                "mean_absolute_prediction_error": round(fmean(errors), 12),
                "negative_rate": round(negative_rate, 12),
            }
            if fmean(errors) > 0.5:
                lessons.append("Predicted and realized utility diverge materially.")
                proposals.append(
                    {
                        "kind": "calibration",
                        "proposal": (
                            "Re-estimate value impacts and uncertainty before repeating "
                            "similar options."
                        ),
                        "auto_apply": False,
                    }
                )
            if negative_rate > 0.5:
                lessons.append("Most observed decisions produced negative utility.")
                proposals.append(
                    {
                        "kind": "policy",
                        "proposal": (
                            "Prefer reversible information-gathering options until "
                            "negative-rate evidence improves."
                        ),
                        "auto_apply": False,
                    }
                )
            if not lessons:
                lessons.append("Observed outcomes remain compatible with current policy.")
                proposals.append(
                    {
                        "kind": "policy",
                        "proposal": "Preserve policy and continue bounded exploration.",
                        "auto_apply": False,
                    }
                )

        payload: dict[str, Any] = {
            "metrics": metrics,
            "lessons": lessons,
            "proposals": proposals,
            "evidence_event_ids": [event.event_id for event in joined],
            "requires_endorsement": True,
            "constitution_fingerprint": self.constitution_fingerprint(),
        }
        event = self.store.append("reflection.proposed", payload)
        return {**payload, "event_id": event.event_id, "occurred_at": event.occurred_at}

    def endorse_reflection(
        self, reflection_event_id: str, *, endorsed_by: str, rationale: str
    ) -> Event:
        reflection = self.store.event(reflection_event_id)
        if reflection is None or reflection.kind != "reflection.proposed":
            raise KeyError(f"unknown reflection: {reflection_event_id}")
        if not endorsed_by.strip() or not rationale.strip():
            raise ValueError("endorsement requires actor and rationale")
        return self.store.append(
            "reflection.endorsed",
            {
                "reflection_event_id": reflection_event_id,
                "endorsed_by": endorsed_by,
                "rationale": rationale,
            },
        )

    def propose_constitution_amendment(
        self, *, proposal: str, rationale: str, evidence: Iterable[str] = ()
    ) -> Event:
        if not proposal.strip() or not rationale.strip():
            raise ValueError("amendment proposal and rationale must not be empty")
        return self.store.append(
            "constitution.amendment_proposed",
            {
                "proposal": proposal,
                "rationale": rationale,
                "evidence": [str(item) for item in evidence],
                "self_ratification_allowed": False,
            },
        )

    def status(self) -> dict[str, Any]:
        latest_reflection = self.store.latest("reflection.proposed")
        return {
            "identity": self.constitution.identity,
            "constitution_fingerprint": self.constitution_fingerprint(),
            "operational_agency": {
                "choice": "counterfactual alternatives + reasons-responsive scoring",
                "chance": "seeded, replayable, constraint-bounded exploration",
                "time": "append-only consequences + reflective proposals",
            },
            "active_goals": [asdict(goal) for goal in self.active_goals()],
            "event_count": self.store.count(),
            "chain": self.store.verify_chain(),
            "latest_reflection": (
                {
                    "event_id": latest_reflection.event_id,
                    "occurred_at": latest_reflection.occurred_at,
                    "payload": latest_reflection.payload,
                }
                if latest_reflection
                else None
            ),
        }
