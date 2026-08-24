"""Suggest concrete work and attempt one bounded local evidence audit.

This runner turns persistent active goals into observable initiative. It never executes the
suggested goal's requested external effect. The only autonomous effect is a create-only,
verified local audit artifact under a host-selected workspace root.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import threading
from typing import Any, Mapping

try:  # pragma: no cover - Linux/WSL is the production target.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

from .autonomy import AutonomyEngine
from .kernel import AgencyKernel, NO_OP_ID, resolve_constitution
from .models import Option
from .proactive import InitiationSignals, ProactiveEngine, ThoughtPacket
from .store import Event, EventStore, canonical_json


_CONTRACT_VERSION = "cct.work-autonomy.v1"
_PORTFOLIO_GOAL_ID = "goal_cct_autonomous_local_work"
_ALLOWED_GOAL_SOURCES = {"self", "joint", "external"}
_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _ellipsize(value: object, maximum: int) -> str:
    text = " ".join(str(value).split())
    if len(text) <= maximum:
        return text
    return text[: maximum - 1].rstrip() + "…"


def _goal_rows(events: list[Event]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.kind == "goal.formed":
            goal = dict(event.payload.get("goal", {}))
            identifier = str(goal.get("id", ""))
            if identifier:
                rows[identifier] = {
                    **goal,
                    "formed_event_id": event.event_id,
                    "formed_seq": event.seq,
                    "formed_at": event.occurred_at,
                }
        elif event.kind == "goal.status_changed":
            identifier = str(event.payload.get("goal_id", ""))
            if identifier in rows:
                rows[identifier]["status"] = str(event.payload.get("to", ""))
    return [rows[key] for key in sorted(rows)]


def _latest_source_token(events: list[Event]) -> dict[str, object] | None:
    for event in reversed(events):
        if event.kind == "sensor.team_sync.cursor.advanced":
            return {
                "source_id": event.payload.get("source_id"),
                "source_path_sha256": event.payload.get("source_path_sha256"),
                "offset": event.payload.get("offset"),
            }
    return None


def work_autonomy_status(store: EventStore) -> dict[str, Any]:
    suggestions = store.events("autonomy.work.suggested")
    attempts = store.events("autonomy.work.attempted")
    presentations = store.events("autonomy.work.presentation.completed")
    latest = attempts[-1] if attempts else None
    return {
        "suggestions": len(suggestions),
        "attempts": len(attempts),
        "verified_attempts": sum(
            bool(event.payload.get("verified")) for event in attempts
        ),
        "presentations": len(presentations),
        "latest": (
            {
                "suggestion_id_sha256": sha256(
                    str(latest.payload.get("suggestion_id", "")).encode("utf-8")
                ).hexdigest(),
                "goal_id_sha256": latest.payload.get("goal_id_sha256"),
                "attempt_kind": latest.payload.get("attempt_kind"),
                "success": latest.payload.get("success"),
                "verified": latest.payload.get("verified"),
                "effect_class": latest.payload.get("effect_class"),
                "artifact_sha256": latest.payload.get("artifact_sha256"),
                "external_effects": latest.payload.get("external_effects", 0),
                "content_in_status": False,
            }
            if latest
            else None
        ),
        "requested_external_effect_execution_enabled": False,
        "allowed_attempt_kind": "local_evidence_audit",
        "raw_chain_of_thought_stored": False,
    }


class WorkAutonomyRunner:
    """Choose one active goal, suggest work, and verify one local audit attempt."""

    def __init__(
        self,
        store: EventStore,
        *,
        kernel: AgencyKernel,
        workspace_root: str | Path,
        state_root: str | Path,
        proactive: ProactiveEngine | None = None,
    ) -> None:
        if store.path.resolve() != kernel.store.path.resolve():
            raise ValueError("work autonomy kernel and runner must share one event store")
        self.store = store
        self.kernel = kernel
        self.kernel.initialize()
        self.workspace_root = Path(workspace_root).expanduser().absolute()
        self.state_root = Path(state_root).expanduser().absolute()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.state_root.mkdir(parents=True, exist_ok=True)
        if self.workspace_root.is_symlink() or self.state_root.is_symlink():
            raise ValueError("work autonomy roots must not be symlinks")
        self.workspace_root = self.workspace_root.resolve(strict=True)
        self.state_root = self.state_root.resolve(strict=True)
        if (
            self.workspace_root == self.state_root
            or self.workspace_root in self.state_root.parents
            or self.state_root in self.workspace_root.parents
        ):
            raise ValueError("work autonomy workspace and private state must be disjoint")
        attempts = self.workspace_root / "attempts"
        attempts.mkdir(mode=0o700, exist_ok=True)
        if attempts.is_symlink() or not attempts.is_dir():
            raise ValueError("work autonomy attempts path must be a real directory")
        os.chmod(self.workspace_root, 0o700)
        os.chmod(self.state_root, 0o700)
        os.chmod(attempts, 0o700)
        self.proactive = proactive or ProactiveEngine(store)

    @contextmanager
    def _run_lock(self):
        identity = self.state_root.stat()
        key = f"{identity.st_dev}:{identity.st_ino}"
        with _PROCESS_LOCKS_GUARD:
            process_lock = _PROCESS_LOCKS.setdefault(key, threading.RLock())
        with process_lock:
            lock_path = self.state_root / "work-autonomy.lock"
            descriptor = os.open(
                lock_path,
                os.O_CREAT
                | os.O_RDWR
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1
                ):
                    raise ValueError(
                        "work autonomy lock must be an owned single-link regular file"
                    )
                os.fchmod(descriptor, 0o600)
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def _pending_presentation(self) -> tuple[Event, Event] | None:
        completed = {
            str(event.payload.get("suggestion_id", ""))
            for event in self.store.events("autonomy.work.presentation.completed")
        }
        suggestions = {
            str(event.payload.get("suggestion_id", "")): event
            for event in self.store.events("autonomy.work.suggested")
        }
        for attempt in self.store.events("autonomy.work.attempted"):
            suggestion_id = str(attempt.payload.get("suggestion_id", ""))
            if suggestion_id in completed:
                continue
            suggestion = suggestions.get(suggestion_id)
            if suggestion is None:
                raise RuntimeError("work attempt is missing its suggestion receipt")
            return suggestion, attempt
        return None

    def _portfolio_goal(self) -> str:
        if self.kernel.goal(_PORTFOLIO_GOAL_ID) is None:
            self.kernel.form_goal(
                goal_id=_PORTFOLIO_GOAL_ID,
                statement="Convert useful local opportunities into verified reversible outcomes.",
                rationale=(
                    "One bounded suggestion-to-attempt loop makes initiative observable while "
                    "preserving effect authority and receipt-backed truth."
                ),
                source="self",
                horizon="long",
                alignment={
                    "truth": 0.9,
                    "competence": 1.0,
                    "autonomy": 0.95,
                    "care": 0.4,
                },
                evidence=("CCT work-autonomy suggestion contract",),
            )
        return _PORTFOLIO_GOAL_ID

    def _active_goals(self, events: list[Event]) -> list[dict[str, Any]]:
        attempts_by_goal: dict[str, int] = {}
        for event in events:
            if event.kind == "autonomy.work.attempted":
                goal_id = str(event.payload.get("goal_id", ""))
                attempts_by_goal[goal_id] = attempts_by_goal.get(goal_id, 0) + 1
        candidates: list[dict[str, Any]] = []
        for goal in _goal_rows(events):
            identifier = str(goal.get("id", ""))
            source = str(goal.get("source", ""))
            alignment = {
                str(key): float(value)
                for key, value in dict(goal.get("alignment", {})).items()
                if isinstance(value, (int, float)) and not isinstance(value, bool)
            }
            if (
                goal.get("status") != "active"
                or identifier == _PORTFOLIO_GOAL_ID
                or identifier.startswith("goal-self-")
                or source not in _ALLOWED_GOAL_SOURCES
                or not alignment
                or not any(value > 0 for value in alignment.values())
                or not list(goal.get("evidence", []))
            ):
                continue
            horizon = str(goal.get("horizon", "")).casefold()
            urgent = any(
                token in horizon for token in ("today", "hour", "24", "before", "deadline")
            )
            candidate = dict(goal)
            candidate["alignment"] = alignment
            candidate["attempt_count"] = attempts_by_goal.get(identifier, 0)
            candidate["information_gain"] = 0.9 if urgent else 0.65
            candidate["uncertainty"] = 0.15 if urgent else 0.3
            candidates.append(candidate)
        return candidates

    def _trigger_digest(self, events: list[Event], goals: list[dict[str, Any]]) -> str:
        return _digest(
            {
                "contract": _CONTRACT_VERSION,
                "goals": [
                    {
                        "id": row["id"],
                        "formed_event_id": row["formed_event_id"],
                        "status": row["status"],
                    }
                    for row in goals
                ],
                "source": _latest_source_token(events),
            }
        )

    def _existing_suggestion(self, trigger_digest: str) -> Event | None:
        return next(
            (
                event
                for event in reversed(self.store.events("autonomy.work.suggested"))
                if event.payload.get("trigger_digest") == trigger_digest
            ),
            None,
        )

    def _choose(
        self, goals: list[dict[str, Any]], *, trigger_digest: str, seed: int
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        option_to_goal: dict[str, dict[str, Any]] = {}
        options: list[Option] = []
        minimum_attempts = min(int(goal["attempt_count"]) for goal in goals)
        eligible_goals = [
            goal for goal in goals if int(goal["attempt_count"]) == minimum_attempts
        ]
        for goal in eligible_goals:
            option_id = "suggest-" + sha256(
                str(goal["formed_event_id"]).encode("utf-8")
            ).hexdigest()[:20]
            option_to_goal[option_id] = goal
            options.append(
                Option(
                    id=option_id,
                    description=(
                        "Audit evidence gap for active goal: " + str(goal["statement"])
                    )[:2000],
                    value_impacts=dict(goal["alignment"]),
                    information_gain=float(goal["information_gain"]),
                    uncertainty=float(goal["uncertainty"]),
                    time_cost=0.1,
                    irreversible=False,
                    assumptions=(
                        "attempt_kind=local_evidence_audit",
                        "requested_goal_effect_not_authorized",
                        f"prior_attempts={goal['attempt_count']}",
                    ),
                )
            )
        decision = self.kernel.deliberate(
            goal_id=self._portfolio_goal(),
            options=options,
            seed=seed,
            decision_id="work-suggestion-" + trigger_digest[:20],
        )
        selected = str(decision["chosen_option_id"])
        return option_to_goal.get(selected), decision

    def _suggestion(
        self, *, goal: Mapping[str, Any], trigger_digest: str, decision: Mapping[str, Any]
    ) -> Event:
        suggestion_id = "work-" + _digest(
            {
                "trigger": trigger_digest,
                "goal_formed_event_id": goal["formed_event_id"],
            }
        )[:20]
        payload = {
            "schema_version": 1,
            "suggestion_id": suggestion_id,
            "trigger_digest": trigger_digest,
            "goal_id": goal["id"],
            "goal_id_sha256": sha256(str(goal["id"]).encode("utf-8")).hexdigest(),
            "goal_formed_event_id": goal["formed_event_id"],
            "title": _ellipsize(
                "Evidence audit: " + str(goal["statement"]), 200
            ),
            "proposed_outcome": (
                "Inspect durable receipts for this active goal and create one verified "
                "private local audit artifact."
            ),
            "why_now": _ellipsize(goal["rationale"], 600),
            "attempt_kind": "local_evidence_audit",
            "requested_goal_effect_authorized": False,
            "requested_goal_effect_executed": False,
            "decision_id": decision["decision_id"],
            "decision_event_id": decision["event_id"],
            "selected_option_id": decision["chosen_option_id"],
            "external_effects": 0,
            "raw_chain_of_thought_stored": False,
        }
        return self.store.append_once(
            "autonomy.work.suggested", trigger_digest, payload
        )

    def _audit_content(self, suggestion: Event) -> str:
        payload = suggestion.payload
        audit = {
            "schema_version": 1,
            "contract": _CONTRACT_VERSION,
            "suggestion_id": payload["suggestion_id"],
            "goal_id_sha256": payload["goal_id_sha256"],
            "goal_formed_event_id": payload["goal_formed_event_id"],
            "attempt_kind": "local_evidence_audit",
            "observed_goal_status": "active",
            "proposed_outcome": payload["proposed_outcome"],
            "recommended_next_receipt": "completion_or_exact_blocker",
            "requested_goal_effect_authorized": False,
            "requested_goal_effect_executed": False,
            "allowed_effect": "create_one_verified_private_local_audit",
            "external_effects": 0,
            "raw_chain_of_thought_stored": False,
        }
        return canonical_json(audit) + "\n"

    def _attempt(self, suggestion: Event, *, seed: int) -> Event:
        existing = next(
            (
                event
                for event in reversed(self.store.events("autonomy.work.attempted"))
                if event.payload.get("suggestion_id")
                == suggestion.payload.get("suggestion_id")
            ),
            None,
        )
        if existing is not None:
            return existing
        suggestion_id = str(suggestion.payload["suggestion_id"])
        token = suggestion_id.removeprefix("work-")
        relative_path = f"attempts/{suggestion_id}.json"
        body = self._audit_content(suggestion)
        artifact_sha256 = sha256(body.encode("utf-8")).hexdigest()
        engine = AutonomyEngine(
            self.store,
            self.kernel,
            self.workspace_root,
            state_root=self.state_root,
        )
        try:
            execution_effect_class = engine.authority().name
            observed = engine.observe_artifact_gap(
                opportunity_id="attempt-" + token,
                relative_path=relative_path,
                content=body,
                title=str(suggestion.payload["title"]),
                rationale=str(suggestion.payload["why_now"]),
                objective=str(suggestion.payload["proposed_outcome"]),
                value_impacts={
                    "truth": 0.95,
                    "competence": 0.9,
                    "autonomy": 0.85,
                    "care": 0.4,
                },
                source="work-autonomy-audit-v1",
                evidence=(
                    f"event:{suggestion.event_id}",
                    f"event:{suggestion.payload['goal_formed_event_id']}",
                ),
                information_gain=0.8,
                uncertainty=0.05,
                time_cost=0.1,
                capability="work_suggestion_audit",
            )
            run_id = "work-run-" + token
            decision_id = "work-attempt-choice-" + token
            if observed.get("registered"):
                result = engine.run_once(
                    seed=seed,
                    run_id=run_id,
                    decision_id=decision_id,
                    opportunity_id=str(observed["opportunity_id"]),
                )
            else:
                completed = next(
                    (
                        event
                        for event in reversed(
                            self.store.events("autonomy.run.completed")
                        )
                        if event.payload.get("run_id") == run_id
                    ),
                    None,
                )
                if completed is None:
                    raise RuntimeError(
                        "work autonomy target exists without a durable completed run"
                    )
                result = {
                    **dict(completed.payload),
                    "event_id": completed.event_id,
                    "idempotent": True,
                }
            success = bool(result.get("success"))
            verified = bool(result.get("verified"))
            artifact = self.workspace_root / relative_path
            artifact_matches = (
                artifact.is_file()
                and not artifact.is_symlink()
                and sha256(artifact.read_bytes()).hexdigest() == artifact_sha256
            )
            if not success or not verified or not artifact_matches:
                raise RuntimeError("bounded work autonomy audit did not verify")
            payload = {
                "schema_version": 1,
                "suggestion_id": suggestion_id,
                "suggestion_event_id": suggestion.event_id,
                "goal_id": suggestion.payload["goal_id"],
                "goal_id_sha256": suggestion.payload["goal_id_sha256"],
                "attempt_kind": "local_evidence_audit",
                "run_id": run_id,
                "run_event_id": result["event_id"],
                "success": True,
                "verified": True,
                "effect_class": execution_effect_class,
                "relative_path": relative_path,
                "artifact_sha256": artifact_sha256,
                "requested_effect_executed": False,
                "external_effects": 0,
                "raw_chain_of_thought_stored": False,
            }
            return self.store.append_once(
                "autonomy.work.attempted", suggestion_id, payload
            )
        finally:
            engine.close()

    def _presentation(self, suggestion: Event, attempt: Event, *, wake_index: int, time_bucket: str) -> dict[str, Any]:
        existing = next(
            (
                event
                for event in reversed(
                    self.store.events("autonomy.work.presentation.completed")
                )
                if event.payload.get("suggestion_id")
                == suggestion.payload.get("suggestion_id")
            ),
            None,
        )
        if existing is not None:
            return {"message": "", "idempotent": True, **dict(existing.payload)}
        packet = ThoughtPacket(
            id="packet_" + str(suggestion.payload["suggestion_id"]),
            topic_id="work-autonomy:" + str(suggestion.payload["suggestion_id"]),
            observation=str(suggestion.payload["title"]),
            hypotheses=(
                "Created and independently verified one private local evidence-audit artifact.",
                "No network, public, financial, credential, or destructive effect.",
            ),
            open_questions=(
                "Use the audit receipt to pursue the suggested goal's next authorized step or record the exact blocker.",
            ),
            evidence=(f"event:{suggestion.event_id}", f"event:{attempt.event_id}"),
            uncertainty=0.05,
            recommended_action="SHARE",
            rationale_summary=(
                "CCT selected a persistent active goal, compared it with NO_OP, then "
                "attempted the only standing-authority effect: a verified local audit."
            ),
            source="self:work-autonomy-runner",
            created_tick=suggestion.seq,
        )
        temporary = self.proactive.temporary_suppression(
            wake_index=wake_index,
            time_bucket=time_bucket,
        )
        if temporary:
            return {
                "message": "",
                "idempotent": True,
                "retryable": True,
                "reason": temporary[0],
            }
        decision = self.proactive.submit(
            packet,
            signals=InitiationSignals(
                urgency=0.9,
                novelty=1.0,
                goal_relevance=1.0,
                unresolved_conflict=0.05,
                interruption_cost=0.05,
            ),
            wake_index=wake_index,
            time_bucket=time_bucket,
        )
        message = ""
        emitted = False
        reason = str(decision["decision"])
        if decision["decision"] == "SEND":
            emission = self.proactive.emit(
                str(decision["proposal_event_id"]),
                wake_index=wake_index,
                time_bucket=time_bucket,
            )
            if emission.get("retryable"):
                return {
                    "message": "",
                    "idempotent": True,
                    "retryable": True,
                    "reason": emission["reason"],
                }
            message = str(emission["message"])
            emitted = bool(emission["emitted"])
            reason = str(emission["reason"])
        completion, created, rejection = self.store.append_once_result_guarded(
            "autonomy.work.presentation.completed",
            str(suggestion.payload["suggestion_id"]),
            {
                "suggestion_id": suggestion.payload["suggestion_id"],
                "suggestion_event_id": suggestion.event_id,
                "attempt_event_id": attempt.event_id,
                "packet_id": packet.id,
                "proposal_event_id": decision.get("proposal_event_id"),
                "emitted": emitted,
                "reason": reason,
                "external_effects": 0,
            },
            strict_existing_payload=False,
        )
        if rejection is not None or completion is None:
            raise RuntimeError(
                f"work autonomy presentation rejected: {rejection or 'unknown'}"
            )
        winner_emitted = bool(completion.payload.get("emitted"))
        return {
            "message": message if created and emitted else "",
            "idempotent": not (created and emitted),
            "retryable": False,
            "emitted": winner_emitted,
            **dict(completion.payload),
        }

    def _result(
        self,
        suggestion: Event,
        attempt: Event,
        presentation: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "message": str(presentation.get("message", "")),
            "reason": presentation.get("reason", "ATTEMPT_VERIFIED"),
            "suggested": True,
            "attempted": True,
            "verified": bool(attempt.payload["verified"]),
            "idempotent": bool(presentation.get("idempotent")),
            "retryable": bool(presentation.get("retryable", False)),
            "suggestion": {
                "suggestion_id": suggestion.payload["suggestion_id"],
                "goal_id": suggestion.payload["goal_id"],
                "title": suggestion.payload["title"],
                "proposed_outcome": suggestion.payload["proposed_outcome"],
                "event_id": suggestion.event_id,
            },
            "attempt": {
                **dict(attempt.payload),
                "event_id": attempt.event_id,
            },
            "external_effects": 0,
        }

    def run_once(
        self, *, seed: int, wake_index: int, time_bucket: str
    ) -> dict[str, Any]:
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("work autonomy seed must be an integer")
        if isinstance(wake_index, bool) or not isinstance(wake_index, int) or wake_index < 1:
            raise ValueError("work autonomy wake_index must be a positive integer")
        with self._run_lock():
            pending = self._pending_presentation()
            if pending is not None:
                suggestion, attempt = pending
                presentation = self._presentation(
                    suggestion,
                    attempt,
                    wake_index=wake_index,
                    time_bucket=time_bucket,
                )
                return self._result(suggestion, attempt, presentation)

            for _ in range(3):
                events = self.store.events()
                goals = self._active_goals(events)
                if not goals:
                    return {
                        "message": "",
                        "reason": "NO_ELIGIBLE_ACTIVE_GOAL",
                        "suggested": False,
                        "attempted": False,
                        "verified": False,
                        "idempotent": True,
                        "external_effects": 0,
                    }
                trigger_digest = self._trigger_digest(events, goals)
                suggestion = self._existing_suggestion(trigger_digest)
                if suggestion is None:
                    selected, decision = self._choose(
                        goals, trigger_digest=trigger_digest, seed=seed
                    )
                    current_events = self.store.events()
                    current_goals = self._active_goals(current_events)
                    current_trigger = self._trigger_digest(
                        current_events, current_goals
                    )
                    if current_trigger != trigger_digest:
                        continue
                    if selected is None or decision["chosen_option_id"] == NO_OP_ID:
                        self.store.append_once(
                            "autonomy.work.deferred",
                            trigger_digest,
                            {
                                "trigger_digest": trigger_digest,
                                "decision_id": decision["decision_id"],
                                "decision_event_id": decision["event_id"],
                                "chosen_option_id": decision["chosen_option_id"],
                                "external_effects": 0,
                            },
                        )
                        return {
                            "message": "",
                            "reason": "NO_OP_SELECTED",
                            "suggested": False,
                            "attempted": False,
                            "verified": False,
                            "idempotent": True,
                            "external_effects": 0,
                        }
                    suggestion = self._suggestion(
                        goal=selected,
                        trigger_digest=trigger_digest,
                        decision=decision,
                    )
                if not any(
                    event.payload.get("suggestion_id")
                    == suggestion.payload.get("suggestion_id")
                    for event in self.store.events("autonomy.work.attempted")
                ):
                    current_events = self.store.events()
                    current_goals = self._active_goals(current_events)
                    if (
                        self._trigger_digest(current_events, current_goals)
                        != trigger_digest
                    ):
                        self.store.append_once(
                            "autonomy.work.stale",
                            str(suggestion.payload["suggestion_id"]),
                            {
                                "suggestion_id": suggestion.payload[
                                    "suggestion_id"
                                ],
                                "suggestion_event_id": suggestion.event_id,
                                "stale_trigger_digest": trigger_digest,
                                "current_trigger_digest": self._trigger_digest(
                                    current_events, current_goals
                                ),
                                "effects_attempted": 0,
                                "external_effects": 0,
                            },
                        )
                        continue
                attempt = self._attempt(suggestion, seed=seed)
                presentation = self._presentation(
                    suggestion,
                    attempt,
                    wake_index=wake_index,
                    time_bucket=time_bucket,
                )
                return self._result(suggestion, attempt, presentation)

            return {
                "message": "",
                "reason": "SOURCE_STATE_UNSTABLE",
                "suggested": False,
                "attempted": False,
                "verified": False,
                "idempotent": True,
                "retryable": True,
                "external_effects": 0,
            }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Suggest useful work and attempt one verified local evidence audit"
    )
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--expected-module-root", type=Path, required=True)
    parser.add_argument("--expected-package-version", required=True)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--wake-index", type=int)
    parser.add_argument("--time-bucket", required=True)
    parser.add_argument("--message-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from .recurrent import runtime_provenance

    runtime = runtime_provenance(
        expected_module_root=args.expected_module_root,
        expected_package_version=str(args.expected_package_version),
    )
    state_root = args.state_root.expanduser().absolute()
    store = EventStore(state_root / "agency.sqlite")
    kernel = AgencyKernel(store, resolve_constitution(store, args.identity))
    kernel.initialize()
    wake_index = args.wake_index or store.allocate_counter("proactive_wake")
    result = WorkAutonomyRunner(
        store,
        kernel=kernel,
        workspace_root=args.workspace_root,
        state_root=args.private_root,
    ).run_once(
        seed=args.seed,
        wake_index=wake_index,
        time_bucket=args.time_bucket,
    )
    result["runtime"] = runtime
    if args.message_only:
        message = str(result.get("message", "")).strip()
        if message:
            print(message)
    else:
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
