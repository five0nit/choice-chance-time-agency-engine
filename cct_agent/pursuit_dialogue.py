"""Proposal-bound priority negotiation for bounded CCT pursuits.

Host-registered structured pursuits become one ranked operator question when priority is
ambiguous, close, consequential, or lacks authority. Operator replies are HMAC-bound to
one exact proposal revision and can change only CCT goal focus; they never grant tool or
effect authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import hmac
from math import isfinite
import re
from typing import Any, Callable, Literal, Mapping, Sequence

from .kernel import NO_OP_ID, canonical_no_op
from .principal import PrincipalModel
from .proactive import InitiationPolicy, InitiationSignals, ProactiveEngine, ThoughtPacket
from .store import Event, EventStore, canonical_json


Authority = Literal["operator", "host_adapter"]
ReplyDecision = Literal["ACTIVATE", "REDIRECT", "REJECT", "CLOSE"]
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]{1,400}$")
_REPLY_DECISIONS = {"ACTIVATE", "REDIRECT", "REJECT", "CLOSE"}


class PursuitDialogueDenied(RuntimeError):
    """Fail-closed proposal, presentation, or reply decision."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _text(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum or any(ord(char) < 32 for char in cleaned):
        raise ValueError(f"{name} must contain 1-{maximum} printable characters")
    return cleaned


def _unit(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    number = float(value)
    if not isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(f"{name} must be finite between 0 and 1")
    return number


def _evidence(values: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise ValueError("evidence must be an array")
    rows = tuple(str(value).strip() for value in values)
    if (
        not rows
        or len(rows) > 8
        or len(rows) != len(set(rows))
        or any(not _EVIDENCE.fullmatch(row) for row in rows)
    ):
        raise ValueError("evidence must contain 1-8 unique opaque URI-style references")
    return rows


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _aware_time(name: str, value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as error:
        raise ValueError(f"{name} must be ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include timezone information")
    return parsed.astimezone(timezone.utc)


def _goal_states(events: Sequence[Event]) -> dict[str, str]:
    states: dict[str, str] = {}
    for event in events:
        if event.kind == "goal.formed":
            row = event.payload.get("goal")
            if isinstance(row, Mapping) and row.get("id"):
                states[str(row["id"])] = str(row.get("status", "active"))
        elif event.kind == "goal.status_changed":
            identifier = str(event.payload.get("goal_id", ""))
            if identifier in states:
                states[identifier] = str(event.payload.get("to", ""))
    return states


@dataclass(frozen=True, slots=True)
class Pursuit:
    """One host-registered, bounded priority candidate."""

    id: str
    goal_id: str
    summary: str
    payoff: float
    cost: float
    uncertainty: float
    required_authority: Authority
    evidence: tuple[str, ...]
    consequential: bool = False
    semantic_taint: bool = False
    producer_text_used: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("pursuit id", self.id))
        object.__setattr__(self, "goal_id", _identifier("pursuit goal id", self.goal_id))
        object.__setattr__(self, "summary", _text("pursuit summary", self.summary, 120))
        object.__setattr__(self, "payoff", _unit("pursuit payoff", self.payoff))
        object.__setattr__(self, "cost", _unit("pursuit cost", self.cost))
        object.__setattr__(
            self, "uncertainty", _unit("pursuit uncertainty", self.uncertainty)
        )
        if self.required_authority not in {"operator", "host_adapter"}:
            raise ValueError("pursuit required_authority must be operator or host_adapter")
        object.__setattr__(self, "evidence", _evidence(self.evidence))
        for name in ("consequential", "semantic_taint", "producer_text_used"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"pursuit {name} must be boolean")

    @property
    def score(self) -> float:
        return round(self.payoff - 0.5 * self.cost - 0.5 * self.uncertainty, 12)

    def as_ranked_payload(self, rank: int) -> dict[str, Any]:
        return {
            "rank": rank,
            "id": self.id,
            "goal_id": self.goal_id,
            "summary": self.summary,
            "payoff": self.payoff,
            "cost": self.cost,
            "uncertainty": self.uncertainty,
            "score": self.score,
            "required_authority": self.required_authority,
            "evidence": list(self.evidence),
            "consequential": self.consequential,
            "semantic_taint": self.semantic_taint,
            "producer_text_used": self.producer_text_used,
            "canonical": False,
        }


@dataclass(frozen=True, slots=True)
class PursuitPortfolio:
    """One exact revision of a priority-negotiation question."""

    id: str
    revision: int
    question: str
    pursuits: tuple[Pursuit, ...]
    expires_at: str
    ambiguous: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("proposal id", self.id))
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or self.revision < 1:
            raise ValueError("proposal revision must be a positive integer")
        object.__setattr__(self, "question", _text("proposal question", self.question, 240))
        rows = tuple(self.pursuits)
        if not 2 <= len(rows) <= 5:
            raise ValueError("priority proposal requires 2-5 pursuits")
        if any(not isinstance(row, Pursuit) for row in rows):
            raise ValueError("priority proposal pursuits must be Pursuit values")
        identifiers = [row.id for row in rows]
        goals = [row.goal_id for row in rows]
        if NO_OP_ID in identifiers or len(identifiers) != len(set(identifiers)):
            raise ValueError("pursuit ids must be unique and cannot redefine canonical NO_OP")
        if len(goals) != len(set(goals)):
            raise ValueError("each pursuit must bind a distinct goal")
        object.__setattr__(self, "pursuits", rows)
        _aware_time("proposal expiry", self.expires_at)
        if not isinstance(self.ambiguous, bool):
            raise ValueError("proposal ambiguous must be boolean")


@dataclass(frozen=True, slots=True)
class PursuitReply:
    """Authenticated metadata-only operator reply; raw reply text is never accepted."""

    id: str
    proposal_id: str
    proposal_revision: int
    portfolio_sha256: str
    principal_id: str
    principal_profile_digest: str
    decision: ReplyDecision
    selected_pursuit_id: str
    evidence: tuple[str, ...]
    source_authority: Authority
    semantic_taint: bool
    signature: str
    raw_reply_text_persisted: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("reply id", self.id))
        object.__setattr__(
            self, "proposal_id", _identifier("reply proposal id", self.proposal_id)
        )
        if (
            isinstance(self.proposal_revision, bool)
            or not isinstance(self.proposal_revision, int)
            or self.proposal_revision < 1
        ):
            raise ValueError("reply proposal_revision must be a positive integer")
        for name in ("portfolio_sha256", "principal_profile_digest", "signature"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ValueError(f"reply {name} must be a lowercase SHA-256")
        object.__setattr__(self, "principal_id", _identifier("reply principal id", self.principal_id))
        if self.decision not in _REPLY_DECISIONS:
            raise ValueError("reply decision must be ACTIVATE, REDIRECT, REJECT, or CLOSE")
        object.__setattr__(
            self,
            "selected_pursuit_id",
            _identifier("selected pursuit id", self.selected_pursuit_id),
        )
        object.__setattr__(self, "evidence", _evidence(self.evidence))
        if self.source_authority not in {"operator", "host_adapter"}:
            raise ValueError("reply source_authority must be operator or host_adapter")
        if not isinstance(self.semantic_taint, bool):
            raise ValueError("reply semantic_taint must be boolean")
        if self.raw_reply_text_persisted is not False:
            raise ValueError("raw reply text must not be persisted")

    def signed_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "reply_id": self.id,
            "proposal_id": self.proposal_id,
            "proposal_revision": self.proposal_revision,
            "portfolio_sha256": self.portfolio_sha256,
            "principal_id": self.principal_id,
            "principal_profile_digest": self.principal_profile_digest,
            "decision": self.decision,
            "selected_pursuit_id": self.selected_pursuit_id,
            "evidence": list(self.evidence),
            "source_authority": self.source_authority,
            "semantic_taint": self.semantic_taint,
            "raw_reply_text_persisted": False,
        }

    @classmethod
    def sign(
        cls,
        *,
        reply_id: str,
        proposal_id: str,
        proposal_revision: int,
        portfolio_sha256: str,
        principal_id: str,
        principal_profile_digest: str,
        decision: str,
        selected_pursuit_id: str,
        evidence: Sequence[str],
        source_authority: Authority,
        semantic_taint: bool,
        secret: bytes,
    ) -> PursuitReply:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("reply authentication secret must contain at least 32 bytes")
        unsigned = {
            "schema_version": 1,
            "reply_id": reply_id,
            "proposal_id": proposal_id,
            "proposal_revision": proposal_revision,
            "portfolio_sha256": portfolio_sha256,
            "principal_id": principal_id,
            "principal_profile_digest": principal_profile_digest,
            "decision": decision,
            "selected_pursuit_id": selected_pursuit_id,
            "evidence": list(evidence),
            "source_authority": source_authority,
            "semantic_taint": semantic_taint,
            "raw_reply_text_persisted": False,
        }
        signature = hmac.new(
            secret, canonical_json(unsigned).encode("utf-8"), "sha256"
        ).hexdigest()
        return cls(
            id=reply_id,
            proposal_id=proposal_id,
            proposal_revision=proposal_revision,
            portfolio_sha256=portfolio_sha256,
            principal_id=principal_id,
            principal_profile_digest=principal_profile_digest,
            decision=decision,  # type: ignore[arg-type]
            selected_pursuit_id=selected_pursuit_id,
            evidence=tuple(evidence),
            source_authority=source_authority,
            semantic_taint=semantic_taint,
            signature=signature,
        )

    def verify(self, secret: bytes) -> bool:
        if not isinstance(secret, bytes) or len(secret) < 32:
            return False
        expected = hmac.new(
            secret, canonical_json(self.signed_payload()).encode("utf-8"), "sha256"
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)


class PursuitDialogue:
    """Persist, present, authenticate, and apply exact priority decisions."""

    def __init__(self, store: EventStore) -> None:
        self.store = store
        self.proactive = ProactiveEngine(
            store,
            policy=InitiationPolicy(max_message_chars=1800),
        )

    @staticmethod
    def _ranked(portfolio: PursuitPortfolio) -> list[Pursuit]:
        return sorted(portfolio.pursuits, key=lambda row: (-row.score, row.id))

    @staticmethod
    def _latest_proposals(events: Sequence[Event]) -> dict[str, Event]:
        rows: dict[str, Event] = {}
        for event in events:
            if event.kind != "pursuit.dialogue.proposed":
                continue
            identifier = str(event.payload["proposal_id"])
            previous = rows.get(identifier)
            if previous is None or int(event.payload["revision"]) > int(
                previous.payload["revision"]
            ):
                rows[identifier] = event
        return rows

    @staticmethod
    def _presented(events: Sequence[Event], proposal_event_id: str) -> bool:
        return any(
            event.kind == "pursuit.dialogue.presentation.completed"
            and event.payload.get("proposal_event_id") == proposal_event_id
            and event.payload.get("emitted") is True
            for event in events
        )

    @staticmethod
    def _applied(events: Sequence[Event], proposal_event_id: str) -> Event | None:
        return next(
            (
                event
                for event in reversed(events)
                if event.kind == "pursuit.dialogue.reply.applied"
                and event.payload.get("proposal_event_id") == proposal_event_id
            ),
            None,
        )

    @staticmethod
    def _expired(events: Sequence[Event], proposal_event_id: str) -> Event | None:
        return next(
            (
                event
                for event in reversed(events)
                if event.kind == "pursuit.dialogue.expired"
                and event.payload.get("proposal_event_id") == proposal_event_id
            ),
            None,
        )

    @staticmethod
    def _authenticated(events: Sequence[Event], proposal_event_id: str) -> Event | None:
        return next(
            (
                event
                for event in reversed(events)
                if event.kind == "pursuit.dialogue.reply.authenticated"
                and event.payload.get("proposal_event_id") == proposal_event_id
            ),
            None,
        )

    def register(self, portfolio: PursuitPortfolio) -> dict[str, Any]:
        if not isinstance(portfolio, PursuitPortfolio):
            raise ValueError("portfolio must be PursuitPortfolio")
        if any(row.semantic_taint or row.producer_text_used for row in portfolio.pursuits):
            raise PursuitDialogueDenied("SEMANTIC_TAINT_REJECTED")
        profile = PrincipalModel(self.store).status()
        if not profile["profile_installed"]:
            raise PursuitDialogueDenied("PRINCIPAL_PROFILE_NOT_INSTALLED")
        events = self.store.events()
        states = _goal_states(events)
        if any(states.get(row.goal_id) not in {"active", "paused"} for row in portfolio.pursuits):
            raise PursuitDialogueDenied("PURSUIT_GOAL_NOT_ACTIONABLE")
        ranked = self._ranked(portfolio)
        triggers: list[str] = []
        if portfolio.ambiguous:
            triggers.append("AMBIGUOUS_PRIORITY")
        if ranked[0].score - ranked[1].score <= 0.10:
            triggers.append("CLOSE_RANKED")
        if any(row.consequential for row in ranked):
            triggers.append("CONSEQUENTIAL")
        if any(row.required_authority == "operator" for row in ranked):
            triggers.append("MISSING_AUTHORITY")
        if not triggers:
            raise PursuitDialogueDenied("NEGOTIATION_NOT_REQUIRED")
        ranked_payload = [
            row.as_ranked_payload(rank) for rank, row in enumerate(ranked, start=1)
        ]
        no_op = canonical_no_op()
        ranked_payload.append(
            {
                "rank": len(ranked_payload) + 1,
                "id": NO_OP_ID,
                "goal_id": None,
                "summary": no_op.description,
                "payoff": 0.0,
                "cost": 0.0,
                "uncertainty": 0.0,
                "score": 0.0,
                "required_authority": "operator",
                "evidence": [],
                "consequential": False,
                "semantic_taint": False,
                "producer_text_used": False,
                "canonical": True,
            }
        )
        portfolio_material = {
            "schema_version": 1,
            "proposal_id": portfolio.id,
            "revision": portfolio.revision,
            "question": portfolio.question,
            "ranked_pursuits": ranked_payload,
            "recommended_pursuit_id": ranked[0].id,
            "trigger_reasons": triggers,
            "expires_at": portfolio.expires_at,
            "principal_id": (profile["profile"] or {})["principal_id"],
            "principal_profile_digest": profile["profile_digest"],
            "principal_profile_revision": profile["revision"],
        }
        portfolio_sha256 = _digest(portfolio_material)
        payload = {
            **portfolio_material,
            "portfolio_sha256": portfolio_sha256,
            "source_authority": "host_adapter",
            "question_kind": "bounded_priority_negotiation",
            "reply_authentication_required": "HMAC-SHA256",
            "execution_authority_granted": False,
            "raw_producer_content_persisted": False,
            "raw_chain_of_thought_stored": False,
        }

        def guard(current: list[Event]) -> str | None:
            active_profile = next(
                (
                    event
                    for event in reversed(current)
                    if event.kind == "principal.profile.installed"
                ),
                None,
            )
            if active_profile is None or active_profile.payload.get(
                "profile_digest"
            ) != profile["profile_digest"]:
                return "PRINCIPAL_PROFILE_CHANGED"
            latest = self._latest_proposals(current).get(portfolio.id)
            expected = 1 if latest is None else int(latest.payload["revision"]) + 1
            if portfolio.revision != expected:
                return "PROPOSAL_REVISION_NOT_MONOTONIC"
            return None

        event, created, rejection = self.store.append_once_result_guarded(
            "pursuit.dialogue.proposed",
            f"{portfolio.id}:{portfolio.revision}",
            payload,
            guard=guard,
            strict_existing_payload=True,
        )
        if rejection is not None:
            raise PursuitDialogueDenied(rejection)
        if event is None:
            raise RuntimeError("priority proposal was not persisted")
        return {**dict(event.payload), "event_id": event.event_id, "created": created}

    def _next(self, events: Sequence[Event]) -> Event | None:
        candidates = []
        for event in self._latest_proposals(events).values():
            if (
                self._applied(events, event.event_id) is not None
                or self._expired(events, event.event_id) is not None
            ):
                continue
            if any(
                row.kind == "pursuit.dialogue.presentation.completed"
                and row.payload.get("proposal_event_id") == event.event_id
                for row in events
            ):
                continue
            candidates.append(event)
        return min(candidates, key=lambda event: event.seq) if candidates else None

    def expire_pending(self) -> dict[str, Any]:
        """Close unanswered expired proposals once without changing goals or authority."""

        created_event_ids: list[str] = []
        events = self.store.events()
        for proposal in sorted(self._latest_proposals(events).values(), key=lambda row: row.seq):
            if (
                self._applied(events, proposal.event_id) is not None
                or self._expired(events, proposal.event_id) is not None
                or self._authenticated(events, proposal.event_id) is not None
                or _aware_time("proposal expiry", self.store.clock())
                <= _aware_time("proposal expiry", proposal.payload["expires_at"])
            ):
                continue
            payload = {
                "schema_version": 1,
                "proposal_event_id": proposal.event_id,
                "proposal_id": proposal.payload["proposal_id"],
                "proposal_revision": proposal.payload["revision"],
                "portfolio_sha256": proposal.payload["portfolio_sha256"],
                "expires_at": proposal.payload["expires_at"],
                "terminal_reason": "UNANSWERED_EXPIRED",
                "goal_transition_count": 0,
                "execution_authority_granted": False,
                "external_effects": 0,
                "raw_reply_text_persisted": False,
            }

            def guard(current: list[Event], *, expected=proposal) -> str | None:
                latest = self._latest_proposals(current).get(
                    str(expected.payload["proposal_id"])
                )
                if latest is None or latest.event_id != expected.event_id:
                    return "STALE_PROPOSAL_REVISION"
                if (
                    self._applied(current, expected.event_id) is not None
                    or self._expired(current, expected.event_id) is not None
                    or self._authenticated(current, expected.event_id) is not None
                ):
                    return "PROPOSAL_ALREADY_TERMINAL"
                if _aware_time("proposal expiry", self.store.clock()) <= _aware_time(
                    "proposal expiry", expected.payload["expires_at"]
                ):
                    return "PROPOSAL_NOT_EXPIRED"
                return None

            terminal, created, rejection = self.store.append_once_result_guarded(
                "pursuit.dialogue.expired",
                proposal.event_id,
                payload,
                guard=guard,
                strict_existing_payload=True,
            )
            if rejection in {"PROPOSAL_ALREADY_TERMINAL", "STALE_PROPOSAL_REVISION"}:
                events = self.store.events()
                continue
            if rejection is not None:
                raise PursuitDialogueDenied(rejection)
            if terminal is None:
                raise RuntimeError("priority proposal expiry was not persisted")
            if created:
                created_event_ids.append(terminal.event_id)
            events = self.store.events()
        return {
            "expired_count": len(created_event_ids),
            "expiration_event_ids": created_event_ids,
            "external_effects": 0,
        }

    @staticmethod
    def _packet(proposal: Event) -> ThoughtPacket:
        payload = proposal.payload
        lines = tuple(
            (
                f"{row['rank']}. {row['id']} — {row['summary']} | "
                f"payoff={float(row['payoff']):.2f} cost={float(row['cost']):.2f} "
                f"uncertainty={float(row['uncertainty']):.2f} "
                f"authority={row['required_authority']} "
                f"evidence={row['evidence'][0] if row['evidence'] else 'canonical:none'}"
            )
            for row in payload["ranked_pursuits"]
        )
        binding = (
            f"Reply must bind {payload['proposal_id']} r{payload['revision']} "
            f"portfolio={payload['portfolio_sha256']}."
        )
        return ThoughtPacket(
            id="packet_pursuit_" + _digest({"proposal_event_id": proposal.event_id})[:20],
            topic_id=f"pursuit:{payload['proposal_id']}:{payload['revision']}",
            observation=(
                f"{payload['question']} "
                f"[{payload['proposal_id']} r{payload['revision']}]"
            ),
            hypotheses=lines,
            open_questions=(
                f"Recommendation: {payload['recommended_pursuit_id']}",
                binding,
            ),
            evidence=(f"event:{proposal.event_id}",),
            uncertainty=max(
                float(row["uncertainty"])
                for row in payload["ranked_pursuits"]
                if row["id"] != NO_OP_ID
            ),
            recommended_action="ASK",
            rationale_summary=(
                "Ranked host-registered pursuits require one exact operator-bound priority decision."
            ),
            source="self:pursuit-dialogue-runner",
            created_tick=proposal.seq,
        )

    def run_once(self, *, wake_index: int, time_bucket: str) -> dict[str, Any]:
        if isinstance(wake_index, bool) or not isinstance(wake_index, int) or wake_index < 1:
            raise ValueError("wake_index must be a positive integer")
        expiration = self.expire_pending()
        proposal = self._next(self.store.events())
        if proposal is None:
            return {
                "message": "",
                "reason": (
                    "PRIORITY_DIALOGUE_EXPIRED"
                    if expiration["expired_count"]
                    else "NO_PRIORITY_DIALOGUE"
                ),
                "candidate_found": False,
                "state_consumed": bool(expiration["expired_count"]),
                **expiration,
                "external_effects": 0,
            }
        temporary = self.proactive.temporary_suppression(
            wake_index=wake_index, time_bucket=time_bucket
        )
        if temporary:
            return {
                "message": "",
                "reason": temporary[0],
                "reason_codes": temporary,
                "proposal_id": proposal.payload["proposal_id"],
                "proposal_revision": proposal.payload["revision"],
                "candidate_found": True,
                "state_consumed": False,
                "external_effects": 0,
            }
        packet = self._packet(proposal)
        decision = self.proactive.submit(
            packet,
            signals=InitiationSignals(
                urgency=0.95,
                novelty=1.0,
                goal_relevance=1.0,
                unresolved_conflict=0.95,
                interruption_cost=0.1,
            ),
            wake_index=wake_index,
            time_bucket=time_bucket,
        )
        emitted = False
        presentation_exists = False
        message = ""
        emission_reason = ""
        if decision["decision"] == "SEND":
            emission = self.proactive.emit(
                str(decision["proposal_event_id"]),
                wake_index=wake_index,
                time_bucket=time_bucket,
            )
            if emission.get("retryable"):
                return {
                    "message": "",
                    "reason": emission["reason"],
                    "reason_codes": [emission["reason"]],
                    "proposal_id": proposal.payload["proposal_id"],
                    "proposal_revision": proposal.payload["revision"],
                    "candidate_found": True,
                    "state_consumed": False,
                    "external_effects": 0,
                }
            emitted = bool(emission["emitted"])
            message = str(emission["message"])
            emission_reason = str(emission["reason"])
            presentation_exists = emitted or any(
                event.kind == "proactive.message.emitted"
                and event.payload.get("proposal_event_id") == decision["proposal_event_id"]
                for event in self.store.events()
            )
        completion_payload = {
            "schema_version": 1,
            "proposal_event_id": proposal.event_id,
            "proposal_id": proposal.payload["proposal_id"],
            "proposal_revision": proposal.payload["revision"],
            "portfolio_sha256": proposal.payload["portfolio_sha256"],
            "packet_id": packet.id,
            "decision": decision["decision"],
            "reason_codes": [*decision["reason_codes"], *([emission_reason] if emission_reason else [])],
            "emitted": presentation_exists,
            "wake_index": wake_index,
            "time_bucket": time_bucket,
            "external_effects": 0,
            "raw_chain_of_thought_stored": False,
        }
        completion, _, rejection = self.store.append_once_result_guarded(
            "pursuit.dialogue.presentation.completed",
            proposal.event_id,
            completion_payload,
            strict_existing_payload=False,
        )
        if rejection is not None or completion is None:
            raise RuntimeError("priority presentation completion was rejected")
        return {
            "message": message,
            "reason": "EMITTED" if emitted else emission_reason or decision["decision"],
            "proposal_id": proposal.payload["proposal_id"],
            "proposal_revision": proposal.payload["revision"],
            "portfolio_sha256": proposal.payload["portfolio_sha256"],
            "candidate_found": True,
            "state_consumed": True,
            "external_effects": 0,
        }

    @staticmethod
    def _validate_reply_action(reply: PursuitReply, proposal: Event) -> None:
        options = {str(row["id"]) for row in proposal.payload["ranked_pursuits"]}
        recommended = str(proposal.payload["recommended_pursuit_id"])
        if reply.selected_pursuit_id not in options:
            raise PursuitDialogueDenied("SELECTED_PURSUIT_NOT_IN_PROPOSAL")
        if reply.decision == "ACTIVATE" and reply.selected_pursuit_id != recommended:
            raise PursuitDialogueDenied("ACTIVATE_MUST_SELECT_RECOMMENDATION")
        if reply.decision == "REDIRECT" and reply.selected_pursuit_id in {
            recommended,
            NO_OP_ID,
        }:
            raise PursuitDialogueDenied("REDIRECT_REQUIRES_ALTERNATE_PURSUIT")
        if reply.decision == "REJECT" and reply.selected_pursuit_id != NO_OP_ID:
            raise PursuitDialogueDenied("REJECT_REQUIRES_NO_OP")
        if reply.decision == "CLOSE" and reply.selected_pursuit_id == NO_OP_ID:
            raise PursuitDialogueDenied("CLOSE_REQUIRES_PURSUIT")

    @staticmethod
    def _transition_targets(
        reply: PursuitReply,
        proposal: Event,
        baseline: Mapping[str, str],
    ) -> dict[str, tuple[str, str]]:
        rows = {
            str(row["id"]): row
            for row in proposal.payload["ranked_pursuits"]
            if row["id"] != NO_OP_ID
        }
        result: dict[str, tuple[str, str]] = {}
        if reply.decision == "ACTIVATE":
            goal_id = str(rows[reply.selected_pursuit_id]["goal_id"])
            if baseline[goal_id] != "active":
                result[goal_id] = (baseline[goal_id], "active")
        elif reply.decision == "REDIRECT":
            selected_goal = str(rows[reply.selected_pursuit_id]["goal_id"])
            for row in rows.values():
                goal_id = str(row["goal_id"])
                current = baseline[goal_id]
                target = "active" if goal_id == selected_goal else "paused"
                if current != target:
                    result[goal_id] = (current, target)
        elif reply.decision == "CLOSE":
            goal_id = str(rows[reply.selected_pursuit_id]["goal_id"])
            if baseline[goal_id] != "completed":
                result[goal_id] = (baseline[goal_id], "completed")
        return result

    def record_reply(
        self,
        reply: PursuitReply,
        *,
        secret: bytes,
        fault_hook: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(reply, PursuitReply) or not reply.verify(secret):
            raise PursuitDialogueDenied("REPLY_AUTHENTICATION_FAILED")
        if reply.semantic_taint:
            raise PursuitDialogueDenied("SEMANTIC_TAINT_REJECTED")
        if reply.source_authority != "operator":
            raise PursuitDialogueDenied("OPERATOR_AUTHORITY_REQUIRED")
        events = self.store.events()
        latest = self._latest_proposals(events).get(reply.proposal_id)
        if latest is None:
            raise PursuitDialogueDenied("PROPOSAL_NOT_FOUND")
        if int(latest.payload["revision"]) != reply.proposal_revision:
            raise PursuitDialogueDenied("STALE_PROPOSAL_REVISION")
        proposal = latest
        if (
            proposal.payload["portfolio_sha256"] != reply.portfolio_sha256
            or proposal.payload["principal_profile_digest"]
            != reply.principal_profile_digest
            or proposal.payload["principal_id"] != reply.principal_id
        ):
            raise PursuitDialogueDenied("PROPOSAL_BINDING_MISMATCH")
        profile = PrincipalModel(self.store).status()
        if (
            profile["profile_digest"] != reply.principal_profile_digest
            or (profile["profile"] or {}).get("principal_id") != reply.principal_id
        ):
            raise PursuitDialogueDenied("PRINCIPAL_PROFILE_CHANGED")
        if not self._presented(events, proposal.event_id):
            raise PursuitDialogueDenied("PROPOSAL_NOT_PRESENTED")
        expired_terminal = self._expired(events, proposal.event_id)
        existing_authentication = next(
            (
                event
                for event in reversed(events)
                if event.kind == "pursuit.dialogue.reply.authenticated"
                and event.payload.get("reply_id") == reply.id
            ),
            None,
        )
        if expired_terminal is not None or (
            existing_authentication is None
            and _aware_time("proposal expiry", self.store.clock())
            > _aware_time("proposal expiry", proposal.payload["expires_at"])
        ):
            raise PursuitDialogueDenied("PROPOSAL_EXPIRED")
        self._validate_reply_action(reply, proposal)
        existing_terminal = next(
            (
                event
                for event in reversed(events)
                if event.kind == "pursuit.dialogue.reply.applied"
                and event.payload.get("reply_id") == reply.id
            ),
            None,
        )
        if existing_terminal is not None:
            return {
                **dict(existing_terminal.payload),
                "event_id": existing_terminal.event_id,
                "applied": False,
                "reason": "DUPLICATE_REPLY",
                "goal_transition_count": 0,
            }
        option_goal_ids = [
            str(row["goal_id"])
            for row in proposal.payload["ranked_pursuits"]
            if row["id"] != NO_OP_ID
        ]
        if existing_authentication is not None:
            persisted_signed = {
                key: existing_authentication.payload.get(key)
                for key in reply.signed_payload()
            }
            if (
                canonical_json(persisted_signed)
                != canonical_json(reply.signed_payload())
                or existing_authentication.payload.get("signature") != reply.signature
                or existing_authentication.payload.get("proposal_event_id")
                != proposal.event_id
            ):
                raise PursuitDialogueDenied("REPLY_ID_CONFLICT")
            raw_baseline = existing_authentication.payload.get("baseline_goal_statuses")
            if not isinstance(raw_baseline, Mapping) or set(raw_baseline) != set(
                option_goal_ids
            ):
                raise PursuitDialogueDenied("AUTHENTICATED_REPLY_MALFORMED")
            baseline = {str(key): str(value) for key, value in raw_baseline.items()}
            if any(status not in {"active", "paused"} for status in baseline.values()):
                raise PursuitDialogueDenied("AUTHENTICATED_REPLY_MALFORMED")
            authentication_payload = dict(existing_authentication.payload)
        else:
            states = _goal_states(events)
            baseline = {goal_id: states.get(goal_id, "") for goal_id in option_goal_ids}
            if any(status not in {"active", "paused"} for status in baseline.values()):
                raise PursuitDialogueDenied("PURSUIT_GOAL_STATE_INVALID")
            authentication_payload = {
                **reply.signed_payload(),
                "signature": reply.signature,
                "signature_scheme": "HMAC-SHA256",
                "reply_sha256": _digest(
                    {"signed": reply.signed_payload(), "signature": reply.signature}
                ),
                "proposal_event_id": proposal.event_id,
                "presentation_verified": True,
                "authenticated": True,
                "baseline_goal_statuses": baseline,
                "instructions_authorized": False,
            }

        def authentication_guard(current: list[Event]) -> str | None:
            active = self._latest_proposals(current).get(reply.proposal_id)
            if active is None or active.event_id != proposal.event_id:
                return "STALE_PROPOSAL_REVISION"
            active_profile = next(
                (
                    event
                    for event in reversed(current)
                    if event.kind == "principal.profile.installed"
                ),
                None,
            )
            if active_profile is None or active_profile.payload.get(
                "profile_digest"
            ) != reply.principal_profile_digest:
                return "PRINCIPAL_PROFILE_CHANGED"
            if not self._presented(current, proposal.event_id):
                return "PROPOSAL_NOT_PRESENTED"
            if self._expired(current, proposal.event_id) is not None or (
                existing_authentication is None
                and _aware_time("proposal expiry", self.store.clock())
                > _aware_time("proposal expiry", proposal.payload["expires_at"])
            ):
                return "PROPOSAL_EXPIRED"
            if self._applied(current, proposal.event_id) is not None or any(
                event.kind == "pursuit.dialogue.reply.authenticated"
                and event.payload.get("proposal_event_id") == proposal.event_id
                for event in current
            ):
                return "TERMINAL_REPLY_EXISTS"
            if _goal_states(current) != _goal_states(events):
                return "GOAL_STATE_DRIFT"
            return None

        if existing_authentication is not None:
            authenticated = existing_authentication
            created = False
        else:
            try:
                authenticated, created, rejection = self.store.append_once_result_guarded(
                    "pursuit.dialogue.reply.authenticated",
                    reply.id,
                    authentication_payload,
                    guard=authentication_guard,
                    strict_existing_payload=True,
                )
            except ValueError as error:
                raise PursuitDialogueDenied("REPLY_ID_CONFLICT") from error
            if rejection is not None:
                raise PursuitDialogueDenied(rejection)
            if authenticated is None:
                raise RuntimeError("authenticated priority reply was not persisted")
        if canonical_json(authenticated.payload) != canonical_json(authentication_payload):
            raise PursuitDialogueDenied("REPLY_ID_CONFLICT")
        if fault_hook is not None:
            fault_hook("after_reply_recorded")

        targets = self._transition_targets(reply, proposal, baseline)
        existing_transitions = {
            str(event.payload.get("goal_id")): event
            for event in self.store.events("goal.status_changed")
            if event.payload.get("pursuit_reply_id") == reply.id
        }
        current_states = _goal_states(self.store.events())
        for goal_id, original in baseline.items():
            expected = targets.get(goal_id, (original, original))[1]
            if goal_id not in existing_transitions:
                expected = original
            if current_states.get(goal_id) != expected:
                raise PursuitDialogueDenied("GOAL_STATE_DRIFT")
        transition_ids: list[str] = []
        for goal_id in sorted(targets):
            before, after = targets[goal_id]
            transition_payload = {
                "goal_id": goal_id,
                "from": before,
                "to": after,
                "reason": (
                    f"Authenticated proposal-bound {reply.decision} reply {reply.id} "
                    f"for {proposal.payload['proposal_id']} r{proposal.payload['revision']}."
                ),
                "pursuit_reply_id": reply.id,
                "proposal_event_id": proposal.event_id,
                "reply_authentication_event_id": authenticated.event_id,
            }

            def transition_guard(current: list[Event], *, expected_goal=goal_id, expected=before) -> str | None:
                auth = self.store.event(authenticated.event_id)
                if auth is None or auth.kind != "pursuit.dialogue.reply.authenticated":
                    return "AUTHENTICATED_REPLY_MISSING"
                if _goal_states(current).get(expected_goal) != expected:
                    return "GOAL_STATE_DRIFT"
                return None

            transition, _, rejection = self.store.append_once_result_guarded(
                "goal.status_changed",
                f"{reply.id}:{goal_id}",
                transition_payload,
                guard=transition_guard,
                strict_existing_payload=True,
            )
            if rejection is not None:
                raise PursuitDialogueDenied(rejection)
            if transition is None:
                raise RuntimeError("goal transition was not persisted")
            transition_ids.append(transition.event_id)
            if fault_hook is not None:
                fault_hook(f"after_goal_transition:{goal_id}")
        if fault_hook is not None:
            fault_hook("after_goal_transitions")
        terminal_payload = {
            "schema_version": 1,
            "reply_id": reply.id,
            "proposal_event_id": proposal.event_id,
            "proposal_id": reply.proposal_id,
            "proposal_revision": reply.proposal_revision,
            "portfolio_sha256": reply.portfolio_sha256,
            "reply_authentication_event_id": authenticated.event_id,
            "decision": reply.decision,
            "selected_pursuit_id": reply.selected_pursuit_id,
            "goal_transition_event_ids": transition_ids,
            "goal_transition_count": len(transition_ids),
            "execution_authority_granted": False,
            "external_effects": 0,
            "raw_reply_text_persisted": False,
        }
        expected_final = {
            goal_id: targets.get(goal_id, (status, status))[1]
            for goal_id, status in baseline.items()
        }

        def terminal_guard(current: list[Event]) -> str | None:
            current_states = _goal_states(current)
            if any(
                current_states.get(goal_id) != status
                for goal_id, status in expected_final.items()
            ):
                return "GOAL_STATE_DRIFT"
            if any(
                event.kind == "pursuit.dialogue.reply.applied"
                and event.payload.get("proposal_event_id") == proposal.event_id
                for event in current
            ):
                return "TERMINAL_REPLY_EXISTS"
            return None

        try:
            terminal, terminal_created, terminal_rejection = (
                self.store.append_once_result_guarded(
                    "pursuit.dialogue.reply.applied",
                    reply.id,
                    terminal_payload,
                    guard=terminal_guard,
                    strict_existing_payload=True,
                )
            )
        except ValueError as error:
            raise PursuitDialogueDenied("REPLY_TERMINAL_CONFLICT") from error
        if terminal_rejection is not None:
            raise PursuitDialogueDenied(terminal_rejection)
        if terminal is None:
            raise RuntimeError("priority reply terminal was not persisted")
        if canonical_json(terminal.payload) != canonical_json(terminal_payload):
            raise PursuitDialogueDenied("REPLY_TERMINAL_CONFLICT")
        return {
            **dict(terminal.payload),
            "event_id": terminal.event_id,
            "applied": terminal_created,
            "reason": "APPLIED" if terminal_created else "DUPLICATE_REPLY",
            "recovered": not created,
        }

    def status(self) -> dict[str, Any]:
        events = self.store.events()
        latest = self._latest_proposals(events)
        return {
            "proposal_count": len(
                [event for event in events if event.kind == "pursuit.dialogue.proposed"]
            ),
            "open_latest_revisions": sum(
                self._applied(events, event.event_id) is None
                and self._expired(events, event.event_id) is None
                for event in latest.values()
            ),
            "expired_proposals": len(
                [event for event in events if event.kind == "pursuit.dialogue.expired"]
            ),
            "presented": len(
                [
                    event
                    for event in events
                    if event.kind == "pursuit.dialogue.presentation.completed"
                    and event.payload.get("emitted") is True
                ]
            ),
            "authenticated_replies": len(
                [
                    event
                    for event in events
                    if event.kind == "pursuit.dialogue.reply.authenticated"
                ]
            ),
            "applied_replies": len(
                [event for event in events if event.kind == "pursuit.dialogue.reply.applied"]
            ),
            "execution_authority_granted_by_reply": False,
            "raw_reply_text_persisted": False,
        }
