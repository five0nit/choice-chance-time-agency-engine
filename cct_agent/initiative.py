"""Adaptive initiative with trusted promotion and verified feedback receipts."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import hmac
from math import isfinite
from typing import Any, Callable, Iterable, Mapping

from .store import Event, EventStore, canonical_json
from .topics import Topic, TopicStore

_ALLOWED_FEEDBACK = {
    "USEFUL": (1.0, 0.0),
    "NEUTRAL": (0.0, 0.5),
    "DISRUPTIVE": (-1.0, 1.0),
}


def _text(value: object, *, name: str, maximum: int) -> str:
    cleaned = str(value).strip()
    if not cleaned:
        raise ValueError(f"{name} must not be empty")
    if len(cleaned) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    return cleaned


def _bounded_copy(value: object, *, maximum: int) -> str:
    cleaned = str(value).strip()
    if not cleaned:
        raise ValueError("promoted text must not be empty")
    if len(cleaned) <= maximum:
        return cleaned
    return cleaned[: maximum - 1].rstrip() + "…"


def _finite(value: Any, *, name: str) -> float:
    number = float(value)
    if not isfinite(number):
        raise ValueError(f"{name} must be finite")
    return number


def _unit(value: Any, *, name: str) -> float:
    number = _finite(value, name=name)
    if not 0.0 <= number <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")
    return number


def _sha256_digest(value: object, *, name: str) -> str:
    digest = _text(value, name=name, maximum=64)
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return digest


def _unique_evidence(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        cleaned = _text(value, name="feedback evidence", maximum=500)
        if cleaned not in result:
            result.append(cleaned)
        if len(result) >= 12:
            break
    return tuple(result)


@dataclass(frozen=True, slots=True)
class PromotionPolicy:
    """Deterministic gate for trusted structured producer events."""

    allowed_kinds: tuple[str, ...] = (
        "blocker",
        "commitment",
        "decision_update",
        "goal_progress",
        "opportunity",
        "outcome",
        "risk",
        "test_result",
    )
    trusted_source_prefixes: tuple[str, ...] = (
        "system:verified:",
        "monitor:",
        "tool:pytest",
        "tool:ci",
    )
    min_attention_score: float = 0.62
    min_goal_relevance: float = 0.60
    min_change_signal: float = 0.50
    max_promotions_per_run: int = 3
    max_source_events_scan: int = 500

    def __post_init__(self) -> None:
        kinds = tuple(dict.fromkeys(str(item).strip() for item in self.allowed_kinds))
        sources = tuple(
            dict.fromkeys(str(item).strip() for item in self.trusted_source_prefixes)
        )
        if not kinds or any(not item for item in kinds):
            raise ValueError("promotion policy requires non-empty allowed kinds")
        if not sources or any(not item for item in sources):
            raise ValueError("promotion policy requires trusted source prefixes")
        object.__setattr__(self, "allowed_kinds", kinds)
        object.__setattr__(self, "trusted_source_prefixes", sources)
        _unit(self.min_attention_score, name="minimum attention score")
        _unit(self.min_goal_relevance, name="minimum goal relevance")
        _unit(self.min_change_signal, name="minimum change signal")
        if not 1 <= self.max_promotions_per_run <= 20:
            raise ValueError("max promotions per run must be between 1 and 20")
        if not 1 <= self.max_source_events_scan <= 10000:
            raise ValueError("max source event scan must be between 1 and 10000")

    def _source_allowed(self, source: str) -> bool:
        for allowed in self.trusted_source_prefixes:
            if allowed.endswith(":") and source.startswith(allowed):
                return True
            if source == allowed:
                return True
        return False

    def evaluate(self, item: Mapping[str, Any]) -> tuple[str, ...]:
        reasons: list[str] = []
        try:
            _text(item.get("id", ""), name="workspace item id", maximum=180)
            kind = _text(item.get("kind", ""), name="workspace kind", maximum=80)
            _text(item.get("summary", ""), name="workspace summary", maximum=2000)
            source = _text(item.get("source", ""), name="workspace source", maximum=200)
            _sha256_digest(
                item.get("content_digest", ""), name="workspace content digest"
            )
            authority = _text(
                item.get("initiative_authority", "untrusted"),
                name="initiative authority",
                maximum=32,
            )
        except (TypeError, ValueError):
            return ("MALFORMED_ITEM",)
        if kind not in self.allowed_kinds:
            reasons.append("KIND_NOT_ALLOWED")
        if authority != "trusted_producer" or not self._source_allowed(source):
            reasons.append("SOURCE_NOT_ALLOWED")
        try:
            attention = _finite(item.get("attention_score", 0.0), name="attention score")
            relevance = _unit(
                item.get("goal_relevance", 0.0), name="workspace goal relevance"
            )
            change_signal = max(
                _unit(item.get("urgency", 0.0), name="workspace urgency"),
                _unit(item.get("novelty", 0.0), name="workspace novelty"),
                _unit(
                    item.get("unresolved_conflict", 0.0),
                    name="workspace unresolved conflict",
                ),
            )
        except (TypeError, ValueError):
            return tuple(dict.fromkeys((*reasons, "MALFORMED_SIGNALS")))
        if attention < self.min_attention_score:
            reasons.append("LOW_ATTENTION")
        if relevance < self.min_goal_relevance:
            reasons.append("LOW_GOAL_RELEVANCE")
        if change_signal < self.min_change_signal:
            reasons.append("LOW_CHANGE_SIGNAL")
        return tuple(dict.fromkeys(reasons))

    def as_payload(self) -> dict[str, Any]:
        return {
            "allowed_kinds": list(self.allowed_kinds),
            "trusted_source_prefixes": list(self.trusted_source_prefixes),
            "initiative_authority_required": "trusted_producer",
            "min_attention_score": self.min_attention_score,
            "min_goal_relevance": self.min_goal_relevance,
            "min_change_signal": self.min_change_signal,
            "max_promotions_per_run": self.max_promotions_per_run,
            "max_source_events_scan": self.max_source_events_scan,
        }


class InitiativeBridge:
    """Promote trusted structured workspace items without reading transcripts."""

    CURSOR_KIND = "proactive.promotion.cursor.advanced"

    def __init__(
        self,
        store: EventStore,
        *,
        policy: PromotionPolicy | None = None,
    ) -> None:
        self.store = store
        self.policy = policy or PromotionPolicy()
        self.topics = TopicStore(store)

    @staticmethod
    def _topic_id(item: Mapping[str, Any]) -> str:
        stream = {
            "kind": str(item["kind"]).strip(),
            "source": str(item["source"]).strip(),
        }
        digest = sha256(canonical_json(stream).encode("utf-8")).hexdigest()[:20]
        return f"topic_auto_{digest}"

    @staticmethod
    def _stable_promotion_key(item: Mapping[str, Any]) -> str:
        identity = {
            "id": str(item.get("id", "")).strip(),
            "kind": str(item.get("kind", "")).strip(),
            "source": str(item.get("source", "")).strip(),
            "content_digest": _sha256_digest(
                item.get("content_digest", ""), name="workspace content digest"
            ),
        }
        return sha256(canonical_json(identity).encode("utf-8")).hexdigest()

    @classmethod
    def _legacy_stable_key(cls, event: Event) -> str | None:
        promotion = event.payload.get("promotion")
        if not isinstance(promotion, dict):
            return None
        item = {
            "id": promotion.get("source_item_id", ""),
            "kind": promotion.get("source_kind", ""),
            "source": promotion.get("source", ""),
            "content_digest": promotion.get("source_content_digest", ""),
        }
        if not all(str(item[name]).strip() for name in ("id", "kind", "source")):
            return None
        try:
            return cls._stable_promotion_key(item)
        except ValueError:
            return None

    @staticmethod
    def _latest_topic_revision(events: Iterable[Event], topic_id: str) -> int:
        revision = 0
        for event in events:
            if event.kind != "proactive.topic.updated":
                continue
            topic = event.payload.get("topic")
            if isinstance(topic, dict) and topic.get("id") == topic_id:
                revision = max(revision, int(topic.get("revision", 0)))
        return revision

    def _build_topic(
        self,
        *,
        item: Mapping[str, Any],
        existing: Topic | None,
    ) -> Topic:
        kind = _text(item["kind"], name="workspace kind", maximum=80)
        source = _text(item["source"], name="workspace source", maximum=200)
        label = kind.replace("_", " ")
        question = f"What bounded observation should determine the next update for this {label}?"
        hypothesis = (
            f"This {label} passed the deterministic promotion gate and may merit one bounded update."
        )
        item_tick = int(item.get("logical_tick", 0))
        return Topic(
            id=self._topic_id(item),
            title=_bounded_copy(f"{label.title()} from {source}", maximum=240),
            summary=_bounded_copy(item["summary"], maximum=1200),
            source=_bounded_copy(f"auto:workspace:{source}", maximum=240),
            status=existing.status if existing else "open",
            logical_tick=max(item_tick, existing.logical_tick if existing else 0),
            revision=(existing.revision + 1) if existing else 1,
            questions=((*existing.questions, question) if existing else (question,)),
            hypotheses=(
                (*existing.hypotheses, hypothesis) if existing else (hypothesis,)
            ),
            commitments=(
                existing.commitments
                if existing
                else ("Preserve source evidence and bounded emission policy.",)
            ),
            urgency=_unit(item.get("urgency", 0.0), name="workspace urgency"),
            novelty=_unit(item.get("novelty", 0.0), name="workspace novelty"),
            goal_relevance=_unit(
                item.get("goal_relevance", 0.0), name="workspace goal relevance"
            ),
            unresolved_conflict=_unit(
                item.get("unresolved_conflict", 0.0),
                name="workspace unresolved conflict",
            ),
        )

    def _upsert_candidate(
        self,
        *,
        source_event: Event,
        item: Mapping[str, Any],
    ) -> tuple[Topic, bool]:
        topic_id = self._topic_id(item)
        promotion_key = self._stable_promotion_key(item)
        for _ in range(8):
            existing = self.topics.get(topic_id)
            expected_revision = existing.revision if existing else 0
            topic = self._build_topic(item=item, existing=existing)
            payload = {
                "topic": topic.as_payload(),
                "previous_revision": expected_revision or None,
                "continuity_scope": "profile",
                "content_mode": "automatic_structured_workspace_promotion",
                "automatic_structured_workspace_promotion": True,
                "source_summary_already_persisted": True,
                "caller_supplied_summary_may_be_copied": True,
                "automatic_raw_conversation_capture": False,
                "raw_chain_of_thought_stored": False,
                "promotion": {
                    "promotion_key": promotion_key,
                    "source_event_id": source_event.event_id,
                    "source_event_kind": source_event.kind,
                    "source_item_id": _text(
                        item.get("id", ""), name="workspace item id", maximum=180
                    ),
                    "source_content_digest": _bounded_copy(
                        item["content_digest"], maximum=64
                    ),
                    "source_kind": _text(
                        item["kind"], name="workspace kind", maximum=80
                    ),
                    "source": _text(
                        item["source"], name="workspace source", maximum=200
                    ),
                    "initiative_authority": "trusted_producer",
                    "attention_score": float(item["attention_score"]),
                    "policy": self.policy.as_payload(),
                    "llm_calls": 0,
                },
            }

            def revision_guard(events: list[Event]) -> str | None:
                latest = self._latest_topic_revision(events, topic_id)
                return None if latest == expected_revision else "TOPIC_RACE"

            event, created, rejection = self.store.append_once_result_guarded(
                "proactive.topic.updated",
                promotion_key,
                payload,
                guard=revision_guard,
                strict_existing_payload=False,
            )
            if rejection == "TOPIC_RACE":
                continue
            if rejection is not None or event is None:
                raise RuntimeError(f"promotion rejected: {rejection or 'unknown'}")
            persisted = Topic.from_payload(dict(event.payload["topic"]))
            return persisted, created
        raise RuntimeError("topic promotion could not resolve concurrent revisions")

    def _cursor(self) -> tuple[int, int]:
        positions = [
            (
                int(event.payload.get("through_source_seq", 0)),
                int(event.payload.get("through_item_index", -1)),
            )
            for event in self.store.events(self.CURSOR_KIND)
        ]
        return max(positions, default=(0, -1))

    def _advance_cursor(
        self,
        position: tuple[int, int],
        *,
        source_event_id: str,
    ) -> None:
        if position <= self._cursor():
            return
        seq, item_index = position
        payload = {
            "through_source_seq": seq,
            "through_item_index": item_index,
            "source_event_id": source_event_id,
            "oldest_unprocessed_first": True,
            "silent_expiration": False,
            "llm_calls": 0,
        }
        self.store.append_once_result(
            self.CURSOR_KIND,
            f"{seq}:{item_index}",
            payload,
        )

    def _promoted_keys(self) -> set[str]:
        keys: set[str] = set()
        for event in self.store.events("proactive.topic.updated"):
            promotion = event.payload.get("promotion")
            if not isinstance(promotion, dict):
                continue
            key = str(promotion.get("promotion_key", "")).strip()
            if len(key) == 64:
                keys.add(key)
            legacy = self._legacy_stable_key(event)
            if legacy:
                keys.add(legacy)
        return keys

    def promote(self) -> dict[str, Any]:
        cursor = self._cursor()
        promoted_keys = self._promoted_keys()
        considered = 0
        eligible_count = 0
        scanned_events = 0
        rejected = Counter()
        promoted: list[dict[str, Any]] = []
        last_position: tuple[int, int] | None = None
        last_event_id = ""
        stop = False

        for source_event in self.store.events("workspace.broadcast"):
            if source_event.seq < cursor[0]:
                continue
            rows = source_event.payload.get("items", [])
            if not isinstance(rows, list):
                if source_event.seq == cursor[0]:
                    continue
                if scanned_events >= self.policy.max_source_events_scan:
                    break
                scanned_events += 1
                considered += 1
                rejected["MALFORMED_FRAME"] += 1
                last_position = (source_event.seq, -1)
                last_event_id = source_event.event_id
                continue
            if not rows:
                if source_event.seq == cursor[0]:
                    continue
                if scanned_events >= self.policy.max_source_events_scan:
                    break
                scanned_events += 1
                last_position = (source_event.seq, -1)
                last_event_id = source_event.event_id
                continue
            start_index = cursor[1] + 1 if source_event.seq == cursor[0] else 0
            if start_index >= len(rows):
                continue
            if scanned_events >= self.policy.max_source_events_scan:
                break
            scanned_events += 1
            for item_index in range(start_index, len(rows)):
                if len(promoted) >= self.policy.max_promotions_per_run:
                    rejected["RUN_CAP"] += 1
                    stop = True
                    break
                considered += 1
                raw = rows[item_index]
                position = (source_event.seq, item_index)
                if not isinstance(raw, dict):
                    rejected["MALFORMED_ITEM"] += 1
                    last_position = position
                    last_event_id = source_event.event_id
                    continue
                item = dict(raw)
                reasons = self.policy.evaluate(item)
                if reasons:
                    rejected.update(reasons)
                    last_position = position
                    last_event_id = source_event.event_id
                    continue
                eligible_count += 1
                key = self._stable_promotion_key(item)
                if key in promoted_keys:
                    rejected["ALREADY_PROMOTED"] += 1
                    last_position = position
                    last_event_id = source_event.event_id
                    continue
                try:
                    topic, created = self._upsert_candidate(
                        source_event=source_event,
                        item=item,
                    )
                except (KeyError, TypeError, ValueError):
                    rejected["MALFORMED_ITEM"] += 1
                    last_position = position
                    last_event_id = source_event.event_id
                    continue
                if created:
                    promoted_keys.add(key)
                    promoted.append(
                        {
                            "topic": topic.as_payload(),
                            "source_event_id": source_event.event_id,
                            "source_item_id": str(item.get("id", "")),
                        }
                    )
                else:
                    rejected["ALREADY_PROMOTED"] += 1
                last_position = position
                last_event_id = source_event.event_id
            if stop:
                break

        if last_position is not None:
            self._advance_cursor(last_position, source_event_id=last_event_id)
        return {
            "considered_count": considered,
            "eligible_count": eligible_count,
            "promoted_count": len(promoted),
            "promoted": promoted,
            "rejected_by_reason": dict(sorted(rejected.items())),
            "scan_cursor": {
                "before": list(cursor),
                "after": list(self._cursor()),
                "source_events_scanned": scanned_events,
                "oldest_unprocessed_first": True,
            },
            "policy": self.policy.as_payload(),
            "llm_calls": 0,
            "automatic_raw_conversation_capture": False,
            "caller_supplied_structured_summaries_may_be_copied": True,
            "raw_chain_of_thought_stored": False,
        }

    def status(self) -> dict[str, Any]:
        promoted = [
            event
            for event in self.store.events("proactive.topic.updated")
            if event.payload.get("automatic_structured_workspace_promotion") is True
        ]
        return {
            "automatic_topic_revisions": len(promoted),
            "automatic_topics": len(
                {str(event.payload["topic"]["id"]) for event in promoted}
            ),
            "scan_cursor": list(self._cursor()),
            "policy": self.policy.as_payload(),
            "llm_calls": 0,
            "automatic_raw_conversation_capture": False,
            "caller_supplied_structured_summaries_may_be_copied": True,
            "raw_chain_of_thought_stored": False,
        }


@dataclass(frozen=True, slots=True)
class FeedbackReceipt:
    """Feedback envelope signed by a transport/UI trust boundary."""

    emission_event_id: str
    outcome: str
    principal_id: str
    boundary_receipt_id: str
    evidence: tuple[str, ...]
    signature: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "emission_event_id",
            _text(self.emission_event_id, name="emission event id", maximum=180),
        )
        normalized_outcome = _text(
            self.outcome, name="feedback outcome", maximum=20
        ).upper()
        if normalized_outcome not in _ALLOWED_FEEDBACK:
            raise ValueError("feedback outcome must be USEFUL, NEUTRAL, or DISRUPTIVE")
        object.__setattr__(self, "outcome", normalized_outcome)
        object.__setattr__(
            self,
            "principal_id",
            _text(self.principal_id, name="verified principal id", maximum=180),
        )
        object.__setattr__(
            self,
            "boundary_receipt_id",
            _text(
                self.boundary_receipt_id,
                name="feedback boundary receipt id",
                maximum=240,
            ),
        )
        object.__setattr__(self, "evidence", _unique_evidence(self.evidence))
        signature = _text(self.signature, name="feedback signature", maximum=64).lower()
        if len(signature) != 64 or any(char not in "0123456789abcdef" for char in signature):
            raise ValueError("feedback signature must be a 64-character hexadecimal digest")
        object.__setattr__(self, "signature", signature)

    def signed_payload(self) -> dict[str, Any]:
        return {
            "emission_event_id": self.emission_event_id,
            "outcome": self.outcome,
            "principal_id": self.principal_id,
            "boundary_receipt_id": self.boundary_receipt_id,
            "evidence": list(self.evidence),
        }


class HMACFeedbackAuthority:
    """Reference trusted-boundary signer/verifier; keep its secret outside agent tools."""

    def __init__(self, secret: bytes) -> None:
        material = bytes(secret)
        if len(material) < 16:
            raise ValueError("feedback authority secret must contain at least 16 bytes")
        self._secret = material

    def _signature(self, payload: Mapping[str, Any]) -> str:
        return hmac.new(
            self._secret,
            canonical_json(dict(payload)).encode("utf-8"),
            "sha256",
        ).hexdigest()

    def issue(
        self,
        *,
        emission_event_id: str,
        outcome: str,
        principal_id: str,
        boundary_receipt_id: str,
        evidence: Iterable[str] = (),
    ) -> FeedbackReceipt:
        normalized_outcome = _text(outcome, name="feedback outcome", maximum=20).upper()
        if normalized_outcome not in _ALLOWED_FEEDBACK:
            raise ValueError("feedback outcome must be USEFUL, NEUTRAL, or DISRUPTIVE")
        payload = {
            "emission_event_id": _text(
                emission_event_id, name="emission event id", maximum=180
            ),
            "outcome": normalized_outcome,
            "principal_id": _text(
                principal_id, name="verified principal id", maximum=180
            ),
            "boundary_receipt_id": _text(
                boundary_receipt_id,
                name="feedback boundary receipt id",
                maximum=240,
            ),
            "evidence": list(_unique_evidence(evidence)),
        }
        return FeedbackReceipt(
            **payload,
            signature=self._signature(payload),
        )

    def verify(self, receipt: FeedbackReceipt) -> bool:
        return hmac.compare_digest(
            receipt.signature,
            self._signature(receipt.signed_payload()),
        )


class ProactiveFeedback:
    """Feedback accepted only through a caller-supplied verified boundary callback."""

    def __init__(
        self,
        store: EventStore,
        *,
        verifier: Callable[[FeedbackReceipt], bool] | None = None,
    ) -> None:
        self.store = store
        self.verifier = verifier

    def record(self, receipt: FeedbackReceipt) -> dict[str, Any]:
        if self.verifier is None:
            raise PermissionError("a verified feedback boundary is required")
        try:
            verified = bool(self.verifier(receipt))
        except Exception as exc:
            raise PermissionError("feedback signature verification failed") from exc
        if not verified:
            raise PermissionError("feedback signature verification failed")
        emission = self.store.event(receipt.emission_event_id)
        if emission is None or emission.kind != "proactive.message.emitted":
            raise KeyError(receipt.emission_event_id)
        utility, interruption_cost = _ALLOWED_FEEDBACK[receipt.outcome]
        payload = {
            "emission_event_id": emission.event_id,
            "proposal_event_id": str(emission.payload["proposal_event_id"]),
            "packet_id": str(emission.payload["packet_id"]),
            "topic_id": str(emission.payload["topic_id"]),
            "outcome": receipt.outcome,
            "utility": utility,
            "observed_interruption_cost": interruption_cost,
            "verified_principal_id": receipt.principal_id,
            "boundary_receipt_id": receipt.boundary_receipt_id,
            "boundary_verification": "external_verifier_callback",
            "signature_digest": sha256(receipt.signature.encode("ascii")).hexdigest(),
            "evidence": list(receipt.evidence),
            "root_policy_changed": False,
            "hard_safety_gates_changed": False,
            "caller_supplied_feedback_persisted": True,
            "automatic_raw_conversation_capture": False,
            "raw_chain_of_thought_stored": False,
        }
        event, created = self.store.append_once_result(
            "proactive.feedback.recorded",
            emission.event_id,
            payload,
        )
        return {
            "created": created,
            "event_id": event.event_id,
            "feedback": dict(event.payload),
            "calibration": self.calibration(),
        }

    def calibration(self) -> dict[str, Any]:
        events = self.store.events("proactive.feedback.recorded")
        utilities = [float(event.payload["utility"]) for event in events]
        interruption_costs = [
            float(event.payload["observed_interruption_cost"]) for event in events
        ]
        count = len(events)
        mean_utility = sum(utilities) / count if count else 0.0
        confidence_weight = count / (count + 4.0) if count else 0.0
        raw_adjustment = mean_utility * confidence_weight * 0.15
        adjustment = round(max(-0.12, min(0.12, raw_adjustment)), 6)
        outcomes = Counter(str(event.payload["outcome"]) for event in events)
        return {
            "sample_count": count,
            "outcomes": {
                name: outcomes.get(name, 0)
                for name in ("USEFUL", "NEUTRAL", "DISRUPTIVE")
            },
            "mean_utility": round(mean_utility, 6),
            "mean_observed_interruption_cost": round(
                sum(interruption_costs) / count if count else 0.0, 6
            ),
            "confidence_weight": round(confidence_weight, 6),
            "score_adjustment": adjustment,
            "adjustment_bound": 0.12,
            "root_policy_changed": False,
            "hard_safety_gates_changed": False,
            "verified_feedback_boundary_required": True,
            "raw_chain_of_thought_stored": False,
        }

    def adjust_score(self, base_score: float) -> tuple[float, dict[str, Any]]:
        base = _unit(base_score, name="base initiation score")
        calibration = self.calibration()
        adjusted = round(
            max(0.0, min(1.0, base + float(calibration["score_adjustment"]))),
            6,
        )
        return adjusted, calibration

    def status(self) -> dict[str, Any]:
        return self.calibration()
