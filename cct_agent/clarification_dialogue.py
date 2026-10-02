"""Typed proactive clarification for important operator-only unknowns.

Clarification is understanding, not effect authority. Trusted host code registers one exact
request; CCT asks up to five important questions; authenticated private Telegram replies are
mapped deterministically to immutable host-owned option values; protected/authority answers
require a separate exact operator confirmation. Neither path mints a capability lease or
execution ticket. Arbitrary free text is hash-only and cannot resume a plan.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import hmac
from math import isfinite
import re
from typing import Any, Callable, Literal, Sequence

from .principal import PrincipalModel
from .proactive import InitiationPolicy, InitiationSignals, ProactiveEngine, ThoughtPacket
from .store import Event, EventStore, canonical_json


QuestionKind = Literal[
    "FACT",
    "PREFERENCE",
    "AUTHORITY",
    "PROTECTED_DECLARATION",
    "CREDENTIAL_HANDOFF",
]
AnswerType = Literal["TEXT", "OPTION"]
AnswerSource = Literal["host_adapter"]
ConfirmationAuthority = Literal["operator", "host_adapter"]
RequestAuthority = Literal["host_adapter", "host_template"]
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]{1,400}$")
_KINDS = {
    "FACT",
    "PREFERENCE",
    "AUTHORITY",
    "PROTECTED_DECLARATION",
    "CREDENTIAL_HANDOFF",
}
_ANSWER_TYPES = {"TEXT", "OPTION"}
_CONFIRMATION_KINDS = {"AUTHORITY", "PROTECTED_DECLARATION", "CREDENTIAL_HANDOFF"}
_SEPARATE_TICKET_KINDS = {"AUTHORITY", "CREDENTIAL_HANDOFF"}
_STANDARD_UNRESOLVED_OPTIONS = {"UNKNOWN", "DECLINE", "MANUAL_NEEDED"}
_SENSITIVE_TEXT = re.compile(
    r"(?i)(?:password|passphrase|secret|token|api[ _-]*key|private[ _-]*key|"
    r"seed[ _-]*phrase|mnemonic|bearer|otp|mfa[ _-]*code|verification[ _-]*code)"
    r"\s*(?::|=|is)\s*\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bsk-[A-Za-z0-9_-]{16,}\b|\b0x[0-9a-fA-F]{64}\b|"
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)


class ClarificationDenied(RuntimeError):
    """Fail-closed clarification request, answer, or confirmation."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest_value(name: str, value: object) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256")
    return value


def _text(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    cleaned = value.strip()
    if (
        not cleaned
        or len(cleaned) > maximum
        or any(ord(char) < 32 for char in cleaned)
    ):
        raise ValueError(f"{name} must contain 1-{maximum} printable characters")
    return cleaned


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


def _unit(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    number = float(value)
    if not isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(f"{name} must be finite between 0 and 1")
    return number


def _aware_time(name: str, value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as error:
        raise ValueError(f"{name} must be ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include timezone information")
    return parsed.astimezone(timezone.utc)


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ClarificationQuestion:
    """One bounded important unknown tied to evidence and a typed answer contract."""

    id: str
    prompt: str
    kind: QuestionKind
    answer_type: AnswerType
    options: tuple[str, ...]
    importance: float
    evidence: tuple[str, ...]
    required: bool = True
    unresolved_options: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("question id", self.id))
        object.__setattr__(self, "prompt", _text("question prompt", self.prompt, 300))
        if self.kind not in _KINDS:
            raise ValueError("question kind is invalid")
        if self.answer_type not in _ANSWER_TYPES:
            raise ValueError("question answer_type is invalid")
        options = tuple(_identifier("question option", value) for value in self.options)
        if len(options) != len(set(options)):
            raise ValueError("question options must be unique")
        if self.answer_type == "OPTION" and not 2 <= len(options) <= 8:
            raise ValueError("OPTION questions require 2-8 options")
        if self.answer_type == "TEXT" and options:
            raise ValueError("TEXT questions cannot define options")
        if self.kind in _CONFIRMATION_KINDS and self.answer_type != "OPTION":
            raise ValueError("protected, authority, and credential questions require OPTION")
        object.__setattr__(self, "options", options)
        unresolved = tuple(
            _identifier("unresolved option", value) for value in self.unresolved_options
        )
        unresolved = tuple(
            dict.fromkeys(
                (
                    *unresolved,
                    *(value for value in options if value in _STANDARD_UNRESOLVED_OPTIONS),
                )
            )
        )
        if (
            len(unresolved) != len(set(unresolved))
            or any(value not in options for value in unresolved)
            or (self.answer_type == "TEXT" and unresolved)
        ):
            raise ValueError("unresolved options must be unique declared OPTION values")
        object.__setattr__(self, "unresolved_options", unresolved)
        object.__setattr__(self, "importance", _unit("question importance", self.importance))
        object.__setattr__(self, "evidence", _evidence(self.evidence))
        if not isinstance(self.required, bool):
            raise ValueError("question required must be boolean")

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "prompt": self.prompt,
            "kind": self.kind,
            "answer_type": self.answer_type,
            "options": list(self.options),
            "importance": self.importance,
            "evidence": list(self.evidence),
            "required": self.required,
            "unresolved_options": list(self.unresolved_options),
        }


@dataclass(frozen=True, slots=True)
class ClarificationRequest:
    """One exact task/revision-bound bundle of one to five important questions."""

    id: str
    revision: int
    task_id: str
    task_revision: int
    task_sha256: str
    summary: str
    questions: tuple[ClarificationQuestion, ...]
    expires_at: str
    resume_plan_id: str
    resume_plan_sha256: str
    evidence: tuple[str, ...]
    template_id: str = "custom-host-reviewed"
    source_authority: RequestAuthority = "host_adapter"
    semantic_taint: bool = False
    producer_text_used: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("request id", self.id))
        for name in ("revision", "task_revision"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        object.__setattr__(self, "task_id", _identifier("task id", self.task_id))
        object.__setattr__(self, "task_sha256", _digest_value("task_sha256", self.task_sha256))
        object.__setattr__(self, "summary", _text("request summary", self.summary, 300))
        rows = tuple(self.questions)
        if not 1 <= len(rows) <= 5 or any(
            not isinstance(row, ClarificationQuestion) for row in rows
        ):
            raise ValueError("clarification request requires 1-5 questions")
        if len({row.id for row in rows}) != len(rows):
            raise ValueError("clarification question ids must be unique")
        object.__setattr__(self, "questions", rows)
        _aware_time("request expiry", self.expires_at)
        object.__setattr__(
            self, "resume_plan_id", _identifier("resume plan id", self.resume_plan_id)
        )
        object.__setattr__(
            self,
            "resume_plan_sha256",
            _digest_value("resume_plan_sha256", self.resume_plan_sha256),
        )
        object.__setattr__(self, "evidence", _evidence(self.evidence))
        object.__setattr__(
            self, "template_id", _identifier("clarification template id", self.template_id)
        )
        if self.source_authority not in {"host_adapter", "host_template"}:
            raise ValueError("clarification request source authority is invalid")
        if not isinstance(self.semantic_taint, bool) or not isinstance(
            self.producer_text_used, bool
        ):
            raise ValueError("clarification semantic flags must be boolean")


def clarification_request_from_template(
    *,
    template_id: str,
    request_id: str,
    revision: int,
    task_id: str,
    task_revision: int,
    task_sha256: str,
    expires_at: str,
    resume_plan_id: str,
    resume_plan_sha256: str,
    evidence: Sequence[str],
) -> ClarificationRequest:
    """Build one request from immutable host-owned question prose and options."""

    identifier = _identifier("clarification template id", template_id)
    template_evidence = (f"template:{identifier}",)
    if identifier == "important-outcome":
        summary = "An important outcome preference is required before this task continues."
        rows = (
            ClarificationQuestion(
                id="important-outcome",
                prompt="Which outcome matters most for this exact task?",
                kind="PREFERENCE",
                answer_type="OPTION",
                options=("VERIFIED_OUTCOME", "REVENUE", "SPEED", "BREADTH"),
                importance=0.95,
                evidence=template_evidence,
            ),
        )
    elif identifier == "first-effect-class":
        summary = "CCT needs Mike's priority before activating the first real effect class."
        rows = (
            ClarificationQuestion(
                id="first-effect-class",
                prompt="Which real effect class should CCT activate and canary first?",
                kind="PREFERENCE",
                answer_type="OPTION",
                options=(
                    "PUBLIC_POST",
                    "CREDENTIAL_USE",
                    "FINANCIAL",
                    "LEGAL",
                    "HIGH_CONSEQUENCE",
                ),
                importance=1.0,
                evidence=template_evidence,
            ),
        )
    elif identifier == "public-effect-envelope":
        summary = "The public-action envelope needs exact scope before any public canary."
        rows = (
            ClarificationQuestion(
                id="public-mode",
                prompt="Which public-action mode should CCT use?",
                kind="PREFERENCE",
                answer_type="OPTION",
                options=("DRAFT_ONLY", "ONE_LIVE_CANARY", "STANDING_BOUNDED"),
                importance=1.0,
                evidence=template_evidence,
            ),
            ClarificationQuestion(
                id="public-daily-cap",
                prompt="What maximum public-post count per day should this envelope allow?",
                kind="AUTHORITY",
                answer_type="OPTION",
                options=("ONE", "TWO", "NONE", "UNKNOWN"),
                importance=1.0,
                evidence=template_evidence,
            ),
            ClarificationQuestion(
                id="public-rollback",
                prompt="Must every public canary support delete or rollback readback?",
                kind="AUTHORITY",
                answer_type="OPTION",
                options=("REQUIRED", "NOT_REQUIRED", "UNKNOWN"),
                importance=1.0,
                evidence=template_evidence,
            ),
        )
    elif identifier == "credential-handoff":
        summary = "A credentialed operation needs a brokered handoff status, never a secret value."
        rows = (
            ClarificationQuestion(
                id="credential-handoff-status",
                prompt="What is the brokered credential handoff status?",
                kind="CREDENTIAL_HANDOFF",
                answer_type="OPTION",
                options=("READY", "MANUAL_NEEDED", "DECLINE"),
                importance=1.0,
                evidence=template_evidence,
            ),
        )
    elif identifier == "financial-risk-posture":
        summary = "A financial operation needs an exact risk posture before any ticket exists."
        rows = (
            ClarificationQuestion(
                id="financial-mode",
                prompt="Which financial mode should CCT prepare?",
                kind="AUTHORITY",
                answer_type="OPTION",
                options=("PAPER_ONLY", "TINY_LIVE", "NONE", "UNKNOWN"),
                importance=1.0,
                evidence=template_evidence,
            ),
            ClarificationQuestion(
                id="financial-loss-response",
                prompt="What should happen when the exact loss budget is reached?",
                kind="AUTHORITY",
                answer_type="OPTION",
                options=("KILL_SWITCH", "PAUSE_AND_ASK", "NONE", "UNKNOWN"),
                importance=1.0,
                evidence=template_evidence,
            ),
        )
    else:
        raise ClarificationDenied("UNKNOWN_CLARIFICATION_TEMPLATE")
    merged_evidence = tuple(dict.fromkeys((*evidence, *template_evidence)))
    return ClarificationRequest(
        id=request_id,
        revision=revision,
        task_id=task_id,
        task_revision=task_revision,
        task_sha256=task_sha256,
        summary=summary,
        questions=rows,
        expires_at=expires_at,
        resume_plan_id=resume_plan_id,
        resume_plan_sha256=resume_plan_sha256,
        evidence=merged_evidence,
        template_id=identifier,
        source_authority="host_template",
        semantic_taint=False,
        producer_text_used=False,
    )


@dataclass(frozen=True, slots=True)
class QuestionAnswer:
    """One normalized typed answer; never a secret-bearing credential value."""

    question_id: str
    value_type: AnswerType
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "question_id", _identifier("answer question id", self.question_id))
        if self.value_type not in _ANSWER_TYPES:
            raise ValueError("answer value_type is invalid")
        maximum = 400 if self.value_type == "TEXT" else 160
        object.__setattr__(self, "value", _text("answer value", self.value, maximum))
        if self.value_type == "TEXT" and _SENSITIVE_TEXT.search(self.value):
            raise ValueError("TEXT answers must not contain credential or secret material")

    def as_payload(self) -> dict[str, str]:
        return {
            "question_id": self.question_id,
            "value_type": self.value_type,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class ClarificationAnswer:
    """Authenticated host-structured understanding; never effect authority."""

    id: str
    request_id: str
    request_revision: int
    request_sha256: str
    principal_id: str
    principal_profile_digest: str
    answers: tuple[QuestionAnswer, ...]
    evidence: tuple[str, ...]
    source_authority: AnswerSource
    raw_answer_text_persisted: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("answer id", self.id))
        object.__setattr__(self, "request_id", _identifier("answer request id", self.request_id))
        if (
            isinstance(self.request_revision, bool)
            or not isinstance(self.request_revision, int)
            or self.request_revision < 1
        ):
            raise ValueError("answer request_revision must be a positive integer")
        object.__setattr__(
            self, "request_sha256", _digest_value("request_sha256", self.request_sha256)
        )
        object.__setattr__(self, "principal_id", _identifier("answer principal id", self.principal_id))
        object.__setattr__(
            self,
            "principal_profile_digest",
            _digest_value("principal_profile_digest", self.principal_profile_digest),
        )
        rows = tuple(self.answers)
        if not 1 <= len(rows) <= 5 or any(not isinstance(row, QuestionAnswer) for row in rows):
            raise ValueError("clarification answer requires 1-5 typed answers")
        if len({row.question_id for row in rows}) != len(rows):
            raise ValueError("answer question ids must be unique")
        object.__setattr__(self, "answers", rows)
        object.__setattr__(self, "evidence", _evidence(self.evidence))
        if self.source_authority != "host_adapter":
            raise ValueError("answers require an authenticated host adapter")
        if self.raw_answer_text_persisted is not False:
            raise ValueError("raw answer text must never be persisted")


@dataclass(frozen=True, slots=True)
class ClarificationConfirmation:
    """Exact operator confirmation of one previously persisted typed answer."""

    id: str
    request_id: str
    request_revision: int
    request_sha256: str
    answer_event_id: str
    answer_sha256: str
    principal_id: str
    principal_profile_digest: str
    evidence: tuple[str, ...]
    source_authority: ConfirmationAuthority
    signature: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("confirmation id", self.id))
        object.__setattr__(
            self, "request_id", _identifier("confirmation request id", self.request_id)
        )
        if (
            isinstance(self.request_revision, bool)
            or not isinstance(self.request_revision, int)
            or self.request_revision < 1
        ):
            raise ValueError("confirmation request_revision must be a positive integer")
        object.__setattr__(
            self,
            "request_sha256",
            _digest_value("confirmation request_sha256", self.request_sha256),
        )
        object.__setattr__(
            self, "answer_event_id", _identifier("confirmation answer event id", self.answer_event_id)
        )
        object.__setattr__(
            self,
            "answer_sha256",
            _digest_value("confirmation answer_sha256", self.answer_sha256),
        )
        object.__setattr__(
            self, "principal_id", _identifier("confirmation principal id", self.principal_id)
        )
        object.__setattr__(
            self,
            "principal_profile_digest",
            _digest_value(
                "confirmation principal_profile_digest", self.principal_profile_digest
            ),
        )
        object.__setattr__(self, "evidence", _evidence(self.evidence))
        if self.source_authority not in {"operator", "host_adapter"}:
            raise ValueError("confirmation source_authority is invalid")
        _digest_value("confirmation signature", self.signature)

    def signed_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "confirmation_id": self.id,
            "request_id": self.request_id,
            "request_revision": self.request_revision,
            "request_sha256": self.request_sha256,
            "answer_event_id": self.answer_event_id,
            "answer_sha256": self.answer_sha256,
            "principal_id": self.principal_id,
            "principal_profile_digest": self.principal_profile_digest,
            "evidence": list(self.evidence),
            "source_authority": self.source_authority,
        }

    @classmethod
    def sign(
        cls,
        *,
        confirmation_id: str,
        request_id: str,
        request_revision: int,
        request_sha256: str,
        answer_event_id: str,
        answer_sha256: str,
        principal_id: str,
        principal_profile_digest: str,
        evidence: Sequence[str],
        source_authority: ConfirmationAuthority,
        secret: bytes,
    ) -> ClarificationConfirmation:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("confirmation secret must contain at least 32 bytes")
        unsigned = {
            "schema_version": 1,
            "confirmation_id": confirmation_id,
            "request_id": request_id,
            "request_revision": request_revision,
            "request_sha256": request_sha256,
            "answer_event_id": answer_event_id,
            "answer_sha256": answer_sha256,
            "principal_id": principal_id,
            "principal_profile_digest": principal_profile_digest,
            "evidence": list(evidence),
            "source_authority": source_authority,
        }
        signature = hmac.new(
            secret, canonical_json(unsigned).encode("utf-8"), "sha256"
        ).hexdigest()
        return cls(
            id=confirmation_id,
            request_id=request_id,
            request_revision=request_revision,
            request_sha256=request_sha256,
            answer_event_id=answer_event_id,
            answer_sha256=answer_sha256,
            principal_id=principal_id,
            principal_profile_digest=principal_profile_digest,
            evidence=tuple(evidence),
            source_authority=source_authority,
            signature=signature,
        )

    def verify(self, secret: bytes) -> bool:
        if not isinstance(secret, bytes) or len(secret) < 32:
            return False
        expected = hmac.new(
            secret, canonical_json(self.signed_payload()).encode("utf-8"), "sha256"
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)


class ClarificationDialogue:
    """Register, ask, remember, confirm, and resolve important unknowns."""

    def __init__(self, store: EventStore) -> None:
        if not isinstance(store, EventStore):
            raise TypeError("store must be an EventStore")
        self.store = store
        self.proactive = ProactiveEngine(
            store,
            policy=InitiationPolicy(max_message_chars=1800),
        )

    @staticmethod
    def _latest_requests(events: Sequence[Event]) -> dict[str, Event]:
        rows: dict[str, Event] = {}
        for event in events:
            if event.kind != "clarification.requested":
                continue
            identifier = str(event.payload["request_id"])
            previous = rows.get(identifier)
            if previous is None or int(event.payload["revision"]) > int(
                previous.payload["revision"]
            ):
                rows[identifier] = event
        return rows

    @staticmethod
    def _presentation(events: Sequence[Event], request_event_id: str) -> Event | None:
        packet_id = "packet_clarification_" + _digest(
            {"request_event_id": request_event_id}
        )[:20]
        emitted = next(
            (
                event
                for event in reversed(events)
                if event.kind == "proactive.message.emitted"
                and event.payload.get("packet_id") == packet_id
            ),
            None,
        )
        if emitted is not None:
            return emitted
        return next(
            (
                event
                for event in reversed(events)
                if event.kind == "clarification.presentation.completed"
                and event.payload.get("request_event_id") == request_event_id
                and event.payload.get("emitted") is True
            ),
            None,
        )

    @staticmethod
    def _understanding(events: Sequence[Event], request_event_id: str) -> Event | None:
        return next(
            (
                event
                for event in reversed(events)
                if event.kind == "clarification.answer.understood"
                and event.payload.get("request_event_id") == request_event_id
            ),
            None,
        )

    @staticmethod
    def _confirmation(events: Sequence[Event], request_event_id: str) -> Event | None:
        return next(
            (
                event
                for event in reversed(events)
                if event.kind == "clarification.answer.confirmed"
                and event.payload.get("request_event_id") == request_event_id
            ),
            None,
        )

    def register(self, request: ClarificationRequest) -> dict[str, Any]:
        if not isinstance(request, ClarificationRequest):
            raise ValueError("request must be ClarificationRequest")
        if request.semantic_taint or request.producer_text_used:
            raise ClarificationDenied("SEMANTIC_TAINT_REJECTED")
        profile = PrincipalModel(self.store).status()
        if not profile["profile_installed"]:
            raise ClarificationDenied("PRINCIPAL_PROFILE_NOT_INSTALLED")
        threshold = float((profile["profile"] or {})["uncertainty_threshold"])
        if any(question.importance < threshold for question in request.questions):
            raise ClarificationDenied("QUESTION_NOT_IMPORTANT")
        material = {
            "schema_version": 1,
            "request_id": request.id,
            "revision": request.revision,
            "task_id": request.task_id,
            "task_revision": request.task_revision,
            "task_sha256": request.task_sha256,
            "summary": request.summary,
            "questions": [question.as_payload() for question in request.questions],
            "expires_at": request.expires_at,
            "resume_plan_id": request.resume_plan_id,
            "resume_plan_sha256": request.resume_plan_sha256,
            "evidence": list(request.evidence),
            "template_id": request.template_id,
            "source_authority": request.source_authority,
            "semantic_taint": False,
            "producer_text_used": False,
            "principal_id": (profile["profile"] or {})["principal_id"],
            "principal_profile_digest": profile["profile_digest"],
            "principal_profile_revision": profile["revision"],
        }
        request_sha256 = _digest(material)
        payload = {
            **material,
            "request_sha256": request_sha256,
            "importance_gate": "principal_uncertainty_threshold",
            "question_count": len(request.questions),
            "confirmation_required": any(
                question.kind in _CONFIRMATION_KINDS for question in request.questions
            ),
            "execution_authority_granted": False,
            "raw_producer_content_persisted": False,
            "raw_chain_of_thought_stored": False,
        }

        def guard(events: list[Event]) -> str | None:
            active_profile = next(
                (
                    event
                    for event in reversed(events)
                    if event.kind == "principal.profile.installed"
                ),
                None,
            )
            if active_profile is None or active_profile.payload.get(
                "profile_digest"
            ) != profile["profile_digest"]:
                return "PRINCIPAL_PROFILE_CHANGED"
            latest_requests = self._latest_requests(events)
            if any(
                existing_id != request.id
                and self._understanding(events, existing.event_id) is None
                and _aware_time("request expiry", self.store.clock())
                <= _aware_time("request expiry", existing.payload["expires_at"])
                for existing_id, existing in latest_requests.items()
            ):
                return "OPEN_CLARIFICATION_EXISTS"
            latest = latest_requests.get(request.id)
            if (
                latest is not None
                and self._understanding(events, latest.event_id) is None
                and _aware_time("request expiry", self.store.clock())
                <= _aware_time("request expiry", latest.payload["expires_at"])
            ):
                return "REQUEST_ALREADY_OPEN"
            expected = 1 if latest is None else int(latest.payload["revision"]) + 1
            if request.revision != expected:
                return "REQUEST_REVISION_NOT_MONOTONIC"
            return None

        event, created, rejection = self.store.append_once_result_guarded(
            "clarification.requested",
            f"{request.id}:{request.revision}",
            payload,
            guard=guard,
            strict_existing_payload=True,
        )
        if rejection is not None:
            raise ClarificationDenied(rejection)
        if event is None:
            raise RuntimeError("clarification request was not persisted")
        return {**dict(event.payload), "event_id": event.event_id, "created": created}

    def _next(self, events: Sequence[Event]) -> Event | None:
        rows = []
        for request in self._latest_requests(events).values():
            if (
                self._presentation(events, request.event_id) is not None
                or self._understanding(events, request.event_id) is not None
                or _aware_time("request expiry", self.store.clock())
                > _aware_time("request expiry", request.payload["expires_at"])
            ):
                continue
            rows.append(request)
        return min(rows, key=lambda event: event.seq) if rows else None

    @staticmethod
    def _packet(request: Event) -> ThoughtPacket:
        payload = request.payload
        question_lines = []
        for question in payload["questions"]:
            options = ""
            if question["answer_type"] == "OPTION":
                options = " choices=" + " / ".join(question["options"])
            question_lines.append(
                f"{question['id']} [{question['kind']}]{options}: {question['prompt']}"
            )
        return ThoughtPacket(
            id="packet_clarification_" + _digest({"request_event_id": request.event_id})[:20],
            topic_id=f"clarification:{payload['request_id']}:{payload['revision']}",
            observation=(
                f"{payload['summary']} [{payload['request_id']} r{payload['revision']}]"
            ),
            hypotheses=tuple(question_lines),
            open_questions=(
                "Reply naturally using the listed option wording; arbitrary free text is hash-only and cannot resume the plan.",
                (
                    f"Binding: {payload['request_id']} r{payload['revision']} "
                    f"request={payload['request_sha256']}"
                ),
            ),
            evidence=(f"event:{request.event_id}",),
            uncertainty=max(float(row["importance"]) for row in payload["questions"]),
            recommended_action="ASK",
            rationale_summary=(
                "Important operator-only details block or materially rerank the exact task; "
                "guessing is forbidden."
            ),
            source="self:clarification-dialogue-runner",
            created_tick=request.seq,
        )

    def run_once(
        self,
        *,
        wake_index: int,
        time_bucket: str,
        fault_hook: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        if isinstance(wake_index, bool) or not isinstance(wake_index, int) or wake_index < 1:
            raise ValueError("wake_index must be a positive integer")
        request = self._next(self.store.events())
        if request is None:
            return {
                "message": "",
                "reason": "NO_CLARIFICATION",
                "candidate_found": False,
                "state_consumed": False,
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
                "request_id": request.payload["request_id"],
                "request_revision": request.payload["revision"],
                "candidate_found": True,
                "state_consumed": False,
                "external_effects": 0,
            }
        packet = self._packet(request)
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
                    "request_id": request.payload["request_id"],
                    "request_revision": request.payload["revision"],
                    "candidate_found": True,
                    "state_consumed": False,
                    "external_effects": 0,
                }
            emitted = bool(emission["emitted"])
            message = str(emission["message"])
            emission_reason = str(emission["reason"])
        if fault_hook is not None:
            fault_hook("after_emission_before_completion")
        presentation_exists = self._presentation(self.store.events(), request.event_id) is not None
        completion_payload = {
            "schema_version": 1,
            "request_event_id": request.event_id,
            "request_id": request.payload["request_id"],
            "request_revision": request.payload["revision"],
            "request_sha256": request.payload["request_sha256"],
            "packet_id": packet.id,
            "decision": decision["decision"],
            "reason_codes": [
                *decision["reason_codes"],
                *([emission_reason] if emission_reason else []),
            ],
            "emitted": presentation_exists,
            "wake_index": wake_index,
            "time_bucket": time_bucket,
            "external_effects": 0,
            "raw_chain_of_thought_stored": False,
        }
        completion, _, rejection = self.store.append_once_result_guarded(
            "clarification.presentation.completed",
            request.event_id,
            completion_payload,
            strict_existing_payload=False,
        )
        if rejection is not None or completion is None:
            raise RuntimeError("clarification presentation completion was rejected")
        return {
            "message": message,
            "reason": "EMITTED" if emitted else emission_reason or decision["decision"],
            "request_id": request.payload["request_id"],
            "request_revision": request.payload["revision"],
            "request_sha256": request.payload["request_sha256"],
            "candidate_found": True,
            "state_consumed": True,
            "external_effects": 0,
        }

    def _request_for_answer(self, answer: ClarificationAnswer) -> tuple[Event, list[Event]]:
        events = self.store.events()
        request = self._latest_requests(events).get(answer.request_id)
        if request is None:
            raise ClarificationDenied("REQUEST_NOT_FOUND")
        if (
            request.payload["revision"] != answer.request_revision
            or request.payload["request_sha256"] != answer.request_sha256
            or request.payload["principal_id"] != answer.principal_id
            or request.payload["principal_profile_digest"]
            != answer.principal_profile_digest
        ):
            raise ClarificationDenied("REQUEST_BINDING_MISMATCH")
        profile = PrincipalModel(self.store).status()
        if (
            profile["profile_digest"] != answer.principal_profile_digest
            or (profile["profile"] or {}).get("principal_id") != answer.principal_id
        ):
            raise ClarificationDenied("PRINCIPAL_PROFILE_CHANGED")
        if self._presentation(events, request.event_id) is None:
            raise ClarificationDenied("REQUEST_NOT_PRESENTED")
        if _aware_time("request expiry", self.store.clock()) > _aware_time(
            "request expiry", request.payload["expires_at"]
        ):
            raise ClarificationDenied("REQUEST_EXPIRED")
        return request, events

    @staticmethod
    def _normalize_answers(
        request: Event, answer: ClarificationAnswer
    ) -> tuple[list[dict[str, Any]], bool, bool, list[str]]:
        questions = {str(row["id"]): row for row in request.payload["questions"]}
        supplied = {row.question_id: row for row in answer.answers}
        required = {identifier for identifier, row in questions.items() if row["required"]}
        if not required.issubset(supplied) or not set(supplied).issubset(questions):
            raise ClarificationDenied("ANSWER_SET_MISMATCH")
        normalized = []
        confirmation_required = False
        separate_ticket_required = False
        unresolved_question_ids: list[str] = []
        for identifier, question in questions.items():
            row = supplied.get(identifier)
            if row is None:
                continue
            if row.value_type != question["answer_type"]:
                raise ClarificationDenied("ANSWER_TYPE_MISMATCH")
            if row.value_type == "OPTION" and row.value not in question["options"]:
                raise ClarificationDenied("ANSWER_OPTION_INVALID")
            if row.value_type == "TEXT":
                unresolved_question_ids.append(identifier)
                normalized.append(
                    {
                        "question_id": identifier,
                        "question_kind": question["kind"],
                        "value_type": "TEXT",
                        "value_sha256": sha256(row.value.encode("utf-8")).hexdigest(),
                        "value_chars": len(row.value),
                        "visibility": "transient_hash_only",
                    }
                )
                continue
            if row.value in question.get("unresolved_options", []):
                unresolved_question_ids.append(identifier)
            if question["kind"] in _CONFIRMATION_KINDS:
                confirmation_required = True
            if question["kind"] in _SEPARATE_TICKET_KINDS:
                separate_ticket_required = True
            normalized.append(
                {
                    "question_id": identifier,
                    "question_kind": question["kind"],
                    "value_type": row.value_type,
                    "value": row.value,
                    "visibility": (
                        "typed_nonsecret_memory"
                        if question["kind"] in {"FACT", "PREFERENCE"}
                        else "per_operation_only"
                    ),
                }
            )
        return (
            normalized,
            confirmation_required,
            separate_ticket_required,
            unresolved_question_ids,
        )

    def record_understanding(self, answer: ClarificationAnswer) -> dict[str, Any]:
        if not isinstance(answer, ClarificationAnswer):
            raise ValueError("answer must be ClarificationAnswer")
        request, baseline_events = self._request_for_answer(answer)
        (
            normalized,
            confirmation_required,
            separate_ticket_required,
            unresolved_question_ids,
        ) = self._normalize_answers(request, answer)
        base_payload = {
            "schema_version": 1,
            "answer_id": answer.id,
            "request_event_id": request.event_id,
            "request_id": answer.request_id,
            "request_revision": answer.request_revision,
            "request_sha256": answer.request_sha256,
            "principal_id": answer.principal_id,
            "principal_profile_digest": answer.principal_profile_digest,
            "answers": normalized,
            "evidence": list(answer.evidence),
            "source_authority": answer.source_authority,
            "operator_authenticated": True,
            "typed_nonsecret_memory": any(
                row["visibility"] == "typed_nonsecret_memory" for row in normalized
            ),
            "protected_values_per_operation": True,
            "confirmation_required": confirmation_required,
            "separate_ticket_required": separate_ticket_required,
            "unresolved_question_ids": unresolved_question_ids,
            "all_required_resolved": not unresolved_question_ids,
            "resume_ready": not confirmation_required and not unresolved_question_ids,
            "execution_authority_granted": False,
            "raw_answer_text_persisted": False,
            "raw_secret_persisted": False,
        }
        answer_sha256 = _digest(base_payload)
        payload = {**base_payload, "answer_sha256": answer_sha256}

        def guard(events: list[Event]) -> str | None:
            active = self._latest_requests(events).get(answer.request_id)
            if active is None or active.event_id != request.event_id:
                return "STALE_REQUEST_REVISION"
            if PrincipalModel(self.store).status()["profile_digest"] != answer.principal_profile_digest:
                return "PRINCIPAL_PROFILE_CHANGED"
            if self._presentation(events, request.event_id) is None:
                return "REQUEST_NOT_PRESENTED"
            if _aware_time("request expiry", self.store.clock()) > _aware_time(
                "request expiry", request.payload["expires_at"]
            ):
                return "REQUEST_EXPIRED"
            if self._understanding(events, request.event_id) is not None:
                return "ANSWER_ALREADY_EXISTS"
            if len(events) < len(baseline_events):
                return "LEDGER_STATE_INVALID"
            return None

        try:
            event, created, rejection = self.store.append_once_result_guarded(
                "clarification.answer.understood",
                answer.id,
                payload,
                guard=guard,
                strict_existing_payload=True,
            )
        except ValueError as error:
            raise ClarificationDenied("ANSWER_ID_CONFLICT") from error
        if rejection == "ANSWER_ALREADY_EXISTS":
            existing = self._understanding(self.store.events(), request.event_id)
            if existing is not None and canonical_json(existing.payload) == canonical_json(payload):
                event = existing
                created = False
                rejection = None
            else:
                raise ClarificationDenied("ANSWER_ALREADY_EXISTS")
        if rejection is not None:
            raise ClarificationDenied(rejection)
        if event is None:
            raise RuntimeError("clarification understanding was not persisted")
        if canonical_json(event.payload) != canonical_json(payload):
            raise ClarificationDenied("ANSWER_ID_CONFLICT")
        confirmation_command = (
            f"CCT CONFIRM {answer.request_id} r{answer.request_revision} "
            f"request={answer.request_sha256} answer={answer_sha256}"
            if confirmation_required
            else None
        )
        return {
            **dict(event.payload),
            "event_id": event.event_id,
            "understood": created,
            "reason": "UNDERSTOOD" if created else "DUPLICATE_ANSWER",
            "confirmation_command": confirmation_command,
        }

    def confirm(
        self,
        confirmation: ClarificationConfirmation,
        *,
        secret: bytes,
    ) -> dict[str, Any]:
        if not isinstance(confirmation, ClarificationConfirmation) or not confirmation.verify(
            secret
        ):
            raise ClarificationDenied("CONFIRMATION_AUTHENTICATION_FAILED")
        if confirmation.source_authority != "operator":
            raise ClarificationDenied("OPERATOR_AUTHORITY_REQUIRED")
        events = self.store.events()
        request = self._latest_requests(events).get(confirmation.request_id)
        if request is None:
            raise ClarificationDenied("REQUEST_NOT_FOUND")
        answer = self.store.event(confirmation.answer_event_id)
        if (
            request.payload["revision"] != confirmation.request_revision
            or request.payload["request_sha256"] != confirmation.request_sha256
            or request.payload["principal_id"] != confirmation.principal_id
            or request.payload["principal_profile_digest"]
            != confirmation.principal_profile_digest
            or answer is None
            or answer.kind != "clarification.answer.understood"
            or answer.payload.get("request_event_id") != request.event_id
            or answer.payload.get("answer_sha256") != confirmation.answer_sha256
        ):
            raise ClarificationDenied("CONFIRMATION_BINDING_MISMATCH")
        profile = PrincipalModel(self.store).status()
        if (
            profile["profile_digest"] != confirmation.principal_profile_digest
            or (profile["profile"] or {}).get("principal_id")
            != confirmation.principal_id
        ):
            raise ClarificationDenied("PRINCIPAL_PROFILE_CHANGED")
        if self._presentation(events, request.event_id) is None:
            raise ClarificationDenied("REQUEST_NOT_PRESENTED")
        if _aware_time("request expiry", self.store.clock()) > _aware_time(
            "request expiry", request.payload["expires_at"]
        ):
            raise ClarificationDenied("REQUEST_EXPIRED")
        payload = {
            **confirmation.signed_payload(),
            "signature": confirmation.signature,
            "signature_scheme": "HMAC-SHA256",
            "request_event_id": request.event_id,
            "operator_authenticated": True,
            "resume_ready": bool(answer.payload.get("all_required_resolved")),
            "execution_authority_granted": False,
            "separate_ticket_required": bool(
                answer.payload.get("separate_ticket_required")
            ),
            "raw_confirmation_text_persisted": False,
            "raw_secret_persisted": False,
        }

        def guard(current: list[Event]) -> str | None:
            active = self._latest_requests(current).get(confirmation.request_id)
            if active is None or active.event_id != request.event_id:
                return "STALE_REQUEST_REVISION"
            if PrincipalModel(self.store).status()["profile_digest"] != confirmation.principal_profile_digest:
                return "PRINCIPAL_PROFILE_CHANGED"
            if _aware_time("request expiry", self.store.clock()) > _aware_time(
                "request expiry", request.payload["expires_at"]
            ):
                return "REQUEST_EXPIRED"
            existing = self._confirmation(current, request.event_id)
            if existing is not None:
                return "CONFIRMATION_ALREADY_EXISTS"
            return None

        try:
            event, created, rejection = self.store.append_once_result_guarded(
                "clarification.answer.confirmed",
                confirmation.id,
                payload,
                guard=guard,
                strict_existing_payload=True,
            )
        except ValueError as error:
            raise ClarificationDenied("CONFIRMATION_ID_CONFLICT") from error
        if rejection == "CONFIRMATION_ALREADY_EXISTS":
            existing = self._confirmation(self.store.events(), request.event_id)
            if existing is not None and canonical_json(existing.payload) == canonical_json(payload):
                event = existing
                created = False
                rejection = None
            else:
                raise ClarificationDenied("CONFIRMATION_ALREADY_EXISTS")
        if rejection is not None:
            raise ClarificationDenied(rejection)
        if event is None:
            raise RuntimeError("clarification confirmation was not persisted")
        if canonical_json(event.payload) != canonical_json(payload):
            raise ClarificationDenied("CONFIRMATION_ID_CONFLICT")
        return {
            **dict(event.payload),
            "event_id": event.event_id,
            "confirmed": created,
            "reason": "CONFIRMED" if created else "DUPLICATE_CONFIRMATION",
        }

    def resolution(self, request_id: str) -> dict[str, Any]:
        identifier = _identifier("request id", request_id)
        events = self.store.events()
        request = self._latest_requests(events).get(identifier)
        if request is None:
            raise ClarificationDenied("REQUEST_NOT_FOUND")
        profile = PrincipalModel(self.store).status()
        if (
            profile["profile_digest"] != request.payload["principal_profile_digest"]
            or (profile["profile"] or {}).get("principal_id")
            != request.payload["principal_id"]
        ):
            raise ClarificationDenied("PRINCIPAL_PROFILE_CHANGED")
        if _aware_time("request expiry", self.store.clock()) > _aware_time(
            "request expiry", request.payload["expires_at"]
        ):
            raise ClarificationDenied("REQUEST_EXPIRED")
        answer = self._understanding(events, request.event_id)
        confirmation = self._confirmation(events, request.event_id)
        if answer is None:
            return {
                "resolved": False,
                "confirmed": False,
                "request_id": identifier,
                "request_revision": request.payload["revision"],
                "execution_authority_granted": False,
            }
        confirmed = confirmation is not None
        resume_ready = bool(answer.payload["resume_ready"]) or (
            confirmed and bool(answer.payload.get("all_required_resolved"))
        )
        return {
            "resolved": resume_ready,
            "confirmed": confirmed,
            "request_id": identifier,
            "request_revision": request.payload["revision"],
            "request_sha256": request.payload["request_sha256"],
            "answer_event_id": answer.event_id,
            "answer_sha256": answer.payload["answer_sha256"],
            "answers": list(answer.payload["answers"]),
            "resume_plan_id": request.payload["resume_plan_id"],
            "resume_plan_sha256": request.payload["resume_plan_sha256"],
            "resume_ready": resume_ready,
            "execution_authority_granted": False,
            "separate_ticket_required": bool(
                answer.payload["separate_ticket_required"]
            ),
        }

    def status(self) -> dict[str, Any]:
        events = self.store.events()
        latest = self._latest_requests(events)
        understood = [
            event for event in events if event.kind == "clarification.answer.understood"
        ]
        confirmed = [
            event for event in events if event.kind == "clarification.answer.confirmed"
        ]
        return {
            "requested": len(
                [event for event in events if event.kind == "clarification.requested"]
            ),
            "latest_revisions": len(latest),
            "presented": sum(
                self._presentation(events, event.event_id) is not None
                for event in events
                if event.kind == "clarification.requested"
            ),
            "understood": len(understood),
            "confirmed": len(confirmed),
            "pending_confirmation": sum(
                event.payload.get("confirmation_required") is True
                and self._confirmation(events, str(event.payload["request_event_id"]))
                is None
                for event in understood
            ),
            "open_unanswered": sum(
                self._understanding(events, event.event_id) is None
                for event in latest.values()
            ),
            "execution_authority_granted_by_answers": False,
            "raw_answer_text_persisted": False,
            "raw_secret_persisted": False,
            "content_in_status": False,
        }

    def context(self, *, max_chars: int = 3000) -> str:
        events = self.store.events()
        lines: list[str] = []
        for request in self._latest_requests(events).values():
            answer = self._understanding(events, request.event_id)
            if answer is None:
                lines.append(
                    f"CCT important clarification pending: {request.payload['request_id']} "
                    f"r{request.payload['revision']} request={request.payload['request_sha256']}"
                )
                for question in request.payload["questions"]:
                    options = (
                        " choices=" + "/".join(question["options"])
                        if question["answer_type"] == "OPTION"
                        else ""
                    )
                    lines.append(
                        f"- {question['id']} [{question['kind']}]: {question['prompt']}{options}"
                    )
                lines.append(
                    "Mike must reply to the exact emitted Telegram clarification using only "
                    "listed option values. The gateway records the allowlisted answer; no "
                    "model-callable tool may assert or infer it."
                )
                continue
            visible = [
                row
                for row in answer.payload["answers"]
                if row["visibility"] == "typed_nonsecret_memory"
            ]
            if visible:
                lines.append("Typed operator understanding (non-authoritative, non-secret):")
                lines.extend(f"- {row['question_id']}={row['value']}" for row in visible)
            if answer.payload["confirmation_required"] and self._confirmation(
                events, request.event_id
            ) is None:
                lines.append(
                    f"- {request.payload['request_id']} exact confirmation pending; no effect "
                    "authority or protected-fact reuse granted."
                )
                lines.append(
                    f"  Reply to the original clarification message with: CCT CONFIRM "
                    f"{request.payload['request_id']} r{request.payload['revision']} "
                    f"request={request.payload['request_sha256']} "
                    f"answer={answer.payload['answer_sha256']}"
                )
        return "\n".join(lines)[:max_chars]
