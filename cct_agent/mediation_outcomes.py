"""Host-registered outcome verification and bounded result parsing."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Callable

from .store import canonical_json


MAX_OUTCOME_RESULT_BYTES = 262_144
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class OutcomeResultInvalid(ValueError):
    """A downstream result cannot enter a registered verifier."""

    def __init__(
        self,
        reason_code: str,
        *,
        result_kind: str | None = None,
        result_bytes: int | None = None,
        result_sha256: str | None = None,
    ) -> None:
        self.reason_code = reason_code
        self.result_kind = result_kind
        self.result_bytes = result_bytes
        self.result_sha256 = result_sha256
        super().__init__(reason_code)


def _identifier(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a 1-160 character identifier")
    return value


def _digest(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class VerificationContext:
    """Bound ticket and claim metadata exposed to a trusted host verifier."""

    ticket_id: str
    claim_event_id: str
    tool_name: str
    arguments_sha256: str
    verifier_id: str
    idempotency_key: str
    goal_id: str
    plan_id: str
    plan_hash: str
    stage: str
    attempt: int
    capability: str
    scope: str

    def __post_init__(self) -> None:
        for name in (
            "ticket_id",
            "claim_event_id",
            "tool_name",
            "verifier_id",
            "idempotency_key",
            "goal_id",
            "plan_id",
            "stage",
            "capability",
        ):
            _identifier(name, getattr(self, name))
        _digest("arguments_sha256", self.arguments_sha256)
        _digest("plan_hash", self.plan_hash)
        if isinstance(self.attempt, bool) or not isinstance(self.attempt, int):
            raise ValueError("attempt must be an integer")
        if self.attempt < 1:
            raise ValueError("attempt must be at least 1")
        if not isinstance(self.scope, str) or not self.scope or len(self.scope) > 512:
            raise ValueError("scope must be a bounded string")


@dataclass(frozen=True, slots=True)
class OutcomeVerification:
    """Privacy-bounded host verification result."""

    verified: bool
    effect_observed: bool
    status: str
    effect_id: str | None = None
    evidence_sha256: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.verified, bool):
            raise ValueError("verified must be a boolean")
        if not isinstance(self.effect_observed, bool):
            raise ValueError("effect_observed must be a boolean")
        _identifier("verification status", self.status)
        if self.effect_id is not None:
            _identifier("effect_id", self.effect_id)
        if self.evidence_sha256 is not None:
            _digest("evidence_sha256", self.evidence_sha256)
        if self.verified and not self.effect_observed:
            raise ValueError("verified outcome requires an observed effect")
        if self.verified and self.effect_id is None:
            raise ValueError("verified outcome requires effect_id")
        if self.verified and self.evidence_sha256 is None:
            raise ValueError("verified outcome requires evidence_sha256")
        if self.effect_id is not None and not self.effect_observed:
            raise ValueError("effect_id requires an observed effect")


@dataclass(frozen=True, slots=True)
class ParsedOutcomeResult:
    """Parsed result plus bounded metadata; raw bytes never enter CCT events."""

    value: object
    kind: str
    byte_count: int
    sha256: str


Verifier = Callable[[object, VerificationContext], OutcomeVerification]
Reconciler = Callable[[VerificationContext], object | None]


@dataclass(frozen=True, slots=True)
class _VerifierRegistration:
    verifier_id: str
    verifier: Verifier
    reconcile: Reconciler | None
    idempotency_proof_id: str | None


class OutcomeVerifierRegistry:
    """Host-only verifier registry; callers cannot supply verifier code or IDs."""

    def __init__(self, *, maximum_result_bytes: int = MAX_OUTCOME_RESULT_BYTES) -> None:
        if (
            isinstance(maximum_result_bytes, bool)
            or not isinstance(maximum_result_bytes, int)
            or maximum_result_bytes < 1
            or maximum_result_bytes > MAX_OUTCOME_RESULT_BYTES
        ):
            raise ValueError(
                f"maximum_result_bytes must be 1-{MAX_OUTCOME_RESULT_BYTES}"
            )
        self.maximum_result_bytes = maximum_result_bytes
        self._registrations: dict[str, _VerifierRegistration] = {}

    @property
    def registered_ids(self) -> frozenset[str]:
        return frozenset(self._registrations)

    def register(
        self,
        verifier_id: str,
        verifier: Verifier,
        *,
        reconcile: Reconciler | None = None,
        idempotency_proof_id: str | None = None,
    ) -> None:
        identifier = _identifier("verifier_id", verifier_id)
        if identifier in self._registrations:
            raise ValueError(f"duplicate outcome verifier: {identifier}")
        if not callable(verifier):
            raise ValueError("verifier must be callable")
        if (reconcile is None) != (idempotency_proof_id is None):
            raise ValueError(
                "reconcile and idempotency_proof_id must be registered together"
            )
        if reconcile is not None and not callable(reconcile):
            raise ValueError("reconcile must be callable")
        proof = (
            _identifier("idempotency_proof_id", idempotency_proof_id)
            if idempotency_proof_id is not None
            else None
        )
        self._registrations[identifier] = _VerifierRegistration(
            verifier_id=identifier,
            verifier=verifier,
            reconcile=reconcile,
            idempotency_proof_id=proof,
        )

    def registration(self, verifier_id: str) -> _VerifierRegistration:
        identifier = _identifier("verifier_id", verifier_id)
        try:
            return self._registrations[identifier]
        except KeyError as error:
            raise KeyError(f"unregistered outcome verifier: {identifier}") from error

    def parse(self, raw_result: object) -> ParsedOutcomeResult:
        value: object
        kind: str
        if isinstance(raw_result, str):
            raw_bytes = raw_result.encode("utf-8")
            try:
                value = json.loads(raw_result)
            except json.JSONDecodeError:
                value = raw_result
                kind = "text"
            else:
                kind = self._json_kind(value)
        elif isinstance(raw_result, bytes):
            raw_bytes = raw_result
            value = raw_result
            kind = "bytes"
        elif raw_result is None or isinstance(
            raw_result, (dict, list, int, float, bool)
        ):
            try:
                encoded = canonical_json(raw_result)
            except (TypeError, ValueError) as error:
                raise OutcomeResultInvalid("RESULT_NOT_CANONICAL") from error
            raw_bytes = encoded.encode("utf-8")
            value = raw_result
            kind = self._json_kind(value)
        else:
            raise OutcomeResultInvalid("RESULT_TYPE_UNSUPPORTED")

        byte_count = len(raw_bytes)
        result_sha256 = sha256(raw_bytes).hexdigest()
        if byte_count > self.maximum_result_bytes:
            raise OutcomeResultInvalid(
                "RESULT_TOO_LARGE",
                result_kind=kind,
                result_bytes=byte_count,
                result_sha256=result_sha256,
            )
        return ParsedOutcomeResult(
            value=value,
            kind=kind,
            byte_count=byte_count,
            sha256=result_sha256,
        )

    def verify_parsed(
        self,
        verifier_id: str,
        parsed: ParsedOutcomeResult,
        context: VerificationContext,
    ) -> OutcomeVerification:
        registration = self.registration(verifier_id)
        verification = registration.verifier(parsed.value, context)
        if not isinstance(verification, OutcomeVerification):
            raise ValueError("registered verifier must return OutcomeVerification")
        return verification

    def verify(
        self,
        verifier_id: str,
        raw_result: object,
        context: VerificationContext,
    ) -> tuple[ParsedOutcomeResult, OutcomeVerification]:
        parsed = self.parse(raw_result)
        return parsed, self.verify_parsed(verifier_id, parsed, context)

    def reconcile(
        self,
        verifier_id: str,
        context: VerificationContext,
    ) -> tuple[object, ParsedOutcomeResult, OutcomeVerification, str] | None:
        registration = self.registration(verifier_id)
        if (
            registration.reconcile is None
            or registration.idempotency_proof_id is None
        ):
            return None
        raw_result = registration.reconcile(context)
        if raw_result is None:
            return None
        parsed, verification = self.verify(verifier_id, raw_result, context)
        if not verification.verified or not verification.effect_observed:
            return None
        return (
            raw_result,
            parsed,
            verification,
            registration.idempotency_proof_id,
        )

    @staticmethod
    def _json_kind(value: object) -> str:
        if isinstance(value, dict):
            return "json-object"
        if isinstance(value, list):
            return "json-array"
        return "json-scalar"
