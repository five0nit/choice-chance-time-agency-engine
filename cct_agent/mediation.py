"""Fail-closed Hermes tool-execution mediation."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from hashlib import sha256
import re
from typing import Any, Protocol

from .execution_tickets import ExecutionTicketAuthority, TicketAuthorityDenied
from .mediation_outcomes import (
    OutcomeResultInvalid,
    OutcomeVerification,
    OutcomeVerifierRegistry,
    ParsedOutcomeResult,
    VerificationContext,
)
from .store import Event, canonical_json


MEDIATION_SCHEMA_VERSION = "cct.tool_execution.v1"
DENIAL_RECEIPT_SCHEMA_VERSION = "cct.tool_execution.denial.v1"
OUTCOME_RECEIPT_SCHEMA_VERSION = "cct.tool_execution.outcome.v1"
COMPLETION_RECEIPT_SCHEMA_VERSION = "cct.tool_execution.completion.v1"
RECOVERY_RECEIPT_SCHEMA_VERSION = "cct.tool_execution.recovery.v1"
MAX_MEDIATED_TOOLS = 32
MAX_TOOL_NAME_CHARS = 128
_TOOL_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ReceiptStore(Protocol):
    def append(self, kind: str, payload: Mapping[str, Any]) -> object: ...

    def append_once_result(
        self, kind: str, logical_key: str, payload: Mapping[str, Any]
    ) -> tuple[Event, bool]: ...

    def events(self, kind: str | None = None) -> list[Event]: ...


def parse_mediated_tools(value: object) -> frozenset[str]:
    """Validate the explicit host-selected tool list without creating defaults."""

    if not isinstance(value, list):
        raise ValueError("mediated_tools must be a list")
    if len(value) > MAX_MEDIATED_TOOLS:
        raise ValueError(
            f"mediated_tools must contain at most {MAX_MEDIATED_TOOLS} identifiers"
        )
    tools: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _TOOL_IDENTIFIER.fullmatch(item):
            raise ValueError(
                "mediated_tools entries must be 1-128 character tool identifiers"
            )
        if item in tools:
            raise ValueError("mediated_tools must not contain duplicate identifiers")
        tools.append(item)
    return frozenset(tools)


class ToolExecutionMediator:
    """Gate configured tools and dispatch one receipt-backed exact invocation."""

    def __init__(
        self,
        store: ReceiptStore,
        mediated_tools: frozenset[str],
        *,
        configuration_valid: bool = True,
        outcome_verifiers: OutcomeVerifierRegistry | None = None,
    ) -> None:
        self.store = store
        self.mediated_tools = mediated_tools
        self.configuration_valid = configuration_valid
        self.ticket_authority = ExecutionTicketAuthority(store)  # type: ignore[arg-type]
        self.outcome_verifiers = outcome_verifiers or OutcomeVerifierRegistry()

    def __call__(self, **callback: Any) -> Any:
        tool_name = callback.get("tool_name")
        if not self.configuration_valid:
            bounded_tool_name = (
                tool_name
                if isinstance(tool_name, str) and _TOOL_IDENTIFIER.fullmatch(tool_name)
                else None
            )
            try:
                return self._deny(
                    bounded_tool_name,
                    callback.get("args"),
                    reason_codes=["POLICY_CONFIGURATION_INVALID"],
                    configuration_valid=False,
                )
            except Exception:
                return self._internal_denial(
                    bounded_tool_name,
                    reason_codes=[
                        "POLICY_CONFIGURATION_INVALID",
                        "MEDIATION_INTERNAL_ERROR",
                    ],
                    configuration_valid=False,
                )
        if isinstance(tool_name, str):
            try:
                selected = tool_name in self.mediated_tools
            except Exception:
                if self.mediated_tools:
                    return self._internal_denial(None)
                return self._next(callback)
            if not selected:
                return self._next(callback)
            try:
                return self._mediate(tool_name, callback.get("args"), callback)
            except Exception:
                return self._internal_denial(tool_name)

        if self.mediated_tools:
            try:
                return self._deny(None, callback.get("args"), malformed_tool=True)
            except Exception:
                return self._internal_denial(None)
        return self._next(callback)

    @staticmethod
    def _next(callback: Mapping[str, Any]) -> Any:
        next_call: Callable[[], Any] = callback["next_call"]
        return next_call()

    def _deny(
        self,
        tool_name: str | None,
        arguments: object,
        *,
        malformed_tool: bool = False,
        reason_codes: list[str] | None = None,
        ticket_id: str | None = None,
        configuration_valid: bool | None = None,
    ) -> str:
        reasons = (
            list(reason_codes)
            if reason_codes is not None
            else ([] if malformed_tool else ["TICKET_REQUIRED"])
        )
        arguments_sha256: str | None = None
        if not isinstance(arguments, dict):
            reasons.append("MALFORMED_CALL")
        else:
            try:
                arguments_sha256 = sha256(
                    canonical_json(arguments).encode("utf-8")
                ).hexdigest()
            except Exception:
                reasons.append("MALFORMED_CALL")
        if malformed_tool and "MALFORMED_CALL" not in reasons:
            reasons.append("MALFORMED_CALL")

        receipt: dict[str, Any] = {
            "schema_version": DENIAL_RECEIPT_SCHEMA_VERSION,
            "tool_name": tool_name,
            "arguments_sha256": arguments_sha256,
            "reason_codes": list(reasons),
            "blocked": True,
            "downstream_called": False,
            "raw_arguments_persisted": False,
        }
        if ticket_id is not None:
            receipt["ticket_id"] = ticket_id
        if configuration_valid is not None:
            receipt["configuration_valid"] = configuration_valid
        receipt_persisted = False
        try:
            self.store.append("mediation.tool.denied", receipt)
            receipt_persisted = True
        except Exception:
            reasons.append("RECEIPT_PERSISTENCE_FAILED")

        mediation: dict[str, Any] = {
            "schema_version": MEDIATION_SCHEMA_VERSION,
            "selected": True,
            "tool_name": tool_name,
            "arguments_sha256": arguments_sha256,
            "receipt_persisted": receipt_persisted,
            "raw_arguments_persisted": False,
        }
        if ticket_id is not None:
            mediation["ticket_id"] = ticket_id
        if configuration_valid is not None:
            mediation["configuration_valid"] = configuration_valid
        return canonical_json(
            {
                "success": False,
                "blocked": True,
                "error": {
                    "code": "CCT_MEDIATION_DENIED",
                    "reasons": reasons,
                },
                "mediation": mediation,
            }
        )

    def _mediate(
        self,
        tool_name: str,
        arguments: object,
        callback: Mapping[str, Any],
    ) -> Any:
        if not isinstance(arguments, dict):
            return self._deny(tool_name, arguments)
        if not callable(callback.get("next_call")):
            return self._deny(
                tool_name,
                arguments,
                reason_codes=["MALFORMED_CALL"],
            )
        try:
            arguments_sha256 = sha256(
                canonical_json(arguments).encode("utf-8")
            ).hexdigest()
        except Exception:
            return self._deny(tool_name, arguments)
        raw_ticket_id = arguments.get("execution_ticket_id")
        if raw_ticket_id is None:
            return self._deny(tool_name, arguments)
        if not isinstance(raw_ticket_id, str) or not _TOOL_IDENTIFIER.fullmatch(
            raw_ticket_id
        ):
            return self._deny(
                tool_name,
                arguments,
                reason_codes=["MALFORMED_TICKET"],
            )
        try:
            claim = self.ticket_authority.claim_dispatch(
                ticket_id=raw_ticket_id,
                tool_name=tool_name,
                arguments_sha256=arguments_sha256,
                registered_verifier_ids=self.outcome_verifiers.registered_ids,
            )
        except TicketAuthorityDenied as error:
            return self._deny(
                tool_name,
                arguments,
                reason_codes=[error.reason_code],
                ticket_id=raw_ticket_id,
            )
        except Exception:
            return self._deny(
                tool_name,
                arguments,
                reason_codes=["MEDIATION_INTERNAL_ERROR"],
                ticket_id=raw_ticket_id,
            )
        if claim["created"] is not True:
            return self._recover(claim)
        return self._dispatch(claim, callback)

    def _dispatch(self, claim: Mapping[str, Any], callback: Mapping[str, Any]) -> Any:
        context = self._verification_context(claim)
        try:
            raw_result = self._next(callback)
        except Exception as error:
            try:
                reconciled = self.outcome_verifiers.reconcile(
                    str(claim["verifier_id"]), context
                )
            except Exception:
                reconciled = None
            if reconciled is not None:
                raw_result, parsed, verification, proof_id = reconciled
                outcome = self._persist_outcome(
                    claim,
                    parsed=parsed,
                    verification=verification,
                    downstream_called=True,
                    adopted_after_restart=False,
                    verification_status=verification.status,
                    idempotency_proof_id=proof_id,
                )
                self._complete(outcome)
                return raw_result
            outcome = self._persist_outcome(
                claim,
                parsed=None,
                verification=None,
                downstream_called=True,
                adopted_after_restart=False,
                verification_status="downstream-exception",
                exception_type=type(error).__name__,
            )
            self._complete(outcome)
            return self._downstream_error_result(claim)

        parsed: ParsedOutcomeResult | None = None
        try:
            parsed = self.outcome_verifiers.parse(raw_result)
            verification = self.outcome_verifiers.verify_parsed(
                str(claim["verifier_id"]), parsed, context
            )
        except OutcomeResultInvalid as error:
            outcome = self._persist_outcome(
                claim,
                parsed=None,
                verification=None,
                downstream_called=True,
                adopted_after_restart=False,
                verification_status=error.reason_code.lower().replace("_", "-"),
                result_kind=error.result_kind,
                result_bytes=error.result_bytes,
                result_sha256=error.result_sha256,
                exception_type=type(error).__name__,
            )
            self._complete(outcome)
            return self._verification_error_result(claim, outcome)
        except Exception as error:
            outcome = self._persist_outcome(
                claim,
                parsed=parsed,
                verification=None,
                downstream_called=True,
                adopted_after_restart=False,
                verification_status="verifier-error",
                exception_type=type(error).__name__,
            )
            self._complete(outcome)
            return self._verification_error_result(claim, outcome)

        outcome = self._persist_outcome(
            claim,
            parsed=parsed,
            verification=verification,
            downstream_called=True,
            adopted_after_restart=False,
            verification_status=verification.status,
        )
        self._complete(outcome)
        if verification.verified:
            return raw_result
        return self._verification_error_result(claim, outcome)

    def _recover(self, claim: Mapping[str, Any]) -> Any:
        ticket_id = str(claim["ticket_id"])
        outcome = self._event_for_ticket("mediation.tool.outcome", ticket_id)
        if outcome is not None:
            self._complete(outcome)
            return self._recovered_result(claim, outcome)

        context = self._verification_context(claim)
        registration = self.outcome_verifiers.registration(str(claim["verifier_id"]))
        if (
            registration.reconcile is None
            or registration.idempotency_proof_id is None
        ):
            return self._recovery_blocked(
                claim,
                ["CLAIM_WITHOUT_RECEIPT", "IDEMPOTENCY_PROOF_REQUIRED"],
                idempotency_proof_id=None,
            )
        try:
            reconciled = self.outcome_verifiers.reconcile(
                str(claim["verifier_id"]), context
            )
        except Exception:
            return self._recovery_blocked(
                claim,
                ["CLAIM_WITHOUT_RECEIPT", "RECONCILIATION_FAILED"],
                idempotency_proof_id=registration.idempotency_proof_id,
            )
        if reconciled is None:
            return self._recovery_blocked(
                claim,
                ["CLAIM_WITHOUT_RECEIPT", "EFFECT_NOT_OBSERVED"],
                idempotency_proof_id=registration.idempotency_proof_id,
            )
        raw_result, parsed, verification, proof_id = reconciled
        outcome = self._persist_outcome(
            claim,
            parsed=parsed,
            verification=verification,
            downstream_called=False,
            adopted_after_restart=True,
            verification_status=verification.status,
            idempotency_proof_id=proof_id,
        )
        self._complete(outcome)
        return raw_result

    def _persist_outcome(
        self,
        claim: Mapping[str, Any],
        *,
        parsed: ParsedOutcomeResult | None,
        verification: OutcomeVerification | None,
        downstream_called: bool,
        adopted_after_restart: bool,
        verification_status: str,
        result_kind: str | None = None,
        result_bytes: int | None = None,
        result_sha256: str | None = None,
        idempotency_proof_id: str | None = None,
        exception_type: str | None = None,
    ) -> Event:
        payload: dict[str, Any] = {
            "schema_version": OUTCOME_RECEIPT_SCHEMA_VERSION,
            "ticket_id": claim["ticket_id"],
            "claim_event_id": claim["event_id"],
            "tool_name": claim["tool_name"],
            "arguments_sha256": claim["arguments_sha256"],
            "verifier_id": claim["verifier_id"],
            "idempotency_key": claim["idempotency_key"],
            "downstream_called": downstream_called,
            "adopted_after_restart": adopted_after_restart,
            "result_kind": parsed.kind if parsed is not None else result_kind,
            "result_bytes": parsed.byte_count if parsed is not None else result_bytes,
            "result_sha256": parsed.sha256 if parsed is not None else result_sha256,
            "verified": verification.verified if verification is not None else False,
            "effect_observed": (
                verification.effect_observed if verification is not None else False
            ),
            "verification_status": verification_status,
            "effect_id": verification.effect_id if verification is not None else None,
            "evidence_sha256": (
                verification.evidence_sha256 if verification is not None else None
            ),
            "idempotency_proof_id": idempotency_proof_id,
            "raw_result_persisted": False,
            "raw_arguments_persisted": False,
            "credentials_persisted": False,
        }
        if exception_type is not None:
            payload["exception_type"] = self._bounded_exception_type(exception_type)
        event, _created = self.store.append_once_result(
            "mediation.tool.outcome",
            str(claim["ticket_id"]),
            payload,
        )
        return event

    def _complete(self, outcome: Event) -> Event:
        payload = {
            "schema_version": COMPLETION_RECEIPT_SCHEMA_VERSION,
            "ticket_id": outcome.payload["ticket_id"],
            "claim_event_id": outcome.payload["claim_event_id"],
            "outcome_event_id": outcome.event_id,
            "tool_name": outcome.payload["tool_name"],
            "verified": outcome.payload["verified"],
            "effect_observed": outcome.payload["effect_observed"],
            "verification_status": outcome.payload["verification_status"],
            "downstream_called": outcome.payload["downstream_called"],
            "adopted_after_restart": outcome.payload["adopted_after_restart"],
            "raw_result_persisted": False,
            "raw_arguments_persisted": False,
        }
        event, _created = self.store.append_once_result(
            "mediation.tool.completed",
            str(outcome.payload["ticket_id"]),
            payload,
        )
        return event

    def _recovery_blocked(
        self,
        claim: Mapping[str, Any],
        reasons: list[str],
        *,
        idempotency_proof_id: str | None,
    ) -> str:
        payload = {
            "schema_version": RECOVERY_RECEIPT_SCHEMA_VERSION,
            "ticket_id": claim["ticket_id"],
            "claim_event_id": claim["event_id"],
            "tool_name": claim["tool_name"],
            "arguments_sha256": claim["arguments_sha256"],
            "verifier_id": claim["verifier_id"],
            "idempotency_key": claim["idempotency_key"],
            "reason_codes": list(reasons),
            "downstream_called": False,
            "effect_retry_permitted": False,
            "idempotency_proof_id": idempotency_proof_id,
            "raw_result_persisted": False,
            "raw_arguments_persisted": False,
        }
        event, _created = self.store.append_once_result(
            "mediation.tool.recovery_blocked",
            str(claim["ticket_id"]),
            payload,
        )
        return canonical_json(
            {
                "success": False,
                "blocked": True,
                "error": {
                    "code": "CCT_MEDIATION_RECOVERY_REQUIRED",
                    "reasons": list(event.payload["reason_codes"]),
                },
                "mediation": {
                    "schema_version": MEDIATION_SCHEMA_VERSION,
                    "selected": True,
                    "tool_name": claim["tool_name"],
                    "arguments_sha256": claim["arguments_sha256"],
                    "ticket_id": claim["ticket_id"],
                    "claim_event_id": claim["event_id"],
                    "downstream_called": False,
                    "effect_retry_permitted": False,
                    "receipt_persisted": True,
                    "raw_arguments_persisted": False,
                },
            }
        )

    def _recovered_result(self, claim: Mapping[str, Any], outcome: Event) -> str:
        verified = outcome.payload.get("verified") is True
        result: dict[str, Any] = {
            "success": verified,
            "blocked": not verified,
            "mediation": {
                "schema_version": MEDIATION_SCHEMA_VERSION,
                "selected": True,
                "tool_name": claim["tool_name"],
                "arguments_sha256": claim["arguments_sha256"],
                "ticket_id": claim["ticket_id"],
                "claim_event_id": claim["event_id"],
                "outcome_event_id": outcome.event_id,
                "verified": verified,
                "effect_observed": outcome.payload.get("effect_observed") is True,
                "recovered_after_restart": True,
                "outcome_receipt_adopted": True,
                "downstream_called": False,
                "effect_retry_permitted": False,
                "raw_result_persisted": False,
                "raw_arguments_persisted": False,
            },
        }
        if not verified:
            result["error"] = {
                "code": "CCT_MEDIATION_OUTCOME_UNVERIFIED",
                "reasons": [
                    str(outcome.payload.get("verification_status", "OUTCOME_UNVERIFIED"))
                    .upper()
                    .replace("-", "_")
                ],
            }
        return canonical_json(result)

    @staticmethod
    def _verification_context(claim: Mapping[str, Any]) -> VerificationContext:
        return VerificationContext(
            ticket_id=claim["ticket_id"],
            claim_event_id=claim["event_id"],
            tool_name=claim["tool_name"],
            arguments_sha256=claim["arguments_sha256"],
            verifier_id=claim["verifier_id"],
            idempotency_key=claim["idempotency_key"],
            goal_id=claim["goal_id"],
            plan_id=claim["plan_id"],
            plan_hash=claim["plan_hash"],
            stage=claim["stage"],
            attempt=claim["attempt"],
            capability=claim["capability"],
            scope=claim["scope"],
        )

    def _event_for_ticket(self, kind: str, ticket_id: str) -> Event | None:
        return next(
            (
                event
                for event in reversed(self.store.events(kind))
                if event.payload.get("ticket_id") == ticket_id
            ),
            None,
        )

    @staticmethod
    def _bounded_exception_type(value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", value):
            return "Exception"
        return value

    @staticmethod
    def _downstream_error_result(claim: Mapping[str, Any]) -> str:
        return canonical_json(
            {
                "success": False,
                "blocked": True,
                "error": {
                    "code": "CCT_MEDIATION_DOWNSTREAM_ERROR",
                    "reasons": ["DOWNSTREAM_EXCEPTION"],
                },
                "mediation": {
                    "schema_version": MEDIATION_SCHEMA_VERSION,
                    "selected": True,
                    "tool_name": claim["tool_name"],
                    "arguments_sha256": claim["arguments_sha256"],
                    "ticket_id": claim["ticket_id"],
                    "claim_event_id": claim["event_id"],
                    "downstream_called": True,
                    "effect_retry_permitted": False,
                    "raw_arguments_persisted": False,
                },
            }
        )

    @staticmethod
    def _verification_error_result(
        claim: Mapping[str, Any], outcome: Event
    ) -> str:
        reason = (
            str(outcome.payload.get("verification_status", "OUTCOME_UNVERIFIED"))
            .upper()
            .replace("-", "_")
        )
        return canonical_json(
            {
                "success": False,
                "blocked": True,
                "error": {
                    "code": "CCT_MEDIATION_VERIFICATION_FAILED",
                    "reasons": [reason],
                },
                "mediation": {
                    "schema_version": MEDIATION_SCHEMA_VERSION,
                    "selected": True,
                    "tool_name": claim["tool_name"],
                    "arguments_sha256": claim["arguments_sha256"],
                    "ticket_id": claim["ticket_id"],
                    "claim_event_id": claim["event_id"],
                    "outcome_event_id": outcome.event_id,
                    "downstream_called": True,
                    "verified": False,
                    "effect_retry_permitted": False,
                    "raw_result_persisted": False,
                    "raw_arguments_persisted": False,
                },
            }
        )

    @staticmethod
    def _internal_denial(
        tool_name: str | None,
        *,
        reason_codes: list[str] | None = None,
        configuration_valid: bool | None = None,
    ) -> str:
        mediation: dict[str, Any] = {
            "schema_version": MEDIATION_SCHEMA_VERSION,
            "selected": True,
            "tool_name": tool_name,
            "arguments_sha256": None,
            "receipt_persisted": False,
            "raw_arguments_persisted": False,
        }
        if configuration_valid is not None:
            mediation["configuration_valid"] = configuration_valid
        return canonical_json(
            {
                "success": False,
                "blocked": True,
                "error": {
                    "code": "CCT_MEDIATION_DENIED",
                    "reasons": reason_codes
                    or ["TICKET_REQUIRED", "MEDIATION_INTERNAL_ERROR"],
                },
                "mediation": mediation,
            }
        )
