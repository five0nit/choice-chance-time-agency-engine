"""Host-only authenticated-access scaffold for browser and computer-use sessions.

This module never resolves, receives, or types credential values. It binds a
verified opaque credential-use receipt to one explicit host route:

- ``browser_real_profile_snapshot`` for signed-in web work; or
- ``computer_use_existing_session`` for an already-authenticated native app.

The scaffold records preparation and readback only. A separate scoped host
ticket is still required before any browser or desktop action executes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Mapping, Sequence
import re

from .store import Event, EventStore, canonical_json


OPERATOR_AUTHENTICATED_ACCESS_PREPARED_SCHEMA_VERSION = (
    "cct.operator_authenticated_access.prepared.v1"
)
OPERATOR_AUTHENTICATED_ACCESS_READBACK_SCHEMA_VERSION = (
    "cct.operator_authenticated_access.readback.v1"
)
MAX_AUTHENTICATED_ACCESS_TARGETS = 64
AUTHENTICATED_ACCESS_ROUTES = frozenset(
    {"browser_real_profile_snapshot", "computer_use_existing_session"}
)
AUTHENTICATED_ACCESS_STATUSES = frozenset({"READY", "AUTH_HANDOFF_REQUIRED"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ROUTE_TARGET_KIND = {
    "browser_real_profile_snapshot": "web",
    "computer_use_existing_session": "native",
}


class AuthenticatedAccessDenied(PermissionError):
    """Fail-closed denial with one stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest(name: str, value: object) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _boolean(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _integer(name: str, value: object, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _hash(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class OperatorAuthenticatedAccessTarget:
    """Host registration for one credential-backed authenticated session route."""

    id: str
    target_kind: str
    route: str
    app_id: str
    consumer_id: str
    owner_principal_id: str
    allowed_purposes: tuple[str, ...]

    def __post_init__(self) -> None:
        for field in (
            "id",
            "target_kind",
            "route",
            "app_id",
            "consumer_id",
            "owner_principal_id",
        ):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if self.route not in AUTHENTICATED_ACCESS_ROUTES:
            raise ValueError("route is not an allowed authenticated-access route")
        if _ROUTE_TARGET_KIND[self.route] != self.target_kind:
            raise ValueError("route and target_kind are inconsistent")
        if not isinstance(self.allowed_purposes, (tuple, list)):
            raise ValueError("allowed_purposes must be an array")
        purposes = tuple(
            sorted({_identifier("allowed purpose", value) for value in self.allowed_purposes})
        )
        if not 1 <= len(purposes) <= 32:
            raise ValueError("allowed_purposes must contain 1-32 values")
        object.__setattr__(self, "allowed_purposes", purposes)


@dataclass(frozen=True, slots=True)
class OperatorAuthenticatedAccessPreview:
    target_id: str
    target_spec_sha256: str
    route: str
    app_id: str
    credential_receipt_event_id: str
    credential_receipt_sha256: str
    credential_handle_id: str
    consumer_id: str
    owner_principal_id: str
    purpose: str
    action_scope_sha256: str
    preview_sha256: str


@dataclass(frozen=True, slots=True)
class OperatorAuthenticatedAccessInvocation:
    operation_id: str
    target_id: str
    credential_receipt_event_id: str
    purpose: str
    action_scope_sha256: str
    expected_target_spec_sha256: str
    expected_credential_receipt_sha256: str
    expected_preview_sha256: str

    @classmethod
    def from_arguments(
        cls, arguments: Mapping[str, Any]
    ) -> "OperatorAuthenticatedAccessInvocation":
        if not isinstance(arguments, Mapping):
            raise ValueError("authenticated-access arguments must be an object")
        fields = {
            "operation_id",
            "target_id",
            "credential_receipt_event_id",
            "purpose",
            "action_scope_sha256",
            "expected_target_spec_sha256",
            "expected_credential_receipt_sha256",
            "expected_preview_sha256",
        }
        if set(arguments) != fields:
            raise ValueError("authenticated-access arguments require exact fields")
        return cls(
            operation_id=_identifier("operation_id", arguments["operation_id"]),
            target_id=_identifier("target_id", arguments["target_id"]),
            credential_receipt_event_id=_identifier(
                "credential_receipt_event_id",
                arguments["credential_receipt_event_id"],
            ),
            purpose=_identifier("purpose", arguments["purpose"]),
            action_scope_sha256=_digest(
                "action_scope_sha256", arguments["action_scope_sha256"]
            ),
            expected_target_spec_sha256=_digest(
                "expected_target_spec_sha256",
                arguments["expected_target_spec_sha256"],
            ),
            expected_credential_receipt_sha256=_digest(
                "expected_credential_receipt_sha256",
                arguments["expected_credential_receipt_sha256"],
            ),
            expected_preview_sha256=_digest(
                "expected_preview_sha256", arguments["expected_preview_sha256"]
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthenticatedAccessHostReadback:
    """Allowlisted host readback; raw window, page, and credential data stay outside."""

    operation_id: str
    prepared_event_id: str
    target_id: str
    target_spec_sha256: str
    route: str
    app_id: str
    status: str
    session_binding_sha256: str
    driver_receipt_sha256: str
    existing_session_ready: bool
    auth_handoff_required: bool
    foreground_unchanged: bool
    ui_action_count: int
    raw_secret_exposed: bool
    secret_input_performed: bool

    @classmethod
    def from_arguments(
        cls, arguments: Mapping[str, Any]
    ) -> "AuthenticatedAccessHostReadback":
        if not isinstance(arguments, Mapping):
            raise ValueError("authenticated-access readback must be an object")
        fields = {
            "operation_id",
            "prepared_event_id",
            "target_id",
            "target_spec_sha256",
            "route",
            "app_id",
            "status",
            "session_binding_sha256",
            "driver_receipt_sha256",
            "existing_session_ready",
            "auth_handoff_required",
            "foreground_unchanged",
            "ui_action_count",
            "raw_secret_exposed",
            "secret_input_performed",
        }
        if set(arguments) != fields:
            raise ValueError("authenticated-access readback requires exact fields")
        readback = cls(
            operation_id=_identifier("operation_id", arguments["operation_id"]),
            prepared_event_id=_identifier(
                "prepared_event_id", arguments["prepared_event_id"]
            ),
            target_id=_identifier("target_id", arguments["target_id"]),
            target_spec_sha256=_digest(
                "target_spec_sha256", arguments["target_spec_sha256"]
            ),
            route=_identifier("route", arguments["route"]),
            app_id=_identifier("app_id", arguments["app_id"]),
            status=_identifier("status", arguments["status"]),
            session_binding_sha256=_digest(
                "session_binding_sha256", arguments["session_binding_sha256"]
            ),
            driver_receipt_sha256=_digest(
                "driver_receipt_sha256", arguments["driver_receipt_sha256"]
            ),
            existing_session_ready=_boolean(
                "existing_session_ready", arguments["existing_session_ready"]
            ),
            auth_handoff_required=_boolean(
                "auth_handoff_required", arguments["auth_handoff_required"]
            ),
            foreground_unchanged=_boolean(
                "foreground_unchanged", arguments["foreground_unchanged"]
            ),
            ui_action_count=_integer(
                "ui_action_count", arguments["ui_action_count"], minimum=0, maximum=0
            ),
            raw_secret_exposed=_boolean(
                "raw_secret_exposed", arguments["raw_secret_exposed"]
            ),
            secret_input_performed=_boolean(
                "secret_input_performed", arguments["secret_input_performed"]
            ),
        )
        readback.validate()
        return readback

    def validate(self) -> None:
        if self.route not in AUTHENTICATED_ACCESS_ROUTES:
            raise ValueError("readback route is not allowed")
        if self.status not in AUTHENTICATED_ACCESS_STATUSES:
            raise ValueError("readback status is not allowed")
        if self.raw_secret_exposed or self.secret_input_performed:
            raise ValueError("authenticated-access readback cannot report secret handling")
        if not self.foreground_unchanged:
            raise ValueError("authenticated-access preparation must preserve foreground")
        if self.status == "READY":
            if not self.existing_session_ready or self.auth_handoff_required:
                raise ValueError("READY readback is inconsistent")
        elif self.existing_session_ready or not self.auth_handoff_required:
            raise ValueError("AUTH_HANDOFF_REQUIRED readback is inconsistent")


@dataclass(frozen=True, slots=True)
class _RegisteredTarget:
    spec: OperatorAuthenticatedAccessTarget
    spec_sha256: str


class OperatorAuthenticatedAccessScaffold:
    """Prepare and verify host-only authenticated-session routing envelopes."""

    def __init__(
        self,
        store: EventStore,
        *,
        targets: Sequence[OperatorAuthenticatedAccessTarget],
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        principal_rows = store.events("principal.profile.installed")
        if not principal_rows:
            raise ValueError("authenticated-access targets require a principal profile")
        principal_id = principal_rows[-1].payload.get("profile", {}).get("principal_id")
        if not isinstance(principal_id, str):
            raise ValueError("installed principal profile is malformed")
        registrations: dict[str, _RegisteredTarget] = {}
        for target in targets:
            if (
                not isinstance(target, OperatorAuthenticatedAccessTarget)
                or target.id in registrations
            ):
                raise ValueError(
                    "targets must contain unique OperatorAuthenticatedAccessTarget values"
                )
            if target.owner_principal_id != principal_id:
                raise ValueError("authenticated-access target owner must match principal")
            registrations[target.id] = _RegisteredTarget(
                spec=target,
                spec_sha256=_hash(asdict(target)),
            )
        if not 1 <= len(registrations) <= MAX_AUTHENTICATED_ACCESS_TARGETS:
            raise ValueError(
                f"targets must contain 1-{MAX_AUTHENTICATED_ACCESS_TARGETS} registrations"
            )
        self.store = store
        self._targets: Mapping[str, _RegisteredTarget] = MappingProxyType(
            registrations
        )
        for registration in registrations.values():
            spec = registration.spec
            payload = {
                "schema_version": 1,
                "authority": "host_adapter",
                "target_id": spec.id,
                "target_kind": spec.target_kind,
                "route": spec.route,
                "app_id": spec.app_id,
                "consumer_id": spec.consumer_id,
                "owner_principal_id": spec.owner_principal_id,
                "allowed_purposes": list(spec.allowed_purposes),
                "target_spec_sha256": registration.spec_sha256,
                "raw_secret_persisted": False,
                "secret_digest_persisted": False,
                "secret_locator_persisted": False,
                "execution_authority_granted": False,
            }
            event, _created = self.store.append_once_result(
                "operator.authenticated_access.target_registered", spec.id, payload
            )
            if canonical_json(event.payload) != canonical_json(payload):
                raise ValueError(f"authenticated-access target changed: {spec.id}")

    def _target(self, target_id: str) -> _RegisteredTarget:
        registration = self._targets.get(_identifier("target_id", target_id))
        if registration is None:
            raise AuthenticatedAccessDenied("AUTHENTICATED_ACCESS_TARGET_NOT_REGISTERED")
        return registration

    def _credential_receipt(self, event_id: str) -> Event:
        event = self.store.event(_identifier("credential receipt event id", event_id))
        if event is None or event.kind != "operator.credential_use.completed":
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_NOT_FOUND")
        payload = event.payload
        if not (
            payload.get("schema_version") == "cct.operator_credential.receipt.v1"
            and payload.get("verification_passed") is True
            and payload.get("status") == "used"
            and payload.get("resolver_authenticated") is True
            and payload.get("resolver_readback_verified") is True
            and payload.get("resolver_effect_count") == 1
            and payload.get("raw_secret_persisted") is False
            and payload.get("raw_secret_exposed") is False
            and payload.get("secret_digest_persisted") is False
            and payload.get("secret_locator_persisted") is False
            and payload.get("resolver_raw_response_persisted") is False
            and payload.get("resolver_configuration_persisted") is False
        ):
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_NOT_VERIFIED")
        try:
            for key in (
                "ticket_id",
                "claim_event_id",
                "effect_id",
                "handle_id",
                "resolver_id",
                "provider",
                "consumer_id",
                "owner_principal_id",
                "purpose",
            ):
                _identifier(key, payload.get(key))
            for key in (
                "handle_spec_sha256",
                "authority_receipt_sha256",
                "preview_sha256",
                "provider_receipt_sha256",
            ):
                _digest(key, payload.get(key))
            _integer(
                "use_count", payload.get("use_count"), minimum=1, maximum=10_000
            )
            _integer("max_uses", payload.get("max_uses"), minimum=1, maximum=10_000)
        except ValueError as error:
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_MALFORMED") from error

        events = self.store.events()
        credential_completions = [
            row
            for row in events
            if row.kind == "operator.credential_use.completed"
            and row.payload.get("ticket_id") == payload["ticket_id"]
        ]
        if (
            len(credential_completions) != 1
            or credential_completions[0].event_id != event.event_id
        ):
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_PROVENANCE_INVALID")
        registrations = [
            row
            for row in events
            if row.kind == "operator.credential_handle.registered"
            and row.payload.get("handle_id") == payload["handle_id"]
        ]
        if len(registrations) != 1:
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_PROVENANCE_INVALID")
        registration = registrations[0].payload
        if not (
            registration.get("authority") == "host_adapter"
            and registration.get("handle_spec_sha256")
            == payload["handle_spec_sha256"]
            and registration.get("resolver_id") == payload["resolver_id"]
            and registration.get("provider") == payload["provider"]
            and registration.get("consumer_id") == payload["consumer_id"]
            and registration.get("owner_principal_id")
            == payload["owner_principal_id"]
            and registration.get("authority_receipt_sha256")
            == payload["authority_receipt_sha256"]
            and registration.get("resolver_authenticated") is True
            and payload["purpose"] in registration.get("allowed_purposes", [])
            and registration.get("max_uses") == payload["max_uses"]
            and registration.get("raw_secret_persisted") is False
            and registration.get("secret_digest_persisted") is False
            and registration.get("secret_locator_persisted") is False
        ):
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_PROVENANCE_INVALID")

        claims = [
            row
            for row in events
            if row.kind == "operator.credential_use.claimed"
            and row.payload.get("ticket_id") == payload["ticket_id"]
        ]
        if (
            len(claims) != 1
            or claims[0].event_id != payload["claim_event_id"]
        ):
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_PROVENANCE_INVALID")
        claim = claims[0]
        claim_payload = claim.payload
        shared = (
            "ticket_id",
            "effect_id",
            "handle_id",
            "handle_spec_sha256",
            "resolver_id",
            "provider",
            "consumer_id",
            "owner_principal_id",
            "purpose",
            "authority_receipt_sha256",
            "preview_sha256",
            "max_uses",
        )
        if not (
            claim_payload.get("schema_version")
            == "cct.operator_credential.claim.v1"
            and all(claim_payload.get(key) == payload.get(key) for key in shared)
            and claim_payload.get("verifier_id") == "operator-credential-readback"
            and claim_payload.get("raw_secret_persisted") is False
            and claim_payload.get("secret_digest_persisted") is False
            and claim_payload.get("secret_locator_persisted") is False
            and claim_payload.get("resolver_configuration_persisted") is False
        ):
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_PROVENANCE_INVALID")

        dispatches = [
            row
            for row in events
            if row.kind == "execution.ticket.consumed"
            and row.payload.get("ticket_id") == payload["ticket_id"]
        ]
        if len(dispatches) != 1:
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_PROVENANCE_INVALID")
        dispatch = dispatches[0]
        dispatch_payload = dispatch.payload
        if not (
            dispatch_payload.get("dispatch_claimed") is True
            and dispatch_payload.get("ticket_consumed") is True
            and dispatch_payload.get("tool_name") == "operator_credential_use"
            and dispatch_payload.get("capability") == "operator.credential"
            and dispatch_payload.get("scope")
            == f"operator/credential/{payload['handle_id']}"
            and dispatch_payload.get("verifier_id") == "operator-credential-readback"
            and dispatch_payload.get("idempotency_key") == payload["ticket_id"]
            and dispatch_payload.get("action_budget") == 1
            and dispatch_payload.get("byte_budget") == 0
            and dispatch_payload.get("value_budget_microunits") == 0
            and dispatch_payload.get("credentials_persisted") is False
            and dispatch_payload.get("raw_arguments_persisted") is False
        ):
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_PROVENANCE_INVALID")

        outcomes = [
            row
            for row in events
            if row.kind == "mediation.tool.outcome"
            and row.payload.get("ticket_id") == payload["ticket_id"]
        ]
        if len(outcomes) != 1:
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_PROVENANCE_INVALID")
        outcome = outcomes[0]
        outcome_payload = outcome.payload
        if not (
            outcome_payload.get("claim_event_id") == dispatch.event_id
            and outcome_payload.get("tool_name") == "operator_credential_use"
            and outcome_payload.get("verifier_id") == "operator-credential-readback"
            and outcome_payload.get("verified") is True
            and outcome_payload.get("verification_status") == "verified"
            and outcome_payload.get("effect_observed") is True
            and outcome_payload.get("effect_id") == payload["effect_id"]
            and outcome_payload.get("evidence_sha256")
            == payload["provider_receipt_sha256"]
            and outcome_payload.get("credentials_persisted") is False
            and outcome_payload.get("raw_arguments_persisted") is False
            and outcome_payload.get("raw_result_persisted") is False
        ):
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_PROVENANCE_INVALID")

        completions = [
            row
            for row in events
            if row.kind == "mediation.tool.completed"
            and row.payload.get("ticket_id") == payload["ticket_id"]
        ]
        if len(completions) != 1:
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_PROVENANCE_INVALID")
        completion = completions[0].payload
        if not (
            completion.get("claim_event_id") == dispatch.event_id
            and completion.get("outcome_event_id") == outcome.event_id
            and completion.get("tool_name") == "operator_credential_use"
            and completion.get("verified") is True
            and completion.get("verification_status") == "verified"
            and completion.get("effect_observed") is True
            and completion.get("raw_arguments_persisted") is False
            and completion.get("raw_result_persisted") is False
        ):
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_PROVENANCE_INVALID")
        return event

    def preview(
        self,
        *,
        target_id: str,
        credential_receipt_event_id: str,
        purpose: str,
        action_scope_sha256: str,
    ) -> OperatorAuthenticatedAccessPreview:
        if self.store.verify_chain().get("valid") is not True:
            raise AuthenticatedAccessDenied("LEDGER_CHAIN_INVALID")
        target = self._target(target_id)
        purpose = _identifier("purpose", purpose)
        action_scope_sha256 = _digest("action_scope_sha256", action_scope_sha256)
        if purpose not in target.spec.allowed_purposes:
            raise AuthenticatedAccessDenied("AUTHENTICATED_ACCESS_PURPOSE_DENIED")
        receipt = self._credential_receipt(credential_receipt_event_id)
        payload = receipt.payload
        if (
            payload.get("consumer_id") != target.spec.consumer_id
            or payload.get("owner_principal_id") != target.spec.owner_principal_id
            or payload.get("purpose") != purpose
        ):
            raise AuthenticatedAccessDenied("CREDENTIAL_RECEIPT_BINDING_MISMATCH")
        credential_receipt_sha256 = _hash(payload)
        material = {
            "schema_version": 1,
            "target_id": target.spec.id,
            "target_spec_sha256": target.spec_sha256,
            "route": target.spec.route,
            "app_id": target.spec.app_id,
            "credential_receipt_event_id": receipt.event_id,
            "credential_receipt_sha256": credential_receipt_sha256,
            "credential_handle_id": payload["handle_id"],
            "consumer_id": payload["consumer_id"],
            "owner_principal_id": payload["owner_principal_id"],
            "purpose": purpose,
            "action_scope_sha256": action_scope_sha256,
            "secret_input_allowed": False,
            "auth_handoff_policy": "user_required",
            "host_ticket_required": True,
            "execution_authority_granted": False,
        }
        return OperatorAuthenticatedAccessPreview(
            target_id=target.spec.id,
            target_spec_sha256=target.spec_sha256,
            route=target.spec.route,
            app_id=target.spec.app_id,
            credential_receipt_event_id=receipt.event_id,
            credential_receipt_sha256=credential_receipt_sha256,
            credential_handle_id=str(payload["handle_id"]),
            consumer_id=str(payload["consumer_id"]),
            owner_principal_id=str(payload["owner_principal_id"]),
            purpose=purpose,
            action_scope_sha256=action_scope_sha256,
            preview_sha256=_hash(material),
        )

    def prepare(self, arguments: Mapping[str, Any]) -> str:
        request = OperatorAuthenticatedAccessInvocation.from_arguments(arguments)
        preview = self.preview(
            target_id=request.target_id,
            credential_receipt_event_id=request.credential_receipt_event_id,
            purpose=request.purpose,
            action_scope_sha256=request.action_scope_sha256,
        )
        if (
            request.expected_target_spec_sha256 != preview.target_spec_sha256
            or request.expected_credential_receipt_sha256
            != preview.credential_receipt_sha256
            or request.expected_preview_sha256 != preview.preview_sha256
        ):
            raise AuthenticatedAccessDenied("AUTHENTICATED_ACCESS_PREVIEW_STALE")
        payload = {
            "schema_version": OPERATOR_AUTHENTICATED_ACCESS_PREPARED_SCHEMA_VERSION,
            "operation_id": request.operation_id,
            "target_id": preview.target_id,
            "target_spec_sha256": preview.target_spec_sha256,
            "route": preview.route,
            "app_id": preview.app_id,
            "credential_receipt_event_id": preview.credential_receipt_event_id,
            "credential_receipt_sha256": preview.credential_receipt_sha256,
            "credential_handle_id": preview.credential_handle_id,
            "consumer_id": preview.consumer_id,
            "owner_principal_id": preview.owner_principal_id,
            "purpose": preview.purpose,
            "action_scope_sha256": preview.action_scope_sha256,
            "preview_sha256": preview.preview_sha256,
            "secret_input_allowed": False,
            "auth_handoff_policy": "user_required",
            "host_ticket_required": True,
            "execution_authority_granted": False,
            "external_effects": 0,
            "ui_action_count": 0,
            "raw_secret_persisted": False,
            "raw_secret_exposed": False,
            "secret_digest_persisted": False,
            "secret_locator_persisted": False,
        }
        try:
            event, created = self.store.append_once_result(
                "operator.authenticated_access.prepared", request.operation_id, payload
            )
        except ValueError as error:
            raise AuthenticatedAccessDenied(
                "AUTHENTICATED_ACCESS_PREPARATION_COLLISION"
            ) from error
        if not created and canonical_json(event.payload) != canonical_json(payload):
            raise AuthenticatedAccessDenied("AUTHENTICATED_ACCESS_PREPARATION_COLLISION")
        return canonical_json(
            {
                "success": True,
                "prepared": {
                    **payload,
                    "prepared_event_id": event.event_id,
                    "replayed": not created,
                },
                "policy": {
                    "secret_input_allowed": False,
                    "auth_handoff_policy": "user_required",
                    "host_ticket_required": True,
                    "execution_authority_granted": False,
                },
            }
        )

    def record_readback(self, arguments: Mapping[str, Any]) -> str:
        if self.store.verify_chain().get("valid") is not True:
            raise AuthenticatedAccessDenied("LEDGER_CHAIN_INVALID")
        readback = AuthenticatedAccessHostReadback.from_arguments(arguments)
        prepared = self.store.event(readback.prepared_event_id)
        if (
            prepared is None
            or prepared.kind != "operator.authenticated_access.prepared"
            or prepared.payload.get("operation_id") != readback.operation_id
            or prepared.payload.get("target_id") != readback.target_id
            or prepared.payload.get("target_spec_sha256")
            != readback.target_spec_sha256
            or prepared.payload.get("route") != readback.route
            or prepared.payload.get("app_id") != readback.app_id
        ):
            raise AuthenticatedAccessDenied("AUTHENTICATED_ACCESS_READBACK_MISMATCH")
        payload = {
            "schema_version": OPERATOR_AUTHENTICATED_ACCESS_READBACK_SCHEMA_VERSION,
            "operation_id": readback.operation_id,
            "prepared_event_id": prepared.event_id,
            "target_id": readback.target_id,
            "target_spec_sha256": readback.target_spec_sha256,
            "route": readback.route,
            "app_id": readback.app_id,
            "status": readback.status,
            "session_binding_sha256": readback.session_binding_sha256,
            "driver_receipt_sha256": readback.driver_receipt_sha256,
            "existing_session_ready": readback.existing_session_ready,
            "auth_handoff_required": readback.auth_handoff_required,
            "foreground_unchanged": readback.foreground_unchanged,
            "ui_action_count": 0,
            "raw_secret_persisted": False,
            "raw_secret_exposed": False,
            "secret_input_performed": False,
            "secret_digest_persisted": False,
            "secret_locator_persisted": False,
            "execution_authority_granted": False,
            "external_effects": 0,
        }
        try:
            event, created = self.store.append_once_result(
                "operator.authenticated_access.readback", readback.operation_id, payload
            )
        except ValueError as error:
            raise AuthenticatedAccessDenied(
                "AUTHENTICATED_ACCESS_READBACK_COLLISION"
            ) from error
        if not created and canonical_json(event.payload) != canonical_json(payload):
            raise AuthenticatedAccessDenied("AUTHENTICATED_ACCESS_READBACK_COLLISION")
        return canonical_json(
            {
                "success": True,
                "readback": {
                    **payload,
                    "readback_event_id": event.event_id,
                    "replayed": not created,
                },
            }
        )
