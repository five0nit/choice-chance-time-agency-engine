"""Ticketed bridge from authenticated-access receipts to Hermes session probes.

The bridge dispatches only fixed, read-only attachment probes. Model callers cannot
supply browser Python, computer-use actions, coordinates, text, URLs, or secrets.
A second ``operator.credential`` execution ticket is required after the credential
receipt and authenticated-access preparation already exist.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re
from typing import Any, Callable, Mapping

from .execution_tickets import GlobalKillSwitch, TicketAuthorityDenied
from .mediation_outcomes import (
    OutcomeVerification,
    OutcomeVerifierRegistry,
    VerificationContext,
)
from .operator_authenticated_access import (
    AUTHENTICATED_ACCESS_ROUTES,
    AuthenticatedAccessHostReadback,
    OperatorAuthenticatedAccessPreview,
    OperatorAuthenticatedAccessScaffold,
)
from .operator_credentials import OPERATOR_CREDENTIAL_VERIFIER_ID
from .store import Event, EventStore, canonical_json


OPERATOR_AUTHENTICATED_SESSION_TOOL = "operator_authenticated_session"
OPERATOR_AUTHENTICATED_SESSION_CLAIM_SCHEMA_VERSION = (
    "cct.operator_authenticated_session.claim.v1"
)
OPERATOR_AUTHENTICATED_SESSION_OBSERVATION_SCHEMA_VERSION = (
    "cct.operator_authenticated_session.observation.v1"
)
OPERATOR_AUTHENTICATED_SESSION_RECEIPT_SCHEMA_VERSION = (
    "cct.operator_authenticated_session.receipt.v1"
)
_BROWSER_SENTINEL = "CCT_BROWSER_SESSION_READY_V1"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
DispatchTool = Callable[[str, dict[str, Any]], object]


class AuthenticatedSessionBridgeDenied(PermissionError):
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


def _hash(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _raw_digest(value: object) -> str:
    if isinstance(value, str):
        material = value
    else:
        try:
            material = canonical_json(value)
        except (TypeError, ValueError) as error:
            raise AuthenticatedSessionBridgeDenied(
                "SESSION_DRIVER_RESULT_NOT_CANONICAL"
            ) from error
    return sha256(material.encode("utf-8")).hexdigest()


def _json_object(value: object) -> dict[str, Any]:
    candidate = value
    if isinstance(value, str):
        try:
            candidate = json.loads(value)
        except json.JSONDecodeError as error:
            raise AuthenticatedSessionBridgeDenied(
                "SESSION_DRIVER_RESULT_MALFORMED"
            ) from error
    if not isinstance(candidate, dict):
        raise AuthenticatedSessionBridgeDenied("SESSION_DRIVER_RESULT_MALFORMED")
    return candidate


@dataclass(frozen=True, slots=True)
class OperatorAuthenticatedSessionPreview:
    ticket_id: str
    prepared_event_id: str
    prepared_sha256: str
    target_id: str
    target_spec_sha256: str
    route: str
    app_id: str
    credential_handle_id: str
    purpose: str
    action_scope_sha256: str
    verifier_id: str
    preview_sha256: str


@dataclass(frozen=True, slots=True)
class OperatorAuthenticatedSessionInvocation:
    ticket_id: str
    prepared_event_id: str
    expected_prepared_sha256: str
    expected_target_spec_sha256: str
    expected_action_scope_sha256: str
    expected_preview_sha256: str
    verifier_id: str

    @classmethod
    def from_arguments(
        cls, arguments: Mapping[str, Any]
    ) -> "OperatorAuthenticatedSessionInvocation":
        if not isinstance(arguments, Mapping):
            raise ValueError("authenticated-session arguments must be an object")
        fields = {
            "execution_ticket_id",
            "prepared_event_id",
            "expected_prepared_sha256",
            "expected_target_spec_sha256",
            "expected_action_scope_sha256",
            "expected_preview_sha256",
            "verifier_id",
        }
        if set(arguments) != fields:
            raise ValueError("authenticated-session arguments require exact fields")
        return cls(
            ticket_id=_identifier(
                "execution_ticket_id", arguments["execution_ticket_id"]
            ),
            prepared_event_id=_identifier(
                "prepared_event_id", arguments["prepared_event_id"]
            ),
            expected_prepared_sha256=_digest(
                "expected_prepared_sha256", arguments["expected_prepared_sha256"]
            ),
            expected_target_spec_sha256=_digest(
                "expected_target_spec_sha256",
                arguments["expected_target_spec_sha256"],
            ),
            expected_action_scope_sha256=_digest(
                "expected_action_scope_sha256",
                arguments["expected_action_scope_sha256"],
            ),
            expected_preview_sha256=_digest(
                "expected_preview_sha256", arguments["expected_preview_sha256"]
            ),
            verifier_id=_identifier("verifier_id", arguments["verifier_id"]),
        )


@dataclass(frozen=True, slots=True)
class AuthenticatedSessionDriverObservation:
    readback: AuthenticatedAccessHostReadback
    dispatch_tool_name: str
    dispatch_count: int
    raw_result_sha256: str

    def __post_init__(self) -> None:
        if self.dispatch_tool_name not in {"browser_exec", "computer_use", "none"}:
            raise ValueError("dispatch_tool_name is not allowed")
        if isinstance(self.dispatch_count, bool) or self.dispatch_count not in {0, 1}:
            raise ValueError("dispatch_count must be zero or one")
        _digest("raw_result_sha256", self.raw_result_sha256)
        if self.dispatch_tool_name == "none" and self.dispatch_count != 0:
            raise ValueError("none dispatch cannot report a call")
        if self.dispatch_tool_name != "none" and self.dispatch_count != 1:
            raise ValueError("tool dispatch must report one call")


class HermesAuthenticatedSessionDriver:
    """Dispatch fixed Hermes probes; return only bounded typed readback."""

    def __init__(
        self,
        dispatch_tool: DispatchTool,
        *,
        browser_real_profile_enabled: bool,
    ) -> None:
        if not callable(dispatch_tool):
            raise ValueError("dispatch_tool must be callable")
        if not isinstance(browser_real_profile_enabled, bool):
            raise ValueError("browser_real_profile_enabled must be a boolean")
        self.dispatch_tool = dispatch_tool
        self.browser_real_profile_enabled = browser_real_profile_enabled

    @staticmethod
    def _session_binding(prepared: Mapping[str, Any], receipt: str, status: str) -> str:
        return _hash(
            {
                "target_id": prepared["target_id"],
                "target_spec_sha256": prepared["target_spec_sha256"],
                "route": prepared["route"],
                "app_id": prepared["app_id"],
                "driver_receipt_sha256": receipt,
                "status": status,
            }
        )

    @classmethod
    def _readback(
        cls,
        prepared_event: Event,
        *,
        status: str,
        driver_receipt_sha256: str,
    ) -> AuthenticatedAccessHostReadback:
        payload = prepared_event.payload
        ready = status == "READY"
        return AuthenticatedAccessHostReadback.from_arguments(
            {
                "operation_id": payload["operation_id"],
                "prepared_event_id": prepared_event.event_id,
                "target_id": payload["target_id"],
                "target_spec_sha256": payload["target_spec_sha256"],
                "route": payload["route"],
                "app_id": payload["app_id"],
                "status": status,
                "session_binding_sha256": cls._session_binding(
                    payload, driver_receipt_sha256, status
                ),
                "driver_receipt_sha256": driver_receipt_sha256,
                "existing_session_ready": ready,
                "auth_handoff_required": not ready,
                "foreground_unchanged": True,
                "ui_action_count": 0,
                "raw_secret_exposed": False,
                "secret_input_performed": False,
            }
        )

    def probe(self, prepared_event: Event) -> AuthenticatedSessionDriverObservation:
        payload = prepared_event.payload
        route = str(payload.get("route"))
        if route not in AUTHENTICATED_ACCESS_ROUTES:
            raise AuthenticatedSessionBridgeDenied("SESSION_ROUTE_NOT_ALLOWED")
        if route == "browser_real_profile_snapshot":
            if not self.browser_real_profile_enabled:
                receipt = _hash(
                    {
                        "route": route,
                        "target_id": payload["target_id"],
                        "reason": "browser_real_profile_not_enabled",
                        "raw_result_persisted": False,
                    }
                )
                return AuthenticatedSessionDriverObservation(
                    readback=self._readback(
                        prepared_event,
                        status="AUTH_HANDOFF_REQUIRED",
                        driver_receipt_sha256=receipt,
                    ),
                    dispatch_tool_name="none",
                    dispatch_count=0,
                    raw_result_sha256=receipt,
                )
            session_name = "cct_" + sha256(
                str(payload["target_id"]).encode("utf-8")
            ).hexdigest()[:20]
            result = self.dispatch_tool(
                "browser_exec",
                {
                    "code": (
                        "# Checking an authenticated browser session\n"
                        "ensure_real_tab()\n"
                        f"print({_BROWSER_SENTINEL!r})"
                    ),
                    "session": session_name,
                    "timeout_s": 120,
                },
            )
            receipt = _raw_digest(result)
            parsed = _json_object(result)
            output = parsed.get("output")
            if not (
                parsed.get("success") is True
                and parsed.get("exit_code") == 0
                and isinstance(output, str)
                and output.strip().splitlines()
                and output.strip().splitlines()[-1] == _BROWSER_SENTINEL
                and parsed.get("session") == session_name
            ):
                raise AuthenticatedSessionBridgeDenied("BROWSER_SESSION_PROBE_FAILED")
            return AuthenticatedSessionDriverObservation(
                readback=self._readback(
                    prepared_event,
                    status="READY",
                    driver_receipt_sha256=receipt,
                ),
                dispatch_tool_name="browser_exec",
                dispatch_count=1,
                raw_result_sha256=receipt,
            )

        result = self.dispatch_tool(
            "computer_use",
            {
                "action": "list_apps",
            },
        )
        receipt = _raw_digest(result)
        parsed = _json_object(result)
        if parsed.get("error") is not None:
            if (
                parsed.get("code") == "auth_user_action_required"
                or parsed.get("auth_handoff") is True
            ):
                status = "AUTH_HANDOFF_REQUIRED"
            else:
                raise AuthenticatedSessionBridgeDenied("COMPUTER_SESSION_PROBE_FAILED")
        else:
            apps = parsed.get("apps")
            if not isinstance(apps, list) or parsed.get("count") != len(apps):
                raise AuthenticatedSessionBridgeDenied("COMPUTER_SESSION_PROBE_FAILED")
            target = str(payload["app_id"]).casefold()
            matches = []
            for row in apps:
                if not isinstance(row, dict):
                    continue
                identities = {
                    str(row.get(key) or "").casefold()
                    for key in ("name", "app", "app_name", "bundle_id", "process_name")
                }
                if target in identities:
                    matches.append(row)
            if len(matches) != 1:
                raise AuthenticatedSessionBridgeDenied(
                    "COMPUTER_SESSION_AMBIGUOUS"
                    if len(matches) > 1
                    else "COMPUTER_SESSION_NOT_FOUND"
                )
            window_count = matches[0].get("window_count")
            if window_count is not None and (
                isinstance(window_count, bool)
                or not isinstance(window_count, int)
                or window_count < 1
            ):
                raise AuthenticatedSessionBridgeDenied("COMPUTER_SESSION_NOT_FOUND")
            status = "READY"
        return AuthenticatedSessionDriverObservation(
            readback=self._readback(
                prepared_event,
                status=status,
                driver_receipt_sha256=receipt,
            ),
            dispatch_tool_name="computer_use",
            dispatch_count=1,
            raw_result_sha256=receipt,
        )


class OperatorAuthenticatedSessionBridge:
    """Execute one ticketed, fixed session probe and verify host readback."""

    def __init__(
        self,
        store: EventStore,
        scaffold: OperatorAuthenticatedAccessScaffold,
        driver: HermesAuthenticatedSessionDriver,
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        if not isinstance(scaffold, OperatorAuthenticatedAccessScaffold):
            raise ValueError("scaffold must be OperatorAuthenticatedAccessScaffold")
        if not isinstance(driver, HermesAuthenticatedSessionDriver):
            raise ValueError("driver must be HermesAuthenticatedSessionDriver")
        self.store = store
        self.scaffold = scaffold
        self.driver = driver

    def _prepared_event(self, event_id: str) -> tuple[Event, OperatorAuthenticatedAccessPreview]:
        if self.store.verify_chain().get("valid") is not True:
            raise AuthenticatedSessionBridgeDenied("LEDGER_CHAIN_INVALID")
        event = self.store.event(_identifier("prepared_event_id", event_id))
        if event is None or event.kind != "operator.authenticated_access.prepared":
            raise AuthenticatedSessionBridgeDenied("ACCESS_PREPARATION_NOT_FOUND")
        payload = event.payload
        if not (
            payload.get("schema_version")
            == "cct.operator_authenticated_access.prepared.v1"
            and payload.get("host_ticket_required") is True
            and payload.get("execution_authority_granted") is False
            and payload.get("secret_input_allowed") is False
            and payload.get("auth_handoff_policy") == "user_required"
            and payload.get("external_effects") == 0
            and payload.get("ui_action_count") == 0
            and payload.get("raw_secret_persisted") is False
            and payload.get("raw_secret_exposed") is False
            and payload.get("secret_digest_persisted") is False
            and payload.get("secret_locator_persisted") is False
        ):
            raise AuthenticatedSessionBridgeDenied("ACCESS_PREPARATION_INVALID")
        try:
            preview = self.scaffold.preview(
                target_id=str(payload["target_id"]),
                credential_receipt_event_id=str(payload["credential_receipt_event_id"]),
                purpose=str(payload["purpose"]),
                action_scope_sha256=str(payload["action_scope_sha256"]),
            )
        except Exception as error:
            raise AuthenticatedSessionBridgeDenied(
                "ACCESS_PREPARATION_LINEAGE_INVALID"
            ) from error
        expected = {
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
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            raise AuthenticatedSessionBridgeDenied("ACCESS_PREPARATION_MISMATCH")
        return event, preview

    def preview(self, *, prepared_event_id: str) -> OperatorAuthenticatedSessionPreview:
        event, access = self._prepared_event(prepared_event_id)
        prepared_sha256 = _hash(event.payload)
        material = {
            "ticket_id": event.payload["operation_id"],
            "prepared_event_id": event.event_id,
            "prepared_sha256": prepared_sha256,
            "target_id": access.target_id,
            "target_spec_sha256": access.target_spec_sha256,
            "route": access.route,
            "app_id": access.app_id,
            "credential_handle_id": access.credential_handle_id,
            "purpose": access.purpose,
            "action_scope_sha256": access.action_scope_sha256,
            "verifier_id": OPERATOR_CREDENTIAL_VERIFIER_ID,
        }
        return OperatorAuthenticatedSessionPreview(
            ticket_id=_identifier("ticket_id", event.payload["operation_id"]),
            prepared_event_id=event.event_id,
            prepared_sha256=prepared_sha256,
            target_id=access.target_id,
            target_spec_sha256=access.target_spec_sha256,
            route=access.route,
            app_id=access.app_id,
            credential_handle_id=access.credential_handle_id,
            purpose=access.purpose,
            action_scope_sha256=access.action_scope_sha256,
            verifier_id=OPERATOR_CREDENTIAL_VERIFIER_ID,
            preview_sha256=_hash(material),
        )

    @staticmethod
    def arguments(preview: OperatorAuthenticatedSessionPreview) -> dict[str, Any]:
        return {
            "execution_ticket_id": preview.ticket_id,
            "prepared_event_id": preview.prepared_event_id,
            "expected_prepared_sha256": preview.prepared_sha256,
            "expected_target_spec_sha256": preview.target_spec_sha256,
            "expected_action_scope_sha256": preview.action_scope_sha256,
            "expected_preview_sha256": preview.preview_sha256,
            "verifier_id": preview.verifier_id,
        }

    def register_outcome_verifier(self, registry: OutcomeVerifierRegistry) -> None:
        registry.register(
            OPERATOR_CREDENTIAL_VERIFIER_ID,
            self._verify_mediated_result,
            reconcile=self._reconcile_mediated_result,
            idempotency_proof_id="authenticated-session-ticket-receipt",
        )

    def outcome_verifiers(self) -> OutcomeVerifierRegistry:
        registry = OutcomeVerifierRegistry()
        self.register_outcome_verifier(registry)
        return registry

    def execute(self, arguments: Mapping[str, Any]) -> str:
        request = OperatorAuthenticatedSessionInvocation.from_arguments(arguments)
        preview = self.preview(prepared_event_id=request.prepared_event_id)
        if (
            request.ticket_id != preview.ticket_id
            or request.expected_prepared_sha256 != preview.prepared_sha256
            or request.expected_target_spec_sha256 != preview.target_spec_sha256
            or request.expected_action_scope_sha256 != preview.action_scope_sha256
            or request.expected_preview_sha256 != preview.preview_sha256
            or request.verifier_id != OPERATOR_CREDENTIAL_VERIFIER_ID
        ):
            raise AuthenticatedSessionBridgeDenied("SESSION_PREVIEW_STALE")
        self._require_dispatch_claim(request, preview, arguments)
        completion = self._completion(request.ticket_id)
        if completion is not None:
            return self._response(completion, replayed=True)
        claim = self._claim(request.ticket_id)
        if claim is not None:
            return self._recover_claim(claim, request, preview)

        claim_payload = {
            "schema_version": OPERATOR_AUTHENTICATED_SESSION_CLAIM_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "prepared_event_id": preview.prepared_event_id,
            "prepared_sha256": preview.prepared_sha256,
            "target_id": preview.target_id,
            "target_spec_sha256": preview.target_spec_sha256,
            "route": preview.route,
            "app_id": preview.app_id,
            "credential_handle_id": preview.credential_handle_id,
            "purpose": preview.purpose,
            "action_scope_sha256": preview.action_scope_sha256,
            "preview_sha256": preview.preview_sha256,
            "verifier_id": request.verifier_id,
            "effect_id": "authenticated-session-"
            + sha256(request.ticket_id.encode("utf-8")).hexdigest()[:24],
            "raw_arguments_persisted": False,
            "raw_driver_result_persisted": False,
            "raw_secret_persisted": False,
            "secret_input_allowed": False,
            "execution_authority_granted": False,
        }

        def admission(events: list[Event]) -> Mapping[str, Any]:
            try:
                GlobalKillSwitch.ensure_clear(events)
            except TicketAuthorityDenied as error:
                raise AuthenticatedSessionBridgeDenied(error.reason_code) from error
            return claim_payload

        claim, created = self.store.append_once_computed(
            "operator.authenticated_session.claimed", request.ticket_id, admission
        )
        if not created:
            return self._recover_claim(claim, request, preview)
        try:
            GlobalKillSwitch(self.store).checkpoint(
                checkpoint_id="authenticated-session-pre-"
                + sha256(request.ticket_id.encode("utf-8")).hexdigest()[:20],
                effect_id=str(claim.payload["effect_id"]),
                step="pre-dispatch",
            )
        except TicketAuthorityDenied as error:
            raise AuthenticatedSessionBridgeDenied(error.reason_code) from error

        prepared_event = self.store.event(preview.prepared_event_id)
        if prepared_event is None:
            raise AuthenticatedSessionBridgeDenied("ACCESS_PREPARATION_NOT_FOUND")
        observation = self.driver.probe(prepared_event)
        observed_event = self._record_driver_observation(
            claim, request, preview, observation
        )
        readback = json.loads(self.scaffold.record_readback(asdict(observation.readback)))[
            "readback"
        ]
        return self._record_completion(
            claim,
            request,
            preview,
            observed_event,
            readback,
            recovered_after_readback=False,
        )

    def _record_driver_observation(
        self,
        claim: Event,
        request: OperatorAuthenticatedSessionInvocation,
        preview: OperatorAuthenticatedSessionPreview,
        observation: AuthenticatedSessionDriverObservation,
    ) -> Event:
        readback = observation.readback
        if (
            readback.operation_id != request.ticket_id
            or readback.prepared_event_id != preview.prepared_event_id
            or readback.target_id != preview.target_id
            or readback.target_spec_sha256 != preview.target_spec_sha256
            or readback.route != preview.route
            or readback.app_id != preview.app_id
        ):
            raise AuthenticatedSessionBridgeDenied("SESSION_DRIVER_READBACK_MISMATCH")
        payload = {
            "schema_version": OPERATOR_AUTHENTICATED_SESSION_OBSERVATION_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "claim_event_id": claim.event_id,
            "effect_id": claim.payload["effect_id"],
            "prepared_event_id": preview.prepared_event_id,
            "target_id": preview.target_id,
            "target_spec_sha256": preview.target_spec_sha256,
            "route": preview.route,
            "app_id": preview.app_id,
            "credential_handle_id": preview.credential_handle_id,
            "purpose": preview.purpose,
            "status": readback.status,
            "session_binding_sha256": readback.session_binding_sha256,
            "driver_receipt_sha256": readback.driver_receipt_sha256,
            "dispatch_tool_name": observation.dispatch_tool_name,
            "dispatch_count": observation.dispatch_count,
            "raw_result_sha256": observation.raw_result_sha256,
            "existing_session_ready": readback.existing_session_ready,
            "auth_handoff_required": readback.auth_handoff_required,
            "foreground_unchanged": True,
            "ui_action_count": 0,
            "raw_driver_result_persisted": False,
            "raw_secret_persisted": False,
            "raw_secret_exposed": False,
            "secret_input_performed": False,
            "execution_authority_granted": False,
            "external_effects": 0,
        }
        event, created = self.store.append_once_result(
            "operator.authenticated_session.driver_observed", request.ticket_id, payload
        )
        if not created and canonical_json(event.payload) != canonical_json(payload):
            raise AuthenticatedSessionBridgeDenied("SESSION_OBSERVATION_COLLISION")
        return event

    def _record_completion(
        self,
        claim: Event,
        request: OperatorAuthenticatedSessionInvocation,
        preview: OperatorAuthenticatedSessionPreview,
        observation: Event,
        readback: Mapping[str, Any],
        *,
        recovered_after_readback: bool,
    ) -> str:
        if not (
            observation.payload.get("ticket_id") == request.ticket_id
            and readback.get("operation_id") == request.ticket_id
            and observation.payload.get("status") == readback.get("status")
            and observation.payload.get("session_binding_sha256")
            == readback.get("session_binding_sha256")
            and observation.payload.get("driver_receipt_sha256")
            == readback.get("driver_receipt_sha256")
        ):
            raise AuthenticatedSessionBridgeDenied("SESSION_READBACK_MISMATCH")
        payload = {
            "schema_version": OPERATOR_AUTHENTICATED_SESSION_RECEIPT_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "claim_event_id": claim.event_id,
            "effect_id": claim.payload["effect_id"],
            "prepared_event_id": preview.prepared_event_id,
            "driver_observation_event_id": observation.event_id,
            "readback_event_id": readback["readback_event_id"],
            "target_id": preview.target_id,
            "target_spec_sha256": preview.target_spec_sha256,
            "route": preview.route,
            "app_id": preview.app_id,
            "credential_handle_id": preview.credential_handle_id,
            "purpose": preview.purpose,
            "action_scope_sha256": preview.action_scope_sha256,
            "status": readback["status"],
            "session_binding_sha256": readback["session_binding_sha256"],
            "driver_receipt_sha256": readback["driver_receipt_sha256"],
            "dispatch_tool_name": observation.payload["dispatch_tool_name"],
            "dispatch_count": observation.payload["dispatch_count"],
            "existing_session_ready": readback["existing_session_ready"],
            "auth_handoff_required": readback["auth_handoff_required"],
            "foreground_unchanged": True,
            "ui_action_count": 0,
            "verification_passed": True,
            "recovered_after_readback": recovered_after_readback,
            "raw_driver_result_persisted": False,
            "raw_secret_persisted": False,
            "raw_secret_exposed": False,
            "secret_input_performed": False,
            "execution_authority_granted": False,
            "external_effects": 0,
        }
        event, created = self.store.append_once_result(
            "operator.authenticated_session.completed", request.ticket_id, payload
        )
        if not created and canonical_json(event.payload) != canonical_json(payload):
            existing = event.payload
            if not (
                existing.get("ticket_id") == request.ticket_id
                and existing.get("verification_passed") is True
                and existing.get("target_id") == preview.target_id
                and existing.get("session_binding_sha256")
                == readback["session_binding_sha256"]
            ):
                raise AuthenticatedSessionBridgeDenied("SESSION_RECEIPT_COLLISION")
        return self._response(event, replayed=not created)

    def _recover_claim(
        self,
        claim: Event,
        request: OperatorAuthenticatedSessionInvocation,
        preview: OperatorAuthenticatedSessionPreview,
    ) -> str:
        self._validate_claim(claim, request, preview)
        observations = [
            event
            for event in self.store.events("operator.authenticated_session.driver_observed")
            if event.payload.get("ticket_id") == request.ticket_id
        ]
        readbacks = [
            event
            for event in self.store.events("operator.authenticated_access.readback")
            if event.payload.get("operation_id") == request.ticket_id
        ]
        if len(observations) != 1 or len(readbacks) != 1:
            raise AuthenticatedSessionBridgeDenied("SESSION_EXECUTION_STATE_UNCERTAIN")
        readback_payload = {
            **readbacks[0].payload,
            "readback_event_id": readbacks[0].event_id,
        }
        return self._record_completion(
            claim,
            request,
            preview,
            observations[0],
            readback_payload,
            recovered_after_readback=True,
        )

    @staticmethod
    def _validate_claim(
        claim: Event,
        request: OperatorAuthenticatedSessionInvocation,
        preview: OperatorAuthenticatedSessionPreview,
    ) -> None:
        expected = {
            "ticket_id": request.ticket_id,
            "prepared_event_id": preview.prepared_event_id,
            "prepared_sha256": preview.prepared_sha256,
            "target_id": preview.target_id,
            "target_spec_sha256": preview.target_spec_sha256,
            "route": preview.route,
            "app_id": preview.app_id,
            "credential_handle_id": preview.credential_handle_id,
            "purpose": preview.purpose,
            "action_scope_sha256": preview.action_scope_sha256,
            "preview_sha256": preview.preview_sha256,
            "verifier_id": request.verifier_id,
        }
        if any(claim.payload.get(key) != value for key, value in expected.items()):
            raise AuthenticatedSessionBridgeDenied("SESSION_CLAIM_COLLISION")

    def _require_dispatch_claim(
        self,
        request: OperatorAuthenticatedSessionInvocation,
        preview: OperatorAuthenticatedSessionPreview,
        arguments: Mapping[str, Any],
    ) -> None:
        arguments_sha256 = sha256(canonical_json(arguments).encode("utf-8")).hexdigest()
        rows = [
            event
            for event in self.store.events("execution.ticket.consumed")
            if event.payload.get("ticket_id") == request.ticket_id
        ]
        if len(rows) != 1:
            raise AuthenticatedSessionBridgeDenied("TICKET_DISPATCH_CLAIM_REQUIRED")
        payload = rows[0].payload
        if not (
            payload.get("dispatch_claimed") is True
            and payload.get("ticket_consumed") is True
            and payload.get("tool_name") == OPERATOR_AUTHENTICATED_SESSION_TOOL
            and payload.get("arguments_sha256") == arguments_sha256
            and payload.get("capability") == "operator.credential"
            and payload.get("scope")
            == f"operator/credential/{preview.credential_handle_id}"
            and payload.get("verifier_id") == OPERATOR_CREDENTIAL_VERIFIER_ID
            and payload.get("idempotency_key") == request.ticket_id
            and payload.get("action_budget") == 1
            and payload.get("byte_budget") == 0
            and payload.get("value_budget_microunits") == 0
        ):
            raise AuthenticatedSessionBridgeDenied("TICKET_DISPATCH_CLAIM_MISMATCH")

    def _claim(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.authenticated_session.claimed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise AuthenticatedSessionBridgeDenied("DUPLICATE_SESSION_CLAIMS")
        return rows[0] if rows else None

    def _completion(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.authenticated_session.completed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise AuthenticatedSessionBridgeDenied("DUPLICATE_SESSION_RECEIPTS")
        return rows[0] if rows else None

    @staticmethod
    def _response(event: Event, *, replayed: bool) -> str:
        payload = event.payload
        return canonical_json(
            {
                "success": payload.get("verification_passed") is True,
                "effect": {
                    "effect_id": payload.get("effect_id"),
                    "idempotency_key": payload.get("ticket_id"),
                    "receipt_event_id": event.event_id,
                },
                "credential_use": {
                    "handle_id": payload.get("credential_handle_id"),
                    "purpose": payload.get("purpose"),
                    "raw_secret_exposed": False,
                    "secret_input_performed": False,
                },
                "authenticated_session": {
                    "target_id": payload.get("target_id"),
                    "route": payload.get("route"),
                    "app_id": payload.get("app_id"),
                    "status": payload.get("status"),
                    "session_binding_sha256": payload.get(
                        "session_binding_sha256"
                    ),
                    "driver_receipt_sha256": payload.get(
                        "driver_receipt_sha256"
                    ),
                    "dispatch_tool_name": payload.get("dispatch_tool_name"),
                    "dispatch_count": payload.get("dispatch_count"),
                    "existing_session_ready": payload.get(
                        "existing_session_ready"
                    ),
                    "auth_handoff_required": payload.get(
                        "auth_handoff_required"
                    ),
                    "foreground_unchanged": True,
                    "ui_action_count": 0,
                    "raw_driver_result_persisted": False,
                    "recovered_after_readback": payload.get(
                        "recovered_after_readback"
                    ),
                    "replayed": replayed,
                },
                "verification": {
                    "passed": payload.get("verification_passed") is True,
                    "verifier_id": OPERATOR_CREDENTIAL_VERIFIER_ID,
                    "evidence_sha256": payload.get("driver_receipt_sha256"),
                },
            }
        )

    def _verify_mediated_result(
        self,
        value: object,
        context: VerificationContext,
    ) -> OutcomeVerification:
        malformed = OutcomeVerification(
            verified=False,
            effect_observed=False,
            status="malformed-result",
        )
        if (
            not isinstance(value, dict)
            or context.verifier_id != OPERATOR_CREDENTIAL_VERIFIER_ID
            or context.tool_name != OPERATOR_AUTHENTICATED_SESSION_TOOL
        ):
            return malformed
        effect = value.get("effect")
        credential = value.get("credential_use")
        session = value.get("authenticated_session")
        verification = value.get("verification")
        if not all(
            isinstance(row, dict)
            for row in (effect, credential, session, verification)
        ):
            return malformed
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            return malformed
        payload = receipt.payload
        assert isinstance(effect, dict)
        assert isinstance(credential, dict)
        assert isinstance(session, dict)
        assert isinstance(verification, dict)
        matched = (
            value.get("success") is True
            and payload.get("verification_passed") is True
            and payload.get("status") in {"READY", "AUTH_HANDOFF_REQUIRED"}
            and effect.get("effect_id") == payload.get("effect_id")
            and effect.get("idempotency_key") == context.idempotency_key
            and effect.get("receipt_event_id") == receipt.event_id
            and credential.get("handle_id") == payload.get("credential_handle_id")
            and credential.get("purpose") == payload.get("purpose")
            and credential.get("raw_secret_exposed") is False
            and credential.get("secret_input_performed") is False
            and session.get("target_id") == payload.get("target_id")
            and session.get("route") == payload.get("route")
            and session.get("app_id") == payload.get("app_id")
            and session.get("status") == payload.get("status")
            and session.get("session_binding_sha256")
            == payload.get("session_binding_sha256")
            and session.get("driver_receipt_sha256")
            == payload.get("driver_receipt_sha256")
            and session.get("dispatch_tool_name")
            == payload.get("dispatch_tool_name")
            and session.get("dispatch_count") == payload.get("dispatch_count")
            and session.get("existing_session_ready")
            == payload.get("existing_session_ready")
            and session.get("auth_handoff_required")
            == payload.get("auth_handoff_required")
            and session.get("foreground_unchanged") is True
            and session.get("ui_action_count") == 0
            and session.get("raw_driver_result_persisted") is False
            and verification.get("passed") is True
            and verification.get("verifier_id")
            == OPERATOR_CREDENTIAL_VERIFIER_ID
            and verification.get("evidence_sha256")
            == payload.get("driver_receipt_sha256")
        )
        return OutcomeVerification(
            verified=matched,
            effect_observed=matched,
            status="verified" if matched else "receipt-mismatch",
            effect_id=str(payload["effect_id"]) if matched else None,
            evidence_sha256=(
                str(payload["driver_receipt_sha256"]) if matched else None
            ),
        )

    def _reconcile_mediated_result(self, context: VerificationContext) -> object | None:
        receipt = self._completion(context.ticket_id)
        if receipt is not None:
            return json.loads(self._response(receipt, replayed=True))
        claim = self._claim(context.ticket_id)
        if claim is None:
            return None
        observations = [
            event
            for event in self.store.events("operator.authenticated_session.driver_observed")
            if event.payload.get("ticket_id") == context.ticket_id
        ]
        readbacks = [
            event
            for event in self.store.events("operator.authenticated_access.readback")
            if event.payload.get("operation_id") == context.ticket_id
        ]
        if len(observations) != 1 or len(readbacks) != 1:
            return None
        request = OperatorAuthenticatedSessionInvocation(
            ticket_id=context.ticket_id,
            prepared_event_id=str(claim.payload["prepared_event_id"]),
            expected_prepared_sha256=str(claim.payload["prepared_sha256"]),
            expected_target_spec_sha256=str(claim.payload["target_spec_sha256"]),
            expected_action_scope_sha256=str(claim.payload["action_scope_sha256"]),
            expected_preview_sha256=str(claim.payload["preview_sha256"]),
            verifier_id=str(claim.payload["verifier_id"]),
        )
        preview = self.preview(prepared_event_id=request.prepared_event_id)
        try:
            response = self._record_completion(
                claim,
                request,
                preview,
                observations[0],
                {**readbacks[0].payload, "readback_event_id": readbacks[0].event_id},
                recovered_after_readback=True,
            )
        except Exception:
            return None
        return json.loads(response)
