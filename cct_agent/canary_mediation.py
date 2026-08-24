"""Outcome verification for ticket-mediated Generalist2 real canaries.

Only typed, hash-bounded adapter completion receipts can satisfy these verifiers.
The model cannot register verifier code, select another profile, or turn a claimed
provider result into authority without a matching canonical CCT event.
"""

from __future__ import annotations

from hashlib import sha256
import re
from typing import Any, Mapping

from .mediation_outcomes import (
    OutcomeVerification,
    OutcomeVerifierRegistry,
    VerificationContext,
)
from .real_canaries import (
    PROFILE_DEPLOYMENT_RECEIPT_VERSION,
    TELEGRAM_DELIVERY_RECEIPT_VERSION,
)
from .store import Event, EventStore, canonical_json


PROFILE_DEPLOY_TOOL = "cct_generalist2_profile_deploy"
PRIVATE_TELEGRAM_TOOL = "cct_private_telegram_delivery"
PROFILE_DEPLOY_VERIFIER = "generalist2-profile-deploy-readback-v1"
PRIVATE_TELEGRAM_VERIFIER = "private-telegram-delivery-readback-v1"
PROFILE_DEPLOY_CAPABILITY = "generalist2.profile-deploy"
PRIVATE_TELEGRAM_CAPABILITY = "generalist2.private-telegram"
PROFILE_DEPLOY_SCOPE = "generalist2/cct-agency"
PRIVATE_TELEGRAM_SCOPE = "telegram/mike/private"
PROFILE_DEPLOY_IDEMPOTENCY_PROOF = "generalist2-profile-operation-id-v1"
PRIVATE_TELEGRAM_IDEMPOTENCY_PROOF = "private-telegram-operation-id-v1"
CANARY_EFFECT_TOOLS = frozenset({PROFILE_DEPLOY_TOOL, PRIVATE_TELEGRAM_TOOL})
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")


def _digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _profile_effect(event: Event) -> dict[str, object] | None:
    payload = event.payload
    required_digests = (
        "artifact_sha256",
        "manifest_sha256",
        "before_runtime_sha256",
        "after_runtime_sha256",
        "state_db_logical_sha256",
        "sqlite_backup_sha256",
    )
    if (
        payload.get("schema_version") != PROFILE_DEPLOYMENT_RECEIPT_VERSION
        or payload.get("profile_name") != "generalist2"
        or payload.get("service_name") != "hermes-gateway-generalist2.service"
        or payload.get("status") != "deployed"
        or payload.get("artifact_readback_verified") is not True
        or payload.get("sqlite_backup_verified") is not True
        or payload.get("profile_mutation_count") != 1
        or payload.get("state_db_restored") is not False
        or payload.get("ambient_credentials_used") is not False
        or payload.get("network_effect") is not False
        or payload.get("service_reload_effect") is not False
        or not _identifier(payload.get("request_id"))
        or not _identifier(payload.get("target_id"))
        or any(not _digest(payload.get(name)) for name in required_digests)
    ):
        return None
    return {
        "effect_type": "generalist2-profile-deployment",
        "effect_id": payload["request_id"],
        "idempotency_key": payload["request_id"],
        "request_id": payload["request_id"],
        "target_id": payload["target_id"],
        "profile_name": "generalist2",
        "service_name": "hermes-gateway-generalist2.service",
        "artifact_sha256": payload["artifact_sha256"],
        "manifest_sha256": payload["manifest_sha256"],
        "before_runtime_sha256": payload["before_runtime_sha256"],
        "after_runtime_sha256": payload["after_runtime_sha256"],
        "state_db_logical_sha256": payload["state_db_logical_sha256"],
        "sqlite_backup_sha256": payload["sqlite_backup_sha256"],
        "artifact_readback_verified": True,
        "sqlite_backup_verified": True,
        "profile_mutation_count": 1,
        "state_db_restored": False,
        "status": "deployed",
        "terminal_event_id": event.event_id,
    }


def _telegram_effect(event: Event) -> dict[str, object] | None:
    payload = event.payload
    digest_fields = (
        "portfolio_sha256",
        "recipient_binding_sha256",
        "message_sha256",
        "provider_receipt_sha256",
        "provider_message_id_sha256",
    )
    if (
        payload.get("schema_version") != TELEGRAM_DELIVERY_RECEIPT_VERSION
        or payload.get("profile_name") != "generalist2"
        or payload.get("service_name") != "hermes-gateway-generalist2.service"
        or payload.get("platform") != "telegram"
        or payload.get("chat_type") != "private"
        or payload.get("principal_id") != "mike"
        or payload.get("delivery_readback_verified") is not True
        or payload.get("external_effect_count") != 1
        or payload.get("ambient_credentials_used") is not False
        or payload.get("host_managed_delivery") is not True
        or payload.get("message_content_persisted") is not False
        or payload.get("raw_producer_content_persisted") is not False
        or payload.get("status") != "delivered"
        or not _identifier(payload.get("request_id"))
        or not _identifier(payload.get("target_id"))
        or not _identifier(payload.get("proposal_event_id"))
        or not _identifier(payload.get("proposal_id"))
        or isinstance(payload.get("proposal_revision"), bool)
        or not isinstance(payload.get("proposal_revision"), int)
        or int(payload["proposal_revision"]) < 1
        or any(not _digest(payload.get(name)) for name in digest_fields)
    ):
        return None
    return {
        "effect_type": "private-telegram-delivery",
        "effect_id": payload["request_id"],
        "idempotency_key": payload["request_id"],
        "request_id": payload["request_id"],
        "target_id": payload["target_id"],
        "profile_name": "generalist2",
        "service_name": "hermes-gateway-generalist2.service",
        "platform": "telegram",
        "chat_type": "private",
        "principal_id": "mike",
        "proposal_event_id": payload["proposal_event_id"],
        "proposal_id": payload["proposal_id"],
        "proposal_revision": payload["proposal_revision"],
        "portfolio_sha256": payload["portfolio_sha256"],
        "recipient_binding_sha256": payload["recipient_binding_sha256"],
        "message_sha256": payload["message_sha256"],
        "provider_receipt_sha256": payload["provider_receipt_sha256"],
        "provider_message_id_sha256": payload["provider_message_id_sha256"],
        "delivery_readback_verified": True,
        "external_effect_count": 1,
        "ambient_credentials_used": False,
        "host_managed_delivery": True,
        "status": "delivered",
        "terminal_event_id": event.event_id,
    }


def _one_completion(
    store: EventStore, kind: str, request_id: str
) -> Event | None:
    rows = [
        event
        for event in store.events(kind)
        if event.payload.get("request_id") == request_id
    ]
    return rows[0] if len(rows) == 1 else None


def _tool_result(effect: Mapping[str, object]) -> str:
    return canonical_json(
        {
            "success": True,
            "effect": dict(effect),
            "raw_result_persisted": False,
            "raw_credentials_persisted": False,
        }
    )


def profile_deployment_tool_result(
    *,
    request_id: str,
    target_id: str,
    artifact_sha256: str,
    manifest_sha256: str,
    before_runtime_sha256: str,
    after_runtime_sha256: str,
    state_db_logical_sha256: str,
    sqlite_backup_sha256: str,
    terminal_event_id: str,
) -> str:
    """Build the bounded tool result emitted by a completed profile adapter."""

    effect = {
        "effect_type": "generalist2-profile-deployment",
        "effect_id": request_id,
        "idempotency_key": request_id,
        "request_id": request_id,
        "target_id": target_id,
        "profile_name": "generalist2",
        "service_name": "hermes-gateway-generalist2.service",
        "artifact_sha256": artifact_sha256,
        "manifest_sha256": manifest_sha256,
        "before_runtime_sha256": before_runtime_sha256,
        "after_runtime_sha256": after_runtime_sha256,
        "state_db_logical_sha256": state_db_logical_sha256,
        "sqlite_backup_sha256": sqlite_backup_sha256,
        "artifact_readback_verified": True,
        "sqlite_backup_verified": True,
        "profile_mutation_count": 1,
        "state_db_restored": False,
        "status": "deployed",
        "terminal_event_id": terminal_event_id,
    }
    if (
        not _identifier(request_id)
        or not _identifier(target_id)
        or not _identifier(terminal_event_id)
        or any(
            not _digest(value)
            for value in (
                artifact_sha256,
                manifest_sha256,
                before_runtime_sha256,
                after_runtime_sha256,
                state_db_logical_sha256,
                sqlite_backup_sha256,
            )
        )
    ):
        raise ValueError("profile deployment tool result is malformed")
    return _tool_result(effect)


def private_telegram_tool_result(event: Event) -> str:
    """Build the bounded tool result from one canonical private delivery event."""

    effect = _telegram_effect(event)
    if effect is None:
        raise ValueError("private Telegram completion event is malformed")
    return _tool_result(effect)


def _verify(
    value: object,
    context: VerificationContext,
    *,
    store: EventStore,
    tool_name: str,
    verifier_id: str,
    capability: str,
    scope: str,
    event_kind: str,
    effect_reader: Any,
) -> OutcomeVerification:
    if (
        context.tool_name != tool_name
        or context.verifier_id != verifier_id
        or context.capability != capability
        or context.scope != scope
        or context.idempotency_key != context.ticket_id
        or not isinstance(value, dict)
        or set(value) != {
            "success",
            "effect",
            "raw_result_persisted",
            "raw_credentials_persisted",
        }
        or value.get("success") is not True
        or value.get("raw_result_persisted") is not False
        or value.get("raw_credentials_persisted") is not False
        or not isinstance(value.get("effect"), dict)
    ):
        return OutcomeVerification(False, False, "binding-mismatch")
    event = _one_completion(store, event_kind, context.ticket_id)
    expected = effect_reader(event) if event is not None else None
    effect = value["effect"]
    if expected is None or canonical_json(effect) != canonical_json(expected):
        return OutcomeVerification(False, False, "readback-mismatch")
    if (
        effect.get("request_id") != context.ticket_id
        or effect.get("effect_id") != context.ticket_id
        or effect.get("idempotency_key") != context.ticket_id
    ):
        return OutcomeVerification(False, False, "ticket-mismatch")
    return OutcomeVerification(
        verified=True,
        effect_observed=True,
        status="verified",
        effect_id=context.ticket_id,
        evidence_sha256=sha256(canonical_json(effect).encode("utf-8")).hexdigest(),
    )


def build_canary_outcome_registry(store: EventStore) -> OutcomeVerifierRegistry:
    """Register exact host-owned verifiers and restart reconciliation readbacks."""

    if not isinstance(store, EventStore):
        raise ValueError("canary outcome registry requires EventStore")
    registry = OutcomeVerifierRegistry()

    def profile_verifier(
        value: object, context: VerificationContext
    ) -> OutcomeVerification:
        return _verify(
            value,
            context,
            store=store,
            tool_name=PROFILE_DEPLOY_TOOL,
            verifier_id=PROFILE_DEPLOY_VERIFIER,
            capability=PROFILE_DEPLOY_CAPABILITY,
            scope=PROFILE_DEPLOY_SCOPE,
            event_kind="canary.profile.deployment.completed",
            effect_reader=_profile_effect,
        )

    def profile_reconcile(context: VerificationContext) -> object | None:
        event = _one_completion(
            store, "canary.profile.deployment.completed", context.ticket_id
        )
        effect = _profile_effect(event) if event is not None else None
        return _tool_result(effect) if effect is not None else None

    def telegram_verifier(
        value: object, context: VerificationContext
    ) -> OutcomeVerification:
        return _verify(
            value,
            context,
            store=store,
            tool_name=PRIVATE_TELEGRAM_TOOL,
            verifier_id=PRIVATE_TELEGRAM_VERIFIER,
            capability=PRIVATE_TELEGRAM_CAPABILITY,
            scope=PRIVATE_TELEGRAM_SCOPE,
            event_kind="canary.telegram.delivery.completed",
            effect_reader=_telegram_effect,
        )

    def telegram_reconcile(context: VerificationContext) -> object | None:
        event = _one_completion(
            store, "canary.telegram.delivery.completed", context.ticket_id
        )
        effect = _telegram_effect(event) if event is not None else None
        return _tool_result(effect) if effect is not None else None

    registry.register(
        PROFILE_DEPLOY_VERIFIER,
        profile_verifier,
        reconcile=profile_reconcile,
        idempotency_proof_id=PROFILE_DEPLOY_IDEMPOTENCY_PROOF,
    )
    registry.register(
        PRIVATE_TELEGRAM_VERIFIER,
        telegram_verifier,
        reconcile=telegram_reconcile,
        idempotency_proof_id=PRIVATE_TELEGRAM_IDEMPOTENCY_PROOF,
    )
    return registry
