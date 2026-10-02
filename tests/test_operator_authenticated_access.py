from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from typing import Any

import pytest

from cct_agent.capabilities import CapabilityLease, CapabilityRegistry, OperatorCapabilityCatalog
from cct_agent.execution_tickets import ExecutionTicket, ExecutionTicketAuthority
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.operator_authenticated_access import (
    AuthenticatedAccessDenied,
    AuthenticatedAccessHostReadback,
    OperatorAuthenticatedAccessScaffold,
    OperatorAuthenticatedAccessTarget,
)
from cct_agent.operator_credentials import (
    OPERATOR_CREDENTIAL_VERIFIER_ID,
    LocalFakeCredentialResolver,
    OperatorCredentialBroker,
    OperatorCredentialHandle,
)
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore, canonical_json


NOW = "2026-09-02T00:00:00+00:00"
FUTURE = "2027-09-03T00:00:00+00:00"
SECRET = b"authenticated-access-private-sentinel-2751"
ACTION_SCOPE_SHA256 = sha256(b"capture-readback-only").hexdigest()
SESSION_BINDING_SHA256 = sha256(b"opaque-session-binding").hexdigest()
DRIVER_RECEIPT_SHA256 = sha256(b"driver-readback").hexdigest()


def configured(tmp_path: Path) -> dict[str, Any]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    installed = PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 1.0},
            directives=(
                PrincipalDirective(
                    id="authenticated-access",
                    kind="preference",
                    statement="Use only verified existing authenticated sessions.",
                    tags=("domain:operator", "action:credential"),
                    priority=95,
                ),
            ),
        ),
        authority="operator",
        evidence=("operator://profile",),
    )
    spec = OperatorCapabilityCatalog(store).install()["credential"]
    CapabilityRegistry(store).grant(
        CapabilityLease(
            id="lease-authenticated-access",
            capability="operator.credential",
            principal_id="mike",
            scopes=("operator/credential/generalist2-browser-session",),
            expires_at=FUTURE,
            max_actions=4,
            max_bytes=0,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://lease/authenticated-access",),
        )
    )
    resolver_root = tmp_path / "resolver"
    resolver_root.mkdir()
    handle = OperatorCredentialHandle(
        id="generalist2-browser-session",
        resolver_id="generalist2-session-resolver",
        provider="local-session-broker",
        consumer_id="browser-real-profile",
        owner_principal_id="mike",
        allowed_purposes=("resume-browser-session",),
        expires_at=FUTURE,
        max_uses=2,
    )
    resolver = LocalFakeCredentialResolver(
        state_root=resolver_root,
        provider=handle.provider,
        consumer_id=handle.consumer_id,
        secrets={handle.id: SECRET},
    )
    broker = OperatorCredentialBroker(
        store,
        handles=(handle,),
        resolvers={handle.resolver_id: resolver},
    )
    target = OperatorAuthenticatedAccessTarget(
        id="chrome-real-profile",
        target_kind="web",
        route="browser_real_profile_snapshot",
        app_id="chrome",
        consumer_id=handle.consumer_id,
        owner_principal_id="mike",
        allowed_purposes=("resume-browser-session",),
    )
    return {
        "store": store,
        "profile_digest": installed["profile_digest"],
        "spec_digest": spec["spec_digest"],
        "resolver_root": resolver_root,
        "handle": handle,
        "resolver": resolver,
        "broker": broker,
        "target": target,
    }


def credential_arguments(fixture: dict[str, Any], ticket_id: str) -> dict[str, Any]:
    preview = fixture["broker"].preview(
        handle_id=fixture["handle"].id,
        purpose="resume-browser-session",
    )
    return {
        "execution_ticket_id": ticket_id,
        "credential_handle_id": preview.handle_id,
        "purpose": preview.purpose,
        "expected_handle_spec_sha256": preview.handle_spec_sha256,
        "expected_authority_receipt_sha256": preview.authority_receipt_sha256,
        "expected_before_state_sha256": preview.before_state_sha256,
        "expected_preview_sha256": preview.preview_sha256,
        "verifier_id": OPERATOR_CREDENTIAL_VERIFIER_ID,
    }


def issue_and_use_credential(fixture: dict[str, Any], ticket_id: str) -> dict[str, Any]:
    payload = credential_arguments(fixture, ticket_id)
    ExecutionTicketAuthority(fixture["store"]).issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name="operator_credential_use",
            arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
            goal_id="goal-cct-authenticated-access",
            plan_id=f"plan-{ticket_id}",
            plan_hash=sha256(f"plan:{ticket_id}".encode()).hexdigest(),
            stage="prepare-authenticated-session",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=fixture["profile_digest"],
            capability="operator.credential",
            capability_spec_digest=fixture["spec_digest"],
            lease_id="lease-authenticated-access",
            scope="operator/credential/generalist2-browser-session",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=0,
            value_budget_microunits=0,
        ),
        authority="operator",
        evidence=(f"operator://goal/{ticket_id}",),
    )

    def next_call() -> str:
        return fixture["broker"].execute(payload)

    result = ToolExecutionMediator(
        fixture["store"],
        frozenset({"operator_credential_use"}),
        outcome_verifiers=fixture["broker"].outcome_verifiers(),
    )(
        tool_name="operator_credential_use",
        args=payload,
        original_args=payload,
        next_call=next_call,
    )
    parsed = json.loads(result) if isinstance(result, str) else result
    assert isinstance(parsed, dict)
    assert parsed["success"] is True
    return parsed


def access_arguments(
    scaffold: OperatorAuthenticatedAccessScaffold,
    credential_receipt_event_id: str,
    operation_id: str,
    *,
    target_id: str = "chrome-real-profile",
) -> dict[str, Any]:
    preview = scaffold.preview(
        target_id=target_id,
        credential_receipt_event_id=credential_receipt_event_id,
        purpose="resume-browser-session",
        action_scope_sha256=ACTION_SCOPE_SHA256,
    )
    return {
        "operation_id": operation_id,
        "target_id": preview.target_id,
        "credential_receipt_event_id": preview.credential_receipt_event_id,
        "purpose": preview.purpose,
        "action_scope_sha256": preview.action_scope_sha256,
        "expected_target_spec_sha256": preview.target_spec_sha256,
        "expected_credential_receipt_sha256": preview.credential_receipt_sha256,
        "expected_preview_sha256": preview.preview_sha256,
    }


def ready_readback(prepared: dict[str, Any], *, status: str = "READY") -> dict[str, Any]:
    row = prepared["prepared"]
    ready = status == "READY"
    return {
        "operation_id": row["operation_id"],
        "prepared_event_id": row["prepared_event_id"],
        "target_id": row["target_id"],
        "target_spec_sha256": row["target_spec_sha256"],
        "route": row["route"],
        "app_id": row["app_id"],
        "status": status,
        "session_binding_sha256": SESSION_BINDING_SHA256,
        "driver_receipt_sha256": DRIVER_RECEIPT_SHA256,
        "existing_session_ready": ready,
        "auth_handoff_required": not ready,
        "foreground_unchanged": True,
        "ui_action_count": 0,
        "raw_secret_exposed": False,
        "secret_input_performed": False,
    }


def forged_credential_receipt(
    fixture: dict[str, Any],
    *,
    ticket_id: str,
    provider_receipt_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": "cct.operator_credential.receipt.v1",
        "ticket_id": ticket_id,
        "claim_event_id": f"evt-{ticket_id}",
        "effect_id": f"credential-{ticket_id}",
        "handle_id": f"unregistered-{ticket_id}",
        "handle_spec_sha256": "0" * 64,
        "resolver_id": "forged-resolver",
        "provider": "forged-provider",
        "consumer_id": fixture["handle"].consumer_id,
        "owner_principal_id": "mike",
        "purpose": "resume-browser-session",
        "authority_receipt_sha256": "1" * 64,
        "preview_sha256": "2" * 64,
        "use_count": 1,
        "max_uses": 2,
        "provider_receipt_sha256": provider_receipt_sha256,
        "resolver_authenticated": True,
        "resolver_readback_verified": True,
        "resolver_effect_count": 1,
        "verification_passed": True,
        "status": "used",
        "recovered_after_resolver_crash": False,
        "raw_secret_persisted": False,
        "raw_secret_exposed": False,
        "secret_digest_persisted": False,
        "secret_locator_persisted": False,
        "resolver_raw_response_persisted": False,
        "resolver_configuration_persisted": False,
    }


def test_verified_credential_receipt_prepares_existing_profile_and_readback(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path)
    credential = issue_and_use_credential(fixture, "ticket-authenticated-access")
    receipt_event_id = str(credential["effect"]["receipt_event_id"])
    scaffold = OperatorAuthenticatedAccessScaffold(
        fixture["store"], targets=(fixture["target"],)
    )
    arguments = access_arguments(scaffold, receipt_event_id, "access-operation-one")

    prepared = json.loads(scaffold.prepare(arguments))
    prepared_replay = json.loads(scaffold.prepare(arguments))
    readback = json.loads(scaffold.record_readback(ready_readback(prepared)))
    readback_replay = json.loads(scaffold.record_readback(ready_readback(prepared)))

    assert prepared["success"] is True
    assert prepared["prepared"]["route"] == "browser_real_profile_snapshot"
    assert prepared["prepared"]["credential_handle_id"] == fixture["handle"].id
    assert prepared["prepared"]["secret_input_allowed"] is False
    assert prepared["prepared"]["execution_authority_granted"] is False
    assert prepared["prepared"]["external_effects"] == 0
    assert prepared_replay["prepared"]["replayed"] is True
    assert readback["readback"]["status"] == "READY"
    assert readback["readback"]["existing_session_ready"] is True
    assert readback["readback"]["ui_action_count"] == 0
    assert readback["readback"]["external_effects"] == 0
    assert readback_replay["readback"]["replayed"] is True

    persisted = canonical_json([event.payload for event in fixture["store"].events()])
    responses = canonical_json([prepared, readback])
    resolver_state = b"".join(
        path.read_bytes() for path in fixture["resolver_root"].glob("*.json")
    )
    assert SECRET not in fixture["store"].path.read_bytes()
    assert SECRET not in resolver_state
    assert SECRET.decode() not in persisted
    assert SECRET.decode() not in responses
    assert fixture["store"].verify_chain()["valid"] is True


def test_auth_handoff_readback_is_typed_no_action_and_no_secret_input(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path)
    credential = issue_and_use_credential(fixture, "ticket-auth-handoff")
    native_target = replace(
        fixture["target"],
        id="windows-native-session",
        target_kind="native",
        route="computer_use_existing_session",
        app_id="windows-native-app",
    )
    scaffold = OperatorAuthenticatedAccessScaffold(
        fixture["store"], targets=(native_target,)
    )
    prepared = json.loads(
        scaffold.prepare(
            access_arguments(
                scaffold,
                str(credential["effect"]["receipt_event_id"]),
                "access-auth-handoff",
                target_id=native_target.id,
            )
        )
    )

    recorded = json.loads(
        scaffold.record_readback(
            ready_readback(prepared, status="AUTH_HANDOFF_REQUIRED")
        )
    )

    assert recorded["readback"]["status"] == "AUTH_HANDOFF_REQUIRED"
    assert recorded["readback"]["route"] == "computer_use_existing_session"
    assert recorded["readback"]["existing_session_ready"] is False
    assert recorded["readback"]["auth_handoff_required"] is True
    assert recorded["readback"]["ui_action_count"] == 0
    assert recorded["readback"]["raw_secret_exposed"] is False
    assert recorded["readback"]["secret_input_performed"] is False

    unsafe = ready_readback(prepared)
    unsafe["secret_input_performed"] = True
    with pytest.raises(ValueError, match="cannot report secret handling"):
        AuthenticatedAccessHostReadback.from_arguments(unsafe)

    acted = ready_readback(prepared)
    acted["ui_action_count"] = 1
    with pytest.raises(ValueError, match="between 0 and 0"):
        AuthenticatedAccessHostReadback.from_arguments(acted)


def test_binding_preview_and_exact_schema_fail_closed(tmp_path: Path) -> None:
    fixture = configured(tmp_path)
    credential = issue_and_use_credential(fixture, "ticket-access-binding")
    receipt_event_id = str(credential["effect"]["receipt_event_id"])
    scaffold = OperatorAuthenticatedAccessScaffold(
        fixture["store"], targets=(fixture["target"],)
    )
    arguments = access_arguments(scaffold, receipt_event_id, "access-binding")

    with_extra = {**arguments, "secret": SECRET.decode()}
    with pytest.raises(ValueError, match="require exact fields"):
        scaffold.prepare(with_extra)

    stale = {**arguments, "expected_credential_receipt_sha256": "f" * 64}
    with pytest.raises(
        AuthenticatedAccessDenied, match="AUTHENTICATED_ACCESS_PREVIEW_STALE"
    ):
        scaffold.prepare(stale)

    wrong_consumer = replace(
        fixture["target"], id="wrong-consumer", consumer_id="other-consumer"
    )
    wrong_scaffold = OperatorAuthenticatedAccessScaffold(
        fixture["store"], targets=(wrong_consumer,)
    )
    with pytest.raises(
        AuthenticatedAccessDenied, match="CREDENTIAL_RECEIPT_BINDING_MISMATCH"
    ):
        wrong_scaffold.preview(
            target_id=wrong_consumer.id,
            credential_receipt_event_id=receipt_event_id,
            purpose="resume-browser-session",
            action_scope_sha256=ACTION_SCOPE_SHA256,
        )

    with pytest.raises(ValueError, match="route and target_kind are inconsistent"):
        replace(fixture["target"], id="bad-route-kind", target_kind="native")

    fake_receipt, _ = fixture["store"].append_once_result(
        "operator.credential_use.completed",
        "unsafe-credential-receipt",
        {
            "verification_passed": True,
            "status": "used",
            "resolver_authenticated": True,
            "resolver_readback_verified": True,
            "resolver_effect_count": 1,
            "raw_secret_persisted": False,
            "raw_secret_exposed": True,
            "secret_digest_persisted": False,
            "secret_locator_persisted": False,
            "resolver_raw_response_persisted": False,
            "resolver_configuration_persisted": False,
            "handle_id": fixture["handle"].id,
            "consumer_id": fixture["handle"].consumer_id,
            "owner_principal_id": "mike",
            "purpose": "resume-browser-session",
            "provider_receipt_sha256": "a" * 64,
        },
    )
    with pytest.raises(
        AuthenticatedAccessDenied, match="CREDENTIAL_RECEIPT_NOT_VERIFIED"
    ):
        scaffold.preview(
            target_id=fixture["target"].id,
            credential_receipt_event_id=fake_receipt.event_id,
            purpose="resume-browser-session",
            action_scope_sha256=ACTION_SCOPE_SHA256,
        )


def test_forged_credential_completion_requires_full_verified_provenance(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path)
    scaffold = OperatorAuthenticatedAccessScaffold(
        fixture["store"], targets=(fixture["target"],)
    )
    malformed, _ = fixture["store"].append_once_result(
        "operator.credential_use.completed",
        "forged-malformed",
        forged_credential_receipt(
            fixture,
            ticket_id="forged-malformed",
            provider_receipt_sha256="not-a-digest",
        ),
    )
    with pytest.raises(
        AuthenticatedAccessDenied, match="CREDENTIAL_RECEIPT_MALFORMED"
    ):
        scaffold.preview(
            target_id=fixture["target"].id,
            credential_receipt_event_id=malformed.event_id,
            purpose="resume-browser-session",
            action_scope_sha256=ACTION_SCOPE_SHA256,
        )

    unregistered, _ = fixture["store"].append_once_result(
        "operator.credential_use.completed",
        "forged-unregistered",
        forged_credential_receipt(
            fixture,
            ticket_id="forged-unregistered",
            provider_receipt_sha256="a" * 64,
        ),
    )
    with pytest.raises(
        AuthenticatedAccessDenied, match="CREDENTIAL_RECEIPT_PROVENANCE_INVALID"
    ):
        scaffold.preview(
            target_id=fixture["target"].id,
            credential_receipt_event_id=unregistered.event_id,
            purpose="resume-browser-session",
            action_scope_sha256=ACTION_SCOPE_SHA256,
        )

    assert not fixture["store"].events("operator.authenticated_access.prepared")
    assert fixture["store"].verify_chain()["valid"] is True


def test_duplicate_claim_and_completion_histories_fail_closed(tmp_path: Path) -> None:
    claim_root = tmp_path / "duplicate-claim"
    claim_root.mkdir()
    claim_fixture = configured(claim_root)
    claim_result = issue_and_use_credential(claim_fixture, "ticket-duplicate-claim")
    claim_receipt_id = str(claim_result["effect"]["receipt_event_id"])
    claim_receipt = claim_fixture["store"].event(claim_receipt_id)
    assert claim_receipt is not None
    claim_event = claim_fixture["store"].event(
        str(claim_receipt.payload["claim_event_id"])
    )
    assert claim_event is not None
    claim_fixture["store"].append(
        "operator.credential_use.claimed", dict(claim_event.payload)
    )
    claim_scaffold = OperatorAuthenticatedAccessScaffold(
        claim_fixture["store"], targets=(claim_fixture["target"],)
    )
    with pytest.raises(
        AuthenticatedAccessDenied, match="CREDENTIAL_RECEIPT_PROVENANCE_INVALID"
    ):
        claim_scaffold.preview(
            target_id=claim_fixture["target"].id,
            credential_receipt_event_id=claim_receipt_id,
            purpose="resume-browser-session",
            action_scope_sha256=ACTION_SCOPE_SHA256,
        )
    assert claim_fixture["store"].verify_chain()["valid"] is True

    completion_root = tmp_path / "duplicate-completion"
    completion_root.mkdir()
    completion_fixture = configured(completion_root)
    completion_result = issue_and_use_credential(
        completion_fixture, "ticket-duplicate-completion"
    )
    completion_receipt_id = str(completion_result["effect"]["receipt_event_id"])
    completion_receipt = completion_fixture["store"].event(completion_receipt_id)
    assert completion_receipt is not None
    duplicate_completion = completion_fixture["store"].append(
        "operator.credential_use.completed", dict(completion_receipt.payload)
    )
    completion_scaffold = OperatorAuthenticatedAccessScaffold(
        completion_fixture["store"], targets=(completion_fixture["target"],)
    )
    for event_id in (completion_receipt_id, duplicate_completion.event_id):
        with pytest.raises(
            AuthenticatedAccessDenied,
            match="CREDENTIAL_RECEIPT_PROVENANCE_INVALID",
        ):
            completion_scaffold.preview(
                target_id=completion_fixture["target"].id,
                credential_receipt_event_id=event_id,
                purpose="resume-browser-session",
                action_scope_sha256=ACTION_SCOPE_SHA256,
            )
    assert not completion_fixture["store"].events(
        "operator.authenticated_access.prepared"
    )
    assert completion_fixture["store"].verify_chain()["valid"] is True


def test_conflicting_host_readback_cannot_replace_verified_state(tmp_path: Path) -> None:
    fixture = configured(tmp_path)
    credential = issue_and_use_credential(fixture, "ticket-access-collision")
    scaffold = OperatorAuthenticatedAccessScaffold(
        fixture["store"], targets=(fixture["target"],)
    )
    prepared = json.loads(
        scaffold.prepare(
            access_arguments(
                scaffold,
                str(credential["effect"]["receipt_event_id"]),
                "access-collision",
            )
        )
    )
    scaffold.record_readback(ready_readback(prepared))

    conflict = ready_readback(prepared, status="AUTH_HANDOFF_REQUIRED")
    with pytest.raises(
        AuthenticatedAccessDenied, match="AUTHENTICATED_ACCESS_READBACK_COLLISION"
    ):
        scaffold.record_readback(conflict)

    mismatch = ready_readback(prepared)
    mismatch["prepared_event_id"] = str(
        fixture["store"].events("operator.authenticated_access.target_registered")[0].event_id
    )
    with pytest.raises(
        AuthenticatedAccessDenied, match="AUTHENTICATED_ACCESS_READBACK_MISMATCH"
    ):
        scaffold.record_readback(mismatch)

    assert len(
        fixture["store"].events("operator.authenticated_access.readback")
    ) == 1
    assert fixture["store"].verify_chain()["valid"] is True


def test_readback_rejects_invalid_event_chain(tmp_path: Path) -> None:
    fixture = configured(tmp_path)
    credential = issue_and_use_credential(fixture, "ticket-invalid-chain")
    receipt_event_id = str(credential["effect"]["receipt_event_id"])
    scaffold = OperatorAuthenticatedAccessScaffold(
        fixture["store"], targets=(fixture["target"],)
    )
    prepared = json.loads(
        scaffold.prepare(
            access_arguments(scaffold, receipt_event_id, "access-invalid-chain")
        )
    )
    with sqlite3.connect(fixture["store"].path) as connection:
        connection.execute(
            "UPDATE events SET payload_json = '{}' WHERE event_id = ?",
            (receipt_event_id,),
        )
        connection.commit()

    assert fixture["store"].verify_chain()["valid"] is False
    with pytest.raises(AuthenticatedAccessDenied, match="LEDGER_CHAIN_INVALID"):
        scaffold.record_readback(ready_readback(prepared))
    assert not fixture["store"].events("operator.authenticated_access.readback")
