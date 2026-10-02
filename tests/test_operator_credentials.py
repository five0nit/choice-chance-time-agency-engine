from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

import pytest

from operator_crash_matrix import race_same_ticket_recovery

from cct_agent.capabilities import CapabilityLease, CapabilityRegistry, OperatorCapabilityCatalog
from cct_agent.execution_tickets import ExecutionTicket, ExecutionTicketAuthority, GlobalKillSwitch
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.operator_credentials import (
    OPERATOR_CREDENTIAL_VERIFIER_ID,
    CredentialBrokerDenied,
    LocalFakeCredentialResolver,
    OperatorCredentialBroker,
    OperatorCredentialHandle,
)
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-25T06:30:00+00:00"
FUTURE = "2026-08-26T06:30:00+00:00"
SECRET = b"credential-private-sentinel-7846"


def configured(tmp_path: Path, *, max_uses: int = 2) -> dict[str, Any]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    installed = PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 1.0},
            directives=(
                PrincipalDirective(
                    id="operator-credential-broker",
                    kind="preference",
                    statement="Use credentials only through exact opaque host registrations.",
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
            id="lease-credential-fake",
            capability="operator.credential",
            principal_id="mike",
            scopes=("operator/credential/generalist2-fake-api",),
            expires_at=FUTURE,
            max_actions=8,
            max_bytes=0,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://lease/credential/fake",),
        )
    )
    state_root = tmp_path / "resolver-state"
    state_root.mkdir()
    handle = OperatorCredentialHandle(
        id="generalist2-fake-api",
        resolver_id="generalist2-local-fake-resolver",
        provider="local-fake-provider",
        consumer_id="staging-deployer",
        owner_principal_id="mike",
        allowed_purposes=("deploy-staging",),
        expires_at=FUTURE,
        max_uses=max_uses,
    )
    resolver = LocalFakeCredentialResolver(
        state_root=state_root,
        provider="local-fake-provider",
        consumer_id="staging-deployer",
        secrets={handle.id: SECRET},
    )
    broker = OperatorCredentialBroker(
        store,
        handles=(handle,),
        resolvers={handle.resolver_id: resolver},
    )
    return {
        "store": store,
        "profile_digest": installed["profile_digest"],
        "spec_digest": spec["spec_digest"],
        "state_root": state_root,
        "handle": handle,
        "resolver": resolver,
        "broker": broker,
    }


def preview_arguments(fixture: dict[str, Any], ticket_id: str, *, purpose: str = "deploy-staging") -> dict[str, Any]:
    preview = fixture["broker"].preview(handle_id=fixture["handle"].id, purpose=purpose)
    return {
        "execution_ticket_id": ticket_id,
        "credential_handle_id": preview.handle_id,
        "purpose": purpose,
        "expected_handle_spec_sha256": preview.handle_spec_sha256,
        "expected_authority_receipt_sha256": preview.authority_receipt_sha256,
        "expected_before_state_sha256": preview.before_state_sha256,
        "expected_preview_sha256": preview.preview_sha256,
        "verifier_id": OPERATOR_CREDENTIAL_VERIFIER_ID,
    }


def issue(fixture: dict[str, Any], payload: dict[str, Any]) -> None:
    ticket_id = str(payload["execution_ticket_id"])
    ExecutionTicketAuthority(fixture["store"]).issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name="operator_credential_use",
            arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
            goal_id="goal-cct-full-operator-effects",
            plan_id=f"plan-{ticket_id}",
            plan_hash=sha256(f"plan:{ticket_id}".encode()).hexdigest(),
            stage="use-brokered-credential",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=fixture["profile_digest"],
            capability="operator.credential",
            capability_spec_digest=fixture["spec_digest"],
            lease_id="lease-credential-fake",
            scope="operator/credential/generalist2-fake-api",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=0,
            value_budget_microunits=0,
        ),
        authority="operator",
        evidence=(f"operator://goal/{ticket_id}",),
    )


def mediated(fixture: dict[str, Any], payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    calls = 0

    def next_call() -> str:
        nonlocal calls
        calls += 1
        return fixture["broker"].execute(payload)

    value = ToolExecutionMediator(
        fixture["store"],
        frozenset({"operator_credential_use"}),
        outcome_verifiers=fixture["broker"].outcome_verifiers(),
    )(
        tool_name="operator_credential_use",
        args=payload,
        original_args=payload,
        next_call=next_call,
    )
    parsed = json.loads(value) if isinstance(value, str) else value
    assert isinstance(parsed, dict)
    return parsed, calls


def test_ticketed_opaque_handle_use_retry_and_zero_secret_leakage(tmp_path: Path) -> None:
    fixture = configured(tmp_path)
    payload = preview_arguments(fixture, "ticket-credential-one")
    assert SECRET.decode() not in canonical_json(payload)
    issue(fixture, payload)

    used, calls = mediated(fixture, payload)
    replay, replay_calls = mediated(fixture, payload)

    assert used["success"] is True
    assert used["credential_use"]["handle_id"] == "generalist2-fake-api"
    assert used["credential_use"]["provider"] == "local-fake-provider"
    assert used["credential_use"]["consumer_id"] == "staging-deployer"
    assert used["credential_use"]["purpose"] == "deploy-staging"
    assert used["credential_use"]["resolver_authenticated"] is True
    assert used["credential_use"]["use_count"] == 1
    assert used["credential_use"]["raw_secret_exposed"] is False
    assert calls == 1
    assert replay["success"] is True
    assert replay["mediation"]["recovered_after_restart"] is True
    assert replay_calls == 0
    assert fixture["resolver"].mutation_count == 1

    persisted = canonical_json([event.payload for event in fixture["store"].events()])
    state_bytes = b"".join(path.read_bytes() for path in fixture["state_root"].glob("*.json"))
    response = canonical_json(used)
    assert SECRET not in fixture["store"].path.read_bytes()
    assert SECRET not in state_bytes
    assert SECRET.decode() not in persisted
    assert SECRET.decode() not in response
    assert fixture["store"].verify_chain()["valid"] is True


@pytest.mark.operator_crash_matrix
def test_post_resolver_crash_reconciles_without_second_secret_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = configured(tmp_path)
    payload = preview_arguments(fixture, "ticket-credential-crash")
    issue(fixture, payload)

    def crash(*_args: Any, **_kwargs: Any) -> Any:
        raise SystemExit("simulated post-resolver crash")

    monkeypatch.setattr(fixture["broker"], "_record_completion", crash)
    with pytest.raises(SystemExit, match="simulated post-resolver crash"):
        mediated(fixture, payload)
    assert fixture["resolver"].mutation_count == 1
    assert not fixture["store"].events("operator.credential_use.completed")

    restarted_resolver = LocalFakeCredentialResolver(
        state_root=fixture["state_root"],
        provider="local-fake-provider",
        consumer_id="staging-deployer",
        secrets={fixture["handle"].id: SECRET},
    )
    restarted_broker = OperatorCredentialBroker(
        fixture["store"],
        handles=(fixture["handle"],),
        resolvers={fixture["handle"].resolver_id: restarted_resolver},
    )
    fixture["resolver"] = restarted_resolver
    fixture["broker"] = restarted_broker
    recoveries = race_same_ticket_recovery(lambda: mediated(fixture, payload))

    assert all(recovered["success"] is True for recovered in recoveries)
    assert restarted_resolver.mutation_count == 0
    completions = fixture["store"].events("operator.credential_use.completed")
    assert len(completions) == 1
    assert completions[0].payload["recovered_after_resolver_crash"] is True


def test_max_use_cap_is_atomic_across_concurrent_tickets(tmp_path: Path) -> None:
    fixture = configured(tmp_path, max_uses=1)
    payloads = [preview_arguments(fixture, f"ticket-credential-cap-{index}") for index in range(2)]
    for payload in payloads:
        issue(fixture, payload)
        ExecutionTicketAuthority(fixture["store"]).claim_dispatch(
            ticket_id=str(payload["execution_ticket_id"]),
            tool_name="operator_credential_use",
            arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
            registered_verifier_ids=frozenset({OPERATOR_CREDENTIAL_VERIFIER_ID}),
        )

    def run(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            return json.loads(fixture["broker"].execute(payload))
        except CredentialBrokerDenied as error:
            return {"denied": error.reason_code}

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, payloads))

    assert sum(row.get("success") is True for row in results) == 1
    assert sum(row.get("denied") == "CREDENTIAL_HANDLE_USE_CAP_EXHAUSTED" for row in results) == 1
    assert fixture["resolver"].mutation_count == 1
    assert len(fixture["store"].events("operator.credential_use.claimed")) == 1


def test_expiry_owner_binding_kill_switch_and_raw_secret_fields_fail_closed(tmp_path: Path) -> None:
    fixture = configured(tmp_path)
    wrong_owner = replace(fixture["handle"], id="wrong-owner", owner_principal_id="other")
    with pytest.raises(ValueError, match="owner must match installed principal"):
        OperatorCredentialBroker(
            fixture["store"],
            handles=(wrong_owner,),
            resolvers={fixture["handle"].resolver_id: fixture["resolver"]},
        )

    expired = replace(
        fixture["handle"],
        id="expired-handle",
        expires_at="2026-08-24T06:30:00+00:00",
    )
    expired_root = tmp_path / "expired-resolver-state"
    expired_root.mkdir()
    expired_resolver = LocalFakeCredentialResolver(
        state_root=expired_root,
        provider="local-fake-provider",
        consumer_id="staging-deployer",
        secrets={expired.id: SECRET},
    )
    expired_broker = OperatorCredentialBroker(
        fixture["store"],
        handles=(expired,),
        resolvers={expired.resolver_id: expired_resolver},
    )
    with pytest.raises(CredentialBrokerDenied, match="CREDENTIAL_HANDLE_EXPIRED"):
        expired_broker.preview(handle_id=expired.id, purpose="deploy-staging")

    payload = preview_arguments(fixture, "ticket-credential-killed")
    payload["secret"] = SECRET.decode()
    with pytest.raises(ValueError, match="exact fields"):
        fixture["broker"].execute(payload)
    del payload["secret"]
    issue(fixture, payload)
    GlobalKillSwitch(fixture["store"]).trip(
        trip_id="kill-before-credential-use",
        authority="operator",
        reason="Stop credential use.",
    )
    result, calls = mediated(fixture, payload)
    assert result["success"] is False
    assert result["error"]["reasons"] == ["GLOBAL_KILL_SWITCH_ACTIVE"]
    assert calls == 0
    assert fixture["resolver"].mutation_count == 0
