from __future__ import annotations

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
from cct_agent.operator_high_consequence import (
    OPERATOR_HIGH_CONSEQUENCE_VERIFIER_ID,
    AuthenticatedGoalEffectAuthority,
    HighConsequenceEffectDenied,
    LocalFakeHighConsequenceDriver,
    OperatorHighConsequenceAdapter,
    OperatorHighConsequenceTarget,
    ProviderHighConsequenceAuthority,
)
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-25T10:00:00+00:00"
FUTURE = "2026-08-26T10:00:00+00:00"
GOAL_ID = "goal-cct-full-operator-effects"
EFFECT_ARGUMENTS_SHA256 = sha256(b"fake service suspension arguments").hexdigest()
DEPENDENCY_PROOF_SHA256 = sha256(b"fake dependency proof").hexdigest()
DECISION_RECEIPT_SHA256 = sha256(b"authenticated operator decision receipt").hexdigest()


def configured(
    tmp_path: Path,
    *,
    authorized_ticket_id: str = "ticket-high-consequence-one",
    reversible: bool = True,
    real_effect: bool = False,
    decision_authenticated: bool = True,
    irreversible_acknowledged: bool = False,
) -> dict[str, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    installed = PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 1.0},
            directives=(
                PrincipalDirective(
                    id="operator-high-consequence-fake",
                    kind="preference",
                    statement="High-consequence effects require exact authenticated decisions.",
                    tags=("domain:operator", "action:high_consequence"),
                    priority=100,
                ),
            ),
        ),
        authority="operator",
        evidence=("operator://profile",),
    )
    spec = OperatorCapabilityCatalog(store).install()["high_consequence"]
    CapabilityRegistry(store).grant(
        CapabilityLease(
            id="lease-high-consequence-fake",
            capability="operator.high_consequence",
            principal_id="mike",
            scopes=("operator/high_consequence/generalist2-fake-control",),
            expires_at=FUTURE,
            max_actions=16,
            max_bytes=0,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://lease/high-consequence/fake",),
        )
    )
    target = OperatorHighConsequenceTarget(
        id="generalist2-fake-control",
        driver_id="generalist2-local-fake-high-consequence",
        provider="local-fake-high-consequence",
        owner_principal_id="mike",
        consequence_class="service-control",
        allowed_effects=("suspend-service",),
        reversible=reversible,
        real_effect=real_effect,
    )
    authority = AuthenticatedGoalEffectAuthority(
        id="authority-service-suspension",
        ticket_id=authorized_ticket_id,
        authority="operator",
        authenticated=decision_authenticated,
        principal_id="mike",
        goal_id=GOAL_ID,
        target_id=target.id,
        consequence_class=target.consequence_class,
        effect_name="suspend-service",
        effect_arguments_sha256=EFFECT_ARGUMENTS_SHA256,
        dependency_proof_sha256=DEPENDENCY_PROOF_SHA256,
        principal_decision_receipt_sha256=DECISION_RECEIPT_SHA256,
        irreversible_acknowledged=irreversible_acknowledged,
        expires_at=FUTURE,
    )
    state_root = tmp_path / "fake-high-consequence-state"
    state_root.mkdir()
    driver = LocalFakeHighConsequenceDriver(
        state_root=state_root,
        provider="local-fake-high-consequence",
    )
    adapter = OperatorHighConsequenceAdapter(
        store,
        targets=(target,),
        goal_effect_authorities=(authority,),
        drivers={target.driver_id: driver},
    )
    return {
        "store": store,
        "profile_digest": installed["profile_digest"],
        "spec_digest": spec["spec_digest"],
        "state_root": state_root,
        "target": target,
        "authority": authority,
        "driver": driver,
        "adapter": adapter,
    }


def preview_arguments(fixture: dict[str, Any], ticket_id: str) -> dict[str, Any]:
    preview = fixture["adapter"].preview(
        goal_effect_authority_id=fixture["authority"].id,
    )
    return {
        "execution_ticket_id": ticket_id,
        "goal_effect_authority_id": preview.goal_effect_authority_id,
        "high_consequence_target_id": preview.target_id,
        "goal_id": preview.goal_id,
        "consequence_class": preview.consequence_class,
        "effect_name": preview.effect_name,
        "effect_arguments_sha256": preview.effect_arguments_sha256,
        "dependency_proof_sha256": preview.dependency_proof_sha256,
        "principal_decision_receipt_sha256": preview.principal_decision_receipt_sha256,
        "irreversible_acknowledged": preview.irreversible_acknowledged,
        "expected_target_spec_sha256": preview.target_spec_sha256,
        "expected_provider_authority_receipt_sha256": (
            preview.provider_authority_receipt_sha256
        ),
        "expected_before_state_sha256": preview.before_state_sha256,
        "expected_preview_sha256": preview.preview_sha256,
        "verifier_id": OPERATOR_HIGH_CONSEQUENCE_VERIFIER_ID,
    }


def issue(
    fixture: dict[str, Any],
    payload: dict[str, Any],
    *,
    goal_id: str = GOAL_ID,
) -> None:
    ticket_id = str(payload["execution_ticket_id"])
    ExecutionTicketAuthority(fixture["store"]).issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name="operator_high_consequence_effect",
            arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
            goal_id=goal_id,
            plan_id=f"plan-{ticket_id}",
            plan_hash=sha256(f"plan:{ticket_id}".encode()).hexdigest(),
            stage="execute-high-consequence-effect",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=fixture["profile_digest"],
            capability="operator.high_consequence",
            capability_spec_digest=fixture["spec_digest"],
            lease_id="lease-high-consequence-fake",
            scope="operator/high_consequence/generalist2-fake-control",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=0,
            value_budget_microunits=0,
        ),
        authority="operator",
        evidence=(f"operator://goal-effect/{ticket_id}",),
    )


def mediated(fixture: dict[str, Any], payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    calls = 0

    def next_call() -> str:
        nonlocal calls
        calls += 1
        return fixture["adapter"].execute(payload)

    value = ToolExecutionMediator(
        fixture["store"],
        frozenset({"operator_high_consequence_effect"}),
        outcome_verifiers=fixture["adapter"].outcome_verifiers(),
    )(
        tool_name="operator_high_consequence_effect",
        args=payload,
        original_args=payload,
        next_call=next_call,
    )
    parsed = json.loads(value) if isinstance(value, str) else value
    assert isinstance(parsed, dict)
    return parsed, calls


def test_exact_authenticated_goal_effect_executes_with_temporal_receipt_and_replay(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path)
    payload = preview_arguments(fixture, "ticket-high-consequence-one")
    issue(fixture, payload)

    result, calls = mediated(fixture, payload)
    replay, replay_calls = mediated(fixture, payload)

    consequence = result["high_consequence_effect"]
    assert result["success"] is True
    assert consequence["goal_id"] == GOAL_ID
    assert consequence["target_id"] == "generalist2-fake-control"
    assert consequence["consequence_class"] == "service-control"
    assert consequence["effect_name"] == "suspend-service"
    assert consequence["principal_decision_receipt_sha256"] == DECISION_RECEIPT_SHA256
    assert consequence["dependency_proof_sha256"] == DEPENDENCY_PROOF_SHA256
    assert consequence["before_state_sha256"] != consequence["after_state_sha256"]
    assert consequence["provider_readback_verified"] is True
    assert consequence["realized_outcome_sha256"]
    assert consequence["rollback_status"] == "available-not-invoked"
    assert consequence["unwind_status"] == "not-applicable"
    assert consequence["real_effect"] is False
    assert consequence["producer_prose_persisted"] is False
    assert result["policy_learning"] == {
        "requires_endorsement": True,
        "self_ratification_allowed": False,
        "status": "proposed",
        "evidence_sha256": consequence["realized_outcome_sha256"],
    }
    assert calls == 1
    assert replay["success"] is True
    assert replay["mediation"]["recovered_after_restart"] is True
    assert replay_calls == 0
    assert fixture["driver"].mutation_count == 1
    assert len(fixture["store"].events("operator.high_consequence.policy_learning.proposed")) == 1
    assert fixture["store"].verify_chain()["valid"] is True


@pytest.mark.operator_crash_matrix
def test_post_provider_crash_adopts_effect_without_second_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = configured(
        tmp_path,
        authorized_ticket_id="ticket-high-consequence-crash",
    )
    payload = preview_arguments(fixture, "ticket-high-consequence-crash")
    issue(fixture, payload)

    def crash(*_args: Any, **_kwargs: Any) -> Any:
        raise SystemExit("simulated post-high-consequence-provider crash")

    monkeypatch.setattr(fixture["adapter"], "_record_completion", crash)
    with pytest.raises(SystemExit, match="simulated post-high-consequence-provider crash"):
        mediated(fixture, payload)
    assert fixture["driver"].mutation_count == 1
    assert not fixture["store"].events("operator.high_consequence_effect.completed")

    restarted_driver = LocalFakeHighConsequenceDriver(
        state_root=fixture["state_root"],
        provider="local-fake-high-consequence",
    )
    restarted_adapter = OperatorHighConsequenceAdapter(
        fixture["store"],
        targets=(fixture["target"],),
        goal_effect_authorities=(fixture["authority"],),
        drivers={fixture["target"].driver_id: restarted_driver},
    )
    fixture["driver"] = restarted_driver
    fixture["adapter"] = restarted_adapter
    recoveries = race_same_ticket_recovery(lambda: mediated(fixture, payload))

    assert all(recovered["success"] is True for recovered in recoveries)
    assert restarted_driver.mutation_count == 0
    completions = fixture["store"].events("operator.high_consequence_effect.completed")
    assert len(completions) == 1
    assert completions[0].payload["recovered_after_provider_crash"] is True


def test_generic_prose_wrong_goal_and_missing_irreversible_ack_cannot_authorize(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="authenticated goal-effect authority"):
        configured(tmp_path / "unauthenticated", decision_authenticated=False)

    with pytest.raises(ValueError, match="irreversible effect requires acknowledgement"):
        configured(tmp_path / "irreversible", reversible=False)

    fixture = configured(
        tmp_path / "wrong-goal",
        authorized_ticket_id="ticket-high-consequence-wrong-goal",
    )
    payload = preview_arguments(fixture, "ticket-high-consequence-wrong-goal")
    issue(fixture, payload, goal_id="generic-user-prose-goal")
    ExecutionTicketAuthority(fixture["store"]).claim_dispatch(
        ticket_id=str(payload["execution_ticket_id"]),
        tool_name="operator_high_consequence_effect",
        arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
        registered_verifier_ids=frozenset(
            {OPERATOR_HIGH_CONSEQUENCE_VERIFIER_ID}
        ),
    )
    with pytest.raises(
        HighConsequenceEffectDenied,
        match="HIGH_CONSEQUENCE_TICKET_GOAL_MISMATCH",
    ):
        fixture["adapter"].execute(payload)
    result, calls = mediated(fixture, payload)
    assert result["success"] is False
    assert result["error"]["reasons"] == [
        "CLAIM_WITHOUT_RECEIPT",
        "EFFECT_NOT_OBSERVED",
    ]
    assert calls == 0
    assert fixture["driver"].mutation_count == 0

    with pytest.raises(ValueError, match="exact fields"):
        fixture["adapter"].execute({**payload, "generic_operator_instruction": "do it"})

    replay_fixture = configured(
        tmp_path / "ticket-reuse",
        authorized_ticket_id="ticket-high-consequence-authorized",
    )
    replayed_authority = preview_arguments(
        replay_fixture,
        "ticket-high-consequence-not-authorized",
    )
    issue(replay_fixture, replayed_authority)
    ExecutionTicketAuthority(replay_fixture["store"]).claim_dispatch(
        ticket_id="ticket-high-consequence-not-authorized",
        tool_name="operator_high_consequence_effect",
        arguments_sha256=sha256(
            canonical_json(replayed_authority).encode()
        ).hexdigest(),
        registered_verifier_ids=frozenset(
            {OPERATOR_HIGH_CONSEQUENCE_VERIFIER_ID}
        ),
    )
    with pytest.raises(
        HighConsequenceEffectDenied,
        match="HIGH_CONSEQUENCE_AUTHORITY_BINDING_MISMATCH",
    ):
        replay_fixture["adapter"].execute(replayed_authority)
    assert replay_fixture["driver"].mutation_count == 0


def test_real_provider_authority_direct_dispatch_and_kill_switch_fail_closed(
    tmp_path: Path,
) -> None:
    fixture = configured(
        tmp_path / "base",
        authorized_ticket_id="ticket-high-consequence-direct",
    )
    payload = preview_arguments(fixture, "ticket-high-consequence-direct")
    with pytest.raises(
        HighConsequenceEffectDenied,
        match="TICKET_DISPATCH_CLAIM_REQUIRED",
    ):
        fixture["adapter"].execute(payload)
    assert fixture["driver"].mutation_count == 0

    real_target = replace(fixture["target"], id="real-target", real_effect=True)
    unauthenticated = ProviderHighConsequenceAuthority(
        target_id="real-target",
        provider=real_target.provider,
        owner_principal_id="mike",
        authenticated=False,
        real_effect=True,
        authority_receipt_sha256="a" * 64,
    )
    original_authority = fixture["driver"].authority
    fixture["driver"].authority = lambda _target: unauthenticated  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="authenticated provider authority"):
        OperatorHighConsequenceAdapter(
            fixture["store"],
            targets=(real_target,),
            goal_effect_authorities=(replace(fixture["authority"], target_id="real-target"),),
            drivers={fixture["target"].driver_id: fixture["driver"]},
        )
    fixture["driver"].authority = original_authority  # type: ignore[method-assign]

    killed_fixture = configured(
        tmp_path / "killed",
        authorized_ticket_id="ticket-high-consequence-killed",
    )
    killed = preview_arguments(killed_fixture, "ticket-high-consequence-killed")
    issue(killed_fixture, killed)
    GlobalKillSwitch(killed_fixture["store"]).trip(
        trip_id="kill-before-high-consequence-effect",
        authority="operator",
        reason="Stop high-consequence effect.",
    )
    result, calls = mediated(killed_fixture, killed)
    assert result["success"] is False
    assert result["error"]["reasons"] == ["GLOBAL_KILL_SWITCH_ACTIVE"]
    assert calls == 0
    assert killed_fixture["driver"].mutation_count == 0
