from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

from operator_crash_matrix import race_same_ticket_recovery

from cct_agent.capabilities import CapabilityLease, CapabilityRegistry, OperatorCapabilityCatalog
from cct_agent.execution_tickets import ExecutionTicket, ExecutionTicketAuthority, GlobalKillSwitch
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.operator_finance import (
    OPERATOR_FINANCIAL_VERIFIER_ID,
    FinancialEffectDenied,
    LocalFakeFinancialDriver,
    OperatorFinancialAccount,
    OperatorFinancialAdapter,
    ProviderFinancialAuthority,
)
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-25T09:45:00+00:00"
FUTURE = "2026-08-26T09:45:00+00:00"


def configured(
    tmp_path: Path,
    *,
    daily_value_cap: int = 5_000_000,
    daily_loss_cap: int = 1_000_000,
) -> dict[str, Any]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    installed = PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 1.0},
            directives=(
                PrincipalDirective(
                    id="operator-financial-fake",
                    kind="preference",
                    statement="Financial effects require exact value and loss budgets.",
                    tags=("domain:operator", "action:financial"),
                    priority=100,
                ),
            ),
        ),
        authority="operator",
        evidence=("operator://profile",),
    )
    spec = OperatorCapabilityCatalog(store).install()["financial"]
    CapabilityRegistry(store).grant(
        CapabilityLease(
            id="lease-financial-fake",
            capability="operator.financial",
            principal_id="mike",
            scopes=("operator/financial/generalist2-paper-account",),
            expires_at=FUTURE,
            max_actions=16,
            max_bytes=0,
            max_value_microunits=10_000_000,
            issued_by="operator",
            evidence=("operator://lease/financial/fake",),
        )
    )
    state_root = tmp_path / "fake-financial-state"
    state_root.mkdir()
    account = OperatorFinancialAccount(
        id="generalist2-paper-account",
        driver_id="generalist2-local-fake-financial",
        provider="local-fake-financial",
        account_id="paper-wallet",
        owner_principal_id="mike",
        allowed_instruments=("TEST-USD",),
        allowed_actions=("buy", "sell"),
        max_order_value_microunits=min(2_000_000, daily_value_cap),
        max_order_loss_microunits=min(500_000, daily_loss_cap),
        daily_value_cap_microunits=daily_value_cap,
        daily_loss_cap_microunits=daily_loss_cap,
        real_value_effect=False,
    )
    driver = LocalFakeFinancialDriver(
        state_root=state_root,
        provider="local-fake-financial",
    )
    adapter = OperatorFinancialAdapter(
        store,
        accounts=(account,),
        drivers={account.driver_id: driver},
    )
    return {
        "store": store,
        "profile_digest": installed["profile_digest"],
        "spec_digest": spec["spec_digest"],
        "state_root": state_root,
        "account": account,
        "driver": driver,
        "adapter": adapter,
    }


def preview_arguments(
    fixture: dict[str, Any],
    ticket_id: str,
    *,
    action: str = "buy",
    value: int = 1_000_000,
    worst_loss: int = 200_000,
) -> dict[str, Any]:
    preview = fixture["adapter"].preview(
        account_id=fixture["account"].id,
        instrument="TEST-USD",
        action=action,
        value_microunits=value,
        worst_case_loss_microunits=worst_loss,
    )
    return {
        "execution_ticket_id": ticket_id,
        "financial_account_id": preview.account_id,
        "instrument": preview.instrument,
        "action": preview.action,
        "value_microunits": value,
        "worst_case_loss_microunits": worst_loss,
        "expected_account_spec_sha256": preview.account_spec_sha256,
        "expected_authority_receipt_sha256": preview.authority_receipt_sha256,
        "expected_before_state_sha256": preview.before_state_sha256,
        "expected_preview_sha256": preview.preview_sha256,
        "verifier_id": OPERATOR_FINANCIAL_VERIFIER_ID,
    }


def issue(
    fixture: dict[str, Any],
    payload: dict[str, Any],
    *,
    ticket_value_budget: int | None = None,
) -> None:
    ticket_id = str(payload["execution_ticket_id"])
    value_budget = (
        int(payload["value_microunits"])
        if ticket_value_budget is None
        else ticket_value_budget
    )
    ExecutionTicketAuthority(fixture["store"]).issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name="operator_financial_effect",
            arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
            goal_id="goal-cct-full-operator-effects",
            plan_id=f"plan-{ticket_id}",
            plan_hash=sha256(f"plan:{ticket_id}".encode()).hexdigest(),
            stage="execute-financial-effect",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=fixture["profile_digest"],
            capability="operator.financial",
            capability_spec_digest=fixture["spec_digest"],
            lease_id="lease-financial-fake",
            scope="operator/financial/generalist2-paper-account",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=0,
            value_budget_microunits=value_budget,
        ),
        authority="operator",
        evidence=(f"operator://goal/{ticket_id}",),
    )


def mediated(fixture: dict[str, Any], payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    calls = 0

    def next_call() -> str:
        nonlocal calls
        calls += 1
        return fixture["adapter"].execute(payload)

    value = ToolExecutionMediator(
        fixture["store"],
        frozenset({"operator_financial_effect"}),
        outcome_verifiers=fixture["adapter"].outcome_verifiers(),
    )(
        tool_name="operator_financial_effect",
        args=payload,
        original_args=payload,
        next_call=next_call,
    )
    parsed = json.loads(value) if isinstance(value, str) else value
    assert isinstance(parsed, dict)
    return parsed, calls


def test_ticketed_fake_trade_readback_retry_and_no_real_value_effect(tmp_path: Path) -> None:
    fixture = configured(tmp_path)
    payload = preview_arguments(fixture, "ticket-financial-one")
    issue(fixture, payload)

    result, calls = mediated(fixture, payload)
    replay, replay_calls = mediated(fixture, payload)

    assert result["success"] is True
    assert result["financial_effect"]["provider"] == "local-fake-financial"
    assert result["financial_effect"]["account_id"] == "paper-wallet"
    assert result["financial_effect"]["instrument"] == "TEST-USD"
    assert result["financial_effect"]["action"] == "buy"
    assert result["financial_effect"]["value_microunits"] == 1_000_000
    assert result["financial_effect"]["worst_case_loss_microunits"] == 200_000
    assert result["financial_effect"]["provider_readback_verified"] is True
    assert result["financial_effect"]["real_value_effect"] is False
    assert result["financial_effect"]["credential_handles_used"] == []
    assert calls == 1
    assert replay["success"] is True
    assert replay["mediation"]["recovered_after_restart"] is True
    assert replay_calls == 0
    assert fixture["driver"].mutation_count == 1
    assert fixture["store"].verify_chain()["valid"] is True


@pytest.mark.operator_crash_matrix
def test_post_provider_crash_recovers_without_second_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = configured(tmp_path)
    payload = preview_arguments(fixture, "ticket-financial-crash")
    issue(fixture, payload)

    def crash(*_args: Any, **_kwargs: Any) -> Any:
        raise SystemExit("simulated post-financial-provider crash")

    monkeypatch.setattr(fixture["adapter"], "_record_completion", crash)
    with pytest.raises(SystemExit, match="simulated post-financial-provider crash"):
        mediated(fixture, payload)
    assert fixture["driver"].mutation_count == 1
    assert not fixture["store"].events("operator.financial_effect.completed")

    restarted_driver = LocalFakeFinancialDriver(
        state_root=fixture["state_root"],
        provider="local-fake-financial",
    )
    restarted_adapter = OperatorFinancialAdapter(
        fixture["store"],
        accounts=(fixture["account"],),
        drivers={fixture["account"].driver_id: restarted_driver},
    )
    fixture["driver"] = restarted_driver
    fixture["adapter"] = restarted_adapter
    recoveries = race_same_ticket_recovery(lambda: mediated(fixture, payload))

    assert all(recovered["success"] is True for recovered in recoveries)
    assert restarted_driver.mutation_count == 0
    completions = fixture["store"].events("operator.financial_effect.completed")
    assert len(completions) == 1
    assert completions[0].payload["recovered_after_provider_crash"] is True


def test_daily_value_and_loss_caps_are_atomic(tmp_path: Path) -> None:
    fixture = configured(
        tmp_path,
        daily_value_cap=1_000_000,
        daily_loss_cap=200_000,
    )
    payloads = [
        preview_arguments(
            fixture,
            f"ticket-financial-cap-{index}",
            value=1_000_000,
            worst_loss=200_000,
        )
        for index in range(2)
    ]
    for payload in payloads:
        issue(fixture, payload)
        ExecutionTicketAuthority(fixture["store"]).claim_dispatch(
            ticket_id=str(payload["execution_ticket_id"]),
            tool_name="operator_financial_effect",
            arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
            registered_verifier_ids=frozenset({OPERATOR_FINANCIAL_VERIFIER_ID}),
        )

    original_preview = fixture["adapter"].preview
    preview_barrier = Barrier(2)

    def synchronized_preview(**kwargs: Any) -> Any:
        preview = original_preview(**kwargs)
        preview_barrier.wait(timeout=10)
        return preview

    fixture["adapter"].preview = synchronized_preview

    def run(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            return json.loads(fixture["adapter"].execute(payload))
        except FinancialEffectDenied as error:
            return {"denied": error.reason_code}

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, payloads))

    assert sum(row.get("success") is True for row in results) == 1
    assert sum(
        row.get("denied") in {
            "FINANCIAL_DAILY_VALUE_CAP_EXHAUSTED",
            "FINANCIAL_DAILY_LOSS_CAP_EXHAUSTED",
        }
        for row in results
    ) == 1
    assert fixture["driver"].mutation_count == 1
    assert len(fixture["store"].events("operator.financial_effect.claimed")) == 1


def test_ticket_value_loss_binding_owner_real_authority_and_kill_fail_closed(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path)
    underbudget = preview_arguments(fixture, "ticket-financial-underbudget")
    issue(fixture, underbudget, ticket_value_budget=999_999)
    ExecutionTicketAuthority(fixture["store"]).claim_dispatch(
        ticket_id="ticket-financial-underbudget",
        tool_name="operator_financial_effect",
        arguments_sha256=sha256(canonical_json(underbudget).encode()).hexdigest(),
        registered_verifier_ids=frozenset({OPERATOR_FINANCIAL_VERIFIER_ID}),
    )
    with pytest.raises(
        FinancialEffectDenied,
        match="TICKET_DISPATCH_CLAIM_MISMATCH",
    ):
        fixture["adapter"].execute(underbudget)
    assert fixture["driver"].mutation_count == 0

    wrong_owner = replace(fixture["account"], id="wrong-owner", owner_principal_id="other")
    with pytest.raises(ValueError, match="owner must match installed principal"):
        OperatorFinancialAdapter(
            fixture["store"],
            accounts=(wrong_owner,),
            drivers={fixture["account"].driver_id: fixture["driver"]},
        )

    real_target = replace(
        fixture["account"],
        id="real-account",
        real_value_effect=True,
    )
    unauthenticated = ProviderFinancialAuthority(
        target_id="real-account",
        provider=real_target.provider,
        account_id=real_target.account_id,
        owner_principal_id="mike",
        authenticated=False,
        real_value_effect=True,
        authority_receipt_sha256="a" * 64,
    )
    monkeypatch_authority = fixture["driver"].authority
    fixture["driver"].authority = lambda _target: unauthenticated  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="authenticated provider authority"):
        OperatorFinancialAdapter(
            fixture["store"],
            accounts=(real_target,),
            drivers={fixture["account"].driver_id: fixture["driver"]},
        )
    fixture["driver"].authority = monkeypatch_authority  # type: ignore[method-assign]

    killed = preview_arguments(fixture, "ticket-financial-killed", action="sell")
    issue(fixture, killed)
    GlobalKillSwitch(fixture["store"]).trip(
        trip_id="kill-before-financial-effect",
        authority="operator",
        reason="Stop financial effect.",
    )
    result, calls = mediated(fixture, killed)
    assert result["success"] is False
    assert result["error"]["reasons"] == ["GLOBAL_KILL_SWITCH_ACTIVE"]
    assert calls == 0
    assert fixture["driver"].mutation_count == 0
