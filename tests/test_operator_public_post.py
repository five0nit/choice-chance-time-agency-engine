from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import threading
from typing import Any

import pytest

from operator_crash_matrix import race_same_ticket_recovery

from cct_agent.capabilities import CapabilityLease, CapabilityRegistry, OperatorCapabilityCatalog
from cct_agent.execution_tickets import ExecutionTicket, ExecutionTicketAuthority, GlobalKillSwitch
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.public_actions import (
    OPERATOR_PUBLIC_POST_VERIFIER_ID,
    LocalFakePublicChannelDriver,
    OperatorPublicChannel,
    OperatorPublicPostAdapter,
    ProviderPublicChannelAuthority,
    PublicActionDenied,
)
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-25T04:00:00+00:00"
FUTURE = "2026-08-26T04:00:00+00:00"
PRIVATE_SENTINEL = "PUBLIC_POST_PRIVATE_43d7"
CONTENT = f"Bounded fake-provider acceptance. {PRIVATE_SENTINEL}"


def configured(tmp_path: Path, *, daily_action_cap: int = 2) -> dict[str, Any]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    installed = PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 1.0},
            directives=(
                PrincipalDirective(
                    id="operator-public-post",
                    kind="preference",
                    statement="Publish only through exact host-registered account and channel bindings.",
                    tags=("domain:operator", "action:public"),
                    priority=90,
                ),
            ),
        ),
        authority="operator",
        evidence=("operator://profile",),
    )
    spec = OperatorCapabilityCatalog(store).install()["public"]
    CapabilityRegistry(store).grant(
        CapabilityLease(
            id="lease-public-fake-channel",
            capability="operator.public",
            principal_id="mike",
            scopes=("operator/public/generalist2-fake-announcements",),
            expires_at=FUTURE,
            max_actions=8,
            max_bytes=65_536,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://lease/public/fake-channel",),
        )
    )
    state_root = tmp_path / "fake-provider-state"
    state_root.mkdir()
    target = OperatorPublicChannel(
        id="generalist2-fake-announcements",
        driver_id="generalist2-local-fake-public",
        provider="local-fake-public",
        account_id="generalist2",
        channel_id="announcements",
        recipient_id="public-feed",
        owner_principal_id="mike",
        max_content_bytes=4096,
        daily_action_cap=daily_action_cap,
        real_public_effect=False,
    )
    driver = LocalFakePublicChannelDriver(
        state_root=state_root,
        provider="local-fake-public",
    )
    adapter = OperatorPublicPostAdapter(
        store,
        channels=(target,),
        drivers={"generalist2-local-fake-public": driver},
    )
    return {
        "store": store,
        "profile_digest": installed["profile_digest"],
        "spec_digest": spec["spec_digest"],
        "state_root": state_root,
        "target": target,
        "driver": driver,
        "adapter": adapter,
    }


def preview_arguments(
    fixture: dict[str, Any],
    ticket_id: str,
    *,
    content: str = CONTENT,
) -> dict[str, Any]:
    preview = fixture["adapter"].preview(
        channel_id="generalist2-fake-announcements",
        content=content,
    )
    return {
        "execution_ticket_id": ticket_id,
        "channel_id": preview.channel_id,
        "content": content,
        "expected_content_sha256": preview.content_sha256,
        "expected_content_byte_count": preview.content_byte_count,
        "expected_before_state_sha256": preview.before_state_sha256,
        "expected_preview_sha256": preview.preview_sha256,
        "verifier_id": OPERATOR_PUBLIC_POST_VERIFIER_ID,
        "max_bytes": 4096,
    }


def issue(fixture: dict[str, Any], payload: dict[str, Any]) -> None:
    ticket_id = str(payload["execution_ticket_id"])
    ExecutionTicketAuthority(fixture["store"]).issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name="operator_public_post",
            arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
            goal_id="goal-cct-full-operator-effects",
            plan_id=f"plan-{ticket_id}",
            plan_hash=sha256(f"plan:{ticket_id}".encode()).hexdigest(),
            stage="execute-public-post",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=fixture["profile_digest"],
            capability="operator.public",
            capability_spec_digest=fixture["spec_digest"],
            lease_id="lease-public-fake-channel",
            scope="operator/public/generalist2-fake-announcements",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=int(payload["max_bytes"]),
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
        return fixture["adapter"].execute(payload)

    value = ToolExecutionMediator(
        fixture["store"],
        frozenset({"operator_public_post"}),
        outcome_verifiers=fixture["adapter"].outcome_verifiers(),
    )(
        tool_name="operator_public_post",
        args=payload,
        original_args=payload,
        next_call=next_call,
    )
    parsed = json.loads(value) if isinstance(value, str) else value
    assert isinstance(parsed, dict)
    return parsed, calls


def test_ticketed_fake_provider_post_readback_retry_and_privacy(tmp_path: Path) -> None:
    fixture = configured(tmp_path)
    payload = preview_arguments(fixture, "ticket-public-one")
    issue(fixture, payload)

    sent, calls = mediated(fixture, payload)
    replay, replay_calls = mediated(fixture, payload)

    assert sent["success"] is True
    assert sent["public_post"]["provider"] == "local-fake-public"
    assert sent["public_post"]["account_id"] == "generalist2"
    assert sent["public_post"]["channel_id"] == "announcements"
    assert sent["public_post"]["recipient_id"] == "public-feed"
    assert sent["public_post"]["owner_principal_id"] == "mike"
    assert sent["public_post"]["provider_authenticated"] is False
    assert sent["public_post"]["content_sha256"] == sha256(CONTENT.encode()).hexdigest()
    assert sent["public_post"]["provider_readback_verified"] is True
    assert sent["public_post"]["provider_effect_count"] == 1
    assert sent["public_post"]["real_public_effect"] is False
    assert calls == 1
    assert replay["success"] is True
    assert replay["mediation"]["recovered_after_restart"] is True
    assert replay_calls == 0
    assert fixture["driver"].mutation_count == 1

    persisted = canonical_json([event.payload for event in fixture["store"].events()])
    assert PRIVATE_SENTINEL not in persisted
    assert CONTENT not in persisted
    assert str(fixture["state_root"]) not in persisted
    assert fixture["store"].verify_chain()["valid"] is True


@pytest.mark.operator_crash_matrix
def test_post_provider_crash_adopts_readback_without_second_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = configured(tmp_path)
    payload = preview_arguments(fixture, "ticket-public-crash")
    issue(fixture, payload)
    original = fixture["adapter"]._record_completion

    def crash(*_args: Any, **_kwargs: Any) -> Any:
        raise SystemExit("simulated post-provider crash")

    monkeypatch.setattr(fixture["adapter"], "_record_completion", crash)
    with pytest.raises(SystemExit, match="simulated post-provider crash"):
        mediated(fixture, payload)
    assert fixture["driver"].mutation_count == 1
    assert not fixture["store"].events("operator.public_post.completed")
    monkeypatch.setattr(fixture["adapter"], "_record_completion", original)

    later_payload = preview_arguments(
        fixture,
        "ticket-public-after-crash",
        content="later provider post",
    )
    issue(fixture, later_payload)
    later, later_calls = mediated(fixture, later_payload)
    assert later["success"] is True
    assert later_calls == 1
    assert fixture["driver"].mutation_count == 2

    restarted_driver = LocalFakePublicChannelDriver(
        state_root=fixture["state_root"],
        provider="local-fake-public",
    )
    restarted = OperatorPublicPostAdapter(
        fixture["store"],
        channels=(fixture["target"],),
        drivers={"generalist2-local-fake-public": restarted_driver},
    )
    fixture["adapter"] = restarted
    recoveries = race_same_ticket_recovery(lambda: mediated(fixture, payload))

    assert all(recovered["success"] is True for recovered in recoveries)
    assert restarted_driver.mutation_count == 0
    assert sum(
        event.payload.get("ticket_id") == "ticket-public-crash"
        for event in fixture["store"].events("operator.public_post.claimed")
    ) == 1
    assert sum(
        event.payload.get("ticket_id") == "ticket-public-crash"
        for event in fixture["store"].events("operator.public_post.completed")
    ) == 1
    completion = next(
        event
        for event in fixture["store"].events("operator.public_post.completed")
        if event.payload.get("ticket_id") == "ticket-public-crash"
    )
    assert completion.payload["recovered_after_provider_crash"] is True


def test_daily_channel_cap_is_atomic_across_concurrent_tickets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = configured(tmp_path, daily_action_cap=1)
    payloads = [
        preview_arguments(fixture, f"ticket-public-cap-{index}", content=f"post {index}")
        for index in range(2)
    ]
    for payload in payloads:
        issue(fixture, payload)
        ExecutionTicketAuthority(fixture["store"]).claim_dispatch(
            ticket_id=str(payload["execution_ticket_id"]),
            tool_name="operator_public_post",
            arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
            registered_verifier_ids=frozenset({OPERATOR_PUBLIC_POST_VERIFIER_ID}),
        )

    original_append = fixture["store"].append_once_computed
    admission_barrier = threading.Barrier(2)

    def synchronized_append(kind: str, logical_key: str, factory: Any):
        if kind == "operator.public_post.claimed":
            admission_barrier.wait(timeout=5)
        return original_append(kind, logical_key, factory)

    monkeypatch.setattr(fixture["store"], "append_once_computed", synchronized_append)

    def run(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            return json.loads(fixture["adapter"].execute(payload))
        except PublicActionDenied as error:
            return {"denied": error.reason_code}

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, payloads))

    assert sum(row.get("success") is True for row in results) == 1
    assert sum(row.get("denied") == "PUBLIC_CHANNEL_DAILY_CAP_EXHAUSTED" for row in results) == 1
    assert fixture["driver"].mutation_count == 1
    assert len(fixture["store"].events("operator.public_post.claimed")) == 1


def test_stale_preview_kill_switch_and_binding_mismatch_block_provider(tmp_path: Path) -> None:
    fixture = configured(tmp_path)
    stale = preview_arguments(fixture, "ticket-public-stale")
    fixture["driver"].seed_foreign_post(fixture["target"], content_sha256="f" * 64)
    issue(fixture, stale)
    ExecutionTicketAuthority(fixture["store"]).claim_dispatch(
        ticket_id="ticket-public-stale",
        tool_name="operator_public_post",
        arguments_sha256=sha256(canonical_json(stale).encode()).hexdigest(),
        registered_verifier_ids=frozenset({OPERATOR_PUBLIC_POST_VERIFIER_ID}),
    )
    with pytest.raises(PublicActionDenied, match="PUBLIC_POST_PREVIEW_STALE"):
        fixture["adapter"].execute(stale)
    assert fixture["driver"].mutation_count == 0

    fresh = preview_arguments(fixture, "ticket-public-killed", content="kill test")
    issue(fixture, fresh)
    GlobalKillSwitch(fixture["store"]).trip(
        trip_id="kill-before-public-post",
        authority="operator",
        reason="Stop public post.",
    )
    result, calls = mediated(fixture, fresh)
    assert result["success"] is False
    assert result["error"]["reasons"] == ["GLOBAL_KILL_SWITCH_ACTIVE"]
    assert calls == 0
    assert fixture["driver"].mutation_count == 0

    with pytest.raises(ValueError, match="driver"):
        OperatorPublicPostAdapter(
            fixture["store"],
            channels=(fixture["target"],),
            drivers={},
        )


def test_content_digest_and_exact_scope_are_enforced(tmp_path: Path) -> None:
    fixture = configured(tmp_path)
    payload = preview_arguments(fixture, "ticket-public-content")
    payload["content"] = "different content"
    issue(fixture, payload)
    ExecutionTicketAuthority(fixture["store"]).claim_dispatch(
        ticket_id="ticket-public-content",
        tool_name="operator_public_post",
        arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
        registered_verifier_ids=frozenset({OPERATOR_PUBLIC_POST_VERIFIER_ID}),
    )
    with pytest.raises(PublicActionDenied, match="PUBLIC_CONTENT_DIGEST_MISMATCH"):
        fixture["adapter"].execute(payload)

    valid = preview_arguments(fixture, "ticket-public-scope", content="scope test")
    issue(fixture, valid)
    consumed = fixture["store"].events("execution.ticket.issued")[-1]
    assert consumed.payload["ticket"]["scope"] == "operator/public/generalist2-fake-announcements"

    underbudget = preview_arguments(
        fixture,
        "ticket-public-underbudget",
        content="content larger than one byte",
    )
    underbudget["max_bytes"] = 1
    issue(fixture, underbudget)
    ExecutionTicketAuthority(fixture["store"]).claim_dispatch(
        ticket_id="ticket-public-underbudget",
        tool_name="operator_public_post",
        arguments_sha256=sha256(canonical_json(underbudget).encode()).hexdigest(),
        registered_verifier_ids=frozenset({OPERATOR_PUBLIC_POST_VERIFIER_ID}),
    )
    with pytest.raises(PublicActionDenied, match="PUBLIC_CONTENT_BYTE_BUDGET_EXCEEDED"):
        fixture["adapter"].execute(underbudget)


def test_channel_owner_and_real_provider_authentication_are_host_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = configured(tmp_path)
    wrong_owner = replace(fixture["target"], id="wrong-owner", owner_principal_id="other")
    with pytest.raises(ValueError, match="owner must match installed principal"):
        OperatorPublicPostAdapter(
            fixture["store"],
            channels=(wrong_owner,),
            drivers={"generalist2-local-fake-public": fixture["driver"]},
        )

    real_target = replace(fixture["target"], id="real-target", real_public_effect=True)
    unauthenticated = ProviderPublicChannelAuthority(
        target_id="real-target",
        provider=real_target.provider,
        account_id=real_target.account_id,
        channel_id=real_target.channel_id,
        recipient_id=real_target.recipient_id,
        owner_principal_id="mike",
        authenticated=False,
        real_public_effect=True,
        authority_receipt_sha256=sha256(b"host unauthenticated readback").hexdigest(),
    )
    monkeypatch.setattr(fixture["driver"], "authority", lambda _target: unauthenticated)
    with pytest.raises(ValueError, match="requires authenticated provider authority"):
        OperatorPublicPostAdapter(
            fixture["store"],
            channels=(real_target,),
            drivers={"generalist2-local-fake-public": fixture["driver"]},
        )
