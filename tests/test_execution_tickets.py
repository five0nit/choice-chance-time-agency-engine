from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import multiprocessing
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

from cct_agent.capabilities import (
    CapabilityLease,
    CapabilityRegistry,
    CapabilityRequest,
    CapabilitySpec,
)
from cct_agent.execution_tickets import (
    ExecutionTicket,
    ExecutionTicketAuthority,
    TicketAuthorityDenied,
)
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-24T03:00:00+00:00"
FUTURE = "2026-08-25T03:00:00+00:00"
PAST = "2026-08-23T03:00:00+00:00"


def _consume_ticket_process(
    database_path: str,
    ticket_id: str,
    arguments_sha256: str,
    start: Any,
    results: Any,
) -> None:
    store = EventStore(database_path, clock=lambda: NOW)
    authority = ExecutionTicketAuthority(store)
    if not start.wait(timeout=10):
        results.put("START_TIMEOUT")
        return
    try:
        authority.consume(
            ticket_id=ticket_id,
            tool_name="workspace_write",
            arguments_sha256=arguments_sha256,
        )
        results.put("consumed")
    except TicketAuthorityDenied as error:
        results.put(error.reason_code)


def configured(
    tmp_path: Path,
    *,
    max_actions: int = 2,
    clock: Any = None,
) -> tuple[EventStore, ExecutionTicketAuthority, str, str]:
    store = EventStore(tmp_path / "agency.sqlite", clock=clock or (lambda: NOW))
    profile = PrincipalProfile(
        principal_id="mike",
        display_name="Mike",
        values={"truth": 1.0, "competence": 1.0},
        directives=(
            PrincipalDirective(
                id="prefer-reversible-work",
                kind="preference",
                statement="Prefer reversible workspace work.",
                tags=("domain:workspace", "action:patch"),
                priority=80,
            ),
        ),
    )
    installed = PrincipalModel(store).install(
        profile,
        authority="operator",
        evidence=("operator://profile",),
    )
    registry = CapabilityRegistry(store)
    registered = registry.register(
        CapabilitySpec(
            name="workspace.patch",
            description="Patch bounded workspace files.",
            effect_kind="patch_text",
            intent_domain="workspace",
            intent_action="patch",
            risk_class="reversible",
            scopes=("docs/**",),
            verifier_id="sha256-readback",
            reversible=True,
            max_actions=max_actions,
            max_bytes=4096,
            max_value_microunits=0,
        ),
        authority="host_adapter",
        evidence=("host://workspace-patch",),
    )
    registry.grant(
        CapabilityLease(
            id="lease-patch",
            capability="workspace.patch",
            principal_id="mike",
            scopes=("docs/**",),
            expires_at=FUTURE,
            max_actions=max_actions,
            max_bytes=4096,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://patch-lease",),
        )
    )
    return (
        store,
        ExecutionTicketAuthority(store),
        installed["profile_digest"],
        registered["spec_digest"],
    )


def call_args(ticket_id: str, *, marker: str = "private-patch-content") -> dict[str, Any]:
    return {
        "execution_ticket_id": ticket_id,
        "path": "docs/note.md",
        "content": marker,
    }


def ticket(
    ticket_id: str,
    arguments: dict[str, Any],
    profile_digest: str,
    spec_digest: str,
    **changes: Any,
) -> ExecutionTicket:
    values: dict[str, Any] = {
        "id": ticket_id,
        "tool_name": "workspace_write",
        "arguments_sha256": sha256(canonical_json(arguments).encode()).hexdigest(),
        "goal_id": "goal-autonomous-work",
        "plan_id": "plan-autonomous-work",
        "plan_hash": "a" * 64,
        "stage": "patch",
        "attempt": 1,
        "principal_id": "mike",
        "principal_profile_digest": profile_digest,
        "capability": "workspace.patch",
        "capability_spec_digest": spec_digest,
        "lease_id": "lease-patch",
        "scope": "docs/note.md",
        "expires_at": FUTURE,
        "action_budget": 1,
        "byte_budget": 128,
        "value_budget_microunits": 0,
    }
    values.update(changes)
    return ExecutionTicket(**values)


def execute(
    mediator: ToolExecutionMediator,
    args: dict[str, Any],
    *,
    tool_name: str = "workspace_write",
) -> tuple[dict[str, Any], int]:
    calls = 0

    def next_call() -> str:
        nonlocal calls
        calls += 1
        return "must-not-run-in-slice-2"

    result = mediator(
        tool_name=tool_name,
        args=args,
        original_args=args,
        next_call=next_call,
    )
    return json.loads(result), calls


def test_issue_and_valid_consumption_are_bound_and_private(tmp_path: Path) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    marker = "private-ticket-payload-9c14"
    args = call_args("ticket-one", marker=marker)
    issued = authority.issue(
        ticket("ticket-one", args, profile_digest, spec_digest),
        authority="operator",
        evidence=("operator://goal-approval",),
    )
    assert issued["created"] is True

    consumption = authority.consume(
        ticket_id="ticket-one",
        tool_name="workspace_write",
        arguments_sha256=sha256(canonical_json(args).encode()).hexdigest(),
    )
    assert consumption["ticket_consumed"] is True
    assert consumption["dispatch_claimed"] is True
    assert consumption["verifier_id"] == "sha256-readback"
    consumed = store.events("execution.ticket.consumed")
    assert len(consumed) == 1
    assert consumed[0].payload["arguments_sha256"] == sha256(
        canonical_json(args).encode()
    ).hexdigest()
    serialized = canonical_json(store.events()[0].payload)
    all_events = canonical_json([event.payload for event in store.events()])
    assert marker not in serialized
    assert marker not in all_events
    assert all(event.payload.get("raw_arguments_persisted") is not True for event in store.events())


def test_absent_unknown_revoked_expired_and_mismatched_tickets_fail_closed(
    tmp_path: Path,
) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    mediator = ToolExecutionMediator(store, frozenset({"workspace_write"}))

    no_ticket, calls = execute(mediator, {"path": "docs/note.md"})
    assert calls == 0
    assert no_ticket["error"]["reasons"] == ["TICKET_REQUIRED"]

    unknown_args = call_args("ticket-unknown")
    unknown, calls = execute(mediator, unknown_args)
    assert calls == 0
    assert unknown["error"]["reasons"] == ["UNKNOWN_TICKET"]

    revoked_args = call_args("ticket-revoked")
    authority.issue(
        ticket("ticket-revoked", revoked_args, profile_digest, spec_digest),
        authority="operator",
        evidence=("operator://approval",),
    )
    authority.revoke(
        "ticket-revoked", authority="operator", reason="Operator cancelled the action."
    )
    revoked, calls = execute(mediator, revoked_args)
    assert calls == 0
    assert revoked["error"]["reasons"] == ["TICKET_REVOKED"]

    expired_args = call_args("ticket-expired")
    with pytest.raises(ValueError, match="TICKET_EXPIRED"):
        authority.issue(
            ticket(
                "ticket-expired",
                expired_args,
                profile_digest,
                spec_digest,
                expires_at=PAST,
            ),
            authority="operator",
            evidence=("operator://approval",),
        )

    mismatch_args = call_args("ticket-mismatch")
    authority.issue(
        ticket("ticket-mismatch", mismatch_args, profile_digest, spec_digest),
        authority="operator",
        evidence=("operator://approval",),
    )
    changed_args = {**mismatch_args, "path": "docs/other.md"}
    mismatch, calls = execute(mediator, changed_args)
    assert calls == 0
    assert mismatch["error"]["reasons"] == ["TICKET_ARGUMENTS_MISMATCH"]

    wrong_tool_args = call_args("ticket-wrong-tool")
    authority.issue(
        ticket("ticket-wrong-tool", wrong_tool_args, profile_digest, spec_digest),
        authority="operator",
        evidence=("operator://approval",),
    )
    wrong_tool, calls = execute(
        ToolExecutionMediator(
            store, frozenset({"workspace_write", "workspace_delete"})
        ),
        wrong_tool_args,
        tool_name="workspace_delete",
    )
    assert calls == 0
    assert wrong_tool["error"]["reasons"] == ["TICKET_TOOL_MISMATCH"]


def test_ticket_issue_rejects_scope_profile_spec_and_budget_drift(tmp_path: Path) -> None:
    _store, authority, profile_digest, spec_digest = configured(tmp_path)
    args = call_args("ticket-drift")
    cases = (
        ({"scope": "secrets/key.txt"}, "SCOPE_DENIED"),
        ({"principal_profile_digest": "b" * 64}, "PRINCIPAL_PROFILE_CHANGED"),
        ({"capability_spec_digest": "c" * 64}, "CAPABILITY_SPEC_CHANGED"),
        ({"action_budget": 3}, "ACTION_BUDGET_EXCEEDED"),
        ({"byte_budget": 5000}, "BYTE_BUDGET_EXCEEDED"),
    )
    for index, (changes, reason) in enumerate(cases):
        scoped_args = {**args, "execution_ticket_id": f"ticket-drift-{index}"}
        with pytest.raises(ValueError, match=reason):
            authority.issue(
                ticket(
                    f"ticket-drift-{index}",
                    scoped_args,
                    profile_digest,
                    spec_digest,
                    **changes,
                ),
                authority="operator",
                evidence=("operator://approval",),
            )


def test_same_ticket_has_one_atomic_consumer(tmp_path: Path) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    args = call_args("ticket-race")
    authority.issue(
        ticket("ticket-race", args, profile_digest, spec_digest),
        authority="operator",
        evidence=("operator://approval",),
    )
    digest = sha256(canonical_json(args).encode()).hexdigest()

    def consume() -> str:
        try:
            authority.consume(
                ticket_id="ticket-race",
                tool_name="workspace_write",
                arguments_sha256=digest,
            )
            return "consumed"
        except TicketAuthorityDenied as error:
            return error.reason_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _item: consume(), range(8)))
    assert outcomes.count("consumed") == 1
    assert outcomes.count("TICKET_REPLAYED") == 7
    assert len(store.events("execution.ticket.consumed")) == 1
    assert store.verify_chain()["valid"] is True


def test_distinct_tickets_cannot_overshoot_one_action_lease(tmp_path: Path) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path, max_actions=1)
    rows: list[tuple[str, dict[str, Any]]] = []
    for identifier in ("ticket-budget-a", "ticket-budget-b"):
        args = call_args(identifier)
        authority.issue(
            ticket(identifier, args, profile_digest, spec_digest),
            authority="operator",
            evidence=("operator://approval",),
        )
        rows.append((identifier, args))

    def consume(row: tuple[str, dict[str, Any]]) -> str:
        identifier, args = row
        try:
            authority.consume(
                ticket_id=identifier,
                tool_name="workspace_write",
                arguments_sha256=sha256(canonical_json(args).encode()).hexdigest(),
            )
            return "consumed"
        except TicketAuthorityDenied as error:
            return error.reason_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, rows))
    assert outcomes.count("consumed") == 1
    assert outcomes.count("LEASE_ACTION_BUDGET_EXHAUSTED") == 1
    assert len(store.events("execution.ticket.consumed")) == 1
    assert store.verify_chain()["valid"] is True


def test_same_ticket_has_one_atomic_consumer_across_processes(tmp_path: Path) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    args = call_args("ticket-process-race")
    authority.issue(
        ticket("ticket-process-race", args, profile_digest, spec_digest),
        authority="operator",
        evidence=("operator://approval",),
    )
    digest = sha256(canonical_json(args).encode()).hexdigest()
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_consume_ticket_process,
            args=(str(store.path), "ticket-process-race", digest, start, results),
        )
        for _index in range(4)
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    outcomes = [results.get(timeout=5) for _process in processes]

    assert outcomes.count("consumed") == 1
    assert outcomes.count("TICKET_REPLAYED") == 3
    assert len(store.events("execution.ticket.consumed")) == 1
    assert store.verify_chain()["valid"] is True


def test_ticket_and_ordinary_reservation_share_one_atomic_lease_budget(
    tmp_path: Path,
) -> None:
    store, authority, profile_digest, spec_digest = configured(
        tmp_path, max_actions=1
    )
    args = call_args("ticket-cross-path")
    authority.issue(
        ticket("ticket-cross-path", args, profile_digest, spec_digest),
        authority="operator",
        evidence=("operator://approval",),
    )
    registry = CapabilityRegistry(store)
    ordinary_request = CapabilityRequest(
        id="ordinary-cross-path",
        capability="workspace.patch",
        principal_id="mike",
        scope="docs/note.md",
        lease_id="lease-patch",
        principal_profile_digest=profile_digest,
        intent_digest="f" * 64,
        intent_domain="workspace",
        intent_action="patch",
        requested_actions=1,
        requested_bytes=128,
        requested_value_microunits=0,
    )
    barrier = Barrier(2)

    def reserve_ordinary() -> str:
        barrier.wait(timeout=10)
        decision = registry.reserve(ordinary_request)
        return f"ordinary:{decision.mode}:{','.join(decision.reasons)}"

    def consume_ticket() -> str:
        barrier.wait(timeout=10)
        try:
            authority.consume(
                ticket_id="ticket-cross-path",
                tool_name="workspace_write",
                arguments_sha256=sha256(canonical_json(args).encode()).hexdigest(),
            )
            return "ticket:consumed"
        except TicketAuthorityDenied as error:
            return f"ticket:{error.reason_code}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        ordinary_future = pool.submit(reserve_ordinary)
        ticket_future = pool.submit(consume_ticket)
        outcomes = [ordinary_future.result(), ticket_future.result()]

    winners = [
        outcome
        for outcome in outcomes
        if outcome in {"ordinary:allow:ACTIVE_LEASE", "ticket:consumed"}
    ]
    assert len(winners) == 1
    assert any("LEASE_ACTION_BUDGET_EXHAUSTED" in outcome for outcome in outcomes)
    status = registry.status()["leases"]["lease-patch"]
    assert status["used"] == {
        "actions": 1,
        "bytes": 128,
        "value_microunits": 0,
    }
    assert status["remaining"]["actions"] == 0
    assert store.verify_chain()["valid"] is True


def test_middleware_replay_and_post_issuance_expiry_deny_without_dispatch(
    tmp_path: Path,
) -> None:
    now = [NOW]
    store, authority, profile_digest, spec_digest = configured(
        tmp_path, clock=lambda: now[0]
    )
    replay_args = call_args("ticket-middleware-replay")
    authority.issue(
        ticket("ticket-middleware-replay", replay_args, profile_digest, spec_digest),
        authority="host_adapter",
        evidence=("host://bounded-plan",),
    )
    digest = sha256(canonical_json(replay_args).encode()).hexdigest()
    authority.consume(
        ticket_id="ticket-middleware-replay",
        tool_name="workspace_write",
        arguments_sha256=digest,
    )
    with pytest.raises(TicketAuthorityDenied) as replay_error:
        authority.consume(
            ticket_id="ticket-middleware-replay",
            tool_name="workspace_write",
            arguments_sha256=digest,
        )
    assert replay_error.value.reason_code == "TICKET_REPLAYED"

    mediator = ToolExecutionMediator(store, frozenset({"workspace_write"}))

    expiring_args = call_args("ticket-middleware-expired")
    authority.issue(
        ticket(
            "ticket-middleware-expired",
            expiring_args,
            profile_digest,
            spec_digest,
            expires_at="2026-08-24T04:00:00+00:00",
        ),
        authority="host_adapter",
        evidence=("host://bounded-plan",),
    )
    now[0] = "2026-08-24T05:00:00+00:00"
    expired, expired_calls = execute(mediator, expiring_args)
    assert expired_calls == 0
    assert expired["error"]["reasons"] == ["TICKET_EXPIRED"]


def test_issuance_and_consumption_receipts_preserve_all_ticket_bindings(
    tmp_path: Path,
) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    args = call_args("ticket-bindings")
    bound_ticket = ticket(
        "ticket-bindings",
        args,
        profile_digest,
        spec_digest,
        goal_id="goal-exact",
        plan_id="plan-exact",
        plan_hash="e" * 64,
        stage="verify",
        attempt=2,
        scope="docs/note.md",
        action_budget=1,
        byte_budget=129,
        value_budget_microunits=0,
    )
    issuance = authority.issue(
        bound_ticket,
        authority="host_adapter",
        evidence=("host://exact-plan-stage",),
    )
    assert issuance["ticket"] == bound_ticket.as_payload()
    consumption = authority.consume(
        ticket_id=bound_ticket.id,
        tool_name=bound_ticket.tool_name,
        arguments_sha256=bound_ticket.arguments_sha256,
    )
    for field, value in bound_ticket.as_payload().items():
        if field in {"id", "expires_at"}:
            continue
        assert consumption[field] == value
    assert consumption["ticket_id"] == bound_ticket.id
    assert consumption["budget_reserved"] is True
    assert consumption["ticket_consumed"] is True
    assert consumption["downstream_called"] is False
    assert store.verify_chain()["valid"] is True


def test_ticket_payload_parser_is_strict() -> None:
    with pytest.raises(ValueError, match="unknown fields"):
        ExecutionTicket.from_payload(
            {
                "id": "ticket-strict",
                "tool_name": "workspace_write",
                "arguments_sha256": "a" * 64,
                "goal_id": "goal",
                "plan_id": "plan",
                "plan_hash": "b" * 64,
                "stage": "patch",
                "attempt": 1,
                "principal_id": "mike",
                "principal_profile_digest": "c" * 64,
                "capability": "workspace.patch",
                "capability_spec_digest": "d" * 64,
                "lease_id": "lease-patch",
                "scope": "docs/note.md",
                "expires_at": FUTURE,
                "action_budget": 1,
                "byte_budget": 1,
                "value_budget_microunits": 0,
                "surprise": True,
            }
        )
