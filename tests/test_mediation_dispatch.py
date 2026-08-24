from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from pathlib import Path
from threading import Barrier, Event
from types import SimpleNamespace
from typing import Any

import pytest

import hermes_plugin
from cct_agent.capabilities import CapabilityLease, CapabilityRegistry, CapabilitySpec
from cct_agent.execution_tickets import ExecutionTicket, ExecutionTicketAuthority
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.mediation_outcomes import (
    OutcomeVerification,
    OutcomeVerifierRegistry,
    VerificationContext,
)
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-24T08:00:00+00:00"
FUTURE = "2026-08-25T08:00:00+00:00"
VERIFIER_ID = "fake-sink-readback"


def configured(
    tmp_path: Path,
) -> tuple[EventStore, ExecutionTicketAuthority, str, str]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
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
            verifier_id=VERIFIER_ID,
            reversible=True,
            max_actions=8,
            max_bytes=8192,
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
            max_actions=8,
            max_bytes=8192,
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


def issue(
    authority: ExecutionTicketAuthority,
    *,
    ticket_id: str,
    profile_digest: str,
    spec_digest: str,
    marker: str = "private-dispatch-input",
) -> dict[str, Any]:
    arguments = {
        "execution_ticket_id": ticket_id,
        "path": "docs/note.md",
        "content": marker,
    }
    authority.issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name="workspace_write",
            arguments_sha256=sha256(canonical_json(arguments).encode()).hexdigest(),
            goal_id="goal-autonomous-work",
            plan_id="plan-autonomous-work",
            plan_hash="a" * 64,
            stage="patch",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=profile_digest,
            capability="workspace.patch",
            capability_spec_digest=spec_digest,
            lease_id="lease-patch",
            scope="docs/note.md",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=128,
            value_budget_microunits=0,
        ),
        authority="operator",
        evidence=("operator://goal-approval",),
    )
    return arguments


def successful_result(ticket_id: str, *, marker: str = "private-tool-output") -> str:
    return canonical_json(
        {
            "success": True,
            "effect": {
                "effect_id": f"effect-{ticket_id}",
                "idempotency_key": ticket_id,
            },
            "output": marker,
        }
    )


def verifier(value: object, context: VerificationContext) -> OutcomeVerification:
    if not isinstance(value, dict):
        return OutcomeVerification(
            verified=False,
            effect_observed=False,
            status="malformed-result",
        )
    effect = value.get("effect")
    if not isinstance(effect, dict):
        return OutcomeVerification(
            verified=False,
            effect_observed=False,
            status="missing-effect",
        )
    effect_id = effect.get("effect_id")
    idempotency_key = effect.get("idempotency_key")
    verified = (
        value.get("success") is True
        and isinstance(effect_id, str)
        and idempotency_key == context.idempotency_key
    )
    return OutcomeVerification(
        verified=verified,
        effect_observed=verified,
        status="verified" if verified else "binding-mismatch",
        effect_id=effect_id if isinstance(effect_id, str) else None,
        evidence_sha256=sha256(
            canonical_json(effect).encode("utf-8")
        ).hexdigest(),
    )


def registry(
    *,
    reconcile: Any = None,
    idempotency_proof_id: str | None = None,
) -> OutcomeVerifierRegistry:
    outcome_registry = OutcomeVerifierRegistry()
    outcome_registry.register(
        VERIFIER_ID,
        verifier,
        reconcile=reconcile,
        idempotency_proof_id=idempotency_proof_id,
    )
    return outcome_registry


def invoke(
    mediator: ToolExecutionMediator,
    arguments: dict[str, Any],
    downstream: Any,
) -> tuple[object, int]:
    calls = 0

    def next_call() -> object:
        nonlocal calls
        calls += 1
        if isinstance(downstream, BaseException):
            raise downstream
        if callable(downstream):
            return downstream()
        return downstream

    result = mediator(
        tool_name="workspace_write",
        args=arguments,
        original_args=arguments,
        next_call=next_call,
    )
    return result, calls


def test_allowed_dispatch_claims_first_calls_once_and_persists_bounded_receipts(
    tmp_path: Path,
) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    ticket_id = "ticket-dispatch-once"
    private_input = "private-dispatch-input-b671"
    private_output = "private-tool-output-a913"
    arguments = issue(
        authority,
        ticket_id=ticket_id,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
        marker=private_input,
    )
    raw_result = successful_result(ticket_id, marker=private_output)

    def downstream() -> str:
        claims = store.events("execution.ticket.consumed")
        assert len(claims) == 1
        assert claims[0].payload["dispatch_claimed"] is True
        assert claims[0].payload["verifier_id"] == VERIFIER_ID
        assert not store.events("mediation.tool.outcome")
        return raw_result

    result, calls = invoke(
        ToolExecutionMediator(
            store,
            frozenset({"workspace_write"}),
            outcome_verifiers=registry(),
        ),
        arguments,
        downstream,
    )

    assert result == raw_result
    assert calls == 1
    outcomes = store.events("mediation.tool.outcome")
    completions = store.events("mediation.tool.completed")
    assert len(outcomes) == len(completions) == 1
    assert outcomes[0].payload == {
        "schema_version": "cct.tool_execution.outcome.v1",
        "ticket_id": ticket_id,
        "claim_event_id": store.events("execution.ticket.consumed")[0].event_id,
        "tool_name": "workspace_write",
        "arguments_sha256": sha256(canonical_json(arguments).encode()).hexdigest(),
        "verifier_id": VERIFIER_ID,
        "idempotency_key": ticket_id,
        "downstream_called": True,
        "adopted_after_restart": False,
        "result_kind": "json-object",
        "result_bytes": len(raw_result.encode("utf-8")),
        "result_sha256": sha256(raw_result.encode("utf-8")).hexdigest(),
        "verified": True,
        "effect_observed": True,
        "verification_status": "verified",
        "effect_id": f"effect-{ticket_id}",
        "evidence_sha256": sha256(
            canonical_json(
                {
                    "effect_id": f"effect-{ticket_id}",
                    "idempotency_key": ticket_id,
                }
            ).encode("utf-8")
        ).hexdigest(),
        "idempotency_proof_id": None,
        "raw_result_persisted": False,
        "raw_arguments_persisted": False,
        "credentials_persisted": False,
    }
    assert completions[0].payload["outcome_event_id"] == outcomes[0].event_id
    assert completions[0].payload["verified"] is True
    persisted = canonical_json([event.payload for event in store.events()])
    assert private_input not in persisted
    assert private_output not in persisted
    assert store.verify_chain()["valid"] is True


def test_plugin_wrapper_uses_host_verifier_registry_and_dispatches_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    ticket_id = "ticket-plugin-dispatch"
    arguments = issue(
        authority,
        ticket_id=ticket_id,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )

    class Context:
        def __init__(self) -> None:
            self.middlewares: list[tuple[str, Any]] = []

        @staticmethod
        def get_config(key: str, default: object = None) -> object:
            if key == "mediated_tools":
                return ["workspace_write"]
            return default

        @staticmethod
        def register_tool(**_kwargs: object) -> None:
            return None

        @staticmethod
        def register_hook(_name: str, _handler: Any) -> None:
            return None

        def register_middleware(self, kind: str, callback: Any) -> None:
            self.middlewares.append((kind, callback))

    monkeypatch.setattr(
        hermes_plugin,
        "_kernel",
        lambda: SimpleNamespace(store=store),
    )
    monkeypatch.setattr(
        hermes_plugin,
        "_outcome_verifier_registry",
        lambda _store: registry(),
    )
    context = Context()
    hermes_plugin.register(context)

    result, calls = invoke(
        context.middlewares[0][1],
        arguments,
        successful_result(ticket_id),
    )

    assert result == successful_result(ticket_id)
    assert calls == 1
    assert len(store.events("mediation.tool.outcome")) == 1


def test_unregistered_verifier_denies_before_claim_or_downstream(tmp_path: Path) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    arguments = issue(
        authority,
        ticket_id="ticket-no-verifier",
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )

    result, calls = invoke(
        ToolExecutionMediator(store, frozenset({"workspace_write"})),
        arguments,
        successful_result("ticket-no-verifier"),
    )

    denial = json.loads(str(result))
    assert calls == 0
    assert denial["error"]["reasons"] == ["VERIFIER_NOT_REGISTERED"]
    assert not store.events("execution.ticket.consumed")
    assert not store.events("mediation.tool.outcome")


def test_malformed_downstream_callback_denies_before_claim(tmp_path: Path) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    arguments = issue(
        authority,
        ticket_id="ticket-malformed-callback",
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )
    mediator = ToolExecutionMediator(
        store,
        frozenset({"workspace_write"}),
        outcome_verifiers=registry(),
    )

    result = mediator(
        tool_name="workspace_write",
        args=arguments,
        original_args=arguments,
        next_call="not-callable",
    )

    denial = json.loads(str(result))
    assert denial["error"]["reasons"] == ["MALFORMED_CALL"]
    assert not store.events("execution.ticket.consumed")
    assert not store.events("mediation.tool.outcome")


def test_verified_outcome_requires_bounded_effect_and_evidence_receipts() -> None:
    with pytest.raises(ValueError, match="effect_id"):
        OutcomeVerification(
            verified=True,
            effect_observed=True,
            status="verified",
            evidence_sha256="a" * 64,
        )
    with pytest.raises(ValueError, match="evidence_sha256"):
        OutcomeVerification(
            verified=True,
            effect_observed=True,
            status="verified",
            effect_id="effect-one",
        )


def test_claim_without_receipt_never_retries_without_idempotency_proof(
    tmp_path: Path,
) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    ticket_id = "ticket-claim-only"
    arguments = issue(
        authority,
        ticket_id=ticket_id,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )
    authority.claim_dispatch(
        ticket_id=ticket_id,
        tool_name="workspace_write",
        arguments_sha256=sha256(canonical_json(arguments).encode()).hexdigest(),
        registered_verifier_ids=frozenset({VERIFIER_ID}),
    )

    result, calls = invoke(
        ToolExecutionMediator(
            store,
            frozenset({"workspace_write"}),
            outcome_verifiers=registry(),
        ),
        arguments,
        successful_result(ticket_id),
    )

    blocked = json.loads(str(result))
    assert calls == 0
    assert blocked["error"] == {
        "code": "CCT_MEDIATION_RECOVERY_REQUIRED",
        "reasons": ["CLAIM_WITHOUT_RECEIPT", "IDEMPOTENCY_PROOF_REQUIRED"],
    }
    assert len(store.events("execution.ticket.consumed")) == 1
    assert not store.events("mediation.tool.outcome")
    assert len(store.events("mediation.tool.recovery_blocked")) == 1


def test_effect_without_receipt_is_adopted_by_registered_readback_without_retry(
    tmp_path: Path,
) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    ticket_id = "ticket-effect-crash"
    arguments = issue(
        authority,
        ticket_id=ticket_id,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )
    authority.claim_dispatch(
        ticket_id=ticket_id,
        tool_name="workspace_write",
        arguments_sha256=sha256(canonical_json(arguments).encode()).hexdigest(),
        registered_verifier_ids=frozenset({VERIFIER_ID}),
    )
    fake_sink = {ticket_id: successful_result(ticket_id, marker="sink-private-result")}
    reconcile_calls = 0

    def reconcile(context: VerificationContext) -> object | None:
        nonlocal reconcile_calls
        reconcile_calls += 1
        return fake_sink.get(context.idempotency_key)

    result, calls = invoke(
        ToolExecutionMediator(
            store,
            frozenset({"workspace_write"}),
            outcome_verifiers=registry(
                reconcile=reconcile,
                idempotency_proof_id="fake-sink-idempotency-v1",
            ),
        ),
        arguments,
        RuntimeError("must-not-run"),
    )

    assert calls == 0
    assert reconcile_calls == 1
    assert result == fake_sink[ticket_id]
    outcome = store.events("mediation.tool.outcome")[0]
    assert outcome.payload["downstream_called"] is False
    assert outcome.payload["adopted_after_restart"] is True
    assert outcome.payload["idempotency_proof_id"] == "fake-sink-idempotency-v1"
    assert outcome.payload["verified"] is True
    assert len(store.events("mediation.tool.completed")) == 1
    assert "sink-private-result" not in canonical_json(
        [event.payload for event in store.events()]
    )


def test_crash_after_effect_uses_readback_and_never_dispatches_again(
    tmp_path: Path,
) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    ticket_id = "ticket-real-effect-crash"
    arguments = issue(
        authority,
        ticket_id=ticket_id,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )
    fake_sink: dict[str, str] = {}
    effect_calls = 0

    def crash_after_effect() -> str:
        nonlocal effect_calls
        effect_calls += 1
        fake_sink[ticket_id] = successful_result(ticket_id)
        raise KeyboardInterrupt("crash after fake effect")

    def reconcile(context: VerificationContext) -> object | None:
        return fake_sink.get(context.idempotency_key)

    mediator = ToolExecutionMediator(
        store,
        frozenset({"workspace_write"}),
        outcome_verifiers=registry(
            reconcile=reconcile,
            idempotency_proof_id="fake-sink-idempotency-v1",
        ),
    )
    with pytest.raises(KeyboardInterrupt, match="crash after fake effect"):
        invoke(mediator, arguments, crash_after_effect)
    assert effect_calls == 1
    assert len(store.events("execution.ticket.consumed")) == 1
    assert not store.events("mediation.tool.outcome")

    recovered, retry_calls = invoke(
        mediator,
        arguments,
        RuntimeError("must-not-dispatch-after-crash"),
    )

    assert retry_calls == 0
    assert effect_calls == 1
    assert recovered == fake_sink[ticket_id]
    assert len(store.events("mediation.tool.outcome")) == 1
    assert len(store.events("mediation.tool.completed")) == 1


def test_receipt_without_completion_is_completed_without_second_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    ticket_id = "ticket-completion-crash"
    arguments = issue(
        authority,
        ticket_id=ticket_id,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )
    mediator = ToolExecutionMediator(
        store,
        frozenset({"workspace_write"}),
        outcome_verifiers=registry(),
    )
    original_append_once_result = store.append_once_result
    crashed = False

    def crash_completion(kind: str, logical_key: str, payload: Any) -> Any:
        nonlocal crashed
        if kind == "mediation.tool.completed" and not crashed:
            crashed = True
            raise KeyboardInterrupt("crash after outcome receipt")
        return original_append_once_result(kind, logical_key, payload)

    monkeypatch.setattr(store, "append_once_result", crash_completion)
    with pytest.raises(KeyboardInterrupt, match="crash after outcome receipt"):
        invoke(mediator, arguments, successful_result(ticket_id))
    assert len(store.events("mediation.tool.outcome")) == 1
    assert not store.events("mediation.tool.completed")

    monkeypatch.setattr(store, "append_once_result", original_append_once_result)
    result, calls = invoke(mediator, arguments, RuntimeError("must-not-run"))

    recovered = json.loads(str(result))
    assert calls == 0
    assert recovered["success"] is True
    assert recovered["mediation"]["recovered_after_restart"] is True
    assert recovered["mediation"]["outcome_receipt_adopted"] is True
    assert len(store.events("mediation.tool.outcome")) == 1
    assert len(store.events("mediation.tool.completed")) == 1


def test_downstream_exception_returns_bounded_failure_and_is_never_retried(
    tmp_path: Path,
) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    ticket_id = "ticket-downstream-error"
    arguments = issue(
        authority,
        ticket_id=ticket_id,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )
    mediator = ToolExecutionMediator(
        store,
        frozenset({"workspace_write"}),
        outcome_verifiers=registry(),
    )

    result, calls = invoke(
        mediator,
        arguments,
        RuntimeError("private exception message must not persist"),
    )
    failed = json.loads(str(result))
    assert calls == 1
    assert failed["error"] == {
        "code": "CCT_MEDIATION_DOWNSTREAM_ERROR",
        "reasons": ["DOWNSTREAM_EXCEPTION"],
    }
    outcome = store.events("mediation.tool.outcome")[0]
    assert outcome.payload["verification_status"] == "downstream-exception"
    assert outcome.payload["exception_type"] == "RuntimeError"
    assert "private exception message" not in canonical_json(
        [event.payload for event in store.events()]
    )

    replay, replay_calls = invoke(
        mediator,
        arguments,
        RuntimeError("must-not-run-again"),
    )
    replayed = json.loads(str(replay))
    assert replay_calls == 0
    assert replayed["success"] is False
    assert replayed["mediation"]["outcome_receipt_adopted"] is True
    assert len(store.events("mediation.tool.outcome")) == 1


def test_downstream_exception_after_effect_uses_registered_readback(
    tmp_path: Path,
) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    ticket_id = "ticket-exception-after-effect"
    arguments = issue(
        authority,
        ticket_id=ticket_id,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )
    fake_sink: dict[str, str] = {}

    def effect_then_error() -> str:
        fake_sink[ticket_id] = successful_result(ticket_id)
        raise RuntimeError("adapter transport closed after committed effect")

    def reconcile(context: VerificationContext) -> object | None:
        return fake_sink.get(context.idempotency_key)

    mediator = ToolExecutionMediator(
        store,
        frozenset({"workspace_write"}),
        outcome_verifiers=registry(
            reconcile=reconcile,
            idempotency_proof_id="fake-sink-idempotency-v1",
        ),
    )

    result, calls = invoke(mediator, arguments, effect_then_error)

    assert calls == 1
    assert result == fake_sink[ticket_id]
    outcome = store.events("mediation.tool.outcome")[0]
    assert outcome.payload["verified"] is True
    assert outcome.payload["downstream_called"] is True
    assert outcome.payload["adopted_after_restart"] is False
    assert outcome.payload["idempotency_proof_id"] == "fake-sink-idempotency-v1"
    assert len(store.events("mediation.tool.completed")) == 1


def test_concurrent_same_ticket_dispatches_downstream_once(tmp_path: Path) -> None:
    store, authority, profile_digest, spec_digest = configured(tmp_path)
    ticket_id = "ticket-concurrent-dispatch"
    arguments = issue(
        authority,
        ticket_id=ticket_id,
        profile_digest=profile_digest,
        spec_digest=spec_digest,
    )
    mediator = ToolExecutionMediator(
        store,
        frozenset({"workspace_write"}),
        outcome_verifiers=registry(),
    )
    entered = Event()
    release = Event()
    start = Barrier(2)
    downstream_calls = 0

    def invoke_concurrently() -> object:
        nonlocal downstream_calls
        start.wait(timeout=10)

        def next_call() -> str:
            nonlocal downstream_calls
            downstream_calls += 1
            entered.set()
            assert release.wait(timeout=10)
            return successful_result(ticket_id)

        return mediator(
            tool_name="workspace_write",
            args=arguments,
            original_args=arguments,
            next_call=next_call,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(invoke_concurrently)
        second = pool.submit(invoke_concurrently)
        assert entered.wait(timeout=10)
        release.set()
        results = [first.result(), second.result()]

    assert downstream_calls == 1
    assert len(store.events("execution.ticket.consumed")) == 1
    assert len(store.events("mediation.tool.outcome")) == 1
    assert len(store.events("mediation.tool.completed")) == 1
    assert results.count(successful_result(ticket_id)) == 1
    decoded = [json.loads(str(result)) for result in results]
    recovery_rows = [
        item
        for item in decoded
        if isinstance(item, dict) and isinstance(item.get("mediation"), dict)
    ]
    assert len(recovery_rows) == 1
    assert recovery_rows[0]["mediation"]["downstream_called"] is False
    assert (
        recovery_rows[0].get("error", {}).get("code")
        == "CCT_MEDIATION_RECOVERY_REQUIRED"
        or recovery_rows[0]["mediation"].get("recovered_after_restart") is True
    )
    assert store.verify_chain()["valid"] is True
