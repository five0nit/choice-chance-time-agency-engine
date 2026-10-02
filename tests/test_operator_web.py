from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
from threading import Thread
import time
from typing import Any

import pytest

from operator_crash_matrix import race_same_ticket_recovery

from cct_agent.capabilities import (
    CapabilityLease,
    CapabilityRegistry,
    OperatorCapabilityCatalog,
)
from cct_agent.execution_tickets import (
    ExecutionTicket,
    ExecutionTicketAuthority,
    GlobalKillSwitch,
)
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.research import (
    OPERATOR_WEB_VERIFIER_ID,
    OperatorWebAdapter,
    OperatorWebSource,
    ResearchDenied,
)
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-25T00:00:00+00:00"
FUTURE = "2026-08-26T00:00:00+00:00"
PRODUCER_SENTINEL = "WEB_PRODUCER_SENTINEL_4e81_untrusted"


class WebFixtureHandler(BaseHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).requests.append(self.path)
        if self.path == "/document":
            body = f"document:{PRODUCER_SENTINEL}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/search?q=bounded+agency":
            body = f'{{"results":["{PRODUCER_SENTINEL}"]}}'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/document")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/oversized":
            body = b"x" * 257
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        return None


@contextmanager
def fixture_server() -> Iterator[tuple[str, type[WebFixtureHandler]]]:
    WebFixtureHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), WebFixtureHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        assert ipaddress.ip_address(str(host)).is_loopback
        yield f"http://{host}:{port}", WebFixtureHandler
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def configured(
    tmp_path: Path,
    base_url: str,
    *,
    max_bytes: int = 256,
) -> tuple[EventStore, OperatorWebAdapter, ExecutionTicketAuthority, str, str]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    installed = PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 1.0},
            directives=(
                PrincipalDirective(
                    id="operator-web",
                    kind="preference",
                    statement="Prefer bounded receipt-backed public web research.",
                    tags=("domain:operator", "action:web"),
                    priority=80,
                ),
            ),
        ),
        authority="operator",
        evidence=("operator://profile",),
    )
    web_spec = OperatorCapabilityCatalog(store).install()["web"]
    CapabilityRegistry(store).grant(
        CapabilityLease(
            id="lease-web-fixture",
            capability="operator.web",
            principal_id="mike",
            scopes=("operator/web/public-fixture",),
            expires_at=FUTURE,
            max_actions=8,
            max_bytes=4096,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://lease/web/public-fixture",),
        )
    )
    adapter = OperatorWebAdapter(
        store,
        sources=(
            OperatorWebSource(
                id="public-fixture",
                base_url=base_url,
                allowed_content_types=("application/json", "text/plain"),
                max_bytes=max_bytes,
                timeout_ms=2_000,
                fetch_path_prefixes=("/",),
                search_path="/search",
                search_parameter="q",
                allow_loopback_http=True,
            ),
        ),
    )
    return (
        store,
        adapter,
        ExecutionTicketAuthority(store),
        installed["profile_digest"],
        web_spec["spec_digest"],
    )


def issue(
    authority: ExecutionTicketAuthority,
    *,
    arguments: dict[str, Any],
    profile_digest: str,
    spec_digest: str,
) -> None:
    ticket_id = str(arguments["execution_ticket_id"])
    authority.issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name="operator_web",
            arguments_sha256=sha256(canonical_json(arguments).encode()).hexdigest(),
            goal_id="goal-cct-full-operator-effects",
            plan_id=f"plan-{ticket_id}",
            plan_hash=sha256(f"plan:{ticket_id}".encode()).hexdigest(),
            stage="execute-web",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=profile_digest,
            capability="operator.web",
            capability_spec_digest=spec_digest,
            lease_id="lease-web-fixture",
            scope="operator/web/public-fixture",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=int(arguments["max_bytes"]),
            value_budget_microunits=0,
        ),
        authority="operator",
        evidence=("operator://goal/web-public-fixture",),
    )


def mediated(
    store: EventStore,
    adapter: OperatorWebAdapter,
    arguments: dict[str, Any],
) -> tuple[dict[str, Any], int]:
    calls = 0

    def next_call() -> str:
        nonlocal calls
        calls += 1
        return adapter.execute(arguments)

    result = ToolExecutionMediator(
        store,
        frozenset({"operator_web"}),
        outcome_verifiers=adapter.outcome_verifiers(),
    )(
        tool_name="operator_web",
        args=arguments,
        original_args=arguments,
        next_call=next_call,
    )
    parsed = json.loads(result) if isinstance(result, str) else result
    assert isinstance(parsed, dict)
    return parsed, calls


@pytest.mark.parametrize(
    ("operation_fields", "expected_path", "expected_type"),
    [
        ({"operation": "fetch", "path": "/document"}, "/document", "text/plain"),
        (
            {"operation": "search", "query": "bounded agency"},
            "/search?q=bounded+agency",
            "application/json",
        ),
    ],
)
def test_ticketed_fetch_and_search_are_bounded_untrusted_hash_receipted_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation_fields: dict[str, str],
    expected_path: str,
    expected_type: str,
) -> None:
    with fixture_server() as (base_url, handler):
        store, adapter, authority, profile_digest, spec_digest = configured(
            tmp_path,
            base_url,
        )
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
        ticket_id = f"ticket-web-{operation_fields['operation']}"
        arguments: dict[str, Any] = {
            "execution_ticket_id": ticket_id,
            "source_id": "public-fixture",
            **operation_fields,
            "timeout_ms": 2_000,
            "max_bytes": 256,
        }
        issue(
            authority,
            arguments=arguments,
            profile_digest=profile_digest,
            spec_digest=spec_digest,
        )

        result, calls = mediated(store, adapter, arguments)
        retry, retry_calls = mediated(store, adapter, arguments)

    assert handler.requests == [expected_path]
    assert calls == 1
    assert retry_calls == 0
    assert result["success"] is True
    assert result["effect"]["idempotency_key"] == ticket_id
    assert result["web"]["operation"] == operation_fields["operation"]
    assert result["web"]["source_id"] == "public-fixture"
    assert result["web"]["content_type"] == expected_type
    assert PRODUCER_SENTINEL in result["web"]["content"]
    assert result["web"]["provenance"] == "external_untrusted"
    assert result["web"]["authority_granted"] is False
    assert result["web"]["eligible_for_goal_authority"] is False
    assert result["web"]["producer_content_persisted"] is False
    assert retry["success"] is True
    assert "web" not in retry
    assert retry["mediation"]["recovered_after_restart"] is True

    receipts = store.events("operator.web.completed")
    assert len(receipts) == 1
    assert receipts[0].payload["ticket_id"] == ticket_id
    assert receipts[0].payload["operation"] == operation_fields["operation"]
    assert receipts[0].payload["producer_content_persisted"] is False
    assert receipts[0].payload["automatic_credentials_sent"] is False
    persisted = canonical_json([event.payload for event in store.events()])
    assert PRODUCER_SENTINEL not in persisted
    assert "bounded agency" not in persisted
    assert store.verify_chain()["valid"] is True


@pytest.mark.operator_crash_matrix
def test_post_response_crash_adopts_verified_web_receipt_without_second_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with fixture_server() as (base_url, handler):
        store, adapter, authority, profile_digest, spec_digest = configured(
            tmp_path,
            base_url,
        )
        arguments = {
            "execution_ticket_id": "ticket-web-crash",
            "source_id": "public-fixture",
            "operation": "fetch",
            "path": "/document",
            "timeout_ms": 2_000,
            "max_bytes": 256,
        }
        issue(
            authority,
            arguments=arguments,
            profile_digest=profile_digest,
            spec_digest=spec_digest,
        )

        def crash(*_args: Any, **_kwargs: Any) -> Any:
            raise SystemExit("simulated post-response crash")

        monkeypatch.setattr(adapter, "_record_completion", crash)
        with pytest.raises(SystemExit, match="simulated post-response crash"):
            mediated(store, adapter, arguments)
        assert handler.requests == ["/document"]
        assert len(store.events("operator.web.effect_verified")) == 1
        assert not store.events("operator.web.completed")

        restarted = OperatorWebAdapter(
            store,
            sources=tuple(adapter._sources.values()),  # noqa: SLF001
        )
        recoveries = race_same_ticket_recovery(
            lambda: mediated(store, restarted, arguments)
        )

    assert all(recovered["success"] is True for recovered in recoveries)
    assert handler.requests == ["/document"]
    assert len(store.events("operator.web.claimed")) == 1
    assert len(store.events("operator.web.effect_verified")) == 1
    completions = store.events("operator.web.completed")
    assert len(completions) == 1
    assert completions[0].payload["recovered_after_crash"] is True
    assert completions[0].payload["producer_content_persisted"] is False
    persisted = canonical_json([event.payload for event in store.events()])
    assert PRODUCER_SENTINEL not in persisted
    assert store.verify_chain()["valid"] is True


@pytest.mark.parametrize(
    ("path", "reason"),
    [("/redirect", "REDIRECT_DENIED"), ("/oversized", "BODY_TOO_LARGE")],
)
def test_redirect_and_body_limit_fail_closed_after_one_target_request(
    tmp_path: Path,
    path: str,
    reason: str,
) -> None:
    with fixture_server() as (base_url, handler):
        store, adapter, authority, profile_digest, spec_digest = configured(
            tmp_path,
            base_url,
            max_bytes=256,
        )
        arguments = {
            "execution_ticket_id": f"ticket-web-{reason.lower()}",
            "source_id": "public-fixture",
            "operation": "fetch",
            "path": path,
            "timeout_ms": 2_000,
            "max_bytes": 256,
        }
        issue(
            authority,
            arguments=arguments,
            profile_digest=profile_digest,
            spec_digest=spec_digest,
        )

        result, calls = mediated(store, adapter, arguments)

    assert calls == 1
    assert handler.requests == [path]
    assert result["success"] is False
    assert not store.events("operator.web.completed")


def test_public_sources_require_https_and_runtime_dns_must_resolve_only_global_addresses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EventStore(tmp_path / "strict.sqlite", clock=lambda: NOW)
    with pytest.raises(ValueError, match="HTTPS"):
        OperatorWebAdapter(
            store,
            sources=(
                OperatorWebSource(
                    id="public-source",
                    base_url="http://example.com",
                    allowed_content_types=("text/plain",),
                    max_bytes=256,
                    timeout_ms=1_000,
                    fetch_path_prefixes=("/",),
                ),
            ),
        )

    source = OperatorWebSource(
        id="public-source",
        base_url="https://example.com",
        allowed_content_types=("text/plain",),
        max_bytes=256,
        timeout_ms=1_000,
        fetch_path_prefixes=("/",),
    )
    adapter = OperatorWebAdapter(store, sources=(source,))
    monkeypatch.setattr(
        "cct_agent.research.socket.getaddrinfo",
        lambda *_args, **_kwargs: [
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(ResearchDenied, match="SSRF_ADDRESS_DENIED"):
        adapter._resolve_public_addresses(source)  # noqa: SLF001


def test_one_total_timeout_budget_covers_all_pinned_address_attempts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = OperatorWebSource(
        id="public-source",
        base_url="https://example.com",
        allowed_content_types=("text/html",),
        max_bytes=256,
        timeout_ms=1_000,
        fetch_path_prefixes=("/",),
    )
    adapter = OperatorWebAdapter(
        EventStore(tmp_path / "timeout.sqlite", clock=lambda: NOW),
        sources=(source,),
    )
    monkeypatch.setattr(
        adapter,
        "_resolve_public_addresses",
        lambda _source: ("203.0.113.10", "203.0.113.11"),
    )
    calls: list[str] = []

    def delayed_failure(**kwargs: Any) -> tuple[int, str, bytes]:
        calls.append(str(kwargs["address"]))
        if len(calls) > 1:
            raise AssertionError("second address must not receive a renewed timeout budget")
        time.sleep(0.03)
        raise OSError("first address timed out")

    monkeypatch.setattr(adapter, "_request_address", delayed_failure)

    with pytest.raises(ResearchDenied, match="TIMEOUT"):
        adapter._request(source, "/", timeout_ms=10, max_bytes=256)  # noqa: SLF001

    assert calls == ["203.0.113.10"]


def test_kill_switch_after_ticket_issue_blocks_web_before_network(tmp_path: Path) -> None:
    with fixture_server() as (base_url, handler):
        store, adapter, authority, profile_digest, spec_digest = configured(
            tmp_path,
            base_url,
        )
        arguments = {
            "execution_ticket_id": "ticket-web-killed",
            "source_id": "public-fixture",
            "operation": "fetch",
            "path": "/document",
            "timeout_ms": 2_000,
            "max_bytes": 256,
        }
        issue(
            authority,
            arguments=arguments,
            profile_digest=profile_digest,
            spec_digest=spec_digest,
        )
        GlobalKillSwitch(store).trip(
            trip_id="kill-before-web",
            authority="operator",
            reason="Stop web dispatch.",
        )

        result, calls = mediated(store, adapter, arguments)

    assert result["success"] is False
    assert result["error"]["reasons"] == ["GLOBAL_KILL_SWITCH_ACTIVE"]
    assert calls == 0
    assert handler.requests == []
    assert not store.events("operator.web.completed")


def test_web_request_schema_rejects_unknown_fields_traversal_and_search_without_registered_endpoint(
    tmp_path: Path,
) -> None:
    with fixture_server() as (base_url, _handler):
        store, adapter, _authority, _profile_digest, _spec_digest = configured(
            tmp_path,
            base_url,
        )
        base = {
            "execution_ticket_id": "ticket-web-invalid",
            "source_id": "public-fixture",
            "operation": "fetch",
            "path": "/document",
            "timeout_ms": 2_000,
            "max_bytes": 256,
        }
        with pytest.raises(ValueError, match="exact common fields"):
            adapter.execute({**base, "url": "https://attacker.invalid"})
        with pytest.raises(ValueError, match="path"):
            adapter.execute({**base, "path": "/../escape"})

    source = OperatorWebSource(
        id="fetch-only",
        base_url="https://example.com",
        allowed_content_types=("text/plain",),
        max_bytes=256,
        timeout_ms=1_000,
        fetch_path_prefixes=("/",),
    )
    assert source.search_path is None
    assert OPERATOR_WEB_VERIFIER_ID == "operator-web-readback"
