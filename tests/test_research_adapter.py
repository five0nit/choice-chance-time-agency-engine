from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

from cct_agent.research import (
    BoundedResearchAdapter,
    ResearchDenied,
    ResearchRequest,
    ResearchSource,
)
from cct_agent.store import EventStore, canonical_json


PRODUCER_SENTINEL = "PRODUCER_SENTINEL_7d953_do_not_promote"


class FixtureHandler(BaseHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).requests.append(self.path)
        if self.path == "/ok":
            body = f'{{"fact":"{PRODUCER_SENTINEL}"}}'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        if self.path == "/oversized":
            body = b"x" * 65
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/unsafe-type":
            body = b"binary-looking"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/invalid-utf8":
            body = b"\xff\xfe"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
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
def fixture_server() -> Iterator[tuple[str, type[FixtureHandler]]]:
    FixtureHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        address = server.server_address
        host, port = str(address[0]), int(address[1])
        assert ipaddress.ip_address(host).is_loopback
        yield f"http://{host}:{port}", FixtureHandler
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def adapter(tmp_path: Path, base_url: str, *, max_bytes: int = 4096) -> tuple[EventStore, BoundedResearchAdapter]:
    store = EventStore(tmp_path / "research.sqlite")
    source = ResearchSource(
        id="fixture-source",
        base_url=base_url,
        allowed_content_types=("application/json", "text/plain"),
        max_bytes=max_bytes,
        timeout_ms=2000,
        allow_loopback_http=True,
    )
    return store, BoundedResearchAdapter(
        store,
        sources=(source,),
        allowed_hosts=frozenset({"127.0.0.1"}),
    )


def test_read_only_fetch_disables_ambient_proxy_and_persists_hash_only_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with fixture_server() as (base_url, handler):
        store, research = adapter(tmp_path, base_url)
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("NO_PROXY", "")

        observation = research.fetch(
            ResearchRequest(
                id="research-ok-1",
                source_id="fixture-source",
                path="/ok",
            )
        )

    expected_body = f'{{"fact":"{PRODUCER_SENTINEL}"}}'
    assert handler.requests == ["/ok"]
    assert observation.content == expected_body
    assert observation.source_url == f"{base_url}/ok"
    assert observation.status_code == 200
    assert observation.content_type == "application/json"
    assert observation.byte_count == len(expected_body.encode())
    assert observation.content_sha256 == sha256(expected_body.encode()).hexdigest()
    assert observation.provenance == "external_untrusted"
    assert observation.authority_granted is False
    assert observation.eligible_for_goal_authority is False
    assert observation.persisted_content is False

    rows = store.events("research.observation.recorded")
    assert len(rows) == 1
    assert rows[0].event_id == observation.receipt_event_id
    assert rows[0].payload == {
        "schema_version": "cct.research.receipt.v1",
        "request_id": "research-ok-1",
        "source_id": "fixture-source",
        "source_url": f"{base_url}/ok",
        "status_code": 200,
        "content_type": "application/json",
        "byte_count": len(expected_body.encode()),
        "content_sha256": sha256(expected_body.encode()).hexdigest(),
        "provenance": "external_untrusted",
        "authority_granted": False,
        "eligible_for_goal_authority": False,
        "producer_content_persisted": False,
        "caller_path_persisted": True,
        "automatic_credentials_sent": False,
    }
    persisted = canonical_json([event.payload for event in store.events()])
    assert PRODUCER_SENTINEL not in persisted
    assert expected_body not in persisted
    assert store.verify_chain()["valid"] is True


def test_redirect_is_denied_without_following_target(tmp_path: Path) -> None:
    with fixture_server() as (base_url, handler):
        store, research = adapter(tmp_path, base_url)
        with pytest.raises(ResearchDenied, match="REDIRECT_DENIED") as caught:
            research.fetch(
                ResearchRequest(
                    id="research-redirect",
                    source_id="fixture-source",
                    path="/redirect",
                )
            )

    assert caught.value.reason_code == "REDIRECT_DENIED"
    assert handler.requests == ["/redirect"]
    assert not store.events("research.observation.recorded")


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("/oversized", "BODY_TOO_LARGE"),
        ("/unsafe-type", "CONTENT_TYPE_DENIED"),
        ("/invalid-utf8", "BODY_NOT_UTF8"),
    ],
)
def test_response_body_and_content_type_gates_fail_closed(
    tmp_path: Path, path: str, reason: str
) -> None:
    with fixture_server() as (base_url, _handler):
        store, research = adapter(tmp_path, base_url, max_bytes=64)
        with pytest.raises(ResearchDenied, match=reason) as caught:
            research.fetch(
                ResearchRequest(
                    id=f"research-{reason.lower()}",
                    source_id="fixture-source",
                    path=path,
                )
            )

    assert caught.value.reason_code == reason
    assert not store.events("research.observation.recorded")


@pytest.mark.parametrize(
    ("base_url", "allowed_hosts", "allow_loopback_http", "message"),
    [
        ("https://user:password@example.com", {"example.com"}, False, "userinfo"),
        ("https://example.com?q=secret", {"example.com"}, False, "query"),
        ("https://example.com#fragment", {"example.com"}, False, "fragment"),
        ("https://example.com/base", {"example.com"}, False, "origin"),
        ("https://example.com", {"other.example"}, False, "allowlisted"),
        ("http://example.com", {"example.com"}, True, "loopback"),
        ("http://127.0.0.1:8000", {"127.0.0.1"}, False, "HTTPS"),
        ("ftp://example.com", {"example.com"}, False, "scheme"),
    ],
)
def test_configured_source_url_and_host_allowlist_are_strict(
    tmp_path: Path,
    base_url: str,
    allowed_hosts: set[str],
    allow_loopback_http: bool,
    message: str,
) -> None:
    store = EventStore(tmp_path / "config.sqlite")
    source = ResearchSource(
        id="strict-source",
        base_url=base_url,
        allowed_content_types=("text/plain",),
        max_bytes=1024,
        timeout_ms=1000,
        allow_loopback_http=allow_loopback_http,
    )
    with pytest.raises(ValueError, match=message):
        BoundedResearchAdapter(
            store,
            sources=(source,),
            allowed_hosts=frozenset(allowed_hosts),
        )


def test_allowlisted_https_origin_is_accepted_without_network_call(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "https.sqlite")
    source = ResearchSource(
        id="https-source",
        base_url="https://Research.Example:443",
        allowed_content_types=("text/html",),
        max_bytes=4096,
        timeout_ms=1000,
    )

    research = BoundedResearchAdapter(
        store,
        sources=(source,),
        allowed_hosts=frozenset({"research.example"}),
    )

    assert research.source_ids == frozenset({"https-source"})
    assert research.sources["https-source"].normalized_base_url == "https://research.example:443"


@pytest.mark.parametrize(
    "path",
    [
        "ok",
        "//other.example/escape",
        "/with?query=secret",
        "/with#fragment",
        "/../escape",
        "/%2e%2e/escape",
        "/back\\slash",
        "/control\nline",
    ],
)
def test_request_path_rejects_ambiguous_or_authority_like_values(path: str) -> None:
    with pytest.raises(ValueError, match="path"):
        ResearchRequest(id="research-bad-path", source_id="fixture-source", path=path)


def test_request_and_source_schemas_reject_unknown_or_malformed_values() -> None:
    with pytest.raises(ValueError, match="identifier"):
        ResearchRequest(id="bad id", source_id="source", path="/ok")
    with pytest.raises(ValueError, match="max_bytes"):
        ResearchSource(
            id="source",
            base_url="https://example.com",
            allowed_content_types=("text/plain",),
            max_bytes=True,  # type: ignore[arg-type]
            timeout_ms=1000,
        )
    with pytest.raises(ValueError, match="timeout_ms"):
        ResearchSource(
            id="source",
            base_url="https://example.com",
            allowed_content_types=("text/plain",),
            max_bytes=1024,
            timeout_ms=1.5,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="content types"):
        ResearchSource(
            id="source",
            base_url="https://example.com",
            allowed_content_types=("*/*",),
            max_bytes=1024,
            timeout_ms=1000,
        )
