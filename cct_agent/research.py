"""Typed, bounded, read-only research adapter with hash-only receipts."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPConnection, HTTPMessage, HTTPSConnection, HTTPResponse
import json
import os
import socket
import time
import ipaddress
import re
import ssl
from types import MappingProxyType
from typing import Any, Literal, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus, unquote, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from .execution_tickets import GlobalKillSwitch, TicketAuthorityDenied
from .mediation_outcomes import (
    OutcomeVerification,
    OutcomeVerifierRegistry,
    VerificationContext,
)
from .store import Event, EventStore, canonical_json


RESEARCH_RECEIPT_SCHEMA_VERSION = "cct.research.receipt.v1"
MAX_RESEARCH_BYTES = 1_048_576
MAX_RESEARCH_TIMEOUT_MS = 10_000
MAX_RESEARCH_SOURCES = 32
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MEDIA_TYPE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$"
)
_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,1023}$")
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _bounded_integer(
    name: str,
    value: object,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _normalize_host(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("allowed host must be a non-empty exact hostname")
    if not value.isascii() or value.endswith(".") or any(ord(char) < 33 for char in value):
        raise ValueError("allowed host must be an exact ASCII hostname")
    lowered = value.lower()
    try:
        return ipaddress.ip_address(lowered).compressed
    except ValueError:
        labels = lowered.split(".")
        if len(lowered) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
            raise ValueError("allowed host must be a valid hostname or IP literal")
        return lowered


def _is_loopback_literal(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _normalized_origin(scheme: str, host: str, port: int | None) -> str:
    rendered_host = f"[{host}]" if ":" in host else host
    rendered_port = f":{port}" if port is not None else ""
    return f"{scheme}://{rendered_host}{rendered_port}"


@dataclass(frozen=True, slots=True)
class ResearchSource:
    """Host-configured source policy. Producer content cannot create this object."""

    id: str
    base_url: str
    allowed_content_types: tuple[str, ...]
    max_bytes: int
    timeout_ms: int
    allow_loopback_http: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("source id", self.id))
        if not isinstance(self.base_url, str) or not self.base_url or len(self.base_url) > 2048:
            raise ValueError("base_url must be a bounded string")
        if not isinstance(self.allowed_content_types, (tuple, list)):
            raise ValueError("allowed content types must be an array")
        normalized: list[str] = []
        for item in self.allowed_content_types:
            if not isinstance(item, str):
                raise ValueError("allowed content types must contain strings")
            media_type = item.lower()
            if item != media_type or not _MEDIA_TYPE.fullmatch(media_type):
                raise ValueError("allowed content types must be exact lowercase media types")
            if media_type not in normalized:
                normalized.append(media_type)
        if not normalized or len(normalized) > 16:
            raise ValueError("allowed content types must contain 1-16 exact media types")
        object.__setattr__(self, "allowed_content_types", tuple(sorted(normalized)))
        _bounded_integer(
            "max_bytes",
            self.max_bytes,
            minimum=1,
            maximum=MAX_RESEARCH_BYTES,
        )
        _bounded_integer(
            "timeout_ms",
            self.timeout_ms,
            minimum=1,
            maximum=MAX_RESEARCH_TIMEOUT_MS,
        )
        if not isinstance(self.allow_loopback_http, bool):
            raise ValueError("allow_loopback_http must be a boolean")

    @property
    def normalized_base_url(self) -> str:
        parsed = urlsplit(self.base_url)
        host = _normalize_host(parsed.hostname)
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("base_url port is invalid") from error
        return _normalized_origin(parsed.scheme.lower(), host, port)


@dataclass(frozen=True, slots=True)
class ResearchRequest:
    """One GET path against a host-registered source."""

    id: str
    source_id: str
    path: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("request id", self.id))
        object.__setattr__(self, "source_id", _identifier("source id", self.source_id))
        if not isinstance(self.path, str) or not _PATH.fullmatch(self.path):
            raise ValueError("path must be a bounded absolute ASCII path")
        if self.path.startswith("//") or "\\" in self.path:
            raise ValueError("path must not contain an authority or backslash")
        percent_text = _PERCENT_ESCAPE.sub("", self.path)
        if "%" in percent_text:
            raise ValueError("path contains a malformed percent escape")
        decoded = unquote(self.path)
        if (
            not decoded.isascii()
            or "?" in decoded
            or "#" in decoded
            or "\\" in decoded
            or "//" in decoded
            or any(part in {".", ".."} for part in decoded.split("/"))
        ):
            raise ValueError("path contains ambiguous or authority-like content")


@dataclass(frozen=True, slots=True)
class ResearchObservation:
    """Transient producer content plus durable hash-receipt metadata."""

    request_id: str
    source_id: str
    source_url: str
    status_code: int
    content_type: str
    byte_count: int
    content_sha256: str
    content: str
    receipt_event_id: str
    provenance: Literal["external_untrusted"] = "external_untrusted"
    authority_granted: bool = False
    eligible_for_goal_authority: bool = False
    persisted_content: bool = False


class ResearchDenied(PermissionError):
    """Bounded denial without transport or producer-text leakage."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> None:
        return None


class BoundedResearchAdapter:
    """Perform one proxy-free GET and persist metadata, never producer prose."""

    def __init__(
        self,
        store: EventStore,
        *,
        sources: tuple[ResearchSource, ...] | list[ResearchSource],
        allowed_hosts: frozenset[str] | set[str],
    ) -> None:
        if not isinstance(sources, (tuple, list)) or not sources:
            raise ValueError("research sources must contain at least one source")
        if len(sources) > MAX_RESEARCH_SOURCES:
            raise ValueError(f"research sources must contain at most {MAX_RESEARCH_SOURCES} sources")
        if not isinstance(allowed_hosts, (frozenset, set)) or not allowed_hosts:
            raise ValueError("allowed_hosts must be a non-empty set")
        normalized_hosts = frozenset(_normalize_host(host) for host in allowed_hosts)
        rows: dict[str, ResearchSource] = {}
        for source in sources:
            if not isinstance(source, ResearchSource):
                raise ValueError("research sources must contain ResearchSource values")
            if source.id in rows:
                raise ValueError("research source IDs must be unique")
            self._validate_source(source, normalized_hosts)
            rows[source.id] = source
        self.store = store
        self._sources = MappingProxyType(rows)
        self._allowed_hosts = normalized_hosts
        self._opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirect(),
        )

    @property
    def sources(self) -> Mapping[str, ResearchSource]:
        return self._sources

    @property
    def source_ids(self) -> frozenset[str]:
        return frozenset(self._sources)

    @staticmethod
    def _validate_source(source: ResearchSource, allowed_hosts: frozenset[str]) -> None:
        value = source.base_url
        if not value.isascii() or value != value.strip() or any(ord(char) < 33 for char in value):
            raise ValueError("base_url must contain an exact ASCII origin")
        parsed = urlsplit(value)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain userinfo")
        if parsed.query:
            raise ValueError("base_url must not contain a query")
        if parsed.fragment:
            raise ValueError("base_url must not contain a fragment")
        if parsed.path not in {"", "/"}:
            raise ValueError("base_url must be an origin without a path")
        if not parsed.hostname:
            raise ValueError("base_url must contain a host")
        host = _normalize_host(parsed.hostname)
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("base_url port is invalid") from error
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("base_url port is invalid")
        scheme = parsed.scheme.lower()
        if scheme not in {"https", "http"}:
            raise ValueError("base_url scheme must be HTTPS or explicit loopback HTTP")
        if host not in allowed_hosts:
            raise ValueError("base_url host is not allowlisted")
        if scheme == "http" and (
            not source.allow_loopback_http or not _is_loopback_literal(host)
        ):
            raise ValueError(
                "HTTPS is required except for an explicit loopback HTTP fixture"
            )
        if scheme == "https" and source.allow_loopback_http:
            raise ValueError("allow_loopback_http is valid only for a loopback HTTP source")
        expected = _normalized_origin(scheme, host, port)
        normalized_input = value[:-1] if value.endswith("/") else value
        if normalized_input.lower() != expected:
            raise ValueError("base_url must be one exact origin")

    def fetch(self, request: ResearchRequest) -> ResearchObservation:
        if not isinstance(request, ResearchRequest):
            raise ValueError("request must be a ResearchRequest")
        source = self._sources.get(request.source_id)
        if source is None:
            raise ResearchDenied("SOURCE_NOT_REGISTERED")
        if any(
            event.payload.get("request_id") == request.id
            for event in self.store.events("research.observation.recorded")
        ):
            raise ResearchDenied("REQUEST_ALREADY_COMPLETED")
        source_url = f"{source.normalized_base_url}{request.path}"
        http_request = Request(
            source_url,
            method="GET",
            headers={
                "Accept": ", ".join(source.allowed_content_types),
                "Connection": "close",
                "User-Agent": "CCT-Research/1.0",
            },
        )
        try:
            response = self._opener.open(
                http_request,
                timeout=source.timeout_ms / 1000,
            )
        except HTTPError as error:
            if 300 <= int(error.code) <= 399:
                raise ResearchDenied("REDIRECT_DENIED") from None
            raise ResearchDenied("HTTP_STATUS_DENIED") from None
        except (URLError, TimeoutError, OSError):
            raise ResearchDenied("TRANSPORT_ERROR") from None

        with response:
            final_url = response.geturl()
            if final_url != source_url:
                raise ResearchDenied("FINAL_URL_CHANGED")
            status = response.getcode()
            if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status <= 299:
                raise ResearchDenied("HTTP_STATUS_DENIED")
            raw_content_type = response.headers.get("Content-Type")
            if not isinstance(raw_content_type, str) or not raw_content_type.strip():
                raise ResearchDenied("CONTENT_TYPE_DENIED")
            content_type = raw_content_type.split(";", 1)[0].strip().lower()
            if content_type not in source.allowed_content_types:
                raise ResearchDenied("CONTENT_TYPE_DENIED")
            charset = response.headers.get_content_charset()
            if charset is not None and charset.lower() not in {"utf-8", "us-ascii", "ascii"}:
                raise ResearchDenied("CHARSET_DENIED")
            content_encoding = response.headers.get("Content-Encoding")
            if content_encoding is not None and content_encoding.lower().strip() != "identity":
                raise ResearchDenied("CONTENT_ENCODING_DENIED")
            raw_length = response.headers.get("Content-Length")
            if raw_length is not None:
                try:
                    declared_length = int(raw_length)
                except (TypeError, ValueError):
                    raise ResearchDenied("CONTENT_LENGTH_INVALID") from None
                if declared_length < 0:
                    raise ResearchDenied("CONTENT_LENGTH_INVALID")
                if declared_length > source.max_bytes:
                    raise ResearchDenied("BODY_TOO_LARGE")
            body = response.read(source.max_bytes + 1)
            if len(body) > source.max_bytes:
                raise ResearchDenied("BODY_TOO_LARGE")
            try:
                content = body.decode("utf-8")
            except UnicodeDecodeError:
                raise ResearchDenied("BODY_NOT_UTF8") from None

        content_digest = sha256(body).hexdigest()
        receipt = {
            "schema_version": RESEARCH_RECEIPT_SCHEMA_VERSION,
            "request_id": request.id,
            "source_id": source.id,
            "source_url": source_url,
            "status_code": status,
            "content_type": content_type,
            "byte_count": len(body),
            "content_sha256": content_digest,
            "provenance": "external_untrusted",
            "authority_granted": False,
            "eligible_for_goal_authority": False,
            "producer_content_persisted": False,
            "caller_path_persisted": True,
            "automatic_credentials_sent": False,
        }
        try:
            event, _created = self.store.append_once_result(
                "research.observation.recorded",
                request.id,
                receipt,
            )
        except Exception as error:
            raise ResearchDenied("RECEIPT_PERSISTENCE_FAILED") from error
        return ResearchObservation(
            request_id=request.id,
            source_id=source.id,
            source_url=source_url,
            status_code=status,
            content_type=content_type,
            byte_count=len(body),
            content_sha256=content_digest,
            content=content,
            receipt_event_id=event.event_id,
        )


OPERATOR_WEB_CLAIM_SCHEMA_VERSION = "cct.operator_web.claim.v1"
OPERATOR_WEB_EFFECT_SCHEMA_VERSION = "cct.operator_web.effect.v1"
OPERATOR_WEB_RECEIPT_SCHEMA_VERSION = "cct.operator_web.receipt.v1"
OPERATOR_WEB_VERIFIER_ID = "operator-web-readback"
MAX_OPERATOR_WEB_SOURCES = 64
MAX_OPERATOR_WEB_BYTES = 131_072
MAX_OPERATOR_WEB_QUERY_BYTES = 2_048
_QUERY_PARAMETER = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


def _validated_path(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("path must be a string")
    return ResearchRequest(
        id="operator-web-path-validation",
        source_id="operator-web-source-validation",
        path=value,
    ).path


@dataclass(frozen=True, slots=True)
class OperatorWebSource:
    """Host-owned public HTTPS source and exact fetch/search policy."""

    id: str
    base_url: str
    allowed_content_types: tuple[str, ...]
    max_bytes: int
    timeout_ms: int
    fetch_path_prefixes: tuple[str, ...]
    search_path: str | None = None
    search_parameter: str | None = None
    allow_loopback_http: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("source id", self.id))
        if not isinstance(self.allowed_content_types, tuple):
            raise ValueError("allowed content types must be an immutable tuple")
        normalized_types: list[str] = []
        for value in self.allowed_content_types:
            if not isinstance(value, str):
                raise ValueError("allowed content types must contain strings")
            normalized = value.lower()
            if value != normalized or not _MEDIA_TYPE.fullmatch(normalized):
                raise ValueError("allowed content types must be exact lowercase media types")
            if normalized not in normalized_types:
                normalized_types.append(normalized)
        if not 1 <= len(normalized_types) <= 16:
            raise ValueError("allowed content types must contain 1-16 exact media types")
        object.__setattr__(self, "allowed_content_types", tuple(sorted(normalized_types)))
        _bounded_integer(
            "max_bytes",
            self.max_bytes,
            minimum=1,
            maximum=MAX_OPERATOR_WEB_BYTES,
        )
        _bounded_integer(
            "timeout_ms",
            self.timeout_ms,
            minimum=1,
            maximum=MAX_RESEARCH_TIMEOUT_MS,
        )
        if not isinstance(self.fetch_path_prefixes, tuple):
            raise ValueError("fetch_path_prefixes must be an immutable tuple")
        prefixes = tuple(
            sorted({_validated_path(value) for value in self.fetch_path_prefixes})
        )
        if not 1 <= len(prefixes) <= 32:
            raise ValueError("fetch_path_prefixes must contain 1-32 paths")
        object.__setattr__(self, "fetch_path_prefixes", prefixes)
        if (self.search_path is None) != (self.search_parameter is None):
            raise ValueError("search_path and search_parameter must be configured together")
        if self.search_path is not None:
            object.__setattr__(self, "search_path", _validated_path(self.search_path))
            if not isinstance(self.search_parameter, str) or not _QUERY_PARAMETER.fullmatch(
                self.search_parameter
            ):
                raise ValueError("search_parameter must be a bounded query identifier")
        if not isinstance(self.allow_loopback_http, bool):
            raise ValueError("allow_loopback_http must be a boolean")

    @property
    def normalized_base_url(self) -> str:
        parsed = urlsplit(self.base_url)
        host = _normalize_host(parsed.hostname)
        try:
            port = parsed.port
        except ValueError as error:
            raise ValueError("base_url port is invalid") from error
        return _normalized_origin(parsed.scheme.lower(), host, port)


@dataclass(frozen=True, slots=True)
class OperatorWebInvocation:
    """Strict ticket-bound public fetch or host-configured search request."""

    ticket_id: str
    source_id: str
    operation: Literal["fetch", "search"]
    timeout_ms: int
    max_bytes: int
    path: str | None = None
    query: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "ticket_id", _identifier("ticket id", self.ticket_id))
        object.__setattr__(self, "source_id", _identifier("source id", self.source_id))
        if self.operation not in {"fetch", "search"}:
            raise ValueError("operation must be fetch or search")
        _bounded_integer(
            "timeout_ms",
            self.timeout_ms,
            minimum=1,
            maximum=MAX_RESEARCH_TIMEOUT_MS,
        )
        _bounded_integer(
            "max_bytes",
            self.max_bytes,
            minimum=1,
            maximum=MAX_OPERATOR_WEB_BYTES,
        )
        if self.operation == "fetch":
            if self.query is not None or self.path is None:
                raise ValueError("fetch requires path and forbids query")
            object.__setattr__(self, "path", _validated_path(self.path))
        else:
            if self.path is not None or not isinstance(self.query, str):
                raise ValueError("search requires query and forbids path")
            if not self.query or "\x00" in self.query:
                raise ValueError("query must be non-empty UTF-8 text without NUL")
            try:
                query_bytes = self.query.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ValueError("query must be valid UTF-8") from error
            if len(query_bytes) > MAX_OPERATOR_WEB_QUERY_BYTES:
                raise ValueError(
                    f"query exceeds {MAX_OPERATOR_WEB_QUERY_BYTES} UTF-8 bytes"
                )
            if any(ord(character) < 32 for character in self.query):
                raise ValueError("query must not contain control characters")

    @classmethod
    def from_arguments(cls, arguments: Mapping[str, Any]) -> "OperatorWebInvocation":
        if not isinstance(arguments, Mapping):
            raise ValueError("web arguments must be an object")
        common = {
            "execution_ticket_id",
            "source_id",
            "operation",
            "timeout_ms",
            "max_bytes",
        }
        operation = arguments.get("operation")
        keys = set(arguments)
        if operation == "fetch" and keys == common | {"path"}:
            path = arguments["path"]
            query = None
        elif operation == "search" and keys == common | {"query"}:
            path = None
            query = arguments["query"]
        else:
            raise ValueError(
                "web arguments require exact common fields plus fetch path or search query"
            )
        return cls(
            ticket_id=arguments["execution_ticket_id"],
            source_id=arguments["source_id"],
            operation=operation,
            timeout_ms=arguments["timeout_ms"],
            max_bytes=arguments["max_bytes"],
            path=path,
            query=query,
        )


class _PinnedHTTPConnection(HTTPConnection):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        pinned_address: str,
        timeout: float,
    ) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_address = pinned_address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
        )


class _PinnedHTTPSConnection(HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        pinned_address: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_address = pinned_address
        self._cct_context = context

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
        )
        self.sock = self._cct_context.wrap_socket(raw_socket, server_hostname=self.host)


class OperatorWebAdapter:
    """Fetch untrusted public content through ticket, DNS pin, and receipt gates."""

    def __init__(
        self,
        store: EventStore,
        *,
        sources: tuple[OperatorWebSource, ...] | list[OperatorWebSource],
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        if not isinstance(sources, (tuple, list)) or not 1 <= len(sources) <= MAX_OPERATOR_WEB_SOURCES:
            raise ValueError(
                f"sources must contain 1-{MAX_OPERATOR_WEB_SOURCES} registrations"
            )
        registrations: dict[str, OperatorWebSource] = {}
        for source in sources:
            if not isinstance(source, OperatorWebSource):
                raise ValueError("sources must contain OperatorWebSource values")
            if source.id in registrations:
                raise ValueError("source IDs must be unique")
            parsed = self._validate_source(source)
            registrations[source.id] = source
            host = _normalize_host(parsed.hostname)
            registration_payload = {
                "schema_version": 1,
                "authority": "host_adapter",
                "source_id": source.id,
                "origin_sha256": sha256(
                    source.normalized_base_url.encode("utf-8")
                ).hexdigest(),
                "host": host,
                "scheme": parsed.scheme.lower(),
                "allowed_content_types": list(source.allowed_content_types),
                "max_bytes": source.max_bytes,
                "timeout_ms": source.timeout_ms,
                "fetch_path_prefixes": list(source.fetch_path_prefixes),
                "search_enabled": source.search_path is not None,
                "search_path": source.search_path,
                "search_parameter": source.search_parameter,
                "automatic_credentials_enabled": False,
            }
            event, _created = store.append_once_result(
                "operator.web_source.registered",
                source.id,
                registration_payload,
            )
            if canonical_json(event.payload) != canonical_json(registration_payload):
                raise ValueError(f"web source registration changed: {source.id}")
        self.store = store
        self._sources: Mapping[str, OperatorWebSource] = MappingProxyType(registrations)
        self._tls_context = ssl.create_default_context()
        try:
            os.chmod(self.store.path, 0o600)
        except OSError as error:
            raise ValueError("operator web receipt store must be private") from error

    @staticmethod
    def _validate_source(source: OperatorWebSource) -> Any:
        policy = ResearchSource(
            id=source.id,
            base_url=source.base_url,
            allowed_content_types=source.allowed_content_types,
            max_bytes=source.max_bytes,
            timeout_ms=source.timeout_ms,
            allow_loopback_http=source.allow_loopback_http,
        )
        parsed = urlsplit(source.base_url)
        if parsed.hostname is None:
            raise ValueError("base_url must contain a host")
        host = _normalize_host(parsed.hostname)
        BoundedResearchAdapter._validate_source(policy, frozenset({host}))
        scheme = parsed.scheme.lower()
        if scheme == "http":
            if not source.allow_loopback_http or not _is_loopback_literal(host):
                raise ValueError("HTTPS is required except for explicit loopback HTTP fixtures")
        elif scheme != "https":
            raise ValueError("public web sources require HTTPS")
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if scheme == "https" and literal is not None and not literal.is_global:
            raise ValueError("public HTTPS source IP literal must be globally routable")
        return parsed

    @property
    def source_ids(self) -> frozenset[str]:
        return frozenset(self._sources)

    def outcome_verifiers(self) -> OutcomeVerifierRegistry:
        registry = OutcomeVerifierRegistry()
        registry.register(
            OPERATOR_WEB_VERIFIER_ID,
            self._verify_mediated_result,
            reconcile=self._reconcile_mediated_result,
            idempotency_proof_id="operator-web-ticket-receipt",
        )
        return registry

    def _resolve_public_addresses(self, source: OperatorWebSource) -> tuple[str, ...]:
        parsed = urlsplit(source.normalized_base_url)
        host = _normalize_host(parsed.hostname)
        if parsed.scheme == "http" and source.allow_loopback_http:
            if not _is_loopback_literal(host):
                raise ResearchDenied("SSRF_ADDRESS_DENIED")
            return (host,)
        try:
            port = parsed.port or 443
            rows = socket.getaddrinfo(
                host,
                port,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except (OSError, ValueError):
            raise ResearchDenied("DNS_RESOLUTION_FAILED") from None
        addresses: set[str] = set()
        for row in rows:
            try:
                address = ipaddress.ip_address(str(row[4][0]))
            except (ValueError, IndexError, TypeError):
                raise ResearchDenied("DNS_RESPONSE_INVALID") from None
            if not address.is_global:
                raise ResearchDenied("SSRF_ADDRESS_DENIED")
            addresses.add(address.compressed)
        if not addresses:
            raise ResearchDenied("DNS_RESOLUTION_FAILED")
        return tuple(sorted(addresses))

    def execute(self, arguments: Mapping[str, Any]) -> str:
        request = OperatorWebInvocation.from_arguments(arguments)
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise ResearchDenied(error.reason_code) from error
        self._require_dispatch_claim(request, arguments)
        source = self._sources.get(request.source_id)
        if source is None:
            raise ResearchDenied("SOURCE_NOT_REGISTERED")
        if request.max_bytes > source.max_bytes:
            raise ResearchDenied("SOURCE_BYTE_BUDGET_EXCEEDED")
        if request.timeout_ms > source.timeout_ms:
            raise ResearchDenied("SOURCE_TIMEOUT_BUDGET_EXCEEDED")
        target_path, query_sha256 = self._target(source, request)
        target_url = f"{source.normalized_base_url}{target_path}"
        effect_id = f"web-{sha256(request.ticket_id.encode()).hexdigest()[:24]}"
        claim_payload = {
            "schema_version": OPERATOR_WEB_CLAIM_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "source_id": source.id,
            "operation": request.operation,
            "target_url_sha256": sha256(target_url.encode("utf-8")).hexdigest(),
            "query_sha256": query_sha256,
            "timeout_ms": request.timeout_ms,
            "max_bytes": request.max_bytes,
            "effect_id": effect_id,
            "provenance": "external_untrusted",
            "authority_granted": False,
            "automatic_credentials_sent": False,
            "producer_content_persisted": False,
            "raw_query_persisted": False,
        }
        claim, created = self.store.append_once_result(
            "operator.web.claimed",
            request.ticket_id,
            claim_payload,
        )
        if not created:
            completed = self._completion(request.ticket_id)
            if completed is None:
                raise ResearchDenied("EXECUTION_STATE_UNCERTAIN")
            return self._response(
                completed,
                content=None,
                target_url=None,
                replayed=True,
            )
        try:
            GlobalKillSwitch(self.store).checkpoint(
                checkpoint_id=f"web-pre-{sha256(request.ticket_id.encode()).hexdigest()[:24]}",
                effect_id=effect_id,
                step="pre-dispatch",
            )
        except TicketAuthorityDenied as error:
            raise ResearchDenied(error.reason_code) from error

        status_code, content_type, body, duration_ms = self._request(
            source,
            target_path,
            timeout_ms=request.timeout_ms,
            max_bytes=request.max_bytes,
        )
        content_sha256 = sha256(body).hexdigest()
        verification_material = {
            "effect_id": effect_id,
            "source_id": source.id,
            "operation": request.operation,
            "target_url_sha256": claim_payload["target_url_sha256"],
            "status_code": status_code,
            "content_type": content_type,
            "byte_count": len(body),
            "content_sha256": content_sha256,
        }
        receipt = {
            "schema_version": OPERATOR_WEB_RECEIPT_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "claim_event_id": claim.event_id,
            "source_id": source.id,
            "operation": request.operation,
            "target_url_sha256": claim_payload["target_url_sha256"],
            "query_sha256": query_sha256,
            "timeout_ms": request.timeout_ms,
            "max_bytes": request.max_bytes,
            "effect_id": effect_id,
            "status_code": status_code,
            "content_type": content_type,
            "byte_count": len(body),
            "content_sha256": content_sha256,
            "duration_ms": duration_ms,
            "verification_passed": True,
            "verification_code": "HTTP_RESPONSE_HASH_MATCH",
            "verification_evidence_sha256": sha256(
                canonical_json(verification_material).encode("utf-8")
            ).hexdigest(),
            "provenance": "external_untrusted",
            "authority_granted": False,
            "eligible_for_goal_authority": False,
            "automatic_credentials_sent": False,
            "producer_content_persisted": False,
            "raw_query_persisted": False,
        }
        effect_receipt = {
            **receipt,
            "schema_version": OPERATOR_WEB_EFFECT_SCHEMA_VERSION,
            "completion_pending": True,
        }
        verified_effect, effect_created = self.store.append_once_result(
            "operator.web.effect_verified",
            request.ticket_id,
            effect_receipt,
        )
        if (
            not effect_created
            or canonical_json(verified_effect.payload) != canonical_json(effect_receipt)
        ):
            raise ResearchDenied("VERIFIED_EFFECT_RECEIPT_COLLISION")
        try:
            content = body.decode("utf-8")
        except UnicodeDecodeError:
            raise ResearchDenied("BODY_NOT_UTF8") from None
        return self._record_completion(
            ticket_id=request.ticket_id,
            receipt=receipt,
            content=content,
            target_url=target_url,
            recovered_after_crash=False,
        )

    def _record_completion(
        self,
        *,
        ticket_id: str,
        receipt: Mapping[str, Any],
        content: str | None,
        target_url: str | None,
        recovered_after_crash: bool,
    ) -> str:
        final_receipt = {
            **dict(receipt),
            "schema_version": OPERATOR_WEB_RECEIPT_SCHEMA_VERSION,
            "recovered_after_crash": recovered_after_crash,
        }
        completed, created = self.store.append_once_result(
            "operator.web.completed",
            ticket_id,
            final_receipt,
        )
        if canonical_json(completed.payload) != canonical_json(final_receipt):
            raise ResearchDenied("COMPLETION_RECEIPT_COLLISION")
        return self._response(
            completed,
            content=content,
            target_url=target_url,
            replayed=recovered_after_crash or not created,
        )

    @staticmethod
    def _target(
        source: OperatorWebSource,
        request: OperatorWebInvocation,
    ) -> tuple[str, str | None]:
        if request.operation == "fetch":
            assert request.path is not None
            if not any(
                request.path == prefix
                or prefix == "/"
                or request.path.startswith(prefix.rstrip("/") + "/")
                for prefix in source.fetch_path_prefixes
            ):
                raise ResearchDenied("FETCH_PATH_DENIED")
            return request.path, None
        if source.search_path is None or source.search_parameter is None:
            raise ResearchDenied("SEARCH_NOT_REGISTERED")
        assert request.query is not None
        encoded = quote_plus(request.query, safe="")
        target = f"{source.search_path}?{source.search_parameter}={encoded}"
        if len(target.encode("ascii")) > 8_192:
            raise ResearchDenied("SEARCH_URL_TOO_LARGE")
        return target, sha256(request.query.encode("utf-8")).hexdigest()

    def _require_dispatch_claim(
        self,
        request: OperatorWebInvocation,
        arguments: Mapping[str, Any],
    ) -> None:
        arguments_sha256 = sha256(canonical_json(arguments).encode("utf-8")).hexdigest()
        claims = [
            event
            for event in self.store.events("execution.ticket.consumed")
            if event.payload.get("ticket_id") == request.ticket_id
        ]
        if len(claims) != 1:
            raise ResearchDenied("TICKET_DISPATCH_CLAIM_REQUIRED")
        payload = claims[0].payload
        if (
            payload.get("dispatch_claimed") is not True
            or payload.get("ticket_consumed") is not True
            or payload.get("tool_name") != "operator_web"
            or payload.get("arguments_sha256") != arguments_sha256
            or payload.get("capability") != "operator.web"
            or payload.get("scope") != f"operator/web/{request.source_id}"
            or payload.get("verifier_id") != OPERATOR_WEB_VERIFIER_ID
            or payload.get("idempotency_key") != request.ticket_id
            or isinstance(payload.get("byte_budget"), bool)
            or not isinstance(payload.get("byte_budget"), int)
            or payload["byte_budget"] < request.max_bytes
        ):
            raise ResearchDenied("TICKET_DISPATCH_CLAIM_MISMATCH")

    def _request(
        self,
        source: OperatorWebSource,
        target_path: str,
        *,
        timeout_ms: int,
        max_bytes: int,
    ) -> tuple[int, str, bytes, int]:
        addresses = self._resolve_public_addresses(source)
        parsed = urlsplit(source.normalized_base_url)
        host = _normalize_host(parsed.hostname)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        started_ns = time.monotonic_ns()
        deadline_ns = started_ns + timeout_ms * 1_000_000
        last_transport_error: BaseException | None = None
        for address in addresses:
            if time.monotonic_ns() >= deadline_ns:
                raise ResearchDenied("TIMEOUT")
            try:
                result = self._request_address(
                    scheme=parsed.scheme,
                    host=host,
                    port=port,
                    address=address,
                    target_path=target_path,
                    allowed_content_types=source.allowed_content_types,
                    max_bytes=max_bytes,
                    deadline_ns=deadline_ns,
                )
            except ResearchDenied:
                raise
            except (OSError, ssl.SSLError, TimeoutError) as error:
                last_transport_error = error
                continue
            duration_ms = max(
                0,
                (time.monotonic_ns() - started_ns + 999_999) // 1_000_000,
            )
            return (*result, duration_ms)
        if time.monotonic_ns() >= deadline_ns:
            raise ResearchDenied("TIMEOUT") from last_transport_error
        raise ResearchDenied("TRANSPORT_ERROR") from last_transport_error

    def _request_address(
        self,
        *,
        scheme: str,
        host: str,
        port: int,
        address: str,
        target_path: str,
        allowed_content_types: tuple[str, ...],
        max_bytes: int,
        deadline_ns: int,
    ) -> tuple[int, str, bytes]:
        remaining_ns = deadline_ns - time.monotonic_ns()
        if remaining_ns <= 0:
            raise ResearchDenied("TIMEOUT")
        timeout_seconds = remaining_ns / 1_000_000_000
        if scheme == "https":
            connection: HTTPConnection = _PinnedHTTPSConnection(
                host,
                port,
                pinned_address=address,
                timeout=timeout_seconds,
                context=self._tls_context,
            )
        else:
            connection = _PinnedHTTPConnection(
                host,
                port,
                pinned_address=address,
                timeout=timeout_seconds,
            )
        response: HTTPResponse | None = None
        try:
            connection.request(
                "GET",
                target_path,
                headers={
                    "Accept": ", ".join(allowed_content_types),
                    "Connection": "close",
                    "User-Agent": "CCT-Operator-Web/1.0",
                },
            )
            response = connection.getresponse()
            status_code = response.status
            if 300 <= status_code <= 399:
                raise ResearchDenied("REDIRECT_DENIED")
            if not 200 <= status_code <= 299:
                raise ResearchDenied("HTTP_STATUS_DENIED")
            raw_content_type = response.headers.get("Content-Type")
            if not isinstance(raw_content_type, str) or not raw_content_type.strip():
                raise ResearchDenied("CONTENT_TYPE_DENIED")
            content_type = raw_content_type.split(";", 1)[0].strip().lower()
            if content_type not in allowed_content_types:
                raise ResearchDenied("CONTENT_TYPE_DENIED")
            charset = response.headers.get_content_charset()
            if charset is not None and charset.lower() not in {"utf-8", "us-ascii", "ascii"}:
                raise ResearchDenied("CHARSET_DENIED")
            content_encoding = response.headers.get("Content-Encoding")
            if content_encoding is not None and content_encoding.lower().strip() != "identity":
                raise ResearchDenied("CONTENT_ENCODING_DENIED")
            raw_length = response.headers.get("Content-Length")
            if raw_length is not None:
                try:
                    declared_length = int(raw_length)
                except (TypeError, ValueError):
                    raise ResearchDenied("CONTENT_LENGTH_INVALID") from None
                if declared_length < 0:
                    raise ResearchDenied("CONTENT_LENGTH_INVALID")
                if declared_length > max_bytes:
                    raise ResearchDenied("BODY_TOO_LARGE")
            body = self._read_bounded(
                connection,
                response,
                max_bytes=max_bytes,
                deadline_ns=deadline_ns,
            )
            try:
                body.decode("utf-8")
            except UnicodeDecodeError:
                raise ResearchDenied("BODY_NOT_UTF8") from None
            return status_code, content_type, body
        finally:
            if response is not None:
                response.close()
            connection.close()

    @staticmethod
    def _read_bounded(
        connection: HTTPConnection,
        response: HTTPResponse,
        *,
        max_bytes: int,
        deadline_ns: int,
    ) -> bytes:
        body = bytearray()
        while True:
            remaining_ns = deadline_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                raise ResearchDenied("TIMEOUT")
            if connection.sock is not None:
                connection.sock.settimeout(remaining_ns / 1_000_000_000)
            chunk = response.read1(min(65_536, max_bytes + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > max_bytes:
                raise ResearchDenied("BODY_TOO_LARGE")
        return bytes(body)

    def _completion(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.web.completed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise ResearchDenied("DUPLICATE_COMPLETION_RECEIPTS")
        return rows[0] if rows else None

    @staticmethod
    def _response(
        event: Event,
        *,
        content: str | None,
        target_url: str | None,
        replayed: bool,
    ) -> str:
        payload = event.payload
        return canonical_json(
            {
                "success": payload.get("verification_passed") is True,
                "effect": {
                    "effect_id": payload.get("effect_id"),
                    "idempotency_key": payload.get("ticket_id"),
                    "receipt_event_id": event.event_id,
                },
                "web": {
                    "source_id": payload.get("source_id"),
                    "operation": payload.get("operation"),
                    "target_url": target_url,
                    "target_url_sha256": payload.get("target_url_sha256"),
                    "status_code": payload.get("status_code"),
                    "content_type": payload.get("content_type"),
                    "byte_count": payload.get("byte_count"),
                    "content_sha256": payload.get("content_sha256"),
                    "duration_ms": payload.get("duration_ms"),
                    "content": content,
                    "provenance": "external_untrusted",
                    "authority_granted": False,
                    "eligible_for_goal_authority": False,
                    "producer_content_persisted": False,
                    "automatic_credentials_sent": False,
                    "recovered_after_crash": payload.get("recovered_after_crash") is True,
                    "replayed": replayed,
                },
                "verification": {
                    "passed": payload.get("verification_passed") is True,
                    "code": payload.get("verification_code"),
                    "evidence_sha256": payload.get("verification_evidence_sha256"),
                    "verifier_id": OPERATOR_WEB_VERIFIER_ID,
                },
            }
        )

    def _verify_mediated_result(
        self,
        value: object,
        context: VerificationContext,
    ) -> OutcomeVerification:
        malformed = OutcomeVerification(
            verified=False,
            effect_observed=False,
            status="malformed-result",
        )
        if not isinstance(value, dict) or context.verifier_id != OPERATOR_WEB_VERIFIER_ID:
            return malformed
        effect = value.get("effect")
        web = value.get("web")
        verification = value.get("verification")
        if not all(isinstance(row, dict) for row in (effect, web, verification)):
            return malformed
        assert isinstance(effect, dict)
        assert isinstance(web, dict)
        assert isinstance(verification, dict)
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            return OutcomeVerification(
                verified=False,
                effect_observed=False,
                status="receipt-missing",
            )
        payload = receipt.payload
        matched = (
            value.get("success") is True
            and payload.get("verification_passed") is True
            and effect.get("effect_id") == payload.get("effect_id")
            and effect.get("idempotency_key") == context.idempotency_key
            and effect.get("receipt_event_id") == receipt.event_id
            and web.get("source_id") == payload.get("source_id")
            and web.get("operation") == payload.get("operation")
            and web.get("target_url_sha256") == payload.get("target_url_sha256")
            and web.get("status_code") == payload.get("status_code")
            and web.get("content_type") == payload.get("content_type")
            and web.get("byte_count") == payload.get("byte_count")
            and web.get("content_sha256") == payload.get("content_sha256")
            and web.get("duration_ms") == payload.get("duration_ms")
            and web.get("provenance") == "external_untrusted"
            and web.get("authority_granted") is False
            and web.get("eligible_for_goal_authority") is False
            and web.get("producer_content_persisted") is False
            and web.get("automatic_credentials_sent") is False
            and web.get("recovered_after_crash")
            is (payload.get("recovered_after_crash") is True)
            and verification.get("passed") is True
            and verification.get("verifier_id") == OPERATOR_WEB_VERIFIER_ID
            and verification.get("code") == payload.get("verification_code")
            and verification.get("evidence_sha256")
            == payload.get("verification_evidence_sha256")
        )
        target_url = web.get("target_url")
        if target_url is not None:
            matched = matched and isinstance(target_url, str) and (
                sha256(target_url.encode("utf-8")).hexdigest()
                == payload.get("target_url_sha256")
            )
        content = web.get("content")
        if content is not None:
            matched = matched and isinstance(content, str)
            if isinstance(content, str):
                body = content.encode("utf-8")
                matched = matched and (
                    len(body) == payload.get("byte_count")
                    and sha256(body).hexdigest() == payload.get("content_sha256")
                )
        return OutcomeVerification(
            verified=matched,
            effect_observed=matched,
            status="verified" if matched else "receipt-mismatch",
            effect_id=str(payload["effect_id"]) if matched else None,
            evidence_sha256=(
                str(payload["verification_evidence_sha256"]) if matched else None
            ),
        )

    def _recover_verified_web(self, context: VerificationContext) -> object | None:
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied:
            return None
        claims = [
            event
            for event in self.store.events("operator.web.claimed")
            if event.payload.get("ticket_id") == context.ticket_id
        ]
        effects = [
            event
            for event in self.store.events("operator.web.effect_verified")
            if event.payload.get("ticket_id") == context.ticket_id
        ]
        dispatches = [
            event
            for event in self.store.events("execution.ticket.consumed")
            if event.payload.get("ticket_id") == context.ticket_id
        ]
        if len(claims) != 1 or len(effects) != 1 or len(dispatches) != 1:
            return None
        claim = claims[0]
        claim_payload = claim.payload
        effect_payload = effects[0].payload
        dispatch = dispatches[0]
        dispatch_payload = dispatch.payload
        source_id = claim_payload.get("source_id")
        source = self._sources.get(source_id) if isinstance(source_id, str) else None
        if (
            source is None
            or context.claim_event_id != dispatch.event_id
            or context.tool_name != "operator_web"
            or context.arguments_sha256 != dispatch_payload.get("arguments_sha256")
            or context.capability != "operator.web"
            or context.verifier_id != OPERATOR_WEB_VERIFIER_ID
            or context.idempotency_key != context.ticket_id
            or context.scope != f"operator/web/{source_id}"
            or dispatch_payload.get("tool_name") != context.tool_name
            or dispatch_payload.get("capability") != context.capability
            or dispatch_payload.get("scope") != context.scope
            or dispatch_payload.get("verifier_id") != context.verifier_id
            or dispatch_payload.get("idempotency_key") != context.idempotency_key
            or dispatch_payload.get("dispatch_claimed") is not True
            or dispatch_payload.get("ticket_consumed") is not True
            or effect_payload.get("schema_version") != OPERATOR_WEB_EFFECT_SCHEMA_VERSION
            or effect_payload.get("completion_pending") is not True
            or effect_payload.get("claim_event_id") != claim.event_id
            or effect_payload.get("verification_passed") is not True
        ):
            return None
        bound_fields = (
            "ticket_id",
            "source_id",
            "operation",
            "target_url_sha256",
            "query_sha256",
            "timeout_ms",
            "max_bytes",
            "effect_id",
            "provenance",
            "authority_granted",
            "automatic_credentials_sent",
            "producer_content_persisted",
            "raw_query_persisted",
        )
        if any(
            effect_payload.get(field) != claim_payload.get(field)
            for field in bound_fields
        ):
            return None
        operation = effect_payload.get("operation")
        timeout_ms = effect_payload.get("timeout_ms")
        max_bytes = effect_payload.get("max_bytes")
        byte_count = effect_payload.get("byte_count")
        duration_ms = effect_payload.get("duration_ms")
        status_code = effect_payload.get("status_code")
        content_type = effect_payload.get("content_type")
        query_sha256 = effect_payload.get("query_sha256")
        digest_fields = (
            "target_url_sha256",
            "content_sha256",
            "verification_evidence_sha256",
        )
        if (
            operation not in {"fetch", "search"}
            or (operation == "search" and source.search_path is None)
            or any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in (timeout_ms, max_bytes, byte_count, duration_ms, status_code)
            )
            or not 1 <= int(timeout_ms) <= source.timeout_ms
            or not 1 <= int(max_bytes) <= source.max_bytes
            or not 0 <= int(byte_count) <= int(max_bytes)
            or int(duration_ms) < 0
            or not 200 <= int(status_code) <= 299
            or not isinstance(content_type, str)
            or content_type not in source.allowed_content_types
            or any(
                not isinstance(effect_payload.get(field), str)
                or not re.fullmatch(r"[0-9a-f]{64}", effect_payload[field])
                for field in digest_fields
            )
            or (
                query_sha256 is not None
                and (
                    not isinstance(query_sha256, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", query_sha256)
                )
            )
            or effect_payload.get("verification_code") != "HTTP_RESPONSE_HASH_MATCH"
            or effect_payload.get("provenance") != "external_untrusted"
            or effect_payload.get("authority_granted") is not False
            or effect_payload.get("eligible_for_goal_authority") is not False
            or effect_payload.get("automatic_credentials_sent") is not False
            or effect_payload.get("producer_content_persisted") is not False
            or effect_payload.get("raw_query_persisted") is not False
        ):
            return None
        verification_material = {
            "effect_id": effect_payload["effect_id"],
            "source_id": source_id,
            "operation": operation,
            "target_url_sha256": effect_payload["target_url_sha256"],
            "status_code": status_code,
            "content_type": content_type,
            "byte_count": byte_count,
            "content_sha256": effect_payload["content_sha256"],
        }
        expected_evidence = sha256(
            canonical_json(verification_material).encode("utf-8")
        ).hexdigest()
        if effect_payload.get("verification_evidence_sha256") != expected_evidence:
            return None
        receipt = dict(effect_payload)
        receipt.pop("completion_pending", None)
        return json.loads(
            self._record_completion(
                ticket_id=context.ticket_id,
                receipt=receipt,
                content=None,
                target_url=None,
                recovered_after_crash=True,
            )
        )

    def _reconcile_mediated_result(self, context: VerificationContext) -> object | None:
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            return self._recover_verified_web(context)
        if receipt.payload.get("verification_passed") is not True:
            return None
        return json.loads(
            self._response(
                receipt,
                content=None,
                target_url=None,
                replayed=True,
            )
        )
