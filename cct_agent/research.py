"""Typed, bounded, read-only research adapter with hash-only receipts."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPMessage
import ipaddress
import re
import ssl
from types import MappingProxyType
from typing import Any, Literal, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from .store import EventStore


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
