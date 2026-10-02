"""Authenticated host-owned mutation boundary for the CCTAE dashboard.

The browser can draft, preview, confirm, and request one exact configured-intent
change. Only this host service opens the canonical event store. The first slice
is deliberately limited to toggling ``operator.web``; it never creates a lease,
execution ticket, credential route, or external effect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
from threading import Lock
from typing import Any, Callable, Mapping

from .capabilities import CapabilityRegistry, _timestamp
from .store import Event, EventStore, GENESIS_HASH, canonical_json


BOOTSTRAP_SCHEMA_VERSION = "cct.admin_dashboard.bootstrap.v1"
CONTROL_SCHEMA_VERSION = "cct.admin_dashboard.control.v1"
PREVIEW_SCHEMA_VERSION = "cct.admin_dashboard.control_preview.v1"
CONFIRMATION_SCHEMA_VERSION = "cct.admin_dashboard.operator_confirmation.v1"
RESULT_SCHEMA_VERSION = "cct.admin_dashboard.control_result.v1"
CONTROL_ACTION = "SET_CAPABILITY_ADMINISTRATIVE_ACTIVE"
CONTROL_CAPABILITY = "operator.web"
MAX_BOOTSTRAP_BYTES = 4096
MAX_SESSION_SECONDS = 900
MAX_CONFIRMATION_SECONDS = 180
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class DashboardControlDenied(PermissionError):
    """Fail-closed control rejection containing only a bounded reason code."""

    def __init__(self, reason_code: str) -> None:
        if not isinstance(reason_code, str) or not _IDENTIFIER.fullmatch(reason_code):
            reason_code = "CONTROL_REQUEST_DENIED"
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a SHA-256 digest")
    return value


def _aware_time(name: str, value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed


def _canonical_digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _strict_mapping(
    value: Any,
    *,
    name: str,
    fields: set[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or {str(key) for key in value} != fields:
        raise ValueError(f"{name} requires exact fields")
    return value


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class _BootstrapSource:
    path: str
    parent_device: int
    parent_inode: int
    file_device: int
    file_inode: int
    file_size: int
    file_mtime_ns: int
    content_sha256: str

    def __post_init__(self) -> None:
        candidate = Path(self.path)
        if not candidate.is_absolute() or not candidate.name:
            raise ValueError("bootstrap source path must be absolute")
        for name in (
            "parent_device",
            "parent_inode",
            "file_device",
            "file_inode",
            "file_size",
            "file_mtime_ns",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"bootstrap source {name} must be non-negative")
        _digest("bootstrap source content_sha256", self.content_sha256)


@dataclass(frozen=True, slots=True)
class OperatorBootstrap:
    principal_id: str
    token: str
    expires_at: str
    source: _BootstrapSource | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        _identifier("bootstrap principal_id", self.principal_id)
        if not isinstance(self.token, str) or not _TOKEN.fullmatch(self.token):
            raise ValueError("bootstrap token must be 32-256 URL-safe characters")
        _aware_time("bootstrap expires_at", self.expires_at)
        if self.source is not None and not isinstance(self.source, _BootstrapSource):
            raise ValueError("bootstrap source binding is invalid")

    def as_payload(self) -> dict[str, str]:
        return {
            "schema_version": BOOTSTRAP_SCHEMA_VERSION,
            "principal_id": self.principal_id,
            "token": self.token,
            "expires_at": self.expires_at,
        }


def create_operator_bootstrap(
    path: str | Path,
    *,
    principal_id: str,
    ttl_seconds: int = 600,
    now: Callable[[], str] = _now_utc,
    token_factory: Callable[[], str] | None = None,
) -> dict[str, str]:
    """Create one host-readable bootstrap file without returning secret bytes."""

    principal = _identifier("bootstrap principal_id", principal_id)
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not 60 <= ttl_seconds <= MAX_SESSION_SECONDS
    ):
        raise ValueError(f"ttl_seconds must be between 60 and {MAX_SESSION_SECONDS}")
    issued = _aware_time("current time", now())
    token = (token_factory or (lambda: secrets.token_urlsafe(32)))()
    expires_at = (issued + timedelta(seconds=ttl_seconds)).isoformat()
    bootstrap = OperatorBootstrap(
        principal_id=principal,
        token=token,
        expires_at=expires_at,
    )
    destination = Path(path).expanduser().absolute()
    parent = destination.parent
    try:
        parent_metadata = parent.stat()
    except OSError as error:
        raise ValueError("bootstrap parent is unavailable") from error
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or parent_metadata.st_mode & 0o022
    ):
        raise ValueError("bootstrap parent must be owner-controlled")
    body = (canonical_json(bootstrap.as_payload()) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    complete = False
    try:
        written = 0
        while written < len(body):
            count = os.write(descriptor, body[written:])
            if count <= 0:
                raise OSError("bootstrap file write made no progress")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError("bootstrap file permissions are invalid")
        complete = True
    finally:
        os.close(descriptor)
        if not complete:
            try:
                destination.unlink()
            except OSError:
                pass
    return {
        "schema_version": BOOTSTRAP_SCHEMA_VERSION,
        "path": str(destination),
        "principal_id": principal,
        "expires_at": expires_at,
        "token_returned": "false",
    }


def load_operator_bootstrap(
    path: str | Path,
    *,
    now: Callable[[], str] = _now_utc,
) -> OperatorBootstrap:
    """Load one descriptor-bound, owner-only bootstrap file."""

    candidate = Path(path).expanduser().absolute()
    parent = candidate.parent
    try:
        parent_metadata = parent.stat()
        before = candidate.lstat()
    except OSError as error:
        raise ValueError("operator bootstrap is unavailable") from error
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or parent_metadata.st_mode & 0o022
    ):
        raise ValueError("operator bootstrap parent must be owner-controlled")
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or before.st_mode & 0o077
        or before.st_size > MAX_BOOTSTRAP_BYTES
    ):
        raise ValueError("operator bootstrap must be an owner-only regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(candidate, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("operator bootstrap changed during open")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_BOOTSTRAP_BYTES:
            chunk = os.read(descriptor, MAX_BOOTSTRAP_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_BOOTSTRAP_BYTES:
                raise ValueError("operator bootstrap exceeds its size limit")
        body = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
        ):
            raise ValueError("operator bootstrap changed during read")
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("operator bootstrap is invalid") from error
    row = _strict_mapping(
        payload,
        name="operator bootstrap",
        fields={"schema_version", "principal_id", "token", "expires_at"},
    )
    if row["schema_version"] != BOOTSTRAP_SCHEMA_VERSION:
        raise ValueError("operator bootstrap schema is unsupported")
    bootstrap = OperatorBootstrap(
        principal_id=row["principal_id"],
        token=row["token"],
        expires_at=row["expires_at"],
        source=_BootstrapSource(
            path=str(candidate),
            parent_device=int(parent_metadata.st_dev),
            parent_inode=int(parent_metadata.st_ino),
            file_device=int(after.st_dev),
            file_inode=int(after.st_ino),
            file_size=int(after.st_size),
            file_mtime_ns=int(after.st_mtime_ns),
            content_sha256=sha256(body).hexdigest(),
        ),
    )
    if _aware_time("bootstrap expires_at", bootstrap.expires_at) <= _aware_time(
        "current time", now()
    ):
        raise ValueError("operator bootstrap is expired")
    return bootstrap


@dataclass(frozen=True, slots=True)
class _OperatorSession:
    principal_id: str
    session_id_sha256: str
    csrf_token: str
    csrf_sha256: str
    expires_at: str


class DashboardSessionAuthority:
    """One-use bootstrap, short-lived cookie sessions, and signed confirmations."""

    def __init__(
        self,
        bootstrap: OperatorBootstrap,
        *,
        now: Callable[[], str] = _now_utc,
        signing_key: bytes | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self.principal_id = bootstrap.principal_id
        self._bootstrap_sha256 = sha256(bootstrap.token.encode("utf-8")).hexdigest()
        self._bootstrap_expires_at = bootstrap.expires_at
        self._bootstrap_source = bootstrap.source
        self._bootstrap_used = False
        self._now = now
        self._signing_key = signing_key or secrets.token_bytes(32)
        if len(self._signing_key) < 32:
            raise ValueError("dashboard signing key must be at least 32 bytes")
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._sessions: dict[str, _OperatorSession] = {}
        self._lock = Lock()

    @property
    def signing_key(self) -> bytes:
        """Host-only key access for process-isolated verification fixtures."""

        return self._signing_key

    @property
    def durable_bootstrap_consumption(self) -> bool:
        """Whether successful unlock atomically removes a bound bootstrap file."""

        return self._bootstrap_source is not None

    def _consume_bootstrap_file(self) -> None:
        source = self._bootstrap_source
        if source is None:
            return
        candidate = Path(source.path)
        parent = candidate.parent
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        parent_descriptor = -1
        descriptor = -1
        try:
            parent_descriptor = os.open(parent, directory_flags)
            parent_metadata = os.fstat(parent_descriptor)
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != os.geteuid()
                or parent_metadata.st_mode & 0o022
                or (parent_metadata.st_dev, parent_metadata.st_ino)
                != (source.parent_device, source.parent_inode)
            ):
                raise ValueError("bootstrap parent identity changed")
            descriptor = os.open(
                candidate.name,
                file_flags,
                dir_fd=parent_descriptor,
            )
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or opened.st_mode & 0o077
                or (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    opened.st_mtime_ns,
                )
                != (
                    source.file_device,
                    source.file_inode,
                    source.file_size,
                    source.file_mtime_ns,
                )
            ):
                raise ValueError("bootstrap file identity changed")
            chunks: list[bytes] = []
            total = 0
            while total <= MAX_BOOTSTRAP_BYTES:
                chunk = os.read(descriptor, MAX_BOOTSTRAP_BYTES + 1 - total)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_BOOTSTRAP_BYTES:
                    raise ValueError("bootstrap file exceeds its size limit")
            body = b"".join(chunks)
            after = os.fstat(descriptor)
            named = os.stat(
                candidate.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                )
                != (
                    source.file_device,
                    source.file_inode,
                    source.file_size,
                    source.file_mtime_ns,
                )
                or (named.st_dev, named.st_ino)
                != (source.file_device, source.file_inode)
                or not hmac.compare_digest(
                    sha256(body).hexdigest(), source.content_sha256
                )
            ):
                raise ValueError("bootstrap file changed before consumption")
            os.unlink(candidate.name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        except (OSError, ValueError) as error:
            raise DashboardControlDenied(
                "OPERATOR_BOOTSTRAP_CONSUMPTION_FAILED"
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if parent_descriptor >= 0:
                os.close(parent_descriptor)

    def _now_value(self) -> tuple[str, datetime]:
        value = self._now()
        return value, _aware_time("current time", value)

    def open_session(self, bootstrap_token: Any) -> dict[str, str]:
        if not isinstance(bootstrap_token, str) or not _TOKEN.fullmatch(bootstrap_token):
            raise DashboardControlDenied("OPERATOR_SESSION_DENIED")
        now_text, current = self._now_value()
        del now_text
        with self._lock:
            presented = sha256(bootstrap_token.encode("utf-8")).hexdigest()
            if (
                self._bootstrap_used
                or _aware_time("bootstrap expires_at", self._bootstrap_expires_at)
                <= current
                or not hmac.compare_digest(presented, self._bootstrap_sha256)
            ):
                raise DashboardControlDenied("OPERATOR_SESSION_DENIED")
            session_token = self._token_factory()
            csrf_token = self._token_factory()
            if (
                not _TOKEN.fullmatch(session_token)
                or not _TOKEN.fullmatch(csrf_token)
                or session_token == csrf_token
                or hmac.compare_digest(
                    sha256(session_token.encode("utf-8")).hexdigest(),
                    self._bootstrap_sha256,
                )
                or hmac.compare_digest(
                    sha256(csrf_token.encode("utf-8")).hexdigest(),
                    self._bootstrap_sha256,
                )
            ):
                raise ValueError("session token factory returned invalid or repeated tokens")
            self._consume_bootstrap_file()
            session_digest = sha256(session_token.encode("utf-8")).hexdigest()
            expires = min(
                _aware_time("bootstrap expires_at", self._bootstrap_expires_at),
                current + timedelta(seconds=MAX_SESSION_SECONDS),
            ).isoformat()
            session = _OperatorSession(
                principal_id=self.principal_id,
                session_id_sha256=session_digest,
                csrf_token=csrf_token,
                csrf_sha256=sha256(csrf_token.encode("utf-8")).hexdigest(),
                expires_at=expires,
            )
            self._sessions[session_digest] = session
            self._bootstrap_used = True
        return {
            "principal_id": session.principal_id,
            "session_token": session_token,
            "session_id_sha256": session.session_id_sha256,
            "csrf_token": session.csrf_token,
            "expires_at": session.expires_at,
        }

    def authenticate(
        self,
        session_token: Any,
        *,
        csrf_token: Any | None = None,
        require_csrf: bool,
    ) -> dict[str, str]:
        if not isinstance(session_token, str) or not _TOKEN.fullmatch(session_token):
            raise DashboardControlDenied("OPERATOR_AUTHENTICATION_REQUIRED")
        session_digest = sha256(session_token.encode("utf-8")).hexdigest()
        with self._lock:
            session = self._sessions.get(session_digest)
        if session is None or not hmac.compare_digest(
            session.session_id_sha256, session_digest
        ):
            raise DashboardControlDenied("OPERATOR_AUTHENTICATION_REQUIRED")
        _now_text, current = self._now_value()
        if _aware_time("session expires_at", session.expires_at) <= current:
            raise DashboardControlDenied("OPERATOR_SESSION_EXPIRED")
        if require_csrf:
            if not isinstance(csrf_token, str) or not _TOKEN.fullmatch(csrf_token):
                raise DashboardControlDenied("OPERATOR_CSRF_DENIED")
            csrf_digest = sha256(csrf_token.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(csrf_digest, session.csrf_sha256):
                raise DashboardControlDenied("OPERATOR_CSRF_DENIED")
        return {
            "principal_id": session.principal_id,
            "session_id_sha256": session.session_id_sha256,
            "csrf_token": session.csrf_token,
            "expires_at": session.expires_at,
        }

    def issue_confirmation(
        self,
        *,
        session: Mapping[str, str],
        preview_sha256: str,
    ) -> dict[str, str]:
        preview_digest = _digest("preview_sha256", preview_sha256)
        principal = _identifier("principal_id", session.get("principal_id"))
        if principal != self.principal_id:
            raise DashboardControlDenied("OPERATOR_PRINCIPAL_MISMATCH")
        session_digest = _digest(
            "session_id_sha256", session.get("session_id_sha256")
        )
        now_text, current = self._now_value()
        expiry = min(
            _aware_time("session expires_at", session.get("expires_at")),
            current + timedelta(seconds=MAX_CONFIRMATION_SECONDS),
        ).isoformat()
        entropy = self._token_factory()
        if not isinstance(entropy, str) or not _TOKEN.fullmatch(entropy):
            raise ValueError("confirmation token factory returned an invalid token")
        body = {
            "schema_version": CONFIRMATION_SCHEMA_VERSION,
            "confirmation_id": f"confirm-{sha256(entropy.encode()).hexdigest()[:24]}",
            "principal_id": principal,
            "session_id_sha256": session_digest,
            "preview_sha256": preview_digest,
            "issued_at": now_text,
            "expires_at": expiry,
        }
        signature = hmac.new(
            self._signing_key,
            canonical_json(body).encode("utf-8"),
            sha256,
        ).hexdigest()
        return {**body, "signature": signature}

    def verify_confirmation(
        self,
        confirmation: Any,
        *,
        preview_sha256: str,
        session_id_sha256: str,
    ) -> dict[str, str]:
        row = _strict_mapping(
            confirmation,
            name="operator confirmation",
            fields={
                "schema_version",
                "confirmation_id",
                "principal_id",
                "session_id_sha256",
                "preview_sha256",
                "issued_at",
                "expires_at",
                "signature",
            },
        )
        if row["schema_version"] != CONFIRMATION_SCHEMA_VERSION:
            raise DashboardControlDenied("OPERATOR_CONFIRMATION_INVALID")
        body = {key: row[key] for key in row if key != "signature"}
        expected_signature = hmac.new(
            self._signing_key,
            canonical_json(body).encode("utf-8"),
            sha256,
        ).hexdigest()
        signature = row["signature"]
        if (
            not isinstance(signature, str)
            or not _DIGEST.fullmatch(signature)
            or not hmac.compare_digest(signature, expected_signature)
        ):
            raise DashboardControlDenied("OPERATOR_CONFIRMATION_INVALID")
        try:
            confirmation_id = _identifier("confirmation_id", row["confirmation_id"])
            principal = _identifier("principal_id", row["principal_id"])
            bound_session = _digest("session_id_sha256", row["session_id_sha256"])
            bound_preview = _digest("preview_sha256", row["preview_sha256"])
            issued = _aware_time("confirmation issued_at", row["issued_at"])
            expires = _aware_time("confirmation expires_at", row["expires_at"])
            _now_text, current = self._now_value()
        except ValueError as error:
            raise DashboardControlDenied("OPERATOR_CONFIRMATION_INVALID") from error
        if expires <= current:
            raise DashboardControlDenied("OPERATOR_CONFIRMATION_EXPIRED")
        if (
            principal != self.principal_id
            or bound_session != _digest("session_id_sha256", session_id_sha256)
            or bound_preview != _digest("preview_sha256", preview_sha256)
            or issued > current
            or expires - issued > timedelta(seconds=MAX_CONFIRMATION_SECONDS)
        ):
            raise DashboardControlDenied("OPERATOR_CONFIRMATION_INVALID")
        return {
            "confirmation_id": confirmation_id,
            "principal_id": principal,
            "session_id_sha256": bound_session,
            "preview_sha256": bound_preview,
            "issued_at": str(row["issued_at"]),
            "expires_at": str(row["expires_at"]),
            "confirmation_sha256": _canonical_digest(dict(row)),
        }


class DashboardControlService:
    """Atomic control service for one bounded configured-intent mutation."""

    def __init__(
        self,
        store: EventStore,
        *,
        sessions: DashboardSessionAuthority,
    ) -> None:
        if sessions.principal_id != sessions.principal_id.strip():
            raise ValueError("operator principal_id is invalid")
        self.store = store
        self.sessions = sessions
        self.principal_id = sessions.principal_id

    @staticmethod
    def _chain(events: list[Event]) -> dict[str, object]:
        previous_hash = GENESIS_HASH
        expected_seq = 1
        for event in events:
            if event.seq != expected_seq or event.previous_hash != previous_hash:
                return {"valid": False, "head_hash": previous_hash}
            expected_hash = EventStore._digest(
                seq=event.seq,
                event_id=event.event_id,
                occurred_at=event.occurred_at,
                kind=event.kind,
                payload=event.payload,
                previous_hash=event.previous_hash,
            )
            if event.event_hash != expected_hash:
                return {"valid": False, "head_hash": previous_hash}
            previous_hash = event.event_hash
            expected_seq += 1
        return {"valid": True, "head_hash": previous_hash}

    @staticmethod
    def _kill_state(events: list[Event]) -> dict[str, object]:
        active: Event | None = None
        latest: Event | None = None
        for event in events:
            if event.kind == "operator.kill_switch.tripped":
                active = event
                latest = event
            elif (
                event.kind == "operator.kill_switch.cleared"
                and active is not None
                and event.payload.get("active_trip_event_id") == active.event_id
            ):
                active = None
                latest = event
        return {
            "active": active is not None,
            "active_trip_event_id": active.event_id if active else None,
            "latest_transition_event_id": latest.event_id if latest else None,
        }

    def _state(self, events: list[Event], *, current_time: str) -> dict[str, Any]:
        chain = self._chain(events)
        if chain["valid"] is not True:
            raise DashboardControlDenied("CONTROL_LEDGER_CHAIN_INVALID")
        registry = CapabilityRegistry(self.store)
        spec_row = registry._spec_rows(events).get(CONTROL_CAPABILITY)
        if spec_row is None:
            raise DashboardControlDenied("CONTROL_CAPABILITY_NOT_INSTALLED")
        spec, spec_digest, revision = spec_row
        if (
            spec.name != CONTROL_CAPABILITY
            or spec.active is not True
            or spec.reversible is not True
            or spec.risk_class not in {"observe", "reversible"}
            or spec.max_value_microunits != 0
        ):
            raise DashboardControlDenied("CONTROL_CAPABILITY_OUT_OF_SCOPE")
        principal = next(
            (
                event
                for event in reversed(events)
                if event.kind == "principal.profile.installed"
            ),
            None,
        )
        if principal is None:
            raise DashboardControlDenied("CONTROL_PRINCIPAL_PROFILE_REQUIRED")
        principal_id = principal.payload.get("profile", {}).get("principal_id")
        principal_digest = principal.payload.get("profile_digest")
        if principal_id != self.principal_id or not isinstance(
            principal_digest, str
        ) or not _DIGEST.fullmatch(principal_digest):
            raise DashboardControlDenied("CONTROL_PRINCIPAL_PROFILE_CHANGED")
        kill = self._kill_state(events)
        leases = registry._leases(events)
        revocations = registry._revocations(events)
        administrative = registry._administrative_states(events).get(
            CONTROL_CAPABILITY,
            {"active": True, "revision": 0, "event_id": None},
        )
        now_value = _timestamp(current_time)
        active_lease_ids = sorted(
            lease_id
            for lease_id, lease in leases.items()
            if lease.capability == CONTROL_CAPABILITY
            and lease_id not in revocations
            and _timestamp(lease.expires_at) > now_value
        )
        state = {
            "capability": CONTROL_CAPABILITY,
            "spec_digest": spec_digest,
            "spec_revision": revision,
            "active": administrative["active"] is True,
            "control_revision": int(administrative["revision"]),
            "control_event_id": administrative["event_id"],
            "active_lease_ids": active_lease_ids,
            "principal_id": self.principal_id,
            "principal_profile_digest": principal_digest,
            "kill_switch_active": kill["active"],
            "kill_switch_transition_event_id": kill["latest_transition_event_id"],
        }
        return {
            **state,
            "state_sha256": _canonical_digest(state),
            "chain_head_hash": chain["head_hash"],
        }

    @staticmethod
    def _draft(value: Any) -> dict[str, Any]:
        row = _strict_mapping(
            value,
            name="control draft",
            fields={"draft_id", "action", "capability", "active"},
        )
        draft_id = _identifier("draft_id", row["draft_id"])
        if row["action"] != CONTROL_ACTION or row["capability"] != CONTROL_CAPABILITY:
            raise DashboardControlDenied("CONTROL_TARGET_DENIED")
        if not isinstance(row["active"], bool):
            raise ValueError("control draft active must be a boolean")
        return {
            "draft_id": draft_id,
            "action": CONTROL_ACTION,
            "capability": CONTROL_CAPABILITY,
            "active": row["active"],
        }

    def preview(self, draft: Any, *, expires_at: str) -> dict[str, Any]:
        normalized = self._draft(draft)
        current_time = self.store.clock()
        expires = _aware_time("preview expires_at", expires_at)
        if expires <= _aware_time("current time", current_time):
            raise DashboardControlDenied("CONTROL_PREVIEW_EXPIRED")
        events = self.store.events()
        state = self._state(events, current_time=current_time)
        if state["kill_switch_active"] is True:
            raise DashboardControlDenied("GLOBAL_KILL_SWITCH_ACTIVE")
        desired = normalized["active"]
        if desired is state["active"]:
            raise DashboardControlDenied("CONTROL_NO_CHANGE")
        if desired is True and state["active_lease_ids"]:
            raise DashboardControlDenied("CONTROL_ENABLE_WITH_ACTIVE_LEASES_DENIED")
        core = {
            "schema_version": PREVIEW_SCHEMA_VERSION,
            "draft": normalized,
            "expires_at": expires_at,
            "state_sha256": state["state_sha256"],
            "before": {
                "active": state["active"],
                "spec_digest": state["spec_digest"],
                "spec_revision": state["spec_revision"],
                "control_revision": state["control_revision"],
                "active_lease_count": len(state["active_lease_ids"]),
                "effective_state": (
                    "LEASED_TICKET_REQUIRED"
                    if state["active"] and state["active_lease_ids"]
                    else "DENY"
                    if state["active"]
                    else "PAUSED"
                ),
            },
            "after": {
                "active": desired,
                "spec_digest": state["spec_digest"],
                "spec_revision": state["spec_revision"],
                "control_revision": int(state["control_revision"]) + 1,
                "effective_state": "DENY" if desired else "PAUSED",
            },
            "impact": {
                "configured_intent_changed": True,
                "configured_intent_expanded": desired is True,
                "lease_created": False,
                "ticket_created": False,
                "route_changed": False,
                "external_effects": 0,
                "readback": "canonical capability registry plus valid event chain",
            },
        }
        return {**core, "preview_sha256": _canonical_digest(core)}

    def _preview_envelope(self, value: Any) -> dict[str, Any]:
        row = _strict_mapping(
            value,
            name="control preview",
            fields={
                "schema_version",
                "draft",
                "expires_at",
                "state_sha256",
                "before",
                "after",
                "impact",
                "preview_sha256",
            },
        )
        if row["schema_version"] != PREVIEW_SCHEMA_VERSION:
            raise DashboardControlDenied("CONTROL_PREVIEW_INVALID")
        try:
            supplied_digest = _digest("preview_sha256", row["preview_sha256"])
            core = {key: row[key] for key in row if key != "preview_sha256"}
            if not hmac.compare_digest(supplied_digest, _canonical_digest(core)):
                raise DashboardControlDenied("CONTROL_PREVIEW_INVALID")
        except (KeyError, TypeError, ValueError) as error:
            raise DashboardControlDenied("CONTROL_PREVIEW_INVALID") from error
        return dict(row)

    def _validated_preview(self, value: Any) -> dict[str, Any]:
        row = self._preview_envelope(value)
        try:
            supplied_digest = _digest("preview_sha256", row["preview_sha256"])
            expires_at = str(row["expires_at"])
            if _aware_time("preview expires_at", expires_at) <= _aware_time(
                "current time", self.store.clock()
            ):
                raise DashboardControlDenied("CONTROL_PREVIEW_EXPIRED")
            expected = self.preview(row["draft"], expires_at=expires_at)
        except DashboardControlDenied:
            raise
        except (KeyError, TypeError, ValueError) as error:
            raise DashboardControlDenied("CONTROL_PREVIEW_INVALID") from error
        if (
            not hmac.compare_digest(supplied_digest, expected["preview_sha256"])
            or canonical_json(row) != canonical_json(expected)
        ):
            raise DashboardControlDenied("CONTROL_PREVIEW_STALE")
        return expected

    def confirm(
        self,
        preview: Any,
        *,
        session: Mapping[str, str],
    ) -> dict[str, str]:
        """Validate a fresh preview before minting one short-lived confirmation."""

        validated_preview = self._validated_preview(preview)
        return self.sessions.issue_confirmation(
            session=session,
            preview_sha256=validated_preview["preview_sha256"],
        )

    def apply(
        self,
        preview: Any,
        confirmation: Any,
        *,
        session_id_sha256: str,
    ) -> dict[str, Any]:
        preview_envelope = self._preview_envelope(preview)
        verified_confirmation = self.sessions.verify_confirmation(
            confirmation,
            preview_sha256=preview_envelope["preview_sha256"],
            session_id_sha256=session_id_sha256,
        )
        confirmation_id = verified_confirmation["confirmation_id"]
        if any(
            event.kind == "capability.control.state_changed"
            and isinstance(event.payload.get("control_receipt"), Mapping)
            and event.payload["control_receipt"].get("confirmation_id")
            == confirmation_id
            for event in self.store.events()
        ):
            raise DashboardControlDenied("CONTROL_CONFIRMATION_REPLAYED")
        validated_preview = preview_envelope
        after_payload = validated_preview["after"]
        desired_active = after_payload["active"]
        expected_state_sha256 = validated_preview["state_sha256"]

        def factory(events: list[Event]) -> tuple[str, Mapping[str, Any]]:
            for event in events:
                receipt = event.payload.get("control_receipt")
                if (
                    event.kind == "capability.control.state_changed"
                    and isinstance(receipt, Mapping)
                    and receipt.get("confirmation_id") == confirmation_id
                ):
                    raise DashboardControlDenied("CONTROL_CONFIRMATION_REPLAYED")
            transaction_confirmation = self.sessions.verify_confirmation(
                confirmation,
                preview_sha256=validated_preview["preview_sha256"],
                session_id_sha256=session_id_sha256,
            )
            transaction_time = self.store.clock()
            if _aware_time("transaction time", transaction_time) >= _aware_time(
                "confirmation expires_at", transaction_confirmation["expires_at"]
            ):
                raise DashboardControlDenied("OPERATOR_CONFIRMATION_EXPIRED")
            state = self._state(events, current_time=transaction_time)
            if state["kill_switch_active"] is True:
                raise DashboardControlDenied("GLOBAL_KILL_SWITCH_ACTIVE")
            if state["state_sha256"] != expected_state_sha256:
                raise DashboardControlDenied("CONTROL_PREVIEW_STALE")
            if desired_active is state["active"]:
                raise DashboardControlDenied("CONTROL_NO_CHANGE")
            if desired_active is True and state["active_lease_ids"]:
                raise DashboardControlDenied(
                    "CONTROL_ENABLE_WITH_ACTIVE_LEASES_DENIED"
                )
            revision = int(state["control_revision"]) + 1
            if revision != after_payload["control_revision"]:
                raise DashboardControlDenied("CONTROL_PREVIEW_STALE")
            if (
                after_payload["spec_digest"] != state["spec_digest"]
                or after_payload["spec_revision"] != state["spec_revision"]
            ):
                raise DashboardControlDenied("CONTROL_PREVIEW_STALE")
            control_receipt = {
                "schema_version": CONTROL_SCHEMA_VERSION,
                "action": CONTROL_ACTION,
                "capability": CONTROL_CAPABILITY,
                "draft_id": validated_preview["draft"]["draft_id"],
                "principal_id": transaction_confirmation["principal_id"],
                "principal_profile_digest": state["principal_profile_digest"],
                "session_id_sha256": transaction_confirmation["session_id_sha256"],
                "confirmation_id": confirmation_id,
                "confirmation_sha256": transaction_confirmation[
                    "confirmation_sha256"
                ],
                "preview_sha256": validated_preview["preview_sha256"],
                "before_state_sha256": expected_state_sha256,
                "spec_digest": state["spec_digest"],
                "spec_revision": state["spec_revision"],
                "before_control_revision": state["control_revision"],
                "after_control_revision": revision,
                "after_active": desired_active,
                "confirmation_issued_at": transaction_confirmation["issued_at"],
                "confirmation_expires_at": transaction_confirmation["expires_at"],
                "applied_at": transaction_time,
                "lease_created": False,
                "ticket_created": False,
                "route_changed": False,
                "external_effects": 0,
                "readback_required": True,
            }
            payload = {
                "schema_version": 1,
                "revision": revision,
                "capability": CONTROL_CAPABILITY,
                "active": desired_active,
                "previous_active": state["active"],
                "previous_control_event_id": state["control_event_id"],
                "authority": "operator",
                "control_receipt": control_receipt,
            }
            logical_key = (
                f"{CONTROL_CAPABILITY}:{revision}:"
                f"{validated_preview['preview_sha256']}"
            )
            return logical_key, payload

        event, created = self.store.append_computed_once(
            "capability.control.state_changed", factory
        )
        if not created:
            raise DashboardControlDenied("CONTROL_CONFIRMATION_REPLAYED")
        status = CapabilityRegistry(self.store).status()
        readback = status["specifications"].get(CONTROL_CAPABILITY)
        chain = self.store.verify_chain()
        if (
            not isinstance(readback, Mapping)
            or readback.get("active") is not True
            or readback.get("administrative_active") is not desired_active
            or readback.get("spec_digest") != after_payload["spec_digest"]
            or readback.get("revision") != after_payload["spec_revision"]
            or readback.get("administrative_revision")
            != after_payload["control_revision"]
            or chain["valid"] is not True
        ):
            raise DashboardControlDenied("CONTROL_READBACK_MISMATCH")
        return {
            "schema_version": RESULT_SCHEMA_VERSION,
            "status": "VERIFIED",
            "action": CONTROL_ACTION,
            "capability": CONTROL_CAPABILITY,
            "active": desired_active,
            "effective_state": after_payload["effective_state"],
            "spec_digest": readback["spec_digest"],
            "spec_revision": readback["revision"],
            "control_revision": readback["administrative_revision"],
            "applied_event_id": event.event_id,
            "confirmation_id": confirmation_id,
            "preview_sha256": validated_preview["preview_sha256"],
            "chain_valid": True,
            "lease_created": False,
            "ticket_created": False,
            "route_changed": False,
            "external_effects": 0,
        }


def bootstrap_main(argv: list[str] | None = None) -> int:
    """Create an owner-only one-use operator bootstrap file."""

    import argparse

    parser = argparse.ArgumentParser(
        prog="cct-dashboard-bootstrap",
        description="Create an owner-only CCTAE dashboard operator bootstrap file.",
    )
    parser.add_argument("--out", required=True)
    parser.add_argument("--principal-id", default="mike")
    parser.add_argument("--ttl-seconds", type=int, default=600)
    args = parser.parse_args(argv)
    result = create_operator_bootstrap(
        Path(args.out),
        principal_id=args.principal_id,
        ttl_seconds=args.ttl_seconds,
    )
    print(
        "CCTAE operator bootstrap created "
        f"at {result['path']} for {result['principal_id']} until {result['expires_at']}. "
        "Secret token was written only to the owner-only file."
    )
    return 0
