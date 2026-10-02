"""Read-only, privacy-minimized projections for the CCTAE operator dashboard."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
from typing import Any, Iterable
from urllib.parse import quote

from .capabilities import CapabilityRegistry
from .execution_tickets import GlobalKillSwitch
from .narrative import HumanNarrative
from .store import Event, EventStore, GENESIS_HASH


DASHBOARD_SCHEMA_VERSION = "cct.admin_dashboard.snapshot.v1"
MAX_DASHBOARD_DATABASE_BYTES = 256 * 1024 * 1024
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:@/-]{1,180}$")
_ACCESS_STATES = {
    "DISCONNECTED",
    "AUTH_HANDOFF_REQUIRED",
    "READY",
    "CONNECTED",
    "READ_VERIFIED",
    "TRIAGE_VERIFIED",
    "DRAFT_VERIFIED",
    "SEND_VERIFIED",
    "VERIFIED",
    "BLOCKED",
}
_CONNECTED_STATES = {
    "CONNECTED",
    "READ_VERIFIED",
    "TRIAGE_VERIFIED",
    "DRAFT_VERIFIED",
    "SEND_VERIFIED",
    "VERIFIED",
}


class DashboardUnavailable(RuntimeError):
    """Bounded reason code for an unavailable dashboard data source."""


class ReadOnlyEventStore:
    """EventStore-compatible reader backed by a stable private SQLite snapshot."""

    def __init__(self, path: str | Path, *, now: str | None = None) -> None:
        candidate = Path(path).expanduser().absolute()
        if not candidate.exists():
            raise DashboardUnavailable("DASHBOARD_DATABASE_NOT_FOUND")
        if candidate.is_symlink():
            raise DashboardUnavailable("DASHBOARD_DATABASE_SYMLINK_DENIED")
        try:
            metadata = candidate.stat()
        except OSError:
            raise DashboardUnavailable("DASHBOARD_DATABASE_UNREADABLE") from None
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise DashboardUnavailable("DASHBOARD_DATABASE_INVALID_FILE")
        self.source_path = candidate
        self._source_identity = (metadata.st_dev, metadata.st_ino)
        self._now = now or datetime.now(timezone.utc).isoformat()
        self.clock: Callable[[], str] = lambda: self._now
        self._temporary = tempfile.TemporaryDirectory(prefix="cct-dashboard-snapshot-")
        self.path = Path(self._temporary.name) / "agency.sqlite"
        self._copy_stable_snapshot()
        snapshot = self.path.stat()
        self._identity = (snapshot.st_dev, snapshot.st_ino)
        self._validate_schema()

    @staticmethod
    def _signature(path: Path) -> tuple[int, int, int, int, int] | None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or path.is_symlink()
        ):
            raise DashboardUnavailable("DASHBOARD_DATABASE_INVALID_FILE")
        if metadata.st_size > MAX_DASHBOARD_DATABASE_BYTES:
            raise DashboardUnavailable("DASHBOARD_DATABASE_TOO_LARGE")
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    @staticmethod
    def _read_descriptor(path: Path) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            raise DashboardUnavailable("DASHBOARD_DATABASE_CHANGED") from None
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise DashboardUnavailable("DASHBOARD_DATABASE_INVALID_FILE")
            if before.st_size > MAX_DASHBOARD_DATABASE_BYTES:
                raise DashboardUnavailable("DASHBOARD_DATABASE_TOO_LARGE")
            chunks: list[bytes] = []
            total = 0
            while total <= MAX_DASHBOARD_DATABASE_BYTES:
                remaining = MAX_DASHBOARD_DATABASE_BYTES + 1 - total
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_DASHBOARD_DATABASE_BYTES:
                    raise DashboardUnavailable("DASHBOARD_DATABASE_TOO_LARGE")
            after = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or not stat.S_ISREG(after.st_mode)
                or after.st_nlink != 1
            ):
                raise DashboardUnavailable("DASHBOARD_DATABASE_CHANGED")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def _copy_stable_snapshot(self) -> None:
        wal_source = Path(f"{self.source_path}-wal")
        for _attempt in range(3):
            source_before = self._signature(self.source_path)
            wal_before = self._signature(wal_source)
            if source_before is None or source_before[:2] != self._source_identity:
                raise DashboardUnavailable("DASHBOARD_DATABASE_CHANGED")
            database_bytes = self._read_descriptor(self.source_path)
            wal_bytes = self._read_descriptor(wal_source) if wal_before is not None else None
            source_after = self._signature(self.source_path)
            wal_after = self._signature(wal_source)
            if source_before == source_after and wal_before == wal_after:
                self.path.write_bytes(database_bytes)
                self.path.chmod(0o600)
                if wal_bytes is not None:
                    wal_target = Path(f"{self.path}-wal")
                    wal_target.write_bytes(wal_bytes)
                    wal_target.chmod(0o600)
                return
        raise DashboardUnavailable("DASHBOARD_DATABASE_BUSY")

    def close(self) -> None:
        temporary = getattr(self, "_temporary", None)
        if temporary is not None:
            temporary.cleanup()
            self._temporary = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _assert_identity(self) -> None:
        try:
            metadata = self.path.stat()
        except OSError:
            raise DashboardUnavailable("DASHBOARD_DATABASE_CHANGED") from None
        if self.path.is_symlink() or (metadata.st_dev, metadata.st_ino) != self._identity:
            raise DashboardUnavailable("DASHBOARD_DATABASE_CHANGED")

    def _connect(self) -> sqlite3.Connection:
        self._assert_identity()
        uri_path = quote(str(self.path), safe="/:\\")
        try:
            connection = sqlite3.connect(
                f"file:{uri_path}?mode=rw",
                uri=True,
                timeout=5.0,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            self._assert_identity()
            return connection
        except (OSError, sqlite3.Error):
            raise DashboardUnavailable("DASHBOARD_DATABASE_INVALID") from None

    def _validate_schema(self) -> None:
        try:
            with self._connect() as connection:
                rows = connection.execute("PRAGMA table_info(events)").fetchall()
        except DashboardUnavailable:
            raise
        except sqlite3.Error:
            raise DashboardUnavailable("DASHBOARD_DATABASE_INVALID") from None
        columns = {str(row["name"]) for row in rows}
        expected = {
            "seq",
            "event_id",
            "occurred_at",
            "kind",
            "payload_json",
            "previous_hash",
            "event_hash",
        }
        if not expected.issubset(columns):
            raise DashboardUnavailable("DASHBOARD_DATABASE_INVALID")

    @staticmethod
    def _event(row: sqlite3.Row) -> Event:
        try:
            payload = json.loads(str(row["payload_json"]))
            if not isinstance(payload, dict):
                raise ValueError
            return Event(
                seq=int(row["seq"]),
                event_id=str(row["event_id"]),
                occurred_at=str(row["occurred_at"]),
                kind=str(row["kind"]),
                payload=payload,
                previous_hash=str(row["previous_hash"]),
                event_hash=str(row["event_hash"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise DashboardUnavailable("DASHBOARD_DATABASE_INVALID") from None

    def events(self, kind: str | None = None) -> list[Event]:
        sql = "SELECT * FROM events"
        parameters: tuple[object, ...] = ()
        if kind is not None:
            sql += " WHERE kind = ?"
            parameters = (kind,)
        sql += " ORDER BY seq"
        try:
            with self._connect() as connection:
                rows = connection.execute(sql, parameters).fetchall()
        except DashboardUnavailable:
            raise
        except sqlite3.Error:
            raise DashboardUnavailable("DASHBOARD_DATABASE_INVALID") from None
        return [self._event(row) for row in rows]

    def event(self, event_id: str) -> Event | None:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM events WHERE event_id = ?", (event_id,)
                ).fetchone()
        except DashboardUnavailable:
            raise
        except sqlite3.Error:
            raise DashboardUnavailable("DASHBOARD_DATABASE_INVALID") from None
        return self._event(row) if row is not None else None

    def latest(self, kind: str) -> Event | None:
        rows = self.events(kind)
        return rows[-1] if rows else None

    def count(self) -> int:
        try:
            with self._connect() as connection:
                return int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        except DashboardUnavailable:
            raise
        except sqlite3.Error:
            raise DashboardUnavailable("DASHBOARD_DATABASE_INVALID") from None

    def verify_chain(self) -> dict[str, object]:
        errors: list[str] = []
        previous_hash = GENESIS_HASH
        expected_seq = 1
        for event in self.events():
            if event.seq != expected_seq:
                errors.append(f"seq {event.seq}: expected {expected_seq}")
            if event.previous_hash != previous_hash:
                errors.append(f"seq {event.seq}: previous hash mismatch")
            expected_hash = EventStore._digest(
                seq=event.seq,
                event_id=event.event_id,
                occurred_at=event.occurred_at,
                kind=event.kind,
                payload=event.payload,
                previous_hash=event.previous_hash,
            )
            if event.event_hash != expected_hash:
                errors.append(f"seq {event.seq}: event hash mismatch")
            previous_hash = event.event_hash
            expected_seq = event.seq + 1
        return {
            "valid": not errors,
            "event_count": expected_seq - 1,
            "head_hash": previous_hash,
            "errors": errors,
        }


def _identifier(value: object, *, fallback: str) -> str:
    candidate = str(value or "").strip()
    if candidate and _SAFE_ID.fullmatch(candidate) and ".." not in candidate:
        return candidate
    digest = sha256(candidate.encode("utf-8")).hexdigest()[:16]
    return f"{fallback}-{digest}"


def _goal_rows(events: Iterable[Event]) -> list[dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    for event in events:
        if event.kind == "goal.formed":
            goal = event.payload.get("goal")
            if not isinstance(goal, dict) or not goal.get("id"):
                continue
            identifier = _identifier(goal.get("id"), fallback="goal")
            rows[identifier] = {
                "goal_id": identifier,
                "source": str(goal.get("source", "unknown"))
                if goal.get("source") in {"self", "external", "joint"}
                else "unknown",
                "status": str(goal.get("status", "active"))
                if goal.get("status") in {"active", "paused", "completed", "abandoned"}
                else "unknown",
                "horizon": str(goal.get("horizon", "unspecified"))[:120],
                "formed_at": event.occurred_at,
                "last_event_id": event.event_id,
            }
        elif event.kind == "goal.status_changed":
            identifier = _identifier(event.payload.get("goal_id"), fallback="goal")
            if identifier in rows:
                state = str(event.payload.get("to", "unknown"))
                rows[identifier]["status"] = (
                    state
                    if state in {"active", "paused", "completed", "abandoned"}
                    else "unknown"
                )
                rows[identifier]["last_event_id"] = event.event_id
    return sorted(rows.values(), key=lambda row: (row["status"] != "active", row["goal_id"]))


def _permission_rows(
    capability_status: dict[str, Any], *, chain_valid: bool, kill_active: bool
) -> list[dict[str, object]]:
    specs = capability_status.get("specifications", {})
    leases = capability_status.get("leases", {})
    rows: list[dict[str, object]] = []
    for name, spec in sorted(specs.items()):
        active = [
            lease
            for lease in leases.values()
            if lease.get("capability") == name
            and lease.get("revoked") is not True
            and lease.get("expired") is not True
        ]
        if not chain_valid:
            effective = "BLOCKED_CHAIN_INVALID"
        elif kill_active:
            effective = "BLOCKED_KILL_SWITCH"
        elif spec.get("active") is not True:
            effective = "DISABLED"
        elif spec.get("administrative_active", True) is not True:
            effective = "PAUSED"
        elif active:
            effective = "LEASED_TICKET_REQUIRED"
        else:
            effective = "DENY"
        expiries = sorted(
            str(lease.get("expires_at")) for lease in active if lease.get("expires_at")
        )
        rows.append(
            {
                "name": _identifier(name, fallback="capability"),
                "effect_kind": _identifier(spec.get("effect_kind"), fallback="effect"),
                "risk_class": _identifier(spec.get("risk_class"), fallback="risk"),
                "reversible": spec.get("reversible") is True,
                "default_mode": str(spec.get("default_mode", "deny")),
                "active": spec.get("active") is True,
                "administrative_active": spec.get("administrative_active", True) is True,
                "administrative_revision": int(spec.get("administrative_revision", 0)),
                "effective_state": effective,
                "scopes": [
                    _identifier(scope, fallback="scope")
                    for scope in list(spec.get("scopes", []))[:8]
                ],
                "verifier_id": _identifier(
                    spec.get("verifier_id"), fallback="verifier"
                ),
                "active_lease_count": len(active),
                "remaining_actions": sum(
                    max(0, int(lease.get("remaining", {}).get("actions", 0)))
                    for lease in active
                ),
                "remaining_bytes": sum(
                    max(0, int(lease.get("remaining", {}).get("bytes", 0)))
                    for lease in active
                ),
                "remaining_value_microunits": sum(
                    max(
                        0,
                        int(
                            lease.get("remaining", {}).get("value_microunits", 0)
                        ),
                    )
                    for lease in active
                ),
                "next_expiry": expiries[0] if expiries else None,
                "control_state": "PREVIEW_ONLY",
            }
        )
    return rows


def _access_rows(events: Iterable[Event]) -> list[dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    for event in events:
        if not (
            event.kind.startswith("operator.authenticated_access.")
            or event.kind.startswith("operator.authenticated_session.")
        ):
            continue
        target = _identifier(
            event.payload.get("target_id", event.payload.get("target")),
            fallback="access-target",
        )
        state = str(event.payload.get("status", "")).upper()
        if state not in _ACCESS_STATES:
            if event.kind.endswith(".prepared"):
                state = "AUTH_HANDOFF_REQUIRED"
            elif event.kind.endswith((".completed", ".readback")):
                state = "VERIFIED"
            else:
                state = "READY"
        rows[target] = {
            "target_id": target,
            "route": _identifier(event.payload.get("route"), fallback="route"),
            "state": state,
            "execution_authority_granted": event.payload.get(
                "execution_authority_granted"
            )
            is True,
            "last_event_id": event.event_id,
            "last_changed_at": event.occurred_at,
        }
    return sorted(rows.values(), key=lambda row: row["target_id"])


def _automation_rows(events: list[Event], *, kill_active: bool) -> list[dict[str, object]]:
    definitions = (
        (
            "proactive-updates",
            "Proactive updates",
            ("proactive.initiation.decided",),
            ("proactive.message.emitted",),
        ),
        (
            "standing-autonomy",
            "Standing autonomy",
            ("standing.autonomy.policy.installed", "standing.autonomy.run.selected"),
            ("standing.autonomy.run.completed",),
        ),
        (
            "continuity-sensor",
            "Continuity sensor",
            ("sensor.team_sync.",),
            ("sensor.team_sync.continuity",),
        ),
        (
            "work-autonomy",
            "Local work autonomy",
            ("autonomy.work.suggested",),
            ("autonomy.work.attempted",),
        ),
    )
    rows: list[dict[str, object]] = []
    for identifier, label, observed_kinds, run_kinds in definitions:
        observed = [
            event
            for event in events
            if any(
                event.kind == kind or (kind.endswith(".") and event.kind.startswith(kind))
                for kind in observed_kinds
            )
        ]
        runs = [
            event
            for event in events
            if any(
                event.kind == kind or (kind.endswith(".") and event.kind.startswith(kind))
                for kind in run_kinds
            )
        ]
        latest = (runs or observed)[-1] if runs or observed else None
        rows.append(
            {
                "id": identifier,
                "label": label,
                "state": "BLOCKED" if kill_active and identifier == "standing-autonomy" else (
                    "OBSERVED" if observed or runs else "NOT_CONFIGURED"
                ),
                "observed_events": len(observed),
                "runs": len(runs),
                "verified_runs": sum(
                    event.payload.get("verified") is True for event in runs
                ),
                "failed_runs": sum(
                    event.payload.get("verified") is False for event in runs
                ),
                "last_event_id": latest.event_id if latest else None,
                "last_changed_at": latest.occurred_at if latest else None,
                "control_state": "PREVIEW_ONLY",
            }
        )
    return rows


def _approval_rows(events: list[Event]) -> list[dict[str, object]]:
    latest: dict[str, Event] = {}
    for event in events:
        if event.kind == "clarification.requested":
            request_id = _identifier(
                event.payload.get("request_id", event.event_id), fallback="clarification"
            )
            current = latest.get(request_id)
            revision = int(event.payload.get("revision", 1))
            if current is None or revision >= int(current.payload.get("revision", 1)):
                latest[request_id] = event
    understood = {
        str(event.payload.get("request_event_id")): event
        for event in events
        if event.kind == "clarification.answer.understood"
    }
    confirmed = {
        str(event.payload.get("request_event_id"))
        for event in events
        if event.kind == "clarification.answer.confirmed"
    }
    rows: list[dict[str, object]] = []
    for request_id, request in sorted(latest.items()):
        answer = understood.get(request.event_id)
        if answer is not None and (
            answer.payload.get("confirmation_required") is not True
            or request.event_id in confirmed
        ):
            continue
        questions = request.payload.get("questions", [])
        rows.append(
            {
                "request_id": request_id,
                "request_event_id": request.event_id,
                "revision": int(request.payload.get("revision", 1)),
                "question_count": len(questions) if isinstance(questions, list) else 0,
                "state": "CONFIRMATION_REQUIRED" if answer is not None else "ACTION_REQUIRED",
                "presented_at": request.occurred_at,
                "control_state": "PREVIEW_ONLY",
            }
        )
    return rows


def _external_effects(events: Iterable[Event]) -> int:
    total = 0
    for event in events:
        value = event.payload.get("external_effects", 0)
        if isinstance(value, bool):
            total += int(value)
        elif isinstance(value, int) and value > 0:
            total += min(value, 1_000_000)
    return total


def build_dashboard_snapshot(
    database: str | Path, *, now: str | None = None
) -> dict[str, object]:
    """Build one bounded dashboard snapshot without mutating the event ledger."""

    try:
        store = ReadOnlyEventStore(database, now=now)
        events = store.events()
        chain = store.verify_chain()
        kill_switch = GlobalKillSwitch(store).status()
        capabilities = CapabilityRegistry(store).status() if chain["valid"] else {
            "specifications": {},
            "leases": {},
            "self_grant_enabled": False,
        }
        goals = _goal_rows(events)
        access = _access_rows(events)
        approvals = _approval_rows(events)
        permissions = _permission_rows(
            capabilities,
            chain_valid=chain["valid"] is True,
            kill_active=kill_switch["active"] is True,
        )
        automations = _automation_rows(
            events, kill_active=kill_switch["active"] is True
        )
        audit = HumanNarrative(store).digest(limit=12)
    except DashboardUnavailable:
        raise
    except (KeyError, TypeError, ValueError, sqlite3.Error):
        raise DashboardUnavailable("DASHBOARD_PROJECTION_INVALID") from None

    external_effects = _external_effects(events)
    active_goals = sum(row["status"] == "active" for row in goals)
    active_leases = sum(row["active_lease_count"] for row in permissions)
    connected = sum(row["state"] in _CONNECTED_STATES for row in access)
    if chain["valid"] is not True:
        outcome = {
            "state": "BLOCKED",
            "headline": "Event-chain verification failed",
            "detail": "Authority and success claims are suppressed until the ledger is repaired.",
            "next_action": "Inspect chain errors before using any control.",
        }
    elif kill_switch["active"] is True:
        outcome = {
            "state": "BLOCKED",
            "headline": "Emergency stop active",
            "detail": "All effect permissions are blocked until the operator clears the current kill switch.",
            "next_action": "Inspect the recorded failure before clearing the stop.",
        }
    elif approvals:
        outcome = {
            "state": "ACTION_REQUIRED",
            "headline": f"{len(approvals)} operator decision pending",
            "detail": "No pending item grants effect authority by itself.",
            "next_action": "Review the exact request and scope before approving.",
        }
    else:
        outcome = {
            "state": "VERIFIED",
            "headline": "Control-plane state verified",
            "detail": "Current permissions, access routes, and automation receipts are readable.",
            "next_action": "No operator action is currently required.",
        }

    generated_at = now or datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": DASHBOARD_SCHEMA_VERSION,
        "generated_at": generated_at,
        "mode": "READ_ONLY",
        "outcome": outcome,
        "summary": {
            "chain_valid": chain["valid"] is True,
            "event_count": int(chain["event_count"]),
            "active_goals": active_goals,
            "capability_count": len(permissions),
            "active_leases": active_leases,
            "pending_approvals": len(approvals),
            "connected_access_routes": connected,
            "external_effects": external_effects,
        },
        "permissions": permissions,
        "access": access,
        "automations": automations,
        "approvals": approvals,
        "goals": goals,
        "audit": {
            "text": audit["text"],
            "rows": audit["rows"],
            "chain": chain,
        },
        "emergency": {
            "kill_switch_active": kill_switch["active"] is True,
            "active_trip_id": (
                _identifier(kill_switch.get("active_trip_id"), fallback="trip")
                if kill_switch.get("active_trip_id")
                else None
            ),
            "active_trip_event_id": kill_switch.get("active_trip_event_id"),
            "latest_transition_event_id": kill_switch.get(
                "latest_transition_event_id"
            ),
            "model_clear_enabled": False,
            "control_state": "PREVIEW_ONLY",
        },
        "privacy": {
            "raw_event_payloads_exposed": False,
            "raw_conversation_content_exposed": False,
            "credential_bytes_exposed": False,
            "database_path_exposed": False,
        },
    }
