"""Append-only, hash-chained SQLite event store."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterable, Mapping
from uuid import uuid4


GENESIS_HASH = "0" * 64


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class Event:
    seq: int
    event_id: str
    occurred_at: str
    kind: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str


class EventStore:
    """Canonical temporal memory with deterministic tamper detection."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], str] = utc_now,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.id_factory = id_factory or (lambda: f"evt_{uuid4().hex}")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    occurred_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_kind_seq ON events(kind, seq)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS logical_keys (
                    namespace TEXT NOT NULL,
                    logical_key TEXT NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    PRIMARY KEY(namespace, logical_key),
                    FOREIGN KEY(event_id) REFERENCES events(event_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS counters (
                    name TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                )
                """
            )

    @staticmethod
    def _digest(
        *,
        seq: int,
        event_id: str,
        occurred_at: str,
        kind: str,
        payload: Mapping[str, Any],
        previous_hash: str,
    ) -> str:
        material = {
            "seq": seq,
            "event_id": event_id,
            "occurred_at": occurred_at,
            "kind": kind,
            "payload": dict(payload),
            "previous_hash": previous_hash,
        }
        return sha256(canonical_json(material).encode("utf-8")).hexdigest()

    def _append_locked(
        self,
        connection: sqlite3.Connection,
        kind: str,
        payload_dict: dict[str, Any],
        *,
        occurred: str,
        identifier: str,
    ) -> Event:
        previous = connection.execute(
            "SELECT seq, event_hash FROM events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seq = int(previous["seq"]) + 1 if previous else 1
        previous_hash = str(previous["event_hash"]) if previous else GENESIS_HASH
        event_hash = self._digest(
            seq=seq,
            event_id=identifier,
            occurred_at=occurred,
            kind=kind,
            payload=payload_dict,
            previous_hash=previous_hash,
        )
        connection.execute(
            """
            INSERT INTO events(
                seq, event_id, occurred_at, kind, payload_json,
                previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                seq,
                identifier,
                occurred,
                kind,
                canonical_json(payload_dict),
                previous_hash,
                event_hash,
            ),
        )
        return Event(
            seq=seq,
            event_id=identifier,
            occurred_at=occurred,
            kind=kind,
            payload=payload_dict,
            previous_hash=previous_hash,
            event_hash=event_hash,
        )

    def append(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        occurred_at: str | None = None,
        event_id: str | None = None,
    ) -> Event:
        if not kind.strip():
            raise ValueError("event kind must not be empty")
        payload_dict = dict(payload)
        canonical_json(payload_dict)
        occurred = occurred_at or self.clock()
        identifier = event_id or self.id_factory()

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            event = self._append_locked(
                connection,
                kind,
                payload_dict,
                occurred=occurred,
                identifier=identifier,
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return event

    def append_once_result(
        self,
        kind: str,
        logical_key: str,
        payload: Mapping[str, Any],
    ) -> tuple[Event, bool]:
        """Append exactly once and report whether this call created the event."""

        event, created, rejection = self.append_once_result_guarded(
            kind, logical_key, payload
        )
        if rejection is not None or event is None:
            raise RuntimeError("unguarded append was unexpectedly rejected")
        return event, created

    def append_once_result_guarded(
        self,
        kind: str,
        logical_key: str,
        payload: Mapping[str, Any],
        *,
        guard: Callable[[list[Event]], str | None] | None = None,
        strict_existing_payload: bool = True,
    ) -> tuple[Event | None, bool, str | None]:
        """Atomically check current events, then append once or return a reason."""

        if not kind.strip() or not logical_key.strip():
            raise ValueError("event kind and logical key must not be empty")
        payload_dict = dict(payload)
        payload_json = canonical_json(payload_dict)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT e.* FROM logical_keys k
                JOIN events e ON e.event_id = k.event_id
                WHERE k.namespace = ? AND k.logical_key = ?
                """,
                (kind, logical_key),
            ).fetchone()
            if existing is not None:
                event = self._row_to_event(existing)
                if strict_existing_payload and canonical_json(event.payload) != payload_json:
                    raise ValueError(
                        f"logical key collision for {kind}:{logical_key}"
                    )
                connection.commit()
                return event, False, None
            if guard is not None:
                rows = connection.execute("SELECT * FROM events ORDER BY seq").fetchall()
                rejection = guard([self._row_to_event(row) for row in rows])
                if rejection is not None:
                    connection.commit()
                    return None, False, str(rejection)
            event = self._append_locked(
                connection,
                kind,
                payload_dict,
                occurred=self.clock(),
                identifier=self.id_factory(),
            )
            connection.execute(
                "INSERT INTO logical_keys(namespace, logical_key, event_id) VALUES (?, ?, ?)",
                (kind, logical_key, event.event_id),
            )
            connection.commit()
            return event, True, None
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def append_once(
        self,
        kind: str,
        logical_key: str,
        payload: Mapping[str, Any],
    ) -> Event:
        """Append one event per namespace/key; exact retries return the first event."""

        return self.append_once_result(kind, logical_key, payload)[0]

    def append_once_computed(
        self,
        kind: str,
        logical_key: str,
        factory: Callable[[list[Event]], Mapping[str, Any]],
    ) -> tuple[Event, bool]:
        """Atomically derive and append one event from the current event sequence.

        The factory runs while an IMMEDIATE SQLite transaction holds the writer
        lock. This supports cumulative budgets and other admission decisions
        that must not race with concurrent requests.
        """

        if not kind.strip() or not logical_key.strip():
            raise ValueError("event kind and logical key must not be empty")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT e.* FROM logical_keys k
                JOIN events e ON e.event_id = k.event_id
                WHERE k.namespace = ? AND k.logical_key = ?
                """,
                (kind, logical_key),
            ).fetchone()
            if existing is not None:
                connection.commit()
                return self._row_to_event(existing), False
            rows = connection.execute("SELECT * FROM events ORDER BY seq").fetchall()
            payload = dict(factory([self._row_to_event(row) for row in rows]))
            canonical_json(payload)
            event = self._append_locked(
                connection,
                kind,
                payload,
                occurred=self.clock(),
                identifier=self.id_factory(),
            )
            connection.execute(
                "INSERT INTO logical_keys(namespace, logical_key, event_id) VALUES (?, ?, ?)",
                (kind, logical_key, event.event_id),
            )
            connection.commit()
            return event, True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def append_computed_once(
        self,
        kind: str,
        factory: Callable[[list[Event]], tuple[str, Mapping[str, Any]]],
    ) -> tuple[Event, bool]:
        """Atomically derive both logical key and payload from current events."""

        if not kind.strip():
            raise ValueError("event kind must not be empty")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute("SELECT * FROM events ORDER BY seq").fetchall()
            logical_key, raw_payload = factory(
                [self._row_to_event(row) for row in rows]
            )
            if not logical_key.strip():
                raise ValueError("computed logical key must not be empty")
            payload = dict(raw_payload)
            payload_text = canonical_json(payload)
            existing = connection.execute(
                """
                SELECT e.* FROM logical_keys k
                JOIN events e ON e.event_id = k.event_id
                WHERE k.namespace = ? AND k.logical_key = ?
                """,
                (kind, logical_key),
            ).fetchone()
            if existing is not None:
                event = self._row_to_event(existing)
                if canonical_json(event.payload) != payload_text:
                    raise ValueError(
                        f"logical key collision for {kind}:{logical_key}"
                    )
                connection.commit()
                return event, False
            event = self._append_locked(
                connection,
                kind,
                payload,
                occurred=self.clock(),
                identifier=self.id_factory(),
            )
            connection.execute(
                "INSERT INTO logical_keys(namespace, logical_key, event_id) VALUES (?, ?, ?)",
                (kind, logical_key, event.event_id),
            )
            connection.commit()
            return event, True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def allocate_counter(self, name: str, *, floor: int = 0) -> int:
        """Atomically reserve the next integer in a named monotonic sequence."""

        if not name.strip() or floor < 0:
            raise ValueError("counter name must be non-empty and floor non-negative")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT value FROM counters WHERE name = ?", (name,)
            ).fetchone()
            current = max(int(row["value"]) if row else 0, floor)
            value = current + 1
            connection.execute(
                """
                INSERT INTO counters(name, value) VALUES (?, ?)
                ON CONFLICT(name) DO UPDATE SET value = excluded.value
                """,
                (name, value),
            )
            connection.commit()
            return value
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def events(self, kind: str | None = None) -> list[Event]:
        sql = "SELECT * FROM events"
        parameters: tuple[object, ...] = ()
        if kind is not None:
            sql += " WHERE kind = ?"
            parameters = (kind,)
        sql += " ORDER BY seq"
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [self._row_to_event(row) for row in rows]

    def event(self, event_id: str) -> Event | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return self._row_to_event(row) if row else None

    def latest(self, kind: str) -> Event | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE kind = ? ORDER BY seq DESC LIMIT 1",
                (kind,),
            ).fetchone()
        return self._row_to_event(row) if row else None

    def count(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def verify_chain(self) -> dict[str, object]:
        errors: list[str] = []
        previous_hash = GENESIS_HASH
        expected_seq = 1
        for event in self.events():
            if event.seq != expected_seq:
                errors.append(f"seq {event.seq}: expected {expected_seq}")
            if event.previous_hash != previous_hash:
                errors.append(f"seq {event.seq}: previous hash mismatch")
            expected_hash = self._digest(
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

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        return Event(
            seq=int(row["seq"]),
            event_id=str(row["event_id"]),
            occurred_at=str(row["occurred_at"]),
            kind=str(row["kind"]),
            payload=json.loads(str(row["payload_json"])),
            previous_hash=str(row["previous_hash"]),
            event_hash=str(row["event_hash"]),
        )

    def export(self) -> Iterable[dict[str, Any]]:
        for event in self.events():
            yield {
                "seq": event.seq,
                "event_id": event.event_id,
                "occurred_at": event.occurred_at,
                "kind": event.kind,
                "payload": event.payload,
                "previous_hash": event.previous_hash,
                "event_hash": event.event_hash,
            }
