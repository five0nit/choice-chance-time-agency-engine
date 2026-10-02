"""Owner-only outbox. Answer text is data, never an execution grant.

Authority is the intersection of host arming, the fresh workspace permission and
an exact queued revision/digest. No CCT execution database or lease is touched.
A network ambiguity is terminal UNKNOWN, not an excuse to send twice.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from .owner_workspace import project_owner_workspace

MESSAGE_SCHEMA = "cct.owner_message.v1"
RUNTIME_SCHEMA = "cct.owner_runtime.v1"
MAX_DAILY_MESSAGES = 10
MAX_OPEN_QUESTIONS = 5
_SECRET = re.compile(r"-----BEGIN .*PRIVATE KEY-----|\b\d{6,}:[A-Za-z0-9_-]{30,}|\b(?:sk-|ghp_)[A-Za-z0-9_-]{20,}")


def stamp(now: datetime) -> str:
    return now.astimezone(timezone.utc).isoformat(timespec="microseconds")


def valid_text(text: Any) -> str:
    if not isinstance(text, str) or not 1 <= len(text.strip()) <= 2000:
        raise ValueError("OWNER_MESSAGE_TEXT_INVALID")
    if _SECRET.search(text):
        raise ValueError("OWNER_MESSAGE_SECRET_REJECTED")
    return text.strip()


def runtime_status(workspace: Any, *, owner_uid: str, project_id: str,
                   armed: bool, now: datetime) -> dict:
    view = project_owner_workspace(workspace, owner_uid=owner_uid, observed_at=now)
    valid = view["observationState"] == "OBSERVED"
    enabled = valid and armed is True and view["requestedPolicy"]["permissions"]["externalMessages"] is True
    return {
        "schemaVersion": RUNTIME_SCHEMA, "ownerUid": owner_uid, "projectId": project_id,
        "scope": "OWNER_MESSAGES_ONLY", "state": "CONNECTED" if valid else "INVALID",
        "updatedAt": stamp(now), "revision": view["revision"],
        "workspaceSha256": view["workspaceSha256"], "policySha256": view["policySha256"],
        "effectivePolicy": {"ownerMessages": enabled, "autonomyMode": "supervised"},
        "unsupportedPermissions": ["credentialAccess", "webResearch", "workspaceRead",
                                   "workspaceWrite", "thirdPartyMessages", "payments", "fullAutonomy"],
        "reasonCode": "OWNER_MESSAGES_ENABLED" if enabled else "OWNER_MESSAGES_DISABLED" if valid else view["reasonCode"],
    }


class OwnerOutbox:
    def __init__(self, path: Path):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink():
            raise ValueError("OWNER_OUTBOX_SYMLINK")
        self.db = sqlite3.connect(path, timeout=20, isolation_level=None)
        path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("""CREATE TABLE IF NOT EXISTS owner_messages (
            id TEXT PRIMARY KEY, payload TEXT NOT NULL, dirty INTEGER NOT NULL DEFAULT 1
        )""")

    def close(self):
        self.db.close()

    def rows(self) -> list[dict]:
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT payload FROM owner_messages ORDER BY rowid DESC")]

    def get(self, message_id: str) -> dict | None:
        row = self.db.execute("SELECT payload FROM owner_messages WHERE id=?", (message_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def save(self, value: dict):
        self.db.execute("UPDATE owner_messages SET payload=?,dirty=1 WHERE id=?",
                        (json.dumps(value, sort_keys=True), value["messageId"]))

    def enqueue(self, *, key: str, kind: str, text: str, status: dict, now: datetime) -> dict:
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{8,120}", key) or kind not in ("ask", "send"):
            raise ValueError("OWNER_MESSAGE_REQUEST_INVALID")
        text = valid_text(text)
        if not status["effectivePolicy"]["ownerMessages"]:
            raise ValueError("OWNER_MESSAGES_DISABLED")
        message_id = "msg-" + sha256(key.encode()).hexdigest()[:32]
        value = {
            "schemaVersion": MESSAGE_SCHEMA, "ownerUid": status["ownerUid"], "messageId": message_id,
            "kind": kind, "text": text, "state": "QUEUED", "createdAt": stamp(now),
            "expiresAt": stamp(now + timedelta(hours=24)), "revision": status["revision"],
            "policySha256": status["policySha256"], "telegramMessageId": None, "answer": None,
            "attemptedAt": None, "reasonCode": "QUEUED", "nextAttemptAt": None,
        }
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self.get(message_id)
            if existing:
                if any(existing[k] != value[k] for k in ("text", "kind", "ownerUid", "revision", "policySha256")):
                    raise ValueError("OWNER_MESSAGE_IDEMPOTENCY_CONFLICT")
                self.db.execute("COMMIT")
                return existing
            rows = self.rows()
            if sum(row["state"] == "QUEUED" for row in rows) >= 20:
                raise ValueError("OWNER_MESSAGE_QUEUE_FULL")
            if kind == "ask" and sum(row["kind"] == "ask" and row["state"] in ("QUEUED", "SENT", "SENDING")
                                     and row["expiresAt"] > stamp(now) for row in rows) >= MAX_OPEN_QUESTIONS:
                raise ValueError("OWNER_QUESTION_LIMIT")
            self.db.execute("INSERT INTO owner_messages(id,payload) VALUES(?,?)", (message_id, json.dumps(value, sort_keys=True)))
            self.db.execute("COMMIT")
            return value
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def recover(self):
        # A prior process might have sent before its durable acknowledgement.
        for row in self.rows():
            if row["state"] == "SENDING":
                row.update(state="UNKNOWN", reasonCode="OWNER_MESSAGE_CRASH_AMBIGUOUS")
                self.save(row)

    def claim(self, message_id: str, status: dict, now: datetime) -> dict | None:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.get(message_id)
            if not row or row["state"] != "QUEUED" or (row["nextAttemptAt"] and row["nextAttemptAt"] > stamp(now)):
                self.db.execute("COMMIT")
                return None
            allowed = (status["effectivePolicy"]["ownerMessages"] and row["ownerUid"] == status["ownerUid"]
                       and row["revision"] == status["revision"] and row["policySha256"] == status["policySha256"]
                       and row["expiresAt"] > stamp(now))
            used = sum(bool(item["attemptedAt"] and item["attemptedAt"] >= stamp(now - timedelta(days=1))) for item in self.rows())
            if not allowed:
                row.update(state="DENIED", reasonCode="OWNER_MESSAGE_REVOKED_STALE_OR_EXPIRED")
            elif used >= MAX_DAILY_MESSAGES:
                row.update(state="DENIED", reasonCode="OWNER_MESSAGE_DAILY_LIMIT")
            else:
                row.update(state="SENDING", attemptedAt=stamp(now), reasonCode="OWNER_MESSAGE_ATTEMPTED")
            self.save(row)
            self.db.execute("COMMIT")
            return row if row["state"] == "SENDING" else None
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def accept_reply(self, message_id: str, reply: dict, *, owner_uid: str, now: datetime) -> bool:
        row = self.get(message_id)
        if not row or row["ownerUid"] != owner_uid or row["kind"] != "ask" or row["state"] != "SENT" or row["expiresAt"] <= stamp(now):
            return False
        if set(reply) != {"schemaVersion", "ownerUid", "messageId", "text", "createdAt"}:
            return False
        if reply["schemaVersion"] != "cct.owner_reply.v1" or reply["ownerUid"] != owner_uid or reply["messageId"] != message_id:
            return False
        created = reply["createdAt"]
        if not isinstance(created, datetime) or created.tzinfo is None:
            return False
        if not row["createdAt"] <= stamp(created) < row["expiresAt"] or created > now + timedelta(seconds=60):
            return False
        try:
            text = valid_text(reply["text"])
        except ValueError:
            return False
        row.update(state="ANSWERED", answer=text, reasonCode="OWNER_ANSWER_RECORDED_NOT_AUTHORITY")
        self.save(row)
        return True
