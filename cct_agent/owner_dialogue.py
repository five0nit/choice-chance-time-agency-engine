"""Adaptive owner interview producer; the existing connection alone delivers.

Saved free-text answers inform drafts only. No executor, leases, task runner,
Telegram polling, model tools or other profile state is accessed here.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time

from .owner_connection import FirebaseOwnerGateway, load_config
from .owner_messaging import OwnerOutbox, runtime_status, stamp, valid_text
from .owner_workspace import normalize_owner_workspace


def now():
    return datetime.now(timezone.utc)


def dialogue_config(home: Path) -> dict:
    path = home / "config" / "cct-owner-dialogue.json"
    if path.is_symlink():
        raise ValueError("OWNER_DIALOGUE_CONFIG_SYMLINK")
    value = json.loads(path.read_text())
    if (set(value) != {"enabled", "conversationId", "modelPython"}
            or type(value["enabled"]) is not bool
            or not isinstance(value["conversationId"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{8,60}", value["conversationId"])
            or not isinstance(value["modelPython"], str)
            or not Path(value["modelPython"]).is_absolute()):
        raise ValueError("OWNER_DIALOGUE_CONFIG_INVALID")
    return value


class OwnerDialogue:
    def __init__(self, home: Path):
        self.home = home
        self.config_path = home / "config" / "cct-owner-connection.json"
        self.identity = load_config(self.config_path)
        self.config = dialogue_config(home)
        self.gateway = FirebaseOwnerGateway(self.identity["projectId"])
        self.outbox = OwnerOutbox(home / "owner-connection" / "messages.sqlite")
        path = home / "owner-connection" / "dialogue.sqlite"
        if path.is_symlink():
            raise ValueError("OWNER_DIALOGUE_DATABASE_SYMLINK")
        self.db = sqlite3.connect(path, timeout=20, isolation_level=None)
        path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS turns (
                key TEXT PRIMARY KEY, conversation TEXT NOT NULL, source TEXT NOT NULL,
                revision INTEGER NOT NULL, decision TEXT NOT NULL,
                message_id TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attempts (key TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS status (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
        """)

    def close(self):
        self.outbox.close()
        self.db.close()

    def record(self, state: str, **details):
        value = {"state": state, "updatedAt": stamp(now()),
                 "conversationId": self.config["conversationId"], **details}
        self.db.execute("INSERT OR REPLACE INTO status(id,payload) VALUES(1,?)", (json.dumps(value),))
        return value

    def gate(self):
        config = dialogue_config(self.home)
        connection = load_config(self.config_path)
        if any(config[k] != self.config[k] for k in ("conversationId", "modelPython")) or any(
                connection[k] != self.identity[k] for k in self.identity if k != "ownerMessagesEnabled"):
            raise ValueError("OWNER_DIALOGUE_IDENTITY_CHANGED_RESTART_REQUIRED")
        raw = self.gateway.read("cct_workspace")
        workspace = normalize_owner_workspace(raw, owner_uid=connection["ownerUid"])
        status = runtime_status(raw, owner_uid=connection["ownerUid"], project_id=connection["projectId"],
                                armed=connection["ownerMessagesEnabled"], now=now())
        enabled = config["enabled"] and workspace["learningEnabled"] and status["effectivePolicy"]["ownerMessages"]
        return enabled, workspace, status

    def tick(self):
        enabled, workspace, status = self.gate()
        if not enabled:
            return self.record("PAUSED")
        turns = list(self.db.execute("SELECT * FROM turns WHERE conversation=? ORDER BY rowid",
                                    (self.config["conversationId"],)))
        history = []
        for turn in turns:
            decision = json.loads(turn["decision"])
            message = self.outbox.get(turn["message_id"])
            # A changed owner workspace supersedes an unanswered old draft.
            # Preserve its receipt; never retry an ambiguous delivery or invent an answer.
            if status["revision"] != turn["revision"] and (message is None or message["state"] != "ANSWERED"):
                continue
            if message is None:
                message = self.outbox.enqueue(key=turn["key"], kind="ask" if decision["kind"] == "ask" else "send",
                                              text=decision["text"], status=status, now=now())
            if message["state"] in ("DENIED", "UNKNOWN"):
                return self.record("BLOCKED", messageId=message["messageId"], reason=message["reasonCode"])
            if message["state"] in ("QUEUED", "SENDING"):
                return self.record("AWAITING_DELIVERY", messageId=message["messageId"])
            if decision["kind"] == "propose":
                return self.record("AWAITING_APPROVAL", messageId=message["messageId"], executionEnabled=False)
            if message["state"] == "SENT":
                if message["expiresAt"] <= stamp(now()):
                    return self.record("BLOCKED", messageId=message["messageId"], reason="OWNER_DIALOGUE_QUESTION_EXPIRED")
                return self.record("AWAITING_REPLY", messageId=message["messageId"])
            if message["state"] != "ANSWERED":
                raise ValueError("OWNER_DIALOGUE_MESSAGE_STATE_INVALID")
            history.append({"question": message["text"], "answer": message["answer"]})
        # A durable turn for each predecessor means the same answer cannot advance twice.
        source = turns[-1]["message_id"] if turns else "start"
        key = f"dialogue:{self.config['conversationId']}:{source}"
        recent = stamp(now() - timedelta(days=1))
        if (self.db.execute("SELECT count(*) FROM attempts WHERE key=?", (key,)).fetchone()[0] >= 3
                or self.db.execute("SELECT count(*) FROM attempts WHERE created_at>=?", (recent,)).fetchone()[0] >= 10):
            return self.record("BLOCKED", reason="OWNER_DIALOGUE_MODEL_ATTEMPT_LIMIT")
        self.db.execute("INSERT INTO attempts(key,created_at) VALUES(?,?)", (key, stamp(now())))
        self.record("THINKING", answersConsumed=len(history), workspaceRevision=workspace["revision"])
        payload = {"savedPreferences": workspace["answers"], "conversation": history,
                   "instruction": "Propose now with assumptions." if len(history) >= 6 else "Choose the useful next question or proposals."}
        result = subprocess.run(
            [self.config["modelPython"], str(Path(__file__).with_name("owner_dialogue_model.py"))],
            input=json.dumps(payload), text=True, capture_output=True, timeout=150,
            env={**os.environ, "HERMES_HOME": str(self.home), "PYTHONUNBUFFERED": "1"},
        )
        if result.returncode:
            raise RuntimeError("OWNER_DIALOGUE_MODEL_UNAVAILABLE")
        decision = json.loads(result.stdout)
        if not isinstance(decision, dict) or set(decision) != {"kind", "text"} or decision["kind"] not in ("ask", "propose"):
            raise ValueError("OWNER_DIALOGUE_OUTPUT_INVALID")
        decision["text"] = valid_text(decision["text"])
        if len(history) >= 6 and decision["kind"] != "propose":
            raise ValueError("OWNER_DIALOGUE_PROPOSAL_REQUIRED")
        if decision["kind"] == "propose":
            decision["text"] = valid_text("Proposed work — awaiting your decision\n\n" + decision["text"] + "\n\nDrafts only. Nothing has been started.")
        enabled, fresh_workspace, fresh_status = self.gate()
        if not enabled or fresh_workspace != workspace:
            return self.record("PAUSED", reason="OWNER_DIALOGUE_WORKSPACE_CHANGED_DURING_GENERATION")
        message_id = "msg-" + sha256(key.encode()).hexdigest()[:32]
        self.db.execute("INSERT INTO turns VALUES(?,?,?,?,?,?,?)",
                        (key, self.config["conversationId"], source, status["revision"],
                         json.dumps(decision), message_id, stamp(now())))
        # Persist model output before enqueue: a crash reuses exact text and key.
        self.outbox.enqueue(key=key, kind="ask" if decision["kind"] == "ask" else "send",
                            text=decision["text"], status=fresh_status, now=now())
        return self.record("AWAITING_DELIVERY", messageId=message_id, answersConsumed=len(history))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "once", "status"))
    args = parser.parse_args(argv)
    home = Path(os.environ["HERMES_HOME"]).resolve()
    directory = home / "owner-connection"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.command == "status":
        db = sqlite3.connect(f"file:{directory / 'dialogue.sqlite'}?mode=ro", uri=True)
        try:
            row = db.execute("SELECT payload FROM status WHERE id=1").fetchone()
            print(row[0] if row else '{"state":"NOT_STARTED"}')
        finally:
            db.close()
        return 0
    with (directory / "dialogue.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        worker = OwnerDialogue(home)
        try:
            while True:
                delay = 15
                try:
                    value = worker.tick()
                except Exception as error:
                    value = worker.record("UNAVAILABLE", errorType=type(error).__name__)
                    delay = 300
                print(json.dumps(value), flush=True)
                if args.command == "once":
                    return 1 if value["state"] == "UNAVAILABLE" else 0
                time.sleep(delay)
        finally:
            worker.close()


if __name__ == "__main__":
    raise SystemExit(main())
