"""Continuous, dashboard-native owner discovery. Draft producer, never executor.

Only discovery.sqlite/discovery.lock are writable local state. Legacy answered
receipts are imported read-only; Telegram and the old outbox are never operated.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timedelta, timezone
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time

from .cloud_projection import publish_projection
from .owner_connection import FirebaseOwnerGateway, load_config
from .cloud_backoff import CloudBackoff, cloud_delay, cloud_recovered, cloud_status
from .owner_dialogue import dialogue_config
from .owner_discovery_model import (
    CATEGORIES, MAX_HISTORY, MAX_INPUT_BYTES, MAX_RESPONSE_BYTES,
    json_object, text, validate_response,
)
from .owner_workspace import normalize_owner_workspace

MAX_ATTEMPTS = 3
MAX_DAILY_FAILURES = 10
RETRY_SECONDS = 300
HEARTBEAT_SECONDS = 15  # Keep in-flight authority/revocation checks responsive.
IDLE_POLL_SECONDS = 60
MODEL_TIMEOUT_SECONDS = 150


def now():
    return datetime.now(timezone.utc)


def stamp(value=None):
    return (value or now()).astimezone(timezone.utc).isoformat(timespec="microseconds")


def aware(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("DISCOVERY_TIMESTAMP_INVALID")
    return value.astimezone(timezone.utc)


def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def empty_learning():
    return {key: [] for key in CATEGORIES}


def prune(value, history):
    """Keep only fully supported prior items when the bounded window advances."""
    ids = {row["questionId"] for row in history}
    def supported(item):
        return set(item["sourceAnswerIds"]) <= ids
    return {
        "learning": {key: [item for item in value["learning"][key] if supported(item)]
                     for key in CATEGORIES},
        "unknowns": value["unknowns"],
        "workIdeas": [item for item in value["workIdeas"] if supported(item)],
    }


class OwnerDiscovery:
    def __init__(self, home: Path):
        self.home = home
        self.config_path = home / "config" / "cct-owner-connection.json"
        self.identity = load_config(self.config_path)
        self.config = dialogue_config(home)
        self.conversation = self.config["conversationId"]
        self.transport_failed = False
        path = home / "owner-connection" / "discovery.sqlite"
        if path.is_symlink():
            raise ValueError("DISCOVERY_DATABASE_SYMLINK")
        self.db = sqlite3.connect(path, timeout=20)
        path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS answers (
                conversation TEXT NOT NULL, id TEXT NOT NULL, question TEXT NOT NULL,
                answer TEXT NOT NULL, created_at TEXT NOT NULL, evidence TEXT NOT NULL,
                origin TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(conversation,id)
            );
            CREATE TABLE IF NOT EXISTS turns (
                key TEXT PRIMARY KEY, conversation TEXT NOT NULL, source TEXT NOT NULL,
                question_id TEXT NOT NULL UNIQUE, input_json TEXT NOT NULL,
                response_json TEXT, created_at TEXT NOT NULL, completed_at TEXT,
                answers_consumed INTEGER NOT NULL,
                UNIQUE(conversation,source)
            );
            CREATE TABLE IF NOT EXISTS attempts (
                id INTEGER PRIMARY KEY, turn_key TEXT NOT NULL,
                created_at TEXT NOT NULL, outcome TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS status (
                id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL
            );
        """)
        anchor = dumps({key: self.identity[key] for key in ("ownerUid", "projectId")})
        row = self.db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
        if row and row[0] != anchor:
            self.db.close()
            raise ValueError("DISCOVERY_DATABASE_IDENTITY_CHANGED")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO meta VALUES('identity',?)", (anchor,))
        try:
            self.gateway = FirebaseOwnerGateway(self.identity["projectId"])
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def gate(self):
        config = dialogue_config(self.home)
        identity = load_config(self.config_path)
        if (any(config[key] != self.config[key] for key in ("conversationId", "modelPython"))
                or any(identity[key] != self.identity[key] for key in ("ownerUid", "projectId"))):
            raise ValueError("DISCOVERY_IDENTITY_CHANGED_RESTART_REQUIRED")
        workspace = normalize_owner_workspace(
            self.gateway.read("cct_workspace"), owner_uid=self.identity["ownerUid"])
        # Dashboard discovery is NOT Telegram/external messaging. Neither its
        # delivery status nor executor permissions gate authenticated site answers.
        return config["enabled"] and workspace["learningEnabled"], workspace

    def latest(self):
        return self.db.execute(
            "SELECT * FROM turns WHERE conversation=? AND response_json IS NOT NULL ORDER BY rowid DESC LIMIT 1",
            (self.conversation,),
        ).fetchone()

    def pending(self):
        return self.db.execute(
            "SELECT * FROM turns WHERE conversation=? AND response_json IS NULL ORDER BY rowid LIMIT 1",
            (self.conversation,),
        ).fetchone()

    def view(self, phase, reason, retry_at=None):
        ready, pending = self.latest(), self.pending()
        history, learned, question, count = [], {
            "learning": empty_learning(), "unknowns": [], "workIdeas": []}, None, 0
        if ready:
            history = json_object(ready["input_json"])["history"]
            output = validate_response(json_object(ready["response_json"]), history)
            learned = {key: output[key] for key in learned}
            question = {"id": ready["question_id"], "text": output["question"]["text"]}
            count = ready["answers_consumed"]
        if pending:
            history = json_object(pending["input_json"])["history"]
            learned = prune(learned, history)
        value = {
            "schemaVersion": "cct.discovery.v1", "ownerUid": self.identity["ownerUid"],
            "conversationId": self.conversation, "phase": phase, "reason": reason,
            "executionEnabled": False, "question": question, "history": history,
            **learned, "answersConsumed": count,
        }
        if retry_at:
            value["retryAt"] = retry_at
        return value

    def record(self, value):
        # Revision is a profile-wide projection sequence, including heartbeats.
        with self.db:
            row = self.db.execute("SELECT payload FROM status WHERE id=1").fetchone()
            revision = json_object(row[0])["revision"] + 1 if row else 1
            value = {**value, "revision": revision, "updatedAt": stamp()}
            self.db.execute("INSERT OR REPLACE INTO status VALUES(1,?)", (dumps(value),))
        return value

    def publish(self, phase, reason, retry_at=None):
        value = self.record(self.view(phase, reason, retry_at))
        try:
            # Gateway sets explicit fields and reads back the exact document.
            value = publish_projection(self.gateway, "cct_discovery", "current", value)
        except Exception:
            self.transport_failed = True
            value = self.record({**self.view(
                "BLOCKED", "Dashboard connection unavailable; saved discovery is safe."),
                **cloud_status(self.gateway)})
        return value

    def import_legacy(self):
        marker = "legacy:" + self.conversation
        if self.db.execute("SELECT 1 FROM meta WHERE key=?", (marker,)).fetchone():
            return
        path = self.home / "owner-connection" / "messages.sqlite"
        if path.is_symlink():
            raise ValueError("DISCOVERY_LEGACY_DATABASE_SYMLINK")
        imported = []
        if path.exists():
            # Do not construct OwnerOutbox: even its constructor can create/mutate
            # the old journal. mode=ro plus query_only prevents updates/recovery.
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=20)) as legacy:
                legacy.execute("PRAGMA query_only=ON")
                for message_id, raw in legacy.execute("SELECT id,payload FROM owner_messages ORDER BY rowid"):
                    item = json_object(raw)
                    if not isinstance(item, dict):
                        raise ValueError("DISCOVERY_LEGACY_RECEIPT_INVALID")
                    if item.get("state") != "ANSWERED" or item.get("ownerUid") != self.identity["ownerUid"]:
                        continue  # UNKNOWN/SENDING/SENT are never answers or retries.
                    if (not isinstance(message_id, str) or not re.fullmatch(r"msg-[0-9a-f]{32}", message_id)
                            or item.get("messageId") != message_id or item.get("kind") != "ask"
                            or item.get("schemaVersion") != "cct.owner_message.v1"
                            or item.get("reasonCode") != "OWNER_ANSWER_RECORDED_NOT_AUTHORITY"):
                        raise ValueError("DISCOVERY_LEGACY_RECEIPT_INVALID")
                    question, answer = text(item.get("text"), 2000), text(item.get("answer"), 2000)
                    created = stamp(aware(datetime.fromisoformat(item["createdAt"])))
                    # Legacy accept_reply did not store answer time. Retain its
                    # real question-created time, not an invented answer timestamp.
                    imported.append((self.conversation, message_id, question, answer, created, raw, "legacy"))
        with self.db:
            self.db.executemany(
                "INSERT OR IGNORE INTO answers(conversation,id,question,answer,created_at,evidence,origin) VALUES(?,?,?,?,?,?,?)",
                imported,
            )
            self.db.execute("INSERT INTO meta VALUES(?,?)", (marker, stamp()))

    def accept_answer(self, turn, value):
        fields = {"schemaVersion", "ownerUid", "questionId", "text", "createdAt"}
        if (not isinstance(value, dict) or set(value) != fields
                or value["schemaVersion"] != "cct.discovery_answer.v1"
                or value["ownerUid"] != self.identity["ownerUid"]
                or value["questionId"] != turn["question_id"]):
            raise ValueError("DISCOVERY_ANSWER_INVALID")
        answer = text(value["text"], 4000)
        created = aware(value["createdAt"])
        if created < datetime.fromisoformat(turn["created_at"]) or created > now() + timedelta(seconds=60):
            raise ValueError("DISCOVERY_ANSWER_TIMESTAMP_INVALID")
        history = json_object(turn["input_json"])["history"]
        output = validate_response(json_object(turn["response_json"]), history)
        evidence = dumps({**value, "createdAt": stamp(created)})
        with self.db:
            existing = self.db.execute("SELECT evidence FROM answers WHERE conversation=? AND id=?",
                                       (self.conversation, turn["question_id"])).fetchone()
            if existing and existing[0] != evidence:
                raise ValueError("DISCOVERY_ANSWER_CHANGED")
            self.db.execute(
                "INSERT OR IGNORE INTO answers(conversation,id,question,answer,created_at,evidence,origin) VALUES(?,?,?,?,?,?,?)",
                (self.conversation, turn["question_id"], output["question"]["text"], answer,
                 stamp(created), evidence, "dashboard"),
            )

    def prepare(self, answer, workspace):
        source = answer["id"] if answer else "start"
        key = dumps([self.identity["ownerUid"], self.identity["projectId"], self.conversation, source])
        question_id = "q-" + sha256(key.encode()).hexdigest()[:32]
        rows = self.db.execute(
            "SELECT * FROM answers WHERE conversation=? AND (consumed=1 OR id=?) ORDER BY created_at DESC,id DESC LIMIT ?",
            (self.conversation, source, MAX_HISTORY),
        ).fetchall()
        history = [{"questionId": row["id"], "question": row["question"],
                    "answer": row["answer"], "createdAt": row["created_at"]} for row in reversed(rows)]
        previous = self.latest()
        learned = {"learning": empty_learning(), "unknowns": [], "workIdeas": []}
        if previous:
            learned = prune(json_object(previous["response_json"]), history)
        request = {"history": history, "previousUnderstanding": learned,
                   "savedPreferences": workspace["answers"], "newAnswerId": source if answer else None}
        encoded = dumps(request)
        if len(encoded.encode()) > MAX_INPUT_BYTES:
            raise ValueError("DISCOVERY_INPUT_TOO_LARGE")
        count = self.db.execute("SELECT count(*) FROM answers WHERE conversation=? AND consumed=1",
                                (self.conversation,)).fetchone()[0] + int(answer is not None)
        with self.db:
            self.db.execute(
                "INSERT INTO turns(key,conversation,source,question_id,input_json,created_at,answers_consumed) VALUES(?,?,?,?,?,?,?)",
                (key, self.conversation, source, question_id, encoded, stamp(), count),
            )
        return self.pending()

    def finish(self, turn, raw, attempt_id=None):
        history = json_object(turn["input_json"])["history"]
        validate_response(json_object(raw), history)
        # This commit is the durable effect boundary. Pause or projection failure
        # AFTER it must never discard the exact response or spend another call.
        with self.db:
            self.db.execute("UPDATE turns SET response_json=?,completed_at=? WHERE key=? AND response_json IS NULL",
                            (raw, stamp(), turn["key"]))
            if turn["source"] != "start":
                self.db.execute("UPDATE answers SET consumed=1 WHERE conversation=? AND id=?",
                                (self.conversation, turn["source"]))
            if attempt_id is not None:
                self.db.execute("UPDATE attempts SET outcome='SAVED' WHERE id=?", (attempt_id,))

    def budget(self, turn):
        attempts = self.db.execute("SELECT * FROM attempts WHERE turn_key=? ORDER BY id", (turn["key"],)).fetchall()
        if any(row["outcome"] in ("IN_FLIGHT", "UNKNOWN") for row in attempts):
            return "A model attempt was interrupted before a durable result. Operator recovery is required; it will not be repeated.", None
        if len(attempts) >= MAX_ATTEMPTS:
            return "This answer reached the three-attempt model limit. Operator recovery is required; your answer is saved.", None
        # Genuine successful answers are not a runaway loop. Limit unsuccessful
        # attempts instead; completed turns and idle heartbeats never regenerate.
        daily = self.db.execute(
            "SELECT created_at FROM attempts WHERE created_at>? AND outcome!='SAVED' ORDER BY created_at",
            (stamp(now() - timedelta(days=1)),),
        ).fetchall()
        if len(daily) >= MAX_DAILY_FAILURES:
            retry_at = stamp(datetime.fromisoformat(daily[-MAX_DAILY_FAILURES][0]) + timedelta(days=1))
            return "Discovery is paused after ten unsuccessful model attempts in 24 hours. Your answer is saved; successful answers do not count toward this limit.", retry_at
        if attempts:
            retry_at = datetime.fromisoformat(attempts[-1]["created_at"]) + timedelta(seconds=RETRY_SECONDS)
            if retry_at > now():
                return "The model did not return a valid discovery turn. Your answer is saved; a bounded retry is scheduled.", stamp(retry_at)
        return None

    def invoke(self, turn):
        # Anonymous private files bound stdout storage and avoid pipe deadlocks.
        # No SDK stderr is persisted or printed: it may contain credentials/data.
        with tempfile.TemporaryFile() as request, tempfile.TemporaryFile() as output:
            request.write(turn["input_json"].encode())
            request.seek(0)
            child = subprocess.Popen(
                [self.config["modelPython"], str(Path(__file__).with_name("owner_discovery_model.py"))],
                stdin=request, stdout=output, stderr=subprocess.DEVNULL,
                env={**os.environ, "HERMES_HOME": str(self.home), "PYTHONUNBUFFERED": "1"},
            )
            deadline = time.monotonic() + MODEL_TIMEOUT_SECONDS
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("DISCOVERY_MODEL_TIMEOUT")
                    try:
                        child.wait(timeout=min(HEARTBEAT_SECONDS, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        try:
                            enabled, _workspace = self.gate()
                        except Exception:
                            # A heartbeat/config outage must not kill and discard
                            # an in-flight response, then make it retryable.
                            self.publish("BLOCKED", "The owner connection needs attention. An already-started response will still be saved.")
                        else:
                            self.publish("THINKING" if enabled else "PAUSED",
                                         "Learning from your saved answer." if enabled else
                                         "Discovery is paused. An already-started response will be saved, not executed.")
                if child.returncode:
                    raise RuntimeError("DISCOVERY_MODEL_UNAVAILABLE")
                output.seek(0)
                raw = output.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("DISCOVERY_MODEL_OUTPUT_TOO_LARGE")
                return raw.decode("utf-8")
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def failed_attempt(self, turn, attempt_id, outcome):
        with self.db:
            self.db.execute("UPDATE attempts SET outcome=? WHERE id=?", (outcome, attempt_id))
        blocked = self.budget(turn) or (
            "The model did not return a valid discovery turn. Your answer is saved; a bounded retry is scheduled.",
            stamp(now() + timedelta(seconds=RETRY_SECONDS)),
        )
        return self.publish("BLOCKED", *blocked)

    def generate(self, turn):
        blocked = self.budget(turn)
        if blocked:
            return self.publish("BLOCKED", *blocked)
        thinking = self.publish("THINKING", "Learning from your saved answer.")
        if self.transport_failed:
            return thinking
        enabled, _workspace = self.gate()
        if not enabled:
            return self.publish("PAUSED", "Discovery is paused. Your answers and drafts are kept.")
        with self.db:
            attempt_id = self.db.execute(
                "INSERT INTO attempts(turn_key,created_at,outcome) VALUES(?,?,'IN_FLIGHT')",
                (turn["key"], stamp()),
            ).lastrowid
        try:
            raw = self.invoke(turn)
            validate_response(json_object(raw), json_object(turn["input_json"])["history"])
        except TimeoutError:
            return self.failed_attempt(turn, attempt_id, "UNKNOWN")
        except (RuntimeError, ValueError, UnicodeError):
            return self.failed_attempt(turn, attempt_id, "FAILED")
        # Storage failures leave IN_FLIGHT, not retryable FAILED. Likewise a hard
        # process death: absent a committed output, do not speculate/re-call.
        self.finish(turn, raw, attempt_id)
        enabled, _workspace = self.gate()
        if enabled and self.db.execute(
                "SELECT 1 FROM answers WHERE conversation=? AND consumed=0 LIMIT 1",
                (self.conversation,)).fetchone():
            # Do not expose an answerable question that the next imported answer
            # would supersede. Every genuine legacy answer gets its own turn.
            return self.publish("THINKING", "Bringing your earlier saved answers into discovery.")
        return self.publish("AWAITING_INPUT" if enabled else "PAUSED",
                            "Your turn. Share whatever feels useful." if enabled else
                            "Discovery is paused. The generated turn is saved.")

    def tick(self):
        self.transport_failed = False
        enabled, workspace = self.gate()
        if not enabled:
            return self.publish("PAUSED", "Discovery is paused. Your answers and drafts are kept.")
        self.import_legacy()
        pending = self.pending()
        if pending:
            return self.generate(pending)
        answer = self.db.execute(
            "SELECT * FROM answers WHERE conversation=? AND consumed=0 ORDER BY created_at,id LIMIT 1",
            (self.conversation,),
        ).fetchone()
        latest = self.latest()
        if answer is None and latest:
            reply = self.gateway.read("cct_discovery_answers", latest["question_id"])
            if reply is None:
                return self.publish("AWAITING_INPUT", "Your turn. Share whatever feels useful.")
            self.accept_answer(latest, reply)
            answer = self.db.execute("SELECT * FROM answers WHERE conversation=? AND id=?",
                                     (self.conversation, latest["question_id"])).fetchone()
            if answer["consumed"]:
                raise ValueError("DISCOVERY_TURN_CHAIN_INVALID")
        turn = self.prepare(answer, workspace)
        if answer is None:
            # A genuine starter question is not a fabricated answer or a model
            # understanding. No model is needed until there is something to learn.
            starter = {"question": {"text": "What has been on your mind lately, or what would you like to change?"},
                       "learning": empty_learning(), "unknowns": [], "workIdeas": []}
            self.finish(turn, dumps(starter))
            return self.publish("AWAITING_INPUT", "Start wherever you like. There is no checklist to complete.")
        return self.generate(turn)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "once", "status"))
    args = parser.parse_args(argv)
    worker = None
    try:
        raw_home = os.environ.get("HERMES_HOME", "")
        if not raw_home or not Path(raw_home).is_absolute():
            raise ValueError("DISCOVERY_EXPLICIT_PROFILE_REQUIRED")
        home = Path(raw_home).resolve()
        directory = home / "owner-connection"
        if directory.is_symlink():
            raise ValueError("DISCOVERY_DIRECTORY_SYMLINK")
        if args.command == "status":
            path = directory / "discovery.sqlite"
            if path.is_symlink():
                raise ValueError("DISCOVERY_DATABASE_SYMLINK")
            if not path.exists():
                print(dumps({"phase": "PAUSED", "reason": "Discovery has not started.", "executionEnabled": False}))
                return 0
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
                row = db.execute("SELECT payload FROM status WHERE id=1").fetchone()
                print(row[0] if row else dumps({"phase": "PAUSED", "reason": "Discovery has no receipt yet.", "executionEnabled": False}))
            return 0
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(directory / "discovery.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            worker = OwnerDiscovery(home)
            while True:
                failed = False
                try:
                    value = worker.tick()
                    if not worker.transport_failed:
                        cloud_recovered(worker.gateway)
                except Exception as error:
                    failed = True
                    # Dependency failure is a local receipt, never a fresh cloud write.
                    reason = (error.reason_code if isinstance(error, CloudBackoff) else
                              "Discovery could not safely continue. Saved answers are kept; the owner configuration or connection needs attention.")
                    value = worker.record({**worker.view("BLOCKED", reason),
                                           **cloud_status(worker.gateway)})
                print(dumps({key: value[key] for key in
                             ("phase", "reason", "updatedAt", "answersConsumed", "executionEnabled", "retryAt", "cloudStatus", "retrySeconds") if key in value}), flush=True)
                if args.command == "once":
                    return 1 if failed or worker.transport_failed or value["phase"] == "BLOCKED" else 0
                time.sleep(cloud_delay(worker.gateway, IDLE_POLL_SECONDS))
    except Exception as error:
        # Never print provider/config exception bodies or private owner material.
        print(dumps({"phase": "BLOCKED", "reason": "Discovery could not start or persist safely.",
                     "errorType": type(error).__name__, "executionEnabled": False}), flush=True)
        return 1
    finally:
        if worker:
            worker.close()


if __name__ == "__main__":
    raise SystemExit(main())
