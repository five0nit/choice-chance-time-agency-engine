"""Profile-local owner bridge/CLI; never opens the execution runtime database.

Only the daemon sends. CLI producers enqueue revision-bound messages; authenticated
Firestore replies are answer data. Private Telegram delivery is outbound only:
no getUpdates polling, gateway restart, or other profile's bot credentials.
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
import time

from .cloud_projection import publish_projection
from .owner_messaging import OwnerOutbox, runtime_status, stamp
from .cloud_backoff import (CloudBackoff, CloudCircuit, cloud_delay, cloud_recovered,
                            cloud_status, firestore_error_policy)


def load_config(path: Path) -> dict:
    home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")).resolve()
    if path.is_symlink() or path.resolve() != home / "config" / "cct-owner-connection.json":
        raise ValueError("OWNER_CONFIG_WRONG_PROFILE")
    value = json.loads(path.read_text())
    if set(value) != {"projectId", "ownerUid", "telegramChatId", "telegramBotUsername", "ownerMessagesEnabled"}:
        raise ValueError("OWNER_CONFIG_SCHEMA_INVALID")
    for key, pattern in (("projectId", r"[a-z][a-z0-9-]{5,50}"), ("ownerUid", r"[A-Za-z0-9_-]{1,128}"),
                         ("telegramChatId", r"[1-9][0-9]{4,18}"), ("telegramBotUsername", r"[A-Za-z0-9_]{5,64}")):
        if not isinstance(value[key], str) or not re.fullmatch(pattern, value[key]):
            raise ValueError("OWNER_CONFIG_IDENTITY_INVALID")
    if type(value["ownerMessagesEnabled"]) is not bool:
        raise ValueError("OWNER_CONFIG_BOOLEAN_INVALID")
    return value


class FirebaseOwnerGateway:
    def __init__(self, project_id: str, *, circuit=None):
        import google.auth
        from google.cloud import firestore
        home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
        self.circuit = circuit or CloudCircuit.for_project(
            project_id, home / "cloud-recovery" / (sha256(project_id.encode()).hexdigest() + ".json"),
            firestore_error_policy())
        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/datastore"], quota_project_id=project_id)
        self.db = firestore.Client(project=project_id, credentials=credentials)

    def read(self, collection: str, name: str = "current"):
        return self.circuit.call(lambda: self.db.collection(collection).document(name).get(
            retry=None, timeout=15).to_dict())

    def query(self, query):
        from google.api_core.retry import Retry
        return self.circuit.call(lambda: list(query.stream(
            retry=Retry(predicate=lambda _error: False), timeout=15)))

    def publish(self, collection: str, name: str, value: dict):
        def write_and_verify():
            ref = self.db.collection(collection).document(name)
            ref.set(value, retry=None, timeout=15)
            if ref.get(retry=None, timeout=15).to_dict() != value:
                raise RuntimeError("OWNER_FIRESTORE_READBACK_MISMATCH")
        self.circuit.call(write_and_verify)
        return value


class TelegramOwnerSender:
    def __init__(self, config: dict):
        import requests
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{25,100}", token):
            raise ValueError("OWNER_TELEGRAM_CREDENTIAL_MISSING")
        self.base = "https://api.telegram.org/bot" + token
        self.config = config
        self.session = requests.Session()
        self.session.trust_env = False

    def _post(self, method: str, body: dict):
        import requests
        try:
            response = self.session.post(self.base + "/" + method, json=body, timeout=(5, 20), allow_redirects=False)
        except requests.RequestException:
            raise RuntimeError("OWNER_TELEGRAM_NETWORK_UNAVAILABLE") from None
        if response.is_redirect or len(response.content) > 100_000:
            raise RuntimeError("OWNER_TELEGRAM_RESPONSE_INVALID")
        return response.status_code, response.json()

    def verify(self):
        code, data = self._post("getMe", {})
        result = data.get("result", {})
        if code != 200 or data.get("ok") is not True or result.get("username", "").lower() != self.config["telegramBotUsername"].lower():
            raise ValueError("OWNER_TELEGRAM_BOT_MISMATCH")
        code, data = self._post("getChat", {"chat_id": self.config["telegramChatId"]})
        result = data.get("result", {})
        if code != 200 or data.get("ok") is not True or str(result.get("id")) != self.config["telegramChatId"] or result.get("type") != "private":
            raise ValueError("OWNER_TELEGRAM_RECIPIENT_MISMATCH")

    def send(self, row: dict, now: datetime) -> dict:
        text = f"CCT {'question' if row['kind'] == 'ask' else 'update'}\n\n{row['text']}"
        if row["kind"] == "ask":
            text += f"\n\nAnswer securely in your dashboard:\nhttps://{self.config['projectId']}.web.app/#owner-messages\n\n{row['messageId']}\nAnswers do not grant execution permissions."
        body = {"chat_id": self.config["telegramChatId"], "text": text,
                "disable_notification": False, "protect_content": True,
                "link_preview_options": {"is_disabled": True}}
        try:
            code, data = self._post("sendMessage", body)
            result = data.get("result", {})
            if code == 200 and data.get("ok") is True and str(result.get("chat", {}).get("id")) == self.config["telegramChatId"] and result.get("text") == text and type(result.get("message_id")) is int:
                return {"state": "SENT", "telegramMessageId": str(result["message_id"]), "reasonCode": "OWNER_TELEGRAM_ACKNOWLEDGED"}
            if code == 429 and data.get("ok") is False:
                retry = data.get("parameters", {}).get("retry_after", 300)
                retry = retry if type(retry) is int and 1 <= retry <= 86400 else 300
                return {"state": "QUEUED", "nextAttemptAt": stamp(now + timedelta(seconds=retry)), "reasonCode": "OWNER_TELEGRAM_RATE_LIMIT"}
            if code in (400, 401, 403) and data.get("ok") is False:
                return {"state": "DENIED", "reasonCode": "OWNER_TELEGRAM_REJECTED"}
        except Exception:
            pass  # Never log exceptions containing the bot-token URL.
        return {"state": "UNKNOWN", "reasonCode": "OWNER_TELEGRAM_DELIVERY_AMBIGUOUS"}


class OwnerConnection:
    def __init__(self, config_path: Path, gateway, outbox: OwnerOutbox, sender=None):
        self.path, self.gateway, self.outbox, self.sender = config_path, gateway, outbox, sender
        self.identity = {key: value for key, value in load_config(config_path).items() if key != "ownerMessagesEnabled"}

    def status(self, now: datetime):
        config = load_config(self.path)
        if any(config[key] != value for key, value in self.identity.items()):
            raise ValueError("OWNER_RUNTIME_IDENTITY_CHANGED_RESTART_REQUIRED")
        return runtime_status(self.gateway.read("cct_workspace"), owner_uid=config["ownerUid"],
                              project_id=config["projectId"], armed=config["ownerMessagesEnabled"], now=now)

    def tick(self, now: datetime):
        self.outbox.recover()
        status = self.status(now)  # Failure never uses cached permission.
        for row in self.outbox.rows():
            if row["kind"] == "ask" and row["state"] == "SENT" and row["expiresAt"] > stamp(now):
                reply = self.gateway.read("cct_owner_replies", row["messageId"])
                if reply:
                    self.outbox.accept_reply(row["messageId"], reply, owner_uid=status["ownerUid"], now=now)
        # Single claimed effect per tick, bounded even after a long outage.
        queued = next((row for row in reversed(self.outbox.rows()) if row["state"] == "QUEUED"), None)
        if queued and self.sender is not None:
            fresh = self.status(datetime.now(timezone.utc))
            row = self.outbox.claim(queued["messageId"], fresh, now)
            if row:
                # A crash or failed pre-send read leaves SENDING: recovery => UNKNOWN.
                gate = self.status(datetime.now(timezone.utc))
                effect_now = datetime.now(timezone.utc)
                if row["expiresAt"] <= stamp(effect_now) or not gate["effectivePolicy"]["ownerMessages"] or any(gate[k] != row[k] for k in ("revision", "policySha256", "ownerUid")):
                    row.update(state="DENIED", reasonCode="OWNER_MESSAGE_REVOKED_BEFORE_SEND")
                else:
                    row.update(self.sender.send(row, effect_now))
                    if row["state"] == "UNKNOWN":
                        self.sender = None
                self.outbox.save(row)
                status = gate
        if self.sender is None and status["effectivePolicy"]["ownerMessages"]:
            status["effectivePolicy"]["ownerMessages"] = False
            status["reasonCode"] = "OWNER_TELEGRAM_UNAVAILABLE"
        status = publish_projection(self.gateway, "cct_owner_runtime", "current", status)
        for record in self.outbox.db.execute("SELECT id,payload FROM owner_messages WHERE dirty=1").fetchall():
            value = json.loads(record[1])
            value["replyDeadline"] = datetime.fromisoformat(value["expiresAt"])
            self.gateway.publish("cct_owner_messages", record[0], value)
            self.outbox.db.execute("UPDATE owner_messages SET dirty=0 WHERE id=? AND payload=?", tuple(record))
        return status


def tick_services(connection, executor, now: datetime):
    """Observe messaging and the isolated executor independently under one lock.

    One failed lane cannot hide observations from the other. A transport failure
    still reaches main's shared exponential backoff; it is never a cached grant.
    """
    owner_status = executor_status = None
    failed = False
    try:
        owner_status = connection.tick(now)
    except CloudBackoff:
        raise  # Shared dependency: do not start the executor after known quota failure.
    except Exception:
        failed = True
    if executor is not None:
        try:
            executor_status = executor.tick()
            failed = failed or executor.transport_failed
        except Exception:
            failed = True
    if failed or owner_status is None:
        raise RuntimeError("OWNER_SERVICES_UNAVAILABLE")
    return owner_status, executor_status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("inbox")
    sub.add_parser("run")
    sub.add_parser("once")
    for kind in ("ask", "send"):
        cmd = sub.add_parser(kind)
        cmd.add_argument("--key", required=True)
        cmd.add_argument("--text", required=True)
    args = parser.parse_args(argv)
    outbox = executor = None
    try:
        config = load_config(args.config)
        home = args.config.parent.parent
        outbox = OwnerOutbox(home / "owner-connection" / "messages.sqlite")
        if args.command == "inbox":
            print(json.dumps(outbox.rows()[:20], ensure_ascii=False))
            return 0
        gateway = FirebaseOwnerGateway(config["projectId"])
        connection = OwnerConnection(args.config, gateway, outbox)
        now = datetime.now(timezone.utc)
        if args.command == "status":
            print(json.dumps({"runtimeReceipt": gateway.read("cct_owner_runtime"),
                              "currentRequestedScope": connection.status(now)}, sort_keys=True))
        elif args.command in ("ask", "send"):
            row = outbox.enqueue(key=args.key, kind=args.command, text=args.text, status=connection.status(now), now=now)
            print(json.dumps(row, ensure_ascii=False))
        else:
            # Cross-process lock covers recovery and the complete effect boundary.
            with (home / "owner-connection" / "daemon.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                outbox.recover()
                backoff = 60
                while True:
                    try:
                        executor_config_failed = False
                        executor_path = home / "config" / "cct-owner-executor.json"
                        if executor is None and (executor_path.exists() or executor_path.is_symlink()):
                            try:
                                from .owner_executor import BoundedExecutor
                                executor = BoundedExecutor(executor_path, gateway, owner_uid=config["ownerUid"], project_id=config["projectId"])
                            except Exception:
                                executor_config_failed = True
                        if connection.sender is None:
                            try:
                                sender = TelegramOwnerSender(config)
                                sender.verify()
                                connection.sender = sender
                            except Exception:
                                pass  # Keep Firebase status/replies alive during Telegram outage.
                        status, executor_status = tick_services(connection, executor, datetime.now(timezone.utc))
                        summary = {"state": status["state"], "revision": status["revision"], "updatedAt": status["updatedAt"]}
                        if executor_status is not None:
                            summary["executorState"] = executor_status["state"]
                            summary["executorReasonCode"] = executor_status["reasonCode"]
                        cloud_recovered(gateway)
                        summary.update(cloud_status(gateway))
                        print(json.dumps(summary), flush=True)
                        if executor_config_failed:
                            raise ValueError("OWNER_EXECUTOR_CONFIG_BLOCKED")
                        backoff = 60
                    except Exception as error:
                        # Bounded class only: SDK exception bodies may contain secrets.
                        print(json.dumps({"state": "UNAVAILABLE", "errorType": type(error).__name__,
                                          **cloud_status(gateway)}), flush=True)
                        if args.command == "once":
                            return 1
                        backoff = min(backoff * 2, 3600)
                    if args.command == "once":
                        break
                    time.sleep(cloud_delay(gateway, backoff))
        return 0
    except Exception as error:
        print(json.dumps({"state": "BLOCKED", "errorType": type(error).__name__,
                          "reason": str(error) if isinstance(error, ValueError) and str(error).startswith("OWNER_") else "OWNER_CONNECTION_FAILED"}))
        return 1
    finally:
        if executor:
            executor.close()
        if outbox:
            outbox.close()


if __name__ == "__main__":
    raise SystemExit(main())
