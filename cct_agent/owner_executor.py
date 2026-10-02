"""Host-pinned, deterministic test executor; never a general autonomy grant.

Call only inside owner_connection's existing daemon lock. The private SQLite
journal consumes attempts before acknowledgement/effect and never replays an
interrupted run. No shell, model, arbitrary URL, directory scan, or old CCT DB.
"""
from __future__ import annotations

from .cloud_projection import publish_projection

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import html
import http.client
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import stat
import threading
import time
import tomllib
from urllib.parse import urlsplit
import uuid

from .owner_messaging import stamp

CONTROL_SCHEMA = "cct.executor_control.v1"
RUNTIME_SCHEMA = "cct.executor_runtime.v1"
RUN_SCHEMA = "cct.executor_run.v1"
PINNED_PROJECT_ROOT = Path("/path/to/owner-approved/cct-project")
PUBLIC_DOC_URLS = (
    "https://hermes-agent.nousresearch.com/docs/",
    "https://hermes-agent.nousresearch.com/docs/user-guide/features/skills/",
)
MAX_TASK_SECONDS = 60
MAX_DAILY_RUNS = 6
MAX_REPORT = 12000
MAX_FILE_BYTES = 131072
MAX_HTTP_BYTES = 1048576
AUDIT_FILES = (
    ("pyproject.toml", "Python manifest"), ("firebase/hosting/package.json", "Node manifest"),
    ("firebase.json", "Firebase manifest"), ("firestore.rules", "Firestore rules"),
    (".gitignore", "Ignore policy"), ("README.md", "Readme"), ("LICENSE", "License"),
    ("docs/OWNER_CONNECTION.md", "Owner connection documentation"),
    ("docs/BOUNDED_EXECUTOR.md", "Bounded executor documentation"),
)
_CONTROL_FIELDS = {"schemaVersion", "ownerUid", "revision", "updatedAt", "enabled",
                   "runNonce", "task", "maxRuns", "intervalSeconds"}
_SECRET = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----|\b\d{6,}:[A-Za-z0-9_-]{25,}|\b(?:sk-|ghp_|gho_|AIza)[A-Za-z0-9_-]{20,}")


class ExecutorStop(Exception):
    def __init__(self, reason: str, state: str = "STOPPED"):
        self.reason, self.state = reason, state
        super().__init__(reason)


class ExecutorUnavailable(Exception):
    """Transport failure; never expose the original SDK error body."""


def _directory(path: Path, *, create: bool = False) -> int:
    """Walk absolute paths by descriptor: symlinks never become authority."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("EXECUTOR_PATH_INVALID")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_regular(root: Path, relative: str, limit: int) -> bytes:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in ("..", ".") for p in parts):
        raise ValueError("EXECUTOR_PATH_INVALID")
    directory = _directory(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("EXECUTOR_FILE_NOT_REGULAR")
            if info.st_size > limit:
                raise ValueError("EXECUTOR_FILE_TOO_LARGE")
            data = bytearray()
            while len(data) <= limit:
                chunk = os.read(fd, min(16384, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > limit:
                raise ValueError("EXECUTOR_FILE_TOO_LARGE")
            after = os.fstat(fd)
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("EXECUTOR_FILE_CHANGED")
            return bytes(data)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def load_executor_config(path: Path, *, owner_uid: str, project_id: str) -> dict:
    home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))
    # Lexical pinning is intentional: resolve() alone would bless symlink aliases.
    if not home.is_absolute() or path != home / "config" / "cct-owner-executor.json":
        raise ValueError("EXECUTOR_CONFIG_WRONG_PROFILE")
    try:
        config = json.loads(_read_regular(home, "config/cct-owner-executor.json", 8192))
    except (OSError, ValueError):
        raise ValueError("EXECUTOR_CONFIG_UNREADABLE") from None
    if not isinstance(config, dict) or set(config) != {"projectId", "ownerUid", "hostEnabled", "projectRoot", "outputRoot"}:
        raise ValueError("EXECUTOR_CONFIG_SCHEMA_INVALID")
    if config["ownerUid"] != owner_uid or config["projectId"] != project_id:
        raise ValueError("EXECUTOR_CONFIG_IDENTITY_INVALID")
    if not isinstance(owner_uid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", owner_uid):
        raise ValueError("EXECUTOR_CONFIG_IDENTITY_INVALID")
    if not isinstance(project_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{5,50}", project_id):
        raise ValueError("EXECUTOR_CONFIG_IDENTITY_INVALID")
    if type(config["hostEnabled"]) is not bool:
        raise ValueError("EXECUTOR_CONFIG_BOOLEAN_INVALID")
    if config["projectRoot"] != str(PINNED_PROJECT_ROOT) or config["outputRoot"] != str(home / "owner-connection" / "executor"):
        raise ValueError("EXECUTOR_CONFIG_SCOPE_INVALID")
    return config


def validate_control(value, owner_uid: str, now: datetime) -> tuple[dict, str]:
    if not isinstance(value, dict) or set(value) != _CONTROL_FIELDS or value["schemaVersion"] != CONTROL_SCHEMA:
        raise ExecutorStop("EXECUTOR_CONTROL_SCHEMA_INVALID", "INVALID")
    if value["ownerUid"] != owner_uid:
        raise ExecutorStop("EXECUTOR_CONTROL_OWNER_MISMATCH", "INVALID")
    for key, low, high in (("revision", 1, 2147483647), ("maxRuns", 1, 3), ("intervalSeconds", 60, 3600)):
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ExecutorStop("EXECUTOR_CONTROL_INTEGER_INVALID", "INVALID")
    if type(value["enabled"]) is not bool or value["task"] not in ("project-audit", "public-docs-check"):
        raise ExecutorStop("EXECUTOR_CONTROL_POLICY_INVALID", "INVALID")
    if not isinstance(value["runNonce"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,80}", value["runNonce"], flags=re.ASCII):
        raise ExecutorStop("EXECUTOR_CONTROL_NONCE_INVALID", "INVALID")
    updated = value["updatedAt"]
    if not isinstance(updated, datetime) or updated.tzinfo is None or updated.utcoffset() is None:
        raise ExecutorStop("EXECUTOR_CONTROL_TIMESTAMP_INVALID", "INVALID")
    age = (now - updated).total_seconds()
    if age < 0 or (value["enabled"] and age > 3600):
        raise ExecutorStop("EXECUTOR_CONTROL_EXPIRED" if age > 3600 else "EXECUTOR_CONTROL_FUTURE", "INVALID")
    canonical = {**value, "updatedAt": stamp(updated)}
    return canonical, sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@contextmanager
def _deadline():
    # The existing daemon is synchronous/main-thread. Fail closed elsewhere; no
    # runaway worker thread can continue after a reported timeout.
    if threading.current_thread() is not threading.main_thread():
        raise ExecutorStop("EXECUTOR_MAIN_THREAD_REQUIRED", "BLOCKED")
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    if previous_timer[0] or previous_timer[1]:
        raise ExecutorStop("EXECUTOR_TIMER_ALREADY_IN_USE", "BLOCKED")
    def expired(signum, frame):
        raise ExecutorStop("EXECUTOR_TASK_TIMEOUT", "BLOCKED")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, MAX_TASK_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def fetch_public_document(url: str, checkpoint) -> dict:
    """Fixed official URLs only; stdlib direct transport ignores ambient proxies.

    No redirects, authentication, cookies, retry, execution, or retained body.
    A blocking DNS/socket operation is additionally bounded by the task alarm.
    """
    if url not in PUBLIC_DOC_URLS:
        raise ExecutorStop("EXECUTOR_URL_NOT_ALLOWED", "BLOCKED")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "hermes-agent.nousresearch.com" or parsed.port or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ExecutorStop("EXECUTOR_URL_NOT_ALLOWED", "BLOCKED")
    checkpoint()
    connection = http.client.HTTPSConnection(parsed.hostname, timeout=3)
    started = time.monotonic()
    try:
        connection.request("GET", parsed.path, headers={"User-Agent": "CCT-Bounded-Docs-Check/1", "Accept": "text/html", "Accept-Encoding": "identity", "Connection": "close"})
        response = connection.getresponse()
        if 300 <= response.status < 400:
            return {"url": url, "status": response.status, "result": "REDIRECT_BLOCKED", "title": "", "sha256": None, "bytes": 0}
        if response.getheader("Content-Encoding", "identity").lower() not in ("identity", ""):
            raise ExecutorStop("EXECUTOR_HTTP_ENCODING_BLOCKED", "BLOCKED")
        size = response.getheader("Content-Length")
        if size and (not size.isascii() or not size.isdigit() or len(size) > 9 or int(size) > MAX_HTTP_BYTES):
            raise ExecutorStop("EXECUTOR_HTTP_RESPONSE_TOO_LARGE", "BLOCKED")
        body = bytearray()
        while True:
            checkpoint()
            if time.monotonic() - started > 15:
                raise ExecutorStop("EXECUTOR_HTTP_TIMEOUT", "BLOCKED")
            chunk = response.read1(min(32768, MAX_HTTP_BYTES + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > MAX_HTTP_BYTES:
                raise ExecutorStop("EXECUTOR_HTTP_RESPONSE_TOO_LARGE", "BLOCKED")
        match = re.search(r"<title\b[^>]*>(.*?)</title\s*>", body.decode("utf-8", "replace"), re.I | re.S)
        title = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]*>", "", match[1]))).strip() if match else ""
        # Only public title metadata; control chars/token-like strings are hidden.
        title = re.sub(r"[^\x20-\x7e]", "?", title)[:160]
        if _SECRET.search(title) or re.search(r"[A-Za-z0-9_-]{32,}", title):
            title = "[title withheld: token-like content]"
        return {"url": url, "status": response.status, "result": "OK" if response.status == 200 else "HTTP_ERROR", "title": title,
                "sha256": sha256(body).hexdigest(), "bytes": len(body)}
    except (OSError, http.client.HTTPException):
        raise ExecutorStop("EXECUTOR_HTTP_UNAVAILABLE", "BLOCKED") from None
    finally:
        connection.close()


class BoundedExecutor:
    def __init__(self, config_path: Path, gateway, *, owner_uid: str, project_id: str, clock=None):
        self.path, self.gateway = config_path, gateway
        self.owner_uid, self.project_id = owner_uid, project_id
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.config = load_executor_config(config_path, owner_uid=owner_uid, project_id=project_id)
        self.output = Path(self.config["outputRoot"])
        self.directory = _directory(self.output, create=True)
        os.fchmod(self.directory, 0o700)
        self.transport_failed = False
        # Reserve regular database path; parent lock serializes initialization.
        for name in ("executor.sqlite", "executor.sqlite-journal", "executor.sqlite-wal", "executor.sqlite-shm"):
            try:
                info = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                os.close(self.directory)
                raise ValueError("EXECUTOR_JOURNAL_NOT_REGULAR")
        fd = os.open("executor.sqlite", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
        os.fchmod(fd, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(f"/proc/self/fd/{self.directory}/executor.sqlite", timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS activations (
                nonce TEXT PRIMARY KEY, revision INTEGER NOT NULL, digest TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, completed INTEGER NOT NULL DEFAULT 0,
                halted INTEGER NOT NULL DEFAULT 0, next_at TEXT, last_id TEXT
            );
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, nonce TEXT NOT NULL, day TEXT NOT NULL,
                payload TEXT NOT NULL, dirty INTEGER NOT NULL DEFAULT 1
            );
        """)
        self.recover()

    def close(self):
        self.db.close()
        os.close(self.directory)

    def _meta(self, key):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _save_meta(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, str(value)))

    def _activation(self, nonce):
        return self.db.execute("SELECT * FROM activations WHERE nonce=?", (nonce,)).fetchone()

    def _save_run(self, row):
        self.db.execute("UPDATE runs SET payload=?,dirty=1 WHERE id=?", (json.dumps(row, sort_keys=True), row["runId"]))

    def recover(self):
        # Called only between tasks. Interrupted work consumes its slot
        # and halts its activation, including any otherwise remaining runs.
        # Repair terminal runs left before the old non-atomic halt write.
        self.db.execute("""
            UPDATE activations SET halted=1 WHERE halted=0 AND nonce IN (
                SELECT nonce FROM runs
                WHERE json_extract(payload,'$.state') IN ('UNKNOWN','BLOCKED','STOPPED')
            )
        """)
        for record in self.db.execute("SELECT payload FROM runs WHERE json_extract(payload,'$.state')='RUNNING'").fetchall():
            self._finish_failed(json.loads(record[0]), "UNKNOWN", "EXECUTOR_INTERRUPTED")

    def _publish(self, collection, name, value):
        try:
            return publish_projection(self.gateway, collection, name, value)
        except Exception:
            self.transport_failed = True
            raise ExecutorUnavailable() from None

    def _flush_runs(self):
        for record in self.db.execute("SELECT id,payload FROM runs WHERE dirty=1 ORDER BY rowid LIMIT 20").fetchall():
            self._publish("cct_executor_runs", record[0], json.loads(record[1]))
            self.db.execute("UPDATE runs SET dirty=0 WHERE id=? AND payload=?", tuple(record))

    def _read_control(self):
        try:
            value = self.gateway.read("cct_executor_control")
        except Exception:
            self.transport_failed = True
            raise ExecutorUnavailable() from None
        return validate_control(value, self.owner_uid, self.clock())

    def _host_gate(self):
        try:
            current = load_executor_config(self.path, owner_uid=self.owner_uid, project_id=self.project_id)
        except (OSError, ValueError):
            raise ExecutorStop("EXECUTOR_HOST_CONFIG_INVALID", "BLOCKED") from None
        if any(current[k] != self.config[k] for k in ("projectId", "ownerUid", "projectRoot", "outputRoot")):
            raise ExecutorStop("EXECUTOR_HOST_CONFIG_CHANGED", "BLOCKED")
        if current["hostEnabled"] is not True:
            raise ExecutorStop("EXECUTOR_HOST_DISABLED", "BLOCKED")

    def _observe(self, control, digest):
        previous = self._meta("revision")
        if previous is not None:
            if control["revision"] < int(previous):
                raise ExecutorStop("EXECUTOR_REVISION_ROLLBACK", "INVALID")
            if control["revision"] == int(previous) and digest != self._meta("digest"):
                raise ExecutorStop("EXECUTOR_REVISION_CONFLICT", "INVALID")
        if previous is None or control["revision"] > int(previous):
            self.db.execute("UPDATE activations SET halted=1 WHERE halted=0")
            self._save_meta("revision", control["revision"])
            self._save_meta("digest", digest)
        if not control["enabled"]:
            self.db.execute("UPDATE activations SET halted=1 WHERE halted=0")
            return
        existing = self._activation(control["runNonce"])
        if existing and (existing["revision"] != control["revision"] or existing["digest"] != digest):
            raise ExecutorStop("EXECUTOR_NONCE_REUSED", "INVALID")
        if not existing:
            self.db.execute("INSERT INTO activations(nonce,revision,digest) VALUES (?,?,?)", (control["runNonce"], control["revision"], digest))

    def _runtime(self, state, reason, control=None, digest=None):
        activation = self._activation(control["runNonce"]) if control else None
        return {"schemaVersion": RUNTIME_SCHEMA, "ownerUid": self.owner_uid, "projectId": self.project_id,
                "revision": control["revision"] if control else None, "controlSha256": digest,
                "updatedAt": stamp(self.clock()), "state": state, "reasonCode": reason,
                "task": control["task"] if control else None, "runNonce": control["runNonce"] if control else None,
                "completedRuns": activation["completed"] if activation else 0, "maxRuns": control["maxRuns"] if control else 0,
                "lastRunId": activation["last_id"] if activation else None,
                "nextRunAt": activation["next_at"] if activation and state == "READY" else None,
                "scope": "BOUNDED_TEST_EXECUTOR"}

    def _claim(self, control):
        now = self.clock()
        run_id = "run-" + uuid.uuid4().hex
        row = {"schemaVersion": RUN_SCHEMA, "ownerUid": self.owner_uid, "runId": run_id,
               "runNonce": control["runNonce"], "revision": control["revision"], "task": control["task"],
               "state": "RUNNING", "startedAt": stamp(now), "finishedAt": None,
               "reportText": "", "artifactSha256": None, "reasonCode": "EXECUTOR_RUNNING"}
        self.db.execute("BEGIN IMMEDIATE")
        try:
            count = self.db.execute("SELECT COUNT(*) FROM runs WHERE day=?", (now.astimezone(timezone.utc).date().isoformat(),)).fetchone()[0]
            if count >= MAX_DAILY_RUNS:
                raise ExecutorStop("EXECUTOR_DAILY_BUDGET", "BLOCKED")
            activation = self._activation(control["runNonce"])
            if not activation or activation["halted"] or activation["attempts"] >= control["maxRuns"]:
                raise ExecutorStop("EXECUTOR_ACTIVATION_EXHAUSTED", "BLOCKED")
            self.db.execute("INSERT INTO runs(id,nonce,day,payload) VALUES (?,?,?,?)", (run_id, control["runNonce"], now.astimezone(timezone.utc).date().isoformat(), json.dumps(row, sort_keys=True)))
            self.db.execute("UPDATE activations SET attempts=attempts+1,last_id=?,next_at=? WHERE nonce=?", (run_id, stamp(now + timedelta(seconds=control["intervalSeconds"])), control["runNonce"]))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        return row

    def _checkpoint(self, digest, deadline):
        if time.monotonic() >= deadline:
            raise ExecutorStop("EXECUTOR_TASK_TIMEOUT", "BLOCKED")
        self._host_gate()
        control, fresh_digest = self._read_control()
        if not control["enabled"] or fresh_digest != digest:
            raise ExecutorStop("EXECUTOR_CONTROL_REVOKED")
        if time.monotonic() >= deadline:
            raise ExecutorStop("EXECUTOR_TASK_TIMEOUT", "BLOCKED")

    def _artifact(self, run_id, report):
        name = run_id + ".txt"
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(report.encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(self.directory)
            actual = _read_regular(self.output, name, MAX_REPORT * 4)
            if actual != report.encode("utf-8"):
                raise ExecutorStop("EXECUTOR_ARTIFACT_READBACK_MISMATCH", "BLOCKED")
            return sha256(actual).hexdigest()
        except BaseException:
            self._discard_artifact(run_id)
            raise

    def _discard_artifact(self, run_id):
        if not re.fullmatch(r"run-[0-9a-f]{32}", run_id):
            raise ValueError("EXECUTOR_RUN_ID_INVALID")
        try:
            os.unlink(run_id + ".txt", dir_fd=self.directory)
        except FileNotFoundError:
            pass

    def perform_task(self, task, checkpoint):
        if task == "public-docs-check":
            lines = ["Bounded public documentation check", "Scope: fixed official sources; no page execution or model calls."]
            for url in PUBLIC_DOC_URLS:
                item = fetch_public_document(url, checkpoint)
                lines.append(json.dumps(item, ensure_ascii=True, sort_keys=True))
            return "\n".join(lines) + "\n"
        if task != "project-audit":
            raise ExecutorStop("EXECUTOR_TASK_NOT_ALLOWED", "BLOCKED")
        lines = ["Bounded project audit", "Scope: fixed manifest/document snapshots only; no shell, model, code execution or recursive scan."]
        present = missing = rejected = markers = 0
        for relative, label in AUDIT_FILES:
            checkpoint()
            try:
                data = _read_regular(Path(self.config["projectRoot"]), relative, MAX_FILE_BYTES)
            except FileNotFoundError:
                missing += 1
                lines.append(f"{label}: MISSING")
                continue
            except (OSError, ValueError):
                rejected += 1
                lines.append(f"{label}: REJECTED (not a stable bounded regular file)")
                continue
            present += 1
            text = data.decode("utf-8", "replace")
            count = len(_SECRET.findall(text))
            markers += count
            lines.append(f"{label}: bytes={len(data)} sha256={sha256(data).hexdigest()} secretMarkers={count}")
            if relative == "pyproject.toml":
                try:
                    manifest = tomllib.loads(text)
                    project = manifest.get("project", {})
                    dependencies = project.get("dependencies", [])
                    lines.append(f"Python readiness: project metadata={isinstance(project, dict) and bool(project)}; dependency entries={len(dependencies) if isinstance(dependencies, list) else 0}; build system={'build-system' in manifest}")
                except (ValueError, TypeError, AttributeError):
                    lines.append("Python readiness: manifest parse failed")
            elif relative in ("firebase/hosting/package.json", "firebase.json"):
                try:
                    manifest = json.loads(text)
                    lines.append(f"{label} readiness: valid object={isinstance(manifest, dict)}")
                except ValueError:
                    lines.append(f"{label} readiness: JSON parse failed")
            elif relative == "firestore.rules":
                allow_all = bool(re.search(r"allow[^;]*:\s*if\s+true\s*;", text))
                lines.append(f"Rules markers: authentication check={'request.auth' in text}; explicit allow-all={allow_all}")
            elif relative == ".gitignore":
                lines.append(f"Ignore markers: env={'.env' in text}; private database={'sqlite' in text}")
        lines.append(f"Inventory: present={present}, missing={missing}, rejected={rejected}, total={len(AUDIT_FILES)}; secret marker occurrences={markers}.")
        lines.append("Readiness is static evidence, not test execution, a security certification or autonomous coding. Review missing/rejected entries and any secret/allow-all markers locally.")
        return "\n".join(lines) + "\n"

    def _finish_failed(self, row, state, reason):
        self._discard_artifact(row["runId"])
        row.update(state=state, reasonCode=reason, finishedAt=stamp(self.clock()), reportText="", artifactSha256=None)
        # The terminal receipt and halt are one durable decision. A crash before
        # commit leaves RUNNING for recovery, never a resumable failed activation.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._save_run(row)
            self.db.execute("UPDATE activations SET halted=1 WHERE nonce=?", (row["runNonce"],))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def tick(self):
        """At most one attempted task. Transport trouble is signaled for backoff."""
        self.transport_failed = False
        control = digest = row = None
        # Finalization can roll back without a process restart. Recover before
        # any new claim; failed recovery must propagate for daemon backoff.
        self.recover()
        try:
            self._flush_runs()
            control, digest = self._read_control()
            self._observe(control, digest)
            if not control["enabled"]:
                result = self._runtime("OFF", "EXECUTOR_OWNER_OFF", control, digest)
            else:
                self._host_gate()
                activation = self._activation(control["runNonce"])
                if activation["halted"]:
                    result = self._runtime("STOPPED", "EXECUTOR_ACTIVATION_HALTED", control, digest)
                elif activation["attempts"] >= control["maxRuns"]:
                    result = self._runtime("COMPLETED", "EXECUTOR_ACTIVATION_COMPLETED", control, digest)
                elif activation["next_at"] and activation["next_at"] > stamp(self.clock()):
                    result = self._runtime("READY", "EXECUTOR_INTERVAL_WAIT", control, digest)
                else:
                    row = self._claim(control)  # Durable attempt BEFORE ack and effect.
                    self._flush_runs()
                    self._publish("cct_executor_runtime", "current", self._runtime("RUNNING", "EXECUTOR_RUNNING", control, digest))
                    deadline = time.monotonic() + MAX_TASK_SECONDS
                    def checkpoint():
                        return self._checkpoint(digest, deadline)
                    with _deadline():
                        checkpoint()  # Fresh post-ack, pre-effect authority.
                        report = self.perform_task(control["task"], checkpoint)
                        checkpoint()  # Revoke/expiry suppresses all completion output.
                        if not isinstance(report, str):
                            raise ExecutorStop("EXECUTOR_REPORT_INVALID", "BLOCKED")
                        report = report[:MAX_REPORT]
                        artifact_hash = self._artifact(row["runId"], report)
                        checkpoint()  # Artifact readback is not authority to publish.
                    row.update(state="COMPLETED", reasonCode="EXECUTOR_VERIFIED", finishedAt=stamp(self.clock()), reportText=report, artifactSha256=artifact_hash)
                    # Publish and read back before persisting success; an ambiguous
                    # write becomes UNKNOWN rather than delayed completed replay.
                    self._publish("cct_executor_runs", row["runId"], row)
                    self.db.execute("BEGIN IMMEDIATE")
                    try:
                        self.db.execute("UPDATE runs SET payload=?,dirty=0 WHERE id=?", (json.dumps(row, sort_keys=True), row["runId"]))
                        self.db.execute("UPDATE activations SET completed=completed+1 WHERE nonce=?", (control["runNonce"],))
                        self.db.execute("COMMIT")
                    except BaseException:
                        self.db.execute("ROLLBACK")
                        raise
                    row = None  # Completion already verified; runtime failure cannot undo it.
                    activation = self._activation(control["runNonce"])
                    state = "COMPLETED" if activation["attempts"] >= control["maxRuns"] else "READY"
                    result = self._runtime(state, "EXECUTOR_VERIFIED", control, digest)
            self._publish("cct_executor_runtime", "current", result)
            return result
        except ExecutorStop as error:
            state = error.state
            if row:
                state = "STOPPED" if state in ("INVALID", "STOPPED") else "BLOCKED"
                self._finish_failed(row, state, error.reason)
            result = self._runtime(state, error.reason, control, digest)
        except ExecutorUnavailable:
            if row:
                self._finish_failed(row, "UNKNOWN", "EXECUTOR_TRANSPORT_AMBIGUOUS")
            # No same-tick retry on quota/read/write/readback failure. The daemon
            # applies its existing backoff; dirty UNKNOWN is retried next tick.
            return self._runtime("UNAVAILABLE", "EXECUTOR_TRANSPORT_UNAVAILABLE", control, digest)
        except Exception:
            if row:
                self._finish_failed(row, "BLOCKED", "EXECUTOR_TASK_FAILED")
            result = self._runtime("BLOCKED", "EXECUTOR_INTERNAL_ERROR", control, digest)
        try:
            self._flush_runs()
            self._publish("cct_executor_runtime", "current", result)
        except ExecutorUnavailable:
            return self._runtime("UNAVAILABLE", "EXECUTOR_TRANSPORT_UNAVAILABLE", control, digest)
        return result
