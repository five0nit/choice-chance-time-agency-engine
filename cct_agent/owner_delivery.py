"""Canonical owner priorities -> private sandboxed delivery, durably and boundedly.

This worker is an execution continuation of the existing dashboard discovery, not
another proposal/Telegram priority queue. Source discovery/report stores are read-only.
Model proposals never create authority. The host config AND current dashboard gate
must permit local delivery; external providers have separately enforced authority.
"""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time

from .cloud_projection import publish_projection
from .owner_connection import FirebaseOwnerGateway
from .cloud_backoff import CloudBackoff, cloud_delay, cloud_recovered, cloud_status
from .owner_discovery_model import validate_response
from .owner_work_model import json_object
from .owner_delivery_model import validate
from .owner_workspace import normalize_owner_workspace


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value):
    return sha256(encode(value).encode()).hexdigest()


def stamp():
    return datetime.now(timezone.utc).isoformat()


def regular(path, maximum=2_000_000):
    path = Path(path)
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise ValueError("DELIVERY_SYMLINK")
    with path.open("rb") as f:
        s = os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.getuid():
            raise ValueError("DELIVERY_FILE_IDENTITY")
        if s.st_mode & 0o022:
            raise ValueError("DELIVERY_FILE_WRITABLE_BY_OTHERS")
        if s.st_size > maximum:
            raise ValueError("DELIVERY_FILE_SIZE")
        value = f.read(maximum + 1)
        if len(value) > maximum:
            raise ValueError("DELIVERY_FILE_SIZE")
    return value


def readonly(path):
    regular(path, 150_000_000)
    db = sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    return db


class CanonicalEvidence:
    def __init__(self, config):
        self.config = config
        self.source = Path(config["sourceHome"])

    def snapshot(self):
        c = self.config
        with closing(readonly(self.source / "owner-connection" / "discovery.sqlite")) as db:
            identity = db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
            if not identity or json_object(identity[0]) != {k: c[k] for k in ("ownerUid", "projectId")}:
                raise ValueError("DELIVERY_SOURCE_IDENTITY")
            row = db.execute("SELECT * FROM turns WHERE conversation=? AND response_json IS NOT NULL ORDER BY rowid DESC LIMIT 1",
                             (c["conversationId"],)).fetchone()
            if not row:
                return {"turnId": None, "candidates": [], "reports": []}
            history = json_object(row["input_json"])["history"]
            output = validate_response(json_object(row["response_json"]), history)
            for item in history:
                saved = db.execute("SELECT answer,consumed FROM answers WHERE conversation=? AND id=?",
                                   (c["conversationId"], item["questionId"])).fetchone()
                if not saved or saved[0] != item["answer"] or saved[1] != 1:
                    raise ValueError("DELIVERY_SOURCE_EVIDENCE")
            candidates = []
            for i, idea in enumerate(output["workIdeas"]):
                candidates.append({"ideaId": f"promote-{row['question_id'][2:]}-{i}",
                    "turnId": row["question_id"], "ideaIndex": i, "idea": idea,
                    "fingerprint": digest({k: " ".join(idea[k].lower().split()) for k in ("title", "firstStep")})})
        reports = []
        with closing(readonly(self.source / "owner-work" / "work.sqlite")) as db:
            expected = {k: c[k] for k in ("ownerUid", "projectId", "conversationId")}
            identity = db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
            if not identity or json_object(identity[0]) != expected:
                raise ValueError("DELIVERY_REPORT_IDENTITY")
            for row in db.execute("SELECT payload FROM jobs WHERE phase='COMPLETE' ORDER BY rowid DESC LIMIT 3"):
                j = json_object(row[0])
                name = j.get("artifactName", "")
                if not re.fullmatch(r"work-[0-9a-f]{24}\.md", name):
                    raise ValueError("DELIVERY_REPORT_NAME")
                data = regular(self.source / "owner-work" / name, 250000)
                if sha256(data).hexdigest() != j.get("artifactSha256"):
                    raise ValueError("DELIVERY_REPORT_HASH")
                reports.append({"id": j["id"], "artifactSha256": j["artifactSha256"],
                    "selection": j["selection"], "report": j["report"], "calculations": j["calculations"]})
        return {"turnId": candidates[0]["turnId"] if candidates else None,
                "candidates": candidates, "reports": reports}


def load_config(home):
    config = json_object(regular(home / "config" / "cct-owner-delivery.json", 30000))
    keys = {"schemaVersion", "ownerUid", "projectId", "conversationId", "sourceHome", "enabled",
            "authorization", "maxDailyJobs", "maxDailyModelCalls", "maxAttempts", "retrySeconds", "services"}
    if set(config) != keys or config["schemaVersion"] != "cct.owner_delivery.config.v1":
        raise ValueError("DELIVERY_CONFIG_SHAPE")
    for key, regex in (("ownerUid", r"[A-Za-z0-9_-]{1,128}"), ("projectId", r"[a-z][a-z0-9-]{5,50}"),
                       ("conversationId", r"[A-Za-z0-9_-]{1,128}")):
        if not isinstance(config[key], str) or not re.fullmatch(regex, config[key]):
            raise ValueError("DELIVERY_CONFIG_IDENTITY")
    if type(config["enabled"]) is not bool or not isinstance(config["authorization"], str) or not config["authorization"].startswith("operator://"):
        raise ValueError("DELIVERY_CONFIG_AUTHORITY")
    for key, lo, hi in (("maxDailyJobs", 1, 4), ("maxDailyModelCalls", 1, 20), ("maxAttempts", 1, 3), ("retrySeconds", 1, 3600)):
        if type(config[key]) is not int or not lo <= config[key] <= hi:
            raise ValueError("DELIVERY_CONFIG_BUDGET")
    source = Path(config["sourceHome"])
    if not source.is_absolute() or source.is_symlink() or source.resolve() == home.resolve():
        raise ValueError("DELIVERY_SOURCE_SCOPE")
    if not isinstance(config["services"], dict):
        raise ValueError("DELIVERY_SERVICE_CONFIG")
    return config


class OwnerDelivery:
    def __init__(self, home, *, gateway=None, evidence=None, driver=None, services=None, model=None, continuation=None, clock=time.time):
        self.home = Path(home).resolve()
        self.config = load_config(self.home)
        self.identity = {k: self.config[k] for k in ("ownerUid", "projectId", "conversationId", "sourceHome", "authorization")}
        self.clock = clock
        self.directory = self.home / "owner-delivery"
        if self.directory.is_symlink():
            raise ValueError("DELIVERY_STATE_SYMLINK")
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.directory.chmod(0o700)
        dbpath = self.directory / "delivery.sqlite"
        if dbpath.exists():
            regular(dbpath, 150000000)
        self.db = sqlite3.connect(dbpath, timeout=20)
        dbpath.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL,
            phase TEXT NOT NULL, created REAL NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, job_id TEXT, stage TEXT,
            created REAL NOT NULL, state TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, at TEXT NOT NULL, kind TEXT NOT NULL,
            data TEXT NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL);
        """)
        saved = self.meta("identity")
        if saved and saved != self.identity:
            raise ValueError("DELIVERY_IDENTITY_CHANGED")
        self.setmeta("identity", self.identity)
        self.gateway = gateway or FirebaseOwnerGateway(self.config["projectId"])
        self.evidence = evidence or CanonicalEvidence(self.config)
        if driver is None:
            from .owner_delivery_local import LocalDeliveryDriver
            driver = LocalDeliveryDriver(self.directory / "artifacts")
        self.driver = driver
        if services is None:
            from .owner_delivery_services import ServiceDispatcher
            services = ServiceDispatcher({"services": self.config["services"], **{k: self.config[k] for k in ("ownerUid", "projectId")}},
                                         self.directory / "services", gateway=self.gateway)
        self.services = services
        self.model_override = model
        from .owner_builds import OwnerBuilds
        self.builds = OwnerBuilds(self)
        if continuation is None:
            from .owner_continuation import Continuation
            continuation = Continuation(self)
        self.continuation = continuation

    def close(self):
        self.db.close()

    def meta(self, key):
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json_object(r[0]) if r else None

    def setmeta(self, key, value):
        with self.db:
            self.db.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, encode(value)))

    def event(self, kind, data):
        previous = self.db.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        previous = previous[0] if previous else "0" * 64
        value = {"at": stamp(), "kind": kind, "data": data, "previous": previous}
        with self.db:
            self.db.execute("INSERT INTO events(at,kind,data,previous,hash) VALUES(?,?,?,?,?)",
                            (value["at"], kind, encode(data), previous, digest(value)))

    def chain_valid(self):
        previous = "0" * 64
        for r in self.db.execute("SELECT * FROM events ORDER BY id"):
            if r["previous"] != previous or r["hash"] != digest({"at": r["at"], "kind": r["kind"], "data": json_object(r["data"]), "previous": previous}):
                return False
            previous = r["hash"]
        return True

    @contextmanager
    def lock(self):
        path = self.directory / "worker.lock"
        if path.is_symlink():
            raise ValueError("DELIVERY_LOCK_SYMLINK")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_nlink != 1:
                raise ValueError("DELIVERY_LOCK_HARDLINK")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def gate(self):
        c = load_config(self.home)
        if ({k: c[k] for k in self.identity} != self.identity
                or digest(c["services"]) != digest(self.config["services"])):
            raise ValueError("DELIVERY_IDENTITY_CHANGED")
        self.config = c
        if hasattr(self, "builds"):
            self.builds.refresh_controls()
        w = self.gateway.read("cct_workspace")
        if not isinstance(w, dict) or w.get("ownerUid") != c["ownerUid"]:
            raise ValueError("DELIVERY_DASHBOARD_IDENTITY")
        w = normalize_owner_workspace(w, owner_uid=c["ownerUid"])
        if (not c["enabled"] or w.get("learningEnabled") is not True or w.get("autonomyMode") != "full"
                or w.get("autonomyAcknowledged") is not True
                or w.get("permissions", {}).get("workspaceWrite") is not True
                or w.get("permissions", {}).get("workspaceRead") is not True):
            raise RuntimeError("DELIVERY_PAUSED")
        active = getattr(self, "_continuation_job", None)
        if active is not None:
            self.continuation.authorize(active)
        return w

    def save(self, job):
        job["updatedAt"] = stamp()
        with self.db:
            self.db.execute("INSERT INTO jobs VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET phase=excluded.phase,payload=excluded.payload",
                (job["id"], job["fingerprint"], job["phase"], job["created"], encode(job)))

    def jobs(self):
        return [json_object(r[0]) for r in self.db.execute("SELECT payload FROM jobs ORDER BY created,id")]

    def model(self, stage, data, job_id):
        self.gate()
        attempt_id = self.builds.charge("provider", job_id, stage)

        state = "INTERRUPTED"
        try:
            payload = {"stage": stage, **data}
            if self.model_override:
                result = self.model_override(payload)
            else:
                env = {k: v for k, v in os.environ.items() if k in {"HOME", "PATH", "LANG", "SSL_CERT_FILE", "SSL_CERT_DIR", "PYTHONPATH"}}
                env["HERMES_HOME"] = str(self.home)
                p = subprocess.run([sys.executable, "-m", "cct_agent.owner_delivery_model"], input=encode(payload),
                    capture_output=True, text=True, timeout=230, env=env, cwd="/tmp")
                if p.returncode or len(p.stdout.encode()) > 180000:
                    raise RuntimeError("DELIVERY_MODEL_FAILED")
                result = json_object(p.stdout)
            validate(result, payload)
            state = "RETURNED"
            return result
        except Exception:
            state = "FAILED"
            raise
        finally:
            with self.db:
                self.db.execute("UPDATE attempts SET state=? WHERE id=?", (state, attempt_id))

    def project(self, phase, reason, job=None, next_action=None):
        # Learning projection loss never invalidates an already verified artifact.
        continuation_error = False
        try:
            if job and job.get("phase") in {"COMPLETE", "BLOCKED"}:
                self.continuation.observe(job)
            continuation = self.continuation.status()
        except Exception:
            continuation_error = True
            continuation = {"schemaVersion": "cct.owner_continuation.v1", "enabled": False,
                "state": "UNAVAILABLE", "objective": "", "whatHappened": "Continuation status unavailable; artifacts retained.",
                "whatImproved": "", "nextAction": "Restore continuation state before automatic work.",
                "blocker": "CONTINUATION_STATUS_UNAVAILABLE", "nextEligibleAt": None,
                "cycleId": "", "parentBuildId": "", "childBuildId": "",
                "research": {"attempted": 0, "verified": 0, "maxPer24h": 2}, "updatedAt": stamp()}
        if not continuation_error and phase in {"PAUSED", "ERROR"} and continuation.get("enabled"):
            continuation = {**continuation, "state": phase, "blocker": reason,
                "nextAction": "Resume only when current owner controls and dependencies permit."}
        if job:
            self.builds.sync_job(job, phase=phase, reason=reason)
        try:
            self.builds.backfill()
            self.builds.project_requests()
        except CloudBackoff:
            raise
        except Exception:
            pass  # Durable work is not replayed on projection loss.
        jobs = self.jobs()
        counts = {"queued": sum(j["phase"] == "QUEUED" for j in jobs), "complete": sum(j["phase"] == "COMPLETE" for j in jobs),
                  "blocked": sum(j["phase"] == "BLOCKED" for j in jobs), "retry": sum(j["phase"] == "RETRY" for j in jobs)}
        if job is None and jobs:
            job = jobs[-1]
        fields = {"id", "ideaId", "turnId", "title", "phase", "attempts", "artifactRoot", "verification", "reason", "nextAction", "retryAt", "review", "reportIds"}
        value = {"schemaVersion": "cct.owner_delivery.v1", "ownerUid": self.config["ownerUid"], "updatedAt": stamp(),
                 "phase": phase, "reason": reason, "trigger": "AUTO_FULL_MODE", "scope": "PRIVATE_SANDBOXED_LOCAL_DELIVERY",
                 "job": {k: v for k, v in job.items() if k in fields} if job else None,
                 "counts": counts, "nextAction": next_action or (job or {}).get("nextAction", "Select the next supported canonical idea within daily limits."),
                 "lastOutcome": self.meta("lastOutcome"), "eventChainValid": self.chain_valid(),
                 "continuation": continuation,
                 "capabilities": [{"id": "local.sandboxed_delivery", "implemented": True, "configured": self.config["enabled"],
                     "authorized": phase not in {"PAUSED", "ERROR"}, "readVerified": any(j["phase"] == "COMPLETE" for j in jobs),
                     "reason": "Private new artifacts only; no live project edits, network, credentials or financial effects."}] + self.services.capabilities()}
        # Projection failure must never turn a completed effect into a rebuild.
        try:
            value = publish_projection(self.gateway, "cct_owner_delivery", "current", value)
            return {**value, "projection": "VERIFIED"}
        except Exception:
            return {**value, "projection": "UNAVAILABLE", **cloud_status(self.gateway)}

    def select(self, snapshot):
        prior = self.jobs()
        used = {j["fingerprint"] for j in prior}
        candidates = [c for c in snapshot["candidates"] if c["fingerprint"] not in used]
        key = digest({"candidates": candidates, "reports": snapshot["reports"], "outcomes": self.meta("lastOutcome")})
        if not candidates or self.meta("noOp") == {"key": key}:
            return None
        selection_tries = self.db.execute("SELECT count(*) FROM attempts WHERE job_id=? AND stage='select'", ("selection-"+key,)).fetchone()[0]
        if selection_tries >= self.config["maxAttempts"]:
            self.setmeta("noOp", {"key": key})
            self.event("SELECTION_BLOCKED", {"selection": key, "reason": "Selection attempt limit; new source evidence required."})
            return None
        self.project("SELECTING", "Comparing canonical ideas with a real NO_OP alternative.")
        result = self.model("select", {"candidates": candidates, "reports": snapshot["reports"],
            "previousOutcomes": [{k: j.get(k) for k in ("ideaId", "phase", "reason")} for j in prior[-10:]],
            "alternatives": [c["ideaId"] for c in candidates] + ["NO_OP"]}, "selection-"+key)
        self.event("SELECTION", {"candidateIds": [c["ideaId"] for c in candidates]+["NO_OP"], "decision": result})
        if result["action"] == "NO_OP":
            self.setmeta("noOp", {"key": key})
            return None
        candidate = next(c for c in candidates if c["ideaId"] == result["ideaId"])
        job = {"id": "delivery-" + digest([self.identity, candidate["fingerprint"]])[:24], **candidate,
            "title": candidate["idea"]["title"], "selection": result, "reportIds": result["reportIds"],
            "reports": [r for r in snapshot["reports"] if r["id"] in result["reportIds"]],
            "created": self.clock(), "createdAt": stamp(), "phase": "QUEUED", "attempts": 0,
            "authority": self.config["authorization"], "reason": "Automatically selected from genuine dashboard discovery; no Promote click.",
            "nextAction": "Build a private isolated executable artifact from this exact idea."}
        self.gate()
        self.save(job)
        return job

    @staticmethod
    def followup_context(job):
        return {k: job[k] for k in ("parentBuild", "ownerRequest", "continuationContext") if k in job}

    def execute(self, job):
        previous = getattr(self, "_continuation_job", None)
        self._continuation_job = job if job.get("continuationContext") is not None else None
        try:
            return self._execute(job)
        finally:
            self._continuation_job = previous

    def _execute(self, job):
        artifact_failure = False
        attempt_limit = min(self.config["maxAttempts"], 2) if job.get("continuationContext") is not None else self.config["maxAttempts"]
        try:
            self.gate()
            if job["phase"] == "NOTIFY":
                return self.finish(job)
            if job.get("action") == "discover":
                return self.builds.discover(job)
            if ((not job.get("bundle") or not job.get("acceptance") or job.get("review") is None)
                    and self.db.execute("SELECT count(*) FROM attempts WHERE created>?", (self.clock()-86400,)).fetchone()[0] >= self.builds.effective()["maxDailyProviderCalls"]):
                return self.project("DAILY_CAP", "Model-call cap reached; saved stage resumes after the rolling window.", job)
            # A persisted immutable bundle can be resumed without another model call.
            if not job.get("bundle"):
                if job["attempts"] >= attempt_limit:
                    raise ValueError("DELIVERY_ATTEMPT_LIMIT")
                job.update(phase="BUILDING", attempts=job["attempts"] + 1, reason="Generating complete local source and tests from linked research.")
                self.save(job)
                self.project(job["phase"], job["reason"], job)
                job["bundle"] = self.model("build", {"selection": job["selection"], "idea": job["idea"], "reports": job["reports"],
                    "previousFailure": job.get("previousFailure"), **self.followup_context(job)}, job["id"])
                job.update(phase="EXECUTING", reason="Immutable bundle saved; running compile, CLI and tests inside networkless sandbox.")
                self.save(job)
            self.gate()
            if not job.get("acceptance"):
                job["acceptance"] = self.model("acceptance", {
                    "selection": job["selection"], "idea": job["idea"],
                    "bundle": job["bundle"], "reports": job["reports"], **self.followup_context(job)}, job["id"])
                self.save(job)
            validate(job["acceptance"], {"stage": "acceptance"})
            self.gate()
            if job["phase"] == "REVIEWING" and job.get("execution"):
                # The durable execution checkpoint already completed this stage.
                result = job["execution"]
            else:
                self.project("EXECUTING", job["reason"], job)
                # Projection includes outbound I/O; do not retain authority
                # observed before a pause/revocation during that operation.
                self.gate()
                tool_attempt = self.builds.charge("tool", job["id"])
                try:
                    result = self.driver.run(job["id"] + "-a" + str(job["attempts"]), job["bundle"], acceptance=job["acceptance"])
                finally:
                    with self.db:
                        self.db.execute("UPDATE tool_attempts SET state='RETURNED' WHERE id=?", (tool_attempt,))
                job["execution"] = result
            # Infrastructure denial is not evidence that generated source is bad.
            if isinstance(result, dict) and result.get("status") == "blocked" and result.get("reason"):
                reason = result["reason"]
                concrete_failure = isinstance(reason, str) and (reason in {
                    "COMPILE_FAILED", "TESTS_FAILED", "ZERO_TESTS", "CLI_ENTRY_MISSING",
                    "CLI_BEHAVIOR_FAILED", "INDEPENDENT_BEHAVIOR_FAILED", "EXECUTION_TIMEOUT", "EXECUTION_OUTPUT_LIMIT",
                    "INTERRUPTED_ATTEMPT", "INVALID_BUNDLE_SCHEMA", "INVALID_TEST_COMMAND",
                    "INVALID_SUMMARY", "SUMMARY_LIMIT", "FILE_COUNT_LIMIT", "INVALID_FILE_SCHEMA",
                    "INVALID_FILE_TYPE", "UNSAFE_ARTIFACT_PATH", "DUPLICATE_ARTIFACT_PATH",
                    "FILE_BYTES_LIMIT", "BUNDLE_BYTES_LIMIT", "FILE_DIRECTORY_COLLISION",
                } or reason.startswith(("READBACK_", "RECEIPT_")))
                if not concrete_failure:
                    # Unknown denials fail closed without guessing that a rebuild helps.
                    raise RuntimeError("DELIVERY_DEPENDENCY_UNAVAILABLE")
            artifact_failure = True
            # Driver contract: normalize after validation; an opaque success string is never enough.
            verification = result.get("verification", {})
            success = (isinstance(verification, dict) and result.get("status") == "completed"
                and result.get("schemaVersion") == "cct-local-delivery/v2"
                and verification.get("status") == "passed"
                and verification.get("independentBehavior") is True
                and verification.get("generatedTestsVerified") is False
                and verification.get("acceptanceDigest") == digest(job["acceptance"])
                and verification.get("testCount") == len(job["acceptance"]["cases"])
                and all(verification.get(k) is True for k in ("compile", "tests", "cli", "readback"))
                and type(verification.get("testCount")) is int and verification["testCount"] > 0
                and result.get("testCount") == verification["testCount"]
                and verification.get("semanticCompletion") is False
                and result.get("private") is True and result.get("sandbox") == "bubblewrap-no-network"
                and isinstance(result.get("artifactRoot"), str) and bool(result.get("manifest")))
            if not success:
                raise RuntimeError("DELIVERY_LOCAL_VERIFICATION_FAILED")
            artifact_failure = False
            job.update(phase="REVIEWING", artifactRoot=result["artifactRoot"], verification=verification,
                       reason="Sandbox checks passed; independently reviewing acceptance and factual claims.")
            self.save(job)
            self.gate()
            review = job.get("review")
            if review is None:
                review = self.model("review", {"selection": job["selection"], "idea": job["idea"], "bundle": job["bundle"],
                    "execution": result, "acceptance": job["acceptance"], "reports": job["reports"], **self.followup_context(job)}, job["id"])
            else:
                validate(review, {"stage": "review"})
            job["review"] = review
            self.save(job)
            if not review["accepted"]:
                artifact_failure = True
                raise RuntimeError("DELIVERY_ACCEPTANCE_REVIEW_FAILED")
            job.update(phase="NOTIFY", reason="Private artifact verified; recording exact owner notification readback.")
            self.save(job)
            return self.finish(job)
        except CloudBackoff:
            # The durable host circuit owns cloud retry deadlines, not artifact
            # recovery. Preserve saved stages (including committed COMPLETE)
            # and let tick report the outage without another projection attempt.
            raise
        except Exception as error:
            code = str(error) if re.fullmatch(r"[A-Z][A-Z0-9_]{1,100}", str(error)) else "DELIVERY_STAGE_FAILED"
            if code == "DELIVERY_PAUSED":
                # Preserve completed stages; pause is not permission to discard or replay.
                return self.project("PAUSED", "Delivery paused by current owner controls. Saved work retained.", job)
            if code in {"DELIVERY_MODEL_DAILY_CAP", "DELIVERY_TOOL_DAILY_CAP"}:
                return self.project("DAILY_CAP", "Rolling provider/sandbox budget reached; saved work retained.", job)
            if code in {"BUILDS_REQUEST_PROVIDER_CAP", "BUILDS_REQUEST_TOOL_CAP"}:
                job.update(phase="BLOCKED", reason=code, nextAction="Request cap exhausted; submit an explicitly budgeted new follow-up from the original build.")
                self.save(job)
                return self.project("BLOCKED", code, job)
            if job["phase"] == "NOTIFY":
                job["recoveryAttempts"] = job.get("recoveryAttempts", 0) + 1
                exhausted = max(job.get("notificationAttempts", 0), job["recoveryAttempts"]) >= self.config["maxAttempts"]
                job.update(phase="BLOCKED" if exhausted else "NOTIFY",
                    reason="Notification readback blocked; verified artifact retained." if exhausted else "Notification readback pending; artifact retained, no rebuild.",
                    nextAction="Owner review needed for notification provider; no artifact rebuild." if exhausted else "Retry exact idempotent notification readback.",
                    retryAt=self.clock()+self.config["retrySeconds"])
            elif artifact_failure:
                job["previousFailure"] = {"code": code, "execution": job.get("execution"), "review": job.get("review")}
                self.builds.backfill()  # Retain the exact failed revision before a repair.
                for field in ("bundle", "acceptance", "execution", "review", "verification", "artifactRoot"):
                    job.pop(field, None)
                job.update(phase="RETRY" if job["attempts"] < attempt_limit else "BLOCKED",
                           reason=code, retryAt=self.clock() + self.config["retrySeconds"] * max(job["attempts"], 1),
                           nextAction="Repair using saved failure evidence on the next eligible tick." if job["attempts"] < attempt_limit else "Attempt budget exhausted; owner review needed. Other safe ideas remain eligible.")
            else:
                # Control reads, permissions, model outages and malformed review
                # responses do not invalidate an already completed stage.
                job["recoveryAttempts"] = job.get("recoveryAttempts", 0) + 1
                exhausted = (job["recoveryAttempts"] >= self.config["maxAttempts"]
                             or (not job.get("bundle") and job["attempts"] >= attempt_limit))
                if exhausted:
                    job["phase"] = "BLOCKED"
                job.update(reason=code,
                    retryAt=self.clock() + self.config["retrySeconds"] * job["recoveryAttempts"],
                    nextAction="Recovery budget exhausted; saved work retained for owner review." if exhausted
                        else "Retry the saved stage after dependency/control recovery; no artifact rebuild.")
            self.save(job)
            self.event("STAGE_FAILED", {"jobId": job["id"], "phase": job["phase"], "code": code, "attempts": job["attempts"]})
            return self.project(job["phase"], job["reason"], job)

    def finish(self, job):
        self.gate()
        job["notificationAttempts"] = job.get("notificationAttempts", 0) + 1
        self.save(job)
        # Stable phase is independent of notification retries and final job state.
        notification = self.services.notify_owner({**job, "phase": "VERIFIED"})
        job["notification"] = notification
        self.save(job)
        if notification.get("state") != "VERIFIED" or notification.get("readVerified") is not True:
            raise RuntimeError("DELIVERY_NOTIFICATION_NOT_VERIFIED")
        job.update(phase="COMPLETE", notification=notification,
            reason="Private executable artifact, sandbox tests, independent acceptance review and owner notification readback complete.",
            nextAction="Select the next unprocessed canonical idea within the daily budget.")
        if job.get("continuationContext") is not None:
            job["nextAction"] = "Learn from verified behavior; compare a justified next version, an evidence gap, new useful work and WAIT within unchanged budgets."
        is_discovery = job.get("action") == "discover"
        if is_discovery:
            job["reason"] = "Saved-evidence discovery brief, separate model review and owner notification readback complete; no fresh web research or executable sandbox tests."
        outcome = {"jobId": job["id"], "ideaId": job["ideaId"], "reportIds": job["reportIds"],
            "status": "REVIEWED_SAVED_EVIDENCE_BRIEF" if is_discovery else "VERIFIED_LOCAL_DELIVERY", "artifactRoot": job["artifactRoot"], "verification": job["verification"],
            "review": job["review"], "notification": notification, "revenueDelta": None,
            "scope": "Saved-evidence exploration, not fresh web research or independently verified facts." if is_discovery else "Local executable behavior and readback, not financial viability or earnings.", "at": stamp()}
        previous = self.db.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        previous = previous[0] if previous else "0" * 64
        event = {"at": stamp(), "kind": "OUTCOME", "data": outcome, "previous": previous}
        job["updatedAt"] = stamp()
        # Completion, learning outcome and event commitment survive a crash together.
        with self.db:
            self.db.execute("UPDATE jobs SET phase=?,payload=? WHERE id=?", ("COMPLETE", encode(job), job["id"]))
            self.db.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("lastOutcome", encode(outcome)))
            self.db.execute("INSERT INTO events(at,kind,data,previous,hash) VALUES(?,?,?,?,?)",
                (event["at"], "OUTCOME", encode(outcome), previous, digest(event)))
        return self.project("COMPLETE", job["reason"], job)

    def tick(self):
        try:
            with self.lock():
                if not self.chain_valid():
                    raise ValueError("DELIVERY_EVENT_CHAIN_INVALID")
                self.gate()
                self.builds.backfill()
                self.builds.ingest()
                self.builds.activate()
                self.builds.project_requests()
                pending = [j for j in self.jobs() if j["phase"] not in {"COMPLETE", "BLOCKED"}]
                if pending:
                    job = pending[0]
                    if job.get("retryAt", 0) > self.clock():
                        return self.project("WAITING_RETRY", "Saved recovery is waiting for its bounded retry time.", job)
                    return self.execute(job)
                if self.continuation.enabled:
                    for finished in self.jobs():
                        if finished["phase"] in {"COMPLETE", "BLOCKED"}:
                            self.continuation.observe(finished)
                    job = self.continuation.tick(self.evidence.snapshot())
                    if job:
                        return self.execute(job)
                    status = self.continuation.status()
                    return self.project(status["state"], status.get("whatHappened", "Continuation waiting."),
                        next_action=status.get("nextAction"))
                daily = self.db.execute("SELECT count(*) FROM jobs WHERE created>?", (self.clock()-86400,)).fetchone()[0]
                if daily >= self.builds.effective()["maxDailyJobs"]:
                    return self.project("DAILY_CAP", "Daily local-job cap reached; automatic continuation when the rolling window permits.")
                snapshot = self.evidence.snapshot()
                job = self.select(snapshot)
                if job:
                    return self.execute(job)
                return self.project("WAITING", "No unprocessed bounded local idea needs work. No model call on unchanged idle ticks.")
        except BlockingIOError:
            return {"phase": "BUSY", "reason": "Another worker owns the serialized execution lease."}
        except CloudBackoff as error:
            # Do not project an error to the failed dependency or modify queued jobs.
            return {"phase": "ERROR", "reason": error.reason_code,
                    "projection": "UNAVAILABLE", **error.receipt}
        except Exception as error:
            code = str(error) if re.fullmatch(r"[A-Z][A-Z0-9_]{1,100}", str(error)) else "DELIVERY_DEPENDENCY_UNAVAILABLE"
            phase = "PAUSED" if code == "DELIVERY_PAUSED" else "DAILY_CAP" if code in {"DELIVERY_MODEL_DAILY_CAP", "DELIVERY_TOOL_DAILY_CAP"} else "ERROR"
            try:
                return self.project(phase, code)
            except Exception:
                return {"phase": phase, "reason": code, "projection": "UNAVAILABLE"}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home", type=Path, default=Path(os.environ.get("HERMES_HOME", Path.home()/".hermes")))
    p.add_argument("--loop-seconds", type=int, default=0)
    args = p.parse_args(argv)
    if args.loop_seconds and not 30 <= args.loop_seconds <= 3600:
        p.error("loop interval must be 30..3600 seconds")
    if args.home.resolve() != Path(os.environ.get("HERMES_HOME", args.home)).resolve():
        p.error("HERMES_HOME mismatch")
    worker = OwnerDelivery(args.home)
    try:
        while True:
            result = worker.tick()
            if result.get("projection") == "VERIFIED":
                cloud_recovered(worker.gateway)
            result.update(cloud_status(worker.gateway))
            print(encode({k: result.get(k) for k in
                          ("phase", "reason", "counts", "cloudStatus", "retrySeconds", "retryAt")}), flush=True)
            if not args.loop_seconds:
                return 0 if result["phase"] not in {"ERROR", "BLOCKED"} else 1
            time.sleep(cloud_delay(worker.gateway, args.loop_seconds))
    finally:
        worker.close()


if __name__ == "__main__":
    raise SystemExit(main())
