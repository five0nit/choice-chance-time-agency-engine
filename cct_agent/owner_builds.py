"""Durable owner build library, immutable requests and charged delivery budgets.

Only the host delivery worker consumes this module. Firestore is an intent/projection
surface, never the canonical job store. All effects still pass OwnerDelivery.gate().
"""
from __future__ import annotations

from .cloud_projection import publish_projection

from datetime import datetime, timezone
from hashlib import sha256
import json
import re


CEILINGS = {"maxDailyJobs": 4, "maxDailyProviderCalls": 20, "maxDailyToolCalls": 12}
CONTROL_KEYS = {"schemaVersion", "ownerUid", "revision", *CEILINGS, "updatedAt"}
REQUEST_KEYS = {"schemaVersion", "ownerUid", "requestId", "parentBuildId", "parentDigest",
                "action", "instructions", "maxProviderCalls", "maxToolCalls", "createdAt",
                "expiresAt", "controlRevision"}
TERMINAL = {"COMPLETE", "REJECTED", "FAILED"}
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,100}")
SCOPE = "Saved-evidence exploration; no fresh web research. Separate model review is not independent factual verification."


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value):
    return sha256(encode(value).encode()).hexdigest()


def timestamp(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("BUILDS_TIMESTAMP_INVALID")
    return value.timestamp()


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def wire(value):
    """Make Firestore timestamp values canonical before immutable local persistence."""
    if isinstance(value, datetime):
        timestamp(value)
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, dict):
        return {k: wire(v) for k, v in value.items()}
    if isinstance(value, list):
        return [wire(v) for v in value]
    return value


def discovery_bundle(brief):
    lines = ["# " + brief["title"], "", SCOPE, "", brief["summary"]]
    for key, label in (("gaps", "Evidence gaps"), ("alternatives", "Alternatives"),
                       ("proposedUpgrades", "Proposed upgrades"), ("researchQuestions", "Further research questions")):
        lines.extend(["", "## " + label, ""] + ["- " + item for item in brief[key]])
    return {"summary": brief["summary"], "files": [{"path": "DISCOVERY.md", "content": "\n".join(lines) + "\n"}],
            "testCommand": "not-applicable-saved-evidence-brief"}


class OwnerBuilds:
    def __init__(self, worker):
        self.worker = worker
        self.db = worker.db
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS build_library(id TEXT PRIMARY KEY, job_id TEXT NOT NULL,
            bundle_digest TEXT NOT NULL, archived INTEGER NOT NULL DEFAULT 0, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS build_requests(id TEXT PRIMARY KEY, payload_digest TEXT NOT NULL,
            payload TEXT NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL,
            build_id TEXT NOT NULL DEFAULT '', accepted REAL NOT NULL, updated REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS tool_attempts(id INTEGER PRIMARY KEY, job_id TEXT NOT NULL,
            created REAL NOT NULL, state TEXT NOT NULL);
        """)

    @property
    def uid(self):
        return self.worker.config["ownerUid"]

    def usage(self, job_id=None):
        if job_id is None:
            arg = (self.worker.clock() - 86400,)
            jobs = self.db.execute("SELECT count(*) FROM jobs WHERE created>?", arg).fetchone()[0]
            provider = self.db.execute("SELECT count(*) FROM attempts WHERE created>?", arg).fetchone()[0]
            tools = self.db.execute("SELECT count(*) FROM tool_attempts WHERE created>?", arg).fetchone()[0]
        else:
            jobs = 1
            provider = self.db.execute("SELECT count(*) FROM attempts WHERE job_id=?", (job_id,)).fetchone()[0]
            tools = self.db.execute("SELECT count(*) FROM tool_attempts WHERE job_id=?", (job_id,)).fetchone()[0]
        return {"jobs": jobs, "providerCalls": provider, "toolCalls": tools}

    def effective(self):
        saved = self.worker.meta("buildControls")
        if saved:
            return saved["effective"]
        return {"maxDailyJobs": self.worker.config["maxDailyJobs"],
                "maxDailyProviderCalls": self.worker.config["maxDailyModelCalls"], "maxDailyToolCalls": 4}

    def publish(self, collection, name, value):
        if value.get("ownerUid") != self.uid:
            raise ValueError("BUILDS_PROJECTION_OWNER")
        return publish_projection(self.worker.gateway, collection, name, value)

    def control_status(self, *, requested=None, state="APPLIED", reason="Host-applied rolling 24-hour limits."):
        saved = self.worker.meta("buildControls") or {}
        revision = saved.get("revision", 0)
        value = {"schemaVersion": "cct.owner_build_controls_status.v1", "ownerUid": self.uid,
                 "requestedRevision": revision if requested is None else requested,
                 "effectiveRevision": revision, "state": state, "reason": reason,
                 "effective": self.effective(), "ceilings": dict(CEILINGS), "usage": self.usage(),
                 "updatedAt": utc(self.worker.clock())}
        self.publish("cct_owner_build_controls_status", "current", value)
        return value

    def refresh_controls(self):
        requested = 0
        try:
            value = self.worker.gateway.read("cct_owner_build_controls", "current")
            saved = self.worker.meta("buildControls")
            if value is None:
                if saved:
                    raise ValueError("BUILDS_CONTROLS_MISSING")
                return self.control_status(state="DEFAULTS", reason="Existing host defaults; no owner revision applied.")
            if isinstance(value, dict) and type(value.get("revision")) is int:
                requested = max(0, value["revision"])
            if (not isinstance(value, dict) or set(value) != CONTROL_KEYS
                    or value.get("schemaVersion") != "cct.owner_build_controls.v1"
                    or value.get("ownerUid") != self.uid
                    or type(value.get("revision")) is not int or value["revision"] < 1):
                raise ValueError("BUILDS_CONTROLS_INVALID")
            timestamp(value["updatedAt"])
            for key, ceiling in CEILINGS.items():
                if type(value[key]) is not int or not 1 <= value[key] <= ceiling:
                    raise ValueError("BUILDS_CONTROLS_LIMIT")
            frozen = wire(value)
            if saved and (value["revision"] < saved["revision"] or
                          (value["revision"] == saved["revision"] and digest(frozen) != saved["digest"])):
                raise ValueError("BUILDS_CONTROLS_STALE")
            if not saved or value["revision"] > saved["revision"]:
                self.worker.setmeta("buildControls", {"revision": value["revision"], "digest": digest(frozen),
                    "effective": {k: value[k] for k in CEILINGS}})
            return self.control_status(requested=requested)
        except Exception:
            try:
                self.control_status(requested=requested, state="REJECTED", reason="Invalid, unavailable or stale owner controls; work held.")
            except Exception:
                pass
            raise

    def charge(self, kind, job_id, stage="sandbox"):
        """Atomically check and durably charge before invocation, including failures.

        SQLite serialization protects direct callers as well as the outer worker lock.
        Global rolling counters and lifetime request counters share this transaction.
        """
        if kind not in {"provider", "tool"}:
            raise ValueError("BUILDS_CHARGE_KIND")
        if kind == "provider" and stage.startswith("continuation_"):
            # Planning has no job yet; recheck enrollment after remote reads.
            self.worker.continuation._gate()
        else:
            self.worker.gate()
        table = "attempts" if kind == "provider" else "tool_attempts"
        key = "maxDailyProviderCalls" if kind == "provider" else "maxDailyToolCalls"
        request_key = "maxProviderCalls" if kind == "provider" else "maxToolCalls"
        self.db.execute("BEGIN IMMEDIATE")
        try:
            used = self.db.execute(f"SELECT count(*) FROM {table} WHERE created>?", (self.worker.clock()-86400,)).fetchone()[0]
            if used >= self.effective()[key]:
                raise RuntimeError("DELIVERY_MODEL_DAILY_CAP" if kind == "provider" else "DELIVERY_TOOL_DAILY_CAP")
            row = self.db.execute("SELECT payload FROM build_requests WHERE build_id=?", (job_id,)).fetchone()
            if row:
                request = json.loads(row[0])
                lifetime = self.db.execute(f"SELECT count(*) FROM {table} WHERE job_id=?", (job_id,)).fetchone()[0]
                if lifetime >= request[request_key]:
                    raise RuntimeError("BUILDS_REQUEST_PROVIDER_CAP" if kind == "provider" else "BUILDS_REQUEST_TOOL_CAP")
            if kind == "provider":
                cursor = self.db.execute("INSERT INTO attempts(job_id,stage,created,state) VALUES(?,?,?,'IN_FLIGHT')",
                                         (job_id, stage, self.worker.clock()))
            else:
                cursor = self.db.execute("INSERT INTO tool_attempts(job_id,created,state) VALUES(?,?,'IN_FLIGHT')",
                                         (job_id, self.worker.clock()))
            self.db.commit()
            return cursor.lastrowid
        except BaseException:
            self.db.rollback()
            raise

    def library(self, build_id):
        row = self.db.execute("SELECT payload FROM build_library WHERE id=?", (build_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def backfill(self):
        """Project saved bundles, with immutable per-digest versions across repairs."""
        for job in self.worker.jobs():
            bundle = job.get("bundle")
            if not bundle:
                continue
            if job.get("action") == "discover":
                if not job.get("discovery") or discovery_bundle(job["discovery"]) != bundle:
                    raise ValueError("BUILDS_DISCOVERY_BUNDLE_MISMATCH")
            else:
                from .owner_delivery_model import validate
                validate(bundle, {"stage": "build"})
            bundle_hash = digest(bundle)
            existing = self.db.execute("SELECT id FROM build_library WHERE job_id=? AND bundle_digest=?", (job["id"], bundle_hash)).fetchone()
            base = self.library(job["id"])
            build_id = existing[0] if existing else (job["id"] if not base else job["id"] + "-v-" + bundle_hash[:16])
            old = self.library(build_id)
            usage = self.usage(job["id"])
            value = {"schemaVersion": "cct.owner_build.v1", "ownerUid": self.uid, "buildId": build_id,
                "parentBuildId": job.get("parentBuildId", ""), "rootBuildId": job.get("rootBuildId", job["id"]),
                "action": job.get("action", "build"), "title": job.get("title", "Saved build")[:200],
                "summary": bundle["summary"], "status": job["phase"], "reason": job.get("reason", ""),
                "createdAt": job.get("createdAt", utc(job["created"])), "updatedAt": job.get("updatedAt", utc(job["created"])),
                "bundleDigest": bundle_hash, "archived": bool(old and old["archived"]),
                "verification": job.get("verification", {"status": "not-verified", "scope": "Saved source only."}),
                "usage": {k: usage[k] for k in ("providerCalls", "toolCalls")},
                "files": [{**f, "sha256": sha256(f["content"].encode()).hexdigest()} for f in bundle["files"]]}
            if job.get("requestId"):
                value.update(requestId=job["requestId"], instructions=job.get("ownerRequest", {}).get("instructions", ""))
            if job.get("review"):
                value["review"] = job["review"]
            if len(encode(value).encode()) > 800000:
                raise ValueError("BUILDS_PROJECTION_SIZE")
            with self.db:
                self.db.execute("INSERT INTO build_library VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                    (build_id, job["id"], bundle_hash, int(value["archived"]), encode(value)))
        # Re-publish every saved version: a source retry cannot erase older evidence.
        for row in self.db.execute("SELECT id,payload FROM build_library ORDER BY rowid"):
            self.publish("cct_owner_builds", row[0], json.loads(row[1]))

    def request_status(self, row):
        request = json.loads(row["payload"])
        return {"schemaVersion": "cct.owner_build_request_status.v1", "ownerUid": self.uid,
            "requestId": row["id"], "parentBuildId": request.get("parentBuildId", ""),
            "action": request.get("action", ""), "state": row["state"], "reason": row["reason"],
            "buildId": row["build_id"], "updatedAt": utc(row["updated"])}

    def project_requests(self):
        for row in self.db.execute("SELECT * FROM build_requests ORDER BY accepted,id"):
            self.publish("cct_owner_build_request_status", row["id"], self.request_status(row))

    def update_request(self, request_id, state, reason, build_id=None):
        with self.db:
            self.db.execute("UPDATE build_requests SET state=?,reason=?,updated=?,build_id=COALESCE(?,build_id) WHERE id=?",
                            (state, reason, self.worker.clock(), build_id, request_id))

    def sync_job(self, job, *, phase=None, reason=None):
        if not job.get("requestId"):
            return
        phase = phase or job["phase"]
        state = ("COMPLETE" if phase == "COMPLETE" else "FAILED" if phase == "BLOCKED" else
                 "WAITING_BUDGET" if phase == "DAILY_CAP" else "RUNNING")
        self.update_request(job["requestId"], state, reason or job.get("reason", ""), job["id"])

    def validate_request(self, document_id, value):
        if (not IDENTIFIER.fullmatch(document_id) or not isinstance(value, dict) or set(value) != REQUEST_KEYS
                or value.get("schemaVersion") != "cct.owner_build_request.v1"
                or value.get("ownerUid") != self.uid or value.get("requestId") != document_id):
            raise ValueError("BUILDS_REQUEST_SHAPE")
        if (not isinstance(value["parentBuildId"], str) or not IDENTIFIER.fullmatch(value["parentBuildId"])
                or not isinstance(value["parentDigest"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["parentDigest"])):
            raise ValueError("BUILDS_REQUEST_PARENT")
        if value["action"] not in {"upgrade", "steer", "discover", "archive", "restore"}:
            raise ValueError("BUILDS_REQUEST_ACTION")
        if (not isinstance(value["instructions"], str) or len(value["instructions"]) > 2000
                or (value["action"] == "steer" and not value["instructions"].strip())):
            raise ValueError("BUILDS_REQUEST_INSTRUCTIONS")
        for key, ceiling in (("maxProviderCalls", 20), ("maxToolCalls", 12)):
            if type(value[key]) is not int or not 1 <= value[key] <= ceiling:
                raise ValueError("BUILDS_REQUEST_LIMIT")
        created, expires = timestamp(value["createdAt"]), timestamp(value["expiresAt"])
        if not created <= self.worker.clock() < expires <= created + 7*86400:
            raise ValueError("BUILDS_REQUEST_EXPIRED")
        revision = (self.worker.meta("buildControls") or {}).get("revision", 0)
        if type(value["controlRevision"]) is not int or value["controlRevision"] != revision:
            raise ValueError("BUILDS_REQUEST_CONTROLS_STALE")
        parent = self.library(value["parentBuildId"])
        if (not parent or parent["ownerUid"] != self.uid or parent["status"] != "COMPLETE"
                or parent["bundleDigest"] != value["parentDigest"]):
            raise ValueError("BUILDS_REQUEST_PARENT_MISMATCH")
        return parent

    def request_page(self, cursor, limit=100):
        gateway = self.worker.gateway
        if hasattr(gateway, "list_build_requests"):
            return gateway.list_build_requests(owner_uid=self.uid, after=cursor, limit=limit)
        from google.cloud.firestore_v1.base_query import FieldFilter
        collection = gateway.db.collection("cct_owner_build_requests")
        query = collection.where(filter=FieldFilter("ownerUid", "==", self.uid)).order_by("__name__").limit(limit)
        if cursor:
            query = query.start_after({"__name__": collection.document(cursor)})
        return [(doc.id, doc.to_dict()) for doc in gateway.query(query)]

    def ingest(self):
        self.worker.gate()
        cursor = (self.worker.meta("buildRequestCursor") or {}).get("after", "")
        rows = self.request_page(cursor)
        if len(rows) > 100:
            raise ValueError("BUILDS_REQUEST_PAGE_LIMIT")
        for document_id, value in rows:
            # Never turn foreign-owner content into owner-visible receipts.
            if not isinstance(value, dict) or value.get("ownerUid") != self.uid or not IDENTIFIER.fullmatch(document_id):
                raise ValueError("BUILDS_REQUEST_STREAM_IDENTITY")
            frozen = wire(value)
            fingerprint = digest(frozen)
            old = self.db.execute("SELECT * FROM build_requests WHERE id=?", (document_id,)).fetchone()
            if old:
                if old["payload_digest"] != fingerprint:
                    raise ValueError("BUILDS_REQUEST_MUTATED")
                continue
            self.worker.gate()  # latest intent revision and full owner authority at acceptance
            try:
                self.validate_request(document_id, value)
                state, reason = "QUEUED", "Immutable owner request accepted; awaiting bounded activation."
            except ValueError as error:
                state, reason = "REJECTED", str(error)
            with self.db:
                self.db.execute("INSERT INTO build_requests VALUES(?,?,?,?,?,'',?,?)",
                    (document_id, fingerprint, encode(frozen), state, reason, self.worker.clock(), self.worker.clock()))
        self.worker.setmeta("buildRequestCursor", {"after": rows[-1][0] if len(rows) == 100 else ""})

    def activate(self):
        """Apply organization requests or atomically enqueue one child job."""
        for row in self.db.execute("SELECT * FROM build_requests WHERE state IN ('QUEUED','WAITING_BUDGET') AND build_id='' ORDER BY accepted,id").fetchall():
            self.worker.gate()
            request = json.loads(row["payload"])
            parent = self.library(request["parentBuildId"])
            if not parent or parent["status"] != "COMPLETE" or parent["bundleDigest"] != request["parentDigest"]:
                self.update_request(row["id"], "FAILED", "BUILDS_REQUEST_PARENT_MISMATCH")
                continue
            if request["action"] in {"archive", "restore"}:
                parent["archived"] = request["action"] == "archive"
                parent["updatedAt"] = utc(self.worker.clock())
                with self.db:
                    self.db.execute("UPDATE build_library SET archived=?,payload=? WHERE id=?",
                                    (int(parent["archived"]), encode(parent), parent["buildId"]))
                    self.db.execute("UPDATE build_requests SET state='COMPLETE',reason=?,updated=? WHERE id=?",
                                    ("Library organization updated; files and history retained.", self.worker.clock(), row["id"]))
                continue
            if self.usage()["jobs"] >= self.effective()["maxDailyJobs"]:
                self.update_request(row["id"], "WAITING_BUDGET", "Rolling job budget reached; accepted request retained.")
                continue
            source = self.db.execute("SELECT payload FROM jobs WHERE id=(SELECT job_id FROM build_library WHERE id=?)", (parent["buildId"],)).fetchone()
            source = json.loads(source[0]) if source else {}
            bundle = {"summary": parent["summary"], "files": [{"path": f["path"], "content": f["content"]} for f in parent["files"]],
                      "testCommand": "not-applicable-saved-evidence-brief" if parent["action"] == "discover" else "python-unittest"}
            if digest(bundle) != request["parentDigest"]:
                self.update_request(row["id"], "FAILED", "BUILDS_PARENT_SOURCE_MISMATCH")
                continue
            job_id = "delivery-request-" + digest([self.uid, row["id"]])[:24]
            selection = {"action": "BUILD", "ideaId": "owner-request-" + row["id"],
                "objective": f"{request['action'].title()} saved build: {parent['title']}",
                "doneWhen": "Requested bounded improvement is implemented and independently verified.",
                "why": "Explicit immutable owner follow-up request.", "reportIds": source.get("reportIds", [])}
            job = {"id": job_id, "fingerprint": digest(["owner-build-request", self.uid, row["id"]]),
                "requestId": row["id"], "action": request["action"], "parentBuildId": parent["buildId"],
                "rootBuildId": parent["rootBuildId"], "parentBuild": {"buildId": parent["buildId"],
                    "bundleDigest": parent["bundleDigest"], "bundle": bundle, "verification": parent["verification"],
                    "selection": source.get("selection", {})}, "ownerRequest": request,
                "ideaId": selection["ideaId"], "idea": source.get("idea", {"title": parent["title"], "firstStep": parent["summary"]}),
                "title": f"{request['action'].title()}: {parent['title']}"[:200], "selection": selection,
                "reportIds": source.get("reportIds", []), "reports": source.get("reports", []),
                "created": self.worker.clock(), "createdAt": utc(self.worker.clock()), "updatedAt": utc(self.worker.clock()),
                "phase": "QUEUED", "attempts": 0, "authority": self.worker.config["authorization"],
                "reason": "Accepted owner follow-up; original artifact is unchanged.",
                "nextAction": "Generate and separately verify the child artifact."}
            # Persist deterministic identity and activation together before provider/sandbox effects.
            self.db.execute("BEGIN IMMEDIATE")
            try:
                if self.usage()["jobs"] >= self.effective()["maxDailyJobs"]:
                    self.db.rollback()
                    self.update_request(row["id"], "WAITING_BUDGET", "Rolling job budget reached.")
                    continue
                self.db.execute("INSERT INTO jobs VALUES(?,?,?,?,?)", (job_id, job["fingerprint"], job["phase"], job["created"], encode(job)))
                self.db.execute("UPDATE build_requests SET state='RUNNING',reason=?,build_id=?,updated=? WHERE id=?",
                                (job["reason"], job_id, self.worker.clock(), row["id"]))
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise
            return job
        return None

    def discover(self, job):
        """A durable non-executable brief with its own separate review checkpoint."""
        from .owner_delivery_model import validate
        self.worker.gate()
        if not job.get("discovery"):
            job.update(phase="BUILDING", attempts=job["attempts"]+1, reason=SCOPE)
            self.worker.save(job)
            job["discovery"] = self.worker.model("discover", {"parentBuild": job["parentBuild"],
                "ownerRequest": job["ownerRequest"], "reports": job["reports"]}, job["id"])
            job["bundle"] = discovery_bundle(job["discovery"])
            job.update(phase="REVIEWING", reason="Saved-evidence brief persisted; separate review pending.")
            self.worker.save(job)
        if job.get("review") is None:
            job["review"] = self.worker.model("discover_review", {"parentBuild": job["parentBuild"],
                "ownerRequest": job["ownerRequest"], "brief": job["discovery"], "bundle": job["bundle"],
                "reports": job["reports"]}, job["id"])
            self.worker.save(job)
        validate(job["review"], {"stage": "discover_review"})
        if not job["review"]["accepted"]:
            job.update(phase="BLOCKED", reason="BUILDS_DISCOVERY_REVIEW_REJECTED")
            self.worker.save(job)
            return self.worker.project("BLOCKED", job["reason"], job)
        job.update(phase="NOTIFY", artifactRoot="", verification={"status": "reviewed", "type": "saved-evidence-discovery",
            "scope": SCOPE, "separateModelReview": True, "sandbox": "not-applicable",
            "independentFactualVerification": False, "freshWebResearch": False, "semanticCompletion": False},
            reason="Saved-evidence discovery brief separately reviewed; owner notification pending.")
        self.worker.save(job)
        return self.worker.finish(job)
