"""Discovery -> saved research plan -> ticketed public GET -> private report.

Own state/lock; no trading, shell execution, messages or general-purpose agent.
One job per explicit owner promotion, processed serially without a daily success cap.
Unknown/interrupted actions stop rather than replay. Projection never calls models.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timedelta
from decimal import Decimal
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time

from .cloud_projection import publish_projection
from .owner_connection import FirebaseOwnerGateway, load_config
from .cloud_backoff import CloudBackoff, cloud_delay, cloud_recovered, cloud_status
from .owner_dialogue import dialogue_config
from .owner_discovery import dumps, now, stamp
from .owner_discovery_model import json_object, validate_response
from .owner_work_web import CATALOG, MAX_BYTES, MAX_SOURCES, WorkWeb
from .store import EventStore

TERMINAL = {"COMPLETE", "BLOCKED"}


def private_file(path, content):
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("WORK_ARTIFACT_SYMLINK")
    temp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def calculations(sources):
    """Illustrative USD fee math from public data, never a profitability claim."""
    successful = {s["id"]: s for s in sources if s["ok"]}
    if "kraken-pair" not in successful:
        return {"available": False, "reason": "No public pair-fee receipt."}
    try:
        raw = json.loads(successful["kraken-pair"]["receipt"]["web"]["content"])
        pair = raw["result"]["XXBTZUSD"]
        fee = Decimal(str(pair["fees"][0][1])) / 100
        if not 0 <= fee < Decimal("0.1"):
            raise ValueError("FEE_RANGE")
        result = {"available": True, "sourceIds": ["kraken-pair"], "currency": "USD",
                  "assumptions": "Illustration only: entry-tier public taker fee, two fills; excludes spread, slippage, funding, withdrawal, tax, data and model costs. Owner budget currency and account eligibility unverified.",
                  "feePercentPerFill": str(fee * 100), "minimumBaseOrder": str(pair["ordermin"]),
                  "baseCurrency": str(pair["base"]),
                  "feeOnlyBreakEvenMovePercent": str(((1 + fee) / (1 - fee) - 1) * 100),
                  "formula": "(1 + fee_fraction) / (1 - fee_fraction) - 1; fee paid in quote on entry and exit",
                  "scenarios": [{"notionalUSD": str(b), "approxTwoFillFeesUSD": str(2 * fee * b)}
                                for b in (Decimal(10), Decimal(100))]}
        if "kraken-price" in successful:
            ticker = json.loads(successful["kraken-price"]["receipt"]["web"]["content"])["result"]["XXBTZUSD"]
            result.update(minimumOrderApproxUSD=str(Decimal(str(pair["ordermin"])) * Decimal(ticker["a"][0])))
            result["sourceIds"].append("kraken-price")
        return result
    except (IndexError, KeyError, TypeError, ValueError, ArithmeticError):
        return {"available": False, "reason": "Public pair/ticker schema or fee values not usable."}


def report_markdown(job):
    report, selection = job["report"], job["selection"]
    lines = [f"# {selection['title']}", "", f"Run: `{job['id']}` · {job['updatedAt']}", "",
             "Scope: public research and private report only. No trading, spending or account changes.",
             "", "## Objective", selection["objective"], "", "## Completion criterion", selection["doneWhen"],
             "", "## Synthesis (model interpretation)", report["summary"], "", "## Source-backed findings"]
    source_numbers = {s["id"]: n for n, s in enumerate(job["sources"], 1)}
    for finding in report["findings"]:
        lines += [f"- {finding['claim']}[{source_numbers[finding['sourceId']]}]", f"  > {finding['quote']}"]
    lines += ["", "## Calculations (deterministic, assumptions explicit)", "```json",
              json.dumps(job["calculations"], indent=2), "```", "", "## Proposed next plan — NOT executed"]
    for n, step in enumerate(report["nextSteps"], 1):
        lines += [f"{n}. **{step['title']}**", f"   Deliverable: {step['deliverable']}",
                  f"   Done when: {step['doneWhen']}", "   Gate: explicit scope/approval required; not queued."]
    lines += ["", "## Owner decisions", *[f"- {s}" for s in report["ownerDecisions"]],
              "", "## Limitations", *[f"- {s}" for s in report["limitations"]], "",
              "## Discovery provenance", *[f"- `{s}`" for s in selection["sourceAnswerIds"]], "", "## Sources"]
    for n, source in enumerate(job["sources"], 1):
        state = f"Fetched {source['fetchedAt']}; SHA256 `{source['sha256']}`" if source["ok"] else f"Unavailable: {source['errorType']}"
        lines += [f"[{n}] {source['title']} — {source['url']}", f"{state}"]
    return "\n\n".join(lines) + "\n"


class OwnerWork:
    def __init__(self, home):
        self.home = home
        self.identity = load_config(home / "config" / "cct-owner-connection.json")
        self.dialogue = dialogue_config(home)
        self.directory = home / "owner-work"
        self.directory.mkdir(mode=0o700, exist_ok=True)
        if self.directory.is_symlink():
            raise ValueError("WORK_DIRECTORY_SYMLINK")
        path = self.directory / "work.sqlite"
        if path.is_symlink():
            raise ValueError("WORK_DATABASE_SYMLINK")
        self.db = sqlite3.connect(path, timeout=20)
        path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                phase TEXT NOT NULL, payload TEXT NOT NULL);
        """)
        identity = dumps({**{k: self.identity[k] for k in ("ownerUid", "projectId")},
                          "conversationId": self.dialogue["conversationId"]})
        saved = self.db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
        if saved and saved[0] != identity:
            raise ValueError("WORK_IDENTITY_CHANGED")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO meta VALUES('identity',?)", (identity,))
        # Interrupted effects are uncertain, even if read-only. Never replay them.
        for row in self.db.execute("SELECT payload FROM jobs WHERE phase NOT IN ('COMPLETE','BLOCKED','QUEUED')").fetchall():
            job = json_object(row[0])
            job.update(phase="BLOCKED", reason="Interrupted action; operator review required. No automatic replay.")
            self.save(job)
        self.gateway = FirebaseOwnerGateway(self.identity["projectId"])

    def close(self):
        self.db.close()

    def gate(self):
        config = json_object((self.home / "config" / "cct-owner-work.json").read_bytes())
        if (set(config) != {"enabled", "authorization"} or type(config["enabled"]) is not bool
                or not isinstance(config["authorization"], str)
                or not config["authorization"].startswith("operator://") or len(config["authorization"]) > 200):
            raise ValueError("WORK_CONFIG_INVALID")
        identity = load_config(self.home / "config" / "cct-owner-connection.json")
        dialogue = dialogue_config(self.home)
        if (any(identity[k] != self.identity[k] for k in ("ownerUid", "projectId"))
                or dialogue != self.dialogue):
            raise ValueError("WORK_IDENTITY_CHANGED")
        workspace = self.gateway.read("cct_workspace")
        if (not config["enabled"] or not dialogue["enabled"] or not workspace
                or workspace.get("ownerUid") != identity["ownerUid"] or workspace.get("learningEnabled") is not True):
            raise RuntimeError("WORK_PAUSED")
        return config

    def snapshot(self, turn_id=None):
        path = self.home / "owner-connection" / "discovery.sqlite"
        if path.is_symlink():
            raise ValueError("WORK_DISCOVERY_SYMLINK")
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            db.row_factory = sqlite3.Row
            identity = db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
            if not identity or json_object(identity[0]) != {k: self.identity[k] for k in ("ownerUid", "projectId")}:
                raise ValueError("WORK_DISCOVERY_IDENTITY_MISMATCH")
            row = db.execute("SELECT * FROM turns WHERE conversation=? AND response_json IS NOT NULL "
                             + ("AND question_id=? " if turn_id else "") + "ORDER BY rowid DESC LIMIT 1",
                             (self.dialogue["conversationId"],) + ((turn_id,) if turn_id else ())).fetchone()
            if not row:
                return None
            history = json_object(row["input_json"])["history"]
            output = validate_response(json_object(row["response_json"]), history)
            if not output["workIdeas"]:
                return None
            for answer in history:
                saved = db.execute("SELECT answer,consumed FROM answers WHERE conversation=? AND id=?",
                                   (self.dialogue["conversationId"], answer["questionId"])).fetchone()
                if not saved or saved[0] != answer["answer"] or saved[1] != 1:
                    raise ValueError("WORK_DISCOVERY_EVIDENCE_MISMATCH")
            return {"turnId": row["question_id"], "turnCreatedAt": row["created_at"], "history": history,
                    **{k: output[k] for k in ("workIdeas", "learning", "unknowns")}}

    def save(self, job):
        job["updatedAt"] = stamp()
        with self.db:
            self.db.execute("INSERT INTO jobs VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET phase=excluded.phase,payload=excluded.payload",
                            (job["id"], job["createdAt"], job["phase"], dumps(job)))

    def publish(self, job, reason=None, phase=None):
        queued = [json_object(row[0]) for row in self.db.execute(
            "SELECT payload FROM jobs WHERE phase='QUEUED' ORDER BY created_at,id")]
        queue = [{"id": j["id"], "requestId": j["requestId"], "title": j["promotedIdea"]["title"],
                  "phase": j["phase"], "createdAt": j["createdAt"]} for j in queued[:20]]
        value = {"schemaVersion": "cct.owner_work.v1", "ownerUid": self.identity["ownerUid"],
                 "conversationId": self.dialogue["conversationId"], "updatedAt": stamp(),
                 "scope": "PUBLIC_RESEARCH_PRIVATE_REPORT", "financialExecutionEnabled": False,
                 "trigger": "OWNER_PROMOTION", "maxConcurrentJobs": 1, "queue": queue,
                 "queuedCount": len(queued), "maxSourcesPerJob": MAX_SOURCES,
                 "maxModelCallsPerJob": 2, "reason": reason or (job or {}).get("reason", "Waiting for a supported work idea."),
                 "phase": phase or (job or {}).get("phase", "WAITING"), "job": None}
        if job:
            projected = {k: v for k, v in job.items() if k not in {"discovery", "sources"}}
            projected["sources"] = [{k: v for k, v in source.items() if k not in {"text", "receipt"}} for source in job["sources"]]
            projected["ownerEvidence"] = [a for a in job["discovery"]["history"]
                                           if a["questionId"] in job.get("selection", {}).get("sourceAnswerIds", [])]
            value["job"] = projected
        self.flush_receipts()
        value = publish_projection(self.gateway, "cct_owner_work", "current", value)
        return value

    def model(self, stage, job):
        from .owner_work_model import validate
        self.gate()
        job.update(phase="SELECTING" if stage == "select" else "SYNTHESIZING",
                   modelCalls=job["modelCalls"] + 1)
        if job["modelCalls"] > 2:
            raise ValueError("WORK_MODEL_BUDGET")
        self.save(job)
        self.publish(job)
        data = {"stage": stage, "discovery": job["discovery"], "catalog": list(CATALOG)}
        if job.get("promotedIdea"):
            data["promotedIdea"] = job["promotedIdea"]
        if stage == "synthesize":
            data.update(selection=job["selection"], calculations=job["calculations"],
                        sources=[{k: v for k, v in s.items() if k != "receipt"} for s in job["sources"]])
        # Provider interpreter uses only this profile. Never execute model text.
        env = {k: v for k, v in os.environ.items() if k in {"HOME", "PATH", "LANG", "SSL_CERT_FILE", "SSL_CERT_DIR", "PYTHONPATH"}}
        env["HERMES_HOME"] = str(self.home)
        script = Path(__file__).with_name("owner_work_model.py")
        result = subprocess.run([self.dialogue["modelPython"], str(script)], input=dumps(data),
                                capture_output=True, text=True, timeout=110, env=env)
        if result.returncode:
            try:
                code = json_object(result.stderr).get("errorCode")
            except (ValueError, TypeError, AttributeError):
                code = None
            raise RuntimeError(code if code in {"WORK_NO_SUITABLE_SOURCE", "WORK_PROMOTED_IDEA_CHANGED", "WORK_QUOTE_UNSUPPORTED"} else "WORK_MODEL_FAILED")
        if len(result.stdout.encode()) > 100_000:
            raise RuntimeError("WORK_MODEL_FAILED")
        output = json_object(result.stdout)
        validate(output, data)
        return output

    def flush_receipts(self):
        """Retry projections, never effects; a failed publication cannot lose a claim."""
        for row in self.db.execute("SELECT payload FROM jobs ORDER BY created_at,id").fetchall():
            job = json_object(row[0])
            if not job.get("requestId"):
                continue
            receipt = {"schemaVersion": "cct.work_receipt.v1", "ownerUid": self.identity["ownerUid"],
                       "requestId": job["requestId"], "jobId": job["id"], "phase": job["phase"],
                       "reason": job["reason"], "title": job["promotedIdea"]["title"], "updatedAt": job["updatedAt"]}
            key, digest = "receipt:" + job["id"], sha256(dumps(receipt).encode()).hexdigest()
            saved = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            if saved and saved[0] == digest:
                continue
            self.gateway.publish("cct_work_receipts", job["requestId"], receipt)
            with self.db:
                self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, digest))

    def accept_promotion(self, request_id, request, config):
        """Claim only an exact archived idea backed by genuine consumed answers."""
        fields = {"schemaVersion", "ownerUid", "conversationId", "turnId", "ideaIndex",
                  "idea", "scope", "state", "createdAt"}
        if (not isinstance(request, dict) or set(request) != fields
                or request["schemaVersion"] != "cct.work_request.v1"
                or request["ownerUid"] != self.identity["ownerUid"]
                or request["conversationId"] != self.dialogue["conversationId"]
                or request["scope"] != "PUBLIC_RESEARCH_PRIVATE_REPORT" or request["state"] != "PENDING"
                or not isinstance(request["turnId"], str) or not re.fullmatch(r"q-[0-9a-f]{32}", request["turnId"])
                or type(request["ideaIndex"]) is not int or not 0 <= request["ideaIndex"] < 4
                or request_id != f"promote-{request['turnId'][2:]}-{request['ideaIndex']}"):
            raise ValueError("WORK_PROMOTION_INVALID")
        created = request["createdAt"]
        if not isinstance(created, datetime) or created.tzinfo is None or created > now() + timedelta(seconds=60):
            raise ValueError("WORK_PROMOTION_TIMESTAMP_INVALID")
        discovery = self.snapshot(request["turnId"])
        index = request["ideaIndex"]
        if (not discovery or index >= len(discovery["workIdeas"])
                or request["idea"] != discovery["workIdeas"][index]
                or created < datetime.fromisoformat(discovery["turnCreatedAt"])):
            raise ValueError("WORK_PROMOTION_EVIDENCE_MISMATCH")
        request_value = {**request, "createdAt": created.isoformat()}
        job_id = "work-" + sha256(dumps([self.identity["ownerUid"], self.dialogue["conversationId"], request_id]).encode()).hexdigest()[:24]
        prior = self.db.execute("SELECT payload FROM jobs WHERE id=?", (job_id,)).fetchone()
        if prior:
            job = json_object(prior[0])
            if job.get("promotionRequest") != request_value:
                raise ValueError("WORK_PROMOTION_CONFLICT")
            return job
        job = {"id": job_id, "requestId": request_id, "promotionRequest": request_value,
               "promotedIdea": request["idea"], "createdAt": created.isoformat(), "phase": "QUEUED",
               "reason": "Your exact idea is queued for public research and a private report.",
               "discovery": {**discovery, "workIdeas": [request["idea"]]},
               "sources": [], "modelCalls": 0, "webAttempts": 0, "authority": config["authorization"],
               "limits": {"sources": MAX_SOURCES, "bytesPerSource": MAX_BYTES, "modelCalls": 2,
                          "externalSpend": 0, "note": "Existing model/Firebase usage may consume account quota; no paid data purchases."}}
        self.save(job)
        return job

    def ingest_promotions(self, config):
        from google.cloud.firestore_v1.base_query import FieldFilter
        pending = self.gateway.db.collection("cct_work_requests").where(
            filter=FieldFilter("state", "==", "PENDING")).limit(20)
        for document in self.gateway.query(pending):
            request = document.to_dict()
            try:
                job = self.accept_promotion(document.id, request, config)
            except ValueError as error:
                self.gateway.publish("cct_work_requests", document.id,
                                     {**request, "state": "REJECTED", "reason": str(error)[:180]})
                continue
            self.flush_receipts()
            # A crash before acknowledgement safely rediscovers the same durable job.
            self.gateway.publish("cct_work_requests", document.id,
                                 {**request, "state": "RECEIVED", "jobId": job["id"]})

    def tick(self):
        latest = self.db.execute("SELECT payload FROM jobs WHERE phase!='QUEUED' ORDER BY created_at DESC LIMIT 1").fetchone()
        last = json_object(latest[0]) if latest else None
        try:
            config = self.gate()
        except RuntimeError as error:
            if str(error) != "WORK_PAUSED":
                raise
            return self.publish(last, "Paused. Saved promotions wait; no new research starts.", "PAUSED")
        self.ingest_promotions(config)
        row = self.db.execute("SELECT payload FROM jobs WHERE phase='QUEUED' ORDER BY created_at,id LIMIT 1").fetchone()
        if not row:
            return self.publish(last, "Promote an idea to start its research. Your discovery answers keep flowing; no daily research wait.")
        job = json_object(row[0])
        self.gate()
        job.update(phase="PLANNING", reason="Starting the exact idea you promoted. Public research only.")
        self.save(job)
        return self.execute(job, config)

    def resume_saved(self, job_id, after_fetch=False):
        """Explicit recovery: known saved plan or all fetched sources, no replay."""
        config = self.gate()
        row = self.db.execute("SELECT payload FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise ValueError("WORK_RESUME_NOT_FOUND")
        job = json_object(row[0])
        if job["phase"] != "BLOCKED" or job["modelCalls"] != 1 or not job.get("selection"):
            raise ValueError("WORK_RESUME_UNSAFE")
        expected = job["selection"]["sourceIds"]
        if after_fetch:
            if ([s["id"] for s in job["sources"]] != expected or job["webAttempts"] != len(expected)
                    or not job.get("effectChainValid")):
                raise ValueError("WORK_RESUME_RECEIPTS_INCOMPLETE")
            for source in job["sources"]:
                if source["ok"] and (source["sha256"] != sha256(source["receipt"]["web"]["content"].encode()).hexdigest()
                        or source["receipt"].get("success") is not True):
                    raise ValueError("WORK_RESUME_RECEIPT_MISMATCH")
        elif job["webAttempts"] != 0 or job["sources"]:
            raise ValueError("WORK_RESUME_UNSAFE")
        from .owner_work_model import validate
        validate(job["selection"], {"stage": "select", "discovery": job["discovery"], "catalog": list(CATALOG),
                                    **({"promotedIdea": job["promotedIdea"]} if job.get("promotedIdea") else {})})
        job.setdefault("recoveryNotes", []).append({"at": stamp(), "previousReason": job["reason"],
            "authority": config["authorization"], "action": "Explicit operator recovery; reuse saved selection and sources, never repeat GETs."})
        job["limits"]["bytesPerSource"] = MAX_BYTES
        self.save(job)
        return self.execute(job, config)

    def execute(self, job, config):
        job_id = job["id"]
        try:
            if not job.get("selection"):
                job["selection"] = self.model("select", job)
            job["executionPlan"] = job.get("executionPlan") or [{"action": "public_get", "sourceId": sid, "status": "PENDING"}
                                    for sid in job["selection"]["sourceIds"]] + [
                {"action": "synthesize_cited_report", "status": "PENDING"},
                {"action": "write_private_report", "status": "PENDING"}]
            job.update(phase="RESEARCHING", reason="Research plan saved; collecting public evidence.")
            self.save(job)
            self.publish(job)
            effect_path = self.directory / "effects.sqlite"
            if effect_path.is_symlink():
                raise ValueError("WORK_EFFECTS_SYMLINK")
            store = EventStore(effect_path)
            web = WorkWeb(store, self.identity["ownerUid"], config["authorization"])
            for sid in job["selection"]["sourceIds"]:
                if sid in {s["id"] for s in job["sources"]}:
                    continue
                self.gate()
                job["webAttempts"] += 1
                self.save(job)
                try:
                    source = web.fetch(job_id, job["selection"], sid)
                except Exception as error:
                    source = {**next(s for s in CATALOG if s["id"] == sid), "ok": False,
                              "errorType": type(error).__name__, "fetchedAt": stamp(),
                              "errorCode": getattr(error, "reason_code", "WORK_FETCH_UNAVAILABLE")}
                job["sources"].append(source)
                next(s for s in job["executionPlan"] if s.get("sourceId") == sid)["status"] = "COMPLETE" if source["ok"] else "UNAVAILABLE"
                self.save(job)
            job["effectChainValid"] = store.verify_chain()["valid"]
            if job["effectChainValid"] is not True:
                raise ValueError("WORK_RECEIPT_CHAIN_INVALID")
            if not any(s["ok"] for s in job["sources"]):
                raise RuntimeError("WORK_NO_RETRIEVED_EVIDENCE")
            job["calculations"] = calculations(job["sources"])
            job["report"] = self.model("synthesize", job)
            job["executionPlan"][-2]["status"] = "COMPLETE"
            job.update(phase="WRITING", reason="Cited report saved; writing private artifact.")
            self.save(job)
            self.gate()
            artifact = self.directory / f"{job_id}.md"
            content = report_markdown(job)
            private_file(artifact, content)
            job.update(artifactName=artifact.name, artifactSha256=sha256(content.encode()).hexdigest())
            job["executionPlan"][-1]["status"] = "COMPLETE"
            job.update(phase="COMPLETE", reason="Research and private report completed. Proposed next steps are not authorized or queued.")
            self.save(job)
        except Exception as error:
            job["errorCode"] = getattr(error, "reason_code", str(error)[:180])
            reason = ("The approved public-source catalog cannot support this idea yet. No substitute idea was researched."
                      if job["errorCode"] == "WORK_NO_SUITABLE_SOURCE" else
                      f"Stopped at bounded work boundary ({type(error).__name__}). Saved evidence retained; no automatic replay.")
            job.update(phase="BLOCKED", reason=reason)
            self.save(job)
            if isinstance(error, CloudBackoff):
                raise  # Keep saved work blocked; never retry its effects or publish into an outage.
        return self.publish(job)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("once", "run", "status", "resume-before-fetch", "resume-after-fetch"))
    parser.add_argument("--job-id")
    args = parser.parse_args(argv)
    if args.command.startswith("resume-") != bool(args.job_id):
        parser.error("--job-id is required only for explicit saved-stage recovery")
    home = Path(os.environ["HERMES_HOME"])
    if not home.is_absolute():
        raise ValueError("WORK_EXPLICIT_PROFILE_REQUIRED")
    directory = home / "owner-work"
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink():
        raise ValueError("WORK_DIRECTORY_SYMLINK")
    if args.command == "status":
        path = directory / "work.sqlite"
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            row = db.execute("SELECT payload FROM jobs ORDER BY created_at DESC LIMIT 1").fetchone()
            print(row[0] if row else "{}")
        return 0
    fd = os.open(directory / "work.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with closing(OwnerWork(home)) as worker:
            while True:
                try:
                    result = worker.resume_saved(args.job_id, args.command == "resume-after-fetch") if args.command.startswith("resume-") else worker.tick()
                    cloud_recovered(worker.gateway)
                    print(dumps({k: result[k] for k in ("phase", "reason", "updatedAt")}), flush=True)
                except Exception as error:
                    result = {"phase": "BLOCKED"}
                    print(dumps({"phase": "BLOCKED", "errorType": type(error).__name__,
                                 **cloud_status(worker.gateway)}), flush=True)
                if args.command != "run":
                    return int(result["phase"] == "BLOCKED")
                time.sleep(cloud_delay(worker.gateway, 60))


if __name__ == "__main__":
    raise SystemExit(main())
