"""Host-only, two-attempt public evidence adapter for private continuation.

Authority remains worker.gate(); producer input is only a cycle ID and a catalog
ID. Charge the existing worker.db BEFORE constructing/dispatching WorkWeb. Its
separate profile-private EventStore is only the ticket/transport receipt ledger,
not another delivery worker or budget. No constructor performs network I/O.

Successful results (including receipt.web.content) are UNTRUSTED factual source
material, never instructions, credentials, goal authority or permissions. The
bounded response is cached privately for durable idempotence; WorkWeb's original
producer_content_persisted=False describes its metadata-only transport events,
not this explicitly contentPersisted=True delivery cache. sha256 hashes the raw
UTF-8 response, while textSha256 hashes the HTML-stripped/truncated text.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
import math
from pathlib import Path
import re
from urllib.parse import urlsplit

from . import owner_work_web
from .cloud_backoff import CloudBackoff
from .mediation import ToolExecutionMediator
from .owner_delivery import regular
from .research import OPERATOR_WEB_VERIFIER_ID
from .store import EventStore, canonical_json


MAX_PER_24H = 2
WINDOW_SECONDS = 86_400
MAX_TEXT_CHARS = 18_000
MAX_RESULT_BYTES = 400_000
MAX_BYTES = owner_work_web.MAX_BYTES
TIMEOUT_MS = 10_000
_IDENTITY_KEYS = ("ownerUid", "projectId", "conversationId", "sourceHome", "authorization")
_CONFIG_KEYS = {"schemaVersion", "ownerUid", "projectId", "authorization", "sourceIds"}
_CYCLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_ERRORS = frozenset({
    "INVALID_CYCLE_ID", "SOURCE_NOT_ALLOWED", "PAUSED", "GATE_UNAVAILABLE",
    "IDENTITY_CHANGED", "CONTEXT_CHANGED", "CATALOG_CHANGED", "DAILY_CAP",
    "CYCLE_CAP", "INTERRUPTED", "FETCH_FAILED", "RECEIPT_INVALID", "STATE_UNAVAILABLE",
})


def _hash(value):
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _error(code):
    # No external/provider exception text or caller-supplied identifiers escapes.
    assert code in _ERRORS
    return {"ok": False, "error": "DELIVERY_RESEARCH_" + code}


class _Denied(Exception):
    def __init__(self, code):
        assert code in _ERRORS
        self.code = code
        super().__init__("DELIVERY_RESEARCH_" + code)


class ResearchDeferred(CloudBackoff):
    """Host cloud cooldown before this invocation claimed any new GET attempt."""


class DeliveryResearch:
    """Public API: catalog(), fetch(cycle_id, source_id), usage().

    Required worker interface: db (sqlite3.Connection), home (Path), config,
    identity, clock(), gate(). Optional builds.effective() supplies current owner
    caps. Use under the existing worker lock; BEGIN IMMEDIATE also prevents
    overspending/idempotence races between processes with separate connections.
    Interrupted claims are never retried, even after the rolling window expires.
    """

    def __init__(self, worker):
        self.worker = worker
        self.db = worker.db
        self._identity = canonical_json({key: worker.config[key] for key in _IDENTITY_KEYS})
        self._worker_identity = canonical_json(worker.identity)
        self._home = Path(worker.home)
        self._catalog_config = self._read_catalog_config()
        self._catalog = owner_work_web.select_catalog(
            self._catalog_config["sourceIds"] if self._catalog_config is not None else None)
        self._web = None
        self._store = None
        # Do not implicitly commit somebody else's work with executescript().
        if self.db.in_transaction:
            raise ValueError("DELIVERY_RESEARCH_STATE_UNAVAILABLE")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("""CREATE TABLE IF NOT EXISTS delivery_research_meta(
                key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS delivery_research_attempts(
                cycle_id TEXT NOT NULL, source_id TEXT NOT NULL, created REAL NOT NULL,
                snapshot TEXT NOT NULL, state TEXT NOT NULL, error TEXT NOT NULL,
                result TEXT, result_sha256 TEXT,
                PRIMARY KEY(cycle_id, source_id))""")
            self.db.execute("""CREATE INDEX IF NOT EXISTS delivery_research_created
                ON delivery_research_attempts(created)""")
            saved = self.db.execute("SELECT value FROM delivery_research_meta WHERE key='identity'").fetchone()
            binding = _hash([self._identity, self._worker_identity, str(self._home)])
            if saved and saved[0] != binding:
                raise ValueError("DELIVERY_RESEARCH_IDENTITY_CHANGED")
            self.db.execute("INSERT OR IGNORE INTO delivery_research_meta VALUES('identity', ?)", (binding,))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def _read_catalog_config(self):
        """Optional local host opt-in; no producer input, defaults or URL overrides."""
        path = self._home / "config/cct-owner-research.json"

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        try:
            try:
                raw = regular(path, 8000)
            except FileNotFoundError:
                return None
            config = json.loads(raw, object_pairs_hook=unique)
            if (type(config) is not dict or set(config) != _CONFIG_KEYS
                    or config["schemaVersion"] != "cct.owner_research.config.v1"
                    or any(config[k] != self.worker.config[k] for k in ("ownerUid", "projectId"))
                    or type(config["authorization"]) is not str
                    or not re.fullmatch(r"operator://[^\s]{1,240}", config["authorization"])
                    or type(config["sourceIds"]) is not list):
                raise ValueError("config")
            owner_work_web.select_catalog(config["sourceIds"])
            return config
        except Exception:
            raise ValueError("DELIVERY_RESEARCH_CONFIG_INVALID") from None

    def catalog(self):
        """Immutable tuple of immutable id/title/url mappings; no search input."""
        return self._catalog

    def _time(self):
        value = self.worker.clock()
        if type(value) not in (int, float) or not math.isfinite(value):
            raise _Denied("STATE_UNAVAILABLE")
        return value

    def usage(self):
        """Attempted and verified counts in the rolling 24h, including crashes."""
        row = self.db.execute("""SELECT count(*),
            coalesce(sum(CASE WHEN state='VERIFIED' THEN 1 ELSE 0 END), 0)
            FROM delivery_research_attempts WHERE created>?""", (self._time() - WINDOW_SECONDS,)).fetchone()
        return {"attempted": row[0], "verified": row[1], "maxPer24h": MAX_PER_24H}

    def _gate(self, expected=None):
        try:
            self.worker.gate()
            continuation = getattr(self.worker, "continuation", None)
            if continuation is not None:
                continuation._configuration(require=True)
        except CloudBackoff:
            raise
        except Exception as exc:
            message = str(exc)
            if message in {"DELIVERY_PAUSED", "DELIVERY_CONTINUATION_PAUSED"}:
                raise _Denied("PAUSED") from None
            if message == "DELIVERY_IDENTITY_CHANGED":
                raise _Denied("IDENTITY_CHANGED") from None
            raise _Denied("GATE_UNAVAILABLE") from None
        try:
            identity = canonical_json({key: self.worker.config[key] for key in _IDENTITY_KEYS})
            if (identity != self._identity
                    or canonical_json(self.worker.identity) != self._worker_identity
                    or Path(self.worker.home) != self._home or self.worker.db is not self.db):
                raise _Denied("IDENTITY_CHANGED")
            try:
                current = self._read_catalog_config()
                catalog = owner_work_web.select_catalog(current["sourceIds"] if current is not None else None)
                unchanged = current == self._catalog_config and catalog == self._catalog
            except Exception:
                unchanged = False
            if not unchanged or owner_work_web.MAX_BYTES != MAX_BYTES:
                raise _Denied("CATALOG_CHANGED")
            caps = self.worker.builds.effective() if hasattr(self.worker, "builds") else None
            context = {"config": self.worker.config, "identity": self.worker.identity,
                       "effectiveCaps": caps, "maxPublicGET": MAX_PER_24H}
            if self._catalog_config is not None:
                context["researchConfig"] = self._catalog_config
                context["researchCatalog"] = [dict(entry) for entry in self._catalog]
            snapshot = _hash(context)
            if expected is not None and expected != snapshot:
                raise _Denied("CONTEXT_CHANGED")
            return snapshot
        except _Denied:
            raise
        except Exception:
            raise _Denied("CONTEXT_CHANGED") from None

    def _claim(self, cycle_id, source_id, snapshot):
        if self.db.in_transaction:
            raise _Denied("STATE_UNAVAILABLE")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("""SELECT state,error,result,result_sha256,snapshot
                FROM delivery_research_attempts WHERE cycle_id=? AND source_id=?""",
                (cycle_id, source_id)).fetchone()
            if row:
                self.db.commit()
                return tuple(row)
            used = self.db.execute("SELECT count(*) FROM delivery_research_attempts WHERE created>?",
                                   (self._time() - WINDOW_SECONDS,)).fetchone()[0]
            if used >= MAX_PER_24H:
                raise _Denied("DAILY_CAP")
            lifetime = self.db.execute("SELECT count(*) FROM delivery_research_attempts WHERE cycle_id=?",
                                       (cycle_id,)).fetchone()[0]
            if lifetime >= MAX_PER_24H:
                raise _Denied("CYCLE_CAP")
            # The crash-safe default is terminal uncertainty, never a free retry.
            self.db.execute("""INSERT INTO delivery_research_attempts
                VALUES(?,?,?,?, 'INTERRUPTED', 'INTERRUPTED', NULL, NULL)""",
                (cycle_id, source_id, self._time(), snapshot))
            self.db.commit()
            return None
        except BaseException:
            self.db.rollback()
            raise

    def _transport(self):
        if self._web is None:
            directory = self._home / "owner-delivery"
            if directory.is_symlink() or any(p.is_symlink() for p in directory.parents):
                raise _Denied("STATE_UNAVAILABLE")
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            path = directory / "research-evidence.sqlite"
            if path.exists() or path.is_symlink():
                regular(path, 150_000_000)
            store = EventStore(path)
            path.chmod(0o600)
            # WorkWeb owns exact URL construction, DNS pinning, TLS, GET-only,
            # credential-free headers, redirect denial, byte/time bounds and
            # ticket mediation. Do not replace any transport method here.
            self._web = owner_work_web.WorkWeb(store, self.worker.config["ownerUid"],
                self.worker.config["authorization"], source_ids=tuple(entry["id"] for entry in self._catalog))
            self._store = store
        return self._web

    def _plan(self, cycle_id, source_id, snapshot):
        return {"schemaVersion": "cct.owner_delivery.research_plan.v1", "cycleId": cycle_id,
                "sourceId": source_id, "authoritySnapshotSha256": snapshot,
                "maxPer24h": MAX_PER_24H, "maxBytes": MAX_BYTES, "timeoutMs": TIMEOUT_MS}

    def _job_id(self, cycle_id):
        return "delivery-research-" + _hash([self._identity, cycle_id])[:32]

    def _verify(self, value, cycle_id, source_id, snapshot):
        """Independently re-run WorkWeb's actual registered receipt verifier."""
        try:
            if not isinstance(value, dict) or len(canonical_json(value).encode()) > MAX_RESULT_BYTES:
                raise ValueError("shape")
            entry = next(item for item in self._catalog if item["id"] == source_id)
            job_id = self._job_id(cycle_id)
            ticket_id = job_id + "-" + source_id
            if (value.get("ok") is not True or value.get("id") != source_id
                    or value.get("title") != entry["title"] or value.get("url") != entry["url"]
                    or value.get("ticketId") != ticket_id):
                raise ValueError("binding")
            fetched = datetime.fromisoformat(value["fetchedAt"])
            if fetched.tzinfo is None:
                raise ValueError("timestamp")
            web_client = self._transport()
            assert self._store is not None
            if self._store.verify_chain()["valid"] is not True:
                raise ValueError("event chain")
            claims = [e for e in self._store.events("execution.ticket.consumed")
                      if e.payload.get("ticket_id") == ticket_id]
            if len(claims) != 1:
                raise ValueError("claim")
            event = claims[0]
            claim = event.payload
            expected = {"principal_id": self.worker.config["ownerUid"], "goal_id": job_id,
                        "plan_id": job_id, "plan_hash": _hash(self._plan(cycle_id, source_id, snapshot)),
                        "tool_name": "operator_web", "capability": "operator.web",
                        "scope": "operator/web/" + source_id, "stage": "public-research",
                        "verifier_id": OPERATOR_WEB_VERIFIER_ID, "idempotency_key": ticket_id,
                        "action_budget": 1, "byte_budget": MAX_BYTES, "value_budget_microunits": 0,
                        "dispatch_claimed": True, "ticket_consumed": True}
            if any(type(claim.get(k)) is not type(v) or claim[k] != v for k, v in expected.items()):
                raise ValueError("ticket binding")
            context = ToolExecutionMediator._verification_context({**claim, "event_id": event.event_id})
            receipt = value["receipt"]
            _, verification = web_client.adapter.outcome_verifiers().verify(OPERATOR_WEB_VERIFIER_ID, receipt, context)
            if not verification.verified or not verification.effect_observed:
                raise ValueError("verification")
            web = receipt["web"]
            body = web["content"].encode("utf-8")
            text = owner_work_web.page_text(web["content"], web["content_type"])
            if (not body or len(body) > MAX_BYTES or web["target_url"] != entry["url"]
                    or web["operation"] != ("search" if urlsplit(entry["url"]).query else "fetch")
                    or type(web["status_code"]) is not int or not 200 <= web["status_code"] <= 299
                    or type(web["duration_ms"]) is not int or not 0 <= web["duration_ms"] <= TIMEOUT_MS
                    or value["sha256"] != sha256(body).hexdigest()
                    or value["text"] != text[:MAX_TEXT_CHARS]
                    or value["textTruncated"] is not (len(text) > MAX_TEXT_CHARS)
                    or value["contentType"] != web["content_type"]):
                raise ValueError("content")
        except _Denied:
            raise
        except Exception:
            raise _Denied("RECEIPT_INVALID") from None

    def _finish(self, cycle_id, source_id, result, snapshot):
        encoded = canonical_json(result)
        checksum = sha256(encoded.encode()).hexdigest()
        if result["ok"]:
            assert self._store is not None
            self._store.append_once_result("owner.delivery_research.verified",
                self._job_id(cycle_id) + "-" + source_id,
                {"cycleIdSha256": _hash(cycle_id), "sourceId": source_id,
                 "snapshotSha256": snapshot, "resultSha256": checksum,
                 "provenance": "external_untrusted", "authorityGranted": False})
        with self.db:
            self.db.execute("""UPDATE delivery_research_attempts SET state=?,error=?,result=?,result_sha256=?
                WHERE cycle_id=? AND source_id=? AND state='INTERRUPTED'""",
                ("VERIFIED" if result["ok"] else "FAILED",
                 "" if result["ok"] else result["error"].removeprefix("DELIVERY_RESEARCH_"),
                 encoded, checksum, cycle_id, source_id))
        return result

    def _cached(self, row, cycle_id, source_id):
        state, error, encoded, checksum, snapshot = row
        if state != "VERIFIED":
            return _error(error if error in _ERRORS else "STATE_UNAVAILABLE")
        if not encoded or len(encoded.encode()) > MAX_RESULT_BYTES or sha256(encoded.encode()).hexdigest() != checksum:
            raise _Denied("RECEIPT_INVALID")
        try:
            result = json.loads(encoded)
        except Exception:
            raise _Denied("RECEIPT_INVALID") from None
        self._verify(result, cycle_id, source_id, snapshot)
        assert self._store is not None
        bindings = [e for e in self._store.events("owner.delivery_research.verified")
                    if e.payload.get("cycleIdSha256") == _hash(cycle_id) and e.payload.get("sourceId") == source_id]
        if len(bindings) != 1 or bindings[0].payload.get("resultSha256") != checksum:
            raise _Denied("RECEIPT_INVALID")
        return result

    def fetch(self, cycle_id, source_id):
        """Return a verified bounded UNTRUSTED receipt or {ok: False, error: code}.

        A BaseException/host crash deliberately propagates, leaving the already
        committed attempt charged and permanently non-retryable. Ordinary errors
        are fixed codes; failed, paused-after-GET and interrupted attempts count.
        ResearchDeferred preserves a typed cloud deadline ONLY if this call has
        not claimed a new attempt. Charged cloud failures remain terminal errors.
        """
        if type(cycle_id) is not str or not _CYCLE.fullmatch(cycle_id):
            return _error("INVALID_CYCLE_ID")
        if type(source_id) is not str or source_id not in {entry["id"] for entry in self._catalog}:
            return _error("SOURCE_NOT_ALLOWED")
        claimed = False
        snapshot = None
        try:
            snapshot = self._gate()
            cached = self._claim(cycle_id, source_id, snapshot)
            if cached is not None:
                result = self._cached(cached, cycle_id, source_id)
                self._gate(snapshot)
                return result
            claimed = True
            web = self._transport()
            self._gate(snapshot)  # Charge is already durable, gate at dispatch.
            try:
                value = web.fetch(self._job_id(cycle_id), self._plan(cycle_id, source_id, snapshot), source_id)
            except Exception:
                raise _Denied("FETCH_FAILED") from None
            finally:
                # Also hold evidence on failed transport, owner pause or read outage.
                self._gate(snapshot)
            self._verify(value, cycle_id, source_id, snapshot)
            value = {**value, "textTrust": "UNTRUSTED", "provenance": "external_untrusted",
                     "authorityGranted": False, "eligibleForGoalAuthority": False, "contentPersisted": True,
                     "textSha256": sha256(value["text"].encode()).hexdigest()}
            if len(canonical_json(value).encode()) > MAX_RESULT_BYTES:
                raise _Denied("RECEIPT_INVALID")
            self._gate(snapshot)
            return self._finish(cycle_id, source_id, value, snapshot)
        except Exception as exc:
            if isinstance(exc, CloudBackoff) and not claimed:
                raise ResearchDeferred(exc.receipt) from None
            code = ("GATE_UNAVAILABLE" if isinstance(exc, CloudBackoff) else
                    exc.code if isinstance(exc, _Denied) else "STATE_UNAVAILABLE")
            result = _error(code)
            if claimed:
                try:
                    self._finish(cycle_id, source_id, result, snapshot)
                except Exception:
                    return _error("STATE_UNAVAILABLE")
            return result
