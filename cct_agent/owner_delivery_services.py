"""Host-owned, target-bound service delivery. No model-created authority.

Reuses the canonical Firebase gateway, execution-ticket authority/kill switch,
owner-workspace validator and DNS-pinned HTTPS transport. The local journal is
an effect/readback journal, NOT an additional permission or ticket issuer.
Import and construction never perform network requests. See OWNER_DELIVERY_SERVICES.md.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import fcntl
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import stat
from typing import Any

from .execution_tickets import ExecutionTicket, ExecutionTicketAuthority, GlobalKillSwitch, TicketAuthorityDenied
from .owner_connection import FirebaseOwnerGateway
from .owner_workspace import project_owner_workspace
from .research import _PinnedHTTPSConnection
from .store import canonical_json

MAX_RESPONSE_BYTES = 262_144
MAX_ISSUE_BODY_BYTES = 16_384
POLICY_FILE = "service-policy.json"
NOTIFICATION_COLLECTION = "cct_owner_messages"
_POLICY_FLAGS = ("githubReadEnabled", "githubIssueCreateEnabled", "financialExecutionEnabled")
_ID = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,119}"
_LOGIN = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
_REPO = rf"{_LOGIN}/[A-Za-z0-9_][A-Za-z0-9_.-]{{0,99}}"
_SECRET = re.compile(r"-----BEGIN .*PRIVATE KEY-----|\b(?:gh[pousr]_|github_pat_|sk-)[A-Za-z0-9_-]{16,}")


class ServiceDenied(PermissionError):
    """Only fixed host reason codes cross the diagnostic boundary."""
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _hash(value: Any) -> str:
    return sha256(canonical_json(value).encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _match(value: Any, pattern: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ServiceDenied("SERVICE_ARGUMENT_INVALID")
    return value


def _positive(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= 2**53 - 1:
        raise ServiceDenied("SERVICE_ARGUMENT_INVALID")
    return value


def _json(raw: str | bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
        if type(value) is not dict:
            raise ValueError("not an object")
        return value
    except (ValueError, TypeError, RecursionError):
        raise ServiceDenied("SERVICE_JSON_INVALID") from None


def _request_json(host: str, method: str, path: str, *, token: str | None = None,
                  payload: dict | None = None) -> dict:
    """One pinned HTTPS attempt: no redirects, netrc, proxies or hidden retries."""
    if host not in {"api.github.com", "api.kraken.com"} or method not in {"GET", "POST"}:
        raise ServiceDenied("SERVICE_HTTP_TARGET_DENIED")
    if host == "api.kraken.com" and (method != "GET" or path != "/0/public/Ticker?pair=XBTUSD" or token is not None):
        raise ServiceDenied("SERVICE_HTTP_TARGET_DENIED")
    if host == "api.github.com":
        pattern = rf"(?:/user|/repos/{_REPO}(?:/issues(?:/[1-9][0-9]{{0,15}})?)?)"
        if not re.fullmatch(pattern, path) or (method == "POST" and not path.endswith("/issues")):
            raise ServiceDenied("SERVICE_HTTP_TARGET_DENIED")
    connection = None
    try:
        addresses = set()
        for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP):
            address = ipaddress.ip_address(row[4][0])
            if not address.is_global:
                raise ServiceDenied("SERVICE_SSRF_ADDRESS_DENIED")
            addresses.add(address.compressed)
        if not addresses:
            raise ServiceDenied("SERVICE_DNS_UNAVAILABLE")
        connection = _PinnedHTTPSConnection(host, 443, pinned_address=sorted(addresses)[0],
                                             timeout=15, context=ssl.create_default_context())
        headers = {"Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": "CCT-owner-services/1"}
        if token is not None:
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", token):
                raise ServiceDenied("SERVICE_CREDENTIAL_INVALID")
            headers["Authorization"] = "Bearer " + token
        if host == "api.github.com":
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        body = canonical_json(payload).encode() if payload is not None else None
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        # Never follow a provider URL, including a redirect on an authenticated GET.
        expected_status = 201 if method == "POST" else 200
        if response.status != expected_status:
            raise ServiceDenied("SERVICE_HTTP_STATUS_REJECTED")
        if response.getheader("Content-Type", "").split(";", 1)[0].lower() != "application/json":
            raise ServiceDenied("SERVICE_HTTP_CONTENT_TYPE_REJECTED")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ServiceDenied("SERVICE_HTTP_ENCODING_REJECTED")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ServiceDenied("SERVICE_HTTP_RESPONSE_TOO_LARGE")
        return _json(raw)
    except ServiceDenied:
        raise
    except Exception:
        raise ServiceDenied("SERVICE_NETWORK_UNAVAILABLE") from None
    finally:
        if connection is not None:
            connection.close()


@dataclass(frozen=True)
class GitHubIssueCreate:
    operation_id: str
    title: str
    body: str

    def __post_init__(self):
        _match(self.operation_id, _ID)
        if (not isinstance(self.title, str) or not self.title.strip() or len(self.title) > 256
                or any(ord(c) < 32 for c in self.title)
                or not isinstance(self.body, str) or len(self.body.encode()) > MAX_ISSUE_BODY_BYTES
                or any(ord(c) < 32 and c not in "\n\r\t" for c in self.body)):
            raise ServiceDenied("SERVICE_ISSUE_CONTENT_INVALID")
        if _SECRET.search(self.title + "\n" + self.body):
            raise ServiceDenied("SERVICE_SECRET_CONTENT_REJECTED")


@dataclass(frozen=True)
class PaymentCommand:
    operation_id: str
    provider: str
    account_id: str
    payee_id: str
    currency: str
    amount_microunits: int

    def __post_init__(self):
        for key in ("operation_id", "provider", "account_id", "payee_id"):
            _match(getattr(self, key), _ID)
        _match(self.currency, r"[A-Z]{3}")
        _positive(self.amount_microunits)


class GitHubServiceDriver:
    """Concrete provider; instantiate only from host-owned target configuration.

    Not a tool surface: the dispatcher is the mandatory policy/ticket boundary.
    No credential value or URL is accepted from a task/command.
    """
    def __init__(self, target: dict):
        fields = {"accountLogin", "accountId", "repository", "repositoryId"}
        if type(target) is not dict or set(target) != fields:
            raise ServiceDenied("SERVICE_GITHUB_CONFIG_INVALID")
        _match(target["accountLogin"], _LOGIN)
        _match(target["repository"], _REPO)
        _positive(target["accountId"])
        _positive(target["repositoryId"])
        self.target = deepcopy(target)
        self.repo_path = "/repos/" + target["repository"]

    @staticmethod
    def configured_credential() -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9_-]{1,512}", os.environ.get("CCT_GITHUB_TOKEN", "")))

    def request(self, method, path, payload=None):
        token = os.environ.get("CCT_GITHUB_TOKEN", "")
        if not self.configured_credential():
            raise ServiceDenied("SERVICE_GITHUB_CREDENTIAL_MISSING")
        return _request_json("api.github.com", method, path, token=token, payload=payload)

    def identity(self) -> dict:
        value = self.request("GET", "/user")
        if (type(value.get("id")) is not int or value["id"] != self.target["accountId"]
                or value.get("login") != self.target["accountLogin"]):
            raise ServiceDenied("SERVICE_GITHUB_ACCOUNT_MISMATCH")
        return {"accountId": value["id"], "accountLogin": value["login"]}

    def repository(self) -> None:
        value = self.request("GET", self.repo_path)
        if (type(value.get("id")) is not int or value["id"] != self.target["repositoryId"]
                or value.get("full_name") != self.target["repository"] or value.get("has_issues") is not True):
            raise ServiceDenied("SERVICE_GITHUB_REPOSITORY_MISMATCH")

    def read_issue(self, number: int) -> dict:
        _positive(number)
        value = self.request("GET", self.repo_path + "/issues/" + str(number))
        expected_url = "https://api.github.com" + self.repo_path
        if (value.get("number") != number or type(value.get("number")) is not int
                or value.get("url") != expected_url + "/issues/" + str(number)
                or value.get("repository_url") != expected_url or "pull_request" in value
                or type(value.get("id")) is not int or value["id"] < 1
                or not isinstance(value.get("title"), str) or len(value["title"]) > 256
                or (value.get("body") is not None and not isinstance(value.get("body"), str))
                or len((value.get("body") or "").encode()) > 65_536
                or value.get("state") not in {"open", "closed"}):
            raise ServiceDenied("SERVICE_GITHUB_ISSUE_TARGET_MISMATCH")
        return {key: value.get(key) for key in ("id", "number", "title", "body", "state", "user")}

    def create_issue(self, command: GitHubIssueCreate) -> int:
        value = self.request("POST", self.repo_path + "/issues", {"title": command.title, "body": command.body})
        number = _positive(value.get("number"))
        if value.get("url") != "https://api.github.com" + self.repo_path + "/issues/" + str(number):
            raise ServiceDenied("SERVICE_GITHUB_ISSUE_TARGET_MISMATCH")
        return number


class KrakenPublicQuoteDriver:
    """One public BTC/USD ticker snapshot. No key, account, order or execution."""
    @staticmethod
    def read() -> dict:
        value = _request_json("api.kraken.com", "GET", "/0/public/Ticker?pair=XBTUSD")
        try:
            if value.get("error") != [] or set(value["result"]) != {"XXBTZUSD"}:
                raise ValueError("schema")
            ticker = value["result"]["XXBTZUSD"]
            prices = {}
            for label, key in (("ask", "a"), ("bid", "b"), ("last", "c")):
                raw = ticker[key][0]
                if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{1,12}(?:\.[0-9]{1,12})?", raw):
                    raise ValueError("price")
                decimal = Decimal(raw)
                if not decimal.is_finite() or decimal <= 0:
                    raise ValueError("price")
                prices[label] = raw
            if Decimal(prices["bid"]) > Decimal(prices["ask"]):
                raise ValueError("spread")
        except (KeyError, IndexError, TypeError, ValueError, InvalidOperation):
            raise ServiceDenied("SERVICE_QUOTE_RESPONSE_INVALID") from None
        return {"provider": "kraken", "instrument": "BTC/USD", "pair": "XBTUSD", **prices,
                "observedAt": _now().isoformat(), "providerTimestamp": None,
                "executable": False, "accountEligibilityVerified": False,
                "source": "https://api.kraken.com/0/public/Ticker?pair=XBTUSD"}


class ServiceDispatcher:
    """Host-only integration surface. Constructor config is never model output.

    ``ticket_authority`` is an existing host engine, not a JSON path or a grant.
    Public/private issue operations consume that engine's exact durable ticket.
    """
    def __init__(self, config: dict, state_dir: Path, gateway=None, *,
                 ticket_authority: ExecutionTicketAuthority | None = None):
        if type(config) is not dict:
            raise ServiceDenied("SERVICE_CONFIG_INVALID")
        self.project_id = _match(config.get("projectId"), r"[a-z][a-z0-9-]{5,50}")
        self.owner_uid = _match(config.get("ownerUid"), r"[A-Za-z0-9_-]{1,128}")
        options = deepcopy(config.get("services", {}))
        if type(options) is not dict or set(options) - {"ownerNotificationsEnabled", "publicQuotesEnabled", "github"}:
            raise ServiceDenied("SERVICE_CONFIG_INVALID")
        for field in ("ownerNotificationsEnabled", "publicQuotesEnabled"):
            if type(options.get(field, False)) is not bool:
                raise ServiceDenied("SERVICE_CONFIG_INVALID")
        self.options = options
        self.github = GitHubServiceDriver(options["github"]) if "github" in options else None
        if ticket_authority is not None and not isinstance(ticket_authority, ExecutionTicketAuthority):
            raise ServiceDenied("SERVICE_TICKET_AUTHORITY_INVALID")
        self.authority = ticket_authority
        self.gateway = gateway
        self.root = Path(state_dir).absolute()
        if self.root.is_symlink() or self.root.resolve() != self.root:
            raise ServiceDenied("SERVICE_STATE_UNSAFE")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        metadata = self.root.stat()
        if metadata.st_uid != os.getuid() or not stat.S_ISDIR(metadata.st_mode):
            raise ServiceDenied("SERVICE_STATE_UNSAFE")
        self.root.chmod(0o700)
        self._root_identity = (metadata.st_dev, metadata.st_ino)
        self.path = self.root / "services.sqlite"
        self._prepare_file(self.path)
        self.identity = {"projectId": self.project_id, "ownerUid": self.owner_uid}
        self.binding = {**self.identity, "github": deepcopy(options.get("github"))}
        self._workspace_verified = False
        with self._locked(), self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS effects (id TEXT PRIMARY KEY, intent_sha256 TEXT NOT NULL,
                    payload TEXT NOT NULL, state TEXT NOT NULL, receipt TEXT);
                CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, binding_sha256 TEXT NOT NULL, value TEXT NOT NULL);
            """)
            existing = db.execute("SELECT value FROM identity WHERE id=1").fetchone()
            if existing and existing[0] != canonical_json(self.identity):
                raise ServiceDenied("SERVICE_STATE_IDENTITY_CHANGED")
            db.execute("INSERT OR IGNORE INTO identity VALUES(1,?)", (canonical_json(self.identity),))

    def _validate_root(self):
        metadata = self.root.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077 or (metadata.st_dev, metadata.st_ino) != self._root_identity):
            raise ServiceDenied("SERVICE_STATE_UNSAFE")

    def _prepare_file(self, path):
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            metadata = os.fstat(fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1 or metadata.st_mode & 0o077):
                raise ServiceDenied("SERVICE_STATE_UNSAFE")
        finally:
            os.close(fd)

    @contextmanager
    def _locked(self):
        self._validate_root()
        path = self.root / "services.lock"
        self._prepare_file(path)
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._validate_root()  # Revalidate after waiting for another dispatcher.
            yield
        finally:
            os.close(fd)

    @contextmanager
    def _db(self):
        self._validate_root()
        self._prepare_file(self.path)
        with closing(sqlite3.connect(self.path, timeout=30, isolation_level=None)) as db:
            db.execute("PRAGMA synchronous=FULL")
            yield db

    def _policy(self) -> dict:
        self._validate_root()
        path = self.root / POLICY_FILE
        fd = None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            metadata = os.fstat(fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in {0, os.getuid()}
                    or metadata.st_nlink != 1 or metadata.st_mode & 0o077 or metadata.st_size > 8192):
                raise ServiceDenied("SERVICE_ROOT_POLICY_INVALID")
            value = _json(os.read(fd, 8193))
            fields = {"schemaVersion", "projectId", "ownerUid", "authorization", *_POLICY_FLAGS}
            if (set(value) != fields or value["schemaVersion"] != "cct.owner_service_policy.v1"
                    or any(value[key] != expected for key, expected in self.identity.items())
                    or any(type(value[key]) is not bool for key in _POLICY_FLAGS)
                    or not isinstance(value["authorization"], str)
                    or not re.fullmatch(r"operator://[A-Za-z0-9._:/-]{1,180}", value["authorization"])):
                raise ServiceDenied("SERVICE_ROOT_POLICY_INVALID")
            return value
        except FileNotFoundError:
            return {key: False for key in _POLICY_FLAGS}
        except ServiceDenied:
            raise
        except Exception:
            raise ServiceDenied("SERVICE_ROOT_POLICY_INVALID") from None
        finally:
            if fd is not None:
                os.close(fd)

    def _github_host_gate(self, write=False):
        policy = self._policy()
        if not policy["githubReadEnabled"] or (write and not policy["githubIssueCreateEnabled"]):
            raise ServiceDenied("SERVICE_ROOT_POLICY_DISABLED")
        if self.github is None:
            raise ServiceDenied("SERVICE_GITHUB_TARGET_NOT_CONFIGURED")
        if not self.github.configured_credential():
            raise ServiceDenied("SERVICE_GITHUB_CREDENTIAL_MISSING")
        if self.authority:
            GlobalKillSwitch.ensure_clear(self.authority.store.events())

    def _github_gate(self, write=False):
        self._github_host_gate(write=write)
        # Saved workspace intent can only restrict separately granted authority.
        # Read and validate current canonical state for every credentialed stage;
        # never reuse notification/probe success or an earlier request's snapshot.
        view = self._workspace()
        requested = view["requestedPolicy"]
        permissions = requested["permissions"]
        if (view["preferences"]["learningEnabled"] is not True
                or requested["autonomyMode"] != "full"
                or requested["autonomyAcknowledged"] is not True):
            raise ServiceDenied("SERVICE_OWNER_WORKSPACE_PAUSED")
        required = ("credentialAccess", "workspaceRead")
        if write:
            required += ("workspaceWrite", "externalMessages")
        if any(permissions.get(key) is not True for key in required):
            raise ServiceDenied("SERVICE_OWNER_WORKSPACE_PERMISSION_DENIED")
        # The canonical workspace read itself can block on network I/O. Do not
        # retain host authority revoked while that read was in flight.
        self._github_host_gate(write=write)

    def _github_stage(self, ticket_id: str, intent: dict, *, write=False):
        """Recheck revocation, root policy and workspace before each provider call."""
        self._github_gate(write=write)
        self._ticket(ticket_id, intent, consume=False)

    def _gateway(self):
        if self.gateway is None:
            self.gateway = FirebaseOwnerGateway(self.project_id)
        project = getattr(getattr(self.gateway, "db", None), "project", None)
        if project is None:
            project = getattr(self.gateway, "project_id", None)
        if project is not None and project != self.project_id:
            raise ServiceDenied("SERVICE_FIREBASE_PROJECT_MISMATCH")
        return self.gateway

    def _workspace(self) -> dict:
        self._workspace_verified = False
        gateway = self._gateway()
        view = project_owner_workspace(gateway.read("cct_workspace"), owner_uid=self.owner_uid, observed_at=_now())
        if view["observationState"] != "OBSERVED":
            raise ServiceDenied("SERVICE_OWNER_WORKSPACE_INVALID")
        self._workspace_verified = True
        return view

    def _notification_gate(self) -> dict:
        """Private dashboard writes require current delivery controls.

        No standing status-notification exception while paused. External-message
        permission is separate: this route writes only the owner's dashboard.
        """
        if not self.options.get("ownerNotificationsEnabled", False):
            raise ServiceDenied("SERVICE_OWNER_NOTIFICATIONS_DISABLED")
        view = self._workspace()
        requested = view["requestedPolicy"]
        if (view["preferences"]["learningEnabled"] is not True
                or requested["autonomyMode"] != "full"
                or requested["autonomyAcknowledged"] is not True):
            raise ServiceDenied("SERVICE_OWNER_WORKSPACE_PAUSED")
        if any(requested["permissions"].get(key) is not True
               for key in ("workspaceRead", "workspaceWrite")):
            raise ServiceDenied("SERVICE_OWNER_WORKSPACE_PERMISSION_DENIED")
        if self.authority:
            GlobalKillSwitch.ensure_clear(self.authority.store.events())
        return view

    @staticmethod
    def _result(state: str, reason: str, **details) -> dict:
        return {"ok": state == "VERIFIED", "state": state, "readVerified": state == "VERIFIED",
                "reasonCode": reason, "effectReplayPermitted": False, **details}

    def _remember(self, capability: str, result: dict) -> dict:
        # Provider content/exception text never becomes stored evidence or authority.
        evidence = {key: result[key] for key in (
            "state", "readVerified", "reasonCode", "documentPath", "messageId", "issueNumber", "receiptSha256"
        ) if key in result}
        evidence["observedAt"] = _now().isoformat()
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO evidence VALUES(?,?,?)",
                       (capability, _hash(self.binding), canonical_json(evidence)))
        return result

    def _failure(self, capability: str, error: Exception, *, ambiguous=False) -> dict:
        code = error.reason_code if isinstance(error, (ServiceDenied, TicketAuthorityDenied)) else "SERVICE_PROVIDER_UNAVAILABLE"
        return self._remember(capability, self._result("UNKNOWN" if ambiguous else "BLOCKED", code))

    def capabilities(self) -> list[dict]:
        """No network, no claims, no ticket issuance. Historical proof != authority."""
        try:
            policy = self._policy()
            policy_error = None
        except ServiceDenied as error:
            policy = {key: False for key in _POLICY_FLAGS}
            policy_error = error.reason_code
        credential = self.github is not None and self.github.configured_credential()
        github_read = bool(credential and policy["githubReadEnabled"])
        stopped = bool(self.authority and GlobalKillSwitch(self.authority.store).status()["active"])
        if stopped:
            github_read = False
        specs = [
            ("owner.firestore.notify", True, self.options.get("ownerNotificationsEnabled", False), False, False),
            # A no-network capability snapshot cannot prove current workspace
            # permission. Identity, like ticketed routes, has no standing grant.
            ("github.identity", True, bool(credential), False, False),
            ("github.issue.read", True, bool(credential), False, True),
            ("github.issue.create", True, bool(credential), False, True),
            ("finance.public_quote", True, True, self.options.get("publicQuotesEnabled", False), False),
            ("finance.payment", False, False, False, True),
        ]
        with self._db() as db:
            records = {row[0]: _json(row[1]) for row in db.execute(
                "SELECT id,value FROM evidence WHERE binding_sha256=?", (_hash(self.binding),))}
        rows = []
        for identifier, implemented, configured, authorized, ticketed in specs:
            evidence = records.get(identifier)
            root = (github_read and (identifier != "github.issue.create" or policy["githubIssueCreateEnabled"])) if identifier.startswith("github.") else bool(authorized)
            reason = ("FINANCIAL_PROVIDER_TARGET_NOT_REGISTERED" if identifier == "finance.payment"
                      else "GLOBAL_KILL_SWITCH_ACTIVE" if stopped and identifier.startswith("github.")
                      else policy_error if policy_error and identifier.startswith("github.")
                      else "SERVICE_TARGET_OR_CREDENTIAL_NOT_CONFIGURED" if not configured
                      else "SERVICE_EXACT_TICKET_REQUIRED" if ticketed and root
                      else "SERVICE_WORKSPACE_RECHECK_REQUIRED" if identifier == "owner.firestore.notify"
                      else "SERVICE_ROOT_POLICY_DISABLED" if not root
                      else "SERVICE_WORKSPACE_RECHECK_REQUIRED" if identifier.startswith("github.")
                      else "SERVICE_SCOPED_READ_AUTHORIZED")
            rows.append({"id": identifier, "implemented": implemented, "configured": configured,
                         "authorized": bool(authorized), "readVerified": bool(evidence and evidence["readVerified"]),
                         "lastEvidence": evidence, "requiresExactTicket": ticketed,
                         "rootPolicyEnabled": bool(root), "ticketAuthorityBound": self.authority is not None,
                         "reasonCode": reason, "authorityFromTaskText": False})
        return rows

    def notify_owner(self, job: dict) -> dict:
        """Publish one stable, template-only private dashboard notification per job.

        Job prose/URLs/credentials are ignored. Job phase is a reported status,
        not this driver's verification of the deliverable. No Telegram send.
        """
        capability = "owner.firestore.notify"
        attempted = False
        try:
            if not self.options.get("ownerNotificationsEnabled", False):
                raise ServiceDenied("SERVICE_OWNER_NOTIFICATIONS_DISABLED")
            if type(job) is not dict:
                raise ServiceDenied("SERVICE_JOB_INVALID")
            job_id = _match(job.get("id"), _ID)
            phase = job.get("phase")
            if phase not in {"COMPLETE", "BLOCKED", "FAILED", "VERIFIED", "NOTIFYING"}:
                raise ServiceDenied("SERVICE_JOB_PHASE_INVALID")
            job_ref = _hash([self.identity, job_id])[:24]
            message_id = "msg-" + _hash(["owner-delivery-notification", self.identity, job_id])[:32]
            intent = _hash({"jobRef": job_ref, "phase": phase, **self.identity})
            document = f"projects/{self.project_id}/databases/(default)/documents/{NOTIFICATION_COLLECTION}/{message_id}"
            with self._locked(), self._db() as db:
                self._notification_gate()  # After waiting for competing dispatch.
                row = db.execute("SELECT intent_sha256,payload FROM effects WHERE id=?", (message_id,)).fetchone()
                if row:
                    if row[0] != intent:
                        raise ServiceDenied("SERVICE_NOTIFICATION_IDEMPOTENCY_CONFLICT")
                    payload = _json(row[1])
                    attempted = True
                else:
                    if self.gateway.read(NOTIFICATION_COLLECTION, message_id) is not None:
                        raise ServiceDenied("SERVICE_NOTIFICATION_TARGET_ALREADY_EXISTS")
                    # Target preflight can block on provider I/O. Recheck after
                    # it and bind the payload to this latest permission snapshot.
                    view = self._notification_gate()
                    created = _now()
                    payload = {"schemaVersion": "cct.owner_message.v1", **self.identity,
                               "messageId": message_id, "kind": "send", "state": "SENT",
                               "text": f"CCT delivery status: {phase} (worker-reported).\nOpen Delivery in your dashboard for the artifact and verification details.\nReference: {job_ref}",
                               "createdAt": created.isoformat(), "expiresAt": (created + timedelta(days=7)).isoformat(),
                               "revision": view["revision"], "policySha256": view["policySha256"],
                               "telegramMessageId": None, "answer": None, "deliveryChannel": "canonical_dashboard",
                               "reasonCode": "OWNER_DASHBOARD_DOCUMENT_WRITTEN", "jobRef": job_ref}
                    # Durable claim precedes the first possible outbound write.
                    db.execute("INSERT INTO effects VALUES(?,?,?,'CLAIMED',NULL)",
                               (message_id, intent, canonical_json(payload)))
                    attempted = True
                    try:
                        self.gateway.publish(NOTIFICATION_COLLECTION, message_id, payload)
                    except Exception:
                        pass  # A write exception may still have committed. Read, never resend.
                self._notification_gate()  # Recheck before retry/readback too.
                actual = self.gateway.read(NOTIFICATION_COLLECTION, message_id)
                verified = actual == payload
                receipt = self._result("VERIFIED" if verified else "UNKNOWN",
                                       "SERVICE_OWNER_DOCUMENT_READ_VERIFIED" if verified else "SERVICE_OWNER_DOCUMENT_READBACK_UNVERIFIED",
                                       messageId=message_id, documentPath=document, **self.identity,
                                       notificationOnly=True, receiptSha256=_hash(payload) if verified else None)
                db.execute("UPDATE effects SET state=?,receipt=? WHERE id=?",
                           (receipt["state"], canonical_json(receipt), message_id))
                return self._remember(capability, receipt)
        except Exception as error:
            return self._failure(capability, error, ambiguous=attempted)

    def github_identity(self) -> dict:
        try:
            self._github_gate()
            identity = self.github.identity()
            return self._remember("github.identity", self._result("VERIFIED", "SERVICE_GITHUB_IDENTITY_READ_VERIFIED", **identity, receiptSha256=_hash(identity)))
        except Exception as error:
            return self._failure("github.identity", error)

    def public_quote(self) -> dict:
        try:
            if not self.options.get("publicQuotesEnabled", False):
                raise ServiceDenied("SERVICE_PUBLIC_QUOTES_DISABLED")
            quote = KrakenPublicQuoteDriver.read()
            return self._remember("finance.public_quote", self._result("VERIFIED", "SERVICE_PUBLIC_QUOTE_READ_VERIFIED", quote=quote, receiptSha256=_hash(quote)))
        except Exception as error:
            return self._failure("finance.public_quote", error)

    def _intent(self, arguments: dict, *, write: bool, scope_suffix: str) -> dict:
        if self.github is None:
            raise ServiceDenied("SERVICE_GITHUB_TARGET_NOT_CONFIGURED")
        effect = "public" if write else "credential"
        material = {"schemaVersion": "cct.owner_service_intent.v1", "target": self.binding, **arguments}
        return {"toolName": "owner_github_issue_create" if write else "owner_github_issue_read",
                "capability": "operator." + effect,
                "scope": f"operator/{effect}/github/{self.github.target['repository']}/issues/{scope_suffix}",
                "arguments": material, "argumentsSha256": _hash(material),
                "byteBudget": MAX_RESPONSE_BYTES, "valueBudgetMicrounits": 0}

    def github_create_intent(self, command: GitHubIssueCreate) -> dict:
        if not isinstance(command, GitHubIssueCreate):
            raise ServiceDenied("SERVICE_TYPED_COMMAND_REQUIRED")
        return self._intent({"operation": "create_issue", "operationId": command.operation_id,
                             "title": command.title, "body": command.body}, write=True,
                            scope_suffix="create/" + command.operation_id)

    def github_read_intent(self, number: int) -> dict:
        number = _positive(number)
        return self._intent({"operation": "get_issue", "issueNumber": number}, write=False, scope_suffix=str(number))

    def _ticket(self, ticket_id: str, intent: dict, *, consume: bool) -> ExecutionTicket:
        _match(ticket_id, r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}")
        if self.authority is None:
            raise ServiceDenied("SERVICE_TICKET_AUTHORITY_NOT_BOUND")
        events = self.authority.store.events()
        issued = self.authority._issued_event(events, ticket_id)
        if issued is None:
            raise TicketAuthorityDenied("UNKNOWN_TICKET")
        ticket = ExecutionTicket.from_payload(issued.payload["ticket"])
        if ticket.tool_name != intent["toolName"]:
            raise TicketAuthorityDenied("TICKET_TOOL_MISMATCH")
        if ticket.arguments_sha256 != intent["argumentsSha256"]:
            raise TicketAuthorityDenied("TICKET_ARGUMENTS_MISMATCH")
        if ticket.principal_id != self.owner_uid or ticket.scope != intent["scope"] or ticket.capability != intent["capability"]:
            raise ServiceDenied("SERVICE_TICKET_TARGET_BINDING_MISMATCH")
        if ticket.action_budget != 1 or ticket.byte_budget < intent["byteBudget"] or ticket.value_budget_microunits != 0:
            raise ServiceDenied("SERVICE_TICKET_BUDGET_MISMATCH")
        if self.authority._revoked(events, ticket_id):
            raise TicketAuthorityDenied("TICKET_REVOKED")
        self.authority._validate_live(ticket, events)
        if consume:
            self.authority.consume(ticket_id=ticket_id, tool_name=intent["toolName"], arguments_sha256=intent["argumentsSha256"])
        return ticket

    def github_get_issue(self, number: int, *, ticket_id: str) -> dict:
        capability = "github.issue.read"
        try:
            intent = self.github_read_intent(number)
            with self._locked():
                self._github_gate()
                self._ticket(ticket_id, intent, consume=True)
                self._github_stage(ticket_id, intent)
                self.github.identity()
                self._github_stage(ticket_id, intent)
                self.github.repository()
                # The ticket may expire while the preflight network reads are in flight.
                self._github_stage(ticket_id, intent)
                issue = self.github.read_issue(number)
                receipt = self._result("VERIFIED", "SERVICE_GITHUB_ISSUE_READ_VERIFIED", issue=issue,
                                       issueNumber=number, contentTrusted=False, authorityGranted=False,
                                       receiptSha256=_hash(issue))
                return self._remember(capability, receipt)
        except Exception as error:
            return self._failure(capability, error)

    def github_create_issue(self, command: GitHubIssueCreate, *, ticket_id: str) -> dict:
        capability = "github.issue.create"
        attempted = False
        effect_id = None
        try:
            intent = self.github_create_intent(command)
            effect_id = "github-create-" + _hash([self.identity, command.operation_id])
            with self._locked(), self._db() as db:
                self._github_gate(write=True)
                self._ticket(ticket_id, intent, consume=False)
                prior = db.execute("SELECT intent_sha256,state,receipt FROM effects WHERE id=?", (effect_id,)).fetchone()
                if prior:
                    if prior[0] != intent["argumentsSha256"]:
                        raise ServiceDenied("SERVICE_OPERATION_IDEMPOTENCY_CONFLICT")
                    # Includes a crash after claim but before POST. Never silently recover by POST.
                    if prior[2] is None:
                        return self._remember(capability, self._result("UNKNOWN", "SERVICE_PRIOR_EFFECT_AMBIGUOUS"))
                    receipt = _json(prior[2])
                    if prior[1] == "VERIFIED":
                        self._github_stage(ticket_id, intent, write=True)
                        self.github.identity()
                        self._github_stage(ticket_id, intent, write=True)
                        self.github.repository()
                        self._github_stage(ticket_id, intent, write=True)
                        actual = self.github.read_issue(receipt["issueNumber"])
                        self._verify_created(actual, command)
                        receipt["receiptSha256"] = _hash(actual)
                    return self._remember(capability, receipt)
                self._ticket(ticket_id, intent, consume=True)
                # No raw public content or token in durable pre-dispatch storage.
                db.execute("INSERT INTO effects VALUES(?,?,?,'CLAIMED',NULL)",
                           (effect_id, intent["argumentsSha256"], canonical_json({"ticketId": ticket_id})))
                self._github_stage(ticket_id, intent, write=True)
                self.github.identity()
                self._github_stage(ticket_id, intent, write=True)
                self.github.repository()
                self._github_stage(ticket_id, intent, write=True)
                attempted = True
                number = self.github.create_issue(command)
                # Save exact returned target before readback for offline/manual reconciliation.
                db.execute("UPDATE effects SET payload=? WHERE id=?", (canonical_json({"ticketId": ticket_id, "issueNumber": number}), effect_id))
                self._github_stage(ticket_id, intent, write=True)
                actual = self.github.read_issue(number)
                self._verify_created(actual, command)
                receipt = self._result("VERIFIED", "SERVICE_GITHUB_ISSUE_CREATE_READ_VERIFIED", issueNumber=number,
                                       url=f"https://github.com/{self.github.target['repository']}/issues/{number}",
                                       ticketId=ticket_id, receiptSha256=_hash(actual))
                db.execute("UPDATE effects SET state='VERIFIED',receipt=? WHERE id=?", (canonical_json(receipt), effect_id))
                return self._remember(capability, receipt)
        except Exception as error:
            result = self._failure(capability, error, ambiguous=attempted)
            # Claim is durable even when transport/verification fails. No attempt is retried.
            if effect_id is not None:
                with self._db() as db:
                    db.execute("UPDATE effects SET state=?,receipt=? WHERE id=? AND state='CLAIMED'",
                               (result["state"], canonical_json(result), effect_id))
            return result

    def _verify_created(self, issue: dict, command: GitHubIssueCreate):
        user = issue.get("user")
        if (issue.get("title") != command.title or (issue.get("body") or "") != command.body
                or not isinstance(user, dict) or user.get("id") != self.github.target["accountId"]
                or user.get("login") != self.github.target["accountLogin"]):
            raise ServiceDenied("SERVICE_GITHUB_CREATE_READBACK_MISMATCH")

    def execute_payment(self, command: PaymentCommand, *, ticket_id: str) -> dict:
        """Fail closed: existing operator_finance contains only a local fake driver.

        This is an honest blocked interface, NOT a live monetary adapter. A real
        registered provider/account/payee, budgets and independent order readback
        must be integrated with OperatorFinancialEngine before this can execute.
        """
        try:
            if not isinstance(command, PaymentCommand):
                raise ServiceDenied("SERVICE_TYPED_COMMAND_REQUIRED")
            _match(ticket_id, r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}")
            if not self._policy()["financialExecutionEnabled"]:
                raise ServiceDenied("FINANCIAL_ROOT_POLICY_DISABLED")
            raise ServiceDenied("FINANCIAL_PROVIDER_TARGET_NOT_REGISTERED")
        except Exception as error:
            return self._failure("finance.payment", error)

    def probe(self) -> dict:
        """Opt-in safe network reads only; never create a notification or issue."""
        results = {}
        try:
            self._workspace()
            results["owner.firestore.notify"] = self._result("VERIFIED", "SERVICE_OWNER_WORKSPACE_READ_VERIFIED", notificationReadVerified=False)
            # Connection proof is not notification write/readback proof.
        except Exception as error:
            results["owner.firestore.notify"] = self._failure("owner.firestore.notify", error)
        results["github.identity"] = self.github_identity()
        results["finance.public_quote"] = self.public_quote()
        return {"schemaVersion": "cct.owner_service_probe.v1", **self.identity, "results": results,
                "capabilities": self.capabilities(), "financialExecutionEnabled": False,
                "publicEffectsAttempted": False, "notificationAttempted": False}
