"""Outbound-only Firebase bridge for the CCTAE administrative dashboard.

Firebase stores owner-authenticated requests and privacy-minimized projections. This
process remains the only component that opens the canonical local event store. It
creates previews, consumes exact confirmations, applies one bounded administrative
state change, and publishes canonical readback receipts.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import socket
import stat
import tempfile
import time
from typing import Any, Callable, Mapping, Protocol

from .capabilities import CapabilityRegistry
from .cloud_backoff import CloudBackoff, CloudCircuit, CloudErrorPolicy
from .cloud_projection import ProjectionCache
from .dashboard import build_dashboard_snapshot
from .dashboard_controls import (
    CONTROL_ACTION,
    CONTROL_CAPABILITY,
    MAX_CONFIRMATION_SECONDS,
    MAX_SESSION_SECONDS,
    DashboardControlDenied,
    DashboardControlService,
    DashboardSessionAuthority,
    OperatorBootstrap,
)
from .owner_workspace import project_owner_workspace
from .store import EventStore, canonical_json


CONFIG_SCHEMA = "cct.firebase_bridge.config.v1"
REQUEST_SCHEMA = "cct.firebase_control_request.v1"
DASHBOARD_SCHEMA = "cct.firebase_dashboard.v1"
RECEIPT_SCHEMA = "cct.firebase_control_receipt.v1"
BRIDGE_STATUS_SCHEMA = "cct.firebase_bridge.status.v1"
AUTHORIZATION_SCHEMA = "cct.firebase_control_authorization.v1"
AUTHORIZATION_EVENT = "firebase.control_request.authorized"
MAX_SNAPSHOT_BYTES = 512 * 1024
MAX_REQUESTS_PER_TICK = 10
MIN_POLL_SECONDS = 60
FIRESTORE_RPC_TIMEOUT_SECONDS = 10.0
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_REQUEST_ID = re.compile(r"^req-[A-Za-z0-9_-]{16,80}$")
_PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ID_TOKEN = re.compile(
    r"^[A-Za-z0-9_-]{10,1024}\.[A-Za-z0-9_-]{10,6144}\.[A-Za-z0-9_-]{10,1024}$"
)


class BridgeRequestDenied(PermissionError):
    """Fail-closed request rejection with one bounded public reason code."""

    def __init__(self, reason_code: str) -> None:
        if not isinstance(reason_code, str) or not _IDENTIFIER.fullmatch(reason_code):
            reason_code = "FIREBASE_BRIDGE_REQUEST_DENIED"
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class FirebaseBridgeConfig:
    project_id: str
    database: Path
    owner_email: str
    owner_uid: str | None
    principal_id: str
    poll_seconds: int
    request_ttl_seconds: int
    claim_ttl_seconds: int
    runtime_directory: Path

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, str) or not _PROJECT_ID.fullmatch(self.project_id):
            raise ValueError("Firebase project_id is invalid")
        if self.owner_email != "owner@example.invalid":
            raise ValueError("Firebase owner_email is outside the fixed owner policy")
        if self.owner_uid is not None and (
            not isinstance(self.owner_uid, str)
            or not _IDENTIFIER.fullmatch(self.owner_uid)
        ):
            raise ValueError("Firebase owner_uid is invalid")
        if not isinstance(self.principal_id, str) or not _IDENTIFIER.fullmatch(self.principal_id):
            raise ValueError("CCT principal_id is invalid")
        if not self.database.is_absolute() or not self.database.name:
            raise ValueError("CCT database path must be absolute")
        if not self.runtime_directory.is_absolute():
            raise ValueError("runtime_directory must be absolute")
        if not 2 <= self.poll_seconds <= 60:
            raise ValueError("poll_seconds must be between 2 and 60")
        if not 30 <= self.request_ttl_seconds <= 300:
            raise ValueError("request_ttl_seconds must be between 30 and 300")
        if not 15 <= self.claim_ttl_seconds <= 120:
            raise ValueError("claim_ttl_seconds must be between 15 and 120")


def _owner_regular_file(path: Path, *, maximum_bytes: int) -> bytes:
    candidate = path.expanduser().absolute()
    parent = candidate.parent
    parent_metadata = parent.stat()
    before = candidate.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or parent_metadata.st_mode & 0o022
    ):
        raise ValueError("bridge config parent must be owner-controlled")
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or before.st_mode & 0o077
        or not 1 <= before.st_size <= maximum_bytes
    ):
        raise ValueError("bridge config must be an owner-only regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(candidate, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("bridge config changed during open")
        chunks: list[bytes] = []
        bytes_read = 0
        while bytes_read <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - bytes_read))
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
        body = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(body) > maximum_bytes
            or len(body) != opened.st_size
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ValueError("bridge config changed during read")
        return body
    finally:
        os.close(descriptor)


def load_bridge_config(path: str | Path) -> FirebaseBridgeConfig:
    body = _owner_regular_file(Path(path), maximum_bytes=16 * 1024)
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("bridge config is invalid") from error
    expected = {
        "schema_version",
        "project_id",
        "database",
        "owner_email",
        "owner_uid",
        "principal_id",
        "poll_seconds",
        "request_ttl_seconds",
        "claim_ttl_seconds",
        "runtime_directory",
    }
    if not isinstance(value, Mapping) or {str(key) for key in value} != expected:
        raise ValueError("bridge config requires exact fields")
    if value["schema_version"] != CONFIG_SCHEMA:
        raise ValueError("bridge config schema is unsupported")
    integer_names = ("poll_seconds", "request_ttl_seconds", "claim_ttl_seconds")
    for name in integer_names:
        if isinstance(value[name], bool) or not isinstance(value[name], int):
            raise ValueError(f"bridge config {name} must be an integer")
    return FirebaseBridgeConfig(
        project_id=value["project_id"],
        database=Path(value["database"]),
        owner_email=value["owner_email"],
        owner_uid=value["owner_uid"],
        principal_id=value["principal_id"],
        poll_seconds=value["poll_seconds"],
        request_ttl_seconds=value["request_ttl_seconds"],
        claim_ttl_seconds=value["claim_ttl_seconds"],
        runtime_directory=Path(value["runtime_directory"]),
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware_datetime(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise BridgeRequestDenied("FIREBASE_REQUEST_TIMESTAMP_INVALID")
    return value.astimezone(timezone.utc)


def _exact_mapping(value: Any, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or {str(key) for key in value} != fields:
        raise BridgeRequestDenied("FIREBASE_REQUEST_INVALID")
    return value


def _request_identifier(value: Any) -> str:
    if not isinstance(value, str) or not _REQUEST_ID.fullmatch(value):
        raise BridgeRequestDenied("FIREBASE_REQUEST_ID_INVALID")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise BridgeRequestDenied("FIREBASE_PREVIEW_DIGEST_INVALID")
    return value


def _id_token(value: Any) -> str:
    if not isinstance(value, str) or not _ID_TOKEN.fullmatch(value):
        raise BridgeRequestDenied("FIREBASE_OWNER_TOKEN_INVALID")
    return value


class IdentityVerifier(Protocol):
    def verify_owner(
        self,
        uid: str,
        email: str,
        id_token: str,
        *,
        request_created_at: datetime,
        maximum_age_seconds: int,
    ) -> str: ...


class BridgeGateway(Protocol):
    def publish_dashboard(self, envelope: Mapping[str, Any]) -> None: ...
    def publish_status(self, status: Mapping[str, Any]) -> None: ...
    def requeue_stale(self, now: datetime) -> int: ...
    def pending_requests(self, limit: int) -> list[tuple[str, Mapping[str, Any]]]: ...
    def claim(self, request_id: str, instance_id: str, expires_at: datetime) -> bool: ...
    def get_receipt(self, request_id: str) -> Mapping[str, Any] | None: ...
    def complete(self, request_id: str, receipt: Mapping[str, Any]) -> None: ...


class FirebaseAdminIdentityVerifier:
    """Verify UID/email/provider against Firebase Auth Admin before local work."""

    def __init__(self, project_id: str, expected_email: str, expected_uid: str | None) -> None:
        try:
            import firebase_admin
            from firebase_admin import auth, tenant_mgt
        except ImportError as error:  # pragma: no cover - deployment dependency
            raise RuntimeError("firebase-admin extra is required") from error
        try:
            app = firebase_admin.get_app(f"cct-firebase-{project_id}")
        except ValueError:
            app = firebase_admin.initialize_app(
                options={"projectId": project_id},
                name=f"cct-firebase-{project_id}",
            )
        self._auth = auth
        self._app = app
        self._invalid_identity_errors = (
            auth.InvalidIdTokenError,  # Includes expired/revoked ID tokens.
            tenant_mgt.TenantIdMismatchError,
            auth.UserDisabledError,
            auth.UserNotFoundError,
        )
        self.expected_email = expected_email
        self.expected_uid = expected_uid

    def verify_owner(
        self,
        uid: str,
        email: str,
        id_token: str,
        *,
        request_created_at: datetime,
        maximum_age_seconds: int,
    ) -> str:
        if (
            not isinstance(uid, str)
            or not _IDENTIFIER.fullmatch(uid)
            or email != self.expected_email
            or (self.expected_uid is not None and uid != self.expected_uid)
        ):
            raise BridgeRequestDenied("FIREBASE_OWNER_IDENTITY_DENIED")
        try:
            claims = self._auth.verify_id_token(
                id_token,
                app=self._app,
                check_revoked=True,
            )
            user = self._auth.get_user(uid, app=self._app)
        except self._invalid_identity_errors as error:
            raise BridgeRequestDenied("FIREBASE_OWNER_TOKEN_INVALID") from error
        if not isinstance(claims, Mapping):
            raise BridgeRequestDenied("FIREBASE_OWNER_TOKEN_INVALID")
        firebase_claim = claims.get("firebase")
        issued_at = claims.get("iat")
        if (
            not isinstance(firebase_claim, Mapping)
            or firebase_claim.get("sign_in_provider") != "google.com"
            or claims.get("sub") != uid
            or claims.get("email") != self.expected_email
            or claims.get("email_verified") is not True
            or isinstance(issued_at, bool)
            or not isinstance(issued_at, int)
        ):
            raise BridgeRequestDenied("FIREBASE_OWNER_TOKEN_INVALID")
        try:
            issued = datetime.fromtimestamp(issued_at, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as error:
            raise BridgeRequestDenied("FIREBASE_OWNER_TOKEN_INVALID") from error
        token_age = request_created_at.astimezone(timezone.utc) - issued
        if token_age < timedelta(seconds=-30) or token_age > timedelta(
            seconds=maximum_age_seconds
        ):
            raise BridgeRequestDenied("FIREBASE_OWNER_TOKEN_EXPIRED")
        try:
            providers = {entry.provider_id for entry in (user.provider_data or ())}
        except (AttributeError, TypeError) as error:
            raise BridgeRequestDenied("FIREBASE_OWNER_IDENTITY_DENIED") from error
        if (
            user.uid != uid
            or user.email != self.expected_email
            or user.email_verified is not True
            or user.disabled is not False
            or "google.com" not in providers
        ):
            raise BridgeRequestDenied("FIREBASE_OWNER_IDENTITY_DENIED")
        return sha256(id_token.encode("utf-8")).hexdigest()


class FirestoreBridgeGateway:
    """Small Firestore adapter; Admin writes never replace local authorization."""

    def __init__(self, project_id: str) -> None:
        try:
            from google.api_core.exceptions import FailedPrecondition
            from google.api_core.retry import Retry
            from google.cloud import firestore
            from google.cloud.firestore_v1.base_query import FieldFilter
        except ImportError as error:  # pragma: no cover - deployment dependency
            raise RuntimeError("google-cloud-firestore extra is required") from error
        self._firestore = firestore
        self._failed_precondition = FailedPrecondition
        self._field_filter = FieldFilter
        # Query.stream inspects retry._predicate after iterator errors; None
        # masks quota failures in Firestore 2.30.0. Disable retries explicitly
        # without removing the Retry interface required by that iterator.
        self._stream_retry = Retry(predicate=lambda _error: False)
        self.client = firestore.Client(project=project_id)
        self._projection_cache = ProjectionCache()

    def read_owner_workspace(self) -> Mapping[str, Any] | None:
        """Observe cloud intent only; no acknowledgement or local authorization."""
        snapshot = self.client.collection("cct_workspace").document("current").get(
            retry=None, timeout=FIRESTORE_RPC_TIMEOUT_SECONDS
        )
        return snapshot.to_dict() if snapshot.exists else None

    def _publish_projection(self, collection, value):
        payload = {**value, "publishedAt": datetime.now(timezone.utc)}
        def write():
            ref = self.client.collection(collection).document("current")
            ref.set(payload, retry=None, timeout=FIRESTORE_RPC_TIMEOUT_SECONDS)
            if ref.get(retry=None, timeout=FIRESTORE_RPC_TIMEOUT_SECONDS).to_dict() != payload:
                raise RuntimeError("FIREBASE_PROJECTION_READBACK_MISMATCH")
        return self._projection_cache.publish(collection, "current", payload, write)

    def publish_dashboard(self, envelope: Mapping[str, Any]) -> None:
        self._publish_projection("cct_dashboard", dict(envelope))

    def publish_status(self, status: Mapping[str, Any]) -> None:
        self._publish_projection("cct_bridge_status", dict(status))

    def requeue_stale(self, now: datetime) -> int:
        query = self.client.collection("cct_control_requests").where(
            filter=self._field_filter("state", "==", "PROCESSING")
        )
        count = 0
        for snapshot in query.stream(
            retry=self._stream_retry, timeout=FIRESTORE_RPC_TIMEOUT_SECONDS,
        ):
            value = snapshot.to_dict() or {}
            expiry = value.get("claimExpiresAt")
            if isinstance(expiry, datetime) and expiry <= now:
                snapshot.reference.update(
                    {
                        "state": "PENDING",
                        "claimId": self._firestore.DELETE_FIELD,
                        "claimExpiresAt": self._firestore.DELETE_FIELD,
                    },
                    retry=None,
                    timeout=FIRESTORE_RPC_TIMEOUT_SECONDS,
                )
                count += 1
        return count

    def pending_requests(self, limit: int) -> list[tuple[str, Mapping[str, Any]]]:
        query = (
            self.client.collection("cct_control_requests")
            .where(filter=self._field_filter("state", "==", "PENDING"))
            .limit(limit)
        )
        return [
            (snapshot.id, snapshot.to_dict() or {})
            for snapshot in query.stream(
                retry=self._stream_retry, timeout=FIRESTORE_RPC_TIMEOUT_SECONDS,
            )
        ]

    def claim(self, request_id: str, instance_id: str, expires_at: datetime) -> bool:
        reference = self.client.collection("cct_control_requests").document(request_id)
        snapshot = reference.get(retry=None, timeout=FIRESTORE_RPC_TIMEOUT_SECONDS)
        if not snapshot.exists or (snapshot.to_dict() or {}).get("state") != "PENDING":
            return False
        # Atomic compare-and-set preserves exclusive claiming without the SDK's
        # transaction begin/commit/rollback RPCs (which hide default retries).
        try:
            reference.update(
                {
                    "state": "PROCESSING",
                    "claimId": instance_id,
                    "claimExpiresAt": expires_at,
                },
                option=self._firestore.LastUpdateOption(snapshot.update_time),
                retry=None,
                timeout=FIRESTORE_RPC_TIMEOUT_SECONDS,
            )
        except self._failed_precondition:
            return False
        return True

    def get_receipt(self, request_id: str) -> Mapping[str, Any] | None:
        snapshot = self.client.collection("cct_control_receipts").document(request_id).get(
            retry=None, timeout=FIRESTORE_RPC_TIMEOUT_SECONDS
        )
        return snapshot.to_dict() if snapshot.exists else None

    def complete(self, request_id: str, receipt: Mapping[str, Any]) -> None:
        request = self.client.collection("cct_control_requests").document(request_id)
        output = self.client.collection("cct_control_receipts").document(request_id)
        batch = self.client.batch()
        payload = dict(receipt)
        payload["processedAt"] = self._firestore.SERVER_TIMESTAMP
        batch.set(output, payload)
        batch.update(
            request,
            {
                "state": "DONE" if payload.get("status") != "ERROR" else "DENIED",
                "completedAt": self._firestore.SERVER_TIMESTAMP,
                "claimExpiresAt": self._firestore.DELETE_FIELD,
                "idToken": self._firestore.DELETE_FIELD,
            },
        )
        batch.commit(retry=None, timeout=FIRESTORE_RPC_TIMEOUT_SECONDS)


class CCTFirebaseBridge:
    def __init__(
        self,
        config: FirebaseBridgeConfig,
        gateway: BridgeGateway,
        identity: IdentityVerifier,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.config = config
        self.gateway = gateway
        self.identity = identity
        self.clock = clock
        identity_seed = (
            f"{socket.gethostname()}:{config.project_id}:{config.database}:"
            f"{config.owner_email}"
        )
        self.instance_id = f"bridge-{sha256(identity_seed.encode()).hexdigest()[:24]}"

    def _control_context(self) -> tuple[DashboardControlService, dict[str, str]]:
        now = self.clock().astimezone(timezone.utc)
        token = sha256(os.urandom(64)).hexdigest()
        bootstrap = OperatorBootstrap(
            principal_id=self.config.principal_id,
            token=token,
            expires_at=(now + timedelta(seconds=MAX_SESSION_SECONDS)).isoformat(),
        )
        sessions = DashboardSessionAuthority(
            bootstrap,
            now=lambda: self.clock().astimezone(timezone.utc).isoformat(),
        )
        session = sessions.open_session(token)
        store = EventStore(
            self.config.database,
            clock=lambda: self.clock().astimezone(timezone.utc).isoformat(),
        )
        return DashboardControlService(store, sessions=sessions), session

    def _normalize_request(
        self,
        document_id: str,
        value: Mapping[str, Any],
    ) -> dict[str, Any]:
        request_id = _request_identifier(document_id)
        kind = value.get("kind")
        base_fields = {
            "schemaVersion",
            "requestId",
            "kind",
            "action",
            "capability",
            "active",
            "ownerUid",
            "ownerEmail",
            "idToken",
            "state",
            "createdAt",
        }
        fields = base_fields if kind == "PREVIEW" else base_fields | {
            "parentRequestId",
            "previewSha256",
        }
        row = _exact_mapping(value, fields)
        if (
            row["schemaVersion"] != REQUEST_SCHEMA
            or row["requestId"] != request_id
            or kind not in {"PREVIEW", "APPLY"}
            or row["action"] != CONTROL_ACTION
            or row["capability"] != CONTROL_CAPABILITY
            or not isinstance(row["active"], bool)
            or row["ownerEmail"] != self.config.owner_email
            or row["state"] != "PENDING"
        ):
            raise BridgeRequestDenied("FIREBASE_REQUEST_INVALID")
        uid = row["ownerUid"]
        if not isinstance(uid, str) or not _IDENTIFIER.fullmatch(uid):
            raise BridgeRequestDenied("FIREBASE_OWNER_IDENTITY_DENIED")
        if self.config.owner_uid is not None and uid != self.config.owner_uid:
            raise BridgeRequestDenied("FIREBASE_OWNER_IDENTITY_DENIED")
        created = _aware_datetime(row["createdAt"])
        id_token = _id_token(row["idToken"])
        normalized = dict(row)
        normalized["createdAt"] = created
        normalized["idToken"] = id_token
        normalized["authTokenSha256"] = sha256(id_token.encode("utf-8")).hexdigest()
        if kind == "APPLY":
            normalized["parentRequestId"] = _request_identifier(row["parentRequestId"])
            normalized["previewSha256"] = _digest(row["previewSha256"])
        return normalized

    def _verify_live_authorization(self, request: Mapping[str, Any]) -> None:
        created = request["createdAt"]
        if not isinstance(created, datetime):
            raise BridgeRequestDenied("FIREBASE_REQUEST_TIMESTAMP_INVALID")
        age = self.clock().astimezone(timezone.utc) - created
        if age < timedelta(seconds=-30) or age > timedelta(
            seconds=self.config.request_ttl_seconds
        ):
            raise BridgeRequestDenied("FIREBASE_REQUEST_EXPIRED")
        verified_digest = self.identity.verify_owner(
            request["ownerUid"],
            self.config.owner_email,
            request["idToken"],
            request_created_at=created,
            maximum_age_seconds=self.config.request_ttl_seconds,
        )
        if (
            not isinstance(verified_digest, str)
            or not _DIGEST.fullmatch(verified_digest)
            or verified_digest != request["authTokenSha256"]
        ):
            raise BridgeRequestDenied("FIREBASE_OWNER_TOKEN_INVALID")

    @staticmethod
    def _authorization_material(request: Mapping[str, Any]) -> dict[str, Any]:
        material = {
            "schemaVersion": request["schemaVersion"],
            "requestId": request["requestId"],
            "kind": request["kind"],
            "action": request["action"],
            "capability": request["capability"],
            "active": request["active"],
            "ownerUid": request["ownerUid"],
            "ownerEmail": request["ownerEmail"],
            "state": request["state"],
            "createdAt": request["createdAt"].isoformat(),
            "authTokenSha256": request["authTokenSha256"],
        }
        if request["kind"] == "APPLY":
            material["parentRequestId"] = request["parentRequestId"]
            material["previewSha256"] = request["previewSha256"]
        return material

    def _authorization_payload(self, request: Mapping[str, Any]) -> dict[str, Any]:
        material = self._authorization_material(request)
        return {
            "schema_version": AUTHORIZATION_SCHEMA,
            "request_id": request["requestId"],
            "request_sha256": sha256(canonical_json(material).encode("utf-8")).hexdigest(),
            "auth_token_sha256": request["authTokenSha256"],
            "owner_uid_sha256": sha256(request["ownerUid"].encode("utf-8")).hexdigest(),
        }

    def _authorization_store(self) -> EventStore:
        return EventStore(
            self.config.database,
            clock=lambda: self.clock().astimezone(timezone.utc).isoformat(),
        )

    def _record_authorization(self, request: Mapping[str, Any]) -> None:
        expected = self._authorization_payload(request)
        try:
            event, _created = self._authorization_store().append_once_result(
                AUTHORIZATION_EVENT,
                request["requestId"],
                expected,
            )
        except ValueError as error:
            raise BridgeRequestDenied("FIREBASE_AUTHORIZATION_COLLISION") from error
        if canonical_json(event.payload) != canonical_json(expected):
            raise BridgeRequestDenied("FIREBASE_AUTHORIZATION_COLLISION")

    def _has_recorded_authorization(self, request: Mapping[str, Any]) -> bool:
        expected = self._authorization_payload(request)
        matching = [
            event
            for event in self._authorization_store().events(AUTHORIZATION_EVENT)
            if event.payload.get("request_id") == request["requestId"]
        ]
        if not matching:
            return False
        if len(matching) != 1 or canonical_json(matching[0].payload) != canonical_json(expected):
            raise BridgeRequestDenied("FIREBASE_AUTHORIZATION_COLLISION")
        return True

    def _preview_receipt(self, request: Mapping[str, Any]) -> dict[str, Any]:
        controls, session = self._control_context()
        expiry = min(
            self.clock().astimezone(timezone.utc)
            + timedelta(seconds=MAX_CONFIRMATION_SECONDS),
            datetime.fromisoformat(session["expires_at"]),
        ).isoformat()
        preview = controls.preview(
            {
                "draft_id": f"firebase-{request['requestId']}",
                "action": CONTROL_ACTION,
                "capability": CONTROL_CAPABILITY,
                "active": request["active"],
            },
            expires_at=expiry,
        )
        return {
            "schemaVersion": RECEIPT_SCHEMA,
            "requestId": request["requestId"],
            "kind": "PREVIEW",
            "status": "PREVIEW_READY",
            "ownerUid": request["ownerUid"],
            "ownerEmail": self.config.owner_email,
            "authTokenSha256": request["authTokenSha256"],
            "previewSha256": preview["preview_sha256"],
            "bridgeInstanceId": self.instance_id,
            "payload": {"preview": preview},
        }

    def _recovered_result(self, preview: Mapping[str, Any]) -> dict[str, Any] | None:
        draft = preview.get("draft")
        if not isinstance(draft, Mapping):
            return None
        draft_id = draft.get("draft_id")
        preview_sha256 = preview.get("preview_sha256")
        if not isinstance(draft_id, str) or not isinstance(preview_sha256, str):
            return None
        store = EventStore(
            self.config.database,
            clock=lambda: self.clock().astimezone(timezone.utc).isoformat(),
        )
        for event in reversed(store.events("capability.control.state_changed")):
            receipt = event.payload.get("control_receipt")
            if not isinstance(receipt, Mapping):
                continue
            if (
                receipt.get("draft_id") == draft_id
                and receipt.get("preview_sha256") == preview_sha256
            ):
                status = CapabilityRegistry(store).status()["specifications"].get(
                    CONTROL_CAPABILITY
                )
                chain = store.verify_chain()
                if not isinstance(status, Mapping) or chain.get("valid") is not True:
                    raise BridgeRequestDenied("FIREBASE_APPLY_RECOVERY_FAILED")
                return {
                    "schema_version": "cct.admin_dashboard.control_result.v1",
                    "status": "VERIFIED",
                    "action": CONTROL_ACTION,
                    "capability": CONTROL_CAPABILITY,
                    "active": event.payload.get("active"),
                    "effective_state": (
                        "DENY" if event.payload.get("active") is True else "PAUSED"
                    ),
                    "spec_digest": status.get("spec_digest"),
                    "spec_revision": status.get("revision"),
                    "control_revision": status.get("administrative_revision"),
                    "applied_event_id": event.event_id,
                    "confirmation_id": receipt.get("confirmation_id"),
                    "preview_sha256": preview_sha256,
                    "chain_valid": True,
                    "lease_created": False,
                    "ticket_created": False,
                    "route_changed": False,
                    "external_effects": 0,
                    "recovered_after_restart": True,
                }
        return None

    def _apply_receipt(self, request: Mapping[str, Any]) -> dict[str, Any]:
        parent = self.gateway.get_receipt(request["parentRequestId"])
        if not isinstance(parent, Mapping):
            raise BridgeRequestDenied("FIREBASE_PREVIEW_RECEIPT_MISSING")
        if parent.get("authTokenSha256") == request["authTokenSha256"]:
            raise BridgeRequestDenied("FIREBASE_OWNER_TOKEN_REUSED")
        if (
            parent.get("status") != "PREVIEW_READY"
            or parent.get("ownerUid") != request["ownerUid"]
            or parent.get("ownerEmail") != self.config.owner_email
            or parent.get("previewSha256") != request["previewSha256"]
            or not isinstance(parent.get("authTokenSha256"), str)
            or not _DIGEST.fullmatch(parent["authTokenSha256"])
        ):
            raise BridgeRequestDenied("FIREBASE_PREVIEW_RECEIPT_MISMATCH")
        payload = parent.get("payload")
        preview = payload.get("preview") if isinstance(payload, Mapping) else None
        if not isinstance(preview, Mapping):
            raise BridgeRequestDenied("FIREBASE_PREVIEW_RECEIPT_INVALID")
        if (
            preview.get("preview_sha256") != request["previewSha256"]
            or not isinstance(preview.get("after"), Mapping)
            or preview["after"].get("active") is not request["active"]
        ):
            raise BridgeRequestDenied("FIREBASE_PREVIEW_RECEIPT_MISMATCH")
        recovered = self._recovered_result(preview)
        if recovered is not None:
            if not self._has_recorded_authorization(request):
                self._verify_live_authorization(request)
            result = recovered
        else:
            self._verify_live_authorization(request)
            self._record_authorization(request)
            controls, session = self._control_context()
            confirmation = controls.confirm(preview, session=session)
            result = controls.apply(
                preview,
                confirmation,
                session_id_sha256=session["session_id_sha256"],
            )
        return {
            "schemaVersion": RECEIPT_SCHEMA,
            "requestId": request["requestId"],
            "kind": "APPLY",
            "status": "APPLY_VERIFIED",
            "ownerUid": request["ownerUid"],
            "ownerEmail": self.config.owner_email,
            "authTokenSha256": request["authTokenSha256"],
            "previewSha256": request["previewSha256"],
            "bridgeInstanceId": self.instance_id,
            "payload": {"result": result},
        }

    def process_request(
        self,
        document_id: str,
        value: Mapping[str, Any],
    ) -> dict[str, Any]:
        request = self._normalize_request(document_id, value)
        if request["kind"] == "PREVIEW":
            self._verify_live_authorization(request)
            return self._preview_receipt(request)
        return self._apply_receipt(request)

    def dashboard_envelope(self) -> dict[str, Any]:
        snapshot = build_dashboard_snapshot(self.config.database)
        snapshot["mode"] = "FIREBASE_REMOTE_CONTROL"
        snapshot["controls"] = {
            "installed": True,
            "authenticated": True,
            "action": CONTROL_ACTION,
            "capability": CONTROL_CAPABILITY,
            "host_apply_only": True,
            "browser_direct_state_write": False,
            "lease_creation_enabled": False,
            "ticket_creation_enabled": False,
            "external_effects_enabled": False,
            "bridge_online": True,
            "bridge_instance_id": self.instance_id,
        }
        permission_rows = snapshot.get("permissions")
        if not isinstance(permission_rows, list):
            raise BridgeRequestDenied("FIREBASE_DASHBOARD_PROJECTION_INVALID")
        for permission in permission_rows:
            if not isinstance(permission, dict):
                raise BridgeRequestDenied("FIREBASE_DASHBOARD_PROJECTION_INVALID")
            permission["control_state"] = (
                "READY"
                if permission.get("name") == CONTROL_CAPABILITY
                else "NOT_AVAILABLE"
            )
        # Optional observation preserves legacy gateway/control interfaces. SDK
        # failures must reach the existing outer backoff owner, not masquerade
        # as a missing document or a successful ONLINE tick. Never authorize
        # execution, append local events, or acknowledge policy from this read.
        read_workspace = getattr(self.gateway, "read_owner_workspace", None)
        workspace = (
            read_workspace()
            if callable(read_workspace) and self.config.owner_uid is not None
            else None
        )
        snapshot["collaboration"] = project_owner_workspace(
            workspace,
            owner_uid=self.config.owner_uid,
            observed_at=self.clock(),
            observer_available=callable(read_workspace),
        )
        encoded = canonical_json(snapshot).encode("utf-8")
        if len(encoded) > MAX_SNAPSHOT_BYTES:
            raise BridgeRequestDenied("FIREBASE_DASHBOARD_TOO_LARGE")
        envelope: dict[str, Any] = {
            "schemaVersion": DASHBOARD_SCHEMA,
            "ownerEmail": self.config.owner_email,
            "bridgeInstanceId": self.instance_id,
            "snapshotSha256": sha256(encoded).hexdigest(),
            "snapshot": snapshot,
        }
        if self.config.owner_uid is not None:
            envelope["ownerUid"] = self.config.owner_uid
        return envelope

    def run_once(self) -> dict[str, Any]:
        now = self.clock().astimezone(timezone.utc)
        requeued = self.gateway.requeue_stale(now)
        self.gateway.publish_dashboard(self.dashboard_envelope())
        processed = 0
        verified = 0
        denied = 0
        for document_id, value in self.gateway.pending_requests(
            MAX_REQUESTS_PER_TICK
        ):
            request_id = document_id if isinstance(document_id, str) else "invalid"
            if not self.gateway.claim(
                request_id,
                self.instance_id,
                now + timedelta(seconds=self.config.claim_ttl_seconds),
            ):
                continue
            processed += 1
            try:
                receipt = self.process_request(request_id, value)
                verified += 1
            except (BridgeRequestDenied, DashboardControlDenied) as error:
                reason = (
                    error.reason_code
                    if hasattr(error, "reason_code")
                    else "FIREBASE_BRIDGE_REQUEST_DENIED"
                )
                receipt = {
                    "schemaVersion": RECEIPT_SCHEMA,
                    "requestId": request_id,
                    "kind": value.get("kind") if isinstance(value, Mapping) else "UNKNOWN",
                    "status": "ERROR",
                    "reasonCode": reason,
                    "ownerUid": (
                        value.get("ownerUid")
                        if isinstance(value, Mapping)
                        and isinstance(value.get("ownerUid"), str)
                        else "denied"
                    ),
                    "ownerEmail": self.config.owner_email,
                    "bridgeInstanceId": self.instance_id,
                    "payload": {},
                }
                denied += 1
            self.gateway.complete(request_id, receipt)
        if verified:
            self.gateway.publish_dashboard(self.dashboard_envelope())
        summary = {
            "schemaVersion": BRIDGE_STATUS_SCHEMA,
            "status": "ONLINE",
            "projectId": self.config.project_id,
            "ownerEmail": self.config.owner_email,
            "bridgeInstanceId": self.instance_id,
            "requeued": requeued,
            "processed": processed,
            "verified": verified,
            "denied": denied,
            "externalEffects": 0,
        }
        self.gateway.publish_status(summary)
        return summary


def _lock_runtime(directory: Path) -> tuple[int, Path]:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = directory.stat()
    if (
        directory.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise ValueError("bridge runtime directory must be owner-only")
    path = directory / "bridge.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(descriptor)
        raise RuntimeError("FIREBASE_BRIDGE_ALREADY_RUNNING") from None
    return descriptor, path





def _cloud_error_policy() -> CloudErrorPolicy:
    # Optional dependencies stay out of core imports and fake-gateway tests.
    from firebase_admin import auth, exceptions as auth_exceptions
    from google.api_core import exceptions

    return CloudErrorPolicy(
        quota=(exceptions.TooManyRequests, auth_exceptions.ResourceExhaustedError),
        transient=(
            exceptions.ServiceUnavailable,
            exceptions.DeadlineExceeded,
            exceptions.Aborted,
            exceptions.InternalServerError,
            exceptions.BadGateway,
            exceptions.GatewayTimeout,
            auth_exceptions.UnavailableError,
            auth_exceptions.DeadlineExceededError,
            auth_exceptions.AbortedError,
            auth_exceptions.InternalError,
            auth.CertificateFetchError,
        ),
        retry=(exceptions.RetryError,),
    )


class BridgeRuntimeFailure(RuntimeError):
    """Fatal, sanitized failure; never converted to a retry or request denial."""


def _write_local_health(directory: Path, receipt: Mapping[str, Any]) -> None:
    # The caller holds _lock_runtime's owner-only directory. Atomic replacement
    # never follows an existing receipt symlink or exposes a partial/public file.
    descriptor, temporary = tempfile.mkstemp(prefix=".bridge-health-", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(dict(receipt), sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / "bridge-health.json")
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run_bridge_loop(
    bridge: CCTFirebaseBridge,
    *,
    once: bool,
    errors: CloudErrorPolicy,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], datetime] = _utc_now,
) -> int:
    """One outer retry owner; a failed tick never advertises ONLINE locally."""
    interval = max(MIN_POLL_SECONDS, bridge.config.poll_seconds)
    circuit = CloudCircuit.for_project(
        bridge.config.project_id, bridge.config.runtime_directory / "cloud-backoff.json",
        errors, clock=lambda: clock().timestamp())
    last_success: str | None = None

    def health(status: str, reason: str, retry_seconds: int) -> dict[str, Any]:
        now = clock().astimezone(timezone.utc)
        receipt = {
            "schemaVersion": "cct.firebase_bridge.local_health.v1",
            "status": status,
            "reasonCode": reason,
            "checkedAt": now.isoformat(),
            "lastSuccessAt": last_success,
            "retrySeconds": retry_seconds,
            "nextAttemptAt": (
                (now + timedelta(seconds=retry_seconds)).isoformat()
                if retry_seconds and not once else None
            ),
        }
        _write_local_health(bridge.config.runtime_directory, receipt)
        return receipt

    while True:
        health("CHECKING", "FIREBASE_BRIDGE_CHECKING", 0)
        try:
            # An expired deadline permits a probe, not an old display receipt.
            # The outer call owns the project lock through the complete tick;
            # never attach this circuit to the gateway and acquire it recursively.
            if circuit.check():
                cache = getattr(getattr(bridge, "gateway", None), "_projection_cache", None)
                if isinstance(cache, ProjectionCache):
                    cache.entries.clear()
            summary = circuit.call(bridge.run_once)
        except Exception as error:
            status = error.receipt["cloudStatus"] if isinstance(error, CloudBackoff) else None
            if status is None:
                receipt = health("FAILED", "FIREBASE_BRIDGE_FATAL_ERROR", 0)
                print(json.dumps(receipt, sort_keys=True), flush=True)
                # Fail loudly/nonzero, but do not leak SDK payloads or tokens in
                # a chained traceback. Unknown/programming errors never retry.
                raise BridgeRuntimeFailure("FIREBASE_BRIDGE_FATAL_ERROR") from None
            delay = error.receipt["retrySeconds"]
            summary = health(status, "FIREBASE_BRIDGE_" + status, max(interval, delay))
            print(json.dumps(summary, sort_keys=True), flush=True)
            if once:
                return 1
            sleep(max(interval, delay))
        else:
            circuit.recovered()
            last_success = clock().astimezone(timezone.utc).isoformat()
            health("ONLINE", "FIREBASE_BRIDGE_OK", 0 if once else interval)
            print(json.dumps(summary, sort_keys=True), flush=True)
            if once:
                return 0
            sleep(interval)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cct-firebase-bridge",
        description="Run the outbound-only Firebase bridge for one CCTAE ledger.",
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    config = load_bridge_config(args.config)
    descriptor, _lock_path = _lock_runtime(config.runtime_directory)
    try:
        gateway = FirestoreBridgeGateway(config.project_id)
        identity = FirebaseAdminIdentityVerifier(
            config.project_id,
            config.owner_email,
            config.owner_uid,
        )
        bridge = CCTFirebaseBridge(config, gateway, identity)
        try:
            return run_bridge_loop(bridge, once=args.once, errors=_cloud_error_policy())
        except BridgeRuntimeFailure:
            return 1
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
