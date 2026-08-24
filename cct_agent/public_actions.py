"""Typed public-action adapter limited to a private local fake outbox."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import re
import secrets
import stat
from types import MappingProxyType
from typing import Iterator, Literal, Mapping

from .deployment import (
    DeploymentDenied,
    DeploymentObservation,
    LocalFakeDeploymentAdapter,
)
from .store import Event, EventStore, canonical_json


PUBLIC_ACTION_CLAIM_SCHEMA_VERSION = "cct.public-action.fake-sink.claim.v1"
PUBLIC_ACTION_RECEIPT_SCHEMA_VERSION = "cct.public-action.fake-sink.receipt.v1"
PUBLIC_ACTION_ENVELOPE_SCHEMA_VERSION = "cct.public-action.fake-sink.envelope.v1"
PUBLIC_ACTION_OUTBOX_SCHEMA_VERSION = "cct.public-action.fake-sink.outbox.v1"
PUBLIC_ACTION_PREVIEW_SCHEMA_VERSION = "cct.public-action.fake-sink.preview.v1"
MAX_PUBLIC_ACTIONS = 64
MAX_OUTBOX_ITEM_BYTES = 65_536
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+=,-]{0,254}$")
_SENSITIVE_TOKENS = {
    ".env",
    "credential",
    "credentials",
    "keychain",
    "keystore",
    "password",
    "private-key",
    "private_key",
    "secret",
    "secrets",
    "service-account",
    "service_account",
    "token",
    "tokens",
    "wallet",
    "wallets",
}


class PublicActionDenied(PermissionError):
    """Fail-closed fake public-action denial with stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest(name: str, value: object) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _bounded_integer(
    name: str,
    value: object,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _outbox_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not _FILENAME.fullmatch(value)
        or value != value.strip()
        or "/" in value
        or "\\" in value
        or not value.endswith(".json")
        or value == ".public-action.lock"
        or value.startswith(".cct-public-action-")
    ):
        raise ValueError("outbox_item_name must be one normalized JSON filename")
    lowered = value.lower()
    tokens = {
        token
        for token in re.split(r"[._-]+", lowered)
        if token
    }
    if lowered in _SENSITIVE_TOKENS or tokens & _SENSITIVE_TOKENS:
        raise ValueError("outbox_item_name cannot address credentials or secrets")
    return value


@dataclass(frozen=True, slots=True)
class FakePublicActionSpec:
    """Immutable host-owned fake channel, action, and structured envelope."""

    id: str
    kind: Literal["fake_sink"]
    channel: Literal["local_fake"]
    action: Literal["publish"]
    envelope_type: Literal["deployment_announcement"]
    template_id: str
    deployment_target_id: str
    outbox_item_name: str
    max_item_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("action id", self.id))
        if self.kind != "fake_sink":
            raise ValueError("public action kind must be fake_sink")
        if self.channel != "local_fake":
            raise ValueError("public action channel must be local_fake")
        if self.action != "publish":
            raise ValueError("public action must be publish")
        if self.envelope_type != "deployment_announcement":
            raise ValueError("envelope_type must be deployment_announcement")
        object.__setattr__(
            self,
            "template_id",
            _identifier("template id", self.template_id),
        )
        object.__setattr__(
            self,
            "deployment_target_id",
            _identifier("deployment target id", self.deployment_target_id),
        )
        object.__setattr__(
            self,
            "outbox_item_name",
            _outbox_name(self.outbox_item_name),
        )
        _bounded_integer(
            "max_item_bytes",
            self.max_item_bytes,
            minimum=1,
            maximum=MAX_OUTBOX_ITEM_BYTES,
        )


@dataclass(frozen=True, slots=True)
class FakePublicActionPreview:
    """Exact deployment/readback-bound fake public-action preview."""

    action_id: str
    action_spec_sha256: str
    kind: Literal["fake_sink"]
    channel: Literal["local_fake"]
    action: Literal["publish"]
    deployment_request_id: str
    deployment_event_id: str
    deployment_target_id: str
    deployment_manifest_sha256: str
    artifact_sha256: str
    sink_readback_sha256: str
    envelope_sha256: str
    outbox_item_sha256: str
    outbox_item_byte_count: int
    preview_sha256: str


@dataclass(frozen=True, slots=True)
class FakePublicActionRequest:
    """Caller-selected action ID bound to one exact host-produced preview."""

    id: str
    action_id: str
    deployment_request_id: str
    expected_deployment_event_id: str
    expected_sink_readback_sha256: str
    expected_envelope_sha256: str
    expected_preview_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("request id", self.id))
        object.__setattr__(
            self,
            "action_id",
            _identifier("action id", self.action_id),
        )
        object.__setattr__(
            self,
            "deployment_request_id",
            _identifier("deployment request id", self.deployment_request_id),
        )
        object.__setattr__(
            self,
            "expected_deployment_event_id",
            _identifier(
                "expected deployment event id",
                self.expected_deployment_event_id,
            ),
        )
        for field in (
            "expected_sink_readback_sha256",
            "expected_envelope_sha256",
            "expected_preview_sha256",
        ):
            object.__setattr__(self, field, _digest(field, getattr(self, field)))


@dataclass(frozen=True, slots=True)
class FakePublicActionObservation:
    """Readback-verified hash-only receipt for one local fake outbox item."""

    request_id: str
    action_id: str
    action_spec_sha256: str
    kind: Literal["fake_sink"]
    channel: Literal["local_fake"]
    action: Literal["publish"]
    deployment_request_id: str
    deployment_event_id: str
    deployment_target_id: str
    deployment_manifest_sha256: str
    artifact_sha256: str
    sink_readback_sha256: str
    envelope_sha256: str
    preview_sha256: str
    outbox_item_sha256: str
    outbox_readback_sha256: str
    outbox_readback_verified: bool
    outbox_mutation_count: int
    status: Literal["sent"]
    terminal_event_id: str
    replayed: bool
    outbox_content_persisted_in_ledger: bool = False
    real_public_effect: bool = False
    network_effect: bool = False
    provider_effect: bool = False
    credential_use: bool = False
    production_effect: bool = False


@dataclass(frozen=True, slots=True)
class _RegisteredAction:
    spec: FakePublicActionSpec
    spec_sha256: str


@dataclass(frozen=True, slots=True)
class _OutboxSnapshot:
    content: bytes
    device: int
    inode: int

    @property
    def digest(self) -> str:
        return sha256(self.content).hexdigest()


class LocalFakePublicActionAdapter:
    """Emit one deployment-bound action into a private local fake outbox."""

    def __init__(
        self,
        store: EventStore,
        *,
        outbox_root: str | Path,
        actions: tuple[FakePublicActionSpec, ...] | list[FakePublicActionSpec],
        deployment: LocalFakeDeploymentAdapter,
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        root = Path(outbox_root)
        if not root.is_absolute() or root.is_symlink():
            raise ValueError("outbox_root must be an absolute real directory")
        try:
            resolved_root = root.resolve(strict=True)
            root_stat = resolved_root.stat()
        except OSError as error:
            raise ValueError("outbox_root must be an existing real directory") from error
        if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != os.getuid():
            raise ValueError("outbox_root must be an owned real directory")
        try:
            os.chmod(resolved_root, 0o700)
        except OSError as error:
            raise ValueError("outbox_root must be private") from error
        if not isinstance(deployment, LocalFakeDeploymentAdapter):
            raise ValueError("deployment must be a LocalFakeDeploymentAdapter")
        if deployment.store.path.resolve() != store.path.resolve():
            raise ValueError("deployment and public action must share one ledger")
        deployment_roots = (deployment.workspace_root, deployment.sink_root)
        if any(
            resolved_root == candidate
            or resolved_root.is_relative_to(candidate)
            or candidate.is_relative_to(resolved_root)
            for candidate in deployment_roots
        ):
            raise ValueError("outbox_root must be separate from deployment roots")
        if not isinstance(actions, (tuple, list)) or not actions:
            raise ValueError("actions must contain at least one FakePublicActionSpec")
        if len(actions) > MAX_PUBLIC_ACTIONS:
            raise ValueError(f"actions must contain at most {MAX_PUBLIC_ACTIONS} values")

        registrations: dict[str, _RegisteredAction] = {}
        item_names: set[str] = set()
        for spec in actions:
            if not isinstance(spec, FakePublicActionSpec):
                raise ValueError("actions must contain FakePublicActionSpec values")
            if spec.id in registrations:
                raise ValueError("public action IDs must be unique")
            if spec.outbox_item_name in item_names:
                raise ValueError("public action outbox item names must be unique")
            if spec.deployment_target_id not in deployment.registered_target_ids:
                raise ValueError("public action deployment target is not registered")
            payload = {
                "id": spec.id,
                "kind": spec.kind,
                "channel": spec.channel,
                "action": spec.action,
                "envelope_type": spec.envelope_type,
                "template_id": spec.template_id,
                "deployment_target_id": spec.deployment_target_id,
                "outbox_item_name": spec.outbox_item_name,
                "max_item_bytes": spec.max_item_bytes,
            }
            registrations[spec.id] = _RegisteredAction(
                spec=spec,
                spec_sha256=sha256(
                    canonical_json(payload).encode("utf-8")
                ).hexdigest(),
            )
            item_names.add(spec.outbox_item_name)

        self.store = store
        self.deployment = deployment
        self.outbox_root = resolved_root
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        self._actions: Mapping[str, _RegisteredAction] = MappingProxyType(
            registrations
        )
        self._lock_path = self.outbox_root / ".public-action.lock"
        try:
            lock_fd = os.open(
                self._lock_path,
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            os.fchmod(lock_fd, 0o600)
            os.close(lock_fd)
            os.chmod(self.store.path, 0o600)
        except OSError as error:
            raise ValueError("public action state must be private and lockable") from error

    @property
    def registered_action_ids(self) -> frozenset[str]:
        return frozenset(self._actions)

    def preview(
        self,
        *,
        action_id: str,
        deployment_request_id: str,
    ) -> FakePublicActionPreview:
        action_id = _identifier("action id", action_id)
        deployment_request_id = _identifier(
            "deployment request id",
            deployment_request_id,
        )
        if self.store.verify_chain().get("valid") is not True:
            raise PublicActionDenied("LEDGER_CHAIN_INVALID")
        registration = self._actions.get(action_id)
        if registration is None:
            raise PublicActionDenied("ACTION_NOT_REGISTERED")
        deployment = self._require_deployment(registration, deployment_request_id)
        return self._make_preview(registration, deployment)

    def execute(
        self,
        request: FakePublicActionRequest,
    ) -> FakePublicActionObservation:
        if not isinstance(request, FakePublicActionRequest):
            raise ValueError("request must be a FakePublicActionRequest")
        if self.store.verify_chain().get("valid") is not True:
            raise PublicActionDenied("LEDGER_CHAIN_INVALID")
        registration = self._actions.get(request.action_id)
        if registration is None:
            raise PublicActionDenied("ACTION_NOT_REGISTERED")

        deployment = self._require_deployment(
            registration,
            request.deployment_request_id,
        )
        expected = self._make_preview(registration, deployment)
        self._validate_request_preview(request, expected)
        with self._exclusive_lock():
            deployment = self._require_deployment(
                registration,
                request.deployment_request_id,
            )
            current = self._make_preview(registration, deployment)
            self._validate_request_preview(request, current)
            terminal = self._terminal_event(request.id)
            if terminal is not None:
                observation = self._observation_from_event(terminal, replayed=True)
                self._validate_terminal(
                    observation,
                    registration,
                    deployment,
                    request,
                )
                self._verify_outbox_readback(registration.spec, observation)
                return observation

            claim = self._claim_event(request.id)
            claim_created = False
            claim_payload = self._claim_payload(
                request,
                registration,
                current,
            )
            if claim is None:
                if self._read_outbox_item(registration.spec, missing_ok=True) is not None:
                    raise PublicActionDenied("OUTBOX_ITEM_ALREADY_EXISTS")
                try:
                    claim, claim_created = self.store.append_once_result(
                        "public_action.fake_sink.claimed",
                        request.id,
                        claim_payload,
                    )
                except ValueError as error:
                    raise PublicActionDenied("REQUEST_COLLISION") from error
                except Exception as error:
                    raise PublicActionDenied("CLAIM_PERSISTENCE_FAILED") from error
            if canonical_json(claim.payload) != canonical_json(claim_payload):
                raise PublicActionDenied("REQUEST_COLLISION")

            outbox_bytes = self._outbox_bytes(registration, deployment)
            item = self._read_outbox_item(registration.spec, missing_ok=True)
            if item is None:
                if sha256(outbox_bytes).hexdigest() != current.outbox_item_sha256:
                    raise PublicActionDenied("ACTION_PREVIEW_STALE")
                self._atomic_create_outbox_item(registration.spec, outbox_bytes)
                item = self._read_outbox_item(registration.spec, missing_ok=False)
            elif (
                item.digest != current.outbox_item_sha256
                or len(item.content) != current.outbox_item_byte_count
            ):
                raise PublicActionDenied("OUTBOX_STATE_UNCERTAIN")
            if item is None or (
                item.digest != current.outbox_item_sha256
                or len(item.content) != current.outbox_item_byte_count
            ):
                raise PublicActionDenied("OUTBOX_READBACK_MISMATCH")

            terminal, completion_created = self._record_completion(
                request,
                registration,
                claim,
                current,
                item,
            )
            return self._observation_from_event(
                terminal,
                replayed=(not claim_created or not completion_created),
            )

    def require_completed(self, request_id: str) -> FakePublicActionObservation:
        request_id = _identifier("request id", request_id)
        if self.store.verify_chain().get("valid") is not True:
            raise PublicActionDenied("LEDGER_CHAIN_INVALID")
        with self._exclusive_lock():
            terminal = self._terminal_event(request_id)
            if terminal is None:
                raise PublicActionDenied("PUBLIC_ACTION_NOT_COMPLETED")
            observation = self._observation_from_event(terminal, replayed=True)
            registration = self._actions.get(observation.action_id)
            if registration is None:
                raise PublicActionDenied("ACTION_REGISTRY_DRIFT")
            deployment = self._require_deployment(
                registration,
                observation.deployment_request_id,
            )
            self._validate_terminal(
                observation,
                registration,
                deployment,
                None,
            )
            self._verify_outbox_readback(registration.spec, observation)
            return observation

    def _require_deployment(
        self,
        registration: _RegisteredAction,
        request_id: str,
    ) -> DeploymentObservation:
        try:
            deployment = self.deployment.require_deployed(request_id)
        except DeploymentDenied as error:
            raise PublicActionDenied(error.reason_code) from error
        if (
            deployment.target_id != registration.spec.deployment_target_id
            or deployment.kind != "local_fake"
            or deployment.status != "deployed"
            or not deployment.public_action_eligible
            or not deployment.sink_readback_verified
            or deployment.network_effect
            or deployment.provider_effect
            or deployment.credential_use
            or deployment.production_effect
        ):
            raise PublicActionDenied("DEPLOYMENT_BINDING_MISMATCH")
        return deployment

    @classmethod
    def _make_preview(
        cls,
        registration: _RegisteredAction,
        deployment: DeploymentObservation,
    ) -> FakePublicActionPreview:
        envelope = cls._envelope_payload(registration, deployment)
        envelope_sha256 = sha256(
            canonical_json(envelope).encode("utf-8")
        ).hexdigest()
        item = cls._outbox_payload(
            registration,
            deployment,
            envelope_sha256=envelope_sha256,
        )
        item_bytes = (canonical_json(item) + "\n").encode("utf-8")
        if len(item_bytes) > registration.spec.max_item_bytes:
            raise PublicActionDenied("OUTBOX_ITEM_TOO_LARGE")
        preview_payload = {
            "schema_version": PUBLIC_ACTION_PREVIEW_SCHEMA_VERSION,
            "action_id": registration.spec.id,
            "action_spec_sha256": registration.spec_sha256,
            "kind": registration.spec.kind,
            "channel": registration.spec.channel,
            "action": registration.spec.action,
            "deployment_request_id": deployment.request_id,
            "deployment_event_id": deployment.terminal_event_id,
            "deployment_target_id": deployment.target_id,
            "deployment_manifest_sha256": deployment.manifest_sha256,
            "artifact_sha256": deployment.artifact_sha256,
            "sink_readback_sha256": deployment.sink_readback_sha256,
            "envelope_sha256": envelope_sha256,
            "outbox_item_name_sha256": sha256(
                registration.spec.outbox_item_name.encode("utf-8")
            ).hexdigest(),
            "outbox_item_sha256": sha256(item_bytes).hexdigest(),
            "outbox_item_byte_count": len(item_bytes),
            "outbox_expected_before": "absent",
            "real_public_effect": False,
            "network_effect": False,
            "provider_effect": False,
            "credential_use": False,
            "production_effect": False,
        }
        return FakePublicActionPreview(
            action_id=registration.spec.id,
            action_spec_sha256=registration.spec_sha256,
            kind="fake_sink",
            channel="local_fake",
            action="publish",
            deployment_request_id=deployment.request_id,
            deployment_event_id=deployment.terminal_event_id,
            deployment_target_id=deployment.target_id,
            deployment_manifest_sha256=deployment.manifest_sha256,
            artifact_sha256=deployment.artifact_sha256,
            sink_readback_sha256=deployment.sink_readback_sha256,
            envelope_sha256=envelope_sha256,
            outbox_item_sha256=sha256(item_bytes).hexdigest(),
            outbox_item_byte_count=len(item_bytes),
            preview_sha256=sha256(
                canonical_json(preview_payload).encode("utf-8")
            ).hexdigest(),
        )

    @staticmethod
    def _envelope_payload(
        registration: _RegisteredAction,
        deployment: DeploymentObservation,
    ) -> dict[str, object]:
        spec = registration.spec
        return {
            "schema_version": PUBLIC_ACTION_ENVELOPE_SCHEMA_VERSION,
            "kind": spec.kind,
            "channel": spec.channel,
            "action": spec.action,
            "envelope_type": spec.envelope_type,
            "template_id": spec.template_id,
            "deployment_target_id": deployment.target_id,
            "deployment_manifest_sha256": deployment.manifest_sha256,
            "artifact_sha256": deployment.artifact_sha256,
            "sink_readback_sha256": deployment.sink_readback_sha256,
        }

    @staticmethod
    def _outbox_payload(
        registration: _RegisteredAction,
        deployment: DeploymentObservation,
        *,
        envelope_sha256: str,
    ) -> dict[str, object]:
        spec = registration.spec
        return {
            "schema_version": PUBLIC_ACTION_OUTBOX_SCHEMA_VERSION,
            "action_id": spec.id,
            "kind": spec.kind,
            "channel": spec.channel,
            "action": spec.action,
            "envelope_type": spec.envelope_type,
            "template_id": spec.template_id,
            "deployment_request_id": deployment.request_id,
            "deployment_event_id": deployment.terminal_event_id,
            "deployment_target_id": deployment.target_id,
            "deployment_manifest_sha256": deployment.manifest_sha256,
            "artifact_sha256": deployment.artifact_sha256,
            "sink_readback_sha256": deployment.sink_readback_sha256,
            "envelope_sha256": envelope_sha256,
            "real_public_effect": False,
            "network_effect": False,
            "provider_effect": False,
            "credential_use": False,
            "production_effect": False,
        }

    @classmethod
    def _outbox_bytes(
        cls,
        registration: _RegisteredAction,
        deployment: DeploymentObservation,
    ) -> bytes:
        envelope_sha256 = sha256(
            canonical_json(
                cls._envelope_payload(registration, deployment)
            ).encode("utf-8")
        ).hexdigest()
        return (
            canonical_json(
                cls._outbox_payload(
                    registration,
                    deployment,
                    envelope_sha256=envelope_sha256,
                )
            )
            + "\n"
        ).encode("utf-8")

    @staticmethod
    def _validate_request_preview(
        request: FakePublicActionRequest,
        preview: FakePublicActionPreview,
    ) -> None:
        if (
            request.action_id != preview.action_id
            or request.deployment_request_id != preview.deployment_request_id
            or request.expected_deployment_event_id != preview.deployment_event_id
            or request.expected_sink_readback_sha256 != preview.sink_readback_sha256
            or request.expected_envelope_sha256 != preview.envelope_sha256
            or request.expected_preview_sha256 != preview.preview_sha256
        ):
            raise PublicActionDenied("ACTION_PREVIEW_MISMATCH")

    @staticmethod
    def _claim_payload(
        request: FakePublicActionRequest,
        registration: _RegisteredAction,
        preview: FakePublicActionPreview,
    ) -> dict[str, object]:
        spec = registration.spec
        return {
            "schema_version": PUBLIC_ACTION_CLAIM_SCHEMA_VERSION,
            "request_id": request.id,
            "action_id": spec.id,
            "action_spec_sha256": registration.spec_sha256,
            "kind": spec.kind,
            "channel": spec.channel,
            "action": spec.action,
            "deployment_request_id": preview.deployment_request_id,
            "deployment_event_id": preview.deployment_event_id,
            "deployment_target_id": preview.deployment_target_id,
            "deployment_manifest_sha256": preview.deployment_manifest_sha256,
            "artifact_sha256": preview.artifact_sha256,
            "sink_readback_sha256": preview.sink_readback_sha256,
            "envelope_sha256": preview.envelope_sha256,
            "preview_sha256": preview.preview_sha256,
            "outbox_item_name_sha256": sha256(
                spec.outbox_item_name.encode("utf-8")
            ).hexdigest(),
            "outbox_item_sha256": preview.outbox_item_sha256,
            "outbox_item_byte_count": preview.outbox_item_byte_count,
            "outbox_expected_before": "absent",
            "outbox_content_persisted_in_ledger": False,
            "real_public_effect": False,
            "network_effect": False,
            "provider_effect": False,
            "credential_use": False,
            "production_effect": False,
        }

    def _record_completion(
        self,
        request: FakePublicActionRequest,
        registration: _RegisteredAction,
        claim: Event,
        preview: FakePublicActionPreview,
        item: _OutboxSnapshot,
    ) -> tuple[Event, bool]:
        spec = registration.spec
        payload = {
            "schema_version": PUBLIC_ACTION_RECEIPT_SCHEMA_VERSION,
            "request_id": request.id,
            "claim_event_id": claim.event_id,
            "action_id": spec.id,
            "action_spec_sha256": registration.spec_sha256,
            "kind": spec.kind,
            "channel": spec.channel,
            "action": spec.action,
            "deployment_request_id": preview.deployment_request_id,
            "deployment_event_id": preview.deployment_event_id,
            "deployment_target_id": preview.deployment_target_id,
            "deployment_manifest_sha256": preview.deployment_manifest_sha256,
            "artifact_sha256": preview.artifact_sha256,
            "sink_readback_sha256": preview.sink_readback_sha256,
            "envelope_sha256": preview.envelope_sha256,
            "preview_sha256": preview.preview_sha256,
            "outbox_item_name_sha256": sha256(
                spec.outbox_item_name.encode("utf-8")
            ).hexdigest(),
            "outbox_item_sha256": preview.outbox_item_sha256,
            "outbox_item_byte_count": preview.outbox_item_byte_count,
            "outbox_readback_sha256": item.digest,
            "outbox_readback_byte_count": len(item.content),
            "outbox_readback_verified": True,
            "outbox_mutation_count": 1,
            "status": "sent",
            "outbox_content_persisted_in_ledger": False,
            "real_public_effect": False,
            "network_effect": False,
            "provider_effect": False,
            "credential_use": False,
            "production_effect": False,
        }
        try:
            event, created = self.store.append_once_result(
                "public_action.fake_sink.completed",
                request.id,
                payload,
            )
        except ValueError as error:
            raise PublicActionDenied("COMPLETION_RECEIPT_COLLISION") from error
        except Exception as error:
            raise PublicActionDenied("RECEIPT_PERSISTENCE_FAILED") from error
        if canonical_json(event.payload) != canonical_json(payload):
            raise PublicActionDenied("COMPLETION_RECEIPT_COLLISION")
        return event, created

    def _claim_event(self, request_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("public_action.fake_sink.claimed")
            if event.payload.get("request_id") == request_id
        ]
        if len(rows) > 1:
            raise PublicActionDenied("DUPLICATE_CLAIM_RECEIPTS")
        return rows[0] if rows else None

    def _terminal_event(self, request_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("public_action.fake_sink.completed")
            if event.payload.get("request_id") == request_id
        ]
        if len(rows) > 1:
            raise PublicActionDenied("DUPLICATE_COMPLETION_RECEIPTS")
        return rows[0] if rows else None

    @staticmethod
    def _observation_from_event(
        event: Event,
        *,
        replayed: bool,
    ) -> FakePublicActionObservation:
        payload = event.payload
        required = {
            "schema_version",
            "request_id",
            "claim_event_id",
            "action_id",
            "action_spec_sha256",
            "kind",
            "channel",
            "action",
            "deployment_request_id",
            "deployment_event_id",
            "deployment_target_id",
            "deployment_manifest_sha256",
            "artifact_sha256",
            "sink_readback_sha256",
            "envelope_sha256",
            "preview_sha256",
            "outbox_item_name_sha256",
            "outbox_item_sha256",
            "outbox_item_byte_count",
            "outbox_readback_sha256",
            "outbox_readback_byte_count",
            "outbox_readback_verified",
            "outbox_mutation_count",
            "status",
            "outbox_content_persisted_in_ledger",
            "real_public_effect",
            "network_effect",
            "provider_effect",
            "credential_use",
            "production_effect",
        }
        string_fields = (
            "request_id",
            "claim_event_id",
            "action_id",
            "deployment_request_id",
            "deployment_event_id",
            "deployment_target_id",
        )
        digest_fields = (
            "action_spec_sha256",
            "deployment_manifest_sha256",
            "artifact_sha256",
            "sink_readback_sha256",
            "envelope_sha256",
            "preview_sha256",
            "outbox_item_name_sha256",
            "outbox_item_sha256",
            "outbox_readback_sha256",
        )
        integer_fields = (
            "outbox_item_byte_count",
            "outbox_readback_byte_count",
            "outbox_mutation_count",
        )
        if (
            set(payload) != required
            or payload.get("schema_version") != PUBLIC_ACTION_RECEIPT_SCHEMA_VERSION
            or payload.get("kind") != "fake_sink"
            or payload.get("channel") != "local_fake"
            or payload.get("action") != "publish"
            or payload.get("status") != "sent"
            or any(not isinstance(payload.get(field), str) for field in string_fields)
            or any(
                not isinstance(payload.get(field), str)
                or not _DIGEST.fullmatch(str(payload[field]))
                for field in digest_fields
            )
            or any(
                isinstance(payload.get(field), bool)
                or not isinstance(payload.get(field), int)
                or int(payload[field]) < 0
                for field in integer_fields
            )
            or payload.get("outbox_item_byte_count")
            != payload.get("outbox_readback_byte_count")
            or payload.get("outbox_item_sha256")
            != payload.get("outbox_readback_sha256")
            or payload.get("outbox_readback_verified") is not True
            or payload.get("outbox_mutation_count") != 1
            or payload.get("outbox_content_persisted_in_ledger") is not False
            or payload.get("real_public_effect") is not False
            or payload.get("network_effect") is not False
            or payload.get("provider_effect") is not False
            or payload.get("credential_use") is not False
            or payload.get("production_effect") is not False
        ):
            raise PublicActionDenied("MALFORMED_COMPLETION_RECEIPT")
        return FakePublicActionObservation(
            request_id=str(payload["request_id"]),
            action_id=str(payload["action_id"]),
            action_spec_sha256=str(payload["action_spec_sha256"]),
            kind="fake_sink",
            channel="local_fake",
            action="publish",
            deployment_request_id=str(payload["deployment_request_id"]),
            deployment_event_id=str(payload["deployment_event_id"]),
            deployment_target_id=str(payload["deployment_target_id"]),
            deployment_manifest_sha256=str(payload["deployment_manifest_sha256"]),
            artifact_sha256=str(payload["artifact_sha256"]),
            sink_readback_sha256=str(payload["sink_readback_sha256"]),
            envelope_sha256=str(payload["envelope_sha256"]),
            preview_sha256=str(payload["preview_sha256"]),
            outbox_item_sha256=str(payload["outbox_item_sha256"]),
            outbox_readback_sha256=str(payload["outbox_readback_sha256"]),
            outbox_readback_verified=True,
            outbox_mutation_count=1,
            status="sent",
            terminal_event_id=event.event_id,
            replayed=replayed,
        )

    @staticmethod
    def _validate_terminal(
        observation: FakePublicActionObservation,
        registration: _RegisteredAction,
        deployment: DeploymentObservation,
        request: FakePublicActionRequest | None,
    ) -> None:
        spec = registration.spec
        if (
            observation.action_id != spec.id
            or observation.action_spec_sha256 != registration.spec_sha256
            or observation.kind != spec.kind
            or observation.channel != spec.channel
            or observation.action != spec.action
        ):
            raise PublicActionDenied("ACTION_REGISTRY_DRIFT")
        if (
            observation.deployment_request_id != deployment.request_id
            or observation.deployment_event_id != deployment.terminal_event_id
            or observation.deployment_target_id != deployment.target_id
            or observation.deployment_manifest_sha256 != deployment.manifest_sha256
            or observation.artifact_sha256 != deployment.artifact_sha256
            or observation.sink_readback_sha256 != deployment.sink_readback_sha256
        ):
            raise PublicActionDenied("DEPLOYMENT_RECEIPT_STALE")
        if request is not None and (
            observation.request_id != request.id
            or observation.action_id != request.action_id
            or observation.deployment_request_id != request.deployment_request_id
            or observation.deployment_event_id
            != request.expected_deployment_event_id
            or observation.sink_readback_sha256
            != request.expected_sink_readback_sha256
            or observation.envelope_sha256 != request.expected_envelope_sha256
            or observation.preview_sha256 != request.expected_preview_sha256
        ):
            raise PublicActionDenied("COMPLETION_RECEIPT_COLLISION")

    def _verify_outbox_readback(
        self,
        spec: FakePublicActionSpec,
        observation: FakePublicActionObservation,
    ) -> None:
        item = self._read_outbox_item(spec, missing_ok=True)
        if item is None or item.digest != observation.outbox_readback_sha256:
            raise PublicActionDenied("OUTBOX_READBACK_STALE")

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        try:
            descriptor = os.open(
                self._lock_path,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as error:
            raise PublicActionDenied("PUBLIC_ACTION_LOCK_UNAVAILABLE") from error
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @contextmanager
    def _root_descriptor(self) -> Iterator[int]:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(self.outbox_root, flags)
        except OSError as error:
            raise PublicActionDenied("OUTBOX_ROOT_UNAVAILABLE") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                (metadata.st_dev, metadata.st_ino) != self._root_identity
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
            ):
                raise PublicActionDenied("OUTBOX_ROOT_CHANGED")
            yield descriptor
        finally:
            os.close(descriptor)

    def _read_outbox_item(
        self,
        spec: FakePublicActionSpec,
        *,
        missing_ok: bool,
    ) -> _OutboxSnapshot | None:
        with self._root_descriptor() as root_fd:
            try:
                descriptor = os.open(
                    spec.outbox_item_name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=root_fd,
                )
            except FileNotFoundError:
                if missing_ok:
                    return None
                raise PublicActionDenied("OUTBOX_ITEM_UNAVAILABLE")
            except OSError as error:
                if error.errno == errno.ELOOP:
                    raise PublicActionDenied("OUTBOX_SYMLINK_DENIED") from error
                raise PublicActionDenied("OUTBOX_ITEM_UNAVAILABLE") from error
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise PublicActionDenied("OUTBOX_NOT_REGULAR")
                if metadata.st_uid != os.getuid():
                    raise PublicActionDenied("OUTBOX_OWNER_DENIED")
                if metadata.st_nlink != 1:
                    raise PublicActionDenied("OUTBOX_LINK_COUNT_DENIED")
                if metadata.st_size > spec.max_item_bytes:
                    raise PublicActionDenied("OUTBOX_ITEM_TOO_LARGE")
                content = bytearray()
                while True:
                    chunk = os.read(
                        descriptor,
                        min(65_536, spec.max_item_bytes + 1 - len(content)),
                    )
                    if not chunk:
                        break
                    content.extend(chunk)
                    if len(content) > spec.max_item_bytes:
                        raise PublicActionDenied("OUTBOX_ITEM_TOO_LARGE")
                path_metadata = os.stat(
                    spec.outbox_item_name,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
                if (
                    path_metadata.st_dev != metadata.st_dev
                    or path_metadata.st_ino != metadata.st_ino
                ):
                    raise PublicActionDenied("OUTBOX_IDENTITY_CHANGED")
                return _OutboxSnapshot(
                    content=bytes(content),
                    device=metadata.st_dev,
                    inode=metadata.st_ino,
                )
            finally:
                os.close(descriptor)

    def _atomic_create_outbox_item(
        self,
        spec: FakePublicActionSpec,
        content: bytes,
    ) -> None:
        if len(content) > spec.max_item_bytes:
            raise PublicActionDenied("OUTBOX_ITEM_TOO_LARGE")
        with self._root_descriptor() as root_fd:
            temporary = f".cct-public-action-{secrets.token_hex(16)}"
            descriptor = -1
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=root_fd,
                )
                view = memoryview(content)
                written = 0
                while written < len(view):
                    written += os.write(descriptor, view[written:])
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                try:
                    os.link(
                        temporary,
                        spec.outbox_item_name,
                        src_dir_fd=root_fd,
                        dst_dir_fd=root_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError as error:
                    raise PublicActionDenied("OUTBOX_ITEM_ALREADY_EXISTS") from error
                os.unlink(temporary, dir_fd=root_fd)
                os.fsync(root_fd)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    os.unlink(temporary, dir_fd=root_fd)
                except FileNotFoundError:
                    pass


__all__ = [
    "FakePublicActionObservation",
    "FakePublicActionPreview",
    "FakePublicActionRequest",
    "FakePublicActionSpec",
    "LocalFakePublicActionAdapter",
    "PublicActionDenied",
]
