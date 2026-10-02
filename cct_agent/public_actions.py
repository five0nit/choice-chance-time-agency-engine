"""Typed public-action adapter limited to a private local fake outbox."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
import errno
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import stat
from types import MappingProxyType
from typing import Any, Iterator, Literal, Mapping, Protocol, Sequence

from .deployment import (
    DeploymentDenied,
    DeploymentObservation,
    LocalFakeDeploymentAdapter,
)
from .execution_tickets import GlobalKillSwitch, TicketAuthorityDenied
from .mediation_outcomes import OutcomeVerification, OutcomeVerifierRegistry, VerificationContext
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


OPERATOR_PUBLIC_POST_CLAIM_SCHEMA_VERSION = "cct.operator_public_post.claim.v1"
OPERATOR_PUBLIC_POST_RECEIPT_SCHEMA_VERSION = "cct.operator_public_post.receipt.v1"
OPERATOR_PUBLIC_POST_VERIFIER_ID = "operator-public-readback"
MAX_OPERATOR_PUBLIC_CHANNELS = 64
MAX_OPERATOR_PUBLIC_CONTENT_BYTES = 65_536
MAX_OPERATOR_PUBLIC_DAILY_CAP = 100


def _operator_hash(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _optional_digest(name: str, value: object) -> str | None:
    if value is None:
        return None
    return _digest(name, value)


def _public_content(value: object, *, maximum: int) -> tuple[str, bytes]:
    if not isinstance(value, str) or not value:
        raise ValueError("content must be a non-empty string")
    if "\x00" in value or any(0 <= ord(character) < 9 for character in value):
        raise ValueError("content contains unsupported control characters")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("content must be valid UTF-8") from error
    if not encoded or len(encoded) > maximum:
        raise ValueError(f"content must be 1-{maximum} UTF-8 bytes")
    return value, encoded


def _public_day(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise PublicActionDenied("PUBLIC_CLOCK_INVALID") from error
    if parsed.tzinfo is None:
        raise PublicActionDenied("PUBLIC_CLOCK_INVALID")
    return parsed.date().isoformat()


@dataclass(frozen=True, slots=True)
class OperatorPublicChannel:
    """Host-owned exact account/channel/recipient route for one public driver."""

    id: str
    driver_id: str
    provider: str
    account_id: str
    channel_id: str
    recipient_id: str
    owner_principal_id: str
    max_content_bytes: int
    daily_action_cap: int
    real_public_effect: bool

    def __post_init__(self) -> None:
        for field in (
            "id",
            "driver_id",
            "provider",
            "account_id",
            "channel_id",
            "recipient_id",
            "owner_principal_id",
        ):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        _bounded_integer(
            "max_content_bytes",
            self.max_content_bytes,
            minimum=1,
            maximum=MAX_OPERATOR_PUBLIC_CONTENT_BYTES,
        )
        _bounded_integer(
            "daily_action_cap",
            self.daily_action_cap,
            minimum=1,
            maximum=MAX_OPERATOR_PUBLIC_DAILY_CAP,
        )
        if not isinstance(self.real_public_effect, bool):
            raise ValueError("real_public_effect must be a boolean")

    @property
    def cap_key_sha256(self) -> str:
        return _operator_hash(
            {
                "provider": self.provider,
                "account_id": self.account_id,
                "channel_id": self.channel_id,
            }
        )


@dataclass(frozen=True, slots=True)
class ProviderPublicChannelAuthority:
    """Host-driver ownership/authentication readback without credentials."""

    target_id: str
    provider: str
    account_id: str
    channel_id: str
    recipient_id: str
    owner_principal_id: str
    authenticated: bool
    real_public_effect: bool
    authority_receipt_sha256: str

    def __post_init__(self) -> None:
        for field in (
            "target_id",
            "provider",
            "account_id",
            "channel_id",
            "recipient_id",
            "owner_principal_id",
        ):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.authenticated, bool) or not isinstance(
            self.real_public_effect, bool
        ):
            raise ValueError("provider public authority flags must be booleans")
        _digest("authority_receipt_sha256", self.authority_receipt_sha256)


@dataclass(frozen=True, slots=True)
class ProviderPublicPostState:
    """Privacy-safe provider readback. Raw post content stays outside ledger."""

    target_id: str
    provider: str
    account_id: str
    channel_id: str
    recipient_id: str
    posted: bool
    content_sha256: str | None
    content_byte_count: int
    provider_post_id_sha256: str
    provider_receipt_sha256: str
    last_operation_id: str | None
    real_public_effect: bool

    def __post_init__(self) -> None:
        for field in (
            "target_id",
            "provider",
            "account_id",
            "channel_id",
            "recipient_id",
        ):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.posted, bool) or not isinstance(self.real_public_effect, bool):
            raise ValueError("provider public-post flags must be booleans")
        _optional_digest("content_sha256", self.content_sha256)
        _bounded_integer(
            "content_byte_count",
            self.content_byte_count,
            minimum=0,
            maximum=MAX_OPERATOR_PUBLIC_CONTENT_BYTES,
        )
        _digest("provider_post_id_sha256", self.provider_post_id_sha256)
        _digest("provider_receipt_sha256", self.provider_receipt_sha256)
        if self.last_operation_id is not None:
            object.__setattr__(
                self,
                "last_operation_id",
                _identifier("last_operation_id", self.last_operation_id),
            )
        if self.posted != (self.content_sha256 is not None):
            raise ValueError("posted state and content digest disagree")
        if not self.posted and self.content_byte_count != 0:
            raise ValueError("absent post cannot report content bytes")

    @property
    def state_sha256(self) -> str:
        return _operator_hash(asdict(self))


@dataclass(frozen=True, slots=True)
class PublicPostProviderCommand:
    operation_id: str
    target_id: str
    provider: str
    account_id: str
    channel_id: str
    recipient_id: str
    content: str
    content_sha256: str
    content_byte_count: int
    expected_before_state_sha256: str
    preview_sha256: str
    credential_handles: tuple[str, ...] = ()


class OperatorPublicPostDriver(Protocol):
    def authority(
        self, target: OperatorPublicChannel
    ) -> ProviderPublicChannelAuthority: ...

    def inspect(
        self,
        target: OperatorPublicChannel,
        operation_id: str | None = None,
    ) -> ProviderPublicPostState: ...

    def post(
        self,
        target: OperatorPublicChannel,
        command: PublicPostProviderCommand,
    ) -> None: ...


class LocalFakePublicChannelDriver:
    """Durable local fake provider proving exact dispatch/readback without publication."""

    def __init__(self, *, state_root: str | Path, provider: str) -> None:
        root = Path(state_root)
        if not root.is_absolute() or root.is_symlink():
            raise ValueError("state_root must be an absolute real directory")
        try:
            resolved = root.resolve(strict=True)
            metadata = resolved.stat()
        except OSError as error:
            raise ValueError("state_root must be an existing real directory") from error
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError("state_root must be an owned real directory")
        os.chmod(resolved, 0o700)
        self.state_root = resolved
        self.provider = _identifier("provider", provider)
        self.mutation_count = 0

    def _path(self, target_id: str) -> Path:
        return self.state_root / f"{sha256(target_id.encode()).hexdigest()}.json"

    def _read(self, target_id: str) -> dict[str, Any] | None:
        path = self._path(target_id)
        descriptor: int | None = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or metadata.st_size > 65_536
            ):
                raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_STATE_UNSAFE")
            content = bytearray()
            while chunk := os.read(descriptor, 65_536):
                content.extend(chunk)
                if len(content) > 65_536:
                    raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_STATE_INVALID")
            value = json.loads(content)
        except FileNotFoundError:
            return None
        except PublicActionDenied:
            raise
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_STATE_INVALID") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not isinstance(value, dict) or value.get("target_id") != target_id:
            raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_STATE_INVALID")
        return value

    def _write(self, target_id: str, payload: Mapping[str, Any]) -> None:
        destination = self._path(target_id)
        temporary = self.state_root / f".{destination.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        data = canonical_json(payload).encode("utf-8")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            written = 0
            while written < len(data):
                written += os.write(descriptor, data[written:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
        except OSError as error:
            raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_STATE_WRITE_FAILED") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _binding(self, target: OperatorPublicChannel) -> None:
        if target.provider != self.provider or target.real_public_effect:
            raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_BINDING_MISMATCH")

    def authority(self, target: OperatorPublicChannel) -> ProviderPublicChannelAuthority:
        self._binding(target)
        material = {
            "driver": "local-fake-public",
            "target_id": target.id,
            "provider": target.provider,
            "account_id": target.account_id,
            "channel_id": target.channel_id,
            "recipient_id": target.recipient_id,
            "owner_principal_id": target.owner_principal_id,
            "authenticated": False,
            "real_public_effect": False,
        }
        return ProviderPublicChannelAuthority(
            target_id=target.id,
            provider=target.provider,
            account_id=target.account_id,
            channel_id=target.channel_id,
            recipient_id=target.recipient_id,
            owner_principal_id=target.owner_principal_id,
            authenticated=False,
            real_public_effect=False,
            authority_receipt_sha256=_operator_hash(material),
        )

    def inspect(
        self,
        target: OperatorPublicChannel,
        operation_id: str | None = None,
    ) -> ProviderPublicPostState:
        self._binding(target)
        requested_operation_id = (
            _identifier("operation_id", operation_id) if operation_id is not None else None
        )
        metadata = self._read(target.id)
        if metadata is not None:
            expected_binding = {
                "schema_version": 1,
                "target_id": target.id,
                "provider": target.provider,
                "account_id": target.account_id,
                "channel_id": target.channel_id,
                "recipient_id": target.recipient_id,
                "owner_principal_id": target.owner_principal_id,
                "raw_content_persisted": False,
                "real_public_effect": False,
            }
            if any(metadata.get(key) != value for key, value in expected_binding.items()):
                raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_STATE_BINDING_MISMATCH")
            posts = metadata.get("posts")
            if not isinstance(metadata.get("last_operation_id"), str) or not isinstance(
                posts, dict
            ):
                raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_STATE_INVALID")
            if not 1 <= len(posts) <= MAX_OPERATOR_PUBLIC_DAILY_CAP:
                raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_STATE_INVALID")
            for stored_operation_id, post in posts.items():
                _identifier("stored operation_id", stored_operation_id)
                if (
                    not isinstance(post, dict)
                    or set(post) != {"content_sha256", "content_byte_count"}
                    or not isinstance(post.get("content_sha256"), str)
                    or isinstance(post.get("content_byte_count"), bool)
                    or not isinstance(post.get("content_byte_count"), int)
                ):
                    raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_STATE_INVALID")
                _digest("stored content_sha256", post["content_sha256"])
                _bounded_integer(
                    "stored content_byte_count",
                    post["content_byte_count"],
                    minimum=1,
                    maximum=target.max_content_bytes,
                )
            if metadata["last_operation_id"] not in posts:
                raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_STATE_INVALID")
        posts = metadata["posts"] if metadata else {}
        selected_operation_id = (
            requested_operation_id
            if requested_operation_id in posts
            else (
                str(metadata["last_operation_id"])
                if metadata is not None and operation_id is None
                else None
            )
        )
        selected = posts.get(selected_operation_id) if selected_operation_id is not None else None
        content_sha256 = str(selected["content_sha256"]) if selected else None
        content_byte_count = int(selected["content_byte_count"]) if selected else 0
        material = {
            "provider": self.provider,
            "target_id": target.id,
            "account_id": target.account_id,
            "channel_id": target.channel_id,
            "recipient_id": target.recipient_id,
            "content_sha256": content_sha256,
            "content_byte_count": content_byte_count,
            "last_operation_id": selected_operation_id,
            "inspection_operation_id": requested_operation_id,
            "history_sha256": _operator_hash(posts),
            "real_public_effect": False,
        }
        return ProviderPublicPostState(
            target_id=target.id,
            provider=self.provider,
            account_id=target.account_id,
            channel_id=target.channel_id,
            recipient_id=target.recipient_id,
            posted=selected is not None,
            content_sha256=content_sha256,
            content_byte_count=content_byte_count,
            provider_post_id_sha256=_operator_hash(
                {
                    "provider": self.provider,
                    "target_id": target.id,
                    "operation": selected_operation_id,
                }
            ),
            provider_receipt_sha256=_operator_hash(material),
            last_operation_id=selected_operation_id,
            real_public_effect=False,
        )

    def post(
        self,
        target: OperatorPublicChannel,
        command: PublicPostProviderCommand,
    ) -> None:
        self._binding(target)
        for name, value in (
            ("operation_id", command.operation_id),
            ("target_id", command.target_id),
            ("provider", command.provider),
            ("account_id", command.account_id),
            ("channel_id", command.channel_id),
            ("recipient_id", command.recipient_id),
        ):
            _identifier(name, value)
        _digest("content_sha256", command.content_sha256)
        _digest("expected_before_state_sha256", command.expected_before_state_sha256)
        _digest("preview_sha256", command.preview_sha256)
        _bounded_integer(
            "content_byte_count",
            command.content_byte_count,
            minimum=1,
            maximum=target.max_content_bytes,
        )
        if (
            command.target_id != target.id
            or command.provider != target.provider
            or command.account_id != target.account_id
            or command.channel_id != target.channel_id
            or command.recipient_id != target.recipient_id
            or command.credential_handles
        ):
            raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_COMMAND_MISMATCH")
        _content, content_bytes = _public_content(
            command.content, maximum=target.max_content_bytes
        )
        if (
            sha256(content_bytes).hexdigest() != command.content_sha256
            or len(content_bytes) != command.content_byte_count
        ):
            raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_CONTENT_MISMATCH")
        existing = self.inspect(target, command.operation_id)
        if (
            existing.last_operation_id == command.operation_id
            and existing.content_sha256 == command.content_sha256
            and existing.content_byte_count == command.content_byte_count
        ):
            return
        current = self.inspect(target)
        if current.state_sha256 != command.expected_before_state_sha256:
            raise PublicActionDenied("FAKE_PUBLIC_PROVIDER_PRESTATE_CHANGED")
        metadata = self._read(target.id)
        posts = dict(metadata["posts"]) if metadata else {}
        posts[command.operation_id] = {
            "content_sha256": command.content_sha256,
            "content_byte_count": command.content_byte_count,
        }
        self._write(
            target.id,
            {
                "schema_version": 1,
                "target_id": target.id,
                "provider": target.provider,
                "account_id": target.account_id,
                "channel_id": target.channel_id,
                "recipient_id": target.recipient_id,
                "owner_principal_id": target.owner_principal_id,
                "posts": posts,
                "last_operation_id": command.operation_id,
                "raw_content_persisted": False,
                "real_public_effect": False,
            },
        )
        self.mutation_count += 1

    def seed_foreign_post(
        self,
        target: OperatorPublicChannel,
        *,
        content_sha256: str,
    ) -> None:
        """Test-only host fixture for provider drift; no raw content is stored."""

        self._binding(target)
        digest = _digest("content_sha256", content_sha256)
        operation_id = "foreign-provider-post"
        self._write(
            target.id,
            {
                "schema_version": 1,
                "target_id": target.id,
                "provider": target.provider,
                "account_id": target.account_id,
                "channel_id": target.channel_id,
                "recipient_id": target.recipient_id,
                "owner_principal_id": target.owner_principal_id,
                "posts": {
                    operation_id: {
                        "content_sha256": digest,
                        "content_byte_count": 1,
                    }
                },
                "last_operation_id": operation_id,
                "raw_content_persisted": False,
                "real_public_effect": False,
            },
        )


@dataclass(frozen=True, slots=True)
class OperatorPublicPostPreview:
    channel_id: str
    channel_spec_sha256: str
    provider: str
    account_id: str
    provider_channel_id: str
    recipient_id: str
    owner_principal_id: str
    provider_authenticated: bool
    provider_authority_receipt_sha256: str
    content_sha256: str
    content_byte_count: int
    before_state_sha256: str
    daily_bucket: str
    channel_cap_key_sha256: str
    daily_action_cap: int
    preview_sha256: str


@dataclass(frozen=True, slots=True)
class OperatorPublicPostInvocation:
    ticket_id: str
    channel_id: str
    content: str
    expected_content_sha256: str
    expected_content_byte_count: int
    expected_before_state_sha256: str
    expected_preview_sha256: str
    verifier_id: str
    max_bytes: int

    @classmethod
    def from_arguments(cls, arguments: Mapping[str, Any]) -> "OperatorPublicPostInvocation":
        if not isinstance(arguments, Mapping):
            raise ValueError("public-post arguments must be an object")
        fields = {
            "execution_ticket_id",
            "channel_id",
            "content",
            "expected_content_sha256",
            "expected_content_byte_count",
            "expected_before_state_sha256",
            "expected_preview_sha256",
            "verifier_id",
            "max_bytes",
        }
        if set(arguments) != fields:
            raise ValueError("public-post arguments require exact fields")
        content, encoded = _public_content(
            arguments["content"], maximum=MAX_OPERATOR_PUBLIC_CONTENT_BYTES
        )
        expected_sha256 = _digest(
            "expected_content_sha256", arguments["expected_content_sha256"]
        )
        expected_count = _bounded_integer(
            "expected_content_byte_count",
            arguments["expected_content_byte_count"],
            minimum=1,
            maximum=MAX_OPERATOR_PUBLIC_CONTENT_BYTES,
        )
        if sha256(encoded).hexdigest() != expected_sha256 or len(encoded) != expected_count:
            raise PublicActionDenied("PUBLIC_CONTENT_DIGEST_MISMATCH")
        return cls(
            ticket_id=_identifier("execution_ticket_id", arguments["execution_ticket_id"]),
            channel_id=_identifier("channel_id", arguments["channel_id"]),
            content=content,
            expected_content_sha256=expected_sha256,
            expected_content_byte_count=expected_count,
            expected_before_state_sha256=_digest(
                "expected_before_state_sha256", arguments["expected_before_state_sha256"]
            ),
            expected_preview_sha256=_digest(
                "expected_preview_sha256", arguments["expected_preview_sha256"]
            ),
            verifier_id=_identifier("verifier_id", arguments["verifier_id"]),
            max_bytes=_bounded_integer(
                "max_bytes",
                arguments["max_bytes"],
                minimum=1,
                maximum=MAX_OPERATOR_PUBLIC_CONTENT_BYTES,
            ),
        )


@dataclass(frozen=True, slots=True)
class _RegisteredOperatorPublicChannel:
    spec: OperatorPublicChannel
    spec_sha256: str
    driver: OperatorPublicPostDriver
    authority: ProviderPublicChannelAuthority


class OperatorPublicPostAdapter:
    """Dispatch exact ticketed public posts through host-registered channel drivers."""

    def __init__(
        self,
        store: EventStore,
        *,
        channels: Sequence[OperatorPublicChannel],
        drivers: Mapping[str, OperatorPublicPostDriver],
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        if not isinstance(drivers, Mapping):
            raise ValueError("drivers must be a mapping")
        principal_rows = store.events("principal.profile.installed")
        if not principal_rows:
            raise ValueError("public channels require an installed principal profile")
        principal_id = principal_rows[-1].payload.get("profile", {}).get("principal_id")
        if not isinstance(principal_id, str):
            raise ValueError("installed principal profile is malformed")
        registrations: dict[str, _RegisteredOperatorPublicChannel] = {}
        for channel in channels:
            if not isinstance(channel, OperatorPublicChannel) or channel.id in registrations:
                raise ValueError("channels must contain unique OperatorPublicChannel values")
            if channel.owner_principal_id != principal_id:
                raise ValueError("public channel owner must match installed principal")
            driver = drivers.get(channel.driver_id)
            if driver is None or not all(
                callable(getattr(driver, name, None))
                for name in ("authority", "inspect", "post")
            ):
                raise ValueError("public channel driver must be host-registered")
            authority = driver.authority(channel)
            if not isinstance(authority, ProviderPublicChannelAuthority):
                raise ValueError("public channel authority readback is malformed")
            if (
                authority.target_id != channel.id
                or authority.provider != channel.provider
                or authority.account_id != channel.account_id
                or authority.channel_id != channel.channel_id
                or authority.recipient_id != channel.recipient_id
                or authority.owner_principal_id != channel.owner_principal_id
                or authority.real_public_effect != channel.real_public_effect
            ):
                raise ValueError("public channel authority binding mismatch")
            if channel.real_public_effect and not authority.authenticated:
                raise ValueError("real public channel requires authenticated provider authority")
            registrations[channel.id] = _RegisteredOperatorPublicChannel(
                spec=channel,
                spec_sha256=_operator_hash(asdict(channel)),
                driver=driver,
                authority=authority,
            )
        if not 1 <= len(registrations) <= MAX_OPERATOR_PUBLIC_CHANNELS:
            raise ValueError(
                f"channels must contain 1-{MAX_OPERATOR_PUBLIC_CHANNELS} registrations"
            )
        self.store = store
        self._channels: Mapping[str, _RegisteredOperatorPublicChannel] = MappingProxyType(
            registrations
        )
        os.chmod(self.store.path, 0o600)
        for registration in registrations.values():
            spec = registration.spec
            payload = {
                "schema_version": 1,
                "authority": "host_adapter",
                "target_id": spec.id,
                "driver_id": spec.driver_id,
                "provider": spec.provider,
                "account_id": spec.account_id,
                "channel_id": spec.channel_id,
                "recipient_id": spec.recipient_id,
                "owner_principal_id": spec.owner_principal_id,
                "provider_authenticated": registration.authority.authenticated,
                "provider_authority_receipt_sha256": (
                    registration.authority.authority_receipt_sha256
                ),
                "max_content_bytes": spec.max_content_bytes,
                "daily_action_cap": spec.daily_action_cap,
                "real_public_effect": spec.real_public_effect,
                "channel_spec_sha256": registration.spec_sha256,
                "provider_configuration_persisted": False,
                "credential_values_persisted": False,
            }
            event, _created = self.store.append_once_result(
                "operator.public_post.channel.registered", spec.id, payload
            )
            if canonical_json(event.payload) != canonical_json(payload):
                raise ValueError(f"public channel registration changed: {spec.id}")

    @property
    def registered_channel_ids(self) -> frozenset[str]:
        return frozenset(self._channels)

    def outcome_verifiers(self) -> OutcomeVerifierRegistry:
        registry = OutcomeVerifierRegistry()
        registry.register(
            OPERATOR_PUBLIC_POST_VERIFIER_ID,
            self._verify_mediated_result,
            reconcile=self._reconcile_mediated_result,
            idempotency_proof_id="operator-public-post-ticket-receipt",
        )
        return registry

    def _registration(self, channel_id: str) -> _RegisteredOperatorPublicChannel:
        registration = self._channels.get(_identifier("channel_id", channel_id))
        if registration is None:
            raise PublicActionDenied("PUBLIC_CHANNEL_NOT_REGISTERED")
        return registration

    @staticmethod
    def _inspect(
        registration: _RegisteredOperatorPublicChannel,
        operation_id: str | None = None,
    ) -> ProviderPublicPostState:
        state = registration.driver.inspect(registration.spec, operation_id)
        if not isinstance(state, ProviderPublicPostState):
            raise PublicActionDenied("PUBLIC_PROVIDER_READBACK_MALFORMED")
        spec = registration.spec
        if (
            state.target_id != spec.id
            or state.provider != spec.provider
            or state.account_id != spec.account_id
            or state.channel_id != spec.channel_id
            or state.recipient_id != spec.recipient_id
            or state.real_public_effect != spec.real_public_effect
        ):
            raise PublicActionDenied("PUBLIC_PROVIDER_READBACK_BINDING_MISMATCH")
        return state

    def preview(self, *, channel_id: str, content: str) -> OperatorPublicPostPreview:
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise PublicActionDenied(error.reason_code) from error
        if self.store.verify_chain().get("valid") is not True:
            raise PublicActionDenied("LEDGER_CHAIN_INVALID")
        registration = self._registration(channel_id)
        _content, encoded = _public_content(
            content, maximum=registration.spec.max_content_bytes
        )
        before = self._inspect(registration)
        daily_bucket = _public_day(self.store.clock())
        material = {
            "schema_version": 1,
            "target_id": registration.spec.id,
            "channel_spec_sha256": registration.spec_sha256,
            "provider": registration.spec.provider,
            "account_id": registration.spec.account_id,
            "channel_id": registration.spec.channel_id,
            "recipient_id": registration.spec.recipient_id,
            "owner_principal_id": registration.spec.owner_principal_id,
            "provider_authenticated": registration.authority.authenticated,
            "provider_authority_receipt_sha256": (
                registration.authority.authority_receipt_sha256
            ),
            "content_sha256": sha256(encoded).hexdigest(),
            "content_byte_count": len(encoded),
            "before_state_sha256": before.state_sha256,
            "daily_bucket": daily_bucket,
            "channel_cap_key_sha256": registration.spec.cap_key_sha256,
            "daily_action_cap": registration.spec.daily_action_cap,
            "real_public_effect": registration.spec.real_public_effect,
            "credential_handles": [],
        }
        return OperatorPublicPostPreview(
            channel_id=registration.spec.id,
            channel_spec_sha256=registration.spec_sha256,
            provider=registration.spec.provider,
            account_id=registration.spec.account_id,
            provider_channel_id=registration.spec.channel_id,
            recipient_id=registration.spec.recipient_id,
            owner_principal_id=registration.spec.owner_principal_id,
            provider_authenticated=registration.authority.authenticated,
            provider_authority_receipt_sha256=(
                registration.authority.authority_receipt_sha256
            ),
            content_sha256=sha256(encoded).hexdigest(),
            content_byte_count=len(encoded),
            before_state_sha256=before.state_sha256,
            daily_bucket=daily_bucket,
            channel_cap_key_sha256=registration.spec.cap_key_sha256,
            daily_action_cap=registration.spec.daily_action_cap,
            preview_sha256=_operator_hash(material),
        )

    @staticmethod
    def _validate_preview(
        request: OperatorPublicPostInvocation,
        preview: OperatorPublicPostPreview,
    ) -> None:
        if (
            request.channel_id != preview.channel_id
            or request.expected_content_sha256 != preview.content_sha256
            or request.expected_content_byte_count != preview.content_byte_count
            or request.expected_before_state_sha256 != preview.before_state_sha256
            or request.expected_preview_sha256 != preview.preview_sha256
        ):
            raise PublicActionDenied("PUBLIC_POST_PREVIEW_STALE")

    def execute(self, arguments: Mapping[str, Any]) -> str:
        request = OperatorPublicPostInvocation.from_arguments(arguments)
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise PublicActionDenied(error.reason_code) from error
        self._require_dispatch_claim(request, arguments)
        registration = self._registration(request.channel_id)
        if request.verifier_id != OPERATOR_PUBLIC_POST_VERIFIER_ID:
            raise PublicActionDenied("PUBLIC_POST_VERIFIER_MISMATCH")
        if request.max_bytes > registration.spec.max_content_bytes:
            raise PublicActionDenied("PUBLIC_CHANNEL_BYTE_BUDGET_EXCEEDED")
        if request.expected_content_byte_count > request.max_bytes:
            raise PublicActionDenied("PUBLIC_CONTENT_BYTE_BUDGET_EXCEEDED")
        completion = self._completion(request.ticket_id)
        if completion is not None:
            return self._response(completion, replayed=True)
        claim = self._claim(request.ticket_id)
        if claim is not None:
            self._validate_claim(claim, request, registration)
            readback = self._inspect(registration, request.ticket_id)
            if self._matches_posted(readback, request, registration):
                return self._record_completion(
                    claim,
                    request,
                    registration,
                    readback,
                    recovered_after_provider_crash=True,
                )
            raise PublicActionDenied("PUBLIC_POST_EXECUTION_STATE_UNCERTAIN")

        preview = self.preview(channel_id=request.channel_id, content=request.content)
        self._validate_preview(request, preview)
        claim_payload = self._claim_payload(request, registration, preview)

        def admission(events: list[Event]) -> Mapping[str, Any]:
            try:
                GlobalKillSwitch.ensure_clear(events)
            except TicketAuthorityDenied as error:
                raise PublicActionDenied(error.reason_code) from error
            used = sum(
                1
                for event in events
                if event.kind == "operator.public_post.claimed"
                and event.payload.get("daily_bucket") == preview.daily_bucket
                and event.payload.get("channel_cap_key_sha256")
                == preview.channel_cap_key_sha256
            )
            if used >= registration.spec.daily_action_cap:
                raise PublicActionDenied("PUBLIC_CHANNEL_DAILY_CAP_EXHAUSTED")
            return claim_payload

        claim, created = self.store.append_once_computed(
            "operator.public_post.claimed", request.ticket_id, admission
        )
        if not created:
            self._validate_claim(claim, request, registration)
            readback = self._inspect(registration, request.ticket_id)
            if self._matches_posted(readback, request, registration):
                return self._record_completion(
                    claim,
                    request,
                    registration,
                    readback,
                    recovered_after_provider_crash=True,
                )
            raise PublicActionDenied("PUBLIC_POST_EXECUTION_STATE_UNCERTAIN")

        effect_id = str(claim.payload["effect_id"])
        try:
            GlobalKillSwitch(self.store).checkpoint(
                checkpoint_id=f"public-pre-{sha256(request.ticket_id.encode()).hexdigest()[:24]}",
                effect_id=effect_id,
                step="pre-provider",
            )
        except TicketAuthorityDenied as error:
            raise PublicActionDenied(error.reason_code) from error
        registration.driver.post(
            registration.spec,
            PublicPostProviderCommand(
                operation_id=request.ticket_id,
                target_id=registration.spec.id,
                provider=registration.spec.provider,
                account_id=registration.spec.account_id,
                channel_id=registration.spec.channel_id,
                recipient_id=registration.spec.recipient_id,
                content=request.content,
                content_sha256=request.expected_content_sha256,
                content_byte_count=request.expected_content_byte_count,
                expected_before_state_sha256=request.expected_before_state_sha256,
                preview_sha256=request.expected_preview_sha256,
                credential_handles=(),
            ),
        )
        readback = self._inspect(registration, request.ticket_id)
        if not self._matches_posted(readback, request, registration):
            raise PublicActionDenied("PUBLIC_PROVIDER_READBACK_MISMATCH")
        return self._record_completion(
            claim,
            request,
            registration,
            readback,
            recovered_after_provider_crash=False,
        )

    @staticmethod
    def _matches_posted(
        readback: ProviderPublicPostState,
        request: OperatorPublicPostInvocation,
        registration: _RegisteredOperatorPublicChannel,
    ) -> bool:
        return (
            readback.posted
            and readback.target_id == registration.spec.id
            and readback.content_sha256 == request.expected_content_sha256
            and readback.content_byte_count == request.expected_content_byte_count
            and readback.last_operation_id == request.ticket_id
        )

    @staticmethod
    def _claim_payload(
        request: OperatorPublicPostInvocation,
        registration: _RegisteredOperatorPublicChannel,
        preview: OperatorPublicPostPreview,
    ) -> dict[str, Any]:
        spec = registration.spec
        return {
            "schema_version": OPERATOR_PUBLIC_POST_CLAIM_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "target_id": spec.id,
            "channel_spec_sha256": registration.spec_sha256,
            "driver_id": spec.driver_id,
            "provider": spec.provider,
            "account_id": spec.account_id,
            "channel_id": spec.channel_id,
            "recipient_id": spec.recipient_id,
            "owner_principal_id": spec.owner_principal_id,
            "provider_authenticated": registration.authority.authenticated,
            "provider_authority_receipt_sha256": (
                registration.authority.authority_receipt_sha256
            ),
            "content_sha256": request.expected_content_sha256,
            "content_byte_count": request.expected_content_byte_count,
            "before_state_sha256": request.expected_before_state_sha256,
            "preview_sha256": request.expected_preview_sha256,
            "verifier_id": request.verifier_id,
            "max_bytes": request.max_bytes,
            "daily_bucket": preview.daily_bucket,
            "channel_cap_key_sha256": preview.channel_cap_key_sha256,
            "daily_action_cap": spec.daily_action_cap,
            "effect_id": f"public-{sha256(request.ticket_id.encode()).hexdigest()[:24]}",
            "real_public_effect": spec.real_public_effect,
            "raw_content_persisted": False,
            "provider_configuration_persisted": False,
            "credential_handles": [],
            "credential_values_persisted": False,
        }

    @staticmethod
    def _validate_claim(
        claim: Event,
        request: OperatorPublicPostInvocation,
        registration: _RegisteredOperatorPublicChannel,
    ) -> None:
        payload = claim.payload
        expected = {
            "ticket_id": request.ticket_id,
            "target_id": request.channel_id,
            "channel_spec_sha256": registration.spec_sha256,
            "provider": registration.spec.provider,
            "account_id": registration.spec.account_id,
            "channel_id": registration.spec.channel_id,
            "recipient_id": registration.spec.recipient_id,
            "owner_principal_id": registration.spec.owner_principal_id,
            "provider_authenticated": registration.authority.authenticated,
            "provider_authority_receipt_sha256": (
                registration.authority.authority_receipt_sha256
            ),
            "content_sha256": request.expected_content_sha256,
            "content_byte_count": request.expected_content_byte_count,
            "before_state_sha256": request.expected_before_state_sha256,
            "preview_sha256": request.expected_preview_sha256,
            "verifier_id": request.verifier_id,
            "max_bytes": request.max_bytes,
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            raise PublicActionDenied("PUBLIC_POST_CLAIM_COLLISION")

    def _record_completion(
        self,
        claim: Event,
        request: OperatorPublicPostInvocation,
        registration: _RegisteredOperatorPublicChannel,
        readback: ProviderPublicPostState,
        *,
        recovered_after_provider_crash: bool,
    ) -> str:
        spec = registration.spec
        payload = {
            "schema_version": OPERATOR_PUBLIC_POST_RECEIPT_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "claim_event_id": claim.event_id,
            "effect_id": claim.payload["effect_id"],
            "target_id": spec.id,
            "channel_spec_sha256": registration.spec_sha256,
            "driver_id": spec.driver_id,
            "provider": spec.provider,
            "account_id": spec.account_id,
            "channel_id": spec.channel_id,
            "recipient_id": spec.recipient_id,
            "owner_principal_id": spec.owner_principal_id,
            "provider_authenticated": registration.authority.authenticated,
            "provider_authority_receipt_sha256": (
                registration.authority.authority_receipt_sha256
            ),
            "content_sha256": request.expected_content_sha256,
            "content_byte_count": request.expected_content_byte_count,
            "preview_sha256": request.expected_preview_sha256,
            "daily_bucket": claim.payload["daily_bucket"],
            "channel_cap_key_sha256": claim.payload["channel_cap_key_sha256"],
            "daily_action_cap": spec.daily_action_cap,
            "provider_post_id_sha256": readback.provider_post_id_sha256,
            "provider_receipt_sha256": readback.provider_receipt_sha256,
            "provider_readback_verified": True,
            "provider_effect_count": 1,
            "real_public_effect": spec.real_public_effect,
            "status": "posted",
            "verification_passed": True,
            "recovered_after_provider_crash": recovered_after_provider_crash,
            "raw_content_persisted": False,
            "provider_raw_response_persisted": False,
            "provider_configuration_persisted": False,
            "credential_handles": [],
            "credential_values_persisted": False,
        }
        event, created = self.store.append_once_result(
            "operator.public_post.completed", request.ticket_id, payload
        )
        if not created and canonical_json(event.payload) != canonical_json(payload):
            existing = event.payload
            if not (
                existing.get("ticket_id") == request.ticket_id
                and existing.get("verification_passed") is True
                and existing.get("content_sha256") == request.expected_content_sha256
            ):
                raise PublicActionDenied("PUBLIC_POST_RECEIPT_COLLISION")
        return self._response(event, replayed=not created)

    def _require_dispatch_claim(
        self,
        request: OperatorPublicPostInvocation,
        arguments: Mapping[str, Any],
    ) -> None:
        arguments_sha256 = sha256(canonical_json(arguments).encode()).hexdigest()
        rows = [
            event
            for event in self.store.events("execution.ticket.consumed")
            if event.payload.get("ticket_id") == request.ticket_id
        ]
        if len(rows) != 1:
            raise PublicActionDenied("TICKET_DISPATCH_CLAIM_REQUIRED")
        payload = rows[0].payload
        if (
            payload.get("dispatch_claimed") is not True
            or payload.get("ticket_consumed") is not True
            or payload.get("tool_name") != "operator_public_post"
            or payload.get("arguments_sha256") != arguments_sha256
            or payload.get("capability") != "operator.public"
            or payload.get("scope") != f"operator/public/{request.channel_id}"
            or payload.get("verifier_id") != OPERATOR_PUBLIC_POST_VERIFIER_ID
            or payload.get("idempotency_key") != request.ticket_id
            or isinstance(payload.get("byte_budget"), bool)
            or not isinstance(payload.get("byte_budget"), int)
            or payload["byte_budget"] < request.max_bytes
            or payload.get("action_budget") != 1
            or payload.get("value_budget_microunits") != 0
        ):
            raise PublicActionDenied("TICKET_DISPATCH_CLAIM_MISMATCH")

    def _claim(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.public_post.claimed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise PublicActionDenied("DUPLICATE_PUBLIC_POST_CLAIMS")
        return rows[0] if rows else None

    def _completion(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.public_post.completed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise PublicActionDenied("DUPLICATE_PUBLIC_POST_RECEIPTS")
        return rows[0] if rows else None

    @staticmethod
    def _response(event: Event, *, replayed: bool) -> str:
        payload = event.payload
        return canonical_json(
            {
                "success": payload.get("verification_passed") is True,
                "effect": {
                    "effect_id": payload.get("effect_id"),
                    "idempotency_key": payload.get("ticket_id"),
                    "receipt_event_id": event.event_id,
                },
                "public_post": {
                    "target_id": payload.get("target_id"),
                    "provider": payload.get("provider"),
                    "account_id": payload.get("account_id"),
                    "channel_id": payload.get("channel_id"),
                    "recipient_id": payload.get("recipient_id"),
                    "owner_principal_id": payload.get("owner_principal_id"),
                    "provider_authenticated": payload.get("provider_authenticated"),
                    "provider_authority_receipt_sha256": payload.get(
                        "provider_authority_receipt_sha256"
                    ),
                    "content_sha256": payload.get("content_sha256"),
                    "content_byte_count": payload.get("content_byte_count"),
                    "provider_post_id_sha256": payload.get("provider_post_id_sha256"),
                    "provider_receipt_sha256": payload.get("provider_receipt_sha256"),
                    "provider_readback_verified": payload.get("provider_readback_verified"),
                    "provider_effect_count": payload.get("provider_effect_count"),
                    "daily_bucket": payload.get("daily_bucket"),
                    "daily_action_cap": payload.get("daily_action_cap"),
                    "real_public_effect": payload.get("real_public_effect"),
                    "recovered_after_provider_crash": payload.get(
                        "recovered_after_provider_crash"
                    ),
                    "credential_handles_used": [],
                    "raw_content_persisted": False,
                    "provider_raw_response_persisted": False,
                    "replayed": replayed,
                },
                "verification": {
                    "passed": payload.get("verification_passed") is True,
                    "verifier_id": OPERATOR_PUBLIC_POST_VERIFIER_ID,
                    "evidence_sha256": payload.get("provider_receipt_sha256"),
                },
            }
        )

    def _verify_mediated_result(
        self,
        value: object,
        context: VerificationContext,
    ) -> OutcomeVerification:
        malformed = OutcomeVerification(
            verified=False, effect_observed=False, status="malformed-result"
        )
        if not isinstance(value, dict) or context.verifier_id != OPERATOR_PUBLIC_POST_VERIFIER_ID:
            return malformed
        effect = value.get("effect")
        public_post = value.get("public_post")
        verification = value.get("verification")
        if not all(isinstance(row, dict) for row in (effect, public_post, verification)):
            return malformed
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            return OutcomeVerification(
                verified=False, effect_observed=False, status="receipt-missing"
            )
        payload = receipt.payload
        assert isinstance(effect, dict)
        assert isinstance(public_post, dict)
        assert isinstance(verification, dict)
        matched = (
            value.get("success") is True
            and payload.get("verification_passed") is True
            and effect.get("effect_id") == payload.get("effect_id")
            and effect.get("idempotency_key") == context.idempotency_key
            and effect.get("receipt_event_id") == receipt.event_id
            and public_post.get("target_id") == payload.get("target_id")
            and public_post.get("provider") == payload.get("provider")
            and public_post.get("account_id") == payload.get("account_id")
            and public_post.get("channel_id") == payload.get("channel_id")
            and public_post.get("recipient_id") == payload.get("recipient_id")
            and public_post.get("owner_principal_id")
            == payload.get("owner_principal_id")
            and public_post.get("provider_authenticated")
            == payload.get("provider_authenticated")
            and public_post.get("provider_authority_receipt_sha256")
            == payload.get("provider_authority_receipt_sha256")
            and public_post.get("content_sha256") == payload.get("content_sha256")
            and public_post.get("provider_receipt_sha256")
            == payload.get("provider_receipt_sha256")
            and public_post.get("provider_readback_verified") is True
            and public_post.get("credential_handles_used") == []
            and public_post.get("raw_content_persisted") is False
            and verification.get("passed") is True
            and verification.get("verifier_id") == OPERATOR_PUBLIC_POST_VERIFIER_ID
            and verification.get("evidence_sha256") == payload.get("provider_receipt_sha256")
        )
        return OutcomeVerification(
            verified=matched,
            effect_observed=matched,
            status="verified" if matched else "receipt-mismatch",
            effect_id=str(payload["effect_id"]) if matched else None,
            evidence_sha256=(str(payload["provider_receipt_sha256"]) if matched else None),
        )

    def _reconcile_mediated_result(self, context: VerificationContext) -> object | None:
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            claim = self._claim(context.ticket_id)
            if claim is None:
                return None
            registration = self._registration(str(claim.payload.get("target_id")))
            request = self._request_from_claim(claim)
            readback = self._inspect(registration, request.ticket_id)
            if not self._matches_posted(readback, request, registration):
                return None
            self._record_completion(
                claim,
                request,
                registration,
                readback,
                recovered_after_provider_crash=True,
            )
            receipt = self._completion(context.ticket_id)
        if receipt is None or receipt.payload.get("verification_passed") is not True:
            return None
        return json.loads(self._response(receipt, replayed=True))

    @staticmethod
    def _request_from_claim(claim: Event) -> OperatorPublicPostInvocation:
        payload = claim.payload
        return OperatorPublicPostInvocation(
            ticket_id=str(payload["ticket_id"]),
            channel_id=str(payload["target_id"]),
            content="content unavailable after dispatch",
            expected_content_sha256=str(payload["content_sha256"]),
            expected_content_byte_count=int(payload["content_byte_count"]),
            expected_before_state_sha256=str(payload["before_state_sha256"]),
            expected_preview_sha256=str(payload["preview_sha256"]),
            verifier_id=str(payload["verifier_id"]),
            max_bytes=int(payload["max_bytes"]),
        )


__all__ = [
    "FakePublicActionObservation",
    "FakePublicActionPreview",
    "FakePublicActionRequest",
    "FakePublicActionSpec",
    "LocalFakePublicActionAdapter",
    "LocalFakePublicChannelDriver",
    "OPERATOR_PUBLIC_POST_VERIFIER_ID",
    "OperatorPublicChannel",
    "OperatorPublicPostAdapter",
    "OperatorPublicPostDriver",
    "OperatorPublicPostInvocation",
    "OperatorPublicPostPreview",
    "ProviderPublicChannelAuthority",
    "ProviderPublicPostState",
    "PublicPostProviderCommand",
    "PublicActionDenied",
]
