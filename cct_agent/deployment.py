"""Typed, verification-bound deployment into an atomic local fake sink."""

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

from .store import Event, EventStore, canonical_json
from .verification import (
    HostRegisteredVerifier,
    VerificationDenied,
    VerificationObservation,
)


DEPLOYMENT_CLAIM_SCHEMA_VERSION = "cct.deployment.local-fake.claim.v1"
DEPLOYMENT_RECEIPT_SCHEMA_VERSION = "cct.deployment.local-fake.receipt.v1"
DEPLOYMENT_PREVIEW_SCHEMA_VERSION = "cct.deployment.local-fake.preview.v1"
MAX_DEPLOYMENT_TARGETS = 64
MAX_ARTIFACT_BYTES = 16_777_216
MAX_RELATIVE_PATH_BYTES = 1024
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+=,-]{0,254}$")
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


class DeploymentDenied(PermissionError):
    """Fail-closed local deployment denial with stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class _SinkMissing(FileNotFoundError):
    pass


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


def _relative_path(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a non-empty exact string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"{name} must be normalized ASCII") from error
    parts = value.split("/")
    if (
        len(encoded) > MAX_RELATIVE_PATH_BYTES
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
        or any(not _PATH_COMPONENT.fullmatch(part) for part in parts)
    ):
        raise ValueError(f"{name} must be normalized and stay inside its root")
    lowered = {part.lower() for part in parts}
    tokenized = {
        token
        for part in parts
        for token in re.split(r"[._-]+", part.lower())
        if token
    }
    if lowered & _SENSITIVE_TOKENS or tokenized & _SENSITIVE_TOKENS:
        raise ValueError(f"{name} cannot address credentials or secrets")
    return value


@dataclass(frozen=True, slots=True)
class DeploymentTarget:
    """Immutable host-owned local fake deployment route."""

    id: str
    kind: Literal["local_fake"]
    source_relative_path: str
    sink_relative_path: str
    verifier_id: str
    max_artifact_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("target id", self.id))
        if self.kind != "local_fake":
            raise ValueError("deployment kind must be local_fake")
        object.__setattr__(
            self,
            "source_relative_path",
            _relative_path("source_relative_path", self.source_relative_path),
        )
        object.__setattr__(
            self,
            "sink_relative_path",
            _relative_path("sink_relative_path", self.sink_relative_path),
        )
        if self.sink_relative_path == ".deployment.lock" or any(
            part.startswith(".cct-deploy-") for part in self.sink_relative_path.split("/")
        ):
            raise ValueError("sink_relative_path uses a reserved local state name")
        object.__setattr__(
            self,
            "verifier_id",
            _identifier("verifier id", self.verifier_id),
        )
        _bounded_integer(
            "max_artifact_bytes",
            self.max_artifact_bytes,
            minimum=1,
            maximum=MAX_ARTIFACT_BYTES,
        )


@dataclass(frozen=True, slots=True)
class DeploymentPreview:
    """Hash-bound preview for one passed verification and current artifact."""

    target_id: str
    target_spec_sha256: str
    kind: Literal["local_fake"]
    verification_request_id: str
    verification_event_id: str
    verifier_id: str
    plan_id: str
    plan_sha256: str
    snapshot_sha256: str
    artifact_sha256: str
    artifact_byte_count: int
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class DeploymentRequest:
    """One exact preview-bound local deployment request."""

    id: str
    target_id: str
    verification_request_id: str
    expected_verification_event_id: str
    expected_snapshot_sha256: str
    expected_artifact_sha256: str
    expected_manifest_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("request id", self.id))
        object.__setattr__(
            self,
            "target_id",
            _identifier("target id", self.target_id),
        )
        object.__setattr__(
            self,
            "verification_request_id",
            _identifier("verification request id", self.verification_request_id),
        )
        object.__setattr__(
            self,
            "expected_verification_event_id",
            _identifier(
                "expected verification event id",
                self.expected_verification_event_id,
            ),
        )
        for field in (
            "expected_snapshot_sha256",
            "expected_artifact_sha256",
            "expected_manifest_sha256",
        ):
            object.__setattr__(self, field, _digest(field, getattr(self, field)))


@dataclass(frozen=True, slots=True)
class DeploymentObservation:
    """Readback-verified hash-only local fake deployment receipt."""

    request_id: str
    target_id: str
    target_spec_sha256: str
    kind: Literal["local_fake"]
    verification_request_id: str
    verification_event_id: str
    snapshot_sha256: str
    artifact_sha256: str
    artifact_byte_count: int
    manifest_sha256: str
    sink_readback_sha256: str
    sink_readback_verified: bool
    sink_mutation_count: int
    status: Literal["deployed"]
    public_action_eligible: bool
    terminal_event_id: str
    replayed: bool
    artifact_persisted_in_ledger: bool = False
    network_effect: bool = False
    provider_effect: bool = False
    credential_use: bool = False
    production_effect: bool = False


@dataclass(frozen=True, slots=True)
class _RegisteredTarget:
    spec: DeploymentTarget
    spec_sha256: str


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    content: bytes
    mode: int
    device: int
    inode: int

    @property
    def digest(self) -> str:
        return sha256(self.content).hexdigest()


class LocalFakeDeploymentAdapter:
    """Copy one verified artifact exactly once into a private local fake sink."""

    def __init__(
        self,
        store: EventStore,
        *,
        workspace_root: str | Path,
        sink_root: str | Path,
        targets: tuple[DeploymentTarget, ...] | list[DeploymentTarget],
        verifier: HostRegisteredVerifier,
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        workspace, workspace_identity = self._validated_root(
            workspace_root,
            name="workspace_root",
            private=False,
        )
        sink, sink_identity = self._validated_root(
            sink_root,
            name="sink_root",
            private=True,
        )
        if workspace == sink:
            raise ValueError("sink_root must be separate from workspace_root")
        if not isinstance(targets, (tuple, list)) or not targets:
            raise ValueError("targets must contain at least one DeploymentTarget")
        if len(targets) > MAX_DEPLOYMENT_TARGETS:
            raise ValueError(
                f"targets must contain at most {MAX_DEPLOYMENT_TARGETS} values"
            )

        registrations: dict[str, _RegisteredTarget] = {}
        source_paths: set[str] = set()
        sink_paths: set[str] = set()
        self.workspace_root = workspace
        self.sink_root = sink
        self._workspace_identity = workspace_identity
        self._sink_identity = sink_identity
        for target in targets:
            if not isinstance(target, DeploymentTarget):
                raise ValueError("targets must contain DeploymentTarget values")
            if target.id in registrations:
                raise ValueError("deployment target IDs must be unique")
            if target.source_relative_path in source_paths:
                raise ValueError("deployment source paths must be unique")
            if target.sink_relative_path in sink_paths:
                raise ValueError("deployment sink paths must be unique")
            try:
                self._read_source(target)
            except DeploymentDenied as error:
                raise ValueError(
                    f"deployment source invalid: {error.reason_code}"
                ) from error
            payload = {
                "id": target.id,
                "kind": target.kind,
                "source_relative_path": target.source_relative_path,
                "sink_relative_path": target.sink_relative_path,
                "verifier_id": target.verifier_id,
                "max_artifact_bytes": target.max_artifact_bytes,
            }
            registrations[target.id] = _RegisteredTarget(
                spec=target,
                spec_sha256=sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
            )
            source_paths.add(target.source_relative_path)
            sink_paths.add(target.sink_relative_path)

        if not isinstance(verifier, HostRegisteredVerifier):
            raise ValueError("verifier must be a HostRegisteredVerifier")
        if verifier.workspace_root != workspace:
            raise ValueError("verifier and deployment workspace roots must match")
        if verifier.store.path.resolve() != store.path.resolve():
            raise ValueError("verifier and deployment adapter must share one ledger")
        for registration in registrations.values():
            target = registration.spec
            if target.verifier_id not in verifier.registered_ids:
                raise ValueError("deployment target verifier is not registered")
            snapshot_paths = {
                str(row["relative_path"])
                for row in verifier.snapshot(target.verifier_id).files
            }
            if target.source_relative_path not in snapshot_paths:
                raise ValueError("deployment source must be part of verifier snapshot")

        self.store = store
        self.verifier = verifier
        self._targets: Mapping[str, _RegisteredTarget] = MappingProxyType(registrations)
        self._lock_path = self.sink_root / ".deployment.lock"
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
            raise ValueError("deployment state must be private and lockable") from error

    @staticmethod
    def _validated_root(
        raw_root: str | Path,
        *,
        name: str,
        private: bool,
    ) -> tuple[Path, tuple[int, int]]:
        root = Path(raw_root)
        if not root.is_absolute() or root.is_symlink():
            raise ValueError(f"{name} must be an absolute real directory")
        try:
            resolved = root.resolve(strict=True)
            metadata = resolved.stat()
        except OSError as error:
            raise ValueError(f"{name} must be an existing real directory") from error
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError(f"{name} must be an owned real directory")
        if private:
            try:
                os.chmod(resolved, 0o700)
            except OSError as error:
                raise ValueError(f"{name} must be private") from error
        return resolved, (metadata.st_dev, metadata.st_ino)

    @property
    def registered_target_ids(self) -> frozenset[str]:
        return frozenset(self._targets)

    def preview(
        self,
        *,
        target_id: str,
        verification_request_id: str,
    ) -> DeploymentPreview:
        target_id = _identifier("target id", target_id)
        verification_request_id = _identifier(
            "verification request id",
            verification_request_id,
        )
        if self.store.verify_chain().get("valid") is not True:
            raise DeploymentDenied("LEDGER_CHAIN_INVALID")
        registration = self._targets.get(target_id)
        if registration is None:
            raise DeploymentDenied("TARGET_NOT_REGISTERED")
        verification = self._require_verification(
            registration,
            verification_request_id,
        )
        artifact = self._read_source(registration.spec)
        return self._make_preview(registration, verification, artifact)

    def deploy(self, request: DeploymentRequest) -> DeploymentObservation:
        if not isinstance(request, DeploymentRequest):
            raise ValueError("request must be a DeploymentRequest")
        if self.store.verify_chain().get("valid") is not True:
            raise DeploymentDenied("LEDGER_CHAIN_INVALID")
        registration = self._targets.get(request.target_id)
        if registration is None:
            raise DeploymentDenied("TARGET_NOT_REGISTERED")

        expected = self._current_preview(registration, request.verification_request_id)
        self._validate_request_preview(request, expected)
        with self._exclusive_lock():
            current = self._current_preview(registration, request.verification_request_id)
            self._validate_request_preview(request, current)
            terminal = self._terminal_event(request.id)
            if terminal is not None:
                observation = self._observation_from_event(terminal, replayed=True)
                self._validate_terminal(observation, registration, request)
                self._verify_sink_readback(registration.spec, observation)
                return observation

            claim = self._claim_event(request.id)
            claim_created = False
            claim_payload = self._claim_payload(request, registration, current)
            if claim is None:
                if self._read_sink(registration.spec, missing_ok=True) is not None:
                    raise DeploymentDenied("SINK_ALREADY_EXISTS")
                try:
                    claim, claim_created = self.store.append_once_result(
                        "deployment.local_fake.claimed",
                        request.id,
                        claim_payload,
                    )
                except ValueError as error:
                    raise DeploymentDenied("REQUEST_COLLISION") from error
                except Exception as error:
                    raise DeploymentDenied("CLAIM_PERSISTENCE_FAILED") from error
            if canonical_json(claim.payload) != canonical_json(claim_payload):
                raise DeploymentDenied("REQUEST_COLLISION")

            sink = self._read_sink(registration.spec, missing_ok=True)
            if sink is None:
                artifact = self._read_source(registration.spec)
                if artifact.digest != current.artifact_sha256:
                    raise DeploymentDenied("DEPLOYMENT_PREVIEW_STALE")
                self._atomic_create_sink(registration.spec, artifact.content)
                sink = self._read_sink(registration.spec, missing_ok=False)
            elif (
                sink.digest != current.artifact_sha256
                or len(sink.content) != current.artifact_byte_count
            ):
                raise DeploymentDenied("SINK_STATE_UNCERTAIN")
            if sink is None or (
                sink.digest != current.artifact_sha256
                or len(sink.content) != current.artifact_byte_count
            ):
                raise DeploymentDenied("SINK_READBACK_MISMATCH")
            terminal, completion_created = self._record_completion(
                request,
                registration,
                claim,
                current,
                sink,
            )
            return self._observation_from_event(
                terminal,
                replayed=(not claim_created or not completion_created),
            )

    def require_deployed(self, request_id: str) -> DeploymentObservation:
        request_id = _identifier("request id", request_id)
        if self.store.verify_chain().get("valid") is not True:
            raise DeploymentDenied("LEDGER_CHAIN_INVALID")
        with self._exclusive_lock():
            terminal = self._terminal_event(request_id)
            if terminal is None:
                raise DeploymentDenied("DEPLOYMENT_NOT_COMPLETED")
            observation = self._observation_from_event(terminal, replayed=True)
            registration = self._targets.get(observation.target_id)
            if registration is None:
                raise DeploymentDenied("TARGET_REGISTRY_DRIFT")
            self._validate_terminal(observation, registration, None)
            self._require_verification(
                registration,
                observation.verification_request_id,
            )
            self._verify_sink_readback(registration.spec, observation)
            return observation

    def _current_preview(
        self,
        registration: _RegisteredTarget,
        verification_request_id: str,
    ) -> DeploymentPreview:
        verification = self._require_verification(
            registration,
            verification_request_id,
        )
        artifact = self._read_source(registration.spec)
        return self._make_preview(registration, verification, artifact)

    def _require_verification(
        self,
        registration: _RegisteredTarget,
        request_id: str,
    ) -> VerificationObservation:
        try:
            verification = self.verifier.require_passed(request_id)
        except VerificationDenied as error:
            raise DeploymentDenied(error.reason_code) from error
        if (
            verification.verifier_id != registration.spec.verifier_id
            or not verification.deployment_eligible
        ):
            raise DeploymentDenied("VERIFICATION_BINDING_MISMATCH")
        return verification

    @staticmethod
    def _make_preview(
        registration: _RegisteredTarget,
        verification: VerificationObservation,
        artifact: _FileSnapshot,
    ) -> DeploymentPreview:
        target = registration.spec
        manifest = {
            "schema_version": DEPLOYMENT_PREVIEW_SCHEMA_VERSION,
            "target_id": target.id,
            "target_spec_sha256": registration.spec_sha256,
            "kind": target.kind,
            "source_relative_path": target.source_relative_path,
            "sink_relative_path": target.sink_relative_path,
            "verification_request_id": verification.request_id,
            "verification_event_id": verification.terminal_event_id,
            "verifier_id": verification.verifier_id,
            "plan_id": verification.plan_id,
            "plan_sha256": verification.plan_sha256,
            "snapshot_sha256": verification.snapshot_after_sha256,
            "artifact_sha256": artifact.digest,
            "artifact_byte_count": len(artifact.content),
            "network_effect": False,
            "provider_effect": False,
            "credential_use": False,
            "production_effect": False,
        }
        return DeploymentPreview(
            target_id=target.id,
            target_spec_sha256=registration.spec_sha256,
            kind="local_fake",
            verification_request_id=verification.request_id,
            verification_event_id=verification.terminal_event_id,
            verifier_id=verification.verifier_id,
            plan_id=verification.plan_id,
            plan_sha256=verification.plan_sha256,
            snapshot_sha256=verification.snapshot_after_sha256,
            artifact_sha256=artifact.digest,
            artifact_byte_count=len(artifact.content),
            manifest_sha256=sha256(
                canonical_json(manifest).encode("utf-8")
            ).hexdigest(),
        )

    @staticmethod
    def _validate_request_preview(
        request: DeploymentRequest,
        preview: DeploymentPreview,
    ) -> None:
        if (
            request.target_id != preview.target_id
            or request.verification_request_id != preview.verification_request_id
            or request.expected_verification_event_id != preview.verification_event_id
            or request.expected_snapshot_sha256 != preview.snapshot_sha256
            or request.expected_artifact_sha256 != preview.artifact_sha256
            or request.expected_manifest_sha256 != preview.manifest_sha256
        ):
            raise DeploymentDenied("DEPLOYMENT_PREVIEW_MISMATCH")

    @staticmethod
    def _claim_payload(
        request: DeploymentRequest,
        registration: _RegisteredTarget,
        preview: DeploymentPreview,
    ) -> dict[str, object]:
        target = registration.spec
        return {
            "schema_version": DEPLOYMENT_CLAIM_SCHEMA_VERSION,
            "request_id": request.id,
            "target_id": target.id,
            "target_spec_sha256": registration.spec_sha256,
            "kind": target.kind,
            "source_relative_path": target.source_relative_path,
            "sink_relative_path": target.sink_relative_path,
            "verification_request_id": preview.verification_request_id,
            "verification_event_id": preview.verification_event_id,
            "verifier_id": preview.verifier_id,
            "plan_id": preview.plan_id,
            "plan_sha256": preview.plan_sha256,
            "snapshot_sha256": preview.snapshot_sha256,
            "artifact_sha256": preview.artifact_sha256,
            "artifact_byte_count": preview.artifact_byte_count,
            "manifest_sha256": preview.manifest_sha256,
            "sink_expected_before": "absent",
            "artifact_persisted_in_ledger": False,
            "network_effect": False,
            "provider_effect": False,
            "credential_use": False,
            "production_effect": False,
        }

    def _record_completion(
        self,
        request: DeploymentRequest,
        registration: _RegisteredTarget,
        claim: Event,
        preview: DeploymentPreview,
        sink: _FileSnapshot,
    ) -> tuple[Event, bool]:
        target = registration.spec
        payload = {
            "schema_version": DEPLOYMENT_RECEIPT_SCHEMA_VERSION,
            "request_id": request.id,
            "claim_event_id": claim.event_id,
            "target_id": target.id,
            "target_spec_sha256": registration.spec_sha256,
            "kind": target.kind,
            "source_relative_path": target.source_relative_path,
            "sink_relative_path": target.sink_relative_path,
            "verification_request_id": preview.verification_request_id,
            "verification_event_id": preview.verification_event_id,
            "verifier_id": preview.verifier_id,
            "plan_id": preview.plan_id,
            "plan_sha256": preview.plan_sha256,
            "snapshot_sha256": preview.snapshot_sha256,
            "artifact_sha256": preview.artifact_sha256,
            "artifact_byte_count": preview.artifact_byte_count,
            "manifest_sha256": preview.manifest_sha256,
            "sink_readback_sha256": sink.digest,
            "sink_readback_byte_count": len(sink.content),
            "sink_readback_verified": True,
            "sink_mutation_count": 1,
            "status": "deployed",
            "public_action_eligible": True,
            "artifact_persisted_in_ledger": False,
            "network_effect": False,
            "provider_effect": False,
            "credential_use": False,
            "production_effect": False,
        }
        try:
            event, created = self.store.append_once_result(
                "deployment.local_fake.completed",
                request.id,
                payload,
            )
        except ValueError as error:
            raise DeploymentDenied("COMPLETION_RECEIPT_COLLISION") from error
        except Exception as error:
            raise DeploymentDenied("RECEIPT_PERSISTENCE_FAILED") from error
        if canonical_json(event.payload) != canonical_json(payload):
            raise DeploymentDenied("COMPLETION_RECEIPT_COLLISION")
        return event, created

    def _claim_event(self, request_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("deployment.local_fake.claimed")
            if event.payload.get("request_id") == request_id
        ]
        if len(rows) > 1:
            raise DeploymentDenied("DUPLICATE_CLAIM_RECEIPTS")
        return rows[0] if rows else None

    def _terminal_event(self, request_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("deployment.local_fake.completed")
            if event.payload.get("request_id") == request_id
        ]
        if len(rows) > 1:
            raise DeploymentDenied("DUPLICATE_COMPLETION_RECEIPTS")
        return rows[0] if rows else None

    @staticmethod
    def _observation_from_event(
        event: Event,
        *,
        replayed: bool,
    ) -> DeploymentObservation:
        payload = event.payload
        required = {
            "schema_version",
            "request_id",
            "claim_event_id",
            "target_id",
            "target_spec_sha256",
            "kind",
            "source_relative_path",
            "sink_relative_path",
            "verification_request_id",
            "verification_event_id",
            "verifier_id",
            "plan_id",
            "plan_sha256",
            "snapshot_sha256",
            "artifact_sha256",
            "artifact_byte_count",
            "manifest_sha256",
            "sink_readback_sha256",
            "sink_readback_byte_count",
            "sink_readback_verified",
            "sink_mutation_count",
            "status",
            "public_action_eligible",
            "artifact_persisted_in_ledger",
            "network_effect",
            "provider_effect",
            "credential_use",
            "production_effect",
        }
        digest_fields = (
            "target_spec_sha256",
            "plan_sha256",
            "snapshot_sha256",
            "artifact_sha256",
            "manifest_sha256",
            "sink_readback_sha256",
        )
        integer_fields = (
            "artifact_byte_count",
            "sink_readback_byte_count",
            "sink_mutation_count",
        )
        if (
            set(payload) != required
            or payload.get("schema_version") != DEPLOYMENT_RECEIPT_SCHEMA_VERSION
            or payload.get("kind") != "local_fake"
            or payload.get("status") != "deployed"
            or any(
                not isinstance(payload.get(field), str)
                for field in (
                    "request_id",
                    "claim_event_id",
                    "target_id",
                    "source_relative_path",
                    "sink_relative_path",
                    "verification_request_id",
                    "verification_event_id",
                    "verifier_id",
                    "plan_id",
                )
            )
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
            or payload.get("artifact_byte_count")
            != payload.get("sink_readback_byte_count")
            or payload.get("artifact_sha256") != payload.get("sink_readback_sha256")
            or payload.get("sink_readback_verified") is not True
            or payload.get("sink_mutation_count") != 1
            or payload.get("public_action_eligible") is not True
            or payload.get("artifact_persisted_in_ledger") is not False
            or payload.get("network_effect") is not False
            or payload.get("provider_effect") is not False
            or payload.get("credential_use") is not False
            or payload.get("production_effect") is not False
        ):
            raise DeploymentDenied("MALFORMED_COMPLETION_RECEIPT")
        return DeploymentObservation(
            request_id=str(payload["request_id"]),
            target_id=str(payload["target_id"]),
            target_spec_sha256=str(payload["target_spec_sha256"]),
            kind="local_fake",
            verification_request_id=str(payload["verification_request_id"]),
            verification_event_id=str(payload["verification_event_id"]),
            snapshot_sha256=str(payload["snapshot_sha256"]),
            artifact_sha256=str(payload["artifact_sha256"]),
            artifact_byte_count=int(payload["artifact_byte_count"]),
            manifest_sha256=str(payload["manifest_sha256"]),
            sink_readback_sha256=str(payload["sink_readback_sha256"]),
            sink_readback_verified=True,
            sink_mutation_count=1,
            status="deployed",
            public_action_eligible=True,
            terminal_event_id=event.event_id,
            replayed=replayed,
        )

    @staticmethod
    def _validate_terminal(
        observation: DeploymentObservation,
        registration: _RegisteredTarget,
        request: DeploymentRequest | None,
    ) -> None:
        if (
            observation.target_id != registration.spec.id
            or observation.target_spec_sha256 != registration.spec_sha256
            or observation.kind != registration.spec.kind
        ):
            raise DeploymentDenied("TARGET_REGISTRY_DRIFT")
        if request is not None and (
            observation.request_id != request.id
            or observation.verification_request_id != request.verification_request_id
            or observation.verification_event_id
            != request.expected_verification_event_id
            or observation.snapshot_sha256 != request.expected_snapshot_sha256
            or observation.artifact_sha256 != request.expected_artifact_sha256
            or observation.manifest_sha256 != request.expected_manifest_sha256
        ):
            raise DeploymentDenied("COMPLETION_RECEIPT_COLLISION")

    def _verify_sink_readback(
        self,
        target: DeploymentTarget,
        observation: DeploymentObservation,
    ) -> None:
        sink = self._read_sink(target, missing_ok=True)
        if sink is None or (
            sink.digest != observation.sink_readback_sha256
            or len(sink.content) != observation.artifact_byte_count
        ):
            raise DeploymentDenied("SINK_READBACK_STALE")

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        try:
            descriptor = os.open(
                self._lock_path,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as error:
            raise DeploymentDenied("DEPLOYMENT_LOCK_UNAVAILABLE") from error
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @contextmanager
    def _parent_descriptor(
        self,
        *,
        root: Path,
        root_identity: tuple[int, int],
        relative_path: str,
        create_directories: bool,
        source: bool,
    ) -> Iterator[tuple[int, str]]:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptors: list[int] = []
        denial_prefix = "SOURCE" if source else "SINK"
        try:
            root_fd = os.open(root, flags)
            descriptors.append(root_fd)
            metadata = os.fstat(root_fd)
            if (metadata.st_dev, metadata.st_ino) != root_identity:
                raise DeploymentDenied(f"{denial_prefix}_ROOT_CHANGED")
            parent_fd = root_fd
            parts = relative_path.split("/")
            for component in parts[:-1]:
                try:
                    next_fd = os.open(component, flags, dir_fd=parent_fd)
                except FileNotFoundError:
                    if not create_directories:
                        raise _SinkMissing(component)
                    try:
                        os.mkdir(component, 0o700, dir_fd=parent_fd)
                    except FileExistsError:
                        pass
                    next_fd = os.open(component, flags, dir_fd=parent_fd)
                    os.fchmod(next_fd, 0o700)
                except OSError as error:
                    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise DeploymentDenied(
                            f"{denial_prefix}_SYMLINK_DENIED"
                        ) from error
                    raise DeploymentDenied(
                        f"{denial_prefix}_PATH_UNAVAILABLE"
                    ) from error
                child = os.fstat(next_fd)
                if (
                    not stat.S_ISDIR(child.st_mode)
                    or child.st_uid != os.getuid()
                ):
                    os.close(next_fd)
                    raise DeploymentDenied(f"{denial_prefix}_DIRECTORY_DENIED")
                descriptors.append(next_fd)
                parent_fd = next_fd
            yield parent_fd, parts[-1]
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _read_source(self, target: DeploymentTarget) -> _FileSnapshot:
        try:
            with self._parent_descriptor(
                root=self.workspace_root,
                root_identity=self._workspace_identity,
                relative_path=target.source_relative_path,
                create_directories=False,
                source=True,
            ) as (parent_fd, name):
                return self._read_file_at(
                    parent_fd,
                    name,
                    max_bytes=target.max_artifact_bytes,
                    prefix="SOURCE",
                )
        except _SinkMissing as error:
            raise DeploymentDenied("SOURCE_PATH_UNAVAILABLE") from error

    def _read_sink(
        self,
        target: DeploymentTarget,
        *,
        missing_ok: bool,
    ) -> _FileSnapshot | None:
        try:
            with self._parent_descriptor(
                root=self.sink_root,
                root_identity=self._sink_identity,
                relative_path=target.sink_relative_path,
                create_directories=False,
                source=False,
            ) as (parent_fd, name):
                try:
                    return self._read_file_at(
                        parent_fd,
                        name,
                        max_bytes=target.max_artifact_bytes,
                        prefix="SINK",
                    )
                except DeploymentDenied as error:
                    if missing_ok and error.reason_code == "SINK_PATH_UNAVAILABLE":
                        return None
                    raise
        except _SinkMissing:
            if missing_ok:
                return None
            raise DeploymentDenied("SINK_PATH_UNAVAILABLE")

    @staticmethod
    def _read_file_at(
        parent_fd: int,
        name: str,
        *,
        max_bytes: int,
        prefix: str,
    ) -> _FileSnapshot:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise DeploymentDenied(f"{prefix}_SYMLINK_DENIED") from error
            raise DeploymentDenied(f"{prefix}_PATH_UNAVAILABLE") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise DeploymentDenied(f"{prefix}_NOT_REGULAR")
            if metadata.st_uid != os.getuid():
                raise DeploymentDenied(f"{prefix}_OWNER_DENIED")
            if metadata.st_nlink != 1:
                raise DeploymentDenied(f"{prefix}_LINK_COUNT_DENIED")
            if metadata.st_size > max_bytes:
                raise DeploymentDenied(f"{prefix}_TOO_LARGE")
            content = bytearray()
            while True:
                chunk = os.read(
                    descriptor,
                    min(65_536, max_bytes + 1 - len(content)),
                )
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > max_bytes:
                    raise DeploymentDenied(f"{prefix}_TOO_LARGE")
            path_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                path_metadata.st_dev != metadata.st_dev
                or path_metadata.st_ino != metadata.st_ino
            ):
                raise DeploymentDenied(f"{prefix}_IDENTITY_CHANGED")
            return _FileSnapshot(
                content=bytes(content),
                mode=stat.S_IMODE(metadata.st_mode),
                device=metadata.st_dev,
                inode=metadata.st_ino,
            )
        finally:
            os.close(descriptor)

    def _atomic_create_sink(self, target: DeploymentTarget, content: bytes) -> None:
        if len(content) > target.max_artifact_bytes:
            raise DeploymentDenied("ARTIFACT_TOO_LARGE")
        with self._parent_descriptor(
            root=self.sink_root,
            root_identity=self._sink_identity,
            relative_path=target.sink_relative_path,
            create_directories=True,
            source=False,
        ) as (parent_fd, name):
            temporary = f".cct-deploy-{secrets.token_hex(16)}"
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
                    dir_fd=parent_fd,
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
                        name,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError as error:
                    raise DeploymentDenied("SINK_ALREADY_EXISTS") from error
                os.unlink(temporary, dir_fd=parent_fd)
                os.fsync(parent_fd)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass


__all__ = [
    "DeploymentDenied",
    "DeploymentObservation",
    "DeploymentPreview",
    "DeploymentRequest",
    "DeploymentTarget",
    "LocalFakeDeploymentAdapter",
]
