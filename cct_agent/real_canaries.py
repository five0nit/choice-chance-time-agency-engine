"""Host-bound real canaries for one Generalist2 plugin and one private Telegram DM.

These adapters own durable claims, exact bindings, readback, crash adoption, and
hash-only receipts. Host drivers own runtime/package or platform mechanics. No
credential, token, chat ID, provider client, or ambient environment value crosses
this module's driver boundary.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import fcntl
import os
from pathlib import Path
import re
import sqlite3
import stat
from types import MappingProxyType
from typing import Any, Iterator, Literal, Mapping, Protocol, Sequence

from .store import Event, EventStore, canonical_json
from .verification import HostRegisteredVerifier, VerificationDenied, VerificationObservation


PROFILE_DEPLOYMENT_CLAIM_VERSION = "cct.canary.profile-deployment.claim.v1"
PROFILE_DEPLOYMENT_RECEIPT_VERSION = "cct.canary.profile-deployment.receipt.v1"
PROFILE_ROLLBACK_CLAIM_VERSION = "cct.canary.profile-rollback.claim.v1"
PROFILE_ROLLBACK_RECEIPT_VERSION = "cct.canary.profile-rollback.receipt.v1"
TELEGRAM_DELIVERY_CLAIM_VERSION = "cct.canary.telegram-delivery.claim.v1"
TELEGRAM_DELIVERY_RECEIPT_VERSION = "cct.canary.telegram-delivery.receipt.v1"
MAX_ARTIFACT_BYTES = 67_108_864
MAX_MESSAGE_CHARS = 1800
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+=,-]{0,254}$")


class ProfileCanaryDenied(PermissionError):
    """Fail-closed Generalist2 profile deployment denial."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class TelegramDeliveryDenied(PermissionError):
    """Fail-closed private Telegram canary denial."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest(name: str, value: object, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _bounded_integer(name: str, value: object, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _relative_path(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a non-empty exact string")
    parts = value.split("/")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"{name} must be normalized ASCII") from error
    if (
        len(encoded) > 1024
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} or not _PATH_COMPONENT.fullmatch(part) for part in parts)
    ):
        raise ValueError(f"{name} must stay inside its registered root")
    return value


def _validated_root(raw: str | Path, name: str, *, private: bool) -> tuple[Path, tuple[int, int]]:
    root = Path(raw)
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
        os.chmod(resolved, 0o700)
    return resolved, (metadata.st_dev, metadata.st_ino)


def _hash_payload(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _aware_time(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as error:
        raise TelegramDeliveryDenied("PROPOSAL_EXPIRY_MALFORMED") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TelegramDeliveryDenied("PROPOSAL_EXPIRY_MALFORMED")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class HostProfileRuntimeState:
    """Privacy-safe host readback. Digests represent config/module bytes, not contents."""

    profile_name: str
    service_name: str
    package_name: str
    plugin_name: str
    package_version: str | None
    artifact_sha256: str | None
    config_sha256: str
    module_path_sha256: str | None
    plugin_enabled: bool
    last_operation_id: str | None

    def __post_init__(self) -> None:
        if self.profile_name != "generalist2":
            raise ValueError("runtime profile must be generalist2")
        if self.service_name != "hermes-gateway-generalist2.service":
            raise ValueError("runtime service must be Generalist2 service")
        if self.package_name != "cct-agency-engine" or self.plugin_name != "cct-agency":
            raise ValueError("runtime package/plugin identity mismatch")
        if self.package_version is not None:
            _identifier("package version", self.package_version)
        _digest("artifact_sha256", self.artifact_sha256, optional=True)
        _digest("config_sha256", self.config_sha256)
        _digest("module_path_sha256", self.module_path_sha256, optional=True)
        if not isinstance(self.plugin_enabled, bool):
            raise ValueError("plugin_enabled must be boolean")
        if self.last_operation_id is not None:
            _identifier("last_operation_id", self.last_operation_id)

    def runtime_payload(self) -> dict[str, object]:
        return {
            "profile_name": self.profile_name,
            "service_name": self.service_name,
            "package_name": self.package_name,
            "plugin_name": self.plugin_name,
            "package_version": self.package_version,
            "artifact_sha256": self.artifact_sha256,
            "config_sha256": self.config_sha256,
            "module_path_sha256": self.module_path_sha256,
            "plugin_enabled": self.plugin_enabled,
        }

    @property
    def runtime_sha256(self) -> str:
        return _hash_payload(self.runtime_payload())


@dataclass(frozen=True, slots=True)
class ProfileDeploymentTarget:
    id: str
    kind: Literal["hermes_profile_plugin"]
    profile_name: Literal["generalist2"]
    service_name: Literal["hermes-gateway-generalist2.service"]
    package_name: Literal["cct-agency-engine"]
    plugin_name: Literal["cct-agency"]
    package_version: str
    artifact_relative_path: str
    state_db_relative_path: str
    verifier_id: str
    max_artifact_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("target id", self.id))
        if self.kind != "hermes_profile_plugin":
            raise ValueError("profile deployment kind must be hermes_profile_plugin")
        if self.profile_name != "generalist2":
            raise ValueError("profile deployment limited to generalist2")
        if self.service_name != "hermes-gateway-generalist2.service":
            raise ValueError("service deployment limited to Generalist2 service")
        if self.package_name != "cct-agency-engine" or self.plugin_name != "cct-agency":
            raise ValueError("profile deployment limited to exact CCT plugin")
        object.__setattr__(
            self, "package_version", _identifier("package version", self.package_version)
        )
        object.__setattr__(
            self, "artifact_relative_path", _relative_path("artifact_relative_path", self.artifact_relative_path)
        )
        object.__setattr__(
            self, "state_db_relative_path", _relative_path("state_db_relative_path", self.state_db_relative_path)
        )
        object.__setattr__(self, "verifier_id", _identifier("verifier id", self.verifier_id))
        _bounded_integer("max_artifact_bytes", self.max_artifact_bytes, 1, MAX_ARTIFACT_BYTES)


@dataclass(frozen=True, slots=True)
class ProfileDeployCommand:
    operation_id: str
    target_id: str
    target_spec_sha256: str
    profile_name: str
    service_name: str
    package_name: str
    plugin_name: str
    package_version: str
    artifact_path: str
    artifact_sha256: str
    artifact_byte_count: int
    verification_event_id: str
    before_runtime_sha256: str
    sqlite_backup_path: str
    sqlite_backup_sha256: str
    ambient_credentials_allowed: bool = False
    network_allowed: bool = False
    service_reload_allowed: bool = False


@dataclass(frozen=True, slots=True)
class ProfileRollbackCommand:
    operation_id: str
    target_id: str
    target_spec_sha256: str
    deployment_operation_id: str
    expected_deployed_runtime_sha256: str
    expected_before_runtime_sha256: str
    sqlite_backup_path: str
    sqlite_backup_sha256: str
    restore_state_database: bool = False
    ambient_credentials_allowed: bool = False
    network_allowed: bool = False
    service_reload_allowed: bool = False


class ProfileDeploymentDriver(Protocol):
    def inspect(self, target: ProfileDeploymentTarget) -> HostProfileRuntimeState: ...

    def deploy(self, command: ProfileDeployCommand) -> None: ...

    def rollback(self, command: ProfileRollbackCommand) -> None: ...


@dataclass(frozen=True, slots=True)
class ProfileDeploymentPreview:
    target_id: str
    target_spec_sha256: str
    verification_request_id: str
    verification_event_id: str
    artifact_sha256: str
    artifact_byte_count: int
    before_runtime_sha256: str
    state_db_logical_sha256: str
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class ProfileDeploymentRequest:
    id: str
    target_id: str
    verification_request_id: str
    expected_verification_event_id: str
    expected_artifact_sha256: str
    expected_manifest_sha256: str
    expected_before_runtime_sha256: str
    expected_state_db_logical_sha256: str

    def __post_init__(self) -> None:
        for name in ("id", "target_id", "verification_request_id", "expected_verification_event_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        for name in (
            "expected_artifact_sha256",
            "expected_manifest_sha256",
            "expected_before_runtime_sha256",
            "expected_state_db_logical_sha256",
        ):
            object.__setattr__(self, name, _digest(name, getattr(self, name)))


@dataclass(frozen=True, slots=True)
class ProfileDeploymentObservation:
    request_id: str
    target_id: str
    profile_name: str
    service_name: str
    artifact_sha256: str
    manifest_sha256: str
    before_runtime_sha256: str
    after_runtime_sha256: str
    state_db_logical_sha256: str
    sqlite_backup_sha256: str
    artifact_readback_verified: bool
    sqlite_backup_verified: bool
    profile_mutation_count: int
    state_db_restored: bool
    status: Literal["deployed"]
    terminal_event_id: str
    replayed: bool


@dataclass(frozen=True, slots=True)
class ProfileRollbackRequest:
    id: str
    deployment_request_id: str
    expected_deployment_event_id: str
    expected_deployed_runtime_sha256: str
    expected_backup_sha256: str

    def __post_init__(self) -> None:
        for name in ("id", "deployment_request_id", "expected_deployment_event_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        for name in ("expected_deployed_runtime_sha256", "expected_backup_sha256"):
            object.__setattr__(self, name, _digest(name, getattr(self, name)))


@dataclass(frozen=True, slots=True)
class ProfileRollbackObservation:
    request_id: str
    deployment_request_id: str
    target_id: str
    before_runtime_sha256: str
    deployed_runtime_sha256: str
    rollback_runtime_sha256: str
    sqlite_backup_sha256: str
    current_state_db_logical_sha256: str
    runtime_readback_verified: bool
    state_db_restored: bool
    rollback_mutation_count: int
    status: Literal["rolled_back"]
    terminal_event_id: str
    replayed: bool


@dataclass(frozen=True, slots=True)
class _Artifact:
    path: Path
    digest: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class _RegisteredProfileTarget:
    spec: ProfileDeploymentTarget
    spec_sha256: str


class Generalist2ProfileDeploymentAdapter:
    """Deploy and roll back one exact verified wheel through a host-owned driver."""

    def __init__(
        self,
        store: EventStore,
        *,
        workspace_root: str | Path,
        profile_root: str | Path,
        adapter_state_root: str | Path,
        targets: Sequence[ProfileDeploymentTarget],
        verifier: HostRegisteredVerifier,
        driver: ProfileDeploymentDriver,
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        workspace, self._workspace_identity = _validated_root(workspace_root, "workspace_root", private=False)
        profile, self._profile_identity = _validated_root(profile_root, "profile_root", private=True)
        state_root, self._state_identity = _validated_root(
            adapter_state_root, "adapter_state_root", private=True
        )
        if profile.name != "generalist2":
            raise ValueError("profile_root must be exact generalist2 profile")
        if any(
            left == right or left.is_relative_to(right) or right.is_relative_to(left)
            for left, right in ((workspace, profile), (workspace, state_root), (profile, state_root))
        ):
            raise ValueError("workspace, profile, and adapter state roots must be separate")
        if not isinstance(verifier, HostRegisteredVerifier):
            raise ValueError("verifier must be HostRegisteredVerifier")
        if verifier.store.path.resolve() != store.path.resolve() or verifier.workspace_root != workspace:
            raise ValueError("verifier must share exact workspace and ledger")
        if not all(callable(getattr(driver, name, None)) for name in ("inspect", "deploy", "rollback")):
            raise ValueError("driver must implement inspect, deploy, and rollback")
        registrations: dict[str, _RegisteredProfileTarget] = {}
        for target in targets:
            if not isinstance(target, ProfileDeploymentTarget) or target.id in registrations:
                raise ValueError("profile deployment targets must be unique typed values")
            if target.verifier_id not in verifier.registered_ids:
                raise ValueError("profile target verifier must be registered")
            snapshot_paths = {
                str(row["relative_path"]) for row in verifier.snapshot(target.verifier_id).files
            }
            if target.artifact_relative_path not in snapshot_paths:
                raise ValueError("profile artifact must be covered by verifier snapshot")
            registrations[target.id] = _RegisteredProfileTarget(
                target, _hash_payload(asdict(target))
            )
        if not registrations:
            raise ValueError("at least one profile deployment target is required")
        self.store = store
        self.workspace_root = workspace
        self.profile_root = profile
        self.adapter_state_root = state_root
        self.verifier = verifier
        self.driver = driver
        self._targets: Mapping[str, _RegisteredProfileTarget] = MappingProxyType(registrations)
        self._backup_root = state_root / "backups"
        self._backup_root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self._backup_root, 0o700)
        self._lock_path = state_root / ".profile-canary.lock"
        descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        os.chmod(self.store.path, 0o600)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self._check_roots()
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _check_roots(self) -> None:
        for path, identity, reason in (
            (self.workspace_root, self._workspace_identity, "WORKSPACE_ROOT_CHANGED"),
            (self.profile_root, self._profile_identity, "PROFILE_ROOT_CHANGED"),
            (self.adapter_state_root, self._state_identity, "ADAPTER_STATE_ROOT_CHANGED"),
        ):
            metadata = path.stat()
            if path.is_symlink() or (metadata.st_dev, metadata.st_ino) != identity:
                raise ProfileCanaryDenied(reason)

    def _registration(self, target_id: str) -> _RegisteredProfileTarget:
        registration = self._targets.get(_identifier("target id", target_id))
        if registration is None:
            raise ProfileCanaryDenied("TARGET_NOT_REGISTERED")
        return registration

    def _artifact(self, target: ProfileDeploymentTarget) -> _Artifact:
        current = self.workspace_root
        parts = target.artifact_relative_path.split("/")
        for part in parts[:-1]:
            current = current / part
            try:
                metadata = current.lstat()
            except OSError as error:
                raise ProfileCanaryDenied("ARTIFACT_PATH_INVALID") from error
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ProfileCanaryDenied("ARTIFACT_PATH_INVALID")
        path = current / parts[-1]
        descriptor: int | None = None
        content = bytearray()
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ProfileCanaryDenied("ARTIFACT_NOT_PRIVATE_REGULAR_FILE")
            while True:
                chunk = os.read(descriptor, min(65536, target.max_artifact_bytes + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > target.max_artifact_bytes:
                    raise ProfileCanaryDenied("ARTIFACT_TOO_LARGE")
        except OSError as error:
            raise ProfileCanaryDenied("ARTIFACT_READ_FAILED") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not content:
            raise ProfileCanaryDenied("ARTIFACT_EMPTY")
        return _Artifact(path=path, digest=sha256(content).hexdigest(), byte_count=len(content))

    def _require_verification(
        self, registration: _RegisteredProfileTarget, request_id: str
    ) -> VerificationObservation:
        try:
            result = self.verifier.require_passed(request_id)
        except VerificationDenied as error:
            raise ProfileCanaryDenied(error.reason_code) from error
        if result.verifier_id != registration.spec.verifier_id or not result.deployment_eligible:
            raise ProfileCanaryDenied("VERIFICATION_BINDING_MISMATCH")
        return result

    def _state_db_path(self, target: ProfileDeploymentTarget) -> Path:
        parts = target.state_db_relative_path.split("/")
        current = self.profile_root
        for part in parts[:-1]:
            current = current / part
            try:
                parent_metadata = current.lstat()
            except OSError as error:
                raise ProfileCanaryDenied("STATE_DB_PARENT_UNSAFE") from error
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or stat.S_ISLNK(parent_metadata.st_mode)
                or parent_metadata.st_uid != os.getuid()
            ):
                raise ProfileCanaryDenied("STATE_DB_PARENT_UNSAFE")
        path = current / parts[-1]
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ProfileCanaryDenied("STATE_DB_MISSING") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise ProfileCanaryDenied("STATE_DB_UNSAFE")
        return path

    @staticmethod
    def _private_file_sha256(path: Path, reason: str) -> str:
        descriptor: int | None = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                raise ProfileCanaryDenied(reason)
            digest = sha256()
            while chunk := os.read(descriptor, 65536):
                digest.update(chunk)
            return digest.hexdigest()
        except OSError as error:
            raise ProfileCanaryDenied(reason) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _sqlite_logical_sha256(path: Path) -> str:
        try:
            connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
            try:
                if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ProfileCanaryDenied("STATE_DB_INTEGRITY_FAILED")
                material = "\n".join(connection.iterdump()).encode("utf-8")
            finally:
                connection.close()
        except ProfileCanaryDenied:
            raise
        except sqlite3.Error as error:
            raise ProfileCanaryDenied("STATE_DB_READ_FAILED") from error
        return sha256(material).hexdigest()

    def _backup_sqlite(
        self, target: ProfileDeploymentTarget, request_id: str, expected_logical: str
    ) -> tuple[Path, str]:
        source = self._state_db_path(target)
        destination = self._backup_root / f"{request_id}.sqlite"
        if destination.exists():
            if destination.is_symlink() or not destination.is_file():
                raise ProfileCanaryDenied("BACKUP_STATE_UNSAFE")
            if self._sqlite_logical_sha256(destination) != expected_logical:
                raise ProfileCanaryDenied("BACKUP_STATE_COLLISION")
            return destination, self._private_file_sha256(
                destination, "BACKUP_STATE_UNSAFE"
            )
        temporary = self._backup_root / f".{request_id}.sqlite.tmp"
        if temporary.exists():
            temporary.unlink()
        try:
            source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=5.0)
            destination_connection = sqlite3.connect(temporary)
            try:
                source_connection.backup(destination_connection)
            finally:
                destination_connection.close()
                source_connection.close()
            os.chmod(temporary, 0o600)
            if self._sqlite_logical_sha256(temporary) != expected_logical:
                raise ProfileCanaryDenied("SQLITE_BACKUP_READBACK_MISMATCH")
            temporary_fd = os.open(
                temporary, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            try:
                os.fsync(temporary_fd)
            finally:
                os.close(temporary_fd)
            os.link(temporary, destination)
            temporary.unlink()
            os.chmod(destination, 0o600)
            directory_fd = os.open(self._backup_root, os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except ProfileCanaryDenied:
            if temporary.exists():
                temporary.unlink()
            raise
        except (OSError, sqlite3.Error) as error:
            if temporary.exists():
                temporary.unlink()
            raise ProfileCanaryDenied("SQLITE_BACKUP_FAILED") from error
        return destination, self._private_file_sha256(
            destination, "BACKUP_STATE_UNSAFE"
        )

    def _inspect(self, target: ProfileDeploymentTarget) -> HostProfileRuntimeState:
        state = self.driver.inspect(target)
        if not isinstance(state, HostProfileRuntimeState):
            raise ProfileCanaryDenied("HOST_READBACK_MALFORMED")
        if (
            state.profile_name != target.profile_name
            or state.service_name != target.service_name
            or state.package_name != target.package_name
            or state.plugin_name != target.plugin_name
        ):
            raise ProfileCanaryDenied("HOST_READBACK_TARGET_MISMATCH")
        return state

    def preview(self, *, target_id: str, verification_request_id: str) -> ProfileDeploymentPreview:
        if self.store.verify_chain().get("valid") is not True:
            raise ProfileCanaryDenied("LEDGER_CHAIN_INVALID")
        registration = self._registration(target_id)
        verification = self._require_verification(registration, verification_request_id)
        artifact = self._artifact(registration.spec)
        state = self._inspect(registration.spec)
        db_digest = self._sqlite_logical_sha256(self._state_db_path(registration.spec))
        material = {
            "schema_version": 1,
            "target_id": registration.spec.id,
            "target_spec_sha256": registration.spec_sha256,
            "verification_request_id": verification.request_id,
            "verification_event_id": verification.terminal_event_id,
            "snapshot_sha256": verification.snapshot_after_sha256,
            "artifact_sha256": artifact.digest,
            "artifact_byte_count": artifact.byte_count,
            "before_runtime_sha256": state.runtime_sha256,
            "state_db_logical_sha256": db_digest,
            "profile_name": "generalist2",
            "service_name": "hermes-gateway-generalist2.service",
            "ambient_credentials_allowed": False,
            "network_allowed": False,
            "service_reload_allowed": False,
        }
        return ProfileDeploymentPreview(
            target_id=registration.spec.id,
            target_spec_sha256=registration.spec_sha256,
            verification_request_id=verification.request_id,
            verification_event_id=verification.terminal_event_id,
            artifact_sha256=artifact.digest,
            artifact_byte_count=artifact.byte_count,
            before_runtime_sha256=state.runtime_sha256,
            state_db_logical_sha256=db_digest,
            manifest_sha256=_hash_payload(material),
        )

    @staticmethod
    def _validate_request(request: ProfileDeploymentRequest, preview: ProfileDeploymentPreview) -> None:
        if (
            request.target_id != preview.target_id
            or request.verification_request_id != preview.verification_request_id
            or request.expected_verification_event_id != preview.verification_event_id
            or request.expected_artifact_sha256 != preview.artifact_sha256
            or request.expected_manifest_sha256 != preview.manifest_sha256
            or request.expected_before_runtime_sha256 != preview.before_runtime_sha256
            or request.expected_state_db_logical_sha256 != preview.state_db_logical_sha256
        ):
            raise ProfileCanaryDenied("DEPLOYMENT_PREVIEW_MISMATCH")

    def _event(self, kind: str, key: str, field: str) -> Event | None:
        rows = [event for event in self.store.events(kind) if event.payload.get(field) == key]
        if len(rows) > 1:
            raise ProfileCanaryDenied("DUPLICATE_CANARY_RECEIPTS")
        return rows[0] if rows else None

    @staticmethod
    def _is_deployed(state: HostProfileRuntimeState, claim: Mapping[str, Any]) -> bool:
        return (
            state.profile_name == "generalist2"
            and state.service_name == "hermes-gateway-generalist2.service"
            and state.package_name == "cct-agency-engine"
            and state.plugin_name == "cct-agency"
            and state.package_version == claim.get("package_version")
            and state.plugin_enabled
            and state.artifact_sha256 == claim.get("artifact_sha256")
            and state.module_path_sha256 is not None
            and state.last_operation_id == claim.get("request_id")
        )

    def deploy(self, request: ProfileDeploymentRequest) -> ProfileDeploymentObservation:
        if not isinstance(request, ProfileDeploymentRequest):
            raise ValueError("request must be ProfileDeploymentRequest")
        if self.store.verify_chain().get("valid") is not True:
            raise ProfileCanaryDenied("LEDGER_CHAIN_INVALID")
        registration = self._registration(request.target_id)
        with self._locked():
            terminal = self._event(
                "canary.profile.deployment.completed", request.id, "request_id"
            )
            if terminal is not None:
                observation = self._deployment_observation(terminal, replayed=True)
                if (
                    request.target_id != observation.target_id
                    or request.expected_verification_event_id
                    != terminal.payload.get("verification_event_id")
                    or request.expected_artifact_sha256 != observation.artifact_sha256
                    or request.expected_manifest_sha256 != observation.manifest_sha256
                    or request.expected_before_runtime_sha256
                    != observation.before_runtime_sha256
                    or request.expected_state_db_logical_sha256
                    != observation.state_db_logical_sha256
                ):
                    raise ProfileCanaryDenied("DEPLOYMENT_REQUEST_COLLISION")
                self._require_verification(registration, request.verification_request_id)
                artifact = self._artifact(registration.spec)
                if artifact.digest != observation.artifact_sha256:
                    raise ProfileCanaryDenied("DEPLOYMENT_ARTIFACT_SOURCE_STALE")
                state = self._inspect(registration.spec)
                if state.runtime_sha256 != observation.after_runtime_sha256:
                    raise ProfileCanaryDenied("DEPLOYMENT_READBACK_STALE")
                return observation
            claim = self._event("canary.profile.deployment.claimed", request.id, "request_id")
            recovering_claim = claim is not None
            verification = self._require_verification(registration, request.verification_request_id)
            artifact = self._artifact(registration.spec)
            if claim is None:
                preview = self.preview(
                    target_id=request.target_id,
                    verification_request_id=request.verification_request_id,
                )
                self._validate_request(request, preview)
                before = self._inspect(registration.spec)
                if before.plugin_enabled and before.artifact_sha256 == artifact.digest:
                    raise ProfileCanaryDenied("PREEXISTING_TARGET_ARTIFACT")
                backup_path, backup_sha = self._backup_sqlite(
                    registration.spec, request.id, preview.state_db_logical_sha256
                )
                payload = {
                    "schema_version": PROFILE_DEPLOYMENT_CLAIM_VERSION,
                    "request_id": request.id,
                    "target_id": registration.spec.id,
                    "target_spec_sha256": registration.spec_sha256,
                    "verification_request_id": verification.request_id,
                    "verification_event_id": verification.terminal_event_id,
                    "artifact_sha256": artifact.digest,
                    "artifact_byte_count": artifact.byte_count,
                    "package_version": registration.spec.package_version,
                    "manifest_sha256": preview.manifest_sha256,
                    "before_runtime": before.runtime_payload(),
                    "before_runtime_sha256": before.runtime_sha256,
                    "state_db_logical_sha256": preview.state_db_logical_sha256,
                    "sqlite_backup_sha256": backup_sha,
                    "backup_path_persisted": False,
                    "artifact_content_persisted": False,
                    "ambient_credentials_allowed": False,
                    "network_allowed": False,
                    "service_reload_allowed": False,
                    "state_db_restore_allowed": False,
                }
                claim, _ = self.store.append_once_result(
                    "canary.profile.deployment.claimed", request.id, payload
                )
            else:
                if (
                    claim.payload.get("target_spec_sha256") != registration.spec_sha256
                    or claim.payload.get("verification_event_id") != verification.terminal_event_id
                    or claim.payload.get("artifact_sha256") != artifact.digest
                    or claim.payload.get("manifest_sha256") != request.expected_manifest_sha256
                    or claim.payload.get("before_runtime_sha256")
                    != request.expected_before_runtime_sha256
                ):
                    raise ProfileCanaryDenied("DEPLOYMENT_CLAIM_COLLISION")
                backup_path = self._backup_root / f"{request.id}.sqlite"
                if (
                    self._private_file_sha256(
                        backup_path, "SQLITE_BACKUP_READBACK_STALE"
                    )
                    != claim.payload.get("sqlite_backup_sha256")
                ):
                    raise ProfileCanaryDenied("SQLITE_BACKUP_READBACK_STALE")
            state = self._inspect(registration.spec)
            if not self._is_deployed(state, claim.payload):
                if state.runtime_sha256 != claim.payload.get("before_runtime_sha256"):
                    raise ProfileCanaryDenied("HOST_RUNTIME_STATE_UNCERTAIN")
                self.driver.deploy(
                    ProfileDeployCommand(
                        operation_id=request.id,
                        target_id=registration.spec.id,
                        target_spec_sha256=registration.spec_sha256,
                        profile_name=registration.spec.profile_name,
                        service_name=registration.spec.service_name,
                        package_name=registration.spec.package_name,
                        plugin_name=registration.spec.plugin_name,
                        package_version=registration.spec.package_version,
                        artifact_path=str(artifact.path),
                        artifact_sha256=artifact.digest,
                        artifact_byte_count=artifact.byte_count,
                        verification_event_id=verification.terminal_event_id,
                        before_runtime_sha256=str(claim.payload["before_runtime_sha256"]),
                        sqlite_backup_path=str(backup_path),
                        sqlite_backup_sha256=str(claim.payload["sqlite_backup_sha256"]),
                    )
                )
                state = self._inspect(registration.spec)
            if not self._is_deployed(state, claim.payload):
                raise ProfileCanaryDenied("DEPLOYMENT_READBACK_MISMATCH")
            terminal, created = self._record_deployment_completion(
                request, registration, claim, state
            )
            return self._deployment_observation(
                terminal, replayed=recovering_claim or not created
            )

    def _record_deployment_completion(
        self,
        request: ProfileDeploymentRequest,
        registration: _RegisteredProfileTarget,
        claim: Event,
        state: HostProfileRuntimeState,
    ) -> tuple[Event, bool]:
        payload = {
            "schema_version": PROFILE_DEPLOYMENT_RECEIPT_VERSION,
            "request_id": request.id,
            "claim_event_id": claim.event_id,
            "target_id": registration.spec.id,
            "target_spec_sha256": registration.spec_sha256,
            "profile_name": "generalist2",
            "service_name": "hermes-gateway-generalist2.service",
            "verification_request_id": claim.payload["verification_request_id"],
            "verification_event_id": claim.payload["verification_event_id"],
            "artifact_sha256": claim.payload["artifact_sha256"],
            "artifact_byte_count": claim.payload["artifact_byte_count"],
            "manifest_sha256": claim.payload["manifest_sha256"],
            "before_runtime_sha256": claim.payload["before_runtime_sha256"],
            "after_runtime_sha256": state.runtime_sha256,
            "after_runtime": state.runtime_payload(),
            "state_db_logical_sha256": claim.payload["state_db_logical_sha256"],
            "sqlite_backup_sha256": claim.payload["sqlite_backup_sha256"],
            "artifact_readback_verified": True,
            "sqlite_backup_verified": True,
            "profile_mutation_count": 1,
            "state_db_restored": False,
            "status": "deployed",
            "artifact_content_persisted": False,
            "backup_path_persisted": False,
            "ambient_credentials_used": False,
            "network_effect": False,
            "service_reload_effect": False,
        }
        return self.store.append_once_result(
            "canary.profile.deployment.completed", request.id, payload
        )

    @staticmethod
    def _deployment_observation(event: Event, *, replayed: bool) -> ProfileDeploymentObservation:
        payload = event.payload
        if (
            payload.get("schema_version") != PROFILE_DEPLOYMENT_RECEIPT_VERSION
            or payload.get("status") != "deployed"
            or payload.get("artifact_readback_verified") is not True
            or payload.get("sqlite_backup_verified") is not True
            or payload.get("profile_mutation_count") != 1
            or payload.get("state_db_restored") is not False
            or payload.get("ambient_credentials_used") is not False
            or payload.get("network_effect") is not False
            or payload.get("service_reload_effect") is not False
        ):
            raise ProfileCanaryDenied("MALFORMED_DEPLOYMENT_RECEIPT")
        return ProfileDeploymentObservation(
            request_id=str(payload["request_id"]),
            target_id=str(payload["target_id"]),
            profile_name=str(payload["profile_name"]),
            service_name=str(payload["service_name"]),
            artifact_sha256=str(payload["artifact_sha256"]),
            manifest_sha256=str(payload["manifest_sha256"]),
            before_runtime_sha256=str(payload["before_runtime_sha256"]),
            after_runtime_sha256=str(payload["after_runtime_sha256"]),
            state_db_logical_sha256=str(payload["state_db_logical_sha256"]),
            sqlite_backup_sha256=str(payload["sqlite_backup_sha256"]),
            artifact_readback_verified=True,
            sqlite_backup_verified=True,
            profile_mutation_count=1,
            state_db_restored=False,
            status="deployed",
            terminal_event_id=event.event_id,
            replayed=replayed,
        )

    def rollback(self, request: ProfileRollbackRequest) -> ProfileRollbackObservation:
        if not isinstance(request, ProfileRollbackRequest):
            raise ValueError("request must be ProfileRollbackRequest")
        if self.store.verify_chain().get("valid") is not True:
            raise ProfileCanaryDenied("LEDGER_CHAIN_INVALID")
        deployment_event = self._event(
            "canary.profile.deployment.completed",
            request.deployment_request_id,
            "request_id",
        )
        if deployment_event is None:
            raise ProfileCanaryDenied("DEPLOYMENT_NOT_COMPLETED")
        deployment = self._deployment_observation(deployment_event, replayed=True)
        if (
            deployment_event.event_id != request.expected_deployment_event_id
            or deployment.after_runtime_sha256 != request.expected_deployed_runtime_sha256
            or deployment.sqlite_backup_sha256 != request.expected_backup_sha256
        ):
            raise ProfileCanaryDenied("ROLLBACK_BINDING_MISMATCH")
        registration = self._registration(deployment.target_id)
        backup_path = self._backup_root / f"{deployment.request_id}.sqlite"
        if (
            self._private_file_sha256(
                backup_path, "SQLITE_BACKUP_READBACK_STALE"
            )
            != deployment.sqlite_backup_sha256
        ):
            raise ProfileCanaryDenied("SQLITE_BACKUP_READBACK_STALE")
        with self._locked():
            terminal = self._event(
                "canary.profile.rollback.completed", request.id, "request_id"
            )
            if terminal is not None:
                observation = self._rollback_observation(terminal, replayed=True)
                if self._inspect(registration.spec).runtime_sha256 != observation.rollback_runtime_sha256:
                    raise ProfileCanaryDenied("ROLLBACK_READBACK_STALE")
                return observation
            claim = self._event("canary.profile.rollback.claimed", request.id, "request_id")
            if claim is None:
                state = self._inspect(registration.spec)
                if state.runtime_sha256 != deployment.after_runtime_sha256:
                    raise ProfileCanaryDenied("DEPLOYED_RUNTIME_DRIFT")
                claim_payload = {
                    "schema_version": PROFILE_ROLLBACK_CLAIM_VERSION,
                    "request_id": request.id,
                    "deployment_request_id": deployment.request_id,
                    "deployment_event_id": deployment_event.event_id,
                    "target_id": deployment.target_id,
                    "target_spec_sha256": registration.spec_sha256,
                    "before_runtime_sha256": deployment.before_runtime_sha256,
                    "deployed_runtime_sha256": deployment.after_runtime_sha256,
                    "sqlite_backup_sha256": deployment.sqlite_backup_sha256,
                    "state_db_restore_allowed": False,
                    "ambient_credentials_allowed": False,
                    "network_allowed": False,
                    "service_reload_allowed": False,
                }
                claim, _ = self.store.append_once_result(
                    "canary.profile.rollback.claimed", request.id, claim_payload
                )
            elif (
                claim.payload.get("deployment_event_id") != deployment_event.event_id
                or claim.payload.get("target_spec_sha256") != registration.spec_sha256
                or claim.payload.get("sqlite_backup_sha256") != deployment.sqlite_backup_sha256
            ):
                raise ProfileCanaryDenied("ROLLBACK_CLAIM_COLLISION")
            state = self._inspect(registration.spec)
            if state.runtime_sha256 != deployment.before_runtime_sha256:
                if state.runtime_sha256 != deployment.after_runtime_sha256:
                    raise ProfileCanaryDenied("ROLLBACK_RUNTIME_STATE_UNCERTAIN")
                self.driver.rollback(
                    ProfileRollbackCommand(
                        operation_id=request.id,
                        target_id=registration.spec.id,
                        target_spec_sha256=registration.spec_sha256,
                        deployment_operation_id=deployment.request_id,
                        expected_deployed_runtime_sha256=deployment.after_runtime_sha256,
                        expected_before_runtime_sha256=deployment.before_runtime_sha256,
                        sqlite_backup_path=str(backup_path),
                        sqlite_backup_sha256=deployment.sqlite_backup_sha256,
                    )
                )
                state = self._inspect(registration.spec)
            if state.runtime_sha256 != deployment.before_runtime_sha256:
                raise ProfileCanaryDenied("ROLLBACK_READBACK_MISMATCH")
            current_db = self._sqlite_logical_sha256(self._state_db_path(registration.spec))
            payload = {
                "schema_version": PROFILE_ROLLBACK_RECEIPT_VERSION,
                "request_id": request.id,
                "claim_event_id": claim.event_id,
                "deployment_request_id": deployment.request_id,
                "deployment_event_id": deployment_event.event_id,
                "target_id": deployment.target_id,
                "before_runtime_sha256": deployment.before_runtime_sha256,
                "deployed_runtime_sha256": deployment.after_runtime_sha256,
                "rollback_runtime_sha256": state.runtime_sha256,
                "sqlite_backup_sha256": deployment.sqlite_backup_sha256,
                "current_state_db_logical_sha256": current_db,
                "runtime_readback_verified": True,
                "state_db_restored": False,
                "rollback_mutation_count": 1,
                "status": "rolled_back",
                "ambient_credentials_used": False,
                "network_effect": False,
                "service_reload_effect": False,
            }
            terminal, created = self.store.append_once_result(
                "canary.profile.rollback.completed", request.id, payload
            )
            return self._rollback_observation(terminal, replayed=not created)

    @staticmethod
    def _rollback_observation(event: Event, *, replayed: bool) -> ProfileRollbackObservation:
        payload = event.payload
        if (
            payload.get("schema_version") != PROFILE_ROLLBACK_RECEIPT_VERSION
            or payload.get("status") != "rolled_back"
            or payload.get("runtime_readback_verified") is not True
            or payload.get("state_db_restored") is not False
            or payload.get("rollback_mutation_count") != 1
        ):
            raise ProfileCanaryDenied("MALFORMED_ROLLBACK_RECEIPT")
        return ProfileRollbackObservation(
            request_id=str(payload["request_id"]),
            deployment_request_id=str(payload["deployment_request_id"]),
            target_id=str(payload["target_id"]),
            before_runtime_sha256=str(payload["before_runtime_sha256"]),
            deployed_runtime_sha256=str(payload["deployed_runtime_sha256"]),
            rollback_runtime_sha256=str(payload["rollback_runtime_sha256"]),
            sqlite_backup_sha256=str(payload["sqlite_backup_sha256"]),
            current_state_db_logical_sha256=str(payload["current_state_db_logical_sha256"]),
            runtime_readback_verified=True,
            state_db_restored=False,
            rollback_mutation_count=1,
            status="rolled_back",
            terminal_event_id=event.event_id,
            replayed=replayed,
        )


@dataclass(frozen=True, slots=True)
class TelegramDeliveryTarget:
    id: str
    kind: Literal["hermes_private_delivery"]
    profile_name: Literal["generalist2"]
    service_name: Literal["hermes-gateway-generalist2.service"]
    platform: Literal["telegram"]
    chat_type: Literal["private"]
    principal_id: Literal["mike"]
    recipient_binding_sha256: str
    max_message_chars: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("target id", self.id))
        if self.kind != "hermes_private_delivery":
            raise ValueError("delivery kind must be hermes_private_delivery")
        if self.profile_name != "generalist2" or self.service_name != "hermes-gateway-generalist2.service":
            raise ValueError("delivery limited to generalist2 owning service")
        if self.platform != "telegram" or self.chat_type != "private":
            raise ValueError("delivery limited to private Telegram")
        if self.principal_id != "mike":
            raise ValueError("delivery limited to Mike principal")
        object.__setattr__(
            self,
            "recipient_binding_sha256",
            _digest("recipient_binding_sha256", self.recipient_binding_sha256),
        )
        _bounded_integer("max_message_chars", self.max_message_chars, 1, MAX_MESSAGE_CHARS)


@dataclass(frozen=True, slots=True)
class TelegramDeliveryReadback:
    operation_id: str
    target_id: str
    proposal_event_id: str
    proposal_id: str
    proposal_revision: int
    portfolio_sha256: str
    recipient_binding_sha256: str
    message_sha256: str
    message_byte_count: int
    provider_receipt_sha256: str
    provider_message_id_sha256: str
    chat_type: Literal["private"]
    delivered: bool

    def __post_init__(self) -> None:
        for name in ("operation_id", "target_id", "proposal_event_id", "proposal_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        _bounded_integer("proposal_revision", self.proposal_revision, 1, 2_147_483_647)
        for name in (
            "portfolio_sha256",
            "recipient_binding_sha256",
            "message_sha256",
            "provider_receipt_sha256",
            "provider_message_id_sha256",
        ):
            object.__setattr__(self, name, _digest(name, getattr(self, name)))
        _bounded_integer("message_byte_count", self.message_byte_count, 1, 65_536)
        if self.chat_type != "private" or self.delivered is not True:
            raise ValueError("readback must prove one private delivered message")


@dataclass(frozen=True, slots=True)
class TelegramDeliveryCommand:
    operation_id: str
    target_id: str
    proposal_event_id: str
    proposal_id: str
    proposal_revision: int
    portfolio_sha256: str
    principal_id: str
    recipient_binding_sha256: str
    message: str
    message_sha256: str
    ambient_credentials_allowed: bool = False
    public_audience_allowed: bool = False
    group_audience_allowed: bool = False


class TelegramDeliveryDriver(Protocol):
    def inspect(
        self, target: TelegramDeliveryTarget, delivery_id: str
    ) -> TelegramDeliveryReadback | None: ...

    def deliver(self, command: TelegramDeliveryCommand) -> None: ...


@dataclass(frozen=True, slots=True)
class TelegramDeliveryPreview:
    target_id: str
    target_spec_sha256: str
    proposal_event_id: str
    proposal_id: str
    proposal_revision: int
    portfolio_sha256: str
    principal_id: str
    recipient_binding_sha256: str
    message_sha256: str
    message_byte_count: int
    preview_sha256: str


@dataclass(frozen=True, slots=True)
class TelegramDeliveryRequest:
    id: str
    target_id: str
    proposal_id: str
    proposal_revision: int
    expected_proposal_event_id: str
    expected_portfolio_sha256: str
    expected_message_sha256: str
    expected_preview_sha256: str

    def __post_init__(self) -> None:
        for name in ("id", "target_id", "proposal_id", "expected_proposal_event_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        _bounded_integer("proposal_revision", self.proposal_revision, 1, 2_147_483_647)
        for name in (
            "expected_portfolio_sha256",
            "expected_message_sha256",
            "expected_preview_sha256",
        ):
            object.__setattr__(self, name, _digest(name, getattr(self, name)))


@dataclass(frozen=True, slots=True)
class TelegramDeliveryObservation:
    request_id: str
    target_id: str
    profile_name: str
    service_name: str
    platform: str
    chat_type: str
    principal_id: str
    proposal_event_id: str
    proposal_id: str
    proposal_revision: int
    portfolio_sha256: str
    recipient_binding_sha256: str
    message_sha256: str
    provider_receipt_sha256: str
    provider_message_id_sha256: str
    delivery_readback_verified: bool
    external_effect_count: int
    ambient_credentials_used: bool
    host_managed_delivery: bool
    status: Literal["delivered"]
    terminal_event_id: str
    replayed: bool


@dataclass(frozen=True, slots=True)
class _RegisteredTelegramTarget:
    spec: TelegramDeliveryTarget
    spec_sha256: str


class PrivateTelegramDeliveryAdapter:
    """Deliver one open typed pursuit proposal to Mike's bound private DM once."""

    def __init__(
        self,
        store: EventStore,
        *,
        adapter_state_root: str | Path,
        targets: Sequence[TelegramDeliveryTarget],
        driver: TelegramDeliveryDriver,
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be EventStore")
        state_root, self._state_identity = _validated_root(
            adapter_state_root, "adapter_state_root", private=True
        )
        if not all(callable(getattr(driver, name, None)) for name in ("inspect", "deliver")):
            raise ValueError("driver must implement inspect and deliver")
        registrations: dict[str, _RegisteredTelegramTarget] = {}
        bindings: set[str] = set()
        for target in targets:
            if not isinstance(target, TelegramDeliveryTarget) or target.id in registrations:
                raise ValueError("delivery targets must be unique typed values")
            if target.recipient_binding_sha256 in bindings:
                raise ValueError("recipient binding must be unique")
            registrations[target.id] = _RegisteredTelegramTarget(target, _hash_payload(asdict(target)))
            bindings.add(target.recipient_binding_sha256)
        if not registrations:
            raise ValueError("at least one private delivery target required")
        self.store = store
        self.adapter_state_root = state_root
        self.driver = driver
        self._targets: Mapping[str, _RegisteredTelegramTarget] = MappingProxyType(registrations)
        self._lock_path = state_root / ".telegram-canary.lock"
        descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        os.chmod(self.store.path, 0o600)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            metadata = self.adapter_state_root.stat()
            if (
                self.adapter_state_root.is_symlink()
                or (metadata.st_dev, metadata.st_ino) != self._state_identity
            ):
                raise TelegramDeliveryDenied("ADAPTER_STATE_ROOT_CHANGED")
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _registration(self, target_id: str) -> _RegisteredTelegramTarget:
        registration = self._targets.get(_identifier("target id", target_id))
        if registration is None:
            raise TelegramDeliveryDenied("TARGET_NOT_REGISTERED")
        return registration

    def _proposal(self, proposal_id: str, revision: int) -> Event:
        proposal_id = _identifier("proposal id", proposal_id)
        _bounded_integer("proposal revision", revision, 1, 2_147_483_647)
        proposals = [
            event
            for event in self.store.events("pursuit.dialogue.proposed")
            if event.payload.get("proposal_id") == proposal_id
        ]
        if not proposals:
            raise TelegramDeliveryDenied("PROPOSAL_NOT_FOUND")
        latest_revision = max(int(event.payload.get("revision", 0)) for event in proposals)
        if revision != latest_revision:
            raise TelegramDeliveryDenied("STALE_PROPOSAL_REVISION")
        rows = [event for event in proposals if int(event.payload.get("revision", 0)) == revision]
        if len(rows) != 1:
            raise TelegramDeliveryDenied("PROPOSAL_REVISION_COLLISION")
        proposal = rows[0]
        payload = proposal.payload
        ranked = payload.get("ranked_pursuits")
        if (
            payload.get("source_authority") != "host_adapter"
            or payload.get("question_kind") != "bounded_priority_negotiation"
            or payload.get("raw_producer_content_persisted") is not False
            or payload.get("raw_chain_of_thought_stored") is not False
            or payload.get("principal_id") != "mike"
            or not isinstance(ranked, list)
            or not 3 <= len(ranked) <= 6
            or any(
                not isinstance(row, Mapping)
                or row.get("semantic_taint") is not False
                or row.get("producer_text_used") is not False
                for row in ranked
            )
        ):
            raise TelegramDeliveryDenied("PROPOSAL_NOT_TYPED_OR_SAFE")
        expected_material = {
            key: payload[key]
            for key in (
                "schema_version",
                "proposal_id",
                "revision",
                "question",
                "ranked_pursuits",
                "recommended_pursuit_id",
                "trigger_reasons",
                "expires_at",
                "principal_id",
                "principal_profile_digest",
                "principal_profile_revision",
            )
        }
        if payload.get("portfolio_sha256") != _hash_payload(expected_material):
            raise TelegramDeliveryDenied("PROPOSAL_PORTFOLIO_HASH_INVALID")
        if _aware_time(self.store.clock()) > _aware_time(payload["expires_at"]):
            raise TelegramDeliveryDenied("PROPOSAL_EXPIRED")
        presented = any(
            event.kind == "pursuit.dialogue.presentation.completed"
            and event.payload.get("proposal_event_id") == proposal.event_id
            and event.payload.get("portfolio_sha256") == payload["portfolio_sha256"]
            and event.payload.get("emitted") is True
            for event in self.store.events()
        )
        if not presented:
            raise TelegramDeliveryDenied("PROPOSAL_NOT_PRESENTED")
        applied = any(
            event.kind == "pursuit.dialogue.reply.applied"
            and event.payload.get("proposal_event_id") == proposal.event_id
            for event in self.store.events()
        )
        if applied:
            raise TelegramDeliveryDenied("PROPOSAL_ALREADY_RESOLVED")
        return proposal

    @staticmethod
    def _message(proposal: Event) -> str:
        payload = proposal.payload
        lines = [
            f"{payload['question']} [{payload['proposal_id']} r{payload['revision']}]",
            "",
        ]
        for row in payload["ranked_pursuits"]:
            evidence = row["evidence"][0] if row["evidence"] else "canonical:none"
            lines.append(
                f"{row['rank']}. {row['id']} — {row['summary']} | "
                f"payoff={float(row['payoff']):.2f} cost={float(row['cost']):.2f} "
                f"uncertainty={float(row['uncertainty']):.2f} "
                f"authority={row['required_authority']} evidence={evidence}"
            )
        lines.extend(
            (
                "",
                f"Recommendation: {payload['recommended_pursuit_id']}",
                f"Reply must bind {payload['proposal_id']} r{payload['revision']} "
                f"portfolio={payload['portfolio_sha256']}.",
            )
        )
        return "\n".join(lines)

    def preview(
        self, *, target_id: str, proposal_id: str, proposal_revision: int
    ) -> TelegramDeliveryPreview:
        if self.store.verify_chain().get("valid") is not True:
            raise TelegramDeliveryDenied("LEDGER_CHAIN_INVALID")
        registration = self._registration(target_id)
        proposal = self._proposal(proposal_id, proposal_revision)
        message = self._message(proposal)
        if len(message) > registration.spec.max_message_chars:
            raise TelegramDeliveryDenied("MESSAGE_TOO_LARGE")
        message_bytes = message.encode("utf-8")
        material = {
            "schema_version": 1,
            "target_id": registration.spec.id,
            "target_spec_sha256": registration.spec_sha256,
            "proposal_event_id": proposal.event_id,
            "proposal_id": proposal.payload["proposal_id"],
            "proposal_revision": proposal.payload["revision"],
            "portfolio_sha256": proposal.payload["portfolio_sha256"],
            "principal_id": "mike",
            "recipient_binding_sha256": registration.spec.recipient_binding_sha256,
            "message_sha256": sha256(message_bytes).hexdigest(),
            "message_byte_count": len(message_bytes),
            "chat_type": "private",
            "public_audience_allowed": False,
            "group_audience_allowed": False,
            "ambient_credentials_allowed": False,
        }
        return TelegramDeliveryPreview(
            target_id=registration.spec.id,
            target_spec_sha256=registration.spec_sha256,
            proposal_event_id=proposal.event_id,
            proposal_id=str(proposal.payload["proposal_id"]),
            proposal_revision=int(proposal.payload["revision"]),
            portfolio_sha256=str(proposal.payload["portfolio_sha256"]),
            principal_id="mike",
            recipient_binding_sha256=registration.spec.recipient_binding_sha256,
            message_sha256=sha256(message_bytes).hexdigest(),
            message_byte_count=len(message_bytes),
            preview_sha256=_hash_payload(material),
        )

    @staticmethod
    def _validate_delivery_request(
        request: TelegramDeliveryRequest, preview: TelegramDeliveryPreview
    ) -> None:
        if (
            request.target_id != preview.target_id
            or request.proposal_id != preview.proposal_id
            or request.proposal_revision != preview.proposal_revision
            or request.expected_proposal_event_id != preview.proposal_event_id
            or request.expected_portfolio_sha256 != preview.portfolio_sha256
            or request.expected_message_sha256 != preview.message_sha256
            or request.expected_preview_sha256 != preview.preview_sha256
        ):
            raise TelegramDeliveryDenied("DELIVERY_PREVIEW_MISMATCH")

    def _event(self, kind: str, request_id: str) -> Event | None:
        rows = [
            event for event in self.store.events(kind) if event.payload.get("request_id") == request_id
        ]
        if len(rows) > 1:
            raise TelegramDeliveryDenied("DUPLICATE_DELIVERY_RECEIPTS")
        return rows[0] if rows else None

    @staticmethod
    def _validate_readback(
        readback: TelegramDeliveryReadback | None,
        request: TelegramDeliveryRequest,
        preview: TelegramDeliveryPreview,
    ) -> TelegramDeliveryReadback:
        if not isinstance(readback, TelegramDeliveryReadback):
            raise TelegramDeliveryDenied("DELIVERY_READBACK_MISSING")
        if (
            readback.operation_id != request.id
            or readback.target_id != preview.target_id
            or readback.proposal_event_id != preview.proposal_event_id
            or readback.proposal_id != preview.proposal_id
            or readback.proposal_revision != preview.proposal_revision
            or readback.portfolio_sha256 != preview.portfolio_sha256
            or readback.recipient_binding_sha256 != preview.recipient_binding_sha256
            or readback.message_sha256 != preview.message_sha256
            or readback.message_byte_count != preview.message_byte_count
            or readback.chat_type != "private"
            or not readback.delivered
        ):
            raise TelegramDeliveryDenied("DELIVERY_READBACK_MISMATCH")
        return readback

    def deliver(self, request: TelegramDeliveryRequest) -> TelegramDeliveryObservation:
        if not isinstance(request, TelegramDeliveryRequest):
            raise ValueError("request must be TelegramDeliveryRequest")
        if self.store.verify_chain().get("valid") is not True:
            raise TelegramDeliveryDenied("LEDGER_CHAIN_INVALID")
        registration = self._registration(request.target_id)
        with self._locked():
            terminal = self._event("canary.telegram.delivery.completed", request.id)
            if terminal is not None:
                observation = self._delivery_observation(terminal, replayed=True)
                payload = terminal.payload
                if (
                    request.target_id != observation.target_id
                    or payload.get("target_spec_sha256") != registration.spec_sha256
                    or request.proposal_id != observation.proposal_id
                    or request.proposal_revision != observation.proposal_revision
                    or request.expected_proposal_event_id != observation.proposal_event_id
                    or request.expected_portfolio_sha256 != observation.portfolio_sha256
                    or request.expected_message_sha256 != observation.message_sha256
                    or request.expected_preview_sha256 != payload.get("preview_sha256")
                    or observation.recipient_binding_sha256
                    != registration.spec.recipient_binding_sha256
                ):
                    raise TelegramDeliveryDenied("DELIVERY_REQUEST_COLLISION")
                readback = self.driver.inspect(registration.spec, request.id)
                if (
                    not isinstance(readback, TelegramDeliveryReadback)
                    or readback.operation_id != request.id
                    or readback.target_id != observation.target_id
                    or readback.proposal_event_id != observation.proposal_event_id
                    or readback.proposal_id != observation.proposal_id
                    or readback.proposal_revision != observation.proposal_revision
                    or readback.portfolio_sha256 != observation.portfolio_sha256
                    or readback.recipient_binding_sha256
                    != observation.recipient_binding_sha256
                    or readback.message_sha256 != observation.message_sha256
                    or readback.message_byte_count != payload.get("message_byte_count")
                    or readback.chat_type != "private"
                    or readback.delivered is not True
                    or readback.provider_receipt_sha256
                    != observation.provider_receipt_sha256
                    or readback.provider_message_id_sha256
                    != observation.provider_message_id_sha256
                ):
                    raise TelegramDeliveryDenied("DELIVERY_READBACK_STALE")
                return observation
            preview = self.preview(
                target_id=request.target_id,
                proposal_id=request.proposal_id,
                proposal_revision=request.proposal_revision,
            )
            self._validate_delivery_request(request, preview)
            message = self._message(
                self._proposal(request.proposal_id, request.proposal_revision)
            )
            claim = self._event("canary.telegram.delivery.claimed", request.id)
            recovering_claim = claim is not None
            readback = self.driver.inspect(registration.spec, request.id)
            if claim is None:
                if readback is not None:
                    raise TelegramDeliveryDenied("PREEXISTING_DELIVERY")
                claim_payload = {
                    "schema_version": TELEGRAM_DELIVERY_CLAIM_VERSION,
                    "request_id": request.id,
                    "target_id": preview.target_id,
                    "target_spec_sha256": preview.target_spec_sha256,
                    "profile_name": "generalist2",
                    "service_name": "hermes-gateway-generalist2.service",
                    "platform": "telegram",
                    "chat_type": "private",
                    "principal_id": "mike",
                    "proposal_event_id": preview.proposal_event_id,
                    "proposal_id": preview.proposal_id,
                    "proposal_revision": preview.proposal_revision,
                    "portfolio_sha256": preview.portfolio_sha256,
                    "recipient_binding_sha256": preview.recipient_binding_sha256,
                    "message_sha256": preview.message_sha256,
                    "message_byte_count": preview.message_byte_count,
                    "preview_sha256": preview.preview_sha256,
                    "message_content_persisted": False,
                    "raw_producer_content_persisted": False,
                    "ambient_credentials_allowed": False,
                    "public_audience_allowed": False,
                    "group_audience_allowed": False,
                }
                claim, _ = self.store.append_once_result(
                    "canary.telegram.delivery.claimed", request.id, claim_payload
                )
            elif (
                claim.payload.get("target_spec_sha256") != preview.target_spec_sha256
                or claim.payload.get("proposal_event_id") != preview.proposal_event_id
                or claim.payload.get("portfolio_sha256") != preview.portfolio_sha256
                or claim.payload.get("message_sha256") != preview.message_sha256
                or claim.payload.get("preview_sha256") != preview.preview_sha256
            ):
                raise TelegramDeliveryDenied("DELIVERY_CLAIM_COLLISION")
            if readback is None:
                self.driver.deliver(
                    TelegramDeliveryCommand(
                        operation_id=request.id,
                        target_id=preview.target_id,
                        proposal_event_id=preview.proposal_event_id,
                        proposal_id=preview.proposal_id,
                        proposal_revision=preview.proposal_revision,
                        portfolio_sha256=preview.portfolio_sha256,
                        principal_id="mike",
                        recipient_binding_sha256=preview.recipient_binding_sha256,
                        message=message,
                        message_sha256=preview.message_sha256,
                    )
                )
                readback = self.driver.inspect(registration.spec, request.id)
            readback = self._validate_readback(readback, request, preview)
            payload = {
                "schema_version": TELEGRAM_DELIVERY_RECEIPT_VERSION,
                "request_id": request.id,
                "claim_event_id": claim.event_id,
                "target_id": preview.target_id,
                "target_spec_sha256": preview.target_spec_sha256,
                "profile_name": "generalist2",
                "service_name": "hermes-gateway-generalist2.service",
                "platform": "telegram",
                "chat_type": "private",
                "principal_id": "mike",
                "proposal_event_id": preview.proposal_event_id,
                "proposal_id": preview.proposal_id,
                "proposal_revision": preview.proposal_revision,
                "portfolio_sha256": preview.portfolio_sha256,
                "recipient_binding_sha256": preview.recipient_binding_sha256,
                "message_sha256": preview.message_sha256,
                "message_byte_count": preview.message_byte_count,
                "preview_sha256": preview.preview_sha256,
                "provider_receipt_sha256": readback.provider_receipt_sha256,
                "provider_message_id_sha256": readback.provider_message_id_sha256,
                "delivery_readback_verified": True,
                "external_effect_count": 1,
                "ambient_credentials_used": False,
                "host_managed_delivery": True,
                "message_content_persisted": False,
                "raw_producer_content_persisted": False,
                "status": "delivered",
            }
            terminal, created = self.store.append_once_result(
                "canary.telegram.delivery.completed", request.id, payload
            )
            return self._delivery_observation(
                terminal, replayed=recovering_claim or not created
            )

    @staticmethod
    def _delivery_observation(event: Event, *, replayed: bool) -> TelegramDeliveryObservation:
        payload = event.payload
        if (
            payload.get("schema_version") != TELEGRAM_DELIVERY_RECEIPT_VERSION
            or payload.get("status") != "delivered"
            or payload.get("profile_name") != "generalist2"
            or payload.get("service_name") != "hermes-gateway-generalist2.service"
            or payload.get("platform") != "telegram"
            or payload.get("chat_type") != "private"
            or payload.get("principal_id") != "mike"
            or payload.get("delivery_readback_verified") is not True
            or payload.get("external_effect_count") != 1
            or payload.get("ambient_credentials_used") is not False
            or payload.get("host_managed_delivery") is not True
            or payload.get("message_content_persisted") is not False
            or payload.get("raw_producer_content_persisted") is not False
        ):
            raise TelegramDeliveryDenied("MALFORMED_DELIVERY_RECEIPT")
        return TelegramDeliveryObservation(
            request_id=str(payload["request_id"]),
            target_id=str(payload["target_id"]),
            profile_name="generalist2",
            service_name="hermes-gateway-generalist2.service",
            platform="telegram",
            chat_type="private",
            principal_id="mike",
            proposal_event_id=str(payload["proposal_event_id"]),
            proposal_id=str(payload["proposal_id"]),
            proposal_revision=int(payload["proposal_revision"]),
            portfolio_sha256=str(payload["portfolio_sha256"]),
            recipient_binding_sha256=str(payload["recipient_binding_sha256"]),
            message_sha256=str(payload["message_sha256"]),
            provider_receipt_sha256=str(payload["provider_receipt_sha256"]),
            provider_message_id_sha256=str(payload["provider_message_id_sha256"]),
            delivery_readback_verified=True,
            external_effect_count=1,
            ambient_credentials_used=False,
            host_managed_delivery=True,
            status="delivered",
            terminal_event_id=event.event_id,
            replayed=replayed,
        )
