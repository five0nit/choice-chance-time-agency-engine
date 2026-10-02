"""Ticketed host-driver deployments with exact preview, readback, and rollback."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping, Protocol, Sequence

from .deployment import DeploymentDenied
from .execution_tickets import GlobalKillSwitch, TicketAuthorityDenied
from .mediation_outcomes import OutcomeVerification, OutcomeVerifierRegistry, VerificationContext
from .store import Event, EventStore, canonical_json
from .verification import HostRegisteredVerifier, VerificationDenied, VerificationObservation


OPERATOR_DEPLOY_CLAIM_SCHEMA_VERSION = "cct.operator_deployment.claim.v1"
OPERATOR_DEPLOY_RECEIPT_SCHEMA_VERSION = "cct.operator_deployment.receipt.v1"
OPERATOR_DEPLOY_VERIFIER_ID = "operator-deploy-readback"
MAX_OPERATOR_DEPLOY_TARGETS = 64
MAX_OPERATOR_DEPLOY_BYTES = 67_108_864
MAX_RELATIVE_PATH_BYTES = 1024
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+=,-]{0,254}$")


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


def _integer(name: str, value: object, *, minimum: int, maximum: int) -> int:
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
        or any(part in {"", ".", ".."} or not _PATH_COMPONENT.fullmatch(part) for part in parts)
    ):
        raise ValueError(f"{name} must stay within its registered root")
    return value


def _hash_payload(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


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


@dataclass(frozen=True, slots=True)
class OperatorDeploymentTarget:
    """Host registration binding one verified artifact to one provider driver."""

    id: str
    driver_id: str
    provider: str
    environment: str
    artifact_relative_path: str
    verifier_id: str
    max_artifact_bytes: int
    rollback_supported: bool

    def __post_init__(self) -> None:
        for field in ("id", "driver_id", "provider", "environment", "verifier_id"):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        object.__setattr__(
            self,
            "artifact_relative_path",
            _relative_path("artifact_relative_path", self.artifact_relative_path),
        )
        _integer(
            "max_artifact_bytes",
            self.max_artifact_bytes,
            minimum=1,
            maximum=MAX_OPERATOR_DEPLOY_BYTES,
        )
        if not isinstance(self.rollback_supported, bool):
            raise ValueError("rollback_supported must be a boolean")


@dataclass(frozen=True, slots=True)
class ProviderDeploymentState:
    """Privacy-safe provider readback. Raw provider response never enters ledger."""

    target_id: str
    provider: str
    environment: str
    deployed: bool
    artifact_sha256: str | None
    artifact_byte_count: int
    deployment_id_sha256: str
    provider_receipt_sha256: str
    last_operation_id: str | None

    def __post_init__(self) -> None:
        for field in ("target_id", "provider", "environment"):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.deployed, bool):
            raise ValueError("deployed must be a boolean")
        _digest("artifact_sha256", self.artifact_sha256, optional=True)
        _integer(
            "artifact_byte_count",
            self.artifact_byte_count,
            minimum=0,
            maximum=MAX_OPERATOR_DEPLOY_BYTES,
        )
        _digest("deployment_id_sha256", self.deployment_id_sha256)
        _digest("provider_receipt_sha256", self.provider_receipt_sha256)
        if self.last_operation_id is not None:
            object.__setattr__(
                self,
                "last_operation_id",
                _identifier("last_operation_id", self.last_operation_id),
            )
        if self.deployed != (self.artifact_sha256 is not None):
            raise ValueError("deployed state and artifact digest disagree")
        if not self.deployed and self.artifact_byte_count != 0:
            raise ValueError("absent deployment cannot report artifact bytes")

    @property
    def state_sha256(self) -> str:
        return _hash_payload(asdict(self))


@dataclass(frozen=True, slots=True)
class DeploymentProviderCommand:
    operation_id: str
    target_id: str
    provider: str
    environment: str
    artifact_path: str
    artifact_sha256: str
    artifact_byte_count: int
    expected_before_state_sha256: str
    preview_sha256: str
    credential_handles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DeploymentProviderRollbackCommand:
    operation_id: str
    deployment_operation_id: str
    target_id: str
    provider: str
    environment: str
    expected_deployed_artifact_sha256: str
    expected_before_artifact_sha256: str | None
    expected_before_artifact_byte_count: int
    credential_handles: tuple[str, ...] = ()


class OperatorDeploymentDriver(Protocol):
    def inspect(self, target: OperatorDeploymentTarget) -> ProviderDeploymentState: ...

    def deploy(
        self,
        target: OperatorDeploymentTarget,
        command: DeploymentProviderCommand,
    ) -> None: ...

    def rollback(
        self,
        target: OperatorDeploymentTarget,
        command: DeploymentProviderRollbackCommand,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class LocalDeploymentRoute:
    """Host-only destination route for one owned local staging target."""

    target_id: str
    environment: str
    root: str | Path
    relative_path: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_id", _identifier("target_id", self.target_id))
        object.__setattr__(self, "environment", _identifier("environment", self.environment))
        object.__setattr__(self, "root", Path(self.root))
        object.__setattr__(
            self,
            "relative_path",
            _relative_path("relative_path", self.relative_path),
        )


@dataclass(frozen=True, slots=True)
class _RegisteredLocalRoute:
    spec: LocalDeploymentRoute
    root: Path
    root_identity: tuple[int, int]
    destination: Path


class LocalDirectoryDeploymentDriver:
    """Real atomic local provider with restart-safe idempotency and rollback backups."""

    def __init__(
        self,
        *,
        state_root: str | Path,
        provider: str,
        routes: Sequence[LocalDeploymentRoute],
    ) -> None:
        self.provider = _identifier("provider", provider)
        state, self._state_identity = _validated_root(state_root, "state_root", private=True)
        registrations: dict[str, _RegisteredLocalRoute] = {}
        for route in routes:
            if not isinstance(route, LocalDeploymentRoute) or route.target_id in registrations:
                raise ValueError("routes must contain unique LocalDeploymentRoute values")
            root, identity = _validated_root(route.root, "route root", private=False)
            destination = root.joinpath(*route.relative_path.split("/"))
            parent = destination.parent
            if not parent.is_dir() or parent.is_symlink():
                raise ValueError("route destination parent must be an existing real directory")
            if destination.exists() and destination.is_symlink():
                raise ValueError("route destination must not be a symlink")
            registrations[route.target_id] = _RegisteredLocalRoute(
                spec=route,
                root=root,
                root_identity=identity,
                destination=destination,
            )
        if not registrations:
            raise ValueError("at least one local deployment route is required")
        self.state_root = state
        self._routes: Mapping[str, _RegisteredLocalRoute] = MappingProxyType(registrations)
        self.mutation_count = 0

    def _route(self, target: OperatorDeploymentTarget) -> _RegisteredLocalRoute:
        route = self._routes.get(target.id)
        if route is None:
            raise DeploymentDenied("LOCAL_ROUTE_NOT_REGISTERED")
        if target.provider != self.provider or target.environment != route.spec.environment:
            raise DeploymentDenied("LOCAL_ROUTE_BINDING_MISMATCH")
        metadata = route.root.stat()
        if (metadata.st_dev, metadata.st_ino) != route.root_identity or route.root.is_symlink():
            raise DeploymentDenied("LOCAL_ROUTE_ROOT_CHANGED")
        return route

    def _metadata_path(self, target_id: str) -> Path:
        return self.state_root / f"{sha256(target_id.encode()).hexdigest()}.json"

    def _read_metadata(self, target_id: str) -> dict[str, Any] | None:
        path = self._metadata_path(target_id)
        if not path.exists():
            return None
        descriptor: int | None = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1:
                raise DeploymentDenied("LOCAL_PROVIDER_METADATA_UNSAFE")
            raw = bytearray()
            while chunk := os.read(descriptor, 65_536):
                raw.extend(chunk)
                if len(raw) > 65_536:
                    raise DeploymentDenied("LOCAL_PROVIDER_METADATA_INVALID")
            value = json.loads(raw)
        except DeploymentDenied:
            raise
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise DeploymentDenied("LOCAL_PROVIDER_METADATA_INVALID") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not isinstance(value, dict) or value.get("target_id") != target_id:
            raise DeploymentDenied("LOCAL_PROVIDER_METADATA_INVALID")
        return value

    def _write_metadata(self, target_id: str, payload: Mapping[str, Any]) -> None:
        path = self._metadata_path(target_id)
        temporary = self.state_root / f".{path.name}.{os.getpid()}.tmp"
        data = canonical_json(payload).encode("utf-8")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            os.write(descriptor, data)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        except OSError as error:
            raise DeploymentDenied("LOCAL_PROVIDER_METADATA_WRITE_FAILED") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary.exists():
                temporary.unlink()

    @staticmethod
    def _read_file(path: Path, *, missing_ok: bool) -> bytes | None:
        descriptor: int | None = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1:
                raise DeploymentDenied("LOCAL_PROVIDER_ARTIFACT_UNSAFE")
            content = bytearray()
            while chunk := os.read(descriptor, 65_536):
                content.extend(chunk)
                if len(content) > MAX_OPERATOR_DEPLOY_BYTES:
                    raise DeploymentDenied("LOCAL_PROVIDER_ARTIFACT_TOO_LARGE")
            return bytes(content)
        except FileNotFoundError:
            if missing_ok:
                return None
            raise DeploymentDenied("LOCAL_PROVIDER_ARTIFACT_MISSING") from None
        except DeploymentDenied:
            raise
        except OSError as error:
            raise DeploymentDenied("LOCAL_PROVIDER_ARTIFACT_READ_FAILED") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _atomic_replace(path: Path, content: bytes) -> None:
        temporary = path.parent / f".{path.name}.cct-{os.getpid()}-{sha256(content).hexdigest()[:12]}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            os.write(descriptor, content)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        except OSError as error:
            raise DeploymentDenied("LOCAL_PROVIDER_WRITE_FAILED") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary.exists():
                temporary.unlink()

    def inspect(self, target: OperatorDeploymentTarget) -> ProviderDeploymentState:
        route = self._route(target)
        content = self._read_file(route.destination, missing_ok=True)
        metadata = self._read_metadata(target.id)
        artifact_sha256 = sha256(content).hexdigest() if content is not None else None
        artifact_byte_count = len(content) if content is not None else 0
        last_operation = metadata.get("last_operation_id") if metadata else None
        material = {
            "provider": self.provider,
            "target_id": target.id,
            "environment": target.environment,
            "artifact_sha256": artifact_sha256,
            "artifact_byte_count": artifact_byte_count,
            "last_operation_id": last_operation,
        }
        return ProviderDeploymentState(
            target_id=target.id,
            provider=self.provider,
            environment=target.environment,
            deployed=content is not None,
            artifact_sha256=artifact_sha256,
            artifact_byte_count=artifact_byte_count,
            deployment_id_sha256=_hash_payload(
                {"provider": self.provider, "target_id": target.id, "operation": last_operation}
            ),
            provider_receipt_sha256=_hash_payload(material),
            last_operation_id=last_operation,
        )

    def deploy(
        self,
        target: OperatorDeploymentTarget,
        command: DeploymentProviderCommand,
    ) -> None:
        route = self._route(target)
        current = self.inspect(target)
        if (
            current.last_operation_id == command.operation_id
            and current.artifact_sha256 == command.artifact_sha256
            and current.artifact_byte_count == command.artifact_byte_count
        ):
            return
        if current.state_sha256 != command.expected_before_state_sha256:
            raise DeploymentDenied("LOCAL_PROVIDER_PRESTATE_CHANGED")
        source = self._read_file(Path(command.artifact_path), missing_ok=False)
        if source is None or sha256(source).hexdigest() != command.artifact_sha256 or len(source) != command.artifact_byte_count:
            raise DeploymentDenied("LOCAL_PROVIDER_SOURCE_MISMATCH")
        before = self._read_file(route.destination, missing_ok=True)
        backup_name = f"{sha256(command.operation_id.encode()).hexdigest()}.backup"
        backup_path = self.state_root / backup_name
        if before is not None:
            existing = self._read_file(backup_path, missing_ok=True)
            if existing is None:
                self._atomic_replace(backup_path, before)
            elif existing != before:
                raise DeploymentDenied("LOCAL_PROVIDER_BACKUP_COLLISION")
        prepared = {
            "schema_version": 1,
            "target_id": target.id,
            "phase": "prepared",
            "last_operation_id": command.operation_id,
            "artifact_sha256": command.artifact_sha256,
            "artifact_byte_count": command.artifact_byte_count,
            "before_artifact_sha256": sha256(before).hexdigest() if before is not None else None,
            "before_artifact_byte_count": len(before) if before is not None else 0,
            "backup_name": backup_name if before is not None else None,
        }
        self._write_metadata(target.id, prepared)
        self._atomic_replace(route.destination, source)
        self._write_metadata(target.id, {**prepared, "phase": "deployed"})
        self.mutation_count += 1

    def rollback(
        self,
        target: OperatorDeploymentTarget,
        command: DeploymentProviderRollbackCommand,
    ) -> None:
        route = self._route(target)
        current = self.inspect(target)
        if current.last_operation_id == command.operation_id:
            return
        metadata = self._read_metadata(target.id)
        if (
            metadata is None
            or metadata.get("last_operation_id") != command.deployment_operation_id
            or current.artifact_sha256 != command.expected_deployed_artifact_sha256
        ):
            raise DeploymentDenied("LOCAL_PROVIDER_ROLLBACK_PRESTATE_CHANGED")
        backup_name = metadata.get("backup_name")
        if command.expected_before_artifact_sha256 is None:
            try:
                route.destination.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise DeploymentDenied("LOCAL_PROVIDER_ROLLBACK_FAILED") from error
        else:
            if not isinstance(backup_name, str):
                raise DeploymentDenied("LOCAL_PROVIDER_BACKUP_MISSING")
            backup = self._read_file(self.state_root / backup_name, missing_ok=False)
            if (
                backup is None
                or sha256(backup).hexdigest() != command.expected_before_artifact_sha256
                or len(backup) != command.expected_before_artifact_byte_count
            ):
                raise DeploymentDenied("LOCAL_PROVIDER_BACKUP_MISMATCH")
            self._atomic_replace(route.destination, backup)
        self._write_metadata(
            target.id,
            {
                "schema_version": 1,
                "target_id": target.id,
                "phase": "rolled_back",
                "last_operation_id": command.operation_id,
                "deployment_operation_id": command.deployment_operation_id,
                "artifact_sha256": command.expected_before_artifact_sha256,
                "artifact_byte_count": command.expected_before_artifact_byte_count,
            },
        )
        self.mutation_count += 1


@dataclass(frozen=True, slots=True)
class OperatorDeploymentPreview:
    target_id: str
    target_spec_sha256: str
    provider: str
    environment: str
    verification_request_id: str
    verification_event_id: str
    snapshot_sha256: str
    artifact_sha256: str
    artifact_byte_count: int
    before_state_sha256: str
    before_artifact_sha256: str | None
    before_artifact_byte_count: int
    preview_sha256: str


@dataclass(frozen=True, slots=True)
class OperatorDeploymentInvocation:
    ticket_id: str
    target_id: str
    verification_request_id: str
    expected_verification_event_id: str
    expected_snapshot_sha256: str
    expected_artifact_sha256: str
    expected_artifact_byte_count: int
    expected_before_state_sha256: str
    expected_preview_sha256: str
    verifier_id: str
    max_bytes: int

    @classmethod
    def from_arguments(cls, arguments: Mapping[str, Any]) -> "OperatorDeploymentInvocation":
        if not isinstance(arguments, Mapping):
            raise ValueError("deployment arguments must be an object")
        fields = {
            "execution_ticket_id",
            "target_id",
            "verification_request_id",
            "expected_verification_event_id",
            "expected_snapshot_sha256",
            "expected_artifact_sha256",
            "expected_artifact_byte_count",
            "expected_before_state_sha256",
            "expected_preview_sha256",
            "verifier_id",
            "max_bytes",
        }
        if set(arguments) != fields:
            raise ValueError("deployment arguments require exact fields")
        return cls(
            ticket_id=_identifier("execution_ticket_id", arguments["execution_ticket_id"]),
            target_id=_identifier("target_id", arguments["target_id"]),
            verification_request_id=_identifier(
                "verification_request_id", arguments["verification_request_id"]
            ),
            expected_verification_event_id=_identifier(
                "expected_verification_event_id",
                arguments["expected_verification_event_id"],
            ),
            expected_snapshot_sha256=str(
                _digest("expected_snapshot_sha256", arguments["expected_snapshot_sha256"])
            ),
            expected_artifact_sha256=str(
                _digest("expected_artifact_sha256", arguments["expected_artifact_sha256"])
            ),
            expected_artifact_byte_count=_integer(
                "expected_artifact_byte_count",
                arguments["expected_artifact_byte_count"],
                minimum=1,
                maximum=MAX_OPERATOR_DEPLOY_BYTES,
            ),
            expected_before_state_sha256=str(
                _digest("expected_before_state_sha256", arguments["expected_before_state_sha256"])
            ),
            expected_preview_sha256=str(
                _digest("expected_preview_sha256", arguments["expected_preview_sha256"])
            ),
            verifier_id=_identifier("verifier_id", arguments["verifier_id"]),
            max_bytes=_integer(
                "max_bytes",
                arguments["max_bytes"],
                minimum=1,
                maximum=MAX_OPERATOR_DEPLOY_BYTES,
            ),
        )


@dataclass(frozen=True, slots=True)
class _Artifact:
    path: Path
    digest: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class _RegisteredTarget:
    spec: OperatorDeploymentTarget
    spec_sha256: str
    driver: OperatorDeploymentDriver


class OperatorDeploymentAdapter:
    """Issue exact deployments only through consumed operator.deploy tickets."""

    def __init__(
        self,
        store: EventStore,
        *,
        workspace_root: str | Path,
        targets: Sequence[OperatorDeploymentTarget],
        verifier: HostRegisteredVerifier,
        drivers: Mapping[str, OperatorDeploymentDriver],
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        workspace, self._workspace_identity = _validated_root(
            workspace_root, "workspace_root", private=False
        )
        if not isinstance(verifier, HostRegisteredVerifier):
            raise ValueError("verifier must be HostRegisteredVerifier")
        if verifier.store.path.resolve() != store.path.resolve() or verifier.workspace_root != workspace:
            raise ValueError("verifier must share exact workspace and ledger")
        if not isinstance(drivers, Mapping):
            raise ValueError("drivers must be a mapping")
        registrations: dict[str, _RegisteredTarget] = {}
        for target in targets:
            if not isinstance(target, OperatorDeploymentTarget) or target.id in registrations:
                raise ValueError("targets must contain unique OperatorDeploymentTarget values")
            driver = drivers.get(target.driver_id)
            if driver is None or not all(
                callable(getattr(driver, name, None)) for name in ("inspect", "deploy", "rollback")
            ):
                raise ValueError("target driver must be host-registered")
            if target.verifier_id not in verifier.registered_ids:
                raise ValueError("target verifier must be registered")
            snapshot_paths = {
                str(row["relative_path"]) for row in verifier.snapshot(target.verifier_id).files
            }
            if target.artifact_relative_path not in snapshot_paths:
                raise ValueError("deployment artifact must be covered by verifier snapshot")
            registrations[target.id] = _RegisteredTarget(
                spec=target,
                spec_sha256=_hash_payload(asdict(target)),
                driver=driver,
            )
        if not 1 <= len(registrations) <= MAX_OPERATOR_DEPLOY_TARGETS:
            raise ValueError(f"targets must contain 1-{MAX_OPERATOR_DEPLOY_TARGETS} registrations")
        self.store = store
        self.workspace_root = workspace
        self.verifier = verifier
        self._targets: Mapping[str, _RegisteredTarget] = MappingProxyType(registrations)
        os.chmod(self.store.path, 0o600)
        for registration in registrations.values():
            payload = {
                "schema_version": 1,
                "authority": "host_adapter",
                "target_id": registration.spec.id,
                "driver_id": registration.spec.driver_id,
                "provider": registration.spec.provider,
                "environment": registration.spec.environment,
                "artifact_relative_path": registration.spec.artifact_relative_path,
                "verifier_id": registration.spec.verifier_id,
                "max_artifact_bytes": registration.spec.max_artifact_bytes,
                "rollback_supported": registration.spec.rollback_supported,
                "provider_configuration_persisted": False,
                "credential_values_persisted": False,
            }
            event, _created = store.append_once_result(
                "operator.deployment.target.registered",
                registration.spec.id,
                payload,
            )
            if canonical_json(event.payload) != canonical_json(payload):
                raise ValueError(f"deployment target registration changed: {registration.spec.id}")

    @property
    def registered_target_ids(self) -> frozenset[str]:
        return frozenset(self._targets)

    def outcome_verifiers(self) -> OutcomeVerifierRegistry:
        registry = OutcomeVerifierRegistry()
        registry.register(
            OPERATOR_DEPLOY_VERIFIER_ID,
            self._verify_mediated_result,
            reconcile=self._reconcile_mediated_result,
            idempotency_proof_id="operator-deployment-ticket-receipt",
        )
        return registry

    def _registration(self, target_id: str) -> _RegisteredTarget:
        registration = self._targets.get(_identifier("target_id", target_id))
        if registration is None:
            raise DeploymentDenied("TARGET_NOT_REGISTERED")
        return registration

    def _require_verification(
        self,
        registration: _RegisteredTarget,
        request_id: str,
    ) -> VerificationObservation:
        try:
            result = self.verifier.require_passed(request_id)
        except VerificationDenied as error:
            raise DeploymentDenied(error.reason_code) from error
        if (
            result.verifier_id != registration.spec.verifier_id
            or not result.deployment_eligible
        ):
            raise DeploymentDenied("VERIFICATION_BINDING_MISMATCH")
        return result

    def _artifact(self, target: OperatorDeploymentTarget) -> _Artifact:
        current = self.workspace_root
        parts = target.artifact_relative_path.split("/")
        for part in parts[:-1]:
            current = current / part
            metadata = current.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise DeploymentDenied("ARTIFACT_PATH_INVALID")
        path = current / parts[-1]
        descriptor: int | None = None
        content = bytearray()
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                raise DeploymentDenied("ARTIFACT_UNSAFE")
            while chunk := os.read(descriptor, 65_536):
                content.extend(chunk)
                if len(content) > target.max_artifact_bytes:
                    raise DeploymentDenied("ARTIFACT_TOO_LARGE")
        except DeploymentDenied:
            raise
        except OSError as error:
            raise DeploymentDenied("ARTIFACT_READ_FAILED") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not content:
            raise DeploymentDenied("ARTIFACT_EMPTY")
        return _Artifact(path=path, digest=sha256(content).hexdigest(), byte_count=len(content))

    @staticmethod
    def _inspect(registration: _RegisteredTarget) -> ProviderDeploymentState:
        state = registration.driver.inspect(registration.spec)
        if not isinstance(state, ProviderDeploymentState):
            raise DeploymentDenied("PROVIDER_READBACK_MALFORMED")
        if (
            state.target_id != registration.spec.id
            or state.provider != registration.spec.provider
            or state.environment != registration.spec.environment
        ):
            raise DeploymentDenied("PROVIDER_READBACK_TARGET_MISMATCH")
        return state

    def preview(
        self,
        *,
        target_id: str,
        verification_request_id: str,
    ) -> OperatorDeploymentPreview:
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise DeploymentDenied(error.reason_code) from error
        if self.store.verify_chain().get("valid") is not True:
            raise DeploymentDenied("LEDGER_CHAIN_INVALID")
        registration = self._registration(target_id)
        verification = self._require_verification(registration, verification_request_id)
        artifact = self._artifact(registration.spec)
        before = self._inspect(registration)
        material = {
            "schema_version": 1,
            "target_id": registration.spec.id,
            "target_spec_sha256": registration.spec_sha256,
            "provider": registration.spec.provider,
            "environment": registration.spec.environment,
            "verification_request_id": verification.request_id,
            "verification_event_id": verification.terminal_event_id,
            "snapshot_sha256": verification.snapshot_after_sha256,
            "artifact_sha256": artifact.digest,
            "artifact_byte_count": artifact.byte_count,
            "before_state_sha256": before.state_sha256,
            "before_artifact_sha256": before.artifact_sha256,
            "before_artifact_byte_count": before.artifact_byte_count,
            "rollback_supported": registration.spec.rollback_supported,
            "credential_handles": [],
        }
        return OperatorDeploymentPreview(
            target_id=registration.spec.id,
            target_spec_sha256=registration.spec_sha256,
            provider=registration.spec.provider,
            environment=registration.spec.environment,
            verification_request_id=verification.request_id,
            verification_event_id=verification.terminal_event_id,
            snapshot_sha256=verification.snapshot_after_sha256,
            artifact_sha256=artifact.digest,
            artifact_byte_count=artifact.byte_count,
            before_state_sha256=before.state_sha256,
            before_artifact_sha256=before.artifact_sha256,
            before_artifact_byte_count=before.artifact_byte_count,
            preview_sha256=_hash_payload(material),
        )

    @staticmethod
    def _validate_preview(
        request: OperatorDeploymentInvocation,
        preview: OperatorDeploymentPreview,
    ) -> None:
        if (
            request.target_id != preview.target_id
            or request.verification_request_id != preview.verification_request_id
            or request.expected_verification_event_id != preview.verification_event_id
            or request.expected_snapshot_sha256 != preview.snapshot_sha256
            or request.expected_artifact_sha256 != preview.artifact_sha256
            or request.expected_artifact_byte_count != preview.artifact_byte_count
            or request.expected_before_state_sha256 != preview.before_state_sha256
            or request.expected_preview_sha256 != preview.preview_sha256
        ):
            raise DeploymentDenied("DEPLOYMENT_PREVIEW_STALE")

    def execute(self, arguments: Mapping[str, Any]) -> str:
        request = OperatorDeploymentInvocation.from_arguments(arguments)
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise DeploymentDenied(error.reason_code) from error
        self._require_dispatch_claim(request, arguments)
        registration = self._registration(request.target_id)
        if request.verifier_id != registration.spec.verifier_id:
            raise DeploymentDenied("TARGET_VERIFIER_MISMATCH")
        if request.max_bytes > registration.spec.max_artifact_bytes:
            raise DeploymentDenied("TARGET_BYTE_BUDGET_EXCEEDED")
        completion = self._completion(request.ticket_id)
        if completion is not None:
            return self._response(completion, replayed=True)
        existing_claim = self._claim(request.ticket_id)
        if existing_claim is not None:
            self._validate_claim(existing_claim, request, registration)
            readback = self._inspect(registration)
            if self._matches_deployed(readback, request):
                return self._record_completion(
                    existing_claim,
                    request,
                    registration,
                    readback,
                    recovered_after_provider_crash=True,
                )
            raise DeploymentDenied("EXECUTION_STATE_UNCERTAIN")

        preview = self.preview(
            target_id=request.target_id,
            verification_request_id=request.verification_request_id,
        )
        self._validate_preview(request, preview)
        artifact = self._artifact(registration.spec)
        claim_payload = self._claim_payload(request, registration, preview)
        claim, created = self.store.append_once_result(
            "operator.deployment.claimed", request.ticket_id, claim_payload
        )
        if not created:
            self._validate_claim(claim, request, registration)
            readback = self._inspect(registration)
            if self._matches_deployed(readback, request):
                return self._record_completion(
                    claim,
                    request,
                    registration,
                    readback,
                    recovered_after_provider_crash=True,
                )
            raise DeploymentDenied("EXECUTION_STATE_UNCERTAIN")

        effect_id = str(claim.payload["effect_id"])
        try:
            GlobalKillSwitch(self.store).checkpoint(
                checkpoint_id=f"deploy-pre-{sha256(request.ticket_id.encode()).hexdigest()[:24]}",
                effect_id=effect_id,
                step="pre-provider",
            )
        except TicketAuthorityDenied as error:
            raise DeploymentDenied(error.reason_code) from error
        registration.driver.deploy(
            registration.spec,
            DeploymentProviderCommand(
                operation_id=request.ticket_id,
                target_id=request.target_id,
                provider=registration.spec.provider,
                environment=registration.spec.environment,
                artifact_path=str(artifact.path),
                artifact_sha256=request.expected_artifact_sha256,
                artifact_byte_count=request.expected_artifact_byte_count,
                expected_before_state_sha256=request.expected_before_state_sha256,
                preview_sha256=request.expected_preview_sha256,
                credential_handles=(),
            ),
        )
        try:
            GlobalKillSwitch(self.store).checkpoint(
                checkpoint_id=f"deploy-readback-{sha256(request.ticket_id.encode()).hexdigest()[:24]}",
                effect_id=effect_id,
                step="provider-readback",
            )
        except TicketAuthorityDenied as error:
            self._rollback_after_failure(request, registration, "kill-switch")
            raise DeploymentDenied(error.reason_code) from error
        readback = self._inspect(registration)
        if not self._matches_deployed(readback, request):
            self._rollback_after_failure(request, registration, "readback-mismatch")
            raise DeploymentDenied("PROVIDER_READBACK_MISMATCH")
        return self._record_completion(
            claim,
            request,
            registration,
            readback,
            recovered_after_provider_crash=False,
        )

    @staticmethod
    def _matches_deployed(
        readback: ProviderDeploymentState,
        request: OperatorDeploymentInvocation,
    ) -> bool:
        return (
            readback.deployed
            and readback.artifact_sha256 == request.expected_artifact_sha256
            and readback.artifact_byte_count == request.expected_artifact_byte_count
            and readback.last_operation_id == request.ticket_id
        )

    @staticmethod
    def _claim_payload(
        request: OperatorDeploymentInvocation,
        registration: _RegisteredTarget,
        preview: OperatorDeploymentPreview,
    ) -> dict[str, Any]:
        return {
            "schema_version": OPERATOR_DEPLOY_CLAIM_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "target_id": request.target_id,
            "target_spec_sha256": registration.spec_sha256,
            "driver_id": registration.spec.driver_id,
            "provider": registration.spec.provider,
            "environment": registration.spec.environment,
            "verification_request_id": request.verification_request_id,
            "verification_event_id": request.expected_verification_event_id,
            "snapshot_sha256": request.expected_snapshot_sha256,
            "artifact_sha256": request.expected_artifact_sha256,
            "artifact_byte_count": request.expected_artifact_byte_count,
            "before_state_sha256": request.expected_before_state_sha256,
            "before_artifact_sha256": preview.before_artifact_sha256,
            "before_artifact_byte_count": preview.before_artifact_byte_count,
            "preview_sha256": request.expected_preview_sha256,
            "verifier_id": request.verifier_id,
            "max_bytes": request.max_bytes,
            "rollback_supported": registration.spec.rollback_supported,
            "effect_id": f"deploy-{sha256(request.ticket_id.encode()).hexdigest()[:24]}",
            "provider_configuration_persisted": False,
            "artifact_content_persisted": False,
            "credential_handles": [],
            "credential_values_persisted": False,
        }

    def _validate_claim(
        self,
        claim: Event,
        request: OperatorDeploymentInvocation,
        registration: _RegisteredTarget,
    ) -> None:
        payload = claim.payload
        expected = {
            "ticket_id": request.ticket_id,
            "target_id": request.target_id,
            "target_spec_sha256": registration.spec_sha256,
            "provider": registration.spec.provider,
            "environment": registration.spec.environment,
            "verification_request_id": request.verification_request_id,
            "verification_event_id": request.expected_verification_event_id,
            "snapshot_sha256": request.expected_snapshot_sha256,
            "artifact_sha256": request.expected_artifact_sha256,
            "artifact_byte_count": request.expected_artifact_byte_count,
            "before_state_sha256": request.expected_before_state_sha256,
            "preview_sha256": request.expected_preview_sha256,
            "verifier_id": request.verifier_id,
            "max_bytes": request.max_bytes,
        }
        if any(payload.get(key) != value for key, value in expected.items()):
            raise DeploymentDenied("DEPLOYMENT_CLAIM_COLLISION")

    def _record_completion(
        self,
        claim: Event,
        request: OperatorDeploymentInvocation,
        registration: _RegisteredTarget,
        readback: ProviderDeploymentState,
        *,
        recovered_after_provider_crash: bool,
    ) -> str:
        payload = {
            "schema_version": OPERATOR_DEPLOY_RECEIPT_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "claim_event_id": claim.event_id,
            "effect_id": claim.payload["effect_id"],
            "target_id": request.target_id,
            "target_spec_sha256": registration.spec_sha256,
            "driver_id": registration.spec.driver_id,
            "provider": registration.spec.provider,
            "environment": registration.spec.environment,
            "artifact_sha256": request.expected_artifact_sha256,
            "artifact_byte_count": request.expected_artifact_byte_count,
            "before_state_sha256": request.expected_before_state_sha256,
            "preview_sha256": request.expected_preview_sha256,
            "verification_event_id": request.expected_verification_event_id,
            "verifier_id": request.verifier_id,
            "provider_deployment_id_sha256": readback.deployment_id_sha256,
            "provider_receipt_sha256": readback.provider_receipt_sha256,
            "provider_readback_verified": True,
            "provider_effect_count": 1,
            "rollback_supported": registration.spec.rollback_supported,
            "status": "deployed",
            "verification_passed": True,
            "recovered_after_provider_crash": recovered_after_provider_crash,
            "artifact_content_persisted": False,
            "provider_raw_response_persisted": False,
            "provider_configuration_persisted": False,
            "credential_handles": [],
            "credential_values_persisted": False,
        }
        event, created = self.store.append_once_result(
            "operator.deployment.completed", request.ticket_id, payload
        )
        if not created and canonical_json(event.payload) != canonical_json(payload):
            existing = event.payload
            if not (
                existing.get("ticket_id") == request.ticket_id
                and existing.get("verification_passed") is True
                and existing.get("artifact_sha256") == request.expected_artifact_sha256
            ):
                raise DeploymentDenied("COMPLETION_RECEIPT_COLLISION")
        return self._response(event, replayed=not created)

    def rollback(
        self,
        *,
        deployment_ticket_id: str,
        rollback_id: str,
    ) -> dict[str, Any]:
        ticket_id = _identifier("deployment_ticket_id", deployment_ticket_id)
        rollback_identifier = _identifier("rollback_id", rollback_id)
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise DeploymentDenied(error.reason_code) from error
        existing_rows = [
            event
            for event in self.store.events("operator.deployment.rollback.completed")
            if event.payload.get("rollback_id") == rollback_identifier
        ]
        if len(existing_rows) > 1:
            raise DeploymentDenied("DUPLICATE_ROLLBACK_RECEIPTS")
        if existing_rows:
            return dict(existing_rows[0].payload)
        completion = self._completion(ticket_id)
        if completion is None or completion.payload.get("verification_passed") is not True:
            raise DeploymentDenied("DEPLOYMENT_NOT_VERIFIED")
        target_id = str(completion.payload["target_id"])
        registration = self._registration(target_id)
        if not registration.spec.rollback_supported:
            raise DeploymentDenied("ROLLBACK_NOT_SUPPORTED")
        claim = self._claim(ticket_id)
        if claim is None:
            raise DeploymentDenied("DEPLOYMENT_CLAIM_MISSING")
        before_sha = claim.payload.get("before_artifact_sha256")
        before_count = int(claim.payload.get("before_artifact_byte_count", 0))
        registration.driver.rollback(
            registration.spec,
            DeploymentProviderRollbackCommand(
                operation_id=rollback_identifier,
                deployment_operation_id=ticket_id,
                target_id=target_id,
                provider=registration.spec.provider,
                environment=registration.spec.environment,
                expected_deployed_artifact_sha256=str(completion.payload["artifact_sha256"]),
                expected_before_artifact_sha256=(str(before_sha) if before_sha is not None else None),
                expected_before_artifact_byte_count=before_count,
                credential_handles=(),
            ),
        )
        readback = self._inspect(registration)
        verified = (
            readback.last_operation_id == rollback_identifier
            and readback.artifact_sha256 == before_sha
            and readback.artifact_byte_count == before_count
        )
        if not verified:
            raise DeploymentDenied("ROLLBACK_READBACK_MISMATCH")
        payload = {
            "schema_version": 1,
            "rollback_id": rollback_identifier,
            "deployment_ticket_id": ticket_id,
            "target_id": target_id,
            "provider": registration.spec.provider,
            "environment": registration.spec.environment,
            "status": "rolled_back",
            "provider_readback_verified": True,
            "provider_receipt_sha256": readback.provider_receipt_sha256,
            "current_artifact_sha256": readback.artifact_sha256,
            "current_artifact_byte_count": readback.artifact_byte_count,
            "provider_effect_count": 1,
            "credential_handles": [],
            "credential_values_persisted": False,
        }
        event, _created = self.store.append_once_result(
            "operator.deployment.rollback.completed", rollback_identifier, payload
        )
        if canonical_json(event.payload) != canonical_json(payload):
            raise DeploymentDenied("ROLLBACK_RECEIPT_COLLISION")
        return dict(event.payload)

    def _rollback_after_failure(
        self,
        request: OperatorDeploymentInvocation,
        registration: _RegisteredTarget,
        reason: str,
    ) -> None:
        if not registration.spec.rollback_supported:
            return
        claim = self._claim(request.ticket_id)
        if claim is None:
            return
        before_sha = claim.payload.get("before_artifact_sha256")
        before_count = int(claim.payload.get("before_artifact_byte_count", 0))
        rollback_id = f"auto-{sha256(f'{request.ticket_id}:{reason}'.encode()).hexdigest()[:24]}"
        registration.driver.rollback(
            registration.spec,
            DeploymentProviderRollbackCommand(
                operation_id=rollback_id,
                deployment_operation_id=request.ticket_id,
                target_id=request.target_id,
                provider=registration.spec.provider,
                environment=registration.spec.environment,
                expected_deployed_artifact_sha256=request.expected_artifact_sha256,
                expected_before_artifact_sha256=(str(before_sha) if before_sha is not None else None),
                expected_before_artifact_byte_count=before_count,
                credential_handles=(),
            ),
        )

    def _require_dispatch_claim(
        self,
        request: OperatorDeploymentInvocation,
        arguments: Mapping[str, Any],
    ) -> None:
        arguments_sha256 = sha256(canonical_json(arguments).encode()).hexdigest()
        rows = [
            event
            for event in self.store.events("execution.ticket.consumed")
            if event.payload.get("ticket_id") == request.ticket_id
        ]
        if len(rows) != 1:
            raise DeploymentDenied("TICKET_DISPATCH_CLAIM_REQUIRED")
        payload = rows[0].payload
        if (
            payload.get("dispatch_claimed") is not True
            or payload.get("ticket_consumed") is not True
            or payload.get("tool_name") != "operator_deploy"
            or payload.get("arguments_sha256") != arguments_sha256
            or payload.get("capability") != "operator.deploy"
            or payload.get("scope") != f"operator/deploy/{request.target_id}"
            or payload.get("verifier_id") != OPERATOR_DEPLOY_VERIFIER_ID
            or payload.get("idempotency_key") != request.ticket_id
            or isinstance(payload.get("byte_budget"), bool)
            or not isinstance(payload.get("byte_budget"), int)
            or payload["byte_budget"] < request.max_bytes
        ):
            raise DeploymentDenied("TICKET_DISPATCH_CLAIM_MISMATCH")

    def _claim(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.deployment.claimed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise DeploymentDenied("DUPLICATE_DEPLOYMENT_CLAIMS")
        return rows[0] if rows else None

    def _completion(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.deployment.completed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise DeploymentDenied("DUPLICATE_DEPLOYMENT_RECEIPTS")
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
                "deployment": {
                    "target_id": payload.get("target_id"),
                    "provider": payload.get("provider"),
                    "environment": payload.get("environment"),
                    "artifact_sha256": payload.get("artifact_sha256"),
                    "artifact_byte_count": payload.get("artifact_byte_count"),
                    "provider_deployment_id_sha256": payload.get(
                        "provider_deployment_id_sha256"
                    ),
                    "provider_receipt_sha256": payload.get("provider_receipt_sha256"),
                    "provider_readback_verified": payload.get(
                        "provider_readback_verified"
                    ),
                    "provider_effect_count": payload.get("provider_effect_count"),
                    "rollback_supported": payload.get("rollback_supported"),
                    "recovered_after_provider_crash": payload.get(
                        "recovered_after_provider_crash"
                    ),
                    "credential_handles_used": [],
                    "artifact_content_persisted": False,
                    "provider_raw_response_persisted": False,
                    "replayed": replayed,
                },
                "verification": {
                    "passed": payload.get("verification_passed") is True,
                    "verifier_id": OPERATOR_DEPLOY_VERIFIER_ID,
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
        if not isinstance(value, dict) or context.verifier_id != OPERATOR_DEPLOY_VERIFIER_ID:
            return malformed
        effect = value.get("effect")
        deployment = value.get("deployment")
        verification = value.get("verification")
        if not all(isinstance(row, dict) for row in (effect, deployment, verification)):
            return malformed
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            return OutcomeVerification(
                verified=False, effect_observed=False, status="receipt-missing"
            )
        payload = receipt.payload
        assert isinstance(effect, dict)
        assert isinstance(deployment, dict)
        assert isinstance(verification, dict)
        matched = (
            value.get("success") is True
            and payload.get("verification_passed") is True
            and effect.get("effect_id") == payload.get("effect_id")
            and effect.get("idempotency_key") == context.idempotency_key
            and effect.get("receipt_event_id") == receipt.event_id
            and deployment.get("target_id") == payload.get("target_id")
            and deployment.get("provider") == payload.get("provider")
            and deployment.get("environment") == payload.get("environment")
            and deployment.get("artifact_sha256") == payload.get("artifact_sha256")
            and deployment.get("provider_receipt_sha256")
            == payload.get("provider_receipt_sha256")
            and deployment.get("provider_readback_verified") is True
            and deployment.get("credential_handles_used") == []
            and deployment.get("artifact_content_persisted") is False
            and verification.get("passed") is True
            and verification.get("verifier_id") == OPERATOR_DEPLOY_VERIFIER_ID
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
            readback = self._inspect(registration)
            if not self._matches_deployed(readback, request):
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
    def _request_from_claim(claim: Event) -> OperatorDeploymentInvocation:
        payload = claim.payload
        return OperatorDeploymentInvocation(
            ticket_id=str(payload["ticket_id"]),
            target_id=str(payload["target_id"]),
            verification_request_id=str(payload["verification_request_id"]),
            expected_verification_event_id=str(payload["verification_event_id"]),
            expected_snapshot_sha256=str(payload["snapshot_sha256"]),
            expected_artifact_sha256=str(payload["artifact_sha256"]),
            expected_artifact_byte_count=int(payload["artifact_byte_count"]),
            expected_before_state_sha256=str(payload["before_state_sha256"]),
            expected_preview_sha256=str(payload["preview_sha256"]),
            verifier_id=str(payload["verifier_id"]),
            max_bytes=int(payload["max_bytes"]),
        )
