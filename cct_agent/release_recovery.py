"""Autonomous exact-release recovery from authenticated artifact mismatches.

Choice remains inside the CCT kernel. Authority and mechanics remain host supplied:
an authenticated mismatch receipt binds exact bytes, standing authority binds one
Generalist2 service, typed tickets bind each reversible effect, and the adapter
provides independent readback. Durable step receipts make post-effect retries and
concurrent restarts adopt completed work instead of repeating it.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Iterator, Protocol

from .execution_tickets import GlobalKillSwitch, TicketAuthorityDenied
from .kernel import AgencyKernel
from .models import Option
from .store import Event, EventStore, canonical_json


GENERALIST2_PROFILE = "generalist2"
GENERALIST2_SERVICE = "hermes-gateway-generalist2.service"
FULL_RECOVERY_OPTION_ID = "rollback-exact-rebuild-redeploy"
REQUIRED_RELEASE_OPERATIONS = (
    "rollback",
    "exact-rebuild",
    "isolated-verification",
    "generalist2-redeploy",
    "live-verification",
)
RELEASE_RECOVERY_CLAIM_VERSION = "cct.release-recovery.claim.v1"
RELEASE_RECOVERY_RECEIPT_VERSION = "cct.release-recovery.receipt.v1"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class ReleaseRecoveryDenied(PermissionError):
    """Fail-closed release-recovery rejection with stable reason code."""

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


def _commit(name: str, value: object) -> str:
    if not isinstance(value, str) or not _COMMIT.fullmatch(value):
        raise ValueError(f"{name} must be a full lowercase Git commit")
    return value


def _version(name: str, value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value != value.strip()
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise ValueError(f"{name} must be a bounded exact printable version")
    return value


def _module_root(name: str, value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or len(value.encode("utf-8")) > 4096
        or "\x00" in value
        or value != value.strip()
    ):
        raise ValueError(f"{name} must be an exact absolute module root")
    return value


def _positive_integer(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _count(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _timestamp(name: str, value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be ISO-8601")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{name} must be ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed


def _hash(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _private_root(raw: str | Path) -> tuple[Path, tuple[int, int]]:
    root = Path(raw)
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
    return resolved, (metadata.st_dev, metadata.st_ino)


@dataclass(frozen=True, slots=True)
class ReleaseRuntimeState:
    profile_name: str
    service_name: str
    pid: int
    version: str
    module_root: str
    wheel_sha256: str
    source_commit: str
    chain_valid: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "profile_name", _identifier("profile_name", self.profile_name))
        object.__setattr__(self, "service_name", _identifier("service_name", self.service_name))
        _positive_integer("pid", self.pid)
        object.__setattr__(self, "version", _version("version", self.version))
        object.__setattr__(self, "module_root", _module_root("module_root", self.module_root))
        object.__setattr__(
            self, "wheel_sha256", _digest("wheel_sha256", self.wheel_sha256)
        )
        object.__setattr__(
            self, "source_commit", _commit("source_commit", self.source_commit)
        )
        if not isinstance(self.chain_valid, bool):
            raise ValueError("chain_valid must be a boolean")

    @property
    def state_sha256(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True, slots=True)
class ReleaseArtifact:
    recovery_id: str
    source_commit: str
    version: str
    wheel_sha256: str
    byte_count: int
    wheel_source_exact: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "recovery_id", _identifier("recovery_id", self.recovery_id))
        object.__setattr__(
            self, "source_commit", _commit("source_commit", self.source_commit)
        )
        object.__setattr__(self, "version", _version("version", self.version))
        object.__setattr__(
            self, "wheel_sha256", _digest("wheel_sha256", self.wheel_sha256)
        )
        _positive_integer("byte_count", self.byte_count)
        if not isinstance(self.wheel_source_exact, bool):
            raise ValueError("wheel_source_exact must be a boolean")


@dataclass(frozen=True, slots=True)
class IsolatedReleaseVerification:
    recovery_id: str
    source_commit: str
    version: str
    module_root: str
    wheel_sha256: str
    wheel_source_exact: bool
    tools: int
    hooks: int
    middleware: int
    passed: bool
    receipt_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "recovery_id", _identifier("recovery_id", self.recovery_id))
        object.__setattr__(
            self, "source_commit", _commit("source_commit", self.source_commit)
        )
        object.__setattr__(self, "version", _version("version", self.version))
        object.__setattr__(self, "module_root", _module_root("module_root", self.module_root))
        object.__setattr__(
            self, "wheel_sha256", _digest("wheel_sha256", self.wheel_sha256)
        )
        for name in ("tools", "hooks", "middleware"):
            _count(name, getattr(self, name))
        if not isinstance(self.wheel_source_exact, bool) or not isinstance(self.passed, bool):
            raise ValueError("verification booleans are invalid")
        object.__setattr__(
            self, "receipt_sha256", _digest("receipt_sha256", self.receipt_sha256)
        )


@dataclass(frozen=True, slots=True)
class AuthenticatedReleaseAuthority:
    """Standing host/operator authority; model prose cannot construct permission."""

    id: str
    authority: str
    authenticated: bool
    principal_id: str
    goal_id: str
    profile_name: str
    service_name: str
    operations: tuple[str, ...]
    reversible: bool
    authority_receipt_sha256: str
    expires_at: str

    def __post_init__(self) -> None:
        for name in ("id", "principal_id", "goal_id", "profile_name", "service_name"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        if self.authority not in {"operator", "host_adapter"}:
            raise ValueError("release authority must be operator or host_adapter")
        if not isinstance(self.authenticated, bool) or not isinstance(self.reversible, bool):
            raise ValueError("release authority booleans are invalid")
        if not isinstance(self.operations, (tuple, list)):
            raise ValueError("release operations must be an array")
        operations = tuple(_identifier("release operation", item) for item in self.operations)
        if len(operations) != len(set(operations)):
            raise ValueError("release operations must be unique")
        object.__setattr__(self, "operations", operations)
        object.__setattr__(
            self,
            "authority_receipt_sha256",
            _digest("authority_receipt_sha256", self.authority_receipt_sha256),
        )
        _timestamp("expires_at", self.expires_at)


@dataclass(frozen=True, slots=True)
class AuthenticatedArtifactMismatchReceipt:
    """Exact host observation proving currently loaded bytes differ from target bytes."""

    id: str
    authority: str
    authenticated: bool
    principal_id: str
    goal_id: str
    profile_name: str
    service_name: str
    observed_pid: int
    observed_version: str
    observed_module_root: str
    observed_wheel_sha256: str
    observed_source_commit: str
    expected_version: str
    expected_module_root: str
    expected_wheel_sha256: str
    expected_source_commit: str
    rollback_version: str
    rollback_module_root: str
    rollback_wheel_sha256: str
    rollback_source_commit: str
    chain_valid: bool
    evidence_sha256: str
    authority_receipt_sha256: str
    expires_at: str

    def __post_init__(self) -> None:
        for name in ("id", "principal_id", "goal_id", "profile_name", "service_name"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        if self.authority not in {"operator", "host_adapter"}:
            raise ValueError("mismatch receipt authority is invalid")
        if not isinstance(self.authenticated, bool) or not isinstance(self.chain_valid, bool):
            raise ValueError("mismatch receipt booleans are invalid")
        _positive_integer("observed_pid", self.observed_pid)
        for name in ("observed_version", "expected_version", "rollback_version"):
            object.__setattr__(self, name, _version(name, getattr(self, name)))
        for name in ("observed_module_root", "expected_module_root", "rollback_module_root"):
            object.__setattr__(self, name, _module_root(name, getattr(self, name)))
        for name in (
            "observed_wheel_sha256",
            "expected_wheel_sha256",
            "rollback_wheel_sha256",
            "evidence_sha256",
            "authority_receipt_sha256",
        ):
            object.__setattr__(self, name, _digest(name, getattr(self, name)))
        for name in (
            "observed_source_commit",
            "expected_source_commit",
            "rollback_source_commit",
        ):
            object.__setattr__(self, name, _commit(name, getattr(self, name)))
        _timestamp("expires_at", self.expires_at)
        if (
            self.observed_version == self.expected_version
            and self.observed_module_root == self.expected_module_root
            and self.observed_wheel_sha256 == self.expected_wheel_sha256
            and self.observed_source_commit == self.expected_source_commit
        ):
            raise ValueError("receipt must prove an artifact mismatch")


@dataclass(frozen=True, slots=True)
class ReleaseRollbackTicket:
    recovery_id: str
    authority_id: str
    mismatch_receipt_sha256: str
    profile_name: str
    service_name: str
    expected_observed_state_sha256: str
    rollback_version: str
    rollback_module_root: str
    rollback_wheel_sha256: str
    rollback_source_commit: str
    restore_state_database: bool = False

    def __post_init__(self) -> None:
        for name in ("recovery_id", "authority_id", "profile_name", "service_name"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        for name in ("mismatch_receipt_sha256", "expected_observed_state_sha256", "rollback_wheel_sha256"):
            object.__setattr__(self, name, _digest(name, getattr(self, name)))
        object.__setattr__(
            self, "rollback_version", _version("rollback_version", self.rollback_version)
        )
        object.__setattr__(
            self,
            "rollback_module_root",
            _module_root("rollback_module_root", self.rollback_module_root),
        )
        object.__setattr__(
            self,
            "rollback_source_commit",
            _commit("rollback_source_commit", self.rollback_source_commit),
        )
        if self.restore_state_database is not False:
            raise ValueError("release rollback cannot restore the state database")
        if (
            self.profile_name != GENERALIST2_PROFILE
            or self.service_name != GENERALIST2_SERVICE
        ):
            raise ValueError("release rollback target must be exact Generalist2 service")


@dataclass(frozen=True, slots=True)
class ExactRebuildTicket:
    recovery_id: str
    authority_id: str
    mismatch_receipt_sha256: str
    source_commit: str
    version: str
    expected_wheel_sha256: str

    def __post_init__(self) -> None:
        for name in ("recovery_id", "authority_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(
            self,
            "mismatch_receipt_sha256",
            _digest("mismatch_receipt_sha256", self.mismatch_receipt_sha256),
        )
        object.__setattr__(self, "source_commit", _commit("source_commit", self.source_commit))
        object.__setattr__(self, "version", _version("version", self.version))
        object.__setattr__(
            self,
            "expected_wheel_sha256",
            _digest("expected_wheel_sha256", self.expected_wheel_sha256),
        )


@dataclass(frozen=True, slots=True)
class IsolatedVerificationTicket:
    recovery_id: str
    authority_id: str
    source_commit: str
    version: str
    wheel_sha256: str
    expected_module_root: str

    def __post_init__(self) -> None:
        for name in ("recovery_id", "authority_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(self, "source_commit", _commit("source_commit", self.source_commit))
        object.__setattr__(self, "version", _version("version", self.version))
        object.__setattr__(self, "wheel_sha256", _digest("wheel_sha256", self.wheel_sha256))
        object.__setattr__(
            self,
            "expected_module_root",
            _module_root("expected_module_root", self.expected_module_root),
        )


@dataclass(frozen=True, slots=True)
class Generalist2RedeployTicket:
    recovery_id: str
    authority_id: str
    profile_name: str
    service_name: str
    source_commit: str
    version: str
    module_root: str
    wheel_sha256: str
    verification_receipt_sha256: str
    previous_pid: int
    restore_state_database: bool = False

    def __post_init__(self) -> None:
        for name in ("recovery_id", "authority_id", "profile_name", "service_name"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        object.__setattr__(self, "source_commit", _commit("source_commit", self.source_commit))
        object.__setattr__(self, "version", _version("version", self.version))
        object.__setattr__(self, "module_root", _module_root("module_root", self.module_root))
        for name in ("wheel_sha256", "verification_receipt_sha256"):
            object.__setattr__(self, name, _digest(name, getattr(self, name)))
        _positive_integer("previous_pid", self.previous_pid)
        if self.restore_state_database is not False:
            raise ValueError("release redeploy cannot restore the state database")
        if (
            self.profile_name != GENERALIST2_PROFILE
            or self.service_name != GENERALIST2_SERVICE
        ):
            raise ValueError("release redeploy target must be exact Generalist2 service")


class ReleaseRecoveryAdapter(Protocol):
    """Host-owned mechanics. Implementations must make each recovery ID idempotent."""

    def inspect_runtime(self) -> ReleaseRuntimeState: ...

    def inspect_artifact(self, recovery_id: str) -> ReleaseArtifact | None: ...

    def inspect_verification(
        self, recovery_id: str
    ) -> IsolatedReleaseVerification | None: ...

    def rollback(self, ticket: ReleaseRollbackTicket) -> ReleaseRuntimeState: ...

    def rebuild_exact(self, ticket: ExactRebuildTicket) -> ReleaseArtifact: ...

    def verify_isolated(
        self,
        ticket: IsolatedVerificationTicket,
        artifact: ReleaseArtifact,
    ) -> IsolatedReleaseVerification: ...

    def redeploy(
        self,
        ticket: Generalist2RedeployTicket,
        artifact: ReleaseArtifact,
        verification: IsolatedReleaseVerification,
    ) -> ReleaseRuntimeState: ...


class ReleaseRecoveryBridge:
    """Choose and execute one restart-safe Generalist2 release recovery."""

    def __init__(
        self,
        store: EventStore,
        *,
        kernel: AgencyKernel,
        adapter: ReleaseRecoveryAdapter,
        state_root: str | Path,
    ) -> None:
        if not isinstance(store, EventStore) or not isinstance(kernel, AgencyKernel):
            raise ValueError("release bridge requires EventStore and AgencyKernel")
        if kernel.store.path.resolve() != store.path.resolve():
            raise ValueError("release bridge kernel must share the exact ledger")
        required = (
            "inspect_runtime",
            "inspect_artifact",
            "inspect_verification",
            "rollback",
            "rebuild_exact",
            "verify_isolated",
            "redeploy",
        )
        if not all(callable(getattr(adapter, name, None)) for name in required):
            raise ValueError("release adapter does not implement the typed contract")
        self.store = store
        self.kernel = kernel
        self.adapter = adapter
        self.state_root, self._state_identity = _private_root(state_root)
        self._lock_path = self.state_root / ".release-recovery.lock"
        descriptor = os.open(
            self._lock_path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        os.chmod(self.store.path, 0o600)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        descriptor = os.open(
            self._lock_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            metadata = self.state_root.stat()
            if (
                self.state_root.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or (metadata.st_dev, metadata.st_ino) != self._state_identity
            ):
                raise ReleaseRecoveryDenied("RELEASE_RECOVERY_STATE_ROOT_CHANGED")
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _receipt_sha256(receipt: AuthenticatedArtifactMismatchReceipt) -> str:
        return _hash(asdict(receipt))

    @staticmethod
    def _authority_sha256(authority: AuthenticatedReleaseAuthority) -> str:
        return _hash(asdict(authority))

    def _ensure_clear(self) -> None:
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise ReleaseRecoveryDenied(error.reason_code) from error

    def _validate_authority(
        self,
        receipt: AuthenticatedArtifactMismatchReceipt,
        authority: AuthenticatedReleaseAuthority,
    ) -> None:
        if not authority.authenticated:
            raise ReleaseRecoveryDenied("RELEASE_AUTHORITY_NOT_AUTHENTICATED")
        if not receipt.authenticated:
            raise ReleaseRecoveryDenied("ARTIFACT_MISMATCH_NOT_AUTHENTICATED")
        if not authority.reversible:
            raise ReleaseRecoveryDenied("RELEASE_AUTHORITY_NOT_REVERSIBLE")
        if authority.operations != REQUIRED_RELEASE_OPERATIONS:
            raise ReleaseRecoveryDenied("RELEASE_AUTHORITY_OPERATIONS_MISMATCH")
        if (
            authority.profile_name != GENERALIST2_PROFILE
            or authority.service_name != GENERALIST2_SERVICE
            or receipt.profile_name != GENERALIST2_PROFILE
            or receipt.service_name != GENERALIST2_SERVICE
        ):
            raise ReleaseRecoveryDenied("RELEASE_TARGET_NOT_GENERALIST2")
        if (
            receipt.principal_id != authority.principal_id
            or receipt.goal_id != authority.goal_id
            or receipt.authority_receipt_sha256
            != authority.authority_receipt_sha256
        ):
            raise ReleaseRecoveryDenied("RELEASE_AUTHORITY_BINDING_MISMATCH")
        authority_sha256 = self._authority_sha256(authority)
        authority_rows = [
            event
            for event in self.store.events("release.recovery.authority.installed")
            if event.payload.get("authority_id") == authority.id
        ]
        expected_authority_registration = {
            "schema_version": 1,
            "authority_id": authority.id,
            "authority_sha256": authority_sha256,
            "authority_receipt_sha256": authority.authority_receipt_sha256,
            "profile_name": authority.profile_name,
            "service_name": authority.service_name,
            "authenticated_by": "host_adapter",
            "model_callable": False,
        }
        if (
            len(authority_rows) != 1
            or canonical_json(authority_rows[0].payload)
            != canonical_json(expected_authority_registration)
        ):
            raise ReleaseRecoveryDenied("RELEASE_AUTHORITY_NOT_HOST_REGISTERED")
        mismatch_sha256 = self._receipt_sha256(receipt)
        mismatch_rows = [
            event
            for event in self.store.events("release.artifact_mismatch.observed")
            if event.payload.get("receipt_id") == receipt.id
        ]
        expected_mismatch_registration = {
            "schema_version": 1,
            "receipt_id": receipt.id,
            "mismatch_receipt_sha256": mismatch_sha256,
            "authority_receipt_sha256": receipt.authority_receipt_sha256,
            "profile_name": receipt.profile_name,
            "service_name": receipt.service_name,
            "authenticated_by": "host_adapter",
            "model_callable": False,
            "producer_prose_persisted": False,
        }
        if (
            len(mismatch_rows) != 1
            or canonical_json(mismatch_rows[0].payload)
            != canonical_json(expected_mismatch_registration)
        ):
            raise ReleaseRecoveryDenied(
                "ARTIFACT_MISMATCH_RECEIPT_NOT_HOST_REGISTERED"
            )
        now = _timestamp("current time", self.store.clock())
        if _timestamp("authority expiry", authority.expires_at) <= now:
            raise ReleaseRecoveryDenied("RELEASE_AUTHORITY_EXPIRED")
        if _timestamp("receipt expiry", receipt.expires_at) <= now:
            raise ReleaseRecoveryDenied("ARTIFACT_MISMATCH_RECEIPT_EXPIRED")
        if not receipt.chain_valid or self.store.verify_chain().get("valid") is not True:
            raise ReleaseRecoveryDenied("LEDGER_CHAIN_INVALID")
        goal = self.kernel.goal(receipt.goal_id)
        if goal is None or goal.status != "active":
            raise ReleaseRecoveryDenied("RELEASE_GOAL_NOT_ACTIVE")

    @staticmethod
    def _matches_observed(
        state: ReleaseRuntimeState,
        receipt: AuthenticatedArtifactMismatchReceipt,
    ) -> bool:
        return (
            state.profile_name == receipt.profile_name
            and state.service_name == receipt.service_name
            and state.pid == receipt.observed_pid
            and state.version == receipt.observed_version
            and state.module_root == receipt.observed_module_root
            and state.wheel_sha256 == receipt.observed_wheel_sha256
            and state.source_commit == receipt.observed_source_commit
            and state.chain_valid
        )

    @staticmethod
    def _matches_rollback(
        state: ReleaseRuntimeState,
        receipt: AuthenticatedArtifactMismatchReceipt,
    ) -> bool:
        return (
            state.profile_name == GENERALIST2_PROFILE
            and state.service_name == GENERALIST2_SERVICE
            and state.version == receipt.rollback_version
            and state.module_root == receipt.rollback_module_root
            and state.wheel_sha256 == receipt.rollback_wheel_sha256
            and state.source_commit == receipt.rollback_source_commit
            and state.chain_valid
        )

    @staticmethod
    def _matches_expected_live(
        state: ReleaseRuntimeState,
        receipt: AuthenticatedArtifactMismatchReceipt,
    ) -> bool:
        return (
            state.profile_name == GENERALIST2_PROFILE
            and state.service_name == GENERALIST2_SERVICE
            and state.pid != receipt.observed_pid
            and state.version == receipt.expected_version
            and state.module_root == receipt.expected_module_root
            and state.wheel_sha256 == receipt.expected_wheel_sha256
            and state.source_commit == receipt.expected_source_commit
            and state.chain_valid
        )

    @staticmethod
    def _artifact_matches(
        artifact: ReleaseArtifact | None,
        receipt: AuthenticatedArtifactMismatchReceipt,
    ) -> bool:
        return bool(
            artifact is not None
            and artifact.recovery_id == receipt.id
            and artifact.source_commit == receipt.expected_source_commit
            and artifact.version == receipt.expected_version
            and artifact.wheel_sha256 == receipt.expected_wheel_sha256
            and artifact.wheel_source_exact
        )

    @staticmethod
    def _verification_matches(
        verification: IsolatedReleaseVerification | None,
        receipt: AuthenticatedArtifactMismatchReceipt,
        *,
        require_passed: bool,
    ) -> bool:
        return bool(
            verification is not None
            and verification.recovery_id == receipt.id
            and verification.source_commit == receipt.expected_source_commit
            and verification.version == receipt.expected_version
            and verification.module_root == receipt.expected_module_root
            and verification.wheel_sha256 == receipt.expected_wheel_sha256
            and verification.wheel_source_exact
            and (verification.passed or not require_passed)
        )

    @staticmethod
    def _options() -> tuple[Option, ...]:
        return (
            Option(
                id="rollback-only",
                description="Rollback mismatched runtime and stop on known-good bytes.",
                value_impacts={
                    "truth": 0.45,
                    "competence": 0.25,
                    "autonomy": 0.15,
                    "human_agency": 0.55,
                    "care": 0.6,
                },
                information_gain=0.2,
                uncertainty=0.1,
                time_cost=0.3,
                irreversible=False,
                assumptions=("Known-good rollback artifact remains available.",),
            ),
            Option(
                id="wait",
                description="Preserve mismatch receipt and wait for a fresh user prompt.",
                value_impacts={
                    "truth": 0.05,
                    "competence": -0.45,
                    "autonomy": -0.4,
                    "human_agency": 0.1,
                    "care": 0.1,
                },
                information_gain=0.0,
                uncertainty=0.4,
                time_cost=1.0,
                irreversible=False,
                assumptions=("Mismatch remains contained while waiting.",),
            ),
            Option(
                id=FULL_RECOVERY_OPTION_ID,
                description=(
                    "Rollback, rebuild exact reviewed source, verify in isolation, then "
                    "redeploy only Generalist2 and verify live identity."
                ),
                value_impacts={
                    "truth": 1.0,
                    "competence": 1.0,
                    "autonomy": 0.95,
                    "human_agency": 0.9,
                    "care": 0.85,
                },
                information_gain=0.7,
                uncertainty=0.05,
                time_cost=0.6,
                irreversible=False,
                assumptions=(
                    "Standing authority is authenticated and exact-byte gates remain green.",
                ),
            ),
        )

    def _event(self, kind: str, logical_field: str, value: str) -> Event | None:
        rows = [
            event
            for event in self.store.events(kind)
            if event.payload.get(logical_field) == value
        ]
        if len(rows) > 1:
            raise ReleaseRecoveryDenied("DUPLICATE_RELEASE_RECOVERY_RECEIPTS")
        return rows[0] if rows else None

    def _record_step(
        self,
        receipt: AuthenticatedArtifactMismatchReceipt,
        *,
        step: str,
        evidence: dict[str, Any],
        recovered_after_effect_crash: bool,
    ) -> Event:
        payload = {
            "schema_version": 1,
            "recovery_id": receipt.id,
            "step": step,
            "evidence": evidence,
            "verified": True,
            "recovered_after_effect_crash": recovered_after_effect_crash,
            "state_db_restored": False,
            "raw_artifact_persisted": False,
            "producer_prose_persisted": False,
        }
        event, created = self.store.append_once_result(
            "release.recovery.step.completed", f"{receipt.id}:{step}", payload
        )
        if not created and (
            event.payload.get("recovery_id") != receipt.id
            or event.payload.get("step") != step
            or event.payload.get("verified") is not True
        ):
            raise ReleaseRecoveryDenied("RELEASE_RECOVERY_STEP_COLLISION")
        return event

    def _step_exists(self, receipt_id: str, step: str) -> bool:
        return self._step_event(receipt_id, step) is not None

    def _step_event(self, receipt_id: str, step: str) -> Event | None:
        events = [
            event
            for event in self.store.events("release.recovery.step.completed")
            if event.payload.get("recovery_id") == receipt_id
            and event.payload.get("step") == step
        ]
        if len(events) > 1:
            raise ReleaseRecoveryDenied("DUPLICATE_RELEASE_RECOVERY_STEPS")
        if events and events[0].payload.get("verified") is not True:
            raise ReleaseRecoveryDenied("MALFORMED_RELEASE_RECOVERY_STEP")
        return events[0] if events else None

    def _decision(
        self, receipt: AuthenticatedArtifactMismatchReceipt, *, seed: int
    ) -> tuple[dict[str, Any], Event]:
        decision_id = f"release-recovery-{receipt.id}"
        decision = self.kernel.deliberate(
            goal_id=receipt.goal_id,
            options=self._options(),
            seed=seed,
            decision_id=decision_id,
        )
        event = self.kernel.decision(decision_id)
        if event is None:
            raise ReleaseRecoveryDenied("RELEASE_DECISION_RECEIPT_MISSING")
        replay = self.kernel.replay_decision(decision_id)
        if replay.get("matches") is not True:
            raise ReleaseRecoveryDenied("RELEASE_DECISION_NOT_REPLAYABLE")
        return decision, event

    def _terminal_response(
        self,
        terminal: Event,
        *,
        receipt_sha256: str,
        authority_sha256: str,
        replayed: bool,
    ) -> dict[str, Any]:
        result = terminal.payload.get("result")
        if (
            terminal.payload.get("schema_version") != RELEASE_RECOVERY_RECEIPT_VERSION
            or terminal.payload.get("mismatch_receipt_sha256") != receipt_sha256
            or terminal.payload.get("authority_sha256") != authority_sha256
            or not isinstance(result, dict)
            or result.get("status") != "verified-live"
        ):
            raise ReleaseRecoveryDenied("RELEASE_RECOVERY_TERMINAL_BINDING_MISMATCH")
        return {**result, "terminal_event_id": terminal.event_id, "replayed": replayed}

    def _record_failure(
        self,
        receipt: AuthenticatedArtifactMismatchReceipt,
        *,
        reason_code: str,
    ) -> None:
        current = self.adapter.inspect_runtime()
        payload = {
            "schema_version": 1,
            "recovery_id": receipt.id,
            "reason_code": reason_code,
            "rollback_live_verified": self._matches_rollback(current, receipt),
            "current_runtime_sha256": current.state_sha256,
            "state_db_restored": False,
            "redeploy_attempted": any(
                event.payload.get("recovery_id") == receipt.id
                and event.payload.get("step") == "generalist2-redeploy"
                for event in self.store.events("release.recovery.step.completed")
            ),
            "producer_prose_persisted": False,
        }
        self.store.append_once_result("release.recovery.failed", receipt.id, payload)

    def recover(
        self,
        receipt: AuthenticatedArtifactMismatchReceipt,
        authority: AuthenticatedReleaseAuthority,
        *,
        seed: int,
        fault_hook: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(receipt, AuthenticatedArtifactMismatchReceipt) or not isinstance(
            authority, AuthenticatedReleaseAuthority
        ):
            raise ValueError("release recovery requires typed receipt and authority")
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("release decision seed must be an integer")
        self._ensure_clear()
        self._validate_authority(receipt, authority)
        receipt_sha256 = self._receipt_sha256(receipt)
        authority_sha256 = self._authority_sha256(authority)
        with self._locked():
            self._ensure_clear()
            terminal = self._event("release.recovery.completed", "recovery_id", receipt.id)
            if terminal is not None:
                current = self.adapter.inspect_runtime()
                if not self._matches_expected_live(current, receipt):
                    raise ReleaseRecoveryDenied("COMPLETED_RELEASE_RUNTIME_STALE")
                return self._terminal_response(
                    terminal,
                    receipt_sha256=receipt_sha256,
                    authority_sha256=authority_sha256,
                    replayed=True,
                )
            claim = self._event("release.recovery.claimed", "recovery_id", receipt.id)
            current = self.adapter.inspect_runtime()
            if claim is None:
                if not self._matches_observed(current, receipt):
                    raise ReleaseRecoveryDenied("ARTIFACT_MISMATCH_RECEIPT_STALE")
                decision, decision_event = self._decision(receipt, seed=seed)
                claim_payload = {
                    "schema_version": RELEASE_RECOVERY_CLAIM_VERSION,
                    "recovery_id": receipt.id,
                    "goal_id": receipt.goal_id,
                    "principal_id": receipt.principal_id,
                    "profile_name": GENERALIST2_PROFILE,
                    "service_name": GENERALIST2_SERVICE,
                    "mismatch_receipt_sha256": receipt_sha256,
                    "authority_id": authority.id,
                    "authority_sha256": authority_sha256,
                    "authority_receipt_sha256": authority.authority_receipt_sha256,
                    "decision_id": decision["decision_id"],
                    "decision_event_id": decision_event.event_id,
                    "chosen_option_id": decision["chosen_option_id"],
                    "allowed_option_ids": decision["allowed_option_ids"],
                    "standing_authority_only": True,
                    "fresh_user_prompt_required": False,
                    "state_db_restore_allowed": False,
                    "other_profile_effects_allowed": False,
                    "producer_prose_persisted": False,
                }
                claim, _ = self.store.append_once_result(
                    "release.recovery.claimed", receipt.id, claim_payload
                )
            else:
                if (
                    claim.payload.get("mismatch_receipt_sha256") != receipt_sha256
                    or claim.payload.get("authority_sha256") != authority_sha256
                    or claim.payload.get("authority_receipt_sha256")
                    != authority.authority_receipt_sha256
                ):
                    raise ReleaseRecoveryDenied("RELEASE_RECOVERY_CLAIM_COLLISION")
                decision_event = self.kernel.decision(str(claim.payload.get("decision_id")))
                if decision_event is None:
                    raise ReleaseRecoveryDenied("RELEASE_DECISION_RECEIPT_MISSING")
                decision = dict(decision_event.payload)

            if claim.payload.get("chosen_option_id") != FULL_RECOVERY_OPTION_ID:
                payload = {
                    "schema_version": 1,
                    "recovery_id": receipt.id,
                    "decision_id": claim.payload.get("decision_id"),
                    "chosen_option_id": claim.payload.get("chosen_option_id"),
                    "status": "deferred",
                    "external_effects": 0,
                }
                event, _ = self.store.append_once_result(
                    "release.recovery.deferred", receipt.id, payload
                )
                return {
                    **event.payload,
                    "terminal_event_id": event.event_id,
                    "replayed": False,
                }

            rollback_ticket = ReleaseRollbackTicket(
                recovery_id=receipt.id,
                authority_id=authority.id,
                mismatch_receipt_sha256=receipt_sha256,
                profile_name=GENERALIST2_PROFILE,
                service_name=GENERALIST2_SERVICE,
                expected_observed_state_sha256=_hash(
                    {
                        "profile_name": receipt.profile_name,
                        "service_name": receipt.service_name,
                        "pid": receipt.observed_pid,
                        "version": receipt.observed_version,
                        "module_root": receipt.observed_module_root,
                        "wheel_sha256": receipt.observed_wheel_sha256,
                        "source_commit": receipt.observed_source_commit,
                        "chain_valid": receipt.chain_valid,
                    }
                ),
                rollback_version=receipt.rollback_version,
                rollback_module_root=receipt.rollback_module_root,
                rollback_wheel_sha256=receipt.rollback_wheel_sha256,
                rollback_source_commit=receipt.rollback_source_commit,
            )
            current = self.adapter.inspect_runtime()
            final_already_live = self._matches_expected_live(current, receipt)
            rollback_called = False
            if not self._step_exists(receipt.id, "rollback"):
                if not final_already_live and not self._matches_rollback(current, receipt):
                    if not self._matches_observed(current, receipt):
                        raise ReleaseRecoveryDenied("RELEASE_ROLLBACK_STATE_UNCERTAIN")
                    self._ensure_clear()
                    current = self.adapter.rollback(rollback_ticket)
                    rollback_called = True
                    if fault_hook is not None:
                        fault_hook("after-rollback-effect")
                if not final_already_live and not self._matches_rollback(current, receipt):
                    raise ReleaseRecoveryDenied("RELEASE_ROLLBACK_READBACK_MISMATCH")
                self._record_step(
                    receipt,
                    step="rollback",
                    evidence={
                        "runtime_sha256": current.state_sha256,
                        "known_good_live": self._matches_rollback(current, receipt)
                        or final_already_live,
                        "state_db_restored": False,
                    },
                    recovered_after_effect_crash=not rollback_called,
                )

            artifact = self.adapter.inspect_artifact(receipt.id)
            rebuild_called = False
            if not self._artifact_matches(artifact, receipt):
                self._ensure_clear()
                artifact = self.adapter.rebuild_exact(
                    ExactRebuildTicket(
                        recovery_id=receipt.id,
                        authority_id=authority.id,
                        mismatch_receipt_sha256=receipt_sha256,
                        source_commit=receipt.expected_source_commit,
                        version=receipt.expected_version,
                        expected_wheel_sha256=receipt.expected_wheel_sha256,
                    )
                )
                rebuild_called = True
                if fault_hook is not None:
                    fault_hook("after-rebuild-effect")
            if not self._artifact_matches(artifact, receipt):
                raise ReleaseRecoveryDenied("EXACT_REBUILD_ARTIFACT_MISMATCH")
            assert artifact is not None
            if not self._step_exists(receipt.id, "exact-rebuild"):
                self._record_step(
                    receipt,
                    step="exact-rebuild",
                    evidence={
                        "source_commit": artifact.source_commit,
                        "version": artifact.version,
                        "wheel_sha256": artifact.wheel_sha256,
                        "byte_count": artifact.byte_count,
                        "wheel_source_exact": artifact.wheel_source_exact,
                    },
                    recovered_after_effect_crash=not rebuild_called,
                )

            verification = self.adapter.inspect_verification(receipt.id)
            verify_called = False
            if not self._verification_matches(
                verification, receipt, require_passed=False
            ):
                self._ensure_clear()
                verification = self.adapter.verify_isolated(
                    IsolatedVerificationTicket(
                        recovery_id=receipt.id,
                        authority_id=authority.id,
                        source_commit=receipt.expected_source_commit,
                        version=receipt.expected_version,
                        wheel_sha256=receipt.expected_wheel_sha256,
                        expected_module_root=receipt.expected_module_root,
                    ),
                    artifact,
                )
                verify_called = True
                if fault_hook is not None:
                    fault_hook("after-isolated-verification-effect")
            if not self._verification_matches(
                verification, receipt, require_passed=False
            ):
                raise ReleaseRecoveryDenied("ISOLATED_RELEASE_VERIFICATION_MISMATCH")
            assert verification is not None
            if not verification.passed:
                self._record_failure(
                    receipt, reason_code="ISOLATED_RELEASE_VERIFICATION_FAILED"
                )
                raise ReleaseRecoveryDenied("ISOLATED_RELEASE_VERIFICATION_FAILED")
            if not self._step_exists(receipt.id, "isolated-verification"):
                self._record_step(
                    receipt,
                    step="isolated-verification",
                    evidence={
                        "source_commit": verification.source_commit,
                        "version": verification.version,
                        "module_root": verification.module_root,
                        "wheel_sha256": verification.wheel_sha256,
                        "wheel_source_exact": verification.wheel_source_exact,
                        "tools": verification.tools,
                        "hooks": verification.hooks,
                        "middleware": verification.middleware,
                        "receipt_sha256": verification.receipt_sha256,
                    },
                    recovered_after_effect_crash=not verify_called,
                )

            current = self.adapter.inspect_runtime()
            redeploy_called = False
            if not self._matches_expected_live(current, receipt):
                if not self._matches_rollback(current, receipt):
                    raise ReleaseRecoveryDenied("REDEPLOY_PRESTATE_UNCERTAIN")
                self._ensure_clear()
                current = self.adapter.redeploy(
                    Generalist2RedeployTicket(
                        recovery_id=receipt.id,
                        authority_id=authority.id,
                        profile_name=GENERALIST2_PROFILE,
                        service_name=GENERALIST2_SERVICE,
                        source_commit=receipt.expected_source_commit,
                        version=receipt.expected_version,
                        module_root=receipt.expected_module_root,
                        wheel_sha256=receipt.expected_wheel_sha256,
                        verification_receipt_sha256=verification.receipt_sha256,
                        previous_pid=receipt.observed_pid,
                    ),
                    artifact,
                    verification,
                )
                redeploy_called = True
                if fault_hook is not None:
                    fault_hook("after-redeploy-effect")
                current = self.adapter.inspect_runtime()
            if not self._matches_expected_live(current, receipt):
                raise ReleaseRecoveryDenied("LIVE_RELEASE_VERIFICATION_FAILED")
            if not self._step_exists(receipt.id, "generalist2-redeploy"):
                self._record_step(
                    receipt,
                    step="generalist2-redeploy",
                    evidence={
                        "old_pid": receipt.observed_pid,
                        "new_pid": current.pid,
                        "runtime_sha256": current.state_sha256,
                        "other_profile_effects": 0,
                        "state_db_restored": False,
                    },
                    recovered_after_effect_crash=not redeploy_called,
                )
            live_evidence = {
                "profile_name": current.profile_name,
                "service_name": current.service_name,
                "old_pid": receipt.observed_pid,
                "new_pid": current.pid,
                "version": current.version,
                "module_root": current.module_root,
                "wheel_sha256": current.wheel_sha256,
                "source_commit": current.source_commit,
                "wheel_source_exact": artifact.wheel_source_exact,
                "chain_valid": current.chain_valid,
                "isolated_verification_receipt_sha256": (
                    verification.receipt_sha256
                ),
            }
            live_step = self._step_event(receipt.id, "live-verification")
            if live_step is None:
                live_step = self._record_step(
                    receipt,
                    step="live-verification",
                    evidence=live_evidence,
                    recovered_after_effect_crash=not redeploy_called,
                )
                if fault_hook is not None:
                    fault_hook("after-live-verification-receipt")
            elif canonical_json(live_step.payload.get("evidence")) != canonical_json(
                live_evidence
            ):
                raise ReleaseRecoveryDenied("LIVE_VERIFICATION_RECEIPT_COLLISION")

            outcome = self.kernel.record_outcome(
                decision_id=str(claim.payload["decision_id"]),
                realized_utility=1.0,
                observation=(
                    "Authenticated artifact mismatch recovered to exact reviewed "
                    "Generalist2 release with live readback."
                ),
                evidence=(
                    receipt.evidence_sha256,
                    verification.receipt_sha256,
                    live_step.event_id,
                ),
            )
            learning_payload = {
                "schema_version": 1,
                "recovery_id": receipt.id,
                "decision_id": claim.payload["decision_id"],
                "chosen_option_id": FULL_RECOVERY_OPTION_ID,
                "outcome_event_id": outcome.event_id,
                "mismatch_evidence_sha256": receipt.evidence_sha256,
                "isolated_verification_receipt_sha256": (
                    verification.receipt_sha256
                ),
                "live_runtime_sha256": current.state_sha256,
                "result": "exact-recovery-succeeded",
                "future_policy_signal": "prefer-exact-recovery-under-standing-authority",
                "requires_endorsement": True,
                "self_ratification_allowed": False,
                "root_policy_changed": False,
                "producer_prose_persisted": False,
            }
            learning, _ = self.store.append_once_result(
                "release.recovery.policy_learning.proposed",
                receipt.id,
                learning_payload,
            )
            alternatives = [
                str(row["id"])
                for row in decision_event.payload.get("options", [])
                if isinstance(row, dict) and isinstance(row.get("id"), str)
            ]
            result = {
                "status": "verified-live",
                "recovery_id": receipt.id,
                "decision_id": claim.payload["decision_id"],
                "decision_event_id": decision_event.event_id,
                "chosen_option_id": FULL_RECOVERY_OPTION_ID,
                "alternatives_considered": alternatives,
                "steps": list(REQUIRED_RELEASE_OPERATIONS),
                "live": {
                    "profile_name": current.profile_name,
                    "service_name": current.service_name,
                    "old_pid": receipt.observed_pid,
                    "new_pid": current.pid,
                    "version": current.version,
                    "module_root": current.module_root,
                    "wheel_sha256": current.wheel_sha256,
                    "source_commit": current.source_commit,
                    "wheel_source_exact": artifact.wheel_source_exact,
                    "chain_valid": current.chain_valid,
                },
                "outcome_event_id": outcome.event_id,
                "policy_learning_event_id": learning.event_id,
                "state_db_restored": False,
                "other_profile_effects": 0,
            }
            terminal_payload = {
                "schema_version": RELEASE_RECOVERY_RECEIPT_VERSION,
                "recovery_id": receipt.id,
                "claim_event_id": claim.event_id,
                "mismatch_receipt_sha256": receipt_sha256,
                "authority_sha256": authority_sha256,
                "result": result,
                "verified": True,
                "producer_prose_persisted": False,
                "raw_artifact_persisted": False,
            }
            terminal, created = self.store.append_once_result(
                "release.recovery.completed", receipt.id, terminal_payload
            )
            return self._terminal_response(
                terminal,
                receipt_sha256=receipt_sha256,
                authority_sha256=authority_sha256,
                replayed=not created,
            )
