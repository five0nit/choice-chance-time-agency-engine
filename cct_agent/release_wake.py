"""Host-authenticated recurrent wake for exact Generalist2 release recovery.

One private signed target is compared with exact live artifact identity. Matching
bytes are archived without ledger/output noise. A mismatch becomes one durable,
metadata-only receipt bound to standing reversible authority, then enters the
Choice-Chance-Time release bridge. Private claims retain the original observation
across rollback/reload crashes; a process lock makes concurrent wakes converge.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
import fcntl
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Iterator, Protocol

from .kernel import AgencyKernel, resolve_constitution
from .recurrent import runtime_provenance
from .release_host import Generalist2ReleaseHostAdapter, Generalist2ReleaseHostConfig
from .release_recovery import (
    GENERALIST2_PROFILE,
    GENERALIST2_SERVICE,
    REQUIRED_RELEASE_OPERATIONS,
    AuthenticatedArtifactMismatchReceipt,
    AuthenticatedReleaseAuthority,
    ReleaseRecoveryAdapter,
    ReleaseRecoveryBridge,
    ReleaseRuntimeState,
)
from .store import EventStore, canonical_json


RELEASE_WAKE_TARGET_VERSION = "cct.release-wake-target.v1"
RELEASE_WAKE_CLAIM_VERSION = "cct.release-wake-claim.v1"
_MAX_TARGET_BYTES = 65_536
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DOCUMENT_FIELDS = {
    "schema_version",
    "id",
    "authority_id",
    "principal_id",
    "goal_id",
    "profile_name",
    "service_name",
    "operations",
    "reversible",
    "authority_expires_at",
    "authority_receipt_sha256",
    "expected_version",
    "expected_module_root",
    "expected_wheel_sha256",
    "expected_source_commit",
    "rollback_version",
    "rollback_module_root",
    "rollback_wheel_sha256",
    "rollback_source_commit",
    "expires_at",
    "seed",
    "issued_by",
    "producer_prose_persisted",
    "signature",
}


class ReleaseWakeDenied(RuntimeError):
    """Fail-closed host wake rejection with stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class ReleaseWakeBridge(Protocol):
    def recover(
        self,
        receipt: AuthenticatedArtifactMismatchReceipt,
        authority: AuthenticatedReleaseAuthority,
        *,
        seed: int,
    ) -> dict[str, Any]: ...


def _identifier(name: str, value: object, *, maximum: int = 159) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or not _IDENTIFIER.fullmatch(value)
    ):
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


def _payload_digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _signature(secret: bytes, value: object) -> str:
    return hmac.new(
        secret,
        canonical_json(value).encode("utf-8"),
        sha256,
    ).hexdigest()


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


def _directory(path: Path, name: str) -> tuple[Path, tuple[int, int]]:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{name} must be an absolute real directory")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{name} must be an existing real directory") from error
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise ValueError(f"{name} must be an owned non-writable real directory")
    return resolved, (metadata.st_dev, metadata.st_ino)


def _private_file_snapshot(
    path: Path, root: Path, name: str, maximum: int
) -> tuple[bytes, tuple[int, int]]:
    if not path.is_absolute() or path.parent != root or path.name in {"", ".", ".."}:
        raise ReleaseWakeDenied(f"{name.upper()}_PATH_INVALID")
    root_fd = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    descriptor = -1
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=root_fd,
        )
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(path.name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise ReleaseWakeDenied(f"{name.upper()}_UNSAFE")
        if metadata.st_size > maximum:
            raise ReleaseWakeDenied(f"{name.upper()}_TOO_LARGE")
        body = bytearray()
        while True:
            block = os.read(descriptor, min(65_536, maximum + 1 - len(body)))
            if not block:
                break
            body.extend(block)
            if len(body) > maximum:
                raise ReleaseWakeDenied(f"{name.upper()}_TOO_LARGE")
        return bytes(body), (metadata.st_dev, metadata.st_ino)
    except ReleaseWakeDenied:
        raise
    except OSError as error:
        raise ReleaseWakeDenied(f"{name.upper()}_OPEN_FAILED") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(root_fd)


def _private_file(path: Path, root: Path, name: str, maximum: int) -> bytes:
    body, _ = _private_file_snapshot(path, root, name, maximum)
    return body


def _atomic_private_json(path: Path, payload: object) -> None:
    body = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    parent_fd = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary = f".{path.name}.{os.getpid()}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        view = memoryview(body)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError("release wake atomic write made no progress")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    except Exception:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except OSError:
            pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


@dataclass(frozen=True, slots=True)
class ReleaseWakeTarget:
    """Strict metadata-only target and standing reversible authority claim."""

    id: str
    authority_id: str
    principal_id: str
    goal_id: str
    profile_name: str
    service_name: str
    operations: tuple[str, ...]
    reversible: bool
    authority_expires_at: str
    authority_receipt_sha256: str
    expected_version: str
    expected_module_root: str
    expected_wheel_sha256: str
    expected_source_commit: str
    rollback_version: str
    rollback_module_root: str
    rollback_wheel_sha256: str
    rollback_source_commit: str
    expires_at: str
    seed: int
    issued_by: str
    producer_prose_persisted: bool
    signature: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("target id", self.id, maximum=100))
        for name in ("authority_id", "principal_id", "goal_id"):
            object.__setattr__(self, name, _identifier(name, getattr(self, name)))
        if self.profile_name != GENERALIST2_PROFILE or self.service_name != GENERALIST2_SERVICE:
            raise ValueError("release wake target must be exact Generalist2 service")
        operations = tuple(_identifier("operation", value) for value in self.operations)
        if operations != REQUIRED_RELEASE_OPERATIONS:
            raise ValueError("release wake operations must match standing authority")
        object.__setattr__(self, "operations", operations)
        if self.reversible is not True:
            raise ValueError("release wake authority must be reversible")
        _timestamp("authority_expires_at", self.authority_expires_at)
        _timestamp("expires_at", self.expires_at)
        object.__setattr__(
            self,
            "authority_receipt_sha256",
            _digest("authority_receipt_sha256", self.authority_receipt_sha256),
        )
        for name in ("expected_version", "rollback_version"):
            object.__setattr__(self, name, _version(name, getattr(self, name)))
        for name in ("expected_module_root", "rollback_module_root"):
            object.__setattr__(self, name, _module_root(name, getattr(self, name)))
        for name in ("expected_wheel_sha256", "rollback_wheel_sha256"):
            object.__setattr__(self, name, _digest(name, getattr(self, name)))
        for name in ("expected_source_commit", "rollback_source_commit"):
            object.__setattr__(self, name, _commit(name, getattr(self, name)))
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("release wake seed must be an integer")
        if self.issued_by != "host_adapter":
            raise ValueError("release wake issuer must be host_adapter")
        if self.producer_prose_persisted is not False:
            raise ValueError("release wake cannot persist producer prose")
        object.__setattr__(self, "signature", _digest("signature", self.signature))

    def authority_material(self) -> dict[str, Any]:
        return {
            "authority_id": self.authority_id,
            "principal_id": self.principal_id,
            "goal_id": self.goal_id,
            "profile_name": self.profile_name,
            "service_name": self.service_name,
            "operations": list(self.operations),
            "reversible": self.reversible,
            "expires_at": self.authority_expires_at,
            "issued_by": self.issued_by,
            "model_callable": False,
        }

    def signed_payload(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        value["operations"] = list(self.operations)
        return value

    def to_document(self) -> dict[str, Any]:
        return {
            "schema_version": RELEASE_WAKE_TARGET_VERSION,
            **self.signed_payload(),
            "signature": self.signature,
        }

    def verify(self, secret: bytes) -> bool:
        return bool(
            isinstance(secret, bytes)
            and len(secret) >= 32
            and self.authority_receipt_sha256
            == _payload_digest(self.authority_material())
            and hmac.compare_digest(self.signature, _signature(secret, self.signed_payload()))
        )

    @classmethod
    def sign(
        cls,
        *,
        target_id: str,
        authority_id: str,
        principal_id: str,
        goal_id: str,
        expected_version: str,
        expected_module_root: str,
        expected_wheel_sha256: str,
        expected_source_commit: str,
        rollback_version: str,
        rollback_module_root: str,
        rollback_wheel_sha256: str,
        rollback_source_commit: str,
        expires_at: str,
        secret: bytes,
        authority_expires_at: str | None = None,
        seed: int = 0,
    ) -> ReleaseWakeTarget:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("release wake signing secret must contain at least 32 bytes")
        authority_expiry = authority_expires_at or expires_at
        authority_material = {
            "authority_id": authority_id,
            "principal_id": principal_id,
            "goal_id": goal_id,
            "profile_name": GENERALIST2_PROFILE,
            "service_name": GENERALIST2_SERVICE,
            "operations": list(REQUIRED_RELEASE_OPERATIONS),
            "reversible": True,
            "expires_at": authority_expiry,
            "issued_by": "host_adapter",
            "model_callable": False,
        }
        unsigned = {
            "id": target_id,
            "authority_id": authority_id,
            "principal_id": principal_id,
            "goal_id": goal_id,
            "profile_name": GENERALIST2_PROFILE,
            "service_name": GENERALIST2_SERVICE,
            "operations": REQUIRED_RELEASE_OPERATIONS,
            "reversible": True,
            "authority_expires_at": authority_expiry,
            "authority_receipt_sha256": _payload_digest(authority_material),
            "expected_version": expected_version,
            "expected_module_root": expected_module_root,
            "expected_wheel_sha256": expected_wheel_sha256,
            "expected_source_commit": expected_source_commit,
            "rollback_version": rollback_version,
            "rollback_module_root": rollback_module_root,
            "rollback_wheel_sha256": rollback_wheel_sha256,
            "rollback_source_commit": rollback_source_commit,
            "expires_at": expires_at,
            "seed": seed,
            "issued_by": "host_adapter",
            "producer_prose_persisted": False,
        }
        candidate = cls(**unsigned, signature="0" * 64)
        return cls(**unsigned, signature=_signature(secret, candidate.signed_payload()))

    @classmethod
    def from_document(cls, value: object) -> ReleaseWakeTarget:
        if (
            not isinstance(value, dict)
            or set(value) != _DOCUMENT_FIELDS
            or value.get("schema_version") != RELEASE_WAKE_TARGET_VERSION
        ):
            raise ValueError("release wake target schema is invalid")
        material = dict(value)
        material.pop("schema_version")
        operations = material.get("operations")
        if not isinstance(operations, list):
            raise ValueError("release wake target operations must be an array")
        material["operations"] = tuple(operations)
        return cls(**material)


@dataclass(frozen=True, slots=True)
class ReleaseWakePaths:
    state_root: Path
    inbox_root: Path
    completed_root: Path
    rejected_root: Path
    claims_root: Path
    bridge_state_root: Path
    secret_file: Path

    def __post_init__(self) -> None:
        root, _ = _directory(Path(self.state_root), "state_root")
        object.__setattr__(self, "state_root", root)
        expected_names = {
            "inbox_root": "inbox",
            "completed_root": "completed",
            "rejected_root": "rejected",
            "claims_root": "claims",
            "bridge_state_root": "bridge-state",
        }
        for name, basename in expected_names.items():
            path, _ = _directory(Path(getattr(self, name)), name)
            if path.parent != root or path.name != basename:
                raise ValueError(f"{name} must be exact direct child of state_root")
            object.__setattr__(self, name, path)
        secret = Path(self.secret_file)
        if secret.parent != root or secret.name != "authentication.key" or secret.is_symlink():
            raise ValueError("secret_file must be exact private state-root file")
        _private_file(secret, root, "authentication_secret", _MAX_TARGET_BYTES)
        object.__setattr__(self, "secret_file", secret)


@dataclass(frozen=True, slots=True)
class _CandidateFile:
    name: str
    body: bytes
    identity: tuple[int, int]
    sha256: str


@dataclass(frozen=True, slots=True)
class _Candidate(_CandidateFile):
    target: ReleaseWakeTarget


FaultHook = Callable[[str], None]


class ReleaseWakeCoordinator:
    """Serialize target admission and invoke one restart-safe release decision."""

    def __init__(
        self,
        *,
        paths: ReleaseWakePaths,
        store: EventStore,
        kernel: AgencyKernel,
        adapter: ReleaseRecoveryAdapter,
        bridge: ReleaseWakeBridge,
        expected_module_root: Path,
        expected_package_version: str,
    ) -> None:
        if not isinstance(paths, ReleaseWakePaths):
            raise ValueError("paths must be ReleaseWakePaths")
        if not isinstance(store, EventStore) or not isinstance(kernel, AgencyKernel):
            raise ValueError("release wake requires EventStore and AgencyKernel")
        if kernel.store.path.resolve() != store.path.resolve():
            raise ValueError("release wake kernel must share the exact ledger")
        if not callable(getattr(adapter, "inspect_runtime", None)):
            raise ValueError("release wake adapter must inspect runtime")
        if not callable(getattr(bridge, "recover", None)):
            raise ValueError("release wake bridge must implement recovery")
        bridge_store = getattr(bridge, "store", store)
        bridge_adapter = getattr(bridge, "adapter", adapter)
        if (
            not isinstance(bridge_store, EventStore)
            or bridge_store.path.resolve() != store.path.resolve()
            or bridge_adapter is not adapter
        ):
            raise ValueError("release wake bridge must bind exact store and adapter")
        self.runtime = runtime_provenance(
            expected_module_root=expected_module_root,
            expected_package_version=expected_package_version,
        )
        self.paths = paths
        self.store = store
        self.kernel = kernel
        self.adapter = adapter
        self.bridge = bridge
        metadata = paths.state_root.stat()
        self._root_identity = (metadata.st_dev, metadata.st_ino)
        self._lock_path = paths.state_root / "release-wake.lock"
        descriptor = os.open(
            self._lock_path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        descriptor = os.open(
            self._lock_path,
            os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            metadata = self.paths.state_root.stat()
            if (
                self.paths.state_root.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o022
                or (metadata.st_dev, metadata.st_ino) != self._root_identity
            ):
                raise ReleaseWakeDenied("RELEASE_WAKE_STATE_ROOT_CHANGED")
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read_candidate(self, name: str, secret: bytes) -> _Candidate:
        if (
            not isinstance(name, str)
            or not name.endswith(".json")
            or name.startswith(".")
            or "/" in name
            or "\x00" in name
            or len(os.fsencode(name)) > 240
        ):
            raise ReleaseWakeDenied("RELEASE_WAKE_CANDIDATE_NAME_INVALID")
        body, identity = _private_file_snapshot(
            self.paths.inbox_root / name,
            self.paths.inbox_root,
            "release_wake_candidate",
            _MAX_TARGET_BYTES,
        )
        try:
            raw = json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_strict_json_object,
            )
            target = ReleaseWakeTarget.from_document(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise ReleaseWakeDenied("RELEASE_WAKE_CANDIDATE_SCHEMA_INVALID") from error
        if not target.verify(secret):
            raise ReleaseWakeDenied("RELEASE_WAKE_CANDIDATE_AUTHENTICATION_FAILED")
        return _Candidate(
            name=name,
            body=body,
            identity=identity,
            sha256=sha256(body).hexdigest(),
            target=target,
        )

    def _archive(self, candidate: _CandidateFile, *, accepted: bool) -> None:
        archived_body, archived_identity = _private_file_snapshot(
            self.paths.inbox_root / candidate.name,
            self.paths.inbox_root,
            "release_wake_candidate",
            _MAX_TARGET_BYTES,
        )
        if (
            archived_identity != candidate.identity
            or archived_body != candidate.body
            or sha256(archived_body).hexdigest() != candidate.sha256
        ):
            raise ReleaseWakeDenied("RELEASE_WAKE_CANDIDATE_CHANGED")
        source_fd = os.open(
            self.paths.inbox_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        destination_root = (
            self.paths.completed_root if accepted else self.paths.rejected_root
        )
        destination_fd = os.open(
            destination_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            metadata = os.stat(candidate.name, dir_fd=source_fd, follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) != candidate.identity:
                raise ReleaseWakeDenied("RELEASE_WAKE_CANDIDATE_CHANGED")
            name_sha256 = sha256(os.fsencode(candidate.name)).hexdigest()
            stem = f"{candidate.sha256[:32]}-{name_sha256[:16]}.json"
            destination = stem
            suffix = 0
            while True:
                try:
                    os.stat(destination, dir_fd=destination_fd, follow_symlinks=False)
                except FileNotFoundError:
                    break
                suffix += 1
                if suffix > 999:
                    raise ReleaseWakeDenied("RELEASE_WAKE_ARCHIVE_EXHAUSTED")
                destination = f"{stem}.{suffix}"
            os.rename(
                candidate.name,
                destination,
                src_dir_fd=source_fd,
                dst_dir_fd=destination_fd,
            )
            os.fsync(source_fd)
            os.fsync(destination_fd)
        except ReleaseWakeDenied:
            raise
        except OSError as error:
            raise ReleaseWakeDenied("RELEASE_WAKE_ARCHIVE_FAILED") from error
        finally:
            os.close(destination_fd)
            os.close(source_fd)

    def _quarantine_unreadable(self, name: str) -> None:
        if (
            not isinstance(name, str)
            or name in {"", ".", ".."}
            or name.startswith(".")
            or "/" in name
            or "\x00" in name
            or len(os.fsencode(name)) > 255
        ):
            raise ReleaseWakeDenied("RELEASE_WAKE_CANDIDATE_NAME_INVALID")
        source_fd = os.open(
            self.paths.inbox_root,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
        destination_fd = os.open(
            self.paths.rejected_root,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            metadata = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if metadata.st_uid != os.geteuid():
                raise ReleaseWakeDenied("RELEASE_WAKE_CANDIDATE_FOREIGN_OWNER")
            fingerprint = _payload_digest(
                {
                    "name_sha256": sha256(os.fsencode(name)).hexdigest(),
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "mode_type": stat.S_IFMT(metadata.st_mode),
                    "byte_count": metadata.st_size,
                }
            )
            name_sha256 = sha256(os.fsencode(name)).hexdigest()
            stem = f"{fingerprint[:32]}-{name_sha256[:16]}.json"
            destination = stem
            suffix = 0
            while True:
                try:
                    os.stat(destination, dir_fd=destination_fd, follow_symlinks=False)
                except FileNotFoundError:
                    break
                suffix += 1
                if suffix > 999:
                    raise ReleaseWakeDenied("RELEASE_WAKE_ARCHIVE_EXHAUSTED")
                destination = f"{stem}.{suffix}"
            os.rename(
                name,
                destination,
                src_dir_fd=source_fd,
                dst_dir_fd=destination_fd,
            )
            os.fsync(source_fd)
            os.fsync(destination_fd)
        except ReleaseWakeDenied:
            raise
        except OSError as error:
            raise ReleaseWakeDenied("RELEASE_WAKE_ARCHIVE_FAILED") from error
        finally:
            os.close(destination_fd)
            os.close(source_fd)

    @staticmethod
    def _matches_expected(state: ReleaseRuntimeState, target: ReleaseWakeTarget) -> bool:
        return (
            state.profile_name == GENERALIST2_PROFILE
            and state.service_name == GENERALIST2_SERVICE
            and state.version == target.expected_version
            and state.module_root == target.expected_module_root
            and state.wheel_sha256 == target.expected_wheel_sha256
            and state.source_commit == target.expected_source_commit
            and state.chain_valid
        )

    def _claim_pending(self, target: ReleaseWakeTarget) -> bool:
        path = self.paths.claims_root / f"{target.id}.json"
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        except OSError as error:
            raise ReleaseWakeDenied("RELEASE_WAKE_CLAIM_INSPECTION_FAILED") from error
        return True

    @staticmethod
    def _authority(target: ReleaseWakeTarget) -> AuthenticatedReleaseAuthority:
        return AuthenticatedReleaseAuthority(
            id=target.authority_id,
            authority="operator",
            authenticated=True,
            principal_id=target.principal_id,
            goal_id=target.goal_id,
            profile_name=target.profile_name,
            service_name=target.service_name,
            operations=target.operations,
            reversible=True,
            authority_receipt_sha256=target.authority_receipt_sha256,
            expires_at=target.authority_expires_at,
        )

    @staticmethod
    def _receipt(
        target: ReleaseWakeTarget, current: ReleaseRuntimeState
    ) -> AuthenticatedArtifactMismatchReceipt:
        evidence = {
            "schema_version": 1,
            "target_id": target.id,
            "target_signature_sha256": sha256(target.signature.encode("ascii")).hexdigest(),
            "observed_runtime_sha256": current.state_sha256,
            "expected": {
                "version": target.expected_version,
                "module_root": target.expected_module_root,
                "wheel_sha256": target.expected_wheel_sha256,
                "source_commit": target.expected_source_commit,
            },
            "producer_prose_persisted": False,
        }
        return AuthenticatedArtifactMismatchReceipt(
            id=f"mismatch-{target.id}-{current.state_sha256[:16]}",
            authority="host_adapter",
            authenticated=True,
            principal_id=target.principal_id,
            goal_id=target.goal_id,
            profile_name=target.profile_name,
            service_name=target.service_name,
            observed_pid=current.pid,
            observed_version=current.version,
            observed_module_root=current.module_root,
            observed_wheel_sha256=current.wheel_sha256,
            observed_source_commit=current.source_commit,
            expected_version=target.expected_version,
            expected_module_root=target.expected_module_root,
            expected_wheel_sha256=target.expected_wheel_sha256,
            expected_source_commit=target.expected_source_commit,
            rollback_version=target.rollback_version,
            rollback_module_root=target.rollback_module_root,
            rollback_wheel_sha256=target.rollback_wheel_sha256,
            rollback_source_commit=target.rollback_source_commit,
            chain_valid=current.chain_valid,
            evidence_sha256=_payload_digest(evidence),
            authority_receipt_sha256=target.authority_receipt_sha256,
            expires_at=target.expires_at,
        )

    def _claim(
        self,
        candidate: _Candidate,
        current: ReleaseRuntimeState,
    ) -> tuple[AuthenticatedReleaseAuthority, AuthenticatedArtifactMismatchReceipt]:
        path = self.paths.claims_root / f"{candidate.target.id}.json"
        if path.exists():
            try:
                value = json.loads(
                    _private_file(
                        path,
                        self.paths.claims_root,
                        "release_wake_claim",
                        _MAX_TARGET_BYTES,
                    ).decode("utf-8")
                )
                authority_material = value.get("authority")
                receipt_material = value.get("receipt")
                if (
                    not isinstance(value, dict)
                    or set(value)
                    != {
                        "schema_version",
                        "target_document_sha256",
                        "authority",
                        "authority_sha256",
                        "receipt",
                        "receipt_sha256",
                        "producer_prose_persisted",
                    }
                    or value.get("schema_version") != RELEASE_WAKE_CLAIM_VERSION
                    or value.get("target_document_sha256")
                    != _payload_digest(candidate.target.to_document())
                    or not isinstance(authority_material, dict)
                    or not isinstance(receipt_material, dict)
                    or value.get("authority_sha256")
                    != _payload_digest(authority_material)
                    or value.get("receipt_sha256") != _payload_digest(receipt_material)
                    or value.get("producer_prose_persisted") is not False
                ):
                    raise ValueError("claim binding mismatch")
                authority = AuthenticatedReleaseAuthority(**authority_material)
                receipt = AuthenticatedArtifactMismatchReceipt(**receipt_material)
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                TypeError,
                ValueError,
            ) as error:
                raise ReleaseWakeDenied("RELEASE_WAKE_CLAIM_MALFORMED") from error
            return authority, receipt
        authority = self._authority(candidate.target)
        receipt = self._receipt(candidate.target, current)
        authority_material = asdict(authority)
        receipt_material = asdict(receipt)
        _atomic_private_json(
            path,
            {
                "schema_version": RELEASE_WAKE_CLAIM_VERSION,
                "target_document_sha256": _payload_digest(
                    candidate.target.to_document()
                ),
                "authority": authority_material,
                "authority_sha256": _payload_digest(authority_material),
                "receipt": receipt_material,
                "receipt_sha256": _payload_digest(receipt_material),
                "producer_prose_persisted": False,
            },
        )
        return authority, receipt

    def _register(
        self,
        authority: AuthenticatedReleaseAuthority,
        receipt: AuthenticatedArtifactMismatchReceipt,
    ) -> None:
        authority_payload = {
            "schema_version": 1,
            "authority_id": authority.id,
            "authority_sha256": _payload_digest(asdict(authority)),
            "authority_receipt_sha256": authority.authority_receipt_sha256,
            "profile_name": authority.profile_name,
            "service_name": authority.service_name,
            "authenticated_by": "host_adapter",
            "model_callable": False,
        }
        authority_event, _ = self.store.append_once_result(
            "release.recovery.authority.installed", authority.id, authority_payload
        )
        if canonical_json(authority_event.payload) != canonical_json(authority_payload):
            raise ReleaseWakeDenied("RELEASE_WAKE_AUTHORITY_COLLISION")
        mismatch_payload = {
            "schema_version": 1,
            "receipt_id": receipt.id,
            "mismatch_receipt_sha256": _payload_digest(asdict(receipt)),
            "authority_receipt_sha256": receipt.authority_receipt_sha256,
            "profile_name": receipt.profile_name,
            "service_name": receipt.service_name,
            "authenticated_by": "host_adapter",
            "model_callable": False,
            "producer_prose_persisted": False,
        }
        mismatch_event, _ = self.store.append_once_result(
            "release.artifact_mismatch.observed", receipt.id, mismatch_payload
        )
        if canonical_json(mismatch_event.payload) != canonical_json(mismatch_payload):
            raise ReleaseWakeDenied("RELEASE_WAKE_MISMATCH_COLLISION")

    def run_once(
        self,
        *,
        max_scan: int = 8,
        fault_hook: FaultHook | None = None,
    ) -> dict[str, Any]:
        if isinstance(max_scan, bool) or not isinstance(max_scan, int) or not 1 <= max_scan <= 32:
            raise ValueError("max_scan must be between 1 and 32")
        with self._locked():
            secret = _private_file(
                self.paths.secret_file,
                self.paths.state_root,
                "authentication_secret",
                _MAX_TARGET_BYTES,
            )
            if len(secret) < 32:
                raise ReleaseWakeDenied("AUTHENTICATION_SECRET_INVALID")
            names = sorted(
                name
                for name in os.listdir(self.paths.inbox_root)
                if isinstance(name, str) and not name.startswith(".")
            )
            scanned = 0
            for name in names:
                if scanned >= max_scan:
                    break
                scanned += 1
                try:
                    candidate = self._read_candidate(name, secret)
                    now = _timestamp("current time", self.store.clock())
                    if (
                        _timestamp("target expiry", candidate.target.expires_at) <= now
                        or _timestamp(
                            "authority expiry", candidate.target.authority_expires_at
                        )
                        <= now
                    ):
                        raise ReleaseWakeDenied("RELEASE_WAKE_CANDIDATE_EXPIRED")
                except ReleaseWakeDenied as error:
                    if error.reason_code.startswith("RELEASE_WAKE_CANDIDATE_"):
                        if error.reason_code in {
                            "RELEASE_WAKE_CANDIDATE_SCHEMA_INVALID",
                            "RELEASE_WAKE_CANDIDATE_AUTHENTICATION_FAILED",
                            "RELEASE_WAKE_CANDIDATE_EXPIRED",
                        }:
                            body, identity = _private_file_snapshot(
                                self.paths.inbox_root / name,
                                self.paths.inbox_root,
                                "release_wake_candidate",
                                _MAX_TARGET_BYTES,
                            )
                            rejected = _CandidateFile(
                                name=name,
                                body=body,
                                identity=identity,
                                sha256=sha256(body).hexdigest(),
                            )
                            self._archive(rejected, accepted=False)
                        else:
                            self._quarantine_unreadable(name)
                        continue
                    raise
                current = self.adapter.inspect_runtime()
                if not isinstance(current, ReleaseRuntimeState) or not current.chain_valid:
                    raise ReleaseWakeDenied("RELEASE_WAKE_RUNTIME_INVALID")
                if self._matches_expected(
                    current, candidate.target
                ) and not self._claim_pending(candidate.target):
                    self._archive(candidate, accepted=True)
                    return {
                        "status": "already-live",
                        "target_id": candidate.target.id,
                        "emit": False,
                        "external_effects": 0,
                    }
                authority, receipt = self._claim(candidate, current)
                self._register(authority, receipt)
                if fault_hook is not None:
                    fault_hook("after-registration")
                result = self.bridge.recover(
                    receipt,
                    authority,
                    seed=candidate.target.seed,
                )
                if fault_hook is not None:
                    fault_hook("after-recovery")
                status = result.get("status")
                if status not in {"verified-live", "deferred"}:
                    raise ReleaseWakeDenied("RELEASE_WAKE_RECOVERY_RESULT_INVALID")
                self._archive(candidate, accepted=True)
                return {
                    **result,
                    "target_id": candidate.target.id,
                    "emit": status == "verified-live",
                }
            return {
                "status": "no-target",
                "emit": False,
                "external_effects": 0,
            }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one host-authenticated Generalist2 CCT release wake"
    )
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--wake-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--host-home-root", type=Path, required=True)
    parser.add_argument("--staging-root", type=Path, required=True)
    parser.add_argument("--adapter-state-root", type=Path, required=True)
    parser.add_argument("--expected-module-root", type=Path, required=True)
    parser.add_argument("--expected-package-version", required=True)
    parser.add_argument("--identity", default="Generalist2-CCT")
    parser.add_argument("--python-executable", type=Path, default=Path(sys.executable))
    parser.add_argument("--uv-executable", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    wake_root = args.wake_root.absolute()
    paths = ReleaseWakePaths(
        state_root=wake_root,
        inbox_root=wake_root / "inbox",
        completed_root=wake_root / "completed",
        rejected_root=wake_root / "rejected",
        claims_root=wake_root / "claims",
        bridge_state_root=wake_root / "bridge-state",
        secret_file=wake_root / "authentication.key",
    )
    profile_root = args.host_home_root / ".hermes" / "profiles" / GENERALIST2_PROFILE
    systemd_root = args.host_home_root / ".config" / "systemd" / "user"
    store = EventStore(args.state_root / "agency.sqlite")
    kernel = AgencyKernel(store, resolve_constitution(store, args.identity))
    kernel.initialize()
    config = Generalist2ReleaseHostConfig(
        repository_root=args.repository_root,
        host_home_root=args.host_home_root,
        profile_root=profile_root,
        staging_root=args.staging_root,
        adapter_state_root=args.adapter_state_root,
        systemd_user_root=systemd_root,
        dropin_path=systemd_root
        / f"{GENERALIST2_SERVICE}.d"
        / "cct-profile-local.conf",
        team_wrapper_path=profile_root / "scripts" / "cct_team_sync_tick.sh",
        proactive_wrapper_path=profile_root / "scripts" / "cct_proactive_tick.sh",
        database_path=args.state_root / "agency.sqlite",
        python_executable=args.python_executable,
        uv_executable=args.uv_executable,
    )
    adapter = Generalist2ReleaseHostAdapter(config)
    bridge = ReleaseRecoveryBridge(
        store,
        kernel=kernel,
        adapter=adapter,
        state_root=paths.bridge_state_root,
    )
    result = ReleaseWakeCoordinator(
        paths=paths,
        store=store,
        kernel=kernel,
        adapter=adapter,
        bridge=bridge,
        expected_module_root=args.expected_module_root,
        expected_package_version=args.expected_package_version,
    ).run_once()
    if args.json or result.get("emit") is True:
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


__all__ = [
    "RELEASE_WAKE_CLAIM_VERSION",
    "RELEASE_WAKE_TARGET_VERSION",
    "ReleaseWakeBridge",
    "ReleaseWakeCoordinator",
    "ReleaseWakeDenied",
    "ReleaseWakePaths",
    "ReleaseWakeTarget",
]


if __name__ == "__main__":
    raise SystemExit(main())
