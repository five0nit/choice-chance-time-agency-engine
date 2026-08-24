"""Expected-hash project patches with registered verification and exact rollback."""

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
from typing import Callable, Iterator, Literal, Mapping

from .store import Event, EventStore


PATCH_CLAIM_SCHEMA_VERSION = "cct.patch.claim.v1"
PATCH_RECEIPT_SCHEMA_VERSION = "cct.patch.receipt.v1"
MAX_PATCH_TARGETS = 64
MAX_PATCH_BYTES = 1_048_576
MAX_RELATIVE_PATH_BYTES = 1024
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+=,-]{0,254}$")


class PatchDenied(PermissionError):
    """Fail-closed patch denial with a stable reason code."""

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


def _relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("relative path must be a non-empty exact string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("relative path must be normalized ASCII") from error
    if len(encoded) > MAX_RELATIVE_PATH_BYTES:
        raise ValueError("relative path is too long")
    parts = value.split("/")
    if (
        value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
        or any(not _PATH_COMPONENT.fullmatch(part) for part in parts)
    ):
        raise ValueError("relative path must be normalized and stay inside workspace")
    return value


@dataclass(frozen=True, slots=True)
class PatchTarget:
    """Immutable host-owned patch target and verification binding."""

    id: str
    relative_path: str
    verifier_id: str
    max_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("target id", self.id))
        object.__setattr__(self, "relative_path", _relative_path(self.relative_path))
        object.__setattr__(self, "verifier_id", _identifier("verifier id", self.verifier_id))
        _bounded_integer(
            "max_bytes",
            self.max_bytes,
            minimum=1,
            maximum=MAX_PATCH_BYTES,
        )


@dataclass(frozen=True, slots=True)
class PatchRequest:
    """One hash-bound replacement. Replacement bytes remain transient."""

    id: str
    target_id: str
    expected_before_sha256: str
    replacement: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("request id", self.id))
        object.__setattr__(self, "target_id", _identifier("target id", self.target_id))
        object.__setattr__(
            self,
            "expected_before_sha256",
            _digest("expected_before_sha256", self.expected_before_sha256),
        )
        if not isinstance(self.replacement, bytes):
            raise ValueError("replacement must be exact bytes")


@dataclass(frozen=True, slots=True)
class PatchVerification:
    """Bounded result returned by one host-registered verifier."""

    passed: bool
    code: str

    def __post_init__(self) -> None:
        if not isinstance(self.passed, bool):
            raise ValueError("passed must be a boolean")
        object.__setattr__(self, "code", _identifier("verification code", self.code))


@dataclass(frozen=True, slots=True)
class PatchObservation:
    """Hash-only terminal patch receipt."""

    request_id: str
    target_id: str
    relative_path: str
    status: Literal["verified", "rolled_back", "rollback_blocked"]
    before_sha256: str
    after_sha256: str
    current_sha256: str
    verification_code: str
    stage_eligible: bool
    backup_retained: bool
    terminal_event_id: str
    replayed: bool
    replacement_persisted: bool = False
    backup_bytes_persisted_in_ledger: bool = False


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    content: bytes
    mode: int
    device: int
    inode: int

    @property
    def digest(self) -> str:
        return sha256(self.content).hexdigest()


Verifier = Callable[[Path], PatchVerification]


class ExpectedHashPatchAdapter:
    """Apply one registered file replacement, verify it, and retain exact rollback."""

    _TERMINAL_KINDS = (
        "patch.operation.verified",
        "patch.rollback.completed",
        "patch.rollback.blocked",
    )

    def __init__(
        self,
        store: EventStore,
        *,
        workspace_root: str | Path,
        state_root: str | Path,
        targets: tuple[PatchTarget, ...] | list[PatchTarget],
        verifiers: Mapping[str, Verifier],
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        root = Path(workspace_root)
        if not root.is_absolute() or root.is_symlink():
            raise ValueError("workspace_root must be an absolute real directory")
        try:
            resolved_root = root.resolve(strict=True)
            root_stat = resolved_root.stat()
        except OSError as error:
            raise ValueError("workspace_root must be an existing real directory") from error
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ValueError("workspace_root must be an existing real directory")

        state = Path(state_root)
        if not state.is_absolute():
            raise ValueError("state_root must be absolute")
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        if state.is_symlink():
            raise ValueError("state_root must not be a symlink")
        try:
            resolved_state = state.resolve(strict=True)
            if not resolved_state.is_dir():
                raise ValueError("state_root must be a directory")
            os.chmod(resolved_state, 0o700)
        except OSError as error:
            raise ValueError("state_root must be a private directory") from error

        if not isinstance(targets, (tuple, list)) or not targets:
            raise ValueError("targets must contain at least one PatchTarget")
        if len(targets) > MAX_PATCH_TARGETS:
            raise ValueError(f"targets must contain at most {MAX_PATCH_TARGETS} values")
        if not isinstance(verifiers, Mapping) or not verifiers:
            raise ValueError("verifiers must be a non-empty mapping")
        normalized_verifiers: dict[str, Verifier] = {}
        for raw_id, verifier in verifiers.items():
            verifier_id = _identifier("verifier id", raw_id)
            if verifier_id in normalized_verifiers or not callable(verifier):
                raise ValueError("verifier IDs must be unique callables")
            normalized_verifiers[verifier_id] = verifier

        registrations: dict[str, PatchTarget] = {}
        paths: set[str] = set()
        for target in targets:
            if not isinstance(target, PatchTarget):
                raise ValueError("targets must contain PatchTarget values")
            if target.id in registrations:
                raise ValueError("target IDs must be unique")
            if target.relative_path in paths:
                raise ValueError("target paths must be unique")
            if target.verifier_id not in normalized_verifiers:
                raise ValueError("target verifier is not registered")
            registrations[target.id] = target
            paths.add(target.relative_path)

        self.store = store
        self.workspace_root = resolved_root
        self.state_root = resolved_state
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        self._targets: Mapping[str, PatchTarget] = MappingProxyType(registrations)
        self._verifiers: Mapping[str, Verifier] = MappingProxyType(normalized_verifiers)
        self._lock_path = self.state_root / ".patch.lock"
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
            raise ValueError("patch state must be private and lockable") from error

    @property
    def registered_target_ids(self) -> frozenset[str]:
        return frozenset(self._targets)

    def apply(self, request: PatchRequest) -> PatchObservation:
        if not isinstance(request, PatchRequest):
            raise ValueError("request must be a PatchRequest")
        target = self._targets.get(request.target_id)
        if target is None:
            raise PatchDenied("TARGET_NOT_REGISTERED")
        if len(request.replacement) > target.max_bytes:
            raise PatchDenied("REPLACEMENT_TOO_LARGE")
        after_sha256 = sha256(request.replacement).hexdigest()
        claim_payload = {
            "schema_version": PATCH_CLAIM_SCHEMA_VERSION,
            "request_id": request.id,
            "target_id": target.id,
            "relative_path": target.relative_path,
            "verifier_id": target.verifier_id,
            "expected_before_sha256": request.expected_before_sha256,
            "replacement_sha256": after_sha256,
            "replacement_byte_count": len(request.replacement),
            "max_bytes": target.max_bytes,
            "replacement_persisted": False,
            "backup_bytes_persisted_in_ledger": False,
        }
        try:
            _claim, created = self.store.append_once_result(
                "patch.operation.claimed",
                request.id,
                claim_payload,
            )
        except ValueError as error:
            raise PatchDenied("REQUEST_COLLISION") from error
        except Exception as error:
            raise PatchDenied("CLAIM_PERSISTENCE_FAILED") from error

        with self._exclusive_lock():
            terminal = self._terminal_event(request.id)
            if terminal is not None:
                if terminal.kind == "patch.operation.verified":
                    snapshot = self._read_target(target)
                    if snapshot.digest != str(terminal.payload["after_sha256"]):
                        terminal = self._record_rollback_blocked(
                            request.id,
                            target,
                            before_sha256=str(terminal.payload["before_sha256"]),
                            after_sha256=str(terminal.payload["after_sha256"]),
                            current_sha256=snapshot.digest,
                            verification_code="FOREIGN_MUTATION",
                        )
                    else:
                        return self._observation(terminal, replayed=True)
                return self._observation(terminal, replayed=True)

            snapshot = self._read_target(target)
            applied_event = self._event_for_request("patch.operation.applied", request.id)
            verification_event = self._event_for_request(
                "patch.verification.recorded", request.id
            )

            if snapshot.digest == request.expected_before_sha256:
                if applied_event is not None and verification_event is not None:
                    if not bool(verification_event.payload["passed"]):
                        terminal = self._record_rollback_completed(
                            request.id,
                            target,
                            before_sha256=request.expected_before_sha256,
                            after_sha256=after_sha256,
                            verification_code=str(verification_event.payload["code"]),
                        )
                        self._delete_backup(request.id)
                        return self._observation(terminal, replayed=True)
                    raise PatchDenied("PATCH_STATE_INCONSISTENT")
                self._save_backup(request.id, snapshot)
                self._record_backup(request.id, target, snapshot)
                self._atomic_replace(
                    target,
                    expected_sha256=request.expected_before_sha256,
                    replacement=request.replacement,
                    mode=snapshot.mode,
                )
                applied_event = self._record_applied(
                    request.id,
                    target,
                    before_sha256=request.expected_before_sha256,
                    after_sha256=after_sha256,
                    byte_count=len(request.replacement),
                )
            elif snapshot.digest == after_sha256 and not created:
                backup = self._load_backup(request.id, request.expected_before_sha256)
                backup_event = self._event_for_request("patch.backup.recorded", request.id)
                if backup_event is None:
                    self._record_backup(request.id, target, backup)
                applied_event = self._record_applied(
                    request.id,
                    target,
                    before_sha256=request.expected_before_sha256,
                    after_sha256=after_sha256,
                    byte_count=len(request.replacement),
                )
            else:
                if created:
                    raise PatchDenied("EXPECTED_BEFORE_HASH_MISMATCH")
                terminal = self._record_rollback_blocked(
                    request.id,
                    target,
                    before_sha256=request.expected_before_sha256,
                    after_sha256=after_sha256,
                    current_sha256=snapshot.digest,
                    verification_code="FOREIGN_MUTATION",
                )
                return self._observation(terminal, replayed=True)

            if applied_event is None:
                raise PatchDenied("PATCH_STATE_INCONSISTENT")
            return self._verify_and_finish(
                request,
                target,
                after_sha256=after_sha256,
                replayed=not created,
                existing_verification=verification_event,
            )

    def rollback(self, request_id: str) -> PatchObservation:
        request_id = _identifier("request id", request_id)
        with self._exclusive_lock():
            terminal = self._terminal_event(request_id)
            if terminal is not None and terminal.kind != "patch.operation.verified":
                return self._observation(terminal, replayed=True)
            verified = self._event_for_request("patch.operation.verified", request_id)
            applied = self._event_for_request("patch.operation.applied", request_id)
            source = verified or applied
            if source is None:
                raise PatchDenied("PATCH_NOT_APPLIED")
            target_id = str(source.payload["target_id"])
            target = self._targets.get(target_id)
            if target is None or target.relative_path != source.payload["relative_path"]:
                raise PatchDenied("TARGET_REGISTRY_DRIFT")
            return self._rollback_locked(
                request_id,
                target,
                before_sha256=str(source.payload["before_sha256"]),
                after_sha256=str(source.payload["after_sha256"]),
                verification_code="EXPLICIT_ROLLBACK",
                replayed=False,
            )

    def require_verified(self, request_id: str) -> PatchObservation:
        request_id = _identifier("request id", request_id)
        with self._exclusive_lock():
            terminal = self._terminal_event(request_id)
            if terminal is None or terminal.kind != "patch.operation.verified":
                raise PatchDenied("PATCH_NOT_VERIFIED")
            target = self._targets.get(str(terminal.payload["target_id"]))
            if target is None or target.relative_path != terminal.payload["relative_path"]:
                raise PatchDenied("TARGET_REGISTRY_DRIFT")
            current = self._read_target(target)
            if current.digest != str(terminal.payload["after_sha256"]):
                self._record_rollback_blocked(
                    request_id,
                    target,
                    before_sha256=str(terminal.payload["before_sha256"]),
                    after_sha256=str(terminal.payload["after_sha256"]),
                    current_sha256=current.digest,
                    verification_code="FOREIGN_MUTATION",
                )
                raise PatchDenied("PATCH_TARGET_CHANGED")
            return self._observation(terminal, replayed=True)

    def _verify_and_finish(
        self,
        request: PatchRequest,
        target: PatchTarget,
        *,
        after_sha256: str,
        replayed: bool,
        existing_verification: Event | None,
    ) -> PatchObservation:
        verification = existing_verification
        if verification is None:
            before_verify = self._read_target(target)
            if before_verify.digest != after_sha256:
                terminal = self._record_rollback_blocked(
                    request.id,
                    target,
                    before_sha256=request.expected_before_sha256,
                    after_sha256=after_sha256,
                    current_sha256=before_verify.digest,
                    verification_code="FOREIGN_MUTATION",
                )
                return self._observation(terminal, replayed=replayed)
            try:
                result = self._verifiers[target.verifier_id](
                    self.workspace_root / target.relative_path
                )
            except Exception:
                result = PatchVerification(passed=False, code="VERIFIER_ERROR")
            if not isinstance(result, PatchVerification):
                result = PatchVerification(passed=False, code="VERIFIER_INVALID_RESULT")
            after_verify = self._read_target(target)
            if after_verify.digest != after_sha256:
                result = PatchVerification(
                    passed=False,
                    code="TARGET_CHANGED_DURING_VERIFICATION",
                )
            verification = self._record_verification(
                request.id,
                target,
                before_sha256=request.expected_before_sha256,
                after_sha256=after_sha256,
                result=result,
                observed_sha256=after_verify.digest,
            )
        if bool(verification.payload["passed"]):
            terminal = self._record_verified(
                request.id,
                target,
                before_sha256=request.expected_before_sha256,
                after_sha256=after_sha256,
                verification_code=str(verification.payload["code"]),
            )
            return self._observation(terminal, replayed=replayed)
        return self._rollback_locked(
            request.id,
            target,
            before_sha256=request.expected_before_sha256,
            after_sha256=after_sha256,
            verification_code=(
                "FOREIGN_MUTATION"
                if str(verification.payload["observed_sha256"]) != after_sha256
                else str(verification.payload["code"])
            ),
            replayed=replayed,
        )

    def _rollback_locked(
        self,
        request_id: str,
        target: PatchTarget,
        *,
        before_sha256: str,
        after_sha256: str,
        verification_code: str,
        replayed: bool,
    ) -> PatchObservation:
        current = self._read_target(target)
        if current.digest == after_sha256:
            backup = self._load_backup(request_id, before_sha256)
            self._atomic_replace(
                target,
                expected_sha256=after_sha256,
                replacement=backup.content,
                mode=backup.mode,
            )
            current = self._read_target(target)
        if current.digest == before_sha256:
            terminal = self._record_rollback_completed(
                request_id,
                target,
                before_sha256=before_sha256,
                after_sha256=after_sha256,
                verification_code=verification_code,
            )
            self._delete_backup(request_id)
            return self._observation(terminal, replayed=replayed)
        terminal = self._record_rollback_blocked(
            request_id,
            target,
            before_sha256=before_sha256,
            after_sha256=after_sha256,
            current_sha256=current.digest,
            verification_code="FOREIGN_MUTATION",
        )
        return self._observation(terminal, replayed=replayed)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        try:
            descriptor = os.open(
                self._lock_path,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as error:
            raise PatchDenied("PATCH_LOCK_UNAVAILABLE") from error
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @contextmanager
    def _parent_descriptor(self, target: PatchTarget) -> Iterator[tuple[int, str]]:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptors: list[int] = []
        try:
            root_fd = os.open(self.workspace_root, flags)
            descriptors.append(root_fd)
            root_stat = os.fstat(root_fd)
            if (root_stat.st_dev, root_stat.st_ino) != self._root_identity:
                raise PatchDenied("WORKSPACE_ROOT_CHANGED")
            parent_fd = root_fd
            parts = target.relative_path.split("/")
            for component in parts[:-1]:
                try:
                    next_fd = os.open(component, flags, dir_fd=parent_fd)
                except OSError as error:
                    if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise PatchDenied("TARGET_SYMLINK_DENIED") from error
                    raise PatchDenied("TARGET_PATH_UNAVAILABLE") from error
                descriptors.append(next_fd)
                parent_fd = next_fd
            yield parent_fd, parts[-1]
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _read_target(self, target: PatchTarget) -> _FileSnapshot:
        with self._parent_descriptor(target) as (parent_fd, name):
            return self._read_target_at(parent_fd, name, target.max_bytes)

    @staticmethod
    def _read_target_at(parent_fd: int, name: str, max_bytes: int) -> _FileSnapshot:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise PatchDenied("TARGET_SYMLINK_DENIED") from error
            raise PatchDenied("TARGET_PATH_UNAVAILABLE") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise PatchDenied("TARGET_NOT_REGULAR")
            if metadata.st_nlink != 1:
                raise PatchDenied("TARGET_LINK_COUNT_DENIED")
            if metadata.st_uid != os.getuid():
                raise PatchDenied("TARGET_OWNER_DENIED")
            if metadata.st_size > max_bytes:
                raise PatchDenied("TARGET_TOO_LARGE")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) > max_bytes:
                raise PatchDenied("TARGET_TOO_LARGE")
            path_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                path_metadata.st_dev != metadata.st_dev
                or path_metadata.st_ino != metadata.st_ino
            ):
                raise PatchDenied("TARGET_IDENTITY_CHANGED")
            return _FileSnapshot(
                content=content,
                mode=stat.S_IMODE(metadata.st_mode),
                device=metadata.st_dev,
                inode=metadata.st_ino,
            )
        finally:
            os.close(descriptor)

    def _atomic_replace(
        self,
        target: PatchTarget,
        *,
        expected_sha256: str,
        replacement: bytes,
        mode: int,
    ) -> None:
        if len(replacement) > target.max_bytes:
            raise PatchDenied("REPLACEMENT_TOO_LARGE")
        with self._parent_descriptor(target) as (parent_fd, name):
            baseline = self._read_target_at(parent_fd, name, target.max_bytes)
            if baseline.digest != expected_sha256:
                raise PatchDenied("TARGET_COMPARE_AND_SWAP_FAILED")
            temporary = f".cct-patch-{secrets.token_hex(16)}"
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
                os.fchmod(descriptor, mode)
                view = memoryview(replacement)
                written = 0
                while written < len(view):
                    written += os.write(descriptor, view[written:])
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                current = self._read_target_at(parent_fd, name, target.max_bytes)
                if (
                    current.digest != expected_sha256
                    or current.device != baseline.device
                    or current.inode != baseline.inode
                ):
                    raise PatchDenied("TARGET_COMPARE_AND_SWAP_FAILED")
                os.rename(
                    temporary,
                    name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.fsync(parent_fd)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass

    def _backup_path(self, request_id: str) -> Path:
        return self.state_root / f"{sha256(request_id.encode('utf-8')).hexdigest()}.bak"

    def _save_backup(self, request_id: str, snapshot: _FileSnapshot) -> None:
        path = self._backup_path(request_id)
        try:
            existing_fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            existing_fd = -1
        except OSError as error:
            raise PatchDenied("BACKUP_COLLISION") from error
        if existing_fd >= 0:
            try:
                metadata = os.fstat(existing_fd)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_uid != os.getuid()
                ):
                    raise PatchDenied("BACKUP_COLLISION")
                existing = self._read_bounded_descriptor(existing_fd, MAX_PATCH_BYTES)
                if sha256(existing).hexdigest() != snapshot.digest:
                    raise PatchDenied("BACKUP_COLLISION")
            finally:
                os.close(existing_fd)
            return
        temporary = self.state_root / f".backup-{secrets.token_hex(16)}"
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                view = memoryview(snapshot.content)
                written = 0
                while written < len(view):
                    written += os.write(descriptor, view[written:])
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
            os.chmod(path, 0o600)
            directory_fd = os.open(
                self.state_root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _load_backup(self, request_id: str, before_sha256: str) -> _FileSnapshot:
        path = self._backup_path(request_id)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            raise PatchDenied("BACKUP_UNAVAILABLE") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.getuid()
            ):
                raise PatchDenied("BACKUP_INVALID")
            content = self._read_bounded_descriptor(descriptor, MAX_PATCH_BYTES)
            if sha256(content).hexdigest() != before_sha256:
                raise PatchDenied("BACKUP_INVALID")
        finally:
            os.close(descriptor)
        backup_event = self._event_for_request("patch.backup.recorded", request_id)
        if backup_event is None:
            mode = 0o600
        else:
            mode = int(backup_event.payload["target_mode"])
        return _FileSnapshot(
            content=content,
            mode=mode,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )

    @staticmethod
    def _read_bounded_descriptor(descriptor: int, maximum: int) -> bytes:
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > maximum:
            raise PatchDenied("BACKUP_INVALID")
        return content

    def _delete_backup(self, request_id: str) -> None:
        try:
            self._backup_path(request_id).unlink()
        except FileNotFoundError:
            pass

    def _append_once(self, kind: str, request_id: str, payload: Mapping[str, object]) -> Event:
        try:
            event, _created = self.store.append_once_result(kind, request_id, payload)
        except ValueError as error:
            raise PatchDenied("PATCH_RECEIPT_COLLISION") from error
        except Exception as error:
            raise PatchDenied("PATCH_RECEIPT_PERSISTENCE_FAILED") from error
        return event

    def _record_backup(
        self,
        request_id: str,
        target: PatchTarget,
        snapshot: _FileSnapshot,
    ) -> Event:
        return self._append_once(
            "patch.backup.recorded",
            request_id,
            {
                "schema_version": PATCH_RECEIPT_SCHEMA_VERSION,
                "request_id": request_id,
                "target_id": target.id,
                "relative_path": target.relative_path,
                "before_sha256": snapshot.digest,
                "before_byte_count": len(snapshot.content),
                "target_mode": snapshot.mode,
                "backup_private": True,
                "backup_bytes_persisted_in_ledger": False,
            },
        )

    def _record_applied(
        self,
        request_id: str,
        target: PatchTarget,
        *,
        before_sha256: str,
        after_sha256: str,
        byte_count: int,
    ) -> Event:
        return self._append_once(
            "patch.operation.applied",
            request_id,
            {
                "schema_version": PATCH_RECEIPT_SCHEMA_VERSION,
                "request_id": request_id,
                "target_id": target.id,
                "relative_path": target.relative_path,
                "before_sha256": before_sha256,
                "after_sha256": after_sha256,
                "after_byte_count": byte_count,
                "replacement_persisted": False,
            },
        )

    def _record_verification(
        self,
        request_id: str,
        target: PatchTarget,
        *,
        before_sha256: str,
        after_sha256: str,
        result: PatchVerification,
        observed_sha256: str,
    ) -> Event:
        return self._append_once(
            "patch.verification.recorded",
            request_id,
            {
                "schema_version": PATCH_RECEIPT_SCHEMA_VERSION,
                "request_id": request_id,
                "target_id": target.id,
                "relative_path": target.relative_path,
                "verifier_id": target.verifier_id,
                "before_sha256": before_sha256,
                "after_sha256": after_sha256,
                "observed_sha256": observed_sha256,
                "passed": result.passed,
                "code": result.code,
            },
        )

    def _record_verified(
        self,
        request_id: str,
        target: PatchTarget,
        *,
        before_sha256: str,
        after_sha256: str,
        verification_code: str,
    ) -> Event:
        return self._append_once(
            "patch.operation.verified",
            request_id,
            self._terminal_payload(
                request_id,
                target,
                status="verified",
                before_sha256=before_sha256,
                after_sha256=after_sha256,
                current_sha256=after_sha256,
                verification_code=verification_code,
                stage_eligible=True,
                backup_retained=True,
            ),
        )

    def _record_rollback_completed(
        self,
        request_id: str,
        target: PatchTarget,
        *,
        before_sha256: str,
        after_sha256: str,
        verification_code: str,
    ) -> Event:
        return self._append_once(
            "patch.rollback.completed",
            request_id,
            self._terminal_payload(
                request_id,
                target,
                status="rolled_back",
                before_sha256=before_sha256,
                after_sha256=after_sha256,
                current_sha256=before_sha256,
                verification_code=verification_code,
                stage_eligible=False,
                backup_retained=False,
            ),
        )

    def _record_rollback_blocked(
        self,
        request_id: str,
        target: PatchTarget,
        *,
        before_sha256: str,
        after_sha256: str,
        current_sha256: str,
        verification_code: str,
    ) -> Event:
        return self._append_once(
            "patch.rollback.blocked",
            request_id,
            self._terminal_payload(
                request_id,
                target,
                status="rollback_blocked",
                before_sha256=before_sha256,
                after_sha256=after_sha256,
                current_sha256=current_sha256,
                verification_code=verification_code,
                stage_eligible=False,
                backup_retained=self._backup_path(request_id).exists(),
            ),
        )

    @staticmethod
    def _terminal_payload(
        request_id: str,
        target: PatchTarget,
        *,
        status: str,
        before_sha256: str,
        after_sha256: str,
        current_sha256: str,
        verification_code: str,
        stage_eligible: bool,
        backup_retained: bool,
    ) -> dict[str, object]:
        return {
            "schema_version": PATCH_RECEIPT_SCHEMA_VERSION,
            "request_id": request_id,
            "target_id": target.id,
            "relative_path": target.relative_path,
            "status": status,
            "before_sha256": before_sha256,
            "after_sha256": after_sha256,
            "current_sha256": current_sha256,
            "verification_code": verification_code,
            "stage_eligible": stage_eligible,
            "backup_retained": backup_retained,
            "replacement_persisted": False,
            "backup_bytes_persisted_in_ledger": False,
        }

    def _event_for_request(self, kind: str, request_id: str) -> Event | None:
        return next(
            (
                event
                for event in reversed(self.store.events(kind))
                if event.payload.get("request_id") == request_id
            ),
            None,
        )

    def _terminal_event(self, request_id: str) -> Event | None:
        candidates = [
            event
            for kind in self._TERMINAL_KINDS
            for event in self.store.events(kind)
            if event.payload.get("request_id") == request_id
        ]
        return max(candidates, key=lambda event: event.seq) if candidates else None

    @staticmethod
    def _observation(event: Event, *, replayed: bool) -> PatchObservation:
        payload = event.payload
        return PatchObservation(
            request_id=str(payload["request_id"]),
            target_id=str(payload["target_id"]),
            relative_path=str(payload["relative_path"]),
            status=str(payload["status"]),  # type: ignore[arg-type]
            before_sha256=str(payload["before_sha256"]),
            after_sha256=str(payload["after_sha256"]),
            current_sha256=str(payload["current_sha256"]),
            verification_code=str(payload["verification_code"]),
            stage_eligible=bool(payload["stage_eligible"]),
            backup_retained=bool(payload["backup_retained"]),
            terminal_event_id=event.event_id,
            replayed=replayed,
        )
