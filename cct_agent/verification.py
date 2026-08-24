"""Host-registered test/build verification bound to plan, stage, and project snapshot."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Literal, Mapping

from .commands import (
    BoundedCommandAdapter,
    CommandDenied,
    CommandObservation,
    CommandRequest,
    CommandSpec,
)
from .store import Event, EventStore, canonical_json


VERIFICATION_CLAIM_SCHEMA_VERSION = "cct.verification.claim.v1"
VERIFICATION_RECEIPT_SCHEMA_VERSION = "cct.verification.receipt.v1"
MAX_VERIFIERS = 64
MAX_SNAPSHOT_FILES = 256
MAX_SNAPSHOT_PATH_BYTES = 1024
MAX_SNAPSHOT_FILE_BYTES = 16_777_216
MAX_SNAPSHOT_TOTAL_BYTES = 67_108_864
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+=,-]{0,254}$")


class VerificationDenied(PermissionError):
    """Fail-closed verifier denial with stable reason code."""

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
        raise ValueError("snapshot path must be a non-empty exact string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("snapshot path must be normalized ASCII") from error
    parts = value.split("/")
    if (
        len(encoded) > MAX_SNAPSHOT_PATH_BYTES
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
        or any(not _PATH_COMPONENT.fullmatch(part) for part in parts)
    ):
        raise ValueError("snapshot path must be normalized and stay inside workspace")
    return value


@dataclass(frozen=True, slots=True)
class ProjectSnapshot:
    """Hash-only manifest for one bounded host-selected source snapshot."""

    sha256: str
    files: tuple[dict[str, object], ...]
    total_bytes: int


@dataclass(frozen=True, slots=True)
class VerifierSpec:
    """Immutable host-owned test/build policy; callers select only its ID."""

    id: str
    kind: Literal["test", "build"]
    plan_id: str
    plan_sha256: str
    stage_id: str
    command: CommandSpec
    snapshot_paths: tuple[str, ...]
    max_snapshot_file_bytes: int
    max_snapshot_total_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("verifier id", self.id))
        if self.kind not in {"test", "build"}:
            raise ValueError("verifier kind must be test or build")
        object.__setattr__(self, "plan_id", _identifier("plan id", self.plan_id))
        object.__setattr__(
            self,
            "plan_sha256",
            _digest("plan_sha256", self.plan_sha256),
        )
        object.__setattr__(self, "stage_id", _identifier("stage id", self.stage_id))
        if not isinstance(self.command, CommandSpec):
            raise ValueError("command must be a CommandSpec")
        if not isinstance(self.snapshot_paths, tuple):
            raise ValueError("snapshot_paths must be an immutable tuple")
        if not 1 <= len(self.snapshot_paths) <= MAX_SNAPSHOT_FILES:
            raise ValueError(
                f"snapshot_paths must contain 1-{MAX_SNAPSHOT_FILES} paths"
            )
        normalized = tuple(_relative_path(path) for path in self.snapshot_paths)
        if len(normalized) != len(set(normalized)):
            raise ValueError("snapshot_paths must be unique")
        object.__setattr__(self, "snapshot_paths", tuple(sorted(normalized)))
        _bounded_integer(
            "max_snapshot_file_bytes",
            self.max_snapshot_file_bytes,
            minimum=1,
            maximum=MAX_SNAPSHOT_FILE_BYTES,
        )
        _bounded_integer(
            "max_snapshot_total_bytes",
            self.max_snapshot_total_bytes,
            minimum=1,
            maximum=MAX_SNAPSHOT_TOTAL_BYTES,
        )
        if self.max_snapshot_file_bytes > self.max_snapshot_total_bytes:
            raise ValueError("snapshot file limit cannot exceed total limit")


@dataclass(frozen=True, slots=True)
class VerificationRequest:
    """One exact plan/stage/snapshot-bound verifier request."""

    id: str
    verifier_id: str
    plan_id: str
    plan_sha256: str
    stage_id: str
    expected_snapshot_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("request id", self.id))
        object.__setattr__(
            self,
            "verifier_id",
            _identifier("verifier id", self.verifier_id),
        )
        object.__setattr__(self, "plan_id", _identifier("plan id", self.plan_id))
        object.__setattr__(
            self,
            "plan_sha256",
            _digest("plan_sha256", self.plan_sha256),
        )
        object.__setattr__(self, "stage_id", _identifier("stage id", self.stage_id))
        object.__setattr__(
            self,
            "expected_snapshot_sha256",
            _digest(
                "expected_snapshot_sha256",
                self.expected_snapshot_sha256,
            ),
        )


@dataclass(frozen=True, slots=True)
class VerificationObservation:
    """Transient bounded output plus durable structured verification receipt."""

    request_id: str
    verifier_id: str
    verifier_spec_sha256: str
    kind: Literal["test", "build"]
    plan_id: str
    plan_sha256: str
    stage_id: str
    status: Literal["passed", "failed"]
    reason_code: str
    snapshot_before_sha256: str
    snapshot_after_sha256: str
    command_receipt_event_id: str
    argv_sha256: str
    exit_status: int | None
    termination_reason: str
    stdout_byte_count: int
    stdout_sha256: str
    stderr_byte_count: int
    stderr_sha256: str
    duration_ms: int
    stage_eligible: bool
    plan_status: Literal["verified", "failed"]
    required_action: Literal["advance", "rollback"]
    deployment_eligible: bool
    public_action_eligible: bool
    terminal_event_id: str
    replayed: bool
    stdout: bytes | None
    stderr: bytes | None
    output_persisted: bool = False
    project_content_persisted: bool = False


@dataclass(frozen=True, slots=True)
class _RegisteredVerifier:
    spec: VerifierSpec
    spec_sha256: str


class HostRegisteredVerifier:
    """Run immutable test/build commands only for exact registered project state."""

    def __init__(
        self,
        store: EventStore,
        *,
        workspace_root: str | Path,
        verifiers: tuple[VerifierSpec, ...] | list[VerifierSpec],
        allowed_executables: frozenset[str | Path] | set[str | Path],
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
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != os.getuid()
        ):
            raise ValueError("workspace_root must be an owned real directory")
        if not isinstance(verifiers, (tuple, list)) or not verifiers:
            raise ValueError("verifiers must contain at least one VerifierSpec")
        if len(verifiers) > MAX_VERIFIERS:
            raise ValueError(f"verifiers must contain at most {MAX_VERIFIERS} values")

        registrations: dict[str, _RegisteredVerifier] = {}
        command_ids: set[str] = set()
        for spec in verifiers:
            if not isinstance(spec, VerifierSpec):
                raise ValueError("verifiers must contain VerifierSpec values")
            if spec.id in registrations:
                raise ValueError("verifier IDs must be unique")
            if spec.command.id in command_ids:
                raise ValueError("verifier command IDs must be unique")
            spec_payload = {
                "id": spec.id,
                "kind": spec.kind,
                "plan_id": spec.plan_id,
                "plan_sha256": spec.plan_sha256,
                "stage_id": spec.stage_id,
                "command": {
                    "id": spec.command.id,
                    "argv": list(spec.command.argv),
                    "cwd": spec.command.cwd,
                    "environment": [list(item) for item in spec.command.environment],
                    "timeout_ms": spec.command.timeout_ms,
                    "max_stdout_bytes": spec.command.max_stdout_bytes,
                    "max_stderr_bytes": spec.command.max_stderr_bytes,
                },
                "snapshot_paths": list(spec.snapshot_paths),
                "max_snapshot_file_bytes": spec.max_snapshot_file_bytes,
                "max_snapshot_total_bytes": spec.max_snapshot_total_bytes,
            }
            registrations[spec.id] = _RegisteredVerifier(
                spec=spec,
                spec_sha256=sha256(
                    canonical_json(spec_payload).encode("utf-8")
                ).hexdigest(),
            )
            command_ids.add(spec.command.id)

        self.store = store
        self.workspace_root = resolved_root
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        self._verifiers: Mapping[str, _RegisteredVerifier] = MappingProxyType(
            registrations
        )
        self._commands = BoundedCommandAdapter(
            store,
            workspace_root=resolved_root,
            commands=tuple(row.spec.command for row in registrations.values()),
            allowed_executables=allowed_executables,
        )
        for verifier_id in self._verifiers:
            try:
                self._snapshot(self._verifiers[verifier_id].spec)
            except VerificationDenied as error:
                raise ValueError(
                    f"snapshot registration invalid: {error.reason_code}"
                ) from error

    @property
    def registered_ids(self) -> frozenset[str]:
        return frozenset(self._verifiers)

    def snapshot(self, verifier_id: str) -> ProjectSnapshot:
        verifier_id = _identifier("verifier id", verifier_id)
        registration = self._verifiers.get(verifier_id)
        if registration is None:
            raise VerificationDenied("VERIFIER_NOT_REGISTERED")
        return self._snapshot(registration.spec)

    def execute(self, request: VerificationRequest) -> VerificationObservation:
        if not isinstance(request, VerificationRequest):
            raise ValueError("request must be a VerificationRequest")
        if self.store.verify_chain().get("valid") is not True:
            raise VerificationDenied("LEDGER_CHAIN_INVALID")
        registration = self._verifiers.get(request.verifier_id)
        if registration is None:
            raise VerificationDenied("VERIFIER_NOT_REGISTERED")
        spec = registration.spec
        if (
            request.plan_id != spec.plan_id
            or request.plan_sha256 != spec.plan_sha256
            or request.stage_id != spec.stage_id
        ):
            raise VerificationDenied("REQUEST_BINDING_MISMATCH")

        terminal = self._terminal_event(request.id)
        if terminal is not None:
            observation = self._observation_from_event(
                terminal,
                stdout=None,
                stderr=None,
                replayed=True,
            )
            self._validate_terminal_binding(observation, registration)
            if observation.status == "passed":
                current = self._snapshot(spec)
                if current.sha256 != observation.snapshot_after_sha256:
                    raise VerificationDenied("PROJECT_SNAPSHOT_STALE")
            return observation

        claim = self._claim_event(request.id)
        claim_created = False
        if claim is None:
            snapshot_before = self._snapshot(spec)
            if snapshot_before.sha256 != request.expected_snapshot_sha256:
                raise VerificationDenied("PROJECT_SNAPSHOT_MISMATCH")
            claim_payload = self._claim_payload(
                request,
                registration,
                snapshot_before,
            )
            try:
                claim, claim_created = self.store.append_once_result(
                    "verification.run.claimed",
                    request.id,
                    claim_payload,
                )
            except ValueError as error:
                raise VerificationDenied("REQUEST_COLLISION") from error
            except Exception as error:
                raise VerificationDenied("CLAIM_PERSISTENCE_FAILED") from error
        snapshot_before = self._snapshot_from_claim(claim, request, registration)

        command_request_id = str(claim.payload["command_request_id"])
        try:
            command = self._commands.execute(
                CommandRequest(
                    id=command_request_id,
                    command_id=spec.command.id,
                )
            )
        except CommandDenied as error:
            raise VerificationDenied(f"VERIFIER_{error.reason_code}") from error
        snapshot_after = self._snapshot(spec)
        terminal, terminal_created = self._record_completion(
            request,
            registration,
            claim,
            snapshot_before,
            snapshot_after,
            command,
        )
        return self._observation_from_event(
            terminal,
            stdout=command.stdout,
            stderr=command.stderr,
            replayed=(
                not claim_created
                or command.replayed
                or not terminal_created
            ),
        )

    def require_passed(self, request_id: str) -> VerificationObservation:
        request_id = _identifier("request id", request_id)
        if self.store.verify_chain().get("valid") is not True:
            raise VerificationDenied("LEDGER_CHAIN_INVALID")
        terminal = self._terminal_event(request_id)
        if terminal is None:
            raise VerificationDenied("VERIFICATION_NOT_COMPLETED")
        observation = self._observation_from_event(
            terminal,
            stdout=None,
            stderr=None,
            replayed=True,
        )
        registration = self._verifiers.get(observation.verifier_id)
        if registration is None:
            raise VerificationDenied("VERIFIER_REGISTRY_DRIFT")
        self._validate_terminal_binding(observation, registration)
        if observation.status != "passed" or not observation.stage_eligible:
            raise VerificationDenied("VERIFICATION_NOT_PASSED")
        current = self._snapshot(registration.spec)
        if current.sha256 != observation.snapshot_after_sha256:
            raise VerificationDenied("PROJECT_SNAPSHOT_STALE")
        return observation

    def _claim_payload(
        self,
        request: VerificationRequest,
        registration: _RegisteredVerifier,
        snapshot: ProjectSnapshot,
    ) -> dict[str, object]:
        spec = registration.spec
        command_request_id = "verification-command:" + sha256(
            request.id.encode("utf-8")
        ).hexdigest()
        return {
            "schema_version": VERIFICATION_CLAIM_SCHEMA_VERSION,
            "request_id": request.id,
            "verifier_id": spec.id,
            "verifier_kind": spec.kind,
            "verifier_spec_sha256": registration.spec_sha256,
            "plan_id": request.plan_id,
            "plan_sha256": request.plan_sha256,
            "stage_id": request.stage_id,
            "expected_snapshot_sha256": request.expected_snapshot_sha256,
            "snapshot_before_sha256": snapshot.sha256,
            "snapshot_files": list(snapshot.files),
            "snapshot_total_bytes": snapshot.total_bytes,
            "command_id": spec.command.id,
            "command_request_id": command_request_id,
            "project_content_persisted": False,
            "raw_command_persisted": False,
            "environment_values_persisted": False,
        }

    def _snapshot_from_claim(
        self,
        claim: Event,
        request: VerificationRequest,
        registration: _RegisteredVerifier,
    ) -> ProjectSnapshot:
        payload = claim.payload
        files = payload.get("snapshot_files")
        total_bytes = payload.get("snapshot_total_bytes")
        if (
            payload.get("schema_version") != VERIFICATION_CLAIM_SCHEMA_VERSION
            or payload.get("request_id") != request.id
            or payload.get("verifier_id") != request.verifier_id
            or payload.get("verifier_kind") != registration.spec.kind
            or payload.get("verifier_spec_sha256") != registration.spec_sha256
            or payload.get("plan_id") != request.plan_id
            or payload.get("plan_sha256") != request.plan_sha256
            or payload.get("stage_id") != request.stage_id
            or payload.get("expected_snapshot_sha256")
            != request.expected_snapshot_sha256
            or payload.get("snapshot_before_sha256")
            != request.expected_snapshot_sha256
            or payload.get("command_id") != registration.spec.command.id
            or payload.get("project_content_persisted") is not False
            or payload.get("raw_command_persisted") is not False
            or payload.get("environment_values_persisted") is not False
            or not isinstance(payload.get("command_request_id"), str)
            or not isinstance(files, list)
            or not 1 <= len(files) <= MAX_SNAPSHOT_FILES
            or isinstance(total_bytes, bool)
            or not isinstance(total_bytes, int)
            or total_bytes < 0
        ):
            raise VerificationDenied("MALFORMED_CLAIM_RECEIPT")
        normalized: list[dict[str, object]] = []
        calculated_total = 0
        for row in files:
            if not isinstance(row, Mapping):
                raise VerificationDenied("MALFORMED_CLAIM_RECEIPT")
            path = row.get("relative_path")
            byte_count = row.get("byte_count")
            digest = row.get("sha256")
            if (
                not isinstance(path, str)
                or path not in registration.spec.snapshot_paths
                or isinstance(byte_count, bool)
                or not isinstance(byte_count, int)
                or byte_count < 0
                or not isinstance(digest, str)
                or not _DIGEST.fullmatch(digest)
            ):
                raise VerificationDenied("MALFORMED_CLAIM_RECEIPT")
            normalized.append(
                {
                    "relative_path": path,
                    "byte_count": byte_count,
                    "sha256": digest,
                }
            )
            calculated_total += byte_count
        if (
            [row["relative_path"] for row in normalized]
            != list(registration.spec.snapshot_paths)
            or calculated_total != total_bytes
        ):
            raise VerificationDenied("MALFORMED_CLAIM_RECEIPT")
        calculated_digest = sha256(
            canonical_json(normalized).encode("utf-8")
        ).hexdigest()
        if calculated_digest != request.expected_snapshot_sha256:
            raise VerificationDenied("MALFORMED_CLAIM_RECEIPT")
        return ProjectSnapshot(
            sha256=calculated_digest,
            files=tuple(normalized),
            total_bytes=calculated_total,
        )

    def _record_completion(
        self,
        request: VerificationRequest,
        registration: _RegisteredVerifier,
        claim: Event,
        snapshot_before: ProjectSnapshot,
        snapshot_after: ProjectSnapshot,
        command: CommandObservation,
    ) -> tuple[Event, bool]:
        if snapshot_after.sha256 != snapshot_before.sha256:
            passed = False
            reason_code = "PROJECT_CHANGED_DURING_VERIFICATION"
        elif command.termination_reason == "exited" and command.exit_status == 0:
            passed = True
            reason_code = "VERIFICATION_PASSED"
        else:
            passed = False
            reasons = {
                "timeout": "VERIFIER_TIMEOUT",
                "stdout_limit": "VERIFIER_STDOUT_LIMIT",
                "stderr_limit": "VERIFIER_STDERR_LIMIT",
                "spawn_error": "VERIFIER_SPAWN_ERROR",
                "exited": "VERIFIER_EXIT_NONZERO",
            }
            reason_code = reasons.get(
                command.termination_reason,
                "VERIFIER_INVALID_TERMINATION",
            )
        status = "passed" if passed else "failed"
        plan_status = "verified" if passed else "failed"
        required_action = "advance" if passed else "rollback"
        payload = {
            "schema_version": VERIFICATION_RECEIPT_SCHEMA_VERSION,
            "request_id": request.id,
            "claim_event_id": claim.event_id,
            "verifier_id": registration.spec.id,
            "verifier_kind": registration.spec.kind,
            "verifier_spec_sha256": registration.spec_sha256,
            "plan_id": request.plan_id,
            "plan_sha256": request.plan_sha256,
            "stage_id": request.stage_id,
            "status": status,
            "reason_code": reason_code,
            "snapshot_before_sha256": snapshot_before.sha256,
            "snapshot_after_sha256": snapshot_after.sha256,
            "snapshot_after_files": list(snapshot_after.files),
            "snapshot_after_total_bytes": snapshot_after.total_bytes,
            "command_receipt_event_id": command.receipt_event_id,
            "argv_sha256": command.argv_sha256,
            "exit_status": command.exit_status,
            "termination_reason": command.termination_reason,
            "stdout_byte_count": command.stdout_byte_count,
            "stdout_sha256": command.stdout_sha256,
            "stderr_byte_count": command.stderr_byte_count,
            "stderr_sha256": command.stderr_sha256,
            "duration_ms": command.duration_ms,
            "stage_eligible": passed,
            "plan_status": plan_status,
            "plan_transition": {
                "from": "verifying",
                "to": plan_status,
            },
            "required_action": required_action,
            "deployment_eligible": passed,
            "public_action_eligible": passed,
            "output_persisted": False,
            "project_content_persisted": False,
        }
        try:
            event, created = self.store.append_once_result(
                "verification.run.completed",
                request.id,
                payload,
            )
        except ValueError as error:
            raise VerificationDenied("COMPLETION_RECEIPT_COLLISION") from error
        except Exception as error:
            raise VerificationDenied("RECEIPT_PERSISTENCE_FAILED") from error
        if canonical_json(event.payload) != canonical_json(payload):
            raise VerificationDenied("COMPLETION_RECEIPT_COLLISION")
        return event, created

    def _claim_event(self, request_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("verification.run.claimed")
            if event.payload.get("request_id") == request_id
        ]
        if len(rows) > 1:
            raise VerificationDenied("DUPLICATE_CLAIM_RECEIPTS")
        return rows[0] if rows else None

    def _terminal_event(self, request_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("verification.run.completed")
            if event.payload.get("request_id") == request_id
        ]
        if len(rows) > 1:
            raise VerificationDenied("DUPLICATE_COMPLETION_RECEIPTS")
        return rows[0] if rows else None

    @staticmethod
    def _validate_terminal_binding(
        observation: VerificationObservation,
        registration: _RegisteredVerifier,
    ) -> None:
        spec = registration.spec
        if (
            observation.verifier_id != spec.id
            or observation.verifier_spec_sha256 != registration.spec_sha256
            or observation.kind != spec.kind
            or observation.plan_id != spec.plan_id
            or observation.plan_sha256 != spec.plan_sha256
            or observation.stage_id != spec.stage_id
        ):
            raise VerificationDenied("VERIFIER_REGISTRY_DRIFT")

    @staticmethod
    def _observation_from_event(
        event: Event,
        *,
        stdout: bytes | None,
        stderr: bytes | None,
        replayed: bool,
    ) -> VerificationObservation:
        payload = event.payload
        required = {
            "schema_version",
            "request_id",
            "claim_event_id",
            "verifier_id",
            "verifier_kind",
            "verifier_spec_sha256",
            "plan_id",
            "plan_sha256",
            "stage_id",
            "status",
            "reason_code",
            "snapshot_before_sha256",
            "snapshot_after_sha256",
            "snapshot_after_files",
            "snapshot_after_total_bytes",
            "command_receipt_event_id",
            "argv_sha256",
            "exit_status",
            "termination_reason",
            "stdout_byte_count",
            "stdout_sha256",
            "stderr_byte_count",
            "stderr_sha256",
            "duration_ms",
            "stage_eligible",
            "plan_status",
            "plan_transition",
            "required_action",
            "deployment_eligible",
            "public_action_eligible",
            "output_persisted",
            "project_content_persisted",
        }
        integer_fields = (
            "snapshot_after_total_bytes",
            "stdout_byte_count",
            "stderr_byte_count",
            "duration_ms",
        )
        digest_fields = (
            "verifier_spec_sha256",
            "plan_sha256",
            "snapshot_before_sha256",
            "snapshot_after_sha256",
            "argv_sha256",
            "stdout_sha256",
            "stderr_sha256",
        )
        if (
            set(payload) != required
            or payload.get("schema_version") != VERIFICATION_RECEIPT_SCHEMA_VERSION
            or payload.get("verifier_kind") not in {"test", "build"}
            or payload.get("status") not in {"passed", "failed"}
            or payload.get("plan_status") not in {"verified", "failed"}
            or payload.get("required_action") not in {"advance", "rollback"}
            or any(
                not isinstance(payload.get(field), str)
                for field in (
                    "request_id",
                    "claim_event_id",
                    "verifier_id",
                    "plan_id",
                    "stage_id",
                    "reason_code",
                    "command_receipt_event_id",
                    "termination_reason",
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
            or (
                payload.get("exit_status") is not None
                and (
                    isinstance(payload.get("exit_status"), bool)
                    or not isinstance(payload.get("exit_status"), int)
                )
            )
            or not isinstance(payload.get("snapshot_after_files"), list)
            or payload.get("stage_eligible")
            is not (payload.get("status") == "passed")
            or payload.get("deployment_eligible")
            is not (payload.get("status") == "passed")
            or payload.get("public_action_eligible")
            is not (payload.get("status") == "passed")
            or payload.get("output_persisted") is not False
            or payload.get("project_content_persisted") is not False
        ):
            raise VerificationDenied("MALFORMED_COMPLETION_RECEIPT")
        snapshot_files = payload["snapshot_after_files"]
        normalized_snapshot_files: list[dict[str, object]] = []
        snapshot_total_bytes = 0
        for row in snapshot_files:
            if not isinstance(row, Mapping) or set(row) != {
                "relative_path",
                "byte_count",
                "sha256",
            }:
                raise VerificationDenied("MALFORMED_COMPLETION_RECEIPT")
            relative_path = row.get("relative_path")
            byte_count = row.get("byte_count")
            file_sha256 = row.get("sha256")
            if (
                not isinstance(relative_path, str)
                or isinstance(byte_count, bool)
                or not isinstance(byte_count, int)
                or byte_count < 0
                or not isinstance(file_sha256, str)
                or not _DIGEST.fullmatch(file_sha256)
            ):
                raise VerificationDenied("MALFORMED_COMPLETION_RECEIPT")
            normalized_snapshot_files.append(
                {
                    "relative_path": relative_path,
                    "byte_count": byte_count,
                    "sha256": file_sha256,
                }
            )
            snapshot_total_bytes += byte_count
        relative_paths = [
            str(row["relative_path"]) for row in normalized_snapshot_files
        ]
        if (
            not normalized_snapshot_files
            or relative_paths != sorted(set(relative_paths))
            or snapshot_total_bytes != payload["snapshot_after_total_bytes"]
            or sha256(
                canonical_json(normalized_snapshot_files).encode("utf-8")
            ).hexdigest()
            != payload["snapshot_after_sha256"]
        ):
            raise VerificationDenied("MALFORMED_COMPLETION_RECEIPT")
        expected_plan_status = (
            "verified" if payload["status"] == "passed" else "failed"
        )
        expected_action = "advance" if payload["status"] == "passed" else "rollback"
        if (
            payload.get("plan_status") != expected_plan_status
            or payload.get("required_action") != expected_action
            or payload.get("plan_transition")
            != {"from": "verifying", "to": expected_plan_status}
        ):
            raise VerificationDenied("MALFORMED_COMPLETION_RECEIPT")
        if stdout is not None and (
            len(stdout) != payload["stdout_byte_count"]
            or sha256(stdout).hexdigest() != payload["stdout_sha256"]
        ):
            raise VerificationDenied("OUTPUT_RECEIPT_MISMATCH")
        if stderr is not None and (
            len(stderr) != payload["stderr_byte_count"]
            or sha256(stderr).hexdigest() != payload["stderr_sha256"]
        ):
            raise VerificationDenied("OUTPUT_RECEIPT_MISMATCH")
        return VerificationObservation(
            request_id=str(payload["request_id"]),
            verifier_id=str(payload["verifier_id"]),
            verifier_spec_sha256=str(payload["verifier_spec_sha256"]),
            kind=payload["verifier_kind"],
            plan_id=str(payload["plan_id"]),
            plan_sha256=str(payload["plan_sha256"]),
            stage_id=str(payload["stage_id"]),
            status=payload["status"],
            reason_code=str(payload["reason_code"]),
            snapshot_before_sha256=str(payload["snapshot_before_sha256"]),
            snapshot_after_sha256=str(payload["snapshot_after_sha256"]),
            command_receipt_event_id=str(payload["command_receipt_event_id"]),
            argv_sha256=str(payload["argv_sha256"]),
            exit_status=payload["exit_status"],
            termination_reason=str(payload["termination_reason"]),
            stdout_byte_count=int(payload["stdout_byte_count"]),
            stdout_sha256=str(payload["stdout_sha256"]),
            stderr_byte_count=int(payload["stderr_byte_count"]),
            stderr_sha256=str(payload["stderr_sha256"]),
            duration_ms=int(payload["duration_ms"]),
            stage_eligible=bool(payload["stage_eligible"]),
            plan_status=payload["plan_status"],
            required_action=payload["required_action"],
            deployment_eligible=bool(payload["deployment_eligible"]),
            public_action_eligible=bool(payload["public_action_eligible"]),
            terminal_event_id=event.event_id,
            replayed=replayed,
            stdout=stdout,
            stderr=stderr,
        )

    def _snapshot(self, spec: VerifierSpec) -> ProjectSnapshot:
        files: list[dict[str, object]] = []
        total_bytes = 0
        for relative_path in spec.snapshot_paths:
            content = self._read_snapshot_file(
                relative_path,
                max_bytes=spec.max_snapshot_file_bytes,
            )
            total_bytes += len(content)
            if total_bytes > spec.max_snapshot_total_bytes:
                raise VerificationDenied("SNAPSHOT_TOTAL_LIMIT_EXCEEDED")
            files.append(
                {
                    "relative_path": relative_path,
                    "byte_count": len(content),
                    "sha256": sha256(content).hexdigest(),
                }
            )
        snapshot_sha256 = sha256(
            canonical_json(files).encode("utf-8")
        ).hexdigest()
        return ProjectSnapshot(
            sha256=snapshot_sha256,
            files=tuple(files),
            total_bytes=total_bytes,
        )

    def _read_snapshot_file(self, relative_path: str, *, max_bytes: int) -> bytes:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        root_fd = -1
        directory_fd = -1
        file_fd = -1
        try:
            root_fd = os.open(
                self.workspace_root,
                flags | os.O_DIRECTORY,
            )
            root_stat = os.fstat(root_fd)
            if (root_stat.st_dev, root_stat.st_ino) != self._root_identity:
                raise VerificationDenied("WORKSPACE_ROOT_CHANGED")
            directory_fd = root_fd
            parts = relative_path.split("/")
            for component in parts[:-1]:
                next_fd = os.open(
                    component,
                    flags | os.O_DIRECTORY,
                    dir_fd=directory_fd,
                )
                descriptor = os.fstat(next_fd)
                if (
                    not stat.S_ISDIR(descriptor.st_mode)
                    or descriptor.st_uid != os.getuid()
                ):
                    os.close(next_fd)
                    raise VerificationDenied("SNAPSHOT_DIRECTORY_DENIED")
                if directory_fd != root_fd:
                    os.close(directory_fd)
                directory_fd = next_fd
            file_fd = os.open(parts[-1], flags, dir_fd=directory_fd)
            descriptor = os.fstat(file_fd)
            if not stat.S_ISREG(descriptor.st_mode):
                raise VerificationDenied("SNAPSHOT_NOT_REGULAR")
            if descriptor.st_uid != os.getuid():
                raise VerificationDenied("SNAPSHOT_OWNER_DENIED")
            if descriptor.st_nlink != 1:
                raise VerificationDenied("SNAPSHOT_LINK_COUNT_DENIED")
            content = bytearray()
            while True:
                chunk = os.read(file_fd, min(65_536, max_bytes + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > max_bytes:
                    raise VerificationDenied("SNAPSHOT_FILE_LIMIT_EXCEEDED")
            return bytes(content)
        except VerificationDenied:
            raise
        except OSError as error:
            raise VerificationDenied("SNAPSHOT_PATH_DENIED") from error
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            if directory_fd >= 0 and directory_fd != root_fd:
                os.close(directory_fd)
            if root_fd >= 0:
                os.close(root_fd)


__all__ = [
    "HostRegisteredVerifier",
    "ProjectSnapshot",
    "VerificationDenied",
    "VerificationObservation",
    "VerificationRequest",
    "VerifierSpec",
]
