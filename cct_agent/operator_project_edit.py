"""Ticketed CAS editing for dynamically registered Mike-owned project roots."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .execution_tickets import GlobalKillSwitch, TicketAuthorityDenied
from .mediation_outcomes import OutcomeVerification, OutcomeVerifierRegistry, VerificationContext
from .patching import (
    ExpectedHashPatchAdapter,
    MAX_PATCH_BYTES,
    PatchDenied,
    PatchObservation,
    PatchRequest,
    PatchTarget,
    PatchVerification,
)
from .store import Event, EventStore, canonical_json


OPERATOR_PROJECT_EDIT_CLAIM_SCHEMA_VERSION = "cct.operator_project_edit.claim.v1"
OPERATOR_PROJECT_EDIT_RECEIPT_SCHEMA_VERSION = "cct.operator_project_edit.receipt.v1"
OPERATOR_PROJECT_EDIT_VERIFIER_ID = "operator-project_edit-readback"
MAX_OWNED_EDIT_PROJECTS = 64
MAX_RELATIVE_PATH_BYTES = 1024
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PATH_COMPONENT = re.compile(r"^(?!\.\.?$)[A-Za-z0-9._@+=,-]{1,255}$")
_SENSITIVE_PARTS = {
    ".env",
    ".git",
    ".ssh",
    "credential",
    "credentials",
    "keychain",
    "keystore",
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


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest(name: str, value: object) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _integer(name: str, value: object, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("relative_path must be a non-empty exact string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("relative_path must be normalized ASCII") from error
    parts = value.split("/")
    if (
        len(encoded) > MAX_RELATIVE_PATH_BYTES
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
        or any(not _PATH_COMPONENT.fullmatch(part) for part in parts)
    ):
        raise ValueError("relative_path must stay inside project as a normalized path")
    lowered = tuple(part.casefold() for part in parts)
    if any(
        part in _SENSITIVE_PARTS
        or part.startswith(".env.")
        or any(token in part for token in _SENSITIVE_PARTS if not token.startswith("."))
        for part in lowered
    ):
        raise ValueError("relative_path belongs to a sensitive class")
    return value


@dataclass(frozen=True, slots=True)
class OwnedProjectEdit:
    """Host-owned root eligible for existing-file CAS replacements."""

    id: str
    root: str | Path
    verifier_ids: tuple[str, ...]
    max_bytes: int = MAX_PATCH_BYTES

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("project id", self.id))
        object.__setattr__(self, "root", Path(self.root))
        if not isinstance(self.verifier_ids, tuple):
            raise ValueError("verifier_ids must be an immutable tuple")
        verifier_ids = tuple(
            _identifier(f"verifier_ids[{index}]", value)
            for index, value in enumerate(self.verifier_ids)
        )
        if not 1 <= len(verifier_ids) <= 64 or len(set(verifier_ids)) != len(
            verifier_ids
        ):
            raise ValueError("verifier_ids must contain 1-64 unique IDs")
        object.__setattr__(self, "verifier_ids", verifier_ids)
        _integer("max_bytes", self.max_bytes, minimum=1, maximum=MAX_PATCH_BYTES)


@dataclass(frozen=True, slots=True)
class ProjectEditInvocation:
    """Strict model-callable request; replacement bytes remain transient."""

    ticket_id: str
    project_id: str
    relative_path: str
    expected_before_sha256: str
    replacement: bytes
    verifier_id: str
    max_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "ticket_id", _identifier("ticket id", self.ticket_id))
        object.__setattr__(self, "project_id", _identifier("project id", self.project_id))
        object.__setattr__(self, "relative_path", _relative_path(self.relative_path))
        object.__setattr__(
            self,
            "expected_before_sha256",
            _digest("expected_before_sha256", self.expected_before_sha256),
        )
        if not isinstance(self.replacement, bytes):
            raise ValueError("replacement must be exact bytes")
        object.__setattr__(self, "verifier_id", _identifier("verifier id", self.verifier_id))
        _integer("max_bytes", self.max_bytes, minimum=1, maximum=MAX_PATCH_BYTES)
        if len(self.replacement) > self.max_bytes:
            raise ValueError("replacement exceeds max_bytes")

    @classmethod
    def from_arguments(cls, arguments: Mapping[str, Any]) -> "ProjectEditInvocation":
        if not isinstance(arguments, Mapping):
            raise ValueError("project edit arguments must be an object")
        fields = {
            "execution_ticket_id",
            "project_id",
            "relative_path",
            "expected_before_sha256",
            "replacement_base64",
            "verifier_id",
            "max_bytes",
        }
        if set(arguments) != fields:
            raise ValueError("project edit arguments require exact fields")
        encoded = arguments["replacement_base64"]
        if not isinstance(encoded, str) or len(encoded) > 1_398_104:
            raise ValueError("replacement_base64 must be bounded canonical Base64")
        try:
            replacement = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("replacement_base64 must be canonical Base64") from None
        if base64.b64encode(replacement).decode("ascii") != encoded:
            raise ValueError("replacement_base64 must be canonical Base64")
        return cls(
            ticket_id=arguments["execution_ticket_id"],
            project_id=arguments["project_id"],
            relative_path=arguments["relative_path"],
            expected_before_sha256=arguments["expected_before_sha256"],
            replacement=replacement,
            verifier_id=arguments["verifier_id"],
            max_bytes=arguments["max_bytes"],
        )


@dataclass(frozen=True, slots=True)
class ProjectEditCandidate:
    before_sha256: str
    after_sha256: str
    byte_count: int
    git_head: str | None
    git_status_before_sha256: str | None


@dataclass(frozen=True, slots=True)
class ProjectEditVerification:
    passed: bool
    code: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.passed, bool):
            raise ValueError("verification passed must be a boolean")
        object.__setattr__(self, "code", _identifier("verification code", self.code))
        _digest("verification evidence_sha256", self.evidence_sha256)


ProjectEditVerifier = Callable[
    [Path, ProjectEditInvocation, ProjectEditCandidate], ProjectEditVerification
]


@dataclass(frozen=True, slots=True)
class _GitSnapshot:
    head: str | None
    status_sha256: str


@dataclass(frozen=True, slots=True)
class _RegisteredProjectEdit:
    spec: OwnedProjectEdit
    root: Path
    root_identity: tuple[int, int]
    root_sha256: str
    git_repository: bool


class OperatorProjectEditAdapter:
    """CAS-edit existing non-sensitive files below registered owned roots."""

    def __init__(
        self,
        store: EventStore,
        *,
        state_root: str | Path,
        projects: tuple[OwnedProjectEdit, ...] | list[OwnedProjectEdit],
        verifiers: Mapping[str, ProjectEditVerifier],
        git_executable: str | Path = "/usr/bin/git",
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        state = Path(state_root)
        if not state.is_absolute():
            raise ValueError("state_root must be absolute")
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        if state.is_symlink():
            raise ValueError("state_root must not be a symlink")
        self.state_root = state.resolve(strict=True)
        os.chmod(self.state_root, 0o700)

        git = Path(git_executable)
        if not git.is_absolute():
            raise ValueError("git_executable must be absolute")
        try:
            resolved_git = git.resolve(strict=True)
            git_stat = resolved_git.stat()
        except OSError as error:
            raise ValueError("git_executable must exist") from error
        if not stat.S_ISREG(git_stat.st_mode) or not os.access(resolved_git, os.X_OK):
            raise ValueError("git_executable must be an executable regular file")
        self.git_executable = resolved_git

        if not isinstance(verifiers, Mapping) or not verifiers:
            raise ValueError("verifiers must be a non-empty mapping")
        normalized_verifiers: dict[str, ProjectEditVerifier] = {}
        for raw_id, verifier in verifiers.items():
            verifier_id = _identifier("verifier id", raw_id)
            if not callable(verifier):
                raise ValueError("project edit verifier must be callable")
            normalized_verifiers[verifier_id] = verifier

        if not isinstance(projects, (tuple, list)) or not 1 <= len(projects) <= MAX_OWNED_EDIT_PROJECTS:
            raise ValueError(
                f"projects must contain 1-{MAX_OWNED_EDIT_PROJECTS} registrations"
            )
        registrations: dict[str, _RegisteredProjectEdit] = {}
        for spec in projects:
            if not isinstance(spec, OwnedProjectEdit):
                raise ValueError("projects must contain OwnedProjectEdit values")
            if spec.id in registrations:
                raise ValueError("project IDs must be unique")
            if any(value not in normalized_verifiers for value in spec.verifier_ids):
                raise ValueError("project references an unregistered verifier")
            root = Path(spec.root)
            if not root.is_absolute() or root.is_symlink():
                raise ValueError("project root must be an absolute non-symlink directory")
            try:
                resolved_root = root.resolve(strict=True)
                root_stat = resolved_root.stat()
            except OSError as error:
                raise ValueError("project root must be an existing real directory") from error
            if not stat.S_ISDIR(root_stat.st_mode):
                raise ValueError("project root must be an existing real directory")
            if hasattr(os, "geteuid") and root_stat.st_uid != os.geteuid():
                raise ValueError("project root must be owned by current host user")
            try:
                git_repository = self._detect_git_repository(resolved_root)
            except PatchDenied as error:
                raise ValueError("project Git metadata is invalid") from error
            root_sha256 = sha256(str(resolved_root).encode()).hexdigest()
            registrations[spec.id] = _RegisteredProjectEdit(
                spec=spec,
                root=resolved_root,
                root_identity=(root_stat.st_dev, root_stat.st_ino),
                root_sha256=root_sha256,
                git_repository=git_repository,
            )
            registration_payload = {
                "schema_version": 1,
                "authority": "host_adapter",
                "project_id": spec.id,
                "root_sha256": root_sha256,
                "root_device": int(root_stat.st_dev),
                "root_inode": int(root_stat.st_ino),
                "verifier_ids": list(spec.verifier_ids),
                "max_bytes": spec.max_bytes,
                "git_repository": git_repository,
                "sensitive_paths_enabled": False,
                "root_path_persisted": False,
            }
            event, _created = store.append_once_result(
                "operator.owned_project.registered", spec.id, registration_payload
            )
            if canonical_json(event.payload) != canonical_json(registration_payload):
                raise ValueError(f"project registration changed: {spec.id}")

        self.store = store
        self._projects: Mapping[str, _RegisteredProjectEdit] = MappingProxyType(registrations)
        self._verifiers: Mapping[str, ProjectEditVerifier] = MappingProxyType(
            normalized_verifiers
        )
        os.chmod(self.store.path, 0o600)

    @property
    def registered_project_ids(self) -> frozenset[str]:
        return frozenset(self._projects)

    def outcome_verifiers(self) -> OutcomeVerifierRegistry:
        registry = OutcomeVerifierRegistry()
        registry.register(
            OPERATOR_PROJECT_EDIT_VERIFIER_ID,
            self._verify_mediated_result,
            reconcile=self._reconcile_mediated_result,
            idempotency_proof_id="operator-project-edit-ticket-receipt",
        )
        return registry

    def execute(self, arguments: Mapping[str, Any]) -> str:
        request = ProjectEditInvocation.from_arguments(arguments)
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise PatchDenied(error.reason_code) from error
        self._require_dispatch_claim(request, arguments)
        registration = self._projects.get(request.project_id)
        if registration is None:
            raise PatchDenied("PROJECT_NOT_REGISTERED")
        if request.verifier_id not in registration.spec.verifier_ids:
            raise PatchDenied("PROJECT_VERIFIER_NOT_REGISTERED")
        if request.max_bytes > registration.spec.max_bytes:
            raise PatchDenied("PROJECT_BYTE_BUDGET_EXCEEDED")
        self._ensure_root(registration)

        target_id = self._target_id(request)
        after_sha256 = sha256(request.replacement).hexdigest()
        effect_id = f"edit-{sha256(request.ticket_id.encode()).hexdigest()[:24]}"
        claim_payload = {
            "schema_version": OPERATOR_PROJECT_EDIT_CLAIM_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "project_id": request.project_id,
            "root_sha256": registration.root_sha256,
            "relative_path": request.relative_path,
            "target_id": target_id,
            "expected_before_sha256": request.expected_before_sha256,
            "replacement_sha256": after_sha256,
            "replacement_byte_count": len(request.replacement),
            "max_bytes": request.max_bytes,
            "verifier_id": request.verifier_id,
            "effect_id": effect_id,
            "git_repository": registration.git_repository,
            "replacement_persisted": False,
            "root_path_persisted": False,
        }
        claim, created = self.store.append_once_result(
            "operator.project_edit.claimed", request.ticket_id, claim_payload
        )
        if not created:
            completed = self._completion(request.ticket_id)
            if completed is None:
                raise PatchDenied("EXECUTION_STATE_UNCERTAIN")
            return self._response(completed, replayed=True)

        git_before = (
            self._git_snapshot(registration, request.relative_path)
            if registration.git_repository
            else None
        )
        if git_before is not None:
            checkpoint_payload = {
                "schema_version": 1,
                "ticket_id": request.ticket_id,
                "project_id": request.project_id,
                "relative_path": request.relative_path,
                "head": git_before.head,
                "status_sha256": git_before.status_sha256,
                "raw_status_persisted": False,
                "root_path_persisted": False,
            }
            checkpoint, _checkpoint_created = self.store.append_once_result(
                "operator.project_edit.git_checkpoint",
                request.ticket_id,
                checkpoint_payload,
            )
            if canonical_json(checkpoint.payload) != canonical_json(checkpoint_payload):
                raise PatchDenied("GIT_CHECKPOINT_COLLISION")

        try:
            GlobalKillSwitch(self.store).checkpoint(
                checkpoint_id=f"edit-pre-{sha256(request.ticket_id.encode()).hexdigest()[:24]}",
                effect_id=effect_id,
                step="pre-write",
            )
        except TicketAuthorityDenied as error:
            raise PatchDenied(error.reason_code) from error

        captured: list[ProjectEditVerification] = []

        def verifier(_path: Path) -> PatchVerification:
            try:
                GlobalKillSwitch(self.store).checkpoint(
                    checkpoint_id=f"edit-verify-{sha256(request.ticket_id.encode()).hexdigest()[:24]}",
                    effect_id=effect_id,
                    step="pre-verification",
                )
            except TicketAuthorityDenied:
                result = ProjectEditVerification(
                    passed=False,
                    code="GLOBAL_KILL_SWITCH_ACTIVE",
                    evidence_sha256=sha256(b"").hexdigest(),
                )
            else:
                candidate = ProjectEditCandidate(
                    before_sha256=request.expected_before_sha256,
                    after_sha256=after_sha256,
                    byte_count=len(request.replacement),
                    git_head=git_before.head if git_before else None,
                    git_status_before_sha256=(
                        git_before.status_sha256 if git_before else None
                    ),
                )
                try:
                    raw_result = self._verifiers[request.verifier_id](
                        registration.root, request, candidate
                    )
                except Exception:
                    raw_result = ProjectEditVerification(
                        passed=False,
                        code="VERIFIER_ERROR",
                        evidence_sha256=sha256(b"").hexdigest(),
                    )
                result = (
                    raw_result
                    if isinstance(raw_result, ProjectEditVerification)
                    else ProjectEditVerification(
                        passed=False,
                        code="VERIFIER_RESULT_INVALID",
                        evidence_sha256=sha256(b"").hexdigest(),
                    )
                )
            captured.append(result)
            return PatchVerification(passed=result.passed, code=result.code)

        patching = self._patch_adapter(
            registration,
            target_id=target_id,
            relative_path=request.relative_path,
            verifier_id=request.verifier_id,
            max_bytes=request.max_bytes,
            verifier=verifier,
        )
        observation = patching.apply(
            PatchRequest(
                id=request.ticket_id,
                target_id=target_id,
                expected_before_sha256=request.expected_before_sha256,
                replacement=request.replacement,
            )
        )
        verification = captured[-1] if captured else ProjectEditVerification(
            passed=observation.status == "verified",
            code=observation.verification_code,
            evidence_sha256=observation.current_sha256,
        )
        git_after = (
            self._git_snapshot(registration, request.relative_path)
            if registration.git_repository
            else None
        )
        return self._record_completion(
            request=request,
            registration=registration,
            claim=claim,
            observation=observation,
            verification=verification,
            git_before=git_before,
            git_after=git_after,
            recovered_after_crash=False,
        )

    def _record_completion(
        self,
        *,
        request: ProjectEditInvocation,
        registration: _RegisteredProjectEdit,
        claim: Event,
        observation: PatchObservation,
        verification: ProjectEditVerification,
        git_before: _GitSnapshot | None,
        git_after: _GitSnapshot | None,
        recovered_after_crash: bool,
    ) -> str:
        git_prestate_restored = (
            observation.status == "rolled_back"
            and (
                git_before == git_after
                if registration.git_repository
                else observation.current_sha256 == observation.before_sha256
            )
        )
        receipt = {
            "schema_version": OPERATOR_PROJECT_EDIT_RECEIPT_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "claim_event_id": claim.event_id,
            "project_id": request.project_id,
            "root_sha256": registration.root_sha256,
            "relative_path": request.relative_path,
            "target_id": claim.payload["target_id"],
            "effect_id": claim.payload["effect_id"],
            "status": observation.status,
            "before_sha256": observation.before_sha256,
            "after_sha256": observation.after_sha256,
            "current_sha256": observation.current_sha256,
            "byte_count": len(request.replacement),
            "max_bytes": request.max_bytes,
            "verifier_id": request.verifier_id,
            "verification_passed": observation.status == "verified" and verification.passed,
            "verification_code": observation.verification_code,
            "verification_evidence_sha256": verification.evidence_sha256,
            "git_repository": registration.git_repository,
            "git_checkpoint_head": git_before.head if git_before else None,
            "git_checkpoint_status_sha256": git_before.status_sha256 if git_before else None,
            "git_after_status_sha256": git_after.status_sha256 if git_after else None,
            "git_prestate_restored": git_prestate_restored,
            "backup_retained": observation.backup_retained,
            "recovered_after_crash": recovered_after_crash,
            "replacement_persisted": False,
            "backup_bytes_persisted_in_ledger": False,
            "root_path_persisted": False,
            "credential_values_persisted": False,
        }
        completed, receipt_created = self.store.append_once_result(
            "operator.project_edit.completed", request.ticket_id, receipt
        )
        if canonical_json(completed.payload) != canonical_json(receipt):
            raise PatchDenied("COMPLETION_RECEIPT_COLLISION")
        return self._response(
            completed,
            replayed=recovered_after_crash or not receipt_created,
        )

    def rollback(self, ticket_id: str) -> dict[str, Any]:
        identifier = _identifier("ticket id", ticket_id)
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise PatchDenied(error.reason_code) from error
        completed = self._completion(identifier)
        if completed is None or completed.payload.get("status") != "verified":
            raise PatchDenied("PROJECT_EDIT_NOT_VERIFIED")
        payload = completed.payload
        project_id = str(payload["project_id"])
        registration = self._projects.get(project_id)
        if registration is None:
            raise PatchDenied("PROJECT_NOT_REGISTERED")
        self._ensure_root(registration)
        patching = self._patch_adapter(
            registration,
            target_id=str(payload["target_id"]),
            relative_path=str(payload["relative_path"]),
            verifier_id="rollback-readback",
            max_bytes=int(payload["max_bytes"]),
            verifier=lambda _path: PatchVerification(
                passed=True, code="ROLLBACK_READBACK"
            ),
        )
        observation = patching.rollback(identifier)
        git_after = (
            self._git_snapshot(registration, str(payload["relative_path"]))
            if registration.git_repository
            else None
        )
        restored = (
            git_after is not None
            and git_after.head == payload.get("git_checkpoint_head")
            and git_after.status_sha256 == payload.get("git_checkpoint_status_sha256")
        ) if registration.git_repository else observation.status == "rolled_back"
        rollback_payload = {
            "schema_version": 1,
            "ticket_id": identifier,
            "project_id": project_id,
            "relative_path": payload["relative_path"],
            "status": observation.status,
            "current_sha256": observation.current_sha256,
            "git_repository": registration.git_repository,
            "git_prestate_restored": restored,
            "root_path_persisted": False,
        }
        event, _created = self.store.append_once_result(
            "operator.project_edit.rollback.completed", identifier, rollback_payload
        )
        if canonical_json(event.payload) != canonical_json(rollback_payload):
            raise PatchDenied("ROLLBACK_RECEIPT_COLLISION")
        return dict(event.payload)

    def _patch_adapter(
        self,
        registration: _RegisteredProjectEdit,
        *,
        target_id: str,
        relative_path: str,
        verifier_id: str,
        max_bytes: int,
        verifier: Callable[[Path], PatchVerification],
    ) -> ExpectedHashPatchAdapter:
        return ExpectedHashPatchAdapter(
            self.store,
            workspace_root=registration.root,
            state_root=self.state_root / registration.root_sha256[:32],
            targets=(
                PatchTarget(
                    id=target_id,
                    relative_path=relative_path,
                    verifier_id=verifier_id,
                    max_bytes=max_bytes,
                ),
            ),
            verifiers={verifier_id: verifier},
        )

    @staticmethod
    def _target_id(request: ProjectEditInvocation) -> str:
        material = f"{request.ticket_id}\0{request.project_id}\0{request.relative_path}"
        return f"target-{sha256(material.encode()).hexdigest()[:24]}"

    def _detect_git_repository(self, root: Path) -> bool:
        marker = root / ".git"
        if marker.is_symlink():
            raise PatchDenied("GIT_MARKER_SYMLINK_DENIED")
        if not marker.exists():
            return False
        top = self._run_git(root, "rev-parse", "--show-toplevel")
        try:
            top_path = Path(top.decode("utf-8").strip()).resolve(strict=True)
        except (OSError, UnicodeDecodeError) as error:
            raise PatchDenied("GIT_CHECKPOINT_FAILED") from error
        if top_path != root:
            raise PatchDenied("GIT_ROOT_CHANGED")
        return True

    def _git_snapshot(
        self,
        registration: _RegisteredProjectEdit,
        relative_path: str,
    ) -> _GitSnapshot:
        top = self._run_git(registration.root, "rev-parse", "--show-toplevel")
        try:
            top_path = Path(top.decode("utf-8").strip()).resolve(strict=True)
        except (OSError, UnicodeDecodeError) as error:
            raise PatchDenied("GIT_CHECKPOINT_FAILED") from error
        if top_path != registration.root:
            raise PatchDenied("GIT_ROOT_CHANGED")
        try:
            head_result = subprocess.run(
                [str(self.git_executable), "rev-parse", "--verify", "HEAD"],
                cwd=registration.root,
                env=self._git_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PatchDenied("GIT_CHECKPOINT_FAILED") from error
        if len(head_result.stdout) > 512 or len(head_result.stderr) > 8192:
            raise PatchDenied("GIT_CHECKPOINT_FAILED")
        head = None
        if head_result.returncode == 0:
            try:
                head = head_result.stdout.decode("ascii").strip()
            except UnicodeDecodeError as error:
                raise PatchDenied("GIT_CHECKPOINT_FAILED") from error
            if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
                raise PatchDenied("GIT_CHECKPOINT_FAILED")
        status = self._run_git(
            registration.root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            relative_path,
        )
        return _GitSnapshot(head=head, status_sha256=sha256(status).hexdigest())

    def _run_git(self, root: Path, *args: str) -> bytes:
        try:
            result = subprocess.run(
                [str(self.git_executable), *args],
                cwd=root,
                env=self._git_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PatchDenied("GIT_CHECKPOINT_FAILED") from error
        if (
            result.returncode != 0
            or len(result.stdout) > 16_384
            or len(result.stderr) > 16_384
        ):
            raise PatchDenied("GIT_CHECKPOINT_FAILED")
        return result.stdout

    @staticmethod
    def _git_environment() -> dict[str, str]:
        return {
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": "/nonexistent",
        }

    @staticmethod
    def _ensure_root(registration: _RegisteredProjectEdit) -> None:
        try:
            current = registration.root.stat()
        except OSError as error:
            raise PatchDenied("PROJECT_ROOT_CHANGED") from error
        if (current.st_dev, current.st_ino) != registration.root_identity:
            raise PatchDenied("PROJECT_ROOT_CHANGED")

    def _require_dispatch_claim(
        self,
        request: ProjectEditInvocation,
        arguments: Mapping[str, Any],
    ) -> None:
        arguments_sha256 = sha256(canonical_json(arguments).encode()).hexdigest()
        claims = [
            event
            for event in self.store.events("execution.ticket.consumed")
            if event.payload.get("ticket_id") == request.ticket_id
        ]
        if len(claims) != 1:
            raise PatchDenied("TICKET_DISPATCH_CLAIM_REQUIRED")
        payload = claims[0].payload
        if (
            payload.get("dispatch_claimed") is not True
            or payload.get("ticket_consumed") is not True
            or payload.get("tool_name") != "operator_project_edit"
            or payload.get("arguments_sha256") != arguments_sha256
            or payload.get("capability") != "operator.project_edit"
            or payload.get("scope") != f"operator/project_edit/{request.project_id}"
            or payload.get("verifier_id") != OPERATOR_PROJECT_EDIT_VERIFIER_ID
            or payload.get("idempotency_key") != request.ticket_id
            or isinstance(payload.get("byte_budget"), bool)
            or not isinstance(payload.get("byte_budget"), int)
            or payload["byte_budget"] < request.max_bytes
        ):
            raise PatchDenied("TICKET_DISPATCH_CLAIM_MISMATCH")

    def _completion(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.project_edit.completed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise PatchDenied("DUPLICATE_COMPLETION_RECEIPTS")
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
                "project_edit": {
                    "project_id": payload.get("project_id"),
                    "relative_path": payload.get("relative_path"),
                    "status": payload.get("status"),
                    "before_sha256": payload.get("before_sha256"),
                    "after_sha256": payload.get("after_sha256"),
                    "current_sha256": payload.get("current_sha256"),
                    "byte_count": payload.get("byte_count"),
                    "git_repository": payload.get("git_repository"),
                    "git_checkpoint_head": payload.get("git_checkpoint_head"),
                    "git_checkpoint_status_sha256": payload.get(
                        "git_checkpoint_status_sha256"
                    ),
                    "git_after_status_sha256": payload.get("git_after_status_sha256"),
                    "git_prestate_restored": payload.get("git_prestate_restored"),
                    "backup_retained": payload.get("backup_retained"),
                    "recovered_after_crash": payload.get("recovered_after_crash") is True,
                    "replacement_persisted": False,
                    "root_path_persisted": False,
                    "replayed": replayed,
                },
                "verification": {
                    "passed": payload.get("verification_passed") is True,
                    "code": payload.get("verification_code"),
                    "evidence_sha256": payload.get("verification_evidence_sha256"),
                    "verifier_id": payload.get("verifier_id"),
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
        if (
            not isinstance(value, dict)
            or context.verifier_id != OPERATOR_PROJECT_EDIT_VERIFIER_ID
        ):
            return malformed
        effect = value.get("effect")
        edit = value.get("project_edit")
        verification = value.get("verification")
        if not all(isinstance(row, dict) for row in (effect, edit, verification)):
            return malformed
        assert isinstance(effect, dict)
        assert isinstance(edit, dict)
        assert isinstance(verification, dict)
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            return OutcomeVerification(
                verified=False, effect_observed=False, status="receipt-missing"
            )
        payload = receipt.payload
        matched = (
            value.get("success") is True
            and payload.get("verification_passed") is True
            and effect.get("effect_id") == payload.get("effect_id")
            and effect.get("idempotency_key") == context.idempotency_key
            and effect.get("receipt_event_id") == receipt.event_id
            and edit.get("project_id") == payload.get("project_id")
            and edit.get("relative_path") == payload.get("relative_path")
            and edit.get("status") == "verified"
            and edit.get("before_sha256") == payload.get("before_sha256")
            and edit.get("after_sha256") == payload.get("after_sha256")
            and edit.get("current_sha256") == payload.get("current_sha256")
            and edit.get("byte_count") == payload.get("byte_count")
            and edit.get("recovered_after_crash")
            is (payload.get("recovered_after_crash") is True)
            and edit.get("replacement_persisted") is False
            and edit.get("root_path_persisted") is False
            and verification.get("passed") is True
            and verification.get("verifier_id") == payload.get("verifier_id")
            and verification.get("code") == payload.get("verification_code")
            and verification.get("evidence_sha256")
            == payload.get("verification_evidence_sha256")
        )
        return OutcomeVerification(
            verified=matched,
            effect_observed=matched,
            status="verified" if matched else "receipt-mismatch",
            effect_id=str(payload["effect_id"]) if matched else None,
            evidence_sha256=(
                str(payload["verification_evidence_sha256"]) if matched else None
            ),
        )

    def _recover_verified_edit(self, context: VerificationContext) -> object | None:
        claims = [
            event
            for event in self.store.events("operator.project_edit.claimed")
            if event.payload.get("ticket_id") == context.ticket_id
        ]
        if len(claims) != 1:
            return None
        claim = claims[0]
        payload = claim.payload
        project_id = payload.get("project_id")
        registration = self._projects.get(project_id) if isinstance(project_id, str) else None
        if (
            registration is None
            or context.tool_name != "operator_project_edit"
            or context.capability != "operator.project_edit"
            or context.verifier_id != OPERATOR_PROJECT_EDIT_VERIFIER_ID
            or context.idempotency_key != context.ticket_id
            or context.scope != f"operator/project_edit/{project_id}"
            or payload.get("verifier_id") not in registration.spec.verifier_ids
            or payload.get("root_sha256") != registration.root_sha256
        ):
            return None
        assert isinstance(project_id, str)
        self._ensure_root(registration)
        relative_path = payload.get("relative_path")
        target_id = payload.get("target_id")
        verifier_id = payload.get("verifier_id")
        max_bytes = payload.get("max_bytes")
        if (
            not isinstance(relative_path, str)
            or not isinstance(target_id, str)
            or not isinstance(verifier_id, str)
            or isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
        ):
            return None
        patching = self._patch_adapter(
            registration,
            target_id=target_id,
            relative_path=relative_path,
            verifier_id=verifier_id,
            max_bytes=max_bytes,
            verifier=lambda _path: PatchVerification(passed=True, code="RECOVERY_READBACK"),
        )
        try:
            observation = patching.require_verified(context.ticket_id)
            replacement = self._read_recovery_bytes(
                registration, relative_path=relative_path, max_bytes=max_bytes
            )
        except (OSError, PatchDenied):
            return None
        if (
            sha256(replacement).hexdigest() != payload.get("replacement_sha256")
            or len(replacement) != payload.get("replacement_byte_count")
            or observation.after_sha256 != payload.get("replacement_sha256")
        ):
            return None

        git_before: _GitSnapshot | None = None
        if registration.git_repository:
            checkpoints = [
                event
                for event in self.store.events("operator.project_edit.git_checkpoint")
                if event.payload.get("ticket_id") == context.ticket_id
            ]
            if len(checkpoints) != 1:
                return None
            checkpoint = checkpoints[0].payload
            head = checkpoint.get("head")
            status_sha256 = checkpoint.get("status_sha256")
            if (head is not None and not isinstance(head, str)) or not isinstance(
                status_sha256, str
            ):
                return None
            try:
                _digest("git status digest", status_sha256)
            except ValueError:
                return None
            git_before = _GitSnapshot(head=head, status_sha256=status_sha256)

        request = ProjectEditInvocation(
            ticket_id=context.ticket_id,
            project_id=project_id,
            relative_path=relative_path,
            expected_before_sha256=str(payload.get("expected_before_sha256")),
            replacement=replacement,
            verifier_id=verifier_id,
            max_bytes=max_bytes,
        )
        candidate = ProjectEditCandidate(
            before_sha256=request.expected_before_sha256,
            after_sha256=str(payload["replacement_sha256"]),
            byte_count=len(replacement),
            git_head=git_before.head if git_before else None,
            git_status_before_sha256=git_before.status_sha256 if git_before else None,
        )
        try:
            verification = self._verifiers[verifier_id](registration.root, request, candidate)
        except Exception:
            return None
        if not isinstance(verification, ProjectEditVerification) or not verification.passed:
            return None
        git_after = (
            self._git_snapshot(registration, relative_path)
            if registration.git_repository
            else None
        )
        return json.loads(
            self._record_completion(
                request=request,
                registration=registration,
                claim=claim,
                observation=observation,
                verification=verification,
                git_before=git_before,
                git_after=git_after,
                recovered_after_crash=True,
            )
        )

    @staticmethod
    def _read_recovery_bytes(
        registration: _RegisteredProjectEdit,
        *,
        relative_path: str,
        max_bytes: int,
    ) -> bytes:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptors: list[int] = []
        try:
            root_fd = os.open(registration.root, flags | os.O_DIRECTORY)
            descriptors.append(root_fd)
            root_stat = os.fstat(root_fd)
            if (root_stat.st_dev, root_stat.st_ino) != registration.root_identity:
                raise OSError("project root changed")
            parent_fd = root_fd
            parts = relative_path.split("/")
            for component in parts[:-1]:
                parent_fd = os.open(component, flags | os.O_DIRECTORY, dir_fd=parent_fd)
                descriptors.append(parent_fd)
            file_fd = os.open(parts[-1], flags, dir_fd=parent_fd)
            descriptors.append(file_fd)
            metadata = os.fstat(file_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
                or metadata.st_size > max_bytes
            ):
                raise OSError("recovery target invalid")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(file_fd, min(65_536, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise OSError("recovery target too large")
            return b"".join(chunks)
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _reconcile_mediated_result(self, context: VerificationContext) -> object | None:
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            return self._recover_verified_edit(context)
        if receipt.payload.get("verification_passed") is not True:
            return None
        return json.loads(self._response(receipt, replayed=True))
