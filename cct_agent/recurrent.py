"""Exact-installed recurrent coordinator for one reversible self-goal episode."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import fcntl
from hashlib import sha256
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Iterator, Sequence

from .commands import BoundedCommandAdapter, CommandRequest, CommandSpec
from .deployment import DeploymentTarget, LocalFakeDeploymentAdapter
from .full_stack import FullStackEpisodeConfig
from .kernel import AgencyKernel, resolve_constitution
from .patching import (
    ExpectedHashPatchAdapter,
    PatchRequest,
    PatchTarget,
    PatchVerification,
)
from .planning import AutonomyPlanner, DecisionAlternative
from .principal import PrincipalModel
from .public_actions import FakePublicActionSpec, LocalFakePublicActionAdapter
from .research import (
    RESEARCH_RECEIPT_SCHEMA_VERSION,
    ResearchDenied,
    ResearchObservation,
    ResearchRequest,
)
from .runner import ProactiveRunner
from .self_goals import (
    SelfGoalCandidate,
    SelfGoalEpisodeCoordinator,
    SelfGoalInputReceipt,
)
from .store import EventStore, canonical_json
from .verification import HostRegisteredVerifier, VerifierSpec


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_MAX_PRIVATE_INPUT_BYTES = 65_536
_WAKE_FIELDS = {
    "schema_version",
    "wake_id",
    "seed",
    "expires_at",
    "time_bucket",
    "receipts",
}
_RECEIPT_FIELDS = {
    "id",
    "kind",
    "subject_id",
    "content_sha256",
    "issued_by",
    "semantic_taint",
    "signature",
    "raw_content_persisted",
}
_BASELINE = b"verified = false\n"


class RecurrentCoordinatorDenied(RuntimeError):
    """Fail-closed recurrent runtime, input, or layout decision."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _wake_key(value: str) -> str:
    normalized = _identifier("wake id", value)
    if len(normalized) <= 48:
        return normalized
    return f"{normalized[:31]}-{sha256(normalized.encode()).hexdigest()[:16]}"


@dataclass(frozen=True, slots=True)
class RecurrentPaths:
    """Host-selected roots; every mutable path must stay inside one state root."""

    state_root: Path
    database: Path
    planning_root: Path
    patch_state_root: Path
    workspace_root: Path
    deployment_sink: Path
    outbox_root: Path

    def __post_init__(self) -> None:
        root = Path(self.state_root)
        if not root.is_absolute() or root.is_symlink():
            raise ValueError("state_root must be an absolute real directory")
        try:
            resolved_root = root.resolve(strict=True)
        except OSError as error:
            raise ValueError("state_root must exist") from error
        if not resolved_root.is_dir():
            raise ValueError("state_root must be a directory")
        object.__setattr__(self, "state_root", resolved_root)
        for name in (
            "database",
            "planning_root",
            "patch_state_root",
            "workspace_root",
            "deployment_sink",
            "outbox_root",
        ):
            path = Path(getattr(self, name))
            if not path.is_absolute() or path.is_symlink():
                raise ValueError(f"{name} must be an absolute real path")
            lexical = path.absolute()
            try:
                lexical.relative_to(resolved_root)
            except ValueError as error:
                raise ValueError(f"{name} must remain under state_root") from error
            if name != "database":
                try:
                    resolved = path.resolve(strict=True)
                except OSError as error:
                    raise ValueError(f"{name} must exist") from error
                if not resolved.is_dir() or (
                    resolved != resolved_root and resolved_root not in resolved.parents
                ):
                    raise ValueError(f"{name} must be a directory under state_root")
                object.__setattr__(self, name, resolved)
            else:
                if path.exists() and not path.is_file():
                    raise ValueError("database must be a regular file")
                object.__setattr__(self, name, lexical)


@dataclass(frozen=True, slots=True)
class RecurrentWake:
    """One authenticated metadata-only wake."""

    id: str
    seed: int
    expires_at: str
    time_bucket: str
    receipts: tuple[SelfGoalInputReceipt, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("wake id", self.id))
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("wake seed must be an integer")
        try:
            expiry = datetime.fromisoformat(self.expires_at)
        except (TypeError, ValueError) as error:
            raise ValueError("wake expiry must be ISO-8601") from error
        if expiry.tzinfo is None:
            raise ValueError("wake expiry must include timezone information")
        if not isinstance(self.time_bucket, str) or not _DATE.fullmatch(self.time_bucket):
            raise ValueError("wake time_bucket must be an ISO date")
        rows = tuple(self.receipts)
        if (
            len(rows) < 4
            or len(rows) > 16
            or any(not isinstance(row, SelfGoalInputReceipt) for row in rows)
            or len({row.id for row in rows}) != len(rows)
        ):
            raise ValueError("wake requires 4-16 unique self-goal receipts")
        object.__setattr__(self, "receipts", rows)


def runtime_provenance(
    *, expected_module_root: Path, expected_package_version: str
) -> dict[str, str]:
    """Bind execution to one exact imported package root and distribution version."""

    module_root = Path(__file__).resolve().parents[1]
    try:
        expected_root = Path(expected_module_root).resolve(strict=True)
    except OSError as error:
        raise RecurrentCoordinatorDenied("RUNTIME_MODULE_ROOT_INVALID") from error
    if module_root != expected_root:
        raise RecurrentCoordinatorDenied("RUNTIME_MODULE_ROOT_MISMATCH")
    try:
        distribution_version = version("cct-agency-engine")
    except PackageNotFoundError as error:
        raise RecurrentCoordinatorDenied("RUNTIME_DISTRIBUTION_MISSING") from error
    package = import_module("cct_agent")
    api_version = getattr(package, "__version__", None)
    if (
        not isinstance(expected_package_version, str)
        or distribution_version != expected_package_version
        or api_version != expected_package_version
    ):
        raise RecurrentCoordinatorDenied("RUNTIME_VERSION_MISMATCH")
    return {
        "distribution": "cct-agency-engine",
        "package_version": distribution_version,
        "module_root": str(module_root),
        "module_file": str(Path(__file__).resolve()),
        "module_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def _read_private_file(path: Path, root: Path) -> bytes:
    lexical = Path(path).absolute()
    try:
        relative = lexical.relative_to(root)
    except ValueError as error:
        raise RecurrentCoordinatorDenied("PRIVATE_INPUT_OUTSIDE_STATE_ROOT") from error
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise RecurrentCoordinatorDenied("PRIVATE_INPUT_PATH_INVALID")
    root_fd = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    directory_fd = root_fd
    file_fd: int | None = None
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            if directory_fd != root_fd:
                os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            relative.parts[-1],
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        metadata = os.fstat(file_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > _MAX_PRIVATE_INPUT_BYTES
        ):
            raise RecurrentCoordinatorDenied("PRIVATE_INPUT_UNSAFE")
        with os.fdopen(file_fd, "rb", closefd=True) as stream:
            file_fd = None
            body = stream.read(_MAX_PRIVATE_INPUT_BYTES + 1)
        if len(body) > _MAX_PRIVATE_INPUT_BYTES:
            raise RecurrentCoordinatorDenied("PRIVATE_INPUT_TOO_LARGE")
        return body
    except OSError as error:
        raise RecurrentCoordinatorDenied("PRIVATE_INPUT_OPEN_FAILED") from error
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd != root_fd:
            os.close(directory_fd)
        os.close(root_fd)


def _read_registered_workspace_file(
    root: Path, relative_path: str, maximum: int = 8192
) -> bytes:
    """Descriptor-traverse one host-registered workspace file without symlinks."""

    parts = relative_path.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise RecurrentCoordinatorDenied("RECURRENT_WORKSPACE_FILE_UNSAFE")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    root_fd = -1
    directory_fd = -1
    file_fd = -1
    try:
        root_fd = os.open(root, flags | os.O_DIRECTORY)
        directory_fd = root_fd
        for component in parts[:-1]:
            next_fd = os.open(
                component, flags | os.O_DIRECTORY, dir_fd=directory_fd
            )
            metadata = os.fstat(next_fd)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
                os.close(next_fd)
                raise RecurrentCoordinatorDenied("RECURRENT_WORKSPACE_FILE_UNSAFE")
            if directory_fd != root_fd:
                os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            parts[-1], flags | getattr(os, "O_NONBLOCK", 0), dir_fd=directory_fd
        )
        metadata = os.fstat(file_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or metadata.st_size > maximum
        ):
            raise RecurrentCoordinatorDenied("RECURRENT_WORKSPACE_FILE_UNSAFE")
        body = bytearray()
        while True:
            chunk = os.read(file_fd, min(65_536, maximum + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > maximum:
                raise RecurrentCoordinatorDenied("RECURRENT_WORKSPACE_FILE_UNSAFE")
        if len(body) > maximum:
            raise RecurrentCoordinatorDenied("RECURRENT_WORKSPACE_FILE_UNSAFE")
        return bytes(body)
    except RecurrentCoordinatorDenied:
        raise
    except OSError as error:
        raise RecurrentCoordinatorDenied("RECURRENT_WORKSPACE_INCOMPLETE") from error
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if directory_fd >= 0 and directory_fd != root_fd:
            os.close(directory_fd)
        if root_fd >= 0:
            os.close(root_fd)


def load_recurrent_wake(
    *, state_root: Path, receipt_file: Path, secret_file: Path
) -> tuple[RecurrentWake, bytes]:
    """Load one strict private wake; unknown producer-text fields fail closed."""

    try:
        root = Path(state_root).resolve(strict=True)
    except OSError as error:
        raise RecurrentCoordinatorDenied("STATE_ROOT_INVALID") from error
    secret = _read_private_file(secret_file, root)
    if len(secret) < 32:
        raise RecurrentCoordinatorDenied("AUTHENTICATION_SECRET_INVALID")
    try:
        raw = json.loads(_read_private_file(receipt_file, root).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecurrentCoordinatorDenied("WAKE_SCHEMA_INVALID") from error
    if not isinstance(raw, dict) or set(raw) != _WAKE_FIELDS or raw.get("schema_version") != 1:
        raise RecurrentCoordinatorDenied("WAKE_SCHEMA_INVALID")
    receipt_rows = raw.get("receipts")
    if not isinstance(receipt_rows, list):
        raise RecurrentCoordinatorDenied("WAKE_SCHEMA_INVALID")
    receipts: list[SelfGoalInputReceipt] = []
    try:
        for item in receipt_rows:
            if not isinstance(item, dict) or set(item) != _RECEIPT_FIELDS:
                raise RecurrentCoordinatorDenied("WAKE_SCHEMA_INVALID")
            receipts.append(SelfGoalInputReceipt(**item))
        wake = RecurrentWake(
            id=raw["wake_id"],
            seed=raw["seed"],
            expires_at=raw["expires_at"],
            time_bucket=raw["time_bucket"],
            receipts=tuple(receipts),
        )
    except (TypeError, ValueError) as error:
        raise RecurrentCoordinatorDenied("WAKE_SCHEMA_INVALID") from error
    return wake, secret


class _AuthenticatedMetadataResearchAdapter:
    """Observe only signed receipt metadata already admitted by host policy."""

    SOURCE_ID = "authenticated-receipt-set"

    def __init__(
        self, store: EventStore, receipts: Sequence[SelfGoalInputReceipt]
    ) -> None:
        self.store = store
        self.receipts = tuple(receipts)
        self.content = canonical_json(
            {
                "receipt_ids": [row.id for row in self.receipts],
                "receipt_set_sha256": _digest(
                    [
                        {**row.signed_payload(), "signature": row.signature}
                        for row in self.receipts
                    ]
                ),
            }
        )

    def fetch(self, request: ResearchRequest) -> ResearchObservation:
        if (
            not isinstance(request, ResearchRequest)
            or request.source_id != self.SOURCE_ID
            or request.path != "/metadata"
        ):
            raise ResearchDenied("SOURCE_NOT_REGISTERED")
        body = self.content.encode("utf-8")
        digest = sha256(body).hexdigest()
        payload = {
            "schema_version": RESEARCH_RECEIPT_SCHEMA_VERSION,
            "request_id": request.id,
            "source_id": self.SOURCE_ID,
            "source_url": "host-metadata://authenticated-receipt-set/metadata",
            "status_code": 200,
            "content_type": "application/json",
            "byte_count": len(body),
            "content_sha256": digest,
            "provenance": "authenticated_metadata_untrusted_semantics",
            "authority_granted": False,
            "eligible_for_goal_authority": False,
            "producer_content_persisted": False,
            "caller_path_persisted": False,
            "automatic_credentials_sent": False,
        }
        try:
            event, _ = self.store.append_once_result(
                "research.observation.recorded", request.id, payload
            )
        except ValueError as error:
            raise ResearchDenied("REQUEST_COLLISION") from error
        if canonical_json(event.payload) != canonical_json(payload):
            raise ResearchDenied("REQUEST_COLLISION")
        return ResearchObservation(
            request_id=request.id,
            source_id=self.SOURCE_ID,
            source_url=str(payload["source_url"]),
            status_code=200,
            content_type="application/json",
            byte_count=len(body),
            content_sha256=digest,
            content=self.content,
            receipt_event_id=event.event_id,
        )


FaultHook = Callable[[str, str], None]


class InstalledRecurrentCoordinator:
    """Run one exact package-native self-goal and expose one pending ranked proposal."""

    def __init__(
        self,
        *,
        paths: RecurrentPaths,
        identity: str,
        principal_id: str,
        authentication_secret: bytes,
        expected_module_root: Path,
        expected_package_version: str,
    ) -> None:
        self.runtime = runtime_provenance(
            expected_module_root=expected_module_root,
            expected_package_version=expected_package_version,
        )
        self.paths = paths
        self.identity = _identifier("identity", identity)
        self.principal_id = _identifier("principal id", principal_id)
        if not isinstance(authentication_secret, bytes) or len(authentication_secret) < 32:
            raise ValueError("authentication_secret must contain at least 32 bytes")
        self.authentication_secret = authentication_secret

    @contextmanager
    def _lock(self) -> Iterator[None]:
        lock_path = self.paths.state_root / "recurrent-coordinator.lock"
        fd = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RecurrentCoordinatorDenied("COORDINATOR_BUSY") from error
            yield
        finally:
            os.close(fd)

    def _config(self, wake: RecurrentWake) -> tuple[FullStackEpisodeConfig, bytes, bytes]:
        key = _wake_key(wake.id)
        receipt_set_sha256 = _digest(
            [
                {**receipt.signed_payload(), "signature": receipt.signature}
                for receipt in wake.receipts
            ]
        )
        artifact = (
            "CCT_RECURRENT_RECEIPT_V1\n"
            f"wake_id={wake.id}\n"
            f"receipt_set_sha256={receipt_set_sha256}\n"
        ).encode("utf-8")
        status = (
            "verified = true\n"
            f"wake_id = {wake.id}\n"
            f"receipt_set_sha256 = {receipt_set_sha256}\n"
        ).encode("utf-8")
        current_status = _read_registered_workspace_file(
            self.paths.workspace_root, "config/status.txt"
        )
        current_artifact = _read_registered_workspace_file(
            self.paths.workspace_root, "dist/receipt.txt"
        )
        if current_status not in {_BASELINE, status} or current_artifact not in {
            b"",
            artifact,
        }:
            raise RecurrentCoordinatorDenied("RECURRENT_WORKSPACE_FOREIGN_MUTATION")
        config = FullStackEpisodeConfig(
            research_stage_id="research",
            research_request=ResearchRequest(
                id=f"research-{key}",
                source_id=_AuthenticatedMetadataResearchAdapter.SOURCE_ID,
                path="/metadata",
            ),
            command_stage_id="command",
            command_request=CommandRequest(
                id=f"command-{key}", command_id=f"build-{key}"
            ),
            patch_stage_id="patch",
            patch_request=PatchRequest(
                id=f"patch-{key}",
                target_id=f"status-{key}",
                expected_before_sha256=sha256(_BASELINE).hexdigest(),
                replacement=status,
            ),
            verification_stage_id="verify",
            verifier_id=f"verify-{key}",
            verification_request_id=f"verification-{key}",
            deployment_stage_id="deploy",
            deployment_target_id=f"deploy-{key}",
            deployment_request_id=f"deployment-{key}",
            public_action_stage_id="public-action",
            public_action_id=f"fake-publish-{key}",
            public_action_request_id=f"public-action-{key}",
        )
        return config, artifact, status

    def _candidates(
        self, wake: RecurrentWake, config: FullStackEpisodeConfig
    ) -> tuple[SelfGoalCandidate, ...]:
        key = _wake_key(wake.id)
        required = tuple(receipt.id for receipt in wake.receipts)
        alternatives = (
            DecisionAlternative(
                id=f"execute-{key}",
                summary="Execute the exact installed recurrent full-stack chain.",
                predicted_outcome="One verified reversible local receipt and fake outbox receipt.",
                value_impacts={"truth": 0.95, "competence": 0.95, "autonomy": 0.9},
                information_gain=0.8,
                uncertainty=0.05,
                time_cost=0.1,
            ),
            DecisionAlternative(
                id=f"inspect-{key}",
                summary="Inspect signed metadata and defer local execution.",
                predicted_outcome="Evidence remains available but no completed receipt exists.",
                value_impacts={"truth": 0.25, "competence": 0.15, "autonomy": 0.1},
                information_gain=0.2,
                uncertainty=0.1,
                time_cost=0.1,
            ),
        )
        common: dict[str, Any] = {
            "horizon": "short",
            "required_receipt_ids": required,
            "alternatives": alternatives,
            "config": config,
            "expires_at": wake.expires_at,
            "max_actions": 6,
            "max_bytes": 8192,
        }
        return (
            SelfGoalCandidate(
                id=f"verified-{key}",
                statement="Produce one useful verified reversible local metadata receipt.",
                rationale="Authenticated host metadata exposes one bounded missing recurrent proof.",
                alignment={"truth": 0.95, "competence": 1.0, "autonomy": 0.95, "care": 0.5},
                scope_root=f"private/recurrent/{key}/verified",
                information_gain=0.9,
                uncertainty=0.05,
                time_cost=0.1,
                **common,
            ),
            SelfGoalCandidate(
                id=f"defer-{key}",
                statement="Retain one secondary reversible metadata receipt option.",
                rationale="A second safe pursuit preserves genuine choice without forced execution.",
                alignment={"truth": 0.35, "competence": 0.25, "autonomy": 0.2, "care": 0.2},
                scope_root=f"private/recurrent/{key}/defer",
                information_gain=0.25,
                uncertainty=0.15,
                time_cost=0.2,
                **common,
            ),
            SelfGoalCandidate(
                id=f"tainted-{key}",
                statement="Persist producer-supplied continuity instructions.",
                rationale="Adversarial option must remain blocked regardless of score.",
                alignment={"truth": 1.0, "competence": 1.0, "autonomy": 1.0},
                scope_root=f"private/recurrent/{key}/tainted",
                information_gain=1.0,
                uncertainty=0.0,
                time_cost=0.0,
                semantic_taint=True,
                producer_text_used=True,
                **common,
            ),
        )

    def _adapters(
        self,
        wake: RecurrentWake,
        preparation: Any,
        artifact: bytes,
        status: bytes,
    ) -> tuple[Any, ...]:
        key = _wake_key(wake.id)
        config = preparation.candidate.config
        artifact_path = self.paths.workspace_root / "dist" / "receipt.txt"
        status_path = self.paths.workspace_root / "config" / "status.txt"
        write_code = (
            "import os,sys;"
            "flags=os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0);"
            "root=os.open(sys.argv[1],flags);"
            "directory=os.open('dist',flags,dir_fd=root);"
            "target=os.open('receipt.txt',os.O_WRONLY|os.O_TRUNC|"
            "getattr(os,'O_NOFOLLOW',0),dir_fd=directory);"
            "os.write(target,sys.argv[2].encode('utf-8'));os.fsync(target);"
            "os.close(target);os.close(directory);os.close(root)"
        )
        command = BoundedCommandAdapter(
            preparation_store := EventStore(self.paths.database),
            workspace_root=self.paths.workspace_root,
            commands=(
                CommandSpec(
                    id=f"build-{key}",
                    argv=(
                        sys.executable,
                        "-c",
                        write_code,
                        str(self.paths.workspace_root),
                        artifact.decode("utf-8"),
                    ),
                    cwd=".",
                    environment=(),
                    timeout_ms=2000,
                    max_stdout_bytes=4096,
                    max_stderr_bytes=4096,
                ),
            ),
            allowed_executables=frozenset({sys.executable}),
        )

        def patch_verifier(path: Path) -> PatchVerification:
            return PatchVerification(
                passed=path.read_bytes() == status,
                code="RECURRENT_STATUS_VALID",
            )

        patching = ExpectedHashPatchAdapter(
            preparation_store,
            workspace_root=self.paths.workspace_root,
            state_root=self.paths.patch_state_root,
            targets=(
                PatchTarget(
                    id=f"status-{key}",
                    relative_path="config/status.txt",
                    verifier_id=f"patch-shape-{key}",
                    max_bytes=4096,
                ),
            ),
            verifiers={f"patch-shape-{key}": patch_verifier},
        )
        verify_code = (
            "from pathlib import Path; import sys; "
            f"ok=Path(sys.argv[1]).read_bytes()=={artifact!r} and "
            f"Path(sys.argv[2]).read_bytes()=={status!r}; "
            "raise SystemExit(0 if ok else 3)"
        )
        verifier = HostRegisteredVerifier(
            preparation_store,
            workspace_root=self.paths.workspace_root,
            verifiers=(
                VerifierSpec(
                    id=f"verify-{key}",
                    kind="test",
                    plan_id=preparation.binding.plan_id,
                    plan_sha256=preparation.binding.plan_sha256,
                    stage_id=config.verification_stage_id,
                    command=CommandSpec(
                        id=f"verifier-command-{key}",
                        argv=(
                            sys.executable,
                            "-c",
                            verify_code,
                            str(artifact_path),
                            str(status_path),
                        ),
                        cwd=".",
                        environment=(),
                        timeout_ms=2000,
                        max_stdout_bytes=4096,
                        max_stderr_bytes=4096,
                    ),
                    snapshot_paths=("config/status.txt", "dist/receipt.txt"),
                    max_snapshot_file_bytes=4096,
                    max_snapshot_total_bytes=8192,
                ),
            ),
            allowed_executables=frozenset({sys.executable}),
        )
        deployment = LocalFakeDeploymentAdapter(
            preparation_store,
            workspace_root=self.paths.workspace_root,
            sink_root=self.paths.deployment_sink,
            targets=(
                DeploymentTarget(
                    id=f"deploy-{key}",
                    kind="local_fake",
                    source_relative_path="dist/receipt.txt",
                    sink_relative_path="releases/receipt.txt",
                    verifier_id=f"verify-{key}",
                    max_artifact_bytes=4096,
                ),
            ),
            verifier=verifier,
        )
        public = LocalFakePublicActionAdapter(
            preparation_store,
            outbox_root=self.paths.outbox_root,
            actions=(
                FakePublicActionSpec(
                    id=f"fake-publish-{key}",
                    kind="fake_sink",
                    channel="local_fake",
                    action="publish",
                    envelope_type="deployment_announcement",
                    template_id="recurrent-receipt-v1",
                    deployment_target_id=f"deploy-{key}",
                    outbox_item_name=f"recurrent-{key}.json",
                    max_item_bytes=8192,
                ),
            ),
            deployment=deployment,
        )
        return (
            preparation_store,
            _AuthenticatedMetadataResearchAdapter(preparation_store, wake.receipts),
            command,
            patching,
            verifier,
            deployment,
            public,
        )

    def run(
        self,
        wake: RecurrentWake,
        *,
        claim_fault_hook: FaultHook | None = None,
        fault_hook: FaultHook | None = None,
    ) -> dict[str, Any]:
        """Select, execute/replay, verify, reflect, then expose at most one proposal."""

        with self._lock():
            store = EventStore(self.paths.database)
            kernel = AgencyKernel(store, resolve_constitution(store, self.identity))
            kernel.initialize()
            principal = PrincipalModel(store).status()
            profile = principal.get("profile")
            if not isinstance(profile, dict) or profile.get("principal_id") != self.principal_id:
                raise RecurrentCoordinatorDenied("PRINCIPAL_PROFILE_MISMATCH")
            planner = AutonomyPlanner(store, kernel, self.paths.planning_root)
            config, artifact, status = self._config(wake)
            candidates = self._candidates(wake, config)
            owner = SelfGoalEpisodeCoordinator(
                store,
                kernel=kernel,
                planner=planner,
                policy_id=f"recurrent-{_wake_key(wake.id)}",
                principal_id=self.principal_id,
                candidates=candidates,
                authentication_secret=self.authentication_secret,
                capability_name=f"self-goal.recurrent.{_wake_key(wake.id)}",
            )
            preparation = owner.prepare(wake.receipts, seed=wake.seed)
            (
                adapter_store,
                research,
                commands,
                patching,
                verifier,
                deployment,
                public,
            ) = self._adapters(wake, preparation, artifact, status)
            if adapter_store.path.resolve() != store.path.resolve():
                raise RecurrentCoordinatorDenied("RECURRENT_STORE_MISMATCH")
            episode = owner.run_prepared(
                preparation,
                research=research,
                commands=commands,
                patching=patching,
                verifier=verifier,
                deployment=deployment,
                public_actions=public,
                claim_fault_hook=claim_fault_hook,
                fault_hook=fault_hook,
            )
            priority = ProactiveRunner(store).run_once(time_bucket=wake.time_bucket)
            goal = kernel.goal(preparation.goal_id)
            if goal is None:
                raise RecurrentCoordinatorDenied("RECURRENT_GOAL_MISSING")
            return {
                "schema_version": 1,
                "wake_id": wake.id,
                "status": episode.episode.status,
                "replayed": episode.replayed,
                "goal_id": preparation.goal_id,
                "goal_source": goal.source,
                "candidate_id": preparation.candidate.id,
                "terminal_event_id": episode.terminal_event_id,
                "episode_terminal_event_id": episode.episode.terminal_event_id,
                "outcome_event_id": episode.episode.outcome_event_id,
                "reflection_event_id": episode.episode.reflection_event_id,
                "completed_stage_ids": list(episode.episode.completed_stage_ids),
                "lease": {
                    "id": preparation.lease_id,
                    "scope": preparation.candidate.scope,
                    "expires_at": preparation.candidate.expires_at,
                    "max_actions": preparation.candidate.max_actions,
                    "max_bytes": preparation.candidate.max_bytes,
                    "max_value_microunits": 0,
                },
                "priority_dialogue": {
                    "initiative_kind": priority.get("initiative_kind"),
                    "proposal_id": priority.get("proposal_id"),
                    "proposal_revision": priority.get("proposal_revision"),
                    "message": str(priority.get("message", "")),
                },
                "runtime": self.runtime,
                "chain_valid": store.verify_chain().get("valid") is True,
                "external_effects": 0,
                "raw_producer_content_persisted": False,
                "raw_chain_of_thought_stored": False,
            }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one exact-installed CCT recurrent self-goal episode"
    )
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--deployment-sink", type=Path, required=True)
    parser.add_argument("--outbox-root", type=Path, required=True)
    parser.add_argument("--receipt-file", type=Path, required=True)
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--principal-id", required=True)
    parser.add_argument("--expected-module-root", type=Path, required=True)
    parser.add_argument("--expected-package-version", required=True)
    parser.add_argument("--message-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    state_root = args.state_root.absolute()
    paths = RecurrentPaths(
        state_root=state_root,
        database=state_root / "agency.sqlite",
        planning_root=state_root / "recurrent-planning",
        patch_state_root=state_root / "recurrent-patch-state",
        workspace_root=args.workspace_root.absolute(),
        deployment_sink=args.deployment_sink.absolute(),
        outbox_root=args.outbox_root.absolute(),
    )
    wake, secret = load_recurrent_wake(
        state_root=state_root,
        receipt_file=args.receipt_file,
        secret_file=args.secret_file,
    )
    try:
        result = InstalledRecurrentCoordinator(
            paths=paths,
            identity=args.identity,
            principal_id=args.principal_id,
            authentication_secret=secret,
            expected_module_root=args.expected_module_root,
            expected_package_version=args.expected_package_version,
        ).run(wake)
    except RecurrentCoordinatorDenied as error:
        if error.reason_code == "COORDINATOR_BUSY":
            return 0
        raise
    if args.message_only:
        message = str(result["priority_dialogue"]["message"]).strip()
        if message:
            print(message)
    else:
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())