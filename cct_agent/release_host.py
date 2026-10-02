"""Generalist2-only host mechanics for exact CCT release recovery.

The governance bridge decides. This module performs host effects against one fixed
profile/service. Source is exported from one immutable Git commit, built into a
hash-bound pure-Python wheel, installed by exact member extraction, loaded through
the installed entry point in a disposable home, then activated through an external
systemd verifier. SQLite state is inspected but never restored.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from typing import Any, Mapping, Protocol
import zipfile

from .release_recovery import (
    GENERALIST2_PROFILE,
    GENERALIST2_SERVICE,
    ExactRebuildTicket,
    Generalist2RedeployTicket,
    IsolatedReleaseVerification,
    IsolatedVerificationTicket,
    ReleaseArtifact,
    ReleaseRecoveryDenied,
    ReleaseRollbackTicket,
    ReleaseRuntimeState,
)
from .store import canonical_json


RELEASE_MANIFEST_VERSION = "cct.generalist2.release-manifest.v1"
HOST_ARTIFACT_RECEIPT_VERSION = "cct.generalist2.host-artifact.v1"
HOST_VERIFICATION_RECEIPT_VERSION = "cct.generalist2.host-verification.v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _digest_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _payload_digest(value: object) -> str:
    return _digest_bytes(canonical_json(value).encode("utf-8"))


def _require_absolute_real_directory(path: Path, name: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ValueError(f"{name} must be an absolute real directory")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise ValueError(f"{name} must be an existing real directory") from error
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError(f"{name} must be an owned real directory")
    return resolved


def _require_absolute_file(path: Path, name: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute real file")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise ValueError(f"{name} must be an existing real file") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
        raise ValueError(f"{name} must resolve to a non-writable regular file")
    return resolved


def _require_exact_file_path(path: Path, root: Path, name: str) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{name} must stay inside its exact root") from error
    current = root
    for component in relative.parts[:-1]:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ValueError(f"{name} parent chain must already exist") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
        ):
            raise ValueError(f"{name} parent chain must be owned real directories")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{name} must be an existing real file") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise ValueError(f"{name} must be an owned single-link real file")


def _safe_descendant(path: Path, root: Path, reason: str) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise ReleaseRecoveryDenied(reason)
    try:
        resolved = path.resolve(strict=False)
    except OSError as error:
        raise ReleaseRecoveryDenied(reason) from error
    if resolved == root or not resolved.is_relative_to(root):
        raise ReleaseRecoveryDenied(reason)
    return resolved


def _atomic_bytes(path: Path, content: bytes, mode: int) -> None:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ValueError("atomic target must be an exact absolute file path")
    parent_descriptor = os.open(
        "/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        for component in path.parent.parts[1:]:
            if component in {"", ".", ".."}:
                raise ValueError("atomic target parent path is unsafe")
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        temporary_name = f".{path.name}.{os.getpid()}.tmp"
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
            dir_fd=parent_descriptor,
        )
        try:
            try:
                view = memoryview(content)
                offset = 0
                while offset < len(view):
                    written = os.write(descriptor, view[offset:])
                    if written <= 0:
                        raise OSError("atomic write made no progress")
                    offset += written
                os.fchmod(descriptor, mode)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except Exception:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                pass
            raise
        try:
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
        except Exception:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except OSError:
                pass
            raise
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _atomic_json(path: Path, payload: object, mode: int = 0o600) -> None:
    _atomic_bytes(
        path,
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode,
    )


def _read_json(path: Path, reason: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise ReleaseRecoveryDenied(reason)
        value = json.loads(path.read_text(encoding="utf-8"))
    except ReleaseRecoveryDenied:
        raise
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseRecoveryDenied(reason) from error
    if not isinstance(value, dict):
        raise ReleaseRecoveryDenied(reason)
    return value


@dataclass(frozen=True, slots=True)
class ReleaseActivationSpec:
    recovery_id: str
    phase: str
    profile_name: str
    service_name: str
    old_pid: int
    release_root: str
    module_root: str
    version: str
    source_commit: str
    wheel_sha256: str
    expected_tools: int
    expected_hooks: int
    expected_middleware: int
    python_executable: str
    profile_root: str
    database_path: str
    dropin_path: str
    team_wrapper_path: str
    proactive_wrapper_path: str
    backup_dropin_path: str
    backup_team_wrapper_path: str
    backup_proactive_wrapper_path: str
    receipt_path: str
    unrelated_services: tuple[str, ...]
    restore_state_database: bool = False

    def __post_init__(self) -> None:
        if self.profile_name != GENERALIST2_PROFILE or self.service_name != GENERALIST2_SERVICE:
            raise ValueError("activation target must be exact Generalist2 service")
        if self.phase not in {"rollback", "redeploy"}:
            raise ValueError("activation phase must be rollback or redeploy")
        if self.restore_state_database is not False:
            raise ValueError("release activation cannot restore SQLite state")


class ReleaseActivationController(Protocol):
    def pid(self, service_name: str) -> int: ...

    def process_environment(self, pid: int) -> Mapping[str, str]: ...

    def activate(self, spec: ReleaseActivationSpec) -> None: ...


class SystemdUserReleaseController:
    """External-verifier activation for one drain-aware user service."""

    def __init__(self, *, timeout_seconds: int = 1200) -> None:
        if isinstance(timeout_seconds, bool) or not 30 <= timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be between 30 and 3600")
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _run(*args: str, check: bool = True, timeout: int = 180) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            check=check,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def pid(self, service_name: str) -> int:
        if service_name != GENERALIST2_SERVICE:
            raise ReleaseRecoveryDenied("RELEASE_TARGET_NOT_GENERALIST2")
        result = self._run(
            "systemctl", "--user", "show", service_name, "-p", "MainPID", "--value"
        )
        try:
            value = int(result.stdout.strip() or "0")
        except ValueError as error:
            raise ReleaseRecoveryDenied("GENERALIST2_PID_READBACK_FAILED") from error
        if value <= 0:
            raise ReleaseRecoveryDenied("GENERALIST2_SERVICE_NOT_RUNNING")
        return value

    def process_environment(self, pid: int) -> Mapping[str, str]:
        try:
            raw = Path(f"/proc/{pid}/environ").read_bytes()
        except OSError as error:
            raise ReleaseRecoveryDenied("GENERALIST2_PROCESS_ENV_UNAVAILABLE") from error
        environment: dict[str, str] = {}
        for row in raw.split(b"\0"):
            if b"=" not in row:
                continue
            key, value = row.split(b"=", 1)
            environment[key.decode("utf-8", "strict")] = value.decode("utf-8", "strict")
        return environment

    @staticmethod
    def _cgroup(pid: int) -> str:
        try:
            return Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").strip()
        except OSError as error:
            raise ReleaseRecoveryDenied("RELEASE_VERIFIER_CGROUP_UNAVAILABLE") from error

    def _adopt_verified_receipt(
        self, spec: ReleaseActivationSpec, receipt_path: Path
    ) -> None:
        receipt = _read_json(receipt_path, "POST_RELOAD_RECEIPT_MALFORMED")
        new_pid = receipt.get("new_pid")
        expected_loader = {
            "version": spec.version,
            "plugin_version": spec.version,
            "module_root": spec.module_root,
            "entrypoint_value": "hermes_plugin",
            "loaded_type": "module",
            "tools": spec.expected_tools,
            "hooks": spec.expected_hooks,
            "middleware": spec.expected_middleware,
            "chain_valid": True,
        }
        unrelated = receipt.get("unrelated_pids")
        if (
            receipt.get("status") != "VERIFIED"
            or receipt.get("phase") != spec.phase
            or receipt.get("recovery_id") != spec.recovery_id
            or receipt.get("old_pid") != spec.old_pid
            or isinstance(new_pid, bool)
            or not isinstance(new_pid, int)
            or new_pid <= 0
            or new_pid == spec.old_pid
            or receipt.get("version") != spec.version
            or receipt.get("source_commit") != spec.source_commit
            or receipt.get("wheel_sha256") != spec.wheel_sha256
            or receipt.get("module_root") != spec.module_root
            or receipt.get("loader") != expected_loader
            or receipt.get("database_restored") is not False
            or not isinstance(unrelated, dict)
            or set(unrelated) != set(spec.unrelated_services)
            or any(
                isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0
                for pid in unrelated.values()
            )
        ):
            raise ReleaseRecoveryDenied("POST_RELOAD_RECEIPT_COLLISION")
        if self.pid(spec.service_name) != new_pid:
            raise ReleaseRecoveryDenied("POST_RELOAD_RECEIPT_RUNTIME_STALE")
        expected_pythonpath = f"{spec.release_root}/bootstrap:{spec.module_root}"
        if self.process_environment(new_pid).get("PYTHONPATH") != expected_pythonpath:
            raise ReleaseRecoveryDenied("POST_RELOAD_RECEIPT_RUNTIME_STALE")

    @staticmethod
    def _archive_bound_failure_receipt(
        spec: ReleaseActivationSpec, receipt_path: Path
    ) -> None:
        receipt = _read_json(receipt_path, "POST_RELOAD_RECEIPT_MALFORMED")
        if (
            receipt.get("status") not in {"ROLLED_BACK", "ROLLBACK_INCOMPLETE"}
            or receipt.get("phase") != spec.phase
            or receipt.get("recovery_id") != spec.recovery_id
            or receipt.get("old_pid") != spec.old_pid
            or receipt.get("version") != spec.version
            or receipt.get("source_commit") != spec.source_commit
            or receipt.get("wheel_sha256") != spec.wheel_sha256
            or receipt.get("module_root") != spec.module_root
            or receipt.get("database_restored") is not False
        ):
            raise ReleaseRecoveryDenied("POST_RELOAD_RECEIPT_COLLISION")
        content = receipt_path.read_bytes()
        archived = receipt_path.with_name(
            f"post-reload-failure-{_digest_bytes(content)}.json"
        )
        if archived.exists():
            if archived.read_bytes() != content:
                raise ReleaseRecoveryDenied("POST_RELOAD_FAILURE_ARCHIVE_COLLISION")
            receipt_path.unlink()
        else:
            os.replace(receipt_path, archived)

    def activate(self, spec: ReleaseActivationSpec) -> None:
        if spec.profile_name != GENERALIST2_PROFILE or spec.service_name != GENERALIST2_SERVICE:
            raise ReleaseRecoveryDenied("RELEASE_TARGET_NOT_GENERALIST2")
        if spec.restore_state_database is not False:
            raise ReleaseRecoveryDenied("STATE_DATABASE_RESTORE_FORBIDDEN")
        spec_path = Path(spec.receipt_path).with_name("activation-spec.json")
        receipt_path = Path(spec.receipt_path)
        if receipt_path.exists():
            existing = _read_json(receipt_path, "POST_RELOAD_RECEIPT_MALFORMED")
            if existing.get("status") == "VERIFIED":
                self._adopt_verified_receipt(spec, receipt_path)
                return
            self._archive_bound_failure_receipt(spec, receipt_path)
        _atomic_json(spec_path, asdict(spec))
        self._run("systemctl", "--user", "daemon-reload")
        unit = f"cct-release-{_payload_digest([spec.recovery_id, spec.phase])[:16]}-verifier.service"
        launched = self._run(
            "systemd-run",
            "--user",
            f"--unit={unit}",
            "--collect",
            f"--property=RuntimeMaxSec={self.timeout_seconds + 300}",
            "--property=TimeoutStopSec=10",
            f"--setenv=PYTHONPATH={Path(__file__).resolve().parent.parent}",
            "--setenv=PYTHONNOUSERSITE=1",
            spec.python_executable,
            "-P",
            "-m",
            "cct_agent.release_host_verifier",
            "--spec",
            str(spec_path),
        )
        del launched
        verifier_pid = 0
        for _ in range(100):
            result = self._run(
                "systemctl", "--user", "show", unit, "-p", "MainPID", "--value"
            )
            verifier_pid = int(result.stdout.strip() or "0")
            if verifier_pid:
                break
            time.sleep(0.05)
        if not verifier_pid or self._cgroup(verifier_pid) == self._cgroup(spec.old_pid):
            raise ReleaseRecoveryDenied("EXTERNAL_RELEASE_VERIFIER_NOT_ISOLATED")
        reload_result = self._run(
            "systemctl", "--user", "reload", spec.service_name, check=False
        )
        if reload_result.returncode:
            raise ReleaseRecoveryDenied("GENERALIST2_DRAIN_RELOAD_FAILED")
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            if receipt_path.exists():
                self._adopt_verified_receipt(spec, receipt_path)
                return
            time.sleep(0.25)
        raise ReleaseRecoveryDenied("POST_RELOAD_VERIFIER_TIMEOUT")


@dataclass(frozen=True, slots=True)
class Generalist2ReleaseHostConfig:
    repository_root: Path
    host_home_root: Path
    profile_root: Path
    staging_root: Path
    adapter_state_root: Path
    systemd_user_root: Path
    dropin_path: Path
    team_wrapper_path: Path
    proactive_wrapper_path: Path
    database_path: Path
    python_executable: Path
    uv_executable: Path
    expected_tools: int = 22
    expected_hooks: int = 3
    expected_middleware: int = 1
    unrelated_services: tuple[str, ...] = (
        "hermes-gateway.service",
        "hermes-gateway-generalist1.service",
        "hermes-gateway-generalist3.service",
    )
    profile_name: str = GENERALIST2_PROFILE
    service_name: str = GENERALIST2_SERVICE

    def __post_init__(self) -> None:
        if self.profile_name != GENERALIST2_PROFILE or self.service_name != GENERALIST2_SERVICE:
            raise ValueError("host adapter target must be exact Generalist2 service")
        for name in ("expected_tools", "expected_hooks", "expected_middleware"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        roots = {
            "repository_root": _require_absolute_real_directory(
                Path(self.repository_root), "repository_root"
            ),
            "host_home_root": _require_absolute_real_directory(
                Path(self.host_home_root), "host_home_root"
            ),
            "profile_root": _require_absolute_real_directory(Path(self.profile_root), "profile_root"),
            "staging_root": _require_absolute_real_directory(Path(self.staging_root), "staging_root"),
            "adapter_state_root": _require_absolute_real_directory(
                Path(self.adapter_state_root), "adapter_state_root"
            ),
            "systemd_user_root": _require_absolute_real_directory(
                Path(self.systemd_user_root), "systemd_user_root"
            ),
        }
        if roots["profile_root"].name != GENERALIST2_PROFILE:
            raise ValueError("profile_root must end in generalist2")
        if roots["profile_root"] != (
            roots["host_home_root"] / ".hermes" / "profiles" / GENERALIST2_PROFILE
        ) or roots["systemd_user_root"] != (
            roots["host_home_root"] / ".config" / "systemd" / "user"
        ):
            raise ValueError("profile and systemd roots must belong to exact host home")
        for name, value in roots.items():
            object.__setattr__(self, name, value)
        for name in ("dropin_path", "team_wrapper_path", "proactive_wrapper_path", "database_path"):
            path = Path(getattr(self, name))
            if not path.is_absolute() or path.is_symlink():
                raise ValueError(f"{name} must be an exact absolute non-symlink path")
            object.__setattr__(self, name, path)
        expected_paths = {
            "dropin_path": roots["systemd_user_root"]
            / f"{GENERALIST2_SERVICE}.d"
            / "cct-profile-local.conf",
            "team_wrapper_path": roots["profile_root"]
            / "scripts"
            / "cct_team_sync_tick.sh",
            "proactive_wrapper_path": roots["profile_root"]
            / "scripts"
            / "cct_proactive_tick.sh",
            "database_path": roots["profile_root"] / "cct-agency" / "agency.sqlite",
        }
        for name, expected in expected_paths.items():
            if Path(getattr(self, name)) != expected:
                raise ValueError(f"{name} must target exact Generalist2 path")
            root = (
                roots["systemd_user_root"]
                if name == "dropin_path"
                else roots["profile_root"]
            )
            _require_exact_file_path(expected, root, name)
        object.__setattr__(
            self, "python_executable", _require_absolute_file(Path(self.python_executable), "python_executable")
        )
        object.__setattr__(
            self, "uv_executable", _require_absolute_file(Path(self.uv_executable), "uv_executable")
        )
        os.chmod(roots["staging_root"], 0o700)
        os.chmod(roots["adapter_state_root"], 0o700)


_LOADER_PROBE = r'''
import importlib.metadata as md
import json
import os
from pathlib import Path
import cct_agent

module_root = str(Path(cct_agent.__file__).resolve().parent.parent)
distributions = list(md.distributions(path=[module_root]))
eps = [ep for dist in distributions for ep in dist.entry_points if ep.group == "hermes_agent.plugins" and ep.name == "cct-agency"]
if len(eps) != 1:
    raise SystemExit(f"entrypoint count mismatch: {len(eps)}")
plugin = eps[0].load()
class Context:
    def __init__(self):
        self.tools = {}
        self.hooks = {}
        self.middlewares = []
    def get_config(self, key, default=None):
        return default
    def register_tool(self, name, handler, schema=None, **kwargs):
        self.tools[name] = handler
    def register_hook(self, name, handler, **kwargs):
        self.hooks.setdefault(name, []).append(handler)
    def register_middleware(self, name, handler, **kwargs):
        self.middlewares.append((name, handler))
context = Context()
plugin.register(context)
status = json.loads(context.tools["cct_status"]({}))
print(json.dumps({
    "version": cct_agent.__version__,
    "plugin_version": plugin.PLUGIN_VERSION,
    "module_root": module_root,
    "entrypoint_value": eps[0].value,
    "loaded_type": type(plugin).__name__,
    "tools": len(context.tools),
    "hooks": sum(len(rows) for rows in context.hooks.values()),
    "middleware": len(context.middlewares),
    "chain_valid": status["status"]["chain"]["valid"],
}, sort_keys=True))
'''

_RUNTIME_PROBE = r'''
import json
from pathlib import Path
import cct_agent
from cct_agent.store import EventStore
store = EventStore(Path(__import__("sys").argv[1]))
print(json.dumps({
    "version": cct_agent.__version__,
    "module_root": str(Path(cct_agent.__file__).resolve().parent.parent),
    "chain_valid": store.verify_chain()["valid"],
}, sort_keys=True))
'''


class Generalist2ReleaseHostAdapter:
    """Real host implementation of ``ReleaseRecoveryAdapter`` for Generalist2."""

    def __init__(
        self,
        config: Generalist2ReleaseHostConfig,
        *,
        controller: ReleaseActivationController | None = None,
    ) -> None:
        if not isinstance(config, Generalist2ReleaseHostConfig):
            raise ValueError("config must be Generalist2ReleaseHostConfig")
        self.config = config
        self.controller = controller or SystemdUserReleaseController()
        required = ("pid", "process_environment", "activate")
        if not all(callable(getattr(self.controller, name, None)) for name in required):
            raise ValueError("controller does not implement release activation contract")

    def _run(
        self,
        *args: str,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int = 300,
        child_umask: int = -1,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                args,
                cwd=cwd,
                env=dict(env) if env is not None else None,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                umask=child_umask,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ReleaseRecoveryDenied("RELEASE_HOST_COMMAND_FAILED") from error

    def _state_dir(self, recovery_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}", recovery_id):
            raise ReleaseRecoveryDenied("RELEASE_RECOVERY_ID_INVALID")
        path = self.config.adapter_state_root / recovery_id
        path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
        return path

    def _release_root(self, module_root: str) -> Path:
        root = _safe_descendant(Path(module_root), self.config.staging_root, "RELEASE_MODULE_ROOT_OUTSIDE_STAGING")
        if root.name != "site-packages":
            raise ReleaseRecoveryDenied("RELEASE_MODULE_ROOT_INVALID")
        release = root.parent
        if release == self.config.staging_root or release.parent != self.config.staging_root:
            raise ReleaseRecoveryDenied("RELEASE_ROOT_INVALID")
        return release

    def _manifest(self, release_root: Path) -> dict[str, Any]:
        manifest = _read_json(
            release_root / "receipts" / "release-manifest.json",
            "RELEASE_MANIFEST_MALFORMED",
        )
        if manifest.get("schema_version") != RELEASE_MANIFEST_VERSION:
            raise ReleaseRecoveryDenied("RELEASE_MANIFEST_VERSION_MISMATCH")
        module_root = release_root / "site-packages"
        if manifest.get("module_root") != str(module_root):
            raise ReleaseRecoveryDenied("RELEASE_MANIFEST_MODULE_ROOT_MISMATCH")
        source_commit = manifest.get("source_commit")
        wheel_sha256 = manifest.get("wheel_sha256")
        if not isinstance(source_commit, str) or not _COMMIT.fullmatch(source_commit):
            raise ReleaseRecoveryDenied("RELEASE_MANIFEST_SOURCE_INVALID")
        if not isinstance(wheel_sha256, str) or not _DIGEST.fullmatch(wheel_sha256):
            raise ReleaseRecoveryDenied("RELEASE_MANIFEST_WHEEL_INVALID")
        artifact_relative = manifest.get("artifact_relative_path")
        if not isinstance(artifact_relative, str) or Path(artifact_relative).is_absolute():
            raise ReleaseRecoveryDenied("RELEASE_MANIFEST_ARTIFACT_PATH_INVALID")
        artifact = (release_root / artifact_relative).resolve(strict=True)
        if not artifact.is_relative_to(release_root) or artifact.is_symlink():
            raise ReleaseRecoveryDenied("RELEASE_MANIFEST_ARTIFACT_PATH_INVALID")
        artifact_metadata = artifact.stat()
        if (
            not stat.S_ISREG(artifact_metadata.st_mode)
            or artifact_metadata.st_uid != os.getuid()
            or artifact_metadata.st_nlink != 1
        ):
            raise ReleaseRecoveryDenied("RELEASE_ARTIFACT_FILE_UNSAFE")
        if _digest_file(artifact) != wheel_sha256:
            raise ReleaseRecoveryDenied("RELEASE_ARTIFACT_DIGEST_MISMATCH")
        source_tree_sha256 = manifest.get("source_tree_sha256")
        if (
            not isinstance(source_tree_sha256, str)
            or not _DIGEST.fullmatch(source_tree_sha256)
            or self._source_tree_digest(release_root / "source") != source_tree_sha256
            or self._git_tree_digest(source_commit) != source_tree_sha256
        ):
            raise ReleaseRecoveryDenied("RELEASE_SOURCE_TREE_MISMATCH")
        self._verify_installed_members(artifact, module_root)
        if not self._wheel_source_exact(release_root / "source", artifact):
            raise ReleaseRecoveryDenied("RELEASE_WHEEL_SOURCE_IDENTITY_MISMATCH")
        return manifest

    @staticmethod
    def _tree_digest(rows: list[dict[str, object]]) -> str:
        return _payload_digest(sorted(rows, key=lambda row: str(row["path"])))

    @classmethod
    def _source_tree_digest(cls, root: Path) -> str:
        if not root.is_dir() or root.is_symlink():
            raise ReleaseRecoveryDenied("RELEASE_SOURCE_TREE_MISSING")
        rows: list[dict[str, object]] = []
        for path in root.rglob("*"):
            relative = str(path.relative_to(root))
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ReleaseRecoveryDenied("RELEASE_SOURCE_TREE_UNSAFE")
            rows.append(
                {
                    "path": relative,
                    "sha256": _digest_file(path),
                    "executable": bool(metadata.st_mode & 0o111),
                }
            )
        if not rows:
            raise ReleaseRecoveryDenied("RELEASE_SOURCE_TREE_MISSING")
        return cls._tree_digest(rows)

    def _git_tree_digest(self, commit: str) -> str:
        try:
            archive = subprocess.run(
                ["git", "archive", "--format=tar", commit],
                cwd=self.config.repository_root,
                check=True,
                capture_output=True,
                timeout=180,
            ).stdout
            rows: list[dict[str, object]] = []
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
                for member in bundle.getmembers():
                    if member.isdir():
                        continue
                    if not member.isfile():
                        raise ReleaseRecoveryDenied("REVIEWED_SOURCE_TREE_UNSAFE")
                    stream = bundle.extractfile(member)
                    if stream is None:
                        raise ReleaseRecoveryDenied("REVIEWED_SOURCE_TREE_INVALID")
                    rows.append(
                        {
                            "path": member.name,
                            "sha256": _digest_bytes(stream.read()),
                            "executable": bool(member.mode & 0o111),
                        }
                    )
        except ReleaseRecoveryDenied:
            raise
        except (OSError, subprocess.SubprocessError, tarfile.TarError) as error:
            raise ReleaseRecoveryDenied("REVIEWED_SOURCE_TREE_INVALID") from error
        return self._tree_digest(rows)

    @staticmethod
    def _verify_installed_members(wheel: Path, module_root: Path) -> None:
        try:
            with zipfile.ZipFile(wheel) as archive:
                package_members = {
                    name: archive.read(name)
                    for name in archive.namelist()
                    if not name.endswith("/")
                    and (name.startswith("cct_agent/") or name.startswith("hermes_plugin/"))
                }
        except (OSError, zipfile.BadZipFile) as error:
            raise ReleaseRecoveryDenied("RELEASE_WHEEL_INVALID") from error
        if not package_members:
            raise ReleaseRecoveryDenied("RELEASE_WHEEL_PACKAGES_MISSING")
        for name, expected in package_members.items():
            path = module_root / name
            try:
                metadata = path.lstat()
            except OSError as error:
                raise ReleaseRecoveryDenied("INSTALLED_WHEEL_MEMBER_MISSING") from error
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or _digest_file(path) != _digest_bytes(expected)
            ):
                raise ReleaseRecoveryDenied("INSTALLED_WHEEL_MEMBER_MISMATCH")
        actual_members = {
            str(path.relative_to(module_root))
            for package_name in ("cct_agent", "hermes_plugin")
            for path in (module_root / package_name).rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
        }
        if actual_members != set(package_members):
            raise ReleaseRecoveryDenied("INSTALLED_WHEEL_MEMBER_SET_MISMATCH")

    def _probe(self, code: str, *, module_root: Path, home: Path, database: Path | None = None) -> dict[str, Any]:
        bootstrap = module_root.parent / "bootstrap"
        environment = {
            "HOME": os.environ.get("HOME", str(self.config.profile_root.parent)),
            "HERMES_HOME": str(home),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": f"{bootstrap}:{module_root}",
            "PYTHONNOUSERSITE": "1",
            "CCT_IDENTITY": "Generalist2-CCT",
        }
        args = [str(self.config.python_executable), "-P", "-c", code]
        if database is not None:
            args.append(str(database))
        result = self._run(*args, cwd=Path("/tmp"), env=environment, timeout=300)
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ReleaseRecoveryDenied("RELEASE_LOADER_PROBE_MALFORMED") from error
        if not isinstance(value, dict):
            raise ReleaseRecoveryDenied("RELEASE_LOADER_PROBE_MALFORMED")
        return value

    def inspect_runtime(self) -> ReleaseRuntimeState:
        pid = self.controller.pid(GENERALIST2_SERVICE)
        environment = self.controller.process_environment(pid)
        raw_pythonpath = environment.get("PYTHONPATH")
        if not isinstance(raw_pythonpath, str):
            raise ReleaseRecoveryDenied("LIVE_PYTHONPATH_MISSING")
        roots = [Path(value) for value in raw_pythonpath.split(os.pathsep) if value]
        module_roots = [path for path in roots if path.name == "site-packages"]
        if len(module_roots) != 1:
            raise ReleaseRecoveryDenied("LIVE_MODULE_ROOT_AMBIGUOUS")
        release_root = self._release_root(str(module_roots[0]))
        manifest = self._manifest(release_root)
        loaded = self._probe(
            _RUNTIME_PROBE,
            module_root=module_roots[0],
            home=self.config.profile_root,
            database=self.config.database_path,
        )
        if (
            loaded.get("version") != manifest.get("version")
            or loaded.get("module_root") != str(module_roots[0])
        ):
            raise ReleaseRecoveryDenied("LIVE_RELEASE_LOADER_MISMATCH")
        return ReleaseRuntimeState(
            profile_name=GENERALIST2_PROFILE,
            service_name=GENERALIST2_SERVICE,
            pid=pid,
            version=str(manifest["version"]),
            module_root=str(module_roots[0]),
            wheel_sha256=str(manifest["wheel_sha256"]),
            source_commit=str(manifest["source_commit"]),
            chain_valid=loaded.get("chain_valid") is True,
        )

    def _artifact_receipt_path(self, recovery_id: str) -> Path:
        return self._state_dir(recovery_id) / "artifact.json"

    def _verification_receipt_path(self, recovery_id: str) -> Path:
        return self._state_dir(recovery_id) / "verification.json"

    def inspect_artifact(self, recovery_id: str) -> ReleaseArtifact | None:
        path = self._artifact_receipt_path(recovery_id)
        if not path.exists():
            return None
        value = _read_json(path, "HOST_ARTIFACT_RECEIPT_MALFORMED")
        material = value.get("artifact")
        if (
            value.get("schema_version") != HOST_ARTIFACT_RECEIPT_VERSION
            or not isinstance(material, dict)
            or value.get("artifact_sha256") != _payload_digest(material)
        ):
            raise ReleaseRecoveryDenied("HOST_ARTIFACT_RECEIPT_MALFORMED")
        artifact = ReleaseArtifact(**material)
        release_root = self._release_root(str(value.get("module_root")))
        manifest = self._manifest(release_root)
        if (
            manifest.get("source_commit") != artifact.source_commit
            or manifest.get("version") != artifact.version
            or manifest.get("wheel_sha256") != artifact.wheel_sha256
        ):
            raise ReleaseRecoveryDenied("HOST_ARTIFACT_RECEIPT_STALE")
        return artifact

    def inspect_verification(self, recovery_id: str) -> IsolatedReleaseVerification | None:
        path = self._verification_receipt_path(recovery_id)
        if not path.exists():
            return None
        value = _read_json(path, "HOST_VERIFICATION_RECEIPT_MALFORMED")
        material = value.get("verification")
        if (
            value.get("schema_version") != HOST_VERIFICATION_RECEIPT_VERSION
            or not isinstance(material, dict)
            or value.get("receipt_sha256") != _payload_digest(material)
        ):
            raise ReleaseRecoveryDenied("HOST_VERIFICATION_RECEIPT_MALFORMED")
        verification = IsolatedReleaseVerification(**material)
        binding_material = dict(material)
        binding_digest = binding_material.pop("receipt_sha256", None)
        if (
            binding_digest != verification.receipt_sha256
            or verification.receipt_sha256 != _payload_digest(binding_material)
        ):
            raise ReleaseRecoveryDenied("HOST_VERIFICATION_RECEIPT_DIGEST_MISMATCH")
        return verification

    def _git(self, *args: str) -> str:
        return self._run("git", *args, cwd=self.config.repository_root).stdout.strip()

    @staticmethod
    def _extract_source(archive_bytes: bytes, destination: Path) -> None:
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
                members = archive.getmembers()
                for member in members:
                    target = (destination / member.name).resolve(strict=False)
                    if not target.is_relative_to(destination):
                        raise ReleaseRecoveryDenied("SOURCE_ARCHIVE_PATH_ESCAPE")
                    if member.issym() or member.islnk() or member.isdev():
                        raise ReleaseRecoveryDenied("SOURCE_ARCHIVE_UNSAFE_MEMBER")
                archive.extractall(destination, members=members, filter="data")
                for member in members:
                    target = (destination / member.name).resolve(strict=True)
                    if member.isdir():
                        os.chmod(target, 0o755)
                    elif member.isfile():
                        os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
        except ReleaseRecoveryDenied:
            raise
        except (OSError, tarfile.TarError) as error:
            raise ReleaseRecoveryDenied("SOURCE_ARCHIVE_INVALID") from error

    @staticmethod
    def _extract_wheel(wheel: Path, destination: Path) -> None:
        try:
            with zipfile.ZipFile(wheel) as archive:
                for info in archive.infolist():
                    if info.filename.endswith("/"):
                        continue
                    target = (destination / info.filename).resolve(strict=False)
                    if not target.is_relative_to(destination):
                        raise ReleaseRecoveryDenied("WHEEL_MEMBER_PATH_ESCAPE")
                    mode = (info.external_attr >> 16) & 0o170000
                    if mode == stat.S_IFLNK:
                        raise ReleaseRecoveryDenied("WHEEL_SYMLINK_FORBIDDEN")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(info.filename))
                    os.chmod(target, 0o600)
        except ReleaseRecoveryDenied:
            raise
        except (OSError, zipfile.BadZipFile) as error:
            raise ReleaseRecoveryDenied("RELEASE_WHEEL_INVALID") from error

    @staticmethod
    def _wheel_version(wheel: Path) -> str:
        with zipfile.ZipFile(wheel) as archive:
            metadata_names = [
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_names) != 1:
                raise ReleaseRecoveryDenied("WHEEL_METADATA_MISSING")
            metadata = archive.read(metadata_names[0]).decode("utf-8", "strict")
        versions = [line[9:].strip() for line in metadata.splitlines() if line.startswith("Version: ")]
        if len(versions) != 1:
            raise ReleaseRecoveryDenied("WHEEL_VERSION_MISSING")
        return versions[0]

    @staticmethod
    def _wheel_source_exact(source: Path, wheel: Path) -> bool:
        with zipfile.ZipFile(wheel) as archive:
            members = {
                name: archive.read(name)
                for name in archive.namelist()
                if not name.endswith("/")
                and (name.startswith("cct_agent/") or name.startswith("hermes_plugin/"))
            }
        if not members:
            return False
        for name, value in members.items():
            source_path = source / name
            if not source_path.is_file() or source_path.read_bytes() != value:
                return False
        source_members = {
            str(path.relative_to(source))
            for package in (source / "cct_agent", source / "hermes_plugin")
            if package.is_dir()
            for path in package.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
        }
        return source_members == set(members)

    def rebuild_exact(self, ticket: ExactRebuildTicket) -> ReleaseArtifact:
        if not isinstance(ticket, ExactRebuildTicket):
            raise ValueError("ticket must be ExactRebuildTicket")
        existing = self.inspect_artifact(ticket.recovery_id)
        if existing is not None:
            return existing
        release_root = self._release_root(
            str(self.config.staging_root / f"release-{ticket.source_commit[:12]}-{ticket.version}" / "site-packages")
        )
        # Expected module root is carried by the subsequent verification ticket. Keep a
        # deterministic host convention so a mismatch receipt can bind it before build.
        if release_root.exists():
            manifest = self._manifest(release_root)
            artifact = ReleaseArtifact(
                recovery_id=ticket.recovery_id,
                source_commit=str(manifest["source_commit"]),
                version=str(manifest["version"]),
                wheel_sha256=str(manifest["wheel_sha256"]),
                byte_count=int(manifest["byte_count"]),
                wheel_source_exact=manifest.get("wheel_source_exact") is True,
            )
        else:
            self._git("cat-file", "-e", f"{ticket.source_commit}^{{commit}}")
            stage = release_root.with_name(f".{release_root.name}.{os.getpid()}.building")
            if stage.exists():
                raise ReleaseRecoveryDenied("RELEASE_BUILD_STAGE_COLLISION")
            stage.mkdir(mode=0o700)
            try:
                source = stage / "source"
                source.mkdir(mode=0o700)
                archive = subprocess.run(
                    ["git", "archive", "--format=tar", ticket.source_commit],
                    cwd=self.config.repository_root,
                    check=True,
                    capture_output=True,
                    timeout=180,
                ).stdout
                self._extract_source(archive, source)
                source_tree_sha256 = self._source_tree_digest(source)
                if source_tree_sha256 != self._git_tree_digest(ticket.source_commit):
                    raise ReleaseRecoveryDenied("EXPORTED_SOURCE_TREE_MISMATCH")
                commit_epoch = self._git("show", "-s", "--format=%ct", ticket.source_commit)
                artifact_dir = stage / "artifact"
                artifact_dir.mkdir(mode=0o700)
                build_source = stage / "build-source"
                shutil.copytree(source, build_source)
                environment = dict(os.environ)
                environment.update(
                    {
                        "SOURCE_DATE_EPOCH": commit_epoch,
                        "PYTHONHASHSEED": "0",
                        "TZ": "UTC",
                        "UV_NO_CACHE": "1",
                    }
                )
                self._run(
                    str(self.config.uv_executable),
                    "build",
                    "--wheel",
                    "--out-dir",
                    str(artifact_dir),
                    str(build_source),
                    cwd=Path("/tmp"),
                    env=environment,
                    timeout=600,
                    child_umask=0o022,
                )
                wheels = list(artifact_dir.glob("*.whl"))
                if len(wheels) != 1:
                    raise ReleaseRecoveryDenied("EXACT_BUILD_WHEEL_COUNT_MISMATCH")
                wheel = wheels[0]
                observed_digest = _digest_file(wheel)
                if observed_digest != ticket.expected_wheel_sha256:
                    raise ReleaseRecoveryDenied("EXACT_BUILD_WHEEL_DIGEST_MISMATCH")
                if self._wheel_version(wheel) != ticket.version:
                    raise ReleaseRecoveryDenied("EXACT_BUILD_WHEEL_VERSION_MISMATCH")
                exact = self._wheel_source_exact(source, wheel)
                if not exact:
                    raise ReleaseRecoveryDenied("EXACT_BUILD_SOURCE_BYTES_MISMATCH")
                shutil.rmtree(build_source)
                module_root = stage / "site-packages"
                module_root.mkdir(mode=0o700)
                self._extract_wheel(wheel, module_root)
                self._verify_installed_members(wheel, module_root)
                bootstrap = stage / "bootstrap"
                bootstrap.mkdir(mode=0o700)
                sitecustomize = (
                    "from pathlib import Path\n"
                    "import sys\n"
                    f"SITE = Path({str(release_root / 'site-packages')!r}).resolve()\n"
                    "text = str(SITE)\n"
                    "if text in sys.path:\n    sys.path.remove(text)\n"
                    "sys.path.insert(0, text)\n"
                )
                (bootstrap / "sitecustomize.py").write_text(sitecustomize, encoding="utf-8")
                os.chmod(bootstrap / "sitecustomize.py", 0o600)
                receipts = stage / "receipts"
                receipts.mkdir(mode=0o700)
                final_artifact = release_root / "artifact" / wheel.name
                manifest = {
                    "schema_version": RELEASE_MANIFEST_VERSION,
                    "source_commit": ticket.source_commit,
                    "version": ticket.version,
                    "wheel_sha256": observed_digest,
                    "byte_count": wheel.stat().st_size,
                    "wheel_source_exact": True,
                    "source_tree_sha256": source_tree_sha256,
                    "module_root": str(release_root / "site-packages"),
                    "artifact_relative_path": f"artifact/{wheel.name}",
                    "profile_name": GENERALIST2_PROFILE,
                    "service_name": GENERALIST2_SERVICE,
                    "database_restored": False,
                }
                _atomic_json(receipts / "release-manifest.json", manifest)
                os.rename(stage, release_root)
                del final_artifact
                artifact = ReleaseArtifact(
                    recovery_id=ticket.recovery_id,
                    source_commit=ticket.source_commit,
                    version=ticket.version,
                    wheel_sha256=observed_digest,
                    byte_count=int(manifest["byte_count"]),
                    wheel_source_exact=True,
                )
            except Exception:
                if stage.exists():
                    shutil.rmtree(stage)
                raise
        if (
            artifact.source_commit != ticket.source_commit
            or artifact.version != ticket.version
            or artifact.wheel_sha256 != ticket.expected_wheel_sha256
            or not artifact.wheel_source_exact
        ):
            raise ReleaseRecoveryDenied("EXACT_BUILD_ARTIFACT_MISMATCH")
        material = asdict(artifact)
        _atomic_json(
            self._artifact_receipt_path(ticket.recovery_id),
            {
                "schema_version": HOST_ARTIFACT_RECEIPT_VERSION,
                "artifact": material,
                "artifact_sha256": _payload_digest(material),
                "module_root": str(release_root / "site-packages"),
                "raw_artifact_persisted": False,
            },
        )
        return artifact

    def verify_isolated(
        self,
        ticket: IsolatedVerificationTicket,
        artifact: ReleaseArtifact,
    ) -> IsolatedReleaseVerification:
        if not isinstance(ticket, IsolatedVerificationTicket) or not isinstance(
            artifact, ReleaseArtifact
        ):
            raise ValueError("isolated verification requires typed ticket and artifact")
        existing = self.inspect_verification(ticket.recovery_id)
        if existing is not None:
            return existing
        release_root = self._release_root(ticket.expected_module_root)
        manifest = self._manifest(release_root)
        if (
            ticket.source_commit != artifact.source_commit
            or ticket.version != artifact.version
            or ticket.wheel_sha256 != artifact.wheel_sha256
            or manifest.get("source_commit") != ticket.source_commit
            or manifest.get("version") != ticket.version
            or manifest.get("wheel_sha256") != ticket.wheel_sha256
        ):
            raise ReleaseRecoveryDenied("ISOLATED_VERIFICATION_INPUT_MISMATCH")
        with tempfile.TemporaryDirectory(
            prefix="cct-release-verify-", dir=self.config.adapter_state_root
        ) as temporary:
            home = Path(temporary) / "home"
            home.mkdir(mode=0o700)
            loaded = self._probe(
                _LOADER_PROBE,
                module_root=Path(ticket.expected_module_root),
                home=home,
            )
        passed = loaded == {
            "version": ticket.version,
            "plugin_version": ticket.version,
            "module_root": ticket.expected_module_root,
            "entrypoint_value": "hermes_plugin",
            "loaded_type": "module",
            "tools": self.config.expected_tools,
            "hooks": self.config.expected_hooks,
            "middleware": self.config.expected_middleware,
            "chain_valid": True,
        }
        material_without_digest = {
            "recovery_id": ticket.recovery_id,
            "source_commit": ticket.source_commit,
            "version": ticket.version,
            "module_root": ticket.expected_module_root,
            "wheel_sha256": ticket.wheel_sha256,
            "wheel_source_exact": artifact.wheel_source_exact,
            "tools": int(loaded.get("tools", -1)),
            "hooks": int(loaded.get("hooks", -1)),
            "middleware": int(loaded.get("middleware", -1)),
            "passed": passed,
        }
        receipt_sha256 = _payload_digest(material_without_digest)
        verification = IsolatedReleaseVerification(
            **material_without_digest,
            receipt_sha256=receipt_sha256,
        )
        material = asdict(verification)
        _atomic_json(
            self._verification_receipt_path(ticket.recovery_id),
            {
                "schema_version": HOST_VERIFICATION_RECEIPT_VERSION,
                "verification": material,
                "receipt_sha256": _payload_digest(material),
                "raw_conversation_persisted": False,
            },
        )
        # The typed bridge requires receipt_sha256 itself to bind the verification
        # material excluding that self-reference. inspect_verification revalidates both.
        return verification

    def _copy_backup(self, source: Path, destination: Path, mode: int) -> None:
        try:
            content = source.read_bytes()
        except OSError as error:
            raise ReleaseRecoveryDenied("RELEASE_ACTIVATION_PRESTATE_MISSING") from error
        _atomic_bytes(destination, content, mode)

    def _candidate_files(self, release_root: Path, version: str) -> tuple[bytes, bytes, bytes]:
        module_root = release_root / "site-packages"
        bootstrap = release_root / "bootstrap"
        dropin = (
            "[Service]\n"
            f'Environment="PYTHONPATH={bootstrap}:{module_root}"\n'
        ).encode("utf-8")
        team = f'''#!/usr/bin/env bash
set -euo pipefail
HERMES_HOME="${{HERMES_HOME:-{self.config.profile_root}}}"
export HERMES_HOME
CCT_RELEASE_ROOT="{release_root}"
export PYTHONPATH="$CCT_RELEASE_ROOT/bootstrap:$CCT_RELEASE_ROOT/site-packages"
export PYTHONNOUSERSITE=1
export CCT_IDENTITY="${{CCT_IDENTITY:-Generalist2-CCT}}"
export CCT_TEAM_SYNC_SOURCE="${{CCT_TEAM_SYNC_SOURCE:-/path/to/operator-home/.openclaw/workspace/automation/team-sync/project_changes.jsonl}}"
exec {self.config.python_executable} -P "$CCT_RELEASE_ROOT/source/scripts/cct_team_sync_tick.py" "$@"
'''.encode("utf-8")
        proactive = f'''#!/usr/bin/env bash
set -euo pipefail
HERMES_HOME="${{HERMES_HOME:-{self.config.profile_root}}}"
export HERMES_HOME
CCT_RELEASE_ROOT="{release_root}"
STATE_ROOT="$HERMES_HOME/cct-agency"
WORK_ROOT="$STATE_ROOT/work-autonomy"
WAKE_ROOT="$STATE_ROOT/recurrent/slice31-b19d05d"
export PYTHONPATH="$CCT_RELEASE_ROOT/bootstrap:$CCT_RELEASE_ROOT/site-packages"
export PYTHONNOUSERSITE=1
work_output=$(
  {self.config.python_executable} -P -c 'from cct_agent.work_autonomy import main; raise SystemExit(main())' \\
    --state-root "$STATE_ROOT" --workspace-root "$WORK_ROOT/workspace" --private-root "$WORK_ROOT/private" \\
    --identity Generalist2-CCT --expected-module-root "$CCT_RELEASE_ROOT/site-packages" \\
    --expected-package-version {version} --time-bucket "${{CCT_TIME_BUCKET:-$(date +%F)}}" --message-only "$@"
)
if [[ -n "$work_output" ]]; then printf '%s\\n' "$work_output"; exit 0; fi
exec {self.config.python_executable} -P -m cct_agent.recurrent \\
  --state-root "$STATE_ROOT" --workspace-root "$WAKE_ROOT/workspace" --deployment-sink "$WAKE_ROOT/deployment" \\
  --outbox-root "$WAKE_ROOT/outbox" --receipt-file "$WAKE_ROOT/recurrent-wake.json" \\
  --secret-file "$WAKE_ROOT/recurrent-secret.key" --identity Generalist2-CCT --principal-id mike \\
  --expected-module-root "$CCT_RELEASE_ROOT/site-packages" --expected-package-version {version} --message-only "$@"
'''.encode("utf-8")
        return dropin, team, proactive

    def _activate_release(
        self,
        *,
        recovery_id: str,
        phase: str,
        release_root: Path,
        old_pid: int,
    ) -> ReleaseRuntimeState:
        manifest = self._manifest(release_root)
        state_dir = self._state_dir(recovery_id) / phase
        state_dir.mkdir(mode=0o700, exist_ok=True)
        backups = (
            (self.config.dropin_path, state_dir / "pre-dropin.conf", 0o644),
            (self.config.team_wrapper_path, state_dir / "pre-team-wrapper.sh", 0o700),
            (self.config.proactive_wrapper_path, state_dir / "pre-proactive-wrapper.sh", 0o700),
        )
        for source, destination, mode in backups:
            if not destination.exists():
                self._copy_backup(source, destination, mode)
        dropin, team, proactive = self._candidate_files(release_root, str(manifest["version"]))
        _atomic_bytes(self.config.dropin_path, dropin, 0o644)
        _atomic_bytes(self.config.team_wrapper_path, team, 0o700)
        _atomic_bytes(self.config.proactive_wrapper_path, proactive, 0o700)
        receipt_path = state_dir / "post-reload.json"
        spec = ReleaseActivationSpec(
            recovery_id=recovery_id,
            phase=phase,
            profile_name=GENERALIST2_PROFILE,
            service_name=GENERALIST2_SERVICE,
            old_pid=old_pid,
            release_root=str(release_root),
            module_root=str(release_root / "site-packages"),
            version=str(manifest["version"]),
            source_commit=str(manifest["source_commit"]),
            wheel_sha256=str(manifest["wheel_sha256"]),
            expected_tools=self.config.expected_tools,
            expected_hooks=self.config.expected_hooks,
            expected_middleware=self.config.expected_middleware,
            python_executable=str(self.config.python_executable),
            profile_root=str(self.config.profile_root),
            database_path=str(self.config.database_path),
            dropin_path=str(self.config.dropin_path),
            team_wrapper_path=str(self.config.team_wrapper_path),
            proactive_wrapper_path=str(self.config.proactive_wrapper_path),
            backup_dropin_path=str(backups[0][1]),
            backup_team_wrapper_path=str(backups[1][1]),
            backup_proactive_wrapper_path=str(backups[2][1]),
            receipt_path=str(receipt_path),
            unrelated_services=self.config.unrelated_services,
        )
        try:
            self.controller.activate(spec)
        except Exception:
            # If caller survives a pre-reload failure, restore config immediately.
            # External verifier performs same rollback after post-reload failure.
            # A rollback failure must never restore authenticated mismatched paths
            # over the selected known-good rollback target.
            if phase != "rollback":
                for (_, source, mode), target in zip(backups, (
                    self.config.dropin_path,
                    self.config.team_wrapper_path,
                    self.config.proactive_wrapper_path,
                )):
                    if source.exists():
                        _atomic_bytes(target, source.read_bytes(), mode)
            raise
        current = self.inspect_runtime()
        if current.pid == old_pid:
            raise ReleaseRecoveryDenied("RELEASE_PID_DID_NOT_CHANGE")
        return current

    def rollback(self, ticket: ReleaseRollbackTicket) -> ReleaseRuntimeState:
        if not isinstance(ticket, ReleaseRollbackTicket):
            raise ValueError("ticket must be ReleaseRollbackTicket")
        if ticket.restore_state_database is not False:
            raise ReleaseRecoveryDenied("STATE_DATABASE_RESTORE_FORBIDDEN")
        if (
            ticket.profile_name != GENERALIST2_PROFILE
            or ticket.service_name != GENERALIST2_SERVICE
        ):
            raise ReleaseRecoveryDenied("RELEASE_TARGET_NOT_GENERALIST2")
        current = self.inspect_runtime()
        if current.state_sha256 != ticket.expected_observed_state_sha256:
            rollback_root = self._release_root(ticket.rollback_module_root)
            manifest = self._manifest(rollback_root)
            if (
                current.version == ticket.rollback_version
                and current.module_root == ticket.rollback_module_root
                and current.wheel_sha256 == ticket.rollback_wheel_sha256
                and current.source_commit == ticket.rollback_source_commit
                and manifest.get("wheel_sha256") == ticket.rollback_wheel_sha256
            ):
                return current
            raise ReleaseRecoveryDenied("RELEASE_ROLLBACK_PRESTATE_MISMATCH")
        rollback_root = self._release_root(ticket.rollback_module_root)
        manifest = self._manifest(rollback_root)
        if (
            manifest.get("version") != ticket.rollback_version
            or manifest.get("wheel_sha256") != ticket.rollback_wheel_sha256
            or manifest.get("source_commit") != ticket.rollback_source_commit
        ):
            raise ReleaseRecoveryDenied("RELEASE_ROLLBACK_ARTIFACT_MISMATCH")
        return self._activate_release(
            recovery_id=ticket.recovery_id,
            phase="rollback",
            release_root=rollback_root,
            old_pid=current.pid,
        )

    def redeploy(
        self,
        ticket: Generalist2RedeployTicket,
        artifact: ReleaseArtifact,
        verification: IsolatedReleaseVerification,
    ) -> ReleaseRuntimeState:
        if not isinstance(ticket, Generalist2RedeployTicket):
            raise ValueError("ticket must be Generalist2RedeployTicket")
        if ticket.restore_state_database is not False:
            raise ReleaseRecoveryDenied("STATE_DATABASE_RESTORE_FORBIDDEN")
        if (
            ticket.profile_name != GENERALIST2_PROFILE
            or ticket.service_name != GENERALIST2_SERVICE
        ):
            raise ReleaseRecoveryDenied("RELEASE_TARGET_NOT_GENERALIST2")
        if (
            artifact.recovery_id != ticket.recovery_id
            or artifact.source_commit != ticket.source_commit
            or artifact.version != ticket.version
            or artifact.wheel_sha256 != ticket.wheel_sha256
            or not artifact.wheel_source_exact
            or verification.recovery_id != ticket.recovery_id
            or verification.receipt_sha256 != ticket.verification_receipt_sha256
            or not verification.passed
        ):
            raise ReleaseRecoveryDenied("REDEPLOY_ARTIFACT_VERIFICATION_BINDING_MISMATCH")
        current = self.inspect_runtime()
        expected_root = self._release_root(ticket.module_root)
        if (
            current.version == ticket.version
            and current.module_root == ticket.module_root
            and current.wheel_sha256 == ticket.wheel_sha256
            and current.source_commit == ticket.source_commit
            and current.pid != ticket.previous_pid
        ):
            return current
        return self._activate_release(
            recovery_id=ticket.recovery_id,
            phase="redeploy",
            release_root=expected_root,
            old_pid=current.pid,
        )


__all__ = [
    "Generalist2ReleaseHostAdapter",
    "Generalist2ReleaseHostConfig",
    "ReleaseActivationController",
    "ReleaseActivationSpec",
    "SystemdUserReleaseController",
]
