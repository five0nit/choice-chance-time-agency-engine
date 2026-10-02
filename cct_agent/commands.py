"""Host-registered, bounded argv command execution with hash-only receipts."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from types import MappingProxyType
from typing import Any, Callable, Literal, Mapping

from .execution_tickets import GlobalKillSwitch, TicketAuthorityDenied
from .mediation_outcomes import (
    OutcomeVerification,
    OutcomeVerifierRegistry,
    VerificationContext,
)
from .store import Event, EventStore, canonical_json


COMMAND_CLAIM_SCHEMA_VERSION = "cct.command.claim.v1"
COMMAND_RECEIPT_SCHEMA_VERSION = "cct.command.receipt.v1"
MAX_COMMANDS = 64
MAX_ARGV_ITEMS = 64
MAX_ARG_BYTES = 4096
MAX_ARGV_BYTES = 32_768
MAX_ENVIRONMENT_ITEMS = 64
MAX_ENVIRONMENT_VALUE_BYTES = 4096
MAX_COMMAND_TIMEOUT_MS = 60_000
MAX_COMMAND_OUTPUT_BYTES = 1_048_576
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_ENVIRONMENT_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class CommandDenied(PermissionError):
    """Fail-closed command denial carrying no subprocess output."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
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
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_string(name: str, value: object, *, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty string without NUL bytes")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{name} must be valid UTF-8") from error
    if len(encoded) > maximum_bytes:
        raise ValueError(f"{name} exceeds {maximum_bytes} UTF-8 bytes")
    return value


def _relative_cwd(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError("cwd must be a bounded workspace-relative path")
    if value == ".":
        return value
    if (
        not value.isascii()
        or value.startswith("/")
        or "\\" in value
        or value.endswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("cwd must stay within workspace as a normalized relative path")
    return value


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """Immutable host-owned command policy. Requests can select only its ID."""

    id: str
    argv: tuple[str, ...]
    cwd: str
    environment: tuple[tuple[str, str], ...]
    timeout_ms: int
    max_stdout_bytes: int
    max_stderr_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("command id", self.id))
        if not isinstance(self.argv, tuple):
            raise ValueError("argv must be an immutable tuple")
        if not 1 <= len(self.argv) <= MAX_ARGV_ITEMS:
            raise ValueError(f"argv must contain 1-{MAX_ARGV_ITEMS} items")
        normalized_argv = tuple(
            _bounded_string(f"argv[{index}]", item, maximum_bytes=MAX_ARG_BYTES)
            for index, item in enumerate(self.argv)
        )
        if sum(len(item.encode("utf-8")) for item in normalized_argv) > MAX_ARGV_BYTES:
            raise ValueError(f"argv exceeds {MAX_ARGV_BYTES} UTF-8 bytes")
        object.__setattr__(self, "argv", normalized_argv)
        object.__setattr__(self, "cwd", _relative_cwd(self.cwd))

        if not isinstance(self.environment, tuple):
            raise ValueError("environment must be an immutable tuple")
        if len(self.environment) > MAX_ENVIRONMENT_ITEMS:
            raise ValueError(
                f"environment must contain at most {MAX_ENVIRONMENT_ITEMS} items"
            )
        normalized_environment: list[tuple[str, str]] = []
        seen_keys: set[str] = set()
        for index, item in enumerate(self.environment):
            if not isinstance(item, tuple) or len(item) != 2:
                raise ValueError(f"environment[{index}] must be a key/value tuple")
            key, value = item
            if not isinstance(key, str) or not _ENVIRONMENT_KEY.fullmatch(key):
                raise ValueError("environment key must be a valid exact variable name")
            if key in seen_keys:
                raise ValueError("environment keys must be unique")
            seen_keys.add(key)
            normalized_environment.append(
                (
                    key,
                    _bounded_string(
                        f"environment[{key}]",
                        value,
                        maximum_bytes=MAX_ENVIRONMENT_VALUE_BYTES,
                    ),
                )
            )
        object.__setattr__(
            self,
            "environment",
            tuple(sorted(normalized_environment)),
        )
        _bounded_integer(
            "timeout_ms",
            self.timeout_ms,
            minimum=1,
            maximum=MAX_COMMAND_TIMEOUT_MS,
        )
        _bounded_integer(
            "max_stdout_bytes",
            self.max_stdout_bytes,
            minimum=0,
            maximum=MAX_COMMAND_OUTPUT_BYTES,
        )
        _bounded_integer(
            "max_stderr_bytes",
            self.max_stderr_bytes,
            minimum=0,
            maximum=MAX_COMMAND_OUTPUT_BYTES,
        )


@dataclass(frozen=True, slots=True)
class CommandRequest:
    """One idempotent request selecting an exact host-registered command."""

    id: str
    command_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("request id", self.id))
        object.__setattr__(self, "command_id", _identifier("command id", self.command_id))


@dataclass(frozen=True, slots=True)
class CommandObservation:
    """Transient bounded output plus durable hash-only execution receipt."""

    request_id: str
    command_id: str
    argv_sha256: str
    cwd: str
    exit_status: int | None
    termination_reason: Literal[
        "exited",
        "timeout",
        "stdout_limit",
        "stderr_limit",
        "spawn_error",
    ]
    stdout_byte_count: int
    stdout_sha256: str
    stderr_byte_count: int
    stderr_sha256: str
    duration_ms: int
    receipt_event_id: str
    replayed: bool
    stdout: bytes | None
    stderr: bytes | None
    persisted_output: bool = False
    shell: bool = False
    ambient_environment_inherited: bool = False


@dataclass(frozen=True, slots=True)
class _RegisteredCommand:
    spec: CommandSpec
    argv: tuple[str, ...]
    cwd_path: Path
    argv_sha256: str


class BoundedCommandAdapter:
    """Execute one allowlisted argv without shell or ambient environment."""

    def __init__(
        self,
        store: EventStore,
        *,
        workspace_root: str | Path,
        commands: tuple[CommandSpec, ...] | list[CommandSpec],
        allowed_executables: frozenset[str | Path] | set[str | Path],
        recovery_probes: Mapping[str, Callable[[], bool]] | None = None,
        effect_fault_hook: Callable[[str, str], None] | None = None,
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        root = Path(workspace_root)
        if not root.is_absolute():
            raise ValueError("workspace_root must be absolute")
        try:
            resolved_root = root.resolve(strict=True)
        except OSError as error:
            raise ValueError("workspace_root must be an existing real directory") from error
        if not resolved_root.is_dir():
            raise ValueError("workspace_root must be an existing real directory")

        if not isinstance(allowed_executables, (frozenset, set)) or not allowed_executables:
            raise ValueError("allowed_executables must be a non-empty set")
        executable_allowlist: set[Path] = set()
        for raw_executable in allowed_executables:
            executable = Path(raw_executable)
            if not executable.is_absolute():
                raise ValueError("allowed executable must be an absolute path")
            try:
                resolved = executable.resolve(strict=True)
            except OSError as error:
                raise ValueError("allowed executable must exist") from error
            descriptor = resolved.stat()
            if not stat.S_ISREG(descriptor.st_mode) or not os.access(resolved, os.X_OK):
                raise ValueError("allowed executable must be an executable regular file")
            executable_allowlist.add(resolved)

        if not isinstance(commands, (tuple, list)) or not commands:
            raise ValueError("commands must contain at least one CommandSpec")
        if len(commands) > MAX_COMMANDS:
            raise ValueError(f"commands must contain at most {MAX_COMMANDS} values")
        registrations: dict[str, _RegisteredCommand] = {}
        for spec in commands:
            if not isinstance(spec, CommandSpec):
                raise ValueError("commands must contain CommandSpec values")
            if spec.id in registrations:
                raise ValueError("command IDs must be unique")
            configured_executable = Path(spec.argv[0])
            if not configured_executable.is_absolute():
                raise ValueError("registered command executable must be absolute")
            try:
                executable = configured_executable.resolve(strict=True)
            except OSError as error:
                raise ValueError("registered command executable must exist") from error
            if executable not in executable_allowlist:
                raise ValueError("registered command executable is not allowlisted")
            cwd_path = (resolved_root / spec.cwd).resolve(strict=True)
            if not cwd_path.is_dir() or (
                cwd_path != resolved_root and resolved_root not in cwd_path.parents
            ):
                raise ValueError("registered command cwd must stay within workspace")
            actual_argv = (str(executable), *spec.argv[1:])
            registrations[spec.id] = _RegisteredCommand(
                spec=spec,
                argv=actual_argv,
                cwd_path=cwd_path,
                argv_sha256=sha256(
                    canonical_json(list(actual_argv)).encode("utf-8")
                ).hexdigest(),
            )

        self.store = store
        self.workspace_root = resolved_root
        self._commands: Mapping[str, _RegisteredCommand] = MappingProxyType(registrations)
        probes = dict(recovery_probes or {})
        if any(command_id not in registrations for command_id in probes) or any(
            not callable(probe) for probe in probes.values()
        ):
            raise ValueError("recovery probes must bind registered command IDs to callables")
        self._recovery_probes: Mapping[str, Callable[[], bool]] = MappingProxyType(
            probes
        )
        if effect_fault_hook is not None and not callable(effect_fault_hook):
            raise ValueError("effect_fault_hook must be callable")
        self._effect_fault_hook = effect_fault_hook
        try:
            os.chmod(self.store.path, 0o600)
        except OSError as error:
            raise ValueError("command receipt store must be private") from error

    @property
    def registered_ids(self) -> frozenset[str]:
        return frozenset(self._commands)

    def execute(self, request: CommandRequest) -> CommandObservation:
        if not isinstance(request, CommandRequest):
            raise ValueError("request must be a CommandRequest")
        registration = self._commands.get(request.command_id)
        if registration is None:
            raise CommandDenied("COMMAND_NOT_REGISTERED")

        claim_payload = {
            "schema_version": COMMAND_CLAIM_SCHEMA_VERSION,
            "request_id": request.id,
            "command_id": registration.spec.id,
            "argv_sha256": registration.argv_sha256,
            "cwd": registration.spec.cwd,
            "environment_keys": sorted(key for key, _value in registration.spec.environment),
            "shell": False,
            "ambient_environment_inherited": False,
            "raw_argv_persisted": False,
            "environment_values_persisted": False,
        }
        try:
            claim, created = self.store.append_once_result(
                "command.execution.claimed",
                request.id,
                claim_payload,
            )
        except Exception as error:
            raise CommandDenied("CLAIM_PERSISTENCE_FAILED") from error
        if canonical_json(claim.payload) != canonical_json(claim_payload):
            raise CommandDenied("CLAIM_RECEIPT_COLLISION")
        if not created:
            completed = self._completed_event(request.id)
            if completed is None:
                completed = self._adopt_claimed(request, registration, claim)
            return self._observation_from_event(completed, stdout=None, stderr=None, replayed=True)

        return self._execute_claimed(request, registration, claim)

    def _execute_claimed(
        self,
        request: CommandRequest,
        registration: _RegisteredCommand,
        claim: Event,
    ) -> CommandObservation:
        started_ns = time.monotonic_ns()
        stdout = b""
        stderr = b""
        exit_status: int | None = None
        termination_reason: Literal[
            "exited",
            "timeout",
            "stdout_limit",
            "stderr_limit",
            "spawn_error",
        ] = "spawn_error"
        try:
            process = subprocess.Popen(
                registration.argv,
                cwd=registration.cwd_path,
                env=dict(registration.spec.environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
            )
        except OSError:
            pass
        else:
            stdout, stderr, termination_reason = self._collect_bounded(
                process,
                timeout_ms=registration.spec.timeout_ms,
                stdout_limit=registration.spec.max_stdout_bytes,
                stderr_limit=registration.spec.max_stderr_bytes,
            )
            exit_status = process.returncode
        duration_ms = max(0, (time.monotonic_ns() - started_ns + 999_999) // 1_000_000)
        if self._effect_fault_hook is not None:
            self._effect_fault_hook(request.id, claim.event_id)
        receipt = {
            "schema_version": COMMAND_RECEIPT_SCHEMA_VERSION,
            "request_id": request.id,
            "claim_event_id": claim.event_id,
            "command_id": registration.spec.id,
            "argv_sha256": registration.argv_sha256,
            "cwd": registration.spec.cwd,
            "environment_keys": sorted(key for key, _value in registration.spec.environment),
            "exit_status": exit_status,
            "termination_reason": termination_reason,
            "stdout_byte_count": len(stdout),
            "stdout_sha256": sha256(stdout).hexdigest(),
            "stderr_byte_count": len(stderr),
            "stderr_sha256": sha256(stderr).hexdigest(),
            "duration_ms": duration_ms,
            "shell": False,
            "ambient_environment_inherited": False,
            "output_persisted": False,
            "environment_values_persisted": False,
        }
        try:
            event, created = self.store.append_once_result(
                "command.execution.completed",
                request.id,
                receipt,
            )
        except Exception as error:
            raise CommandDenied("RECEIPT_PERSISTENCE_FAILED") from error
        if not created or canonical_json(event.payload) != canonical_json(receipt):
            raise CommandDenied("COMPLETION_RECEIPT_COLLISION")
        return self._observation_from_event(
            event,
            stdout=stdout,
            stderr=stderr,
            replayed=False,
        )

    def _adopt_claimed(
        self,
        request: CommandRequest,
        registration: _RegisteredCommand,
        claim: Event,
    ) -> Event:
        probe = self._recovery_probes.get(registration.spec.id)
        if probe is None:
            raise CommandDenied("EXECUTION_STATE_UNCERTAIN")
        try:
            verified = probe()
        except Exception as error:
            raise CommandDenied("EXECUTION_STATE_UNCERTAIN") from error
        if verified is not True:
            raise CommandDenied("EXECUTION_STATE_UNCERTAIN")
        adoption_payload = {
            "schema_version": "cct.command.readback-adoption.v1",
            "request_id": request.id,
            "claim_event_id": claim.event_id,
            "command_id": registration.spec.id,
            "argv_sha256": registration.argv_sha256,
            "readback_verified": True,
            "probe_output_persisted": False,
        }
        try:
            adoption, _ = self.store.append_once_result(
                "command.execution.readback_adopted",
                request.id,
                adoption_payload,
            )
        except Exception as error:
            raise CommandDenied("RECOVERY_RECEIPT_PERSISTENCE_FAILED") from error
        if canonical_json(adoption.payload) != canonical_json(adoption_payload):
            raise CommandDenied("RECOVERY_RECEIPT_COLLISION")
        empty_digest = sha256(b"").hexdigest()
        receipt = {
            "schema_version": COMMAND_RECEIPT_SCHEMA_VERSION,
            "request_id": request.id,
            "claim_event_id": claim.event_id,
            "command_id": registration.spec.id,
            "argv_sha256": registration.argv_sha256,
            "cwd": registration.spec.cwd,
            "environment_keys": sorted(
                key for key, _value in registration.spec.environment
            ),
            "exit_status": 0,
            "termination_reason": "exited",
            "stdout_byte_count": 0,
            "stdout_sha256": empty_digest,
            "stderr_byte_count": 0,
            "stderr_sha256": empty_digest,
            "duration_ms": 0,
            "shell": False,
            "ambient_environment_inherited": False,
            "output_persisted": False,
            "environment_values_persisted": False,
        }
        try:
            completed, _ = self.store.append_once_result(
                "command.execution.completed",
                request.id,
                receipt,
            )
        except Exception as error:
            raise CommandDenied("RECEIPT_PERSISTENCE_FAILED") from error
        if canonical_json(completed.payload) != canonical_json(receipt):
            raise CommandDenied("COMPLETION_RECEIPT_COLLISION")
        return completed

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill()
            except OSError:
                pass

    @classmethod
    def _collect_bounded(
        cls,
        process: subprocess.Popen[bytes],
        *,
        timeout_ms: int,
        stdout_limit: int,
        stderr_limit: int,
    ) -> tuple[
        bytes,
        bytes,
        Literal["exited", "timeout", "stdout_limit", "stderr_limit"],
    ]:
        if process.stdout is None or process.stderr is None:
            cls._terminate(process)
            process.wait()
            return b"", b"", "stderr_limit"

        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        limits = {"stdout": stdout_limit, "stderr": stderr_limit}
        deadline_ns = time.monotonic_ns() + timeout_ms * 1_000_000
        reason: Literal["exited", "timeout", "stdout_limit", "stderr_limit"] = "exited"
        terminated = False
        try:
            while selector.get_map():
                now_ns = time.monotonic_ns()
                if not terminated and now_ns >= deadline_ns:
                    reason = "timeout"
                    terminated = True
                    cls._terminate(process)
                wait_seconds = 0.05
                if not terminated:
                    wait_seconds = min(
                        wait_seconds,
                        max(0.0, (deadline_ns - now_ns) / 1_000_000_000),
                    )
                for key, _mask in selector.select(wait_seconds):
                    stream_name = str(key.data)
                    try:
                        chunk = os.read(key.fd, 65_536)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[stream_name]
                    remaining = max(0, limits[stream_name] - len(buffer))
                    if remaining:
                        buffer.extend(chunk[:remaining])
                    if not terminated and len(chunk) > remaining:
                        reason = (
                            "stdout_limit" if stream_name == "stdout" else "stderr_limit"
                        )
                        terminated = True
                        cls._terminate(process)
                if process.poll() is not None and not selector.get_map():
                    break
        finally:
            selector.close()
            for stream in (process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            cls._terminate(process)
            process.wait(timeout=2)
        return bytes(buffers["stdout"]), bytes(buffers["stderr"]), reason

    def _completed_event(self, request_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("command.execution.completed")
            if event.payload.get("request_id") == request_id
        ]
        if len(rows) > 1:
            raise CommandDenied("DUPLICATE_COMPLETION_RECEIPTS")
        return rows[0] if rows else None

    @staticmethod
    def _observation_from_event(
        event: Event,
        *,
        stdout: bytes | None,
        stderr: bytes | None,
        replayed: bool,
    ) -> CommandObservation:
        payload = event.payload
        required = {
            "schema_version",
            "request_id",
            "claim_event_id",
            "command_id",
            "argv_sha256",
            "cwd",
            "environment_keys",
            "exit_status",
            "termination_reason",
            "stdout_byte_count",
            "stdout_sha256",
            "stderr_byte_count",
            "stderr_sha256",
            "duration_ms",
            "shell",
            "ambient_environment_inherited",
            "output_persisted",
            "environment_values_persisted",
        }
        if set(payload) != required:
            raise CommandDenied("MALFORMED_COMPLETION_RECEIPT")
        reason = payload.get("termination_reason")
        if reason not in {
            "exited",
            "timeout",
            "stdout_limit",
            "stderr_limit",
            "spawn_error",
        }:
            raise CommandDenied("MALFORMED_COMPLETION_RECEIPT")
        exit_status = payload.get("exit_status")
        integer_fields = (
            "stdout_byte_count",
            "stderr_byte_count",
            "duration_ms",
        )
        if (
            payload.get("schema_version") != COMMAND_RECEIPT_SCHEMA_VERSION
            or not isinstance(payload.get("request_id"), str)
            or not isinstance(payload.get("command_id"), str)
            or not isinstance(payload.get("cwd"), str)
            or not isinstance(payload.get("claim_event_id"), str)
            or not isinstance(payload.get("environment_keys"), list)
            or any(not isinstance(item, str) for item in payload["environment_keys"])
            or (exit_status is not None and (isinstance(exit_status, bool) or not isinstance(exit_status, int)))
            or any(
                isinstance(payload.get(field), bool)
                or not isinstance(payload.get(field), int)
                or payload[field] < 0
                for field in integer_fields
            )
            or any(
                not isinstance(payload.get(field), str)
                or not _DIGEST.fullmatch(payload[field])
                for field in ("argv_sha256", "stdout_sha256", "stderr_sha256")
            )
            or payload.get("shell") is not False
            or payload.get("ambient_environment_inherited") is not False
            or payload.get("output_persisted") is not False
            or payload.get("environment_values_persisted") is not False
        ):
            raise CommandDenied("MALFORMED_COMPLETION_RECEIPT")
        if stdout is not None and (
            len(stdout) != payload["stdout_byte_count"]
            or sha256(stdout).hexdigest() != payload["stdout_sha256"]
        ):
            raise CommandDenied("OUTPUT_RECEIPT_MISMATCH")
        if stderr is not None and (
            len(stderr) != payload["stderr_byte_count"]
            or sha256(stderr).hexdigest() != payload["stderr_sha256"]
        ):
            raise CommandDenied("OUTPUT_RECEIPT_MISMATCH")
        return CommandObservation(
            request_id=str(payload["request_id"]),
            command_id=str(payload["command_id"]),
            argv_sha256=str(payload["argv_sha256"]),
            cwd=str(payload["cwd"]),
            exit_status=exit_status,
            termination_reason=reason,
            stdout_byte_count=int(payload["stdout_byte_count"]),
            stdout_sha256=str(payload["stdout_sha256"]),
            stderr_byte_count=int(payload["stderr_byte_count"]),
            stderr_sha256=str(payload["stderr_sha256"]),
            duration_ms=int(payload["duration_ms"]),
            receipt_event_id=event.event_id,
            replayed=replayed,
            stdout=stdout,
            stderr=stderr,
        )


OPERATOR_SHELL_CLAIM_SCHEMA_VERSION = "cct.operator_shell.claim.v1"
OPERATOR_SHELL_EFFECT_SCHEMA_VERSION = "cct.operator_shell.effect.v1"
OPERATOR_SHELL_RECEIPT_SCHEMA_VERSION = "cct.operator_shell.receipt.v1"
OPERATOR_SHELL_VERIFIER_ID = "operator-shell-readback"
MAX_OWNED_PROJECTS = 64
MAX_SHELL_MANIFESTS = 64
MAX_SHELL_MANIFEST_BYTES = 32_768
_DIRECT_SHELL_EXECUTABLES = {
    "bash",
    "csh",
    "dash",
    "fish",
    "ksh",
    "sh",
    "tcsh",
    "zsh",
}


@dataclass(frozen=True, slots=True)
class ShellManifest:
    """Host-private shell program selected by opaque ID, never caller text."""

    id: str
    script: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("manifest id", self.id))
        object.__setattr__(
            self,
            "script",
            _bounded_string(
                "manifest script",
                self.script,
                maximum_bytes=MAX_SHELL_MANIFEST_BYTES,
            ),
        )


@dataclass(frozen=True, slots=True)
class OwnedProjectShell:
    """Host-owned project root and exact verifier/manifest registrations."""

    id: str
    root: str | Path
    verifier_ids: tuple[str, ...]
    manifests: tuple[ShellManifest, ...] = ()
    direct_argv_enabled: bool = True
    bash_executable: str | Path = "/bin/bash"

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("project id", self.id))
        object.__setattr__(self, "root", Path(self.root))
        if not isinstance(self.verifier_ids, tuple):
            raise ValueError("verifier_ids must be an immutable tuple")
        normalized_verifiers = tuple(
            _identifier(f"verifier_ids[{index}]", value)
            for index, value in enumerate(self.verifier_ids)
        )
        if not normalized_verifiers or len(normalized_verifiers) > 64:
            raise ValueError("verifier_ids must contain 1-64 IDs")
        if len(set(normalized_verifiers)) != len(normalized_verifiers):
            raise ValueError("verifier_ids must be unique")
        object.__setattr__(self, "verifier_ids", normalized_verifiers)
        if not isinstance(self.manifests, tuple):
            raise ValueError("manifests must be an immutable tuple")
        if len(self.manifests) > MAX_SHELL_MANIFESTS or any(
            not isinstance(manifest, ShellManifest) for manifest in self.manifests
        ):
            raise ValueError(
                f"manifests must contain at most {MAX_SHELL_MANIFESTS} ShellManifest values"
            )
        if len({manifest.id for manifest in self.manifests}) != len(self.manifests):
            raise ValueError("manifest IDs must be unique")
        if not isinstance(self.direct_argv_enabled, bool):
            raise ValueError("direct_argv_enabled must be a boolean")
        object.__setattr__(self, "bash_executable", Path(self.bash_executable))


@dataclass(frozen=True, slots=True)
class ShellInvocation:
    """Strict model-callable shell request already bound by an execution ticket."""

    ticket_id: str
    project_id: str
    cwd: str
    verifier_id: str
    timeout_ms: int
    max_stdout_bytes: int
    max_stderr_bytes: int
    argv: tuple[str, ...] | None = None
    manifest_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "ticket_id", _identifier("ticket id", self.ticket_id))
        object.__setattr__(self, "project_id", _identifier("project id", self.project_id))
        object.__setattr__(self, "cwd", _relative_cwd(self.cwd))
        object.__setattr__(
            self,
            "verifier_id",
            _identifier("verifier id", self.verifier_id),
        )
        _bounded_integer(
            "timeout_ms",
            self.timeout_ms,
            minimum=1,
            maximum=MAX_COMMAND_TIMEOUT_MS,
        )
        _bounded_integer(
            "max_stdout_bytes",
            self.max_stdout_bytes,
            minimum=0,
            maximum=MAX_COMMAND_OUTPUT_BYTES,
        )
        _bounded_integer(
            "max_stderr_bytes",
            self.max_stderr_bytes,
            minimum=0,
            maximum=MAX_COMMAND_OUTPUT_BYTES,
        )
        if (self.argv is None) == (self.manifest_id is None):
            raise ValueError("exactly one of argv or manifest_id is required")
        if self.argv is not None:
            if not isinstance(self.argv, tuple) or not 1 <= len(self.argv) <= MAX_ARGV_ITEMS:
                raise ValueError(f"argv must be an immutable tuple with 1-{MAX_ARGV_ITEMS} items")
            normalized = tuple(
                _bounded_string(
                    f"argv[{index}]",
                    value,
                    maximum_bytes=MAX_ARG_BYTES,
                )
                for index, value in enumerate(self.argv)
            )
            if sum(len(value.encode("utf-8")) for value in normalized) > MAX_ARGV_BYTES:
                raise ValueError(f"argv exceeds {MAX_ARGV_BYTES} UTF-8 bytes")
            object.__setattr__(self, "argv", normalized)
        if self.manifest_id is not None:
            object.__setattr__(
                self,
                "manifest_id",
                _identifier("manifest id", self.manifest_id),
            )

    @classmethod
    def from_arguments(cls, arguments: Mapping[str, Any]) -> "ShellInvocation":
        if not isinstance(arguments, Mapping):
            raise ValueError("shell arguments must be an object")
        common = {
            "execution_ticket_id",
            "project_id",
            "cwd",
            "verifier_id",
            "timeout_ms",
            "max_stdout_bytes",
            "max_stderr_bytes",
        }
        keys = set(arguments)
        if keys == common | {"argv"}:
            raw_argv = arguments["argv"]
            if not isinstance(raw_argv, list):
                raise ValueError("argv must be an array")
            argv: tuple[str, ...] | None = tuple(raw_argv)
            manifest_id = None
        elif keys == common | {"manifest_id"}:
            argv = None
            manifest_id = arguments["manifest_id"]
        else:
            raise ValueError(
                "shell arguments require exact common fields plus argv or manifest_id"
            )
        return cls(
            ticket_id=arguments["execution_ticket_id"],
            project_id=arguments["project_id"],
            cwd=arguments["cwd"],
            verifier_id=arguments["verifier_id"],
            timeout_ms=arguments["timeout_ms"],
            max_stdout_bytes=arguments["max_stdout_bytes"],
            max_stderr_bytes=arguments["max_stderr_bytes"],
            argv=argv,
            manifest_id=manifest_id,
        )


@dataclass(frozen=True, slots=True)
class ShellExecutionObservation:
    ticket_id: str
    project_id: str
    cwd: str
    argv_sha256: str
    shell_mode: Literal["direct_argv", "private_manifest"]
    manifest_id: str | None
    exit_status: int | None
    termination_reason: Literal[
        "exited",
        "timeout",
        "stdout_limit",
        "stderr_limit",
        "spawn_error",
    ]
    stdout: bytes
    stderr: bytes
    duration_ms: int


@dataclass(frozen=True, slots=True)
class ShellVerification:
    passed: bool
    code: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.passed, bool):
            raise ValueError("verification passed must be a boolean")
        object.__setattr__(self, "code", _identifier("verification code", self.code))
        if not isinstance(self.evidence_sha256, str) or not _DIGEST.fullmatch(
            self.evidence_sha256
        ):
            raise ValueError("verification evidence_sha256 must be a SHA-256 digest")


ProjectShellVerifier = Callable[
    [Path, ShellInvocation, ShellExecutionObservation], ShellVerification
]


@dataclass(frozen=True, slots=True)
class _RegisteredProjectShell:
    spec: OwnedProjectShell
    root: Path
    root_identity: tuple[int, int]
    root_sha256: str
    manifests: Mapping[str, ShellManifest]
    bash_executable: Path


class OperatorShellAdapter:
    """Execute ticket-bound argv only within host-registered owned project roots."""

    def __init__(
        self,
        store: EventStore,
        *,
        projects: tuple[OwnedProjectShell, ...] | list[OwnedProjectShell],
        verifiers: Mapping[str, ProjectShellVerifier],
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        if not isinstance(projects, (tuple, list)) or not 1 <= len(projects) <= MAX_OWNED_PROJECTS:
            raise ValueError(f"projects must contain 1-{MAX_OWNED_PROJECTS} registrations")
        if not isinstance(verifiers, Mapping) or not verifiers:
            raise ValueError("verifiers must be a non-empty mapping")
        normalized_verifiers: dict[str, ProjectShellVerifier] = {}
        for raw_id, verifier in verifiers.items():
            verifier_id = _identifier("verifier id", raw_id)
            if not callable(verifier):
                raise ValueError("project shell verifier must be callable")
            normalized_verifiers[verifier_id] = verifier

        registrations: dict[str, _RegisteredProjectShell] = {}
        for spec in projects:
            if not isinstance(spec, OwnedProjectShell):
                raise ValueError("projects must contain OwnedProjectShell values")
            if spec.id in registrations:
                raise ValueError("project IDs must be unique")
            if any(verifier_id not in normalized_verifiers for verifier_id in spec.verifier_ids):
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
                raise ValueError("project root must be owned by the current host user")
            bash = Path(spec.bash_executable)
            if not bash.is_absolute():
                raise ValueError("bash executable must be absolute")
            try:
                resolved_bash = bash.resolve(strict=True)
                bash_stat = resolved_bash.stat()
            except OSError as error:
                raise ValueError("bash executable must exist") from error
            if not stat.S_ISREG(bash_stat.st_mode) or not os.access(resolved_bash, os.X_OK):
                raise ValueError("bash executable must be an executable regular file")
            manifest_map = MappingProxyType({manifest.id: manifest for manifest in spec.manifests})
            root_sha256 = sha256(str(resolved_root).encode("utf-8")).hexdigest()
            registration = _RegisteredProjectShell(
                spec=spec,
                root=resolved_root,
                root_identity=(root_stat.st_dev, root_stat.st_ino),
                root_sha256=root_sha256,
                manifests=manifest_map,
                bash_executable=resolved_bash,
            )
            registrations[spec.id] = registration
            registration_payload = {
                "schema_version": 1,
                "authority": "host_adapter",
                "project_id": spec.id,
                "root_sha256": root_sha256,
                "root_device": int(root_stat.st_dev),
                "root_inode": int(root_stat.st_ino),
                "direct_argv_enabled": spec.direct_argv_enabled,
                "verifier_ids": list(spec.verifier_ids),
                "manifests": [
                    {
                        "id": manifest.id,
                        "script_sha256": sha256(manifest.script.encode("utf-8")).hexdigest(),
                    }
                    for manifest in spec.manifests
                ],
                "manifest_content_persisted": False,
                "root_path_persisted": False,
            }
            event, _created = store.append_once_result(
                "operator.project_shell.registered",
                spec.id,
                registration_payload,
            )
            if canonical_json(event.payload) != canonical_json(registration_payload):
                raise ValueError(f"project registration changed: {spec.id}")

        self.store = store
        self._projects: Mapping[str, _RegisteredProjectShell] = MappingProxyType(
            registrations
        )
        self._verifiers: Mapping[str, ProjectShellVerifier] = MappingProxyType(
            normalized_verifiers
        )
        try:
            os.chmod(self.store.path, 0o600)
        except OSError as error:
            raise ValueError("operator shell receipt store must be private") from error

    @property
    def registered_project_ids(self) -> frozenset[str]:
        return frozenset(self._projects)

    def outcome_verifiers(self) -> OutcomeVerifierRegistry:
        registry = OutcomeVerifierRegistry()
        registry.register(
            OPERATOR_SHELL_VERIFIER_ID,
            self._verify_mediated_result,
            reconcile=self._reconcile_mediated_result,
            idempotency_proof_id="operator-shell-ticket-receipt",
        )
        return registry

    def execute(self, arguments: Mapping[str, Any]) -> str:
        request = ShellInvocation.from_arguments(arguments)
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise CommandDenied(error.reason_code) from error
        self._require_dispatch_claim(request, arguments)
        registration = self._projects.get(request.project_id)
        if registration is None:
            raise CommandDenied("PROJECT_NOT_REGISTERED")
        if request.verifier_id not in registration.spec.verifier_ids:
            raise CommandDenied("PROJECT_VERIFIER_NOT_REGISTERED")
        argv, cwd_path, shell_mode, manifest_id = self._prepare(
            registration,
            request,
        )
        argv_sha256 = sha256(canonical_json(list(argv)).encode("utf-8")).hexdigest()
        effect_id = f"shell-{sha256(request.ticket_id.encode('utf-8')).hexdigest()[:24]}"
        claim_payload = {
            "schema_version": OPERATOR_SHELL_CLAIM_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "project_id": request.project_id,
            "root_sha256": registration.root_sha256,
            "cwd": request.cwd,
            "argv_sha256": argv_sha256,
            "shell_mode": shell_mode,
            "manifest_id": manifest_id,
            "verifier_id": request.verifier_id,
            "timeout_ms": request.timeout_ms,
            "max_stdout_bytes": request.max_stdout_bytes,
            "max_stderr_bytes": request.max_stderr_bytes,
            "effect_id": effect_id,
            "ambient_environment_inherited": False,
            "raw_argv_persisted": False,
            "manifest_content_persisted": False,
            "root_path_persisted": False,
        }
        claim, created = self.store.append_once_result(
            "operator.shell.claimed",
            request.ticket_id,
            claim_payload,
        )
        if not created:
            completed = self._completion(request.ticket_id)
            if completed is None:
                raise CommandDenied("EXECUTION_STATE_UNCERTAIN")
            return self._response(completed, stdout=None, stderr=None, replayed=True)

        return self._execute_claimed(
            request=request,
            registration=registration,
            argv=argv,
            cwd_path=cwd_path,
            shell_mode=shell_mode,
            manifest_id=manifest_id,
            argv_sha256=argv_sha256,
            effect_id=effect_id,
            claim=claim,
        )

    def _require_dispatch_claim(
        self,
        request: ShellInvocation,
        arguments: Mapping[str, Any],
    ) -> None:
        arguments_sha256 = sha256(
            canonical_json(arguments).encode("utf-8")
        ).hexdigest()
        claims = [
            event
            for event in self.store.events("execution.ticket.consumed")
            if event.payload.get("ticket_id") == request.ticket_id
        ]
        if len(claims) != 1:
            raise CommandDenied("TICKET_DISPATCH_CLAIM_REQUIRED")
        payload = claims[0].payload
        if (
            payload.get("dispatch_claimed") is not True
            or payload.get("ticket_consumed") is not True
            or payload.get("tool_name") != "operator_shell"
            or payload.get("arguments_sha256") != arguments_sha256
            or payload.get("capability") != "operator.shell"
            or payload.get("scope") != f"operator/shell/{request.project_id}"
            or payload.get("verifier_id") != OPERATOR_SHELL_VERIFIER_ID
            or payload.get("idempotency_key") != request.ticket_id
            or isinstance(payload.get("byte_budget"), bool)
            or not isinstance(payload.get("byte_budget"), int)
            or payload["byte_budget"]
            < request.max_stdout_bytes + request.max_stderr_bytes
        ):
            raise CommandDenied("TICKET_DISPATCH_CLAIM_MISMATCH")

    def _prepare(
        self,
        registration: _RegisteredProjectShell,
        request: ShellInvocation,
    ) -> tuple[
        tuple[str, ...],
        Path,
        Literal["direct_argv", "private_manifest"],
        str | None,
    ]:
        current = registration.root.stat()
        if (current.st_dev, current.st_ino) != registration.root_identity:
            raise CommandDenied("PROJECT_ROOT_CHANGED")
        try:
            cwd_path = (registration.root / request.cwd).resolve(strict=True)
        except OSError as error:
            raise CommandDenied("PROJECT_CWD_INVALID") from error
        if not cwd_path.is_dir() or (
            cwd_path != registration.root and registration.root not in cwd_path.parents
        ):
            raise CommandDenied("PROJECT_CWD_ESCAPE")

        if request.argv is not None:
            if not registration.spec.direct_argv_enabled:
                raise CommandDenied("DIRECT_ARGV_DISABLED")
            raw_executable = Path(request.argv[0])
            if not raw_executable.is_absolute():
                raise CommandDenied("EXECUTABLE_MUST_BE_ABSOLUTE")
            try:
                executable = raw_executable.resolve(strict=True)
                descriptor = executable.stat()
            except OSError as error:
                raise CommandDenied("EXECUTABLE_NOT_FOUND") from error
            if not stat.S_ISREG(descriptor.st_mode) or not os.access(executable, os.X_OK):
                raise CommandDenied("EXECUTABLE_NOT_RUNNABLE")
            if (
                raw_executable.name.lower() in _DIRECT_SHELL_EXECUTABLES
                or executable.name.lower() in _DIRECT_SHELL_EXECUTABLES
            ):
                raise CommandDenied("DIRECT_SHELL_COMMAND_DENIED")
            return (
                (str(executable), *request.argv[1:]),
                cwd_path,
                "direct_argv",
                None,
            )

        manifest = registration.manifests.get(str(request.manifest_id))
        if manifest is None:
            raise CommandDenied("SHELL_MANIFEST_NOT_REGISTERED")
        return (
            (str(registration.bash_executable), "-lc", manifest.script),
            cwd_path,
            "private_manifest",
            manifest.id,
        )

    def _execute_claimed(
        self,
        *,
        request: ShellInvocation,
        registration: _RegisteredProjectShell,
        argv: tuple[str, ...],
        cwd_path: Path,
        shell_mode: Literal["direct_argv", "private_manifest"],
        manifest_id: str | None,
        argv_sha256: str,
        effect_id: str,
        claim: Event,
    ) -> str:
        try:
            GlobalKillSwitch(self.store).checkpoint(
                checkpoint_id=f"shell-pre-{sha256(request.ticket_id.encode()).hexdigest()[:24]}",
                effect_id=effect_id,
                step="pre-dispatch",
            )
        except TicketAuthorityDenied as error:
            raise CommandDenied(error.reason_code) from error

        started_ns = time.monotonic_ns()
        stdout = b""
        stderr = b""
        exit_status: int | None = None
        termination_reason: Literal[
            "exited",
            "timeout",
            "stdout_limit",
            "stderr_limit",
            "spawn_error",
        ] = "spawn_error"
        try:
            process = subprocess.Popen(
                argv,
                cwd=cwd_path,
                env={},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
            )
        except OSError:
            pass
        else:
            stdout, stderr, termination_reason = BoundedCommandAdapter._collect_bounded(
                process,
                timeout_ms=request.timeout_ms,
                stdout_limit=request.max_stdout_bytes,
                stderr_limit=request.max_stderr_bytes,
            )
            exit_status = process.returncode
        duration_ms = max(0, (time.monotonic_ns() - started_ns + 999_999) // 1_000_000)
        observation = ShellExecutionObservation(
            ticket_id=request.ticket_id,
            project_id=request.project_id,
            cwd=request.cwd,
            argv_sha256=argv_sha256,
            shell_mode=shell_mode,
            manifest_id=manifest_id,
            exit_status=exit_status,
            termination_reason=termination_reason,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
        )
        verification = self._run_verifier(registration, request, observation)
        passed = (
            termination_reason == "exited"
            and exit_status == 0
            and verification.passed
        )
        verification_code = verification.code if passed else (
            verification.code
            if termination_reason == "exited" and exit_status == 0
            else "COMMAND_FAILED"
        )
        receipt = {
            "schema_version": OPERATOR_SHELL_RECEIPT_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "claim_event_id": claim.event_id,
            "project_id": request.project_id,
            "root_sha256": registration.root_sha256,
            "cwd": request.cwd,
            "argv_sha256": argv_sha256,
            "shell_mode": shell_mode,
            "manifest_id": manifest_id,
            "verifier_id": request.verifier_id,
            "effect_id": effect_id,
            "timeout_ms": request.timeout_ms,
            "max_stdout_bytes": request.max_stdout_bytes,
            "max_stderr_bytes": request.max_stderr_bytes,
            "exit_status": exit_status,
            "termination_reason": termination_reason,
            "stdout_byte_count": len(stdout),
            "stdout_sha256": sha256(stdout).hexdigest(),
            "stderr_byte_count": len(stderr),
            "stderr_sha256": sha256(stderr).hexdigest(),
            "duration_ms": duration_ms,
            "verification_passed": passed,
            "verification_code": verification_code,
            "verification_evidence_sha256": verification.evidence_sha256,
            "ambient_environment_inherited": False,
            "raw_argv_persisted": False,
            "manifest_content_persisted": False,
            "root_path_persisted": False,
            "output_persisted": False,
            "credential_values_persisted": False,
        }
        if passed:
            effect_receipt = {
                **receipt,
                "schema_version": OPERATOR_SHELL_EFFECT_SCHEMA_VERSION,
                "completion_pending": True,
            }
            verified_effect, effect_created = self.store.append_once_result(
                "operator.shell.effect_verified",
                request.ticket_id,
                effect_receipt,
            )
            if (
                not effect_created
                or canonical_json(verified_effect.payload)
                != canonical_json(effect_receipt)
            ):
                raise CommandDenied("VERIFIED_EFFECT_RECEIPT_COLLISION")
        return self._record_completion(
            ticket_id=request.ticket_id,
            receipt=receipt,
            stdout=stdout,
            stderr=stderr,
            recovered_after_crash=False,
        )

    def _record_completion(
        self,
        *,
        ticket_id: str,
        receipt: Mapping[str, Any],
        stdout: bytes | None,
        stderr: bytes | None,
        recovered_after_crash: bool,
    ) -> str:
        final_receipt = {
            **dict(receipt),
            "schema_version": OPERATOR_SHELL_RECEIPT_SCHEMA_VERSION,
            "recovered_after_crash": recovered_after_crash,
        }
        completed, created = self.store.append_once_result(
            "operator.shell.completed",
            ticket_id,
            final_receipt,
        )
        if canonical_json(completed.payload) != canonical_json(final_receipt):
            raise CommandDenied("COMPLETION_RECEIPT_COLLISION")
        return self._response(
            completed,
            stdout=stdout,
            stderr=stderr,
            replayed=recovered_after_crash or not created,
        )

    def _run_verifier(
        self,
        registration: _RegisteredProjectShell,
        request: ShellInvocation,
        observation: ShellExecutionObservation,
    ) -> ShellVerification:
        if observation.termination_reason != "exited" or observation.exit_status != 0:
            evidence = {
                "exit_status": observation.exit_status,
                "termination_reason": observation.termination_reason,
                "stdout_sha256": sha256(observation.stdout).hexdigest(),
                "stderr_sha256": sha256(observation.stderr).hexdigest(),
            }
            return ShellVerification(
                passed=False,
                code="COMMAND_FAILED",
                evidence_sha256=sha256(
                    canonical_json(evidence).encode("utf-8")
                ).hexdigest(),
            )
        try:
            result = self._verifiers[request.verifier_id](
                registration.root,
                request,
                observation,
            )
        except Exception:
            return ShellVerification(
                passed=False,
                code="VERIFIER_ERROR",
                evidence_sha256=sha256(b"").hexdigest(),
            )
        if not isinstance(result, ShellVerification):
            return ShellVerification(
                passed=False,
                code="VERIFIER_RESULT_INVALID",
                evidence_sha256=sha256(b"").hexdigest(),
            )
        return result

    def _completion(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.shell.completed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise CommandDenied("DUPLICATE_COMPLETION_RECEIPTS")
        return rows[0] if rows else None

    @staticmethod
    def _response(
        event: Event,
        *,
        stdout: bytes | None,
        stderr: bytes | None,
        replayed: bool,
    ) -> str:
        payload = event.payload
        return canonical_json(
            {
                "success": payload.get("verification_passed") is True,
                "effect": {
                    "effect_id": payload.get("effect_id"),
                    "idempotency_key": payload.get("ticket_id"),
                    "receipt_event_id": event.event_id,
                },
                "shell": {
                    "project_id": payload.get("project_id"),
                    "cwd": payload.get("cwd"),
                    "argv_sha256": payload.get("argv_sha256"),
                    "shell_mode": payload.get("shell_mode"),
                    "manifest_id": payload.get("manifest_id"),
                    "exit_status": payload.get("exit_status"),
                    "termination_reason": payload.get("termination_reason"),
                    "stdout_byte_count": payload.get("stdout_byte_count"),
                    "stdout_sha256": payload.get("stdout_sha256"),
                    "stderr_byte_count": payload.get("stderr_byte_count"),
                    "stderr_sha256": payload.get("stderr_sha256"),
                    "duration_ms": payload.get("duration_ms"),
                    "stdout_base64": (
                        base64.b64encode(stdout).decode("ascii") if stdout is not None else None
                    ),
                    "stderr_base64": (
                        base64.b64encode(stderr).decode("ascii") if stderr is not None else None
                    ),
                    "ambient_environment_inherited": False,
                    "output_persisted": False,
                    "recovered_after_crash": payload.get("recovered_after_crash") is True,
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
            verified=False,
            effect_observed=False,
            status="malformed-result",
        )
        if not isinstance(value, dict) or context.verifier_id != OPERATOR_SHELL_VERIFIER_ID:
            return malformed
        effect = value.get("effect")
        shell = value.get("shell")
        verification = value.get("verification")
        if not all(isinstance(row, dict) for row in (effect, shell, verification)):
            return malformed
        assert isinstance(effect, dict)
        assert isinstance(shell, dict)
        assert isinstance(verification, dict)
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            return OutcomeVerification(
                verified=False,
                effect_observed=False,
                status="receipt-missing",
            )
        payload = receipt.payload
        matched = (
            value.get("success") is True
            and payload.get("verification_passed") is True
            and effect.get("effect_id") == payload.get("effect_id")
            and effect.get("idempotency_key") == context.idempotency_key
            and effect.get("receipt_event_id") == receipt.event_id
            and shell.get("project_id") == payload.get("project_id")
            and shell.get("cwd") == payload.get("cwd")
            and shell.get("argv_sha256") == payload.get("argv_sha256")
            and shell.get("shell_mode") == payload.get("shell_mode")
            and shell.get("manifest_id") == payload.get("manifest_id")
            and shell.get("exit_status") == payload.get("exit_status")
            and shell.get("termination_reason") == payload.get("termination_reason")
            and shell.get("stdout_byte_count") == payload.get("stdout_byte_count")
            and shell.get("stdout_sha256") == payload.get("stdout_sha256")
            and shell.get("stderr_byte_count") == payload.get("stderr_byte_count")
            and shell.get("stderr_sha256") == payload.get("stderr_sha256")
            and shell.get("duration_ms") == payload.get("duration_ms")
            and shell.get("ambient_environment_inherited") is False
            and shell.get("output_persisted") is False
            and shell.get("recovered_after_crash")
            is (payload.get("recovered_after_crash") is True)
            and verification.get("passed") is True
            and verification.get("verifier_id") == payload.get("verifier_id")
            and verification.get("code") == payload.get("verification_code")
            and verification.get("evidence_sha256")
            == payload.get("verification_evidence_sha256")
        )
        for field in ("stdout", "stderr"):
            encoded = shell.get(f"{field}_base64")
            if encoded is None:
                continue
            if not isinstance(encoded, str):
                matched = False
                continue
            try:
                raw = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                matched = False
                continue
            matched = matched and (
                len(raw) == payload.get(f"{field}_byte_count")
                and sha256(raw).hexdigest() == payload.get(f"{field}_sha256")
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

    def _recover_verified_shell(self, context: VerificationContext) -> object | None:
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied:
            return None
        claims = [
            event
            for event in self.store.events("operator.shell.claimed")
            if event.payload.get("ticket_id") == context.ticket_id
        ]
        effects = [
            event
            for event in self.store.events("operator.shell.effect_verified")
            if event.payload.get("ticket_id") == context.ticket_id
        ]
        if len(claims) != 1 or len(effects) != 1:
            return None
        claim = claims[0]
        claim_payload = claim.payload
        effect_payload = effects[0].payload
        project_id = claim_payload.get("project_id")
        registration = self._projects.get(project_id) if isinstance(project_id, str) else None
        if (
            registration is None
            or context.tool_name != "operator_shell"
            or context.capability != "operator.shell"
            or context.verifier_id != OPERATOR_SHELL_VERIFIER_ID
            or context.idempotency_key != context.ticket_id
            or context.scope != f"operator/shell/{project_id}"
            or claim_payload.get("verifier_id") not in registration.spec.verifier_ids
            or claim_payload.get("root_sha256") != registration.root_sha256
            or effect_payload.get("schema_version") != OPERATOR_SHELL_EFFECT_SCHEMA_VERSION
            or effect_payload.get("completion_pending") is not True
            or effect_payload.get("claim_event_id") != claim.event_id
            or effect_payload.get("verification_passed") is not True
        ):
            return None
        cwd = claim_payload.get("cwd")
        integer_fields = (
            "timeout_ms",
            "max_stdout_bytes",
            "max_stderr_bytes",
        )
        if (
            not isinstance(cwd, str)
            or any(
                isinstance(claim_payload.get(field), bool)
                or not isinstance(claim_payload.get(field), int)
                for field in integer_fields
            )
        ):
            return None
        try:
            normalized_cwd = _relative_cwd(cwd)
            current = registration.root.stat()
            cwd_path = (registration.root / normalized_cwd).resolve(strict=True)
        except (OSError, ValueError):
            return None
        if (
            (current.st_dev, current.st_ino) != registration.root_identity
            or not cwd_path.is_dir()
            or (cwd_path != registration.root and registration.root not in cwd_path.parents)
        ):
            return None
        bound_fields = (
            "ticket_id",
            "project_id",
            "root_sha256",
            "cwd",
            "argv_sha256",
            "shell_mode",
            "manifest_id",
            "verifier_id",
            "effect_id",
            "timeout_ms",
            "max_stdout_bytes",
            "max_stderr_bytes",
        )
        if any(
            effect_payload.get(field) != claim_payload.get(field)
            for field in bound_fields
        ):
            return None
        digest_fields = (
            "argv_sha256",
            "stdout_sha256",
            "stderr_sha256",
            "verification_evidence_sha256",
        )
        count_fields = ("stdout_byte_count", "stderr_byte_count", "duration_ms")
        if (
            any(
                not isinstance(effect_payload.get(field), str)
                or not _DIGEST.fullmatch(effect_payload[field])
                for field in digest_fields
            )
            or any(
                isinstance(effect_payload.get(field), bool)
                or not isinstance(effect_payload.get(field), int)
                or effect_payload[field] < 0
                for field in count_fields
            )
            or int(effect_payload["stdout_byte_count"])
            > int(effect_payload["max_stdout_bytes"])
            or int(effect_payload["stderr_byte_count"])
            > int(effect_payload["max_stderr_bytes"])
            or effect_payload.get("termination_reason") != "exited"
            or effect_payload.get("exit_status") != 0
        ):
            return None
        receipt = dict(effect_payload)
        receipt.pop("completion_pending", None)
        return json.loads(
            self._record_completion(
                ticket_id=context.ticket_id,
                receipt=receipt,
                stdout=None,
                stderr=None,
                recovered_after_crash=True,
            )
        )

    def _reconcile_mediated_result(self, context: VerificationContext) -> object | None:
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            return self._recover_verified_shell(context)
        if receipt.payload.get("verification_passed") is not True:
            return None
        return json.loads(
            self._response(receipt, stdout=None, stderr=None, replayed=True)
        )
