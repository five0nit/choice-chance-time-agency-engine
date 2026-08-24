"""Host-registered, bounded argv command execution with hash-only receipts."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from types import MappingProxyType
from typing import Literal, Mapping

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
        if not created:
            completed = self._completed_event(request.id)
            if completed is None:
                raise CommandDenied("EXECUTION_STATE_UNCERTAIN")
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
