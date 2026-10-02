"""Restart-safe cloud cooldowns, never cached authority or automatic RPC retries.

A failed RPC opens a circuit shared by gateways using the same state path. The
file lock serializes check/RPC/failure persistence so sibling workers cannot race
past a known failure. Successful individual reads do not reset write failures;
only a complete successful worker cycle resets the exponential delay.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import secrets
import stat
import time


@contextmanager
def _shared_directory(path: Path):
    """Open an explicitly provisioned private directory without following links.

    Ancestors must be root/owner controlled. A root-owned sticky directory (e.g.
    /tmp) is allowed, but the configured leaf must be owner-only. Keep the opened
    descriptor through lock/read/replace so a path swap cannot redirect state I/O.
    """
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("CLOUD_RECOVERY_DIRECTORY_UNSAFE")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)

    try:
        for index, part in enumerate(path.parts[1:]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            metadata = os.fstat(fd)
            leaf = index == len(path.parts) - 2
            if leaf:
                unsafe = metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
            else:
                sticky_root = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
                unsafe = (metadata.st_uid not in (0, os.geteuid())
                          or (metadata.st_mode & 0o022 and not sticky_root))
            if unsafe:
                raise ValueError("CLOUD_RECOVERY_DIRECTORY_UNSAFE")
        if path == Path("/"):
            raise ValueError("CLOUD_RECOVERY_DIRECTORY_UNSAFE")
    except (OSError, ValueError):
        os.close(fd)
        raise ValueError("CLOUD_RECOVERY_DIRECTORY_UNSAFE") from None
    try:
        yield fd
    finally:
        os.close(fd)


@dataclass(frozen=True, slots=True)
class CloudErrorPolicy:
    """Classify SDK types, not exception text or caller-controlled code fields."""

    quota: tuple[type[Exception], ...]
    transient: tuple[type[Exception], ...]
    retry: tuple[type[Exception], ...]

    def classify(self, error: Exception) -> str | None:
        seen: set[int] = set()
        for _ in range(8):
            if id(error) in seen:
                return None
            seen.add(id(error))
            if isinstance(error, self.quota):
                return "QUOTA_BACKOFF"
            if isinstance(error, self.transient):
                return "TRANSIENT_BACKOFF"
            if not isinstance(error, self.retry):
                return None
            cause = getattr(error, "cause", None) or error.__cause__ or error.__context__
            if cause is None:
                return "TRANSIENT_BACKOFF"
            if not isinstance(cause, Exception):
                return None
            error = cause
        return None


def firestore_error_policy() -> CloudErrorPolicy:
    from google.api_core import exceptions
    return CloudErrorPolicy(
        quota=(exceptions.TooManyRequests,),
        transient=(exceptions.ServiceUnavailable, exceptions.DeadlineExceeded,
                   exceptions.Aborted, exceptions.InternalServerError,
                   exceptions.BadGateway, exceptions.GatewayTimeout),
        retry=(exceptions.RetryError,),
    )


class CloudBackoff(RuntimeError):
    """Sanitized dependency failure, including a locally suppressed RPC."""

    def __init__(self, receipt):
        self.receipt = receipt
        self.reason_code = "FIRESTORE_" + receipt["cloudStatus"]
        super().__init__(self.reason_code)


class CloudCircuit:
    def __init__(self, path: Path, errors: CloudErrorPolicy, *, clock=time.time,
                 shared_directory=False):
        self.path, self.errors, self.clock = Path(path), errors, clock
        self._shared_directory = shared_directory

    @classmethod
    def for_project(cls, project_id: str, fallback: Path, errors: CloudErrorPolicy,
                    *, clock=time.time):
        """Only explicit host configuration shares state across profile workers.

        Unset preserves the caller's legacy path. An invalid explicit value is a
        startup error, never a silent fallback to an independent circuit.
        """
        configured = os.environ.get("CCT_CLOUD_RECOVERY_DIR")
        if configured is None:
            return cls(fallback, errors, clock=clock)
        directory = Path(configured)
        if not configured or not directory.is_absolute() or ".." in directory.parts:
            raise ValueError("CLOUD_RECOVERY_DIRECTORY_UNSAFE")
        with _shared_directory(directory):
            pass
        return cls(directory / (sha256(project_id.encode()).hexdigest() + ".json"),
                   errors, clock=clock, shared_directory=True)

    @contextmanager
    def _directory(self):
        directory = self.path.parent
        if self._shared_directory:
            with _shared_directory(directory) as fd:
                yield fd
            return
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                raise ValueError("CLOUD_CIRCUIT_DIRECTORY_UNSAFE")
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def _lock(self):
        with self._directory() as directory:
            fd = os.open(self.path.name + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            try:
                metadata = os.fstat(fd)
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                        or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
                    raise ValueError("CLOUD_CIRCUIT_LOCK_UNSAFE")
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield directory
            finally:
                os.close(fd)

    def _load(self, directory):
        try:
            fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
                    or metadata.st_size > 4096):
                raise ValueError("CLOUD_CIRCUIT_STATE_UNSAFE")
            state = json.load(stream)
        if (not isinstance(state, dict)
                or set(state) != {"status", "delay", "until"}
                or state["status"] not in {"QUOTA_BACKOFF", "TRANSIENT_BACKOFF", "CLOSED"}
                or type(state["delay"]) is not int or not 0 <= state["delay"] <= 1800
                or type(state["until"]) not in (int, float)
                or not math.isfinite(state["until"]) or not 0 <= state["until"] < 253402300800):
            raise ValueError("CLOUD_CIRCUIT_STATE_INVALID")
        return state

    def _save(self, state, directory):
        temporary = ".cloud-circuit-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(state, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass

    def _receipt(self, state):
        if not state or state["status"] == "CLOSED":
            return {}
        return {"cloudStatus": state["status"],
                "retrySeconds": max(0, math.ceil(state["until"] - self.clock())),
                "retryAt": datetime.fromtimestamp(state["until"], timezone.utc).isoformat()}

    def status(self):
        with self._lock() as directory:
            return self._receipt(self._load(directory))

    def check(self):
        receipt = self.status()
        if receipt.get("retrySeconds", 0):
            raise CloudBackoff(receipt)
        return receipt  # Expiry permits a fresh probe, not cached recovery.

    @contextmanager
    def display_cache_guard(self):
        """Serialize local cache decisions with sibling failure persistence.

        Never perform an RPC inside this guard: gateway calls take this lock
        themselves. Expired backoff permits a fresh write, not cached recovery.
        """
        with self._lock() as directory:
            receipt = self._receipt(self._load(directory))
            if receipt.get("retrySeconds", 0):
                raise CloudBackoff(receipt)
            yield not receipt

    def call(self, operation):
        with self._lock() as directory:
            state = self._load(directory)
            receipt = self._receipt(state)
            if receipt.get("retrySeconds", 0):
                raise CloudBackoff(receipt)
            try:
                return operation()
            except CloudBackoff:
                raise
            except Exception as error:
                status = self.errors.classify(error)
                if status is None:
                    raise
                base, maximum = (300, 1800) if status == "QUOTA_BACKOFF" else (30, 300)
                delay = min(state["delay"] * 2, maximum) if state and state["status"] == status else base
                state = {"status": status, "delay": delay, "until": self.clock() + delay}
                self._save(state, directory)
                raise CloudBackoff(self._receipt(state)) from None

    def recovered(self):
        with self._lock() as directory:
            state = self._load(directory)
            # A sibling failure during a successful cycle must not be cleared.
            if state and state["status"] != "CLOSED" and state["until"] <= self.clock():
                self._save({"status": "CLOSED", "delay": 0, "until": 0}, directory)


def cloud_status(gateway):
    circuit = getattr(gateway, "circuit", None)
    return circuit.status() if isinstance(circuit, CloudCircuit) else {}


def cloud_delay(gateway, minimum):
    return max(minimum, cloud_status(gateway).get("retrySeconds", 0))


def cloud_recovered(gateway):
    circuit = getattr(gateway, "circuit", None)
    if isinstance(circuit, CloudCircuit):
        circuit.recovered()
