"""Recurrently bridge authenticated operator interest to registered task executors.

Interest remains direction, never authority. Host code must register one exact executor for
one immutable feedback event. The executor must use the existing separately leased,
hierarchical full-stack path and return its typed terminal receipt. A process-safe lock,
append-once claim, terminal readback, and adoption path make concurrent and restarted wakes
converge without repeating verified adapter effects.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import re
import stat
import threading
from typing import Any, Callable, Iterator, Protocol, Sequence

try:  # pragma: no cover - Linux/WSL is the production target.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

from .opportunity_handoff import OpportunityTaskHandoff, OpportunityTaskHandoffDenied
from .self_goals import SelfGoalInputReceipt
from .store import Event, EventStore, canonical_json


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_INTEREST_DECISIONS = {"ACCEPT", "INTERESTED"}
_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


class InterestTaskWakeDenied(RuntimeError):
    """Fail-closed registered-interest wake decision."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _accepted_feedback(event: Event, *, principal_id: str | None = None) -> bool:
    payload = event.payload
    return (
        event.kind == "opportunity.initiative.feedback"
        and payload.get("decision") in _INTEREST_DECISIONS
        and payload.get("operator_interest_recorded") is True
        and payload.get("source_authority") in {"operator", "host_adapter"}
        and (principal_id is None or payload.get("principal_id") == principal_id)
        and payload.get("execution_authority_granted") is False
        and payload.get("capability_lease_changed") is False
        and payload.get("opportunity_execution_status_changed") is False
        and payload.get("external_effects") == 0
        and isinstance(payload.get("opportunity_id"), str)
    )


@dataclass(frozen=True, slots=True)
class InterestTaskExecutionReceipt:
    terminal_event_id: str
    replayed: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "terminal_event_id",
            _identifier("terminal event id", self.terminal_event_id),
        )
        if not isinstance(self.replayed, bool):
            raise ValueError("replayed must be a boolean")


class InterestTaskExecutor(Protocol):
    def execute(
        self, *, opportunity_id: str, feedback_event_id: str
    ) -> InterestTaskExecutionReceipt: ...


@dataclass(frozen=True, slots=True)
class InterestTaskRegistration:
    """Host-owned registration for one immutable accepted-interest event."""

    id: str
    opportunity_id: str
    feedback_event_id: str
    authority_receipt: SelfGoalInputReceipt
    executor: InterestTaskExecutor

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("registration id", self.id))
        object.__setattr__(
            self,
            "opportunity_id",
            _identifier("opportunity id", self.opportunity_id),
        )
        object.__setattr__(
            self,
            "feedback_event_id",
            _identifier("feedback event id", self.feedback_event_id),
        )
        if not isinstance(self.authority_receipt, SelfGoalInputReceipt):
            raise ValueError("authority_receipt must be a signed self-goal receipt")
        if not callable(getattr(self.executor, "execute", None)):
            raise ValueError("registered interest executor must expose execute")


class InterestTaskWakeCoordinator:
    """Run or adopt one oldest registered accepted-interest task per wake."""

    def __init__(
        self,
        store: EventStore,
        *,
        principal_id: str,
        state_root: str | Path,
        authentication_secret: bytes,
        registrations: Sequence[InterestTaskRegistration],
    ) -> None:
        self.store = store
        self.principal_id = _identifier("principal id", principal_id)
        if not isinstance(authentication_secret, bytes) or len(authentication_secret) < 32:
            raise ValueError("authentication_secret must contain at least 32 bytes")
        self.authentication_secret = authentication_secret
        self.state_root = Path(state_root).expanduser().absolute()
        self.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.state_root.is_symlink():
            raise ValueError("interest wake state root must not be a symlink")
        self.state_root = self.state_root.resolve(strict=True)
        metadata = self.state_root.stat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError("interest wake state root must be an owned directory")
        os.chmod(self.state_root, 0o700)
        rows = tuple(registrations)
        by_feedback = {row.feedback_event_id: row for row in rows}
        if len(by_feedback) != len(rows) or len({row.id for row in rows}) != len(rows):
            raise ValueError("interest task registrations must be unique")
        self.registrations = by_feedback
        configuration = {
            "schema_version": 1,
            "principal_id": self.principal_id,
            "state_root_sha256": sha256(str(self.state_root).encode("utf-8")).hexdigest(),
            "database_path_sha256": sha256(
                str(self.store.path.resolve()).encode("utf-8")
            ).hexdigest(),
            "installed_by": "host_adapter",
            "model_callable": False,
            "producer_text_persisted": False,
            "external_effects": 0,
        }
        self._bind_configuration(configuration)

    def _bind_configuration(self, configuration: dict[str, Any]) -> None:
        lock_descriptor = os.open(
            self.state_root / "configuration.lock",
            os.O_CREAT
            | os.O_RDWR
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            lock_metadata = os.fstat(lock_descriptor)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or lock_metadata.st_uid != os.getuid()
                or lock_metadata.st_nlink != 1
            ):
                raise InterestTaskWakeDenied("INTEREST_WAKE_STATE_ROOT_MISMATCH")
            os.fchmod(lock_descriptor, 0o600)
            if fcntl is not None:
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            configuration_path = self.state_root / "configuration.json"
            configuration_bytes = (canonical_json(configuration) + "\n").encode("utf-8")
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(configuration_path, flags, 0o600)
            except FileExistsError:
                try:
                    descriptor = os.open(
                        configuration_path,
                        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                    )
                except OSError as error:
                    raise InterestTaskWakeDenied(
                        "INTEREST_WAKE_STATE_ROOT_MISMATCH"
                    ) from error
                try:
                    metadata = os.fstat(descriptor)
                    observed = os.read(descriptor, 8193)
                finally:
                    os.close(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1
                    or metadata.st_mode & 0o077
                    or observed != configuration_bytes
                ):
                    raise InterestTaskWakeDenied("INTEREST_WAKE_STATE_ROOT_MISMATCH")
            else:
                try:
                    os.fchmod(descriptor, 0o600)
                    offset = 0
                    while offset < len(configuration_bytes):
                        try:
                            written = os.write(
                                descriptor,
                                configuration_bytes[offset:],
                            )
                        except InterruptedError:
                            continue
                        if written <= 0:
                            raise OSError("configuration write made no progress")
                        offset += written
                    os.fsync(descriptor)
                except BaseException:
                    try:
                        os.unlink(configuration_path)
                    except OSError:
                        pass
                    raise
                finally:
                    os.close(descriptor)
            try:
                installed, _ = self.store.append_once_result(
                    "opportunity.initiative.task_wake.configuration.installed",
                    "canonical",
                    configuration,
                )
            except ValueError as error:
                raise InterestTaskWakeDenied(
                    "INTEREST_WAKE_STATE_ROOT_MISMATCH"
                ) from error
            if canonical_json(installed.payload) != canonical_json(configuration):
                raise InterestTaskWakeDenied("INTEREST_WAKE_STATE_ROOT_MISMATCH")
        finally:
            if fcntl is not None:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            os.close(lock_descriptor)

    @contextmanager
    def _run_lock(self) -> Iterator[None]:
        identity = self.state_root.stat()
        key = f"{identity.st_dev}:{identity.st_ino}"
        with _PROCESS_LOCKS_GUARD:
            process_lock = _PROCESS_LOCKS.setdefault(key, threading.RLock())
        with process_lock:
            descriptor = os.open(
                self.state_root / "interest-task-wake.lock",
                os.O_CREAT
                | os.O_RDWR
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1
                ):
                    raise ValueError(
                        "interest wake lock must be an owned single-link regular file"
                    )
                os.fchmod(descriptor, 0o600)
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def _one(self, kind: str, feedback_event_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events(kind)
            if event.payload.get("feedback_event_id") == feedback_event_id
        ]
        if len(rows) > 1:
            raise InterestTaskWakeDenied("INTEREST_WAKE_DUPLICATE_LEDGER_ROWS")
        return rows[0] if rows else None

    def _task_terminal(self, feedback_event_id: str) -> Event | None:
        return self._one(
            "opportunity.initiative.task_handoff.completed",
            feedback_event_id,
        )

    def _validate_terminal(
        self,
        terminal: Event,
        *,
        registration: InterestTaskRegistration,
        interest_binding_sha256: str | None = None,
    ) -> None:
        payload = terminal.payload
        if (
            terminal.kind != "opportunity.initiative.task_handoff.completed"
            or payload.get("feedback_event_id") != registration.feedback_event_id
            or payload.get("opportunity_id") != registration.opportunity_id
            or payload.get("status") != "completed"
            or payload.get("interest_granted_execution_authority") is not False
            or payload.get("execution_authority_source")
            != "separate_host_policy_capability_lease"
            or payload.get("external_effects") != 0
            or payload.get("raw_producer_content_persisted") is not False
            or isinstance(payload.get("adapter_effects"), bool)
            or not isinstance(payload.get("adapter_effects"), int)
            or int(payload["adapter_effects"]) < 1
        ):
            raise InterestTaskWakeDenied("INTEREST_TASK_TERMINAL_INVALID")
        if (
            interest_binding_sha256 is not None
            and payload.get("interest_binding_sha256") != interest_binding_sha256
        ):
            raise InterestTaskWakeDenied("INTEREST_TASK_TERMINAL_BINDING_MISMATCH")
        references = (
            ("handoff_event_id", "opportunity.initiative.task_handoff.prepared"),
            ("episode_terminal_event_id", "autonomy.self_goal.episode.terminal"),
            ("outcome_event_id", "outcome.observed"),
            ("reflection_event_id", "reflection.proposed"),
        )
        for field, kind in references:
            value = payload.get(field)
            event = self.store.event(str(value)) if isinstance(value, str) else None
            if event is None or event.kind != kind:
                raise InterestTaskWakeDenied("INTEREST_TASK_TERMINAL_EVIDENCE_MISSING")
        handoff = self.store.event(str(payload["handoff_event_id"]))
        assert handoff is not None
        if (
            handoff.payload.get("feedback_event_id") != registration.feedback_event_id
            or handoff.payload.get("opportunity_id") != registration.opportunity_id
            or handoff.payload.get("interest_binding_sha256")
            != payload.get("interest_binding_sha256")
            or handoff.payload.get("execution_authority_source")
            != "separate_host_policy_capability_lease"
            or handoff.payload.get("external_effects") != 0
        ):
            raise InterestTaskWakeDenied("INTEREST_TASK_HANDOFF_EVIDENCE_INVALID")

    def _complete(
        self,
        *,
        registration: InterestTaskRegistration,
        terminal: Event,
        interest_binding_sha256: str,
        executed: bool,
        replayed: bool,
    ) -> dict[str, Any]:
        payload = {
            "schema_version": 1,
            "registration_id": registration.id,
            "registration_sha256": _digest(
                {
                    "id": registration.id,
                    "opportunity_id": registration.opportunity_id,
                    "feedback_event_id": registration.feedback_event_id,
                    "authority_receipt_id": registration.authority_receipt.id,
                    "authority_receipt_sha256": _digest(
                        registration.authority_receipt.signed_payload()
                        | {"signature": registration.authority_receipt.signature}
                    ),
                }
            ),
            "opportunity_id": registration.opportunity_id,
            "feedback_event_id": registration.feedback_event_id,
            "interest_binding_sha256": interest_binding_sha256,
            "task_terminal_event_id": terminal.event_id,
            "task_terminal_sha256": _digest(terminal.payload),
            "executed_in_this_wake": executed,
            "replayed": replayed,
            "execution_authority_source": "separate_host_policy_capability_lease",
            "operator_interest_granted_authority": False,
            "producer_text_persisted": False,
            "external_effects": 0,
        }
        try:
            event, created = self.store.append_once_result(
                "opportunity.initiative.task_wake.completed",
                registration.feedback_event_id,
                payload,
            )
        except ValueError as error:
            raise InterestTaskWakeDenied("INTEREST_WAKE_COMPLETION_CONFLICT") from error
        if canonical_json(event.payload) != canonical_json(payload):
            raise InterestTaskWakeDenied("INTEREST_WAKE_COMPLETION_CONFLICT")
        return {
            "status": "verified-completed",
            "registration_id_sha256": sha256(registration.id.encode("utf-8")).hexdigest(),
            "feedback_event_id_sha256": sha256(
                registration.feedback_event_id.encode("utf-8")
            ).hexdigest(),
            "terminal_event_id": terminal.event_id,
            "executed": executed,
            "replayed": replayed or not created,
            "emit": created,
            "external_effects": 0,
        }

    def _reject(
        self,
        registration: InterestTaskRegistration,
        feedback: Event,
        reason_code: str,
    ) -> None:
        payload = {
            "schema_version": 1,
            "registration_id": registration.id,
            "opportunity_id": registration.opportunity_id,
            "feedback_event_id": feedback.event_id,
            "feedback_sha256": _digest(feedback.payload),
            "reason_code": _identifier("reason code", reason_code),
            "effect_attempted": False,
            "producer_text_persisted": False,
            "external_effects": 0,
        }
        try:
            event, _ = self.store.append_once_result(
                "opportunity.initiative.task_wake.rejected",
                feedback.event_id,
                payload,
            )
        except ValueError as error:
            raise InterestTaskWakeDenied("INTEREST_WAKE_REJECTION_CONFLICT") from error
        if canonical_json(event.payload) != canonical_json(payload):
            raise InterestTaskWakeDenied("INTEREST_WAKE_REJECTION_CONFLICT")

    def run_once(
        self,
        *,
        fault_hook: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        with self._run_lock():
            feedback_rows = [
                event
                for event in self.store.events("opportunity.initiative.feedback")
                if _accepted_feedback(event, principal_id=self.principal_id)
            ]
            for feedback in feedback_rows:
                registration = self.registrations.get(feedback.event_id)
                if registration is None:
                    continue
                if self._one(
                    "opportunity.initiative.task_wake.completed", feedback.event_id
                ) is not None:
                    continue
                terminal = self._task_terminal(feedback.event_id)
                if terminal is not None:
                    try:
                        self._validate_terminal(terminal, registration=registration)
                    except InterestTaskWakeDenied as error:
                        self._reject(registration, feedback, error.reason_code)
                        continue
                    result = self._complete(
                        registration=registration,
                        terminal=terminal,
                        interest_binding_sha256=str(
                            terminal.payload["interest_binding_sha256"]
                        ),
                        executed=False,
                        replayed=True,
                    )
                    if fault_hook is not None:
                        fault_hook("after-completion")
                    return result
                if self._one(
                    "opportunity.initiative.task_wake.rejected", feedback.event_id
                ) is not None:
                    continue
                if registration.opportunity_id != feedback.payload.get("opportunity_id"):
                    self._reject(
                        registration,
                        feedback,
                        "INTEREST_WAKE_REGISTRATION_MISMATCH",
                    )
                    continue
                try:
                    interest = OpportunityTaskHandoff(
                        self.store,
                        principal_id=self.principal_id,
                    ).inspect_interest(
                        opportunity_id=registration.opportunity_id,
                        feedback_event_id=registration.feedback_event_id,
                    )
                except OpportunityTaskHandoffDenied as error:
                    self._reject(registration, feedback, error.reason_code)
                    continue
                authority_receipt = registration.authority_receipt
                if not (
                    authority_receipt.kind == "opportunity"
                    and authority_receipt.subject_id == interest.opportunity_id
                    and authority_receipt.content_sha256 == interest.digest
                    and authority_receipt.issued_by == "host_adapter"
                    and authority_receipt.semantic_taint is False
                    and authority_receipt.raw_content_persisted is False
                    and authority_receipt.verify(self.authentication_secret)
                ):
                    raise InterestTaskWakeDenied("HOST_INTEREST_BINDING_REQUIRED")
                claim_payload = {
                    "schema_version": 1,
                    "registration_id": registration.id,
                    "opportunity_id": registration.opportunity_id,
                    "feedback_event_id": registration.feedback_event_id,
                    "feedback_sha256": _digest(feedback.payload),
                    "interest_binding_sha256": interest.digest,
                    "authority_receipt_id": authority_receipt.id,
                    "authority_receipt_sha256": _digest(
                        authority_receipt.signed_payload()
                        | {"signature": authority_receipt.signature}
                    ),
                    "operator_interest_granted_authority": False,
                    "execution_authority_source": "separate_host_policy_capability_lease",
                    "producer_text_persisted": False,
                    "external_effects": 0,
                }
                try:
                    claim, _ = self.store.append_once_result(
                        "opportunity.initiative.task_wake.claimed",
                        feedback.event_id,
                        claim_payload,
                    )
                except ValueError as error:
                    raise InterestTaskWakeDenied("INTEREST_WAKE_CLAIM_CONFLICT") from error
                if canonical_json(claim.payload) != canonical_json(claim_payload):
                    raise InterestTaskWakeDenied("INTEREST_WAKE_CLAIM_CONFLICT")
                if fault_hook is not None:
                    fault_hook("after-claim")
                receipt = registration.executor.execute(
                    opportunity_id=registration.opportunity_id,
                    feedback_event_id=registration.feedback_event_id,
                )
                if type(receipt) is not InterestTaskExecutionReceipt:
                    raise InterestTaskWakeDenied("INTEREST_TASK_TYPED_RECEIPT_REQUIRED")
                terminal = self.store.event(receipt.terminal_event_id)
                if terminal is None:
                    raise InterestTaskWakeDenied("INTEREST_TASK_TERMINAL_MISSING")
                self._validate_terminal(
                    terminal,
                    registration=registration,
                    interest_binding_sha256=interest.digest,
                )
                if fault_hook is not None:
                    fault_hook("after-execution")
                result = self._complete(
                    registration=registration,
                    terminal=terminal,
                    interest_binding_sha256=interest.digest,
                    executed=True,
                    replayed=receipt.replayed,
                )
                if fault_hook is not None:
                    fault_hook("after-completion")
                return result
            return {
                "status": "no-pending-registered-interest",
                "executed": False,
                "replayed": True,
                "emit": False,
                "external_effects": 0,
            }


def interest_task_wake_status(store: EventStore) -> dict[str, Any]:
    accepted = [
        event
        for event in store.events("opportunity.initiative.feedback")
        if _accepted_feedback(event)
    ]
    claims = store.events("opportunity.initiative.task_wake.claimed")
    completed = store.events("opportunity.initiative.task_wake.completed")
    rejected = store.events("opportunity.initiative.task_wake.rejected")
    terminal_ids = {
        str(event.payload.get("feedback_event_id", "")) for event in completed
    }
    rejected_ids = {
        str(event.payload.get("feedback_event_id", "")) for event in rejected
    }
    latest = completed[-1] if completed else None
    return {
        "accepted_interests": len(accepted),
        "claims": len(claims),
        "completed": len(completed),
        "rejected": len(rejected),
        "unresolved_accepted_interests": sum(
            event.event_id not in terminal_ids and event.event_id not in rejected_ids
            for event in accepted
        ),
        "registered_executor_count_available": False,
        "latest": (
            {
                "registration_id_sha256": sha256(
                    str(latest.payload.get("registration_id", "")).encode("utf-8")
                ).hexdigest(),
                "feedback_event_id_sha256": sha256(
                    str(latest.payload.get("feedback_event_id", "")).encode("utf-8")
                ).hexdigest(),
                "task_terminal_sha256": latest.payload.get("task_terminal_sha256"),
                "executed_in_completion_wake": latest.payload.get(
                    "executed_in_this_wake"
                ),
                "replayed": latest.payload.get("replayed"),
                "external_effects": latest.payload.get("external_effects", 0),
            }
            if latest is not None
            else None
        ),
        "content_in_status": False,
        "producer_text_persisted": False,
        "external_effects": 0,
    }


__all__ = [
    "InterestTaskExecutionReceipt",
    "InterestTaskExecutor",
    "InterestTaskRegistration",
    "InterestTaskWakeCoordinator",
    "InterestTaskWakeDenied",
    "interest_task_wake_status",
]
