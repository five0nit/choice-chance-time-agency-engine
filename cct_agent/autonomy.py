"""Capability-first autonomous local-work loop for CCT Phase 10.

The proposal/model layer may suggest opportunities. Only host-authorized opportunities can
cross this module's executor boundary. The boundary supports one reversible primitive:
atomic text writes under one resolved workspace root. Execution receipts contain hashes,
counts, and relative paths—never file content.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import asdict, dataclass, field
import errno
from hashlib import sha256
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import threading
from typing import Any, Iterator, Mapping, Sequence

from .kernel import AgencyKernel, NO_OP_ID
from .models import Option
from .store import Event, EventStore, canonical_json

try:  # pragma: no cover - Linux/WSL is the production target.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
_EXECUTABLE_AUTHORITIES = {"host_adapter", "operator"}
_FORBIDDEN_NAMES = {
    ".cct-quarantine", ".env", ".git", ".ssh", "credentials", "credential", "secrets", "secret",
    "wallet", "wallets", "private_key", "id_rsa", "id_ed25519", "authorized_keys",
    "known_hosts", "login data", "cookies",
}
_FORBIDDEN_PREFIXES = {
    ".env", "credential", "credentials", "secret", "secrets", "wallet", "wallets",
    "private_key", "id_rsa", "id_ed25519", "api_key", "api-key", "apikey", "token",
    "service_account", "service-account", "firebase-adminsdk",
}
_FORBIDDEN_SUFFIXES = {
    ".asc", ".gpg", ".jks", ".key", ".keystore", ".p12", ".pem", ".pfx",
}
_MAX_PLAN_STEPS = 32
_MAX_TEXT_BYTES = 262_144
_MAX_BACKUP_BYTES = 1_048_576
_RENAME_NOREPLACE = 1


def _rename_noreplace(
    source_fd: int, source: str, destination_fd: int, destination: str
) -> None:
    """Atomically rename without replacing an existing destination (Linux/WSL)."""

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2(RENAME_NOREPLACE) is required")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_fd,
        os.fsencode(source),
        destination_fd,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)
_PROCESS_LOCKS: dict[str, threading.RLock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


def _digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _digest_json(value: object) -> str:
    return _digest_bytes(canonical_json(value).encode("utf-8"))


def _identifier(name: str, value: str) -> str:
    text = str(value)
    if not _ID_RE.fullmatch(text):
        raise ValueError(f"{name} must match {_ID_RE.pattern}")
    return text


def _bounded_text(name: str, value: str, maximum: int) -> str:
    text = str(value)
    if not text.strip() or len(text) > maximum:
        raise ValueError(f"{name} must contain 1..{maximum} characters")
    return text


def _finite(name: str, value: float, *, low: float, high: float) -> float:
    numeric = float(value)
    if not math.isfinite(numeric) or not low <= numeric <= high:
        raise ValueError(f"{name} must be finite between {low} and {high}")
    return numeric


def _safe_relative_path(value: str) -> str:
    raw = str(value)
    if "\\" in raw:
        raise ValueError("action path must use normalized POSIX separators")
    path = PurePosixPath(raw)
    if (
        not raw
        or path.is_absolute()
        or path.as_posix() != raw
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("action path must be a non-empty normalized relative path")
    for part in path.parts:
        lowered = part.casefold()
        prefixed = any(
            lowered == prefix
            or any(lowered.startswith(prefix + separator) for separator in (".", "_", "-"))
            for prefix in _FORBIDDEN_PREFIXES
        )
        if (
            lowered in _FORBIDDEN_NAMES
            or prefixed
            or Path(lowered).suffix in _FORBIDDEN_SUFFIXES
        ):
            raise ValueError("action path targets protected credential or repository state")
    return path.as_posix()


@dataclass(frozen=True, slots=True)
class Opportunity:
    """One typed candidate objective for the opportunity portfolio."""

    id: str
    title: str
    rationale: str
    objective: str
    source: str
    source_authority: str
    value_impacts: Mapping[str, float]
    plan: Mapping[str, Any]
    evidence: tuple[str, ...] = field(default_factory=tuple)
    information_gain: float = 0.0
    uncertainty: float = 0.0
    time_cost: float = 0.0
    capability: str = "local_workspace_write"
    goal_id: str | None = None

    def __post_init__(self) -> None:
        _identifier("opportunity id", self.id)
        _bounded_text("opportunity title", self.title, 240)
        _bounded_text("opportunity rationale", self.rationale, 1200)
        _bounded_text("opportunity objective", self.objective, 800)
        _bounded_text("opportunity source", self.source, 200)
        _bounded_text("opportunity source_authority", self.source_authority, 80)
        _identifier("opportunity capability", self.capability)
        if self.goal_id is not None:
            _identifier("opportunity goal id", self.goal_id)
        _finite("opportunity information_gain", self.information_gain, low=0.0, high=1.0)
        _finite("opportunity uncertainty", self.uncertainty, low=0.0, high=1.0)
        _finite("opportunity time_cost", self.time_cost, low=0.0, high=10_000.0)
        if not self.value_impacts:
            raise ValueError("opportunity requires value impacts")
        if len(self.value_impacts) > 16:
            raise ValueError("opportunity value impacts exceed 16 entries")
        for key, value in self.value_impacts.items():
            _bounded_text("value impact name", str(key), 80)
            _finite(f"value impact {key}", float(value), low=-1.0, high=1.0)
        if len(self.evidence) > 16:
            raise ValueError("opportunity evidence exceeds 16 entries")
        for item in self.evidence:
            _bounded_text("opportunity evidence item", str(item), 600)
        canonical_json(dict(self.plan))

    @property
    def executable(self) -> bool:
        return self.source_authority in _EXECUTABLE_AUTHORITIES


@dataclass(frozen=True, slots=True)
class AuthorityEnvelope:
    level: int
    name: str
    max_actions: int
    max_total_bytes: int
    allow_replace: bool
    allowed_actions: tuple[str, ...] = ("write_text",)

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


_AUTHORITY_LEVELS = {
    1: AuthorityEnvelope(1, "reversible_local_create", 4, 16_384, False),
    2: AuthorityEnvelope(2, "verified_local_batch_create", 10, 65_536, False),
    3: AuthorityEnvelope(3, "earned_local_create_throughput", 24, 262_144, False),
}


class AutonomyEngine:
    """Select, plan, execute, verify, learn, and adapt bounded local work."""

    def __init__(
        self,
        store: EventStore,
        kernel: AgencyKernel,
        workspace_root: str | Path,
        *,
        state_root: str | Path | None = None,
    ) -> None:
        self.store = store
        self.kernel = kernel
        root = Path(workspace_root).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink():
            raise ValueError("workspace root must not be a symlink")
        self.workspace_root = root.resolve(strict=True)
        state_candidate = Path(state_root or (store.path.parent / "autonomy")).expanduser()
        state_candidate.mkdir(parents=True, exist_ok=True)
        if state_candidate.is_symlink():
            raise ValueError("state root must not be a symlink")
        self.state_root = state_candidate.resolve(strict=True)
        if (
            self.workspace_root == self.state_root
            or self.workspace_root in self.state_root.parents
            or self.state_root in self.workspace_root.parents
        ):
            raise ValueError("workspace root and private state root must be disjoint")
        store_path = store.path.expanduser().resolve()
        if store_path == self.workspace_root or self.workspace_root in store_path.parents:
            raise ValueError("event store must not reside inside the action workspace")
        self._workspace_root_fd = self._open_pinned_root(
            self.workspace_root, "workspace root"
        )
        try:
            self._state_root_fd = self._open_pinned_root(
                self.state_root, "private state root"
            )
        except Exception:
            os.close(self._workspace_root_fd)
            raise
        workspace_identity = os.fstat(self._workspace_root_fd)
        state_identity = os.fstat(self._state_root_fd)
        if os.path.samestat(workspace_identity, state_identity):
            os.close(self._workspace_root_fd)
            os.close(self._state_root_fd)
            del self._workspace_root_fd
            del self._state_root_fd
            raise ValueError("workspace root and private state root share one identity")
        self.opportunity_root = self.state_root / "opportunities"
        self.backup_root = self.state_root / "backups"
        os.fchmod(self._state_root_fd, 0o700)
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for name in ("opportunities", "backups"):
            try:
                os.mkdir(name, 0o700, dir_fd=self._state_root_fd)
            except FileExistsError:
                pass
            child = os.open(name, directory_flags, dir_fd=self._state_root_fd)
            try:
                if not stat.S_ISDIR(os.fstat(child).st_mode):
                    raise ValueError(f"private state {name} is not a directory")
                os.fchmod(child, 0o700)
            finally:
                os.close(child)
        self.lock_path = self.state_root / "run.lock"

    @staticmethod
    def _open_pinned_root(path: Path, label: str) -> int:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            visible = os.stat(path, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or not os.path.samestat(opened, visible):
                raise ValueError(f"{label} identity changed while opening")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def duplicate_state_root_fd(self) -> int:
        """Return a caller-owned descriptor for the pinned private state root."""

        return os.dup(self._state_root_fd)

    def close(self) -> None:
        for attribute in ("_workspace_root_fd", "_state_root_fd"):
            descriptor = getattr(self, attribute, None)
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                delattr(self, attribute)

    def __del__(self) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Opportunity portfolio and learned ranking
    # ------------------------------------------------------------------
    def register_opportunity(self, opportunity: Opportunity) -> dict[str, Any]:
        plan = self._validate_plan(dict(opportunity.plan), executable=opportunity.executable)
        plan_bytes = canonical_json(plan).encode("utf-8")
        if len(plan_bytes) > _MAX_BACKUP_BYTES:
            raise ValueError("normalized plan exceeds 1 MiB private-state bound")
        plan_digest = _digest_bytes(plan_bytes)
        plan_path = self.opportunity_root / f"{opportunity.id}.json"
        plan_relative = f"opportunities/{opportunity.id}.json"
        try:
            existing = self._read_private(plan_relative)
        except FileNotFoundError:
            try:
                self._write_private(plan_path, plan_bytes, no_replace=True)
            except FileExistsError:
                existing = self._read_private(plan_relative)
            else:
                existing = plan_bytes
        except OSError as exc:
            raise ValueError("opportunity plan state is not a regular file") from exc
        if existing != plan_bytes:
            if _digest_bytes(existing) != plan_digest:
                raise ValueError(f"opportunity plan collision: {opportunity.id}")
        payload = {
            "opportunity_id": opportunity.id,
            "title": opportunity.title,
            "rationale": opportunity.rationale,
            "objective": opportunity.objective,
            "source": opportunity.source,
            "source_authority": opportunity.source_authority,
            "executable": opportunity.executable,
            "content_trust": (
                "host_or_operator_metadata"
                if opportunity.executable
                else "self_generated_untrusted_proposal"
            ),
            "instructions_authorized": False,
            "value_impacts": {str(k): float(v) for k, v in opportunity.value_impacts.items()},
            "evidence": [str(item) for item in opportunity.evidence],
            "information_gain": float(opportunity.information_gain),
            "uncertainty": float(opportunity.uncertainty),
            "time_cost": float(opportunity.time_cost),
            "capability": opportunity.capability,
            "goal_id": opportunity.goal_id,
            "plan_sha256": plan_digest,
            "plan_file": plan_path.name,
            "plan_content_in_event_ledger": False,
            "status": "open",
        }
        event, created = self.store.append_once_result(
            "autonomy.opportunity.registered", opportunity.id, payload
        )
        return {**payload, "event_id": event.event_id, "created": created}

    def observe_artifact_gap(
        self,
        *,
        opportunity_id: str,
        relative_path: str,
        content: str,
        title: str,
        rationale: str,
        objective: str,
        value_impacts: Mapping[str, float],
        source: str,
        evidence: Sequence[str] = (),
        information_gain: float = 0.4,
        uncertainty: float = 0.1,
        time_cost: float = 0.1,
        capability: str = "verified_local_artifact",
    ) -> dict[str, Any]:
        """Detect one host-configured missing artifact without accepting commands."""

        identifier = _identifier("opportunity id", opportunity_id)
        safe_path = _safe_relative_path(relative_path)
        body = _bounded_text("artifact content", content, _MAX_TEXT_BYTES)
        expected = _digest_bytes(body.encode("utf-8"))
        current = self._read_workspace_file(safe_path)
        if current is not None and _digest_bytes(current) == expected:
            return {
                "observed": True,
                "registered": False,
                "status": "already_satisfied",
                "opportunity_id": identifier,
                "relative_path": safe_path,
                "expected_sha256": expected,
            }
        if current is not None:
            blocked = self.store.append_once(
                "autonomy.opportunity.observed_blocked",
                identifier,
                {
                    "opportunity_id": identifier,
                    "relative_path": safe_path,
                    "reason": "existing_target_mismatch_requires_higher_authority",
                    "observed_sha256": _digest_bytes(current),
                    "expected_sha256": expected,
                },
            )
            return {
                **dict(blocked.payload),
                "observed": True,
                "registered": False,
                "status": "blocked",
                "event_id": blocked.event_id,
            }
        plan = {
            "steps": [
                {
                    "id": "create-artifact",
                    "title": f"Create {safe_path}",
                    "preconditions": [{"kind": "path_absent", "path": safe_path}],
                    "action": {
                        "kind": "write_text",
                        "path": safe_path,
                        "content": body,
                    },
                    "verify": [
                        {"kind": "sha256_equals", "path": safe_path, "sha256": expected}
                    ],
                }
            ],
            "final_verify": [
                {"kind": "sha256_equals", "path": safe_path, "sha256": expected}
            ],
        }
        registered = self.register_opportunity(
            Opportunity(
                id=identifier,
                title=title,
                rationale=rationale,
                objective=objective,
                source=f"host_adapter:{_bounded_text('adapter source', source, 160)}",
                source_authority="host_adapter",
                value_impacts={str(key): float(value) for key, value in value_impacts.items()},
                plan=plan,
                evidence=tuple(str(item) for item in evidence),
                information_gain=float(information_gain),
                uncertainty=float(uncertainty),
                time_cost=float(time_cost),
                capability=capability,
            )
        )
        detected = self.store.append_once(
            "autonomy.opportunity.detected",
            identifier,
            {
                "opportunity_id": identifier,
                "relative_path": safe_path,
                "expected_sha256": expected,
                "registration_event_id": registered["event_id"],
                "adapter_source": source,
            },
        )
        return {
            "observed": True,
            "registered": True,
            "status": "open",
            "opportunity_id": identifier,
            "relative_path": safe_path,
            "expected_sha256": expected,
            "event_id": detected.event_id,
        }

    def opportunities(self) -> list[dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        for event in self.store.events():
            if event.kind == "autonomy.opportunity.registered":
                rows[str(event.payload["opportunity_id"])] = {
                    **dict(event.payload),
                    "registered_at": event.occurred_at,
                    "event_id": event.event_id,
                }
            elif event.kind == "autonomy.opportunity.status_changed":
                identifier = str(event.payload["opportunity_id"])
                if identifier in rows:
                    rows[identifier]["status"] = str(event.payload["to"])
                    rows[identifier]["last_run_id"] = event.payload.get("run_id")
        return [rows[key] for key in sorted(rows)]

    def _capability_learning(self, capability: str) -> dict[str, Any]:
        samples: list[float] = []
        for event in self.store.events("autonomy.run.completed"):
            if event.payload.get("capability") != capability:
                continue
            if not event.payload.get("success"):
                samples.append(0.0)
            elif int(event.payload.get("receipt_count", 0)) <= 0:
                continue
            elif int(event.payload.get("recovered_steps", 0)) > 0:
                samples.append(0.25)
            else:
                samples.append(1.0)
        if not samples:
            return {"samples": 0, "quality": 0.5, "success_rate": None}
        success_rate = sum(value > 0 for value in samples) / len(samples)
        return {
            "samples": len(samples),
            "quality": round(sum(samples) / len(samples), 12),
            "success_rate": round(success_rate, 12),
        }

    def _portfolio_goal(self) -> str:
        goal_id = "goal_cct_autonomous_local_work"
        if self.kernel.goal(goal_id) is None:
            self.kernel.form_goal(
                goal_id=goal_id,
                statement="Convert useful local opportunities into verified reversible outcomes.",
                rationale=(
                    "A complete observe-to-outcome loop expands operational competence and "
                    "autonomy while preserving truth through receipts."
                ),
                source="self",
                horizon="long",
                alignment={"truth": 0.9, "competence": 1.0, "autonomy": 0.9, "care": 0.4},
                evidence=("CCT Phase 10 capability-first action-loop contract",),
            )
        return goal_id

    def select_opportunity(
        self,
        *,
        seed: int,
        decision_id: str | None = None,
        opportunity_ids: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        scoped_ids: frozenset[str] | None = None
        if opportunity_ids is not None:
            if not isinstance(opportunity_ids, (tuple, list, frozenset)):
                raise ValueError("opportunity_ids must be a bounded sequence")
            scoped_ids = frozenset(
                _identifier("scoped opportunity id", str(identifier))
                for identifier in opportunity_ids
            )
            if not 1 <= len(scoped_ids) <= 32:
                raise ValueError("opportunity_ids must contain 1-32 unique ids")
        options: list[Option] = []
        learning: dict[str, dict[str, Any]] = {}
        for row in self.opportunities():
            if row.get("status") != "open":
                continue
            if scoped_ids is not None and row["opportunity_id"] not in scoped_ids:
                continue
            capability = str(row["capability"])
            learned = self._capability_learning(capability)
            learning[str(row["opportunity_id"])] = learned
            impacts = {str(k): float(v) for k, v in dict(row["value_impacts"]).items()}
            if learned["samples"]:
                adjustment = (float(learned["quality"]) - 0.5) * 0.6
                impacts["competence"] = max(-1.0, min(1.0, impacts.get("competence", 0.0) + adjustment))
            uncertainty = float(row["uncertainty"])
            if learned["samples"]:
                uncertainty = min(1.0, uncertainty + (1.0 - float(learned["quality"])) * 0.4)
            blocked: list[str] = []
            if not row.get("executable"):
                blocked.append("Only host_adapter or authenticated operator opportunities may execute.")
            options.append(
                Option(
                    id=str(row["opportunity_id"]),
                    description=str(row["title"]),
                    value_impacts=impacts,
                    information_gain=float(row["information_gain"]),
                    uncertainty=uncertainty,
                    time_cost=float(row["time_cost"]),
                    irreversible=False,
                    blocked_reasons=tuple(blocked),
                    assumptions=(
                        f"capability={capability}",
                        f"learning_samples={learned['samples']}",
                        f"learned_quality={learned['quality']}",
                    ),
                )
            )
        identifier = decision_id or f"autonomy_portfolio_{self.store.allocate_counter('autonomy_portfolio')}"
        decision = self.kernel.deliberate(
            goal_id=self._portfolio_goal(), options=options, seed=seed, decision_id=identifier
        )
        selected = str(decision["chosen_option_id"])
        event = self.store.append_once(
            "autonomy.opportunity.selected",
            identifier,
            {
                "decision_id": identifier,
                "opportunity_id": selected,
                "learning": learning,
                "seed": seed,
                "selection_event_id": decision["event_id"],
            },
        )
        return {**decision, "opportunity_id": selected, "portfolio_event_id": event.event_id, "learning": learning}

    # ------------------------------------------------------------------
    # Hierarchical objectives and temporal planning
    # ------------------------------------------------------------------
    def _ensure_objective(self, opportunity: Mapping[str, Any], plan: Mapping[str, Any]) -> dict[str, Any]:
        opportunity_id = str(opportunity["opportunity_id"])
        goal_id = f"goal_{opportunity_id}"
        if self.kernel.goal(goal_id) is None:
            self.kernel.form_goal(
                goal_id=goal_id,
                statement=str(opportunity["objective"]),
                rationale=str(opportunity["rationale"]),
                source="self" if opportunity["source_authority"] == "host_adapter" else "joint",
                horizon="short",
                alignment=dict(opportunity["value_impacts"]),
                evidence=tuple(str(item) for item in opportunity.get("evidence", [])),
            )
        objective_id = f"objective_{opportunity_id}"
        root_payload = {
            "objective_id": objective_id,
            "goal_id": goal_id,
            "opportunity_id": opportunity_id,
            "parent_objective_id": None,
            "kind": "root",
            "statement": str(opportunity["objective"]),
            "status": "active",
        }
        root_event = self.store.append_once("autonomy.objective.created", objective_id, root_payload)
        milestones: list[dict[str, Any]] = []
        for index, step in enumerate(plan["steps"], start=1):
            milestone_id = f"{objective_id}.m{index}"
            payload = {
                "objective_id": milestone_id,
                "goal_id": goal_id,
                "opportunity_id": opportunity_id,
                "parent_objective_id": objective_id,
                "kind": "milestone",
                "statement": str(step.get("title") or step["id"]),
                "step_id": str(step["id"]),
                "status": "active",
            }
            event = self.store.append_once("autonomy.objective.created", milestone_id, payload)
            milestones.append({**payload, "event_id": event.event_id})
        return {
            **root_payload,
            "event_id": root_event.event_id,
            "milestones": milestones,
        }

    def _load_plan(self, opportunity: Mapping[str, Any]) -> dict[str, Any]:
        plan_file = PurePosixPath(str(opportunity["plan_file"]))
        if len(plan_file.parts) != 1 or plan_file.name != str(opportunity["plan_file"]):
            raise ValueError("opportunity plan path is not trusted")
        raw = self._read_private(f"opportunities/{plan_file.name}")
        if _digest_bytes(raw) != opportunity["plan_sha256"]:
            raise ValueError("opportunity plan digest mismatch")
        return self._validate_plan(json.loads(raw), executable=bool(opportunity["executable"]))

    def _validate_plan(self, plan: Mapping[str, Any], *, executable: bool) -> dict[str, Any]:
        row = dict(plan)
        unknown_plan = set(row) - {"version", "steps", "final_verify"}
        if unknown_plan:
            raise ValueError(f"plan has unknown fields: {sorted(unknown_plan)}")
        if "version" in row and row["version"] != 1:
            raise ValueError("plan version must be 1")
        if not isinstance(row.get("steps", []), list):
            raise ValueError("plan steps must be an array")
        steps = list(row.get("steps", []))
        if executable and not steps:
            raise ValueError("executable opportunity requires at least one plan step")
        if len(steps) > _MAX_PLAN_STEPS:
            raise ValueError(f"plan exceeds {_MAX_PLAN_STEPS} steps")
        normalized: list[dict[str, Any]] = []
        ids: set[str] = set()
        for raw_step in steps:
            if not isinstance(raw_step, Mapping):
                raise ValueError("each plan step must be an object")
            step = dict(raw_step)
            unknown_step = set(step) - {
                "id", "title", "depends_on", "preconditions", "action", "verify",
                "max_attempts", "fallback",
            }
            if unknown_step:
                raise ValueError(f"plan step has unknown fields: {sorted(unknown_step)}")
            step_id = _identifier("step id", str(step["id"]))
            if step_id in ids:
                raise ValueError(f"duplicate step id: {step_id}")
            ids.add(step_id)
            depends_raw = step.get("depends_on", [])
            preconditions_raw = step.get("preconditions", [])
            verify_raw = step.get("verify", [])
            if not isinstance(depends_raw, list) or len(depends_raw) > _MAX_PLAN_STEPS:
                raise ValueError(f"step {step_id} dependencies must be a bounded array")
            if not isinstance(preconditions_raw, list) or len(preconditions_raw) > 16:
                raise ValueError(f"step {step_id} preconditions must be a bounded array")
            if not isinstance(verify_raw, list) or len(verify_raw) > 16:
                raise ValueError(f"step {step_id} verification must be a bounded array")
            depends = [_identifier("dependency id", str(item)) for item in depends_raw]
            action = self._validate_action(dict(step["action"]))
            preconditions = [
                self._validate_check(dict(item), verifier=False) for item in preconditions_raw
            ]
            verify = [self._validate_check(dict(item), verifier=True) for item in verify_raw]
            if not verify:
                raise ValueError(f"step {step_id} requires independent verification")
            if not self._verifies_action(action, verify):
                raise ValueError(
                    f"step {step_id} must verify its action path and content hash"
                )
            fallback = step.get("fallback")
            normalized_fallback = None
            if fallback is not None:
                if not isinstance(fallback, Mapping):
                    raise ValueError(f"step {step_id} fallback must be an object")
                fallback_row = dict(fallback)
                unknown_fallback = set(fallback_row) - {"action", "preconditions", "verify"}
                if unknown_fallback:
                    raise ValueError(
                        f"step {step_id} fallback has unknown fields: {sorted(unknown_fallback)}"
                    )
                fallback_preconditions = fallback_row.get("preconditions", [])
                fallback_verify = fallback_row.get("verify", [])
                if not isinstance(fallback_preconditions, list) or len(fallback_preconditions) > 16:
                    raise ValueError(f"step {step_id} fallback preconditions are unbounded")
                if not isinstance(fallback_verify, list) or len(fallback_verify) > 16:
                    raise ValueError(f"step {step_id} fallback verification is unbounded")
                normalized_fallback = {
                    "action": self._validate_action(dict(fallback_row["action"])),
                    "preconditions": [
                        self._validate_check(dict(item), verifier=False)
                        for item in fallback_preconditions
                    ],
                    "verify": [
                        self._validate_check(dict(item), verifier=True)
                        for item in fallback_verify
                    ],
                }
                if not normalized_fallback["verify"]:
                    raise ValueError(f"step {step_id} fallback requires verification")
                if not self._verifies_action(
                    normalized_fallback["action"], normalized_fallback["verify"]
                ):
                    raise ValueError(
                        f"step {step_id} fallback must verify its action path and content hash"
                    )
            max_attempts = step.get("max_attempts", 1)
            if (
                isinstance(max_attempts, bool)
                or not isinstance(max_attempts, int)
                or not 1 <= max_attempts <= 3
            ):
                raise ValueError(f"step {step_id} max_attempts must be an integer from 1 to 3")
            normalized.append(
                {
                    "id": step_id,
                    "title": _bounded_text("step title", str(step.get("title") or step_id), 240),
                    "depends_on": depends,
                    "preconditions": preconditions,
                    "action": action,
                    "verify": verify,
                    "max_attempts": max_attempts,
                    "fallback": normalized_fallback,
                }
            )
        for step in normalized:
            unknown = set(step["depends_on"]) - ids
            if unknown:
                raise ValueError(f"step {step['id']} references unknown dependencies: {sorted(unknown)}")
        self._topological_steps(normalized)
        finals_raw = row.get("final_verify", [])
        if not isinstance(finals_raw, list) or len(finals_raw) > 16:
            raise ValueError("plan final verification must be a bounded array")
        finals = [self._validate_check(dict(item), verifier=True) for item in finals_raw]
        if executable and not finals:
            raise ValueError("executable plan requires final verification")
        return {"version": 1, "steps": normalized, "final_verify": finals}

    @staticmethod
    def _verifies_action(
        action: Mapping[str, Any], checks: list[dict[str, Any]]
    ) -> bool:
        """Require branch-local proof of the exact bytes the action proposes."""

        return any(
            check.get("kind") == "sha256_equals"
            and check.get("path") == action.get("path")
            and check.get("sha256") == action.get("content_sha256")
            for check in checks
        )

    @staticmethod
    def _validate_action(action: Mapping[str, Any]) -> dict[str, Any]:
        unknown = set(action) - {
            "kind", "path", "content", "allow_replace", "content_sha256", "bytes",
        }
        if unknown:
            raise ValueError(f"action has unknown fields: {sorted(unknown)}")
        kind = str(action.get("kind", ""))
        if kind != "write_text":
            raise ValueError("only the reversible write_text action is allowed")
        relative = _safe_relative_path(str(action.get("path", "")))
        content_value = action.get("content", "")
        if not isinstance(content_value, str):
            raise ValueError("write_text content must be a string")
        content = content_value
        allow_replace = action.get("allow_replace", False)
        if not isinstance(allow_replace, bool):
            raise ValueError("write_text allow_replace must be boolean")
        size = len(content.encode("utf-8"))
        if size > _MAX_TEXT_BYTES:
            raise ValueError(f"write_text content exceeds {_MAX_TEXT_BYTES} bytes")
        content_sha256 = _digest_bytes(content.encode("utf-8"))
        if "content_sha256" in action and action["content_sha256"] != content_sha256:
            raise ValueError("write_text content_sha256 does not match content")
        if "bytes" in action and action["bytes"] != size:
            raise ValueError("write_text bytes does not match encoded content")
        return {
            "kind": kind,
            "path": relative,
            "content": content,
            "content_sha256": content_sha256,
            "bytes": size,
            "allow_replace": allow_replace,
        }

    @staticmethod
    def _validate_check(check: Mapping[str, Any], *, verifier: bool) -> dict[str, Any]:
        kind = str(check.get("kind", ""))
        allowed = {"path_exists", "path_absent", "sha256_equals"}
        if kind not in allowed:
            raise ValueError(f"unsupported {'verification' if verifier else 'precondition'}: {kind}")
        allowed_fields = {"kind", "path", "sha256"} if kind == "sha256_equals" else {"kind", "path"}
        unknown = set(check) - allowed_fields
        if unknown:
            raise ValueError(f"check has unknown fields: {sorted(unknown)}")
        path = _safe_relative_path(str(check.get("path", "")))
        result = {"kind": kind, "path": path}
        if kind == "sha256_equals":
            expected = str(check.get("sha256", ""))
            if not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError("sha256_equals requires a lowercase SHA-256 digest")
            result["sha256"] = expected
        return result

    @staticmethod
    def _topological_steps(steps: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        pending = {str(step["id"]): dict(step) for step in steps}
        ordered: list[dict[str, Any]] = []
        completed: set[str] = set()
        while pending:
            ready = sorted(
                identifier
                for identifier, step in pending.items()
                if set(step.get("depends_on", [])) <= completed
            )
            if not ready:
                raise ValueError("plan dependency graph contains a cycle")
            for identifier in ready:
                ordered.append(pending.pop(identifier))
                completed.add(identifier)
        return ordered

    # ------------------------------------------------------------------
    # Authority, execution, receipts, rollback, and learning
    # ------------------------------------------------------------------
    def authority(self) -> AuthorityEnvelope:
        latest = self.store.latest("autonomy.authority.updated")
        level = int(latest.payload["level"]) if latest else 1
        return _AUTHORITY_LEVELS[max(1, min(3, level))]

    def _update_authority(self, *, run_id: str) -> dict[str, Any]:
        runs = self.store.events("autonomy.run.completed")[-20:]
        successes = [
            event
            for event in runs
            if event.payload.get("success")
            and event.payload.get("verified")
            and int(event.payload.get("receipt_count", 0)) > 0
        ]
        clean = [
            event for event in successes
            if int(event.payload.get("recovered_steps", 0)) == 0
            and not event.payload.get("rollback_performed")
        ]
        failures = [event for event in runs if not event.payload.get("success")]
        current = self.authority().level
        new_level = current
        reason = "preserve demonstrated envelope"
        if failures and runs[-1] in failures:
            new_level = 1
            reason = "latest failure contracts authority"
        elif current == 1 and len(clean) >= 3 and not failures:
            new_level = 2
            reason = "three clean verified successes earned local replacement authority"
        elif current == 2 and len(clean) >= 10 and len(successes) / len(runs) >= 0.9:
            new_level = 3
            reason = "ten clean successes with >=90% success earned higher throughput"
        payload = {
            "run_id": run_id,
            "level": new_level,
            "previous_level": current,
            "reason": reason,
            "window_runs": len(runs),
            "verified_successes": len(successes),
            "clean_successes": len(clean),
            "failures": len(failures),
            "envelope": _AUTHORITY_LEVELS[new_level].as_payload(),
        }
        event = self.store.append_once("autonomy.authority.updated", run_id, payload)
        return {**payload, "event_id": event.event_id}

    @contextmanager
    def _run_lock(self) -> Iterator[None]:
        state_identity = os.fstat(self._state_root_fd)
        key = f"{state_identity.st_dev}:{state_identity.st_ino}"
        with _PROCESS_LOCKS_GUARD:
            process_lock = _PROCESS_LOCKS.setdefault(key, threading.RLock())
        with process_lock:
            descriptor = os.open(
                "run.lock",
                os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=self._state_root_fd,
            )
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError("run lock must be a regular file")
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def run_once(
        self,
        *,
        seed: int,
        run_id: str | None = None,
        decision_id: str | None = None,
        opportunity_id: str | None = None,
    ) -> dict[str, Any]:
        if run_id is not None:
            _identifier("run id", run_id)
        if opportunity_id is not None:
            opportunity_id = _identifier("scoped opportunity id", opportunity_id)
        with self._run_lock():
            resumed_start: Event | None = None
            if run_id:
                existing = self._run_event(run_id, "autonomy.run.completed")
                if existing is not None:
                    authority = self._finalize_completion(dict(existing.payload))
                    return {
                        **dict(existing.payload),
                        "event_id": existing.event_id,
                        "authority": authority,
                        "idempotent": True,
                    }
                resumed_start = self._run_event(run_id, "autonomy.run.started")
            if resumed_start is not None:
                recorded_decision = str(resumed_start.payload["decision_id"])
                if decision_id is not None and decision_id != recorded_decision:
                    raise ValueError("run resume decision_id conflicts with the recorded start")
                selection = {
                    "decision_id": recorded_decision,
                    "opportunity_id": str(resumed_start.payload["opportunity_id"]),
                }
                if (
                    opportunity_id is not None
                    and selection["opportunity_id"] != opportunity_id
                ):
                    raise ValueError(
                        "run resume opportunity_id conflicts with the recorded start"
                    )
            else:
                selection = self.select_opportunity(
                    seed=seed,
                    decision_id=decision_id,
                    opportunity_ids=(opportunity_id,) if opportunity_id else None,
                )
            opportunity_id = str(selection["opportunity_id"])
            if opportunity_id == NO_OP_ID:
                event = self.store.append_once(
                    "autonomy.portfolio.deferred",
                    str(selection["decision_id"]),
                    {
                        "decision_id": selection["decision_id"],
                        "reason": "canonical NO_OP selected; no external effect",
                        "external_effects": 0,
                    },
                )
                return {
                    "success": True,
                    "decision_id": selection["decision_id"],
                    "chosen_option_id": NO_OP_ID,
                    "external_effects": 0,
                    "event_id": event.event_id,
                }
            opportunity = next(
                row for row in self.opportunities() if row["opportunity_id"] == opportunity_id
            )
            plan = self._load_plan(opportunity)
            objective = self._ensure_objective(opportunity, plan)
            plan_id = f"plan_{opportunity_id}"
            plan_event = self.store.append_once(
                "autonomy.plan.created",
                plan_id,
                {
                    "plan_id": plan_id,
                    "opportunity_id": opportunity_id,
                    "objective_id": objective["objective_id"],
                    "plan_sha256": opportunity["plan_sha256"],
                    "step_ids": [step["id"] for step in plan["steps"]],
                    "dependency_edges": [
                        [dependency, step["id"]]
                        for step in plan["steps"]
                        for dependency in step["depends_on"]
                    ],
                    "temporal_order": [step["id"] for step in self._topological_steps(plan["steps"])],
                    "content_in_event_ledger": False,
                },
            )
            identifier = run_id or "run_" + _digest_json(
                {"decision_id": selection["decision_id"], "plan_id": plan_id}
            )[:20]
            _identifier("run id", identifier)
            start_payload = {
                "run_id": identifier,
                "decision_id": selection["decision_id"],
                "opportunity_id": opportunity_id,
                "objective_id": objective["objective_id"],
                "plan_id": plan_id,
                "plan_event_id": plan_event.event_id,
                "authority": (
                    dict(resumed_start.payload["authority"])
                    if resumed_start is not None
                    else self.authority().as_payload()
                ),
            }
            if resumed_start is not None:
                if canonical_json(resumed_start.payload) != canonical_json(start_payload):
                    raise ValueError("run resume state does not match its recorded plan")
                started = resumed_start
            else:
                started = self.store.append_once(
                    "autonomy.run.started", identifier, start_payload
                )
            recorded_level = int(start_payload["authority"]["level"])
            if recorded_level not in _AUTHORITY_LEVELS:
                raise ValueError("run recorded an unknown authority level")
            result = self._execute_plan(
                identifier, plan, envelope=_AUTHORITY_LEVELS[recorded_level]
            )
            realized = 1.0 if result["success"] else -1.0
            realized -= 0.2 * int(result["recovered_steps"])
            realized -= 0.4 if result["rollback_performed"] else 0.0
            receipt_event_ids = [
                event.event_id
                for event in self.store.events("autonomy.action.receipt")
                if event.payload.get("run_id") == identifier
            ]
            execution = self.store.append_once(
                "autonomy.run.executed",
                identifier,
                {
                    "run_id": identifier,
                    "success": bool(result["success"]),
                    "verified": bool(result["verified"]),
                    "recovered_steps": int(result["recovered_steps"]),
                    "rollback_performed": bool(result["rollback_performed"]),
                    "rollback_complete": bool(result["rollback_complete"]),
                    "receipt_event_ids": receipt_event_ids,
                    "realized_utility": round(realized, 12),
                },
            )
            evidence = [f"event:{execution.event_id}"]
            outcome = self.kernel.record_outcome(
                decision_id=str(selection["decision_id"]),
                realized_utility=realized,
                observation=(
                    "Autonomous local plan completed with independent verification."
                    if result["success"]
                    else "Autonomous local plan failed; prior mutations were rolled back where safe."
                ),
                evidence=evidence,
            )
            completion_payload = {
                "run_id": identifier,
                "decision_id": selection["decision_id"],
                "opportunity_id": opportunity_id,
                "objective_id": objective["objective_id"],
                "plan_id": plan_id,
                "capability": opportunity["capability"],
                "success": bool(result["success"]),
                "verified": bool(result["verified"]),
                "recovered_steps": int(result["recovered_steps"]),
                "rollback_performed": bool(result["rollback_performed"]),
                "rollback_complete": bool(result["rollback_complete"]),
                "receipt_count": int(result["receipt_count"]),
                "realized_utility": round(realized, 12),
                "outcome_event_id": outcome.event_id,
                "started_event_id": started.event_id,
                "evidence_event_ids": [execution.event_id],
            }
            completed = self.store.append_once(
                "autonomy.run.completed", identifier, completion_payload
            )
            authority = self._finalize_completion(completion_payload)
            return {
                **completion_payload,
                "event_id": completed.event_id,
                "authority": authority,
                "idempotent": False,
            }

    def _finalize_completion(self, completion: Mapping[str, Any]) -> dict[str, Any]:
        """Repair the idempotent post-completion projections after a crash."""

        identifier = str(completion["run_id"])
        opportunity_id = str(completion["opportunity_id"])
        objective_id = str(completion["objective_id"])
        success = bool(completion["success"])
        desired_opportunity = "completed" if success else "failed"
        desired_objective = "completed" if success else "paused"
        self.store.append_once(
            "autonomy.opportunity.status_changed",
            identifier,
            {
                "opportunity_id": opportunity_id,
                "from": "open",
                "to": desired_opportunity,
                "run_id": identifier,
            },
        )
        self.store.append_once(
            "autonomy.objective.status_changed",
            identifier,
            {
                "objective_id": objective_id,
                "from": "active",
                "to": desired_objective,
                "run_id": identifier,
            },
        )
        goal = self.kernel.goal(f"goal_{opportunity_id}")
        if goal is not None and goal.status != desired_objective:
            self.kernel.set_goal_status(
                goal.id,
                desired_objective,
                f"Autonomy run {identifier} {'verified' if success else 'failed'}.",
            )
        authority_event = self._run_event(identifier, "autonomy.authority.updated")
        if authority_event is None:
            return self._update_authority(run_id=identifier)
        return {**dict(authority_event.payload), "event_id": authority_event.event_id}

    def _execute_plan(
        self,
        run_id: str,
        plan: Mapping[str, Any],
        *,
        envelope: AuthorityEnvelope | None = None,
    ) -> dict[str, Any]:
        envelope = envelope or self.authority()
        receipts: list[dict[str, Any]] = []
        evidence_events: list[str] = []
        recovered_steps = 0
        any_rollback = False
        all_rollbacks_complete = True
        actions_used = 0
        bytes_used = 0
        for step in self._topological_steps(plan["steps"]):
            step_success = False
            primary_failure: dict[str, Any] | None = None
            rollback_incomplete = False
            for attempt in range(1, int(step["max_attempts"]) + 1):
                actions_used += 1
                if actions_used > envelope.max_actions:
                    primary_failure = {"code": "action_budget_exhausted", "error_type": "BudgetExceeded"}
                    break
                bytes_used += int(step["action"]["bytes"])
                if bytes_used > envelope.max_total_bytes:
                    primary_failure = {"code": "byte_budget_exhausted", "error_type": "BudgetExceeded"}
                    break
                attempted = self._attempt_step(
                    run_id, str(step["id"]), attempt, step["action"],
                    step["preconditions"], step["verify"], envelope,
                )
                evidence_events.extend(attempted["event_ids"])
                if attempted["receipt"] is not None:
                    if attempted["success"]:
                        receipts.append(attempted["receipt"])
                    else:
                        rollback = self._rollback(run_id, [attempted["receipt"]], reason="failed_verification")
                        any_rollback = True
                        all_rollbacks_complete = (
                            all_rollbacks_complete and bool(rollback["complete"])
                        )
                        rollback_incomplete = not bool(rollback["complete"])
                        evidence_events.extend(rollback["event_ids"])
                if attempted["success"]:
                    step_success = True
                    break
                primary_failure = attempted
            if (
                not step_success
                and not rollback_incomplete
                and step.get("fallback") is not None
            ):
                fallback = dict(step["fallback"])
                replan = self.store.append(
                    "autonomy.plan.replanned",
                    {
                        "run_id": run_id,
                        "step_id": step["id"],
                        "reason_code": str((primary_failure or {}).get("code", "primary_failed")),
                        "fallback_action": fallback["action"]["kind"],
                        "fallback_path": fallback["action"]["path"],
                    },
                )
                evidence_events.append(replan.event_id)
                actions_used += 1
                bytes_used += int(fallback["action"]["bytes"])
                if actions_used <= envelope.max_actions and bytes_used <= envelope.max_total_bytes:
                    attempted = self._attempt_step(
                        run_id, str(step["id"]), 1, fallback["action"],
                        fallback["preconditions"], fallback["verify"], envelope,
                        branch="fallback",
                    )
                    evidence_events.extend(attempted["event_ids"])
                    if attempted["receipt"] is not None:
                        if attempted["success"]:
                            receipts.append(attempted["receipt"])
                        else:
                            rollback = self._rollback(run_id, [attempted["receipt"]], reason="fallback_verification_failed")
                            any_rollback = True
                            all_rollbacks_complete = (
                                all_rollbacks_complete and bool(rollback["complete"])
                            )
                            rollback_incomplete = not bool(rollback["complete"])
                            evidence_events.extend(rollback["event_ids"])
                    step_success = bool(attempted["success"])
                    if step_success:
                        recovered_steps += 1
            if not step_success:
                rollback = self._rollback(run_id, receipts, reason="terminal_step_failure")
                any_rollback = any_rollback or bool(receipts)
                all_rollbacks_complete = (
                    all_rollbacks_complete and bool(rollback["complete"])
                )
                evidence_events.extend(rollback["event_ids"])
                return {
                    "success": False,
                    "verified": False,
                    "recovered_steps": recovered_steps,
                    "rollback_performed": any_rollback,
                    "rollback_complete": all_rollbacks_complete,
                    "receipt_count": len(receipts),
                    "evidence_event_ids": evidence_events,
                }
        final = self._evaluate_checks(plan["final_verify"])
        latest_receipt_by_path = {
            str(receipt["relative_path"]): receipt for receipt in receipts
        }
        receipt_final = self._evaluate_checks(
            [
                {
                    "kind": "sha256_equals",
                    "path": relative_path,
                    "sha256": str(receipt["after_sha256"]),
                }
                for relative_path, receipt in latest_receipt_by_path.items()
            ]
        )
        final_passed = bool(final["passed"] and receipt_final["passed"])
        final_event = self.store.append(
            "autonomy.plan.verified",
            {
                "run_id": run_id,
                "passed": final_passed,
                "checks": final["checks"],
                "receipt_checks": receipt_final["checks"],
            },
        )
        evidence_events.append(final_event.event_id)
        if not final_passed:
            rollback = self._rollback(run_id, receipts, reason="final_verification_failed")
            any_rollback = any_rollback or bool(receipts)
            all_rollbacks_complete = (
                all_rollbacks_complete and bool(rollback["complete"])
            )
            evidence_events.extend(rollback["event_ids"])
            return {
                "success": False,
                "verified": False,
                "recovered_steps": recovered_steps,
                "rollback_performed": any_rollback,
                "rollback_complete": all_rollbacks_complete,
                "receipt_count": len(receipts),
                "evidence_event_ids": evidence_events,
            }
        return {
            "success": True,
            "verified": True,
            "recovered_steps": recovered_steps,
            "rollback_performed": any_rollback,
            "rollback_complete": all_rollbacks_complete,
            "receipt_count": len(receipts),
            "evidence_event_ids": evidence_events,
        }

    def _action_event(
        self,
        kind: str,
        run_id: str,
        step_id: str,
        branch: str,
        attempt: int,
    ) -> Event | None:
        for event in reversed(self.store.events(kind)):
            payload = event.payload
            if (
                payload.get("run_id") == run_id
                and payload.get("step_id") == step_id
                and payload.get("branch") == branch
                and int(payload.get("attempt", 0)) == attempt
            ):
                return event
        return None

    def _receipt_from_claim(self, claim: Event, *, reconciled: bool) -> dict[str, Any]:
        payload = dict(claim.payload)
        if not self._claim_target_matches(payload):
            raise OSError("claimed action target lacks prepared-inode authorship proof")
        receipt_payload = {
            "run_id": payload["run_id"],
            "step_id": payload["step_id"],
            "branch": payload["branch"],
            "attempt": payload["attempt"],
            "action": payload["action"],
            "relative_path": payload["relative_path"],
            "before_exists": payload["before_exists"],
            "before_sha256": payload["before_sha256"],
            "after_sha256": payload["after_sha256"],
            "bytes_written": payload["bytes_written"],
            "backup_file": payload["backup_file"],
            "prepared_dev": payload["prepared_dev"],
            "prepared_ino": payload["prepared_ino"],
            "claim_event_id": claim.event_id,
            "reconciled_after_restart": reconciled,
            "content_in_event_ledger": False,
            "reversible": True,
        }
        logical_key = (
            f"{payload['run_id']}:{payload['step_id']}:"
            f"{payload['branch']}:{payload['attempt']}"
        )
        event = self.store.append_once(
            "autonomy.action.receipt", logical_key, receipt_payload
        )
        return {**receipt_payload, "event_id": event.event_id}

    def _attempt_step(
        self,
        run_id: str,
        step_id: str,
        attempt: int,
        action: Mapping[str, Any],
        preconditions: Sequence[Mapping[str, Any]],
        verifiers: Sequence[Mapping[str, Any]],
        envelope: AuthorityEnvelope,
        *,
        branch: str = "primary",
    ) -> dict[str, Any]:
        receipt_event = self._action_event(
            "autonomy.action.receipt", run_id, step_id, branch, attempt
        )
        claim_event = self._action_event(
            "autonomy.action.claimed", run_id, step_id, branch, attempt
        )
        receipt = (
            {**dict(receipt_event.payload), "event_id": receipt_event.event_id}
            if receipt_event is not None
            else None
        )
        # Crash recovery: reconcile a durable claim or receipt before any retry.
        existing = self._evaluate_checks(verifiers)
        if existing["passed"]:
            proof = receipt if receipt is not None else (
                claim_event.payload if claim_event is not None else None
            )
            if proof is not None and not self._claim_target_matches(proof):
                event = self.store.append(
                    "autonomy.step.failed",
                    {
                        "run_id": run_id,
                        "step_id": step_id,
                        "branch": branch,
                        "attempt": attempt,
                        "code": "authorship_conflict",
                        "error_type": "AuthorshipConflict",
                        "external_effects": 0,
                    },
                )
                return {
                    "success": False,
                    "receipt": receipt,
                    "event_ids": [event.event_id],
                    "code": "authorship_conflict",
                    "error_type": "AuthorshipConflict",
                }
            if receipt is None and claim_event is not None:
                receipt = self._receipt_from_claim(claim_event, reconciled=True)
            event = self.store.append_once(
                "autonomy.step.recovered",
                f"{run_id}:{step_id}:{branch}:{attempt}",
                {
                    "run_id": run_id, "step_id": step_id, "branch": branch,
                    "attempt": attempt, "reason": "artifact_already_verified",
                    "receipt_event_id": receipt["event_id"] if receipt is not None else None,
                },
            )
            event_ids = [event.event_id]
            if receipt is not None:
                event_ids.insert(0, receipt["event_id"])
            return {"success": True, "receipt": receipt, "event_ids": event_ids}
        if receipt is not None:
            event = self.store.append_once(
                "autonomy.step.recovered_failed_verification",
                f"{run_id}:{step_id}:{branch}:{attempt}",
                {
                    "run_id": run_id,
                    "step_id": step_id,
                    "branch": branch,
                    "attempt": attempt,
                    "receipt_event_id": receipt["event_id"],
                    "reason": "receipt_exists_but_verification_failed",
                },
            )
            return {
                "success": False,
                "receipt": receipt,
                "event_ids": [receipt["event_id"], event.event_id],
                "code": "verification_failed",
                "error_type": "VerificationFailed",
            }
        if claim_event is not None:
            if self._claim_target_matches(claim_event.payload):
                receipt = self._receipt_from_claim(claim_event, reconciled=True)
                event = self.store.append_once(
                    "autonomy.step.recovered_failed_verification",
                    f"{run_id}:{step_id}:{branch}:{attempt}",
                    {
                        "run_id": run_id,
                        "step_id": step_id,
                        "branch": branch,
                        "attempt": attempt,
                        "receipt_event_id": receipt["event_id"],
                        "reason": "claimed_action_present_but_verification_failed",
                    },
                )
                return {
                    "success": False,
                    "receipt": receipt,
                    "event_ids": [receipt["event_id"], event.event_id],
                    "code": "verification_failed",
                    "error_type": "VerificationFailed",
                }
        precondition = self._evaluate_checks(preconditions)
        if not precondition["passed"]:
            event = self.store.append(
                "autonomy.step.failed",
                {
                    "run_id": run_id, "step_id": step_id, "branch": branch,
                    "attempt": attempt, "code": "precondition_failed",
                    "checks": precondition["checks"], "external_effects": 0,
                },
            )
            return {
                "success": False, "receipt": None, "event_ids": [event.event_id],
                "code": "precondition_failed", "error_type": "PreconditionFailed",
            }
        try:
            receipt = self._apply_action(
                run_id, step_id, branch, attempt, action, envelope
            )
        except (ValueError, OSError) as exc:
            event = self.store.append(
                "autonomy.step.failed",
                {
                    "run_id": run_id, "step_id": step_id, "branch": branch,
                    "attempt": attempt, "code": "action_failed",
                    "error_type": type(exc).__name__, "external_effects": 0,
                },
            )
            return {
                "success": False, "receipt": None, "event_ids": [event.event_id],
                "code": "action_failed", "error_type": type(exc).__name__,
            }
        verification = self._evaluate_checks(verifiers)
        event = self.store.append(
            "autonomy.step.verified",
            {
                "run_id": run_id, "step_id": step_id, "branch": branch,
                "attempt": attempt, "passed": verification["passed"],
                "checks": verification["checks"],
                "receipt_event_id": receipt["event_id"],
            },
        )
        return {
            "success": bool(verification["passed"]),
            "receipt": receipt,
            "event_ids": [receipt["event_id"], event.event_id],
            "code": None if verification["passed"] else "verification_failed",
            "error_type": None if verification["passed"] else "VerificationFailed",
        }

    def _apply_action(
        self,
        run_id: str,
        step_id: str,
        branch: str,
        attempt: int,
        action: Mapping[str, Any],
        envelope: AuthorityEnvelope,
    ) -> dict[str, Any]:
        if action["kind"] not in envelope.allowed_actions:
            raise ValueError("action is outside current authority envelope")
        if action.get("allow_replace") or envelope.allow_replace:
            raise ValueError("Phase 10 authority is create-only")
        relative_path = str(action["path"])
        content = str(action["content"]).encode("utf-8")
        operation_key = f"{run_id}:{step_id}:{branch}:{attempt}"
        claim = self._action_event(
            "autonomy.action.claimed", run_id, step_id, branch, attempt
        )
        if claim is None:
            if self._read_workspace_file(relative_path) is not None:
                raise ValueError("create-only target already exists")
            temp_key = _digest_bytes(operation_key.encode("utf-8"))[:24]
            prepared = self._prepare_workspace_file(
                relative_path, content, temp_key=temp_key
            )
            claim_payload = {
                "run_id": run_id,
                "step_id": step_id,
                "branch": branch,
                "attempt": attempt,
                "action": "write_text",
                "relative_path": relative_path,
                "before_exists": False,
                "before_sha256": None,
                "after_sha256": action["content_sha256"],
                "bytes_written": len(content),
                "backup_file": None,
                **prepared,
                "content_in_event_ledger": False,
                "reversible": True,
            }
            claim = self.store.append_once(
                "autonomy.action.claimed", operation_key, claim_payload
            )
        expected = {
            "relative_path": relative_path,
            "after_sha256": action["content_sha256"],
            "bytes_written": len(content),
            "before_exists": False,
        }
        if any(claim.payload.get(key) != value for key, value in expected.items()):
            raise ValueError("durable action claim conflicts with requested create")
        published = False
        try:
            self._publish_claimed_file(claim.payload)
            published = True
            return self._receipt_from_claim(claim, reconciled=False)
        except Exception as action_error:
            if published or self._claim_target_matches(claim.payload):
                try:
                    token = _digest_bytes(operation_key.encode("utf-8"))[:24]
                    self._quarantine_claimed_target(claim.payload, token=token)
                except Exception as rollback_error:
                    raise OSError(
                        "action failed after publication and quarantine rollback was incomplete"
                    ) from rollback_error
            raise action_error

    def _rollback(
        self, run_id: str, receipts: Sequence[Mapping[str, Any]], *, reason: str
    ) -> dict[str, Any]:
        complete = True
        event_ids: list[str] = []
        for receipt in reversed(receipts):
            restored = False
            code = "quarantined"
            quarantine_file: str | None = None
            try:
                if receipt["before_exists"]:
                    raise OSError("legacy replacement receipt is outside Phase 10 authority")
                token = _digest_bytes(
                    f"{run_id}:{receipt['event_id']}".encode("utf-8")
                )[:24]
                quarantine_file = self._quarantine_claimed_target(
                    receipt, token=token
                )
                restored = True
                if quarantine_file is None:
                    code = "already_restored"
            except (ValueError, OSError) as exc:
                complete = False
                code = type(exc).__name__
            event = self.store.append(
                "autonomy.action.rolled_back",
                {
                    "run_id": run_id,
                    "receipt_event_id": receipt["event_id"],
                    "relative_path": receipt["relative_path"],
                    "reason": reason,
                    "restored": restored,
                    "code": code,
                    "quarantine_file": quarantine_file,
                },
            )
            event_ids.append(event.event_id)
        return {"complete": complete, "event_ids": event_ids}

    def _evaluate_checks(self, checks: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for check in checks:
            kind = str(check["kind"])
            try:
                observed_bytes = self._read_workspace_file(str(check["path"]))
                if kind == "path_exists":
                    passed = observed_bytes is not None
                    observed = "file" if passed else "absent_or_not_regular"
                elif kind == "path_absent":
                    passed = observed_bytes is None
                    observed = "absent" if passed else "present"
                elif kind == "sha256_equals":
                    observed = (
                        _digest_bytes(observed_bytes)
                        if observed_bytes is not None
                        else None
                    )
                    passed = observed == check["sha256"]
                else:  # validation prevents this branch.
                    raise ValueError(f"unsupported check: {kind}")
            except (ValueError, OSError):
                passed = False
                observed = "unsafe_or_unreadable_target"
            results.append(
                {
                    "kind": kind,
                    "path": check["path"],
                    "passed": passed,
                    "expected_sha256": check.get("sha256"),
                    "observed": observed,
                }
            )
        return {"passed": all(row["passed"] for row in results), "checks": results}

    @contextmanager
    def _workspace_parent_fd(self, relative: str) -> Iterator[tuple[int, str]]:
        """Open every parent component without following symlinks."""

        safe = _safe_relative_path(relative)
        parts = PurePosixPath(safe).parts
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.dup(self._workspace_root_fd)
        try:
            for component in parts[:-1]:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            yield descriptor, parts[-1]
        except OSError as exc:
            raise ValueError(
                "action parent must be an existing non-symlink directory"
            ) from exc
        finally:
            os.close(descriptor)

    def _read_workspace_file(self, relative: str) -> bytes | None:
        with self._workspace_parent_fd(relative) as (parent_fd, name):
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise ValueError(
                    "action target must be a regular non-symlink file"
                ) from exc
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                os.close(descriptor)
                raise ValueError("action target must be a single-link regular file")
            if metadata.st_size > _MAX_BACKUP_BYTES:
                os.close(descriptor)
                raise ValueError("action target exceeds bounded read/backup size")
            with os.fdopen(descriptor, "rb") as stream:
                content = stream.read(_MAX_BACKUP_BYTES + 1)
                if len(content) > _MAX_BACKUP_BYTES:
                    raise ValueError("action target exceeds bounded read/backup size")
                return content

    def _prepare_workspace_file(
        self, relative: str, content: bytes, *, temp_key: str
    ) -> dict[str, Any]:
        with self._workspace_parent_fd(relative) as (parent_fd, name):
            nonce = os.urandom(4).hex()
            temp_name = f".{name}.cct-{temp_key}-{nonce}.tmp"
            flags = (
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                    metadata = os.fstat(stream.fileno())
                os.fsync(parent_fd)
                return {
                    "prepared_name": temp_name,
                    "prepared_dev": int(metadata.st_dev),
                    "prepared_ino": int(metadata.st_ino),
                }
            except Exception:
                # A failed preparation never publishes to the requested path.
                raise

    @staticmethod
    def _same_identity(metadata: os.stat_result, claim: Mapping[str, Any]) -> bool:
        return (
            int(metadata.st_dev) == int(claim["prepared_dev"])
            and int(metadata.st_ino) == int(claim["prepared_ino"])
        )

    def _claim_target_matches(self, claim: Mapping[str, Any]) -> bool:
        relative = str(claim["relative_path"])
        try:
            with self._workspace_parent_fd(relative) as (parent_fd, name):
                descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=parent_fd,
                )
                with os.fdopen(descriptor, "rb", closefd=True) as stream:
                    metadata = os.fstat(stream.fileno())
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or not self._same_identity(metadata, claim)
                    ):
                        return False
                    content = stream.read(_MAX_BACKUP_BYTES + 1)
                    return (
                        len(content) <= _MAX_BACKUP_BYTES
                        and _digest_bytes(content) == claim["after_sha256"]
                    )
        except (FileNotFoundError, OSError, ValueError):
            return False

    def _publish_claimed_file(self, claim: Mapping[str, Any]) -> None:
        relative = str(claim["relative_path"])
        prepared_name = str(claim["prepared_name"])
        if "/" in prepared_name or not prepared_name.startswith("."):
            raise ValueError("claimed prepared file name is invalid")
        with self._workspace_parent_fd(relative) as (parent_fd, name):
            try:
                target_metadata = os.stat(
                    name, dir_fd=parent_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                target_metadata = None
            if target_metadata is not None:
                if self._same_identity(target_metadata, claim):
                    return
                raise FileExistsError("create-only target was concurrently occupied")
            prepared_metadata = os.stat(
                prepared_name, dir_fd=parent_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(prepared_metadata.st_mode)
                or prepared_metadata.st_nlink != 1
                or not self._same_identity(prepared_metadata, claim)
            ):
                raise OSError("prepared file identity does not match durable claim")
            _rename_noreplace(
                parent_fd, prepared_name, parent_fd, name
            )
            os.fsync(parent_fd)
        if not self._claim_target_matches(claim):
            raise OSError("published target does not match durable claim")

    def _quarantine_claimed_target(
        self, claim: Mapping[str, Any], *, token: str
    ) -> str | None:
        relative = str(claim["relative_path"])
        quarantine_name = f"{token}-{PurePosixPath(relative).name}"
        quarantine_relative = f"quarantine/{quarantine_name}"
        with self._workspace_parent_fd(relative) as (parent_fd, name):
            with self._private_parent_fd(
                quarantine_relative, create_parents=True
            ) as (quarantine_fd, destination):
                def captured_matches_claim() -> bool:
                    try:
                        captured = os.stat(
                            destination, dir_fd=quarantine_fd, follow_symlinks=False
                        )
                    except FileNotFoundError:
                        return False
                    if not self._same_identity(captured, claim):
                        return False
                    descriptor = os.open(
                        destination,
                        os.O_RDONLY
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=quarantine_fd,
                    )
                    with os.fdopen(descriptor, "rb", closefd=True) as stream:
                        content = stream.read(_MAX_BACKUP_BYTES + 1)
                    return (
                        len(content) <= _MAX_BACKUP_BYTES
                        and _digest_bytes(content) == claim["after_sha256"]
                    )

                try:
                    os.stat(destination, dir_fd=quarantine_fd, follow_symlinks=False)
                except FileNotFoundError:
                    quarantine_exists = False
                else:
                    quarantine_exists = True
                if quarantine_exists:
                    if captured_matches_claim():
                        return quarantine_relative
                    try:
                        _rename_noreplace(
                            quarantine_fd, destination, parent_fd, name
                        )
                        os.fsync(parent_fd)
                        os.fsync(quarantine_fd)
                    except OSError as restore_error:
                        raise OSError(
                            f"foreign capture preserved at {quarantine_relative}; "
                            "original path is occupied"
                        ) from restore_error
                    raise OSError("foreign quarantine capture restored to original path")

                try:
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return None
                _rename_noreplace(parent_fd, name, quarantine_fd, destination)
                os.fsync(parent_fd)
                os.fsync(quarantine_fd)
                if captured_matches_claim():
                    return quarantine_relative
                try:
                    _rename_noreplace(
                        quarantine_fd, destination, parent_fd, name
                    )
                    os.fsync(parent_fd)
                    os.fsync(quarantine_fd)
                except OSError as restore_error:
                    raise OSError(
                        f"conflicting target preserved at {quarantine_relative}; "
                        "original path was concurrently reoccupied"
                    ) from restore_error
                raise OSError("captured target was not created by this claim; restored")

    @contextmanager
    def _private_parent_fd(
        self, relative: str, *, create_parents: bool = False
    ) -> Iterator[tuple[int, str]]:
        candidate = PurePosixPath(relative)
        if (
            candidate.is_absolute()
            or len(candidate.parts) < 1
            or any(part in {"", ".", ".."} for part in candidate.parts)
        ):
            raise ValueError("private state reference must be relative")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.dup(self._state_root_fd)
        try:
            for component in candidate.parts[:-1]:
                try:
                    next_descriptor = os.open(component, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create_parents:
                        raise
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    next_descriptor = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            yield descriptor, candidate.parts[-1]
        finally:
            os.close(descriptor)

    def _write_private(
        self, path: Path, content: bytes, *, no_replace: bool = False
    ) -> None:
        try:
            relative = path.absolute().relative_to(self.state_root).as_posix()
        except ValueError as exc:
            raise ValueError("private state write escapes state root") from exc
        with self._private_parent_fd(relative, create_parents=True) as (parent_fd, name):
            try:
                metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                metadata = None
            if metadata is not None and (
                not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            ):
                raise ValueError("private state target must be a single-link regular file")
            temp = f".{name}.cct-{os.getpid()}-{os.urandom(4).hex()}.tmp"
            descriptor = os.open(
                temp,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
            try:
                with os.fdopen(descriptor, "wb", closefd=True) as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                if no_replace:
                    _rename_noreplace(parent_fd, temp, parent_fd, name)
                else:
                    os.replace(
                        temp,
                        name,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                os.fsync(parent_fd)
            finally:
                try:
                    os.unlink(temp, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass

    def _read_private(self, relative: str) -> bytes:
        with self._private_parent_fd(relative) as (parent_fd, name):
            descriptor = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
            with os.fdopen(descriptor, "rb", closefd=True) as stream:
                metadata = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_size > _MAX_BACKUP_BYTES
                ):
                    raise ValueError("private state file exceeds bounded regular-file policy")
                content = stream.read(_MAX_BACKUP_BYTES + 1)
                if len(content) > _MAX_BACKUP_BYTES:
                    raise ValueError("private state file exceeds bounded regular-file policy")
                return content

    def _run_event(self, run_id: str, kind: str) -> Event | None:
        return next(
            (
                event for event in reversed(self.store.events(kind))
                if event.payload.get("run_id") == run_id
            ),
            None,
        )

    def status(self) -> dict[str, Any]:
        opportunities = self.opportunities()
        projected_opportunities = []
        for row in opportunities:
            model_controlled = row["source_authority"] not in _EXECUTABLE_AUTHORITIES
            projected_opportunities.append({
                "opportunity_id": None if model_controlled else row["opportunity_id"],
                "opportunity_id_sha256": _digest_bytes(
                    str(row["opportunity_id"]).encode("utf-8")
                ),
                "status": row.get("status"),
                "source_authority": row["source_authority"],
                "executable": bool(row["executable"]),
                "capability": None if model_controlled else row["capability"],
                "capability_sha256": _digest_bytes(
                    str(row["capability"]).encode("utf-8")
                ),
                "value_impacts": dict(row["value_impacts"]),
                "information_gain": row["information_gain"],
                "uncertainty": row["uncertainty"],
                "time_cost": row["time_cost"],
                "plan_sha256": row["plan_sha256"],
                "plan_file": None if model_controlled else row["plan_file"],
                "title_sha256": _digest_bytes(str(row["title"]).encode("utf-8")),
                "rationale_sha256": _digest_bytes(str(row["rationale"]).encode("utf-8")),
                "objective_sha256": _digest_bytes(str(row["objective"]).encode("utf-8")),
                "source_sha256": _digest_bytes(str(row["source"]).encode("utf-8")),
                "evidence_count": len(row.get("evidence", [])),
                "registered_at": row["registered_at"],
                "event_id": row["event_id"],
                "last_run_id": row.get("last_run_id"),
                "content_in_status": False,
            })
        runs = self.store.events("autonomy.run.completed")
        latest = runs[-1] if runs else None
        capability_names = sorted(
            {
                str(row["capability"])
                for row in opportunities
                if row["source_authority"] in _EXECUTABLE_AUTHORITIES
            }
        )
        return {
            "authority": self.authority().as_payload(),
            "workspace_root_sha256": _digest_bytes(str(self.workspace_root).encode("utf-8")),
            "state_root_sha256": _digest_bytes(str(self.state_root).encode("utf-8")),
            "opportunities": {
                "total": len(opportunities),
                "open": sum(row.get("status") == "open" for row in opportunities),
                "executable_open": sum(
                    1
                    for row in opportunities
                    if row.get("status") == "open" and bool(row.get("executable"))
                ),
                "rows": projected_opportunities,
            },
            "capability_learning": {
                name: self._capability_learning(name) for name in capability_names
            },
            "runs": {
                "total": len(runs),
                "verified_successes": sum(
                    bool(event.payload.get("success") and event.payload.get("verified"))
                    for event in runs
                ),
                "effectful_verified_successes": sum(
                    bool(
                        event.payload.get("success")
                        and event.payload.get("verified")
                        and int(event.payload.get("receipt_count", 0)) > 0
                    )
                    for event in runs
                ),
                "failures": sum(not bool(event.payload.get("success")) for event in runs),
                "latest": ({**dict(latest.payload), "event_id": latest.event_id} if latest else None),
            },
            "allowed_effects": ["atomic write_text under workspace_root"],
            "forbidden_effects": [
                "commands", "deletes", "network", "public actions", "financial actions",
                "credential access", "legal actions", "irreversible actions",
            ],
            "chain": self.store.verify_chain(),
        }
