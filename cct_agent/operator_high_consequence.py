"""Ticketed high-consequence goal effects with exact host authority and readback."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping, Protocol, Sequence

from .execution_tickets import GlobalKillSwitch, TicketAuthorityDenied
from .mediation_outcomes import OutcomeVerification, OutcomeVerifierRegistry, VerificationContext
from .store import Event, EventStore, canonical_json


OPERATOR_HIGH_CONSEQUENCE_CLAIM_SCHEMA_VERSION = (
    "cct.operator_high_consequence.claim.v1"
)
OPERATOR_HIGH_CONSEQUENCE_RECEIPT_SCHEMA_VERSION = (
    "cct.operator_high_consequence.receipt.v1"
)
OPERATOR_HIGH_CONSEQUENCE_VERIFIER_ID = "operator-high_consequence-readback"
MAX_OPERATOR_HIGH_CONSEQUENCE_TARGETS = 64
MAX_OPERATOR_GOAL_EFFECT_AUTHORITIES = 256
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class HighConsequenceEffectDenied(PermissionError):
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


def _hash(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _timestamp(name: str, value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{name} must be ISO-8601") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed


def _private_root(raw: str | Path) -> tuple[Path, tuple[int, int]]:
    root = Path(raw)
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("state_root must be an absolute real directory")
    try:
        resolved = root.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise ValueError("state_root must be an existing real directory") from error
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError("state_root must be an owned real directory")
    os.chmod(resolved, 0o700)
    return resolved, (metadata.st_dev, metadata.st_ino)


@dataclass(frozen=True, slots=True)
class OperatorHighConsequenceTarget:
    id: str
    driver_id: str
    provider: str
    owner_principal_id: str
    consequence_class: str
    allowed_effects: tuple[str, ...]
    reversible: bool
    real_effect: bool

    def __post_init__(self) -> None:
        for field in (
            "id",
            "driver_id",
            "provider",
            "owner_principal_id",
            "consequence_class",
        ):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.allowed_effects, (tuple, list)):
            raise ValueError("allowed_effects must be an array")
        effects = tuple(
            sorted({_identifier("allowed_effect", item) for item in self.allowed_effects})
        )
        if not 1 <= len(effects) <= 64:
            raise ValueError("allowed_effects must contain 1-64 values")
        object.__setattr__(self, "allowed_effects", effects)
        if not isinstance(self.reversible, bool) or not isinstance(self.real_effect, bool):
            raise ValueError("target effect booleans are invalid")


@dataclass(frozen=True, slots=True)
class AuthenticatedGoalEffectAuthority:
    """Host-supplied exact principal decision; never derived from producer prose."""

    id: str
    ticket_id: str
    authority: str
    authenticated: bool
    principal_id: str
    goal_id: str
    target_id: str
    consequence_class: str
    effect_name: str
    effect_arguments_sha256: str
    dependency_proof_sha256: str
    principal_decision_receipt_sha256: str
    irreversible_acknowledged: bool
    expires_at: str

    def __post_init__(self) -> None:
        for field in (
            "id",
            "ticket_id",
            "principal_id",
            "goal_id",
            "target_id",
            "consequence_class",
            "effect_name",
        ):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if self.authority not in {"operator", "host_adapter"}:
            raise ValueError("goal-effect authority must be operator or host_adapter")
        if not isinstance(self.authenticated, bool) or not isinstance(
            self.irreversible_acknowledged, bool
        ):
            raise ValueError("goal-effect authority booleans are invalid")
        for field in (
            "effect_arguments_sha256",
            "dependency_proof_sha256",
            "principal_decision_receipt_sha256",
        ):
            object.__setattr__(self, field, _digest(field, getattr(self, field)))
        _timestamp("expires_at", self.expires_at)


@dataclass(frozen=True, slots=True)
class ProviderHighConsequenceAuthority:
    target_id: str
    provider: str
    owner_principal_id: str
    authenticated: bool
    real_effect: bool
    authority_receipt_sha256: str

    def __post_init__(self) -> None:
        for field in ("target_id", "provider", "owner_principal_id"):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.authenticated, bool) or not isinstance(
            self.real_effect, bool
        ):
            raise ValueError("provider authority booleans are invalid")
        object.__setattr__(
            self,
            "authority_receipt_sha256",
            _digest("authority_receipt_sha256", self.authority_receipt_sha256),
        )


@dataclass(frozen=True, slots=True)
class ProviderHighConsequenceState:
    target_id: str
    provider: str
    owner_principal_id: str
    operation_applied: bool
    operation_id: str | None
    consequence_class: str | None
    effect_name: str | None
    effect_arguments_sha256: str
    total_effect_count: int
    revision: int
    target_state_sha256: str
    provider_receipt_sha256: str
    last_operation_id: str | None
    real_effect: bool

    def __post_init__(self) -> None:
        for field in ("target_id", "provider", "owner_principal_id"):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.operation_applied, bool) or not isinstance(
            self.real_effect, bool
        ):
            raise ValueError("provider state booleans are invalid")
        for field in (
            "operation_id",
            "consequence_class",
            "effect_name",
            "last_operation_id",
        ):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _identifier(field, value))
        if isinstance(self.total_effect_count, bool) or not isinstance(
            self.total_effect_count, int
        ):
            raise ValueError("total_effect_count must be an integer")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int):
            raise ValueError("revision must be an integer")
        if self.total_effect_count < 0 or self.revision < 0:
            raise ValueError("provider state counters cannot be negative")
        for field in (
            "effect_arguments_sha256",
            "target_state_sha256",
            "provider_receipt_sha256",
        ):
            object.__setattr__(self, field, _digest(field, getattr(self, field)))
        selected = (
            self.operation_id is not None
            and self.consequence_class is not None
            and self.effect_name is not None
        )
        if self.operation_applied != selected:
            raise ValueError("provider operation state is inconsistent")
        if not self.operation_applied and self.effect_arguments_sha256 != "0" * 64:
            raise ValueError("absent operation cannot report effect arguments")


@dataclass(frozen=True, slots=True)
class HighConsequenceProviderCommand:
    operation_id: str
    target_id: str
    provider: str
    owner_principal_id: str
    consequence_class: str
    effect_name: str
    effect_arguments_sha256: str
    dependency_proof_sha256: str
    principal_decision_receipt_sha256: str
    expected_before_state_sha256: str
    preview_sha256: str


class OperatorHighConsequenceDriver(Protocol):
    def authority(
        self,
        target: OperatorHighConsequenceTarget,
    ) -> ProviderHighConsequenceAuthority: ...

    def inspect(
        self,
        target: OperatorHighConsequenceTarget,
        operation_id: str | None = None,
    ) -> ProviderHighConsequenceState: ...

    def execute(
        self,
        target: OperatorHighConsequenceTarget,
        command: HighConsequenceProviderCommand,
    ) -> None: ...

    def rollback(
        self,
        target: OperatorHighConsequenceTarget,
        operation_id: str,
    ) -> None: ...


class LocalFakeHighConsequenceDriver:
    """Private hash-only fake provider; never performs a real-world effect."""

    def __init__(self, *, state_root: str | Path, provider: str) -> None:
        self.state_root, self._state_identity = _private_root(state_root)
        self.provider = _identifier("provider", provider)
        self.mutation_count = 0

    def _validate_root(self) -> None:
        metadata = self.state_root.stat()
        if (
            self.state_root.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or (metadata.st_dev, metadata.st_ino) != self._state_identity
        ):
            raise HighConsequenceEffectDenied("HIGH_CONSEQUENCE_PROVIDER_ROOT_CHANGED")

    def _path(self, target_id: str) -> Path:
        return self.state_root / f"{sha256(target_id.encode()).hexdigest()}.json"

    def _read(self, target_id: str) -> dict[str, Any] | None:
        self._validate_root()
        path = self._path(target_id)
        descriptor: int | None = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                raise HighConsequenceEffectDenied(
                    "HIGH_CONSEQUENCE_PROVIDER_STATE_UNSAFE"
                )
            raw = bytearray()
            while chunk := os.read(descriptor, 65_536):
                raw.extend(chunk)
                if len(raw) > 1_048_576:
                    raise HighConsequenceEffectDenied(
                        "HIGH_CONSEQUENCE_PROVIDER_STATE_INVALID"
                    )
            value = json.loads(raw)
        except FileNotFoundError:
            return None
        except HighConsequenceEffectDenied:
            raise
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_PROVIDER_STATE_INVALID"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not isinstance(value, dict) or value.get("target_id") != target_id:
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_PROVIDER_STATE_INVALID"
            )
        operations = value.get("operations")
        if not isinstance(operations, dict) or len(operations) > 10_000:
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_PROVIDER_STATE_INVALID"
            )
        return value

    def _write(self, target_id: str, payload: Mapping[str, Any]) -> None:
        self._validate_root()
        path = self._path(target_id)
        temporary = self.state_root / f".{path.name}.{os.getpid()}.tmp"
        data = canonical_json(payload).encode("utf-8")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            os.write(descriptor, data)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        except OSError as error:
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_PROVIDER_STATE_WRITE_FAILED"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary.exists():
                temporary.unlink()

    def _binding(self, target: OperatorHighConsequenceTarget) -> None:
        if target.provider != self.provider or target.real_effect:
            raise HighConsequenceEffectDenied(
                "FAKE_HIGH_CONSEQUENCE_PROVIDER_BINDING_MISMATCH"
            )

    def authority(
        self,
        target: OperatorHighConsequenceTarget,
    ) -> ProviderHighConsequenceAuthority:
        self._binding(target)
        material = {
            "target_id": target.id,
            "provider": target.provider,
            "owner_principal_id": target.owner_principal_id,
            "authenticated": False,
            "real_effect": False,
            "producer_prose_consumed": False,
        }
        return ProviderHighConsequenceAuthority(
            target_id=target.id,
            provider=target.provider,
            owner_principal_id=target.owner_principal_id,
            authenticated=False,
            real_effect=False,
            authority_receipt_sha256=_hash(material),
        )

    def inspect(
        self,
        target: OperatorHighConsequenceTarget,
        operation_id: str | None = None,
    ) -> ProviderHighConsequenceState:
        self._binding(target)
        if operation_id is not None:
            operation_id = _identifier("operation_id", operation_id)
        metadata = self._read(target.id)
        operations = dict(metadata["operations"]) if metadata else {}
        revision = int(metadata["revision"]) if metadata else 0
        last_operation_id = metadata.get("last_operation_id") if metadata else None
        selected = operations.get(operation_id) if operation_id is not None else None
        state_material = {
            "target_id": target.id,
            "provider": target.provider,
            "owner_principal_id": target.owner_principal_id,
            "operations": operations,
            "revision": revision,
            "last_operation_id": last_operation_id,
            "real_effect": False,
        }
        state_sha256 = _hash(state_material)
        receipt_material = {
            **state_material,
            "selected_operation_id": operation_id,
            "selected": selected,
        }
        return ProviderHighConsequenceState(
            target_id=target.id,
            provider=target.provider,
            owner_principal_id=target.owner_principal_id,
            operation_applied=selected is not None,
            operation_id=operation_id if selected else None,
            consequence_class=(
                str(selected["consequence_class"]) if selected else None
            ),
            effect_name=str(selected["effect_name"]) if selected else None,
            effect_arguments_sha256=(
                str(selected["effect_arguments_sha256"]) if selected else "0" * 64
            ),
            total_effect_count=len(operations),
            revision=revision,
            target_state_sha256=state_sha256,
            provider_receipt_sha256=_hash(receipt_material),
            last_operation_id=(
                str(last_operation_id) if isinstance(last_operation_id, str) else None
            ),
            real_effect=False,
        )

    def execute(
        self,
        target: OperatorHighConsequenceTarget,
        command: HighConsequenceProviderCommand,
    ) -> None:
        self._binding(target)
        for field in (
            "operation_id",
            "target_id",
            "provider",
            "owner_principal_id",
            "consequence_class",
            "effect_name",
        ):
            _identifier(field, getattr(command, field))
        for field in (
            "effect_arguments_sha256",
            "dependency_proof_sha256",
            "principal_decision_receipt_sha256",
            "expected_before_state_sha256",
            "preview_sha256",
        ):
            _digest(field, getattr(command, field))
        if (
            command.target_id != target.id
            or command.provider != target.provider
            or command.owner_principal_id != target.owner_principal_id
            or command.consequence_class != target.consequence_class
            or command.effect_name not in target.allowed_effects
        ):
            raise HighConsequenceEffectDenied(
                "FAKE_HIGH_CONSEQUENCE_PROVIDER_COMMAND_MISMATCH"
            )
        existing = self.inspect(target, command.operation_id)
        if existing.operation_applied:
            if (
                existing.consequence_class != command.consequence_class
                or existing.effect_name != command.effect_name
                or existing.effect_arguments_sha256
                != command.effect_arguments_sha256
            ):
                raise HighConsequenceEffectDenied(
                    "HIGH_CONSEQUENCE_PROVIDER_OPERATION_COLLISION"
                )
            return
        before = self.inspect(target)
        if before.target_state_sha256 != command.expected_before_state_sha256:
            raise HighConsequenceEffectDenied("HIGH_CONSEQUENCE_PROVIDER_PRESTATE_CHANGED")
        metadata = self._read(target.id)
        operations = dict(metadata["operations"]) if metadata else {}
        revision = int(metadata["revision"]) if metadata else 0
        operations[command.operation_id] = {
            "consequence_class": command.consequence_class,
            "effect_name": command.effect_name,
            "effect_arguments_sha256": command.effect_arguments_sha256,
            "dependency_proof_sha256": command.dependency_proof_sha256,
            "principal_decision_receipt_sha256": (
                command.principal_decision_receipt_sha256
            ),
            "preview_sha256": command.preview_sha256,
        }
        self._write(
            target.id,
            {
                "schema_version": 1,
                "target_id": target.id,
                "provider": target.provider,
                "owner_principal_id": target.owner_principal_id,
                "operations": operations,
                "revision": revision + 1,
                "last_operation_id": command.operation_id,
                "real_effect": False,
                "producer_prose_persisted": False,
            },
        )
        self.mutation_count += 1

    def rollback(
        self,
        target: OperatorHighConsequenceTarget,
        operation_id: str,
    ) -> None:
        self._binding(target)
        operation_id = _identifier("operation_id", operation_id)
        if not target.reversible:
            raise HighConsequenceEffectDenied("HIGH_CONSEQUENCE_ROLLBACK_UNAVAILABLE")
        metadata = self._read(target.id)
        operations = dict(metadata["operations"]) if metadata else {}
        if operation_id not in operations:
            return
        del operations[operation_id]
        revision = int(metadata["revision"]) if metadata else 0
        self._write(
            target.id,
            {
                "schema_version": 1,
                "target_id": target.id,
                "provider": target.provider,
                "owner_principal_id": target.owner_principal_id,
                "operations": operations,
                "revision": revision + 1,
                "last_operation_id": operation_id,
                "real_effect": False,
                "producer_prose_persisted": False,
            },
        )
        self.mutation_count += 1


@dataclass(frozen=True, slots=True)
class OperatorHighConsequencePreview:
    goal_effect_authority_id: str
    ticket_id: str
    target_id: str
    target_spec_sha256: str
    provider: str
    provider_authenticated: bool
    provider_authority_receipt_sha256: str
    principal_id: str
    goal_id: str
    consequence_class: str
    effect_name: str
    effect_arguments_sha256: str
    dependency_proof_sha256: str
    principal_decision_receipt_sha256: str
    irreversible_acknowledged: bool
    before_state_sha256: str
    preview_sha256: str


@dataclass(frozen=True, slots=True)
class OperatorHighConsequenceInvocation:
    ticket_id: str
    goal_effect_authority_id: str
    target_id: str
    goal_id: str
    consequence_class: str
    effect_name: str
    effect_arguments_sha256: str
    dependency_proof_sha256: str
    principal_decision_receipt_sha256: str
    irreversible_acknowledged: bool
    expected_target_spec_sha256: str
    expected_provider_authority_receipt_sha256: str
    expected_before_state_sha256: str
    expected_preview_sha256: str
    verifier_id: str

    @classmethod
    def from_arguments(
        cls,
        arguments: Mapping[str, Any],
    ) -> "OperatorHighConsequenceInvocation":
        if not isinstance(arguments, Mapping):
            raise ValueError("high-consequence arguments must be an object")
        fields = {
            "execution_ticket_id",
            "goal_effect_authority_id",
            "high_consequence_target_id",
            "goal_id",
            "consequence_class",
            "effect_name",
            "effect_arguments_sha256",
            "dependency_proof_sha256",
            "principal_decision_receipt_sha256",
            "irreversible_acknowledged",
            "expected_target_spec_sha256",
            "expected_provider_authority_receipt_sha256",
            "expected_before_state_sha256",
            "expected_preview_sha256",
            "verifier_id",
        }
        if set(arguments) != fields:
            raise ValueError("high-consequence arguments require exact fields")
        irreversible_acknowledged = arguments["irreversible_acknowledged"]
        if not isinstance(irreversible_acknowledged, bool):
            raise ValueError("irreversible_acknowledged must be a boolean")
        return cls(
            ticket_id=_identifier(
                "execution_ticket_id", arguments["execution_ticket_id"]
            ),
            goal_effect_authority_id=_identifier(
                "goal_effect_authority_id", arguments["goal_effect_authority_id"]
            ),
            target_id=_identifier(
                "high_consequence_target_id",
                arguments["high_consequence_target_id"],
            ),
            goal_id=_identifier("goal_id", arguments["goal_id"]),
            consequence_class=_identifier(
                "consequence_class", arguments["consequence_class"]
            ),
            effect_name=_identifier("effect_name", arguments["effect_name"]),
            effect_arguments_sha256=_digest(
                "effect_arguments_sha256", arguments["effect_arguments_sha256"]
            ),
            dependency_proof_sha256=_digest(
                "dependency_proof_sha256", arguments["dependency_proof_sha256"]
            ),
            principal_decision_receipt_sha256=_digest(
                "principal_decision_receipt_sha256",
                arguments["principal_decision_receipt_sha256"],
            ),
            irreversible_acknowledged=irreversible_acknowledged,
            expected_target_spec_sha256=_digest(
                "expected_target_spec_sha256",
                arguments["expected_target_spec_sha256"],
            ),
            expected_provider_authority_receipt_sha256=_digest(
                "expected_provider_authority_receipt_sha256",
                arguments["expected_provider_authority_receipt_sha256"],
            ),
            expected_before_state_sha256=_digest(
                "expected_before_state_sha256",
                arguments["expected_before_state_sha256"],
            ),
            expected_preview_sha256=_digest(
                "expected_preview_sha256", arguments["expected_preview_sha256"]
            ),
            verifier_id=_identifier("verifier_id", arguments["verifier_id"]),
        )


@dataclass(frozen=True, slots=True)
class _RegisteredHighConsequenceTarget:
    spec: OperatorHighConsequenceTarget
    spec_sha256: str
    driver: OperatorHighConsequenceDriver
    provider_authority: ProviderHighConsequenceAuthority


class OperatorHighConsequenceAdapter:
    def __init__(
        self,
        store: EventStore,
        *,
        targets: Sequence[OperatorHighConsequenceTarget],
        goal_effect_authorities: Sequence[AuthenticatedGoalEffectAuthority],
        drivers: Mapping[str, OperatorHighConsequenceDriver],
    ) -> None:
        if not isinstance(store, EventStore) or not isinstance(drivers, Mapping):
            raise ValueError("high-consequence adapter configuration is invalid")
        principal_rows = store.events("principal.profile.installed")
        if not principal_rows:
            raise ValueError("high-consequence targets require an installed principal")
        principal_id = principal_rows[-1].payload.get("profile", {}).get("principal_id")
        registrations: dict[str, _RegisteredHighConsequenceTarget] = {}
        for target in targets:
            if (
                not isinstance(target, OperatorHighConsequenceTarget)
                or target.id in registrations
            ):
                raise ValueError(
                    "targets must contain unique OperatorHighConsequenceTarget values"
                )
            if target.owner_principal_id != principal_id:
                raise ValueError("high-consequence target owner must match principal")
            driver = drivers.get(target.driver_id)
            required = ["authority", "inspect", "execute"]
            if target.reversible:
                required.append("rollback")
            if driver is None or not all(
                callable(getattr(driver, name, None)) for name in required
            ):
                raise ValueError("high-consequence driver must be host-registered")
            provider_authority = driver.authority(target)
            if not isinstance(
                provider_authority, ProviderHighConsequenceAuthority
            ):
                raise ValueError("high-consequence provider authority is malformed")
            if (
                provider_authority.target_id != target.id
                or provider_authority.provider != target.provider
                or provider_authority.owner_principal_id
                != target.owner_principal_id
                or provider_authority.real_effect != target.real_effect
            ):
                raise ValueError("high-consequence provider authority binding mismatch")
            if target.real_effect and not provider_authority.authenticated:
                raise ValueError(
                    "real high-consequence target requires authenticated provider authority"
                )
            registrations[target.id] = _RegisteredHighConsequenceTarget(
                spec=target,
                spec_sha256=_hash(asdict(target)),
                driver=driver,
                provider_authority=provider_authority,
            )
        if not 1 <= len(registrations) <= MAX_OPERATOR_HIGH_CONSEQUENCE_TARGETS:
            raise ValueError("high-consequence target registration count is invalid")

        authority_rows: dict[str, AuthenticatedGoalEffectAuthority] = {}
        for authority in goal_effect_authorities:
            if (
                not isinstance(authority, AuthenticatedGoalEffectAuthority)
                or authority.id in authority_rows
            ):
                raise ValueError("goal-effect authorities must be unique typed values")
            if not authority.authenticated:
                raise ValueError("authenticated goal-effect authority is required")
            if authority.principal_id != principal_id:
                raise ValueError("goal-effect authority principal mismatch")
            registration = registrations.get(authority.target_id)
            if registration is None:
                raise ValueError("goal-effect authority target is not registered")
            spec = registration.spec
            if (
                authority.consequence_class != spec.consequence_class
                or authority.effect_name not in spec.allowed_effects
            ):
                raise ValueError("goal-effect authority target binding mismatch")
            if not spec.reversible and not authority.irreversible_acknowledged:
                raise ValueError("irreversible effect requires acknowledgement")
            authority_rows[authority.id] = authority
        if not 1 <= len(authority_rows) <= MAX_OPERATOR_GOAL_EFFECT_AUTHORITIES:
            raise ValueError("goal-effect authority registration count is invalid")

        self.store = store
        self._targets: Mapping[str, _RegisteredHighConsequenceTarget] = (
            MappingProxyType(registrations)
        )
        self._goal_effect_authorities: Mapping[
            str, AuthenticatedGoalEffectAuthority
        ] = MappingProxyType(authority_rows)
        os.chmod(self.store.path, 0o600)
        self._record_registrations()

    def _record_registrations(self) -> None:
        for registration in self._targets.values():
            spec = registration.spec
            payload = {
                "schema_version": 1,
                "authority": "host_adapter",
                "target_id": spec.id,
                "driver_id": spec.driver_id,
                "provider": spec.provider,
                "owner_principal_id": spec.owner_principal_id,
                "consequence_class": spec.consequence_class,
                "allowed_effects": list(spec.allowed_effects),
                "reversible": spec.reversible,
                "real_effect": spec.real_effect,
                "target_spec_sha256": registration.spec_sha256,
                "provider_authenticated": (
                    registration.provider_authority.authenticated
                ),
                "provider_authority_receipt_sha256": (
                    registration.provider_authority.authority_receipt_sha256
                ),
                "producer_prose_persisted": False,
            }
            event, _created = self.store.append_once_result(
                "operator.high_consequence_target.registered", spec.id, payload
            )
            if canonical_json(event.payload) != canonical_json(payload):
                raise ValueError(f"high-consequence target changed: {spec.id}")
        for authority in self._goal_effect_authorities.values():
            payload = {
                "schema_version": 1,
                "authority_id": authority.id,
                "ticket_id": authority.ticket_id,
                "authority": authority.authority,
                "authenticated": authority.authenticated,
                "principal_id": authority.principal_id,
                "goal_id": authority.goal_id,
                "target_id": authority.target_id,
                "consequence_class": authority.consequence_class,
                "effect_name": authority.effect_name,
                "effect_arguments_sha256": authority.effect_arguments_sha256,
                "dependency_proof_sha256": authority.dependency_proof_sha256,
                "principal_decision_receipt_sha256": (
                    authority.principal_decision_receipt_sha256
                ),
                "irreversible_acknowledged": (
                    authority.irreversible_acknowledged
                ),
                "expires_at": authority.expires_at,
                "producer_prose_persisted": False,
                "model_authority_inference_allowed": False,
            }
            event, _created = self.store.append_once_result(
                "operator.high_consequence_goal_effect.authorized",
                authority.id,
                payload,
            )
            if canonical_json(event.payload) != canonical_json(payload):
                raise ValueError(f"goal-effect authority changed: {authority.id}")

    def outcome_verifiers(self) -> OutcomeVerifierRegistry:
        registry = OutcomeVerifierRegistry()
        registry.register(
            OPERATOR_HIGH_CONSEQUENCE_VERIFIER_ID,
            self._verify_mediated_result,
            reconcile=self._reconcile_mediated_result,
            idempotency_proof_id="operator-high-consequence-ticket-receipt",
        )
        return registry

    def _registration(
        self,
        target_id: str,
    ) -> _RegisteredHighConsequenceTarget:
        registration = self._targets.get(_identifier("target_id", target_id))
        if registration is None:
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_TARGET_NOT_REGISTERED"
            )
        return registration

    def _goal_effect_authority(
        self,
        authority_id: str,
    ) -> AuthenticatedGoalEffectAuthority:
        authority = self._goal_effect_authorities.get(
            _identifier("goal_effect_authority_id", authority_id)
        )
        if authority is None:
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_GOAL_EFFECT_NOT_AUTHORIZED"
            )
        if _timestamp("authority expires_at", authority.expires_at) <= _timestamp(
            "current time", self.store.clock()
        ):
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_GOAL_EFFECT_AUTHORITY_EXPIRED"
            )
        return authority

    @staticmethod
    def _inspect(
        registration: _RegisteredHighConsequenceTarget,
        operation_id: str | None = None,
    ) -> ProviderHighConsequenceState:
        state = registration.driver.inspect(registration.spec, operation_id)
        if not isinstance(state, ProviderHighConsequenceState):
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_PROVIDER_READBACK_MALFORMED"
            )
        spec = registration.spec
        if (
            state.target_id != spec.id
            or state.provider != spec.provider
            or state.owner_principal_id != spec.owner_principal_id
            or state.real_effect != spec.real_effect
        ):
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_PROVIDER_READBACK_BINDING_MISMATCH"
            )
        return state

    def _ensure_clear(self) -> None:
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise HighConsequenceEffectDenied(error.reason_code) from error

    def preview(
        self,
        *,
        goal_effect_authority_id: str,
    ) -> OperatorHighConsequencePreview:
        self._ensure_clear()
        if self.store.verify_chain().get("valid") is not True:
            raise HighConsequenceEffectDenied("LEDGER_CHAIN_INVALID")
        authority = self._goal_effect_authority(goal_effect_authority_id)
        registration = self._registration(authority.target_id)
        before = self._inspect(registration)
        material = {
            "schema_version": 1,
            "goal_effect_authority_id": authority.id,
            "ticket_id": authority.ticket_id,
            "target_id": registration.spec.id,
            "target_spec_sha256": registration.spec_sha256,
            "provider": registration.spec.provider,
            "provider_authenticated": (
                registration.provider_authority.authenticated
            ),
            "provider_authority_receipt_sha256": (
                registration.provider_authority.authority_receipt_sha256
            ),
            "principal_id": authority.principal_id,
            "goal_id": authority.goal_id,
            "consequence_class": authority.consequence_class,
            "effect_name": authority.effect_name,
            "effect_arguments_sha256": authority.effect_arguments_sha256,
            "dependency_proof_sha256": authority.dependency_proof_sha256,
            "principal_decision_receipt_sha256": (
                authority.principal_decision_receipt_sha256
            ),
            "irreversible_acknowledged": authority.irreversible_acknowledged,
            "before_state_sha256": before.target_state_sha256,
            "real_effect": registration.spec.real_effect,
            "producer_prose_persisted": False,
        }
        return OperatorHighConsequencePreview(
            goal_effect_authority_id=authority.id,
            ticket_id=authority.ticket_id,
            target_id=registration.spec.id,
            target_spec_sha256=registration.spec_sha256,
            provider=registration.spec.provider,
            provider_authenticated=registration.provider_authority.authenticated,
            provider_authority_receipt_sha256=(
                registration.provider_authority.authority_receipt_sha256
            ),
            principal_id=authority.principal_id,
            goal_id=authority.goal_id,
            consequence_class=authority.consequence_class,
            effect_name=authority.effect_name,
            effect_arguments_sha256=authority.effect_arguments_sha256,
            dependency_proof_sha256=authority.dependency_proof_sha256,
            principal_decision_receipt_sha256=(
                authority.principal_decision_receipt_sha256
            ),
            irreversible_acknowledged=authority.irreversible_acknowledged,
            before_state_sha256=before.target_state_sha256,
            preview_sha256=_hash(material),
        )

    @staticmethod
    def _validate_preview(
        request: OperatorHighConsequenceInvocation,
        preview: OperatorHighConsequencePreview,
    ) -> None:
        matched = (
            request.goal_effect_authority_id
            == preview.goal_effect_authority_id
            and request.ticket_id == preview.ticket_id
            and request.target_id == preview.target_id
            and request.goal_id == preview.goal_id
            and request.consequence_class == preview.consequence_class
            and request.effect_name == preview.effect_name
            and request.effect_arguments_sha256
            == preview.effect_arguments_sha256
            and request.dependency_proof_sha256
            == preview.dependency_proof_sha256
            and request.principal_decision_receipt_sha256
            == preview.principal_decision_receipt_sha256
            and request.irreversible_acknowledged
            == preview.irreversible_acknowledged
            and request.expected_target_spec_sha256
            == preview.target_spec_sha256
            and request.expected_provider_authority_receipt_sha256
            == preview.provider_authority_receipt_sha256
            and request.expected_before_state_sha256
            == preview.before_state_sha256
            and request.expected_preview_sha256 == preview.preview_sha256
        )
        if not matched:
            raise HighConsequenceEffectDenied("HIGH_CONSEQUENCE_PREVIEW_STALE")

    def execute(self, arguments: Mapping[str, Any]) -> str:
        request = OperatorHighConsequenceInvocation.from_arguments(arguments)
        self._ensure_clear()
        self._require_dispatch_claim(request, arguments)
        if request.verifier_id != OPERATOR_HIGH_CONSEQUENCE_VERIFIER_ID:
            raise HighConsequenceEffectDenied("HIGH_CONSEQUENCE_VERIFIER_MISMATCH")
        completion = self._completion(request.ticket_id)
        if completion is not None:
            return self._response(completion, replayed=True)
        authority = self._goal_effect_authority(request.goal_effect_authority_id)
        registration = self._registration(request.target_id)
        self._validate_request_authority(request, authority, registration)
        claim = self._claim(request.ticket_id)
        if claim is not None:
            self._validate_claim(claim, request, registration)
            readback = self._inspect(registration, request.ticket_id)
            if self._matches_effect(readback, request):
                return self._record_completion(
                    claim,
                    request,
                    registration,
                    readback,
                    recovered_after_provider_crash=True,
                )
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_EXECUTION_STATE_UNCERTAIN"
            )

        preview = self.preview(
            goal_effect_authority_id=request.goal_effect_authority_id
        )
        self._validate_preview(request, preview)
        claim_payload = self._claim_payload(request, registration)

        def admission(events: list[Event]) -> Mapping[str, Any]:
            try:
                GlobalKillSwitch.ensure_clear(events)
            except TicketAuthorityDenied as error:
                raise HighConsequenceEffectDenied(error.reason_code) from error
            return claim_payload

        claim, created = self.store.append_once_computed(
            "operator.high_consequence_effect.claimed",
            request.ticket_id,
            admission,
        )
        if not created:
            self._validate_claim(claim, request, registration)
            readback = self._inspect(registration, request.ticket_id)
            if self._matches_effect(readback, request):
                return self._record_completion(
                    claim,
                    request,
                    registration,
                    readback,
                    recovered_after_provider_crash=True,
                )
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_EXECUTION_STATE_UNCERTAIN"
            )
        try:
            GlobalKillSwitch(self.store).checkpoint(
                checkpoint_id=(
                    "high-consequence-pre-"
                    f"{sha256(request.ticket_id.encode()).hexdigest()[:20]}"
                ),
                effect_id=str(claim.payload["effect_id"]),
                step="pre-provider",
            )
        except TicketAuthorityDenied as error:
            raise HighConsequenceEffectDenied(error.reason_code) from error
        registration.driver.execute(
            registration.spec,
            HighConsequenceProviderCommand(
                operation_id=request.ticket_id,
                target_id=registration.spec.id,
                provider=registration.spec.provider,
                owner_principal_id=registration.spec.owner_principal_id,
                consequence_class=request.consequence_class,
                effect_name=request.effect_name,
                effect_arguments_sha256=request.effect_arguments_sha256,
                dependency_proof_sha256=request.dependency_proof_sha256,
                principal_decision_receipt_sha256=(
                    request.principal_decision_receipt_sha256
                ),
                expected_before_state_sha256=(
                    request.expected_before_state_sha256
                ),
                preview_sha256=request.expected_preview_sha256,
            ),
        )
        readback = self._inspect(registration, request.ticket_id)
        if not self._matches_effect(readback, request):
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_PROVIDER_READBACK_MISMATCH"
            )
        return self._record_completion(
            claim,
            request,
            registration,
            readback,
            recovered_after_provider_crash=False,
        )

    @staticmethod
    def _validate_request_authority(
        request: OperatorHighConsequenceInvocation,
        authority: AuthenticatedGoalEffectAuthority,
        registration: _RegisteredHighConsequenceTarget,
    ) -> None:
        if (
            request.goal_effect_authority_id != authority.id
            or request.ticket_id != authority.ticket_id
            or request.target_id != authority.target_id
            or request.goal_id != authority.goal_id
            or request.consequence_class != authority.consequence_class
            or request.effect_name != authority.effect_name
            or request.effect_arguments_sha256
            != authority.effect_arguments_sha256
            or request.dependency_proof_sha256
            != authority.dependency_proof_sha256
            or request.principal_decision_receipt_sha256
            != authority.principal_decision_receipt_sha256
            or request.irreversible_acknowledged
            != authority.irreversible_acknowledged
            or request.expected_target_spec_sha256 != registration.spec_sha256
            or request.expected_provider_authority_receipt_sha256
            != registration.provider_authority.authority_receipt_sha256
        ):
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_AUTHORITY_BINDING_MISMATCH"
            )

    @staticmethod
    def _matches_effect(
        readback: ProviderHighConsequenceState,
        request: OperatorHighConsequenceInvocation,
    ) -> bool:
        return (
            readback.operation_applied
            and readback.operation_id == request.ticket_id
            and readback.consequence_class == request.consequence_class
            and readback.effect_name == request.effect_name
            and readback.effect_arguments_sha256
            == request.effect_arguments_sha256
        )

    @staticmethod
    def _claim_payload(
        request: OperatorHighConsequenceInvocation,
        registration: _RegisteredHighConsequenceTarget,
    ) -> dict[str, Any]:
        spec = registration.spec
        return {
            "schema_version": OPERATOR_HIGH_CONSEQUENCE_CLAIM_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "goal_effect_authority_id": request.goal_effect_authority_id,
            "target_id": spec.id,
            "target_spec_sha256": registration.spec_sha256,
            "driver_id": spec.driver_id,
            "provider": spec.provider,
            "owner_principal_id": spec.owner_principal_id,
            "provider_authenticated": (
                registration.provider_authority.authenticated
            ),
            "provider_authority_receipt_sha256": (
                registration.provider_authority.authority_receipt_sha256
            ),
            "goal_id": request.goal_id,
            "consequence_class": request.consequence_class,
            "effect_name": request.effect_name,
            "effect_arguments_sha256": request.effect_arguments_sha256,
            "dependency_proof_sha256": request.dependency_proof_sha256,
            "principal_decision_receipt_sha256": (
                request.principal_decision_receipt_sha256
            ),
            "irreversible_acknowledged": request.irreversible_acknowledged,
            "before_state_sha256": request.expected_before_state_sha256,
            "preview_sha256": request.expected_preview_sha256,
            "verifier_id": request.verifier_id,
            "effect_id": (
                "high-consequence-"
                f"{sha256(request.ticket_id.encode()).hexdigest()[:20]}"
            ),
            "reversible": spec.reversible,
            "real_effect": spec.real_effect,
            "producer_prose_persisted": False,
            "model_authority_inference_allowed": False,
        }

    @staticmethod
    def _validate_claim(
        claim: Event,
        request: OperatorHighConsequenceInvocation,
        registration: _RegisteredHighConsequenceTarget,
    ) -> None:
        expected = {
            "ticket_id": request.ticket_id,
            "goal_effect_authority_id": request.goal_effect_authority_id,
            "target_id": request.target_id,
            "target_spec_sha256": registration.spec_sha256,
            "goal_id": request.goal_id,
            "consequence_class": request.consequence_class,
            "effect_name": request.effect_name,
            "effect_arguments_sha256": request.effect_arguments_sha256,
            "dependency_proof_sha256": request.dependency_proof_sha256,
            "principal_decision_receipt_sha256": (
                request.principal_decision_receipt_sha256
            ),
            "before_state_sha256": request.expected_before_state_sha256,
            "preview_sha256": request.expected_preview_sha256,
            "verifier_id": request.verifier_id,
        }
        if any(claim.payload.get(key) != value for key, value in expected.items()):
            raise HighConsequenceEffectDenied("HIGH_CONSEQUENCE_CLAIM_COLLISION")

    def _record_completion(
        self,
        claim: Event,
        request: OperatorHighConsequenceInvocation,
        registration: _RegisteredHighConsequenceTarget,
        readback: ProviderHighConsequenceState,
        *,
        recovered_after_provider_crash: bool,
    ) -> str:
        spec = registration.spec
        realized_outcome_sha256 = _hash(
            {
                "ticket_id": request.ticket_id,
                "before_state_sha256": request.expected_before_state_sha256,
                "after_state_sha256": readback.target_state_sha256,
                "provider_receipt_sha256": readback.provider_receipt_sha256,
                "effect_name": request.effect_name,
            }
        )
        learning_payload = {
            "schema_version": 1,
            "ticket_id": request.ticket_id,
            "goal_id": request.goal_id,
            "effect_id": claim.payload["effect_id"],
            "realized_outcome_sha256": realized_outcome_sha256,
            "status": "proposed",
            "requires_endorsement": True,
            "self_ratification_allowed": False,
            "root_policy_changed": False,
            "producer_prose_persisted": False,
        }
        learning, _learning_created = self.store.append_once_result(
            "operator.high_consequence.policy_learning.proposed",
            request.ticket_id,
            learning_payload,
        )
        if canonical_json(learning.payload) != canonical_json(learning_payload):
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_POLICY_LEARNING_COLLISION"
            )
        rollback_status = (
            "available-not-invoked" if spec.reversible else "not-supported"
        )
        payload = {
            "schema_version": OPERATOR_HIGH_CONSEQUENCE_RECEIPT_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "claim_event_id": claim.event_id,
            "effect_id": claim.payload["effect_id"],
            "goal_effect_authority_id": request.goal_effect_authority_id,
            "target_id": spec.id,
            "target_spec_sha256": registration.spec_sha256,
            "driver_id": spec.driver_id,
            "provider": spec.provider,
            "owner_principal_id": spec.owner_principal_id,
            "provider_authenticated": (
                registration.provider_authority.authenticated
            ),
            "provider_authority_receipt_sha256": (
                registration.provider_authority.authority_receipt_sha256
            ),
            "principal_id": self._goal_effect_authority(
                request.goal_effect_authority_id
            ).principal_id,
            "goal_id": request.goal_id,
            "consequence_class": request.consequence_class,
            "effect_name": request.effect_name,
            "effect_arguments_sha256": request.effect_arguments_sha256,
            "dependency_proof_sha256": request.dependency_proof_sha256,
            "principal_decision_receipt_sha256": (
                request.principal_decision_receipt_sha256
            ),
            "irreversible_acknowledged": request.irreversible_acknowledged,
            "before_state_sha256": request.expected_before_state_sha256,
            "after_state_sha256": readback.target_state_sha256,
            "provider_receipt_sha256": readback.provider_receipt_sha256,
            "provider_readback_verified": True,
            "provider_effect_count": 1,
            "realized_outcome_sha256": realized_outcome_sha256,
            "rollback_status": rollback_status,
            "unwind_status": "not-applicable",
            "policy_learning_event_id": learning.event_id,
            "policy_learning_requires_endorsement": True,
            "self_ratification_allowed": False,
            "verification_passed": True,
            "status": "executed",
            "recovered_after_provider_crash": recovered_after_provider_crash,
            "real_effect": spec.real_effect,
            "producer_prose_persisted": False,
            "provider_raw_response_persisted": False,
            "model_authority_inference_allowed": False,
        }
        event, created = self.store.append_once_result(
            "operator.high_consequence_effect.completed",
            request.ticket_id,
            payload,
        )
        if not created and canonical_json(event.payload) != canonical_json(payload):
            existing = event.payload
            if not (
                existing.get("ticket_id") == request.ticket_id
                and existing.get("verification_passed") is True
                and existing.get("realized_outcome_sha256")
                == realized_outcome_sha256
            ):
                raise HighConsequenceEffectDenied(
                    "HIGH_CONSEQUENCE_RECEIPT_COLLISION"
                )
        return self._response(event, replayed=not created)

    def _require_dispatch_claim(
        self,
        request: OperatorHighConsequenceInvocation,
        arguments: Mapping[str, Any],
    ) -> None:
        arguments_sha256 = sha256(canonical_json(arguments).encode()).hexdigest()
        rows = [
            event
            for event in self.store.events("execution.ticket.consumed")
            if event.payload.get("ticket_id") == request.ticket_id
        ]
        if len(rows) != 1:
            raise HighConsequenceEffectDenied("TICKET_DISPATCH_CLAIM_REQUIRED")
        payload = rows[0].payload
        if payload.get("goal_id") != request.goal_id:
            raise HighConsequenceEffectDenied(
                "HIGH_CONSEQUENCE_TICKET_GOAL_MISMATCH"
            )
        if (
            payload.get("dispatch_claimed") is not True
            or payload.get("ticket_consumed") is not True
            or payload.get("tool_name") != "operator_high_consequence_effect"
            or payload.get("arguments_sha256") != arguments_sha256
            or payload.get("capability") != "operator.high_consequence"
            or payload.get("scope")
            != f"operator/high_consequence/{request.target_id}"
            or payload.get("verifier_id")
            != OPERATOR_HIGH_CONSEQUENCE_VERIFIER_ID
            or payload.get("idempotency_key") != request.ticket_id
            or payload.get("byte_budget") != 0
            or payload.get("action_budget") != 1
            or payload.get("value_budget_microunits") != 0
        ):
            raise HighConsequenceEffectDenied(
                "TICKET_DISPATCH_CLAIM_MISMATCH"
            )

    def _claim(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.high_consequence_effect.claimed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise HighConsequenceEffectDenied(
                "DUPLICATE_HIGH_CONSEQUENCE_CLAIMS"
            )
        return rows[0] if rows else None

    def _completion(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events(
                "operator.high_consequence_effect.completed"
            )
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise HighConsequenceEffectDenied(
                "DUPLICATE_HIGH_CONSEQUENCE_RECEIPTS"
            )
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
                "high_consequence_effect": {
                    "target_id": payload.get("target_id"),
                    "provider": payload.get("provider"),
                    "owner_principal_id": payload.get("owner_principal_id"),
                    "provider_authenticated": payload.get(
                        "provider_authenticated"
                    ),
                    "goal_id": payload.get("goal_id"),
                    "consequence_class": payload.get("consequence_class"),
                    "effect_name": payload.get("effect_name"),
                    "effect_arguments_sha256": payload.get(
                        "effect_arguments_sha256"
                    ),
                    "dependency_proof_sha256": payload.get(
                        "dependency_proof_sha256"
                    ),
                    "principal_decision_receipt_sha256": payload.get(
                        "principal_decision_receipt_sha256"
                    ),
                    "irreversible_acknowledged": payload.get(
                        "irreversible_acknowledged"
                    ),
                    "before_state_sha256": payload.get("before_state_sha256"),
                    "after_state_sha256": payload.get("after_state_sha256"),
                    "provider_receipt_sha256": payload.get(
                        "provider_receipt_sha256"
                    ),
                    "provider_readback_verified": payload.get(
                        "provider_readback_verified"
                    ),
                    "realized_outcome_sha256": payload.get(
                        "realized_outcome_sha256"
                    ),
                    "rollback_status": payload.get("rollback_status"),
                    "unwind_status": payload.get("unwind_status"),
                    "real_effect": payload.get("real_effect"),
                    "recovered_after_provider_crash": payload.get(
                        "recovered_after_provider_crash"
                    ),
                    "producer_prose_persisted": payload.get(
                        "producer_prose_persisted"
                    ),
                    "replayed": replayed,
                },
                "policy_learning": {
                    "requires_endorsement": payload.get(
                        "policy_learning_requires_endorsement"
                    ),
                    "self_ratification_allowed": payload.get(
                        "self_ratification_allowed"
                    ),
                    "status": "proposed",
                    "evidence_sha256": payload.get("realized_outcome_sha256"),
                },
                "verification": {
                    "passed": payload.get("verification_passed") is True,
                    "verifier_id": OPERATOR_HIGH_CONSEQUENCE_VERIFIER_ID,
                    "evidence_sha256": payload.get("realized_outcome_sha256"),
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
        if (
            not isinstance(value, dict)
            or context.verifier_id != OPERATOR_HIGH_CONSEQUENCE_VERIFIER_ID
        ):
            return malformed
        effect = value.get("effect")
        consequence = value.get("high_consequence_effect")
        learning = value.get("policy_learning")
        verification = value.get("verification")
        if not all(
            isinstance(row, dict)
            for row in (effect, consequence, learning, verification)
        ):
            return malformed
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            return OutcomeVerification(
                verified=False,
                effect_observed=False,
                status="receipt-missing",
            )
        payload = receipt.payload
        assert isinstance(effect, dict)
        assert isinstance(consequence, dict)
        assert isinstance(learning, dict)
        assert isinstance(verification, dict)
        matched = (
            value.get("success") is True
            and payload.get("verification_passed") is True
            and effect.get("effect_id") == payload.get("effect_id")
            and effect.get("idempotency_key") == context.idempotency_key
            and effect.get("receipt_event_id") == receipt.event_id
            and consequence.get("target_id") == payload.get("target_id")
            and consequence.get("goal_id") == payload.get("goal_id")
            and consequence.get("consequence_class")
            == payload.get("consequence_class")
            and consequence.get("effect_name") == payload.get("effect_name")
            and consequence.get("principal_decision_receipt_sha256")
            == payload.get("principal_decision_receipt_sha256")
            and consequence.get("dependency_proof_sha256")
            == payload.get("dependency_proof_sha256")
            and consequence.get("before_state_sha256")
            == payload.get("before_state_sha256")
            and consequence.get("after_state_sha256")
            == payload.get("after_state_sha256")
            and consequence.get("provider_readback_verified") is True
            and consequence.get("realized_outcome_sha256")
            == payload.get("realized_outcome_sha256")
            and consequence.get("producer_prose_persisted") is False
            and learning.get("requires_endorsement") is True
            and learning.get("self_ratification_allowed") is False
            and verification.get("passed") is True
            and verification.get("verifier_id")
            == OPERATOR_HIGH_CONSEQUENCE_VERIFIER_ID
            and verification.get("evidence_sha256")
            == payload.get("realized_outcome_sha256")
        )
        return OutcomeVerification(
            verified=matched,
            effect_observed=matched,
            status="verified" if matched else "receipt-mismatch",
            effect_id=str(payload["effect_id"]) if matched else None,
            evidence_sha256=(
                str(payload["realized_outcome_sha256"]) if matched else None
            ),
        )

    def _reconcile_mediated_result(
        self,
        context: VerificationContext,
    ) -> object | None:
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            claim = self._claim(context.ticket_id)
            if claim is None:
                return None
            registration = self._registration(str(claim.payload.get("target_id")))
            request = self._request_from_claim(claim)
            readback = self._inspect(registration, request.ticket_id)
            if not self._matches_effect(readback, request):
                return None
            self._record_completion(
                claim,
                request,
                registration,
                readback,
                recovered_after_provider_crash=True,
            )
            receipt = self._completion(context.ticket_id)
        if receipt is None:
            return None
        return json.loads(self._response(receipt, replayed=True))

    @staticmethod
    def _request_from_claim(claim: Event) -> OperatorHighConsequenceInvocation:
        payload = claim.payload
        return OperatorHighConsequenceInvocation(
            ticket_id=str(payload["ticket_id"]),
            goal_effect_authority_id=str(payload["goal_effect_authority_id"]),
            target_id=str(payload["target_id"]),
            goal_id=str(payload["goal_id"]),
            consequence_class=str(payload["consequence_class"]),
            effect_name=str(payload["effect_name"]),
            effect_arguments_sha256=str(payload["effect_arguments_sha256"]),
            dependency_proof_sha256=str(payload["dependency_proof_sha256"]),
            principal_decision_receipt_sha256=str(
                payload["principal_decision_receipt_sha256"]
            ),
            irreversible_acknowledged=bool(
                payload["irreversible_acknowledged"]
            ),
            expected_target_spec_sha256=str(payload["target_spec_sha256"]),
            expected_provider_authority_receipt_sha256=str(
                payload["provider_authority_receipt_sha256"]
            ),
            expected_before_state_sha256=str(payload["before_state_sha256"]),
            expected_preview_sha256=str(payload["preview_sha256"]),
            verifier_id=str(payload["verifier_id"]),
        )
