"""Ticketed financial effects with hard value/loss budgets and provider readback."""

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


OPERATOR_FINANCIAL_CLAIM_SCHEMA_VERSION = "cct.operator_financial.claim.v1"
OPERATOR_FINANCIAL_RECEIPT_SCHEMA_VERSION = "cct.operator_financial.receipt.v1"
OPERATOR_FINANCIAL_VERIFIER_ID = "operator-financial-readback"
MAX_OPERATOR_FINANCIAL_ACCOUNTS = 64
MAX_FINANCIAL_MICROUNITS = 1_000_000_000_000
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class FinancialEffectDenied(PermissionError):
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


def _integer(name: str, value: object, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= MAX_FINANCIAL_MICROUNITS:
        raise ValueError(
            f"{name} must be between {minimum} and {MAX_FINANCIAL_MICROUNITS}"
        )
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


def _day(value: str) -> str:
    return _timestamp("current time", value).date().isoformat()


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
class OperatorFinancialAccount:
    id: str
    driver_id: str
    provider: str
    account_id: str
    owner_principal_id: str
    allowed_instruments: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    max_order_value_microunits: int
    max_order_loss_microunits: int
    daily_value_cap_microunits: int
    daily_loss_cap_microunits: int
    real_value_effect: bool

    def __post_init__(self) -> None:
        for field in (
            "id",
            "driver_id",
            "provider",
            "account_id",
            "owner_principal_id",
        ):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        for field in ("allowed_instruments", "allowed_actions"):
            raw = getattr(self, field)
            if not isinstance(raw, (tuple, list)):
                raise ValueError(f"{field} must be an array")
            values = tuple(sorted({_identifier(field, value) for value in raw}))
            if not 1 <= len(values) <= 64:
                raise ValueError(f"{field} must contain 1-64 values")
            object.__setattr__(self, field, values)
        for field in (
            "max_order_value_microunits",
            "max_order_loss_microunits",
            "daily_value_cap_microunits",
            "daily_loss_cap_microunits",
        ):
            _integer(field, getattr(self, field), minimum=1)
        if self.max_order_value_microunits > self.daily_value_cap_microunits:
            raise ValueError("order value cap cannot exceed daily value cap")
        if self.max_order_loss_microunits > self.daily_loss_cap_microunits:
            raise ValueError("order loss cap cannot exceed daily loss cap")
        if not isinstance(self.real_value_effect, bool):
            raise ValueError("real_value_effect must be a boolean")

    @property
    def cap_key_sha256(self) -> str:
        return _hash(
            {
                "provider": self.provider,
                "account_id": self.account_id,
                "owner_principal_id": self.owner_principal_id,
            }
        )


@dataclass(frozen=True, slots=True)
class ProviderFinancialAuthority:
    target_id: str
    provider: str
    account_id: str
    owner_principal_id: str
    authenticated: bool
    real_value_effect: bool
    authority_receipt_sha256: str

    def __post_init__(self) -> None:
        for field in ("target_id", "provider", "account_id", "owner_principal_id"):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.authenticated, bool) or not isinstance(
            self.real_value_effect, bool
        ):
            raise ValueError("authority booleans are invalid")
        object.__setattr__(
            self,
            "authority_receipt_sha256",
            _digest("authority_receipt_sha256", self.authority_receipt_sha256),
        )


@dataclass(frozen=True, slots=True)
class ProviderFinancialState:
    target_id: str
    provider: str
    account_id: str
    owner_principal_id: str
    order_recorded: bool
    operation_id: str | None
    instrument: str | None
    action: str | None
    value_microunits: int
    worst_case_loss_microunits: int
    total_order_count: int
    total_value_microunits: int
    total_worst_case_loss_microunits: int
    provider_order_id_sha256: str
    provider_receipt_sha256: str
    last_operation_id: str | None
    real_value_effect: bool

    def __post_init__(self) -> None:
        for field in ("target_id", "provider", "account_id", "owner_principal_id"):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.order_recorded, bool) or not isinstance(
            self.real_value_effect, bool
        ):
            raise ValueError("financial state booleans are invalid")
        for field in ("operation_id", "instrument", "action", "last_operation_id"):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _identifier(field, value))
        for field in (
            "value_microunits",
            "worst_case_loss_microunits",
            "total_order_count",
            "total_value_microunits",
            "total_worst_case_loss_microunits",
        ):
            _integer(field, getattr(self, field))
        for field in ("provider_order_id_sha256", "provider_receipt_sha256"):
            object.__setattr__(self, field, _digest(field, getattr(self, field)))
        selected = (
            self.operation_id is not None
            and self.instrument is not None
            and self.action is not None
        )
        if self.order_recorded != selected:
            raise ValueError("financial operation state is inconsistent")
        if not self.order_recorded and (
            self.value_microunits or self.worst_case_loss_microunits
        ):
            raise ValueError("absent operation cannot report value")

    @property
    def state_sha256(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True, slots=True)
class FinancialProviderCommand:
    operation_id: str
    target_id: str
    provider: str
    account_id: str
    owner_principal_id: str
    instrument: str
    action: str
    value_microunits: int
    worst_case_loss_microunits: int
    expected_before_state_sha256: str
    preview_sha256: str
    credential_handles: tuple[str, ...] = ()


class OperatorFinancialDriver(Protocol):
    def authority(
        self,
        target: OperatorFinancialAccount,
    ) -> ProviderFinancialAuthority: ...

    def inspect(
        self,
        target: OperatorFinancialAccount,
        operation_id: str | None = None,
    ) -> ProviderFinancialState: ...

    def execute(
        self,
        target: OperatorFinancialAccount,
        command: FinancialProviderCommand,
    ) -> None: ...


class LocalFakeFinancialDriver:
    """Private hash-only fake provider; never transfers real value."""

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
            raise FinancialEffectDenied("FINANCIAL_PROVIDER_STATE_ROOT_CHANGED")

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
                raise FinancialEffectDenied("FINANCIAL_PROVIDER_STATE_UNSAFE")
            raw = bytearray()
            while chunk := os.read(descriptor, 65_536):
                raw.extend(chunk)
                if len(raw) > 1_048_576:
                    raise FinancialEffectDenied("FINANCIAL_PROVIDER_STATE_INVALID")
            value = json.loads(raw)
        except FileNotFoundError:
            return None
        except FinancialEffectDenied:
            raise
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise FinancialEffectDenied("FINANCIAL_PROVIDER_STATE_INVALID") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not isinstance(value, dict) or value.get("target_id") != target_id:
            raise FinancialEffectDenied("FINANCIAL_PROVIDER_STATE_INVALID")
        orders = value.get("orders")
        if not isinstance(orders, dict) or len(orders) > 10_000:
            raise FinancialEffectDenied("FINANCIAL_PROVIDER_STATE_INVALID")
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
            raise FinancialEffectDenied("FINANCIAL_PROVIDER_STATE_WRITE_FAILED") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary.exists():
                temporary.unlink()

    def _binding(self, target: OperatorFinancialAccount) -> None:
        if target.provider != self.provider or target.real_value_effect:
            raise FinancialEffectDenied("FAKE_FINANCIAL_PROVIDER_BINDING_MISMATCH")

    def authority(
        self,
        target: OperatorFinancialAccount,
    ) -> ProviderFinancialAuthority:
        self._binding(target)
        material = {
            "target_id": target.id,
            "provider": target.provider,
            "account_id": target.account_id,
            "owner_principal_id": target.owner_principal_id,
            "authenticated": False,
            "real_value_effect": False,
            "credential_values_persisted": False,
        }
        return ProviderFinancialAuthority(
            target_id=target.id,
            provider=target.provider,
            account_id=target.account_id,
            owner_principal_id=target.owner_principal_id,
            authenticated=False,
            real_value_effect=False,
            authority_receipt_sha256=_hash(material),
        )

    def inspect(
        self,
        target: OperatorFinancialAccount,
        operation_id: str | None = None,
    ) -> ProviderFinancialState:
        self._binding(target)
        if operation_id is not None:
            operation_id = _identifier("operation_id", operation_id)
        metadata = self._read(target.id)
        orders = dict(metadata["orders"]) if metadata else {}
        selected = orders.get(operation_id) if operation_id is not None else None
        total_value = sum(int(row["value_microunits"]) for row in orders.values())
        total_loss = sum(
            int(row["worst_case_loss_microunits"]) for row in orders.values()
        )
        last_operation_id = metadata.get("last_operation_id") if metadata else None
        selected_value = int(selected["value_microunits"]) if selected else 0
        selected_loss = (
            int(selected["worst_case_loss_microunits"]) if selected else 0
        )
        material = {
            "target_id": target.id,
            "provider": target.provider,
            "account_id": target.account_id,
            "owner_principal_id": target.owner_principal_id,
            "operation_id": operation_id,
            "selected": selected,
            "total_order_count": len(orders),
            "total_value_microunits": total_value,
            "total_worst_case_loss_microunits": total_loss,
            "last_operation_id": last_operation_id,
            "real_value_effect": False,
        }
        return ProviderFinancialState(
            target_id=target.id,
            provider=target.provider,
            account_id=target.account_id,
            owner_principal_id=target.owner_principal_id,
            order_recorded=selected is not None,
            operation_id=operation_id if selected else None,
            instrument=str(selected["instrument"]) if selected else None,
            action=str(selected["action"]) if selected else None,
            value_microunits=selected_value,
            worst_case_loss_microunits=selected_loss,
            total_order_count=len(orders),
            total_value_microunits=total_value,
            total_worst_case_loss_microunits=total_loss,
            provider_order_id_sha256=_hash(
                {
                    "provider": target.provider,
                    "target_id": target.id,
                    "operation_id": operation_id if selected else None,
                }
            ),
            provider_receipt_sha256=_hash(material),
            last_operation_id=(
                str(last_operation_id) if isinstance(last_operation_id, str) else None
            ),
            real_value_effect=False,
        )

    def execute(
        self,
        target: OperatorFinancialAccount,
        command: FinancialProviderCommand,
    ) -> None:
        self._binding(target)
        for field in (
            "operation_id",
            "target_id",
            "provider",
            "account_id",
            "owner_principal_id",
            "instrument",
            "action",
        ):
            _identifier(field, getattr(command, field))
        _integer("value_microunits", command.value_microunits, minimum=1)
        _integer(
            "worst_case_loss_microunits",
            command.worst_case_loss_microunits,
        )
        _digest("expected_before_state_sha256", command.expected_before_state_sha256)
        _digest("preview_sha256", command.preview_sha256)
        if (
            command.target_id != target.id
            or command.provider != target.provider
            or command.account_id != target.account_id
            or command.owner_principal_id != target.owner_principal_id
            or command.instrument not in target.allowed_instruments
            or command.action not in target.allowed_actions
            or command.credential_handles
        ):
            raise FinancialEffectDenied("FAKE_FINANCIAL_PROVIDER_COMMAND_MISMATCH")
        existing = self.inspect(target, command.operation_id)
        if existing.order_recorded:
            if (
                existing.instrument != command.instrument
                or existing.action != command.action
                or existing.value_microunits != command.value_microunits
                or existing.worst_case_loss_microunits
                != command.worst_case_loss_microunits
            ):
                raise FinancialEffectDenied("FINANCIAL_PROVIDER_OPERATION_COLLISION")
            return
        before = self.inspect(target)
        if before.state_sha256 != command.expected_before_state_sha256:
            raise FinancialEffectDenied("FINANCIAL_PROVIDER_PRESTATE_CHANGED")
        metadata = self._read(target.id)
        orders = dict(metadata["orders"]) if metadata else {}
        orders[command.operation_id] = {
            "instrument": command.instrument,
            "action": command.action,
            "value_microunits": command.value_microunits,
            "worst_case_loss_microunits": command.worst_case_loss_microunits,
        }
        self._write(
            target.id,
            {
                "schema_version": 1,
                "target_id": target.id,
                "provider": target.provider,
                "account_id": target.account_id,
                "owner_principal_id": target.owner_principal_id,
                "orders": orders,
                "last_operation_id": command.operation_id,
                "real_value_effect": False,
                "credential_values_persisted": False,
            },
        )
        self.mutation_count += 1


@dataclass(frozen=True, slots=True)
class OperatorFinancialPreview:
    account_id: str
    account_spec_sha256: str
    provider: str
    provider_account_id: str
    owner_principal_id: str
    provider_authenticated: bool
    authority_receipt_sha256: str
    instrument: str
    action: str
    value_microunits: int
    worst_case_loss_microunits: int
    before_state_sha256: str
    daily_bucket: str
    account_cap_key_sha256: str
    preview_sha256: str


@dataclass(frozen=True, slots=True)
class OperatorFinancialInvocation:
    ticket_id: str
    account_id: str
    instrument: str
    action: str
    value_microunits: int
    worst_case_loss_microunits: int
    expected_account_spec_sha256: str
    expected_authority_receipt_sha256: str
    expected_before_state_sha256: str
    expected_preview_sha256: str
    verifier_id: str

    @classmethod
    def from_arguments(
        cls,
        arguments: Mapping[str, Any],
    ) -> "OperatorFinancialInvocation":
        if not isinstance(arguments, Mapping):
            raise ValueError("financial arguments must be an object")
        fields = {
            "execution_ticket_id",
            "financial_account_id",
            "instrument",
            "action",
            "value_microunits",
            "worst_case_loss_microunits",
            "expected_account_spec_sha256",
            "expected_authority_receipt_sha256",
            "expected_before_state_sha256",
            "expected_preview_sha256",
            "verifier_id",
        }
        if set(arguments) != fields:
            raise ValueError("financial arguments require exact fields")
        return cls(
            ticket_id=_identifier(
                "execution_ticket_id", arguments["execution_ticket_id"]
            ),
            account_id=_identifier(
                "financial_account_id", arguments["financial_account_id"]
            ),
            instrument=_identifier("instrument", arguments["instrument"]),
            action=_identifier("action", arguments["action"]),
            value_microunits=_integer(
                "value_microunits", arguments["value_microunits"], minimum=1
            ),
            worst_case_loss_microunits=_integer(
                "worst_case_loss_microunits",
                arguments["worst_case_loss_microunits"],
            ),
            expected_account_spec_sha256=_digest(
                "expected_account_spec_sha256",
                arguments["expected_account_spec_sha256"],
            ),
            expected_authority_receipt_sha256=_digest(
                "expected_authority_receipt_sha256",
                arguments["expected_authority_receipt_sha256"],
            ),
            expected_before_state_sha256=_digest(
                "expected_before_state_sha256",
                arguments["expected_before_state_sha256"],
            ),
            expected_preview_sha256=_digest(
                "expected_preview_sha256",
                arguments["expected_preview_sha256"],
            ),
            verifier_id=_identifier("verifier_id", arguments["verifier_id"]),
        )


@dataclass(frozen=True, slots=True)
class _RegisteredFinancialAccount:
    spec: OperatorFinancialAccount
    spec_sha256: str
    driver: OperatorFinancialDriver
    authority: ProviderFinancialAuthority


class OperatorFinancialAdapter:
    def __init__(
        self,
        store: EventStore,
        *,
        accounts: Sequence[OperatorFinancialAccount],
        drivers: Mapping[str, OperatorFinancialDriver],
    ) -> None:
        if not isinstance(store, EventStore) or not isinstance(drivers, Mapping):
            raise ValueError("financial adapter configuration is invalid")
        principal_rows = store.events("principal.profile.installed")
        if not principal_rows:
            raise ValueError("financial accounts require an installed principal profile")
        principal_id = principal_rows[-1].payload.get("profile", {}).get("principal_id")
        registrations: dict[str, _RegisteredFinancialAccount] = {}
        for account in accounts:
            if not isinstance(account, OperatorFinancialAccount) or account.id in registrations:
                raise ValueError(
                    "accounts must contain unique OperatorFinancialAccount values"
                )
            if account.owner_principal_id != principal_id:
                raise ValueError("financial account owner must match installed principal")
            driver = drivers.get(account.driver_id)
            if driver is None or not all(
                callable(getattr(driver, name, None))
                for name in ("authority", "inspect", "execute")
            ):
                raise ValueError("financial driver must be host-registered")
            authority = driver.authority(account)
            if not isinstance(authority, ProviderFinancialAuthority):
                raise ValueError("financial authority readback is malformed")
            if (
                authority.target_id != account.id
                or authority.provider != account.provider
                or authority.account_id != account.account_id
                or authority.owner_principal_id != account.owner_principal_id
                or authority.real_value_effect != account.real_value_effect
            ):
                raise ValueError("financial authority binding mismatch")
            if account.real_value_effect and not authority.authenticated:
                raise ValueError(
                    "real financial account requires authenticated provider authority"
                )
            registrations[account.id] = _RegisteredFinancialAccount(
                spec=account,
                spec_sha256=_hash(asdict(account)),
                driver=driver,
                authority=authority,
            )
        if not 1 <= len(registrations) <= MAX_OPERATOR_FINANCIAL_ACCOUNTS:
            raise ValueError("financial accounts registration count is invalid")
        self.store = store
        self._accounts: Mapping[str, _RegisteredFinancialAccount] = MappingProxyType(
            registrations
        )
        os.chmod(self.store.path, 0o600)
        for registration in registrations.values():
            spec = registration.spec
            payload = {
                "schema_version": 1,
                "authority": "host_adapter",
                "target_id": spec.id,
                "driver_id": spec.driver_id,
                "provider": spec.provider,
                "account_id": spec.account_id,
                "owner_principal_id": spec.owner_principal_id,
                "allowed_instruments": list(spec.allowed_instruments),
                "allowed_actions": list(spec.allowed_actions),
                "max_order_value_microunits": spec.max_order_value_microunits,
                "max_order_loss_microunits": spec.max_order_loss_microunits,
                "daily_value_cap_microunits": spec.daily_value_cap_microunits,
                "daily_loss_cap_microunits": spec.daily_loss_cap_microunits,
                "provider_authenticated": registration.authority.authenticated,
                "authority_receipt_sha256": (
                    registration.authority.authority_receipt_sha256
                ),
                "account_spec_sha256": registration.spec_sha256,
                "real_value_effect": spec.real_value_effect,
                "credential_values_persisted": False,
            }
            event, _created = self.store.append_once_result(
                "operator.financial_account.registered", spec.id, payload
            )
            if canonical_json(event.payload) != canonical_json(payload):
                raise ValueError(f"financial account registration changed: {spec.id}")

    def outcome_verifiers(self) -> OutcomeVerifierRegistry:
        registry = OutcomeVerifierRegistry()
        registry.register(
            OPERATOR_FINANCIAL_VERIFIER_ID,
            self._verify_mediated_result,
            reconcile=self._reconcile_mediated_result,
            idempotency_proof_id="operator-financial-ticket-receipt",
        )
        return registry

    def _registration(self, account_id: str) -> _RegisteredFinancialAccount:
        registration = self._accounts.get(_identifier("account_id", account_id))
        if registration is None:
            raise FinancialEffectDenied("FINANCIAL_ACCOUNT_NOT_REGISTERED")
        return registration

    @staticmethod
    def _inspect(
        registration: _RegisteredFinancialAccount,
        operation_id: str | None = None,
    ) -> ProviderFinancialState:
        state = registration.driver.inspect(registration.spec, operation_id)
        if not isinstance(state, ProviderFinancialState):
            raise FinancialEffectDenied("FINANCIAL_PROVIDER_READBACK_MALFORMED")
        spec = registration.spec
        if (
            state.target_id != spec.id
            or state.provider != spec.provider
            or state.account_id != spec.account_id
            or state.owner_principal_id != spec.owner_principal_id
            or state.real_value_effect != spec.real_value_effect
        ):
            raise FinancialEffectDenied(
                "FINANCIAL_PROVIDER_READBACK_BINDING_MISMATCH"
            )
        return state

    def _ensure_clear(self) -> None:
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise FinancialEffectDenied(error.reason_code) from error

    def preview(
        self,
        *,
        account_id: str,
        instrument: str,
        action: str,
        value_microunits: int,
        worst_case_loss_microunits: int,
    ) -> OperatorFinancialPreview:
        self._ensure_clear()
        if self.store.verify_chain().get("valid") is not True:
            raise FinancialEffectDenied("LEDGER_CHAIN_INVALID")
        registration = self._registration(account_id)
        instrument = _identifier("instrument", instrument)
        action = _identifier("action", action)
        value = _integer("value_microunits", value_microunits, minimum=1)
        loss = _integer(
            "worst_case_loss_microunits", worst_case_loss_microunits
        )
        spec = registration.spec
        if instrument not in spec.allowed_instruments:
            raise FinancialEffectDenied("FINANCIAL_INSTRUMENT_DENIED")
        if action not in spec.allowed_actions:
            raise FinancialEffectDenied("FINANCIAL_ACTION_DENIED")
        if value > spec.max_order_value_microunits:
            raise FinancialEffectDenied("FINANCIAL_ORDER_VALUE_CAP_EXCEEDED")
        if loss > spec.max_order_loss_microunits or loss > value:
            raise FinancialEffectDenied("FINANCIAL_ORDER_LOSS_CAP_EXCEEDED")
        before = self._inspect(registration)
        daily_bucket = _day(self.store.clock())
        material = {
            "schema_version": 1,
            "target_id": spec.id,
            "account_spec_sha256": registration.spec_sha256,
            "provider": spec.provider,
            "account_id": spec.account_id,
            "owner_principal_id": spec.owner_principal_id,
            "provider_authenticated": registration.authority.authenticated,
            "authority_receipt_sha256": (
                registration.authority.authority_receipt_sha256
            ),
            "instrument": instrument,
            "action": action,
            "value_microunits": value,
            "worst_case_loss_microunits": loss,
            "before_state_sha256": before.state_sha256,
            "daily_bucket": daily_bucket,
            "account_cap_key_sha256": spec.cap_key_sha256,
            "real_value_effect": spec.real_value_effect,
            "credential_handles": [],
        }
        return OperatorFinancialPreview(
            account_id=spec.id,
            account_spec_sha256=registration.spec_sha256,
            provider=spec.provider,
            provider_account_id=spec.account_id,
            owner_principal_id=spec.owner_principal_id,
            provider_authenticated=registration.authority.authenticated,
            authority_receipt_sha256=(
                registration.authority.authority_receipt_sha256
            ),
            instrument=instrument,
            action=action,
            value_microunits=value,
            worst_case_loss_microunits=loss,
            before_state_sha256=before.state_sha256,
            daily_bucket=daily_bucket,
            account_cap_key_sha256=spec.cap_key_sha256,
            preview_sha256=_hash(material),
        )

    @staticmethod
    def _validate_preview(
        request: OperatorFinancialInvocation,
        preview: OperatorFinancialPreview,
    ) -> None:
        expected = (
            request.account_id == preview.account_id
            and request.instrument == preview.instrument
            and request.action == preview.action
            and request.value_microunits == preview.value_microunits
            and request.worst_case_loss_microunits
            == preview.worst_case_loss_microunits
            and request.expected_account_spec_sha256
            == preview.account_spec_sha256
            and request.expected_authority_receipt_sha256
            == preview.authority_receipt_sha256
            and request.expected_before_state_sha256 == preview.before_state_sha256
            and request.expected_preview_sha256 == preview.preview_sha256
        )
        if not expected:
            raise FinancialEffectDenied("FINANCIAL_PREVIEW_STALE")

    def execute(self, arguments: Mapping[str, Any]) -> str:
        request = OperatorFinancialInvocation.from_arguments(arguments)
        self._ensure_clear()
        self._require_dispatch_claim(request, arguments)
        registration = self._registration(request.account_id)
        if request.verifier_id != OPERATOR_FINANCIAL_VERIFIER_ID:
            raise FinancialEffectDenied("FINANCIAL_VERIFIER_MISMATCH")
        completion = self._completion(request.ticket_id)
        if completion is not None:
            return self._response(completion, replayed=True)
        claim = self._claim(request.ticket_id)
        if claim is not None:
            self._validate_claim(claim, request, registration)
            readback = self._inspect(registration, request.ticket_id)
            if self._matches_order(readback, request):
                return self._record_completion(
                    claim,
                    request,
                    registration,
                    readback,
                    recovered_after_provider_crash=True,
                )
            raise FinancialEffectDenied("FINANCIAL_EXECUTION_STATE_UNCERTAIN")

        preview = self.preview(
            account_id=request.account_id,
            instrument=request.instrument,
            action=request.action,
            value_microunits=request.value_microunits,
            worst_case_loss_microunits=request.worst_case_loss_microunits,
        )
        self._validate_preview(request, preview)
        claim_payload = self._claim_payload(request, registration, preview)

        def admission(events: list[Event]) -> Mapping[str, Any]:
            try:
                GlobalKillSwitch.ensure_clear(events)
            except TicketAuthorityDenied as error:
                raise FinancialEffectDenied(error.reason_code) from error
            rows = [
                event
                for event in events
                if event.kind == "operator.financial_effect.claimed"
                and event.payload.get("daily_bucket") == preview.daily_bucket
                and event.payload.get("account_cap_key_sha256")
                == preview.account_cap_key_sha256
            ]
            used_value = sum(int(row.payload["value_microunits"]) for row in rows)
            used_loss = sum(
                int(row.payload["worst_case_loss_microunits"]) for row in rows
            )
            if (
                used_value + request.value_microunits
                > registration.spec.daily_value_cap_microunits
            ):
                raise FinancialEffectDenied("FINANCIAL_DAILY_VALUE_CAP_EXHAUSTED")
            if (
                used_loss + request.worst_case_loss_microunits
                > registration.spec.daily_loss_cap_microunits
            ):
                raise FinancialEffectDenied("FINANCIAL_DAILY_LOSS_CAP_EXHAUSTED")
            return claim_payload

        claim, created = self.store.append_once_computed(
            "operator.financial_effect.claimed", request.ticket_id, admission
        )
        if not created:
            self._validate_claim(claim, request, registration)
            readback = self._inspect(registration, request.ticket_id)
            if self._matches_order(readback, request):
                return self._record_completion(
                    claim,
                    request,
                    registration,
                    readback,
                    recovered_after_provider_crash=True,
                )
            raise FinancialEffectDenied("FINANCIAL_EXECUTION_STATE_UNCERTAIN")

        try:
            GlobalKillSwitch(self.store).checkpoint(
                checkpoint_id=(
                    "financial-pre-"
                    f"{sha256(request.ticket_id.encode()).hexdigest()[:24]}"
                ),
                effect_id=str(claim.payload["effect_id"]),
                step="pre-provider",
            )
        except TicketAuthorityDenied as error:
            raise FinancialEffectDenied(error.reason_code) from error
        registration.driver.execute(
            registration.spec,
            FinancialProviderCommand(
                operation_id=request.ticket_id,
                target_id=registration.spec.id,
                provider=registration.spec.provider,
                account_id=registration.spec.account_id,
                owner_principal_id=registration.spec.owner_principal_id,
                instrument=request.instrument,
                action=request.action,
                value_microunits=request.value_microunits,
                worst_case_loss_microunits=request.worst_case_loss_microunits,
                expected_before_state_sha256=request.expected_before_state_sha256,
                preview_sha256=request.expected_preview_sha256,
                credential_handles=(),
            ),
        )
        readback = self._inspect(registration, request.ticket_id)
        if not self._matches_order(readback, request):
            raise FinancialEffectDenied("FINANCIAL_PROVIDER_READBACK_MISMATCH")
        return self._record_completion(
            claim,
            request,
            registration,
            readback,
            recovered_after_provider_crash=False,
        )

    @staticmethod
    def _matches_order(
        readback: ProviderFinancialState,
        request: OperatorFinancialInvocation,
    ) -> bool:
        return (
            readback.order_recorded
            and readback.operation_id == request.ticket_id
            and readback.instrument == request.instrument
            and readback.action == request.action
            and readback.value_microunits == request.value_microunits
            and readback.worst_case_loss_microunits
            == request.worst_case_loss_microunits
        )

    @staticmethod
    def _claim_payload(
        request: OperatorFinancialInvocation,
        registration: _RegisteredFinancialAccount,
        preview: OperatorFinancialPreview,
    ) -> dict[str, Any]:
        spec = registration.spec
        return {
            "schema_version": OPERATOR_FINANCIAL_CLAIM_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "target_id": spec.id,
            "account_spec_sha256": registration.spec_sha256,
            "driver_id": spec.driver_id,
            "provider": spec.provider,
            "account_id": spec.account_id,
            "owner_principal_id": spec.owner_principal_id,
            "provider_authenticated": registration.authority.authenticated,
            "authority_receipt_sha256": (
                registration.authority.authority_receipt_sha256
            ),
            "instrument": request.instrument,
            "action": request.action,
            "value_microunits": request.value_microunits,
            "worst_case_loss_microunits": request.worst_case_loss_microunits,
            "before_state_sha256": request.expected_before_state_sha256,
            "preview_sha256": request.expected_preview_sha256,
            "daily_bucket": preview.daily_bucket,
            "account_cap_key_sha256": preview.account_cap_key_sha256,
            "daily_value_cap_microunits": spec.daily_value_cap_microunits,
            "daily_loss_cap_microunits": spec.daily_loss_cap_microunits,
            "verifier_id": request.verifier_id,
            "effect_id": (
                "financial-"
                f"{sha256(request.ticket_id.encode()).hexdigest()[:24]}"
            ),
            "real_value_effect": spec.real_value_effect,
            "credential_handles": [],
            "credential_values_persisted": False,
            "provider_configuration_persisted": False,
        }

    @staticmethod
    def _validate_claim(
        claim: Event,
        request: OperatorFinancialInvocation,
        registration: _RegisteredFinancialAccount,
    ) -> None:
        expected = {
            "ticket_id": request.ticket_id,
            "target_id": request.account_id,
            "account_spec_sha256": registration.spec_sha256,
            "provider": registration.spec.provider,
            "account_id": registration.spec.account_id,
            "owner_principal_id": registration.spec.owner_principal_id,
            "instrument": request.instrument,
            "action": request.action,
            "value_microunits": request.value_microunits,
            "worst_case_loss_microunits": request.worst_case_loss_microunits,
            "before_state_sha256": request.expected_before_state_sha256,
            "preview_sha256": request.expected_preview_sha256,
            "verifier_id": request.verifier_id,
        }
        if any(claim.payload.get(key) != value for key, value in expected.items()):
            raise FinancialEffectDenied("FINANCIAL_CLAIM_COLLISION")

    def _record_completion(
        self,
        claim: Event,
        request: OperatorFinancialInvocation,
        registration: _RegisteredFinancialAccount,
        readback: ProviderFinancialState,
        *,
        recovered_after_provider_crash: bool,
    ) -> str:
        spec = registration.spec
        payload = {
            "schema_version": OPERATOR_FINANCIAL_RECEIPT_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "claim_event_id": claim.event_id,
            "effect_id": claim.payload["effect_id"],
            "target_id": spec.id,
            "account_spec_sha256": registration.spec_sha256,
            "driver_id": spec.driver_id,
            "provider": spec.provider,
            "account_id": spec.account_id,
            "owner_principal_id": spec.owner_principal_id,
            "provider_authenticated": registration.authority.authenticated,
            "authority_receipt_sha256": (
                registration.authority.authority_receipt_sha256
            ),
            "instrument": request.instrument,
            "action": request.action,
            "value_microunits": request.value_microunits,
            "worst_case_loss_microunits": request.worst_case_loss_microunits,
            "preview_sha256": request.expected_preview_sha256,
            "daily_bucket": claim.payload["daily_bucket"],
            "daily_value_cap_microunits": spec.daily_value_cap_microunits,
            "daily_loss_cap_microunits": spec.daily_loss_cap_microunits,
            "provider_order_id_sha256": readback.provider_order_id_sha256,
            "provider_receipt_sha256": readback.provider_receipt_sha256,
            "provider_readback_verified": True,
            "provider_effect_count": 1,
            "real_value_effect": spec.real_value_effect,
            "verification_passed": True,
            "status": "executed",
            "recovered_after_provider_crash": recovered_after_provider_crash,
            "credential_handles": [],
            "credential_values_persisted": False,
            "provider_raw_response_persisted": False,
            "provider_configuration_persisted": False,
        }
        event, created = self.store.append_once_result(
            "operator.financial_effect.completed", request.ticket_id, payload
        )
        if not created and canonical_json(event.payload) != canonical_json(payload):
            existing = event.payload
            if not (
                existing.get("ticket_id") == request.ticket_id
                and existing.get("verification_passed") is True
                and existing.get("instrument") == request.instrument
                and existing.get("value_microunits") == request.value_microunits
            ):
                raise FinancialEffectDenied("FINANCIAL_RECEIPT_COLLISION")
        return self._response(event, replayed=not created)

    def _require_dispatch_claim(
        self,
        request: OperatorFinancialInvocation,
        arguments: Mapping[str, Any],
    ) -> None:
        arguments_sha256 = sha256(canonical_json(arguments).encode()).hexdigest()
        rows = [
            event
            for event in self.store.events("execution.ticket.consumed")
            if event.payload.get("ticket_id") == request.ticket_id
        ]
        if len(rows) != 1:
            raise FinancialEffectDenied("TICKET_DISPATCH_CLAIM_REQUIRED")
        payload = rows[0].payload
        if (
            payload.get("dispatch_claimed") is not True
            or payload.get("ticket_consumed") is not True
            or payload.get("tool_name") != "operator_financial_effect"
            or payload.get("arguments_sha256") != arguments_sha256
            or payload.get("capability") != "operator.financial"
            or payload.get("scope")
            != f"operator/financial/{request.account_id}"
            or payload.get("verifier_id") != OPERATOR_FINANCIAL_VERIFIER_ID
            or payload.get("idempotency_key") != request.ticket_id
            or payload.get("byte_budget") != 0
            or payload.get("action_budget") != 1
            or not isinstance(payload.get("value_budget_microunits"), int)
            or payload["value_budget_microunits"] < request.value_microunits
        ):
            raise FinancialEffectDenied("TICKET_DISPATCH_CLAIM_MISMATCH")

    def _claim(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.financial_effect.claimed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise FinancialEffectDenied("DUPLICATE_FINANCIAL_CLAIMS")
        return rows[0] if rows else None

    def _completion(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.financial_effect.completed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise FinancialEffectDenied("DUPLICATE_FINANCIAL_RECEIPTS")
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
                "financial_effect": {
                    "target_id": payload.get("target_id"),
                    "provider": payload.get("provider"),
                    "account_id": payload.get("account_id"),
                    "owner_principal_id": payload.get("owner_principal_id"),
                    "provider_authenticated": payload.get(
                        "provider_authenticated"
                    ),
                    "instrument": payload.get("instrument"),
                    "action": payload.get("action"),
                    "value_microunits": payload.get("value_microunits"),
                    "worst_case_loss_microunits": payload.get(
                        "worst_case_loss_microunits"
                    ),
                    "provider_order_id_sha256": payload.get(
                        "provider_order_id_sha256"
                    ),
                    "provider_receipt_sha256": payload.get(
                        "provider_receipt_sha256"
                    ),
                    "provider_readback_verified": payload.get(
                        "provider_readback_verified"
                    ),
                    "provider_effect_count": payload.get(
                        "provider_effect_count"
                    ),
                    "daily_value_cap_microunits": payload.get(
                        "daily_value_cap_microunits"
                    ),
                    "daily_loss_cap_microunits": payload.get(
                        "daily_loss_cap_microunits"
                    ),
                    "real_value_effect": payload.get("real_value_effect"),
                    "recovered_after_provider_crash": payload.get(
                        "recovered_after_provider_crash"
                    ),
                    "credential_handles_used": [],
                    "replayed": replayed,
                },
                "verification": {
                    "passed": payload.get("verification_passed") is True,
                    "verifier_id": OPERATOR_FINANCIAL_VERIFIER_ID,
                    "evidence_sha256": payload.get("provider_receipt_sha256"),
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
        if not isinstance(value, dict) or context.verifier_id != OPERATOR_FINANCIAL_VERIFIER_ID:
            return malformed
        effect = value.get("effect")
        financial = value.get("financial_effect")
        verification = value.get("verification")
        if not all(isinstance(row, dict) for row in (effect, financial, verification)):
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
        assert isinstance(financial, dict)
        assert isinstance(verification, dict)
        matched = (
            value.get("success") is True
            and payload.get("verification_passed") is True
            and effect.get("effect_id") == payload.get("effect_id")
            and effect.get("idempotency_key") == context.idempotency_key
            and effect.get("receipt_event_id") == receipt.event_id
            and financial.get("target_id") == payload.get("target_id")
            and financial.get("provider") == payload.get("provider")
            and financial.get("account_id") == payload.get("account_id")
            and financial.get("owner_principal_id")
            == payload.get("owner_principal_id")
            and financial.get("instrument") == payload.get("instrument")
            and financial.get("action") == payload.get("action")
            and financial.get("value_microunits")
            == payload.get("value_microunits")
            and financial.get("worst_case_loss_microunits")
            == payload.get("worst_case_loss_microunits")
            and financial.get("provider_receipt_sha256")
            == payload.get("provider_receipt_sha256")
            and financial.get("provider_readback_verified") is True
            and financial.get("credential_handles_used") == []
            and verification.get("passed") is True
            and verification.get("verifier_id") == OPERATOR_FINANCIAL_VERIFIER_ID
            and verification.get("evidence_sha256")
            == payload.get("provider_receipt_sha256")
        )
        return OutcomeVerification(
            verified=matched,
            effect_observed=matched,
            status="verified" if matched else "receipt-mismatch",
            effect_id=str(payload["effect_id"]) if matched else None,
            evidence_sha256=(
                str(payload["provider_receipt_sha256"]) if matched else None
            ),
        )

    def _reconcile_mediated_result(self, context: VerificationContext) -> object | None:
        receipt = self._completion(context.ticket_id)
        if receipt is None:
            claim = self._claim(context.ticket_id)
            if claim is None:
                return None
            registration = self._registration(str(claim.payload.get("target_id")))
            request = self._request_from_claim(claim)
            readback = self._inspect(registration, request.ticket_id)
            if not self._matches_order(readback, request):
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
    def _request_from_claim(claim: Event) -> OperatorFinancialInvocation:
        payload = claim.payload
        return OperatorFinancialInvocation(
            ticket_id=str(payload["ticket_id"]),
            account_id=str(payload["target_id"]),
            instrument=str(payload["instrument"]),
            action=str(payload["action"]),
            value_microunits=int(payload["value_microunits"]),
            worst_case_loss_microunits=int(
                payload["worst_case_loss_microunits"]
            ),
            expected_account_spec_sha256=str(payload["account_spec_sha256"]),
            expected_authority_receipt_sha256=str(
                payload["authority_receipt_sha256"]
            ),
            expected_before_state_sha256=str(payload["before_state_sha256"]),
            expected_preview_sha256=str(payload["preview_sha256"]),
            verifier_id=str(payload["verifier_id"]),
        )
