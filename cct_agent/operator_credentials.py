"""Ticketed opaque credential broker with host-owned secret resolution."""

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
from .mediation_outcomes import (
    OutcomeVerification,
    OutcomeVerifierRegistry,
    VerificationContext,
)
from .store import Event, EventStore, canonical_json


OPERATOR_CREDENTIAL_CLAIM_SCHEMA_VERSION = "cct.operator_credential.claim.v1"
OPERATOR_CREDENTIAL_RECEIPT_SCHEMA_VERSION = "cct.operator_credential.receipt.v1"
OPERATOR_CREDENTIAL_VERIFIER_ID = "operator-credential-readback"
MAX_OPERATOR_CREDENTIAL_HANDLES = 128
MAX_CREDENTIAL_USES = 10_000
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class CredentialBrokerDenied(PermissionError):
    """Fail-closed broker denial with a stable reason code."""

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


def _integer(name: str, value: object, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


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


def _hash(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


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
class OperatorCredentialHandle:
    """Opaque host registration; contains no credential value or locator."""

    id: str
    resolver_id: str
    provider: str
    consumer_id: str
    owner_principal_id: str
    allowed_purposes: tuple[str, ...]
    expires_at: str
    max_uses: int

    def __post_init__(self) -> None:
        for field in (
            "id",
            "resolver_id",
            "provider",
            "consumer_id",
            "owner_principal_id",
        ):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.allowed_purposes, (tuple, list)):
            raise ValueError("allowed_purposes must be an array")
        purposes = tuple(
            sorted({_identifier("allowed purpose", value) for value in self.allowed_purposes})
        )
        if not 1 <= len(purposes) <= 32:
            raise ValueError("allowed_purposes must contain 1-32 values")
        object.__setattr__(self, "allowed_purposes", purposes)
        _timestamp("expires_at", self.expires_at)
        _integer("max_uses", self.max_uses, minimum=1, maximum=MAX_CREDENTIAL_USES)


@dataclass(frozen=True, slots=True)
class ProviderCredentialAuthority:
    handle_id: str
    provider: str
    consumer_id: str
    owner_principal_id: str
    authenticated: bool
    authority_receipt_sha256: str

    def __post_init__(self) -> None:
        for field in ("handle_id", "provider", "consumer_id", "owner_principal_id"):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.authenticated, bool):
            raise ValueError("authenticated must be a boolean")
        object.__setattr__(
            self,
            "authority_receipt_sha256",
            _digest("authority_receipt_sha256", self.authority_receipt_sha256),
        )


@dataclass(frozen=True, slots=True)
class ProviderCredentialUseState:
    handle_id: str
    provider: str
    consumer_id: str
    owner_principal_id: str
    use_recorded: bool
    operation_id: str | None
    purpose: str | None
    use_count: int
    provider_receipt_sha256: str
    last_operation_id: str | None

    def __post_init__(self) -> None:
        for field in ("handle_id", "provider", "consumer_id", "owner_principal_id"):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.use_recorded, bool):
            raise ValueError("use_recorded must be a boolean")
        for field in ("operation_id", "purpose", "last_operation_id"):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _identifier(field, value))
        _integer("use_count", self.use_count, minimum=0, maximum=MAX_CREDENTIAL_USES)
        object.__setattr__(
            self,
            "provider_receipt_sha256",
            _digest("provider_receipt_sha256", self.provider_receipt_sha256),
        )
        if self.use_recorded != (self.operation_id is not None and self.purpose is not None):
            raise ValueError("credential use state is inconsistent")

    @property
    def state_sha256(self) -> str:
        return _hash(asdict(self))


@dataclass(frozen=True, slots=True)
class CredentialResolverCommand:
    operation_id: str
    handle_id: str
    provider: str
    consumer_id: str
    owner_principal_id: str
    purpose: str
    expected_before_state_sha256: str
    preview_sha256: str


class OperatorCredentialResolver(Protocol):
    def authority(
        self,
        handle: OperatorCredentialHandle,
    ) -> ProviderCredentialAuthority: ...

    def inspect(
        self,
        handle: OperatorCredentialHandle,
        operation_id: str | None = None,
    ) -> ProviderCredentialUseState: ...

    def invoke(
        self,
        handle: OperatorCredentialHandle,
        command: CredentialResolverCommand,
    ) -> None: ...


class LocalFakeCredentialResolver:
    """Host-only fake resolver. Secret bytes never enter command, state, or receipt."""

    def __init__(
        self,
        *,
        state_root: str | Path,
        provider: str,
        consumer_id: str,
        secrets: Mapping[str, bytes],
    ) -> None:
        self.state_root, self._state_identity = _private_root(state_root)
        self.provider = _identifier("provider", provider)
        self.consumer_id = _identifier("consumer_id", consumer_id)
        if not isinstance(secrets, Mapping) or not secrets:
            raise ValueError("secrets must be a non-empty host mapping")
        material: dict[str, bytes] = {}
        for raw_handle, raw_secret in secrets.items():
            handle_id = _identifier("credential handle id", raw_handle)
            if not isinstance(raw_secret, bytes) or not raw_secret:
                raise ValueError("host secret values must be non-empty bytes")
            material[handle_id] = bytes(raw_secret)
        self._secrets: Mapping[str, bytes] = MappingProxyType(material)
        self.mutation_count = 0

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(provider={self.provider!r}, "
            f"consumer_id={self.consumer_id!r}, handles={len(self._secrets)})"
        )

    def _validate_root(self) -> None:
        metadata = self.state_root.stat()
        if (
            self.state_root.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or (metadata.st_dev, metadata.st_ino) != self._state_identity
        ):
            raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_STATE_ROOT_CHANGED")

    def _path(self, handle_id: str) -> Path:
        return self.state_root / f"{sha256(handle_id.encode()).hexdigest()}.json"

    def _read(self, handle_id: str) -> dict[str, Any] | None:
        self._validate_root()
        path = self._path(handle_id)
        descriptor: int | None = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
            ):
                raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_STATE_UNSAFE")
            raw = bytearray()
            while chunk := os.read(descriptor, 65_536):
                raw.extend(chunk)
                if len(raw) > 131_072:
                    raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_STATE_INVALID")
            value = json.loads(raw)
        except FileNotFoundError:
            return None
        except CredentialBrokerDenied:
            raise
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_STATE_INVALID") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not isinstance(value, dict) or value.get("handle_id") != handle_id:
            raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_STATE_INVALID")
        uses = value.get("uses")
        if not isinstance(uses, dict) or len(uses) > MAX_CREDENTIAL_USES:
            raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_STATE_INVALID")
        return value

    def _write(self, handle_id: str, payload: Mapping[str, Any]) -> None:
        self._validate_root()
        path = self._path(handle_id)
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
            raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_STATE_WRITE_FAILED") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary.exists():
                temporary.unlink()

    def _binding(self, handle: OperatorCredentialHandle) -> None:
        if (
            handle.provider != self.provider
            or handle.consumer_id != self.consumer_id
            or handle.id not in self._secrets
        ):
            raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_BINDING_MISMATCH")

    def authority(self, handle: OperatorCredentialHandle) -> ProviderCredentialAuthority:
        self._binding(handle)
        material = {
            "handle_id": handle.id,
            "provider": handle.provider,
            "consumer_id": handle.consumer_id,
            "owner_principal_id": handle.owner_principal_id,
            "authenticated": True,
            "secret_value_persisted": False,
            "secret_digest_persisted": False,
        }
        return ProviderCredentialAuthority(
            handle_id=handle.id,
            provider=handle.provider,
            consumer_id=handle.consumer_id,
            owner_principal_id=handle.owner_principal_id,
            authenticated=True,
            authority_receipt_sha256=_hash(material),
        )

    def inspect(
        self,
        handle: OperatorCredentialHandle,
        operation_id: str | None = None,
    ) -> ProviderCredentialUseState:
        self._binding(handle)
        if operation_id is not None:
            operation_id = _identifier("operation_id", operation_id)
        metadata = self._read(handle.id)
        uses = dict(metadata["uses"]) if metadata else {}
        selected = uses.get(operation_id) if operation_id is not None else None
        selected_purpose = selected.get("purpose") if isinstance(selected, dict) else None
        selected_receipt = (
            selected.get("provider_receipt_sha256")
            if isinstance(selected, dict)
            else None
        )
        last_operation_id = metadata.get("last_operation_id") if metadata else None
        receipt = selected_receipt or _hash(
            {
                "handle_id": handle.id,
                "provider": handle.provider,
                "consumer_id": handle.consumer_id,
                "owner_principal_id": handle.owner_principal_id,
                "use_count": len(uses),
                "last_operation_id": last_operation_id,
                "operation_id": operation_id,
                "secret_value_persisted": False,
                "secret_digest_persisted": False,
            }
        )
        return ProviderCredentialUseState(
            handle_id=handle.id,
            provider=handle.provider,
            consumer_id=handle.consumer_id,
            owner_principal_id=handle.owner_principal_id,
            use_recorded=selected is not None,
            operation_id=operation_id if selected is not None else None,
            purpose=str(selected_purpose) if selected is not None else None,
            use_count=len(uses),
            provider_receipt_sha256=str(receipt),
            last_operation_id=(
                str(last_operation_id) if isinstance(last_operation_id, str) else None
            ),
        )

    def invoke(
        self,
        handle: OperatorCredentialHandle,
        command: CredentialResolverCommand,
    ) -> None:
        self._binding(handle)
        for field in (
            "operation_id",
            "handle_id",
            "provider",
            "consumer_id",
            "owner_principal_id",
            "purpose",
        ):
            _identifier(field, getattr(command, field))
        _digest("expected_before_state_sha256", command.expected_before_state_sha256)
        _digest("preview_sha256", command.preview_sha256)
        if (
            command.handle_id != handle.id
            or command.provider != handle.provider
            or command.consumer_id != handle.consumer_id
            or command.owner_principal_id != handle.owner_principal_id
            or command.purpose not in handle.allowed_purposes
        ):
            raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_COMMAND_MISMATCH")
        existing = self.inspect(handle, command.operation_id)
        if existing.use_recorded:
            if existing.purpose != command.purpose:
                raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_OPERATION_COLLISION")
            return
        before = self.inspect(handle)
        if before.state_sha256 != command.expected_before_state_sha256:
            raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_PRESTATE_CHANGED")
        secret = self._secrets.get(handle.id)
        if not isinstance(secret, bytes) or not secret:
            raise CredentialBrokerDenied("CREDENTIAL_SECRET_UNAVAILABLE")
        # Test fake for host-owned invocation. Secret is consumed only inside resolver.
        secret_was_consumed = bool(secret[0] | 1)
        if not secret_was_consumed:
            raise CredentialBrokerDenied("CREDENTIAL_SECRET_USE_FAILED")
        metadata = self._read(handle.id)
        uses = dict(metadata["uses"]) if metadata else {}
        receipt = _hash(
            {
                "handle_id": handle.id,
                "provider": handle.provider,
                "consumer_id": handle.consumer_id,
                "owner_principal_id": handle.owner_principal_id,
                "operation_id": command.operation_id,
                "purpose": command.purpose,
                "use_sequence": len(uses) + 1,
                "authenticated": True,
                "secret_value_persisted": False,
                "secret_digest_persisted": False,
            }
        )
        uses[command.operation_id] = {
            "purpose": command.purpose,
            "provider_receipt_sha256": receipt,
        }
        self._write(
            handle.id,
            {
                "schema_version": 1,
                "handle_id": handle.id,
                "provider": handle.provider,
                "consumer_id": handle.consumer_id,
                "owner_principal_id": handle.owner_principal_id,
                "uses": uses,
                "last_operation_id": command.operation_id,
                "raw_secret_persisted": False,
                "secret_digest_persisted": False,
            },
        )
        self.mutation_count += 1


@dataclass(frozen=True, slots=True)
class OperatorCredentialPreview:
    handle_id: str
    handle_spec_sha256: str
    provider: str
    consumer_id: str
    owner_principal_id: str
    resolver_authenticated: bool
    authority_receipt_sha256: str
    purpose: str
    before_state_sha256: str
    use_count: int
    max_uses: int
    preview_sha256: str


@dataclass(frozen=True, slots=True)
class OperatorCredentialInvocation:
    ticket_id: str
    handle_id: str
    purpose: str
    expected_handle_spec_sha256: str
    expected_authority_receipt_sha256: str
    expected_before_state_sha256: str
    expected_preview_sha256: str
    verifier_id: str

    @classmethod
    def from_arguments(
        cls,
        arguments: Mapping[str, Any],
    ) -> "OperatorCredentialInvocation":
        if not isinstance(arguments, Mapping):
            raise ValueError("credential arguments must be an object")
        fields = {
            "execution_ticket_id",
            "credential_handle_id",
            "purpose",
            "expected_handle_spec_sha256",
            "expected_authority_receipt_sha256",
            "expected_before_state_sha256",
            "expected_preview_sha256",
            "verifier_id",
        }
        if set(arguments) != fields:
            raise ValueError("credential arguments require exact fields")
        return cls(
            ticket_id=_identifier(
                "execution_ticket_id", arguments["execution_ticket_id"]
            ),
            handle_id=_identifier(
                "credential_handle_id", arguments["credential_handle_id"]
            ),
            purpose=_identifier("purpose", arguments["purpose"]),
            expected_handle_spec_sha256=_digest(
                "expected_handle_spec_sha256",
                arguments["expected_handle_spec_sha256"],
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
class _RegisteredCredential:
    spec: OperatorCredentialHandle
    spec_sha256: str
    resolver: OperatorCredentialResolver
    authority: ProviderCredentialAuthority


class OperatorCredentialBroker:
    """Use opaque credential handles through exact host-owned resolvers."""

    def __init__(
        self,
        store: EventStore,
        *,
        handles: Sequence[OperatorCredentialHandle],
        resolvers: Mapping[str, OperatorCredentialResolver],
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        if not isinstance(resolvers, Mapping):
            raise ValueError("resolvers must be a mapping")
        principal_rows = store.events("principal.profile.installed")
        if not principal_rows:
            raise ValueError("credential handles require an installed principal profile")
        principal_id = principal_rows[-1].payload.get("profile", {}).get("principal_id")
        if not isinstance(principal_id, str):
            raise ValueError("installed principal profile is malformed")
        registrations: dict[str, _RegisteredCredential] = {}
        for handle in handles:
            if not isinstance(handle, OperatorCredentialHandle) or handle.id in registrations:
                raise ValueError(
                    "handles must contain unique OperatorCredentialHandle values"
                )
            if handle.owner_principal_id != principal_id:
                raise ValueError("credential handle owner must match installed principal")
            resolver = resolvers.get(handle.resolver_id)
            if resolver is None or not all(
                callable(getattr(resolver, name, None))
                for name in ("authority", "inspect", "invoke")
            ):
                raise ValueError("credential resolver must be host-registered")
            authority = resolver.authority(handle)
            if not isinstance(authority, ProviderCredentialAuthority):
                raise ValueError("credential resolver authority readback is malformed")
            if (
                authority.handle_id != handle.id
                or authority.provider != handle.provider
                or authority.consumer_id != handle.consumer_id
                or authority.owner_principal_id != handle.owner_principal_id
                or not authority.authenticated
            ):
                raise ValueError("credential resolver authority binding mismatch")
            registrations[handle.id] = _RegisteredCredential(
                spec=handle,
                spec_sha256=_hash(asdict(handle)),
                resolver=resolver,
                authority=authority,
            )
        if not 1 <= len(registrations) <= MAX_OPERATOR_CREDENTIAL_HANDLES:
            raise ValueError(
                "handles must contain 1-"
                f"{MAX_OPERATOR_CREDENTIAL_HANDLES} registrations"
            )
        self.store = store
        self._handles: Mapping[str, _RegisteredCredential] = MappingProxyType(
            registrations
        )
        os.chmod(self.store.path, 0o600)
        for registration in registrations.values():
            spec = registration.spec
            payload = {
                "schema_version": 1,
                "authority": "host_adapter",
                "handle_id": spec.id,
                "resolver_id": spec.resolver_id,
                "provider": spec.provider,
                "consumer_id": spec.consumer_id,
                "owner_principal_id": spec.owner_principal_id,
                "allowed_purposes": list(spec.allowed_purposes),
                "expires_at": spec.expires_at,
                "max_uses": spec.max_uses,
                "handle_spec_sha256": registration.spec_sha256,
                "resolver_authenticated": registration.authority.authenticated,
                "authority_receipt_sha256": (
                    registration.authority.authority_receipt_sha256
                ),
                "raw_secret_persisted": False,
                "secret_digest_persisted": False,
                "secret_locator_persisted": False,
            }
            event, _created = self.store.append_once_result(
                "operator.credential_handle.registered", spec.id, payload
            )
            if canonical_json(event.payload) != canonical_json(payload):
                raise ValueError(f"credential handle registration changed: {spec.id}")

    @property
    def registered_handle_ids(self) -> frozenset[str]:
        return frozenset(self._handles)

    def outcome_verifiers(self) -> OutcomeVerifierRegistry:
        registry = OutcomeVerifierRegistry()
        registry.register(
            OPERATOR_CREDENTIAL_VERIFIER_ID,
            self._verify_mediated_result,
            reconcile=self._reconcile_mediated_result,
            idempotency_proof_id="operator-credential-ticket-receipt",
        )
        return registry

    def _registration(self, handle_id: str) -> _RegisteredCredential:
        registration = self._handles.get(_identifier("handle_id", handle_id))
        if registration is None:
            raise CredentialBrokerDenied("CREDENTIAL_HANDLE_NOT_REGISTERED")
        return registration

    @staticmethod
    def _inspect(
        registration: _RegisteredCredential,
        operation_id: str | None = None,
    ) -> ProviderCredentialUseState:
        state = registration.resolver.inspect(registration.spec, operation_id)
        if not isinstance(state, ProviderCredentialUseState):
            raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_READBACK_MALFORMED")
        spec = registration.spec
        if (
            state.handle_id != spec.id
            or state.provider != spec.provider
            or state.consumer_id != spec.consumer_id
            or state.owner_principal_id != spec.owner_principal_id
        ):
            raise CredentialBrokerDenied(
                "CREDENTIAL_RESOLVER_READBACK_BINDING_MISMATCH"
            )
        return state

    def _ensure_live(self, registration: _RegisteredCredential) -> None:
        try:
            GlobalKillSwitch.ensure_clear(self.store.events())
        except TicketAuthorityDenied as error:
            raise CredentialBrokerDenied(error.reason_code) from error
        if _timestamp("current time", self.store.clock()) >= _timestamp(
            "handle expires_at", registration.spec.expires_at
        ):
            raise CredentialBrokerDenied("CREDENTIAL_HANDLE_EXPIRED")

    def preview(self, *, handle_id: str, purpose: str) -> OperatorCredentialPreview:
        if self.store.verify_chain().get("valid") is not True:
            raise CredentialBrokerDenied("LEDGER_CHAIN_INVALID")
        registration = self._registration(handle_id)
        self._ensure_live(registration)
        purpose = _identifier("purpose", purpose)
        if purpose not in registration.spec.allowed_purposes:
            raise CredentialBrokerDenied("CREDENTIAL_PURPOSE_DENIED")
        before = self._inspect(registration)
        if before.use_count >= registration.spec.max_uses:
            raise CredentialBrokerDenied("CREDENTIAL_HANDLE_USE_CAP_EXHAUSTED")
        material = {
            "schema_version": 1,
            "handle_id": registration.spec.id,
            "handle_spec_sha256": registration.spec_sha256,
            "provider": registration.spec.provider,
            "consumer_id": registration.spec.consumer_id,
            "owner_principal_id": registration.spec.owner_principal_id,
            "resolver_authenticated": registration.authority.authenticated,
            "authority_receipt_sha256": (
                registration.authority.authority_receipt_sha256
            ),
            "purpose": purpose,
            "before_state_sha256": before.state_sha256,
            "use_count": before.use_count,
            "max_uses": registration.spec.max_uses,
            "raw_secret_present": False,
            "secret_digest_present": False,
            "secret_locator_present": False,
        }
        return OperatorCredentialPreview(
            handle_id=registration.spec.id,
            handle_spec_sha256=registration.spec_sha256,
            provider=registration.spec.provider,
            consumer_id=registration.spec.consumer_id,
            owner_principal_id=registration.spec.owner_principal_id,
            resolver_authenticated=registration.authority.authenticated,
            authority_receipt_sha256=(
                registration.authority.authority_receipt_sha256
            ),
            purpose=purpose,
            before_state_sha256=before.state_sha256,
            use_count=before.use_count,
            max_uses=registration.spec.max_uses,
            preview_sha256=_hash(material),
        )

    @staticmethod
    def _validate_preview(
        request: OperatorCredentialInvocation,
        preview: OperatorCredentialPreview,
    ) -> None:
        if (
            request.handle_id != preview.handle_id
            or request.purpose != preview.purpose
            or request.expected_handle_spec_sha256 != preview.handle_spec_sha256
            or request.expected_authority_receipt_sha256
            != preview.authority_receipt_sha256
            or request.expected_before_state_sha256 != preview.before_state_sha256
            or request.expected_preview_sha256 != preview.preview_sha256
        ):
            raise CredentialBrokerDenied("CREDENTIAL_PREVIEW_STALE")

    def execute(self, arguments: Mapping[str, Any]) -> str:
        request = OperatorCredentialInvocation.from_arguments(arguments)
        registration = self._registration(request.handle_id)
        self._ensure_live(registration)
        self._require_dispatch_claim(request, arguments)
        if request.verifier_id != OPERATOR_CREDENTIAL_VERIFIER_ID:
            raise CredentialBrokerDenied("CREDENTIAL_VERIFIER_MISMATCH")
        completion = self._completion(request.ticket_id)
        if completion is not None:
            return self._response(completion, replayed=True)
        claim = self._claim(request.ticket_id)
        if claim is not None:
            self._validate_claim(claim, request, registration)
            readback = self._inspect(registration, request.ticket_id)
            if self._matches_use(readback, request):
                return self._record_completion(
                    claim,
                    request,
                    registration,
                    readback,
                    recovered_after_resolver_crash=True,
                )
            raise CredentialBrokerDenied("CREDENTIAL_EXECUTION_STATE_UNCERTAIN")

        preview = self.preview(handle_id=request.handle_id, purpose=request.purpose)
        self._validate_preview(request, preview)
        claim_payload = self._claim_payload(request, registration, preview)

        def admission(events: list[Event]) -> Mapping[str, Any]:
            try:
                GlobalKillSwitch.ensure_clear(events)
            except TicketAuthorityDenied as error:
                raise CredentialBrokerDenied(error.reason_code) from error
            used = sum(
                1
                for event in events
                if event.kind == "operator.credential_use.claimed"
                and event.payload.get("handle_id") == request.handle_id
            )
            if used >= registration.spec.max_uses:
                raise CredentialBrokerDenied("CREDENTIAL_HANDLE_USE_CAP_EXHAUSTED")
            return claim_payload

        claim, created = self.store.append_once_computed(
            "operator.credential_use.claimed", request.ticket_id, admission
        )
        if not created:
            self._validate_claim(claim, request, registration)
            readback = self._inspect(registration, request.ticket_id)
            if self._matches_use(readback, request):
                return self._record_completion(
                    claim,
                    request,
                    registration,
                    readback,
                    recovered_after_resolver_crash=True,
                )
            raise CredentialBrokerDenied("CREDENTIAL_EXECUTION_STATE_UNCERTAIN")

        effect_id = str(claim.payload["effect_id"])
        try:
            GlobalKillSwitch(self.store).checkpoint(
                checkpoint_id=(
                    "credential-pre-"
                    f"{sha256(request.ticket_id.encode()).hexdigest()[:24]}"
                ),
                effect_id=effect_id,
                step="pre-resolver",
            )
        except TicketAuthorityDenied as error:
            raise CredentialBrokerDenied(error.reason_code) from error
        registration.resolver.invoke(
            registration.spec,
            CredentialResolverCommand(
                operation_id=request.ticket_id,
                handle_id=registration.spec.id,
                provider=registration.spec.provider,
                consumer_id=registration.spec.consumer_id,
                owner_principal_id=registration.spec.owner_principal_id,
                purpose=request.purpose,
                expected_before_state_sha256=request.expected_before_state_sha256,
                preview_sha256=request.expected_preview_sha256,
            ),
        )
        readback = self._inspect(registration, request.ticket_id)
        if not self._matches_use(readback, request):
            raise CredentialBrokerDenied("CREDENTIAL_RESOLVER_READBACK_MISMATCH")
        return self._record_completion(
            claim,
            request,
            registration,
            readback,
            recovered_after_resolver_crash=False,
        )

    @staticmethod
    def _matches_use(
        readback: ProviderCredentialUseState,
        request: OperatorCredentialInvocation,
    ) -> bool:
        return (
            readback.use_recorded
            and readback.operation_id == request.ticket_id
            and readback.purpose == request.purpose
        )

    @staticmethod
    def _claim_payload(
        request: OperatorCredentialInvocation,
        registration: _RegisteredCredential,
        preview: OperatorCredentialPreview,
    ) -> dict[str, Any]:
        spec = registration.spec
        return {
            "schema_version": OPERATOR_CREDENTIAL_CLAIM_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "handle_id": spec.id,
            "handle_spec_sha256": registration.spec_sha256,
            "resolver_id": spec.resolver_id,
            "provider": spec.provider,
            "consumer_id": spec.consumer_id,
            "owner_principal_id": spec.owner_principal_id,
            "purpose": request.purpose,
            "authority_receipt_sha256": (
                registration.authority.authority_receipt_sha256
            ),
            "before_state_sha256": request.expected_before_state_sha256,
            "preview_sha256": request.expected_preview_sha256,
            "use_count_before": preview.use_count,
            "max_uses": spec.max_uses,
            "verifier_id": request.verifier_id,
            "effect_id": (
                "credential-"
                f"{sha256(request.ticket_id.encode()).hexdigest()[:24]}"
            ),
            "raw_secret_persisted": False,
            "secret_digest_persisted": False,
            "secret_locator_persisted": False,
            "resolver_configuration_persisted": False,
        }

    @staticmethod
    def _validate_claim(
        claim: Event,
        request: OperatorCredentialInvocation,
        registration: _RegisteredCredential,
    ) -> None:
        expected = {
            "ticket_id": request.ticket_id,
            "handle_id": request.handle_id,
            "handle_spec_sha256": registration.spec_sha256,
            "resolver_id": registration.spec.resolver_id,
            "provider": registration.spec.provider,
            "consumer_id": registration.spec.consumer_id,
            "owner_principal_id": registration.spec.owner_principal_id,
            "purpose": request.purpose,
            "authority_receipt_sha256": (
                registration.authority.authority_receipt_sha256
            ),
            "before_state_sha256": request.expected_before_state_sha256,
            "preview_sha256": request.expected_preview_sha256,
            "verifier_id": request.verifier_id,
        }
        if any(claim.payload.get(key) != value for key, value in expected.items()):
            raise CredentialBrokerDenied("CREDENTIAL_CLAIM_COLLISION")

    def _record_completion(
        self,
        claim: Event,
        request: OperatorCredentialInvocation,
        registration: _RegisteredCredential,
        readback: ProviderCredentialUseState,
        *,
        recovered_after_resolver_crash: bool,
    ) -> str:
        spec = registration.spec
        payload = {
            "schema_version": OPERATOR_CREDENTIAL_RECEIPT_SCHEMA_VERSION,
            "ticket_id": request.ticket_id,
            "claim_event_id": claim.event_id,
            "effect_id": claim.payload["effect_id"],
            "handle_id": spec.id,
            "handle_spec_sha256": registration.spec_sha256,
            "resolver_id": spec.resolver_id,
            "provider": spec.provider,
            "consumer_id": spec.consumer_id,
            "owner_principal_id": spec.owner_principal_id,
            "purpose": request.purpose,
            "authority_receipt_sha256": (
                registration.authority.authority_receipt_sha256
            ),
            "preview_sha256": request.expected_preview_sha256,
            "use_count": readback.use_count,
            "max_uses": spec.max_uses,
            "provider_receipt_sha256": readback.provider_receipt_sha256,
            "resolver_authenticated": True,
            "resolver_readback_verified": True,
            "resolver_effect_count": 1,
            "verification_passed": True,
            "status": "used",
            "recovered_after_resolver_crash": recovered_after_resolver_crash,
            "raw_secret_persisted": False,
            "raw_secret_exposed": False,
            "secret_digest_persisted": False,
            "secret_locator_persisted": False,
            "resolver_raw_response_persisted": False,
            "resolver_configuration_persisted": False,
        }
        event, created = self.store.append_once_result(
            "operator.credential_use.completed", request.ticket_id, payload
        )
        if not created and canonical_json(event.payload) != canonical_json(payload):
            existing = event.payload
            if not (
                existing.get("ticket_id") == request.ticket_id
                and existing.get("verification_passed") is True
                and existing.get("handle_id") == request.handle_id
                and existing.get("purpose") == request.purpose
            ):
                raise CredentialBrokerDenied("CREDENTIAL_RECEIPT_COLLISION")
        return self._response(event, replayed=not created)

    def _require_dispatch_claim(
        self,
        request: OperatorCredentialInvocation,
        arguments: Mapping[str, Any],
    ) -> None:
        arguments_sha256 = sha256(canonical_json(arguments).encode()).hexdigest()
        rows = [
            event
            for event in self.store.events("execution.ticket.consumed")
            if event.payload.get("ticket_id") == request.ticket_id
        ]
        if len(rows) != 1:
            raise CredentialBrokerDenied("TICKET_DISPATCH_CLAIM_REQUIRED")
        payload = rows[0].payload
        if (
            payload.get("dispatch_claimed") is not True
            or payload.get("ticket_consumed") is not True
            or payload.get("tool_name") != "operator_credential_use"
            or payload.get("arguments_sha256") != arguments_sha256
            or payload.get("capability") != "operator.credential"
            or payload.get("scope")
            != f"operator/credential/{request.handle_id}"
            or payload.get("verifier_id") != OPERATOR_CREDENTIAL_VERIFIER_ID
            or payload.get("idempotency_key") != request.ticket_id
            or payload.get("byte_budget") != 0
            or payload.get("action_budget") != 1
            or payload.get("value_budget_microunits") != 0
        ):
            raise CredentialBrokerDenied("TICKET_DISPATCH_CLAIM_MISMATCH")

    def _claim(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.credential_use.claimed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise CredentialBrokerDenied("DUPLICATE_CREDENTIAL_CLAIMS")
        return rows[0] if rows else None

    def _completion(self, ticket_id: str) -> Event | None:
        rows = [
            event
            for event in self.store.events("operator.credential_use.completed")
            if event.payload.get("ticket_id") == ticket_id
        ]
        if len(rows) > 1:
            raise CredentialBrokerDenied("DUPLICATE_CREDENTIAL_RECEIPTS")
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
                "credential_use": {
                    "handle_id": payload.get("handle_id"),
                    "provider": payload.get("provider"),
                    "consumer_id": payload.get("consumer_id"),
                    "owner_principal_id": payload.get("owner_principal_id"),
                    "purpose": payload.get("purpose"),
                    "resolver_authenticated": payload.get(
                        "resolver_authenticated"
                    ),
                    "authority_receipt_sha256": payload.get(
                        "authority_receipt_sha256"
                    ),
                    "provider_receipt_sha256": payload.get(
                        "provider_receipt_sha256"
                    ),
                    "resolver_readback_verified": payload.get(
                        "resolver_readback_verified"
                    ),
                    "resolver_effect_count": payload.get(
                        "resolver_effect_count"
                    ),
                    "use_count": payload.get("use_count"),
                    "max_uses": payload.get("max_uses"),
                    "recovered_after_resolver_crash": payload.get(
                        "recovered_after_resolver_crash"
                    ),
                    "raw_secret_exposed": False,
                    "secret_digest_persisted": False,
                    "secret_locator_persisted": False,
                    "replayed": replayed,
                },
                "verification": {
                    "passed": payload.get("verification_passed") is True,
                    "verifier_id": OPERATOR_CREDENTIAL_VERIFIER_ID,
                    "evidence_sha256": payload.get(
                        "provider_receipt_sha256"
                    ),
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
            or context.verifier_id != OPERATOR_CREDENTIAL_VERIFIER_ID
        ):
            return malformed
        effect = value.get("effect")
        credential_use = value.get("credential_use")
        verification = value.get("verification")
        if not all(
            isinstance(row, dict)
            for row in (effect, credential_use, verification)
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
        assert isinstance(credential_use, dict)
        assert isinstance(verification, dict)
        matched = (
            value.get("success") is True
            and payload.get("verification_passed") is True
            and effect.get("effect_id") == payload.get("effect_id")
            and effect.get("idempotency_key") == context.idempotency_key
            and effect.get("receipt_event_id") == receipt.event_id
            and credential_use.get("handle_id") == payload.get("handle_id")
            and credential_use.get("provider") == payload.get("provider")
            and credential_use.get("consumer_id") == payload.get("consumer_id")
            and credential_use.get("owner_principal_id")
            == payload.get("owner_principal_id")
            and credential_use.get("purpose") == payload.get("purpose")
            and credential_use.get("resolver_authenticated") is True
            and credential_use.get("provider_receipt_sha256")
            == payload.get("provider_receipt_sha256")
            and credential_use.get("resolver_readback_verified") is True
            and credential_use.get("raw_secret_exposed") is False
            and credential_use.get("secret_digest_persisted") is False
            and credential_use.get("secret_locator_persisted") is False
            and verification.get("passed") is True
            and verification.get("verifier_id")
            == OPERATOR_CREDENTIAL_VERIFIER_ID
            and verification.get("evidence_sha256")
            == payload.get("provider_receipt_sha256")
        )
        return OutcomeVerification(
            verified=matched,
            effect_observed=matched,
            status="verified" if matched else "receipt-mismatch",
            effect_id=str(payload["effect_id"]) if matched else None,
            evidence_sha256=(
                str(payload["provider_receipt_sha256"])
                if matched
                else None
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
            registration = self._registration(str(claim.payload.get("handle_id")))
            request = self._request_from_claim(claim)
            readback = self._inspect(registration, request.ticket_id)
            if not self._matches_use(readback, request):
                return None
            self._record_completion(
                claim,
                request,
                registration,
                readback,
                recovered_after_resolver_crash=True,
            )
            receipt = self._completion(context.ticket_id)
        if receipt is None:
            return None
        return json.loads(self._response(receipt, replayed=True))

    @staticmethod
    def _request_from_claim(claim: Event) -> OperatorCredentialInvocation:
        payload = claim.payload
        return OperatorCredentialInvocation(
            ticket_id=str(payload["ticket_id"]),
            handle_id=str(payload["handle_id"]),
            purpose=str(payload["purpose"]),
            expected_handle_spec_sha256=str(payload["handle_spec_sha256"]),
            expected_authority_receipt_sha256=str(
                payload["authority_receipt_sha256"]
            ),
            expected_before_state_sha256=str(payload["before_state_sha256"]),
            expected_preview_sha256=str(payload["preview_sha256"]),
            verifier_id=str(payload["verifier_id"]),
        )
