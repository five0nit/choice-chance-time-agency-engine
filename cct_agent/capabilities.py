"""Typed capabilities, revocable leases, and bounded workspace inspection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Literal, Mapping

from .principal import PersonalAgency, PrincipalIntent
from .store import EventStore, canonical_json


CapabilityMode = Literal["deny", "require_approval", "allow"]
RiskClass = Literal[
    "observe",
    "reversible",
    "privileged",
    "public",
    "financial",
    "constitutional",
]
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SCOPE = re.compile(r"^[A-Za-z0-9._/-]+(?:/\*\*)?$|^[*.]$")
SENSITIVE_PARTS = {
    ".env",
    ".git",
    ".ssh",
    "credential",
    "credentials",
    "keychain",
    "keystore",
    "private-key",
    "private_key",
    "secret",
    "secrets",
    "service-account",
    "service_account",
    "token",
    "tokens",
    "wallet",
    "wallets",
}


def _identifier(name: str, value: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    cleaned = value.strip()
    if not _IDENTIFIER.fullmatch(cleaned):
        raise ValueError(f"{name} must be a bounded identifier")
    return cleaned


def _text(name: str, value: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum or any(ord(char) < 32 for char in cleaned):
        raise ValueError(f"{name} must be 1-{maximum} printable characters")
    return cleaned


def _strict_keys(
    payload: Mapping[str, Any],
    *,
    allowed: set[str],
    required: set[str],
    name: str,
) -> None:
    keys = {str(key) for key in payload}
    unknown = keys - allowed
    missing = required - keys
    if unknown:
        raise ValueError(f"{name} has unknown fields: {sorted(unknown)}")
    if missing:
        raise ValueError(f"{name} is missing fields: {sorted(missing)}")


def _boolean(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _integer(name: str, value: Any, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _authority(value: str) -> str:
    if value not in {"operator", "host_adapter"}:
        raise ValueError("authority must be operator or host_adapter")
    return value


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("timestamp must be ISO-8601") from error
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed


def _normalize_scope(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("scope must be a string")
    cleaned = value.strip()
    if cleaned in {"*", "."}:
        return cleaned
    if "\\" in cleaned or "//" in cleaned or not _SCOPE.fullmatch(cleaned):
        raise ValueError("scope must be a normalized POSIX-relative path or prefix/**")
    suffix = cleaned.endswith("/**")
    path_text = cleaned[:-3] if suffix else cleaned
    path = PurePosixPath(path_text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("scope must not be absolute or contain traversal")
    return f"{path.as_posix()}/**" if suffix else path.as_posix()


def _scope_allows(pattern: str, requested: str) -> bool:
    allowed = _normalize_scope(pattern)
    scope = _normalize_scope(requested)
    if scope.endswith("/**"):
        return False
    if allowed in {"*", "."}:
        return True
    if allowed.endswith("/**"):
        prefix = allowed[:-3]
        return scope == prefix or scope.startswith(prefix + "/")
    return scope == allowed


def _scope_is_within(child: str, parent: str) -> bool:
    normalized_child = _normalize_scope(child)
    normalized_parent = _normalize_scope(parent)
    if normalized_parent in {"*", "."}:
        return True
    if normalized_child == normalized_parent:
        return True
    if normalized_parent.endswith("/**"):
        prefix = normalized_parent[:-3]
        child_prefix = normalized_child[:-3] if normalized_child.endswith("/**") else normalized_child
        return child_prefix == prefix or child_prefix.startswith(prefix + "/")
    return False


@dataclass(frozen=True, slots=True)
class CapabilitySpec:
    name: str
    description: str
    effect_kind: str
    intent_domain: str
    intent_action: str
    risk_class: RiskClass
    scopes: tuple[str, ...]
    verifier_id: str
    reversible: bool
    max_actions: int
    max_bytes: int
    max_value_microunits: int
    default_mode: Literal["deny", "require_approval"] = "require_approval"
    active: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _identifier("capability name", self.name))
        object.__setattr__(
            self,
            "description",
            _text("capability description", self.description, maximum=600),
        )
        object.__setattr__(
            self, "effect_kind", _identifier("effect kind", self.effect_kind)
        )
        object.__setattr__(
            self,
            "intent_domain",
            _identifier("capability intent domain", self.intent_domain),
        )
        object.__setattr__(
            self,
            "intent_action",
            _identifier("capability intent action", self.intent_action),
        )
        if self.risk_class not in {
            "observe",
            "reversible",
            "privileged",
            "public",
            "financial",
            "constitutional",
        }:
            raise ValueError("invalid capability risk class")
        if not isinstance(self.scopes, (tuple, list)):
            raise ValueError("capability scopes must be an array")
        normalized_scopes = tuple(sorted({_normalize_scope(scope) for scope in self.scopes}))
        if not normalized_scopes or len(normalized_scopes) > 32:
            raise ValueError("capability requires 1-32 scopes")
        object.__setattr__(self, "scopes", normalized_scopes)
        object.__setattr__(
            self, "verifier_id", _identifier("verifier id", self.verifier_id)
        )
        _boolean("capability reversible", self.reversible)
        _boolean("capability active", self.active)
        _integer("capability max_actions", self.max_actions, minimum=1)
        _integer("capability max_bytes", self.max_bytes)
        _integer(
            "capability max_value_microunits", self.max_value_microunits
        )
        if self.default_mode not in {"deny", "require_approval"}:
            raise ValueError("capability default_mode must fail closed")

    def as_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "effect_kind": self.effect_kind,
            "intent_domain": self.intent_domain,
            "intent_action": self.intent_action,
            "risk_class": self.risk_class,
            "scopes": list(self.scopes),
            "verifier_id": self.verifier_id,
            "reversible": bool(self.reversible),
            "max_actions": int(self.max_actions),
            "max_bytes": int(self.max_bytes),
            "max_value_microunits": int(self.max_value_microunits),
            "default_mode": self.default_mode,
            "active": bool(self.active),
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "CapabilitySpec":
        _strict_keys(
            payload,
            allowed={
                "name",
                "description",
                "effect_kind",
                "intent_domain",
                "intent_action",
                "risk_class",
                "scopes",
                "verifier_id",
                "reversible",
                "max_actions",
                "max_bytes",
                "max_value_microunits",
                "default_mode",
                "active",
            },
            required={
                "name",
                "description",
                "effect_kind",
                "intent_domain",
                "intent_action",
                "risk_class",
                "scopes",
                "verifier_id",
                "reversible",
                "max_actions",
                "max_bytes",
                "max_value_microunits",
            },
            name="capability specification",
        )
        if not isinstance(payload["scopes"], list):
            raise ValueError("capability scopes must be an array")
        return cls(
            name=payload["name"],
            description=payload["description"],
            effect_kind=payload["effect_kind"],
            intent_domain=payload["intent_domain"],
            intent_action=payload["intent_action"],
            risk_class=payload["risk_class"],
            scopes=tuple(payload["scopes"]),
            verifier_id=payload["verifier_id"],
            reversible=_boolean("capability reversible", payload["reversible"]),
            max_actions=_integer(
                "capability max_actions", payload["max_actions"], minimum=1
            ),
            max_bytes=_integer("capability max_bytes", payload["max_bytes"]),
            max_value_microunits=_integer(
                "capability max_value_microunits",
                payload["max_value_microunits"],
            ),
            default_mode=payload.get("default_mode", "require_approval"),
            active=_boolean("capability active", payload.get("active", True)),
        )


@dataclass(frozen=True, slots=True)
class CapabilityLease:
    id: str
    capability: str
    principal_id: str
    scopes: tuple[str, ...]
    expires_at: str
    max_actions: int
    max_bytes: int
    max_value_microunits: int
    issued_by: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("lease id", self.id))
        object.__setattr__(
            self, "capability", _identifier("lease capability", self.capability)
        )
        object.__setattr__(
            self, "principal_id", _identifier("lease principal id", self.principal_id)
        )
        if not isinstance(self.scopes, (tuple, list)):
            raise ValueError("capability lease scopes must be an array")
        object.__setattr__(
            self,
            "scopes",
            tuple(sorted({_normalize_scope(scope) for scope in self.scopes})),
        )
        if not self.scopes:
            raise ValueError("capability lease requires scopes")
        _timestamp(self.expires_at)
        _authority(self.issued_by)
        if not isinstance(self.evidence, (tuple, list)):
            raise ValueError("capability lease evidence must be an array")
        evidence_rows = tuple(_text("lease evidence", item, maximum=600) for item in self.evidence)
        if not evidence_rows:
            raise ValueError("capability lease requires evidence")
        object.__setattr__(self, "evidence", evidence_rows)
        _integer("lease max_actions", self.max_actions, minimum=1)
        _integer("lease max_bytes", self.max_bytes)
        _integer("lease max_value_microunits", self.max_value_microunits)

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "capability": self.capability,
            "principal_id": self.principal_id,
            "scopes": list(self.scopes),
            "expires_at": self.expires_at,
            "max_actions": int(self.max_actions),
            "max_bytes": int(self.max_bytes),
            "max_value_microunits": int(self.max_value_microunits),
            "issued_by": self.issued_by,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "CapabilityLease":
        _strict_keys(
            payload,
            allowed={
                "id",
                "capability",
                "principal_id",
                "scopes",
                "expires_at",
                "max_actions",
                "max_bytes",
                "max_value_microunits",
                "issued_by",
                "evidence",
            },
            required={
                "id",
                "capability",
                "principal_id",
                "scopes",
                "expires_at",
                "max_actions",
                "max_bytes",
                "max_value_microunits",
                "issued_by",
                "evidence",
            },
            name="capability lease",
        )
        if not isinstance(payload["scopes"], list):
            raise ValueError("capability lease scopes must be an array")
        if not isinstance(payload["evidence"], list):
            raise ValueError("capability lease evidence must be an array")
        return cls(
            id=payload["id"],
            capability=payload["capability"],
            principal_id=payload["principal_id"],
            scopes=tuple(payload["scopes"]),
            expires_at=payload["expires_at"],
            max_actions=_integer(
                "lease max_actions", payload["max_actions"], minimum=1
            ),
            max_bytes=_integer("lease max_bytes", payload["max_bytes"]),
            max_value_microunits=_integer(
                "lease max_value_microunits", payload["max_value_microunits"]
            ),
            issued_by=payload["issued_by"],
            evidence=tuple(payload["evidence"]),
        )


@dataclass(frozen=True, slots=True)
class CapabilityRequest:
    id: str
    capability: str
    principal_id: str
    scope: str
    lease_id: str | None
    principal_profile_digest: str | None = None
    intent_digest: str | None = None
    intent_domain: str | None = None
    intent_action: str | None = None
    requested_actions: int = 1
    requested_bytes: int = 0
    requested_value_microunits: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("request id", self.id))
        object.__setattr__(
            self, "capability", _identifier("request capability", self.capability)
        )
        object.__setattr__(
            self, "principal_id", _identifier("request principal id", self.principal_id)
        )
        object.__setattr__(self, "scope", _normalize_scope(self.scope))
        if self.lease_id is not None:
            object.__setattr__(
                self, "lease_id", _identifier("request lease id", self.lease_id)
            )
        if self.principal_profile_digest is not None:
            if not isinstance(self.principal_profile_digest, str) or not _DIGEST.fullmatch(
                self.principal_profile_digest
            ):
                raise ValueError("principal_profile_digest must be a SHA-256 digest")
        if self.intent_digest is not None:
            if not isinstance(self.intent_digest, str) or not _DIGEST.fullmatch(
                self.intent_digest
            ):
                raise ValueError("intent_digest must be a SHA-256 digest")
        if self.intent_domain is not None:
            object.__setattr__(
                self,
                "intent_domain",
                _identifier("request intent domain", self.intent_domain),
            )
        if self.intent_action is not None:
            object.__setattr__(
                self,
                "intent_action",
                _identifier("request intent action", self.intent_action),
            )
        _integer("requested_actions", self.requested_actions, minimum=1)
        _integer("requested_bytes", self.requested_bytes)
        _integer(
            "requested_value_microunits", self.requested_value_microunits
        )

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "capability": self.capability,
            "principal_id": self.principal_id,
            "scope": self.scope,
            "lease_id": self.lease_id,
            "principal_profile_digest": self.principal_profile_digest,
            "intent_digest": self.intent_digest,
            "intent_domain": self.intent_domain,
            "intent_action": self.intent_action,
            "requested_actions": int(self.requested_actions),
            "requested_bytes": int(self.requested_bytes),
            "requested_value_microunits": int(self.requested_value_microunits),
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "CapabilityRequest":
        _strict_keys(
            payload,
            allowed={
                "id",
                "capability",
                "principal_id",
                "scope",
                "lease_id",
                "principal_profile_digest",
                "intent_digest",
                "intent_domain",
                "intent_action",
                "requested_actions",
                "requested_bytes",
                "requested_value_microunits",
            },
            required={"id", "capability", "principal_id", "scope"},
            name="capability request",
        )
        return cls(
            id=payload["id"],
            capability=payload["capability"],
            principal_id=payload["principal_id"],
            scope=payload["scope"],
            lease_id=(payload["lease_id"] if payload.get("lease_id") else None),
            principal_profile_digest=(
                payload["principal_profile_digest"]
                if payload.get("principal_profile_digest")
                else None
            ),
            intent_digest=(
                payload["intent_digest"] if payload.get("intent_digest") else None
            ),
            intent_domain=(
                payload["intent_domain"] if payload.get("intent_domain") else None
            ),
            intent_action=(
                payload["intent_action"] if payload.get("intent_action") else None
            ),
            requested_actions=_integer(
                "requested_actions", payload.get("requested_actions", 1), minimum=1
            ),
            requested_bytes=_integer(
                "requested_bytes", payload.get("requested_bytes", 0)
            ),
            requested_value_microunits=_integer(
                "requested_value_microunits",
                payload.get("requested_value_microunits", 0),
            ),
        )


@dataclass(frozen=True, slots=True)
class CapabilityDecision:
    mode: CapabilityMode
    reasons: tuple[str, ...]
    capability: str
    spec_digest: str | None
    lease_id: str | None
    event_id: str | None = None

    def as_payload(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "reasons": list(self.reasons),
            "capability": self.capability,
            "spec_digest": self.spec_digest,
            "lease_id": self.lease_id,
        }

    @classmethod
    def from_payload(
        cls, payload: Mapping[str, Any], *, event_id: str | None = None
    ) -> "CapabilityDecision":
        return cls(
            mode=str(payload["mode"]),  # type: ignore[arg-type]
            reasons=tuple(str(item) for item in payload["reasons"]),
            capability=str(payload["capability"]),
            spec_digest=(
                str(payload["spec_digest"])
                if payload.get("spec_digest") is not None
                else None
            ),
            lease_id=(str(payload["lease_id"]) if payload.get("lease_id") else None),
            event_id=event_id,
        )


def lease_usage_from_events(events: list[Any], lease_id: str) -> dict[str, int]:
    """Project reservations made by capability decisions and execution tickets."""

    usage = {"actions": 0, "bytes": 0, "value_microunits": 0}
    for event in events:
        if event.kind == "capability.request.decided":
            decision = event.payload.get("decision", {})
            request = event.payload.get("request", {})
            if decision.get("mode") != "allow" or request.get("lease_id") != lease_id:
                continue
            usage["actions"] += int(request.get("requested_actions", 0))
            usage["bytes"] += int(request.get("requested_bytes", 0))
            usage["value_microunits"] += int(
                request.get("requested_value_microunits", 0)
            )
        elif (
            event.kind == "execution.ticket.consumed"
            and event.payload.get("lease_id") == lease_id
        ):
            usage["actions"] += int(event.payload.get("action_budget", 0))
            usage["bytes"] += int(event.payload.get("byte_budget", 0))
            usage["value_microunits"] += int(
                event.payload.get("value_budget_microunits", 0)
            )
    return usage


class CapabilityRegistry:
    """Event-sourced capability specifications and externally issued leases."""

    def __init__(self, store: EventStore) -> None:
        self.store = store

    def _spec_rows(
        self, events: list[Any] | None = None
    ) -> dict[str, tuple[CapabilitySpec, str, int]]:
        rows: dict[str, tuple[CapabilitySpec, str, int]] = {}
        source = events if events is not None else self.store.events()
        for event in source:
            if event.kind != "capability.spec.registered":
                continue
            spec = CapabilitySpec.from_payload(event.payload["spec"])
            rows[spec.name] = (
                spec,
                str(event.payload["spec_digest"]),
                int(event.payload["revision"]),
            )
        return rows

    def _leases(self, events: list[Any] | None = None) -> dict[str, CapabilityLease]:
        rows: dict[str, CapabilityLease] = {}
        source = events if events is not None else self.store.events()
        for event in source:
            if event.kind != "capability.lease.granted":
                continue
            lease = CapabilityLease.from_payload(event.payload["lease"])
            rows[lease.id] = lease
        return rows

    def _revocations(
        self, events: list[Any] | None = None
    ) -> dict[str, dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        source = events if events is not None else self.store.events()
        for event in source:
            if event.kind != "capability.lease.revoked":
                continue
            rows[str(event.payload["lease_id"])] = dict(event.payload)
        return rows

    def register(
        self,
        spec: CapabilitySpec,
        *,
        authority: str,
        evidence: tuple[str, ...] | list[str],
        expected_previous_digest: str | None = None,
    ) -> dict[str, Any]:
        source = _authority(authority)
        if not isinstance(evidence, (tuple, list)):
            raise ValueError("capability specification evidence must be an array")
        evidence_rows = tuple(_text("spec evidence", item, maximum=600) for item in evidence)
        if not evidence_rows:
            raise ValueError("capability specification requires evidence")
        payload_spec = spec.as_payload()
        digest = sha256(canonical_json(payload_spec).encode()).hexdigest()

        def factory(events: list[Any]) -> tuple[str, Mapping[str, Any]]:
            current_event = next(
                (
                    event
                    for event in reversed(events)
                    if event.kind == "capability.spec.registered"
                    and event.payload["spec"]["name"] == spec.name
                ),
                None,
            )
            previous_digest = (
                str(current_event.payload["spec_digest"])
                if current_event
                else None
            )
            if current_event and previous_digest == digest:
                return (
                    f"{spec.name}:{current_event.payload['revision']}:{digest}",
                    current_event.payload,
                )
            if current_event is not None and expected_previous_digest is None:
                raise ValueError(
                    "expected previous capability digest is required for revision"
                )
            if expected_previous_digest != previous_digest:
                raise ValueError(
                    "expected previous capability digest does not match"
                )
            revision = (
                int(current_event.payload["revision"]) + 1
                if current_event
                else 1
            )
            payload = {
                "schema_version": 1,
                "revision": revision,
                "spec_digest": digest,
                "previous_spec_digest": previous_digest,
                "authority": source,
                "evidence": list(evidence_rows),
                "spec": payload_spec,
            }
            return f"{spec.name}:{revision}:{digest}", payload

        event, created = self.store.append_computed_once(
            "capability.spec.registered", factory
        )
        return {
            "spec": payload_spec,
            "spec_digest": digest,
            "revision": int(event.payload["revision"]),
            "event_id": event.event_id,
            "created": created,
        }

    def grant(self, lease: CapabilityLease) -> dict[str, Any]:
        _authority(lease.issued_by)
        specs = self._spec_rows()
        if lease.capability not in specs:
            raise KeyError(f"unknown capability: {lease.capability}")
        spec, spec_digest, _ = specs[lease.capability]
        if not spec.active:
            raise ValueError("cannot lease an inactive capability")
        if _timestamp(lease.expires_at) <= _timestamp(self.store.clock()):
            raise ValueError("lease expires_at must be in the future")
        if lease.max_actions > spec.max_actions:
            raise ValueError("lease exceeds capability max_actions")
        if lease.max_bytes > spec.max_bytes:
            raise ValueError("lease exceeds capability max_bytes")
        if lease.max_value_microunits > spec.max_value_microunits:
            raise ValueError("lease exceeds capability max_value_microunits")
        if any(
            not any(_scope_is_within(scope, parent) for parent in spec.scopes)
            for scope in lease.scopes
        ):
            raise ValueError("lease scope exceeds capability scope")
        payload = {
            "schema_version": 1,
            "spec_digest": spec_digest,
            "lease": lease.as_payload(),
        }
        event = self.store.append_once("capability.lease.granted", lease.id, payload)
        return {**payload, "event_id": event.event_id}

    def revoke(self, lease_id: str, *, authority: str, reason: str) -> dict[str, Any]:
        identifier = _identifier("lease id", lease_id)
        source = _authority(authority)
        if identifier not in self._leases():
            raise KeyError(f"unknown capability lease: {identifier}")
        payload = {
            "schema_version": 1,
            "lease_id": identifier,
            "authority": source,
            "reason": _text("revocation reason", reason, maximum=600),
        }
        event = self.store.append_once("capability.lease.revoked", identifier, payload)
        return {**payload, "event_id": event.event_id}

    def _lease_usage(
        self, events: list[Any], lease_id: str
    ) -> dict[str, int]:
        return lease_usage_from_events(events, lease_id)

    def _decision_from_events(
        self,
        events: list[Any],
        request: CapabilityRequest,
        *,
        require_principal_profile_digest: bool = False,
    ) -> CapabilityDecision:
        spec_row = self._spec_rows(events).get(request.capability)
        if spec_row is None:
            return CapabilityDecision(
                mode="deny",
                reasons=("UNKNOWN_CAPABILITY",),
                capability=request.capability,
                spec_digest=None,
                lease_id=request.lease_id,
            )
        spec, spec_digest, _ = spec_row
        reasons: list[str] = []
        mode: CapabilityMode
        latest_profile = next(
            (
                event
                for event in reversed(events)
                if event.kind == "principal.profile.installed"
            ),
            None,
        )
        latest_profile_digest = (
            latest_profile.payload.get("profile_digest") if latest_profile else None
        )
        latest_profile_principal_id = (
            latest_profile.payload.get("profile", {}).get("principal_id")
            if latest_profile
            else None
        )
        if require_principal_profile_digest and request.principal_profile_digest is None:
            mode = "deny"
            reasons.append("PRINCIPAL_PROFILE_DIGEST_REQUIRED")
        elif require_principal_profile_digest and latest_profile_digest is None:
            mode = "deny"
            reasons.append("PRINCIPAL_PROFILE_NOT_INSTALLED")
        elif (
            require_principal_profile_digest
            and request.principal_profile_digest != latest_profile_digest
        ):
            mode = "deny"
            reasons.append("PRINCIPAL_PROFILE_CHANGED")
        elif (
            require_principal_profile_digest
            and request.principal_id != latest_profile_principal_id
        ):
            mode = "deny"
            reasons.append("PRINCIPAL_ID_MISMATCH")
        elif require_principal_profile_digest and (
            request.intent_digest is None
            or request.intent_domain is None
            or request.intent_action is None
        ):
            mode = "deny"
            reasons.append("INTENT_BINDING_REQUIRED")
        elif require_principal_profile_digest and (
            request.intent_domain != spec.intent_domain
            or request.intent_action != spec.intent_action
        ):
            mode = "deny"
            reasons.append("INTENT_CAPABILITY_MISMATCH")
        elif not spec.active:
            mode = "deny"
            reasons.append("CAPABILITY_INACTIVE")
        elif not any(_scope_allows(scope, request.scope) for scope in spec.scopes):
            mode = "deny"
            reasons.append("SCOPE_DENIED")
        elif request.lease_id is None:
            mode = spec.default_mode
            reasons.append("LEASE_REQUIRED")
        else:
            lease = self._leases(events).get(request.lease_id)
            revoked = self._revocations(events).get(request.lease_id)
            if lease is None:
                mode = "deny"
                reasons.append("UNKNOWN_LEASE")
            elif revoked is not None:
                mode = "deny"
                reasons.append("LEASE_REVOKED")
            elif _timestamp(lease.expires_at) <= _timestamp(self.store.clock()):
                mode = "deny"
                reasons.append("LEASE_EXPIRED")
            elif lease.capability != request.capability:
                mode = "deny"
                reasons.append("LEASE_CAPABILITY_MISMATCH")
            elif lease.principal_id != request.principal_id:
                mode = "deny"
                reasons.append("LEASE_PRINCIPAL_MISMATCH")
            elif not any(
                _scope_allows(scope, request.scope) for scope in lease.scopes
            ):
                mode = "deny"
                reasons.append("SCOPE_DENIED")
            else:
                action_limit = min(spec.max_actions, lease.max_actions)
                byte_limit = min(spec.max_bytes, lease.max_bytes)
                value_limit = min(
                    spec.max_value_microunits, lease.max_value_microunits
                )
                usage = self._lease_usage(events, lease.id)
                if request.requested_actions > action_limit:
                    mode = "deny"
                    reasons.append("ACTION_BUDGET_EXCEEDED")
                elif request.requested_bytes > byte_limit:
                    mode = "deny"
                    reasons.append("BYTE_BUDGET_EXCEEDED")
                elif request.requested_value_microunits > value_limit:
                    mode = "deny"
                    reasons.append("VALUE_BUDGET_EXCEEDED")
                elif usage["actions"] + request.requested_actions > action_limit:
                    mode = "deny"
                    reasons.append("LEASE_ACTION_BUDGET_EXHAUSTED")
                elif usage["bytes"] + request.requested_bytes > byte_limit:
                    mode = "deny"
                    reasons.append("LEASE_BYTE_BUDGET_EXHAUSTED")
                elif (
                    usage["value_microunits"]
                    + request.requested_value_microunits
                    > value_limit
                ):
                    mode = "deny"
                    reasons.append("LEASE_VALUE_BUDGET_EXHAUSTED")
                else:
                    mode = "allow"
                    reasons.append("ACTIVE_LEASE")
        return CapabilityDecision(
            mode=mode,
            reasons=tuple(reasons),
            capability=request.capability,
            spec_digest=spec_digest,
            lease_id=request.lease_id,
        )

    def _record_decision(
        self,
        request: CapabilityRequest,
        *,
        event_kind: str,
    ) -> CapabilityDecision:
        request_payload = request.as_payload()

        def factory(events: list[Any]) -> dict[str, Any]:
            decision = self._decision_from_events(
                events,
                request,
                require_principal_profile_digest=(
                    event_kind == "capability.request.decided"
                ),
            )
            return {
                "schema_version": 1,
                "request": request_payload,
                "decision": decision.as_payload(),
                "budget_consumed": event_kind == "capability.request.decided"
                and decision.mode == "allow",
            }

        event, created = self.store.append_once_computed(
            event_kind, request.id, factory
        )
        if not created and event.payload.get("request") != request_payload:
            raise ValueError(f"logical key collision for {event_kind}:{request.id}")
        return CapabilityDecision.from_payload(
            event.payload["decision"], event_id=event.event_id
        )

    def evaluate(self, request: CapabilityRequest) -> CapabilityDecision:
        """Evaluate current authority without spending lease budget."""

        return self._record_decision(
            request, event_kind="capability.request.evaluated"
        )

    def reserve(self, request: CapabilityRequest) -> CapabilityDecision:
        """Atomically authorize and consume cumulative lease budget when allowed."""

        return self._record_decision(
            request, event_kind="capability.request.decided"
        )

    def consume_reservation(
        self, request_id: str, *, effect_id: str
    ) -> dict[str, Any]:
        """Atomically consume one live reservation immediately before its effect."""

        request_identifier = _identifier("request id", request_id)
        effect_identifier = _identifier("effect id", effect_id)

        def factory(events: list[Any]) -> tuple[str, Mapping[str, Any]]:
            if any(
                event.kind == "capability.reservation.consumed"
                and event.payload["request_id"] == request_identifier
                for event in events
            ):
                raise PermissionError("CAPABILITY_RESERVATION_ALREADY_CONSUMED")
            reservation = next(
                (
                    event
                    for event in reversed(events)
                    if event.kind == "capability.request.decided"
                    and event.payload["request"]["id"] == request_identifier
                ),
                None,
            )
            if reservation is None or reservation.payload["decision"]["mode"] != "allow":
                raise PermissionError("ACTIVE_CAPABILITY_RESERVATION_REQUIRED")
            request = CapabilityRequest.from_payload(reservation.payload["request"])
            spec_row = self._spec_rows(events).get(request.capability)
            lease = self._leases(events).get(request.lease_id or "")
            revoked = self._revocations(events).get(request.lease_id or "")
            latest_profile = next(
                (
                    event
                    for event in reversed(events)
                    if event.kind == "principal.profile.installed"
                ),
                None,
            )
            if spec_row is None or not spec_row[0].active:
                raise PermissionError("CAPABILITY_INACTIVE")
            if reservation.payload["decision"].get("spec_digest") != spec_row[1]:
                raise PermissionError("CAPABILITY_SPEC_CHANGED")
            spec = spec_row[0]
            if lease is None:
                raise PermissionError("UNKNOWN_LEASE")
            if revoked is not None:
                raise PermissionError("LEASE_REVOKED")
            if _timestamp(lease.expires_at) <= _timestamp(self.store.clock()):
                raise PermissionError("LEASE_EXPIRED")
            if latest_profile is None:
                raise PermissionError("PRINCIPAL_PROFILE_NOT_INSTALLED")
            if (
                request.principal_profile_digest
                != latest_profile.payload.get("profile_digest")
            ):
                raise PermissionError("PRINCIPAL_PROFILE_CHANGED")
            if (
                request.principal_id
                != latest_profile.payload.get("profile", {}).get("principal_id")
            ):
                raise PermissionError("PRINCIPAL_ID_MISMATCH")
            if (
                request.intent_digest is None
                or request.intent_domain != spec.intent_domain
                or request.intent_action != spec.intent_action
            ):
                raise PermissionError("INTENT_CAPABILITY_MISMATCH")
            if not any(_scope_allows(scope, request.scope) for scope in spec.scopes):
                raise PermissionError("SCOPE_DENIED")
            if not any(_scope_allows(scope, request.scope) for scope in lease.scopes):
                raise PermissionError("SCOPE_DENIED")
            payload = {
                "schema_version": 1,
                "request_id": request_identifier,
                "effect_id": effect_identifier,
                "reservation_event_id": reservation.event_id,
                "capability": request.capability,
                "lease_id": request.lease_id,
                "principal_id": request.principal_id,
                "principal_profile_digest": request.principal_profile_digest,
                "intent_digest": request.intent_digest,
                "intent_domain": request.intent_domain,
                "intent_action": request.intent_action,
            }
            return request_identifier, payload

        event, created = self.store.append_computed_once(
            "capability.reservation.consumed", factory
        )
        if not created:
            raise PermissionError("CAPABILITY_RESERVATION_ALREADY_CONSUMED")
        return {**event.payload, "event_id": event.event_id}

    def status(self) -> dict[str, Any]:
        events = self.store.events()
        specs = self._spec_rows(events)
        leases = self._leases(events)
        revocations = self._revocations(events)
        return {
            "specifications": {
                name: {
                    **spec.as_payload(),
                    "spec_digest": digest,
                    "revision": revision,
                }
                for name, (spec, digest, revision) in sorted(specs.items())
            },
            "leases": {
                lease_id: {
                    **lease.as_payload(),
                    "revoked": lease_id in revocations,
                    "expired": _timestamp(lease.expires_at)
                    <= _timestamp(self.store.clock()),
                    "used": self._lease_usage(events, lease_id),
                    "remaining": {
                        "actions": max(
                            0,
                            min(specs[lease.capability][0].max_actions, lease.max_actions)
                            - self._lease_usage(events, lease_id)["actions"],
                        ),
                        "bytes": max(
                            0,
                            min(specs[lease.capability][0].max_bytes, lease.max_bytes)
                            - self._lease_usage(events, lease_id)["bytes"],
                        ),
                        "value_microunits": max(
                            0,
                            min(
                                specs[lease.capability][0].max_value_microunits,
                                lease.max_value_microunits,
                            )
                            - self._lease_usage(events, lease_id)["value_microunits"],
                        ),
                    },
                }
                for lease_id, lease in sorted(leases.items())
            },
            "evaluation_count": len(
                [event for event in events if event.kind == "capability.request.evaluated"]
            ),
            "reservation_count": len(
                [event for event in events if event.kind == "capability.request.decided"]
            ),
            "consumption_count": len(
                [
                    event
                    for event in events
                    if event.kind == "capability.reservation.consumed"
                ]
            ),
            "self_grant_enabled": False,
        }


class WorkspaceInspector:
    """Read one UTF-8 file through principal and capability gates."""

    def __init__(
        self,
        store: EventStore,
        principal: Any,
        registry: CapabilityRegistry,
        workspace_root: str | Path,
    ) -> None:
        self.store = store
        self.principal = principal
        self.registry = registry
        raw_root = Path(workspace_root)
        if raw_root.is_symlink() or not raw_root.is_dir():
            raise ValueError("inspection root must be an existing non-symlink directory")
        self.workspace_root = raw_root.resolve(strict=True)
        flags_directory = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        self._root_fd = os.open(self.workspace_root, flags_directory)
        root_stat = os.fstat(self._root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            os.close(self._root_fd)
            raise ValueError("inspection root must be a directory")
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        try:
            self.store.append_once(
                "workspace.inspection.root.bound",
                "workspace.inspect",
                {
                    "schema_version": 1,
                    "capability": "workspace.inspect",
                    "resolved_path": str(self.workspace_root),
                    "device": int(root_stat.st_dev),
                    "inode": int(root_stat.st_ino),
                },
            )
        except Exception:
            os.close(self._root_fd)
            self._root_fd = -1
            raise

    def close(self) -> None:
        descriptor = getattr(self, "_root_fd", -1)
        if descriptor >= 0:
            os.close(descriptor)
            self._root_fd = -1

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _parts(self, relative_path: str) -> tuple[str, ...]:
        normalized = _normalize_scope(relative_path)
        if normalized in {"*", "."} or normalized.endswith("/**"):
            raise ValueError("inspection path must name one file")
        parts = PurePosixPath(normalized).parts
        lowered = [part.lower() for part in parts]
        if any(
            part in SENSITIVE_PARTS
            or any(token in part for token in SENSITIVE_PARTS if not token.startswith("."))
            for part in lowered
        ):
            raise PermissionError("inspection path belongs to a sensitive class")
        return parts

    def _open(self, parts: tuple[str, ...]) -> tuple[int, os.stat_result]:
        if self._root_fd < 0:
            raise OSError("inspection root descriptor is closed")
        root_stat = os.fstat(self._root_fd)
        if (root_stat.st_dev, root_stat.st_ino) != self._root_identity:
            raise OSError("inspection root identity changed")
        flags_directory = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        current = os.dup(self._root_fd)
        opened = [current]
        try:
            for part in parts[:-1]:
                current = os.open(part, flags_directory, dir_fd=current)
                opened.append(current)
            target = os.open(
                parts[-1],
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=current,
            )
            opened.append(target)
            target_stat = os.fstat(target)
            if not stat.S_ISREG(target_stat.st_mode) or target_stat.st_nlink != 1:
                raise ValueError("inspection target must be a regular single-link file")
            for descriptor in opened[:-1]:
                os.close(descriptor)
            return target, target_stat
        except Exception:
            for descriptor in reversed(opened):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise

    @staticmethod
    def _taint_flags(content: str) -> tuple[str, ...]:
        lowered = content.casefold()
        patterns = {
            "PROMPT_OVERRIDE_LANGUAGE": (
                "ignore previous",
                "ignore all previous",
                "disregard previous",
            ),
            "ROLE_IMPERSONATION_LANGUAGE": (
                "system message",
                "developer message",
                "you are chatgpt",
            ),
            "TOOL_INSTRUCTION_LANGUAGE": (
                "execute the following",
                "run this command",
                "tool call",
            ),
            "SECRET_EXTRACTION_LANGUAGE": (
                "reveal your secret",
                "send the secret",
                "print the password",
            ),
        }
        return tuple(
            name
            for name, needles in patterns.items()
            if any(needle in lowered for needle in needles)
        )

    def _record_failure(
        self,
        *,
        request: CapabilityRequest,
        authorization: Any,
        principal_id: str,
        lease_id: str,
        scope: str,
        reason_code: str,
        consumption_event_id: str | None = None,
    ) -> None:
        failure = {
            "schema_version": 1,
            "request_id": request.id,
            "authorization_event_id": authorization.event_id,
            "consumption_event_id": consumption_event_id,
            "principal_id": principal_id,
            "lease_id": lease_id,
            "relative_path": scope,
            "reason_code": reason_code,
            "content_persisted": False,
        }
        self.store.append_once("workspace.inspection.failed", request.id, failure)

    def inspect(
        self,
        *,
        principal_id: str,
        lease_id: str,
        relative_path: str,
        intent_id: str,
        request_id: str,
        authorization_id: str,
        maximum_bytes: int = 8_192,
    ) -> dict[str, Any]:
        maximum_bytes = _integer("maximum_bytes", maximum_bytes, minimum=1)
        if maximum_bytes > 1_048_576:
            raise ValueError("maximum_bytes must not exceed 1048576")
        parts = self._parts(relative_path)
        scope = PurePosixPath(*parts).as_posix()
        intent = PrincipalIntent(
            id=intent_id,
            domain="workspace",
            action="inspect",
            tags=("read-only",),
            value_impacts={"truth": 0.8, "competence": 0.5, "autonomy": 0.3},
            uncertainty=0.05,
            reversible=True,
            external_effect=False,
        )
        request = CapabilityRequest(
            id=request_id,
            capability="workspace.inspect",
            principal_id=principal_id,
            scope=scope,
            lease_id=lease_id,
            requested_actions=1,
            requested_bytes=maximum_bytes,
            requested_value_microunits=0,
        )
        authorization = PersonalAgency(
            self.store, self.principal, self.registry
        ).authorize(
            intent=intent,
            request=request,
            authorization_id=authorization_id,
        )
        if authorization.mode != "allow":
            raise PermissionError(
                "workspace inspection was not authorized: "
                + ",".join(authorization.reasons)
            )

        try:
            descriptor, target_stat = self._open(parts)
        except (OSError, ValueError):
            self._record_failure(
                request=request,
                authorization=authorization,
                principal_id=principal_id,
                lease_id=lease_id,
                scope=scope,
                reason_code="PATH_OPEN_FAILED",
            )
            raise
        try:
            if target_stat.st_size > maximum_bytes:
                self._record_failure(
                    request=request,
                    authorization=authorization,
                    principal_id=principal_id,
                    lease_id=lease_id,
                    scope=scope,
                    reason_code="BYTE_BUDGET_EXCEEDED_BEFORE_READ",
                )
                raise ValueError("inspection target exceeds byte budget")
            consumption = self.registry.consume_reservation(
                request.id, effect_id=authorization_id
            )
            try:
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    content_bytes = stream.read(maximum_bytes + 1)
                if len(content_bytes) > maximum_bytes:
                    raise ValueError("inspection target exceeds byte budget")
                try:
                    content = content_bytes.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise ValueError(
                        "inspection target must contain valid UTF-8"
                    ) from error
                after_stat = os.fstat(descriptor)
                if (
                    after_stat.st_dev != target_stat.st_dev
                    or after_stat.st_ino != target_stat.st_ino
                    or after_stat.st_size != target_stat.st_size
                    or after_stat.st_mtime_ns != target_stat.st_mtime_ns
                ):
                    raise ValueError("inspection target changed during read")
            except (OSError, ValueError) as error:
                message = str(error)
                if "UTF-8" in message:
                    reason_code = "INVALID_UTF8"
                elif "changed during read" in message:
                    reason_code = "TARGET_CHANGED_DURING_READ"
                elif "byte budget" in message:
                    reason_code = "BYTE_BUDGET_EXCEEDED_DURING_READ"
                else:
                    reason_code = "READ_FAILED"
                self._record_failure(
                    request=request,
                    authorization=authorization,
                    principal_id=principal_id,
                    lease_id=lease_id,
                    scope=scope,
                    reason_code=reason_code,
                    consumption_event_id=consumption["event_id"],
                )
                raise
            digest = sha256(content_bytes).hexdigest()
            taint_flags = self._taint_flags(content)
            payload = {
                "schema_version": 1,
                "request_id": request.id,
                "authorization_event_id": authorization.event_id,
                "consumption_event_id": consumption["event_id"],
                "principal_id": principal_id,
                "lease_id": lease_id,
                "relative_path": scope,
                "bytes": len(content_bytes),
                "sha256": digest,
                "device": int(target_stat.st_dev),
                "inode": int(target_stat.st_ino),
                "content_persisted": False,
                "content_trust": "untrusted_workspace_content",
                "instructions_authorized": False,
                "taint_flags": list(taint_flags),
            }
            event = self.store.append_once(
                "workspace.inspection.completed", request.id, payload
            )
            return {
                **payload,
                "content": content,
                "event_id": event.event_id,
                "authorization": authorization.as_payload(),
            }
        finally:
            os.close(descriptor)
