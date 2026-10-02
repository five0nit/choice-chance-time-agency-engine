"""Host-issued, single-use execution tickets with atomic lease budgets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any, Mapping

from .capabilities import (
    CapabilityRegistry,
    _scope_allows,
    lease_usage_from_events,
)
from .store import Event, EventStore, canonical_json


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_TOOL_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class TicketAuthorityDenied(PermissionError):
    """Fail-closed execution-ticket rejection with a stable reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


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


def _identifier(name: str, value: Any, *, tool: bool = False) -> str:
    pattern = _TOOL_IDENTIFIER if tool else _IDENTIFIER
    if not isinstance(value, str) or not pattern.fullmatch(value):
        maximum = 128 if tool else 160
        raise ValueError(f"{name} must be a 1-{maximum} character identifier")
    return value


def _digest(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a SHA-256 digest")
    return value


def _integer(name: str, value: Any, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _timestamp(name: str, value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{name} must be ISO-8601") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed


def _authority(value: Any) -> str:
    if value not in {"operator", "host_adapter"}:
        raise ValueError("authority must be operator or host_adapter")
    return str(value)


def _bounded_text(name: str, value: Any, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{name} must be 1-{maximum} printable characters")
    return value.strip()


def _kill_switch_status(events: list[Event]) -> dict[str, Any]:
    active_trip: Event | None = None
    latest_transition: Event | None = None
    for event in events:
        if event.kind == "operator.kill_switch.tripped":
            active_trip = event
            latest_transition = event
        elif event.kind == "operator.kill_switch.cleared":
            if (
                active_trip is not None
                and event.payload.get("active_trip_event_id") == active_trip.event_id
            ):
                active_trip = None
                latest_transition = event
    return {
        "active": active_trip is not None,
        "active_trip_event_id": active_trip.event_id if active_trip else None,
        "active_trip_id": (
            active_trip.payload.get("trip_id") if active_trip is not None else None
        ),
        "latest_transition_event_id": (
            latest_transition.event_id if latest_transition is not None else None
        ),
        "model_clear_enabled": False,
    }


class GlobalKillSwitch:
    """Durable host/operator emergency stop shared by every operator effect."""

    def __init__(self, store: EventStore) -> None:
        self.store = store

    @staticmethod
    def ensure_clear(events: list[Event]) -> None:
        if _kill_switch_status(events)["active"]:
            raise TicketAuthorityDenied("GLOBAL_KILL_SWITCH_ACTIVE")

    def status(self) -> dict[str, Any]:
        return _kill_switch_status(self.store.events())

    def trip(
        self,
        *,
        trip_id: str,
        authority: str,
        reason: str,
    ) -> dict[str, Any]:
        identifier = _identifier("trip id", trip_id)
        payload = {
            "schema_version": 1,
            "trip_id": identifier,
            "authority": _authority(authority),
            "reason": _bounded_text("kill-switch reason", reason, maximum=600),
            "active": True,
            "model_clear_enabled": False,
        }
        event, created = self.store.append_once_result(
            "operator.kill_switch.tripped", identifier, payload
        )
        if canonical_json(event.payload) != canonical_json(payload):
            raise ValueError(
                f"logical key collision for operator.kill_switch.tripped:{identifier}"
            )
        return {
            **event.payload,
            **self.status(),
            "event_id": event.event_id,
            "created": created,
        }

    def clear(
        self,
        *,
        clear_id: str,
        authority: str,
        active_trip_event_id: str,
        evidence: str,
    ) -> dict[str, Any]:
        identifier = _identifier("clear id", clear_id)
        source = _authority(authority)
        trip_event_id = _identifier("active trip event id", active_trip_event_id)
        payload = {
            "schema_version": 1,
            "clear_id": identifier,
            "authority": source,
            "active_trip_event_id": trip_event_id,
            "evidence": _bounded_text("kill-switch clear evidence", evidence, maximum=600),
            "active": False,
            "model_clear_enabled": False,
        }

        def factory(events: list[Event]) -> Mapping[str, Any]:
            status = _kill_switch_status(events)
            if not status["active"]:
                raise TicketAuthorityDenied("KILL_SWITCH_NOT_ACTIVE")
            if status["active_trip_event_id"] != trip_event_id:
                raise TicketAuthorityDenied("KILL_SWITCH_STATE_CHANGED")
            return payload

        event, created = self.store.append_once_computed(
            "operator.kill_switch.cleared",
            identifier,
            factory,
        )
        if canonical_json(event.payload) != canonical_json(payload):
            raise ValueError(
                f"logical key collision for operator.kill_switch.cleared:{identifier}"
            )
        return {
            **event.payload,
            **self.status(),
            "event_id": event.event_id,
            "created": created,
        }

    def checkpoint(
        self,
        *,
        checkpoint_id: str,
        effect_id: str,
        step: str,
    ) -> dict[str, Any]:
        """Record one atomic clear check between separately mediated effect legs."""

        identifier = _identifier("checkpoint id", checkpoint_id)
        payload = {
            "schema_version": 1,
            "checkpoint_id": identifier,
            "effect_id": _identifier("effect id", effect_id),
            "step": _identifier("effect step", step),
            "clear": True,
        }

        def factory(events: list[Event]) -> tuple[str, Mapping[str, Any]]:
            self.ensure_clear(events)
            return identifier, payload

        event, created = self.store.append_computed_once(
            "operator.kill_switch.checkpoint", factory
        )
        return {**event.payload, "event_id": event.event_id, "created": created}


@dataclass(frozen=True, slots=True)
class ExecutionTicket:
    """One immutable host-issued authority envelope for one exact invocation."""

    id: str
    tool_name: str
    arguments_sha256: str
    goal_id: str
    plan_id: str
    plan_hash: str
    stage: str
    attempt: int
    principal_id: str
    principal_profile_digest: str
    capability: str
    capability_spec_digest: str
    lease_id: str
    scope: str
    expires_at: str
    action_budget: int
    byte_budget: int
    value_budget_microunits: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("ticket id", self.id))
        object.__setattr__(
            self,
            "tool_name",
            _identifier("tool_name", self.tool_name, tool=True),
        )
        object.__setattr__(
            self,
            "arguments_sha256",
            _digest("arguments_sha256", self.arguments_sha256),
        )
        object.__setattr__(self, "goal_id", _identifier("goal_id", self.goal_id))
        object.__setattr__(self, "plan_id", _identifier("plan_id", self.plan_id))
        object.__setattr__(self, "plan_hash", _digest("plan_hash", self.plan_hash))
        object.__setattr__(self, "stage", _identifier("stage", self.stage))
        _integer("attempt", self.attempt, minimum=1)
        object.__setattr__(
            self,
            "principal_id",
            _identifier("principal_id", self.principal_id),
        )
        object.__setattr__(
            self,
            "principal_profile_digest",
            _digest("principal_profile_digest", self.principal_profile_digest),
        )
        object.__setattr__(
            self,
            "capability",
            _identifier("capability", self.capability),
        )
        object.__setattr__(
            self,
            "capability_spec_digest",
            _digest("capability_spec_digest", self.capability_spec_digest),
        )
        object.__setattr__(self, "lease_id", _identifier("lease_id", self.lease_id))
        if not isinstance(self.scope, str):
            raise ValueError("scope must be a string")
        normalized_scope = self.scope.strip()
        if (
            not normalized_scope
            or len(normalized_scope) > 512
            or "\\" in normalized_scope
            or normalized_scope.startswith("/")
            or any(part in {"", ".", ".."} for part in normalized_scope.split("/"))
        ):
            raise ValueError("scope must be a normalized POSIX-relative path")
        object.__setattr__(self, "scope", normalized_scope)
        _timestamp("expires_at", self.expires_at)
        _integer("action_budget", self.action_budget, minimum=1)
        _integer("byte_budget", self.byte_budget)
        _integer("value_budget_microunits", self.value_budget_microunits)

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tool_name": self.tool_name,
            "arguments_sha256": self.arguments_sha256,
            "goal_id": self.goal_id,
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "stage": self.stage,
            "attempt": self.attempt,
            "principal_id": self.principal_id,
            "principal_profile_digest": self.principal_profile_digest,
            "capability": self.capability,
            "capability_spec_digest": self.capability_spec_digest,
            "lease_id": self.lease_id,
            "scope": self.scope,
            "expires_at": self.expires_at,
            "action_budget": self.action_budget,
            "byte_budget": self.byte_budget,
            "value_budget_microunits": self.value_budget_microunits,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ExecutionTicket":
        fields = {
            "id",
            "tool_name",
            "arguments_sha256",
            "goal_id",
            "plan_id",
            "plan_hash",
            "stage",
            "attempt",
            "principal_id",
            "principal_profile_digest",
            "capability",
            "capability_spec_digest",
            "lease_id",
            "scope",
            "expires_at",
            "action_budget",
            "byte_budget",
            "value_budget_microunits",
        }
        _strict_keys(
            payload,
            allowed=fields,
            required=fields,
            name="execution ticket",
        )
        return cls(
            id=payload["id"],
            tool_name=payload["tool_name"],
            arguments_sha256=payload["arguments_sha256"],
            goal_id=payload["goal_id"],
            plan_id=payload["plan_id"],
            plan_hash=payload["plan_hash"],
            stage=payload["stage"],
            attempt=_integer("attempt", payload["attempt"], minimum=1),
            principal_id=payload["principal_id"],
            principal_profile_digest=payload["principal_profile_digest"],
            capability=payload["capability"],
            capability_spec_digest=payload["capability_spec_digest"],
            lease_id=payload["lease_id"],
            scope=payload["scope"],
            expires_at=payload["expires_at"],
            action_budget=_integer(
                "action_budget", payload["action_budget"], minimum=1
            ),
            byte_budget=_integer("byte_budget", payload["byte_budget"]),
            value_budget_microunits=_integer(
                "value_budget_microunits",
                payload["value_budget_microunits"],
            ),
        )


class ExecutionTicketAuthority:
    """Issue, revoke, validate, and consume execution tickets transactionally."""

    def __init__(self, store: EventStore) -> None:
        self.store = store
        self.capabilities = CapabilityRegistry(store)

    @staticmethod
    def _issued_event(events: list[Event], ticket_id: str) -> Event | None:
        return next(
            (
                event
                for event in reversed(events)
                if event.kind == "execution.ticket.issued"
                and event.payload.get("ticket", {}).get("id") == ticket_id
            ),
            None,
        )

    @staticmethod
    def _revoked(events: list[Event], ticket_id: str) -> bool:
        return any(
            event.kind == "execution.ticket.revoked"
            and event.payload.get("ticket_id") == ticket_id
            for event in events
        )

    @staticmethod
    def _consumed(events: list[Event], ticket_id: str) -> bool:
        return any(
            event.kind == "execution.ticket.consumed"
            and event.payload.get("ticket_id") == ticket_id
            for event in events
        )

    @staticmethod
    def _latest_profile(events: list[Event]) -> Event | None:
        return next(
            (
                event
                for event in reversed(events)
                if event.kind == "principal.profile.installed"
            ),
            None,
        )

    def _validate_live(self, ticket: ExecutionTicket, events: list[Event]) -> None:
        GlobalKillSwitch.ensure_clear(events)
        if _timestamp("expires_at", ticket.expires_at) <= _timestamp(
            "current time", self.store.clock()
        ):
            raise TicketAuthorityDenied("TICKET_EXPIRED")
        profile = self._latest_profile(events)
        if profile is None:
            raise TicketAuthorityDenied("PRINCIPAL_PROFILE_NOT_INSTALLED")
        if profile.payload.get("profile_digest") != ticket.principal_profile_digest:
            raise TicketAuthorityDenied("PRINCIPAL_PROFILE_CHANGED")
        if profile.payload.get("profile", {}).get("principal_id") != ticket.principal_id:
            raise TicketAuthorityDenied("PRINCIPAL_ID_MISMATCH")

        spec_row = self.capabilities._spec_rows(events).get(ticket.capability)
        if spec_row is None:
            raise TicketAuthorityDenied("UNKNOWN_CAPABILITY")
        spec, spec_digest, _revision = spec_row
        if not spec.active:
            raise TicketAuthorityDenied("CAPABILITY_INACTIVE")
        administrative = self.capabilities._administrative_states(events).get(
            ticket.capability
        )
        if administrative is not None and administrative["active"] is not True:
            raise TicketAuthorityDenied("CAPABILITY_ADMINISTRATIVELY_PAUSED")
        if spec_digest != ticket.capability_spec_digest:
            raise TicketAuthorityDenied("CAPABILITY_SPEC_CHANGED")
        lease = self.capabilities._leases(events).get(ticket.lease_id)
        if lease is None:
            raise TicketAuthorityDenied("UNKNOWN_LEASE")
        if self.capabilities._revocations(events).get(ticket.lease_id) is not None:
            raise TicketAuthorityDenied("LEASE_REVOKED")
        if _timestamp("lease expires_at", lease.expires_at) <= _timestamp(
            "current time", self.store.clock()
        ):
            raise TicketAuthorityDenied("LEASE_EXPIRED")
        if lease.capability != ticket.capability:
            raise TicketAuthorityDenied("LEASE_CAPABILITY_MISMATCH")
        if lease.principal_id != ticket.principal_id:
            raise TicketAuthorityDenied("LEASE_PRINCIPAL_MISMATCH")
        if not any(_scope_allows(scope, ticket.scope) for scope in spec.scopes):
            raise TicketAuthorityDenied("SCOPE_DENIED")
        if not any(_scope_allows(scope, ticket.scope) for scope in lease.scopes):
            raise TicketAuthorityDenied("SCOPE_DENIED")

        action_limit = min(spec.max_actions, lease.max_actions)
        byte_limit = min(spec.max_bytes, lease.max_bytes)
        value_limit = min(
            spec.max_value_microunits,
            lease.max_value_microunits,
        )
        if ticket.action_budget > action_limit:
            raise TicketAuthorityDenied("ACTION_BUDGET_EXCEEDED")
        if ticket.byte_budget > byte_limit:
            raise TicketAuthorityDenied("BYTE_BUDGET_EXCEEDED")
        if ticket.value_budget_microunits > value_limit:
            raise TicketAuthorityDenied("VALUE_BUDGET_EXCEEDED")

    def issue(
        self,
        ticket: ExecutionTicket,
        *,
        authority: str,
        evidence: tuple[str, ...] | list[str],
    ) -> dict[str, Any]:
        source = _authority(authority)
        if not isinstance(evidence, (tuple, list)):
            raise ValueError("ticket evidence must be an array")
        evidence_rows = tuple(
            _bounded_text("ticket evidence", item, maximum=600) for item in evidence
        )
        if not evidence_rows:
            raise ValueError("ticket issuance requires evidence")
        payload = {
            "schema_version": 1,
            "authority": source,
            "evidence": list(evidence_rows),
            "ticket": ticket.as_payload(),
            "raw_arguments_persisted": False,
            "credentials_persisted": False,
        }

        def factory(events: list[Event]) -> Mapping[str, Any]:
            try:
                self._validate_live(ticket, events)
            except TicketAuthorityDenied as error:
                raise ValueError(error.reason_code) from error
            lease = self.capabilities._leases(events)[ticket.lease_id]
            if _timestamp("expires_at", ticket.expires_at) > _timestamp(
                "lease expires_at", lease.expires_at
            ):
                raise ValueError("ticket expiry exceeds lease expiry")
            return payload

        event, created = self.store.append_once_computed(
            "execution.ticket.issued",
            ticket.id,
            factory,
        )
        if canonical_json(event.payload) != canonical_json(payload):
            raise ValueError(
                f"logical key collision for execution.ticket.issued:{ticket.id}"
            )
        return {**event.payload, "event_id": event.event_id, "created": created}

    def revoke(
        self,
        ticket_id: str,
        *,
        authority: str,
        reason: str,
    ) -> dict[str, Any]:
        identifier = _identifier("ticket id", ticket_id)
        payload = {
            "schema_version": 1,
            "ticket_id": identifier,
            "authority": _authority(authority),
            "reason": _bounded_text("revocation reason", reason, maximum=600),
        }

        def factory(events: list[Event]) -> Mapping[str, Any]:
            if self._issued_event(events, identifier) is None:
                raise KeyError(f"unknown execution ticket: {identifier}")
            return payload

        event, created = self.store.append_once_computed(
            "execution.ticket.revoked",
            identifier,
            factory,
        )
        if canonical_json(event.payload) != canonical_json(payload):
            raise ValueError(
                f"logical key collision for execution.ticket.revoked:{identifier}"
            )
        return {**event.payload, "event_id": event.event_id, "created": created}

    def claim_dispatch(
        self,
        *,
        ticket_id: str,
        tool_name: str,
        arguments_sha256: str,
        registered_verifier_ids: frozenset[str] | None = None,
    ) -> dict[str, Any]:
        """Atomically reserve authority and create one durable pre-dispatch claim.

        Exact retries return the original claim with ``created=False`` so the
        middleware can reconcile an outcome without executing the effect again.
        ``consume`` retains the public single-use rejection contract.
        """

        identifier = _identifier("ticket id", ticket_id)
        invoked_tool = _identifier("tool_name", tool_name, tool=True)
        invoked_arguments_digest = _digest("arguments_sha256", arguments_sha256)
        if registered_verifier_ids is not None:
            if not isinstance(registered_verifier_ids, frozenset):
                raise ValueError("registered_verifier_ids must be a frozenset")
            for verifier_id in registered_verifier_ids:
                _identifier("registered verifier id", verifier_id)

        def factory(events: list[Event]) -> Mapping[str, Any]:
            GlobalKillSwitch.ensure_clear(events)
            issuance = self._issued_event(events, identifier)
            if issuance is None:
                raise TicketAuthorityDenied("UNKNOWN_TICKET")
            if self._revoked(events, identifier):
                raise TicketAuthorityDenied("TICKET_REVOKED")
            raw_ticket = issuance.payload.get("ticket")
            if not isinstance(raw_ticket, Mapping):
                raise TicketAuthorityDenied("MALFORMED_TICKET")
            try:
                issued_ticket = ExecutionTicket.from_payload(raw_ticket)
            except (TypeError, ValueError) as error:
                raise TicketAuthorityDenied("MALFORMED_TICKET") from error
            if issued_ticket.tool_name != invoked_tool:
                raise TicketAuthorityDenied("TICKET_TOOL_MISMATCH")
            if issued_ticket.arguments_sha256 != invoked_arguments_digest:
                raise TicketAuthorityDenied("TICKET_ARGUMENTS_MISMATCH")
            self._validate_live(issued_ticket, events)

            spec = self.capabilities._spec_rows(events)[issued_ticket.capability][0]
            if (
                registered_verifier_ids is not None
                and spec.verifier_id not in registered_verifier_ids
            ):
                raise TicketAuthorityDenied("VERIFIER_NOT_REGISTERED")
            lease = self.capabilities._leases(events)[issued_ticket.lease_id]
            usage = lease_usage_from_events(events, issued_ticket.lease_id)
            action_limit = min(spec.max_actions, lease.max_actions)
            byte_limit = min(spec.max_bytes, lease.max_bytes)
            value_limit = min(
                spec.max_value_microunits,
                lease.max_value_microunits,
            )
            if usage["actions"] + issued_ticket.action_budget > action_limit:
                raise TicketAuthorityDenied("LEASE_ACTION_BUDGET_EXHAUSTED")
            if usage["bytes"] + issued_ticket.byte_budget > byte_limit:
                raise TicketAuthorityDenied("LEASE_BYTE_BUDGET_EXHAUSTED")
            if (
                usage["value_microunits"]
                + issued_ticket.value_budget_microunits
                > value_limit
            ):
                raise TicketAuthorityDenied("LEASE_VALUE_BUDGET_EXHAUSTED")

            return {
                "schema_version": 1,
                "ticket_id": issued_ticket.id,
                "issuance_event_id": issuance.event_id,
                "tool_name": issued_ticket.tool_name,
                "arguments_sha256": issued_ticket.arguments_sha256,
                "goal_id": issued_ticket.goal_id,
                "plan_id": issued_ticket.plan_id,
                "plan_hash": issued_ticket.plan_hash,
                "stage": issued_ticket.stage,
                "attempt": issued_ticket.attempt,
                "principal_id": issued_ticket.principal_id,
                "principal_profile_digest": issued_ticket.principal_profile_digest,
                "capability": issued_ticket.capability,
                "capability_spec_digest": issued_ticket.capability_spec_digest,
                "lease_id": issued_ticket.lease_id,
                "scope": issued_ticket.scope,
                "verifier_id": spec.verifier_id,
                "idempotency_key": issued_ticket.id,
                "action_budget": issued_ticket.action_budget,
                "byte_budget": issued_ticket.byte_budget,
                "value_budget_microunits": issued_ticket.value_budget_microunits,
                "budget_reserved": True,
                "ticket_consumed": True,
                "dispatch_claimed": True,
                "downstream_called": False,
                "effect_retry_permitted": False,
                "raw_arguments_persisted": False,
                "credentials_persisted": False,
            }

        event, created = self.store.append_once_computed(
            "execution.ticket.consumed",
            identifier,
            factory,
        )
        payload = event.payload
        if (
            payload.get("ticket_id") != identifier
            or payload.get("tool_name") != invoked_tool
            or payload.get("arguments_sha256") != invoked_arguments_digest
            or payload.get("dispatch_claimed") is not True
            or payload.get("idempotency_key") != identifier
            or not isinstance(payload.get("verifier_id"), str)
        ):
            raise TicketAuthorityDenied("MALFORMED_DISPATCH_CLAIM")
        if (
            registered_verifier_ids is not None
            and payload["verifier_id"] not in registered_verifier_ids
        ):
            raise TicketAuthorityDenied("VERIFIER_NOT_REGISTERED")
        return {
            **payload,
            "event_id": event.event_id,
            "created": created,
        }

    def consume(
        self,
        *,
        ticket_id: str,
        tool_name: str,
        arguments_sha256: str,
    ) -> dict[str, Any]:
        claim = self.claim_dispatch(
            ticket_id=ticket_id,
            tool_name=tool_name,
            arguments_sha256=arguments_sha256,
        )
        if not claim["created"]:
            raise TicketAuthorityDenied("TICKET_REPLAYED")
        return {key: value for key, value in claim.items() if key != "created"}
