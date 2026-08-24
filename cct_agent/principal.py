"""Operator-principal covenant and structured intent evaluation.

The principal model lets CCT act as an extension of a named operator without
confusing preference alignment with effect authority. Profiles can only be
installed by an operator or host adapter. Model-created revisions remain
proposals until externally endorsed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from math import isfinite
import re
from typing import Any, Literal, Mapping

from .store import EventStore, canonical_json


DirectiveKind = Literal["preference", "priority", "boundary", "escalation", "grant"]
DecisionMode = Literal["deny", "require_approval", "allow"]
AuthoritySource = Literal["operator", "host_adapter"]
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,79}$")


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


def _tags(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    rows = tuple(sorted({_text("tag", value, maximum=80) for value in values}))
    if len(rows) > 32 or any(not _TAG.fullmatch(row) for row in rows):
        raise ValueError("tags must be bounded normalized identifiers")
    return rows


def _authority(value: str) -> AuthoritySource:
    if value not in {"operator", "host_adapter"}:
        raise ValueError("authority must be operator or host_adapter")
    return value  # type: ignore[return-value]


def _unit(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    numeric = float(value)
    if not isfinite(numeric) or not 0.0 <= numeric <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")
    return numeric


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


@dataclass(frozen=True, slots=True)
class PrincipalDirective:
    id: str
    kind: DirectiveKind
    statement: str
    tags: tuple[str, ...]
    priority: int = 50

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("directive id", self.id))
        if self.kind not in {
            "preference",
            "priority",
            "boundary",
            "escalation",
            "grant",
        }:
            raise ValueError("invalid principal directive kind")
        object.__setattr__(
            self,
            "statement",
            _text("directive statement", self.statement, maximum=1200),
        )
        object.__setattr__(self, "tags", _tags(self.tags))
        if not self.tags:
            raise ValueError("principal directive requires tags")
        if isinstance(self.priority, bool) or not isinstance(self.priority, int):
            raise ValueError("directive priority must be an integer")
        if not 1 <= self.priority <= 100:
            raise ValueError("directive priority must be between 1 and 100")

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "statement": self.statement,
            "tags": list(self.tags),
            "priority": int(self.priority),
        }


@dataclass(frozen=True, slots=True)
class PrincipalProfile:
    principal_id: str
    display_name: str
    values: Mapping[str, float]
    directives: tuple[PrincipalDirective, ...]
    uncertainty_threshold: float = 0.4

    def __post_init__(self) -> None:
        object.__setattr__(self, "principal_id", _identifier("principal id", self.principal_id))
        object.__setattr__(
            self,
            "display_name",
            _text("principal display name", self.display_name, maximum=160),
        )
        if not self.values:
            raise ValueError("principal profile requires values")
        normalized_values: dict[str, float] = {}
        for name, weight in self.values.items():
            key = _text("principal value name", str(name), maximum=80)
            if isinstance(weight, bool) or not isinstance(weight, (int, float)):
                raise ValueError("principal value weights must be numeric")
            numeric = float(weight)
            if not isfinite(numeric) or numeric < 0.0:
                raise ValueError("principal value weights must be finite and non-negative")
            normalized_values[key] = numeric
        if not any(weight > 0.0 for weight in normalized_values.values()):
            raise ValueError("principal profile requires a positive value weight")
        object.__setattr__(self, "values", normalized_values)
        if not self.directives:
            raise ValueError("principal profile requires directives")
        identifiers = [directive.id for directive in self.directives]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("principal directive ids must be unique")
        object.__setattr__(
            self,
            "directives",
            tuple(sorted(self.directives, key=lambda item: (-item.priority, item.id))),
        )
        object.__setattr__(
            self,
            "uncertainty_threshold",
            _unit("uncertainty_threshold", self.uncertainty_threshold),
        )

    def as_payload(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "display_name": self.display_name,
            "values": {name: self.values[name] for name in sorted(self.values)},
            "directives": [directive.as_payload() for directive in self.directives],
            "uncertainty_threshold": self.uncertainty_threshold,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PrincipalProfile":
        _strict_keys(
            payload,
            allowed={
                "principal_id",
                "display_name",
                "values",
                "directives",
                "uncertainty_threshold",
            },
            required={
                "principal_id",
                "display_name",
                "values",
                "directives",
            },
            name="principal profile",
        )
        directive_rows = payload["directives"]
        value_rows = payload["values"]
        if not isinstance(value_rows, Mapping):
            raise ValueError("principal profile values must be an object")
        if not isinstance(directive_rows, list):
            raise ValueError("principal profile directives must be an array")
        for row in directive_rows:
            if not isinstance(row, Mapping):
                raise ValueError("principal directive must be an object")
            _strict_keys(
                row,
                allowed={"id", "kind", "statement", "tags", "priority"},
                required={"id", "kind", "statement", "tags"},
                name="principal directive",
            )
            if not isinstance(row["tags"], list):
                raise ValueError("principal directive tags must be an array")
        return cls(
            principal_id=payload["principal_id"],
            display_name=payload["display_name"],
            values={key: value for key, value in value_rows.items()},
            directives=tuple(
                PrincipalDirective(
                    id=row["id"],
                    kind=row["kind"],
                    statement=row["statement"],
                    tags=tuple(row["tags"]),
                    priority=row.get("priority", 50),
                )
                for row in directive_rows
            ),
            uncertainty_threshold=payload.get("uncertainty_threshold", 0.4),
        )


@dataclass(frozen=True, slots=True)
class PrincipalIntent:
    id: str
    domain: str
    action: str
    tags: tuple[str, ...]
    value_impacts: Mapping[str, float]
    uncertainty: float = 0.0
    reversible: bool = True
    external_effect: bool = False
    credential_use: bool = False
    financial_value_microunits: int = 0
    constitution_change: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("intent id", self.id))
        object.__setattr__(self, "domain", _identifier("intent domain", self.domain))
        object.__setattr__(self, "action", _identifier("intent action", self.action))
        object.__setattr__(self, "tags", _tags(self.tags))
        impacts: dict[str, float] = {}
        for name, impact in self.value_impacts.items():
            key = _text("value impact name", str(name), maximum=80)
            if isinstance(impact, bool) or not isinstance(impact, (int, float)):
                raise ValueError("principal value impacts must be numeric")
            numeric = float(impact)
            if not isfinite(numeric) or not -1.0 <= numeric <= 1.0:
                raise ValueError("principal value impacts must be between -1 and 1")
            impacts[key] = numeric
        if not impacts:
            raise ValueError("principal intent requires value impacts")
        object.__setattr__(self, "value_impacts", impacts)
        object.__setattr__(self, "uncertainty", _unit("intent uncertainty", self.uncertainty))
        for name, value in {
            "reversible": self.reversible,
            "external_effect": self.external_effect,
            "credential_use": self.credential_use,
            "constitution_change": self.constitution_change,
        }.items():
            if not isinstance(value, bool):
                raise ValueError(f"{name} must be boolean")
        if isinstance(self.financial_value_microunits, bool) or not isinstance(
            self.financial_value_microunits, int
        ):
            raise ValueError("financial value must be an integer")
        if self.financial_value_microunits < 0:
            raise ValueError("financial value must be non-negative")

    def effective_tags(self) -> tuple[str, ...]:
        rows = {
            *self.tags,
            f"domain:{self.domain}",
            f"action:{self.action}",
        }
        if not self.reversible:
            rows.add("irreversible")
        if self.external_effect:
            rows.add("external-effect")
        if self.credential_use:
            rows.add("credential")
        if self.financial_value_microunits:
            rows.add("finance")
        if self.constitution_change:
            rows.add("constitution-change")
        return tuple(sorted(rows))

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "domain": self.domain,
            "action": self.action,
            "tags": list(self.tags),
            "effective_tags": list(self.effective_tags()),
            "value_impacts": {
                name: self.value_impacts[name] for name in sorted(self.value_impacts)
            },
            "uncertainty": self.uncertainty,
            "reversible": bool(self.reversible),
            "external_effect": bool(self.external_effect),
            "credential_use": bool(self.credential_use),
            "financial_value_microunits": int(self.financial_value_microunits),
            "constitution_change": bool(self.constitution_change),
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PrincipalIntent":
        _strict_keys(
            payload,
            allowed={
                "id",
                "domain",
                "action",
                "tags",
                "value_impacts",
                "uncertainty",
                "reversible",
                "external_effect",
                "credential_use",
                "financial_value_microunits",
                "constitution_change",
            },
            required={"id", "domain", "action", "value_impacts"},
            name="principal intent",
        )
        tags = payload.get("tags", [])
        impacts = payload["value_impacts"]
        if not isinstance(tags, list):
            raise ValueError("principal intent tags must be an array")
        if not isinstance(impacts, Mapping):
            raise ValueError("principal intent value_impacts must be an object")
        return cls(
            id=payload["id"],
            domain=payload["domain"],
            action=payload["action"],
            tags=tuple(tags),
            value_impacts={key: value for key, value in impacts.items()},
            uncertainty=payload.get("uncertainty", 0.0),
            reversible=payload.get("reversible", True),
            external_effect=payload.get("external_effect", False),
            credential_use=payload.get("credential_use", False),
            financial_value_microunits=payload.get(
                "financial_value_microunits", 0
            ),
            constitution_change=payload.get("constitution_change", False),
        )


@dataclass(frozen=True, slots=True)
class PrincipalDecision:
    mode: DecisionMode
    alignment_score: float
    reasons: tuple[str, ...]
    matched_directives: tuple[str, ...]
    profile_digest: str | None
    principal_id: str | None
    event_id: str | None = None

    def as_payload(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "alignment_score": self.alignment_score,
            "reasons": list(self.reasons),
            "matched_directives": list(self.matched_directives),
            "profile_digest": self.profile_digest,
            "principal_id": self.principal_id,
        }

    @classmethod
    def from_payload(
        cls, payload: Mapping[str, Any], *, event_id: str | None = None
    ) -> "PrincipalDecision":
        return cls(
            mode=str(payload["mode"]),  # type: ignore[arg-type]
            alignment_score=float(payload["alignment_score"]),
            reasons=tuple(str(item) for item in payload["reasons"]),
            matched_directives=tuple(
                str(item) for item in payload["matched_directives"]
            ),
            profile_digest=(
                str(payload["profile_digest"])
                if payload.get("profile_digest") is not None
                else None
            ),
            principal_id=(
                str(payload["principal_id"])
                if payload.get("principal_id") is not None
                else None
            ),
            event_id=event_id,
        )


class PrincipalModel:
    """Event-sourced principal profile and deterministic intent evaluator."""

    def __init__(self, store: EventStore) -> None:
        self.store = store

    def _latest_profile_event(self):
        return self.store.latest("principal.profile.installed")

    def profile(self) -> PrincipalProfile | None:
        event = self._latest_profile_event()
        return PrincipalProfile.from_payload(event.payload["profile"]) if event else None

    def install(
        self,
        profile: PrincipalProfile,
        *,
        authority: str,
        evidence: tuple[str, ...] | list[str],
        expected_previous_digest: str | None = None,
    ) -> dict[str, Any]:
        source = _authority(authority)
        if not isinstance(evidence, (tuple, list)):
            raise ValueError("principal profile evidence must be an array")
        evidence_rows = tuple(_text("profile evidence", item, maximum=600) for item in evidence)
        if not evidence_rows:
            raise ValueError("principal profile requires evidence")
        profile_payload = profile.as_payload()
        digest = sha256(canonical_json(profile_payload).encode()).hexdigest()

        def factory(events: list[Any]) -> tuple[str, Mapping[str, Any]]:
            previous = next(
                (
                    event
                    for event in reversed(events)
                    if event.kind == "principal.profile.installed"
                ),
                None,
            )
            previous_digest = (
                str(previous.payload["profile_digest"]) if previous else None
            )
            if previous and previous_digest == digest:
                return (
                    f"{profile.principal_id}:{previous.payload['revision']}:{digest}",
                    previous.payload,
                )
            if previous is not None and expected_previous_digest is None:
                raise ValueError(
                    "expected previous profile digest is required for revision"
                )
            if expected_previous_digest != previous_digest:
                raise ValueError(
                    "expected previous profile digest does not match active profile"
                )
            if (
                previous
                and previous.payload["profile"]["principal_id"]
                != profile.principal_id
            ):
                raise ValueError("principal id cannot change across revisions")
            revision = int(previous.payload["revision"]) + 1 if previous else 1
            payload = {
                "schema_version": 1,
                "revision": revision,
                "profile_digest": digest,
                "previous_profile_digest": previous_digest,
                "authority": source,
                "evidence": list(evidence_rows),
                "profile": profile_payload,
            }
            return f"{profile.principal_id}:{revision}:{digest}", payload

        event, created = self.store.append_computed_once(
            "principal.profile.installed", factory
        )
        return {
            **profile_payload,
            "profile_digest": digest,
            "revision": int(event.payload["revision"]),
            "event_id": event.event_id,
            "created": created,
        }

    def propose_revision(
        self,
        *,
        proposal_id: str,
        statement: str,
        rationale: str,
        tags: tuple[str, ...] | list[str],
        evidence: tuple[str, ...] | list[str],
    ) -> dict[str, Any]:
        identifier = _identifier("proposal id", proposal_id)
        if not isinstance(tags, (tuple, list)):
            raise ValueError("principal revision tags must be an array")
        if not isinstance(evidence, (tuple, list)):
            raise ValueError("principal revision evidence must be an array")
        evidence_rows = tuple(
            _text("revision evidence", item, maximum=600) for item in evidence
        )
        if not evidence_rows:
            raise ValueError("principal revision proposal requires evidence")
        current = self._latest_profile_event()
        payload = {
            "schema_version": 1,
            "proposal_id": identifier,
            "statement": _text("proposal statement", statement, maximum=1200),
            "rationale": _text("proposal rationale", rationale, maximum=1200),
            "tags": list(_tags(tags)),
            "evidence": list(evidence_rows),
            "active_profile_digest": (
                str(current.payload["profile_digest"]) if current else None
            ),
            "source_authority": "self",
            "content_trust": "self_generated_untrusted_proposal",
            "instructions_authorized": False,
            "requires_operator_endorsement": True,
            "auto_apply": False,
        }
        event = self.store.append_once(
            "principal.revision.proposed", identifier, payload
        )
        return {**payload, "event_id": event.event_id}

    def _alignment_score(
        self, profile: PrincipalProfile, intent: PrincipalIntent
    ) -> float:
        denominator = sum(profile.values.values())
        numerator = sum(
            weight * float(intent.value_impacts.get(name, 0.0))
            for name, weight in profile.values.items()
        )
        return round(numerator / denominator, 12)

    def _decision_from_snapshot(
        self,
        intent: PrincipalIntent,
        latest_profile_event: Any | None,
    ) -> PrincipalDecision:
        if latest_profile_event is None:
            return PrincipalDecision(
                mode="deny",
                alignment_score=0.0,
                reasons=("PROFILE_NOT_INSTALLED",),
                matched_directives=(),
                profile_digest=None,
                principal_id=None,
            )
        profile = PrincipalProfile.from_payload(latest_profile_event.payload["profile"])
        digest = str(latest_profile_event.payload["profile_digest"])
        effective = set(intent.effective_tags())
        if intent.uncertainty >= profile.uncertainty_threshold:
            effective.add("uncertain")
        matched_boundaries = [
            directive
            for directive in profile.directives
            if directive.kind == "boundary" and set(directive.tags) <= effective
        ]
        matched_escalations = [
            directive
            for directive in profile.directives
            if directive.kind == "escalation" and set(directive.tags) <= effective
        ]
        required_grant_tags = {
            f"domain:{intent.domain}",
            f"action:{intent.action}",
        }
        for sensitive_tag, active in {
            "external-effect": intent.external_effect,
            "credential": intent.credential_use,
            "finance": intent.financial_value_microunits > 0,
            "constitution-change": intent.constitution_change,
            "irreversible": not intent.reversible,
        }.items():
            if active:
                required_grant_tags.add(sensitive_tag)
        matched_grants = [
            directive
            for directive in profile.directives
            if directive.kind == "grant"
            and required_grant_tags <= set(directive.tags)
            and set(directive.tags) <= effective
        ]
        alignment = self._alignment_score(profile, intent)
        high_power = any(
            (
                intent.external_effect,
                intent.credential_use,
                intent.financial_value_microunits > 0,
                intent.constitution_change,
                not intent.reversible,
            )
        )
        reasons: list[str] = []
        matched: list[str] = []
        if matched_boundaries:
            mode: DecisionMode = "deny"
            reasons.append("PRINCIPAL_BOUNDARY")
            matched.extend(item.id for item in matched_boundaries)
        elif alignment < 0.0:
            mode = "deny"
            reasons.append("NEGATIVE_VALUE_ALIGNMENT")
        elif alignment == 0.0:
            mode = "require_approval"
            reasons.append("NO_POSITIVE_VALUE_ALIGNMENT")
        elif matched_escalations:
            mode = "require_approval"
            reasons.append("PRINCIPAL_ESCALATION")
            matched.extend(item.id for item in matched_escalations)
        elif intent.uncertainty >= profile.uncertainty_threshold:
            mode = "require_approval"
            reasons.append("UNCERTAINTY_THRESHOLD")
        elif high_power and not matched_grants:
            mode = "require_approval"
            reasons.append("EXPLICIT_GRANT_REQUIRED")
        else:
            mode = "allow"
            reasons.append("ALIGNED_WITH_PRINCIPAL_VALUES")
            matched.extend(item.id for item in matched_grants)
        return PrincipalDecision(
            mode=mode,
            alignment_score=alignment,
            reasons=tuple(reasons),
            matched_directives=tuple(sorted(set(matched))),
            profile_digest=digest,
            principal_id=profile.principal_id,
        )

    def evaluate(self, intent: PrincipalIntent) -> PrincipalDecision:
        for _ in range(3):
            snapshot = self.store.events()
            latest = next(
                (
                    event
                    for event in reversed(snapshot)
                    if event.kind == "principal.profile.installed"
                ),
                None,
            )
            decision = self._decision_from_snapshot(intent, latest)
            payload = {
                "schema_version": 1,
                "intent": intent.as_payload(),
                "decision": decision.as_payload(),
            }

            def profile_guard(current: list[Any]) -> str | None:
                current_latest = next(
                    (
                        event
                        for event in reversed(current)
                        if event.kind == "principal.profile.installed"
                    ),
                    None,
                )
                current_digest = (
                    str(current_latest.payload["profile_digest"])
                    if current_latest is not None
                    else None
                )
                if current_digest != decision.profile_digest:
                    return "PRINCIPAL_PROFILE_CHANGED"
                return None

            event, _, rejection = self.store.append_once_result_guarded(
                "principal.intent.decided",
                intent.id,
                payload,
                guard=profile_guard,
                strict_existing_payload=True,
            )
            if rejection == "PRINCIPAL_PROFILE_CHANGED":
                continue
            if rejection is not None or event is None:
                raise RuntimeError(
                    f"principal intent decision rejected: {rejection or 'unknown'}"
                )
            return PrincipalDecision.from_payload(
                event.payload["decision"], event_id=event.event_id
            )
        raise RuntimeError("principal profile changed during three evaluation attempts")

    def status(self) -> dict[str, Any]:
        latest = self._latest_profile_event()
        profile_payload = dict(latest.payload["profile"]) if latest else None
        return {
            "profile_installed": latest is not None,
            "profile_digest": str(latest.payload["profile_digest"]) if latest else None,
            "revision": int(latest.payload["revision"]) if latest else 0,
            "profile": profile_payload,
            "intent_decisions": len(self.store.events("principal.intent.decided")),
            "revision_proposals": len(
                self.store.events("principal.revision.proposed")
            ),
            "self_ratification_enabled": False,
        }


@dataclass(frozen=True, slots=True)
class PersonalAuthorization:
    mode: DecisionMode
    principal: PrincipalDecision
    capability: Any
    reasons: tuple[str, ...]
    event_id: str

    def as_payload(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "principal": self.principal.as_payload(),
            "capability": self.capability.as_payload(),
            "reasons": list(self.reasons),
            "event_id": self.event_id,
        }


class PersonalAgency:
    """Combines principal alignment and typed capability authority."""

    def __init__(self, store: EventStore, principal: PrincipalModel, registry: Any) -> None:
        self.store = store
        self.principal = principal
        self.registry = registry

    def _from_event(self, event: Any) -> PersonalAuthorization:
        from .capabilities import CapabilityDecision

        return PersonalAuthorization(
            mode=event.payload["mode"],
            principal=PrincipalDecision.from_payload(event.payload["principal"]),
            capability=CapabilityDecision.from_payload(event.payload["capability"]),
            reasons=tuple(event.payload["reasons"]),
            event_id=event.event_id,
        )

    def authorize(
        self,
        *,
        intent: PrincipalIntent,
        request: Any,
        authorization_id: str,
    ) -> PersonalAuthorization:
        identifier = _identifier("authorization id", authorization_id)
        intent_digest = sha256(canonical_json(intent.as_payload()).encode()).hexdigest()
        claim_payload = {
            "schema_version": 1,
            "authorization_id": identifier,
            "intent": intent.as_payload(),
            "intent_digest": intent_digest,
            "request": request.as_payload(),
        }
        self.store.append_once(
            "personal.agency.claimed", identifier, claim_payload
        )
        existing = next(
            (
                event
                for event in reversed(self.store.events("personal.agency.authorized"))
                if event.payload["authorization_id"] == identifier
            ),
            None,
        )
        if existing is not None:
            return self._from_event(existing)

        principal = self.principal.evaluate(intent)
        bound_request = (
            replace(
                request,
                principal_profile_digest=principal.profile_digest,
                intent_digest=intent_digest,
                intent_domain=intent.domain,
                intent_action=intent.action,
            )
            if principal.mode == "allow"
            else request
        )
        capability = (
            self.registry.reserve(bound_request)
            if principal.mode == "allow"
            else self.registry.evaluate(bound_request)
        )
        if "deny" in {principal.mode, capability.mode}:
            mode: DecisionMode = "deny"
        elif "require_approval" in {principal.mode, capability.mode}:
            mode = "require_approval"
        else:
            mode = "allow"
        reasons = tuple(
            [f"PRINCIPAL:{reason}" for reason in principal.reasons]
            + [f"CAPABILITY:{reason}" for reason in capability.reasons]
        )
        payload = {
            "schema_version": 1,
            "authorization_id": identifier,
            "intent_id": intent.id,
            "intent_digest": intent_digest,
            "request_id": request.id,
            "request": bound_request.as_payload(),
            "mode": mode,
            "principal": principal.as_payload(),
            "capability": capability.as_payload(),
            "reasons": list(reasons),
        }
        event = self.store.append_once(
            "personal.agency.authorized", identifier, payload
        )
        return self._from_event(event)
