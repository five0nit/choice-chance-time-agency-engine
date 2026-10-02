"""Strict, read-only observation of owner workspace *intent*, not authority.

This module does not open an event store, mint leases/tickets, access credentials,
execute card decisions, or acknowledge runtime policy. Even valid full-autonomy
intent projects NOT_CONNECTED until a separately reviewed executor is installed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import re
from typing import Any, Mapping

from .store import canonical_json


WORKSPACE_SCHEMA = "cct.owner_workspace.v1"
PROJECTION_SCHEMA = "cct.owner_workspace_projection.v1"
PERMISSION_KEYS = (
    "credentialAccess", "webResearch", "workspaceRead", "workspaceWrite",
    "externalMessages", "payments",
)
ANSWER_CHOICES = {
    "focus": ("revenue", "career", "systems", "creative"),
    "horizon": ("today", "week", "month"),
    "risk": ("conservative", "balanced", "experimental"),
    "interruptions": ("always", "milestones", "blockers"),
    "success": ("revenue", "shipped", "learning", "timeSaved"),
    "nextStep": ("research", "build", "repair", "review"),
}
_WORKSPACE_FIELDS = {
    "schemaVersion", "ownerUid", "revision", "updatedAt", "learningEnabled",
    "permissions", "autonomyMode", "autonomyAcknowledged", "answers", "decisions",
}
_OWNER_UID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,159}")
_CARD_ID = re.compile(r"[A-Za-z0-9_-]{1,80}")
_REASON_CODES = frozenset({
    "OWNER_WORKSPACE_OBSERVED", "OWNER_WORKSPACE_MISSING",
    "OWNER_WORKSPACE_INVALID", "OWNER_WORKSPACE_SCHEMA_INVALID",
    "OWNER_WORKSPACE_OWNER_NOT_PINNED", "OWNER_WORKSPACE_OWNER_MISMATCH",
    "OWNER_WORKSPACE_REVISION_INVALID", "OWNER_WORKSPACE_TIMESTAMP_INVALID",
    "OWNER_WORKSPACE_BOOLEAN_INVALID", "OWNER_WORKSPACE_AUTONOMY_INVALID",
    "OWNER_WORKSPACE_ANSWER_INVALID", "OWNER_WORKSPACE_DECISION_INVALID",
    "OWNER_WORKSPACE_OBSERVER_UNAVAILABLE",
})


class OwnerWorkspaceInvalid(ValueError):
    """One bounded public error code; never includes untrusted values or keys."""

    def __init__(self, reason_code: str = "OWNER_WORKSPACE_INVALID") -> None:
        self.reason_code = (
            reason_code
            if isinstance(reason_code, str) and reason_code in _REASON_CODES
            else "OWNER_WORKSPACE_INVALID"
        )
        super().__init__(self.reason_code)


def _exact_mapping(value: Any, keys: set[str]) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or any(type(key) is not str for key in value)
        or set(value) != keys
    ):
        raise OwnerWorkspaceInvalid("OWNER_WORKSPACE_SCHEMA_INVALID")
    return value


def _boolean(value: Any) -> bool:
    # Python's bool is an int subclass. Never coerce strings, 0, or 1 here.
    if type(value) is not bool:
        raise OwnerWorkspaceInvalid("OWNER_WORKSPACE_BOOLEAN_INVALID")
    return value


def _timestamp(value: Any) -> str:
    # Firestore's DatetimeWithNanoseconds is a datetime subclass. Requiring a
    # resolved aware value rejects pending SERVER_TIMESTAMP and client strings.
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise OwnerWorkspaceInvalid("OWNER_WORKSPACE_TIMESTAMP_INVALID")
    return value.astimezone(timezone.utc).isoformat()


def normalize_owner_workspace(value: Any, *, owner_uid: str | None) -> dict[str, Any]:
    """Return a fresh JSON-safe exact workspace, or reject it in its entirety.

    The configured owner is the trust anchor. Firestore security rules enforce
    write authentication, timestamp provenance and sequential transactions; a
    snapshot observer cannot establish those from document values alone.
    """
    if not isinstance(owner_uid, str) or not _OWNER_UID.fullmatch(owner_uid):
        raise OwnerWorkspaceInvalid("OWNER_WORKSPACE_OWNER_NOT_PINNED")
    row = _exact_mapping(value, _WORKSPACE_FIELDS)
    if row["schemaVersion"] != WORKSPACE_SCHEMA:
        raise OwnerWorkspaceInvalid("OWNER_WORKSPACE_SCHEMA_INVALID")
    if not isinstance(row["ownerUid"], str) or row["ownerUid"] != owner_uid:
        raise OwnerWorkspaceInvalid("OWNER_WORKSPACE_OWNER_MISMATCH")
    if type(row["revision"]) is not int or not 1 <= row["revision"] <= 2147483647:
        raise OwnerWorkspaceInvalid("OWNER_WORKSPACE_REVISION_INVALID")
    updated_at = _timestamp(row["updatedAt"])
    learning_enabled = _boolean(row["learningEnabled"])
    acknowledged = _boolean(row["autonomyAcknowledged"])
    mode = row["autonomyMode"]
    if (
        not isinstance(mode, str)
        or mode not in ("supervised", "full")
        or (mode == "full" and not acknowledged)
    ):
        raise OwnerWorkspaceInvalid("OWNER_WORKSPACE_AUTONOMY_INVALID")
    raw_permissions = _exact_mapping(row["permissions"], set(PERMISSION_KEYS))
    permissions = {key: _boolean(raw_permissions[key]) for key in PERMISSION_KEYS}
    raw_answers = _exact_mapping(row["answers"], set(ANSWER_CHOICES))
    answers: dict[str, str] = {}
    for key, choices in ANSWER_CHOICES.items():
        answer = raw_answers[key]
        if not isinstance(answer, str) or (answer != "" and answer not in choices):
            raise OwnerWorkspaceInvalid("OWNER_WORKSPACE_ANSWER_INVALID")
        answers[key] = answer
    raw_decisions = row["decisions"]
    if not isinstance(raw_decisions, Mapping) or len(raw_decisions) > 60:
        raise OwnerWorkspaceInvalid("OWNER_WORKSPACE_DECISION_INVALID")
    decisions: dict[str, str] = {}
    for key, decision in raw_decisions.items():
        if (
            not isinstance(key, str)
            or not _CARD_ID.fullmatch(key)
            or not isinstance(decision, str)
            or decision not in ("approve", "reject", "later")
        ):
            raise OwnerWorkspaceInvalid("OWNER_WORKSPACE_DECISION_INVALID")
        decisions[key] = decision
    return {
        "schemaVersion": WORKSPACE_SCHEMA,
        "ownerUid": owner_uid,
        "revision": row["revision"],
        "updatedAt": updated_at,
        "learningEnabled": learning_enabled,
        "permissions": permissions,
        "autonomyMode": mode,
        "autonomyAcknowledged": acknowledged,
        "answers": answers,
        "decisions": decisions,
    }


def project_owner_workspace(
    value: Any,
    *,
    owner_uid: str | None,
    observed_at: datetime,
    observer_available: bool = True,
) -> dict[str, Any]:
    """Project only bounded saved intent; never claim it is effective policy.

    Invalid/missing input discards the whole document, including previously true
    permissions. There is intentionally no cache and no runtime-ack input.
    """
    projection: dict[str, Any] = {
        "schemaVersion": PROJECTION_SCHEMA,
        "source": "cct_workspace/current",
        "observationState": "MISSING",
        "reasonCode": "OWNER_WORKSPACE_MISSING",
        "observedAt": _timestamp(observed_at),
        "revision": None,
        "workspaceUpdatedAt": None,
        "workspaceSha256": None,
        "policySha256": None,
        "requestedPolicy": {
            "permissions": {key: False for key in PERMISSION_KEYS},
            "autonomyMode": "supervised",
            "autonomyAcknowledged": False,
        },
        "preferences": {
            "learningEnabled": True,
            "answers": {key: "" for key in ANSWER_CHOICES},
            "decisions": {},
        },
        "runtimeAdapterState": "NOT_CONNECTED",
        "runtimeAcknowledgement": None,
        "effectivePolicy": None,
        "enforcementActive": False,
    }
    if not isinstance(owner_uid, str) or not _OWNER_UID.fullmatch(owner_uid):
        projection.update(
            observationState="OWNER_NOT_PINNED",
            reasonCode="OWNER_WORKSPACE_OWNER_NOT_PINNED",
        )
        return projection
    if not observer_available:
        projection.update(
            observationState="UNAVAILABLE",
            reasonCode="OWNER_WORKSPACE_OBSERVER_UNAVAILABLE",
        )
        return projection
    if value is None:
        return projection
    try:
        workspace = normalize_owner_workspace(value, owner_uid=owner_uid)
    except OwnerWorkspaceInvalid as error:
        projection.update(observationState="INVALID", reasonCode=error.reason_code)
        return projection
    policy = {key: workspace[key] for key in (
        "permissions", "autonomyMode", "autonomyAcknowledged",
    )}
    policy_material = {
        "schemaVersion": WORKSPACE_SCHEMA, "ownerUid": owner_uid, **policy,
    }
    projection.update(
        observationState="OBSERVED",
        reasonCode="OWNER_WORKSPACE_OBSERVED",
        revision=workspace["revision"],
        workspaceUpdatedAt=workspace["updatedAt"],
        workspaceSha256=sha256(canonical_json(workspace).encode("utf-8")).hexdigest(),
        policySha256=sha256(canonical_json(policy_material).encode("utf-8")).hexdigest(),
        requestedPolicy=policy,
        preferences={key: workspace[key] for key in (
            "learningEnabled", "answers", "decisions",
        )},
    )
    return projection
