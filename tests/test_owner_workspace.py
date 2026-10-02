from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cct_agent import firebase_bridge
from cct_agent.owner_workspace import (
    ANSWER_CHOICES,
    PERMISSION_KEYS,
    WORKSPACE_SCHEMA,
    OwnerWorkspaceInvalid,
    normalize_owner_workspace,
    project_owner_workspace,
)
from cct_agent.store import canonical_json


NOW = datetime(2026, 9, 12, 11, 0, tzinfo=timezone.utc)
OWNER_UID = "firebase-owner-uid"


def workspace() -> dict:
    return {
        "schemaVersion": WORKSPACE_SCHEMA,
        "ownerUid": OWNER_UID,
        "revision": 1,
        "updatedAt": NOW,
        "learningEnabled": True,
        "permissions": {key: False for key in PERMISSION_KEYS},
        "autonomyMode": "supervised",
        "autonomyAcknowledged": False,
        "answers": {key: "" for key in ANSWER_CHOICES},
        "decisions": {},
    }


def test_exact_workspace_projects_requested_intent_not_execution() -> None:
    value = workspace()
    value["permissions"]["webResearch"] = True
    value["answers"]["focus"] = "systems"
    value["decisions"]["onboarding-repair"] = "approve"
    projection = project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW)
    assert projection["observationState"] == "OBSERVED"
    assert projection["revision"] == 1
    assert projection["requestedPolicy"]["permissions"]["webResearch"] is True
    assert projection["preferences"]["answers"]["focus"] == "systems"
    assert projection["runtimeAdapterState"] == "NOT_CONNECTED"
    assert projection["runtimeAcknowledgement"] is None
    assert projection["effectivePolicy"] is None
    assert projection["enforcementActive"] is False
    assert projection["policySha256"] is not None
    assert projection["workspaceSha256"] is not None
    assert OWNER_UID not in json.dumps(projection)


@pytest.mark.parametrize(
    "field", ["schemaVersion", "ownerUid", "updatedAt", "permissions", "answers"]
)
def test_missing_schema_fields_fail_closed(field: str) -> None:
    value = workspace()
    del value[field]
    with pytest.raises(OwnerWorkspaceInvalid):
        normalize_owner_workspace(value, owner_uid=OWNER_UID)
    assert_closed(project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW))


def assert_closed(projection: dict) -> None:
    assert projection["observationState"] != "OBSERVED"
    assert not any(projection["requestedPolicy"]["permissions"].values())
    assert projection["requestedPolicy"]["autonomyMode"] == "supervised"
    assert projection["requestedPolicy"]["autonomyAcknowledged"] is False
    assert projection["policySha256"] is None
    assert projection["workspaceSha256"] is None
    assert projection["revision"] is None
    assert projection["runtimeAdapterState"] == "NOT_CONNECTED"
    assert projection["runtimeAcknowledgement"] is None
    assert projection["effectivePolicy"] is None
    assert projection["enforcementActive"] is False


@pytest.mark.parametrize(
    "location,key",
    [
        (None, "idToken"),
        (None, "lease"),
        (None, "effectivePolicy"),
        (None, "runtimeAcknowledgement"),
        (None, "runtimeAdapterState"),
        ("permissions", "operator.web"),
        ("permissions", "sudo"),
        ("answers", "systemPrompt"),
    ],
)
def test_malicious_extra_fields_are_rejected_without_echo(
    location: str | None, key: str
) -> None:
    value = workspace()
    value["permissions"]["payments"] = True
    target = value if location is None else value[location]
    target[key] = "PRIVATE-CREDENTIAL-MUST-NOT-PROJECT"
    with pytest.raises(OwnerWorkspaceInvalid):
        normalize_owner_workspace(value, owner_uid=OWNER_UID)
    projection = project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW)
    assert_closed(projection)
    assert "PRIVATE-CREDENTIAL" not in json.dumps(projection)


@pytest.mark.parametrize("bad", [0, 1, "false", "true", None, [], {}])
@pytest.mark.parametrize(
    "field", ["learningEnabled", "autonomyAcknowledged", *PERMISSION_KEYS]
)
def test_booleans_require_actual_bool(field: str, bad: object) -> None:
    value = workspace()
    target = value["permissions"] if field in PERMISSION_KEYS else value
    target[field] = bad
    assert_closed(project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW))


@pytest.mark.parametrize(
    "revision", [True, False, 0, -1, 1.0, "1", None, 2147483648, 10**100]
)
def test_revision_is_positive_integer_not_bool(revision: object) -> None:
    value = workspace()
    value["revision"] = revision
    assert_closed(project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW))


@pytest.mark.parametrize("mode", ["FULL", "automatic", " full", True, None, [], {}])
def test_unknown_or_malformed_mode_fails_closed(mode: object) -> None:
    value = workspace()
    value["autonomyMode"] = mode
    value["autonomyAcknowledged"] = True
    assert_closed(project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW))


def test_full_mode_requires_confirmation_and_never_enables_permissions() -> None:
    value = workspace()
    value["autonomyMode"] = "full"
    assert_closed(project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW))
    value["autonomyAcknowledged"] = True
    projection = project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW)
    assert projection["observationState"] == "OBSERVED"
    assert projection["requestedPolicy"]["autonomyMode"] == "full"
    assert not any(projection["requestedPolicy"]["permissions"].values())
    assert projection["enforcementActive"] is False
    assert projection["runtimeAdapterState"] == "NOT_CONNECTED"


@pytest.mark.parametrize("question", list(ANSWER_CHOICES))
@pytest.mark.parametrize(
    "answer", ["unknown", "<script>alert(1)</script>", "REVENUE", 1, True, [], {}]
)
def test_unknown_or_malicious_answers_fail_closed(
    question: str, answer: object
) -> None:
    value = workspace()
    value["answers"][question] = answer
    assert_closed(project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW))


@pytest.mark.parametrize(
    "decisions",
    [
        {"card": "execute"},
        {"card": True},
        {"card": []},
        {"": "approve"},
        {"<script>": "approve"},
        {"a/b": "approve"},
        {"a" * 81: "approve"},
        {"card.with.dot": "approve"},
        {"card:with:colon": "approve"},
        {"card\n": "approve"},
        {1: "approve"},
        {f"card-{i}": "approve" for i in range(61)},
        [],
        None,
    ],
)
def test_decisions_require_bounded_ids_and_known_enum(decisions: object) -> None:
    value = workspace()
    value["decisions"] = decisions
    assert_closed(project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW))


@pytest.mark.parametrize("owner_uid", [None, "", "other-owner"])
def test_owner_uid_must_be_pinned_and_match(owner_uid: str | None) -> None:
    assert_closed(
        project_owner_workspace(workspace(), owner_uid=owner_uid, observed_at=NOW)
    )


@pytest.mark.parametrize(
    "timestamp", [None, "2026-09-12T11:00:00Z", NOW.replace(tzinfo=None), 123]
)
def test_timestamp_must_be_resolved_aware_datetime(timestamp: object) -> None:
    value = workspace()
    value["updatedAt"] = timestamp
    assert_closed(project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW))


def test_digest_is_canonical_and_policy_digest_excludes_preferences_and_revision() -> (
    None
):
    original = workspace()
    first = project_owner_workspace(original, owner_uid=OWNER_UID, observed_at=NOW)
    reordered = dict(reversed(list(original.items())))
    reordered["permissions"] = dict(reversed(list(original["permissions"].items())))
    same = project_owner_workspace(
        reordered, owner_uid=OWNER_UID, observed_at=NOW + timedelta(seconds=5)
    )
    assert same["policySha256"] == first["policySha256"]
    assert same["workspaceSha256"] == first["workspaceSha256"]
    changed = deepcopy(original)
    changed["revision"] = 2
    changed["updatedAt"] += timedelta(seconds=1)
    changed["answers"]["risk"] = "balanced"
    second = project_owner_workspace(changed, owner_uid=OWNER_UID, observed_at=NOW)
    assert second["policySha256"] == first["policySha256"]
    assert second["workspaceSha256"] != first["workspaceSha256"]
    changed["permissions"]["payments"] = True
    third = project_owner_workspace(changed, owner_uid=OWNER_UID, observed_at=NOW)
    assert third["policySha256"] != second["policySha256"]
    normalized = normalize_owner_workspace(original, owner_uid=OWNER_UID)
    assert (
        first["workspaceSha256"]
        == sha256(canonical_json(normalized).encode()).hexdigest()
    )


def test_preference_reset_and_disabled_learning_preserve_policy_without_stale_cache() -> (
    None
):
    value = workspace()
    value["autonomyMode"] = "full"
    value["autonomyAcknowledged"] = True
    value["permissions"]["workspaceRead"] = True
    value["answers"]["focus"] = "creative"
    value["decisions"]["card-1"] = "approve"
    before = project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW)
    value["answers"] = {key: "" for key in ANSWER_CHOICES}
    value["decisions"] = {}
    value["learningEnabled"] = False
    value["revision"] += 1
    after = project_owner_workspace(value, owner_uid=OWNER_UID, observed_at=NOW)
    assert after["requestedPolicy"] == before["requestedPolicy"]
    assert after["policySha256"] == before["policySha256"]
    assert after["preferences"] == {
        "learningEnabled": False,
        "answers": value["answers"],
        "decisions": {},
    }
    after["requestedPolicy"]["permissions"]["payments"] = True
    assert value["permissions"]["payments"] is False
    assert before["preferences"]["answers"]["focus"] == "creative"


def test_firestore_gateway_reads_exact_document_with_bounded_rpc_and_no_writes() -> (
    None
):
    gateway = object.__new__(firebase_bridge.FirestoreBridgeGateway)
    gateway.client = Mock()
    document = gateway.client.collection.return_value.document.return_value
    document.get.return_value = SimpleNamespace(
        exists=True, to_dict=lambda: workspace()
    )
    assert gateway.read_owner_workspace() == workspace()
    gateway.client.collection.assert_called_once_with("cct_workspace")
    gateway.client.collection.return_value.document.assert_called_once_with("current")
    document.get.assert_called_once_with(
        retry=None, timeout=firebase_bridge.FIRESTORE_RPC_TIMEOUT_SECONDS
    )
    document.set.assert_not_called()
    document.update.assert_not_called()
    gateway.client.batch.assert_not_called()
    document.get.return_value = SimpleNamespace(
        exists=False, to_dict=Mock(side_effect=AssertionError)
    )
    assert gateway.read_owner_workspace() is None


def test_bridge_projection_is_additive_and_does_not_open_execution_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw_snapshot = {
        "permissions": [{"name": "operator.web", "active": False}],
        "goals": [],
    }
    monkeypatch.setattr(
        firebase_bridge, "build_dashboard_snapshot", lambda path: deepcopy(raw_snapshot)
    )
    gateway = SimpleNamespace(read_owner_workspace=Mock(return_value=workspace()))
    identity = Mock()
    config = firebase_bridge.FirebaseBridgeConfig(
        project_id="demo-cctae-control",
        database=tmp_path / "agency.sqlite",
        owner_email="owner@example.invalid",
        owner_uid=OWNER_UID,
        principal_id="mike",
        poll_seconds=3,
        request_ttl_seconds=180,
        claim_ttl_seconds=60,
        runtime_directory=tmp_path / "runtime",
    )
    bridge = firebase_bridge.CCTFirebaseBridge(
        config, gateway, identity, clock=lambda: NOW
    )
    monkeypatch.setattr(
        bridge, "_control_context", Mock(side_effect=AssertionError("must not execute"))
    )
    monkeypatch.setattr(
        bridge,
        "_authorization_store",
        Mock(side_effect=AssertionError("must not write events")),
    )
    envelope = bridge.dashboard_envelope()
    assert envelope["snapshot"]["collaboration"]["observationState"] == "OBSERVED"
    assert envelope["snapshot"]["controls"]["external_effects_enabled"] is False
    assert envelope["snapshot"]["permissions"][0]["active"] is False
    assert (
        envelope["snapshotSha256"]
        == sha256(canonical_json(envelope["snapshot"]).encode()).hexdigest()
    )
    identity.verify_owner.assert_not_called()
    gateway.read_owner_workspace.assert_called_once_with()

    gateway.read_owner_workspace.return_value = None
    assert_closed(bridge.dashboard_envelope()["snapshot"]["collaboration"])
    gateway.read_owner_workspace.return_value = {"idToken": "PRIVATE"}
    invalid = bridge.dashboard_envelope()["snapshot"]["collaboration"]
    assert_closed(invalid)
    assert "PRIVATE" not in json.dumps(invalid)

    # Legacy gateway implementations continue supporting existing control tests.
    bridge.gateway = SimpleNamespace()
    unsupported = bridge.dashboard_envelope()["snapshot"]["collaboration"]
    assert unsupported["observationState"] == "UNAVAILABLE"
    assert_closed(unsupported)


def test_workspace_read_sdk_failures_keep_existing_outer_backoff_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        firebase_bridge, "build_dashboard_snapshot", lambda path: {"permissions": []}
    )
    gateway = SimpleNamespace(
        read_owner_workspace=Mock(side_effect=RuntimeError("SDK failure"))
    )
    config = firebase_bridge.FirebaseBridgeConfig(
        project_id="demo-cctae-control",
        database=tmp_path / "agency.sqlite",
        owner_email="owner@example.invalid",
        owner_uid=OWNER_UID,
        principal_id="mike",
        poll_seconds=3,
        request_ttl_seconds=180,
        claim_ttl_seconds=60,
        runtime_directory=tmp_path / "runtime",
    )
    bridge = firebase_bridge.CCTFirebaseBridge(
        config, gateway, Mock(), clock=lambda: NOW
    )
    with pytest.raises(RuntimeError, match="SDK failure"):
        bridge.dashboard_envelope()
    gateway.read_owner_workspace.assert_called_once_with()
