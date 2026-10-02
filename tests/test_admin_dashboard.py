from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import cct_agent.dashboard as dashboard_module
from cct_agent.capabilities import CapabilityLease, CapabilityRegistry, OperatorCapabilityCatalog
from cct_agent.dashboard import (
    MAX_DASHBOARD_DATABASE_BYTES,
    DashboardUnavailable,
    ReadOnlyEventStore,
    build_dashboard_snapshot,
)
from cct_agent.dashboard_server import create_dashboard_server, validate_bind_host
from cct_agent.execution_tickets import GlobalKillSwitch
from cct_agent.store import EventStore


NOW = "2026-09-04T04:45:00+00:00"
FUTURE = "2026-09-05T04:45:00+00:00"
SECRET_SENTINEL = "PRIVATE_MESSAGE_DO_NOT_RENDER_86c5"


def configured_store(tmp_path: Path) -> EventStore:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    catalog = OperatorCapabilityCatalog(store).install()
    shell = catalog["shell"]["spec"]
    CapabilityRegistry(store).grant(
        CapabilityLease(
            id="lease-dashboard-shell",
            capability="operator.shell",
            principal_id="mike",
            scopes=("operator/shell/cct-free-agent",),
            expires_at=FUTURE,
            max_actions=24,
            max_bytes=262_144,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://dashboard-fixture",),
        )
    )
    store.append(
        "goal.formed",
        {
            "goal": {
                "id": "goal_cctae_administrative_control_plane_20260904",
                "statement": SECRET_SENTINEL,
                "rationale": SECRET_SENTINEL,
                "source": "joint",
                "horizon": "persistent",
                "alignment": {"truth": 1.0},
                "evidence": [SECRET_SENTINEL],
                "status": "active",
            },
            "alignment_score": 1.0,
            "constitution_fingerprint": "a" * 64,
        },
    )
    store.append(
        "operator.authenticated_access.prepared",
        {
            "schema_version": "cct.operator_authenticated_access.prepared.v1",
            "target_id": "whatsapp-self-test",
            "route": "browser_real_profile_snapshot",
            "status": "AUTH_HANDOFF_REQUIRED",
            "host_ticket_required": True,
            "execution_authority_granted": False,
            "producer_text": SECRET_SENTINEL,
        },
    )
    store.append(
        "clarification.requested",
        {
            "request_id": "clarify-first-effect",
            "revision": 2,
            "questions": [{"id": "first-effect-class", "prompt": SECRET_SENTINEL}],
            "raw_secret": SECRET_SENTINEL,
        },
    )
    store.append(
        "proactive.initiation.decided",
        {
            "packet_id": "dashboard-packet",
            "decision": "WAIT",
            "reason_codes": ["NO_MATERIAL_CHANGE"],
        },
    )
    GlobalKillSwitch(store).trip(
        trip_id="dashboard-fixture-stop",
        authority="operator",
        reason=SECRET_SENTINEL,
    )
    connection = sqlite3.connect(store.path)
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    assert shell["name"] == "operator.shell"
    return store


def file_digests(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for candidate in (path, Path(f"{path}-wal")):
        if candidate.exists() and (candidate == path or candidate.stat().st_size > 0):
            result[candidate.name] = sha256(candidate.read_bytes()).hexdigest()
    return result


def event_count(path: Path) -> int:
    connection = sqlite3.connect(path)
    try:
        return int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
    finally:
        connection.close()


def test_snapshot_is_human_first_complete_and_read_only(tmp_path: Path) -> None:
    store = configured_store(tmp_path)
    before_events = event_count(store.path)
    before_files = file_digests(store.path)

    snapshot = build_dashboard_snapshot(store.path, now=NOW)

    assert snapshot["schema_version"] == "cct.admin_dashboard.snapshot.v1"
    assert snapshot["mode"] == "READ_ONLY"
    assert snapshot["outcome"] == {
        "state": "BLOCKED",
        "headline": "Emergency stop active",
        "detail": "All effect permissions are blocked until the operator clears the current kill switch.",
        "next_action": "Inspect the recorded failure before clearing the stop.",
    }
    assert snapshot["summary"] == {
        "chain_valid": True,
        "event_count": before_events,
        "active_goals": 1,
        "capability_count": 8,
        "active_leases": 1,
        "pending_approvals": 1,
        "connected_access_routes": 0,
        "external_effects": 0,
    }
    permissions = {row["name"]: row for row in snapshot["permissions"]}
    assert set(permissions) == {
        "operator.shell",
        "operator.web",
        "operator.project_edit",
        "operator.deploy",
        "operator.public",
        "operator.credential",
        "operator.financial",
        "operator.high_consequence",
    }
    assert permissions["operator.shell"]["effective_state"] == "BLOCKED_KILL_SWITCH"
    assert permissions["operator.shell"]["active_lease_count"] == 1
    assert permissions["operator.shell"]["remaining_actions"] == 24
    assert permissions["operator.web"]["active_lease_count"] == 0
    assert snapshot["access"] == [
        {
            "target_id": "whatsapp-self-test",
            "route": "browser_real_profile_snapshot",
            "state": "AUTH_HANDOFF_REQUIRED",
            "execution_authority_granted": False,
            "last_event_id": snapshot["access"][0]["last_event_id"],
            "last_changed_at": NOW,
        }
    ]
    assert snapshot["automations"][0]["id"] == "proactive-updates"
    assert snapshot["automations"][0]["state"] == "OBSERVED"
    assert snapshot["approvals"][0]["request_id"] == "clarify-first-effect"
    assert snapshot["approvals"][0]["state"] == "ACTION_REQUIRED"
    assert snapshot["goals"][0]["goal_id"] == "goal_cctae_administrative_control_plane_20260904"
    assert snapshot["emergency"]["kill_switch_active"] is True
    assert snapshot["emergency"]["model_clear_enabled"] is False
    assert snapshot["privacy"]["raw_event_payloads_exposed"] is False
    assert snapshot["privacy"]["database_path_exposed"] is False

    serialized = json.dumps(snapshot, sort_keys=True)
    assert SECRET_SENTINEL not in serialized
    assert str(store.path) not in serialized
    assert '"payload"' not in serialized
    assert file_digests(store.path) == before_files
    assert store.count() == before_events


def test_read_only_store_rejects_missing_symlink_and_malformed_database(tmp_path: Path) -> None:
    with pytest.raises(DashboardUnavailable, match="DASHBOARD_DATABASE_NOT_FOUND"):
        ReadOnlyEventStore(tmp_path / "missing.sqlite")

    real = tmp_path / "real.sqlite"
    EventStore(real)
    link = tmp_path / "linked.sqlite"
    link.symlink_to(real)
    with pytest.raises(DashboardUnavailable, match="DASHBOARD_DATABASE_SYMLINK_DENIED"):
        ReadOnlyEventStore(link)

    malformed = tmp_path / "malformed.sqlite"
    malformed.write_text("not sqlite", encoding="utf-8")
    with pytest.raises(DashboardUnavailable, match="DASHBOARD_DATABASE_INVALID"):
        build_dashboard_snapshot(malformed, now=NOW)

    oversized = tmp_path / "oversized.sqlite"
    with oversized.open("wb") as handle:
        handle.truncate(MAX_DASHBOARD_DATABASE_BYTES + 1)
    with pytest.raises(DashboardUnavailable, match="DASHBOARD_DATABASE_TOO_LARGE"):
        ReadOnlyEventStore(oversized)


def test_descriptor_read_enforces_cap_before_and_during_growth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = 4096
    monkeypatch.setattr(dashboard_module, "MAX_DASHBOARD_DATABASE_BYTES", cap)
    original_read = os.read
    read_calls = 0
    bytes_returned = 0

    def tracked_read(descriptor: int, count: int) -> bytes:
        nonlocal read_calls, bytes_returned
        read_calls += 1
        chunk = original_read(descriptor, count)
        bytes_returned += len(chunk)
        return chunk

    monkeypatch.setattr(dashboard_module.os, "read", tracked_read)
    oversized = tmp_path / "descriptor-oversized.sqlite"
    with oversized.open("wb") as handle:
        handle.truncate(cap + 1)
    with pytest.raises(DashboardUnavailable, match="DASHBOARD_DATABASE_TOO_LARGE"):
        ReadOnlyEventStore._read_descriptor(oversized)
    assert read_calls == 0
    assert bytes_returned == 0

    growing = tmp_path / "descriptor-growing.sqlite"
    growing.write_bytes(b"x" * 1024)
    read_calls = 0
    bytes_returned = 0
    grown = False

    def growing_read(descriptor: int, count: int) -> bytes:
        nonlocal read_calls, bytes_returned, grown
        read_calls += 1
        chunk = original_read(descriptor, count)
        bytes_returned += len(chunk)
        if not grown:
            with growing.open("r+b") as handle:
                handle.truncate(cap + 1024 * 1024)
            grown = True
        return chunk

    monkeypatch.setattr(dashboard_module.os, "read", growing_read)
    with pytest.raises(DashboardUnavailable, match="DASHBOARD_DATABASE_TOO_LARGE"):
        ReadOnlyEventStore._read_descriptor(growing)
    assert read_calls == 2
    assert bytes_returned == cap + 1


def test_continuity_automation_uses_canonical_team_sync_sensor_events(
    tmp_path: Path,
) -> None:
    store = configured_store(tmp_path)
    store.append(
        "sensor.team_sync.cursor.advanced",
        {
            "source_id": "configured-team-sync",
            "source_path_sha256": "b" * 64,
            "offset": 123,
            "raw_source_line_stored": False,
            "source_path": SECRET_SENTINEL,
        },
    )
    store.append(
        "sensor.team_sync.continuity",
        {
            "source_id": "configured-team-sync",
            "source_path_sha256": "b" * 64,
            "mode": "SOURCE_EVENTS",
            "observation_count": 1,
            "producer_free_text_persisted": False,
        },
    )

    snapshot = build_dashboard_snapshot(store.path, now=NOW)
    continuity = next(
        row for row in snapshot["automations"] if row["id"] == "continuity-sensor"
    )

    assert continuity["state"] == "OBSERVED"
    assert continuity["observed_events"] == 2
    assert continuity["runs"] == 1
    assert SECRET_SENTINEL not in json.dumps(snapshot, sort_keys=True)


def test_http_dashboard_serves_assets_snapshot_and_denies_mutation(tmp_path: Path) -> None:
    store = configured_store(tmp_path)
    before_events = event_count(store.path)
    before = file_digests(store.path)
    server = create_dashboard_server(
        database=store.path,
        host="127.0.0.1",
        port=0,
        now=lambda: NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urlopen(f"{base}/", timeout=3) as response:
            html = response.read().decode("utf-8")
            assert response.status == 200
            assert "CCTAE Control Plane" in html
            assert response.headers["Content-Security-Policy"] == (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
            )
            assert response.headers["X-Frame-Options"] == "DENY"
            assert response.headers["Permissions-Policy"] == (
                "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
            )
            assert response.headers["Cache-Control"] == "no-store"

        with urlopen(f"{base}/api/dashboard", timeout=3) as response:
            payload = json.load(response)
            assert response.status == 200
            assert payload["summary"]["chain_valid"] is True
            assert response.headers["Content-Type"] == "application/json; charset=utf-8"

        for asset in ("styles.css", "app.js"):
            with urlopen(f"{base}/assets/{asset}", timeout=3) as response:
                assert response.status == 200
                assert response.read()

        with pytest.raises(HTTPError) as mutation:
            urlopen(Request(f"{base}/api/dashboard", data=b"{}", method="POST"), timeout=3)
        assert mutation.value.code == 405
        assert json.load(mutation.value)["error"] == "READ_ONLY_DASHBOARD"

        hostile_host = Request(f"{base}/api/dashboard", headers={"Host": "evil.example"})
        with pytest.raises(HTTPError) as rebinding:
            urlopen(hostile_host, timeout=3)
        assert rebinding.value.code == 421
        assert json.load(rebinding.value)["error"] == "DASHBOARD_HOST_DENIED"

        with pytest.raises(HTTPError) as missing:
            urlopen(f"{base}/not-found", timeout=3)
        assert missing.value.code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assert file_digests(store.path) == before
    assert event_count(store.path) == before_events


def test_server_is_loopback_only() -> None:
    assert validate_bind_host("127.0.0.1") == "127.0.0.1"
    assert validate_bind_host("localhost") == "localhost"
    assert validate_bind_host("::1") == "::1"
    with pytest.raises(ValueError, match="dashboard host must be loopback-only"):
        validate_bind_host("0.0.0.0")


def test_static_ui_contract_is_mobile_safe_and_uses_text_only_rendering() -> None:
    static = Path(__file__).parents[1] / "cct_agent" / "dashboard_static"
    html = (static / "index.html").read_text(encoding="utf-8")
    css = (static / "styles.css").read_text(encoding="utf-8")
    javascript = (static / "app.js").read_text(encoding="utf-8")

    for section in (
        "overview",
        "permissions",
        "access",
        "automations",
        "approvals",
        "audit",
        "emergency",
    ):
        assert f'id="{section}"' in html
    assert "Preview controls" in html
    assert "EXACT OPERATOR CONFIRMATION" in html
    assert "Confirmation expires" in html
    assert "Local CCTAE · bound ledger" in html
    assert 'type="password"' in html
    assert "disabled" in html
    assert "@media (max-width: 760px)" in css
    assert "overflow-x: auto" in css
    assert ".innerHTML" not in javascript
    assert "localStorage" not in javascript
    assert "sessionStorage" not in javascript
    assert "textContent" in javascript
    assert "fetch('/api/dashboard'" in javascript
    for endpoint in (
        "/api/operator/session",
        "/api/controls/preview",
        "/api/controls/confirm",
        "/api/controls/apply",
    ):
        assert endpoint in javascript
