from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import multiprocessing
from pathlib import Path
from threading import Thread
from typing import Any, cast
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from cct_agent.capabilities import (
    CapabilityLease,
    CapabilityRegistry,
    CapabilityRequest,
    OperatorCapabilityCatalog,
)
from cct_agent.dashboard import build_dashboard_snapshot
from cct_agent.dashboard_controls import (
    BOOTSTRAP_SCHEMA_VERSION,
    CONTROL_ACTION,
    CONTROL_CAPABILITY,
    DashboardControlDenied,
    DashboardControlService,
    DashboardSessionAuthority,
    OperatorBootstrap,
    create_operator_bootstrap,
    load_operator_bootstrap,
)
from cct_agent.dashboard_server import create_dashboard_server
from cct_agent.execution_tickets import (
    ExecutionTicket,
    ExecutionTicketAuthority,
    GlobalKillSwitch,
    TicketAuthorityDenied,
)
from cct_agent.narrative import HumanNarrative
from cct_agent.store import EventStore


NOW = "2026-09-04T11:00:00+00:00"
FUTURE = "2026-09-04T11:30:00+00:00"
BOOTSTRAP_TOKEN = "B" * 43
SIGNING_KEY = b"dashboard-control-test-signing-key-32"
SECRET_SENTINEL = "CONTROL_SECRET_MUST_NOT_PERSIST_4bf7"


def token_factory() -> Any:
    values = iter(
        [
            "S" * 43,
            "C" * 43,
            "A" * 43,
            "D" * 43,
            "E" * 43,
            "F" * 43,
        ]
    )
    return lambda: next(values)


def configured_control(
    tmp_path: Path,
    *,
    durable_bootstrap: bool = False,
) -> tuple[EventStore, DashboardSessionAuthority, DashboardControlService]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    OperatorCapabilityCatalog(store).install()
    store.append(
        "principal.profile.installed",
        {
            "schema_version": 1,
            "profile_digest": "a" * 64,
            "profile": {"principal_id": "mike"},
        },
    )
    if durable_bootstrap:
        bootstrap_path = tmp_path / "server-operator-bootstrap.json"
        create_operator_bootstrap(
            bootstrap_path,
            principal_id="mike",
            ttl_seconds=600,
            now=lambda: NOW,
            token_factory=lambda: BOOTSTRAP_TOKEN,
        )
        bootstrap = load_operator_bootstrap(bootstrap_path, now=lambda: NOW)
    else:
        bootstrap = OperatorBootstrap(
            principal_id="mike",
            token=BOOTSTRAP_TOKEN,
            expires_at=FUTURE,
        )
    sessions = DashboardSessionAuthority(
        bootstrap,
        now=lambda: NOW,
        signing_key=SIGNING_KEY,
        token_factory=token_factory(),
    )
    return store, sessions, DashboardControlService(store, sessions=sessions)


def open_session(sessions: DashboardSessionAuthority) -> dict[str, str]:
    return sessions.open_session(BOOTSTRAP_TOKEN)


def pause_preview(
    controls: DashboardControlService,
    session: dict[str, str],
    *,
    draft_id: str = "draft-pause-web",
) -> dict[str, Any]:
    return controls.preview(
        {
            "draft_id": draft_id,
            "action": CONTROL_ACTION,
            "capability": CONTROL_CAPABILITY,
            "active": False,
        },
        expires_at=session["expires_at"],
    )


def confirm_and_apply(
    controls: DashboardControlService,
    session: dict[str, str],
    preview: dict[str, Any],
) -> tuple[dict[str, str], dict[str, Any]]:
    confirmation = controls.confirm(preview, session=session)
    result = controls.apply(
        preview,
        confirmation,
        session_id_sha256=session["session_id_sha256"],
    )
    return confirmation, result


def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    origin: str,
    cookie: str | None = None,
    csrf: str | None = None,
) -> tuple[int, dict[str, Any], Any]:
    headers = {"Content-Type": "application/json", "Origin": origin}
    if cookie:
        headers["Cookie"] = cookie
    if csrf:
        headers["X-CCT-CSRF"] = csrf
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.load(response), response.headers
    except HTTPError as error:
        return error.code, json.load(error), error.headers


def _process_apply_worker(
    database: str,
    preview: dict[str, Any],
    confirmation: dict[str, str],
    session_id_sha256: str,
    barrier: Any,
    queue: Any,
) -> None:
    store = EventStore(database, clock=lambda: NOW)
    sessions = DashboardSessionAuthority(
        OperatorBootstrap(
            principal_id="mike",
            token=BOOTSTRAP_TOKEN,
            expires_at=FUTURE,
        ),
        now=lambda: NOW,
        signing_key=SIGNING_KEY,
    )
    controls = DashboardControlService(store, sessions=sessions)
    barrier.wait(timeout=10)
    try:
        result = controls.apply(
            preview,
            confirmation,
            session_id_sha256=session_id_sha256,
        )
        queue.put(("VERIFIED", result["applied_event_id"]))
    except DashboardControlDenied as error:
        queue.put(("DENIED", error.reason_code))


def test_bootstrap_file_is_owner_only_bounded_and_secret_not_returned(tmp_path: Path) -> None:
    path = tmp_path / "operator-bootstrap.json"
    result = create_operator_bootstrap(
        path,
        principal_id="mike",
        ttl_seconds=600,
        now=lambda: NOW,
        token_factory=lambda: BOOTSTRAP_TOKEN,
    )

    assert result == {
        "schema_version": BOOTSTRAP_SCHEMA_VERSION,
        "path": str(path),
        "principal_id": "mike",
        "expires_at": "2026-09-04T11:10:00+00:00",
        "token_returned": "false",
    }
    assert BOOTSTRAP_TOKEN not in json.dumps(result, sort_keys=True)
    assert path.stat().st_mode & 0o777 == 0o600
    loaded = load_operator_bootstrap(path, now=lambda: NOW)
    assert loaded.token == BOOTSTRAP_TOKEN

    path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only regular file"):
        load_operator_bootstrap(path, now=lambda: NOW)
    path.chmod(0o600)
    link = tmp_path / "bootstrap-link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="owner-only regular file"):
        load_operator_bootstrap(link, now=lambda: NOW)


def test_durable_bootstrap_is_consumed_once_across_preloaded_authorities(
    tmp_path: Path,
) -> None:
    path = tmp_path / "durable-operator-bootstrap.json"
    create_operator_bootstrap(
        path,
        principal_id="mike",
        ttl_seconds=600,
        now=lambda: NOW,
        token_factory=lambda: BOOTSTRAP_TOKEN,
    )
    first = load_operator_bootstrap(path, now=lambda: NOW)
    second = load_operator_bootstrap(path, now=lambda: NOW)
    first_sessions = DashboardSessionAuthority(
        first,
        now=lambda: NOW,
        signing_key=SIGNING_KEY,
        token_factory=token_factory(),
    )
    second_sessions = DashboardSessionAuthority(
        second,
        now=lambda: NOW,
        signing_key=SIGNING_KEY,
        token_factory=token_factory(),
    )

    assert first_sessions.durable_bootstrap_consumption is True
    assert first_sessions.open_session(BOOTSTRAP_TOKEN)["principal_id"] == "mike"
    assert not path.exists()
    with pytest.raises(
        DashboardControlDenied, match="OPERATOR_BOOTSTRAP_CONSUMPTION_FAILED"
    ):
        second_sessions.open_session(BOOTSTRAP_TOKEN)


def test_controlled_server_rejects_process_local_bootstrap(tmp_path: Path) -> None:
    store, sessions, controls = configured_control(tmp_path)
    assert sessions.durable_bootstrap_consumption is False
    with pytest.raises(
        ValueError, match="requires durable bootstrap-file consumption"
    ):
        create_dashboard_server(
            database=store.path,
            host="127.0.0.1",
            port=0,
            sessions=sessions,
            controls=controls,
        )


def test_session_is_one_use_csrf_bound_and_confirmation_is_signed(tmp_path: Path) -> None:
    _store, sessions, controls = configured_control(tmp_path)
    session = open_session(sessions)
    with pytest.raises(DashboardControlDenied, match="OPERATOR_SESSION_DENIED"):
        sessions.open_session(BOOTSTRAP_TOKEN)
    with pytest.raises(DashboardControlDenied, match="OPERATOR_CSRF_DENIED"):
        sessions.authenticate(
            session["session_token"], csrf_token="X" * 43, require_csrf=True
        )
    authenticated = sessions.authenticate(
        session["session_token"],
        csrf_token=session["csrf_token"],
        require_csrf=True,
    )
    assert authenticated["session_id_sha256"] == session["session_id_sha256"]

    preview = pause_preview(controls, session)
    confirmation = controls.confirm(preview, session=authenticated)
    assert confirmation["preview_sha256"] == preview["preview_sha256"]
    tampered = {**confirmation, "principal_id": "attacker"}
    with pytest.raises(DashboardControlDenied, match="OPERATOR_CONFIRMATION_INVALID"):
        controls.apply(
            preview,
            tampered,
            session_id_sha256=session["session_id_sha256"],
        )


def test_confirmation_expiry_is_rechecked_after_writer_lock_wait(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": NOW}
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: clock["now"])
    OperatorCapabilityCatalog(store).install()
    store.append(
        "principal.profile.installed",
        {
            "schema_version": 1,
            "profile_digest": "a" * 64,
            "profile": {"principal_id": "mike"},
        },
    )
    sessions = DashboardSessionAuthority(
        OperatorBootstrap("mike", BOOTSTRAP_TOKEN, FUTURE),
        now=lambda: clock["now"],
        signing_key=SIGNING_KEY,
        token_factory=token_factory(),
    )
    controls = DashboardControlService(store, sessions=sessions)
    session = open_session(sessions)
    preview = pause_preview(controls, session)
    confirmation = controls.confirm(preview, session=session)
    original_append = store.append_computed_once

    def delayed_append(kind: str, factory: Any) -> Any:
        clock["now"] = "2026-09-04T11:03:01+00:00"
        return original_append(kind, factory)

    monkeypatch.setattr(store, "append_computed_once", delayed_append)
    before = store.count()
    with pytest.raises(
        DashboardControlDenied, match="OPERATOR_CONFIRMATION_EXPIRED"
    ):
        controls.apply(
            preview,
            confirmation,
            session_id_sha256=session["session_id_sha256"],
        )
    assert store.count() == before
    assert not store.events("capability.control.state_changed")


def test_preview_is_deterministic_zero_mutation_and_apply_has_exact_readback(
    tmp_path: Path,
) -> None:
    store, sessions, controls = configured_control(tmp_path)
    session = open_session(sessions)
    before_count = store.count()
    before_chain = store.verify_chain()

    preview = pause_preview(controls, session)
    assert pause_preview(controls, session) == preview
    assert preview["before"]["effective_state"] == "DENY"
    assert preview["after"]["effective_state"] == "PAUSED"
    assert preview["impact"] == {
        "configured_intent_changed": True,
        "configured_intent_expanded": False,
        "lease_created": False,
        "ticket_created": False,
        "route_changed": False,
        "external_effects": 0,
        "readback": "canonical capability registry plus valid event chain",
    }
    assert store.count() == before_count
    assert store.verify_chain() == before_chain

    confirmation, result = confirm_and_apply(controls, session, preview)
    assert result["status"] == "VERIFIED"
    assert result["capability"] == CONTROL_CAPABILITY
    assert result["active"] is False
    assert result["effective_state"] == "PAUSED"
    assert result["external_effects"] == 0
    assert result["lease_created"] is False
    assert result["ticket_created"] is False
    assert store.count() == before_count + 1
    assert store.verify_chain()["valid"] is True

    status = CapabilityRegistry(store).status()
    web = status["specifications"][CONTROL_CAPABILITY]
    assert web["active"] is True
    assert web["administrative_active"] is False
    assert web["spec_digest"] == result["spec_digest"]
    assert web["revision"] == result["spec_revision"]
    assert web["administrative_revision"] == result["control_revision"]
    count_before_catalog_reinstall = store.count()
    OperatorCapabilityCatalog(store).install()
    assert store.count() == count_before_catalog_reinstall
    assert CapabilityRegistry(store).status()["specifications"][CONTROL_CAPABILITY][
        "administrative_active"
    ] is False
    event = store.event(result["applied_event_id"])
    assert event is not None
    receipt = event.payload["control_receipt"]
    assert receipt["confirmation_id"] == result["confirmation_id"]
    assert receipt["preview_sha256"] == preview["preview_sha256"]
    assert receipt["external_effects"] == 0
    assert event.payload["authority"] == "operator"

    persisted = json.dumps([item.payload for item in store.events()], sort_keys=True)
    for secret in (
        BOOTSTRAP_TOKEN,
        session["session_token"],
        session["csrf_token"],
        confirmation["signature"],
        SECRET_SENTINEL,
    ):
        assert secret not in persisted
    narrative = HumanNarrative(store).digest(limit=1)
    narrative_rows = cast(list[dict[str, Any]], narrative["rows"])
    assert narrative_rows[0]["family"] == "capability-control"
    assert "no lease, ticket, or external effect" in narrative_rows[0]["text"]


def test_resume_is_reversible_only_without_active_lease(tmp_path: Path) -> None:
    store, sessions, controls = configured_control(tmp_path)
    session = open_session(sessions)
    pause = pause_preview(controls, session)
    confirm_and_apply(controls, session, pause)

    resume = controls.preview(
        {
            "draft_id": "draft-resume-web",
            "action": CONTROL_ACTION,
            "capability": CONTROL_CAPABILITY,
            "active": True,
        },
        expires_at=session["expires_at"],
    )
    assert resume["impact"]["configured_intent_expanded"] is True
    assert resume["after"]["effective_state"] == "DENY"
    _confirmation, result = confirm_and_apply(controls, session, resume)
    assert result["active"] is True
    assert result["effective_state"] == "DENY"

    web = CapabilityRegistry(store)._spec_rows()[CONTROL_CAPABILITY]
    CapabilityRegistry(store).grant(
        CapabilityLease(
            id="lease-controlled-web",
            capability=CONTROL_CAPABILITY,
            principal_id="mike",
            scopes=("operator/web/example",),
            expires_at=FUTURE,
            max_actions=1,
            max_bytes=0,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://test",),
        )
    )
    pause_with_lease = pause_preview(
        controls, session, draft_id="draft-pause-web-with-lease"
    )
    confirm_and_apply(controls, session, pause_with_lease)
    with pytest.raises(
        DashboardControlDenied, match="CONTROL_ENABLE_WITH_ACTIVE_LEASES_DENIED"
    ):
        controls.preview(
            {
                "draft_id": "draft-resume-denied",
                "action": CONTROL_ACTION,
                "capability": CONTROL_CAPABILITY,
                "active": True,
            },
            expires_at=session["expires_at"],
        )
    assert web[0].name == CONTROL_CAPABILITY


def test_pause_blocks_evaluation_new_leases_and_ticket_issuance(tmp_path: Path) -> None:
    store, sessions, controls = configured_control(tmp_path)
    registry = CapabilityRegistry(store)
    spec = registry.status()["specifications"][CONTROL_CAPABILITY]
    registry.grant(
        CapabilityLease(
            id="lease-web-before-pause",
            capability=CONTROL_CAPABILITY,
            principal_id="mike",
            scopes=("operator/web/example",),
            expires_at=FUTURE,
            max_actions=2,
            max_bytes=0,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://pause-boundary-test",),
        )
    )
    before = registry.evaluate(
        CapabilityRequest(
            id="evaluate-web-before-pause",
            capability=CONTROL_CAPABILITY,
            principal_id="mike",
            scope="operator/web/example",
            lease_id="lease-web-before-pause",
        )
    )
    assert before.mode == "allow"
    authority = ExecutionTicketAuthority(store)
    issued_ticket = ExecutionTicket(
        id="ticket-web-before-pause",
        tool_name="browser_read",
        arguments_sha256="b" * 64,
        goal_id="goal-web-before-pause",
        plan_id="plan-web-before-pause",
        plan_hash="c" * 64,
        stage="read",
        attempt=1,
        principal_id="mike",
        principal_profile_digest="a" * 64,
        capability=CONTROL_CAPABILITY,
        capability_spec_digest=spec["spec_digest"],
        lease_id="lease-web-before-pause",
        scope="operator/web/example",
        expires_at=FUTURE,
        action_budget=1,
        byte_budget=0,
        value_budget_microunits=0,
    )
    authority.issue(
        issued_ticket,
        authority="host_adapter",
        evidence=("host://ticket-before-pause",),
    )

    session = open_session(sessions)
    pause = pause_preview(controls, session)
    confirm_and_apply(controls, session, pause)

    after = registry.evaluate(
        CapabilityRequest(
            id="evaluate-web-after-pause",
            capability=CONTROL_CAPABILITY,
            principal_id="mike",
            scope="operator/web/example",
            lease_id="lease-web-before-pause",
        )
    )
    assert after.mode == "deny"
    assert after.reasons == ("CAPABILITY_ADMINISTRATIVELY_PAUSED",)
    with pytest.raises(
        TicketAuthorityDenied, match="CAPABILITY_ADMINISTRATIVELY_PAUSED"
    ):
        authority.claim_dispatch(
            ticket_id=issued_ticket.id,
            tool_name=issued_ticket.tool_name,
            arguments_sha256=issued_ticket.arguments_sha256,
        )
    with pytest.raises(ValueError, match="administratively paused"):
        registry.grant(
            CapabilityLease(
                id="lease-web-after-pause",
                capability=CONTROL_CAPABILITY,
                principal_id="mike",
                scopes=("operator/web/example",),
                expires_at=FUTURE,
                max_actions=1,
                max_bytes=0,
                max_value_microunits=0,
                issued_by="operator",
                evidence=("operator://must-be-denied",),
            )
        )
    new_ticket = replace(issued_ticket, id="ticket-web-after-pause")
    with pytest.raises(ValueError, match="CAPABILITY_ADMINISTRATIVELY_PAUSED"):
        authority.issue(
            new_ticket,
            authority="host_adapter",
            evidence=("host://must-be-denied",),
        )


def test_unrelated_ledger_event_does_not_stale_target_bound_preview(tmp_path: Path) -> None:
    store, sessions, controls = configured_control(tmp_path)
    session = open_session(sessions)
    preview = pause_preview(controls, session)
    confirmation = controls.confirm(preview, session=session)
    store.append(
        "goal.status_changed",
        {
            "goal_id": "unrelated-goal",
            "from": "active",
            "to": "paused",
            "reason": "unrelated test event",
        },
    )
    result = controls.apply(
        preview,
        confirmation,
        session_id_sha256=session["session_id_sha256"],
    )
    assert result["status"] == "VERIFIED"
    assert result["effective_state"] == "PAUSED"


def test_stale_target_principal_and_kill_switch_fail_closed(tmp_path: Path) -> None:
    store, sessions, controls = configured_control(tmp_path)
    session = open_session(sessions)
    preview = pause_preview(controls, session)
    confirmation = controls.confirm(preview, session=session)

    registry = CapabilityRegistry(store)
    spec, digest, _revision = registry._spec_rows()[CONTROL_CAPABILITY]
    registry.register(
        replace(spec, description=f"{spec.description} Updated."),
        authority="host_adapter",
        evidence=("host://test-state-change",),
        expected_previous_digest=digest,
    )
    with pytest.raises(DashboardControlDenied, match="CONTROL_PREVIEW_STALE"):
        controls.apply(
            preview,
            confirmation,
            session_id_sha256=session["session_id_sha256"],
        )

    fresh = pause_preview(controls, session, draft_id="draft-after-state-change")
    fresh_confirmation = controls.confirm(fresh, session=session)
    GlobalKillSwitch(store).trip(
        trip_id="dashboard-control-stop",
        authority="operator",
        reason="test stop",
    )
    with pytest.raises(DashboardControlDenied, match="GLOBAL_KILL_SWITCH_ACTIVE"):
        controls.apply(
            fresh,
            fresh_confirmation,
            session_id_sha256=session["session_id_sha256"],
        )


def test_confirmation_replay_and_two_threads_produce_one_change(tmp_path: Path) -> None:
    store, sessions, controls = configured_control(tmp_path)
    session = open_session(sessions)
    preview = pause_preview(controls, session)
    confirmation = controls.confirm(preview, session=session)

    def apply() -> tuple[str, str]:
        try:
            result = controls.apply(
                preview,
                confirmation,
                session_id_sha256=session["session_id_sha256"],
            )
            return "VERIFIED", result["applied_event_id"]
        except DashboardControlDenied as error:
            return "DENIED", error.reason_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _value: apply(), range(2)))
    assert sorted(result[0] for result in results) == ["DENIED", "VERIFIED"]
    assert any(result == ("DENIED", "CONTROL_CONFIRMATION_REPLAYED") for result in results)
    controlled_events = [
        event
        for event in store.events("capability.control.state_changed")
        if isinstance(event.payload.get("control_receipt"), dict)
    ]
    assert len(controlled_events) == 1

    with pytest.raises(DashboardControlDenied, match="CONTROL_CONFIRMATION_REPLAYED"):
        controls.apply(
            preview,
            confirmation,
            session_id_sha256=session["session_id_sha256"],
        )


def test_two_processes_share_one_atomic_confirmation_result(tmp_path: Path) -> None:
    store, sessions, controls = configured_control(tmp_path)
    session = open_session(sessions)
    preview = pause_preview(controls, session)
    confirmation = controls.confirm(preview, session=session)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    queue = context.Queue()
    processes = [
        context.Process(
            target=_process_apply_worker,
            args=(
                str(store.path),
                preview,
                confirmation,
                session["session_id_sha256"],
                barrier,
                queue,
            ),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    results = [queue.get(timeout=3), queue.get(timeout=3)]
    assert sorted(result[0] for result in results) == ["DENIED", "VERIFIED"]
    assert any(result == ("DENIED", "CONTROL_CONFIRMATION_REPLAYED") for result in results)
    assert len(
        [
            event
            for event in store.events("capability.control.state_changed")
            if isinstance(event.payload.get("control_receipt"), dict)
        ]
    ) == 1
    assert store.verify_chain()["valid"] is True


def test_http_flow_requires_origin_cookie_csrf_and_exact_confirmation(tmp_path: Path) -> None:
    store, sessions, controls = configured_control(
        tmp_path, durable_bootstrap=True
    )
    bootstrap_path = tmp_path / "server-operator-bootstrap.json"
    assert bootstrap_path.is_file()
    before = store.count()
    server = create_dashboard_server(
        database=store.path,
        host="127.0.0.1",
        port=0,
        now=lambda: NOW,
        sessions=sessions,
        controls=controls,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urlopen(f"{base}/api/dashboard", timeout=5) as response:
            locked = json.load(response)
        assert locked["mode"] == "CONTROLLED_HOST_APPLY"
        assert locked["controls"]["installed"] is True
        assert locked["controls"]["authenticated"] is False
        web = next(row for row in locked["permissions"] if row["name"] == CONTROL_CAPABILITY)
        assert web["control_state"] == "AUTHENTICATION_REQUIRED"

        status, denied, _headers = post_json(
            f"{base}/api/operator/session",
            {"bootstrap_token": BOOTSTRAP_TOKEN},
            origin="http://evil.example",
        )
        assert (status, denied["error"]) == (403, "DASHBOARD_ORIGIN_DENIED")
        assert store.count() == before

        status, opened, headers = post_json(
            f"{base}/api/operator/session",
            {"bootstrap_token": BOOTSTRAP_TOKEN},
            origin=base,
        )
        assert status == 200
        assert opened["authenticated"] is True
        assert not bootstrap_path.exists()
        with pytest.raises(ValueError, match="operator bootstrap is unavailable"):
            load_operator_bootstrap(bootstrap_path, now=lambda: NOW)
        assert BOOTSTRAP_TOKEN not in json.dumps(opened)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        assert "HttpOnly" in headers["Set-Cookie"]
        assert "SameSite=Strict" in headers["Set-Cookie"]
        csrf = opened["csrf_token"]

        draft = {
            "draft_id": "draft-http-pause",
            "action": CONTROL_ACTION,
            "capability": CONTROL_CAPABILITY,
            "active": False,
        }
        status, denied, _headers = post_json(
            f"{base}/api/controls/preview",
            {"draft": draft},
            origin=base,
            cookie=cookie,
        )
        assert (status, denied["error"]) == (403, "OPERATOR_CSRF_DENIED")
        assert store.count() == before

        status, preview, _headers = post_json(
            f"{base}/api/controls/preview",
            {"draft": draft},
            origin=base,
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        assert store.count() == before
        status, confirmation, _headers = post_json(
            f"{base}/api/controls/confirm",
            {"preview": preview},
            origin=base,
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        assert store.count() == before
        status, result, _headers = post_json(
            f"{base}/api/controls/apply",
            {"preview": preview, "confirmation": confirmation},
            origin=base,
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        assert result["status"] == "VERIFIED"
        assert result["external_effects"] == 0
        assert store.count() == before + 1

        status, replay, _headers = post_json(
            f"{base}/api/controls/apply",
            {"preview": preview, "confirmation": confirmation},
            origin=base,
            cookie=cookie,
            csrf=csrf,
        )
        assert (status, replay["error"]) == (409, "CONTROL_CONFIRMATION_REPLAYED")
        assert store.count() == before + 1

        with urlopen(
            Request(f"{base}/api/dashboard", headers={"Cookie": cookie}), timeout=5
        ) as response:
            readback = json.load(response)
        web = next(row for row in readback["permissions"] if row["name"] == CONTROL_CAPABILITY)
        assert web["active"] is True
        assert web["administrative_active"] is False
        assert web["effective_state"] == "PAUSED"
        assert readback["controls"]["authenticated"] is True
        serialized = json.dumps(readback, sort_keys=True)
        assert BOOTSTRAP_TOKEN not in serialized
        assert confirmation["signature"] not in serialized
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_http_suppresses_raw_control_exceptions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, sessions, controls = configured_control(
        tmp_path, durable_bootstrap=True
    )
    server = create_dashboard_server(
        database=store.path,
        host="127.0.0.1",
        port=0,
        now=lambda: NOW,
        sessions=sessions,
        controls=controls,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        status, opened, headers = post_json(
            f"{base}/api/operator/session",
            {"bootstrap_token": BOOTSTRAP_TOKEN},
            origin=base,
        )
        assert status == 200
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        monkeypatch.setattr(
            controls,
            "preview",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError(SECRET_SENTINEL)
            ),
        )
        status, payload, _headers = post_json(
            f"{base}/api/controls/preview",
            {
                "draft": {
                    "draft_id": "draft-raw-error",
                    "action": CONTROL_ACTION,
                    "capability": CONTROL_CAPABILITY,
                    "active": False,
                }
            },
            origin=base,
            cookie=cookie,
            csrf=opened["csrf_token"],
        )
        assert status == 500
        assert payload["error"] == "CONTROL_INTERNAL_ERROR"
        assert SECRET_SENTINEL not in json.dumps(payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_malformed_administrative_event_fails_closed(tmp_path: Path) -> None:
    store, _sessions, _controls = configured_control(tmp_path)
    store.append(
        "capability.control.state_changed",
        {
            "schema_version": 1,
            "revision": 1,
            "capability": CONTROL_CAPABILITY,
            "active": False,
            "previous_active": True,
            "previous_control_event_id": None,
            "authority": "operator",
            "control_receipt": {"external_effects": 0},
        },
    )
    with pytest.raises(ValueError, match="controlled capability receipt"):
        CapabilityRegistry(store).status()


def test_snapshot_never_claims_control_created_external_authority(tmp_path: Path) -> None:
    store, sessions, controls = configured_control(tmp_path)
    session = open_session(sessions)
    preview = pause_preview(controls, session)
    confirm_and_apply(controls, session, preview)

    snapshot = build_dashboard_snapshot(store.path, now=NOW)
    summary = cast(dict[str, Any], snapshot["summary"])
    permissions = cast(list[dict[str, Any]], snapshot["permissions"])
    audit = cast(dict[str, Any], snapshot["audit"])
    audit_rows = cast(list[dict[str, Any]], audit["rows"])
    assert summary["external_effects"] == 0
    assert summary["active_leases"] == 0
    web = next(row for row in permissions if row["name"] == CONTROL_CAPABILITY)
    assert web["active"] is True
    assert web["administrative_active"] is False
    assert web["effective_state"] == "PAUSED"
    assert "no lease, ticket, or external effect" in audit_rows[0]["text"]
