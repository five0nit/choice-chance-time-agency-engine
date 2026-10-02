from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from cct_agent.capabilities import CapabilityRegistry, OperatorCapabilityCatalog
from cct_agent.firebase_bridge import (
    CONFIG_SCHEMA,
    CCTFirebaseBridge,
    BridgeRequestDenied,
    FirebaseAdminIdentityVerifier,
    FirebaseBridgeConfig,
    load_bridge_config,
)
from cct_agent.store import EventStore


NOW = datetime(2026, 9, 5, 1, 0, tzinfo=timezone.utc)
OWNER_UID = "firebase-owner-uid"
OWNER_EMAIL = "owner@example.invalid"


class FakeIdentity:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def verify_owner(
        self,
        uid: str,
        email: str,
        id_token: str,
        *,
        request_created_at: datetime,
        maximum_age_seconds: int,
    ) -> str:
        self.calls.append((uid, email, id_token))
        if uid != OWNER_UID or email != OWNER_EMAIL:
            raise BridgeRequestDenied("FIREBASE_OWNER_IDENTITY_DENIED")
        assert request_created_at == NOW
        assert maximum_age_seconds == 180
        return sha256(id_token.encode()).hexdigest()


class FakeGateway:
    def __init__(self) -> None:
        self.receipts: dict[str, Mapping[str, Any]] = {}
        self.dashboard: Mapping[str, Any] | None = None
        self.status: Mapping[str, Any] | None = None

    def publish_dashboard(self, envelope: Mapping[str, Any]) -> None:
        self.dashboard = dict(envelope)

    def publish_status(self, status: Mapping[str, Any]) -> None:
        self.status = dict(status)

    def requeue_stale(self, now: datetime) -> int:
        return 0

    def pending_requests(self, limit: int) -> list[tuple[str, Mapping[str, Any]]]:
        return []

    def claim(self, request_id: str, instance_id: str, expires_at: datetime) -> bool:
        return True

    def get_receipt(self, request_id: str) -> Mapping[str, Any] | None:
        return self.receipts.get(request_id)

    def complete(self, request_id: str, receipt: Mapping[str, Any]) -> None:
        self.receipts[request_id] = dict(receipt)


def configured_bridge(
    tmp_path: Path,
    *,
    clock: Any = lambda: NOW,
) -> tuple[CCTFirebaseBridge, FakeGateway, FakeIdentity, EventStore]:
    database = tmp_path / "agency.sqlite"
    store = EventStore(database, clock=lambda: clock().isoformat())
    OperatorCapabilityCatalog(store).install()
    store.append(
        "principal.profile.installed",
        {
            "schema_version": 1,
            "profile_digest": "a" * 64,
            "profile": {"principal_id": "mike"},
        },
    )
    gateway = FakeGateway()
    identity = FakeIdentity()
    config = FirebaseBridgeConfig(
        project_id="demo-cctae-control",
        database=database,
        owner_email=OWNER_EMAIL,
        owner_uid=OWNER_UID,
        principal_id="mike",
        poll_seconds=3,
        request_ttl_seconds=180,
        claim_ttl_seconds=60,
        runtime_directory=tmp_path / "runtime",
    )
    return CCTFirebaseBridge(config, gateway, identity, clock=clock), gateway, identity, store


def request(
    request_id: str,
    *,
    kind: str = "PREVIEW",
    active: bool = False,
    id_token: str | None = None,
) -> dict[str, Any]:
    if id_token is None:
        suffix = "cHJldmlldw" if kind == "PREVIEW" else "YXBwbHk"
        id_token = f"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvd25lciIsImtpbmQiOiJ{suffix}ifQ.c2lnbmF0dXJl{suffix}"
    value: dict[str, Any] = {
        "schemaVersion": "cct.firebase_control_request.v1",
        "requestId": request_id,
        "kind": kind,
        "action": "SET_CAPABILITY_ADMINISTRATIVE_ACTIVE",
        "capability": "operator.web",
        "active": active,
        "ownerUid": OWNER_UID,
        "ownerEmail": OWNER_EMAIL,
        "idToken": id_token,
        "state": "PENDING",
        "createdAt": NOW,
    }
    return value


def test_preview_is_zero_mutation_and_apply_has_canonical_readback(tmp_path: Path) -> None:
    bridge, gateway, identity, store = configured_bridge(tmp_path)
    preview_id = "req-previewbridge123456"
    before = store.count()
    preview_receipt = bridge.process_request(preview_id, request(preview_id))

    assert preview_receipt["status"] == "PREVIEW_READY"
    assert preview_receipt["ownerUid"] == OWNER_UID
    assert preview_receipt["authTokenSha256"] == sha256(
        request(preview_id)["idToken"].encode()
    ).hexdigest()
    assert preview_receipt["payload"]["preview"]["after"]["active"] is False
    assert store.count() == before
    assert store.verify_chain()["valid"] is True
    gateway.receipts[preview_id] = preview_receipt

    apply_id = "req-applybridge12345678"
    apply = request(apply_id, kind="APPLY")
    apply["parentRequestId"] = preview_id
    apply["previewSha256"] = preview_receipt["previewSha256"]
    applied = bridge.process_request(apply_id, apply)

    assert applied["status"] == "APPLY_VERIFIED"
    assert applied["payload"]["result"]["status"] == "VERIFIED"
    assert applied["payload"]["result"]["external_effects"] == 0
    assert store.count() == before + 2
    assert CapabilityRegistry(store).status()["specifications"]["operator.web"][
        "administrative_active"
    ] is False
    assert identity.calls == [
        (OWNER_UID, OWNER_EMAIL, request(preview_id)["idToken"]),
        (OWNER_UID, OWNER_EMAIL, request(apply_id, kind="APPLY")["idToken"]),
    ]


def test_apply_retry_recovers_exact_existing_event_without_second_mutation(tmp_path: Path) -> None:
    bridge, gateway, _identity, store = configured_bridge(tmp_path)
    preview_id = "req-recoverpreview12345"
    preview = bridge.process_request(preview_id, request(preview_id))
    gateway.receipts[preview_id] = preview
    first_id = "req-recoverapply123456"
    first = request(first_id, kind="APPLY")
    first.update(parentRequestId=preview_id, previewSha256=preview["previewSha256"])
    result = bridge.process_request(first_id, first)
    count = store.count()

    retry_id = "req-recoverretry123456"
    retry = request(retry_id, kind="APPLY")
    retry.update(parentRequestId=preview_id, previewSha256=preview["previewSha256"])
    recovered = bridge.process_request(retry_id, retry)

    assert result["payload"]["result"]["applied_event_id"] == recovered["payload"]["result"]["applied_event_id"]
    assert recovered["payload"]["result"]["recovered_after_restart"] is True
    assert store.count() == count
    assert len(store.events("capability.control.state_changed")) == 1


def test_wrong_owner_expired_extra_fields_and_receipt_mismatch_fail_closed(tmp_path: Path) -> None:
    bridge, gateway, _identity, _store = configured_bridge(tmp_path)
    wrong = request("req-wrongowner12345678")
    wrong["ownerUid"] = "attacker"
    with pytest.raises(BridgeRequestDenied, match="FIREBASE_OWNER_IDENTITY_DENIED"):
        bridge.process_request(wrong["requestId"], wrong)

    expired = request("req-expiredbridge123456")
    expired["createdAt"] = datetime(2026, 9, 4, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(BridgeRequestDenied, match="FIREBASE_REQUEST_EXPIRED"):
        bridge.process_request(expired["requestId"], expired)

    extra = request("req-extrafieldbridge123")
    extra["rawToken"] = "must-not-be-accepted"
    with pytest.raises(BridgeRequestDenied, match="FIREBASE_REQUEST_INVALID"):
        bridge.process_request(extra["requestId"], extra)

    missing_token = request("req-missingtoken1234567")
    del missing_token["idToken"]
    with pytest.raises(BridgeRequestDenied, match="FIREBASE_REQUEST_INVALID"):
        bridge.process_request(missing_token["requestId"], missing_token)

    malformed_token = request("req-malformedtoken12345", id_token="not-a-jwt")
    with pytest.raises(BridgeRequestDenied, match="FIREBASE_OWNER_TOKEN_INVALID"):
        bridge.process_request(malformed_token["requestId"], malformed_token)

    apply_id = "req-missingreceipt123456"
    apply = request(apply_id, kind="APPLY")
    apply.update(parentRequestId="req-parentmissing123456", previewSha256="b" * 64)
    with pytest.raises(BridgeRequestDenied, match="FIREBASE_PREVIEW_RECEIPT_MISSING"):
        bridge.process_request(apply_id, apply)
    assert gateway.receipts == {}


def test_apply_requires_new_owner_token_and_binds_both_receipts(tmp_path: Path) -> None:
    bridge, gateway, _identity, _store = configured_bridge(tmp_path)
    token = request("req-unusedpreview12345")["idToken"]
    preview_id = "req-tokenpreview123456"
    preview = bridge.process_request(preview_id, request(preview_id, id_token=token))
    gateway.receipts[preview_id] = preview
    apply_id = "req-tokenapply12345678"
    apply = request(apply_id, kind="APPLY", id_token=token)
    apply.update(parentRequestId=preview_id, previewSha256=preview["previewSha256"])

    with pytest.raises(BridgeRequestDenied, match="FIREBASE_OWNER_TOKEN_REUSED"):
        bridge.process_request(apply_id, apply)


def test_post_apply_crash_recovers_after_request_ttl_without_second_mutation(
    tmp_path: Path,
) -> None:
    current = [NOW]
    bridge, gateway, identity, store = configured_bridge(
        tmp_path,
        clock=lambda: current[0],
    )
    preview_id = "req-crashpreview123456"
    preview = bridge.process_request(preview_id, request(preview_id))
    gateway.receipts[preview_id] = preview
    apply_id = "req-crashapply12345678"
    apply = request(apply_id, kind="APPLY")
    apply.update(parentRequestId=preview_id, previewSha256=preview["previewSha256"])

    first = bridge.process_request(apply_id, apply)
    event_count = len(store.events("capability.control.state_changed"))
    current[0] = NOW + timedelta(seconds=181)
    recovered = bridge.process_request(apply_id, apply)

    assert first["status"] == recovered["status"] == "APPLY_VERIFIED"
    assert recovered["payload"]["result"]["recovered_after_restart"] is True
    assert len(store.events("capability.control.state_changed")) == event_count == 1
    authorizations = store.events("firebase.control_request.authorized")
    assert len(authorizations) == 1
    authorization_json = json.dumps(authorizations[0].payload, sort_keys=True)
    assert apply["idToken"] not in authorization_json
    assert OWNER_EMAIL not in authorization_json
    assert len(identity.calls) == 2

    changed_token = request(
        apply_id,
        kind="APPLY",
        id_token=(
            "eyJhbGciOiJSUzI1NiJ9.eyJraW5kIjoiY2hhbmdlZCJ9."
            "c2lnbmF0dXJlLWNoYW5nZWQtdG9rZW4"
        ),
    )
    changed_token.update(
        parentRequestId=preview_id,
        previewSha256=preview["previewSha256"],
    )
    with pytest.raises(BridgeRequestDenied, match="FIREBASE_AUTHORIZATION_COLLISION"):
        bridge.process_request(apply_id, changed_token)

    stale_retry_id = "req-crashretry12345678"
    stale_retry = request(stale_retry_id, kind="APPLY")
    stale_retry.update(
        parentRequestId=preview_id,
        previewSha256=preview["previewSha256"],
    )
    with pytest.raises(BridgeRequestDenied, match="FIREBASE_REQUEST_EXPIRED"):
        bridge.process_request(stale_retry_id, stale_retry)
    assert len(identity.calls) == 2


def test_recorded_authorization_cannot_create_new_effect_after_ttl(
    tmp_path: Path,
) -> None:
    current = [NOW]
    bridge, gateway, identity, store = configured_bridge(
        tmp_path,
        clock=lambda: current[0],
    )
    preview_id = "req-authorizedpreview123"
    preview = bridge.process_request(preview_id, request(preview_id))
    gateway.receipts[preview_id] = preview
    apply_id = "req-authorizedapply12345"
    apply = request(apply_id, kind="APPLY")
    apply.update(parentRequestId=preview_id, previewSha256=preview["previewSha256"])
    normalized = bridge._normalize_request(apply_id, apply)
    bridge._verify_live_authorization(normalized)
    bridge._record_authorization(normalized)
    current[0] = NOW + timedelta(seconds=181)

    with pytest.raises(BridgeRequestDenied, match="FIREBASE_REQUEST_EXPIRED"):
        bridge.process_request(apply_id, apply)

    assert len(identity.calls) == 2
    assert len(store.events("firebase.control_request.authorized")) == 1
    assert not store.events("capability.control.state_changed")


def test_firebase_verifier_rejects_wrong_claims_and_disabled_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import types

    user = types.SimpleNamespace(
        uid=OWNER_UID,
        email=OWNER_EMAIL,
        email_verified=True,
        disabled=False,
        provider_data=[types.SimpleNamespace(provider_id="google.com")],
    )
    claims = {
        "sub": OWNER_UID,
        "email": OWNER_EMAIL,
        "email_verified": True,
        "iat": int(NOW.timestamp()),
        "firebase": {"sign_in_provider": "google.com"},
    }
    auth = types.SimpleNamespace(
        get_user=lambda uid, app: user,
        verify_id_token=lambda token, app, check_revoked: dict(claims),
        InvalidIdTokenError=BridgeRequestDenied,
        UserDisabledError=BridgeRequestDenied,
        UserNotFoundError=BridgeRequestDenied,
    )
    firebase_admin = types.ModuleType("firebase_admin")
    setattr(firebase_admin, "auth", auth)
    setattr(firebase_admin, "tenant_mgt", types.SimpleNamespace(
        TenantIdMismatchError=BridgeRequestDenied,
    ))
    setattr(firebase_admin, "get_app", lambda name: object())
    monkeypatch.setitem(sys.modules, "firebase_admin", firebase_admin)

    verifier = FirebaseAdminIdentityVerifier("demo-cctae-control", OWNER_EMAIL, OWNER_UID)
    token = request("req-verifier123456789")["idToken"]
    digest = verifier.verify_owner(
        OWNER_UID,
        OWNER_EMAIL,
        token,
        request_created_at=NOW,
        maximum_age_seconds=180,
    )
    assert digest == sha256(token.encode()).hexdigest()

    claims["firebase"] = {"sign_in_provider": "custom"}
    with pytest.raises(BridgeRequestDenied, match="FIREBASE_OWNER_TOKEN_INVALID"):
        verifier.verify_owner(
            OWNER_UID,
            OWNER_EMAIL,
            token,
            request_created_at=NOW,
            maximum_age_seconds=180,
        )

    claims["firebase"] = {"sign_in_provider": "google.com"}
    claims["iat"] = int(NOW.timestamp()) - 181
    with pytest.raises(BridgeRequestDenied, match="FIREBASE_OWNER_TOKEN_EXPIRED"):
        verifier.verify_owner(
            OWNER_UID,
            OWNER_EMAIL,
            token,
            request_created_at=NOW,
            maximum_age_seconds=180,
        )

    claims["iat"] = int(NOW.timestamp())
    user.disabled = True
    with pytest.raises(BridgeRequestDenied, match="FIREBASE_OWNER_IDENTITY_DENIED"):
        verifier.verify_owner(
            OWNER_UID,
            OWNER_EMAIL,
            token,
            request_created_at=NOW,
            maximum_age_seconds=180,
        )


def test_dashboard_envelope_is_bounded_and_excludes_local_paths_and_secrets(tmp_path: Path) -> None:
    bridge, _gateway, _identity, _store = configured_bridge(tmp_path)
    envelope = bridge.dashboard_envelope()
    serialized = json.dumps(envelope, sort_keys=True)
    assert envelope["schemaVersion"] == "cct.firebase_dashboard.v1"
    assert envelope["ownerUid"] == OWNER_UID
    assert envelope["snapshot"]["controls"]["bridge_online"] is True
    assert envelope["snapshot"]["controls"]["external_effects_enabled"] is False
    assert str(tmp_path) not in serialized
    assert "bootstrap" not in serialized.casefold()
    assert len(serialized.encode()) < 512 * 1024


def test_config_loader_requires_owner_only_exact_schema(tmp_path: Path) -> None:
    config_path = tmp_path / "bridge.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": CONFIG_SCHEMA,
                "project_id": "demo-cctae",
                "database": str(tmp_path / "agency.sqlite"),
                "owner_email": OWNER_EMAIL,
                "owner_uid": None,
                "principal_id": "mike",
                "poll_seconds": 3,
                "request_ttl_seconds": 180,
                "claim_ttl_seconds": 60,
                "runtime_directory": str(tmp_path / "runtime"),
            }
        ),
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    loaded = load_bridge_config(config_path)
    assert loaded.project_id == "demo-cctae"
    assert loaded.owner_uid is None

    malformed = json.loads(config_path.read_text(encoding="utf-8"))
    malformed["project_id"] = 123456789012
    config_path.write_text(json.dumps(malformed), encoding="utf-8")
    config_path.chmod(0o600)
    with pytest.raises(ValueError, match="project_id is invalid"):
        load_bridge_config(config_path)

    malformed["project_id"] = "demo-cctae"
    config_path.write_text(json.dumps(malformed), encoding="utf-8")
    config_path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only regular file"):
        load_bridge_config(config_path)


# Cloud regression tests use injected exception classes, never Firebase extras.
class FakeQuotaError(Exception):
    pass


class FakeTransientError(Exception):
    pass


class FakeRetryError(Exception):
    def __init__(self, cause: Exception | None = None) -> None:
        super().__init__("PRIVATE-TOKEN-DO-NOT-LOG")
        self.cause = cause


class StopLoop(BaseException):
    pass


def cloud_policy() -> Any:
    from cct_agent import firebase_bridge as module

    return module.CloudErrorPolicy(
        quota=(FakeQuotaError,), transient=(FakeTransientError,), retry=(FakeRetryError,)
    )


def run_scripted_loop(
    tmp_path: Path, outcomes: list[Any], *, poll_seconds: int = 3
) -> tuple[list[int], list[dict[str, Any]], int]:
    from dataclasses import replace
    from types import SimpleNamespace
    from cct_agent import firebase_bridge as module

    bridge, _gateway, _identity, _store = configured_bridge(tmp_path)
    config = replace(bridge.config, poll_seconds=poll_seconds)
    config.runtime_directory.mkdir(mode=0o700)
    calls = 0
    current = [NOW]
    sleeps: list[int] = []
    receipts: list[dict[str, Any]] = []

    def tick() -> dict[str, Any]:
        nonlocal calls
        assert calls == len(sleeps), "cloud retried without a sleep"
        outcome = outcomes[calls]
        calls += 1
        if isinstance(outcome, Exception):
            raise outcome
        return {"status": "ONLINE"}

    def sleep(seconds: int) -> None:
        sleeps.append(seconds)
        path = config.runtime_directory / "bridge-health.json"
        assert path.stat().st_mode & 0o777 == 0o600
        receipts.append(json.loads(path.read_text()))
        current[0] += timedelta(seconds=seconds)
        if calls == len(outcomes):
            raise StopLoop

    with pytest.raises(StopLoop):
        module.run_bridge_loop(
            SimpleNamespace(config=config, run_once=tick),
            once=False, errors=cloud_policy(), sleep=sleep, clock=lambda: current[0],
        )
    return sleeps, receipts, calls


def test_quota_backoff_is_bounded_and_never_retries_without_sleep(tmp_path: Path) -> None:
    sleeps, receipts, calls = run_scripted_loop(
        tmp_path, [FakeQuotaError("PRIVATE-TOKEN-DO-NOT-LOG") for _ in range(6)]
    )
    assert calls == 6
    assert sleeps == [300, 600, 1200, 1800, 1800, 1800]
    assert {receipt["status"] for receipt in receipts} == {"QUOTA_BACKOFF"}
    assert all(receipt["lastSuccessAt"] is None for receipt in receipts)
    assert receipts[0]["nextAttemptAt"] == (NOW + timedelta(seconds=300)).isoformat()


def test_transient_backoff_is_bounded_and_success_resets_it(tmp_path: Path) -> None:
    sleeps, receipts, _calls = run_scripted_loop(
        tmp_path,
        [FakeTransientError() for _ in range(6)]
        + [None, FakeTransientError(), FakeQuotaError(), None, FakeQuotaError()],
    )
    assert sleeps == [60, 60, 120, 240, 300, 300, 60, 60, 300, 60, 300]
    assert receipts[6]["status"] == "ONLINE"
    assert receipts[7]["status"] == "TRANSIENT_BACKOFF"
    assert receipts[7]["lastSuccessAt"] == (NOW + timedelta(seconds=sum(sleeps[:6]))).isoformat()


@pytest.mark.parametrize("poll_seconds,expected", [(2, 60), (3, 60), (30, 60), (60, 60)])
def test_continuous_loop_clamps_legacy_poll_interval(
    tmp_path: Path, poll_seconds: int, expected: int
) -> None:
    sleeps, _receipts, _calls = run_scripted_loop(tmp_path, [None], poll_seconds=poll_seconds)
    assert sleeps == [expected]


@pytest.mark.parametrize("link", ["cause", "__cause__", "__context__"])
def test_retry_error_preserves_quota_classification(link: str) -> None:
    wrapped = FakeRetryError()
    setattr(wrapped, link, FakeRetryError(FakeQuotaError("PRIVATE-TOKEN-DO-NOT-LOG")))
    assert cloud_policy().classify(wrapped) == "QUOTA_BACKOFF"
    assert cloud_policy().classify(FakeRetryError(FakeTransientError())) == "TRANSIENT_BACKOFF"
    assert cloud_policy().classify(FakeRetryError()) == "TRANSIENT_BACKOFF"
    assert cloud_policy().classify(FakeRetryError(ValueError("bug"))) is None
    assert cloud_policy().classify(ValueError("ResourceExhausted")) is None
    wrapped.cause = wrapped
    wrapped.__cause__ = None
    wrapped.__context__ = None
    assert cloud_policy().classify(wrapped) is None


def test_quota_logs_and_local_receipts_never_include_exception_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class UnprintableQuota(FakeQuotaError):
        def __str__(self) -> str:
            raise AssertionError("exception must never be rendered")

    _sleeps, receipts, _calls = run_scripted_loop(tmp_path, [FakeRetryError(UnprintableQuota())])
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "PRIVATE-TOKEN-DO-NOT-LOG" not in captured.out + json.dumps(receipts)
    assert [json.loads(line)["status"] for line in captured.out.splitlines()] == ["QUOTA_BACKOFF"]


@pytest.mark.parametrize("outcome,exit_code,status", [
    (None, 0, "ONLINE"),
    (FakeQuotaError("PRIVATE-TOKEN-DO-NOT-LOG"), 1, "QUOTA_BACKOFF"),
    (FakeRetryError(FakeTransientError()), 1, "TRANSIENT_BACKOFF"),
])
def test_main_once_exit_status_receipt_and_no_sleep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    outcome: Exception | None, exit_code: int, status: str,
) -> None:
    from cct_agent import firebase_bridge as module

    bridge, gateway, identity, _store = configured_bridge(tmp_path)
    monkeypatch.setattr(module, "load_bridge_config", lambda _path: bridge.config)
    monkeypatch.setattr(module, "FirestoreBridgeGateway", lambda _project: gateway)
    monkeypatch.setattr(module, "FirebaseAdminIdentityVerifier", lambda *_args: identity)
    monkeypatch.setattr(module, "_cloud_error_policy", cloud_policy)

    def tick(_self: Any) -> dict[str, Any]:
        if outcome is not None:
            raise outcome
        return {"status": "ONLINE"}

    monkeypatch.setattr(module.CCTFirebaseBridge, "run_once", tick)
    monkeypatch.setattr(module.time, "sleep", lambda _: pytest.fail("--once must not sleep"))
    assert module.main(["--config", "unused", "--once"]) == exit_code
    receipt = json.loads((bridge.config.runtime_directory / "bridge-health.json").read_text())
    assert receipt["status"] == status
    # main released the singleton lock even after cloud failure.
    descriptor, _path = module._lock_runtime(bridge.config.runtime_directory)
    module.os.close(descriptor)


def test_programming_error_is_fatal_sanitized_and_not_a_retry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from cct_agent import firebase_bridge as module

    bridge, _gateway, _identity, _store = configured_bridge(tmp_path)
    bridge.config.runtime_directory.mkdir(mode=0o700)
    bridge.run_once = lambda: (_ for _ in ()).throw(TypeError("PRIVATE-TOKEN-DO-NOT-LOG"))
    with pytest.raises(module.BridgeRuntimeFailure, match="FIREBASE_BRIDGE_FATAL_ERROR"):
        module.run_bridge_loop(
            bridge, once=False, errors=cloud_policy(),
            sleep=lambda _: pytest.fail("fatal error retried"), clock=lambda: NOW,
        )
    receipt = json.loads((bridge.config.runtime_directory / "bridge-health.json").read_text())
    assert receipt["status"] == "FAILED"
    assert receipt["retrySeconds"] == 0
    assert "PRIVATE-TOKEN-DO-NOT-LOG" not in capsys.readouterr().out + json.dumps(receipt)


@pytest.mark.parametrize("error_type", [FakeQuotaError, TypeError])
def test_request_cloud_or_programming_error_is_not_completed_as_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]
) -> None:
    bridge, gateway, _identity, _store = configured_bridge(tmp_path)
    apply_id = "req-cloudfailure123456"
    monkeypatch.setattr(gateway, "pending_requests", lambda _limit: [(apply_id, request(apply_id))])
    monkeypatch.setattr(bridge, "process_request", lambda *_args: (_ for _ in ()).throw(error_type()))
    with pytest.raises(error_type):
        bridge.run_once()
    assert gateway.receipts == {}
    assert gateway.status is None


def test_firestore_rpc_options_are_explicit_and_claim_is_compare_and_set() -> None:
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from cct_agent import firebase_bridge as module

    class FailedPrecondition(Exception):
        pass

    gateway = module.FirestoreBridgeGateway.__new__(module.FirestoreBridgeGateway)
    gateway._firestore = SimpleNamespace(
        SERVER_TIMESTAMP=object(), DELETE_FIELD=object(),
        LastUpdateOption=lambda timestamp: ("last-update", timestamp),
    )
    gateway._failed_precondition = FailedPrecondition
    gateway._field_filter = lambda *args: args
    gateway._stream_retry = MagicMock()
    gateway.client = MagicMock()
    collection = gateway.client.collection.return_value
    document = collection.document.return_value
    snapshot = document.get.return_value
    snapshot.exists = True
    snapshot.to_dict.return_value = {"state": "PENDING"}
    snapshot.update_time = NOW
    stale = MagicMock()
    stale.to_dict.return_value = {"claimExpiresAt": NOW - timedelta(seconds=1)}
    collection.where.return_value.stream.return_value = [stale]
    collection.where.return_value.limit.return_value.stream.return_value = []
    options = {"retry": None, "timeout": 10.0}

    gateway._projection_cache = module.ProjectionCache()
    snapshot.to_dict.side_effect = lambda: document.set.call_args.args[0]
    gateway.publish_dashboard({})
    assert isinstance(document.set.call_args.args[0]["publishedAt"], datetime)
    assert document.set.call_args.kwargs == options
    gateway.publish_status({"status": "ONLINE"})
    assert document.set.call_args.args[0]["status"] == "ONLINE"
    assert document.set.call_args.kwargs == options
    snapshot.to_dict.side_effect = None
    assert gateway.requeue_stale(NOW) == 1
    collection.where.return_value.stream.assert_called_with(
        retry=gateway._stream_retry, timeout=10.0,
    )
    assert stale.reference.update.call_args.kwargs == options
    assert gateway.pending_requests(10) == []
    collection.where.return_value.limit.return_value.stream.assert_called_with(
        retry=gateway._stream_retry, timeout=10.0,
    )
    gateway.get_receipt("req-rpcoptions12345678")
    document.get.assert_called_with(**options)
    assert gateway.claim("req-rpcoptions12345678", "instance", NOW) is True
    document.get.assert_called_with(**options)
    assert document.update.call_args.kwargs == {"option": ("last-update", NOW), **options}
    document.update.side_effect = FailedPrecondition()
    assert gateway.claim("req-rpcoptions12345678", "instance", NOW) is False
    document.update.reset_mock()
    snapshot.to_dict.return_value = {"state": "PROCESSING"}
    assert gateway.claim("req-rpcoptions12345678", "instance", NOW) is False
    document.update.assert_not_called()
    gateway.complete("req-rpcoptions12345678", {"status": "APPLY_VERIFIED"})
    gateway.client.batch.return_value.commit.assert_called_with(**options)
    gateway.client.transaction.assert_not_called()


@pytest.mark.parametrize("error_type", [FakeQuotaError, FakeTransientError, TypeError])
def test_auth_infrastructure_and_programming_errors_are_not_owner_denials(
    error_type: type[Exception],
) -> None:
    from types import SimpleNamespace

    verifier = FirebaseAdminIdentityVerifier.__new__(FirebaseAdminIdentityVerifier)
    verifier.expected_email = OWNER_EMAIL
    verifier.expected_uid = OWNER_UID
    verifier._app = object()
    verifier._invalid_identity_errors = (BridgeRequestDenied,)
    verifier._auth = SimpleNamespace(
        verify_id_token=lambda *_args, **_kwargs: (_ for _ in ()).throw(error_type()),
    )
    with pytest.raises(error_type):
        verifier.verify_owner(
            OWNER_UID, OWNER_EMAIL, "unused", request_created_at=NOW, maximum_age_seconds=180,
        )


def test_quota_after_apply_recovers_exact_event_after_backoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cct_agent import firebase_bridge as module

    current = [NOW]
    bridge, gateway, identity, store = configured_bridge(tmp_path, clock=lambda: current[0])
    bridge.config.runtime_directory.mkdir(mode=0o700)
    preview_id = "req-quotapreview123456"
    preview = bridge.process_request(preview_id, request(preview_id))
    gateway.receipts[preview_id] = preview
    apply_id = "req-quotaapply12345678"
    apply = request(apply_id, kind="APPLY")
    apply.update(parentRequestId=preview_id, previewSha256=preview["previewSha256"])
    monkeypatch.setattr(gateway, "pending_requests", lambda _: [(apply_id, apply)])
    original_complete = gateway.complete
    completion_calls = 0

    def complete(request_id: str, receipt: Mapping[str, Any]) -> None:
        nonlocal completion_calls
        completion_calls += 1
        if completion_calls == 1:
            raise FakeRetryError(FakeQuotaError("PRIVATE-TOKEN-DO-NOT-LOG"))
        original_complete(request_id, receipt)

    monkeypatch.setattr(gateway, "complete", complete)
    observed: list[str] = []

    def sleep(seconds: float) -> None:
        health = json.loads((bridge.config.runtime_directory / "bridge-health.json").read_text())
        observed.append(health["status"])
        if len(observed) == 1:
            assert seconds == 300
            assert gateway.status is None
            assert apply_id not in gateway.receipts
            current[0] += timedelta(seconds=seconds)
        else:
            assert seconds == 60
            raise StopLoop

    with pytest.raises(StopLoop):
        module.run_bridge_loop(
            bridge, once=False, errors=cloud_policy(), sleep=sleep, clock=lambda: current[0],
        )
    assert observed == ["QUOTA_BACKOFF", "ONLINE"]
    assert gateway.receipts[apply_id]["payload"]["result"]["recovered_after_restart"] is True
    assert len(store.events("capability.control.state_changed")) == 1
    assert len(store.events("firebase.control_request.authorized")) == 1
    assert len(identity.calls) == 2
    assert store.verify_chain()["valid"] is True


def test_local_health_replaces_symlinks_without_writing_the_target(tmp_path: Path) -> None:
    from cct_agent import firebase_bridge as module

    runtime = tmp_path / "runtime"
    descriptor, _ = module._lock_runtime(runtime)
    try:
        other = tmp_path / "do-not-change"
        other.write_text("unchanged")
        health = runtime / "bridge-health.json"
        health.symlink_to(other)
        module._write_local_health(runtime, {"status": "QUOTA_BACKOFF"})
        assert other.read_text() == "unchanged"
        assert not health.is_symlink()
        assert health.stat().st_mode & 0o777 == 0o600
        assert runtime.stat().st_mode & 0o777 == 0o700
        assert json.loads(health.read_text())["status"] == "QUOTA_BACKOFF"
    finally:
        module.os.close(descriptor)


def test_installed_firestore_sdk_serializes_atomic_claim_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Optional local-only compatibility gate against the existing pinned extras.
    firestore = pytest.importorskip("google.cloud.firestore")
    from google.api_core import exceptions
    from google.auth.credentials import AnonymousCredentials
    from google.cloud.firestore_v1 import types
    from unittest.mock import MagicMock
    from cct_agent import firebase_bridge as module

    monkeypatch.setattr(module.socket.socket, "connect", lambda *_: pytest.fail("network attempted"))
    client = firestore.Client(project="demo-cctae-control", credentials=AnonymousCredentials())
    rpc = MagicMock()
    client._firestore_api_internal = rpc
    document_path = "projects/demo-cctae-control/databases/(default)/documents/cct_control_requests/req-sdkclaim123456789"
    rpc.batch_get_documents.return_value = iter([types.BatchGetDocumentsResponse(
        found=types.Document(
            name=document_path, fields={"state": types.Value(string_value="PENDING")},
            create_time=NOW, update_time=NOW,
        ), read_time=NOW,
    )])
    rpc.commit.return_value = types.CommitResponse(
        write_results=[types.WriteResult(update_time=NOW)], commit_time=NOW,
    )
    monkeypatch.setattr(firestore, "Client", lambda **_: client)
    gateway = module.FirestoreBridgeGateway("demo-cctae-control")
    assert gateway.claim("req-sdkclaim123456789", "instance", NOW) is True
    assert rpc.batch_get_documents.call_args.kwargs["retry"] is None
    assert rpc.batch_get_documents.call_args.kwargs["timeout"] == 10.0
    assert rpc.commit.call_args.kwargs["retry"] is None
    assert rpc.commit.call_args.kwargs["timeout"] == 10.0
    writes = rpc.commit.call_args.kwargs["request"]["writes"]
    assert writes[0].current_document.update_time == NOW
    policy = module._cloud_error_policy()
    assert policy.classify(exceptions.ResourceExhausted("private")) == "QUOTA_BACKOFF"
    assert policy.classify(exceptions.RetryError("private", exceptions.ResourceExhausted("private"))) == "QUOTA_BACKOFF"
