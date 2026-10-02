"""Network-free compatibility regressions using the pinned deployment SDKs."""
from __future__ import annotations

from datetime import datetime, timezone
import socket
from unittest.mock import MagicMock

import pytest

from cct_agent import firebase_bridge as module


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_args: object, **_kwargs: object) -> None:
        pytest.fail("network attempted in SDK compatibility test")

    monkeypatch.setattr(socket.socket, "connect", blocked)


def test_real_firebase_identity_constructor_exports(monkeypatch: pytest.MonkeyPatch) -> None:
    firebase_admin = pytest.importorskip("firebase_admin")
    from firebase_admin import auth, tenant_mgt

    monkeypatch.setattr(firebase_admin, "get_app", lambda _name: object())
    verifier = module.FirebaseAdminIdentityVerifier(
        "demo-cctae-control", "owner@example.invalid", None,
    )
    assert auth.InvalidIdTokenError in verifier._invalid_identity_errors
    assert tenant_mgt.TenantIdMismatchError in verifier._invalid_identity_errors
    assert auth.UserDisabledError in verifier._invalid_identity_errors
    assert auth.UserNotFoundError in verifier._invalid_identity_errors


@pytest.mark.parametrize("method", ["pending_requests", "requeue_stale"])
@pytest.mark.parametrize("error_name,expected", [
    ("ResourceExhausted", "QUOTA_BACKOFF"),
    ("ServiceUnavailable", "TRANSIENT_BACKOFF"),
    ("DeadlineExceeded", "TRANSIENT_BACKOFF"),
])
def test_real_firestore_iterator_failure_keeps_original_error_without_retry(
    monkeypatch: pytest.MonkeyPatch, method: str, error_name: str, expected: str,
) -> None:
    firestore = pytest.importorskip("google.cloud.firestore")
    from google.api_core import exceptions
    from google.auth.credentials import AnonymousCredentials

    client = firestore.Client(project="demo-cctae-control", credentials=AnonymousCredentials())
    rpc = MagicMock()
    client._firestore_api_internal = rpc
    error_type = getattr(exceptions, error_name)
    original = error_type("synthetic SDK failure")

    def failed_stream():
        raise original
        yield  # Make failure occur during SDK iterator consumption, not creation.

    rpc.run_query.side_effect = lambda **_: failed_stream()
    monkeypatch.setattr(firestore, "Client", lambda **_: client)
    gateway = module.FirestoreBridgeGateway("demo-cctae-control")
    argument = 10 if method == "pending_requests" else datetime.now(timezone.utc)
    with pytest.raises(error_type) as raised:
        getattr(gateway, method)(argument)
    assert raised.value is original
    assert module._cloud_error_policy().classify(raised.value) == expected
    assert rpc.run_query.call_count == 1
    options = rpc.run_query.call_args.kwargs
    assert options["timeout"] == 10.0
    # Query.stream requires a Retry object, even when its predicate forbids retry.
    assert options["retry"]._predicate(original) is False
