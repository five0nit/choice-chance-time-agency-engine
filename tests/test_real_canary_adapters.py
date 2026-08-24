from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import sqlite3
from pathlib import Path
import sys
from typing import Any

import pytest

from cct_agent.commands import CommandSpec
from cct_agent.real_canaries import (
    Generalist2ProfileDeploymentAdapter,
    HostProfileRuntimeState,
    PrivateTelegramDeliveryAdapter,
    ProfileCanaryDenied,
    ProfileDeploymentRequest,
    ProfileDeploymentTarget,
    ProfileRollbackRequest,
    TelegramDeliveryDenied,
    TelegramDeliveryReadback,
    TelegramDeliveryRequest,
    TelegramDeliveryTarget,
)
from cct_agent.store import EventStore, canonical_json
from cct_agent.verification import HostRegisteredVerifier, VerificationRequest, VerifierSpec
from tests.test_pursuit_dialogue import setup_dialogue


PLAN_SHA256 = sha256(b"slice-14-real-canary-plan").hexdigest()
WHEEL = b"exact cct wheel artifact\n"
PRIVATE_SENTINEL = "REAL_CANARY_PRIVATE_SENTINEL_91a6_not_for_ledger"
RECIPIENT_BINDING = sha256(b"generalist2:telegram:mike-home-private-dm").hexdigest()


class FakeProfileDriver:
    def __init__(self, state: HostProfileRuntimeState) -> None:
        self.state = state
        self.before_by_operation: dict[str, HostProfileRuntimeState] = {}
        self.deploy_calls = 0
        self.rollback_calls = 0

    def inspect(self, target: ProfileDeploymentTarget) -> HostProfileRuntimeState:
        assert target.profile_name == "generalist2"
        return self.state

    def deploy(self, command: Any) -> None:
        if command.operation_id in self.before_by_operation:
            return
        self.deploy_calls += 1
        self.before_by_operation[command.operation_id] = self.state
        self.state = HostProfileRuntimeState(
            profile_name="generalist2",
            service_name="hermes-gateway-generalist2.service",
            package_name="cct-agency-engine",
            plugin_name="cct-agency",
            package_version="0.9.0a3",
            artifact_sha256=command.artifact_sha256,
            config_sha256=sha256(b"enabled exact cct config").hexdigest(),
            module_path_sha256=sha256(b"profile-local/cct_agent/__init__.py").hexdigest(),
            plugin_enabled=True,
            last_operation_id=command.operation_id,
        )

    def rollback(self, command: Any) -> None:
        if self.state.last_operation_id == command.operation_id:
            return
        self.rollback_calls += 1
        before = self.before_by_operation[command.deployment_operation_id]
        self.state = replace(before, last_operation_id=command.operation_id)


class FakeTelegramDriver:
    def __init__(self) -> None:
        self.rows: dict[str, TelegramDeliveryReadback] = {}
        self.delivery_calls = 0
        self.raise_after_effect = False

    def inspect(
        self, target: TelegramDeliveryTarget, delivery_id: str
    ) -> TelegramDeliveryReadback | None:
        assert target.recipient_binding_sha256 == RECIPIENT_BINDING
        return self.rows.get(delivery_id)

    def deliver(self, command: Any) -> None:
        if command.operation_id not in self.rows:
            self.delivery_calls += 1
            self.rows[command.operation_id] = TelegramDeliveryReadback(
                operation_id=command.operation_id,
                target_id=command.target_id,
                proposal_event_id=command.proposal_event_id,
                proposal_id=command.proposal_id,
                proposal_revision=command.proposal_revision,
                portfolio_sha256=command.portfolio_sha256,
                recipient_binding_sha256=command.recipient_binding_sha256,
                message_sha256=command.message_sha256,
                message_byte_count=len(command.message.encode("utf-8")),
                provider_receipt_sha256=sha256(
                    f"telegram-receipt:{command.operation_id}".encode()
                ).hexdigest(),
                provider_message_id_sha256=sha256(
                    f"telegram-message:{command.operation_id}".encode()
                ).hexdigest(),
                chat_type="private",
                delivered=True,
            )
        if self.raise_after_effect:
            self.raise_after_effect = False
            raise RuntimeError("simulated transport return crash")


def verifier_spec() -> VerifierSpec:
    return VerifierSpec(
        id="release-wheel-verifier",
        kind="build",
        plan_id="slice14-release-plan",
        plan_sha256=PLAN_SHA256,
        stage_id="verify-wheel",
        command=CommandSpec(
            id="release-wheel-command",
            argv=(sys.executable, "-c", "raise SystemExit(0)"),
            cwd=".",
            environment=(),
            timeout_ms=2000,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
        ),
        snapshot_paths=("dist/cct_agency_engine-0.9.0a3-py3-none-any.whl", "project.txt"),
        max_snapshot_file_bytes=8192,
        max_snapshot_total_bytes=16384,
    )


def profile_target(**changes: Any) -> ProfileDeploymentTarget:
    values: dict[str, Any] = {
        "id": "generalist2-cct-plugin",
        "kind": "hermes_profile_plugin",
        "profile_name": "generalist2",
        "service_name": "hermes-gateway-generalist2.service",
        "package_name": "cct-agency-engine",
        "plugin_name": "cct-agency",
        "package_version": "0.9.0a3",
        "artifact_relative_path": "dist/cct_agency_engine-0.9.0a3-py3-none-any.whl",
        "state_db_relative_path": "cct-agency/agency.sqlite",
        "verifier_id": "release-wheel-verifier",
        "max_artifact_bytes": 8192,
    }
    values.update(changes)
    return ProfileDeploymentTarget(**values)


def initial_profile_state() -> HostProfileRuntimeState:
    return HostProfileRuntimeState(
        profile_name="generalist2",
        service_name="hermes-gateway-generalist2.service",
        package_name="cct-agency-engine",
        plugin_name="cct-agency",
        package_version="0.9.0a2",
        artifact_sha256=sha256(b"prior wheel").hexdigest(),
        config_sha256=sha256(b"prior config").hexdigest(),
        module_path_sha256=sha256(b"prior module path").hexdigest(),
        plugin_enabled=True,
        last_operation_id=None,
    )


def build_profile_fixture(tmp_path: Path, *, artifact: bytes = WHEEL):
    workspace = tmp_path / "workspace"
    (workspace / "dist").mkdir(parents=True)
    artifact_path = workspace / "dist" / "cct_agency_engine-0.9.0a3-py3-none-any.whl"
    artifact_path.write_bytes(artifact)
    (workspace / "project.txt").write_text("verified source\n")
    profile_root = tmp_path / "profiles" / "generalist2"
    state_db = profile_root / "cct-agency" / "agency.sqlite"
    state_db.parent.mkdir(parents=True)
    with sqlite3.connect(state_db) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE continuity(seq INTEGER PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO continuity(value) VALUES ('constitution-root')")
    adapter_state = tmp_path / "adapter-state"
    adapter_state.mkdir()
    store = EventStore(tmp_path / "canary.sqlite")
    verifier = HostRegisteredVerifier(
        store,
        workspace_root=workspace,
        verifiers=(verifier_spec(),),
        allowed_executables=frozenset({sys.executable}),
    )
    snapshot = verifier.snapshot("release-wheel-verifier")
    verification_request = VerificationRequest(
        id="slice14-wheel-verification",
        verifier_id="release-wheel-verifier",
        plan_id="slice14-release-plan",
        plan_sha256=PLAN_SHA256,
        stage_id="verify-wheel",
        expected_snapshot_sha256=snapshot.sha256,
    )
    driver = FakeProfileDriver(initial_profile_state())
    adapter = Generalist2ProfileDeploymentAdapter(
        store,
        workspace_root=workspace,
        profile_root=profile_root,
        adapter_state_root=adapter_state,
        targets=(profile_target(),),
        verifier=verifier,
        driver=driver,
    )
    return (
        adapter,
        driver,
        verifier,
        store,
        workspace,
        profile_root,
        adapter_state,
        verification_request,
    )


def deployment_request(adapter: Generalist2ProfileDeploymentAdapter) -> ProfileDeploymentRequest:
    preview = adapter.preview(
        target_id="generalist2-cct-plugin",
        verification_request_id="slice14-wheel-verification",
    )
    return ProfileDeploymentRequest(
        id="deploy-generalist2-cct-1",
        target_id=preview.target_id,
        verification_request_id=preview.verification_request_id,
        expected_verification_event_id=preview.verification_event_id,
        expected_artifact_sha256=preview.artifact_sha256,
        expected_manifest_sha256=preview.manifest_sha256,
        expected_before_runtime_sha256=preview.before_runtime_sha256,
        expected_state_db_logical_sha256=preview.state_db_logical_sha256,
    )


def test_exact_generalist2_wheel_deploys_with_sqlite_backup_readback_and_reversible_rollback(
    tmp_path: Path,
) -> None:
    artifact = WHEEL + PRIVATE_SENTINEL.encode()
    adapter, driver, verifier, store, _workspace, profile_root, state_root, request_verify = (
        build_profile_fixture(tmp_path, artifact=artifact)
    )
    assert verifier.execute(request_verify).status == "passed"
    request = deployment_request(adapter)

    deployed = adapter.deploy(request)
    replay = adapter.deploy(request)

    assert deployed.status == "deployed"
    assert deployed.profile_name == "generalist2"
    assert deployed.service_name == "hermes-gateway-generalist2.service"
    assert deployed.artifact_sha256 == sha256(artifact).hexdigest()
    assert deployed.artifact_readback_verified is True
    assert deployed.profile_mutation_count == 1
    assert deployed.sqlite_backup_verified is True
    assert deployed.state_db_restored is False
    assert replay.replayed is True
    assert driver.deploy_calls == 1
    backup = state_root / "backups" / "deploy-generalist2-cct-1.sqlite"
    assert backup.is_file()
    with sqlite3.connect(backup) as connection:
        assert connection.execute("SELECT value FROM continuity").fetchone()[0] == "constitution-root"

    # Continuity advances after deployment. Rollback must never overwrite live SQLite.
    state_db = profile_root / "cct-agency" / "agency.sqlite"
    with sqlite3.connect(state_db) as connection:
        connection.execute("INSERT INTO continuity(value) VALUES ('post-deploy-event')")
    rollback_request = ProfileRollbackRequest(
        id="rollback-generalist2-cct-1",
        deployment_request_id=request.id,
        expected_deployment_event_id=deployed.terminal_event_id,
        expected_deployed_runtime_sha256=deployed.after_runtime_sha256,
        expected_backup_sha256=deployed.sqlite_backup_sha256,
    )
    rolled_back = adapter.rollback(rollback_request)
    rollback_replay = adapter.rollback(rollback_request)

    assert rolled_back.status == "rolled_back"
    assert rolled_back.runtime_readback_verified is True
    assert rolled_back.state_db_restored is False
    assert rolled_back.rollback_mutation_count == 1
    assert rollback_replay.replayed is True
    assert driver.rollback_calls == 1
    with sqlite3.connect(state_db) as connection:
        assert connection.execute("SELECT value FROM continuity ORDER BY seq").fetchall() == [
            ("constitution-root",),
            ("post-deploy-event",),
        ]
    assert store.verify_chain()["valid"] is True
    persisted = canonical_json([event.payload for event in store.events()])
    assert PRIVATE_SENTINEL not in persisted
    assert str(profile_root) not in persisted
    assert '"artifact_content"' not in persisted


def test_profile_deploy_adopts_post_effect_crash_once_across_fresh_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, driver, verifier, store, workspace, profile_root, state_root, request_verify = (
        build_profile_fixture(tmp_path)
    )
    verifier.execute(request_verify)
    request = deployment_request(adapter)
    original = adapter._record_deployment_completion

    def crash(*args: Any, **kwargs: Any) -> Any:
        raise SystemExit("simulated crash after profile effect")

    monkeypatch.setattr(adapter, "_record_deployment_completion", crash)
    with pytest.raises(SystemExit, match="simulated crash"):
        adapter.deploy(request)
    assert driver.deploy_calls == 1
    assert not store.events("canary.profile.deployment.completed")

    verifier2 = HostRegisteredVerifier(
        store,
        workspace_root=workspace,
        verifiers=(verifier_spec(),),
        allowed_executables=frozenset({sys.executable}),
    )
    restarted = Generalist2ProfileDeploymentAdapter(
        store,
        workspace_root=workspace,
        profile_root=profile_root,
        adapter_state_root=state_root,
        targets=(profile_target(),),
        verifier=verifier2,
        driver=driver,
    )
    recovered = restarted.deploy(request)

    assert recovered.replayed is True
    assert driver.deploy_calls == 1
    assert len(store.events("canary.profile.deployment.claimed")) == 1
    assert len(store.events("canary.profile.deployment.completed")) == 1
    assert recovered.terminal_event_id
    monkeypatch.setattr(adapter, "_record_deployment_completion", original)


def test_profile_target_artifact_and_foreign_state_fail_closed_before_host_call(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="generalist2"):
        profile_target(profile_name="default")
    with pytest.raises(ValueError, match="Generalist2"):
        profile_target(service_name="hermes-gateway.service")
    adapter, driver, verifier, store, workspace, *_rest, request_verify = build_profile_fixture(tmp_path)
    verifier.execute(request_verify)
    request = deployment_request(adapter)
    (workspace / "dist" / "cct_agency_engine-0.9.0a3-py3-none-any.whl").write_bytes(b"drift")
    with pytest.raises(ProfileCanaryDenied, match="PROJECT_SNAPSHOT_STALE"):
        adapter.deploy(request)
    assert driver.deploy_calls == 0
    assert not store.events("canary.profile.deployment.claimed")


def telegram_target(**changes: Any) -> TelegramDeliveryTarget:
    values: dict[str, Any] = {
        "id": "generalist2-mike-private-dm",
        "kind": "hermes_private_delivery",
        "profile_name": "generalist2",
        "service_name": "hermes-gateway-generalist2.service",
        "platform": "telegram",
        "chat_type": "private",
        "principal_id": "mike",
        "recipient_binding_sha256": RECIPIENT_BINDING,
        "max_message_chars": 1800,
    }
    values.update(changes)
    return TelegramDeliveryTarget(**values)


def telegram_fixture(tmp_path: Path):
    store, _kernel, dialogue, proposal = setup_dialogue(tmp_path)
    presentation = dialogue.run_once(wake_index=1, time_bucket="2026-08-24")
    assert presentation["reason"] == "EMITTED"
    driver = FakeTelegramDriver()
    state_root = tmp_path / "delivery-state"
    state_root.mkdir()
    adapter = PrivateTelegramDeliveryAdapter(
        store,
        adapter_state_root=state_root,
        targets=(telegram_target(),),
        driver=driver,
    )
    return adapter, driver, store, state_root, proposal


def telegram_request(adapter: PrivateTelegramDeliveryAdapter) -> TelegramDeliveryRequest:
    preview = adapter.preview(
        target_id="generalist2-mike-private-dm",
        proposal_id="priority-20260824",
        proposal_revision=1,
    )
    return TelegramDeliveryRequest(
        id="telegram-priority-delivery-1",
        target_id=preview.target_id,
        proposal_id=preview.proposal_id,
        proposal_revision=preview.proposal_revision,
        expected_proposal_event_id=preview.proposal_event_id,
        expected_portfolio_sha256=preview.portfolio_sha256,
        expected_message_sha256=preview.message_sha256,
        expected_preview_sha256=preview.preview_sha256,
    )


def test_private_proposal_bound_telegram_delivery_readback_is_exactly_once_and_hash_only(
    tmp_path: Path,
) -> None:
    adapter, driver, store, _state_root, proposal = telegram_fixture(tmp_path)
    request = telegram_request(adapter)

    delivered = adapter.deliver(request)
    store.append(
        "pursuit.dialogue.reply.applied",
        {
            "proposal_event_id": delivered.proposal_event_id,
            "reply_id": "reply-after-real-delivery",
        },
    )
    replay = adapter.deliver(request)

    assert delivered.status == "delivered"
    assert delivered.profile_name == "generalist2"
    assert delivered.service_name == "hermes-gateway-generalist2.service"
    assert delivered.platform == "telegram"
    assert delivered.chat_type == "private"
    assert delivered.principal_id == "mike"
    assert delivered.proposal_id == proposal["proposal_id"]
    assert delivered.portfolio_sha256 == proposal["portfolio_sha256"]
    assert delivered.delivery_readback_verified is True
    assert delivered.external_effect_count == 1
    assert delivered.ambient_credentials_used is False
    assert delivered.host_managed_delivery is True
    assert replay.replayed is True
    assert driver.delivery_calls == 1
    assert len(store.events("canary.telegram.delivery.claimed")) == 1
    assert len(store.events("canary.telegram.delivery.completed")) == 1
    persisted = canonical_json(
        [
            event.payload
            for event in store.events()
            if event.kind.startswith("canary.telegram.delivery.")
        ]
    )
    assert RECIPIENT_BINDING in persisted
    assert "Which bounded pursuit should CCT own next?" not in persisted
    assert "Ship exact reviewed candidate" not in persisted
    assert store.verify_chain()["valid"] is True


def test_telegram_transport_return_crash_adopts_readback_without_duplicate_send(
    tmp_path: Path,
) -> None:
    adapter, driver, store, state_root, _proposal = telegram_fixture(tmp_path)
    request = telegram_request(adapter)
    driver.raise_after_effect = True
    with pytest.raises(RuntimeError, match="simulated transport return crash"):
        adapter.deliver(request)
    assert driver.delivery_calls == 1
    assert not store.events("canary.telegram.delivery.completed")

    restarted = PrivateTelegramDeliveryAdapter(
        store,
        adapter_state_root=state_root,
        targets=(telegram_target(),),
        driver=driver,
    )
    recovered = restarted.deliver(request)
    duplicate_wake = restarted.deliver(request)

    assert recovered.replayed is True
    assert duplicate_wake.replayed is True
    assert driver.delivery_calls == 1
    assert len(store.events("canary.telegram.delivery.completed")) == 1


def test_telegram_denies_group_foreign_preexisting_and_stale_proposal_without_send(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="private"):
        telegram_target(chat_type="group")
    with pytest.raises(ValueError, match="generalist2"):
        telegram_target(profile_name="default")
    adapter, driver, store, _state_root, _proposal = telegram_fixture(tmp_path)
    request = telegram_request(adapter)
    preview = adapter.preview(
        target_id=request.target_id,
        proposal_id=request.proposal_id,
        proposal_revision=request.proposal_revision,
    )
    driver.rows[request.id] = TelegramDeliveryReadback(
        operation_id=request.id,
        target_id=request.target_id,
        proposal_event_id=preview.proposal_event_id,
        proposal_id=request.proposal_id,
        proposal_revision=request.proposal_revision,
        portfolio_sha256=preview.portfolio_sha256,
        recipient_binding_sha256=RECIPIENT_BINDING,
        message_sha256=preview.message_sha256,
        message_byte_count=preview.message_byte_count,
        provider_receipt_sha256=sha256(b"foreign receipt").hexdigest(),
        provider_message_id_sha256=sha256(b"foreign message").hexdigest(),
        chat_type="private",
        delivered=True,
    )
    with pytest.raises(TelegramDeliveryDenied, match="PREEXISTING_DELIVERY"):
        adapter.deliver(request)
    assert driver.delivery_calls == 0
    assert not store.events("canary.telegram.delivery.claimed")

    # Exact later revision makes revision 1 stale before any new host call.
    proposed = store.events("pursuit.dialogue.proposed")[0]
    stale_adapter = PrivateTelegramDeliveryAdapter(
        store,
        adapter_state_root=_state_root,
        targets=(telegram_target(id="second-private-target"),),
        driver=FakeTelegramDriver(),
    )
    store.append(
        "pursuit.dialogue.proposed",
        {**proposed.payload, "revision": 2, "portfolio_sha256": "f" * 64},
    )
    with pytest.raises(TelegramDeliveryDenied, match="STALE_PROPOSAL_REVISION"):
        stale_adapter.preview(
            target_id="second-private-target",
            proposal_id="priority-20260824",
            proposal_revision=1,
        )
