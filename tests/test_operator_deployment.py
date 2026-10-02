from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any

import pytest

from operator_crash_matrix import race_same_ticket_recovery

from cct_agent.capabilities import CapabilityLease, CapabilityRegistry, OperatorCapabilityCatalog
from cct_agent.commands import CommandSpec
from cct_agent.deployment import DeploymentDenied
from cct_agent.execution_tickets import ExecutionTicket, ExecutionTicketAuthority, GlobalKillSwitch
from cct_agent.mediation import ToolExecutionMediator
from cct_agent.operator_deployment import (
    OPERATOR_DEPLOY_VERIFIER_ID,
    LocalDeploymentRoute,
    LocalDirectoryDeploymentDriver,
    OperatorDeploymentAdapter,
    OperatorDeploymentTarget,
)
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore, canonical_json
from cct_agent.verification import HostRegisteredVerifier, VerificationRequest, VerifierSpec


NOW = "2026-08-25T00:00:00+00:00"
FUTURE = "2026-08-26T00:00:00+00:00"
PLAN_SHA256 = sha256(b"operator-deployment-plan").hexdigest()
ARTIFACT = b"verified CCT staging artifact\n"
PRIVATE_SENTINEL = "OPERATOR_DEPLOY_PRIVATE_7c31"
BEFORE = b"previous staged artifact\n"


def verifier_spec() -> VerifierSpec:
    return VerifierSpec(
        id="release-artifact-verifier",
        kind="build",
        plan_id="operator-deployment-plan",
        plan_sha256=PLAN_SHA256,
        stage_id="verify-artifact",
        command=CommandSpec(
            id="operator-deployment-verify-command",
            argv=(sys.executable, "-c", "raise SystemExit(0)"),
            cwd=".",
            environment=(),
            timeout_ms=2000,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
        ),
        snapshot_paths=("dist/cct-staging.bundle", "release.txt"),
        max_snapshot_file_bytes=8192,
        max_snapshot_total_bytes=16384,
    )


def configured(tmp_path: Path, *, artifact: bytes = ARTIFACT):
    workspace = tmp_path / "workspace"
    (workspace / "dist").mkdir(parents=True)
    (workspace / "dist" / "cct-staging.bundle").write_bytes(artifact)
    (workspace / "release.txt").write_text("verified release\n")
    destination_root = tmp_path / "generalist2-staging"
    destination_root.mkdir()
    destination = destination_root / "current.bundle"
    destination.write_bytes(BEFORE)
    driver_state = tmp_path / "driver-state"
    driver_state.mkdir()
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    installed = PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 1.0},
            directives=(
                PrincipalDirective(
                    id="operator-deployment",
                    kind="preference",
                    statement="Prefer exact previewed deployments with provider readback and rollback.",
                    tags=("domain:operator", "action:deploy"),
                    priority=90,
                ),
            ),
        ),
        authority="operator",
        evidence=("operator://profile",),
    )
    spec = OperatorCapabilityCatalog(store).install()["deploy"]
    CapabilityRegistry(store).grant(
        CapabilityLease(
            id="lease-deploy-generalist2-staging",
            capability="operator.deploy",
            principal_id="mike",
            scopes=("operator/deploy/generalist2-staging",),
            expires_at=FUTURE,
            max_actions=8,
            max_bytes=8192,
            max_value_microunits=0,
            issued_by="operator",
            evidence=("operator://lease/deploy/generalist2-staging",),
        )
    )
    verifier = HostRegisteredVerifier(
        store,
        workspace_root=workspace,
        verifiers=(verifier_spec(),),
        allowed_executables=frozenset({sys.executable}),
    )
    verification_request = VerificationRequest(
        id="operator-deployment-verification",
        verifier_id="release-artifact-verifier",
        plan_id="operator-deployment-plan",
        plan_sha256=PLAN_SHA256,
        stage_id="verify-artifact",
        expected_snapshot_sha256=verifier.snapshot("release-artifact-verifier").sha256,
    )
    assert verifier.execute(verification_request).status == "passed"
    target = OperatorDeploymentTarget(
        id="generalist2-staging",
        driver_id="generalist2-local",
        provider="generalist2-local-staging",
        environment="staging",
        artifact_relative_path="dist/cct-staging.bundle",
        verifier_id="release-artifact-verifier",
        max_artifact_bytes=8192,
        rollback_supported=True,
    )
    driver = LocalDirectoryDeploymentDriver(
        state_root=driver_state,
        provider="generalist2-local-staging",
        routes=(
            LocalDeploymentRoute(
                target_id="generalist2-staging",
                environment="staging",
                root=destination_root,
                relative_path="current.bundle",
            ),
        ),
    )
    adapter = OperatorDeploymentAdapter(
        store,
        workspace_root=workspace,
        targets=(target,),
        verifier=verifier,
        drivers={"generalist2-local": driver},
    )
    return {
        "store": store,
        "workspace": workspace,
        "destination": destination,
        "driver_state": driver_state,
        "verifier": verifier,
        "target": target,
        "driver": driver,
        "adapter": adapter,
        "profile_digest": installed["profile_digest"],
        "spec_digest": spec["spec_digest"],
    }


def preview_arguments(fixture: dict[str, Any], ticket_id: str) -> dict[str, Any]:
    preview = fixture["adapter"].preview(
        target_id="generalist2-staging",
        verification_request_id="operator-deployment-verification",
    )
    return {
        "execution_ticket_id": ticket_id,
        "target_id": preview.target_id,
        "verification_request_id": preview.verification_request_id,
        "expected_verification_event_id": preview.verification_event_id,
        "expected_snapshot_sha256": preview.snapshot_sha256,
        "expected_artifact_sha256": preview.artifact_sha256,
        "expected_artifact_byte_count": preview.artifact_byte_count,
        "expected_before_state_sha256": preview.before_state_sha256,
        "expected_preview_sha256": preview.preview_sha256,
        "verifier_id": "release-artifact-verifier",
        "max_bytes": 8192,
    }


def issue(fixture: dict[str, Any], payload: dict[str, Any]) -> None:
    ticket_id = str(payload["execution_ticket_id"])
    ExecutionTicketAuthority(fixture["store"]).issue(
        ExecutionTicket(
            id=ticket_id,
            tool_name="operator_deploy",
            arguments_sha256=sha256(canonical_json(payload).encode()).hexdigest(),
            goal_id="goal-cct-full-operator-effects",
            plan_id=f"plan-{ticket_id}",
            plan_hash=sha256(f"plan:{ticket_id}".encode()).hexdigest(),
            stage="execute-deployment",
            attempt=1,
            principal_id="mike",
            principal_profile_digest=fixture["profile_digest"],
            capability="operator.deploy",
            capability_spec_digest=fixture["spec_digest"],
            lease_id="lease-deploy-generalist2-staging",
            scope="operator/deploy/generalist2-staging",
            expires_at=FUTURE,
            action_budget=1,
            byte_budget=int(payload["max_bytes"]),
            value_budget_microunits=0,
        ),
        authority="operator",
        evidence=(f"operator://goal/{ticket_id}",),
    )


def mediated(fixture: dict[str, Any], payload: dict[str, Any]) -> tuple[dict[str, Any], int]:
    calls = 0

    def next_call() -> str:
        nonlocal calls
        calls += 1
        return fixture["adapter"].execute(payload)

    value = ToolExecutionMediator(
        fixture["store"],
        frozenset({"operator_deploy"}),
        outcome_verifiers=fixture["adapter"].outcome_verifiers(),
    )(
        tool_name="operator_deploy",
        args=payload,
        original_args=payload,
        next_call=next_call,
    )
    parsed = json.loads(value) if isinstance(value, str) else value
    assert isinstance(parsed, dict)
    return parsed, calls


def test_ticketed_local_provider_deploys_readbacks_retries_and_rolls_back(tmp_path: Path) -> None:
    artifact = ARTIFACT + PRIVATE_SENTINEL.encode()
    fixture = configured(tmp_path, artifact=artifact)
    payload = preview_arguments(fixture, "ticket-deploy-staging")
    issue(fixture, payload)

    deployed, calls = mediated(fixture, payload)
    replay, replay_calls = mediated(fixture, payload)

    assert deployed["success"] is True
    assert deployed["deployment"]["provider"] == "generalist2-local-staging"
    assert deployed["deployment"]["environment"] == "staging"
    assert deployed["deployment"]["target_id"] == "generalist2-staging"
    assert deployed["deployment"]["artifact_sha256"] == sha256(artifact).hexdigest()
    assert deployed["deployment"]["provider_readback_verified"] is True
    assert deployed["deployment"]["provider_effect_count"] == 1
    assert deployed["deployment"]["credential_handles_used"] == []
    assert fixture["destination"].read_bytes() == artifact
    assert calls == 1
    assert replay["success"] is True
    assert replay["mediation"]["recovered_after_restart"] is True
    assert replay_calls == 0

    rolled_back = fixture["adapter"].rollback(
        deployment_ticket_id="ticket-deploy-staging",
        rollback_id="rollback-deploy-staging",
    )
    rollback_replay = fixture["adapter"].rollback(
        deployment_ticket_id="ticket-deploy-staging",
        rollback_id="rollback-deploy-staging",
    )
    assert rolled_back["status"] == "rolled_back"
    assert rolled_back["provider_readback_verified"] is True
    assert rollback_replay == rolled_back
    assert fixture["destination"].read_bytes() == BEFORE

    persisted = canonical_json([event.payload for event in fixture["store"].events()])
    assert PRIVATE_SENTINEL not in persisted
    assert str(fixture["destination"].parent) not in persisted
    assert fixture["store"].verify_chain()["valid"] is True


@pytest.mark.operator_crash_matrix
def test_post_provider_crash_is_adopted_without_second_deploy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = configured(tmp_path)
    payload = preview_arguments(fixture, "ticket-deploy-crash")
    issue(fixture, payload)
    original = fixture["adapter"]._record_completion

    def crash(*_args: Any, **_kwargs: Any) -> Any:
        raise SystemExit("simulated post-provider crash")

    monkeypatch.setattr(fixture["adapter"], "_record_completion", crash)
    with pytest.raises(SystemExit, match="simulated post-provider crash"):
        mediated(fixture, payload)
    assert fixture["driver"].mutation_count == 1
    assert not fixture["store"].events("operator.deployment.completed")
    monkeypatch.setattr(fixture["adapter"], "_record_completion", original)

    restarted_driver = LocalDirectoryDeploymentDriver(
        state_root=fixture["driver_state"],
        provider="generalist2-local-staging",
        routes=(
            LocalDeploymentRoute(
                target_id="generalist2-staging",
                environment="staging",
                root=fixture["destination"].parent,
                relative_path="current.bundle",
            ),
        ),
    )
    restarted = OperatorDeploymentAdapter(
        fixture["store"],
        workspace_root=fixture["workspace"],
        targets=(fixture["target"],),
        verifier=fixture["verifier"],
        drivers={"generalist2-local": restarted_driver},
    )
    fixture["adapter"] = restarted
    recoveries = race_same_ticket_recovery(lambda: mediated(fixture, payload))

    assert all(recovered["success"] is True for recovered in recoveries)
    assert restarted_driver.mutation_count == 0
    assert len(fixture["store"].events("operator.deployment.claimed")) == 1
    completions = fixture["store"].events("operator.deployment.completed")
    assert len(completions) == 1
    assert completions[0].payload["recovered_after_provider_crash"] is True


def test_stale_preview_and_kill_switch_block_before_provider_mutation(tmp_path: Path) -> None:
    fixture = configured(tmp_path)
    stale = preview_arguments(fixture, "ticket-deploy-stale")
    fixture["destination"].write_bytes(b"foreign provider drift\n")
    issue(fixture, stale)
    ExecutionTicketAuthority(fixture["store"]).claim_dispatch(
        ticket_id="ticket-deploy-stale",
        tool_name="operator_deploy",
        arguments_sha256=sha256(canonical_json(stale).encode()).hexdigest(),
        registered_verifier_ids=frozenset({OPERATOR_DEPLOY_VERIFIER_ID}),
    )
    with pytest.raises(DeploymentDenied, match="DEPLOYMENT_PREVIEW_STALE"):
        fixture["adapter"].execute(stale)
    assert fixture["driver"].mutation_count == 0

    fresh = preview_arguments(fixture, "ticket-deploy-killed")
    issue(fixture, fresh)
    GlobalKillSwitch(fixture["store"]).trip(
        trip_id="kill-before-deployment",
        authority="operator",
        reason="Stop provider deployment.",
    )
    result, calls = mediated(fixture, fresh)
    assert result["success"] is False
    assert result["error"]["reasons"] == ["GLOBAL_KILL_SWITCH_ACTIVE"]
    assert calls == 0
    assert fixture["driver"].mutation_count == 0


def test_unregistered_driver_and_unsafe_local_route_fail_closed(tmp_path: Path) -> None:
    fixture = configured(tmp_path)
    with pytest.raises(ValueError, match="driver"):
        OperatorDeploymentAdapter(
            fixture["store"],
            workspace_root=fixture["workspace"],
            targets=(fixture["target"],),
            verifier=fixture["verifier"],
            drivers={},
        )
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ValueError, match="relative_path"):
        LocalDeploymentRoute(
            target_id="escape",
            environment="staging",
            root=outside,
            relative_path="../escape.bundle",
        )
