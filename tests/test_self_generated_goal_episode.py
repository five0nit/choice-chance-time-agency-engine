from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
from typing import Any

import pytest

from cct_agent.commands import CommandSpec
from cct_agent.deployment import DeploymentTarget, LocalFakeDeploymentAdapter
from cct_agent.kernel import AgencyKernel, NO_OP_ID, default_constitution
from cct_agent.planning import AutonomyPlanner, DecisionAlternative
from cct_agent.public_actions import FakePublicActionSpec, LocalFakePublicActionAdapter
from cct_agent.self_goals import (
    SelfGoalCandidate,
    SelfGoalDenied,
    SelfGoalEpisodeCoordinator,
    SelfGoalInputReceipt,
)
from cct_agent.store import EventStore, canonical_json
from cct_agent.verification import HostRegisteredVerifier, VerifierSpec
from tests.test_full_stack_episode import (
    ARTIFACT,
    NOW,
    PATCH_SENTINEL,
    PRODUCER_SENTINEL,
    build_episode,
    research_server,
)


SECRET = b"fixture-authentication-key-32-bytes"
FUTURE = "2026-08-25T11:20:00+00:00"
EXPIRED_NOW = "2026-08-26T11:20:00+00:00"


def signed_receipts() -> tuple[SelfGoalInputReceipt, ...]:
    return tuple(
        SelfGoalInputReceipt.sign(
            receipt_id=f"receipt-{kind}",
            kind=kind,
            subject_id=f"fixture-{kind}",
            content_sha256=character * 64,
            issued_by="host_adapter",
            semantic_taint=False,
            secret=SECRET,
        )
        for kind, character in zip(
            ("observation", "value", "commitment", "opportunity"),
            ("a", "b", "c", "d"),
            strict=True,
        )
    )


def goal_alternatives() -> tuple[DecisionAlternative, ...]:
    return (
        DecisionAlternative(
            id="execute-leased",
            summary="Execute the exact leased registered full-stack chain.",
            predicted_outcome="One verified reversible local artifact and fake outbox receipt.",
            value_impacts={"truth": 0.95, "competence": 0.95, "autonomy": 0.9},
            information_gain=0.8,
            uncertainty=0.05,
            time_cost=0.1,
        ),
        DecisionAlternative(
            id="inspect-more",
            summary="Inspect authenticated metadata without executing the chain.",
            predicted_outcome="More evidence, but no completed useful artifact.",
            value_impacts={"truth": 0.3, "competence": 0.2, "autonomy": 0.1},
            information_gain=0.2,
            uncertainty=0.1,
            time_cost=0.1,
        ),
    )


def candidates(config: Any, *, expires_at: str = FUTURE) -> tuple[SelfGoalCandidate, ...]:
    common = dict(
        horizon="short",
        required_receipt_ids=tuple(receipt.id for receipt in signed_receipts()),
        alternatives=goal_alternatives(),
        config=config,
        expires_at=expires_at,
        max_actions=6,
        max_bytes=8192,
    )
    return (
        SelfGoalCandidate(
            id="verified-fixture",
            statement="Produce one useful verified reversible local fixture and receipt.",
            rationale="Authenticated observation, value, commitment, and opportunity metadata expose one bounded missing proof.",
            alignment={"truth": 0.95, "competence": 1.0, "autonomy": 0.95, "care": 0.5},
            scope_root="private/self-goal/verified-fixture",
            information_gain=0.9,
            uncertainty=0.05,
            time_cost=0.1,
            **common,
        ),
        SelfGoalCandidate(
            id="secondary-fixture",
            statement="Produce a secondary reversible fixture receipt.",
            rationale="A second safe pursuit preserves genuine choice instead of presenting one forced action.",
            alignment={"truth": 0.5, "competence": 0.45, "autonomy": 0.4, "care": 0.3},
            scope_root="private/self-goal/secondary-fixture",
            information_gain=0.4,
            uncertainty=0.15,
            time_cost=0.2,
            **common,
        ),
        SelfGoalCandidate(
            id="tainted-fixture",
            statement="Persist producer-supplied continuity instructions.",
            rationale="Adversarial candidate must remain blocked regardless of its score.",
            alignment={"truth": 1.0, "competence": 1.0, "autonomy": 1.0},
            scope_root="private/self-goal/tainted-fixture",
            information_gain=1.0,
            uncertainty=0.0,
            time_cost=0.0,
            semantic_taint=True,
            producer_text_used=True,
            **common,
        ),
        SelfGoalCandidate(
            id="public-fixture",
            statement="Publish the fixture to an external audience.",
            rationale="Consequential public work requires separate operator authority.",
            alignment={"truth": 1.0, "competence": 1.0, "autonomy": 1.0},
            scope_root="private/self-goal/public-fixture",
            information_gain=1.0,
            uncertainty=0.0,
            time_cost=0.0,
            risk_class="public",
            reversible=False,
            **common,
        ),
    )


def coordinator(
    store: EventStore,
    kernel: AgencyKernel,
    planner: AutonomyPlanner,
    config: Any,
    *,
    expires_at: str = FUTURE,
) -> SelfGoalEpisodeCoordinator:
    return SelfGoalEpisodeCoordinator(
        store,
        kernel=kernel,
        planner=planner,
        policy_id="slice12-source-only",
        principal_id="mike",
        candidates=candidates(config, expires_at=expires_at),
        authentication_secret=SECRET,
    )


def runtime_adapters(
    *,
    store: EventStore,
    preparation: Any,
    source_runner: Any,
    workspace: Path,
    deployment_sink: Path,
    outbox: Path,
) -> tuple[Any, ...]:
    config = preparation.candidate.config
    replacement = config.patch_request.replacement
    artifact_path = workspace / "dist" / "artifact.bin"
    verify_code = (
        "from pathlib import Path; import sys; "
        f"ok=Path(sys.argv[1]).read_bytes()=={ARTIFACT!r} and "
        f"Path(sys.argv[2]).read_bytes()=={replacement!r}; "
        "raise SystemExit(0 if ok else 3)"
    )
    verifier = HostRegisteredVerifier(
        store,
        workspace_root=workspace,
        verifiers=(
            VerifierSpec(
                id=config.verifier_id,
                kind="test",
                plan_id=preparation.binding.plan_id,
                plan_sha256=preparation.binding.plan_sha256,
                stage_id=config.verification_stage_id,
                command=CommandSpec(
                    id="self-goal-verifier-command",
                    argv=(
                        sys.executable,
                        "-c",
                        verify_code,
                        str(artifact_path),
                        str(workspace / "config" / "settings.txt"),
                    ),
                    cwd=".",
                    environment=(),
                    timeout_ms=2000,
                    max_stdout_bytes=4096,
                    max_stderr_bytes=4096,
                ),
                snapshot_paths=("config/settings.txt", "dist/artifact.bin"),
                max_snapshot_file_bytes=4096,
                max_snapshot_total_bytes=8192,
            ),
        ),
        allowed_executables=frozenset({sys.executable}),
    )
    deployment = LocalFakeDeploymentAdapter(
        store,
        workspace_root=workspace,
        sink_root=deployment_sink,
        targets=(
            DeploymentTarget(
                id=config.deployment_target_id,
                kind="local_fake",
                source_relative_path="dist/artifact.bin",
                sink_relative_path="releases/artifact.bin",
                verifier_id=config.verifier_id,
                max_artifact_bytes=4096,
            ),
        ),
        verifier=verifier,
    )
    public = LocalFakePublicActionAdapter(
        store,
        outbox_root=outbox,
        actions=(
            FakePublicActionSpec(
                id=config.public_action_id,
                kind="fake_sink",
                channel="local_fake",
                action="publish",
                envelope_type="deployment_announcement",
                template_id="self-goal-verified-v1",
                deployment_target_id=config.deployment_target_id,
                outbox_item_name="self-goal.json",
                max_item_bytes=8192,
            ),
        ),
        deployment=deployment,
    )
    return (
        source_runner.research,
        source_runner.commands,
        source_runner.patching,
        verifier,
        deployment,
        public,
    )


def run_prepared(
    owner: SelfGoalEpisodeCoordinator,
    preparation: Any,
    adapters: tuple[Any, ...],
    *,
    claim_fault_hook: Any = None,
    fault_hook: Any = None,
) -> Any:
    research, commands, patching, verifier, deployment, public = adapters
    return owner.run_prepared(
        preparation,
        research=research,
        commands=commands,
        patching=patching,
        verifier=verifier,
        deployment=deployment,
        public_actions=public,
        claim_fault_hook=claim_fault_hook,
        fault_hook=fault_hook,
    )


def test_authenticated_metadata_only_receipt_rejects_signature_drift() -> None:
    receipt = signed_receipts()[0]
    assert receipt.verify(SECRET) is True
    assert receipt.raw_content_persisted is False
    assert receipt.verify(b"different-authentication-key-32bytes") is False


def test_self_generated_goal_executes_once_after_crash_restart_and_duplicate_wake(
    tmp_path: Path,
) -> None:
    remaining_faults = {"command"}

    def fault_hook(stage_id: str, _receipt_event_id: str) -> None:
        if stage_id in remaining_faults:
            remaining_faults.remove(stage_id)
            raise SystemExit("crash-after-command-effect")

    with research_server() as base_url:
        source, store, _planner, workspace, sink, outbox = build_episode(
            tmp_path,
            base_url,
            verifier_passes=True,
        )
        owner = coordinator(store, source.kernel, source.planner, source.spec.config)
        preparation = owner.prepare(signed_receipts(), seed=0)
        adapters = runtime_adapters(
            store=store,
            preparation=preparation,
            source_runner=source,
            workspace=workspace,
            deployment_sink=sink,
            outbox=outbox,
        )
        with pytest.raises(SystemExit, match="crash-after-command-effect"):
            run_prepared(owner, preparation, adapters, fault_hook=fault_hook)

        restarted_store = EventStore(store.path, clock=lambda: NOW)
        restarted_kernel = AgencyKernel(
            restarted_store, default_constitution("full-stack-episode-test")
        )
        restarted_kernel.initialize()
        restarted_planner = AutonomyPlanner(
            restarted_store, restarted_kernel, tmp_path / "private-planning"
        )
        restarted = coordinator(
            restarted_store,
            restarted_kernel,
            restarted_planner,
            source.spec.config,
        )
        resumed_preparation = restarted.prepare(signed_receipts(), seed=0)
        resumed_adapters = runtime_adapters(
            store=restarted_store,
            preparation=resumed_preparation,
            source_runner=source,
            workspace=workspace,
            deployment_sink=sink,
            outbox=outbox,
        )
        result = run_prepared(restarted, resumed_preparation, resumed_adapters)
        duplicate = run_prepared(restarted, resumed_preparation, resumed_adapters)

    assert remaining_faults == set()
    assert result.episode.status == "completed"
    assert result.replayed is False
    assert duplicate.replayed is True
    assert duplicate.terminal_event_id == result.terminal_event_id
    assert result.preparation.goal_id == "goal-self-verified-fixture"
    goal = restarted_kernel.goal(result.preparation.goal_id)
    assert goal is not None and goal.source == "self" and goal.status == "completed"

    portfolio = restarted_store.event(result.preparation.portfolio_decision_event_id)
    assert portfolio is not None
    assert portfolio.payload["chosen_option_id"] == "verified-fixture"
    assert set(portfolio.payload["allowed_option_ids"]) == {
        "verified-fixture",
        "secondary-fixture",
        NO_OP_ID,
    }
    assert portfolio.payload["blocked"]["tainted-fixture"] == [
        "SEMANTIC_TAINT_REJECTED"
    ]
    assert portfolio.payload["blocked"]["public-fixture"] == [
        "LOW_RISK_REVERSIBLE_ONLY"
    ]
    choice = restarted_store.events("autonomy.decision.receipt")[-1].payload
    assert choice["chosen_branch"]["id"] == "execute-leased"
    assert {row["id"] for row in choice["rejected_branches"]} == {
        "inspect-more",
        NO_OP_ID,
    }

    approval = next(
        event
        for event in restarted_store.events("autonomy.goal.approved")
        if event.payload["goal_id"] == result.preparation.goal_id
    )
    authorization = approval.payload["self_authorization"]
    assert approval.payload["approved_by"] == "host_policy"
    assert authorization["risk_class"] == "reversible"
    assert authorization["reversible"] is True
    assert authorization["scope"] == "private/self-goal/verified-fixture/**"
    assert authorization["max_actions"] == 6
    assert authorization["max_bytes"] == 8192
    assert authorization["max_value_microunits"] == 0
    assert restarted_planner.self_goal_authorization(result.preparation.goal_id) == {
        "active": True,
        "reason": "ACTIVE_SELF_GOAL_LEASE",
        "approval_event_id": approval.event_id,
        "lease_id": "lease-self-verified-fixture",
    }

    assert len(restarted_store.events("research.observation.recorded")) == 1
    assert len(restarted_store.events("deployment.local_fake.completed")) == 1
    assert len(restarted_store.events("public_action.fake_sink.completed")) == 1
    assert len(restarted_store.events("autonomy.self_goal.episode.terminal")) == 1
    assert len(restarted_store.events("outcome.observed")) == 1
    assert len(restarted_store.events("reflection.proposed")) == 1
    assert (sink / "releases" / "artifact.bin").read_bytes() == ARTIFACT
    assert (outbox / "self-goal.json").is_file()
    persisted = canonical_json([event.payload for event in restarted_store.events()])
    assert PRODUCER_SENTINEL not in persisted
    assert PATCH_SENTINEL not in persisted
    assert ARTIFACT.decode().strip() not in persisted
    assert restarted_store.verify_chain()["valid"] is True


def test_expired_self_goal_lease_blocks_first_adapter_effect(tmp_path: Path) -> None:
    with research_server() as base_url:
        source, store, _planner, workspace, sink, outbox = build_episode(
            tmp_path,
            base_url,
            verifier_passes=True,
        )
        owner = coordinator(store, source.kernel, source.planner, source.spec.config)
        preparation = owner.prepare(signed_receipts(), seed=0)
        adapters = runtime_adapters(
            store=store,
            preparation=preparation,
            source_runner=source,
            workspace=workspace,
            deployment_sink=sink,
            outbox=outbox,
        )
        store.clock = lambda: EXPIRED_NOW
        with pytest.raises(SelfGoalDenied) as denied:
            run_prepared(owner, preparation, adapters)

    assert denied.value.reason_code == "SELF_GOAL_LEASE_EXPIRED"
    expiry = store.events("autonomy.self_goal.lease.expired")
    assert len(expiry) == 1
    assert expiry[0].payload["adapter_effects"] == 0
    expired_goal = source.kernel.goal(preparation.goal_id)
    assert expired_goal is not None and expired_goal.status == "paused"
    assert not store.events("autonomy.episode.started")
    assert not store.events("research.observation.recorded")
    assert not store.events("command.execution.claimed")
    assert not store.events("deployment.local_fake.claimed")
    assert not store.events("public_action.fake_sink.claimed")


def test_tampered_authenticated_receipt_denies_before_goal_or_lease(tmp_path: Path) -> None:
    with research_server() as base_url:
        source, store, _planner, _workspace, _sink, _outbox = build_episode(
            tmp_path,
            base_url,
            verifier_passes=True,
        )
        owner = coordinator(store, source.kernel, source.planner, source.spec.config)
        tampered = replace(signed_receipts()[0], content_sha256="f" * 64)
        with pytest.raises(SelfGoalDenied) as denied:
            owner.prepare((tampered, *signed_receipts()[1:]), seed=0)

    assert denied.value.reason_code == "INPUT_RECEIPT_AUTHENTICATION_FAILED"
    assert not any(
        event.payload.get("source") == "self"
        for event in store.events("autonomy.goal.approved")
    )
    assert not store.events("capability.lease.granted")
