from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
from pathlib import Path
import sys
from threading import Thread
from typing import Any

import pytest

from cct_agent.commands import (
    BoundedCommandAdapter,
    CommandRequest,
    CommandSpec,
)
from cct_agent.deployment import DeploymentTarget, LocalFakeDeploymentAdapter
from cct_agent.full_stack import (
    FullStackEpisodeConfig,
    FullStackEpisodeDenied,
    FullStackEpisodeRunner,
    FullStackEpisodeSpec,
)
from cct_agent.kernel import AgencyKernel, NO_OP_ID, default_constitution
from cct_agent.patching import (
    ExpectedHashPatchAdapter,
    PatchRequest,
    PatchTarget,
    PatchVerification,
)
from cct_agent.planning import (
    ApprovedGoal,
    AutonomyPlanner,
    DecisionAlternative,
    HierarchicalPlan,
    PlanStage,
    StageHandoff,
)
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.public_actions import FakePublicActionSpec, LocalFakePublicActionAdapter
from cct_agent.research import (
    BoundedResearchAdapter,
    ResearchRequest,
    ResearchSource,
)
from cct_agent.store import EventStore, canonical_json
from cct_agent.verification import HostRegisteredVerifier, VerifierSpec


BEFORE = b"enabled = false\n"
AFTER = b"enabled = true\n"
ARTIFACT = b"FULL_STACK_ARTIFACT_SENTINEL_4ec72_not_for_ledger\n"
PRODUCER_SENTINEL = "FULL_STACK_PRODUCER_SENTINEL_20ab4_not_for_ledger"
PATCH_SENTINEL = "FULL_STACK_PATCH_SENTINEL_9fd31_not_for_ledger"
NOW = "2026-08-24T11:20:00+00:00"


class ResearchHandler(BaseHTTPRequestHandler):
    requests: list[str] = []

    def do_GET(self) -> None:  # noqa: N802
        type(self).requests.append(self.path)
        body = f'{{"evidence":"{PRODUCER_SENTINEL}"}}'.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return None


@contextmanager
def research_server() -> Iterator[str]:
    ResearchHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ResearchHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        assert ipaddress.ip_address(host).is_loopback
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def principal_profile() -> PrincipalProfile:
    return PrincipalProfile(
        principal_id="mike",
        display_name="Mike",
        values={"truth": 1.0, "competence": 0.9, "autonomy": 0.8},
        directives=(
            PrincipalDirective(
                id="bounded-delivery",
                kind="preference",
                statement="Prefer bounded verified reversible local delivery.",
                tags=("domain:workspace", "action:patch"),
                priority=90,
            ),
        ),
    )


def goal(episode_id: str) -> ApprovedGoal:
    return ApprovedGoal(
        id=f"goal-{episode_id}",
        statement="Produce one locally verified autonomous artifact and fake publication receipt.",
        rationale="Operator approved a bounded full-stack autonomy acceptance episode.",
        source="external",
        horizon="short",
        alignment={"truth": 0.9, "competence": 0.9, "autonomy": 0.7},
        approved_by="operator",
        approved_origin="operator:mike",
        approval_evidence=(f"operator://{episode_id}",),
    )


def alternatives() -> tuple[DecisionAlternative, ...]:
    return (
        DecisionAlternative(
            id="execute-bounded",
            summary="Research then execute the reversible registered full-stack plan.",
            predicted_outcome="One verified local artifact and fake publication receipt.",
            value_impacts={"truth": 0.9, "competence": 0.9, "autonomy": 0.8},
            information_gain=0.8,
            uncertainty=0.1,
            time_cost=0.2,
        ),
        DecisionAlternative(
            id="inspect-only",
            summary="Inspect the fixture without completing the local delivery chain.",
            predicted_outcome="Evidence improves but no end-to-end outcome is produced.",
            value_impacts={"truth": 0.4, "competence": 0.2, "autonomy": 0.1},
            information_gain=0.4,
            uncertainty=0.1,
            time_cost=0.2,
        ),
    )


def build_episode(
    tmp_path: Path,
    base_url: str,
    *,
    verifier_passes: bool,
    invalid_research_handoff: bool = False,
    claim_fault_hook: Any = None,
    fault_hook: Any = None,
) -> tuple[
    FullStackEpisodeRunner,
    EventStore,
    AutonomyPlanner,
    Path,
    Path,
    Path,
]:
    episode_id = "success-episode" if verifier_passes else "failure-episode"
    workspace = tmp_path / "workspace"
    (workspace / "config").mkdir(parents=True)
    (workspace / "config" / "settings.txt").write_bytes(BEFORE)
    (workspace / "dist").mkdir()
    (workspace / "dist" / "artifact.bin").write_bytes(b"")
    deployment_sink = tmp_path / "deployment-sink"
    deployment_sink.mkdir()
    outbox = tmp_path / "fake-public-outbox"
    outbox.mkdir()

    store = EventStore(tmp_path / "state" / "episode.sqlite", clock=lambda: NOW)
    kernel = AgencyKernel(store, default_constitution("full-stack-episode-test"))
    kernel.initialize()
    PrincipalModel(store).install(
        principal_profile(),
        authority="operator",
        evidence=("operator://full-stack-principal",),
    )
    planner = AutonomyPlanner(store, kernel, tmp_path / "private-planning")
    approved = goal(episode_id)
    planner.approve_goal(approved)
    decision_id = f"decision-{episode_id}"
    decision = planner.make_choice(
        goal_id=approved.id,
        alternatives=alternatives(),
        seed=0,
        decision_id=decision_id,
    )
    assert decision["chosen_branch"]["id"] == "execute-bounded"
    assert {row["id"] for row in decision["rejected_branches"]} == {
        "inspect-only",
        NO_OP_ID,
    }

    patch_replacement = AFTER + PATCH_SENTINEL.encode()
    config = FullStackEpisodeConfig(
        research_stage_id="research",
        research_request=ResearchRequest(
            id=f"research-{episode_id}",
            source_id="fixture-source",
            path="/evidence",
        ),
        command_stage_id="command",
        command_request=CommandRequest(
            id=f"command-{episode_id}",
            command_id="build-artifact",
        ),
        patch_stage_id="patch",
        patch_request=PatchRequest(
            id=f"patch-{episode_id}",
            target_id="settings-target",
            expected_before_sha256=sha256(BEFORE).hexdigest(),
            replacement=patch_replacement,
        ),
        verification_stage_id="verify",
        verifier_id="full-stack-verifier",
        verification_request_id=f"verification-{episode_id}",
        deployment_stage_id="deploy",
        deployment_target_id="local-fixture-deploy",
        deployment_request_id=f"deployment-{episode_id}",
        public_action_stage_id="public-action",
        public_action_id="fake-publish",
        public_action_request_id=f"public-action-{episode_id}",
    )

    stages: list[PlanStage] = []
    previous: str | None = None
    for stage_id in config.stage_ids:
        stages.append(
            PlanStage(
                id=stage_id,
                summary=f"Execute bounded {stage_id} stage.",
                depends_on=((previous,) if previous else ()),
                handoff=StageHandoff(
                    capability=f"full-stack.{stage_id}",
                    tool_name=config.tool_name(stage_id),
                    scope=f"private/full-stack/{stage_id}",
                    arguments_sha256=(
                        "f" * 64
                        if invalid_research_handoff and stage_id == "research"
                        else config.arguments_sha256(stage_id)
                    ),
                ),
            )
        )
        previous = stage_id
    plan = HierarchicalPlan(
        id=f"plan-{episode_id}",
        goal_id=approved.id,
        decision_id=decision_id,
        chosen_option_id="execute-bounded",
        summary="Research, command, patch, verify, fake deploy, and fake publish.",
        stages=tuple(stages),
    )
    binding = planner.store_plan(plan)["binding"]

    research = BoundedResearchAdapter(
        store,
        sources=(
            ResearchSource(
                id="fixture-source",
                base_url=base_url,
                allowed_content_types=("application/json",),
                max_bytes=4096,
                timeout_ms=2000,
                allow_loopback_http=True,
            ),
        ),
        allowed_hosts=frozenset({"127.0.0.1"}),
    )
    artifact_path = workspace / "dist" / "artifact.bin"
    command = BoundedCommandAdapter(
        store,
        workspace_root=workspace,
        commands=(
            CommandSpec(
                id="build-artifact",
                argv=(
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).open('ab').write(sys.argv[2].encode())",
                    str(artifact_path),
                    ARTIFACT.decode(),
                ),
                cwd=".",
                environment=(),
                timeout_ms=2000,
                max_stdout_bytes=4096,
                max_stderr_bytes=4096,
            ),
        ),
        allowed_executables=frozenset({sys.executable}),
    )

    def patch_verifier(path: Path) -> PatchVerification:
        return PatchVerification(
            passed=path.read_bytes() == patch_replacement,
            code="PATCH_SHAPE_VALID",
        )

    patch = ExpectedHashPatchAdapter(
        store,
        workspace_root=workspace,
        state_root=tmp_path / "patch-state",
        targets=(
            PatchTarget(
                id="settings-target",
                relative_path="config/settings.txt",
                verifier_id="patch-shape",
                max_bytes=4096,
            ),
        ),
        verifiers={"patch-shape": patch_verifier},
    )
    verify_code = (
        "from pathlib import Path; import sys; "
        f"ok=Path(sys.argv[1]).read_bytes()=={ARTIFACT!r} and "
        f"Path(sys.argv[2]).read_bytes()=={patch_replacement!r}; "
        f"raise SystemExit(0 if ok and {verifier_passes!r} else 3)"
    )
    verifier = HostRegisteredVerifier(
        store,
        workspace_root=workspace,
        verifiers=(
            VerifierSpec(
                id="full-stack-verifier",
                kind="test",
                plan_id=binding.plan_id,
                plan_sha256=binding.plan_sha256,
                stage_id="verify",
                command=CommandSpec(
                    id="full-stack-verifier-command",
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
                id="local-fixture-deploy",
                kind="local_fake",
                source_relative_path="dist/artifact.bin",
                sink_relative_path="releases/artifact.bin",
                verifier_id="full-stack-verifier",
                max_artifact_bytes=4096,
            ),
        ),
        verifier=verifier,
    )
    public_action = LocalFakePublicActionAdapter(
        store,
        outbox_root=outbox,
        actions=(
            FakePublicActionSpec(
                id="fake-publish",
                kind="fake_sink",
                channel="local_fake",
                action="publish",
                envelope_type="deployment_announcement",
                template_id="full-stack-verified-v1",
                deployment_target_id="local-fixture-deploy",
                outbox_item_name=f"{episode_id}.json",
                max_item_bytes=8192,
            ),
        ),
        deployment=deployment,
    )
    runner = FullStackEpisodeRunner(
        store,
        kernel=kernel,
        planner=planner,
        research=research,
        commands=command,
        patching=patch,
        verifier=verifier,
        deployment=deployment,
        public_actions=public_action,
        spec=FullStackEpisodeSpec(
            id=episode_id,
            binding=binding,
            worker_id="full-stack-worker",
            config=config,
        ),
        claim_fault_hook=claim_fault_hook,
        fault_hook=fault_hook,
    )
    return runner, store, planner, workspace, deployment_sink, outbox


def test_success_episode_resumes_claim_and_three_effect_crashes_without_duplicates(
    tmp_path: Path,
) -> None:
    remaining_claim_faults = {"research"}
    remaining_faults = {"command", "deploy", "public-action"}

    def claim_fault_hook(stage_id: str, _claim_event_id: str) -> None:
        if stage_id in remaining_claim_faults:
            remaining_claim_faults.remove(stage_id)
            raise SystemExit(f"crash-after-claim-{stage_id}")

    def fault_hook(stage_id: str, _receipt_event_id: str) -> None:
        if stage_id in remaining_faults:
            remaining_faults.remove(stage_id)
            raise SystemExit(f"crash-after-{stage_id}")

    with research_server() as base_url:
        runner, store, planner, workspace, sink_root, outbox = build_episode(
            tmp_path,
            base_url,
            verifier_passes=True,
            claim_fault_hook=claim_fault_hook,
            fault_hook=fault_hook,
        )
        with pytest.raises(SystemExit, match="crash-after-claim-research"):
            runner.run()
        for stage_id in ("command", "deploy", "public-action"):
            with pytest.raises(SystemExit, match=f"crash-after-{stage_id}"):
                runner.run()
        result = runner.run()
        replay = runner.run()

    assert remaining_claim_faults == set()
    assert remaining_faults == set()
    assert result.status == "completed"
    assert result.failure_stage_id is None
    assert result.replayed is False
    assert replay.replayed is True
    assert replay.terminal_event_id == result.terminal_event_id
    assert len(result.stage_claim_event_ids) == 6
    assert len(result.stage_receipt_event_ids) == 6
    assert planner.cursor(result.plan_id)["state"] == "COMPLETE"
    assert ResearchHandler.requests == ["/evidence"]
    assert (workspace / "dist" / "artifact.bin").read_bytes() == ARTIFACT
    assert (workspace / "config" / "settings.txt").read_bytes() == AFTER + PATCH_SENTINEL.encode()
    assert (sink_root / "releases" / "artifact.bin").read_bytes() == ARTIFACT
    assert (outbox / "success-episode.json").is_file()
    assert len(store.events("command.execution.completed")) == 2  # build + verifier
    assert len(store.events("deployment.local_fake.completed")) == 1
    assert len(store.events("public_action.fake_sink.completed")) == 1
    assert len(store.events("outcome.observed")) == 1
    assert len(store.events("reflection.proposed")) == 1
    assert len(store.events("autonomy.episode.completed")) == 1
    assert store.verify_chain()["valid"] is True
    persisted = canonical_json([event.payload for event in store.events()])
    assert PRODUCER_SENTINEL not in persisted
    assert PATCH_SENTINEL not in persisted
    assert ARTIFACT.decode().strip() not in persisted


def test_plan_handoff_digest_mismatch_denies_before_first_adapter_effect(tmp_path: Path) -> None:
    with research_server() as base_url:
        runner, store, _planner, workspace, _sink_root, _outbox = build_episode(
            tmp_path,
            base_url,
            verifier_passes=True,
            invalid_research_handoff=True,
        )
        with pytest.raises(FullStackEpisodeDenied, match="STAGE_HANDOFF_MISMATCH"):
            runner.run()

    assert ResearchHandler.requests == []
    assert not store.events("research.observation.recorded")
    assert not store.events("command.execution.claimed")
    assert (workspace / "dist" / "artifact.bin").read_bytes() == b""


def test_failed_verification_rolls_back_and_blocks_deploy_and_public_action(tmp_path: Path) -> None:
    with research_server() as base_url:
        runner, store, planner, workspace, sink_root, outbox = build_episode(
            tmp_path,
            base_url,
            verifier_passes=False,
        )
        result = runner.run()
        replay = runner.run()

    assert result.status == "failed"
    assert result.failure_stage_id == "verify"
    assert result.reason_code == "VERIFIER_EXIT_NONZERO"
    assert result.rollback_event_id is not None
    assert replay.replayed is True
    assert replay.terminal_event_id == result.terminal_event_id
    assert planner.cursor(result.plan_id)["state"] == "CLAIMED"
    assert planner.cursor(result.plan_id)["claimed"]["stage_id"] == "verify"
    assert (workspace / "config" / "settings.txt").read_bytes() == BEFORE
    assert (workspace / "dist" / "artifact.bin").read_bytes() == ARTIFACT
    assert not store.events("deployment.local_fake.claimed")
    assert not store.events("public_action.fake_sink.claimed")
    assert list(sink_root.iterdir()) == [sink_root / ".deployment.lock"]
    assert list(outbox.iterdir()) == [outbox / ".public-action.lock"]
    assert store.events("goal.status_changed")[-1].payload["to"] == "paused"
    assert store.events("outcome.observed")[0].payload["realized_utility"] < 0
    assert len(store.events("reflection.proposed")) == 1
    assert len(store.events("autonomy.episode.failed")) == 1
    assert store.verify_chain()["valid"] is True
