from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path

import pytest

import cct_agent
from cct_agent.kernel import AgencyKernel, NO_OP_ID, default_constitution
from cct_agent.opportunity_handoff import OpportunityTaskHandoff
from cct_agent.opportunity_initiative import OpportunityInitiative
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.pursuit_dialogue import Pursuit, PursuitDialogue, PursuitPortfolio
from cct_agent.recurrent import (
    InstalledRecurrentCoordinator,
    RecurrentCoordinatorDenied,
    RecurrentPaths,
    RecurrentWake,
    load_recurrent_wake,
    runtime_provenance,
)
from cct_agent.self_goals import SelfGoalInputReceipt
from cct_agent.store import EventStore, canonical_json


SECRET = b"recurrent-coordinator-auth-key-32bytes"
EXPIRY = "2099-08-25T11:20:00+00:00"
RAW_SENTINEL = "RECURRENT_RAW_PRODUCER_SENTINEL_7f2a1"


def signed_receipts() -> tuple[SelfGoalInputReceipt, ...]:
    return tuple(
        SelfGoalInputReceipt.sign(
            receipt_id=f"recurrent-{kind}",
            kind=kind,
            subject_id=f"host-{kind}",
            content_sha256=character * 64,
            issued_by="host_adapter",
            semantic_taint=False,
            secret=SECRET,
        )
        for kind, character in zip(
            ("observation", "value", "commitment", "opportunity"),
            ("1", "2", "3", "4"),
            strict=True,
        )
    )


def signed_interest_receipts(
    opportunity_id: str, interest_sha256: str
) -> tuple[SelfGoalInputReceipt, ...]:
    rows = list(signed_receipts()[:3])
    rows.append(
        SelfGoalInputReceipt.sign(
            receipt_id="recurrent-opportunity",
            kind="opportunity",
            subject_id=opportunity_id,
            content_sha256=interest_sha256,
            issued_by="host_adapter",
            semantic_taint=False,
            secret=SECRET,
        )
    )
    return tuple(rows)


def paths(tmp_path: Path) -> RecurrentPaths:
    state_root = tmp_path / "state"
    workspace = state_root / "workspace" / "wake-slice20"
    deployment = state_root / "deployment" / "wake-slice20"
    outbox = state_root / "outbox" / "wake-slice20"
    for directory in (
        workspace / "config",
        workspace / "dist",
        deployment,
        outbox,
        state_root / "planning",
        state_root / "patch-state",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    status_file = workspace / "config" / "status.txt"
    artifact_file = workspace / "dist" / "receipt.txt"
    status_file.write_bytes(b"verified = false\n")
    artifact_file.write_bytes(b"")
    os.chmod(status_file, 0o600)
    os.chmod(artifact_file, 0o600)
    return RecurrentPaths(
        state_root=state_root,
        database=state_root / "agency.sqlite",
        planning_root=state_root / "planning",
        patch_state_root=state_root / "patch-state",
        workspace_root=workspace,
        deployment_sink=deployment,
        outbox_root=outbox,
    )


def initialize_governance(rows: RecurrentPaths) -> EventStore:
    store = EventStore(rows.database)
    kernel = AgencyKernel(store, default_constitution("recurrent-test"))
    kernel.initialize()
    PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"truth": 1.0, "competence": 0.95, "autonomy": 0.95},
            directives=(
                PrincipalDirective(
                    id="bounded-recurrent-work",
                    kind="preference",
                    statement="Prefer verified reversible local recurrent work.",
                    tags=("domain:autonomy", "action:execute"),
                    priority=100,
                ),
            ),
        ),
        authority="operator",
        evidence=("operator:recurrent-coordinator",),
    )
    for goal_id, status in (
        ("goal-release-candidate", "paused"),
        ("goal-evidence-gap", "active"),
    ):
        kernel.form_goal(
            goal_id=goal_id,
            statement=f"Advance {goal_id} through one bounded receipt.",
            rationale="Exact ranked pursuit dialogue must remain available from installed coordinator.",
            source="joint",
            horizon="short",
            alignment={"truth": 0.8, "competence": 0.8, "autonomy": 0.7},
            evidence=(f"receipt:{goal_id}",),
        )
        if status == "paused":
            kernel.set_goal_status(goal_id, "paused", "Await exact operator priority.")
    PursuitDialogue(store).register(
        PursuitPortfolio(
            id="recurrent-priority",
            revision=1,
            question="Which bounded CCT pursuit should own next slot?",
            pursuits=(
                Pursuit(
                    id="release-candidate",
                    goal_id="goal-release-candidate",
                    summary="Ship exact reviewed candidate",
                    payoff=0.88,
                    cost=0.24,
                    uncertainty=0.18,
                    required_authority="operator",
                    evidence=("receipt:release-candidate",),
                    consequential=True,
                ),
                Pursuit(
                    id="evidence-gap",
                    goal_id="goal-evidence-gap",
                    summary="Resolve highest-impact evidence gap",
                    payoff=0.85,
                    cost=0.22,
                    uncertainty=0.20,
                    required_authority="operator",
                    evidence=("receipt:evidence-gap",),
                ),
            ),
            expires_at=EXPIRY,
            ambiguous=True,
        )
    )
    return store


def register_accepted_interest(store: EventStore) -> tuple[str, str, str]:
    opportunity_id = "recurrent-accepted-interest"
    registration = store.append(
        "autonomy.opportunity.registered",
        {
            "schema_version": 1,
            "opportunity_id": opportunity_id,
            "status": "open",
            "source_authority": "self",
            "external_effects": 0,
        },
    )
    principal = PrincipalModel(store).status()
    presentation = store.append(
        "opportunity.initiative.completed",
        {
            "schema_version": 1,
            "opportunity_id": opportunity_id,
            "registration_event_id": registration.event_id,
            "emitted": True,
            "principal": {
                "principal_id": "mike",
                "profile_digest": principal["profile_digest"],
            },
            "external_effects": 0,
        },
    )
    feedback = OpportunityInitiative(store).record_feedback(
        feedback_id="recurrent-accepted-interest-feedback",
        opportunity_id=opportunity_id,
        principal_id="mike",
        decision="INTERESTED",
        evidence=("host:recurrent-accepted-interest",),
        source_authority="host_adapter",
    )
    assert feedback["presentation_event_id"] == presentation.event_id
    binding = OpportunityTaskHandoff(store, principal_id="mike").inspect_interest(
        opportunity_id=opportunity_id,
        feedback_event_id=str(feedback["event_id"]),
    )
    return opportunity_id, str(feedback["event_id"]), binding.digest


def coordinator(rows: RecurrentPaths) -> InstalledRecurrentCoordinator:
    return InstalledRecurrentCoordinator(
        paths=rows,
        identity="recurrent-test",
        principal_id="mike",
        authentication_secret=SECRET,
        expected_module_root=Path(cct_agent.__file__).resolve().parents[1],
        expected_package_version=cct_agent.__version__,
    )


def test_installed_recurrent_coordinator_resumes_full_self_goal_and_exposes_dialogue(
    tmp_path: Path,
) -> None:
    rows = paths(tmp_path)
    store = initialize_governance(rows)
    wake = RecurrentWake(
        id="wake-slice20",
        seed=0,
        expires_at=EXPIRY,
        time_bucket="2099-08-25",
        receipts=signed_receipts(),
    )
    remaining_faults = {"command"}

    def fault_hook(stage_id: str, _receipt_event_id: str) -> None:
        if stage_id in remaining_faults:
            remaining_faults.remove(stage_id)
            raise SystemExit("crash-after-recurrent-command")

    with pytest.raises(SystemExit, match="crash-after-recurrent-command"):
        coordinator(rows).run(wake, fault_hook=fault_hook)

    result = coordinator(rows).run(wake)
    duplicate = coordinator(rows).run(wake)

    assert remaining_faults == set()
    assert result["status"] == "completed"
    assert result["replayed"] is False
    assert duplicate["status"] == "completed"
    assert duplicate["replayed"] is True
    assert duplicate["terminal_event_id"] == result["terminal_event_id"]
    assert result["goal_source"] == "self"
    assert result["lease"]["max_actions"] == 6
    assert result["lease"]["max_bytes"] == 8192
    assert result["lease"]["max_value_microunits"] == 0
    assert result["lease"]["scope"].endswith("/**")
    assert result["runtime"]["package_version"] == cct_agent.__version__
    assert Path(result["runtime"]["module_root"]) == Path(cct_agent.__file__).resolve().parents[1]
    assert result["priority_dialogue"]["initiative_kind"] == "pursuit_dialogue"
    assert "Recommendation: release-candidate" in result["priority_dialogue"]["message"]
    assert NO_OP_ID in result["priority_dialogue"]["message"]
    assert duplicate["priority_dialogue"]["message"] == ""
    assert result["external_effects"] == 0
    assert result["chain_valid"] is True

    events = store.events()
    portfolio = next(
        event
        for event in events
        if event.kind == "decision.made"
        and event.payload.get("decision_id", "").startswith("self-portfolio-recurrent-")
    )
    assert portfolio.payload["chosen_option_id"].startswith("verified-wake-slice20")
    assert NO_OP_ID in portfolio.payload["allowed_option_ids"]
    assert any(
        reason == ["SEMANTIC_TAINT_REJECTED"]
        for reason in portfolio.payload["blocked"].values()
    )
    assert len(store.events("research.observation.recorded")) == 1
    assert len(store.events("command.execution.completed")) == 2
    assert len(store.events("deployment.local_fake.completed")) == 1
    assert len(store.events("public_action.fake_sink.completed")) == 1
    assert len(store.events("autonomy.self_goal.episode.terminal")) == 1
    assert len(store.events("outcome.observed")) == 1
    assert len(store.events("reflection.proposed")) == 1
    persisted = canonical_json([event.payload for event in events])
    assert RAW_SENTINEL not in persisted
    assert "verified = true" not in persisted
    assert store.verify_chain()["valid"] is True
    assert (rows.deployment_sink / "releases" / "receipt.txt").is_file()
    assert (rows.outbox_root / "recurrent-wake-slice20.json").is_file()


def test_installed_recurrent_coordinator_wakes_signed_accepted_interest_once(
    tmp_path: Path,
) -> None:
    rows = paths(tmp_path)
    store = initialize_governance(rows)
    opportunity_id, feedback_event_id, interest_digest = register_accepted_interest(store)
    wake = RecurrentWake(
        id="wake-accepted-interest",
        seed=0,
        expires_at=EXPIRY,
        time_bucket="2099-08-25",
        receipts=signed_interest_receipts(opportunity_id, interest_digest),
    )

    remaining_faults = {"command-effect"}

    def fault_hook(stage_id: str, _receipt_event_id: str) -> None:
        if stage_id in remaining_faults:
            remaining_faults.remove(stage_id)
            raise SystemExit("crash-after-accepted-interest-command-effect")

    with pytest.raises(SystemExit, match="crash-after-accepted-interest-command-effect"):
        coordinator(rows).run(wake, fault_hook=fault_hook)

    first = coordinator(rows).run(wake)
    duplicate = coordinator(rows).run(wake)

    assert remaining_faults == set()
    assert first["status"] == "completed"
    assert first["interest_task_wake"]["status"] == "verified-completed"
    assert first["interest_task_wake"]["executed"] is True
    assert duplicate["status"] == "completed"
    assert duplicate["replayed"] is True
    assert duplicate["interest_task_wake"]["emit"] is False
    assert len(store.events("opportunity.initiative.task_wake.configuration.installed")) == 1
    assert len(store.events("opportunity.initiative.task_wake.claimed")) == 1
    assert len(store.events("opportunity.initiative.task_wake.completed")) == 1
    assert len(store.events("opportunity.initiative.task_handoff.completed")) == 1
    assert len(store.events("command.execution.readback_adopted")) == 1
    assert len(store.events("deployment.local_fake.completed")) == 1
    assert len(store.events("public_action.fake_sink.completed")) == 1
    terminal = store.events("opportunity.initiative.task_handoff.completed")[0]
    assert terminal.payload["feedback_event_id"] == feedback_event_id
    assert terminal.payload["interest_granted_execution_authority"] is False
    assert terminal.payload["execution_authority_source"] == (
        "separate_host_policy_capability_lease"
    )
    assert terminal.payload["external_effects"] == 0
    assert store.verify_chain()["valid"] is True


def test_private_wake_loader_and_runtime_provenance_fail_closed(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    secret_path = state_root / "secret.key"
    secret_path.write_bytes(SECRET)
    receipt_path = state_root / "wake.json"
    receipt_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "wake_id": "wake-slice20",
                "seed": 0,
                "expires_at": EXPIRY,
                "time_bucket": "2099-08-25",
                "receipts": [asdict(receipt) for receipt in signed_receipts()],
            }
        ),
        encoding="utf-8",
    )
    os.chmod(secret_path, 0o600)
    os.chmod(receipt_path, 0o600)

    wake, secret = load_recurrent_wake(
        state_root=state_root,
        receipt_file=receipt_path,
        secret_file=secret_path,
    )
    assert wake.id == "wake-slice20"
    assert secret == SECRET
    assert len(wake.receipts) == 4

    wrong_root = tmp_path / "wrong-site-packages"
    wrong_root.mkdir()
    with pytest.raises(RecurrentCoordinatorDenied, match="RUNTIME_MODULE_ROOT_MISMATCH"):
        runtime_provenance(
            expected_module_root=wrong_root,
            expected_package_version=cct_agent.__version__,
        )

    raw = json.loads(receipt_path.read_text(encoding="utf-8"))
    raw["producer_text"] = RAW_SENTINEL
    receipt_path.write_text(json.dumps(raw), encoding="utf-8")
    os.chmod(receipt_path, 0o600)
    with pytest.raises(RecurrentCoordinatorDenied, match="WAKE_SCHEMA_INVALID"):
        load_recurrent_wake(
            state_root=state_root,
            receipt_file=receipt_path,
            secret_file=secret_path,
        )


def test_recurrent_workspace_foreign_mutation_denies_before_self_goal_effect(
    tmp_path: Path,
) -> None:
    rows = paths(tmp_path)
    store = initialize_governance(rows)
    (rows.workspace_root / "dist" / "receipt.txt").write_text(
        RAW_SENTINEL, encoding="utf-8"
    )
    wake = RecurrentWake(
        id="wake-slice20",
        seed=0,
        expires_at=EXPIRY,
        time_bucket="2099-08-25",
        receipts=signed_receipts(),
    )

    with pytest.raises(
        RecurrentCoordinatorDenied, match="RECURRENT_WORKSPACE_FOREIGN_MUTATION"
    ):
        coordinator(rows).run(wake)

    assert not store.events("autonomy.self_goal.input.recorded")
    assert not store.events("command.execution.claimed")
    assert not store.events("deployment.local_fake.claimed")
    assert not store.events("public_action.fake_sink.claimed")


def test_recurrent_workspace_symlinked_component_denies_before_effect(
    tmp_path: Path,
) -> None:
    rows = paths(tmp_path)
    store = initialize_governance(rows)
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "receipt.txt"
    outside_file.write_bytes(b"")
    os.chmod(outside_file, 0o600)
    artifact_file = rows.workspace_root / "dist" / "receipt.txt"
    artifact_file.unlink()
    artifact_file.parent.rmdir()
    artifact_file.parent.symlink_to(outside, target_is_directory=True)
    wake = RecurrentWake(
        id="wake-slice20",
        seed=0,
        expires_at=EXPIRY,
        time_bucket="2099-08-25",
        receipts=signed_receipts(),
    )

    with pytest.raises(RecurrentCoordinatorDenied, match="RECURRENT_WORKSPACE_INCOMPLETE"):
        coordinator(rows).run(wake)

    assert not store.events("autonomy.self_goal.input.recorded")
    assert outside_file.read_bytes() == b""
