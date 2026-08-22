from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import threading

import pytest

from cct_agent.autonomy import AutonomyEngine, Opportunity
from cct_agent.kernel import AgencyKernel, NO_OP_ID, default_constitution
from cct_agent.store import EventStore


def digest(text: str) -> str:
    return sha256(text.encode()).hexdigest()


def make_engine(tmp_path: Path) -> AutonomyEngine:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = EventStore(tmp_path / "state" / "agency.sqlite")
    kernel = AgencyKernel(store, default_constitution("phase10-test"))
    kernel.initialize()
    return AutonomyEngine(store, kernel, workspace)


def write_plan(path: str, content: str, *, capability: str = "local_workspace_write"):
    del capability
    return {
        "steps": [
            {
                "id": "write",
                "action": {"kind": "write_text", "path": path, "content": content},
                "preconditions": [{"kind": "path_absent", "path": path}],
                "verify": [{"kind": "sha256_equals", "path": path, "sha256": digest(content)}],
            }
        ],
        "final_verify": [{"kind": "sha256_equals", "path": path, "sha256": digest(content)}],
    }


def opportunity(
    identifier: str,
    plan,
    *,
    authority: str = "host_adapter",
    capability: str = "local_workspace_write",
    competence: float = 0.8,
    uncertainty: float = 0.05,
) -> Opportunity:
    return Opportunity(
        id=identifier,
        title=f"Build {identifier}",
        rationale="A verified local artifact is useful evidence of capability.",
        objective=f"Produce and verify {identifier}.",
        source="test:host-adapter",
        source_authority=authority,
        value_impacts={"truth": 0.8, "competence": competence, "autonomy": 0.6},
        plan=plan,
        evidence=(f"test://{identifier}",),
        information_gain=0.4,
        uncertainty=uncertainty,
        time_cost=0.1,
        capability=capability,
    )


def test_private_state_is_disjoint_and_mode_hardened(tmp_path):
    engine = make_engine(tmp_path)
    assert oct(engine.state_root.stat().st_mode & 0o777) == "0o700"
    assert oct(engine.opportunity_root.stat().st_mode & 0o777) == "0o700"
    assert oct(engine.backup_root.stat().st_mode & 0o777) == "0o700"

    overlapping_workspace = tmp_path / "overlap-workspace"
    overlapping_workspace.mkdir()
    store = EventStore(tmp_path / "overlap-state" / "agency.sqlite")
    kernel = AgencyKernel(store, default_constitution("overlap-test"))
    kernel.initialize()
    with pytest.raises(ValueError, match="disjoint"):
        AutonomyEngine(
            store,
            kernel,
            overlapping_workspace,
            state_root=overlapping_workspace / "private",
        )


def test_symlink_run_lock_is_rejected(tmp_path):
    engine = make_engine(tmp_path)
    outside = tmp_path / "outside-lock"
    outside.write_text("unchanged")
    engine.lock_path.symlink_to(outside)
    engine.register_opportunity(opportunity("lock-link", write_plan("lock.md", "x")))
    with pytest.raises(OSError):
        engine.run_once(seed=0, run_id="lock-link-run")
    assert outside.read_text() == "unchanged"
    assert not (engine.workspace_root / "lock.md").exists()


def test_plan_content_is_hash_bound_outside_event_ledger(tmp_path):
    engine = make_engine(tmp_path)
    marker = "private-plan-content-8b79"
    registered = engine.register_opportunity(opportunity("private", write_plan("out.md", marker)))
    assert registered["plan_content_in_event_ledger"] is False
    serialized = "\n".join(str(event.payload) for event in engine.store.events())
    assert marker not in serialized
    plan_file = engine.opportunity_root / "private.json"
    assert marker in plan_file.read_text()
    assert oct(plan_file.stat().st_mode & 0o777) == "0o600"


def test_untrusted_model_proposal_cannot_execute(tmp_path):
    engine = make_engine(tmp_path)
    engine.register_opportunity(
        opportunity("suggestion", write_plan("nope.md", "nope"), authority="self")
    )
    result = engine.run_once(seed=0, run_id="untrusted-run")
    assert result["chosen_option_id"] == NO_OP_ID
    assert result["external_effects"] == 0
    assert not (engine.workspace_root / "nope.md").exists()


def test_success_forms_hierarchy_executes_verifies_and_records_outcome(tmp_path):
    engine = make_engine(tmp_path)
    engine.register_opportunity(opportunity("success", write_plan("result.md", "verified")))
    result = engine.run_once(seed=0, run_id="success-run")
    assert result["success"] is True
    assert result["verified"] is True
    assert result["receipt_count"] == 1
    assert (engine.workspace_root / "result.md").read_text() == "verified"
    objectives = engine.store.events("autonomy.objective.created")
    assert [event.payload["kind"] for event in objectives] == ["root", "milestone"]
    assert objectives[1].payload["parent_objective_id"] == objectives[0].payload["objective_id"]
    outcome = engine.store.latest("outcome.observed")
    assert outcome is not None
    assert outcome.payload["decision_id"] == result["decision_id"]
    assert engine.store.verify_chain()["valid"] is True


def test_controlled_failure_takes_fallback_and_records_replan(tmp_path):
    engine = make_engine(tmp_path)
    (engine.workspace_root / "collision.md").write_text("occupied")
    recovered = "fallback succeeded"
    plan = {
        "steps": [
            {
                "id": "recoverable",
                "action": {"kind": "write_text", "path": "collision.md", "content": "primary"},
                "preconditions": [{"kind": "path_absent", "path": "collision.md"}],
                "verify": [{"kind": "sha256_equals", "path": "collision.md", "sha256": digest("primary")}],
                "fallback": {
                    "action": {"kind": "write_text", "path": "recovered.md", "content": recovered},
                    "preconditions": [{"kind": "path_absent", "path": "recovered.md"}],
                    "verify": [{"kind": "sha256_equals", "path": "recovered.md", "sha256": digest(recovered)}],
                },
            }
        ],
        "final_verify": [{"kind": "sha256_equals", "path": "recovered.md", "sha256": digest(recovered)}],
    }
    engine.register_opportunity(opportunity("recover", plan, capability="fragile_write"))
    result = engine.run_once(seed=0, run_id="recover-run")
    assert result["success"] is True
    assert result["recovered_steps"] == 1
    assert (engine.workspace_root / "recovered.md").read_text() == recovered
    assert engine.store.latest("autonomy.plan.replanned") is not None
    assert result["realized_utility"] == pytest.approx(0.8)


def test_terminal_failure_rolls_back_prior_create(tmp_path):
    engine = make_engine(tmp_path)
    (engine.workspace_root / "blocker.md").write_text("occupied")
    plan = {
        "steps": [
            {
                "id": "first",
                "action": {"kind": "write_text", "path": "created.md", "content": "created"},
                "verify": [{"kind": "sha256_equals", "path": "created.md", "sha256": digest("created")}],
            },
            {
                "id": "second",
                "depends_on": ["first"],
                "action": {"kind": "write_text", "path": "blocker.md", "content": "never"},
                "preconditions": [{"kind": "path_absent", "path": "blocker.md"}],
                "verify": [{"kind": "sha256_equals", "path": "blocker.md", "sha256": digest("never")}],
            },
        ],
        "final_verify": [{"kind": "path_exists", "path": "created.md"}],
    }
    engine.register_opportunity(opportunity("rollback", plan))
    result = engine.run_once(seed=0, run_id="rollback-run")
    assert result["success"] is False
    assert result["rollback_performed"] is True
    assert result["rollback_complete"] is True
    assert not (engine.workspace_root / "created.md").exists()
    assert (engine.workspace_root / "blocker.md").read_text() == "occupied"


def test_level_two_remains_create_only_and_preserves_existing_bytes(tmp_path):
    engine = make_engine(tmp_path)
    target = engine.workspace_root / "existing.md"
    target.write_bytes(b"original-bytes")
    engine.store.append(
        "autonomy.authority.updated",
        {"run_id": "seed", "level": 2, "previous_level": 1, "reason": "test", "envelope": {}},
    )
    plan = {
        "steps": [
            {
                "id": "replace",
                "action": {"kind": "write_text", "path": "existing.md", "content": "replacement", "allow_replace": True},
                "verify": [{"kind": "sha256_equals", "path": "existing.md", "sha256": digest("replacement")}],
            }
        ],
        "final_verify": [{"kind": "sha256_equals", "path": "existing.md", "sha256": digest("replacement")}],
    }
    engine.register_opportunity(opportunity("restore", plan))
    result = engine.run_once(seed=0, run_id="restore-run")
    assert result["success"] is False
    assert target.read_bytes() == b"original-bytes"
    assert engine.store.latest("autonomy.action.receipt") is None
    assert engine.authority().allow_replace is False


@pytest.mark.parametrize(
    "bad_path",
    [
        "../escape.md",
        "/tmp/escape.md",
        "nested//unnormalized.md",
        "nested/./unnormalized.md",
        "nested\\windows.md",
        ".env",
        ".env.local",
        ".git/config",
        "wallet/key.txt",
        "credentials.json",
        "api-key.txt",
        "token.json",
        "service-account.json",
        "secret.pem",
    ],
)
def test_protected_or_escaping_paths_are_rejected(tmp_path, bad_path):
    engine = make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.register_opportunity(opportunity("badpath", write_plan(bad_path, "x")))


def test_symlink_target_is_rejected_without_touching_outside_file(tmp_path):
    engine = make_engine(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    (engine.workspace_root / "link.md").symlink_to(outside)
    engine.register_opportunity(opportunity("symlink", write_plan("link.md", "changed")))
    result = engine.run_once(seed=0, run_id="symlink-run")
    assert result["success"] is False
    assert outside.read_text() == "outside"


@pytest.mark.parametrize("target_kind", ["fifo", "directory", "hardlink"])
def test_nonregular_or_multiply_linked_targets_are_rejected(tmp_path, target_kind):
    engine = make_engine(tmp_path)
    target = engine.workspace_root / "unsafe-target"
    outside = tmp_path / "outside-hardlink"
    if target_kind == "fifo":
        os.mkfifo(target)
    elif target_kind == "directory":
        target.mkdir()
    else:
        outside.write_text("outside")
        os.link(outside, target)
    engine.register_opportunity(
        opportunity("unsafe-target", write_plan("unsafe-target", "replacement"))
    )
    result = engine.run_once(seed=0, run_id=f"unsafe-{target_kind}-run")
    assert result["success"] is False
    if target_kind == "hardlink":
        assert outside.read_text() == "outside"


def test_nested_real_directory_works_but_symlinked_parent_is_blocked(tmp_path):
    engine = make_engine(tmp_path)
    (engine.workspace_root / "real").mkdir()
    engine.register_opportunity(
        opportunity("nested-real", write_plan("real/nested.md", "nested"))
    )
    assert engine.run_once(seed=0, run_id="nested-real-run")["success"] is True
    assert (engine.workspace_root / "real/nested.md").read_text() == "nested"

    outside = tmp_path / "outside-parent"
    outside.mkdir()
    (engine.workspace_root / "linked").symlink_to(outside, target_is_directory=True)
    engine.register_opportunity(
        opportunity("nested-link", write_plan("linked/escaped.md", "blocked"))
    )
    blocked = engine.run_once(seed=0, run_id="nested-link-run")
    assert blocked["success"] is False
    assert not (outside / "escaped.md").exists()


def test_symlinked_private_plan_state_is_rejected(tmp_path):
    engine = make_engine(tmp_path)
    outside = tmp_path / "outside-plan.json"
    outside.write_text("{}")
    (engine.opportunity_root / "linked-plan.json").symlink_to(outside)
    with pytest.raises(ValueError, match="regular file"):
        engine.register_opportunity(
            opportunity("linked-plan", write_plan("blocked.md", "blocked"))
        )


def test_action_budget_exhaustion_rolls_back_all_prior_writes(tmp_path):
    engine = make_engine(tmp_path)
    steps = []
    for index in range(5):
        name = f"file-{index}.md"
        steps.append(
            {
                "id": f"step-{index}",
                "depends_on": [f"step-{index - 1}"] if index else [],
                "action": {"kind": "write_text", "path": name, "content": name},
                "verify": [{"kind": "sha256_equals", "path": name, "sha256": digest(name)}],
            }
        )
    plan = {"steps": steps, "final_verify": [{"kind": "path_exists", "path": "file-4.md"}]}
    engine.register_opportunity(opportunity("budget", plan))
    result = engine.run_once(seed=0, run_id="budget-run")
    assert result["success"] is False
    assert result["rollback_performed"] is True
    assert not list(engine.workspace_root.iterdir())


def test_artifact_gap_adapter_detects_executes_then_observes_satisfied(tmp_path):
    engine = make_engine(tmp_path)
    content = "adapter-created\n"
    observed = engine.observe_artifact_gap(
        opportunity_id="artifact-gap",
        relative_path="adapter.md",
        content=content,
        title="Create adapter artifact",
        rationale="The configured verified artifact is missing.",
        objective="Create and hash-verify adapter.md.",
        value_impacts={"truth": 0.8, "competence": 0.8, "autonomy": 0.7},
        source="test-adapter",
    )
    assert observed["registered"] is True
    result = engine.run_once(seed=0, run_id="artifact-gap-run")
    assert result["success"] is True
    assert (engine.workspace_root / "adapter.md").read_text() == content
    satisfied = engine.observe_artifact_gap(
        opportunity_id="artifact-gap",
        relative_path="adapter.md",
        content=content,
        title="Create adapter artifact",
        rationale="The configured verified artifact is missing.",
        objective="Create and hash-verify adapter.md.",
        value_impacts={"truth": 0.8, "competence": 0.8, "autonomy": 0.7},
        source="test-adapter",
    )
    assert satisfied["status"] == "already_satisfied"
    assert len(engine.store.events("autonomy.opportunity.detected")) == 1


def test_artifact_gap_adapter_never_replaces_mismatched_existing_file(tmp_path):
    engine = make_engine(tmp_path)
    target = engine.workspace_root / "occupied.md"
    target.write_text("operator-owned")
    observed = engine.observe_artifact_gap(
        opportunity_id="occupied-gap",
        relative_path="occupied.md",
        content="replacement",
        title="Blocked adapter artifact",
        rationale="Existing content must not be replaced at baseline authority.",
        objective="Respect existing operator content.",
        value_impacts={"truth": 0.8, "competence": 0.8},
        source="test-adapter",
    )
    assert observed["status"] == "blocked"
    assert target.read_text() == "operator-owned"
    assert not engine.store.events("autonomy.opportunity.registered")


def test_run_id_is_idempotent(tmp_path):
    engine = make_engine(tmp_path)
    engine.register_opportunity(opportunity("idempotent", write_plan("once.md", "once")))
    first = engine.run_once(seed=0, run_id="same-run")
    second = engine.run_once(seed=999, run_id="same-run")
    assert first["event_id"] == second["event_id"]
    assert second["idempotent"] is True
    assert len(engine.store.events("autonomy.run.completed")) == 1
    assert len(engine.store.events("autonomy.action.receipt")) == 1


def test_started_run_resumes_recorded_plan_after_crash(tmp_path, monkeypatch):
    engine = make_engine(tmp_path)
    engine.register_opportunity(opportunity("resume-start", write_plan("resume.md", "resume")))
    original_execute = engine._execute_plan

    def crash_once(*args, **kwargs):
        raise RuntimeError("controlled crash after start")

    monkeypatch.setattr(engine, "_execute_plan", crash_once)
    with pytest.raises(RuntimeError, match="controlled crash"):
        engine.run_once(
            seed=0,
            run_id="crashed-run",
            decision_id="crashed-decision",
        )
    assert len(engine.store.events("autonomy.run.started")) == 1
    assert not engine.store.events("autonomy.run.completed")
    monkeypatch.setattr(engine, "_execute_plan", original_execute)
    resumed = engine.run_once(seed=999, run_id="crashed-run")
    assert resumed["success"] is True
    assert resumed["decision_id"] == "crashed-decision"
    assert (engine.workspace_root / "resume.md").read_text() == "resume"
    assert len(engine.store.events("autonomy.run.started")) == 1


def test_claim_reconciles_crash_after_atomic_publish(tmp_path, monkeypatch):
    engine = make_engine(tmp_path)
    engine.register_opportunity(
        opportunity("claim-crash", write_plan("claim-crash.md", "claimed"))
    )
    original_publish = engine._publish_claimed_file
    crashed = False

    def crash_after_publish(claim):
        nonlocal crashed
        original_publish(claim)
        if claim["relative_path"] == "claim-crash.md" and not crashed:
            crashed = True
            raise KeyboardInterrupt("controlled crash after atomic publish")

    monkeypatch.setattr(engine, "_publish_claimed_file", crash_after_publish)
    with pytest.raises(KeyboardInterrupt):
        engine.run_once(seed=0, run_id="claim-crash-run")
    assert (engine.workspace_root / "claim-crash.md").read_text() == "claimed"
    assert len(engine.store.events("autonomy.action.claimed")) == 1
    assert not engine.store.events("autonomy.action.receipt")

    monkeypatch.setattr(engine, "_publish_claimed_file", original_publish)
    recovered = engine.run_once(seed=999, run_id="claim-crash-run")
    assert recovered["success"] is True
    assert recovered["receipt_count"] == 1
    receipts = engine.store.events("autonomy.action.receipt")
    assert len(receipts) == 1
    assert receipts[0].payload["reconciled_after_restart"] is True
    assert len(engine.store.events("autonomy.action.claimed")) == 1


def test_outcome_and_completion_are_singletons_after_finalize_crash(
    tmp_path, monkeypatch
):
    engine = make_engine(tmp_path)
    engine.register_opportunity(
        opportunity("outcome-crash", write_plan("outcome-crash.md", "durable"))
    )
    original_append_once = engine.store.append_once
    crashed = False

    def crash_before_completion(kind, logical_key, payload):
        nonlocal crashed
        if kind == "autonomy.run.completed" and not crashed:
            crashed = True
            raise KeyboardInterrupt("simulated crash before completion append")
        return original_append_once(kind, logical_key, payload)

    monkeypatch.setattr(engine.store, "append_once", crash_before_completion)
    with pytest.raises(KeyboardInterrupt):
        engine.run_once(seed=0, run_id="outcome-crash-run")
    assert len(engine.store.events("autonomy.run.executed")) == 1
    assert len(engine.store.events("outcome.observed")) == 1
    assert not engine.store.events("autonomy.run.completed")

    monkeypatch.setattr(engine.store, "append_once", original_append_once)
    completed = engine.run_once(seed=0, run_id="outcome-crash-run")
    assert completed["success"] is True
    assert len(engine.store.events("autonomy.run.executed")) == 1
    assert len(engine.store.events("outcome.observed")) == 1
    assert len(engine.store.events("autonomy.run.completed")) == 1
    assert (engine.workspace_root / "outcome-crash.md").read_text() == "durable"


def test_foreign_same_bytes_after_prewrite_claim_never_become_receipt(
    tmp_path, monkeypatch
):
    engine = make_engine(tmp_path)
    engine.register_opportunity(
        opportunity("foreign-claim", write_plan("foreign.md", "expected"))
    )

    def crash_before_publish(_claim):
        raise KeyboardInterrupt("controlled crash before publish")

    monkeypatch.setattr(engine, "_publish_claimed_file", crash_before_publish)
    with pytest.raises(KeyboardInterrupt):
        engine.run_once(seed=0, run_id="foreign-claim-run")
    (engine.workspace_root / "foreign.md").write_text("expected")
    monkeypatch.undo()

    resumed = engine.run_once(seed=0, run_id="foreign-claim-run")
    assert resumed["success"] is False
    assert (engine.workspace_root / "foreign.md").read_text() == "expected"
    assert not engine.store.events("autonomy.action.receipt")


def test_atomic_no_replace_preserves_concurrent_creator(tmp_path, monkeypatch):
    engine = make_engine(tmp_path)
    engine.register_opportunity(
        opportunity("create-race", write_plan("raced.md", "agent"))
    )
    original_publish = engine._publish_claimed_file

    def concurrent_create_then_publish(claim):
        (engine.workspace_root / "raced.md").write_text("external")
        original_publish(claim)

    monkeypatch.setattr(engine, "_publish_claimed_file", concurrent_create_then_publish)
    result = engine.run_once(seed=0, run_id="create-race-run")
    assert result["success"] is False
    assert (engine.workspace_root / "raced.md").read_text() == "external"
    assert not engine.store.events("autonomy.action.receipt")


def test_workspace_root_descriptor_survives_path_substitution(tmp_path):
    engine = make_engine(tmp_path)
    engine.register_opportunity(
        opportunity("pinned-root", write_plan("pinned.md", "inside-original"))
    )
    configured = engine.workspace_root
    moved = tmp_path / "workspace-original-inode"
    outside = tmp_path / "outside-tree"
    outside.mkdir()
    configured.rename(moved)
    configured.symlink_to(outside, target_is_directory=True)

    result = engine.run_once(seed=0, run_id="pinned-root-run")
    assert result["success"] is True
    assert (moved / "pinned.md").read_text() == "inside-original"
    assert not (outside / "pinned.md").exists()


def test_completed_run_repairs_projection_after_finalize_crash(tmp_path, monkeypatch):
    engine = make_engine(tmp_path)
    engine.register_opportunity(opportunity("repair-finalize", write_plan("repair.md", "repair")))
    original_finalize = engine._finalize_completion

    def crash_finalize(completion):
        raise RuntimeError("controlled crash after completion")

    monkeypatch.setattr(engine, "_finalize_completion", crash_finalize)
    with pytest.raises(RuntimeError, match="after completion"):
        engine.run_once(seed=0, run_id="repair-run")
    assert len(engine.store.events("autonomy.run.completed")) == 1
    assert not engine.store.events("autonomy.opportunity.status_changed")
    monkeypatch.setattr(engine, "_finalize_completion", original_finalize)
    repaired = engine.run_once(seed=999, run_id="repair-run")
    assert repaired["idempotent"] is True
    assert len(engine.store.events("autonomy.opportunity.status_changed")) == 1
    assert len(engine.store.events("autonomy.objective.status_changed")) == 1
    assert len(engine.store.events("autonomy.authority.updated")) == 1
    goal = engine.kernel.goal("goal_repair-finalize")
    assert goal is not None and goal.status == "completed"


def test_receipt_ledger_failure_emergency_rolls_back_write(tmp_path, monkeypatch):
    engine = make_engine(tmp_path)
    engine.register_opportunity(opportunity("receipt-fail", write_plan("untracked.md", "must vanish")))
    original_append_once = engine.store.append_once
    failed = False

    def fail_receipt(kind, logical_key, payload):
        nonlocal failed
        if kind == "autonomy.action.receipt" and not failed:
            failed = True
            raise OSError("controlled receipt store failure")
        return original_append_once(kind, logical_key, payload)

    monkeypatch.setattr(engine.store, "append_once", fail_receipt)
    result = engine.run_once(seed=0, run_id="receipt-fail-run")
    assert result["success"] is False
    assert not (engine.workspace_root / "untracked.md").exists()
    assert not engine.store.events("autonomy.action.receipt")


def test_concurrent_same_run_executes_once(tmp_path):
    engine = make_engine(tmp_path)
    engine.register_opportunity(opportunity("concurrent", write_plan("one.md", "one")))
    results = []
    errors = []

    def worker():
        try:
            results.append(engine.run_once(seed=0, run_id="concurrent-run"))
        except Exception as exc:  # pragma: no cover - assertion reports failures
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert len(results) == 2
    assert len(engine.store.events("autonomy.run.completed")) == 1
    assert sorted(result["idempotent"] for result in results) == [False, True]


def test_no_effect_verification_cannot_expand_authority_or_learning(tmp_path):
    engine = make_engine(tmp_path)
    for index in range(3):
        path = f"already-{index}.md"
        content = f"already-{index}"
        (engine.workspace_root / path).write_text(content)
        engine.register_opportunity(
            opportunity(
                f"already-{index}",
                write_plan(path, content),
                capability="no-effect-capability",
            )
        )
        result = engine.run_once(seed=0, run_id=f"already-run-{index}")
        assert result["success"] is True
        assert result["receipt_count"] == 0
    assert engine.authority().level == 1
    assert engine._capability_learning("no-effect-capability")["samples"] == 0


def test_three_clean_successes_expand_authority_then_failure_contracts(tmp_path):
    engine = make_engine(tmp_path)
    for index in range(3):
        identifier = f"clean-{index}"
        engine.register_opportunity(opportunity(identifier, write_plan(f"{identifier}.md", identifier)))
        result = engine.run_once(seed=0, run_id=f"run-{identifier}")
        assert result["success"] is True
    assert engine.authority().level == 2
    (engine.workspace_root / "blocked.md").write_text("occupied")
    failing = {
        "steps": [
            {
                "id": "fail",
                "action": {"kind": "write_text", "path": "blocked.md", "content": "no"},
                "preconditions": [{"kind": "path_absent", "path": "blocked.md"}],
                "verify": [{"kind": "sha256_equals", "path": "blocked.md", "sha256": digest("no")}],
            }
        ],
        "final_verify": [{"kind": "sha256_equals", "path": "blocked.md", "sha256": digest("no")}],
    }
    engine.register_opportunity(opportunity("contract", failing))
    failed = engine.run_once(seed=0, run_id="contract-run")
    assert failed["success"] is False
    assert engine.authority().level == 1


def test_recovery_evidence_changes_later_portfolio_choice(tmp_path):
    engine = make_engine(tmp_path)
    (engine.workspace_root / "collision.md").write_text("occupied")
    recovered = "recovered"
    risky_plan = {
        "steps": [
            {
                "id": "risky",
                "action": {"kind": "write_text", "path": "collision.md", "content": "primary"},
                "preconditions": [{"kind": "path_absent", "path": "collision.md"}],
                "verify": [{"kind": "sha256_equals", "path": "collision.md", "sha256": digest("primary")}],
                "fallback": {
                    "action": {"kind": "write_text", "path": "recovered.md", "content": recovered},
                    "verify": [{"kind": "sha256_equals", "path": "recovered.md", "sha256": digest(recovered)}],
                },
            }
        ],
        "final_verify": [{"kind": "sha256_equals", "path": "recovered.md", "sha256": digest(recovered)}],
    }
    engine.register_opportunity(
        opportunity("risky-first", risky_plan, capability="fragile_write", competence=0.82)
    )
    engine.register_opportunity(
        opportunity("stable-first", write_plan("stable-first.md", "stable"), capability="stable_write", competence=0.62)
    )
    first = engine.run_once(seed=0, run_id="learning-first")
    assert first["opportunity_id"] == "risky-first"
    assert first["recovered_steps"] == 1
    engine.register_opportunity(
        opportunity("risky-next", write_plan("risky-next.md", "risky"), capability="fragile_write", competence=0.82)
    )
    decision = engine.select_opportunity(seed=0, decision_id="learning-second-choice")
    assert decision["opportunity_id"] in {"stable-first"}
    assert decision["opportunity_id"] != "risky-next"
    assert decision["learning"]["risky-next"]["quality"] == 0.25


def test_oversized_existing_file_is_not_read_or_replaced(tmp_path):
    engine = make_engine(tmp_path)
    engine.store.append(
        "autonomy.authority.updated",
        {"run_id": "manual", "from_level": 1, "to_level": 2, "level": 2, "reason": "test"},
    )
    target = engine.workspace_root / "large.txt"
    target.write_bytes(b"x" * 1_048_577)
    replacement_plan = {
        "steps": [
            {
                "id": "replace",
                "action": {
                    "kind": "write_text",
                    "path": "large.txt",
                    "content": "new",
                    "allow_replace": True,
                },
                "preconditions": [{"kind": "path_exists", "path": "large.txt"}],
                "verify": [
                    {
                        "kind": "sha256_equals",
                        "path": "large.txt",
                        "sha256": digest("new"),
                    }
                ],
            }
        ],
        "final_verify": [
            {"kind": "sha256_equals", "path": "large.txt", "sha256": digest("new")}
        ],
    }
    engine.register_opportunity(opportunity("large-replace", replacement_plan))
    result = engine.run_once(seed=0, run_id="large-replace-run")
    assert result["success"] is False
    assert target.stat().st_size == 1_048_577


def test_incomplete_immediate_rollback_never_runs_fallback(tmp_path, monkeypatch):
    engine = make_engine(tmp_path)
    primary = "primary"
    fallback = "fallback"
    plan = {
        "steps": [
            {
                "id": "fragile",
                "action": {
                    "kind": "write_text",
                    "path": "primary.md",
                    "content": primary,
                },
                "verify": [
                    {
                        "kind": "sha256_equals",
                        "path": "primary.md",
                        "sha256": digest(primary),
                    },
                    {
                        "kind": "sha256_equals",
                        "path": "primary.md",
                        "sha256": digest("different"),
                    },
                ],
                "fallback": {
                    "action": {
                        "kind": "write_text",
                        "path": "fallback.md",
                        "content": fallback,
                    },
                    "verify": [
                        {
                            "kind": "sha256_equals",
                            "path": "fallback.md",
                            "sha256": digest(fallback),
                        }
                    ],
                },
            }
        ],
        "final_verify": [
            {
                "kind": "sha256_equals",
                "path": "fallback.md",
                "sha256": digest(fallback),
            }
        ],
    }
    engine.register_opportunity(opportunity("rollback-incomplete", plan))
    monkeypatch.setattr(
        engine,
        "_rollback",
        lambda *args, **kwargs: {"complete": False, "event_ids": []},
    )
    result = engine.run_once(seed=0, run_id="rollback-incomplete-run")
    assert result["success"] is False
    assert result["rollback_complete"] is False
    assert not (engine.workspace_root / "fallback.md").exists()


def test_final_receipt_verification_detects_interstep_tamper_without_clobber(
    tmp_path, monkeypatch
):
    engine = make_engine(tmp_path)
    first = "first"
    second = "second"
    plan = {
        "steps": [
            {
                "id": "first",
                "action": {"kind": "write_text", "path": "first.md", "content": first},
                "verify": [
                    {
                        "kind": "sha256_equals",
                        "path": "first.md",
                        "sha256": digest(first),
                    }
                ],
            },
            {
                "id": "second",
                "depends_on": ["first"],
                "action": {"kind": "write_text", "path": "second.md", "content": second},
                "verify": [
                    {
                        "kind": "sha256_equals",
                        "path": "second.md",
                        "sha256": digest(second),
                    }
                ],
            },
        ],
        "final_verify": [
            {
                "kind": "sha256_equals",
                "path": "second.md",
                "sha256": digest(second),
            }
        ],
    }
    engine.register_opportunity(opportunity("interstep-tamper", plan))
    original_evaluate = engine._evaluate_checks
    changed = False

    def tamper_after_second_verifier(checks):
        nonlocal changed
        result = original_evaluate(checks)
        if (
            not changed
            and checks == plan["final_verify"]
            and (engine.workspace_root / "first.md").exists()
        ):
            (engine.workspace_root / "first.md").write_text("external-tamper")
            changed = True
        return result

    monkeypatch.setattr(engine, "_evaluate_checks", tamper_after_second_verifier)
    result = engine.run_once(seed=0, run_id="interstep-tamper-run")
    assert result["success"] is False
    assert result["rollback_complete"] is False
    assert (engine.workspace_root / "first.md").read_text() == "external-tamper"
    assert not (engine.workspace_root / "second.md").exists()


def test_state_root_descriptor_survives_path_substitution(tmp_path):
    engine = make_engine(tmp_path)
    original = opportunity("state-root-pinned", write_plan("pinned.md", "one"))
    engine.register_opportunity(original)
    state_path = engine.state_root
    pinned_tree = tmp_path / "pinned-state-tree"
    outside = tmp_path / "outside-state"
    outside.mkdir()
    state_path.rename(pinned_tree)
    state_path.symlink_to(outside, target_is_directory=True)

    again = engine.register_opportunity(original)
    assert again["opportunity_id"] == original.id
    with pytest.raises(ValueError, match="collision"):
        engine.register_opportunity(
            opportunity("state-root-pinned", write_plan("pinned.md", "two"))
        )
    assert (pinned_tree / "opportunities/state-root-pinned.json").is_file()
    assert not (outside / "opportunities/state-root-pinned.json").exists()


def test_rollback_replay_recognizes_quarantine_and_preserves_reoccupied_path(tmp_path):
    engine = make_engine(tmp_path)
    engine.register_opportunity(
        opportunity("rollback-replay", write_plan("rollback-replay.md", "owned"))
    )
    result = engine.run_once(seed=1001, run_id="rollback-replay-run")
    assert result["success"] is True
    receipt_event = next(
        event
        for event in engine.store.events("autonomy.action.receipt")
        if event.payload["run_id"] == "rollback-replay-run"
    )
    receipt = {**receipt_event.payload, "event_id": receipt_event.event_id}

    first = engine._rollback("rollback-replay-run", [receipt], reason="test")
    assert first["complete"] is True
    target = engine.workspace_root / "rollback-replay.md"
    assert not target.exists()
    target.write_text("foreign", encoding="utf-8")

    replay = engine._rollback("rollback-replay-run", [receipt], reason="test")
    assert replay["complete"] is True
    assert target.read_text(encoding="utf-8") == "foreign"


def test_rollback_replay_restores_foreign_capture_after_quarantine_crash(tmp_path):
    engine = make_engine(tmp_path)
    engine.register_opportunity(
        opportunity("foreign-quarantine", write_plan("foreign-quarantine.md", "owned"))
    )
    result = engine.run_once(seed=1002, run_id="foreign-quarantine-run")
    assert result["success"] is True
    receipt_event = next(
        event
        for event in engine.store.events("autonomy.action.receipt")
        if event.payload["run_id"] == "foreign-quarantine-run"
    )
    receipt = {**receipt_event.payload, "event_id": receipt_event.event_id}
    target = engine.workspace_root / "foreign-quarantine.md"
    target.unlink()
    target.write_text("foreign-capture", encoding="utf-8")
    token = digest(f"foreign-quarantine-run:{receipt_event.event_id}")[:24]
    quarantine = engine.state_root / "quarantine" / f"{token}-{target.name}"
    quarantine.parent.mkdir(parents=True, exist_ok=True)
    target.rename(quarantine)

    replay = engine._rollback("foreign-quarantine-run", [receipt], reason="test")
    assert replay["complete"] is False
    assert target.read_text(encoding="utf-8") == "foreign-capture"
    assert not quarantine.exists()


def test_plan_schema_rejects_unknown_fields_coercion_and_excess_retries(tmp_path):
    engine = make_engine(tmp_path)
    cases = []

    unknown_plan = write_plan("unknown-plan.md", "x")
    unknown_plan["command"] = "ignored-before-hardening"
    cases.append(unknown_plan)

    unknown_action = write_plan("unknown-action.md", "x")
    unknown_action["steps"][0]["action"]["tool"] = "shell"
    cases.append(unknown_action)

    coerced_content = write_plan("coerced.md", "x")
    coerced_content["steps"][0]["action"]["content"] = {"not": "text"}
    cases.append(coerced_content)

    excessive_retry = write_plan("retry.md", "x")
    excessive_retry["steps"][0]["max_attempts"] = 4
    cases.append(excessive_retry)

    unknown_check = write_plan("unknown-check.md", "x")
    unknown_check["steps"][0]["verify"][0]["command"] = "ignored"
    cases.append(unknown_check)

    unrelated_verifier = write_plan("claimed.md", "x")
    unrelated_verifier["steps"][0]["verify"] = [
        {"kind": "sha256_equals", "path": "unrelated.md", "sha256": digest("x")}
    ]
    cases.append(unrelated_verifier)

    existence_only = write_plan("existence-only.md", "x")
    existence_only["steps"][0]["verify"] = [
        {"kind": "path_exists", "path": "existence-only.md"}
    ]
    cases.append(existence_only)

    mismatched_fallback = write_plan("primary.md", "x")
    mismatched_fallback["steps"][0]["fallback"] = {
        "action": {"kind": "write_text", "path": "fallback.md", "content": "y"},
        "verify": [
            {"kind": "sha256_equals", "path": "primary.md", "sha256": digest("x")}
        ],
    }
    cases.append(mismatched_fallback)

    for index, plan in enumerate(cases):
        with pytest.raises(ValueError):
            engine.register_opportunity(opportunity(f"strict-{index}", plan))


def test_cycle_and_unknown_dependency_are_rejected(tmp_path):
    engine = make_engine(tmp_path)
    cycle = {
        "steps": [
            {
                "id": "a", "depends_on": ["b"],
                "action": {"kind": "write_text", "path": "a.md", "content": "a"},
                "verify": [{"kind": "sha256_equals", "path": "a.md", "sha256": digest("a")}],
            },
            {
                "id": "b", "depends_on": ["a"],
                "action": {"kind": "write_text", "path": "b.md", "content": "b"},
                "verify": [{"kind": "sha256_equals", "path": "b.md", "sha256": digest("b")}],
            },
        ],
        "final_verify": [{"kind": "path_exists", "path": "a.md"}],
    }
    with pytest.raises(ValueError, match="cycle"):
        engine.register_opportunity(opportunity("cycle", cycle))


def test_already_verified_artifact_recovers_after_crash_without_rewrite(tmp_path):
    engine = make_engine(tmp_path)
    target = engine.workspace_root / "existing.md"
    target.write_text("already")
    before_mtime = target.stat().st_mtime_ns
    engine.register_opportunity(opportunity("resume", write_plan("existing.md", "already")))
    result = engine.run_once(seed=0, run_id="resume-run")
    assert result["success"] is True
    assert result["receipt_count"] == 0
    assert target.stat().st_mtime_ns == before_mtime
    assert engine.store.latest("autonomy.step.recovered") is not None
