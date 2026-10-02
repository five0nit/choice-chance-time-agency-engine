from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
from threading import Event, Thread, current_thread
import time
from unittest.mock import patch

import pytest

from cct_agent.autonomy import AutonomyEngine
from cct_agent.kernel import AgencyKernel, default_constitution
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.store import EventStore
from cct_agent.work_autonomy import WorkAutonomyRunner, main


NOW = "2026-08-25T08:30:00+10:00"


def test_cli_requires_runtime_provenance_arguments(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(
            [
                "--state-root",
                str(tmp_path / "state"),
                "--workspace-root",
                str(tmp_path / "workspace"),
                "--private-root",
                str(tmp_path / "private"),
                "--identity",
                "work-autonomy-test",
                "--time-bucket",
                "2026-08-25",
            ]
        )


def configured_runner(tmp_path: Path) -> tuple[EventStore, WorkAutonomyRunner]:
    store = EventStore(tmp_path / "state" / "agency.sqlite", clock=lambda: NOW)
    kernel = AgencyKernel(store, default_constitution("work-autonomy-test"))
    kernel.initialize()
    PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={
                "truth": 1.0,
                "competence": 0.95,
                "autonomy": 0.95,
                "usefulness": 0.95,
            },
            directives=(
                PrincipalDirective(
                    id="prefer-verified-autonomy",
                    kind="preference",
                    statement="Prefer useful reversible work backed by verification receipts.",
                    tags=("domain:opportunity", "action:review"),
                    priority=95,
                ),
            ),
            uncertainty_threshold=0.35,
        ),
        authority="operator",
        evidence=("operator:work-autonomy-test",),
    )
    kernel.form_goal(
        goal_id="goal-verify-project-health",
        statement="Verify project health and produce one bounded evidence receipt.",
        rationale="A fresh verified receipt turns a known evidence gap into useful local work.",
        source="joint",
        horizon="today",
        alignment={"truth": 1.0, "competence": 0.95, "autonomy": 0.9},
        evidence=("tool:pytest:387 passed", "goal:goal-verify-project-health"),
    )
    runner = WorkAutonomyRunner(
        store,
        kernel=kernel,
        workspace_root=tmp_path / "workspace",
        state_root=tmp_path / "work-state",
    )
    return store, runner


def test_cli_uses_shared_proactive_wake_counter(tmp_path: Path) -> None:
    store, _runner = configured_runner(tmp_path)
    with patch(
        "cct_agent.recurrent.runtime_provenance",
        return_value={
            "module_root": str(tmp_path / "site-packages"),
            "package_version": "0.9.0a10",
        },
    ):
        assert (
            main(
                [
                    "--state-root",
                    str(store.path.parent),
                    "--workspace-root",
                    str(tmp_path / "cli-workspace"),
                    "--private-root",
                    str(tmp_path / "cli-private"),
                    "--identity",
                    "work-autonomy-test",
                    "--expected-module-root",
                    str(tmp_path / "site-packages"),
                    "--expected-package-version",
                    "0.9.0a10",
                    "--time-bucket",
                    "2026-08-25",
                    "--message-only",
                ]
            )
            == 0
        )
    with sqlite3.connect(store.path) as connection:
        counters = dict(connection.execute("SELECT name,value FROM counters"))
    assert counters["proactive_wake"] == 1
    assert "work_autonomy_wake" not in counters


def test_suggests_work_attempts_local_audit_and_duplicate_is_silent(tmp_path: Path) -> None:
    store, runner = configured_runner(tmp_path)

    first = runner.run_once(seed=0, wake_index=1, time_bucket="2026-08-25")
    duplicate = WorkAutonomyRunner(
        EventStore(store.path, clock=lambda: NOW),
        kernel=AgencyKernel(
            EventStore(store.path, clock=lambda: NOW),
            default_constitution("work-autonomy-test"),
        ),
        workspace_root=tmp_path / "workspace",
        state_root=tmp_path / "work-state",
    ).run_once(seed=0, wake_index=2, time_bucket="2026-08-25")

    assert first["suggested"] is True
    assert first["attempted"] is True
    assert first["verified"] is True
    assert first["external_effects"] == 0
    assert first["suggestion"]["goal_id"] == "goal-verify-project-health"
    assert first["attempt"]["effect_class"] == "reversible_local_create"
    assert first["attempt"]["artifact_sha256"]
    assert "Suggested work:" in first["message"]
    assert "Attempted autonomously:" in first["message"]
    assert "No network, public, financial, credential, or destructive effect." in first["message"]

    artifact = tmp_path / "workspace" / first["attempt"]["relative_path"]
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["suggestion_id"] == first["suggestion"]["suggestion_id"]
    assert payload["attempt_kind"] == "local_evidence_audit"
    assert payload["external_effects"] == 0

    assert duplicate["message"] == ""
    assert duplicate["idempotent"] is True
    assert len(store.events("autonomy.work.suggested")) == 1
    assert len(store.events("autonomy.work.attempted")) == 1
    assert len(store.events("autonomy.action.receipt")) == 1
    assert store.verify_chain()["valid"] is True


def test_high_consequence_goal_is_only_attempted_as_local_evidence_audit(tmp_path: Path) -> None:
    store, runner = configured_runner(tmp_path)
    kernel = runner.kernel
    kernel.set_goal_status(
        "goal-verify-project-health",
        "completed",
        "Fixture now selects the consequential goal.",
    )
    kernel.form_goal(
        goal_id="goal-public-release",
        statement="Publish a public release after operator approval.",
        rationale="Release remains consequential and must not inherit local-write authority.",
        source="joint",
        horizon="today",
        alignment={"truth": 0.9, "competence": 0.9, "autonomy": 0.8},
        evidence=("operator:release-requires-approval",),
    )

    result = runner.run_once(seed=0, wake_index=1, time_bucket="2026-08-25")

    assert result["suggested"] is True
    assert result["attempted"] is True
    assert result["verified"] is True
    assert result["attempt"]["attempt_kind"] == "local_evidence_audit"
    assert result["attempt"]["requested_effect_executed"] is False
    assert result["external_effects"] == 0
    assert not store.events("public_action.real.completed")
    assert not store.events("deployment.profile.completed")


def test_work_attempt_cannot_execute_stronger_foreign_open_opportunity(
    tmp_path: Path,
) -> None:
    store, runner = configured_runner(tmp_path)
    engine = AutonomyEngine(
        store,
        runner.kernel,
        runner.workspace_root,
        state_root=runner.state_root,
    )
    try:
        foreign = engine.observe_artifact_gap(
            opportunity_id="foreign-open",
            relative_path="foreign.txt",
            content="foreign effect\n",
            title="Higher-scored foreign opportunity",
            rationale="This pre-existing executable opportunity must remain out of scope.",
            objective="Create the foreign artifact.",
            value_impacts={
                "truth": 1.0,
                "competence": 1.0,
                "autonomy": 1.0,
                "care": 1.0,
            },
            source="foreign-host-adapter",
            information_gain=1.0,
            uncertainty=0.0,
            time_cost=0.0,
        )
        assert foreign["registered"] is True
    finally:
        engine.close()

    result = runner.run_once(seed=0, wake_index=1, time_bucket="2026-08-25")

    assert result["verified"] is True
    assert result["attempt"]["run_id"].startswith("work-run-")
    assert not (runner.workspace_root / "foreign.txt").exists()
    assert (runner.workspace_root / result["attempt"]["relative_path"]).is_file()
    assert store.verify_chain()["valid"] is True


def test_concurrent_same_state_creates_one_attempt_and_one_message(tmp_path: Path) -> None:
    store, seed_runner = configured_runner(tmp_path)

    def run(_: int) -> dict[str, object]:
        worker_store = EventStore(store.path, clock=lambda: NOW)
        worker_kernel = AgencyKernel(
            worker_store, default_constitution("work-autonomy-test")
        )
        return WorkAutonomyRunner(
            worker_store,
            kernel=worker_kernel,
            workspace_root=seed_runner.workspace_root,
            state_root=seed_runner.state_root,
        ).run_once(seed=0, wake_index=1, time_bucket="2026-08-25")

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(run, (1, 2, 3, 4)))

    assert sum(bool(result["message"]) for result in results) == 1
    assert len(store.events("autonomy.work.suggested")) == 1
    assert len(store.events("autonomy.work.attempted")) == 1
    assert len(store.events("autonomy.action.receipt")) == 1
    assert len(store.events("autonomy.work.presentation.completed")) == 1
    assert len(store.events("proactive.message.emitted")) == 1
    assert store.verify_chain()["valid"] is True


def test_new_trusted_source_state_triggers_next_least_attempted_goal(tmp_path: Path) -> None:
    store, runner = configured_runner(tmp_path)
    runner.kernel.form_goal(
        goal_id="goal-document-runtime",
        statement="Document runtime evidence and produce one bounded receipt.",
        rationale="A second active goal proves work rotation after real source change.",
        source="joint",
        horizon="today",
        alignment={"truth": 0.9, "competence": 0.9, "autonomy": 0.85},
        evidence=("tool:runtime:loader verified",),
    )

    first = runner.run_once(seed=0, wake_index=1, time_bucket="2026-08-25")
    unchanged = runner.run_once(seed=0, wake_index=2, time_bucket="2026-08-25")
    store.append_once(
        "sensor.team_sync.cursor.advanced",
        "source-state-2",
        {"offset": 2, "cycle_tick": 2},
    )
    changed = runner.run_once(seed=0, wake_index=4, time_bucket="2026-08-25")
    store.append_once(
        "sensor.team_sync.cursor.advanced",
        "same-source-state-new-cycle",
        {"offset": 2, "cycle_tick": 3},
    )
    same_offset = runner.run_once(
        seed=0, wake_index=7, time_bucket="2026-08-25"
    )

    assert first["message"]
    assert unchanged["message"] == ""
    assert changed["message"]
    assert same_offset["message"] == ""
    assert changed["suggestion"]["goal_id"] != first["suggestion"]["goal_id"]
    assert len(store.events("autonomy.work.suggested")) == 2
    assert len(store.events("autonomy.work.attempted")) == 2
    assert len(store.events("proactive.message.emitted")) == 2
    assert store.verify_chain()["valid"] is True


def test_source_change_during_selection_restarts_before_any_stale_effect(
    tmp_path: Path,
) -> None:
    store, seed_runner = configured_runner(tmp_path)
    paused = Event()
    resume = Event()
    blocked_once = False
    original_choose = WorkAutonomyRunner._choose

    def paused_choose(self, goals, *, trigger_digest, seed):
        nonlocal blocked_once
        result = original_choose(
            self, goals, trigger_digest=trigger_digest, seed=seed
        )
        if current_thread().name == "stale" and not blocked_once:
            blocked_once = True
            paused.set()
            assert resume.wait(timeout=5)
        return result

    results: list[dict[str, object]] = []
    errors: list[BaseException] = []

    def run(name: str, wake_index: int) -> None:
        try:
            worker_store = EventStore(store.path, clock=lambda: NOW)
            worker_kernel = AgencyKernel(
                worker_store, default_constitution("work-autonomy-test")
            )
            runner = WorkAutonomyRunner(
                worker_store,
                kernel=worker_kernel,
                workspace_root=seed_runner.workspace_root,
                state_root=seed_runner.state_root,
            )
            results.append(
                runner.run_once(
                    seed=0,
                    wake_index=wake_index,
                    time_bucket="2026-08-25",
                )
            )
        except BaseException as error:
            errors.append(error)

    with patch.object(WorkAutonomyRunner, "_choose", paused_choose):
        stale = Thread(target=run, args=("stale", 1), name="stale")
        stale.start()
        assert paused.wait(timeout=5)
        store.append_once(
            "sensor.team_sync.cursor.advanced",
            "source-advanced-during-selection",
            {"source_id": "project_changes", "offset": 99},
        )
        fresh = Thread(target=run, args=("fresh", 4), name="fresh")
        fresh.start()
        time.sleep(0.1)
        resume.set()
        stale.join(timeout=10)
        fresh.join(timeout=10)

    assert not stale.is_alive() and not fresh.is_alive()
    assert errors == []
    assert len(results) == 2
    assert len(store.events("autonomy.work.attempted")) == 1
    assert len(store.events("autonomy.action.receipt")) == 1
    assert len(list((seed_runner.workspace_root / "attempts").glob("*.json"))) == 1
    assert sum(bool(result["message"]) for result in results) == 1
    assert store.verify_chain()["valid"] is True


def test_pending_presentation_blocks_new_attempt_until_retry_succeeds(
    tmp_path: Path,
) -> None:
    store, runner = configured_runner(tmp_path)
    with patch.object(
        runner.proactive, "temporary_suppression", return_value=["DAILY_CAP"]
    ):
        first = runner.run_once(
            seed=0, wake_index=1, time_bucket="2026-08-25"
        )
        store.append_once(
            "sensor.team_sync.cursor.advanced",
            "new-source-while-presentation-pending",
            {"source_id": "project_changes", "offset": 101},
        )
        blocked = runner.run_once(
            seed=0, wake_index=4, time_bucket="2026-08-25"
        )

    delivered = runner.run_once(
        seed=0, wake_index=7, time_bucket="2026-08-25"
    )

    assert first["attempted"] is True and first["retryable"] is True
    assert blocked["attempted"] is True and blocked["retryable"] is True
    assert first["suggestion"]["suggestion_id"] == blocked["suggestion"][
        "suggestion_id"
    ]
    assert delivered["message"].startswith("Suggested work:")
    assert len(store.events("autonomy.work.suggested")) == 1
    assert len(store.events("autonomy.work.attempted")) == 1
    assert len(store.events("autonomy.action.receipt")) == 1
    assert len(store.events("autonomy.work.presentation.completed")) == 1
    assert store.verify_chain()["valid"] is True
