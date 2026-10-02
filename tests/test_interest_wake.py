from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import multiprocessing
from pathlib import Path
from threading import Lock
from typing import Any

import pytest

import cct_agent.interest_wake as interest_wake
from cct_agent.interest_wake import (
    InterestTaskExecutionReceipt,
    InterestTaskRegistration,
    InterestTaskWakeCoordinator,
    interest_task_wake_status,
)
from cct_agent.opportunity_handoff import OpportunityTaskHandoff
from cct_agent.store import EventStore
from tests.test_full_stack_episode import build_episode, research_server
from tests.test_opportunity_handoff import (
    SECRET,
    accepted_interest,
    interest_receipts,
    owner_for_interest,
)
from tests.test_self_generated_goal_episode import runtime_adapters


@dataclass
class RealFullStackExecutor:
    source: object
    store: EventStore
    workspace: Path
    deployment_sink: Path
    outbox: Path
    opportunity_id: str
    feedback_event_id: str
    calls: int = 0

    def execute(
        self, *, opportunity_id: str, feedback_event_id: str
    ) -> InterestTaskExecutionReceipt:
        assert opportunity_id == self.opportunity_id
        assert feedback_event_id == self.feedback_event_id
        self.calls += 1
        handoff = OpportunityTaskHandoff(self.store, principal_id="mike")
        interest = handoff.inspect_interest(
            opportunity_id=opportunity_id,
            feedback_event_id=feedback_event_id,
        )
        receipts = interest_receipts(
            opportunity_id=opportunity_id,
            interest_sha256=interest.digest,
        )
        owner = owner_for_interest(
            self.source,
            self.store,
            "receipt-opportunity",
        )
        preparation = handoff.prepare(
            owner,
            opportunity_id=opportunity_id,
            feedback_event_id=feedback_event_id,
            receipts=receipts,
            seed=0,
        )
        adapters = runtime_adapters(
            store=self.store,
            preparation=preparation.self_goal,
            source_runner=self.source,
            workspace=self.workspace,
            deployment_sink=self.deployment_sink,
            outbox=self.outbox,
        )
        result = handoff.run_prepared(
            owner,
            preparation,
            research=adapters[0],
            commands=adapters[1],
            patching=adapters[2],
            verifier=adapters[3],
            deployment=adapters[4],
            public_actions=adapters[5],
        )
        return InterestTaskExecutionReceipt(
            terminal_event_id=result.terminal_event_id,
            replayed=result.replayed,
        )


@dataclass
class SyntheticProcessExecutor:
    """Minimal host-owned terminal graph used only to probe process serialization."""

    store: EventStore
    count_path: Path

    def execute(
        self, *, opportunity_id: str, feedback_event_id: str
    ) -> InterestTaskExecutionReceipt:
        with self.count_path.open("ab") as stream:
            stream.write(b"effect\n")
            stream.flush()
        interest = OpportunityTaskHandoff(self.store, principal_id="mike").inspect_interest(
            opportunity_id=opportunity_id,
            feedback_event_id=feedback_event_id,
        )
        handoff, _ = self.store.append_once_result(
            "opportunity.initiative.task_handoff.prepared",
            feedback_event_id,
            {
                "schema_version": 1,
                "opportunity_id": opportunity_id,
                "feedback_event_id": feedback_event_id,
                "interest_binding_sha256": interest.digest,
                "execution_authority_source": "separate_host_policy_capability_lease",
                "external_effects": 0,
            },
        )
        episode, _ = self.store.append_once_result(
            "autonomy.self_goal.episode.terminal",
            feedback_event_id,
            {"schema_version": 1, "status": "completed", "external_effects": 0},
        )
        outcome, _ = self.store.append_once_result(
            "outcome.observed",
            "process-" + feedback_event_id,
            {"schema_version": 1, "realized_utility": 1.0},
        )
        reflection, _ = self.store.append_once_result(
            "reflection.proposed",
            "process-" + feedback_event_id,
            {"schema_version": 1, "requires_endorsement": True},
        )
        terminal, created = self.store.append_once_result(
            "opportunity.initiative.task_handoff.completed",
            feedback_event_id,
            {
                "schema_version": 1,
                "handoff_event_id": handoff.event_id,
                "opportunity_id": opportunity_id,
                "feedback_event_id": feedback_event_id,
                "interest_binding_sha256": interest.digest,
                "goal_id": "goal-process-race",
                "lease_id": "lease-process-race",
                "episode_terminal_event_id": episode.event_id,
                "outcome_event_id": outcome.event_id,
                "reflection_event_id": reflection.event_id,
                "status": "completed",
                "adapter_effects": 1,
                "interest_granted_execution_authority": False,
                "execution_authority_source": "separate_host_policy_capability_lease",
                "external_effects": 0,
                "raw_producer_content_persisted": False,
            },
        )
        return InterestTaskExecutionReceipt(
            terminal_event_id=terminal.event_id,
            replayed=not created,
        )


def _process_wake_worker(
    store_path: str,
    state_root: str,
    count_path: str,
    registration_id: str,
    opportunity_id: str,
    feedback_event_id: str,
    authority_receipt: Any,
    barrier: Any,
    queue: Any,
) -> None:
    store = EventStore(store_path)
    registration = InterestTaskRegistration(
        id=registration_id,
        opportunity_id=opportunity_id,
        feedback_event_id=feedback_event_id,
        authority_receipt=authority_receipt,
        executor=SyntheticProcessExecutor(store, Path(count_path)),
    )
    barrier.wait()
    try:
        result = coordinator(
            store,
            Path(state_root),
            registration,
        ).run_once()
        queue.put(("ok", result["status"], result["executed"]))
    except BaseException as error:  # pragma: no cover - returned for parent diagnosis.
        queue.put(("error", type(error).__name__, str(error)))


def configured(tmp_path: Path, base_url: str):
    source, store, _planner, workspace, sink, outbox = build_episode(
        tmp_path,
        base_url,
        verifier_passes=True,
    )
    opportunity_id, feedback_event_id = accepted_interest(source, store, tmp_path)
    interest = OpportunityTaskHandoff(store, principal_id="mike").inspect_interest(
        opportunity_id=opportunity_id,
        feedback_event_id=feedback_event_id,
    )
    authority_receipt = interest_receipts(
        opportunity_id=opportunity_id,
        interest_sha256=interest.digest,
    )[-1]
    executor = RealFullStackExecutor(
        source=source,
        store=store,
        workspace=workspace,
        deployment_sink=sink,
        outbox=outbox,
        opportunity_id=opportunity_id,
        feedback_event_id=feedback_event_id,
    )
    registration = InterestTaskRegistration(
        id="registered-accepted-local-task",
        opportunity_id=opportunity_id,
        feedback_event_id=feedback_event_id,
        authority_receipt=authority_receipt,
        executor=executor,
    )
    return source, store, executor, registration


def coordinator(
    store: EventStore,
    state_root: Path,
    *registrations: InterestTaskRegistration,
) -> InterestTaskWakeCoordinator:
    return InterestTaskWakeCoordinator(
        store,
        principal_id="mike",
        state_root=state_root,
        authentication_secret=SECRET,
        registrations=registrations,
    )


def test_accepted_interest_wake_executes_real_plan_and_restart_adopts_after_effect(
    tmp_path: Path,
) -> None:
    with research_server() as base_url:
        _source, store, executor, registration = configured(tmp_path, base_url)
        state_root = tmp_path / "wake-state"

        def crash(boundary: str) -> None:
            if boundary == "after-execution":
                raise SystemExit("crash-after-interest-task-execution")

        with pytest.raises(SystemExit, match="crash-after-interest-task-execution"):
            coordinator(store, state_root, registration).run_once(fault_hook=crash)

        assert executor.calls == 1
        assert len(store.events("opportunity.initiative.task_handoff.completed")) == 1
        assert not store.events("opportunity.initiative.task_wake.completed")

        resumed = coordinator(
            EventStore(store.path),
            state_root,
            registration,
        ).run_once()
        duplicate = coordinator(
            EventStore(store.path),
            state_root,
            registration,
        ).run_once()

    assert resumed["status"] == "verified-completed"
    assert resumed["executed"] is False
    assert resumed["replayed"] is True
    assert duplicate == {
        "status": "no-pending-registered-interest",
        "executed": False,
        "replayed": True,
        "emit": False,
        "external_effects": 0,
    }
    assert executor.calls == 1
    assert len(store.events("opportunity.initiative.task_wake.claimed")) == 1
    assert len(store.events("opportunity.initiative.task_wake.completed")) == 1
    assert len(store.events("deployment.local_fake.completed")) == 1
    assert len(store.events("public_action.fake_sink.completed")) == 1
    assert store.verify_chain()["valid"] is True


def test_concurrent_same_interest_runs_one_real_executor_and_one_terminal(
    tmp_path: Path,
) -> None:
    with research_server() as base_url:
        _source, store, executor, registration = configured(tmp_path, base_url)
        state_root = tmp_path / "wake-state"
        counter_lock = Lock()
        original = executor.execute

        def counted(**kwargs):
            with counter_lock:
                return original(**kwargs)

        executor.execute = counted  # type: ignore[method-assign]

        def run(_: int):
            return coordinator(
                EventStore(store.path),
                state_root,
                registration,
            ).run_once()

        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(run, range(6)))

    assert executor.calls == 1
    assert sum(row["executed"] is True for row in results) == 1
    assert len(store.events("opportunity.initiative.task_wake.claimed")) == 1
    assert len(store.events("opportunity.initiative.task_wake.completed")) == 1
    assert len(store.events("opportunity.initiative.task_handoff.completed")) == 1
    assert len(store.events("command.execution.completed")) == 2  # build + verifier
    assert store.verify_chain()["valid"] is True


def test_synchronized_process_wakes_execute_registered_host_effect_once(
    tmp_path: Path,
) -> None:
    with research_server() as base_url:
        _source, store, _executor, registration = configured(tmp_path, base_url)
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(6)
        queue = context.Queue()
        count_path = tmp_path / "process-effect-count.txt"
        workers = [
            context.Process(
                target=_process_wake_worker,
                args=(
                    str(store.path),
                    str(tmp_path / "process-wake-state"),
                    str(count_path),
                    registration.id,
                    registration.opportunity_id,
                    registration.feedback_event_id,
                    registration.authority_receipt,
                    barrier,
                    queue,
                ),
            )
            for _ in range(6)
        ]
        for worker in workers:
            worker.start()
        results = [queue.get(timeout=30) for _ in workers]
        for worker in workers:
            worker.join(timeout=30)

    assert all(worker.exitcode == 0 for worker in workers)
    assert all(row[0] == "ok" for row in results), results
    assert sum(row[2] is True for row in results) == 1
    assert count_path.read_bytes() == b"effect\n"
    assert len(store.events("opportunity.initiative.task_wake.claimed")) == 1
    assert len(store.events("opportunity.initiative.task_wake.completed")) == 1
    assert len(store.events("opportunity.initiative.task_handoff.completed")) == 1
    assert store.verify_chain()["valid"] is True


def test_invalid_oldest_interest_is_rejected_without_starving_valid_registration(
    tmp_path: Path,
) -> None:
    with research_server() as base_url:
        source, store, _planner, workspace, sink, outbox = build_episode(
            tmp_path,
            base_url,
            verifier_passes=True,
        )
        invalid, _ = store.append_once_result(
            "opportunity.initiative.feedback",
            "invalid-oldest-feedback",
            {
                "schema_version": 1,
                "feedback_id": "invalid-oldest-feedback",
                "opportunity_id": "missing-opportunity",
                "principal_id": "mike",
                "principal_profile_digest": "a" * 64,
                "presentation_event_id": "missing-presentation-event",
                "decision": "INTERESTED",
                "snooze_until": None,
                "evidence": ["operator:invalid-oldest-feedback"],
                "source_authority": "operator",
                "operator_interest_recorded": True,
                "task_outcome_recorded": False,
                "task_outcome": None,
                "execution_authority_granted": False,
                "capability_lease_changed": False,
                "opportunity_execution_status_changed": False,
                "external_effects": 0,
            },
        )
        opportunity_id, feedback_event_id = accepted_interest(source, store, tmp_path)
        valid_interest = OpportunityTaskHandoff(store, principal_id="mike").inspect_interest(
            opportunity_id=opportunity_id,
            feedback_event_id=feedback_event_id,
        )
        invalid_authority = interest_receipts(
            opportunity_id="missing-opportunity",
            interest_sha256="f" * 64,
        )[-1]
        valid_authority = interest_receipts(
            opportunity_id=opportunity_id,
            interest_sha256=valid_interest.digest,
        )[-1]
        executor = RealFullStackExecutor(
            source=source,
            store=store,
            workspace=workspace,
            deployment_sink=sink,
            outbox=outbox,
            opportunity_id=opportunity_id,
            feedback_event_id=feedback_event_id,
        )
        invalid_registration = InterestTaskRegistration(
            id="registered-invalid-oldest",
            opportunity_id="missing-opportunity",
            feedback_event_id=invalid.event_id,
            authority_receipt=invalid_authority,
            executor=executor,
        )
        valid_registration = InterestTaskRegistration(
            id="registered-valid-after-invalid",
            opportunity_id=opportunity_id,
            feedback_event_id=feedback_event_id,
            authority_receipt=valid_authority,
            executor=executor,
        )
        store.append(
            "opportunity.initiative.task_handoff.completed",
            {
                "schema_version": 1,
                "opportunity_id": "missing-opportunity",
                "feedback_event_id": invalid.event_id,
                "status": "completed",
                "external_effects": 0,
            },
        )

        result = coordinator(
            store,
            tmp_path / "wake-state",
            invalid_registration,
            valid_registration,
        ).run_once()

    assert result["status"] == "verified-completed"
    assert result["executed"] is True
    rejected = store.events("opportunity.initiative.task_wake.rejected")
    assert len(rejected) == 1
    assert rejected[0].payload["reason_code"] == "INTEREST_TASK_TERMINAL_INVALID"
    assert len(store.events("opportunity.initiative.task_wake.completed")) == 1
    assert store.verify_chain()["valid"] is True


def test_status_is_content_free_and_reports_pending_registered_wake(tmp_path: Path) -> None:
    with research_server() as base_url:
        _source, store, _executor, registration = configured(tmp_path, base_url)
        status = interest_task_wake_status(store)

    assert status == {
        "accepted_interests": 1,
        "claims": 0,
        "completed": 0,
        "rejected": 0,
        "unresolved_accepted_interests": 1,
        "registered_executor_count_available": False,
        "latest": None,
        "content_in_status": False,
        "producer_text_persisted": False,
        "external_effects": 0,
    }
    assert registration.feedback_event_id not in str(status)


def test_signed_host_interest_receipt_and_one_canonical_state_root_are_required(
    tmp_path: Path,
) -> None:
    with research_server() as base_url:
        _source, store, executor, registration = configured(tmp_path, base_url)
        wrong = InterestTaskRegistration(
            id="wrong-host-binding",
            opportunity_id=registration.opportunity_id,
            feedback_event_id=registration.feedback_event_id,
            authority_receipt=interest_receipts(
                opportunity_id=registration.opportunity_id,
                interest_sha256="f" * 64,
            )[-1],
            executor=executor,
        )
        wrong_signature = InterestTaskRegistration(
            id="wrong-host-signature",
            opportunity_id=registration.opportunity_id,
            feedback_event_id=registration.feedback_event_id,
            authority_receipt=type(registration.authority_receipt).sign(
                receipt_id="wrong-signature-opportunity",
                kind="opportunity",
                subject_id=registration.opportunity_id,
                content_sha256=registration.authority_receipt.content_sha256,
                issued_by="host_adapter",
                semantic_taint=False,
                secret=b"different-interest-authentication-key",
            ),
            executor=executor,
        )
        for invalid in (wrong, wrong_signature):
            with pytest.raises(Exception, match="HOST_INTEREST_BINDING_REQUIRED"):
                coordinator(store, tmp_path / "canonical-wake", invalid).run_once()

        canonical = coordinator(store, tmp_path / "canonical-wake", registration)
        with pytest.raises(Exception, match="INTEREST_WAKE_STATE_ROOT_MISMATCH"):
            coordinator(store, tmp_path / "split-wake", registration)
        with pytest.raises(Exception, match="INTEREST_WAKE_STATE_ROOT_MISMATCH"):
            coordinator(
                EventStore(tmp_path / "second-ledger.sqlite"),
                tmp_path / "canonical-wake",
                registration,
            )

        result = canonical.run_once()

    assert result["executed"] is True
    assert executor.calls == 1
    assert len(
        store.events("opportunity.initiative.task_wake.configuration.installed")
    ) == 1


def test_configuration_short_write_completes_and_global_database_binding_is_unique(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = EventStore(tmp_path / "configuration.sqlite")
    state_root = tmp_path / "configuration-wake"
    original_write = interest_wake.os.write
    calls = 0

    def short_once(descriptor: int, data: bytes) -> int:
        nonlocal calls
        calls += 1
        if calls == 1 and len(data) > 2:
            return original_write(descriptor, data[: len(data) // 2])
        return original_write(descriptor, data)

    monkeypatch.setattr(interest_wake.os, "write", short_once)
    InterestTaskWakeCoordinator(
        store,
        principal_id="mike",
        state_root=state_root,
        authentication_secret=SECRET,
        registrations=(),
    )
    first_bytes = (state_root / "configuration.json").read_bytes()
    assert first_bytes.endswith(b"\n")
    assert calls >= 2

    InterestTaskWakeCoordinator(
        store,
        principal_id="mike",
        state_root=state_root,
        authentication_secret=SECRET,
        registrations=(),
    )
    with pytest.raises(Exception, match="INTEREST_WAKE_STATE_ROOT_MISMATCH"):
        InterestTaskWakeCoordinator(
            store,
            principal_id="other",
            state_root=tmp_path / "other-principal-wake",
            authentication_secret=SECRET,
            registrations=(),
        )

    assert (state_root / "configuration.json").read_bytes() == first_bytes
    assert len(
        store.events("opportunity.initiative.task_wake.configuration.installed")
    ) == 1
