"""Crash-resumable full-stack autonomy episodes over registered local adapters."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Callable, Literal

from .commands import (
    BoundedCommandAdapter,
    CommandDenied,
    CommandRequest,
)
from .deployment import (
    DeploymentDenied,
    DeploymentRequest,
    LocalFakeDeploymentAdapter,
)
from .kernel import AgencyKernel
from .patching import ExpectedHashPatchAdapter, PatchDenied, PatchRequest
from .planning import (
    AutonomyPlanner,
    PlanBinding,
    PlanningDenied,
    WorkerAdvanceRequest,
    WorkerClaimRequest,
)
from .public_actions import (
    FakePublicActionRequest,
    LocalFakePublicActionAdapter,
    PublicActionDenied,
)
from .research import (
    BoundedResearchAdapter,
    ResearchDenied,
    ResearchRequest,
)
from .store import Event, EventStore, canonical_json
from .verification import (
    HostRegisteredVerifier,
    VerificationDenied,
    VerificationRequest,
)


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
EpisodeStatus = Literal["completed", "failed"]
FaultHook = Callable[[str, str], None]


class FullStackEpisodeDenied(RuntimeError):
    """Fail-closed episode admission or integrity failure."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be a bounded identifier")
    return value


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _store_path(store: EventStore) -> Path:
    return Path(store.path).resolve()


@dataclass(frozen=True, slots=True)
class FullStackEpisodeConfig:
    """Private exact requests and host registration IDs for one six-capability chain."""

    research_stage_id: str
    research_request: ResearchRequest
    command_stage_id: str
    command_request: CommandRequest
    patch_stage_id: str
    patch_request: PatchRequest
    verification_stage_id: str
    verifier_id: str
    verification_request_id: str
    deployment_stage_id: str
    deployment_target_id: str
    deployment_request_id: str
    public_action_stage_id: str
    public_action_id: str
    public_action_request_id: str

    def __post_init__(self) -> None:
        for field in (
            "research_stage_id",
            "command_stage_id",
            "patch_stage_id",
            "verification_stage_id",
            "verifier_id",
            "verification_request_id",
            "deployment_stage_id",
            "deployment_target_id",
            "deployment_request_id",
            "public_action_stage_id",
            "public_action_id",
            "public_action_request_id",
        ):
            object.__setattr__(self, field, _identifier(field, getattr(self, field)))
        if not isinstance(self.research_request, ResearchRequest):
            raise ValueError("research_request must be a ResearchRequest")
        if not isinstance(self.command_request, CommandRequest):
            raise ValueError("command_request must be a CommandRequest")
        if not isinstance(self.patch_request, PatchRequest):
            raise ValueError("patch_request must be a PatchRequest")
        if len(self.stage_ids) != len(set(self.stage_ids)):
            raise ValueError("full-stack stage IDs must be unique")
        request_ids = (
            self.research_request.id,
            self.command_request.id,
            self.patch_request.id,
            self.verification_request_id,
            self.deployment_request_id,
            self.public_action_request_id,
        )
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("full-stack request IDs must be unique")

    @property
    def stage_ids(self) -> tuple[str, ...]:
        return (
            self.research_stage_id,
            self.command_stage_id,
            self.patch_stage_id,
            self.verification_stage_id,
            self.deployment_stage_id,
            self.public_action_stage_id,
        )

    def _capability(self, stage_id: str) -> str:
        by_stage = dict(
            zip(
                self.stage_ids,
                ("research", "command", "patch", "verification", "deployment", "public_action"),
                strict=True,
            )
        )
        try:
            return by_stage[stage_id]
        except KeyError as error:
            raise KeyError(f"unknown full-stack stage: {stage_id}") from error

    def tool_name(self, stage_id: str) -> str:
        return {
            "research": "cct_research_fetch",
            "command": "cct_command_execute",
            "patch": "cct_patch_apply",
            "verification": "cct_verifier_execute",
            "deployment": "cct_local_fake_deploy",
            "public_action": "cct_fake_public_action",
        }[self._capability(stage_id)]

    def argument_payload(self, stage_id: str) -> dict[str, object]:
        capability = self._capability(stage_id)
        if capability == "research":
            return {
                "request_id": self.research_request.id,
                "source_id": self.research_request.source_id,
                "path": self.research_request.path,
            }
        if capability == "command":
            return {
                "request_id": self.command_request.id,
                "command_id": self.command_request.command_id,
            }
        if capability == "patch":
            return {
                "request_id": self.patch_request.id,
                "target_id": self.patch_request.target_id,
                "expected_before_sha256": self.patch_request.expected_before_sha256,
                "replacement_sha256": sha256(self.patch_request.replacement).hexdigest(),
                "replacement_byte_count": len(self.patch_request.replacement),
            }
        if capability == "verification":
            return {
                "request_id": self.verification_request_id,
                "verifier_id": self.verifier_id,
            }
        if capability == "deployment":
            return {
                "request_id": self.deployment_request_id,
                "target_id": self.deployment_target_id,
                "verification_request_id": self.verification_request_id,
            }
        return {
            "request_id": self.public_action_request_id,
            "action_id": self.public_action_id,
            "deployment_request_id": self.deployment_request_id,
        }

    def arguments_sha256(self, stage_id: str) -> str:
        return _digest(self.argument_payload(stage_id))

    @property
    def digest(self) -> str:
        return _digest(
            [
                {
                    "stage_id": stage_id,
                    "tool_name": self.tool_name(stage_id),
                    "arguments_sha256": self.arguments_sha256(stage_id),
                }
                for stage_id in self.stage_ids
            ]
        )


@dataclass(frozen=True, slots=True)
class FullStackEpisodeSpec:
    """One plan-bound worker episode; configuration itself grants no new authority."""

    id: str
    binding: PlanBinding
    worker_id: str
    config: FullStackEpisodeConfig

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _identifier("episode id", self.id))
        object.__setattr__(self, "worker_id", _identifier("worker id", self.worker_id))
        if not isinstance(self.binding, PlanBinding):
            raise ValueError("binding must be a PlanBinding")
        if not isinstance(self.config, FullStackEpisodeConfig):
            raise ValueError("config must be a FullStackEpisodeConfig")


@dataclass(frozen=True, slots=True)
class FullStackEpisodeResult:
    """Bounded terminal receipt linking planner, adapters, outcome, and reflection."""

    episode_id: str
    status: EpisodeStatus
    goal_id: str
    plan_id: str
    decision_id: str
    completed_stage_ids: tuple[str, ...]
    stage_claim_event_ids: tuple[tuple[str, str], ...]
    stage_receipt_event_ids: tuple[tuple[str, str], ...]
    outcome_event_id: str
    reflection_event_id: str
    goal_status_event_id: str
    terminal_event_id: str
    failure_stage_id: str | None
    reason_code: str
    rollback_event_id: str | None
    later_effects_blocked: bool
    replayed: bool


@dataclass(frozen=True, slots=True)
class _StageResult:
    stage_id: str
    receipt_event_id: str
    evidence_sha256: str
    succeeded: bool
    reason_code: str

    def outcome_sha256(self) -> str:
        return _digest(
            {
                "stage_id": self.stage_id,
                "receipt_event_id": self.receipt_event_id,
                "evidence_sha256": self.evidence_sha256,
                "succeeded": self.succeeded,
                "reason_code": self.reason_code,
            }
        )


class FullStackEpisodeRunner:
    """Drive one approved plan through registered adapters and resume claimed stages."""

    _TERMINAL_KINDS = (
        "autonomy.episode.completed",
        "autonomy.episode.failed",
    )

    def __init__(
        self,
        store: EventStore,
        *,
        kernel: AgencyKernel,
        planner: AutonomyPlanner,
        research: BoundedResearchAdapter,
        commands: BoundedCommandAdapter,
        patching: ExpectedHashPatchAdapter,
        verifier: HostRegisteredVerifier,
        deployment: LocalFakeDeploymentAdapter,
        public_actions: LocalFakePublicActionAdapter,
        spec: FullStackEpisodeSpec,
        claim_fault_hook: FaultHook | None = None,
        fault_hook: FaultHook | None = None,
    ) -> None:
        if not isinstance(store, EventStore):
            raise ValueError("store must be an EventStore")
        if not isinstance(kernel, AgencyKernel) or not isinstance(planner, AutonomyPlanner):
            raise ValueError("kernel and planner must be CCT governance objects")
        if not isinstance(spec, FullStackEpisodeSpec):
            raise ValueError("spec must be a FullStackEpisodeSpec")
        if claim_fault_hook is not None and not callable(claim_fault_hook):
            raise ValueError("claim_fault_hook must be callable")
        if fault_hook is not None and not callable(fault_hook):
            raise ValueError("fault_hook must be callable")
        components = (
            kernel,
            planner,
            research,
            commands,
            patching,
            verifier,
            deployment,
            public_actions,
        )
        if any(
            not hasattr(component, "store")
            or _store_path(component.store) != _store_path(store)
            for component in components
        ):
            raise ValueError("all full-stack components must share one event store")
        self.store = store
        self.kernel = kernel
        self.planner = planner
        self.research = research
        self.commands = commands
        self.patching = patching
        self.verifier = verifier
        self.deployment = deployment
        self.public_actions = public_actions
        self.spec = spec
        self.claim_fault_hook = claim_fault_hook
        self.fault_hook = fault_hook
        self._validate_registration()

    def _validate_registration(self) -> None:
        config = self.spec.config
        if config.command_request.command_id not in self.commands.registered_ids:
            raise ValueError("episode command is not host registered")
        if config.patch_request.target_id not in self.patching.registered_target_ids:
            raise ValueError("episode patch target is not host registered")
        if config.verifier_id not in self.verifier.registered_ids:
            raise ValueError("episode verifier is not host registered")
        if config.deployment_target_id not in self.deployment.registered_target_ids:
            raise ValueError("episode deployment target is not host registered")
        if config.public_action_id not in self.public_actions.registered_action_ids:
            raise ValueError("episode public action is not host registered")
        plan_events = [
            event
            for event in self.store.events("autonomy.plan.stored")
            if event.payload.get("plan_id") == self.spec.binding.plan_id
        ]
        if len(plan_events) != 1:
            raise ValueError("episode requires one exact stored plan")
        plan = plan_events[0].payload
        if (
            plan.get("goal_id") != self.spec.binding.goal_id
            or plan.get("decision_id") != self.spec.binding.decision_id
            or plan.get("plan_sha256") != self.spec.binding.plan_sha256
            or plan.get("atomic_stage_ids") != list(config.stage_ids)
        ):
            raise ValueError("episode configuration does not match stored plan")

    def _terminal_event(self) -> Event | None:
        rows = [
            event
            for kind in self._TERMINAL_KINDS
            for event in self.store.events(kind)
            if event.payload.get("episode_id") == self.spec.id
        ]
        if len(rows) > 1:
            raise FullStackEpisodeDenied("EPISODE_TERMINAL_CONFLICT")
        return rows[0] if rows else None

    def _start(self) -> None:
        payload = {
            "schema_version": "cct.autonomy.full-stack-episode.start.v1",
            "episode_id": self.spec.id,
            "goal_id": self.spec.binding.goal_id,
            "plan_id": self.spec.binding.plan_id,
            "decision_id": self.spec.binding.decision_id,
            "plan_sha256": self.spec.binding.plan_sha256,
            "worker_id": self.spec.worker_id,
            "stage_ids": list(self.spec.config.stage_ids),
            "configuration_sha256": self.spec.config.digest,
            "configuration_content_persisted": False,
            "execution_authority_granted": False,
        }
        try:
            event, _ = self.store.append_once_result(
                "autonomy.episode.started",
                self.spec.id,
                payload,
            )
        except ValueError as error:
            raise FullStackEpisodeDenied("EPISODE_START_CONFLICT") from error
        if canonical_json(event.payload) != canonical_json(payload):
            raise FullStackEpisodeDenied("EPISODE_START_CONFLICT")

    def run(self) -> FullStackEpisodeResult:
        if self.store.verify_chain().get("valid") is not True:
            raise FullStackEpisodeDenied("LEDGER_CHAIN_INVALID")
        terminal = self._terminal_event()
        if terminal is not None:
            self._validate_terminal_effects(terminal)
            return self._result_from_event(terminal, replayed=True)
        self._start()

        while True:
            cursor = self.planner.cursor(self.spec.binding.plan_id)
            if cursor["state"] == "COMPLETE":
                return self._finalize_success(tuple(cursor["completed_stage_ids"]))
            claim = self._claim(cursor)
            stage_id = str(claim["stage_id"])
            if self.claim_fault_hook is not None:
                self.claim_fault_hook(stage_id, str(claim["event_id"]))
            stage = self._execute_stage(stage_id)
            if self.fault_hook is not None:
                self.fault_hook(stage_id, stage.receipt_event_id)
            if not stage.succeeded:
                return self._finalize_failure(stage)
            attempt = claim.get("attempt")
            claim_event_id = claim.get("event_id")
            claim_revision = claim.get("cursor_revision")
            if (
                isinstance(attempt, bool)
                or not isinstance(attempt, int)
                or not isinstance(claim_event_id, str)
                or isinstance(claim_revision, bool)
                or not isinstance(claim_revision, int)
            ):
                raise FullStackEpisodeDenied("CURSOR_STATE_INVALID")
            advanced = self.planner.advance_stage(
                WorkerAdvanceRequest(
                    binding=self.spec.binding,
                    worker_id=self.spec.worker_id,
                    stage_id=stage_id,
                    attempt=attempt,
                    claim_event_id=claim_event_id,
                    expected_revision=claim_revision,
                    outcome_sha256=stage.outcome_sha256(),
                )
            )
            if advanced["stage_id"] != stage_id:
                raise FullStackEpisodeDenied("STAGE_ADVANCE_MISMATCH")

    def _claim(self, cursor: dict[str, object]) -> dict[str, object]:
        state = cursor.get("state")
        revision = cursor.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int):
            raise FullStackEpisodeDenied("CURSOR_STATE_INVALID")
        if state == "READY":
            expected_revision = revision
        elif state == "CLAIMED":
            claimed = cursor.get("claimed")
            if not isinstance(claimed, dict) or claimed.get("worker_id") != self.spec.worker_id:
                raise FullStackEpisodeDenied("EPISODE_WORKER_CONFLICT")
            expected_revision = revision - 1
        else:
            raise FullStackEpisodeDenied("CURSOR_STATE_INVALID")
        try:
            claim = self.planner.claim_stage(
                WorkerClaimRequest(
                    binding=self.spec.binding,
                    worker_id=self.spec.worker_id,
                    expected_revision=expected_revision,
                )
            )
        except PlanningDenied as error:
            raise FullStackEpisodeDenied(error.reason_code) from error
        stage_id = str(claim["stage_id"])
        if stage_id not in self.spec.config.stage_ids:
            raise FullStackEpisodeDenied("UNEXPECTED_PLAN_STAGE")
        ticket = claim.get("execution_ticket_binding")
        if not isinstance(ticket, dict) or (
            ticket.get("goal_id") != self.spec.binding.goal_id
            or ticket.get("plan_id") != self.spec.binding.plan_id
            or ticket.get("plan_hash") != self.spec.binding.plan_sha256
            or ticket.get("stage") != stage_id
            or ticket.get("tool_name") != self.spec.config.tool_name(stage_id)
            or ticket.get("arguments_sha256")
            != self.spec.config.arguments_sha256(stage_id)
        ):
            raise FullStackEpisodeDenied("STAGE_HANDOFF_MISMATCH")
        return claim

    def _execute_stage(self, stage_id: str) -> _StageResult:
        config = self.spec.config
        try:
            if stage_id == config.research_stage_id:
                result = self.research.fetch(config.research_request)
                return _StageResult(
                    stage_id,
                    result.receipt_event_id,
                    result.content_sha256,
                    True,
                    "RESEARCH_OBSERVED",
                )
            if stage_id == config.command_stage_id:
                result = self.commands.execute(config.command_request)
                succeeded = result.termination_reason == "exited" and result.exit_status == 0
                reason = (
                    "COMMAND_COMPLETED"
                    if succeeded
                    else (
                        "COMMAND_EXIT_NONZERO"
                        if result.termination_reason == "exited"
                        else f"COMMAND_{result.termination_reason.upper()}"
                    )
                )
                return _StageResult(
                    stage_id,
                    result.receipt_event_id,
                    _digest(
                        {
                            "argv_sha256": result.argv_sha256,
                            "exit_status": result.exit_status,
                            "termination_reason": result.termination_reason,
                            "stdout_sha256": result.stdout_sha256,
                            "stderr_sha256": result.stderr_sha256,
                        }
                    ),
                    succeeded,
                    reason,
                )
            if stage_id == config.patch_stage_id:
                result = self.patching.apply(config.patch_request)
                return _StageResult(
                    stage_id,
                    result.terminal_event_id,
                    result.current_sha256,
                    result.stage_eligible,
                    result.verification_code,
                )
            if stage_id == config.verification_stage_id:
                snapshot = self.verifier.snapshot(config.verifier_id)
                result = self.verifier.execute(
                    VerificationRequest(
                        id=config.verification_request_id,
                        verifier_id=config.verifier_id,
                        plan_id=self.spec.binding.plan_id,
                        plan_sha256=self.spec.binding.plan_sha256,
                        stage_id=config.verification_stage_id,
                        expected_snapshot_sha256=snapshot.sha256,
                    )
                )
                return _StageResult(
                    stage_id,
                    result.terminal_event_id,
                    result.snapshot_after_sha256,
                    result.status == "passed",
                    result.reason_code,
                )
            if stage_id == config.deployment_stage_id:
                preview = self.deployment.preview(
                    target_id=config.deployment_target_id,
                    verification_request_id=config.verification_request_id,
                )
                result = self.deployment.deploy(
                    DeploymentRequest(
                        id=config.deployment_request_id,
                        target_id=preview.target_id,
                        verification_request_id=preview.verification_request_id,
                        expected_verification_event_id=preview.verification_event_id,
                        expected_snapshot_sha256=preview.snapshot_sha256,
                        expected_artifact_sha256=preview.artifact_sha256,
                        expected_manifest_sha256=preview.manifest_sha256,
                    )
                )
                return _StageResult(
                    stage_id,
                    result.terminal_event_id,
                    result.sink_readback_sha256,
                    result.sink_readback_verified,
                    "LOCAL_FAKE_DEPLOYED",
                )
            if stage_id == config.public_action_stage_id:
                preview = self.public_actions.preview(
                    action_id=config.public_action_id,
                    deployment_request_id=config.deployment_request_id,
                )
                result = self.public_actions.execute(
                    FakePublicActionRequest(
                        id=config.public_action_request_id,
                        action_id=preview.action_id,
                        deployment_request_id=preview.deployment_request_id,
                        expected_deployment_event_id=preview.deployment_event_id,
                        expected_sink_readback_sha256=preview.sink_readback_sha256,
                        expected_envelope_sha256=preview.envelope_sha256,
                        expected_preview_sha256=preview.preview_sha256,
                    )
                )
                return _StageResult(
                    stage_id,
                    result.terminal_event_id,
                    result.outbox_readback_sha256,
                    result.outbox_readback_verified,
                    "FAKE_PUBLIC_ACTION_SENT",
                )
        except (
            ResearchDenied,
            CommandDenied,
            PatchDenied,
            VerificationDenied,
            DeploymentDenied,
            PublicActionDenied,
        ) as error:
            receipt = self._latest_stage_receipt(stage_id)
            return _StageResult(
                stage_id,
                receipt.event_id if receipt is not None else self._active_claim_event_id(),
                "0" * 64,
                False,
                error.reason_code,
            )
        raise FullStackEpisodeDenied("UNEXPECTED_PLAN_STAGE")

    def _active_claim_event_id(self) -> str:
        cursor = self.planner.cursor(self.spec.binding.plan_id)
        claimed = cursor.get("claimed")
        if not isinstance(claimed, dict):
            raise FullStackEpisodeDenied("CURSOR_STATE_INVALID")
        event_id = claimed.get("claim_event_id")
        if not isinstance(event_id, str) or not _IDENTIFIER.fullmatch(event_id):
            raise FullStackEpisodeDenied("CURSOR_STATE_INVALID")
        return event_id

    def _event_matches_stage(self, event: Event, stage_id: str) -> bool:
        config = self.spec.config
        request_by_stage = {
            config.research_stage_id: config.research_request.id,
            config.command_stage_id: config.command_request.id,
            config.patch_stage_id: config.patch_request.id,
            config.verification_stage_id: config.verification_request_id,
            config.deployment_stage_id: config.deployment_request_id,
            config.public_action_stage_id: config.public_action_request_id,
        }
        terminal_kinds = {
            config.research_stage_id: {"research.observation.recorded"},
            config.command_stage_id: {"command.execution.completed"},
            config.patch_stage_id: {
                "patch.operation.verified",
                "patch.rollback.completed",
                "patch.rollback.blocked",
            },
            config.verification_stage_id: {"verification.run.completed"},
            config.deployment_stage_id: {"deployment.local_fake.completed"},
            config.public_action_stage_id: {"public_action.fake_sink.completed"},
        }
        return (
            event.kind in terminal_kinds[stage_id]
            and event.payload.get("request_id") == request_by_stage[stage_id]
        )

    def _latest_stage_receipt(self, stage_id: str) -> Event | None:
        rows = [
            event for event in self.store.events() if self._event_matches_stage(event, stage_id)
        ]
        return rows[-1] if rows else None

    def _collect_receipts(
        self,
        *,
        required_stage_ids: tuple[str, ...],
    ) -> tuple[tuple[str, str], ...]:
        rows: list[tuple[str, str]] = []
        for stage_id in self.spec.config.stage_ids:
            event = self._latest_stage_receipt(stage_id)
            if event is None:
                if stage_id in required_stage_ids:
                    raise FullStackEpisodeDenied("STAGE_RECEIPT_MISSING")
                continue
            rows.append((stage_id, event.event_id))
        return tuple(rows)

    def _collect_claims(
        self,
        *,
        required_stage_ids: tuple[str, ...],
    ) -> tuple[tuple[str, str], ...]:
        rows: list[tuple[str, str]] = []
        events = [
            event
            for event in self.store.events("autonomy.plan.stage.claimed")
            if event.payload.get("plan_id") == self.spec.binding.plan_id
        ]
        for stage_id in self.spec.config.stage_ids:
            matches = [
                event for event in events if event.payload.get("stage_id") == stage_id
            ]
            if len(matches) > 1:
                raise FullStackEpisodeDenied("STAGE_CLAIM_CONFLICT")
            if not matches:
                if stage_id in required_stage_ids:
                    raise FullStackEpisodeDenied("STAGE_CLAIM_MISSING")
                continue
            rows.append((stage_id, matches[0].event_id))
        return tuple(rows)

    def _rollback_if_needed(self, failure: _StageResult) -> str | None:
        config = self.spec.config
        if failure.stage_id == config.patch_stage_id:
            event = self._latest_stage_receipt(config.patch_stage_id)
            if event is not None and event.kind.startswith("patch.rollback."):
                return event.event_id
        verified = [
            event
            for event in self.store.events("patch.operation.verified")
            if event.payload.get("request_id") == config.patch_request.id
        ]
        if not verified:
            return None
        try:
            return self.patching.rollback(config.patch_request.id).terminal_event_id
        except PatchDenied as error:
            raise FullStackEpisodeDenied(error.reason_code) from error

    def _outcome(
        self,
        *,
        status: EpisodeStatus,
        evidence_event_ids: tuple[str, ...],
    ) -> Event:
        if status == "completed":
            utility = 1.0
            observation = (
                "Full-stack episode completed with verified local fake deployment "
                "and fake public-action receipts."
            )
        else:
            utility = -1.0
            observation = (
                "Full-stack episode failed closed; reversible patch rollback and "
                "later-effect gating were observed."
            )
        return self.kernel.record_outcome(
            decision_id=self.spec.binding.decision_id,
            realized_utility=utility,
            observation=observation,
            evidence=evidence_event_ids,
        )

    def _reflection(self, outcome_event_id: str) -> Event:
        rows = [
            event
            for event in self.store.events("reflection.proposed")
            if outcome_event_id in event.payload.get("evidence_event_ids", [])
        ]
        if len(rows) > 1:
            raise FullStackEpisodeDenied("REFLECTION_CONFLICT")
        if rows:
            return rows[0]
        reflected = self.kernel.reflect()
        event = self.store.event(str(reflected["event_id"]))
        if event is None:
            raise FullStackEpisodeDenied("REFLECTION_RECEIPT_MISSING")
        return event

    def _goal_status(self, status: EpisodeStatus) -> Event:
        target = "completed" if status == "completed" else "paused"
        current = self.kernel.goal(self.spec.binding.goal_id)
        if current is None:
            raise FullStackEpisodeDenied("GOAL_NOT_FOUND")
        if current.status != target:
            self.kernel.set_goal_status(
                self.spec.binding.goal_id,
                target,
                (
                    "Verified full-stack episode completed."
                    if status == "completed"
                    else "Episode failed closed; operator-approved goal paused for review or replanning."
                ),
            )
        rows = [
            event
            for event in self.store.events("goal.status_changed")
            if event.payload.get("goal_id") == self.spec.binding.goal_id
            and event.payload.get("to") == target
        ]
        if not rows:
            raise FullStackEpisodeDenied("GOAL_STATUS_RECEIPT_MISSING")
        return rows[-1]

    def _later_effects_blocked(self) -> bool:
        config = self.spec.config
        return not any(
            event.payload.get("request_id")
            in {config.deployment_request_id, config.public_action_request_id}
            for kind in (
                "deployment.local_fake.claimed",
                "public_action.fake_sink.claimed",
            )
            for event in self.store.events(kind)
        )

    def _terminal_payload(
        self,
        *,
        status: EpisodeStatus,
        completed_stage_ids: tuple[str, ...],
        claims: tuple[tuple[str, str], ...],
        receipts: tuple[tuple[str, str], ...],
        outcome: Event,
        reflection: Event,
        goal_status: Event,
        failure_stage_id: str | None,
        reason_code: str,
        rollback_event_id: str | None,
        later_effects_blocked: bool,
    ) -> dict[str, object]:
        return {
            "schema_version": "cct.autonomy.full-stack-episode.receipt.v1",
            "episode_id": self.spec.id,
            "status": status,
            "goal_id": self.spec.binding.goal_id,
            "plan_id": self.spec.binding.plan_id,
            "decision_id": self.spec.binding.decision_id,
            "plan_sha256": self.spec.binding.plan_sha256,
            "configuration_sha256": self.spec.config.digest,
            "completed_stage_ids": list(completed_stage_ids),
            "stage_claim_event_ids": {stage: event for stage, event in claims},
            "stage_receipt_event_ids": {stage: event for stage, event in receipts},
            "outcome_event_id": outcome.event_id,
            "reflection_event_id": reflection.event_id,
            "goal_status_event_id": goal_status.event_id,
            "failure_stage_id": failure_stage_id,
            "reason_code": reason_code,
            "rollback_event_id": rollback_event_id,
            "later_effects_blocked": later_effects_blocked,
            "raw_adapter_content_persisted": False,
            "hidden_reasoning_persisted": False,
            "real_deployment_effect": False,
            "real_public_effect": False,
        }

    def _finalize_success(
        self,
        completed_stage_ids: tuple[str, ...],
    ) -> FullStackEpisodeResult:
        if completed_stage_ids != self.spec.config.stage_ids:
            raise FullStackEpisodeDenied("EPISODE_STAGE_SET_MISMATCH")
        receipts = self._collect_receipts(required_stage_ids=self.spec.config.stage_ids)
        claims = self._collect_claims(required_stage_ids=self.spec.config.stage_ids)
        evidence = tuple(event_id for _stage, event_id in receipts)
        outcome = self._outcome(status="completed", evidence_event_ids=evidence)
        reflection = self._reflection(outcome.event_id)
        goal_status = self._goal_status("completed")
        payload = self._terminal_payload(
            status="completed",
            completed_stage_ids=completed_stage_ids,
            claims=claims,
            receipts=receipts,
            outcome=outcome,
            reflection=reflection,
            goal_status=goal_status,
            failure_stage_id=None,
            reason_code="EPISODE_COMPLETED",
            rollback_event_id=None,
            later_effects_blocked=False,
        )
        try:
            event, created = self.store.append_once_result(
                "autonomy.episode.completed",
                self.spec.id,
                payload,
            )
        except ValueError as error:
            raise FullStackEpisodeDenied("EPISODE_TERMINAL_CONFLICT") from error
        return self._result_from_event(event, replayed=not created)

    def _finalize_failure(self, failure: _StageResult) -> FullStackEpisodeResult:
        rollback_event_id = self._rollback_if_needed(failure)
        cursor = self.planner.cursor(self.spec.binding.plan_id)
        completed = tuple(str(value) for value in cursor["completed_stage_ids"])
        required = (*completed, failure.stage_id)
        receipts = self._collect_receipts(required_stage_ids=required)
        claims = self._collect_claims(required_stage_ids=required)
        later_effects_blocked = self._later_effects_blocked()
        if failure.stage_id in self.spec.config.stage_ids[:4] and not later_effects_blocked:
            raise FullStackEpisodeDenied("LATER_EFFECT_ALREADY_PRESENT")
        evidence_rows = [event_id for _stage, event_id in receipts]
        if rollback_event_id is not None and rollback_event_id not in evidence_rows:
            evidence_rows.append(rollback_event_id)
        outcome = self._outcome(
            status="failed",
            evidence_event_ids=tuple(evidence_rows),
        )
        reflection = self._reflection(outcome.event_id)
        goal_status = self._goal_status("failed")
        payload = self._terminal_payload(
            status="failed",
            completed_stage_ids=completed,
            claims=claims,
            receipts=receipts,
            outcome=outcome,
            reflection=reflection,
            goal_status=goal_status,
            failure_stage_id=failure.stage_id,
            reason_code=failure.reason_code,
            rollback_event_id=rollback_event_id,
            later_effects_blocked=later_effects_blocked,
        )
        try:
            event, created = self.store.append_once_result(
                "autonomy.episode.failed",
                self.spec.id,
                payload,
            )
        except ValueError as error:
            raise FullStackEpisodeDenied("EPISODE_TERMINAL_CONFLICT") from error
        return self._result_from_event(event, replayed=not created)

    def _validate_terminal_effects(self, terminal: Event) -> None:
        if terminal.kind == "autonomy.episode.completed":
            self.verifier.require_passed(self.spec.config.verification_request_id)
            self.deployment.require_deployed(self.spec.config.deployment_request_id)
            self.public_actions.require_completed(self.spec.config.public_action_request_id)
            self.patching.require_verified(self.spec.config.patch_request.id)
        elif terminal.kind == "autonomy.episode.failed":
            if terminal.payload.get("later_effects_blocked") is True and not self._later_effects_blocked():
                raise FullStackEpisodeDenied("LATER_EFFECT_ALREADY_PRESENT")

    def _result_from_event(
        self,
        event: Event,
        *,
        replayed: bool,
    ) -> FullStackEpisodeResult:
        payload = event.payload
        status = payload.get("status")
        claim_rows = payload.get("stage_claim_event_ids")
        receipt_rows = payload.get("stage_receipt_event_ids")
        completed = payload.get("completed_stage_ids")
        if (
            payload.get("schema_version")
            != "cct.autonomy.full-stack-episode.receipt.v1"
            or status not in {"completed", "failed"}
            or payload.get("episode_id") != self.spec.id
            or payload.get("goal_id") != self.spec.binding.goal_id
            or payload.get("plan_id") != self.spec.binding.plan_id
            or payload.get("decision_id") != self.spec.binding.decision_id
            or payload.get("plan_sha256") != self.spec.binding.plan_sha256
            or payload.get("configuration_sha256") != self.spec.config.digest
            or not isinstance(claim_rows, dict)
            or not isinstance(receipt_rows, dict)
            or not isinstance(completed, list)
        ):
            raise FullStackEpisodeDenied("EPISODE_TERMINAL_MISMATCH")
        required_ids = (
            payload.get("outcome_event_id"),
            payload.get("reflection_event_id"),
            payload.get("goal_status_event_id"),
        )
        if any(
            not isinstance(value, str) or not _IDENTIFIER.fullmatch(value)
            for value in required_ids
        ):
            raise FullStackEpisodeDenied("EPISODE_TERMINAL_MISMATCH")
        failure_stage_id = payload.get("failure_stage_id")
        rollback_event_id = payload.get("rollback_event_id")
        reason_code = payload.get("reason_code")
        if (
            (failure_stage_id is not None and not isinstance(failure_stage_id, str))
            or (rollback_event_id is not None and not isinstance(rollback_event_id, str))
            or not isinstance(reason_code, str)
            or not _IDENTIFIER.fullmatch(reason_code)
            or (
                status == "completed"
                and (
                    failure_stage_id is not None
                    or tuple(str(value) for value in completed) != self.spec.config.stage_ids
                )
            )
            or (
                status == "failed"
                and (
                    failure_stage_id not in self.spec.config.stage_ids
                    or tuple(str(value) for value in completed)
                    != self.spec.config.stage_ids[
                        : self.spec.config.stage_ids.index(str(failure_stage_id))
                    ]
                )
            )
        ):
            raise FullStackEpisodeDenied("EPISODE_TERMINAL_MISMATCH")
        if event.kind != f"autonomy.episode.{status}":
            raise FullStackEpisodeDenied("EPISODE_TERMINAL_MISMATCH")
        required_stages = (
            self.spec.config.stage_ids
            if status == "completed"
            else (*tuple(str(value) for value in completed), str(failure_stage_id))
        )
        expected_claims = dict(self._collect_claims(required_stage_ids=required_stages))
        expected_receipts = dict(self._collect_receipts(required_stage_ids=required_stages))
        if claim_rows != expected_claims or receipt_rows != expected_receipts:
            raise FullStackEpisodeDenied("EPISODE_TERMINAL_MISMATCH")
        outcome = self.store.event(str(required_ids[0]))
        reflection = self.store.event(str(required_ids[1]))
        goal_status = self.store.event(str(required_ids[2]))
        expected_goal_status = "completed" if status == "completed" else "paused"
        if (
            outcome is None
            or outcome.kind != "outcome.observed"
            or outcome.payload.get("decision_id") != self.spec.binding.decision_id
            or reflection is None
            or reflection.kind != "reflection.proposed"
            or outcome.event_id not in reflection.payload.get("evidence_event_ids", [])
            or goal_status is None
            or goal_status.kind != "goal.status_changed"
            or goal_status.payload.get("goal_id") != self.spec.binding.goal_id
            or goal_status.payload.get("to") != expected_goal_status
        ):
            raise FullStackEpisodeDenied("EPISODE_TERMINAL_MISMATCH")
        if rollback_event_id is not None:
            rollback = self.store.event(rollback_event_id)
            if rollback is None or rollback.kind not in {
                "patch.rollback.completed",
                "patch.rollback.blocked",
            }:
                raise FullStackEpisodeDenied("EPISODE_TERMINAL_MISMATCH")
        return FullStackEpisodeResult(
            episode_id=self.spec.id,
            status=status,
            goal_id=self.spec.binding.goal_id,
            plan_id=self.spec.binding.plan_id,
            decision_id=self.spec.binding.decision_id,
            completed_stage_ids=tuple(str(value) for value in completed),
            stage_claim_event_ids=tuple(
                (str(stage_id), str(claim_rows[stage_id]))
                for stage_id in self.spec.config.stage_ids
                if stage_id in claim_rows
            ),
            stage_receipt_event_ids=tuple(
                (str(stage_id), str(receipt_rows[stage_id]))
                for stage_id in self.spec.config.stage_ids
                if stage_id in receipt_rows
            ),
            outcome_event_id=str(required_ids[0]),
            reflection_event_id=str(required_ids[1]),
            goal_status_event_id=str(required_ids[2]),
            terminal_event_id=event.event_id,
            failure_stage_id=failure_stage_id,
            reason_code=reason_code,
            rollback_event_id=rollback_event_id,
            later_effects_blocked=payload.get("later_effects_blocked") is True,
            replayed=replayed,
        )


__all__ = [
    "FullStackEpisodeConfig",
    "FullStackEpisodeDenied",
    "FullStackEpisodeResult",
    "FullStackEpisodeRunner",
    "FullStackEpisodeSpec",
]
