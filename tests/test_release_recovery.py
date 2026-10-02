from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from operator_crash_matrix import race_same_ticket_recovery

from cct_agent.execution_tickets import GlobalKillSwitch
from cct_agent.kernel import AgencyKernel, default_constitution
from cct_agent.release_recovery import (
    FULL_RECOVERY_OPTION_ID,
    REQUIRED_RELEASE_OPERATIONS,
    AuthenticatedArtifactMismatchReceipt,
    AuthenticatedReleaseAuthority,
    ExactRebuildTicket,
    Generalist2RedeployTicket,
    IsolatedReleaseVerification,
    IsolatedVerificationTicket,
    ReleaseArtifact,
    ReleaseRecoveryBridge,
    ReleaseRecoveryDenied,
    ReleaseRollbackTicket,
    ReleaseRuntimeState,
)
from cct_agent.store import EventStore, canonical_json


NOW = "2026-08-25T14:00:00+00:00"
FUTURE = "2026-08-26T14:00:00+00:00"
GOAL_ID = "goal-cct-full-operator-effects"
SOURCE_BAD = "1" * 40
SOURCE_ROLLBACK = "2" * 40
SOURCE_EXPECTED = "3" * 40
WHEEL_BAD = "a" * 64
WHEEL_ROLLBACK = "b" * 64
WHEEL_EXPECTED = "c" * 64
AUTHORITY_RECEIPT = "d" * 64
EVIDENCE = "e" * 64
MODULE_BAD = "/profile/generalist2/releases/bad/site-packages"
MODULE_ROLLBACK = "/profile/generalist2/releases/rollback/site-packages"
MODULE_EXPECTED = "/profile/generalist2/releases/expected/site-packages"


def digest(value: object) -> str:
    from hashlib import sha256

    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def register_authority(
    store: EventStore, authority: AuthenticatedReleaseAuthority
) -> None:
    store.append_once_result(
        "release.recovery.authority.installed",
        authority.id,
        {
            "schema_version": 1,
            "authority_id": authority.id,
            "authority_sha256": digest(asdict(authority)),
            "authority_receipt_sha256": authority.authority_receipt_sha256,
            "profile_name": authority.profile_name,
            "service_name": authority.service_name,
            "authenticated_by": "host_adapter",
            "model_callable": False,
        },
    )


def register_mismatch(
    store: EventStore, receipt: AuthenticatedArtifactMismatchReceipt
) -> None:
    store.append_once_result(
        "release.artifact_mismatch.observed",
        receipt.id,
        {
            "schema_version": 1,
            "receipt_id": receipt.id,
            "mismatch_receipt_sha256": digest(asdict(receipt)),
            "authority_receipt_sha256": receipt.authority_receipt_sha256,
            "profile_name": receipt.profile_name,
            "service_name": receipt.service_name,
            "authenticated_by": "host_adapter",
            "model_callable": False,
            "producer_prose_persisted": False,
        },
    )


def runtime(
    *,
    pid: int,
    version: str,
    module_root: str,
    wheel: str,
    source: str,
) -> ReleaseRuntimeState:
    return ReleaseRuntimeState(
        profile_name="generalist2",
        service_name="hermes-gateway-generalist2.service",
        pid=pid,
        version=version,
        module_root=module_root,
        wheel_sha256=wheel,
        source_commit=source,
        chain_valid=True,
    )


class FakeReleaseAdapter:
    """Host fake with durable state so restarted/forked bridges adopt effects."""

    def __init__(self, root: Path, *, verification_passed: bool = True) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.verification_passed = verification_passed
        if not self._state_path.exists():
            self._write(
                {
                    "runtime": asdict(
                        runtime(
                            pid=101,
                            version="0.9.0a10-bad",
                            module_root=MODULE_BAD,
                            wheel=WHEEL_BAD,
                            source=SOURCE_BAD,
                        )
                    ),
                    "artifact": None,
                    "verification": None,
                    "calls": {"rollback": 0, "rebuild": 0, "verify": 0, "redeploy": 0},
                }
            )

    @property
    def _state_path(self) -> Path:
        return self.root / "release-state.json"

    def _read(self) -> dict[str, Any]:
        import json

        return json.loads(self._state_path.read_text())

    def _write(self, value: dict[str, Any]) -> None:
        temporary = self.root / f".release-state-{__import__('os').getpid()}.tmp"
        temporary.write_text(canonical_json(value), encoding="utf-8")
        temporary.replace(self._state_path)

    @property
    def calls(self) -> dict[str, int]:
        return dict(self._read()["calls"])

    def inspect_runtime(self) -> ReleaseRuntimeState:
        return ReleaseRuntimeState(**self._read()["runtime"])

    def inspect_artifact(self, recovery_id: str) -> ReleaseArtifact | None:
        value = self._read()["artifact"]
        return ReleaseArtifact(**value) if value else None

    def inspect_verification(
        self, recovery_id: str
    ) -> IsolatedReleaseVerification | None:
        value = self._read()["verification"]
        return IsolatedReleaseVerification(**value) if value else None

    def rollback(self, ticket: ReleaseRollbackTicket) -> ReleaseRuntimeState:
        value = self._read()
        value["calls"]["rollback"] += 1
        value["runtime"] = asdict(
            runtime(
                pid=102,
                version=ticket.rollback_version,
                module_root=ticket.rollback_module_root,
                wheel=ticket.rollback_wheel_sha256,
                source=ticket.rollback_source_commit,
            )
        )
        self._write(value)
        return self.inspect_runtime()

    def rebuild_exact(self, ticket: ExactRebuildTicket) -> ReleaseArtifact:
        value = self._read()
        value["calls"]["rebuild"] += 1
        value["artifact"] = asdict(
            ReleaseArtifact(
                recovery_id=ticket.recovery_id,
                source_commit=ticket.source_commit,
                version=ticket.version,
                wheel_sha256=ticket.expected_wheel_sha256,
                byte_count=12345,
                wheel_source_exact=True,
            )
        )
        self._write(value)
        artifact = self.inspect_artifact(ticket.recovery_id)
        assert artifact is not None
        return artifact

    def verify_isolated(
        self,
        ticket: IsolatedVerificationTicket,
        artifact: ReleaseArtifact,
    ) -> IsolatedReleaseVerification:
        value = self._read()
        value["calls"]["verify"] += 1
        value["verification"] = asdict(
            IsolatedReleaseVerification(
                recovery_id=ticket.recovery_id,
                source_commit=artifact.source_commit,
                version=artifact.version,
                module_root=ticket.expected_module_root,
                wheel_sha256=artifact.wheel_sha256,
                wheel_source_exact=artifact.wheel_source_exact,
                tools=21,
                hooks=3,
                middleware=1,
                passed=self.verification_passed,
                receipt_sha256="f" * 64,
            )
        )
        self._write(value)
        verification = self.inspect_verification(ticket.recovery_id)
        assert verification is not None
        return verification

    def redeploy(
        self,
        ticket: Generalist2RedeployTicket,
        artifact: ReleaseArtifact,
        verification: IsolatedReleaseVerification,
    ) -> ReleaseRuntimeState:
        value = self._read()
        value["calls"]["redeploy"] += 1
        value["runtime"] = asdict(
            runtime(
                pid=202,
                version=artifact.version,
                module_root=verification.module_root,
                wheel=artifact.wheel_sha256,
                source=artifact.source_commit,
            )
        )
        self._write(value)
        return self.inspect_runtime()


def configured(tmp_path: Path, *, verification_passed: bool = True) -> dict[str, Any]:
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    kernel = AgencyKernel(store, default_constitution("Release-Recovery-Test"))
    kernel.initialize()
    kernel.form_goal(
        goal_id=GOAL_ID,
        statement="Keep exact reviewed CCT release live on Generalist2.",
        rationale="Repair authenticated artifact mismatches without waiting for another prompt.",
        source="joint",
        horizon="overnight",
        alignment={"truth": 1.0, "competence": 1.0, "autonomy": 0.8},
        evidence=("operator://standing-release-authority",),
    )
    authority = AuthenticatedReleaseAuthority(
        id="authority-generalist2-release-recovery",
        authority="operator",
        authenticated=True,
        principal_id="mike",
        goal_id=GOAL_ID,
        profile_name="generalist2",
        service_name="hermes-gateway-generalist2.service",
        operations=REQUIRED_RELEASE_OPERATIONS,
        reversible=True,
        authority_receipt_sha256=AUTHORITY_RECEIPT,
        expires_at=FUTURE,
    )
    receipt = AuthenticatedArtifactMismatchReceipt(
        id="mismatch-generalist2-a11",
        authority="host_adapter",
        authenticated=True,
        principal_id="mike",
        goal_id=GOAL_ID,
        profile_name="generalist2",
        service_name="hermes-gateway-generalist2.service",
        observed_pid=101,
        observed_version="0.9.0a10-bad",
        observed_module_root=MODULE_BAD,
        observed_wheel_sha256=WHEEL_BAD,
        observed_source_commit=SOURCE_BAD,
        expected_version="0.9.0a11",
        expected_module_root=MODULE_EXPECTED,
        expected_wheel_sha256=WHEEL_EXPECTED,
        expected_source_commit=SOURCE_EXPECTED,
        rollback_version="0.9.0a10",
        rollback_module_root=MODULE_ROLLBACK,
        rollback_wheel_sha256=WHEEL_ROLLBACK,
        rollback_source_commit=SOURCE_ROLLBACK,
        chain_valid=True,
        evidence_sha256=EVIDENCE,
        authority_receipt_sha256=AUTHORITY_RECEIPT,
        expires_at=FUTURE,
    )
    register_authority(store, authority)
    register_mismatch(store, receipt)
    state_root = tmp_path / "bridge-state"
    state_root.mkdir()
    adapter = FakeReleaseAdapter(tmp_path / "host-state", verification_passed=verification_passed)
    bridge = ReleaseRecoveryBridge(
        store,
        kernel=kernel,
        adapter=adapter,
        state_root=state_root,
    )
    return {
        "store": store,
        "kernel": kernel,
        "authority": authority,
        "receipt": receipt,
        "adapter": adapter,
        "bridge": bridge,
        "state_root": state_root,
    }


def restarted(fixture: dict[str, Any]) -> ReleaseRecoveryBridge:
    return ReleaseRecoveryBridge(
        fixture["store"],
        kernel=fixture["kernel"],
        adapter=FakeReleaseAdapter(fixture["adapter"].root),
        state_root=fixture["state_root"],
    )


def test_authenticated_mismatch_selects_and_executes_full_recovery_once(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path)

    result = fixture["bridge"].recover(
        fixture["receipt"], fixture["authority"], seed=0
    )
    replay = restarted(fixture).recover(
        fixture["receipt"], fixture["authority"], seed=0
    )

    assert result["status"] == "verified-live"
    assert result["chosen_option_id"] == FULL_RECOVERY_OPTION_ID
    assert result["alternatives_considered"] == [
        "rollback-only",
        "wait",
        FULL_RECOVERY_OPTION_ID,
        "NO_OP",
    ]
    assert result["steps"] == [
        "rollback",
        "exact-rebuild",
        "isolated-verification",
        "generalist2-redeploy",
        "live-verification",
    ]
    assert result["live"] == {
        "profile_name": "generalist2",
        "service_name": "hermes-gateway-generalist2.service",
        "old_pid": 101,
        "new_pid": 202,
        "version": "0.9.0a11",
        "module_root": MODULE_EXPECTED,
        "wheel_sha256": WHEEL_EXPECTED,
        "source_commit": SOURCE_EXPECTED,
        "wheel_source_exact": True,
        "chain_valid": True,
    }
    assert result["replayed"] is False
    assert replay["replayed"] is True
    assert fixture["adapter"].calls == {
        "rollback": 1,
        "rebuild": 1,
        "verify": 1,
        "redeploy": 1,
    }
    assert len(fixture["store"].events("decision.made")) == 1
    assert len(fixture["store"].events("outcome.observed")) == 1
    assert len(fixture["store"].events("release.recovery.policy_learning.proposed")) == 1
    assert fixture["store"].verify_chain()["valid"] is True


@pytest.mark.parametrize(
    "boundary",
    [
        "after-rollback-effect",
        "after-rebuild-effect",
        "after-isolated-verification-effect",
        "after-redeploy-effect",
    ],
)
def test_every_post_effect_crash_is_adopted_without_second_effect(
    tmp_path: Path,
    boundary: str,
) -> None:
    fixture = configured(tmp_path)

    def crash(step: str) -> None:
        if step == boundary:
            raise SystemExit(boundary)

    with pytest.raises(SystemExit, match=boundary):
        fixture["bridge"].recover(
            fixture["receipt"],
            fixture["authority"],
            seed=0,
            fault_hook=crash,
        )

    result = restarted(fixture).recover(
        fixture["receipt"], fixture["authority"], seed=0
    )
    replay = restarted(fixture).recover(
        fixture["receipt"], fixture["authority"], seed=0
    )

    assert result["status"] == "verified-live"
    assert replay["replayed"] is True
    assert fixture["adapter"].calls == {
        "rollback": 1,
        "rebuild": 1,
        "verify": 1,
        "redeploy": 1,
    }


@pytest.mark.operator_crash_matrix
def test_same_release_forked_recovery_attempts_converge(tmp_path: Path) -> None:
    fixture = configured(tmp_path)

    def crash_after_rollback(step: str) -> None:
        if step == "after-rollback-effect":
            raise SystemExit(step)

    with pytest.raises(SystemExit):
        fixture["bridge"].recover(
            fixture["receipt"],
            fixture["authority"],
            seed=0,
            fault_hook=crash_after_rollback,
        )

    recoveries = race_same_ticket_recovery(
        lambda: (
            {
                **restarted(fixture).recover(
                    fixture["receipt"], fixture["authority"], seed=0
                ),
                "success": True,
            },
            0,
        )
    )

    assert all(row["status"] == "verified-live" for row in recoveries)
    assert fixture["adapter"].calls == {
        "rollback": 1,
        "rebuild": 1,
        "verify": 1,
        "redeploy": 1,
    }
    assert len(fixture["store"].events("release.recovery.completed")) == 1


def test_stale_or_unauthenticated_receipt_fails_before_decision_and_effect(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path)
    stale = AuthenticatedArtifactMismatchReceipt(
        **{
            **asdict(fixture["receipt"]),
            "id": "mismatch-generalist2-a11-stale",
            "observed_pid": 999,
        }
    )
    register_mismatch(fixture["store"], stale)
    with pytest.raises(ReleaseRecoveryDenied, match="ARTIFACT_MISMATCH_RECEIPT_STALE"):
        fixture["bridge"].recover(stale, fixture["authority"], seed=0)

    unauthenticated = AuthenticatedReleaseAuthority(
        **{
            **asdict(fixture["authority"]),
            "authenticated": False,
        }
    )
    with pytest.raises(ReleaseRecoveryDenied, match="RELEASE_AUTHORITY_NOT_AUTHENTICATED"):
        fixture["bridge"].recover(
            fixture["receipt"], unauthenticated, seed=0
        )

    assert not fixture["store"].events("decision.made")
    assert fixture["adapter"].calls == {
        "rollback": 0,
        "rebuild": 0,
        "verify": 0,
        "redeploy": 0,
    }


def test_terminal_retry_rejects_changed_receipt_or_authority_binding(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path)
    fixture["bridge"].recover(fixture["receipt"], fixture["authority"], seed=0)

    changed_receipt = AuthenticatedArtifactMismatchReceipt(
        **{
            **asdict(fixture["receipt"]),
            "expected_version": "0.9.0a12",
        }
    )
    current = fixture["adapter"]._read()
    current["runtime"]["version"] = "0.9.0a12"
    fixture["adapter"]._write(current)
    with pytest.raises(
        ReleaseRecoveryDenied,
        match="ARTIFACT_MISMATCH_RECEIPT_NOT_HOST_REGISTERED",
    ):
        restarted(fixture).recover(changed_receipt, fixture["authority"], seed=0)

    changed_authority = AuthenticatedReleaseAuthority(
        **{
            **asdict(fixture["authority"]),
            "authority_receipt_sha256": "9" * 64,
        }
    )
    with pytest.raises(ReleaseRecoveryDenied, match="RELEASE_AUTHORITY_BINDING_MISMATCH"):
        restarted(fixture).recover(fixture["receipt"], changed_authority, seed=0)


def test_crash_after_live_step_receipt_replays_without_collision_or_effect(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path)

    def crash(step: str) -> None:
        if step == "after-live-verification-receipt":
            raise SystemExit(step)

    with pytest.raises(SystemExit, match="after-live-verification-receipt"):
        fixture["bridge"].recover(
            fixture["receipt"], fixture["authority"], seed=0, fault_hook=crash
        )

    recovered = restarted(fixture).recover(
        fixture["receipt"], fixture["authority"], seed=0
    )
    assert recovered["status"] == "verified-live"
    assert fixture["adapter"].calls == {
        "rollback": 1,
        "rebuild": 1,
        "verify": 1,
        "redeploy": 1,
    }


def test_kill_switch_between_effect_legs_stops_remaining_release_calls(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path)
    original = fixture["adapter"].rollback

    def rollback_then_trip(ticket: ReleaseRollbackTicket) -> ReleaseRuntimeState:
        state = original(ticket)
        GlobalKillSwitch(fixture["store"]).trip(
            trip_id="trip-between-release-legs",
            authority="host_adapter",
            reason="Stop after rollback readback.",
        )
        return state

    fixture["adapter"].rollback = rollback_then_trip
    with pytest.raises(ReleaseRecoveryDenied, match="GLOBAL_KILL_SWITCH_ACTIVE"):
        fixture["bridge"].recover(
            fixture["receipt"], fixture["authority"], seed=0
        )

    assert fixture["adapter"].calls == {
        "rollback": 1,
        "rebuild": 0,
        "verify": 0,
        "redeploy": 0,
    }
    assert fixture["adapter"].inspect_runtime().source_commit == SOURCE_ROLLBACK


def test_failed_isolated_verification_keeps_rollback_live_and_blocks_redeploy(
    tmp_path: Path,
) -> None:
    fixture = configured(tmp_path, verification_passed=False)

    with pytest.raises(ReleaseRecoveryDenied, match="ISOLATED_RELEASE_VERIFICATION_FAILED"):
        fixture["bridge"].recover(
            fixture["receipt"], fixture["authority"], seed=0
        )

    current = fixture["adapter"].inspect_runtime()
    assert current.source_commit == SOURCE_ROLLBACK
    assert current.wheel_sha256 == WHEEL_ROLLBACK
    assert fixture["adapter"].calls == {
        "rollback": 1,
        "rebuild": 1,
        "verify": 1,
        "redeploy": 0,
    }
    failures = fixture["store"].events("release.recovery.failed")
    assert len(failures) == 1
    assert failures[0].payload["rollback_live_verified"] is True
    assert fixture["store"].verify_chain()["valid"] is True
