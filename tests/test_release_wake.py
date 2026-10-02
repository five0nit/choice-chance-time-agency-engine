from __future__ import annotations

from dataclasses import asdict
import json
import multiprocessing
import os
from pathlib import Path
from typing import Any

import pytest

import cct_agent
import cct_agent.release_wake as release_wake
from cct_agent.kernel import AgencyKernel, default_constitution
from cct_agent.release_recovery import ReleaseRecoveryBridge
from cct_agent.release_wake import (
    ReleaseWakeCoordinator,
    ReleaseWakePaths,
    ReleaseWakeTarget,
)
from cct_agent.store import EventStore, canonical_json
from tests.test_release_recovery import (
    FakeReleaseAdapter,
    FUTURE,
    GOAL_ID,
    MODULE_EXPECTED,
    MODULE_ROLLBACK,
    NOW,
    SOURCE_EXPECTED,
    SOURCE_ROLLBACK,

    WHEEL_EXPECTED,
    WHEEL_ROLLBACK,
    runtime,
)


SECRET = b"release-wake-host-authentication-secret-32bytes"
VERSION_EXPECTED = "0.9.0a15"
VERSION_ROLLBACK = "0.9.0a12"


def wake_paths(tmp_path: Path) -> ReleaseWakePaths:
    root = tmp_path / "release-wake"
    inbox = root / "inbox"
    completed = root / "completed"
    rejected = root / "rejected"
    claims = root / "claims"
    bridge = root / "bridge-state"
    for directory in (root, inbox, completed, rejected, claims, bridge):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
    secret = root / "authentication.key"
    secret.write_bytes(SECRET)
    os.chmod(secret, 0o600)
    return ReleaseWakePaths(
        state_root=root,
        inbox_root=inbox,
        completed_root=completed,
        rejected_root=rejected,
        claims_root=claims,
        bridge_state_root=bridge,
        secret_file=secret,
    )


def initialize(tmp_path: Path) -> dict[str, Any]:
    rows = wake_paths(tmp_path)
    store = EventStore(tmp_path / "agency.sqlite", clock=lambda: NOW)
    kernel = AgencyKernel(store, default_constitution("Release-Wake-Test"))
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
    adapter = FakeReleaseAdapter(tmp_path / "host-state")
    bridge = ReleaseRecoveryBridge(
        store,
        kernel=kernel,
        adapter=adapter,
        state_root=rows.bridge_state_root,
    )
    return {
        "paths": rows,
        "store": store,
        "kernel": kernel,
        "adapter": adapter,
        "bridge": bridge,
    }


def signed_target(target_id: str = "release-target-a11") -> ReleaseWakeTarget:
    target = ReleaseWakeTarget.sign(
        target_id=target_id,
        authority_id="authority-generalist2-release-recovery",
        principal_id="mike",
        goal_id=GOAL_ID,
        expected_version=VERSION_EXPECTED,
        expected_module_root=MODULE_EXPECTED,
        expected_wheel_sha256=WHEEL_EXPECTED,
        expected_source_commit=SOURCE_EXPECTED,
        rollback_version=VERSION_ROLLBACK,
        rollback_module_root=MODULE_ROLLBACK,
        rollback_wheel_sha256=WHEEL_ROLLBACK,
        rollback_source_commit=SOURCE_ROLLBACK,
        expires_at=FUTURE,
        secret=SECRET,
    )
    assert len(target.authority_receipt_sha256) == 64
    return target


def write_target(rows: ReleaseWakePaths, name: str, target: ReleaseWakeTarget) -> Path:
    path = rows.inbox_root / name
    path.write_text(
        json.dumps(target.to_document(), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return path


def coordinator(fixture: dict[str, Any]) -> ReleaseWakeCoordinator:
    return ReleaseWakeCoordinator(
        paths=fixture["paths"],
        store=fixture["store"],
        kernel=fixture["kernel"],
        adapter=fixture["adapter"],
        bridge=fixture["bridge"],
        expected_module_root=Path(cct_agent.__file__).resolve().parents[1],
        expected_package_version=cct_agent.__version__,
    )


def restarted(fixture: dict[str, Any]) -> ReleaseWakeCoordinator:
    adapter = FakeReleaseAdapter(fixture["adapter"].root)
    bridge = ReleaseRecoveryBridge(
        fixture["store"],
        kernel=fixture["kernel"],
        adapter=adapter,
        state_root=fixture["paths"].bridge_state_root,
    )
    return ReleaseWakeCoordinator(
        paths=fixture["paths"],
        store=fixture["store"],
        kernel=fixture["kernel"],
        adapter=adapter,
        bridge=bridge,
        expected_module_root=Path(cct_agent.__file__).resolve().parents[1],
        expected_package_version=cct_agent.__version__,
    )


def test_matching_runtime_is_byte_silent_and_writes_no_ledger_rows(tmp_path: Path) -> None:
    fixture = initialize(tmp_path)
    target = signed_target()
    value = fixture["adapter"]._read()
    value["runtime"] = asdict(
        runtime(
            pid=101,
            version=target.expected_version,
            module_root=target.expected_module_root,
            wheel=target.expected_wheel_sha256,
            source=target.expected_source_commit,
        )
    )
    fixture["adapter"]._write(value)
    path = write_target(fixture["paths"], "001-target.json", target)
    before = len(fixture["store"].events())

    result = coordinator(fixture).run_once()

    assert result == {
        "status": "already-live",
        "target_id": target.id,
        "emit": False,
        "external_effects": 0,
    }
    assert len(fixture["store"].events()) == before
    assert not path.exists()
    assert len(list(fixture["paths"].completed_root.iterdir())) == 1
    assert fixture["store"].verify_chain()["valid"] is True


def test_mismatch_registration_restart_and_post_recovery_crash_adopt_once(
    tmp_path: Path,
) -> None:
    fixture = initialize(tmp_path)
    target = signed_target()
    path = write_target(fixture["paths"], "001-target.json", target)
    seen: list[str] = []

    def fail_after_registration(boundary: str) -> None:
        seen.append(boundary)
        if boundary == "after-registration":
            raise SystemExit("crash-after-registration")

    with pytest.raises(SystemExit, match="crash-after-registration"):
        coordinator(fixture).run_once(fault_hook=fail_after_registration)

    assert path.exists()
    assert len(fixture["store"].events("release.recovery.authority.installed")) == 1
    assert len(fixture["store"].events("release.artifact_mismatch.observed")) == 1

    def fail_after_recovery(boundary: str) -> None:
        if boundary == "after-recovery":
            raise SystemExit("crash-after-recovery")

    with pytest.raises(SystemExit, match="crash-after-recovery"):
        restarted(fixture).run_once(fault_hook=fail_after_recovery)

    assert path.exists()
    result = restarted(fixture).run_once()

    assert result["status"] == "verified-live"
    assert result["replayed"] is True
    assert result["emit"] is True
    assert fixture["adapter"].calls == {
        "rollback": 1,
        "rebuild": 1,
        "verify": 1,
        "redeploy": 1,
    }
    assert len(fixture["store"].events("release.recovery.completed")) == 1
    assert len(fixture["store"].events("outcome.observed")) == 1
    assert len(fixture["store"].events("release.recovery.policy_learning.proposed")) == 1
    persisted = canonical_json([event.payload for event in fixture["store"].events()])
    assert "release-target-a11" in persisted
    assert "producer_text" not in persisted
    assert fixture["store"].verify_chain()["valid"] is True


class _CrashAfterRollbackBridge:
    def __init__(self, bridge: ReleaseRecoveryBridge) -> None:
        self.store = bridge.store
        self.adapter = bridge.adapter
        self.bridge = bridge

    def recover(self, receipt: Any, authority: Any, *, seed: int) -> dict[str, Any]:
        def crash(boundary: str) -> None:
            if boundary == "after-rollback-effect":
                raise SystemExit("crash-after-wake-rollback")

        return self.bridge.recover(
            receipt,
            authority,
            seed=seed,
            fault_hook=crash,
        )


class _CrashAfterRedeployBridge:
    def __init__(self, bridge: ReleaseRecoveryBridge) -> None:
        self.store = bridge.store
        self.adapter = bridge.adapter
        self.bridge = bridge

    def recover(self, receipt: Any, authority: Any, *, seed: int) -> dict[str, Any]:
        def crash(boundary: str) -> None:
            if boundary == "after-redeploy-effect":
                raise SystemExit("crash-after-wake-redeploy")

        return self.bridge.recover(
            receipt,
            authority,
            seed=seed,
            fault_hook=crash,
        )


def test_restart_after_physical_rollback_reuses_original_mismatch_claim(
    tmp_path: Path,
) -> None:
    fixture = initialize(tmp_path)
    write_target(fixture["paths"], "001-target.json", signed_target())
    crashing = ReleaseWakeCoordinator(
        paths=fixture["paths"],
        store=fixture["store"],
        kernel=fixture["kernel"],
        adapter=fixture["adapter"],
        bridge=_CrashAfterRollbackBridge(fixture["bridge"]),
        expected_module_root=Path(cct_agent.__file__).resolve().parents[1],
        expected_package_version=cct_agent.__version__,
    )

    with pytest.raises(SystemExit, match="crash-after-wake-rollback"):
        crashing.run_once()

    rollback_state = fixture["adapter"].inspect_runtime()
    assert rollback_state.version == VERSION_ROLLBACK
    claims = list(fixture["paths"].claims_root.glob("*.json"))
    assert len(claims) == 1
    original_claim = claims[0].read_bytes()

    result = restarted(fixture).run_once()

    assert result["status"] == "verified-live"
    assert claims[0].read_bytes() == original_claim
    assert fixture["adapter"].calls == {
        "rollback": 1,
        "rebuild": 1,
        "verify": 1,
        "redeploy": 1,
    }
    assert len(fixture["store"].events("release.artifact_mismatch.observed")) == 1
    assert len(fixture["store"].events("release.recovery.completed")) == 1
    assert fixture["store"].verify_chain()["valid"] is True


def test_restart_after_physical_redeploy_finishes_pending_claim_and_learning(
    tmp_path: Path,
) -> None:
    fixture = initialize(tmp_path)
    target_path = write_target(
        fixture["paths"], "001-target.json", signed_target()
    )
    crashing = ReleaseWakeCoordinator(
        paths=fixture["paths"],
        store=fixture["store"],
        kernel=fixture["kernel"],
        adapter=fixture["adapter"],
        bridge=_CrashAfterRedeployBridge(fixture["bridge"]),
        expected_module_root=Path(cct_agent.__file__).resolve().parents[1],
        expected_package_version=cct_agent.__version__,
    )

    with pytest.raises(SystemExit, match="crash-after-wake-redeploy"):
        crashing.run_once()

    assert target_path.exists()
    assert fixture["adapter"].inspect_runtime().version == VERSION_EXPECTED
    assert not fixture["store"].events("release.recovery.completed")
    assert not fixture["store"].events("outcome.observed")

    result = restarted(fixture).run_once()

    assert result["status"] == "verified-live"
    assert result["replayed"] is False
    assert not target_path.exists()
    assert fixture["adapter"].calls == {
        "rollback": 1,
        "rebuild": 1,
        "verify": 1,
        "redeploy": 1,
    }
    assert len(fixture["store"].events("release.recovery.completed")) == 1
    assert len(fixture["store"].events("outcome.observed")) == 1
    assert len(fixture["store"].events("release.recovery.policy_learning.proposed")) == 1
    assert fixture["store"].verify_chain()["valid"] is True


def test_malformed_oldest_receipt_is_quarantined_without_starving_valid_target(
    tmp_path: Path,
) -> None:
    fixture = initialize(tmp_path)
    malformed = fixture["paths"].inbox_root / "000-malformed.json"
    malformed.write_text('{"producer_text":"DO NOT PERSIST ME"', encoding="utf-8")
    os.chmod(malformed, 0o600)
    target = signed_target()
    valid = write_target(fixture["paths"], "001-target.json", target)

    result = coordinator(fixture).run_once(max_scan=2)

    assert result["status"] == "verified-live"
    assert result["target_id"] == target.id
    assert "DO NOT PERSIST ME" not in canonical_json(result)
    assert not malformed.exists()
    assert not valid.exists()
    rejected = list(fixture["paths"].rejected_root.iterdir())
    assert len(rejected) == 1
    assert rejected[0].read_text(encoding="utf-8").startswith('{"producer_text"')
    persisted = canonical_json([event.payload for event in fixture["store"].events()])
    assert "DO NOT PERSIST ME" not in persisted
    assert fixture["store"].verify_chain()["valid"] is True


@pytest.mark.parametrize(
    "malformed_kind",
    ["duplicate-key", "oversized", "long-name", "invalid-utf8-name"],
)
def test_other_malformed_oldest_receipts_cannot_starve_valid_target(
    tmp_path: Path,
    malformed_kind: str,
) -> None:
    fixture = initialize(tmp_path)
    malformed: Path | None = None
    malformed_bytes_path: bytes | None = None
    if malformed_kind == "invalid-utf8-name":
        malformed_bytes_path = (
            os.fsencode(fixture["paths"].inbox_root) + b"/000-invalid-\xff.json"
        )
        descriptor = os.open(
            malformed_bytes_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        os.write(descriptor, b"x")
        os.close(descriptor)
    else:
        malformed_name = (
            "0" * 236 + ".json"
            if malformed_kind == "long-name"
            else "000-malformed.json"
        )
        malformed = fixture["paths"].inbox_root / malformed_name
        assert malformed is not None
        if malformed_kind == "duplicate-key":
            document = signed_target("release-target-duplicate").to_document()
            valid_body = json.dumps(document, sort_keys=True)[1:]
            malformed.write_text(
                '{"expected_version":"DUPLICATE_PRODUCER_PROSE_SENTINEL",'
                + valid_body,
                encoding="utf-8",
            )
        elif malformed_kind == "oversized":
            malformed.write_bytes(b"x" * 65_537)
        else:
            malformed.write_bytes(b"x")
        os.chmod(malformed, 0o600)
    target = signed_target()
    valid = write_target(fixture["paths"], "001-target.json", target)

    result = coordinator(fixture).run_once(max_scan=2)

    assert result["status"] == "verified-live"
    assert result["target_id"] == target.id
    if malformed is not None:
        assert not malformed.exists()
    else:
        assert malformed_bytes_path is not None
        assert not os.path.exists(malformed_bytes_path)
    assert not valid.exists()
    assert len(list(fixture["paths"].rejected_root.iterdir())) == 1
    persisted = canonical_json([event.payload for event in fixture["store"].events()])
    assert "DUPLICATE_PRODUCER_PROSE_SENTINEL" not in persisted
    assert "DUPLICATE_PRODUCER_PROSE_SENTINEL" not in canonical_json(result)
    assert fixture["store"].verify_chain()["valid"] is True


@pytest.mark.parametrize(
    ("result", "json_mode", "expected_output"),
    [
        ({"status": "no-target", "emit": False}, False, ""),
        ({"status": "already-live", "emit": False}, False, ""),
        (
            {"status": "no-target", "emit": False},
            True,
            '{"emit": false, "status": "no-target"}\n',
        ),
    ],
)
def test_cli_default_match_and_no_target_are_byte_silent_and_json_is_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    result: dict[str, Any],
    json_mode: bool,
    expected_output: str,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    placeholder = tmp_path / "placeholder"
    placeholder.mkdir()

    class FakeKernel:
        def initialize(self) -> None:
            return None

    class FakeCoordinator:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def run_once(self) -> dict[str, Any]:
            return result

    class FakePaths:
        bridge_state_root = placeholder

    monkeypatch.setattr(release_wake, "ReleaseWakePaths", lambda **_kwargs: FakePaths())
    monkeypatch.setattr(release_wake, "EventStore", lambda _path: object())
    monkeypatch.setattr(release_wake, "resolve_constitution", lambda *_args: object())
    monkeypatch.setattr(release_wake, "AgencyKernel", lambda *_args: FakeKernel())
    monkeypatch.setattr(
        release_wake, "Generalist2ReleaseHostConfig", lambda **_kwargs: object()
    )
    monkeypatch.setattr(
        release_wake, "Generalist2ReleaseHostAdapter", lambda _config: object()
    )
    monkeypatch.setattr(
        release_wake, "ReleaseRecoveryBridge", lambda *_args, **_kwargs: object()
    )
    monkeypatch.setattr(release_wake, "ReleaseWakeCoordinator", FakeCoordinator)
    arguments = [
        "--state-root",
        str(state_root),
        "--wake-root",
        str(placeholder),
        "--repository-root",
        str(placeholder),
        "--host-home-root",
        str(tmp_path),
        "--staging-root",
        str(placeholder),
        "--adapter-state-root",
        str(placeholder),
        "--expected-module-root",
        str(placeholder),
        "--expected-package-version",
        cct_agent.__version__,
        "--uv-executable",
        str(placeholder),
    ]
    if json_mode:
        arguments.append("--json")

    assert release_wake.main(arguments) == 0
    assert capsys.readouterr().out == expected_output


def _concurrent_worker(root: str, gate: Any, output: Any) -> None:
    base = Path(root)
    paths = ReleaseWakePaths(
        state_root=base / "release-wake",
        inbox_root=base / "release-wake" / "inbox",
        completed_root=base / "release-wake" / "completed",
        rejected_root=base / "release-wake" / "rejected",
        claims_root=base / "release-wake" / "claims",
        bridge_state_root=base / "release-wake" / "bridge-state",
        secret_file=base / "release-wake" / "authentication.key",
    )
    store = EventStore(base / "agency.sqlite", clock=lambda: NOW)
    kernel = AgencyKernel(store, default_constitution("Release-Wake-Test"))
    adapter = FakeReleaseAdapter(base / "host-state")
    bridge = ReleaseRecoveryBridge(
        store,
        kernel=kernel,
        adapter=adapter,
        state_root=paths.bridge_state_root,
    )
    wake = ReleaseWakeCoordinator(
        paths=paths,
        store=store,
        kernel=kernel,
        adapter=adapter,
        bridge=bridge,
        expected_module_root=Path(cct_agent.__file__).resolve().parents[1],
        expected_package_version=cct_agent.__version__,
    )
    gate.wait(timeout=10)
    try:
        output.put(wake.run_once()["status"])
    except BaseException as error:
        output.put(f"ERROR:{type(error).__name__}:{error}")


def test_two_process_wakes_converge_on_one_recovery(tmp_path: Path) -> None:
    fixture = initialize(tmp_path)
    write_target(fixture["paths"], "001-target.json", signed_target())
    context = multiprocessing.get_context("fork")
    gate = context.Event()
    output = context.Queue()
    workers = [
        context.Process(target=_concurrent_worker, args=(str(tmp_path), gate, output))
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    gate.set()
    for worker in workers:
        worker.join(timeout=30)
        assert worker.exitcode == 0
    statuses = sorted(output.get(timeout=5) for _ in workers)

    assert statuses == ["no-target", "verified-live"]
    assert fixture["adapter"].calls == {
        "rollback": 1,
        "rebuild": 1,
        "verify": 1,
        "redeploy": 1,
    }
    assert len(fixture["store"].events("release.recovery.completed")) == 1
    assert fixture["store"].verify_chain()["valid"] is True
