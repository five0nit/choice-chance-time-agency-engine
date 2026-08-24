from __future__ import annotations

from hashlib import sha256
import multiprocessing
import os
from pathlib import Path
import stat
from typing import Any

import pytest

from cct_agent.patching import (
    ExpectedHashPatchAdapter,
    PatchDenied,
    PatchRequest,
    PatchTarget,
    PatchVerification,
)
from cct_agent.store import EventStore, canonical_json


BEFORE = b"enabled = false\n"
AFTER = b"enabled = true\n"
PATCH_SENTINEL = "PATCH_PRIVATE_SENTINEL_59d91_not_for_ledger"


def digest(value: bytes) -> str:
    return sha256(value).hexdigest()


def passing_verifier(_path: Path) -> PatchVerification:
    return PatchVerification(passed=True, code="TESTS_PASSED")


def adapter_for(
    tmp_path: Path,
    *,
    verifier: Any = passing_verifier,
    target_path: str = "config/settings.txt",
) -> tuple[ExpectedHashPatchAdapter, EventStore, Path, Path]:
    workspace = tmp_path / "workspace"
    target = workspace / target_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(BEFORE)
    state_root = tmp_path / "patch-state"
    store = EventStore(tmp_path / "patch.sqlite")
    adapter = ExpectedHashPatchAdapter(
        store,
        workspace_root=workspace,
        state_root=state_root,
        targets=(
            PatchTarget(
                id="settings-target",
                relative_path=target_path,
                verifier_id="fixture-verifier",
                max_bytes=4096,
            ),
        ),
        verifiers={"fixture-verifier": verifier},
    )
    return adapter, store, target, state_root


def request(*, request_id: str = "patch-request-1", replacement: bytes = AFTER) -> PatchRequest:
    return PatchRequest(
        id=request_id,
        target_id="settings-target",
        expected_before_sha256=digest(BEFORE),
        replacement=replacement,
    )


def test_expected_hash_patch_verifies_once_and_persists_hash_only_receipts(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    def verifier(path: Path) -> PatchVerification:
        calls.append(path.read_text())
        return PatchVerification(passed=True, code="TESTS_PASSED")

    adapter, store, target, state_root = adapter_for(tmp_path, verifier=verifier)
    first = adapter.apply(request(replacement=AFTER + PATCH_SENTINEL.encode()))
    inode_after_first = target.stat().st_ino
    replay = adapter.apply(request(replacement=AFTER + PATCH_SENTINEL.encode()))

    expected_after = AFTER + PATCH_SENTINEL.encode()
    assert target.read_bytes() == expected_after
    assert calls == [expected_after.decode()]
    assert first.status == "verified"
    assert first.stage_eligible is True
    assert first.replayed is False
    assert first.before_sha256 == digest(BEFORE)
    assert first.after_sha256 == digest(expected_after)
    assert first.verification_code == "TESTS_PASSED"
    assert first.backup_retained is True
    assert replay.status == "verified"
    assert replay.stage_eligible is True
    assert replay.replayed is True
    assert replay.terminal_event_id == first.terminal_event_id
    assert target.stat().st_ino == inode_after_first
    assert adapter.require_verified(first.request_id).terminal_event_id == first.terminal_event_id

    claims = store.events("patch.operation.claimed")
    backups = store.events("patch.backup.recorded")
    applied = store.events("patch.operation.applied")
    verifications = store.events("patch.verification.recorded")
    verified = store.events("patch.operation.verified")
    assert [len(rows) for rows in (claims, backups, applied, verifications, verified)] == [1, 1, 1, 1, 1]
    persisted = canonical_json([event.payload for event in store.events()])
    assert PATCH_SENTINEL not in persisted
    assert BEFORE.decode().strip() not in persisted
    assert '"replacement"' not in persisted
    assert store.verify_chain()["valid"] is True
    backup_files = [path for path in state_root.iterdir() if path.name.endswith(".bak")]
    assert len(backup_files) == 1
    assert backup_files[0].read_bytes() == BEFORE
    assert stat.S_IMODE(backup_files[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(state_root.stat().st_mode) == 0o700


def test_registered_verifier_failure_restores_exact_before_bytes_and_blocks_stage(
    tmp_path: Path,
) -> None:
    def failing_verifier(path: Path) -> PatchVerification:
        assert path.read_bytes() == AFTER
        return PatchVerification(passed=False, code="TESTS_FAILED")

    adapter, store, target, state_root = adapter_for(tmp_path, verifier=failing_verifier)
    result = adapter.apply(request())
    replay = adapter.apply(request())

    assert target.read_bytes() == BEFORE
    assert result.status == "rolled_back"
    assert result.stage_eligible is False
    assert result.verification_code == "TESTS_FAILED"
    assert result.current_sha256 == digest(BEFORE)
    assert result.backup_retained is False
    assert replay.status == "rolled_back"
    assert replay.replayed is True
    with pytest.raises(PatchDenied, match="PATCH_NOT_VERIFIED"):
        adapter.require_verified(result.request_id)
    assert len(store.events("patch.rollback.completed")) == 1
    assert not [path for path in state_root.iterdir() if path.name.endswith(".bak")]


def test_foreign_mutation_during_verification_is_not_clobbered_and_blocks_stage(
    tmp_path: Path,
) -> None:
    foreign = b"foreign writer won\n"

    def mutating_verifier(path: Path) -> PatchVerification:
        assert path.read_bytes() == AFTER
        path.write_bytes(foreign)
        return PatchVerification(passed=False, code="TESTS_FAILED")

    adapter, store, target, _state_root = adapter_for(tmp_path, verifier=mutating_verifier)
    result = adapter.apply(request())

    assert target.read_bytes() == foreign
    assert result.status == "rollback_blocked"
    assert result.stage_eligible is False
    assert result.current_sha256 == digest(foreign)
    assert result.verification_code == "FOREIGN_MUTATION"
    assert len(store.events("patch.rollback.blocked")) == 1
    assert not store.events("patch.rollback.completed")
    with pytest.raises(PatchDenied, match="PATCH_NOT_VERIFIED"):
        adapter.require_verified(result.request_id)


def test_explicit_rollback_restores_exact_bytes_and_foreign_change_blocks_rollback(
    tmp_path: Path,
) -> None:
    adapter, store, target, _state_root = adapter_for(tmp_path)
    applied = adapter.apply(request(request_id="explicit-rollback"))

    rolled_back = adapter.rollback(applied.request_id)
    assert target.read_bytes() == BEFORE
    assert rolled_back.status == "rolled_back"
    assert rolled_back.stage_eligible is False
    assert adapter.rollback(applied.request_id).replayed is True

    second = request(request_id="foreign-after-success")
    verified = adapter.apply(second)
    foreign = b"post-write foreign mutation\n"
    target.write_bytes(foreign)

    with pytest.raises(PatchDenied, match="PATCH_TARGET_CHANGED"):
        adapter.require_verified(verified.request_id)
    blocked = adapter.rollback(verified.request_id)
    assert blocked.status == "rollback_blocked"
    assert blocked.stage_eligible is False
    assert target.read_bytes() == foreign
    assert len(store.events("patch.rollback.blocked")) == 1


def test_expected_hash_mismatch_denies_before_backup_write_or_verifier(
    tmp_path: Path,
) -> None:
    called = False

    def verifier(_path: Path) -> PatchVerification:
        nonlocal called
        called = True
        return PatchVerification(passed=True, code="IMPOSSIBLE")

    adapter, store, target, state_root = adapter_for(tmp_path, verifier=verifier)
    bad_request = PatchRequest(
        id="wrong-before-hash",
        target_id="settings-target",
        expected_before_sha256=digest(b"other"),
        replacement=AFTER,
    )

    with pytest.raises(PatchDenied, match="EXPECTED_BEFORE_HASH_MISMATCH"):
        adapter.apply(bad_request)

    assert target.read_bytes() == BEFORE
    assert called is False
    assert len(store.events("patch.operation.claimed")) == 1
    assert not store.events("patch.backup.recorded")
    assert not [path for path in state_root.iterdir() if path.name.endswith(".bak")]


def test_symlink_escape_hardlink_and_unsafe_target_paths_fail_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    store = EventStore(tmp_path / "unsafe.sqlite")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(BEFORE)
    (workspace / "escape.txt").symlink_to(outside)

    def build(relative_path: str) -> ExpectedHashPatchAdapter:
        return ExpectedHashPatchAdapter(
            store,
            workspace_root=workspace,
            state_root=state_root,
            targets=(
                PatchTarget(
                    id="target",
                    relative_path=relative_path,
                    verifier_id="verify",
                    max_bytes=4096,
                ),
            ),
            verifiers={"verify": passing_verifier},
        )

    with pytest.raises(PatchDenied, match="TARGET_SYMLINK_DENIED"):
        build("escape.txt").apply(
            PatchRequest(
                id="symlink-request",
                target_id="target",
                expected_before_sha256=digest(BEFORE),
                replacement=AFTER,
            )
        )
    assert outside.read_bytes() == BEFORE

    hardlink = workspace / "hardlink.txt"
    os.link(outside, hardlink)
    with pytest.raises(PatchDenied, match="TARGET_LINK_COUNT_DENIED"):
        build("hardlink.txt").apply(
            PatchRequest(
                id="hardlink-request",
                target_id="target",
                expected_before_sha256=digest(BEFORE),
                replacement=AFTER,
            )
        )
    assert outside.read_bytes() == BEFORE

    for unsafe in ("../outside.txt", "/tmp/outside.txt", "a//b", "a/./b", "a\\b"):
        with pytest.raises(ValueError, match="relative path"):
            PatchTarget(
                id="unsafe",
                relative_path=unsafe,
                verifier_id="verify",
                max_bytes=4096,
            )


def test_crash_after_atomic_write_is_adopted_without_second_file_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter, store, target, _state_root = adapter_for(tmp_path)
    original_record = adapter._record_applied

    def crash_before_receipt(*args: Any, **kwargs: Any) -> Any:
        raise SystemExit("simulated crash after atomic write")

    monkeypatch.setattr(adapter, "_record_applied", crash_before_receipt)
    with pytest.raises(SystemExit, match="simulated crash"):
        adapter.apply(request(request_id="write-crash"))
    inode_after_crash = target.stat().st_ino
    assert target.read_bytes() == AFTER
    assert not store.events("patch.operation.applied")

    monkeypatch.setattr(adapter, "_record_applied", original_record)
    recovered = adapter.apply(request(request_id="write-crash"))

    assert recovered.status == "verified"
    assert recovered.replayed is True
    assert target.read_bytes() == AFTER
    assert target.stat().st_ino == inode_after_crash
    assert len(store.events("patch.operation.applied")) == 1
    assert len(store.events("patch.operation.verified")) == 1


def _concurrent_patch_worker(
    store_path: str,
    workspace_path: str,
    state_path: str,
    barrier: Any,
    queue: Any,
) -> None:
    adapter = ExpectedHashPatchAdapter(
        EventStore(store_path),
        workspace_root=workspace_path,
        state_root=state_path,
        targets=(
            PatchTarget(
                id="settings-target",
                relative_path="config/settings.txt",
                verifier_id="fixture-verifier",
                max_bytes=4096,
            ),
        ),
        verifiers={"fixture-verifier": passing_verifier},
    )
    barrier.wait()
    try:
        result = adapter.apply(request(request_id="concurrent-patch"))
    except PatchDenied as error:
        queue.put(error.reason_code)
    else:
        queue.put("REPLAY" if result.replayed else "APPLIED")


def test_concurrent_patch_requests_produce_one_verified_effect_receipt(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    target = workspace / "config" / "settings.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(BEFORE)
    state_root = tmp_path / "state"
    store_path = tmp_path / "concurrent.sqlite"
    EventStore(store_path)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(4)
    queue = context.Queue()
    workers = [
        context.Process(
            target=_concurrent_patch_worker,
            args=(str(store_path), str(workspace), str(state_root), barrier, queue),
        )
        for _ in range(4)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0
    results = [queue.get(timeout=2) for _ in workers]

    assert results.count("APPLIED") == 1
    assert set(results) <= {"APPLIED", "REPLAY"}
    assert target.read_bytes() == AFTER
    store = EventStore(store_path)
    assert len(store.events("patch.operation.claimed")) == 1
    assert len(store.events("patch.operation.applied")) == 1
    assert len(store.events("patch.operation.verified")) == 1
    assert store.verify_chain()["valid"] is True


@pytest.mark.parametrize(
    "factory",
    [
        lambda: PatchRequest(
            id="bad id",
            target_id="target",
            expected_before_sha256=digest(BEFORE),
            replacement=AFTER,
        ),
        lambda: PatchRequest(
            id="request",
            target_id="target",
            expected_before_sha256="BAD",
            replacement=AFTER,
        ),
        lambda: PatchRequest(
            id="request",
            target_id="target",
            expected_before_sha256=digest(BEFORE),
            replacement="text",  # type: ignore[arg-type]
        ),
        lambda: PatchTarget(
            id="target",
            relative_path="file.txt",
            verifier_id="verify",
            max_bytes=True,  # type: ignore[arg-type]
        ),
        lambda: PatchVerification(passed=1, code="BAD"),  # type: ignore[arg-type]
        lambda: PatchVerification(passed=True, code="bad code"),
    ],
)
def test_patch_schemas_reject_malformed_values(factory: Any) -> None:
    with pytest.raises(ValueError):
        factory()
