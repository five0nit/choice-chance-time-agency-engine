"""External post-reload verifier for Generalist2 CCT release activation.

Runs in a transient user-systemd unit outside gateway cgroup. On failure, restores
only service drop-in and scheduler wrappers, reloads only Generalist2, and never
restores SQLite state.
"""

from __future__ import annotations

import argparse
from dataclasses import fields
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
from typing import Any

from .release_host import (
    ReleaseActivationSpec,
    _LOADER_PROBE,
    _atomic_bytes,
    _atomic_json,
)


def _run(*args: str, check: bool = True, env: dict[str, str] | None = None, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=check,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


def _pid(service: str) -> int:
    result = _run(
        "systemctl", "--user", "show", service, "-p", "MainPID", "--value"
    )
    return int(result.stdout.strip() or "0")


def _copy(source: Path, destination: Path, mode: int) -> None:
    metadata = source.lstat()
    if (
        not source.is_file()
        or source.is_symlink()
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise OSError("release rollback source is unsafe")
    _atomic_bytes(destination, source.read_bytes(), mode)


def _restore(spec: ReleaseActivationSpec) -> list[str]:
    if spec.phase == "rollback":
        # Never restore the authenticated mismatched prestate over the selected
        # known-good rollback target. Keep target config in place for inspection.
        return ["known-good rollback target retained after verifier failure"]
    errors: list[str] = []
    for source, destination, mode in (
        (Path(spec.backup_dropin_path), Path(spec.dropin_path), 0o644),
        (Path(spec.backup_team_wrapper_path), Path(spec.team_wrapper_path), 0o700),
        (
            Path(spec.backup_proactive_wrapper_path),
            Path(spec.proactive_wrapper_path),
            0o700,
        ),
    ):
        try:
            _copy(source, destination, mode)
        except OSError as error:
            errors.append(f"{type(error).__name__}: {error}"[:500])
    try:
        _run("systemctl", "--user", "daemon-reload")
        _run("systemctl", "--user", "reload", spec.service_name, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        errors.append(f"{type(error).__name__}: {error}"[:500])
    return errors


def _load_spec(path: Path) -> ReleaseActivationSpec:
    raw = json.loads(path.read_text(encoding="utf-8"))
    allowed = {field.name for field in fields(ReleaseActivationSpec)}
    if not isinstance(raw, dict) or set(raw) != allowed:
        raise RuntimeError("activation spec schema mismatch")
    if isinstance(raw.get("unrelated_services"), list):
        raw["unrelated_services"] = tuple(raw["unrelated_services"])
    return ReleaseActivationSpec(**raw)


def verify(spec: ReleaseActivationSpec) -> dict[str, Any]:
    unrelated_before = {service: _pid(service) for service in spec.unrelated_services}
    if any(pid <= 0 for pid in unrelated_before.values()):
        raise RuntimeError("unrelated service inactive before verification")
    deadline = time.monotonic() + 1200
    new_pid = 0
    while time.monotonic() < deadline:
        current = _pid(spec.service_name)
        if current > 0 and current != spec.old_pid:
            new_pid = current
            break
        time.sleep(0.25)
    if not new_pid:
        raise RuntimeError("new Generalist2 PID not observed")
    expected_pythonpath = f"{spec.release_root}/bootstrap:{spec.module_root}"
    process_environment = Path(f"/proc/{new_pid}/environ").read_bytes().split(b"\0")
    if f"PYTHONPATH={expected_pythonpath}".encode("utf-8") not in process_environment:
        raise RuntimeError("live PYTHONPATH mismatch")
    with sqlite3.connect(f"file:{spec.database_path}?mode=ro", uri=True) as connection:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RuntimeError("SQLite quick_check failed")
    home = Path(spec.receipt_path).parent / "post-reload-home"
    home.mkdir(mode=0o700, exist_ok=True)
    environment = {
        "HOME": os.environ.get("HOME", str(Path(spec.profile_root).parent)),
        "HERMES_HOME": spec.profile_root,
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": expected_pythonpath,
        "PYTHONNOUSERSITE": "1",
        "CCT_IDENTITY": "Generalist2-CCT",
    }
    loaded = json.loads(
        _run(
            spec.python_executable,
            "-P",
            "-c",
            _LOADER_PROBE,
            env=environment,
            timeout=300,
        ).stdout
    )
    expected = {
        "version": spec.version,
        "plugin_version": spec.version,
        "module_root": spec.module_root,
        "entrypoint_value": "hermes_plugin",
        "loaded_type": "module",
        "tools": spec.expected_tools,
        "hooks": spec.expected_hooks,
        "middleware": spec.expected_middleware,
        "chain_valid": True,
    }
    if loaded != expected:
        raise RuntimeError(f"loader mismatch: {loaded}")
    unrelated_after = {service: _pid(service) for service in spec.unrelated_services}
    if unrelated_after != unrelated_before:
        raise RuntimeError("unrelated service PID changed")
    return {
        "status": "VERIFIED",
        "phase": spec.phase,
        "recovery_id": spec.recovery_id,
        "old_pid": spec.old_pid,
        "new_pid": new_pid,
        "version": spec.version,
        "source_commit": spec.source_commit,
        "wheel_sha256": spec.wheel_sha256,
        "module_root": spec.module_root,
        "loader": loaded,
        "unrelated_pids": unrelated_after,
        "database_restored": False,
        "recorded_at": datetime.now(UTC).isoformat(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    args = parser.parse_args(argv)
    path = Path(args.spec)
    spec: ReleaseActivationSpec | None = None
    receipt_path: Path | None = None
    try:
        spec = _load_spec(path)
        receipt_path = Path(spec.receipt_path)
        result = verify(spec)
        _atomic_json(receipt_path, result)
        return 0
    except Exception as error:
        rollback_errors: list[str] = []
        try:
            if spec is not None:
                rollback_errors = _restore(spec)
        except Exception as rollback_error:
            rollback_errors.append(
                f"{type(rollback_error).__name__}: {rollback_error}"[:500]
            )
        if receipt_path is None:
            receipt_path = path.with_name("post-reload.json")
        _atomic_json(
            receipt_path,
            {
                "status": "ROLLED_BACK" if not rollback_errors else "ROLLBACK_INCOMPLETE",
                "phase": spec.phase if spec is not None else None,
                "recovery_id": spec.recovery_id if spec is not None else None,
                "old_pid": spec.old_pid if spec is not None else None,
                "version": spec.version if spec is not None else None,
                "source_commit": spec.source_commit if spec is not None else None,
                "wheel_sha256": spec.wheel_sha256 if spec is not None else None,
                "module_root": spec.module_root if spec is not None else None,
                "reason": f"{type(error).__name__}: {error}"[:1200],
                "rollback_errors": rollback_errors,
                "database_restored": False,
                "recorded_at": datetime.now(UTC).isoformat(),
            },
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
