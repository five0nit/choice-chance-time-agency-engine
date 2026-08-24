#!/usr/bin/env python3
"""Run one silent model-free team-sync continuity sensor tick."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import fcntl
import json
import os
from pathlib import Path
import stat
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cct_agent import (  # noqa: E402
    AgencyKernel,
    EventStore,
    TeamSyncSensor,
    TeamSyncSensorPolicy,
    resolve_constitution,
)

def _configured_source() -> Path | None:
    configured = os.environ.get("CCT_TEAM_SYNC_SOURCE", "").strip()
    return Path(configured).expanduser() if configured else None


def _projects(config_path: Path) -> tuple[str, ...]:
    if not config_path.exists():
        return ()
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("projects", []), list):
        raise ValueError("team-sync sensor config must contain a projects array")
    projects = raw.get("projects", [])
    if not all(isinstance(project, str) for project in projects):
        raise ValueError("team-sync sensor projects must be strings")
    return tuple(projects)


def _assert_private_regular_state_path(path: Path) -> None:
    if not path.exists():
        return
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"CCT state path must be regular: {path.name}")
    if metadata.st_uid != os.getuid():
        raise ValueError(f"CCT state path must be owned by the sensor uid: {path.name}")
    if metadata.st_nlink != 1:
        raise ValueError(f"CCT state path must not be hardlinked: {path.name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--source", type=Path, default=_configured_source())
    args = parser.parse_args(argv)
    if args.source is None:
        parser.error("--source or CCT_TEAM_SYNC_SOURCE is required")

    hermes_home = Path(
        os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))
    )
    source = args.source.absolute()
    if hermes_home.is_symlink():
        raise ValueError("HERMES_HOME must not be a symlink")
    resolved_home = hermes_home.resolve(strict=True)
    state_dir = hermes_home / "cct-agency"
    if state_dir.is_symlink():
        raise ValueError("CCT state directory must not be a symlink")
    state_dir.mkdir(parents=True, exist_ok=True)
    if state_dir.resolve(strict=True).parent != resolved_home:
        raise ValueError("CCT state directory escaped HERMES_HOME")
    config_path = state_dir / "team-sync-sensor.json"
    lock_path = state_dir / "team-sync-sensor.lock"
    database = state_dir / "agency.sqlite"
    auxiliary_database_paths = tuple(
        database.with_name(f"{database.name}{suffix}")
        for suffix in ("-wal", "-shm", "-journal")
    )
    for candidate in (
        config_path,
        lock_path,
        database,
        *auxiliary_database_paths,
    ):
        if candidate.is_symlink():
            raise ValueError(f"CCT state path must not be a symlink: {candidate.name}")
        _assert_private_regular_state_path(candidate)

    with lock_path.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        policy = TeamSyncSensorPolicy(projects=_projects(config_path))
        store = EventStore(database)
        constitution = resolve_constitution(
            store, os.environ.get("CCT_IDENTITY", "CCT-Agent")
        )
        AgencyKernel(store, constitution).initialize()
        sensor = TeamSyncSensor(
            store,
            constitution,
            source,
            policy=policy,
            trusted_root=source.parent,
        )
        result = sensor.run_once(observed_at=datetime.now(UTC))
        if args.report:
            print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
