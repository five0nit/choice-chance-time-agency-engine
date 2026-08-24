#!/usr/bin/env python3
"""Emit at most one proactive message; empty stdout means scheduler silence."""

from __future__ import annotations

from datetime import UTC, datetime
import fcntl
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cct_agent import (  # noqa: E402
    AgencyKernel,
    EventStore,
    ProactiveRunner,
    resolve_constitution,
)


def main() -> int:
    hermes_home = Path(
        os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))
    )
    state_dir = hermes_home / "cct-agency"
    state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = state_dir / "proactive-runner.lock"
    database = state_dir / "agency.sqlite"
    with lock_path.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        store = EventStore(database)
        constitution = resolve_constitution(
            store, os.environ.get("CCT_IDENTITY", "CCT-Agent")
        )
        AgencyKernel(store, constitution).initialize()
        result = ProactiveRunner(store).run_once(
            time_bucket=datetime.now(UTC).date().isoformat()
        )
        message = str(result.get("message", "")).strip()
        if message:
            print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
