"""Read-only local soak evidence; never drive work or query cloud services.

The observer cannot certify live cloud notification or exactly-once external effects.
It reports saved notification readbacks and local duplicate outcomes separately.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def atomic(path, value):
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(encode(value) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def ledger_snapshot(home, since):
    home = Path(home).resolve()
    db = home / "owner-delivery/delivery.sqlite"
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=5) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN")  # All ledger counts come from one consistent snapshot.
        integrity = conn.execute("PRAGMA quick_check").fetchone()[0]
        previous = "0" * 64
        chain_valid = True
        outcomes = Counter()
        for row in conn.execute("SELECT * FROM events ORDER BY id"):
            value = {"at": row["at"], "kind": row["kind"], "data": json.loads(row["data"]), "previous": row["previous"]}
            chain_valid &= row["previous"] == previous and row["hash"] == digest(value)
            previous = row["hash"]
            if row["kind"] == "OUTCOME":
                outcomes[value["data"].get("jobId")] += 1
        jobs = []
        artifact_base = (home / "owner-delivery/artifacts").resolve()
        for row in conn.execute("SELECT payload FROM jobs ORDER BY created,id"):
            j = json.loads(row[0])
            manifest = j.get("execution", {}).get("manifest", [])
            checks = []
            for entry in manifest:
                root = Path(j.get("artifactRoot", ""))
                path = root / entry["path"]
                safe = (not path.is_symlink() and path.resolve().is_relative_to(artifact_base)
                        and path.is_file() and path.stat().st_size <= 2000000)
                checks.append(safe and hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"])
            notification = j.get("notification", {})
            jobs.append({"id": j["id"], "created": j["created"], "phase": j["phase"],
                         "fresh": j["created"] >= since,
                         "artifactVerifiedNow": bool(checks) and all(checks),
                         "savedTestsPassed": j.get("verification", {}).get("status") == "passed",
                         "savedAcceptanceReview": j.get("review", {}).get("accepted") is True,
                         "savedNotificationReadback": notification.get("readVerified") is True,
                         "notificationId": notification.get("messageId"),
                         "nextActionPresent": bool(j.get("nextAction")),
                         "attempts": j.get("attempts"),
                         "outcomeCount": outcomes[j["id"]]})
        counts = {name: conn.execute("SELECT count(*) FROM " + name).fetchone()[0]
                  for name in ("jobs", "events", "attempts", "tool_attempts", "continuation_cycles")}
        cycles = [{"id": r["id"], "state": r["state"], "created": r["created"]}
                  for r in conn.execute("SELECT id,state,created FROM continuation_cycles ORDER BY created DESC LIMIT 3")]
    return {"integrity": integrity, "chainValid": bool(chain_valid), "counts": counts, "jobs": jobs,
            "cycles": cycles, "duplicateLocalOutcomes": sum(max(0, n - 1) for n in outcomes.values()),
            "notificationScope": "saved cloud-document readback, not current remote or Telegram delivery"}


def service_snapshot(units):
    result = {}
    for unit in units:
        p = subprocess.run(["systemctl", "--user", "show", unit, "-p", "ActiveState", "-p", "SubState",
                            "-p", "MainPID", "-p", "NRestarts"], capture_output=True, text=True, timeout=10)
        values = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
        result[unit] = {"queryExit": p.returncode, **values}
    return result


def run(config, now=None, services=None):
    now = time.time() if now is None else now
    directory = Path(config["stateDirectory"])
    if directory.is_symlink():
        raise ValueError("OBSERVER_STATE_SYMLINK")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    fd = os.open(directory / "observer.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        statepath = directory / "state.json"
        state = json.loads(statepath.read_text()) if statepath.exists() else {"samples": 0, "lastNotice": 0, "closed": False}
        binding = digest(config)
        if state.get("binding", binding) != binding:
            raise ValueError("OBSERVER_CONFIG_CHANGED")
        if state["closed"]:
            return ""
        snapshot: dict = {"at": datetime.fromtimestamp(now, timezone.utc).isoformat(), "source": "local-read-only-observer"}
        try:
            snapshot["ledger"] = ledger_snapshot(config["home"], config["startedAt"])
            snapshot["services"] = service_snapshot(config["units"]) if services is None else services
            ledger = snapshot["ledger"]
            bad = ledger["integrity"] != "ok" or not ledger["chainValid"] or ledger["duplicateLocalOutcomes"] != 0
            bad |= any(j["phase"] == "COMPLETE" and not j["artifactVerifiedNow"] for j in ledger["jobs"])
            bad |= any(v.get("ActiveState") != "active" for v in snapshot["services"].values())
            snapshot["circuits"] = {}
            for configured in config.get("circuitFiles", []):
                path = Path(configured)
                circuit = json.loads(path.read_text()) if path.exists() else {"status": "UNOBSERVED"}
                snapshot["circuits"][str(path)] = circuit
                bad |= circuit.get("status") not in {"CLOSED", "UNOBSERVED"}
            fresh = [j["id"] for j in ledger["jobs"] if j["fresh"] and j["phase"] == "COMPLETE"
                     and j["artifactVerifiedNow"] and j["savedTestsPassed"] and j["savedAcceptanceReview"]
                     and j["savedNotificationReadback"]]
            snapshot.update(health="FAILURE" if bad else "LOCAL_CHECKS_OK", freshVerifiedJobs=fresh)
        except Exception as error:
            snapshot.update(health="OBSERVER_ERROR", errorType=type(error).__name__, freshVerifiedJobs=[])
        sequence = state["samples"] + 1
        snapshot["sequence"] = sequence
        atomic(directory / ("sample-%05d.json" % sequence), snapshot)
        expired = now >= config["endsAt"]
        changed = snapshot["health"] != state.get("health") or snapshot["freshVerifiedJobs"] != state.get("freshVerifiedJobs", [])
        notify = expired or changed or now - state["lastNotice"] >= 86400
        state.update(binding=binding, samples=sequence, health=snapshot["health"],
                     freshVerifiedJobs=snapshot["freshVerifiedJobs"], closed=expired,
                     lastNotice=now if notify else state["lastNotice"])
        atomic(statepath, state)
        if not notify:
            return ""
        label = "window ended" if expired else "running"
        # A healthy read-only sample does not establish productive autonomy.
        return (f"CCT reliability trial {label}: {sequence} local samples; {snapshot['health']}; "
                f"{len(snapshot['freshVerifiedJobs'])} fresh verified deliveries. "
                "Cloud recovery, automatic selection, next-step reasoning and multi-day productivity require separate receipts. "
                f"Evidence: {directory}")
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    config = json.loads(args.config.read_text())
    if not (0 < config["endsAt"] - config["startedAt"] <= 4 * 86400):
        raise ValueError("OBSERVER_WINDOW_INVALID")
    try:
        output = run(config)
    except BlockingIOError:
        return 0
    if output:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
