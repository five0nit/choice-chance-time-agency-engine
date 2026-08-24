#!/usr/bin/env python3
"""Run one host-bounded CCT autonomy wake.

A private, profile-owned artifact adapter file may describe missing local artifacts. The
runner converts only that narrow schema into typed ``write_text`` opportunities; it never
accepts commands, deletes, arbitrary action kinds, or paths outside the autonomy workspace.
NO_OP stays silent in ``--message-only`` mode.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cct_agent import AgencyKernel, AutonomyEngine, EventStore, resolve_constitution  # noqa: E402

_MAX_ADAPTER_BYTES = 65_536
_MAX_ADAPTERS = 16
_ALLOWED_ADAPTER_FIELDS = {
    "opportunity_id",
    "relative_path",
    "content",
    "title",
    "rationale",
    "objective",
    "value_impacts",
    "evidence",
    "information_gain",
    "uncertainty",
    "time_cost",
    "capability",
}
_REQUIRED_ADAPTER_FIELDS = {
    "opportunity_id",
    "relative_path",
    "content",
    "title",
    "rationale",
    "objective",
    "value_impacts",
}


def build_parser() -> argparse.ArgumentParser:
    home = Path(os.getenv("HERMES_HOME", str(Path.home() / ".hermes")))
    state_root = home / "cct-agency" / "autonomy"
    parser = argparse.ArgumentParser(description="Run one CCT capability-first autonomy wake")
    parser.add_argument("--db", default=str(home / "cct-agency" / "agency.sqlite"))
    parser.add_argument("--workspace", default=str(home / "cct-agency" / "workspace"))
    parser.add_argument("--state-root", default=str(state_root))
    parser.add_argument(
        "--adapter-file",
        default=None,
        help="Private host-owned artifact adapter file under --state-root",
    )
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--decision-id")
    parser.add_argument("--message-only", action="store_true")
    return parser


def load_private_adapters(
    path: Path, state_root: Path, *, pinned_root_fd: int | None = None
) -> list[dict[str, Any]]:
    lexical_root = state_root.absolute()
    lexical_path = path.absolute()
    try:
        relative = lexical_path.relative_to(lexical_root)
    except ValueError as exc:
        raise ValueError("adapter file must remain under state root") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("adapter file path is invalid")
    open_directory = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if pinned_root_fd is not None:
        directory_fd = os.dup(pinned_root_fd)
    else:
        resolved_root = state_root.resolve(strict=True)
        directory_fd = os.open(resolved_root, open_directory)
        if not os.path.samestat(
            os.fstat(directory_fd), os.stat(resolved_root, follow_symlinks=False)
        ):
            os.close(directory_fd)
            raise ValueError("adapter state root identity changed while opening")
    file_fd: int | None = None
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(component, open_directory, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        try:
            file_fd = os.open(
                relative.parts[-1],
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return []
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("adapter file must be a single-link regular file")
        if metadata.st_uid != os.geteuid():
            raise ValueError("adapter file must be owned by the current user")
        if metadata.st_mode & 0o077:
            raise ValueError("adapter file must not be group/world accessible")
        if metadata.st_size > _MAX_ADAPTER_BYTES:
            raise ValueError("adapter file exceeds 64 KiB")
        with os.fdopen(file_fd, "rb", closefd=True) as stream:
            file_fd = None
            encoded = stream.read(_MAX_ADAPTER_BYTES + 1)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)
    if len(encoded) > _MAX_ADAPTER_BYTES:
        raise ValueError("adapter file exceeds 64 KiB")
    raw = json.loads(encoded.decode("utf-8"))
    if not isinstance(raw, list) or len(raw) > _MAX_ADAPTERS:
        raise ValueError("adapter file must contain at most 16 objects")
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"adapter {index} must be an object")
        unknown = set(item) - _ALLOWED_ADAPTER_FIELDS
        missing = _REQUIRED_ADAPTER_FIELDS - set(item)
        if unknown or missing:
            raise ValueError(
                f"adapter {index} has unknown={sorted(unknown)} missing={sorted(missing)}"
            )
        text_fields = (
            "opportunity_id",
            "relative_path",
            "content",
            "title",
            "rationale",
            "objective",
        )
        if any(not isinstance(item[field], str) for field in text_fields):
            raise ValueError(f"adapter {index} required text fields must be strings")
        if not isinstance(item["value_impacts"], dict):
            raise ValueError(f"adapter {index} value_impacts must be an object")
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            for value in item["value_impacts"].values()
        ):
            raise ValueError(f"adapter {index} value_impacts values must be numeric")
        evidence = item.get("evidence", [])
        if not isinstance(evidence, list) or any(not isinstance(value, str) for value in evidence):
            raise ValueError(f"adapter {index} evidence must be a string array")
        if "capability" in item and not isinstance(item["capability"], str):
            raise ValueError(f"adapter {index} capability must be a string")
        for field in ("information_gain", "uncertainty", "time_cost"):
            if field in item and (
                isinstance(item[field], bool) or not isinstance(item[field], (int, float))
            ):
                raise ValueError(f"adapter {index} {field} must be numeric")
        rows.append(dict(item))
    return rows


def main() -> int:
    args = build_parser().parse_args()
    state_root = Path(args.state_root)
    state_root.mkdir(parents=True, exist_ok=True)
    store = EventStore(args.db)
    kernel = AgencyKernel(
        store,
        resolve_constitution(store, os.environ.get("CCT_IDENTITY", "CCT-Agent")),
    )
    kernel.initialize()
    engine = AutonomyEngine(store, kernel, args.workspace, state_root=state_root)
    adapter_path = (
        Path(args.adapter_file)
        if args.adapter_file is not None
        else state_root / "artifact-adapters.json"
    )
    observations = []
    pinned_state_fd = engine.duplicate_state_root_fd()
    try:
        adapter_rows = load_private_adapters(
            adapter_path, state_root, pinned_root_fd=pinned_state_fd
        )
    finally:
        os.close(pinned_state_fd)
    for row in adapter_rows:
        observations.append(
            engine.observe_artifact_gap(
                opportunity_id=str(row["opportunity_id"]),
                relative_path=str(row["relative_path"]),
                content=str(row["content"]),
                title=str(row["title"]),
                rationale=str(row["rationale"]),
                objective=str(row["objective"]),
                value_impacts=dict(row["value_impacts"]),
                source=f"private-file:{adapter_path.name}",
                evidence=tuple(str(item) for item in row.get("evidence", [])),
                information_gain=float(row.get("information_gain", 0.4)),
                uncertainty=float(row.get("uncertainty", 0.1)),
                time_cost=float(row.get("time_cost", 0.1)),
                capability=str(row.get("capability", "verified_local_artifact")),
            )
        )
    result = engine.run_once(
        seed=args.seed,
        run_id=args.run_id,
        decision_id=args.decision_id,
    )
    if observations:
        result = {**result, "observations": observations}
    if args.message_only and result.get("chosen_option_id") == "NO_OP":
        return 0
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
