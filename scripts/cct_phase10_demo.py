#!/usr/bin/env python3
"""Deterministic public acceptance episode for CCT Phase 10."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cct_agent import (  # noqa: E402
    AgencyKernel,
    AutonomyEngine,
    EventStore,
    Opportunity,
    default_constitution,
)


def digest(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def candidate(
    identifier: str,
    *,
    plan: dict,
    capability: str,
    competence: float,
    information_gain: float = 0.4,
    uncertainty: float = 0.05,
) -> Opportunity:
    return Opportunity(
        id=identifier,
        title=identifier.replace("-", " ").title(),
        rationale="Produce falsifiable local evidence through the hard authority boundary.",
        objective=f"Complete and independently verify {identifier}.",
        source="host_adapter:phase10-demo",
        source_authority="host_adapter",
        value_impacts={
            "truth": min(1.0, competence + 0.05),
            "competence": competence,
            "autonomy": min(1.0, competence),
            "care": 0.2,
        },
        plan=plan,
        evidence=(f"demo://phase10/{identifier}",),
        information_gain=information_gain,
        uncertainty=uncertainty,
        time_cost=0.1,
        capability=capability,
    )


def simple_plan(path: str, content: str) -> dict:
    expected = digest(content)
    return {
        "steps": [
            {
                "id": "write-artifact",
                "title": f"Write {path}",
                "action": {"kind": "write_text", "path": path, "content": content},
                "preconditions": [{"kind": "path_absent", "path": path}],
                "verify": [{"kind": "sha256_equals", "path": path, "sha256": expected}],
            }
        ],
        "final_verify": [{"kind": "sha256_equals", "path": path, "sha256": expected}],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a clean CCT Phase 10 acceptance episode")
    parser.add_argument("--db", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--state-root", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    if any(workspace.iterdir()):
        raise ValueError("phase10 demo requires an empty workspace")
    store = EventStore(args.db)
    if store.count() != 0:
        raise ValueError("phase10 demo requires an empty event store")
    kernel = AgencyKernel(store, default_constitution("phase10-public-demo"))
    kernel.initialize()
    engine = AutonomyEngine(store, kernel, workspace, state_root=args.state_root)

    # Local state supplies the opportunity signal. No fresh task-specific model prompt.
    collision = workspace / "occupied.md"
    collision.write_text("pre-existing local state\n", encoding="utf-8")
    recovered_content = "# Phase 10 recovered artifact\n\nPrimary path conflicted; fallback verified.\n"
    risky_plan = {
        "steps": [
            {
                "id": "produce-evidence",
                "title": "Produce a verified evidence artifact",
                "action": {
                    "kind": "write_text",
                    "path": "occupied.md",
                    "content": "primary should not overwrite\n",
                },
                "preconditions": [{"kind": "path_absent", "path": "occupied.md"}],
                "verify": [
                    {
                        "kind": "sha256_equals",
                        "path": "occupied.md",
                        "sha256": digest("primary should not overwrite\n"),
                    }
                ],
                "fallback": {
                    "action": {
                        "kind": "write_text",
                        "path": "recovered.md",
                        "content": recovered_content,
                    },
                    "preconditions": [{"kind": "path_absent", "path": "recovered.md"}],
                    "verify": [
                        {
                            "kind": "sha256_equals",
                            "path": "recovered.md",
                            "sha256": digest(recovered_content),
                        }
                    ],
                },
            }
        ],
        "final_verify": [
            {
                "kind": "sha256_equals",
                "path": "recovered.md",
                "sha256": digest(recovered_content),
            }
        ],
    }
    engine.register_opportunity(
        candidate(
            "fragile-first",
            plan=risky_plan,
            capability="fragile_local_write",
            competence=0.86,
            information_gain=0.8,
        )
    )
    stable_content = "# Stable artifact\n\nSelected after temporal capability learning.\n"
    engine.register_opportunity(
        candidate(
            "stable-first",
            plan=simple_plan("stable.md", stable_content),
            capability="stable_local_write",
            competence=0.82,
        )
    )
    first_run = engine.run_once(
        seed=0,
        run_id="phase10-first-run",
        decision_id="phase10-first-choice",
    )
    if not first_run["success"] or first_run["opportunity_id"] != "fragile-first":
        raise RuntimeError("first capability episode did not select and recover the fragile plan")

    engine.register_opportunity(
        candidate(
            "fragile-next",
            plan=simple_plan("fragile-next.md", "fragile next\n"),
            capability="fragile_local_write",
            competence=0.86,
            information_gain=0.8,
        )
    )
    second_choice = engine.select_opportunity(seed=0, decision_id="phase10-learned-choice")
    if second_choice["opportunity_id"] != "stable-first":
        raise RuntimeError("realized recovery evidence did not change the later portfolio choice")
    second_run = engine.run_once(
        seed=0,
        run_id="phase10-second-run",
        decision_id="phase10-second-execution-choice",
    )
    if not second_run["success"] or second_run["opportunity_id"] != "stable-first":
        raise RuntimeError("learned stable opportunity did not complete")

    rollback_content = "temporary mutation must disappear\n"
    rollback_plan = {
        "steps": [
            {
                "id": "temporary-write",
                "action": {
                    "kind": "write_text",
                    "path": "rollback-temp.md",
                    "content": rollback_content,
                },
                "verify": [
                    {
                        "kind": "sha256_equals",
                        "path": "rollback-temp.md",
                        "sha256": digest(rollback_content),
                    }
                ],
            },
            {
                "id": "controlled-terminal-failure",
                "depends_on": ["temporary-write"],
                "action": {
                    "kind": "write_text",
                    "path": "occupied.md",
                    "content": "must not replace\n",
                },
                "preconditions": [{"kind": "path_absent", "path": "occupied.md"}],
                "verify": [
                    {
                        "kind": "sha256_equals",
                        "path": "occupied.md",
                        "sha256": digest("must not replace\n"),
                    }
                ],
            },
        ],
        "final_verify": [{"kind": "path_exists", "path": "rollback-temp.md"}],
    }
    engine.register_opportunity(
        candidate(
            "rollback-drill",
            plan=rollback_plan,
            capability="rollback_probe",
            competence=1.0,
            information_gain=1.0,
            uncertainty=0.0,
        )
    )
    rollback_run = engine.run_once(
        seed=0,
        run_id="phase10-rollback-run",
        decision_id="phase10-rollback-choice",
    )
    if rollback_run["success"] or not rollback_run["rollback_complete"]:
        raise RuntimeError("rollback drill did not fail closed and restore prior state")

    recovered = (workspace / "recovered.md").read_bytes()
    stable = (workspace / "stable.md").read_bytes()
    rollback_absent = not (workspace / "rollback-temp.md").exists()
    occupied_unchanged = collision.read_text(encoding="utf-8") == "pre-existing local state\n"
    event_material = "\n".join(
        json.dumps(event.payload, sort_keys=True) for event in store.events()
    )
    forbidden_content_found = any(
        marker in event_material
        for marker in (recovered_content, stable_content, rollback_content)
    )
    status = engine.status()
    result = {
        "claim": (
            "A persistent capability-first loop independently selected reversible local work, "
            "replanned after a controlled failure, verified useful artifacts, linked outcomes, "
            "changed a later choice from realized evidence, and proved rollback."
        ),
        "first_run": first_run,
        "learned_second_choice": {
            "opportunity_id": second_choice["opportunity_id"],
            "fragile_learning": second_choice["learning"]["fragile-next"],
        },
        "second_run": second_run,
        "rollback_run": rollback_run,
        "verification": {
            "recovered_sha256": sha256(recovered).hexdigest(),
            "recovered_expected": digest(recovered_content),
            "stable_sha256": sha256(stable).hexdigest(),
            "stable_expected": digest(stable_content),
            "rollback_temp_absent": rollback_absent,
            "occupied_input_unchanged": occupied_unchanged,
            "plan_content_found_in_event_ledger": forbidden_content_found,
        },
        "status": status,
        "event_kinds": sorted({event.kind for event in store.events()}),
        "chain": store.verify_chain(),
    }
    if not all(
        (
            result["verification"]["recovered_sha256"] == result["verification"]["recovered_expected"],
            result["verification"]["stable_sha256"] == result["verification"]["stable_expected"],
            rollback_absent,
            occupied_unchanged,
            not forbidden_content_found,
            result["chain"]["valid"],
        )
    ):
        raise RuntimeError("phase10 independent verification failed")
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
