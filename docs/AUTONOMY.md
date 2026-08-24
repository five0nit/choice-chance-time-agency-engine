# Capability-first local autonomy

CCT Agency Engine `0.7.0` closes the loop from opportunity to verified local outcome. It does not grant an LLM arbitrary shell, network, deletion, credential, or publication authority.

## Loop

```text
host observation / model proposal
        ↓
append-only opportunity portfolio
        ↓
CCT option scoring + canonical NO_OP + learned reliability
        ↓
hierarchical root objective + per-step milestones
        ↓
hash-bound temporal plan with dependency DAG
        ↓
progressive authority envelope
        ↓
atomic local write → independent hash verification
        ↓
receipt / fallback replan / reverse-order rollback
        ↓
CCT outcome → capability reliability → later portfolio choice
```

## Trust boundary

`Opportunity.source_authority` determines eligibility:

- `host_adapter` — executable after all structural checks.
- `operator` — executable when an authenticated host integration supplies it.
- all other values, including model `self` proposals — persisted but blocked from execution.

The Hermes `cct_opportunity_propose` tool intentionally creates `self` proposals with no executable plan. It requires one active CCT `goal_id` and evidence; the proactive lane suppresses ungrounded self proposals. A host adapter must attach a typed plan through the Python API. `cct_autonomy_run` can only select plans that were already registered by `host_adapter` or `operator` authority.

## Initial effect vocabulary

Only one action exists:

```json
{
  "kind": "write_text",
  "path": "relative/path.md",
  "content": "exact text",
  "allow_replace": false
}
```

Host-side validation rejects:

- absolute paths, `..`, non-normalized paths;
- symlink roots, parents, and targets;
- `.git`, `.env`, credential, wallet, private-key, and key-store names;
- missing or symlinked parent directories;
- action kinds other than `write_text`;
- plans without per-step and final independent verification;
- dependency cycles and unknown dependencies;
- more than 32 plan steps or 262,144 bytes in one action.

There is no command executor, delete, move, network client, browser action, public action, financial action, credential access, package install, or arbitrary import path.

## Plan privacy and provenance

Executable content is stored in a private `0600` JSON file under a disjoint `0700` autonomy state root. The event ledger stores:

- plan SHA-256;
- private plan filename;
- step identifiers;
- dependency edges and topological order;
- durable pre-publish claims and receipts with relative paths, byte counts, content SHA-256, and prepared `(device, inode)` identity.

File content is not copied into event payloads. Plan digest mismatch stops execution.

## Preconditions and verification

Supported checks:

- `path_exists`
- `path_absent`
- `sha256_equals`

Every step requires a branch-local `sha256_equals` verifier for the exact action path and proposed content hash; optional additional verifiers can impose broader conditions. Every executable plan requires final verification. Before completion, receipt-derived checks re-verify the latest executed hash for every affected path, even when caller final checks omit an earlier step. Verification reopens the target and compares exact state. A pre-existing artifact that already satisfies all step verifiers is accepted without rewriting it, but a zero-effect completion earns no capability-learning sample or authority expansion.

## Replanning and rollback

A step may contain one structurally validated fallback branch. Primary failure records `autonomy.plan.replanned`; the fallback is independently checked and verified.

Before an earned-authority replacement, the executor writes a private backup and records its SHA-256. Terminal step or final verification failure rolls successful actions back in reverse order. Rollback refuses to clobber a file whose current hash no longer equals the action receipt, recording incomplete rollback instead.

## Concurrency and idempotency

- A process lock plus OS file lock serializes runs per autonomy state root.
- Caller-supplied run IDs are validated and idempotent after completion.
- Event logical keys prevent duplicate starts, action claims, receipts, completions, decisions, authority updates, and status transitions.
- A hash-only action claim is durable before atomic replacement. If a process dies after replacing but before writing its receipt, the next identical run reconciles exactly one receipt from that claim without rewriting.
- A replay-stable `autonomy.run.executed` event anchors the semantic result before outcome/final completion; restart after outcome creation cannot duplicate the outcome.
- Rollback recognizes an already-restored before-state as complete and never clobbers a path whose hash matches neither the receipt's before nor after state.
- Workspace, private state, and the event database cannot overlap. Workspace and private-state traversal use opened directory descriptors with `O_NOFOLLOW`.

## Progressive authority

| Level | Name | Actions | Bytes | Replace |
|---:|---|---:|---:|---|
| 1 | `reversible_local_create` | 4 | 16,384 | no |
| 2 | `verified_local_batch_create` | 10 | 65,536 | no |
| 3 | `earned_local_create_throughput` | 24 | 262,144 | no |

Rules:

- start at level 1;
- earn level 2 after three clean, receipt-backed verified successes and no failures in the 20-run window;
- earn level 3 after ten clean verified successes and at least 90% success;
- contract to level 1 after the latest failed run;
- no authority level adds new effect kinds or weakens path/credential/irreversibility blocks.

All Phase 10 levels are create-only. A prepared file inode is durably claimed, then published with Linux `renameat2(RENAME_NOREPLACE)`. Restart reconciliation requires both the claimed inode and content hash. Rollback atomically moves the claimed inode into private quarantine; a foreign inode is restored with no-replace semantics and never deleted or overwritten.

A successful fallback run remains successful but receives quality `0.25` for capability learning because primary execution failed. A clean success receives `1.0`; a terminal failure receives `0.0`. This changes later uncertainty and competence scoring without changing root values or bypassing `NO_OP`.

## Event families

- `autonomy.opportunity.detected|registered|selected|status_changed|observed_blocked`
- `autonomy.objective.created|status_changed`
- `autonomy.plan.created|replanned|verified`
- `autonomy.run.started|executed|completed`
- `autonomy.step.failed|verified|recovered|recovered_failed_verification`
- `autonomy.action.claimed|receipt|rolled_back`
- `autonomy.authority.updated`
- existing `decision.made` and `outcome.observed`

All events remain inside the existing append-only SHA-256 chain.

## Host wake

```bash
HERMES_HOME=/path/to/profile python3 scripts/cct_autonomy_tick.py \
  --seed 0 --message-only
```

The wake performs zero LLM calls. `NO_OP` produces empty stdout in `--message-only` mode.

An optional private host adapter at
`$HERMES_HOME/cct-agency/autonomy/artifact-adapters.json` can notice configured missing artifacts before selection. The file must be a current-user-owned regular file under the autonomy state root, mode `0600` (no group/world permissions), at most 64 KiB, and contain at most 16 narrow artifact objects. Each object supplies `opportunity_id`, `relative_path`, exact `content`, `title`, `rationale`, `objective`, and numeric `value_impacts`; optional evidence/scoring fields remain bounded. The adapter does not accept action kinds, commands, deletes, roots, or authority levels. Already-satisfied targets are ignored. Existing mismatched targets are reported blocked rather than replaced.

The status projection exposes root/proposal hashes, counts, relative plan references, receipts, and bounded scoring metadata. It does not replay proposal prose, artifact content, backup bytes, or absolute roots.

## Acceptance episode

```bash
receipt=$(mktemp -d /tmp/cct-phase10-demo-XXXXXX)
python3 scripts/cct_phase10_demo.py \
  --db "$receipt/agency.sqlite" \
  --workspace "$receipt/workspace" \
  --state-root "$receipt/autonomy" \
  > "$receipt/result.json"
```

The deterministic episode proves:

1. an initially higher-value fragile opportunity wins;
2. a real local collision causes a primary precondition failure;
3. a fallback plan creates and hash-verifies a useful artifact;
4. the linked realised outcome lowers that capability's quality;
5. a later near-tie changes to the stable opportunity;
6. the stable artifact is independently hash-verified;
7. a controlled terminal failure removes a prior temporary write through rollback;
8. the original collision file remains byte-identical;
9. plan content does not appear in event payloads;
10. the event chain verifies.
