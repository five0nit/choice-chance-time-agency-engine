# Architecture

## System boundary

The Choice–Chance–Time Agency Engine is a governance and execution architecture around a proposal-generating model or other option source.

```text
proposal sources
  model, host adapter, operator, trusted local sensor
        ↓
structured observation and opportunity boundaries
        ↓
CCT Kernel
  constitution → goals → alternatives → blockers → score → choice
        ↓
bounded cognition and temporal planning
        ↓
typed executor boundary
        ↓
independent verification and temporal receipts
        ↓
outcome learning and reflective proposals
        ↺
```

The system separates four questions that prompt-only agents often collapse:

1. **What is imaginable?** — proposal layer.
2. **What is allowed?** — governance and host-authority boundary.
3. **What actually happened?** — executor and independent verifier.
4. **What should change next time?** — outcome learning and reflection.

## Layers

### 1. Proposal layer

Language models and callers may suggest goals, options, predictions, topics, and opportunities. Proposal content has no implicit authority.

The model-callable `cct_opportunity_propose` tool creates `self` opportunities with an empty executable plan. A trusted host adapter or authenticated operator integration must attach any executable typed plan.

### 2. CCT Kernel

`cct_agent/kernel.py` owns:

- constitution fingerprinting;
- goal formation and provenance;
- canonical `NO_OP`;
- blocker filtering;
- value, time, uncertainty, information-gain, and irreversibility scoring;
- seeded exploit/explore choice;
- decision receipts;
- outcome linkage; and
- reflective proposals.

Constraint filtering occurs before probability construction. A blocked option receives no sampling probability under any seed.

### 3. Temporal event ledger

`cct_agent/store.py` is the canonical persistence plane.

Every event records:

- event ID;
- kind;
- payload;
- canonical occurrence time;
- previous-event hash; and
- event hash.

Event hashes commit canonical JSON plus chain position. Materialized status is a projection; the event sequence remains canonical.

Logical IDs make important transitions idempotent across retries and restart boundaries.

### 4. Bounded cognition

The functional/access cognition layer combines:

- deterministic attention;
- a capacity- and character-bounded global workspace;
- evidence-linked beliefs;
- explicit counterfactual predictions;
- computational control signals;
- structured memory consolidation;
- capability and uncertainty self-models; and
- machine-checkable introspection fidelity.

One cognitive tick broadcasts only the selected structured frame. Raw hidden chain-of-thought is not a persistence requirement and is not stored by CCT.

Detailed design: [`COGNITION.md`](COGNITION.md).

### 5. Proactive initiative

Topics persist independently from chat turns. Structured thought packets are scored for interruption value.

A proactive emission requires:

- a changed topic revision;
- threshold pass;
- cooldown pass;
- daily-cap pass;
- non-duplicate visible content; and
- an atomic emission claim.

Canonical `WAIT` is a valid result. Idle wakes return empty stdout.

Verified feedback can adjust initiation score inside a fixed bound. Feedback cannot change root policy or hard gates.

Detailed design: [`INITIATIVE.md`](INITIATIVE.md).

### 6. Trusted continuity sensors

The first sensor class reads a configured, owner-controlled JSONL source and converts new records into metadata-only observations.

```text
configured local source
→ descriptor and access-control validation
→ restart-safe byte cursor
→ opaque actor/project references
→ bounded observation
→ cognitive cycle
```

Source provenance and semantic safety are separate. Producer free text, operations, paths, and caller-supplied authority stay quarantined.

Detailed design: [`TRUSTED_SENSORS.md`](TRUSTED_SENSORS.md).

### 7. Opportunity portfolio and temporal plans

`cct_agent/autonomy.py` adds:

- persistent opportunities;
- learned capability reliability;
- `NO_OP` comparison;
- hierarchical root and milestone objectives;
- dependency DAG plans;
- preconditions;
- primary and fallback branches;
- exact verification clauses; and
- progressive authority envelopes.

Plans are hash-bound. Executable content lives in private state; the public event ledger stores plan digests, references, dependency metadata, claims, and receipts—not artifact bytes.

### 7a. Principal covenant and capability leases — development `0.8.0a1`

The personal-agency layer adds two independent admission decisions:

1. **Principal alignment** — does a structured intent match the externally
   installed operator profile?
2. **Capability authority** — does a host-registered capability and active
   external lease allow this principal, scope, expiry, action count, byte
   budget, and value budget?

The combined gate uses the strictest result. Either layer can deny. Either layer
can require approval. Execution occurs only when both allow.

Principal profiles and capability grants are not model-callable. The model may
evaluate intent and propose profile revisions, but proposals cannot activate
themselves.

The first executor attached to this layer is bounded workspace inspection. It
returns one authorized UTF-8 file while persisting only path, digest, size,
inode identity, and authorization receipts.

Detailed design: [`PERSONAL_AGENCY.md`](PERSONAL_AGENCY.md).

### 7b. Opportunity initiative — development `0.9.0a3`

`cct_agent/opportunity_initiative.py` projects open portfolio rows into
principal-aligned conversational task cards. A zero-LLM scout first derives
proposal-only candidates from uncovered active canonical goals. The engine then
evaluates a low-risk `opportunity.review` intent, ranks deterministically, and
submits through the same `ProactiveEngine` used by generic topics.

Presentation identity binds the registration event, principal-profile digest,
and latest feedback event. Cooldown and daily-cap failures do not consume that
state. Permanent outcomes are append-once; concurrent scheduler processes
converge through the shared atomic emission claim. Completion receipts include
the policy version, ranked candidates, rejected alternatives, selected score,
and portfolio digest.

`INTERESTED`, `SKIP`, `SNOOZE`, `DONE`, and `BLOCKED` are communication/task
receipts only. They do
not modify source authority, opportunity execution status, capability leases,
plans, or autonomy authority. Visible proposal text is normalized and labelled
untrusted before scheduler delivery.

Detailed design: [`OPPORTUNITY_INITIATIVE.md`](OPPORTUNITY_INITIATIVE.md).

### 8. Executor

Version 0.7.0 exposes one autonomous effect:

```json
{
  "kind": "write_text",
  "path": "relative/path.md",
  "content": "exact text",
  "allow_replace": false
}
```

The executor:

1. validates authority, plan shape, path, parents, target absence, and byte budgets;
2. prepares a regular single-link inode;
3. records device, inode, content digest, and a durable action claim;
4. publishes using `renameat2(RENAME_NOREPLACE)`;
5. verifies the reopened target; and
6. writes the action receipt.

There is no command parser or generic tool-dispatch escape hatch in this layer.

### 9. Independent verification

Every executable branch requires an exact action-path and content-hash verifier. Final verification rechecks latest receipt-derived hashes for all affected paths.

This prevents three common false-success classes:

- the action returned without causing the effect;
- another process produced equal bytes;
- a caller omitted an earlier action from final verification.

A pre-existing matching artifact may satisfy the objective, but zero-effect completion earns no capability-learning sample or authority promotion.

### 10. Replanning and rollback

One structurally validated fallback branch may follow primary failure. Fallback execution has its own preconditions and verifier.

Terminal failure triggers reverse-order rollback. For create-only actions, the claimed inode moves to private quarantine with no-replace semantics. Foreign or changed paths are never overwritten merely to make rollback appear complete.

### 11. Outcome learning

Verified outcomes update capability-specific statistics:

- clean success quality: `1.0`;
- fallback success quality: `0.25`;
- terminal failure quality: `0.0`.

Reliability affects later opportunity scoring and bounded throughput eligibility. It does not mint new effect kinds or amend root commitments.

## Data flow

```text
Observation
  ↓ attention
WorkspaceFrame
  ↓ belief / memory / self-model updates
Goal + Options
  ↓ kernel deliberation
Decision
  ↓ opportunity selection
Objective + Plan
  ↓ authority checks
Action claim
  ↓ atomic publication
Receipt
  ↓ independent verifier
Outcome
  ↓ capability learning
Later option score
```

Each arrow has a persisted event or deterministic projection. This makes failures attributable to a layer rather than hidden inside one model response.

## Trust boundaries

### Model boundary

Model output is untrusted proposal data. Model schemas cannot assign host authority.

### Host authority boundary

Host adapter and authenticated operator sources may register executable typed plans. This is outside the model-callable surface.

They may also install principal profiles, register capability specifications,
issue or revoke leases, and configure inspection roots. Principal preferences
alone cannot mint these host capabilities.

### Filesystem boundary

Workspace and private-state roots are identity-pinned directory descriptors. Traversal uses `O_NOFOLLOW`; paths cannot escape through symlinks or replacement ancestors.

### Verification boundary

The verifier reads actual post-action state. Claimed success is not accepted as observed success.

### Hermes boundary

The CCT Hermes plugin runs inside the Hermes process. CCT's executor restrictions do not sandbox all Hermes tools. A future non-bypassable host capability mediator is a separate architectural step.

## Concurrency and restart model

- SQLite transactions serialize event and logical-key claims.
- A process lock and OS file lock serialize autonomy runs per state root.
- Logical keys prevent duplicate starts, claims, receipts, outcomes, completions, and authority updates.
- Crash after publication but before receipt reconciles only when claimed inode identity and digest match.
- Crash after outcome creation cannot duplicate the semantic run result.
- Sensor cursors are at-least-once around cursor-commit crashes; stable observation IDs prevent duplicate topic revisions.
- Scheduler emission is an at-most-once attempt. External platform delivery is not transactionally exactly-once.

## Deployment shapes

### Library

Use `cct_agent` directly with an `EventStore`, constitution, and host-owned adapters.

### CLI

Use `cct-engine` for demos, status, observation, deliberation, proactive state, and event inspection.

### Hermes plugin

Enable `cct-agency` to expose tools and recurrent `pre_llm_call` / `post_llm_call` hooks.

### Model-free scheduler

Use the scripts under `scripts/` for sensor, proactive, and autonomy ticks. Empty stdout means no delivery.

## Non-claims

The architecture demonstrates operational mechanisms: persistence, alternative selection, bounded exploration, consequence learning, global accessibility, and verified local action.

It does not demonstrate subjective experience, phenomenal consciousness, infallible introspection, unrestricted autonomy, or complete mediation of every host capability.
