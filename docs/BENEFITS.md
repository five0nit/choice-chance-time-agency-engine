# Benefits

## Executive summary

The Choice–Chance–Time Agency Engine turns agent autonomy from a prompt claim into an inspectable operating loop.

```text
propose → choose → authorize → execute → verify → learn
```

Each transition is explicit. This produces practical benefits for builders, operators, evaluators, and researchers.

## Benefits for agent builders

### 1. Stable governance outside prompt prose

Prompt instructions drift with model, context, and phrasing. CCT keeps values, blockers, provenance, sampling, receipts, and amendment rules in deterministic code and persistent state.

### 2. Genuine alternative tracking

The engine records chosen and rejected options, not only the final answer. This supports counterfactual inspection and makes reasons-responsiveness testable.

### 3. Replayable exploration

Seed, stream identity, candidate ordering, probabilities, draws, and scores are retained. Exploration can be reproduced without letting chance bypass constraints.

### 4. One temporal spine

Goals, beliefs, decisions, outcomes, reflections, sensor cursors, action claims, receipts, rollbacks, and authority updates share one append-only event chain.

This reduces split-brain state across separate memory, planner, and executor logs.

### 5. Explicit authorization seams

Model proposals cannot label themselves trusted. Host adapters and authenticated operator integrations own executable-plan registration.

This makes authority reviewable and keeps creative generation separate from permission.

### 6. Capability-specific learning

Reliability belongs to a named capability. Success with one action class does not create global trust.

This supports progressive deployment and limits blast radius.

### 7. Low idle cost

Sensor, heartbeat, promotion, proactive, and autonomy ticks are deterministic and make zero model calls. Quiet state produces empty output.

## Benefits for operators

### 1. Evidence instead of confidence

The engine distinguishes:

- planned;
- attempted;
- effectful;
- verified;
- recovered; and
- completed.

An action receipt and independent recheck support every effect claim.

### 2. Visible permission boundaries

Status exposes allowed effects, forbidden effects, action and byte budgets, learned reliability, open opportunities, run receipts, and event-chain health.

### 3. Built-in defer option

`NO_OP` prevents an agent from treating action as mandatory. Deferral is an explicit chosen branch with reasons, not a silent failure.

### 4. Safer failure behavior

Primary failure may take one validated fallback. Terminal failure triggers reverse-order rollback. Changed or foreign state is preserved rather than overwritten to manufacture a clean result.

### 5. Bounded interruption

Proactive output requires meaningful changed state and passes cooldown, daily cap, semantic deduplication, and threshold gates.

### 6. Authority can contract

A failed run returns the autonomy envelope to Level 1. Authority is not a permanent badge granted once.

## Benefits for evaluation and operations teams

### 1. Causal incident reconstruction

A failure can be assigned to a layer: sensor, promotion, choice, plan, authority, executor, verifier, rollback, or learning.

### 2. Behavior contracts

Tests can assert relationships:

- blocked options never sampled;
- same inputs and seed replay exactly;
- changed impacts alter exploit choice;
- effect claims match actual bytes;
- authority changes follow outcome history.

These contracts survive implementation refactors better than snapshot tests.

### 3. Restart and concurrency evidence

Logical keys, locks, claims, receipts, and cursor semantics give concrete targets for crash and race testing.

### 4. Honest delivery semantics

The engine distinguishes internal idempotency from external platform guarantees. At-most-once scheduler emission does not become a false exactly-once messaging claim.

## Benefits for research

### 1. Operational agency testbed

CCT makes Choice, Chance, and Time measurable through alternatives, replayable exploration, persistent commitments, consequences, and policy revision.

### 2. Global-workspace experiments

Attention competition, broadcast capacity, lesion behavior, memory consolidation, and metacognitive calibration are deterministic and testable.

### 3. Initiative calibration

Matched `WAIT` and `SEND` controls can show whether verified feedback causally crossed an interruption threshold.

### 4. Progressive authority experiments

Capability-specific success and failure receipts support studies of earned autonomy without assuming one global agent trust score.

### 5. Precise non-claim boundary

The architecture supports consciousness-like functional mechanisms while explicitly avoiding claims of subjective experience or phenomenal consciousness.

## Compared with common alternatives

| Pattern | Useful property | Missing property CCT adds |
|---|---|---|
| Prompt-only agent | Flexible reasoning | Stable invariants and temporal replay |
| Tool-calling agent | Real effects | Proposal/authorization separation and receipts |
| Planner/executor | Multi-step work | Canonical `NO_OP`, capability learning, earned authority |
| Memory/RAG layer | Historical context | Goals, decisions, outcomes, and amendment provenance |
| Workflow engine | Deterministic tasks | Counterfactual choice and bounded exploration |
| Sandbox | Process isolation | Reasons, consequences, learning, and operator-facing agency state |

CCT does not replace all these layers. It coordinates their governance and temporal evidence.

## Practical target

The current alpha proves a narrow local loop. The next benefit step is a typed capability registry:

- inspect approved files;
- apply bounded patches with expected-before hashes;
- run pre-registered checks;
- verify diffs and outputs; and
- learn reliability per capability.

That moves CCT from verified artifact creation toward autonomous local maintenance without granting arbitrary shell access.
