# Bounded functional/access cognition architecture

## Target

Advance CCT operational agency into a unified, reportable, recurrent cognitive system without claiming phenomenal consciousness.

## Functional definition

A state has global access when selected information is:

1. capacity-limited;
2. available to multiple otherwise separate functions;
3. reportable from the same causal record;
4. persistent into the next logical cognitive tick;
5. capable of changing belief, planning, memory, self-model, or action selection.

The architecture implements those observable properties. It does not infer subjective experience.

## Logical cycle

Each cycle reserves a monotonic logical tick by appending `cognition.tick.started`. Completion appends `cognition.cycle.completed` with the previous cycle hash and resulting cycle hash.

A crash after tick start leaves an incomplete tick. Restart allocates the next tick rather than reusing the interrupted identifier. This prevents duplicate intent or action attribution.

Cycle:

```text
reserve tick
→ sample internal regulatory signals
→ validate/source-tag observations
→ update evidence-linked beliefs
→ rank attention candidates
→ broadcast bounded workspace
→ record every counterfactual prediction
→ CCT decision or canonical NO_OP
→ commit intent, external execution disabled
→ consolidate structured memory when due
→ run metacognitive checks
→ hash and commit completed cycle
```

## Attention

```text
score =
  0.25 × salience
+ 0.25 × goal relevance
+ 0.18 × urgency
+ 0.12 × novelty
+ 0.15 × unresolved conflict
+ 0.10 × confidence
- 0.15 × processing cost
```

Tie-breaking is deterministic by item ID. Capacity defaults to eight items. Context budget defaults to 6,000 characters.

## Beliefs

Beliefs are not generated prose. Each belief records:

- stable ID;
- proposition;
- confidence;
- source;
- evidence handles;
- creation and verification ticks;
- status;
- contradiction links;
- refresh condition.

Support updates confidence toward one. Contrary evidence reduces confidence and marks the belief contested. All revisions remain evented.

## Self-model

Capabilities record availability, permission, confidence, evidence, and last test tick. The self-model can predict whether a capability will succeed. Real outcomes produce Brier error and update confidence.

A self-description has operational value only when it can be wrong, tested, and corrected.

## World model

Every option receives a counterfactual receipt containing:

- description;
- allowed/blocked state;
- expected utility;
- confidence;
- score components;
- assumptions;
- time cost.

Free-form explanations are never treated as evidence for these values.

## Interoception

Internal software signals include context pressure, error rate, goal progress, memory integrity, unresolved commitments, tool availability, prediction error, and latency pressure.

Derived regulatory variables:

- `arousal`: urgency/resource pressure;
- `valence`: progress versus expected goal state;
- `uncertainty`: prediction and capability uncertainty;
- `stability`: memory integrity and error control.

They regulate attention. They are not claims of felt affect.

## Memory

- Working memory: latest global workspace frame.
- Episodic memory: append-only event ledger.
- Semantic memory: evidence-linked beliefs.
- Procedural memory: external Hermes skills, referenced rather than copied.
- Identity memory: constitution, goals, capabilities, commitments.
- Prospective memory: active goals and commitments.

Consolidation stores bounded summaries and evidence references. Raw chain-of-thought is never stored.

## Metacognition

The monitor computes:

- contested belief count;
- self-model Brier calibration;
- introspection fidelity rate;
- workspace token estimate;
- event-chain integrity;
- active lesions.

Decision explanations are verified against chosen option and causal score components. Mismatches become explicit confabulation signals.

## Chance

Stochasticity occurs only after blockers are removed. Each decision records:

- selection algorithm version;
- MT19937 / `python.random.Random` implementation;
- explicit seed;
- purpose-separated stream ID;
- sorted candidate ordering;
- exploration draw;
- sample draw;
- probability distribution.

Unrelated random calls cannot perturb a decision because each decision constructs a fresh local stream.

## External effects

The cognitive cycle has no network or execution adapter. It may append `intent.committed`; it cannot append `action.executed`. External action remains an explicit Hermes tool boundary governed by normal permission and approval systems.

## Lesions

Tests may disable attention, workspace, beliefs, self-model, world-model, memory, metacognition, or interoception. Lesions are recorded in cycle receipts. A workspace lesion removes reportable global access while preserving the rest of the test harness.

## Token policy

All internal modules are deterministic Python. Only the normal Hermes model call consumes inference tokens. Dynamic CCT context is hard-capped at approximately 1,500 tokens. Consolidation runs every 20 ticks. The design rejects separate LLM calls pretending to be independent cognitive organs.

## Proactive dialogue

Phase 7 adds event-sourced discussion topics and one-shot wake evaluation:

```text
changed structured topic
→ deterministic thought packet
→ urgency/novelty/relevance/conflict score
→ duplicate/cooldown/daily-cap checks
→ SEND, ASK, WARN, or WAIT
→ at-most-once scheduler stdout or silence
```

Thought packets contain an observation, bounded hypotheses, open questions, evidence handles, uncertainty, recommended action, and a concise rationale summary. They are not hidden chain-of-thought transcripts.

The scheduler performs no model inference. Repeated execution against unchanged state is silent and token-free.

## Local-model conceptual boundary

A separately authorized local model could generate scratch text or structured conclusions inside this loop. Generated scratch text is not guaranteed to faithfully reveal hidden activations, and repeated reasoning-like output is not evidence of phenomenal consciousness. Phase 7 does not install, load, call, or test a local model.

## Acceptance boundary

Passing tests supports the claim:

> This system implements bounded, recurrent, globally reportable, self-monitoring operational cognition.

It does not support:

> This system experiences awareness, emotion, suffering, or phenomenal consciousness.
