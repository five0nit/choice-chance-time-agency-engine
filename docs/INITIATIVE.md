# Adaptive initiative

Introduced during the project's Phase 8 development cycle.

## Claim

Phase 8 demonstrates **bounded adaptive initiative**: structured events from an explicitly trusted producer can create proactive topic revisions without a caller manually creating each topic. Feedback carrying a verified host-boundary receipt can calibrate later initiation scores inside unchanged hard gates.

It does not demonstrate phenomenal consciousness, feelings, sentience, moral personhood, or metaphysical free will.

## Data flow

```text
trusted host producer → Observation(initiative_authority="trusted_producer")
        ↓
deterministic attention → workspace.broadcast
        ↓
trusted-source + kind + numeric promotion gate
        ↓
stable source-item key + atomic topic revision
        ↓
oldest-unprocessed cursor advances
        ↓
ProactiveRunner → ThoughtPacket
        ↓
base score + bounded verified-feedback adjustment
        ↓
threshold / duplicate / cooldown / daily-cap gates
        ↓
SEND or canonical WAIT
        ↓
emission receipt ← signed transport/UI feedback receipt
```

No model call occurs in promotion, calibration, wake selection, or message rendering.

## Promotion contract

### Trusted producer boundary

Every `Observation` defaults to:

```text
initiative_authority = "untrusted"
```

The model-callable `cct_observe` schema does not expose `initiative_authority`. Supplying an allowlisted `kind`, high numeric scores, or a source-looking string through that tool therefore cannot authorize promotion.

A host integration must construct a structured observation itself with:

```text
initiative_authority = "trusted_producer"
```

and a source matching the configured trusted-source policy. Default trusted sources are:

- namespace prefix `system:verified:`;
- namespace prefix `monitor:`;
- exact source `tool:pytest`;
- exact source `tool:ci`.

This is a host-code trust boundary, not a claim that arbitrary text beginning with one of those strings is authenticated. The authority marker is not model-callable. A process with arbitrary database or host-code access remains outside this boundary.

### Kind and numeric gates

Default kind allowlist:

- `blocker`
- `commitment`
- `decision_update`
- `goal_progress`
- `opportunity`
- `outcome`
- `risk`
- `test_result`

A trusted-source item must also satisfy:

```text
attention_score >= 0.62
goal_relevance >= 0.60
max(urgency, novelty, unresolved_conflict) >= 0.50
```

Generic `cognitive_trigger` and `response_outcome` events are not allowlisted. Normal model-call activity cannot create proactive topics by itself.

### Identity, backlog, and lifecycle

Eligible events are grouped into a stable topic stream using the SHA-256 digest of `(source, kind)`.

The source-item promotion key is a SHA-256 digest over stable producer identity:

```text
(id, kind, source, content_digest)
```

`content_digest` is required and must be a lowercase 64-character SHA-256 digest. Missing or malformed digests fail closed. The key does not include the enclosing `workspace.broadcast` event ID or `logical_tick`, so rebroadcasting the exact producer item does not create another topic revision.

The bridge stores a monotonic `(workspace event sequence, item index)` cursor. Each run scans the **oldest unprocessed** bounded batch—not the newest tail—so a backlog larger than the scan/run cap drains over later wakes instead of silently losing old eligible items.

Malformed frames/items receive rejection codes, advance the monotonic cursor exactly once, and do not block later valid items in the same batch or backlog. Automatic revisions preserve an existing topic's `paused` or `closed` state; only an explicit topic operation may reopen it.

### Atomicity and concurrent runners

Topic promotion uses one SQLite `BEGIN IMMEDIATE` transaction to:

1. check the stable source-item key;
2. check the latest topic revision;
3. append the next topic revision;
4. bind the logical promotion key;
5. commit.

A concurrent revision race returns `TOPIC_RACE`, reconstructs the latest topic, and retries. An exact source-item retry returns the original event.

Runner initiation, emission, and completion remain atomic and idempotent. Concurrent runners may read one revision, but the initiation-decision logical key elects one canonical decision even across the packet-only crash boundary; losing submissions adopt that receipt instead of colliding on different wake indices. Only one emission receipt wins. Completion uses the same logical topic-revision key with idempotent losing-path behavior, so the loser returns silence instead of raising a payload-collision exception.

Visible-content duplicate hashing normalizes Unicode, case, whitespace, and punctuation before hashing the rendered observation, first hypothesis, and first question. This suppresses simple variants such as `Build passed.` versus `Build passed!` without invoking a semantic model.

Default per-wake resource bounds:

- at most 500 workspace events scanned;
- at most three topic revisions created;
- existing threshold, cooldown, daily cap, and character cap still govern messages.

## Feedback contract

Feedback attaches to an existing `proactive.message.emitted` event. Outcomes:

| Outcome | Utility | Observed interruption cost |
|---|---:|---:|
| `USEFUL` | `1.0` | `0.0` |
| `NEUTRAL` | `0.0` | `0.5` |
| `DISRUPTIVE` | `-1.0` | `1.0` |

A `FeedbackReceipt` binds:

- emission event ID;
- outcome;
- verified principal ID;
- transport/UI boundary receipt ID;
- bounded evidence handles;
- signature.

`ProactiveFeedback.record()` has no source-string trust shortcut. It fails closed unless initialized with a verifier callback and that callback validates the receipt. The included `HMACFeedbackAuthority` is a dependency-free reference signer/verifier for a host integration; its shared secret must remain in the transport/UI trust boundary and outside model-callable tools.

There is deliberately **no** `cct_proactive_feedback` Hermes tool and no unsigned `proactive-feedback` CLI command. A normal model tool call cannot manufacture external provenance. The public demo uses a fixed, explicitly non-production HMAC fixture only to make the verification path reproducible.

One emission accepts one canonical feedback event. Exact retries are idempotent; a conflicting outcome for the same emission fails with a logical-key collision.

### Calibration formula

For `n` verified feedback samples:

```text
mean_utility = sum(utility) / n
confidence_weight = n / (n + 4)
score_adjustment = clamp(mean_utility × confidence_weight × 0.15, -0.12, +0.12)
adjusted_score = clamp(base_score + score_adjustment, 0, 1)
```

Every initiation decision records base score, adjusted score, sample count, outcome counts, mean utility, confidence weight, and bounded adjustment.

Feedback cannot alter:

- constitution or root values;
- blocker filtering;
- content deduplication;
- cooldown;
- daily message cap;
- message character cap;
- external-execution authorization.

## Privacy boundary

| Data | Behavior |
|---|---|
| Raw conversation text | Received transiently by Hermes hooks but never persisted by CCT |
| Turn metadata | Unsalted SHA-256 digests and character counts persist in post-call completion receipts |
| Hidden chain-of-thought | Never requested or stored |
| Structured workspace summaries | Already persisted by cognition; eligible summaries may be copied into topic revisions |
| Caller-supplied topic summaries | Persisted when `cct_topic_update` is called |
| Verified feedback outcome/principal/receipt/evidence handles | Persisted when feedback is recorded |
| Feedback signing secret | Never persisted in the CCT event ledger |
| Model scratch text | Not used |

“Structured” does not guarantee non-sensitive. Producers must not place raw private conversation or secrets into observation summaries or feedback evidence.

## Public demo

Use a fresh database:

```bash
python3 -m cct_agent.cli \
  --db /tmp/cct-phase8-demo.sqlite \
  phase8-demo
```

The command fails if the target database already contains events. A successful JSON receipt proves:

1. a trusted high-value `test_result` entered the workspace;
2. the bridge created an automatic topic revision;
3. the first proactive wake emitted;
4. the second candidate scored `0.629` and returned `WAIT` without feedback;
5. one verified `USEFUL` receipt produced a `+0.03` bounded adjustment;
6. the matched second decision scored `0.659` and crossed the `0.65` threshold to `SEND`;
7. the unchanged next wake returned `NO_NEW_STATE` and no message;
8. a recursive payload-key scan found no forbidden raw-message/chain-of-thought keys;
9. the full event chain verified.

Canonical verification:

```bash
python3 -m pytest -v --tb=short
python3 -m compileall -q cct_agent hermes_plugin tests scripts
git diff --check
```

## Remaining limits

- External platform delivery is not transactionally exactly-once. The database emission claim is idempotent; scheduler stdout is an at-most-once attempt.
- HMAC verification authenticates possession of a shared secret, not a human identity by itself. Production principal authentication belongs to the transport/UI boundary.
- The kernel cannot protect against a process with arbitrary host-code, database, or signing-secret access.
- Global feedback currently calibrates every proactive action type; per-topic and per-action calibration needs real samples.
- Stable automatic topic grouping uses `(source, kind)` and may be too coarse for broad sources.
- Punctuation-insensitive hashing is bounded normalization, not model-level semantic equivalence.
- No local or remote model is invoked by this phase.
