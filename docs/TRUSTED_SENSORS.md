# Trusted continuity sensor

## Claim boundary

The trusted continuity sensor, introduced in CCT 0.5 and packaged in the
CCT Agency Engine 0.7 public alpha, implements a **continuously scheduled,
persistent, event-responsive functional cognition loop**. It does not implement
or establish a continuous subjective mind, phenomenal consciousness, feelings,
or an unobserved inner monologue.

The concrete claim is:

> A local structured event source can wake a bounded global-workspace cycle, preserve attributed evidence and temporal state, promote meaningful changes into proactive continuity, and remain silently active when nothing relevant changes.

## Configured source

The sensor reads one explicitly configured, owner-controlled JSONL stream:

```bash
python scripts/cct_team_sync_tick.py \
  --source /absolute/path/to/project_changes.jsonl \
  --report
```

The Hermes plugin also accepts the non-secret setting
`plugins.entries.cct-agency.settings.team_sync_source`. No operator-local
source path is compiled into the public package.

It records structured project receipts such as:

- actor;
- project;
- event kind;
- free-text summary (quarantined at the sensor boundary);
- timestamp;
- optional file, operation, and next-step metadata.

The sensor persists a fixed metadata-only receipt plus hash-based evidence handles. It deliberately does not persist the producer summary, `ops`, `files`, `next`, arbitrary source file contents, ByteRover projection output, raw chat transcripts, or hidden reasoning.

## Data flow

```text
team-sync append helper
        ↓
project_changes.jsonl
        ↓ every 5 minutes
canonical-path / type / owner / mode checks
        ↓
byte cursor + bounded JSONL scanner
        ↓
kind map + bounded signal policy
        ↓ host-only
Observation(initiative_authority="trusted_producer")
        ↓
CognitiveCycle
  attention → workspace → interoception → metacognition → cycle hash
        ↓
InitiativeBridge
  source/kind/digest/attention/relevance/change gates
        ↓
TopicStore revision
        ↓ every 30 minutes
ProactiveRunner
  threshold → cooldown → daily cap → semantic deduplication
        ↓
SEND or WAIT
```

No model call occurs in the sensor, heartbeat, promotion, or proactive decision path.

## Trust boundary

`initiative_authority` never comes from a JSONL field. The adapter supplies it only after validating:

1. allowlisted filename `project_changes.jsonl`;
2. no source or trusted-root symlink;
3. source is a regular file with one hard link;
4. exact resolved parent directory;
5. source and root owner UID equal the sensor UID;
6. source and root are not world writable;
7. group-writable paths use the sensor GID and that group resolves to no other local UID;
8. source and root carry no extended POSIX access/default ACL.

This proves the event crossed the configured same-UID host boundary. It does not prove a human identity or protect against a compromised same-UID process. Producer labels and free text never receive initiative authority and never enter the ledger, workspace, topic context, or proactive message; only opaque label references survive.

The scheduled entry point accepts only the exact canonical source. Its `--source` override is limited to `CCT_SENSOR_TEST_MODE=1` with an isolated `HERMES_HOME` resolving under `/tmp`; profile/state/database paths must not be symlinked or hardlinked. Fixture data therefore cannot be redirected into the live ledger or an external state target. A model or process with arbitrary same-UID terminal/filesystem access can still append to the canonical stream or mutate the ledger; that principal is inside—not protected by—the declared local trust boundary.

## Event policy

| Source kind | CCT kind | Signal posture |
|---|---|---|
| `blocker` | `blocker` | High urgency and conflict. |
| `decision` | `decision_update` | High relevance and conflict. |
| `change` | `goal_progress` | Material progress, normally able to cross initiation threshold. |
| `test` | `test_result` | Cognitively visible; routine results usually remain below interruption threshold. |
| `status` | `goal_progress` | Low signal; normally fails automatic promotion. |
| `risk` | `risk` | High conflict and urgency. |
| `opportunity` | `opportunity` | High novelty and relevance. |

Unknown kinds fail closed. Optional project filtering can narrow the stream without changing source authority.

## Cursor and restart semantics

The canonical source position is an append-only CCT event containing:

- source ID and path SHA-256;
- device/inode;
- byte offset;
- observed timestamp;
- scan/accept/reject counts;
- linked cognitive tick;
- explicit privacy flags.

First run starts at the current file tail. Existing history is not imported.

A source batch is processed before its cursor is committed. A crash in that interval can replay the batch—at-least-once reading—but the same observation receives the same evidence/content identity. `InitiativeBridge` therefore produces one automatic topic revision, not a duplicate user-visible initiative.

Truncation and inode rotation create an explicit reset receipt and resume from byte zero. Repeated offsets remain distinct append-only cursor epochs.

## Bounds and malformed data

Per wake:

- at most eight accepted observations;
- at most 64 source segments;
- at most 256 KiB scanned;
- at most 16 KiB per source line segment;
- bounded field lengths;
- incomplete final line deferred until newline;
- malformed/oversized records rejected by digest and cursor position, without raw-line persistence;
- oldest source data drains across subsequent wakes.

## Homeostatic heartbeat

A source event runs a normal `CognitiveCycle`.

When there are no source events, the five-minute sensor remains write-free until 30 minutes have elapsed since the latest sensor activity. It then runs one empty homeostatic cycle. That cycle checks and records:

- ledger integrity;
- goal progress control state;
- unresolved commitments;
- tool availability;
- interoceptive stability;
- metacognitive calibration;
- cycle continuity hash.

It invents no observation and emits no message. Idle wakes inside the interval write nothing.

## What creates an unsolicited message

A heartbeat alone does not create a proactive topic. A source record must:

1. be accepted by the host sensor;
2. survive bounded attention;
3. pass `PromotionPolicy` source, kind, digest, attention, goal-relevance, and change-signal gates;
4. create or revise an open topic;
5. pass initiation threshold, cooldown, daily cap, character cap, and semantic deduplication.

Silence is normal active behavior, not scheduler failure.

## Persistent ingredients

| Ingredient | Implementation |
|---|---|
| sensory stream | team-sync JSONL sensor |
| recurrent wake | 5-minute no-agent cron |
| global access | bounded workspace broadcast |
| goal continuity | CCT goal ledger and self-model |
| temporal identity | SHA-256-chained SQLite events and cycle hashes |
| attention | deterministic bounded competition |
| self-regulation | interoception and metacognition |
| initiative | trusted promotion plus proactive runner |
| restraint | canonical `NO_OP`, `WAIT`, hard gates, silent idle |
| learning | outcomes, reflections, signed usefulness feedback, bounded calibration |
| language interaction | normal Hermes model call only when a conversation is actually active |

## Scheduler and delivery semantics

The sensor is intended as a Hermes `no_agent` script job every five minutes. Empty stdout is silent. A non-zero exit is an operational alert.

The proactive scheduler may run at a slower cadence than the sensor. SQLite decisions, topics, cursors, and emission claims are idempotent where documented. External platform acceptance/display remains outside the SQLite transaction; end-to-end exactly-once delivery is not claimed.

## Privacy

- producer free-text persistence: false;
- automatic raw-conversation capture: false;
- hidden chain-of-thought persistence: false;
- fixed metadata-only receipts may persist: true;
- record SHA-256 persists and leaks equality: true;
- opaque actor/project references, allowlisted kind, and canonical timestamp persist: true;
- `ops`, `files`, `next`, and arbitrary source file contents persist: false;
- local profile SQLite audience: the configured Hermes profile and host operators;
- external model calls during sensor/heartbeat/proactive tick: zero.

## Verification

See:

- `tests/test_team_sync_sensor.py`;
- `reports/phase9-preflight-2026-08-22.md`;
- `reports/phase9-verification-2026-08-22.md`.
