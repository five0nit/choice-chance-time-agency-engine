# Continuous owner discovery

The owner dashboard has two views: **Discover** is a continuous, one-question conversation; **Inside CCT** shows evidence-linked interpretations, unknowns and candidate work. This is a draft producer, not an executor. `executionEnabled` is always `false`; work ideas are `DRAFT_ONLY`.

## Run

Use an explicit owning profile and its installed interpreter:

```sh
HERMES_HOME=/absolute/owning/profile /absolute/release/venv/bin/cct-owner-discovery run
HERMES_HOME=/absolute/owning/profile /absolute/release/venv/bin/cct-owner-discovery once
HERMES_HOME=/absolute/owning/profile /absolute/release/venv/bin/cct-owner-discovery status
```

`status` reads SQLite in read-only mode; it does not call Firebase or the model. `once` performs a real worker tick, not a test. `run` holds the profile-local process lock and polls every 15 seconds, backing off connection failures. Replace the owning dialogue service command rather than running two interview producers. No gateway restart or default-profile worker change is needed.

Configuration reuses `config/cct-owner-dialogue.json` (`enabled`, `conversationId`, `modelPython`) and the exact identity in `config/cct-owner-connection.json`. Firebase uses the existing approved host credential. The adapter resolves only the owning profile's explicitly pinned model/provider and offers no tools. Identity, conversation or interpreter changes require a worker restart; malformed configuration fails closed.

## Durable conversation

- Local state is `owner-connection/discovery.sqlite` and `discovery.lock`, with restrictive permissions.
- On first activation for a conversation, import genuine `ANSWERED` rows from `messages.sqlite` through `mode=ro` and `query_only`. Preserve original `msg-` IDs and complete receipt evidence. Never construct the old outbox, repair transport states or resend `UNKNOWN` Telegram deliveries.
- The starter question needs no model and claims no learning. A genuine imported or site answer causes one durable next turn. There is no fixed answer-count stop and no recurring model call while awaiting input.
- Persist the exact validated model response and answer consumption together before projection. Reprojection does not regenerate. A crash without a committed result leaves an in-flight attempt blocked for operator recovery, not silently retried.
- Keep all imported and site answers in SQLite. The model and cloud view use the latest 40 incorporated answers; claims whose cited sources leave that window are pruned. This is bounded conversational understanding, not a complete long-term knowledge graph.
- A provider attempt is bounded to 150 seconds and three attempts per answer, with five-minute retry spacing. A rolling 24-hour circuit breaker counts ten unsuccessful attempts (anything not `SAVED`), not successful genuine-answer turns. There is no daily successful-answer cap; provider quotas still apply. Interrupted/unknown attempts need operator recovery. Visible `BLOCKED` reasons and `retryAt` distinguish a scheduled retry from a terminal limit. Underlying provider transport behavior is inherited from the installed adapter.
- As direction emerges, work ideas should name a tangible next deliverable, evidence needed and completion criterion. Follow-up questions target owner-only unknowns rather than asking the owner to do research. These remain proposed work, not a researched plan, an execution queue or authority.

## Cloud contract

Host-only `cct_discovery/current` contains schema `cct.discovery.v1`, exact owner/conversation identity, monotonic revision, ISO heartbeat, phase/reason, current question, answer history, learning, unknowns, work ideas and incorporated-answer count. Phases are `AWAITING_INPUT`, `THINKING`, `PAUSED`, `BLOCKED`.

All learned items and work ideas cite source answer IDs present in that exact projected history. Unsupported claims, malformed output, extra model fields and execution-ready ideas are rejected. Citations prove the evidence reference exists, not that every interpretation is correct; the owner can correct an interpretation in the next reply.

The verified owner creates only `cct_discovery_answers/{questionId}`:

```json
{"schemaVersion":"cct.discovery_answer.v1","ownerUid":"<verified owner>","questionId":"q-<32 lowercase hex>","text":"<owner's actual words>","createdAt":"<Firestore serverTimestamp>"}
```

Firestore requires an exact current awaiting-input question, owner identity, `learningEnabled: true`, server timestamp and 1–4000 nonblank characters. Answers are create-only; browser updates/deletes and host-learning writes are denied. The browser reads the exact server answer back before reporting saved; ambiguous saves keep the draft and require refresh. Site discovery is independent of Telegram delivery and external-messaging permissions.

Pause/resume uses existing workspace `learningEnabled`. An already-running response may finish and be saved after pause, but it cannot execute work. Diagnostic executor controls remain separate and are not activated by discovery.

## Verification boundary

Use real owner replies and exact installed/cloud readbacks to establish the working conversation. Do not seed fabricated answers, run project-audit jobs, or describe local preview transport as authenticated browser verification. Visual captures may render a read-only export of genuine cloud state with writes disabled; label that provenance explicitly. Automated tests/evals are intentionally held for this owner-directed rollout.
