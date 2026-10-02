# A16 Human Narrative Layer

## Purpose

CCT's append-only ledger remains the canonical machine truth. A16 adds a deterministic, read-only projection that answers operator questions without requiring raw JSON inspection:

- What happened?
- What result was proved?
- Did CCT use or gain authority?
- Does the operator need to act?
- Which exact ledger event supports the statement?

The projection does not summarize with an LLM and does not append narrative events back into the ledger.

## Output contract

Every narrative item contains:

- one fixed result class: `VERIFIED`, `FAILED`, `ROLLED_BACK`, `BLOCKED`, `ACTION_REQUIRED`, or `RECORDED`;
- one concise deterministic sentence whose fixed wording states any authority boundary;
- `ACTION_REQUIRED` only when the event family itself represents an operator gate;
- exact `seq` and `event_hash`, plus exact canonical `event_id`/`kind` when they match the bounded lowercase metadata grammar; unsafe caller-controlled identifiers are represented only by SHA-256.

Narrative output never includes an event's raw payload. Templates may read only allowlisted structured fields with strict enums or identifier syntax. Unknown events receive a content-free fallback.

## Views

### Human status

Summarizes chain health, event totals, goal-state counts, unresolved operator-action signals, and the latest significant event.

```bash
cct-engine --db state/agency.sqlite human-status
```

### Latest explanation

Explains the latest significant non-routine event.

```bash
cct-engine --db state/agency.sqlite explain-latest
```

### Activity digest

Returns a bounded newest-first list of significant events.

```bash
cct-engine --db state/agency.sqlite digest --limit 8
```

Add `--json` to any A16 command for structured narrative output. Existing `status` and `events` commands remain the raw technical surfaces.

## Hermes integration

`cct_human_summary` is the preferred tool for plain-language operator questions.

Views:

- `status`
- `latest`
- `digest`

`limit` is bounded. Tool output contains human text and exact event references but no raw event payloads. `cct_status` remains available for detailed technical diagnosis.

## Privacy and authority boundaries

- No arbitrary producer text is interpolated.
- No secrets, file contents, command output, messages, prompts, or raw arguments are rendered.
- `INTERESTED` or clarification answers never become effect authority in narrative wording.
- A non-negative `outcome.observed` claim is `VERIFIED` only when its evidence references a canonical successful verified run/effect completion; caller-supplied utility or evidence labels alone remain `RECORDED`.
- Status counts only the latest unanswered clarification or a required-but-unconfirmed answer as unresolved action.
- An invalid event chain overrides success language and requires operator attention.
- Reading narratives creates no ledger event and consumes no capability lease.
