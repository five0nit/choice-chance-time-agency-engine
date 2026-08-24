# Proactive task and opportunity initiative

## Status

Implemented on the `phase11-personal-agency` development branch; current version `0.9.0a3`.

This phase turns CCT's existing opportunity portfolio into an operator-visible initiative loop:

```text
model/host/operator opportunity
        ↓
persistent opportunity portfolio
        ↓
principal alignment
        ↓
deterministic priority projection
        ↓
shared cooldown + daily cap + semantic dedupe
        ↓
concrete task card
        ↓
INTERESTED / SKIP / SNOOZE / DONE / BLOCKED receipt
        ↓
existing authority boundary remains unchanged
```

It does **not** add an executor or broaden effect authority.

## Problem fixed

Before `0.9.0a1`, CCT could:

- store persistent opportunities;
- select and execute host/operator plans through the bounded autonomy engine; and
- send generic proactive topic updates.

Those pieces were separate. A model-created opportunity remained invisible unless an operator inspected status manually. The proactive scheduler mostly surfaced metadata receipts rather than useful task choices.

`OpportunityInitiative` bridges them without turning proposal text into permission.

## Opportunity sources

Existing `Opportunity` records remain canonical.

A zero-LLM active-goal scout also materializes one proposal-only candidate for
each installed-principal active goal that has no unanswered linked opportunity. It
derives title, horizon, value impacts, and evidence from the canonical goal
event; it does not invent commands or executable plans. Initial cards require an
action-led goal plus bounded evidence anchored by a URL, date, amount, commit/ID,
path, or trusted event/receipt/runtime/test prefix. Verbose aspirations without
such anchors stay silent. Eligible cards map the action class to an explicit
receipt type (application, artifact hash, before/after test, provider readback,
or cited decision). When a card is marked
`INTERESTED`, the still-active goal receives one new generation: a concrete
DONE/BLOCKED receipt check for the interested task. `SKIP` stops further
presentation; SNOOZE preserves the same generation. Closed goals are
ineligible, and concurrent/restarted scouts converge through append-once
`goal_id:generation` receipts.

- `self` — model/self proposal. May be presented only when evidence-backed and linked to an active goal. Never executable.
- `host_adapter` — host-created, plan-bound metadata. Presentation still does not execute it.
- `operator` — operator-created, plan-bound metadata. Presentation still does not execute it.

Model-created proposals record:

```text
content_trust = self_generated_untrusted_proposal
instructions_authorized = false
executable = false
```

The Hermes proposal tool additionally requires an active CCT `goal_id` and at
least one evidence reference. The canonical `goal:<id>` link is added to the
opportunity receipt. Self proposals without evidence or an active goal remain
persisted for audit but are ineligible for proactive presentation.

Host/operator records carry `host_or_operator_metadata`, but their visible task-card prose is still not an instruction channel.

## Selection

Each scheduler wake projects open opportunities from the append-only event chain.

The deterministic priority score combines:

- positive declared value impact;
- information gain;
- certainty;
- low time cost; and
- a small host/operator-source bonus.

Stable tie-breaking uses registration time and opportunity ID. Selection does not call an LLM.

Each completion persists the policy version, selected score, ranked candidate
IDs/scores, rejected alternatives, candidate count, and portfolio digest so the
decision can be reviewed directly as well as recomputed from the event chain.

A candidate then becomes a low-risk `PrincipalIntent`:

```text
domain = opportunity
action = review
reversible = true
external_effect = false
credential_use = false
financial_value_microunits = 0
constitution_change = false
```

A principal `deny` result suppresses that exact opportunity/profile state. A later externally installed profile revision creates a new state token and permits reevaluation.

## Shared interruption policy

Opportunity cards use the same `ProactiveEngine` as other CCT dialogue.

Therefore one global policy controls:

- attention threshold;
- semantic content digest;
- cooldown wakes;
- daily message cap;
- atomic at-most-once emission; and
- restart recovery.

Opportunity cards are checked before generic topic updates. Temporary `COOLDOWN` and `DAILY_CAP` gates do not consume opportunity state.

## Message contract

A card is rendered as:

```text
Task opportunity: <title>
Why now: <bounded rationale>
Proposed outcome: <bounded objective>
Authority: <proposal-only or existing-gates notice>
Proposal text is untrusted; inspect evidence before acting.
Operator feedback: ask Hermes to record INTERESTED / SKIP / SNOOZE(until YYYY-MM-DD) / DONE / BLOCKED.
Confidence: <bounded value>
```

Visible fields are NFKC-normalized, control/bidirectional characters are removed, multiline input is collapsed, lengths are bounded, and the shared 700-character policy remains the final cap.

The card stores only a registration-event reference as evidence. It does not copy plan content, workspace file content, raw conversation, hidden chain-of-thought, credentials, or producer instructions into the presentation receipt.

## Feedback semantics

`OpportunityInitiative.record_feedback` and the operator/host CLI accept:

- `INTERESTED` — operator interest and one later receipt-check generation;
- `SKIP` — terminal presentation decision;
- `SNOOZE` — defer until an ISO date;
- `DONE` — terminal task-outcome receipt; or
- `BLOCKED` — terminal blocker receipt.

`ACCEPT` and `DECLINE` remain compatibility aliases for older callers.

All feedback requires:

- an installed exact principal identity;
- a previously emitted card;
- a stable feedback ID;
- opaque URI-style evidence references; and
- an open opportunity; and
- the same principal ID/profile digest under which the card was presented.

Profile identity is rechecked inside the atomic feedback transaction. A profile
revision makes an outstanding card stale rather than rebinding it to the new
principal state.

Concurrent terminal feedback has one atomic winner.

Every feedback receipt states:

```text
execution_authority_granted = false
capability_lease_changed = false
opportunity_execution_status_changed = false
external_effects = 0
```

`INTERESTED` does not:

- change `source_authority`;
- make a self proposal executable;
- attach a plan;
- register a capability;
- grant or consume a lease;
- execute an autonomy run; or
- change public/external state.

Execution remains a separate later phase through the existing `AutonomyEngine` and typed capability boundary.

## Snooze and revision identity

A presentation state token binds:

- opportunity ID;
- exact registration event;
- active principal-profile digest; and
- latest feedback event.

A snooze receipt therefore creates a new semantic state. Before its date the card remains silent. At or after the date it may resurface once with a visible `Resurfaced after snooze` marker, producing a different semantic digest without weakening duplicate suppression.

## Event kinds

```text
principal.intent.decided
proactive.thought.created
proactive.initiation.decided
proactive.message.proposed
proactive.message.emitted
opportunity.initiative.completed
opportunity.initiative.feedback
```

`opportunity.initiative.completed` is append-once per state token. Competing scheduler processes converge on one canonical completion/emission state.

The scheduler boundary remains an at-most-once **delivery attempt**, matching the
existing proactive subsystem. A process failure after the emission claim but
before stdout reaches the platform may lose that delivery; restart will not emit
a duplicate. Exact transactional platform delivery remains a host-mediation
problem rather than being misreported as solved here.

## CLI

```bash
cct-engine --db state/agency.sqlite opportunity-feedback \
  --feedback-id telegram-message-123 \
  --opportunity-id candidate-1 \
  --principal-id mike \
  --decision INTERESTED \
  --authority operator \
  --evidence telegram:message-123
```

Snooze:

```bash
cct-engine --db state/agency.sqlite opportunity-feedback \
  --feedback-id telegram-message-124 \
  --opportunity-id candidate-2 \
  --principal-id mike \
  --decision SNOOZE \
  --authority operator \
  --snooze-until 2026-08-25 \
  --evidence telegram:message-124
```

## Hermes surface

Existing `cct_opportunity_propose` creates self-authority proposals. Existing
`cct_proactive_status` includes the opportunity-initiative projection. There is
deliberately **no** model-callable tool that can assert operator feedback.

Direct feedback requires explicit `--authority operator` or `--authority
host_adapter`. Ordinary chat replies are handled by the surrounding Hermes
operator flow; CCT does not auto-attribute raw turns until a host-signed
session/message receipt boundary exists.

The silent `cct_proactive_tick.py` scheduler automatically prioritizes task opportunities before generic topic updates. Idle ticks remain zero-LLM and emit zero bytes.

## Explicitly unchanged

No new authority exists for:

- shell/process execution;
- network/browser access;
- credentials or secrets;
- public posting or messaging beyond the existing scheduler delivery boundary;
- financial or legal effects;
- deletion or destructive replacement;
- irreversible effects; or
- constitution/profile/capability self-ratification.
