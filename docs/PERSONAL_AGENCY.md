# Personal agency: acting as an extension of a principal

## Status

Implemented on the `phase11-personal-agency` development branch as version `0.8.0a1`.

This phase adds one real new capability—bounded workspace inspection—and the authority architecture needed to add stronger capabilities without confusing user alignment, permission, and execution.

It is not installed into a live profile or published as a release by this branch alone.

## Goal

CCT should act like a reliable extension of a named person:

- remember explicit values and standing directives;
- distinguish preferences from hard boundaries;
- escalate uncertainty and high-power effects;
- propose useful work independently;
- hold revocable typed authority;
- execute only when both principal alignment and capability authority allow it;
- preserve receipts explaining every transition.

The principal model is not impersonation. It is a structured delegation contract.

## Two-key authorization

```text
structured intent
    ↓
principal covenant
    allow / require approval / deny
    ↓
typed capability registry
    active lease / scope / budget / expiry
    ↓
combined personal-agency gate
    ↓
typed executor
    ↓
independent receipt
```

A principal `allow` result means *the action fits the installed operator profile*. It never means *the action has effect authority*.

A capability `allow` result means *a host-registered capability and externally issued lease permit this bounded request*. It does not establish that the request serves the principal.

Execution requires both.

## Principal covenant

`PrincipalProfile` contains:

- `principal_id` and display name;
- weighted values;
- bounded structured directives;
- uncertainty threshold;
- revision digest.

Directive kinds:

| Kind | Meaning | Grants effects? |
|---|---|---:|
| `preference` | Default style or choice preference | No |
| `priority` | Relative importance | No |
| `boundary` | Matching intent is denied | No |
| `escalation` | Matching intent requires approval | No |
| `grant` | Named high-power intent may pass principal alignment | Still no capability grant |

A high-power grant must include the exact domain, action, and every active
sensitive axis: `external-effect`, `credential`, `finance`,
`constitution-change`, and/or `irreversible`. A generic domain/action grant
cannot silently authorize a stronger axis.

Profiles may only be installed by `operator` or `host_adapter` authority. Revisions are hash-linked to the active profile digest.

Profile and capability-specification revisions require the exact previous
digest. Revision number, logical key, and payload are derived under one SQLite
writer transaction, so concurrent revisions have one winner and one stale
request instead of duplicate revision numbers.

Intent evaluation reads profile policy and digest from one event snapshot, then
atomically rechecks that digest before persisting the decision. A concurrent
profile revision causes bounded reevaluation; an allow calculated under an old
profile cannot be labeled with a new digest or reach capability reservation.

The model may call `propose_revision`. The resulting event always records:

```text
source_authority = self
content_trust = self_generated_untrusted_proposal
instructions_authorized = false
requires_operator_endorsement = true
auto_apply = false
```

Self-ratification remains disabled.

## Typed capability registry

A `CapabilitySpec` defines:

- stable name and effect kind;
- exact principal-intent domain and action binding;
- risk class;
- allowed scopes;
- verifier ID;
- reversibility;
- action, byte, and value ceilings;
- fail-closed default mode;
- active state.

A `CapabilityLease` defines:

- principal;
- capability;
- narrower scopes;
- expiry;
- smaller budgets;
- issuing authority;
- evidence.

Only `operator` or `host_adapter` may register specifications, grant leases, update specifications, or revoke leases. There is no model-callable grant tool.

Every request receives one of:

- `deny`;
- `require_approval`;
- `allow`.

Reason codes identify unknown capability, missing lease, expired/revoked lease, scope mismatch, principal mismatch, and budget overruns.

Lease budgets are cumulative, not merely per request. Admission and budget
consumption are computed under one SQLite `BEGIN IMMEDIATE` transaction, so
concurrent requests cannot both spend the last action, byte, or value allowance.

An effect reservation also carries the exact principal-profile SHA-256 used by
the alignment decision. The atomic reservation rechecks that digest against the
latest installed profile. A concurrent operator profile revision therefore
produces `PRINCIPAL_PROFILE_CHANGED` instead of authorizing under stale intent.
It also carries the canonical intent digest and must match the capability's
declared intent domain/action and the active profile's principal identity.

## Real capability: bounded workspace inspection

`WorkspaceInspector` reads one UTF-8 regular file when all gates pass.

Guards:

- configured existing workspace root;
- pinned open root directory descriptor and device/inode identity;
- relative normalized POSIX path;
- no `..`, absolute path, backslash, duplicate separator, or wildcard target;
- sensitive path classes blocked;
- descriptor-relative parent traversal;
- `O_NOFOLLOW` for root, parents, and target where supported;
- regular single-link target only;
- byte ceiling checked before and after read;
- principal alignment decision;
- active capability lease;
- single-use reservation consumption immediately before content read;
- exact scope and budget checks.

The returned result contains bounded text marked
`untrusted_workspace_content`; `instructions_authorized` is always false.
Deterministic prompt-override, role-impersonation, tool-instruction, and
secret-extraction phrases produce explicit taint flags. The event ledger stores
only path, byte count, SHA-256, inode identity, taint flags, lease, and
authorization receipt—not file content. Authorized read failures receive bounded
reason-code receipts; the lease budget remains consumed conservatively.

## CLI

Operator-only profile and authority setup:

```bash
cct-engine --db state/agency.sqlite principal-install \
  --profile examples/principal-profile.example.json \
  --authority operator \
  --evidence operator://reviewed-profile

cct-engine --db state/agency.sqlite capability-register \
  --spec examples/workspace-inspect-spec.example.json \
  --authority host_adapter \
  --evidence host://workspace-inspection-v1

cct-engine --db state/agency.sqlite capability-grant \
  --lease /private/reviewed-workspace-inspect-lease.json
```

Inspection:

```bash
cct-engine --db state/agency.sqlite workspace-inspect \
  --root /approved/workspace \
  --path docs/status.md \
  --principal-id principal \
  --lease-id lease-workspace-inspect \
  --intent-id intent-status-read \
  --request-id request-status-read \
  --authorization-id authorization-status-read
```

Revocation:

```bash
cct-engine --db state/agency.sqlite capability-revoke \
  --lease-id lease-workspace-inspect \
  --authority operator \
  --reason "Operator contracted authority."
```

## Hermes tools

Six tools are added:

- `cct_principal_status`;
- `cct_principal_evaluate`;
- `cct_principal_propose`;
- `cct_capability_status`;
- `cct_capability_evaluate`;
- `cct_workspace_inspect`.

The first five inspect, evaluate, or propose only. `cct_workspace_inspect`
creates a real read effect and requires:

1. configured `inspection_root`;
2. installed principal profile;
3. registered `workspace.inspect` capability;
4. active matching lease;
5. matching principal identity, scope, expiry, and byte budget.

## High-power preparation

The registry accepts risk classes for:

- `privileged`;
- `public`;
- `financial`;
- `constitutional`.

That is schema preparation, not execution authority. No executor exists yet for arbitrary shell, network, credentials, publishing, finance, or constitutional mutation.

Those domains need separate brokers and verifiers. Adding a spec alone cannot create an effect kind.

## Current invariants

- principal preference is not permission;
- capability permission is not principal alignment;
- both gates must allow execution;
- model-created revisions cannot activate themselves;
- model tools cannot register specifications or grant leases;
- scopes and budgets can narrow, never widen, when leased;
- unknown capabilities deny;
- missing leases never auto-allow;
- revoked and expired leases deny;
- lease action, byte, and value budgets are cumulative and race-safe;
- effect reservations are bound to the evaluated principal-profile digest;
- principal identity and intent domain/action are bound to the capability;
- revocation and expiry invalidate outstanding unconsumed reservations;
- every reservation is single-use;
- inspection content does not enter the event ledger;
- inspected text is always untrusted and never carries instruction authority;
- the event chain remains canonical and replay-verifiable.
