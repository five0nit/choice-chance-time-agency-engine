# CCTAE Administrative Dashboard

The administrative dashboard is a local-first operator control plane for CCTAE. Its default mode remains read-only. An explicitly configured second mode adds one narrow host-owned permission control without making browser state authoritative.

## Modes

### `READ_ONLY` — default

```bash
cct-dashboard \
  --db ~/.hermes/profiles/generalist2/cct-agency/agency.sqlite \
  --host 127.0.0.1 \
  --port 8787
```

This mode opens no canonical mutation route. `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS` remain denied.

### `CONTROLLED_HOST_APPLY` — explicit

Create one short-lived, owner-only bootstrap file in a private directory:

```bash
BOOTSTRAP_DIR="$(mktemp -d /tmp/cct-dashboard-bootstrap-XXXXXX)"
cct-dashboard-bootstrap \
  --out "$BOOTSTRAP_DIR/operator.json" \
  --principal-id mike \
  --ttl-seconds 600
```

Start the dashboard with that exact file:

```bash
cct-dashboard \
  --db ~/.hermes/profiles/generalist2/cct-agency/agency.sqlite \
  --host 127.0.0.1 \
  --port 8787 \
  --operator-bootstrap "$BOOTSTRAP_DIR/operator.json"
```

Open `http://127.0.0.1:8787/`. Read the token from the owner-only bootstrap file locally and paste it into the unlock field. A successful unlock atomically removes that exact descriptor-bound bootstrap file and fsyncs its owner-controlled parent, so the same file cannot be reused after a server restart. Invalid tokens do not consume it; any identity/change/delete failure denies the session. The returned operator session is in-memory, short-lived, bound to an `HttpOnly; SameSite=Strict` loopback cookie, and paired with a CSRF token that remains in page memory. Neither token is written to the CCTAE ledger.

Only `127.0.0.1`, `localhost`, and `::1` are accepted. Wildcard and LAN-facing bind addresses are rejected. Remote/Tailscale exposure is not part of this release.

## First controlled action

The only installed mutation is:

```text
SET_CAPABILITY_ADMINISTRATIVE_ACTIVE → operator.web
```

This controls a separate administrative pause projection; it does **not** rewrite the fixed host capability specification.

- **Pause:** changes `operator.web` administrative state to `PAUSED`. Existing leases remain recorded but cannot authorize evaluation, lease grant, ticket issue/claim, or reservation consumption.
- **Resume:** changes administrative state to active only when no active `operator.web` lease exists. Effective authority after resume remains `DENY` because no lease or ticket is created.
- Every other capability control remains unavailable.
- The control never creates a lease, ticket, access route, credential handle, provider call, or external effect.

## Mutation contract

```text
DRAFT
→ deterministic PREVIEW
→ exact operator CONFIRMATION
→ atomic HOST APPLY
→ canonical READBACK
→ append-only RECEIPT
```

### Preview

The preview performs no mutation. It binds:

- exact action and capability;
- requested administrative active state;
- fixed capability spec digest and revision;
- current administrative control revision;
- active lease IDs;
- principal profile digest;
- kill-switch transition state;
- expiry and preview SHA-256.

Unrelated ledger events do not invalidate a preview. A changed target spec, control revision, lease set, principal profile, or kill-switch state does.

### Confirmation

The host session authority signs the exact preview digest with a process-local key. Confirmation is principal-bound, session-bound, short-lived, and one-use. Freshness is checked once at request admission and again inside the `BEGIN IMMEDIATE` writer transaction after lock acquisition; an expired confirmation cannot commit after a database-lock wait. Raw bootstrap/session/CSRF/signature values are excluded from ledger receipts.

### Apply and readback

The browser sends an authenticated request; it never opens SQLite or edits policy/config files. The host service performs one `BEGIN IMMEDIATE` event-store transaction, revalidates all target state, and appends one `capability.control.state_changed` event. Concurrent tabs/processes cannot create two state changes from one confirmation.

Success is returned only after `CapabilityRegistry.status()` and event-chain verification match the expected administrative revision and state. HTTP success alone is not the receipt.

## Current views

- **Overview:** what happened, why it matters, current blocker, next action, and bounded counts.
- **Permissions:** fixed specification, administrative pause, risk, scope, active lease, remaining budgets, ticket requirement, kill-switch state, verifier, and one supported control.
- **Access:** authenticated route and target progression without credential or conversation content.
- **Automations:** CCT-native observed/run/verified/failed counts. It does not infer that a cron or provider is connected.
- **Approvals:** unresolved clarification metadata without raw question or answer text.
- **Audit:** fixed-vocabulary human narrative and exact receipt references.
- **Emergency:** global stop state and an audit jump. Kill-switch controls remain unavailable in this slice.

## Read and privacy boundaries

The dashboard:

- creates stable private SQLite snapshots for projections using bounded descriptor reads;
- caps each source database/WAL component at 256 MiB before allocation;
- validates the control database and parent as owner-controlled regular paths;
- accepts state-changing requests only from an exact same-origin loopback page;
- requires JSON content type, bounded request size, operator cookie, and CSRF token;
- suppresses raw exception causes at the HTTP boundary;
- emits strict same-origin, no-store, frame-denial, and CSP headers;
- renders dynamic values through `textContent`, never HTML insertion;
- never returns raw event payloads, conversation content, credential bytes, the database path, or bootstrap/session secrets;
- never treats connection, configuration, a clarification, or administrative resume as completed effect authority.

## State vocabulary

Permission states remain explicit:

- `DENY`
- `PAUSED`
- `DISABLED`
- `LEASED_TICKET_REQUIRED`
- `BLOCKED_KILL_SWITCH`
- `BLOCKED_CHAIN_INVALID`

A specification is not a lease. A lease is not a ticket. A connected route is not send authority. A preview is not confirmation. An appended change is not reported `VERIFIED` until canonical readback and chain verification pass.

## Discovery receipt

See [`docs/discovery/brief2ship-admin-controls-20260904.md`](discovery/brief2ship-admin-controls-20260904.md). No candidate code executed; no new dependency was added.
