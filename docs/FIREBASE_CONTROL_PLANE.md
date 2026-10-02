# Firebase Owner Control Plane

## Live target

- Firebase project: `demo-cctae`
- Hosting URL: `https://demo-cctae.web.app`
- Authorized identity: exact verified Google account `owner@example.invalid`
- Canonical CCT state: profile-local `cct-agency/agency.sqlite`

Firebase Hosting serves a public application shell. Firestore data and every control request are deny-by-default and available only after exact Firebase Auth policy passes. No CCT state, credential, event payload, database path, bootstrap token, or session secret is embedded in the web bundle.

## Architecture

```text
Firebase Hosting static shell
  -> Firebase Auth: verified google.com identity
  -> Firestore owner-only request/receipt documents
       ^ outbound HTTPS only
       |
local hermes-cct-firebase-bridge.service
  -> Firebase Admin re-verifies UID/email/provider
  -> zero-mutation CCT preview
  -> exact receipt-bound apply request
  -> short-lived local confirmation
  -> BEGIN IMMEDIATE host apply
  -> CapabilityRegistry + event-chain readback
  -> privacy-minimized Firestore receipt
```

Firebase does not connect to SQLite. Browser code cannot write dashboard projections or receipts. Local bridge service account can access only this dedicated Firebase project and holds no Hermes or Telegram credential.

## Firestore model

- `cct_dashboard/current`: privacy-minimized dashboard projection; bridge write, owner get.
- `cct_bridge_status/current`: bounded liveness receipt; bridge write, owner get.
- `cct_control_requests/{requestId}`: owner create/get; no client update/delete/list.
- `cct_control_receipts/{requestId}`: bridge write, owner get; no client write/list.

Apply creation requires an existing matching owner-bound preview receipt and exact SHA-256. Local apply revalidates current CCT state. Crash recovery identifies the existing canonical CCT event by deterministic draft ID plus preview digest and returns the original event instead of mutating twice.

Every request also carries a freshly minted Firebase ID token. The local bridge verifies its Firebase signature, project audience, revocation state, immutable UID, verified email, Google provider, and issuance freshness before local work. Receipts retain only its SHA-256; the raw token is removed from the completed request. Apply requires a different fresh token from its parent preview. This prevents possession of the bridge service-account key alone from fabricating an accepted owner request.

Before an APPLY can mutate local state, the bridge appends one privacy-minimized authorization event to the canonical hash chain. It binds the exact request and token digests without storing the token or email. If the process crashes after canonical apply but before Firestore completion, the same exact request can later recover canonical readback from that durable authorization even after the transient request/token expiry. A different or modified request still requires live owner verification and cannot create a new effect after expiry.

## Auth policy

`firebase.json` enables only Google Sign-In. Anonymous and Email/Password providers are disabled. `firestore.rules` independently requires:

- authenticated user;
- `email_verified == true`;
- exact email `owner@example.invalid`;
- `firebase.sign_in_provider == google.com`;
- request `ownerUid == request.auth.uid`;
- exact request schemas and server timestamps.

The Firebase UID is pinned in the local bridge config, Firestore Rules, and hosted `ownerPolicy.pinnedUid`. The record is linked to the real `google.com` provider subject, with verified email and no password credential. Access therefore requires the exact UID, exact verified email, and Google sign-in provider.

## Build and test

### Sign-in bootstrap regression

Google popup authentication dynamically loads scripts from `https://apis.google.com`. Hosting CSP must allow that exact origin in `script-src` in addition to `'self'`; do not add wildcard scripts, `unsafe-inline`, or `unsafe-eval`. A reachable owner gate does not prove sign-in works: exercise **Continue with Google** in a clean browser, assert no CSP violation, and verify the real Google sign-in page opens without entering credentials. Test desktop and phone viewports. Existing owner UID/email/provider checks and Firestore Rules remain unchanged.

Telegram/in-app browsers can impose their own Google OAuth restrictions. Open the link in Chrome or Safari; keep password, MFA, and consent prompts as user handoffs.

This repair uses the Brief2Ship tiny-edit exception: existing canonical Firebase worktree, established Firebase SDK/build/test stack, no new implementation base or dependency. Live CSP violation and a two-test RED regression are the pre-edit evidence.

```bash
cd firebase/hosting
npm ci
npm test
npm run build
npm run test:rules
cd ../..
python3 -m pytest -v --tb=short tests/test_firebase_bridge.py
python3 -m pytest -v --tb=short
```

## Local bridge configuration

Copy `config/firebase-bridge.example.json` to the profile-local config path and set mode `0600`. Service account JSON belongs in profile-local secret storage with mode `0600`; never commit it.

Expected profile paths:

```text
/path/to/profile/config/cct-firebase-bridge.json
/path/to/profile/secrets/cctae-firebase-bridge.json
/path/to/profile/runtime/cct-firebase-bridge/
```

## Quota-safe polling and local health

Continuous mode waits at least **30 seconds** after each successful tick, including
when a legacy v1 config still says `poll_seconds: 3`. Set `poll_seconds` explicitly
to `30` for operational clarity; the exact v1 fields and accepted range remain
unchanged. `--once` still performs one tick without sleeping and exits nonzero if
that tick fails.

An idle tick makes two projection/status writes and two queries. Ignoring RPC
latency, 3-second polling would make 57,600 baseline writes/day; 30-second polling
makes at most 5,760 baseline writes/day and 5,760 empty-query minimum reads/day.
Request processing, populated queries, browser reads, restarts, and extra manual
`--once` invocations add usage. This is not a project-wide quota guarantee.

- `ResourceExhausted`/HTTP 429: `QUOTA_BACKOFF`, starting at 300 seconds and doubling
  to a maximum of 1,800 seconds.
- Recognized temporary cloud failures: `TRANSIENT_BACKOFF`, starting at 30 seconds
  and doubling to a maximum of 300 seconds (never faster than configured polling).
- SDK `RetryError` wrappers are inspected by trusted exception type and bounded
  cause traversal, not error-message matching. Successful ticks reset backoff.
- Unknown/programming failures are fatal/nonzero, not silently retried or completed
  as owner denials. Only explicit request/identity authorization failures are denied.
- Firestore document reads, writes, and completion batches use `retry=None`.
  Query streams use `Retry(predicate=lambda _error: False)`: Firestore 2.30.0
  requires the Retry interface when handling iterator errors, even when retries
  are disabled. All RPCs use a 10-second timeout. Request claims use an atomic update-time
  precondition instead of SDK transactions with hidden begin/commit/rollback
  retries. A competing update makes the claim fail without processing the request.

The pinned-SDK compatibility gate must run with `firebase-admin==7.5.0` and
`google-cloud-firestore==2.30.0` installed, not merely optional-test skips. It
constructs the real identity adapter (tenant mismatch is exported from
`firebase_admin.tenant_mgt`, not `firebase_admin.auth`) and injects failures into
real query iterators with network-free mocked RPCs. Each failure must retain its
original SDK type and make exactly one RPC attempt.

The singleton bridge writes `<runtime_directory>/bridge-health.json` atomically
with mode `0600` inside its validated owner-only runtime directory. It records
`CHECKING`, `ONLINE`, `QUOTA_BACKOFF`, `TRANSIENT_BACKOFF`, or `FAILED`, plus bounded
`reasonCode`, `checkedAt`, `lastSuccessAt`, `retrySeconds`, and `nextAttemptAt` fields.
Failure output never serializes exception messages, credentials, tokens, or cloud
payloads. The local receipt remains available even when Firestore rejects writes;
no extra cloud write is attempted to announce a failed cloud write.

Use this local receipt and the service process state together during recovery.
A previous remote `ONLINE` snapshot can remain stale while quota is exhausted;
remote timestamps must not be treated as current liveness. A receipt is a last
observation, not proof a stopped process is still running. Quota backoff does not
restore exhausted daily quota: wait for provider quota recovery and verify a fresh
successful tick. Do not use repeated `--once` calls or service restarts to bypass
backoff. No UI freshness changes or automatic service restart are part of this fix.

A cloud failure after canonical APPLY still leaves the request recoverable through
the existing exact durable authorization and event readback. Backoff does not
extend authorization expiry or allow an expired request to create a new effect.

## Deployment

```bash
firebase deploy --only auth,firestore:rules,firestore:indexes,hosting --project demo-cctae --json
```

No Cloud Functions or billing-plan upgrade required.

## Rollback

1. Stop and disable `hermes-cct-firebase-bridge.service`.
2. Revoke/delete service-account key.
3. Deploy closed Firestore rules or disable Google provider.
4. Roll Hosting back through Firebase release history.
5. CCT event ledger remains append-only. Any already verified administrative pause/resume remains auditable and must be reversed through a new exact control operation, never by deleting history.

## Security non-claims

- Hosting app shell is publicly downloadable; data and controls are not.
- Firebase connectivity is not CCT effect authority.
- Administrative resume leaves effective `operator.web` authority `DENY` unless separate matching lease and ticket exist.
- Bridge receipts report `externalEffects: 0`; this control does not perform browser/provider work.
