# Autonomous Builds — implementation contract

## Discovery/base decision

Target: extend the existing authenticated CCT Firebase dashboard and private delivery worker with an artifact library, real budget controls, and durable follow-up actions, without increasing live limits automatically or granting new effect classes.

Brief2Ship executed without candidate execution or dependency installation. Receipts:
- `/tmp/brief2ship-preflight-cct-builds-etFldh/discovery.json` — broad local/GitHub/npm/PyPI query, inconclusive.
- `/tmp/brief2ship-preflight-cct-builds-local-MvmSEl/discovery.json` — refined local inspection, inconclusive CLI score 70.17/100, decision score 65.64. Pinned local commit `6462a3f55c4cd3106452bd71728895b6eb8f9db0`.

Human disposition: **selective-reuse** of the canonical CCT repository. Relevant owner_delivery Python implementation, FirebaseOwnerGateway, hosting manifests and MIT LICENSE inspected directly. CLI license blocker resolved by direct reading of the standard MIT license, copyright Michael Costea and contributors. Dependency-free Python core and existing Firebase stack need no new application framework. New candidate sandbox execution was deliberately not requested; regression/package verification follows implementation. Package-version OSV evidence remains unavailable, not asserted clean.

Rejected alternative bases: `adafruit-circuitpython-requests@4.1.17` (CLI 65.67/100, HTTP client for CircuitPython, not an artifact/control plane); `act-build@0.12.0` (55.86/100, ACT WASM build tooling, wrong execution/data model). Existing CCT code supplies the exact identity, authority, sandbox, durable jobs and projection seams. No replacement kernel, generic execution tool or new public effect authority.

## Owner experience

Route `#owner-builds`, label `Builds`. Show every projected build with title, purpose, status, creation time, verification scope, immutable files (plain text viewing and download), parent/root lineage, follow-up requests and reasons for waiting. Search and archive/restore. Preserve previous versions. Do not describe model review as arbitrary correctness or revenue. Existing live artifact must appear after worker projection; no model call needed for backfill.

Controls expose global rolling-24-hour budgets and actual charged usage; requested versus host-applied revision stays distinct. Defaults remain existing 1 job / 12 model calls, with tool dispatch cap 4. Host ceilings: 4 jobs / 20 provider calls / 12 tool calls. Tool calls here mean bounded sandbox verification dispatches, NOT generic Hermes tools, network requests, tests within a sandbox, or Firebase sync reads. State that directly in the UI. Provider calls mean tool-free delivery model requests; transport retries must not silently exceed accounting. Existing service-authority, pause, identity and final effect gates remain intact.

## Wire contract v1

All collections owner-readable only. Build/file/usage/status projections host-written only. Owner writes validated intent, never runtime status.

### `cct_owner_builds/{buildId}` (host projection)

Fields: `schemaVersion: 'cct.owner_build.v1'`, `ownerUid`, `buildId`, `parentBuildId` (empty for original), `rootBuildId`, `action` (`build|upgrade|steer|discover`), `title`, `summary`, `status`, `reason`, `createdAt`, `updatedAt`, `bundleDigest`, `archived` (bool), `verification` (object), `usage: {providerCalls, toolCalls}`, `files: [{path, content, sha256}]`. Optional `requestId`, `instructions`. Bound all payloads below Firestore document size. Files displayed as text/download only, never execute HTML/JS/Markdown. Server projection may include additional strictly read-only evidence.

### `cct_owner_build_controls/current` (owner intent)

Exact fields: `schemaVersion: 'cct.owner_build_controls.v1'`, `ownerUid`, `revision` (positive integer, previous+1 in transaction), `maxDailyJobs` (1..4), `maxDailyProviderCalls` (1..20), `maxDailyToolCalls` (1..12), `updatedAt` (server timestamp). UI previews before confirmation and writes using Firestore transaction. Initial revision 1; deletes prohibited. Host rejects invalid controls, stale/reused revisions, owner drift. Never silently discard existing usage on budget changes.

### `cct_owner_build_controls_status/current` (host readback)

`schemaVersion: 'cct.owner_build_controls_status.v1'`, `ownerUid`, `requestedRevision`, `effectiveRevision`, `state`, `reason`, `effective: {maxDailyJobs, maxDailyProviderCalls, maxDailyToolCalls}`, `ceilings` with same keys, `usage: {jobs, providerCalls, toolCalls}`, `updatedAt`. Default effectiveRevision 0 until owner intent applied. Effective defaults read existing local config (1/12), new tools 4. Status must refresh even while job cap reached. Preserve rolling usage; fail closed on invalid controls.

### `cct_owner_build_requests/{requestId}` (immutable owner request)

Exact fields: `schemaVersion: 'cct.owner_build_request.v1'`, `ownerUid`, `requestId` (safe UUID/identifier 1..100), `parentBuildId`, `parentDigest` (64 lower hex), `action: 'upgrade'|'steer'|'discover'|'archive'|'restore'`, `instructions` (string 0..2000; steer nonempty), `maxProviderCalls` (1..20), `maxToolCalls` (1..12), `createdAt` (server timestamp), `expiresAt` (timestamp, up to 7 days after creation), `controlRevision` (nonnegative integer). Create only. Match exact parent bundle digest, current control revision, owner, expiry and available authority before accepting. Preview target/action/budget/instructions; confirm exact frozen payload. Ordinary queue waiting after acceptance does not expire the accepted work. Duplicate reads/wakes do not repeat actions. Two requests are distinct explicit requests; same ID/payload is idempotent.

### `cct_owner_build_request_status/{requestId}` (host receipt)

`schemaVersion: 'cct.owner_build_request_status.v1'`, `ownerUid`, `requestId`, `parentBuildId`, `action`, `state` (`QUEUED|WAITING_BUDGET|RUNNING|COMPLETE|REJECTED|FAILED`), `reason`, `buildId` (empty until assigned), `updatedAt`; optional exact evidence.

## Runtime behavior

- Backfill saved jobs into owner-only library, preserving originals and certifying only known verification receipts.
- Host consumes a bounded durable request stream; restart-safe cursor/ingest so terminal old requests cannot starve newer requests. Job ID derived from request ID, persisted before model/OS/service effects.
- `upgrade` / `steer`: child artifact generation uses parent's actual saved bundle and source evidence plus clearly separated owner instructions, then existing independent acceptance, sandbox and separate review. Original bundle unchanged. Per-request model/tool budgets are enforced cumulatively as well as global budgets. Exhausted budgets yield explicit waiting/blocked state, no retry storm.
- `discover`: produce a saved, separately reviewed discovery brief from the build and available evidence: gaps, alternatives, proposed upgrades and further research questions. Explicitly label **saved-evidence exploration; no fresh web research**. Does not masquerade as independent factual verification or a new web capability. Prefer deterministic rendering of a bounded structured discovery response. It needs no executable sandbox; report type and verification honestly. Saved brief is visible and can be used as the parent of later upgrade/steer work.
- `archive` / `restore`: reversible library organization only; retain files/history. No build/model/effect authority expansion.
- Requests awaiting global quota are retained and resumed. Updating limits takes effect at host readback and next allowed stage, not only the form.
- Provider attempt accounting is persistent and serialized; disable model SDK retries or account every transport attempt. Sandbox dispatches use a separate persistent charged counter and remain mandatory fail-closed with no generic shell/network/credentials.
- Owner pause/identity checks apply before model invocation, sandbox execution, request activation and notifications; no bypass by budgets, promotion or discovery.

## Work lanes and verification order

Backend lane: `cct_agent/owner_delivery.py`, `cct_agent/owner_delivery_model.py`, new `cct_agent/owner_builds.py`, targeted Python tests and `docs/OWNER_BUILDS_RUNTIME.md` only.
UI lane: `firebase/hosting/**` only; parent owns package script integration if necessary.
Parent: `firestore.rules`, rules tests, cross-lane integration, rollout, independent review.

Write all implementation/tests first; only run tests once parent confirms all slices integrated. Syntax/import checks okay. No child deploy, commit, runtime config, live calls, credentials, global installs or generated-code host execution. Keep current live delivery worker unchanged until verified release. Parent verifies all child output rather than trusting summaries.
