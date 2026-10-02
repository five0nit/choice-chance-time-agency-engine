# Private continuation runtime

Implementation contract: [OWNER_CONTINUATION_CONTRACT.md](OWNER_CONTINUATION_CONTRACT.md). Rollout evidence must be recorded separately; this document is an operating contract, not a success receipt.

## What changes

The same `hermes-cct-owner-delivery-generalist2.service` performs one serialized bounded cycle per wake. Explicit Builds requests and existing pending jobs take priority. With continuation enabled, saved candidates, factual reports, exact private artifacts and host-certified outcomes feed automatic selection. Public research uses fixed catalog IDs only. A reviewed proposal becomes a private delivery job through the same generation, networkless Bubblewrap, host acceptance, independent semantic review and exact private dashboard notification readback stages.

No generic model tools, host shell, project edits, browser sessions, account access, public posting, payments or trades are added. Catalog evidence can inform numerical experiments but is not proof of account eligibility, executable prices, financial viability or revenue.

## Controls and bounds

Host opt-in file: `<HERMES_HOME>/config/cct-owner-continuation.json`, regular single-link private file, schema `cct.owner_continuation.config.v1`, bound to the existing `ownerUid`/`projectId`, with `enabled` and non-secret `authorization` provenance. It must never be generated from a model result or client projection. Missing config in a never-enrolled profile preserves legacy behavior. After enrollment, deletion/replacement/revocation must fail closed rather than falling back to old automatic selection.

Current deployment scope preserves existing **1 job / 12 provider calls / 4 sandbox dispatches** per rolling 24h; no budget-reset or quota bypass. All continuation model stages share provider accounting. Public evidence has a separate hard **2 fetch attempts per rolling 24h** ceiling. Failures/interrupted requests count; repeated same-cycle source consumption cannot cause another network request. Each automatic artifact receives an initial build plus at most one repair. Existing explicit owner requests retain their original limits.

Pausing learning or Full autonomy in the authenticated workspace stops new effects, including resumed automatic jobs. Every model/network/sandbox/notification boundary rechecks current owner/host authority. Stale or unavailable identity/control/projection data does not permit optimistic execution. No model may widen its envelope based on successful outcomes.

## Outcome and novelty

Host-certified completion is evidence of local behavior, not self-reported usefulness. Outcomes retain exact parent/child IDs, immutable artifact digests, acceptance and independent review. A bounded planner can choose new work, a demonstrably new version, a factual gap, or WAIT. An independent novelty review rejects solved/renamed ideas. Structural fingerprints and durable decisions suppress exact retries across restarts; semantic review is a bounded model judgment, not a mathematical guarantee of global originality.

The host retains cumulative stage limits and backoff so outages and unchanged evidence do not consume provider calls on every 60-second wake. Daily cap exhaustion preserves the current checkpoint; lifetime exhaustion stops that cycle rather than silently renewing its allowance tomorrow. Genuine new evidence or a completed outcome can justify another cycle.

## Public evidence boundary

The initial catalog reuses `owner_work_web.CATALOG`: DEX Screener docs, Solana fee docs, CoinGecko rate-limit docs, and Kraken public BTC/USD pair/ticker/order-book snapshots. This is **fresh allowlisted public-source research**, not unrestricted Internet search. The model may select IDs; it cannot introduce URLs, query parameters, redirects, credentials or new domains. Bytes, DNS-pinned transport, response types and timeouts remain host bounded. All fetched text stays untrusted evidence.

## Operator UI

Builds receives the existing host-written `cct_owner_delivery/current` projection with nested `continuation` status. It shows what happened, what improved, the selected objective, next action, exact blocker/eligibility time and separate public-GET usage. Missing/malformed/stale status shows unavailable; it never turns an absent projection into a success or claims a selected follow-up has executed. Dynamic text remains escaped and private DOM resets on sign-out. No new Firestore client-write authority is required.

## Release and rollback

Intended interpreter: `/path/to/operator-home/.hermes/profiles/generalist2/releases/cct-continuation-20260915-r2/venv/bin/python`. Prior Builds interpreter remains `/path/to/operator-home/.hermes/profiles/generalist2/releases/cct-builds-20260915/venv/bin/python`. Only the private worker may reload; default and generalist2 Telegram gateway services remain untouched.

Continuation provider charging uses the continuation gate at the final accounting boundary. Its local enrollment check runs after potentially blocking gateway/control reads, before the transaction charges or invokes a provider. Revocation regressions cover planning, decision and novelty stages at both provider gates, including disabled/missing enrollment and owner/project/authorization drift. This is a narrow correction in the canonical repository; the original Brief2Ship selective-reuse receipts remain the build-base evidence, not a new implementation.

Before rollout: finish all slices, run source/full-cycle/boundary/UI/rules/browser suites, review an exact commit, reproduce a clean wheel twice, run installed tests outside the repo, and perform bounded actual-provider/public-fetch checks without resetting budgets. Live readback must confirm source hashes, exact service command/PID, fresh owner projection, unchanged effective caps, original artifact integrity and unrelated gateway PIDs. Backend readback and emulator rendering do not establish signed-in production visual verification.

Rollback first stops the private worker. Preserve the live database and usage; do not restore a pre-rollout snapshot over later valid events. Keep the worker stopped if continuation jobs remain pending: the older worker cannot safely interpret their new authority/lineage. Restore the saved unit/prior interpreter and prior Hosting version only after pending work is explicitly reconciled. Keep config and evidence backups private. Never broaden permissions or reset budgets to clear a blocked test.
