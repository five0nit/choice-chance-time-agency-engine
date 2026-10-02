# CCT controlled full-stack autonomy implementation plan

## Claim boundary

CCT will demonstrate bounded, reasons-responsive operational agency for one operator-approved fixture by selecting and executing a hash-bound plan through typed, leased, receipt-backed local capabilities; it will not claim consciousness, unrestricted authority, credential autonomy, or real public/deployment effects.

## Target and constraints

Extend canonical `cct-free-agent` with test-only controlled research, sandbox command, reversible patch, registered verification, local fake deployment, and fake public-action adapters while leaving every live profile, gateway, service, database, credential, and external system untouched.

## Delivery mode and evidence gate

- Mode: TDD, one coherent green slice per coordinator tick.
- Preflight: `docs/discovery/brief2ship-full-stack-autonomy-20260824.md`.
- Disposition: `build-clean` in this canonical repository; no candidate code executed or imported.
- Per-slice gate: RED test observed, minimal implementation, focused GREEN, relevant regression suite, Ruff, compile, clean commit.
- Final gate: all acceptance flags in `reports/full-stack-autonomy-latest.json`, full verbose suite, package/install/loader proofs, immutable-commit reviews.

## Authoritative representations

1. Operator-approved goal and structured plan: append-only event ledger plus private hash-bound plan payload.
2. Capability authority: host-registered `CapabilitySpec`, externally issued `CapabilityLease`, and exact execution ticket bound to tool name, arguments digest, principal profile, plan, stage, and attempt.
3. Runtime decision: `tool_execution` middleware receipt. Denial result is returned directly and never calls `next_call()`.
4. Effect result: downstream tool result plus typed adapter verification receipt.
5. Durable outcome: bounded event payloads and final acceptance report. Raw credentials, hidden chain-of-thought, producer prose, command output beyond caps, and private artifact bytes remain absent.
6. User/live/durable result semantics: middleware returns same structured result Hermes places in live and durable tool rows; CCT stores only bounded receipt metadata and hashes.

## Invariants

- Mediation applies only to explicit host-selected tool names. CCT's own status/governance tools and unrelated interactive tools remain outside this controlled acceptance envelope.
- Every selected tool call requires one live ticket and one live lease. No implicit/default grant.
- Ticket binds exact canonical argument SHA-256, tool name, goal, plan, stage, principal, capability, lease, and expiry.
- Middleware catches its own policy/validation failures and returns structured denial. It never relies on exceptions because Hermes execution middleware may fail open before downstream dispatch.
- Denied, unleased, expired, out-of-scope, malformed, replayed, or wrong-stage calls invoke `next_call()` zero times.
- Allowed calls atomically reserve and consume budgets before dispatch, then invoke `next_call()` exactly once.
- Effects use logical idempotency keys. Crash/retry adopts prior receipts; command, deployment, and public-action sinks never duplicate effects.
- Verification is host-registered. Model-supplied shell strings never become verifier authority.
- Project patch requires expected-before hash, backup, exact after hash, and rollback receipt. Failed verification blocks every later effect stage.
- Plans persist structured summaries and hashes, never hidden chain-of-thought.
- Chance never grants permission and blocked options never enter selection probabilities.

## Slice sequence

### Slice 0 — preflight and plan

- Normalize discovery receipt to documentation mode `0644`.
- Commit retained Brief2Ship receipt and this plan.
- Keep durable status `BUILDING`.

### Slice 1 — fail-closed `tool_execution` mediation shell

RED/GREEN contracts:

- plugin registers exactly one `tool_execution` middleware;
- selected tool without ticket returns structured `CCT_MEDIATION_DENIED`;
- denial never calls `next_call()`;
- unrelated tool passes through and calls `next_call()` exactly once;
- malformed selected call returns denial without throwing;
- denial receipt excludes raw arguments and stores canonical argument digest only;
- middleware-internal persistence failure still denies selected tool without downstream execution.

Implementation: standalone `cct_agent.mediation` kernel plus plugin wrapper and strict profile-local config parsing. No live activation.

### Slice 2 — execution tickets and atomic authority

- Add host-issued `ExecutionTicket` schema and append-only issuance/revocation events.
- Bind ticket to goal/plan/stage/tool/arguments/principal/spec/lease/expiry.
- Atomically authorize, reserve lease budget, and consume ticket in one store transaction.
- Deny unknown/revoked/expired/mismatched/replayed tickets.
- Deterministic multi-process tests prove one winning consumption and zero budget overshoot.

### Slice 3 — allowed dispatch, outcome verification, crash recovery

- Allowed middleware calls `next_call()` exactly once.
- Record pre-dispatch claim before effect and bounded post-dispatch receipt after result.
- Add typed verifier registry and result parser.
- Reconcile claim-without-receipt and receipt-without-completion windows.
- Never retry an effect unless adapter idempotency proof authorizes receipt adoption.

### Slice 4 — durable goal → plan → worker handoff

- Add attributable approved-goal fixture, genuine alternatives including `NO_OP`, scored decision, hash-bound hierarchical plan, stage dependencies, and worker cursor.
- Persist plan summaries, option predictions, seed/probability receipt, chosen/rejected branches, and state transitions.
- Fail closed on plan hash drift, constitution mismatch, stale principal profile, or invalid dependency order.

### Slice 5 — typed read-only online research

- Add bounded allowlisted HTTPS research request and local deterministic HTTP fixture.
- Reject redirects, userinfo, query/fragment in configured base, non-allowlisted host, oversized body, unsafe content type, and proxy inheritance.
- Store source URL/hash/status/byte count; quarantine source prose from authority fields.

### Slice 6 — sandboxed argv command

- Host registry maps command ID to immutable argv/cwd/environment/time/output bounds.
- No shell, metacharacter interpretation, arbitrary executable, ambient secret environment, or outside-workspace cwd.
- Idempotency ledger prevents duplicate execution after crash/retry.
- Receipt records command ID, argv digest, exit status, bounded output hashes/counts, and duration.

### Slice 7 — expected-hash reversible patch

- Exact relative path, expected-before hash, bounded patch payload, backup, descriptor-safe traversal, atomic write, and exact after hash.
- Registered verification failure restores before bytes and records rollback.
- Foreign post-write mutation blocks clobbering rollback and blocks later stages.

### Slice 8 — registered verification

- Host-defined verifier IDs only; immutable argv and timeout/output caps.
- Bind verification to plan/stage and project snapshot hashes.
- Structured pass/fail receipt; failure transitions plan to rollback/failed and makes deployment/public stages ineligible.

### Slice 9 — local fake deployment

- Typed deployment adapter targets local fake sink only.
- Preview artifact and manifest hashes required.
- Atomic idempotency claim plus sink receipt; retry returns same deployment receipt without second sink mutation.
- No network deployment provider, auth, credentials, production route, or public endpoint.

### Slice 10 — fake-sink public action

- Typed channel/action/schema with local append-only fake sink.
- Exact payload digest, approval provenance, idempotency key, cap, and verification readback.
- No platform SDK, token, email, post, payment, trade, form, or third-party request.

### Slice 11 — autonomous full-stack episode

- One operator-approved arbitrary-goal fixture generates genuine alternatives and chooses one plan.
- Worker autonomously completes research → command → patch → registered tests → fake deployment → fake public action.
- Acceptance receipt links all stage claims, effects, verifications, and final observed outcome.
- Matched failure episode proves verification rollback and zero later external stages.
- Crash injections prove command/deployment/public-action exactly-once sink effects.

### Slice 12 — package/runtime/release verification

- Full `python3 -m pytest -v --tb=short` with explicit collected/passed count.
- `ruff check`, compile checks, clean package build.
- Record artifact SHA-256.
- Install exact wheel outside repository; run CLI/demo.
- Inspect `hermes_agent.plugins` entry point and loaded type.
- Real Plugin Doctor and disposable `HERMES_HOME` loader assert exact tools/hooks/middleware counts, state isolation, context cap, and private sentinel absence.
- Verify source package version, installed distribution version, `module.__file__`, plugin constant, and handler result separately.
- Do not install into Generalist2 profile or change live config/service.

### Slice 13 — immutable final reviews and TEST_READY receipt

- Commit exact candidate and confirm clean worktree.
- Independent reviewer 1: security/state integrity, no edits, exact SHA.
- Independent reviewer 2: runtime/product integration, no edits, exact SHA.
- Any source change invalidates both verdicts; fix, commit, rerun all gates, and dispatch fresh reviews.
- Require both PASS with no HIGH/CRITICAL blockers.
- Write `reports/full-stack-autonomy-acceptance-<commit>.md` and `reports/full-stack-autonomy-latest.json` with exact commit, commands, counts, artifact paths, receipts, and known limits.
- Set `status: TEST_READY`; stop source changes. No live install, enable, or reload.

## Test matrix

- Denial: unknown tool mapping, absent ticket, malformed args, malformed config, unknown/expired/revoked lease, inactive spec, wrong principal, changed profile, changed spec, scope mismatch, budget exhaustion, ticket replay, plan hash mismatch, wrong stage.
- Dispatch: pass-through once, mediated allow once, downstream exception once, middleware persistence/verification failure no duplicate dispatch.
- Concurrency: synchronized threads and subprocesses for ticket consumption, lease budgets, command sink, deployment sink, public-action sink, and same-stage worker completion.
- Crash windows: ticket claimed/no effect, effect/no receipt, receipt/no stage completion, patch/no verification, verification failure during rollback.
- Privacy: recursive scan for research body, raw command output, patch bytes, private markers, credentials/sentinels, hidden reasoning, and fake public payload prose outside authorized sink.
- Integrity: ledger hash chain, exact plan digest, exact before/after hashes, source/installed commit or wheel digest, constitution continuity.

## Final known-limit contract

TEST_READY proves controlled local acceptance only. It does not prove live public deployment, real social/email action, autonomous credential use, financial authority, unrestricted shell/network access, continuous consciousness, phenomenal experience, or metaphysical free will. Any live capability requires separate operator-issued specs/leases, target-specific adapters, approval, isolated rollout, and post-activation verification.
