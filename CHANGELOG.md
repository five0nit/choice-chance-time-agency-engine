# Changelog

All notable public changes are documented here.

## 0.9.0a22 — public candidate (unreleased)

- Consolidates the create-only core and optional capability-limited operator/owner integrations in the public documentation.
- Documents Python >=3.11, the standard-library core, optional Firebase dependencies, and Linux/POSIX sandbox prerequisites without promising cross-platform parity.
- Replaces private operational logs, raw discovery receipts, host-specific paths and deployed owner/cloud identifiers with durable architecture, configuration and verification guides.
- Adds the educational GitHub Pages entry point and intended version-pinned Git installation; neither implies publication or deployment has completed.
- Tracks full tests, package/build inspection, installed checks, site verification, and remote readback as explicit release gates in [PUBLIC_RELEASE.md](PUBLIC_RELEASE.md).

## 0.9.0a21 — development

### Firebase owner control plane

- Fixed Google sign-in bootstrap being blocked by Hosting CSP; allowed only the required `https://apis.google.com` script origin, retained bounded bootstrap error codes, and added in-app-browser guidance.
- Added an exact verified-Google-owner Firebase Hosting dashboard with deny-by-default Firestore rules.
- Bound each Firebase control request to a freshly verified owner ID token, scrubbed raw tokens after completion, required a distinct APPLY proof, and removed the owner email from the public bundle.
- Added a privacy-minimized pre-effect authorization event so post-apply crashes recover exact canonical readback after request expiry without permitting a new stale effect.
- Added an outbound-only local sidecar that publishes a privacy-minimized snapshot and processes `PREVIEW` / `APPLY` request-receipt pairs.
- Preserved canonical SQLite authority, expiry/replay gates, atomic host apply, crash adoption, and canonical readback for `operator.web` administrative pause/resume.
- Added Firestore emulator tests, hosted bundle contract tests, profile-local systemd packaging, and rollback documentation.

## 0.9.0a17 — development

### Operator-endorsed standing autonomy

- encode Mike's automatic, earned, and per-operation capability classes with deterministic `per_operation` conflict precedence;
- keep raw password, MFA, recovery-code, and secret entry behind opaque host brokerage or authenticated human handoff;
- require exact verified facts and no pending CAPTCHA, MFA, legal declaration, protected self-report, or human attestation before standing-authority job submission;
- add profile-owned mode-0600 authority/config binding, registered project roots, immutable command IDs, expected-utility/uncertainty gates, expiring lease budgets, single-use tickets, readback verification, and global-kill-switch failure handling;
- add process-serialized `cct-standing-autonomy` worker with unchanged-Git-state silence and automatic earned-tier promotion inside the operator-approved ceiling;
- conditionally expose `cct_standing_autonomy_status` and `cct_standing_autonomy_run`; callers cannot supply command text, project paths, secrets, budgets, or arbitrary effect parameters.

## 0.9.0a16 — development

### Deterministic human narrative layer

- add a read-only, dependency-free projection that translates significant ledger events into concise operator language without changing canonical events;
- expose human status, latest-event explanation, and bounded activity digests with exact event references;
- keep arbitrary payload text, secrets, producer prose, and raw technical bodies out of narrative output;
- preserve raw `status` and `events` surfaces as explicit technical drill-down;
- add one preferred Hermes narrative tool while retaining all existing governance and effect-authority boundaries.

### Connected capability self-model

- project legacy verified `autonomy.run.completed` receipts into capability competence without rewriting the canonical ledger;
- create one replay-safe success prediction before each new typed autonomy attempt and resolve it once after independent completion evidence;
- keep learned competence explicitly separate from capability leases, permissions, and effect authority.

### Causally regulated attention

- feed bounded interoceptive resource/error/commitment signals into deterministic attention weights;
- reduce, never expand, effective workspace capacity and character budget under context pressure;
- persist exact effective weights, budgets, signals, and regulatory event linkage in each workspace receipt for replay.

### Governed stall trigger

- fingerprint repeated `NO_OP`, fully blocked frontiers, and unchanged unresolved-conflict evidence without persisting producer prose;
- emit one idempotent `cognition.stall.detected` and one proposal-only `cognition.exploration.requested` per repeated state;
- require provenance, assumptions, uncertainty, and a falsifiable discriminator while granting zero permission or effect authority.

### Exact-review hardening

- reserve `VERIFIED` outcome narrative for receipts linked to canonical independent completion evidence;
- count only unanswered or confirmation-pending latest clarifications as unresolved operator action;
- hash trace identifiers outside the bounded lowercase metadata grammar;
- bind SelfModel confidence correction to the pre-attempt prior and reject conflicting resolution replays;
- reject unknown interoceptive signal names before any event persistence.

### Authenticated browser/native-session scaffold

- bind one independently verified opaque credential-use receipt to either a consent-gated browser real-profile snapshot or an already-authenticated native computer-use session;
- require exact target, route, consumer, owner, purpose, receipt, and action-scope hashes plus exactly one host registration, ticket dispatch, credential claim, credential completion, verified outcome, and terminal completion while granting no host action or effect authority;
- reject malformed, unregistered, or duplicate credential histories and reject host readback whenever the event chain is invalid;
- accept only `READY` or `AUTH_HANDOFF_REQUIRED` host readback with zero UI actions, zero secret input, and unchanged foreground;
- add an operator-configured Hermes bridge whose model-facing effect tool is absent unless explicitly mediated and separately ticketed;
- dispatch only fixed browser session code or native app inventory, hash and discard raw driver output, and reconcile post-readback crashes without repeating host dispatch;
- keep isolated public browsing as the default and treat headed windows or agent-cursor overlays as optional visibility rather than proof.

## 0.9.0a15 — development

### Recurrent accepted-interest task wake

- Added a host-registered wake coordinator that binds one authenticated
  `INTERESTED`/`ACCEPT` feedback event to the existing separately leased,
  hierarchical full-stack task path.
- Added crash adoption, thread/process serialization, append-once claims,
  terminal graph readback, malformed-oldest draining, and content-free status.
- Operator interest still grants no execution authority; producer text and
  external effects remain absent from wake receipts.

## 0.9.0a14 — development

### Important-detail clarification dialogue

- ask one to five task/revision-bound questions when an important unknown blocks or
  materially reranks work instead of guessing;
- accept natural private Telegram replies only when they quote the exact emitted question,
  mapping them deterministically to immutable host-owned option codes;
- require an exact private gateway confirmation for protected, credential, or authority
  answers, while still requiring a separate scoped capability ticket or lease for effects;
- preserve restart-safe request/answer/confirmation bindings, stale/expiry/profile guards,
  concurrent idempotency, hash-only free text, redacted status, and zero raw-secret persistence;
- prioritize open clarification requests ahead of pursuit/opportunity/topic emissions and
  inject only bounded typed understanding into future model context.

## 0.9.0a13 — development

### Operator-interest task handoff

- bind one exact presented `INTERESTED`/`ACCEPT` receipt to a host-signed
  metadata digest without treating conversational interest as effect authority;
- require every executable host-template candidate to reference that digest and
  require a separate active reversible zero-value capability lease before work;
- execute/replay the existing research, command, patch, verification, local fake
  deployment, and fake public-action chain once with linked outcome/reflection;
- reject missing bindings, `SKIP`, stale principal profiles, and authority-
  overclaiming feedback before any self-goal approval, lease, or adapter effect;
- claim each feedback binding before capability/lease creation, bind the exact
  policy/candidate/lease/plan at execution, require concrete bounded/local-fake
  adapters, recheck authority after every stage claim, and record adapter counts.

## 0.9.0a12 — development

### Installed scheduler provenance

- prefer the reviewed installed `cct_agent` package when the release team-sync
  wrapper supplies it, instead of shadowing it with the exported source tree;
- retain source-tree fallback for direct repository execution;
- prove production-style scheduler startup does not generate files beneath the
  hash-bound exported source tree.

## 0.9.0a11 — development

### Full governed operator effect envelope

- add exact ticketed, host-registered public-post drivers with atomic daily caps,
  provider readback, retry suppression, privacy-safe receipts, and restart adoption;
- add opaque credential brokerage that keeps secret bytes inside host resolvers while
  binding provider, consumer, owner, purpose, expiry, and maximum use count;
- add financial/trading drivers with exact account, instrument, action, notional,
  worst-case-loss, per-order, and atomic daily value/loss budgets;
- add high-consequence drivers requiring a ticket-bound authenticated principal
  decision, dependency proof, irreversible acknowledgement, provider readback,
  rollback status, and endorsement-gated learning;
- verify cross-capability same-ticket idempotency, provider crash adoption,
  process-safe ticket consumption, and the global kill switch;
- retain real public, credential, financial, legal, and irreversible effects as
  deny-by-default until an exact authenticated host registration grants them.

## 0.9.0a9 — development

### Ticketed operator capability foundation

- add a durable host-owned global kill switch checked at ticket issue, dispatch,
  and between-step checkpoints;
- add deny-by-default registrations for shell, web, project-edit, deployment,
  public, credential, financial, and high-consequence effect classes;
- execute exact bounded commands only inside host-registered owned projects with
  empty ambient environments, output limits, readback verification, and retry suppression;
- fetch public HTTPS sources through DNS/IP pinning, SSRF and redirect denial,
  bounded time/bytes, hash-only receipts, and no persisted producer body;
- apply expected-hash CAS edits to registered owned projects with Git checkpoints,
  descriptor-bound traversal, exact readback, and automatic rollback;
- deploy exact artifacts through host-registered provider drivers with preview,
  provider readback, restart adoption, idempotency, and rollback;
- retain public posting, credential use, finance/trading, and high-consequence
  effects as inactive until their typed drivers and acceptance gates pass.

## 0.9.0a8 — development

### Suggested work with bounded autonomous attempts

- select one attributable active goal against genuine alternatives and canonical `NO_OP`;
- emit a concrete work suggestion tied to a durable trigger digest;
- autonomously attempt one create-only private local evidence audit through the existing typed executor;
- verify exact artifact bytes and link suggestion, decision, action, outcome, and presentation receipts;
- rotate toward the least-attempted active goal after a new trusted source-state token;
- suppress unchanged duplicate wakes and serialize concurrent workers to one attempt/message;
- expose redacted work-autonomy counts and latest verified-attempt status;
- keep shell, network, browser, publication, financial, credential, destructive, and irreversible requested effects disabled.

## 0.9.0a3 — development

### Atomic constitution root hardening

- Serialize constitution creation through one SQLite logical-key transaction so
  concurrent processes converge on one canonical root event.
- Make losing initializers adopt the winning root only when its fingerprint is
  exact; conflicting constitutions fail closed without appending a second root.
- Preserve integer-versus-float JSON representation during rehydration and
  require reconstructed payload bytes to reproduce the committed fingerprint.
- Add deterministic two-process and integer-root restart regressions.

## 0.9.0a2 — development

### Constitution continuity repair

- Rehydrate one exact hash-valid initialized constitution from an existing event
  ledger so later public default wording changes cannot brick a live profile.
- Require the configured identity to match the stored identity exactly; reject
  invalid chains, non-genesis or duplicate initialization events, malformed
  fields, and bad constitution fingerprints.
- Route the Hermes plugin, team-sync sensor, autonomy scheduler, and CLI through
  the same restart-safe constitution resolver without rewriting the ledger.
- Establish the constitution eagerly at plugin registration and scheduler entry
  points so no sensor, proactive, principal, or capability event can precede it.

## 0.9.0a1 — development

### Principal-aligned opportunity initiative

- connected the persistent opportunity portfolio to the silent proactive scheduler;
- added deterministic task-card priority before generic topic updates;
- added principal review for every opportunity presentation state;
- reused one global cooldown, daily cap, threshold, semantic digest, and atomic emission guard;
- added bounded concrete task cards with visible proposal-only authority wording;
- added NFKC/control/bidirectional text normalization and untrusted-content labeling;
- added atomic `INTERESTED`, `SKIP`, `SNOOZE`, `DONE`, and `BLOCKED` receipts with ACCEPT/DECLINE compatibility aliases;
- bound presentation identity to opportunity event, principal-profile digest, and feedback revision;
- added snooze resumption without weakening permanent semantic duplicate suppression;
- required active-goal/evidence grounding for model proposals and added operator/host CLI feedback, redacted status, ranked selection receipts, and the Phase 12 demo;
- added zero-LLM active-goal task origination plus DONE/BLOCKED follow-up generations after operator interest;
- made principal intent evaluation profile-policy/digest atomic across concurrent revisions;
- added process-race, cooldown, cap, restart, priority, sanitization, and no-authority-expansion tests;
- opportunity acceptance still cannot grant capabilities, attach plans, execute effects, or change autonomous authority.

## 0.8.0a1 — development

### Personal agency foundation

- added externally installed operator-principal profiles;
- added structured preferences, priorities, boundaries, escalations, and grants;
- added deterministic intent alignment with high-power escalation;
- added non-self-ratifying profile revision proposals;
- made principal and capability-spec revisions previous-digest-bound and atomic;
- added typed capability specifications and externally issued leases;
- added expiry, revocation, scope, action, byte, value, and principal gates;
- made lease action, byte, and value consumption cumulative and atomic;
- bound principal identity and canonical intent to capability specifications;
- added single-use reservation consumption with live revocation/expiry rechecks;
- moved filesystem traversal behind authorization and pinned the inspection root descriptor;
- added combined principal/capability authorization receipts;
- added real bounded workspace inspection with descriptor-relative path hardening;
- added six Hermes tools and nine CLI commands;
- added prepared inactive schemas for future high-power domains;
- no shell, network, credential, publication, finance, or constitutional executor enabled.

## 0.7.0 — 2026-08-23

### Public release packaging

- renamed public system to **Choice–Chance–Time Agency Engine**;
- retained **CCT Kernel** for the governance core and **CCT Agency** for the Hermes plugin;
- renamed distribution to `cct-agency-engine`;
- added preferred `cct-engine` CLI while retaining `cct-agent` compatibility;
- replaced operator-local defaults with public-neutral identity and explicit source configuration;
- added native repository-root Hermes plugin manifest and registration shim;
- added full public architecture, authority, benefit, integration, verification, security, contribution, and roadmap documentation;
- added public CI and release metadata;
- removed private development receipts from the public snapshot.

### Engine capability baseline

- persistent Choice–Chance–Time governance kernel;
- bounded global-workspace cognition;
- proactive dialogue and adaptive initiative;
- trusted metadata-only continuity sensor;
- opportunity portfolio, temporal plans, create-only local executor;
- exact verification, fallback, rollback, restart reconciliation;
- capability learning and progressive create throughput;
- fifteen Hermes tools and two lifecycle hooks.

### Compatibility

- Python import namespace remains `cct_agent`;
- Hermes plugin ID remains `cct-agency`;
- existing private pre-0.7 stores require the exact matching constitution identity or a fresh state root.
