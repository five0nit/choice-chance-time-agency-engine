# Changelog

All notable public changes are documented here.

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
