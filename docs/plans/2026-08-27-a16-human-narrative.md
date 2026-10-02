# A16 Human Narrative Layer Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Add deterministic, privacy-safe human summaries of CCT ledger state and recent work through the Python API, CLI, and Hermes plugin without weakening the canonical event chain or hiding technical evidence.

**Architecture:** Add a read-only `HumanNarrative` projection over `EventStore`. It groups known event families into fixed operator-language result classes and emits bounded text plus exact event references, never arbitrary payload dumps. Existing raw status/events remain the technical drill-down; A16 adds human-first CLI commands and one preferred Hermes tool.

**Tech Stack:** Python 3.11+, standard library only, SQLite-backed `EventStore`, argparse CLI, native Hermes plugin, pytest/ruff verification.

**Reuse disposition:** `build-clean` inside the canonical repository. Brief2Ship receipts: `/tmp/brief2ship-preflight-cct-a16-z166fG/discovery.md` and `/tmp/brief2ship-preflight-cct-a16-retry-tcrHCQ/discovery.md`.

---

### Task 1: Lock the narrative contract with failing tests

**Objective:** Specify deterministic summaries, privacy boundaries, exact traceability, digest behavior, and unknown-event fallback before implementation.

**Files:**
- Create: `tests/test_human_narrative.py`

**Steps:**
1. Test empty-store status.
2. Test goal/decision/outcome summaries without arbitrary payload leakage.
3. Test `VERIFIED`, `FAILED`, `ROLLED_BACK`, `BLOCKED`, `ACTION_REQUIRED`, and `RECORDED` vocabulary.
4. Test exact `seq`, `event_id`, `kind`, and `event_hash` references.
5. Test unknown event fallback and hostile producer sentinel exclusion.
6. Test deterministic repeated rendering and bounded digest limits.
7. Run the focused test and verify RED.

### Task 2: Implement the read-only deterministic projection

**Objective:** Make the narrative contract pass without adding dependencies or ledger writes.

**Files:**
- Create: `cct_agent/narrative.py`
- Modify: `cct_agent/__init__.py`

**Steps:**
1. Add immutable narrative result models.
2. Add exact event-family classification and routine-event suppression.
3. Add payload-safe templates using allowlisted structured values only.
4. Add status, latest, and digest projections.
5. Guarantee no ledger mutation and verify the event chain before claims.
6. Run focused tests and verify GREEN.

### Task 3: Add human-first CLI surfaces

**Objective:** Let operators read CCT without parsing raw JSON while preserving existing technical commands.

**Files:**
- Modify: `cct_agent/cli.py`
- Modify: `tests/test_human_narrative.py`

**Steps:**
1. Add `human-status`.
2. Add `explain-latest`.
3. Add `digest --limit N`.
4. Default to plain text; add `--json` for structured narrative output.
5. Keep existing `status` and `events` unchanged as technical drill-down.
6. Exercise CLI functions against a temporary ledger.

### Task 4: Add the preferred Hermes narrative tool

**Objective:** Give Hermes one bounded tool for human status, latest explanation, and digest views.

**Files:**
- Modify: `hermes_plugin/__init__.py`
- Modify: `plugin.yaml`
- Modify: `hermes_plugin/plugin.yaml`
- Modify: `tests/test_kernel.py`
- Modify: `tests/test_mediation.py`
- Modify: `tests/test_human_narrative.py`

**Steps:**
1. Add `cct_human_summary` with `view=status|latest|digest` and bounded `limit`.
2. Return `text`, structured narrative rows, chain state, and exact event references—never raw payloads.
3. Describe it as the preferred tool for plain-language operator questions.
4. Preserve `cct_status` for technical diagnostics.
5. Update exact registration counts and manifest declarations.
6. Test schema rejection, hostile sentinel exclusion, and no ledger mutation.

### Task 5: Mark A16 and document operator use

**Objective:** Make the release identity and human workflow self-explanatory.

**Files:**
- Modify: `pyproject.toml`
- Modify: `cct_agent/__init__.py`
- Modify: `hermes_plugin/__init__.py`
- Modify: `plugin.yaml`
- Modify: `hermes_plugin/plugin.yaml`
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `docs/REPOSITORY_DISCOVERY.md`

**Steps:**
1. Bump development version to `0.9.0a16`.
2. Document the deterministic human projection and raw technical fallback.
3. Record both Brief2Ship receipts and `build-clean` disposition.
4. Add exact CLI examples and the Hermes tool contract.

### Task 6: Verify source, package, and installed behavior

**Objective:** Prove A16 through real execution without touching the live Generalist2 gateway.

**Steps:**
1. Run focused A16 tests.
2. Run plugin/kernel/mediation regression tests.
3. Run the full suite and compare any failures with the recorded baseline.
4. Run `ruff`, `compileall`, and `git diff --check`.
5. Build wheel and sdist twice; compare hashes.
6. Install wheel into a fresh temporary environment.
7. Invoke installed `cct-engine human-status`, `explain-latest`, and `digest` against a real temporary ledger.
8. Load installed Hermes entry point and verify tool/hook/middleware counts.
9. Inspect real text output for hierarchy, trace references, privacy sentinels, and authority wording.
10. Commit only verified scoped files. Do not deploy or restart any live Hermes profile.
