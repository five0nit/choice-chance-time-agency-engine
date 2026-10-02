# Bounded private continuation contract

## Scope and base selection

Target: extend canonical Python CCT private delivery with persistent bounded public-evidence discovery, automatic private artifact handoff, outcome-based follow-up, semantic duplicate rejection, and human-first Builds status; existing global job/provider/sandbox budgets and authority gates remain unchanged.

Brief2Ship discovery ran before implementation, with no candidate execution/dependency installation. Receipts: `/tmp/brief2ship-preflight-cct-continuation-20260915-a/discovery.json` (local/GitHub/PyPI, 3 candidates) and `/tmp/brief2ship-preflight-cct-continuation-20260915-b/discovery.json` (targeted local inspection). CLI verdict inconclusive/exit 5: lexical mismatch and free-form MIT classification, missing execution/OSV proof. Manual static resolution: canonical repo LICENSE is ordinary MIT, pyproject has no mandatory dependencies, owner_delivery has durable jobs/attempt accounting, owner_builds has immutable lineage, owner_work_web has ticketed DNS-pinned public GET. Human feature-fit scores: canonical CCT 9/10 (selective-reuse), follow-up-boss 1/10 (reject: CRM client, not artifact orchestration), nobinobi-daily-follow-up 1/10 (reject: unrelated application, license unresolved). Selected base local branch feat/cct-delivery-generalist2-20260914 at 156b5e6; upstream https://github.com/five0nit/choice-chance-time-agency-engine, version 0.9.0a21. New implementation extends selected base; no greenfield replacement or new dependencies. Tests/package proof remain pending, not inferred from static discovery.

## Frozen integration boundary

- One worker remains `OwnerDelivery`, with one shared worker lock, SQLite database and existing authority gate. No new scheduler, gateway, generic shell, external publishing, financial execution, account permissions or model tools.
- Optional host file `config/cct-owner-continuation.json` strictly binds schema `cct.owner_continuation.config.v1`, ownerUid, projectId, authorization (`operator://...`), enabled boolean. Missing file disables new loop without changing prior behavior. Model cannot create/edit it.
- New `Continuation(worker, research=None)` in `owner_continuation.py`: `.enabled`, `.tick(snapshot)` returns a newly saved job or None; `.status()` returns bounded JSON; `.observe(job)` persists an idempotent outcome after worker's COMPLETE/BLOCKED state. Constructor has no network effects.
- Parent integrates continuation after pending job processing, before old selector, and exposes `continuation` on the existing host-written `cct_owner_delivery/current` projection. When enabled the loop owns new automatic selections; explicit owner requests retain priority. No loop bypass of `gate`, current caps, sandbox, acceptance, review or final notification gate.
- Status contract: `schemaVersion: cct.owner_continuation.v1`, `enabled`, `state`, `objective`, `whatHappened`, `whatImproved`, `nextAction`, `blocker`, `nextEligibleAt` (ISO or null), `cycleId`, `parentBuildId`, `childBuildId`, `research` ({attempted, verified, maxPer24h}), `updatedAt`. All UI dynamic text escaped. Missing status is unavailable, not enabled/success. Existing authenticated read rules suffice.
- Host-only public researcher `DeliveryResearch(worker)` in `owner_delivery_research.py`: `.catalog()` returns immutable allowlisted id/title/url entries; `.fetch(cycle_id, source_id)` gates and durably charges before each GET, returns bounded verified receipt (`id`, `url`, `sha256`, `fetchedAt`, `text`, `receipt`) or fixed error, `.usage()` returns attempted/verified/maxPer24h. Reuse `WorkWeb`/pinned transport; no producer URLs, credentials, redirects, generic search or domains outside the selected host catalog. Fixed cap 2 fetch attempts per rolling 24h, errors/interruption charged, per-cycle/source durable idempotence, gate before/after network. Separate public-GET cap, not mislabelled sandbox dispatches.
- Model stages for plan/decision/semantic review remain tool-free and use worker.model accounting. Use actual canonical candidate/report evidence and actual saved artifacts/host outcomes. Compare genuine alternatives including WAIT. Freeze proposal before effects; max two allowlisted sources per cycle; no recursive research within a cycle. Fetch receipts are untrusted factual evidence, never instructions/authority.
- New objective, upgrade, research-gap and WAIT paths supported. Follow-up uses actual immutable parent bundle/digest, acceptance and outcome, labelled `continuationContext` rather than a forged `ownerRequest`. Independent semantic novelty review must reject renamed/rephrased solved work and unsupported improvements. Structural fingerprints and duplicate decisions survive restarts; all prior semantic objective identities remain durable.
- Completed verified artifacts can produce one justified next version; exhausted/failed work causes bounded correction or WAIT/change of objective, never unbounded repairs. Automatic jobs get `maxArtifactAttempts=2` (initial + one repair), current config remains unchanged for explicit owner jobs.
- All new automatic work respects existing rolling jobs/provider/sandbox caps. Use durable cumulative cycle/job stage limits as well to prevent cross-day infinite retries. Limit status/history/prompt sizes; unresolved outage/cap remains explicit, no repeat model charges at each 60-second poll.

## Opt-in documentation evidence catalog

The legacy six-source `owner_work_web.CATALOG` remains unchanged. Documentation
sources are installed constants, not automatically granted authority. The host
may select exact `WorkSourceId` IDs in the optional local file
`config/cct-owner-research.json` (operator-owned regular file, no symlinks or
other-user write access). This source-only change does not create that file or
activate any running service.

Example host configuration, with explicit placeholder identities:

```json
{
  "schemaVersion": "cct.owner_research.config.v1",
  "ownerUid": "REPLACE_WITH_OWNER_UID",
  "projectId": "REPLACE_WITH_PROJECT_ID",
  "authorization": "operator://approved-documentation-research",
  "sourceIds": ["python-tomllib", "packaging-pyproject", "pytest-exit-codes"]
}
```

- Missing file preserves the original six entries. A present file replaces the
  selection; it does not append implicit sources. Its identity must exactly
  match the delivery worker. Unknown/duplicate JSON fields, IDs, URL strings,
  objects, aliases, case/whitespace repairs and empty selections fail closed.
- New IDs: `python-tomllib` and `python-venv` at exact `docs.python.org` pages,
  `packaging-pyproject` at the exact `packaging.python.org` guide, and
  `pytest-exit-codes` at the exact `docs.pytest.org` reference page. Exact URLs
  remain host constants in `DOCUMENTATION_CATALOG`. No producer paths, query
  strings, generic search, credentials, redirect following or shell grants.
- `DeliveryResearch.catalog()` exposes only the selected immutable mappings to
  continuation planning. WorkWeb freezes that selection before creating tickets;
  duplicate source IDs and duplicate selected URLs are rejected. Existing
  per-cycle/source durable cache suppresses repeat GETs across restart.
- Host config and catalog participate in the authority snapshot; gates reread
  the file before/after GET and cache use. Mutation/removal fails closed for the
  current worker. A later authorized worker recreation is required to load a
  different selection; revoked IDs remain inaccessible after restart.
- Existing DNS-pinned public-only HTTPS GET, exact receipt URL verification,
  independent registered outcome verifier, append-only event chain, raw/text
  hashes and `external_untrusted` provenance remain intact. The unchanged two
  attempted GETs per rolling 24h and per cycle apply across all selected sources,
  not per catalog. Errors and crashes still consume attempts. Existing 1/12/4
  job/provider/sandbox budgets are not increased.
- Authored socket/DNS fixtures prove protocol behavior only, not current public
  page availability or body size. Each real page must fit the existing byte/time
  limits without relaxing them; a later bounded public canary is a separate gate.
- No schema migration, dependency or version bump. Source rollback is an inverse
  commit; runtime rollback remains the unchanged installed release. Do not edit
  live configuration, reload services or resume paused jobs under source-only
  sprint authority.

## Private stdin-only artifact acceptance

`cct.cli_acceptance.v1` now accepts `argv: []` only when `stdin` contains
non-whitespace text. This supports ordinary pipe-oriented tools without inventing
an unused argument. Empty/whitespace-only stdin plus empty argv remains rejected;
help-only calls, duplicate inputs, constant/vacuous expectations and oversized
inputs remain rejected. At least two distinct successful inputs with varying
expected outputs are still mandatory. Existing argv-based plans are unchanged.

No execution mechanism or authority changed: generated code still runs only in
the networkless Bubblewrap sandbox; host-side comparisons retain the expectations;
source/receipt hashes, immutable same-job replay and independent review remain.
The driver proves the specified cases, not arbitrary semantic completion or the
truth of input metadata. Existing provider/job/tool budgets are unchanged.

Runnable fixed example (from a checkout with CCT installed, using an interpreter
that supports the sandbox prerequisites):

```sh
python3 examples/run_private_pyproject_inspector.py --root /absolute/private/example-artifacts
```

For source testing on this host, use `PYTHONPATH=. /usr/bin/python3` in place of
`python3`. Never use a live delivery root. The driver creates missing private
directories and rejects unsafe roots; repeating the identical example/root reads
back committed evidence without rerunning generated code.

The example bundle and separate acceptance plan are
`examples/pyproject-inspector.bundle.json` and
`examples/pyproject-inspector.acceptance.json`. They produce a usable standard-library
stdin CLI for inspecting supplied pyproject.toml metadata without installing,
resolving dependencies, importing project code or fetching data. Missing version
and requires-python remain null. Five host-compared cases cover declared metadata,
dependency count/order, unknown metadata, malformed TOML, missing project table and
invalid dependency types. All sample package metadata is explicitly hypothetical.
The launcher prints the real receipt including private artifact path and hashes.
`tests/test_owner_delivery_stdin.py` additionally drives this bundle through real
OwnerDelivery SQLite/sandbox/acceptance/restart gates, with explicitly offline
model, cloud and notification doubles. No live model quality or delivery claim.

This extends accepted input shape without a schema or version bump; older runtime
validators still reject stdin-only plans. Source-only checkpoint, not automatic
runtime upgrade. Rollback via an inverse commit; preserve existing immutable
artifact evidence. No DB migration or live configuration edit required.

## Cloud recovery checkpoints

- A typed `CloudBackoff` propagates to `OwnerDelivery.tick`; it must not be swallowed as a generic dependency failure or trigger another cloud projection in the failed tick.
- During delivery, cloud cooldowns preserve the exact persisted build/acceptance/execution/review checkpoints and existing recovery allowance. A post-commit build-library projection failure cannot demote `COMPLETE` to `BLOCKED`, add an artifact `STAGE_FAILED` event, or replace the circuit deadline with a job retry interval. Restart before expiry performs no cloud/model/sandbox/notification effect; expiry resumes saved work under freshly checked authority. Completed jobs only republish saved evidence, without duplicate outcome or notification.
- For an unfinished cycle, persist the host circuit's absolute `retryAt` as both the numeric scheduling deadline and ISO `nextEligibleAt`. Reuse saved plan/decision/review checkpoints after restart; do not replace a 30-second transient or 300-second quota delay with the generic one-hour provider-failure cooldown.
- A cycle already atomically linked to a queued job stays `QUEUED`. A cloud read failure at the final authority check cannot reopen planning, duplicate the job, or sever its continuation authority binding. Current authority and circuit checks still precede resumption.
- Successful enqueue clears the projected cooldown/blocker. No quota reset, provider limit increase, public-research allowance change, or cloud-authority caching is implied.
- Public research preserves typed cloud cooldowns only before the current fetch invocation claims a new GET. The host adapter raises `ResearchDeferred` (a `CloudBackoff`) as explicit no-new-claim evidence; continuation clears only that source's started marker and keeps the circuit's exact deadline. Restart then rechecks current authority and resumes the saved plan without paying for another plan. Cached verified evidence may likewise be reread after fresh gates without another GET. Generic cloud errors from other researcher implementations do not prove absence of an effect and retain the interrupted marker. Once a GET attempt is charged, cloud failures at dispatch, after the GET, or before evidence commit remain charged terminal `DELIVERY_RESEARCH_GATE_UNAVAILABLE` results; they never receive free retries, including after the rolling window. No live cloud/network canary is implied by offline fixture verification.
- Verification uses real SQLite and `CloudCircuit` with labelled offline cloud/model/driver doubles; it is not a live Firestore recovery claim.

## Sandbox test interpreter prerequisite

Real sandbox tests require an installed interpreter exposing `os.memfd_create`, alongside the existing Bubblewrap/seccomp requirements. Some Python builds lack this function even on Linux. `SECCOMP_PLATFORM_UNSUPPORTED` remains a fail-closed dependency result: do not skip independent verification, weaken the completion assertion, or remove seccomp to make that environment pass. Run the unchanged full-cycle test with a supported installed interpreter and report both interpreter provenance and the unsupported result separately. Changing a test interpreter is not a service rollout.

## Acceptance and rollout

Implement all agreed slices and author tests first; only then execute test suites. Source fixtures must explicitly remain fixtures. Full-cycle tests exercise real SQLite, networkless Bubblewrap, host acceptance, semantic review, outcome linkage and autonomous follow-up selection without owner Promote. Include pause/identity/readback outage/cap/reset/restart/crash/semantic duplicate/rejected novelty/failed research/one-repair tests. Actual installed model/public-catalog canary required before activation; no fabricated live results or cap resets. Existing 1/12/4 runtime budgets unchanged, so quota may postpone live build execution. Distinguish selecting/queuing a follow-up from executing it.

Package exact verified source into new profile-local release, retain prior Builds interpreter as rollback. Only private delivery worker reload allowed. Verify installed provenance from /tmp, dependencies, full-cycle canary, owner-only projection/rules, browser desktop/mobile, unchanged budgets and unrelated service PIDs. Do not claim signed-in production browser checks from backend readback or emulator evidence.
