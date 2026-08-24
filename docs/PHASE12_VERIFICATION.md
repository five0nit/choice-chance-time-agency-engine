# Phase 12 verification — proactive opportunity initiative `0.9.0a1`

## Disposition

**Local development candidate verified. Not publicly released. Live profile activation requires exact-source installation and scheduler readback; the Telegram gateway must not be restarted without explicit approval.**

Branch: `phase11-personal-agency`

## Repository-first receipt

- durable receipt: `reports/phase12-brief2ship-preflight-20260823/discovery.md`
- original receipt: `/tmp/brief2ship-preflight-cct-proactive-50oh5q/discovery.md`
- sources: GitHub, PyPI
- candidate execution: disabled
- external disposition: `build-clean`
- implementation disposition: `selective-reuse` of the canonical CCT tree

See [`PHASE12_PREFLIGHT.md`](PHASE12_PREFLIGHT.md).

## Automated verification

```text
pytest:                         194 passed
focused Phase 12 tests:         26 passed
Ruff:                           PASS
compileall:                     PASS
git diff --check:               PASS
public release hygiene:         PUBLIC_RELEASE_CHECK_PASS files=77
Hermes Plugin Doctor:           21 tools, 2 hooks
Phase 12 acceptance episode:    PASS
isolated wheel import/version:  PASS
```

The acceptance episode proved:

- a self-authority opportunity stayed non-executable;
- the zero-LLM active-goal scout originated a real canonical-goal task without a seeded opportunity;
- principal alignment permitted bounded opportunity review;
- a concrete task card beat a generic topic update;
- card text carried untrusted/proposal-only authority wording;
- `INTERESTED` recorded operator interest only;
- no capability lease, executable plan, status transition, autonomy run, or authority promotion resulted;
- a second opportunity remained unconsumed during two cooldown wakes;
- that opportunity emitted once after cooldown;
- two proactive emissions and one canonical event chain were verified.

Acceptance receipt generated under:

```text
/tmp/cct-phase12-remediation-demo-eKoKrH/result.json
```

## First immutable review and remediation

Commit `1a499526759f3bd82d6eb1a9a28fb0ca46b3dfc7` received one architecture
`BLOCK` and one security `BLOCK` (no critical/high executor-authority breach;
one high strict-turn-binding defect plus material-medium findings).

Remediation:

- removed automatic raw-turn feedback attribution rather than weakening its claim;
- kept feedback on explicit operator/host CLI/API boundaries only;
- bound feedback to the exact presented principal ID/profile digest and rechecked it atomically;
- redacted clear opportunity IDs from proactive and model-controlled autonomy status;
- added ranked candidate/rejected-alternative replay receipts;
- required active-goal/evidence grounding for model proposals;
- added the zero-LLM active-goal scout so CCT originates tasks from canonical goals;
- changed reply UX from action-implying `do it` to `interested`;
- added stale-profile, concurrent-profile, grounding, scout, and selection-receipt regressions.

The first verdict is not reused for the remediated commit; a fresh exact-commit
review remains mandatory.

Commit `47d70e07793ebdb143f785d41ec876dd4a575cb5` then received fresh security
and architecture `BLOCK` verdicts. Remediation:

- principal intent policy and digest now come from one snapshot and are atomically rechecked/retried;
- nested proactive status now exposes only message/topic/packet hashes and counts;
- model-controlled autonomy status hides clear plan filenames and capability-learning keys;
- vague goals without descriptive evidence remain silent;
- verbose aspirations without an action-led statement and structured evidence anchor remain silent;
- initial scout cards name the active goal and latest evidence-backed receipt action;
- INTERESTED creates a new DONE/BLOCKED receipt-check generation while the goal remains active;
- SKIP/DONE/BLOCKED stop generation and SNOOZE preserves the current generation;
- the card now honestly asks Hermes to record operator feedback through the CLI/API boundary instead of claiming direct raw-chat ingestion.

Neither blocked verdict applies to the next remediated commit; exact review must
run again.

Commit `d682459da43adab5b7715d841370312b0878d0af` then received fresh clean-import
security and product `BLOCK` verdicts. Remediation:

- hashed open/closed topic IDs and all topic prose in model-callable status;
- required structured evidence anchors plus action-led statements, not merely verbose prose;
- mapped action classes to explicit expected receipt types;
- added INTERESTED/SKIP/SNOOZE/DONE/BLOCKED to the CLI/API contract;
- recorded terminal DONE/BLOCKED outcome receipts and stopped later generation;
- included DONE/BLOCKED in the operator-facing feedback footer;
- corrected interest-status counting for canonical INTERESTED feedback;
- added realistic verbose-aspiration, topic-status privacy, BLOCKED, and full DONE lifecycle regressions.

That verdict is also stale for the next remediated commit; exact clean-import
review remains mandatory.

## Package verification

Artifacts:

```text
cct_agency_engine-0.9.0a1-py3-none-any.whl
cct_agency_engine-0.9.0a1.tar.gz
```

Final checksums are generated after the exact source commit. They are not embedded
in this package-input document because doing so would make package hashes
recursive.

The wheel was installed without dependencies in a fresh Python 3.11 virtual
environment with `PYTHONPATH` removed. Distribution/module versions and imports
for `OpportunityInitiative`, `PrincipalModel`, and `ProactiveRunner` matched
`0.9.0a1`.

## Behavioral and security properties exercised

- no principal profile means no opportunity presentation;
- installing an externally attributed profile creates a fresh reevaluation state;
- self proposals may be shown but never become executable;
- host/operator plans remain behind existing selection, capability, budget, and verification gates;
- opportunity cards take priority over generic topic messages;
- temporary cooldown and daily-cap gates preserve unconsumed opportunity state;
- the opportunity lane shares the existing global daily cap;
- identical visible content remains semantically deduplicated;
- controls, bidirectional characters, tabs, and multiline fields are normalized;
- card control/footer lines survive the 700-character bound;
- thread and synchronized subprocess races emit and complete exactly once;
- emission-before-completion crashes recover without duplicate output;
- feedback requires a previously emitted bound card and exact installed principal;
- model/self-attributed feedback is rejected;
- concurrent terminal feedback has one atomic winner;
- `INTERESTED`, `SKIP`, `DONE`, and `BLOCKED` are terminal for one presentation generation;
- snooze remains silent before its date and resurfaces once as a new semantic state;
- the model-callable Hermes surface cannot assert operator feedback;
- model proposals require an active CCT goal and at least one evidence reference;
- self proposals without active-goal/evidence grounding are ineligible for presentation;
- selection completions carry ranked candidates, scores, rejected alternatives, and a portfolio digest;
- stale and concurrently revised principal profiles cannot accept old card feedback;
- principal intent evaluation snapshots profile policy/digest atomically and retries on revision races;
- CLI feedback requires explicit `operator` or `host_adapter` attribution;
- proactive/autonomy status projections exclude clear topic/opportunity IDs, topic/card prose, model plan filenames, and model-only capability names;
- accepted active-goal tasks produce a new DONE/BLOCKED receipt-check generation;
- DONE and BLOCKED produce terminal task-outcome receipts and stop further generation;
- hidden chain-of-thought remains absent;
- event-chain verification remains valid.

## Known limit

Scheduler emission is an at-most-once delivery attempt. A crash after the atomic
emission claim but before stdout reaches the platform may lose the delivery;
restart will not emit a duplicate. Transactional external-platform delivery is
still a future host-mediation capability.

## Remaining gates

1. independent security/concurrency and architecture review of the exact clean commit;
2. resolve critical/high and material medium findings;
3. rebuild/re-run receipts after any fix;
4. backup and install the exact reviewed source into the generalist2 profile;
5. explicitly bind the proactive scheduler to that source;
6. install the reviewed principal profile into the live CCT store;
7. seed real bounded task opportunities and verify one silent dry run plus scheduled behavior;
8. do not restart the live Telegram gateway without explicit approval;
9. no public push/tag/release without separate publication approval.
