# Discovery → research → plan → bounded work

## Scope

`owner_work.py` is a separate, profile-local worker. It reads completed genuine discovery turns without instantiating or changing the discovery worker. A discovery idea is evidence for selecting useful research, not permission to trade or operate accounts.

Allowed execution is a saved host-bounded research plan: catalog-selected public HTTPS GETs, a tool-free cited synthesis, and a private Markdown report. No arbitrary URLs, shell tasks, messages, orders, transfers, account changes or diagnostic project-audit runs.

## Boundaries and persistence

- Host configuration explicitly enables this lane; the owner's existing learning/Pause switch gates it at action boundaries.
- At most one new job in a rolling 24 hours, tied to a completed discovery turn; no repeated job for an unchanged turn. Discovery conversation remains independent of this research cap.
- At most six public source attempts and two model calls per job. No autonomous retry of an uncertain/interrupted job.
- `owner_work_web.py` owns the catalog. It reuses `OperatorWebAdapter`, public-DNS-pinned transport, exact short-lived capability leases, mediated one-use tickets and effect receipts. Producer output cannot widen the catalog or authorize tools.
- Save model/HTTP attempt claims before execution, then retain source snapshots, source IDs, hashes and receipts. Save the selection and execution plan before fetching; save the final report before cloud projection.
- Exact-source quote validation is mandatory. Missing fields/fee arrays are evidence gaps, never zero fees. Public prices are snapshots, not executable quotes; public fee data does not establish account eligibility.
- The private report's concrete next steps remain proposed and `requiresApproval: true`. They do not automatically enter another executor.
- Firestore `cct_owner_work/current` allows owner get only, with no browser list/write permission. The Inside CCT panel distinguishes saved execution receipts from proposed next actions.

## Runtime

Run with the isolated installed release interpreter and the same profile/ADC environment used by the continuous discovery service:

```sh
python -m cct_agent.owner_work once
python -m cct_agent.owner_work run
```

The worker uses its own `owner-work/` SQLite state, lock, effect ledger and private report artifacts. Do not start it from another profile or overwrite another worker's state. The `run` command polls; a healthy waiting tick is not a newly completed research job.

Operator-only recovery commands exist for known interrupted stages:

```sh
python -m cct_agent.owner_work resume-before-fetch --job-id <exact-job-id>
python -m cct_agent.owner_work resume-after-fetch --job-id <exact-job-id>
```

Read the durable job first. Before-fetch recovery requires no attempted HTTP effects. After-fetch recovery requires the exact complete saved source set and only the selection model call consumed; it uses those snapshots and does not re-fetch. Preserve failed receipts and reject uncertain partial retrieval or already-consumed synthesis budgets. Never delete a job to circumvent these guards.

## Actual-use verification

Use real owner evidence; no manufactured replies. Verify the completed job, saved artifact hash, quote/source integrity, exact local/cloud projection equality, unchanged financial/diagnostic controls, installed-source parity, active worker state and deployed HTML/assets/rules. Read-only previews of captured real state prove rendering, not authenticated browser submission.

The first live lane produced a completed public-source report while correctly leaving fee-aware profitability unproven. This establishes the research/report execution connection, not autonomous trading or unrestricted project execution.
