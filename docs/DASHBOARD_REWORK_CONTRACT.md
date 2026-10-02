# Learning dashboard contract

## Reuse decision
Target: rework the existing authenticated Firebase web dashboard with explicit owner permissions, adaptive questions, decisions, CCT priorities, and an autonomy switch; preserve repair work, no credential values in cloud/UI and no inferred execution authority.

Disposition: **selective-reuse**. Status: complete manual base selection after CLI inconclusive license normalization. Base: https://github.com/five0nit/choice-chance-time-agency-engine, Firebase worktree commit `9794a6b433ca9996ac7e3f8b071fb3e0306bf071`, package `0.9.0a21`. Existing MIT LICENSE and pyproject MIT declaration inspected; standard grant/warranty text, no extra restriction. Reuse existing Firebase Auth exact Google UID, Firestore, esbuild, host bridge and tests. Do not merge or replace active repair branch `phase17-standing-autonomy`.

Discovery receipt: `/tmp/brief2ship-preflight-cct-dashboard-20260912-2115/discovery.json` and `discovery.md`. Local scores: cct-free-agent 64.35, Firebase worktree 63.81, hosting 40.50. Existing Firebase worktree selected for actual deployed auth/bridge/UI contract; main repair branch lacks same deployment base. CLI license-normalization unknown manually resolved; OSV and full tests remain validation gates, not claims of production readiness. No new dependencies selected.

## Source of truth and rollout
Owner workspace lives at Firestore `cct_workspace/current`, protected by the same exact owner policy. Owner can save intent and preference answers even while host bridge is stopped. No credential values, tokens or raw private runtime context are added here. Existing host-bound preview/apply controls remain unchanged. New permissions and autonomy are **requested policy** until a compatible executor acknowledges the exact policy digest/revision. Never label saved intent as effective execution. Runtime rollout held for repair-owner reconciliation.

Workspace fields (exact):
- `schemaVersion`: `cct.owner_workspace.v1`
- `ownerUid`: existing pinned UID
- `revision`: integer starting 1, increments exactly one via transaction
- `updatedAt`: server timestamp
- `learningEnabled`: boolean, default true
- `permissions`: exact boolean keys `credentialAccess`, `webResearch`, `workspaceRead`, `workspaceWrite`, `externalMessages`, `payments`, all default false
- `autonomyMode`: `supervised` or `full`, default supervised
- `autonomyAcknowledged`: boolean; full requires true
- `answers`: exact string keys `focus`, `horizon`, `risk`, `interruptions`, `success`, `nextStep`; each default empty string; bounded choices below
- `decisions`: map of bounded stable card ID to `approve`, `reject`, `later` (max 60 entries)

Question choices:
- focus: `revenue`, `career`, `systems`, `creative`
- horizon: `today`, `week`, `month`
- risk: `conservative`, `balanced`, `experimental`
- interruptions: `always`, `milestones`, `blockers`
- success: `revenue`, `shipped`, `learning`, `timeSaved`
- nextStep: `research`, `build`, `repair`, `review`

Learning is an explainable deterministic preference model, not LLM retraining. Follow-up order depends on answers, and decision feedback reranks suggestions. Seeds are explicitly labeled **onboarding suggestions**, never real CCT thoughts. Real snapshot goals/approvals are separate source-labeled cards. No arbitrary hidden reasoning is claimed. Show inspect/reset learned answers and disable learning without changing permission or autonomy fields.

UI module `workspace-model.js`: export `defaultWorkspace()`, `questionsFor(workspace)`, `recommendationsFor(workspace, snapshot)`, `learningSummary(workspace)`; module may add helpers. Workspace persistence module may be separate. Cards title/summary/options remain bounded and rendered through textContent.

Bridge integration: publish additive `snapshot.collaboration` with documented runtime adapter state `NOT_CONNECTED` by default. Read-only workspace observation and canonical event projection can be exposed, but do not apply owner cloud intent as CCT leases/tickets or install an executor. A missing runtime acknowledgement must remain visible. Existing bridge auth/preview/apply unaffected.

Acceptance: saved owner-only settings, transactional conflicts safe; answers change follow-up question and recommendation ranking; reset clears learned answers only; full autonomy requires explicit confirmation and never enables extra permissions; no optimistic saved/effective claims before server readback; offline/stale snapshot truth; unauthenticated/outsider/invalid-schema writes rejected; desktop and phone QA.
