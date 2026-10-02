# Brief2Ship discovery — CCT suggested-work autonomy

- Date: 2026-08-25 AEST
- Target: make CCT suggest concrete useful work, attempt one low-risk reversible task without a fresh prompt, verify the result, and remain silent on unchanged duplicate wakes.
- Constraints: Python 3.11+, Hermes plugin, no new dependency, profile-scoped state, no unrestricted shell/network/public/financial/credential/destructive effects, append-only receipts, restart/concurrency safety.
- Raw receipt: `/tmp/brief2ship-preflight-cct-autonomy-klIDW5/discovery.md`
- Sources: GitHub and PyPI; candidate code was not executed.

## Candidates

| Score | Candidate | License | Disposition | Reason |
|---:|---|---|---|---|
| 66.35 | `yantrikdb-hermes-plugin` | MIT | reject | Healthy Hermes memory plugin, but only 1.94 feature-match points; no typed effect authority, verified local executor, or suggestion-to-attempt loop. |
| 59.96 | `xeus-python-shell` | BSD-3-Clause | reject | Python shell, not an agent-governance or bounded autonomy base. |
| 58.44 | `xberg-hermes-plugin` | MIT | reject | Inspection blocked and no observed governance/execution contracts. |
| 53.30 | `yoooclaw-hermes-plugin` | MIT | reject | Missing repository/reuse evidence and no matching authority model. |

GitHub search returned HTTP 422 for the long query; PyPI returned eight candidates. Missing source evidence remains explicit in the raw receipt.

## Decision

**Disposition: `selective-reuse`.**

Use the existing canonical CCT repository and reuse:

- `opportunity_initiative.py` patterns for concrete task selection;
- `autonomy.py` for create-only execution, hash verification, rollback, idempotency, and authority learning;
- `proactive.py` for cooldown, daily caps, duplicate suppression, and scheduler-visible output;
- `store.py` for append-once crash/concurrency receipts;
- `principal.py` and `kernel.py` for attributable goals, genuine choice, `NO_OP`, and replay.

No external candidate replaces these integrated contracts. Add one narrow suggestion-to-local-audit bridge; no new framework or dependency.
