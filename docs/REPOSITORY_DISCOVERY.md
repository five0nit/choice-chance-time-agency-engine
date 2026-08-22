# Repository discovery and reuse decision

## Target

Package a public, dependency-free Python Choice–Chance–Time agency engine with:

- persistent goal provenance;
- replayable reasons-responsive choice;
- bounded stochastic exploration;
- temporal event memory;
- global-workspace cognition;
- proactive initiative;
- trusted continuity sensors;
- reversible verified local execution;
- outcome learning;
- progressive authority; and
- native Hermes integration.

## Discovery method

Repository and package discovery ran before public repackaging using the installed Brief2Ship CLI.

Sources:

- GitHub;
- PyPI.

Candidate code was not executed and candidate dependencies were not installed.

The first broad query caused GitHub Search HTTP 422 because of query length. A shorter refined pass completed, and the surviving candidates were inspected statically.

## Candidate summary

| Candidate | Observed fit | Disposition | Reason |
|---|---:|---|---|
| Existing canonical CCT implementation | 95/100 | `selective-reuse` | Already implements the exact theory, event ledger, cognition, initiative, sensor, autonomy, verification, rollback, tests, and Hermes plugin required for this release. |
| `selenium-python-ai-agent` | low semantic fit despite metadata score | `reject` | Selenium test-agent package; no Choice–Chance–Time governance, temporal agency ledger, or progressive authority model. |
| `z3t-ai-agent-sdk` | low semantic fit | `reject` | General agent SDK; adopting it would replace rather than package the verified dependency-free CCT architecture. |
| `voice-ai-governance` | narrow governance domain | `reject` | Voice-governance package, not an operational agency engine. |
| `ai-agent-governance` | archived / insufficient evidence | `reject` | No suitable maintained implementation evidence for this architecture. |
| Other generic agent SDK/plugin results | low fit or ambiguous licensing | `reject` | Missing the required CCT theory, replay, verification, and authority contracts. |

## Decision

**Disposition: `selective-reuse` of the existing canonical CCT implementation.**

Public packaging changes the name, metadata, documentation, configuration defaults, plugin manifest, CI, and release hygiene. It does not replace the verified core with an unrelated framework.

No external candidate source was copied.

## Why not fork an existing agent framework?

CCT is not another orchestration wrapper. Its defining contribution is the relationship between:

- goal provenance;
- complete alternatives;
- constraint-before-chance selection;
- replayable temporal consequences;
- model proposal versus host authority;
- exact effect verification;
- rollback; and
- capability-specific earned authority.

A general agent SDK can host these ideas but does not provide them as one coherent behavioral contract. Replatforming would increase dependency and migration risk while weakening existing evidence.

## Public packaging boundary

The public repository excludes private development receipts, operator-local paths, profile IDs, and runtime state. Public verification evidence is regenerated from the sanitized source and documented in [`VERIFICATION.md`](VERIFICATION.md).
