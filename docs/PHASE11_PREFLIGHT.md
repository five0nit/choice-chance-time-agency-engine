# Phase 11 repository-first discovery

## Target

Add an operator-principal covenant, typed capability leases, combined authorization, and bounded workspace inspection to CCT without introducing arbitrary commands, dependencies, raw credential handling, or public effects.

## Receipt

- Tool: installed `brief2ship discover`
- Receipt: `/tmp/brief2ship-preflight-cct-personal-agency-QikxIF/discovery.md/discovery.md`
- Sources: GitHub, PyPI, crates.io
- Tests of candidates: disabled
- Top candidate: `yui-agent-policy`
- Top score: `68.54/100`
- Overall disposition: **`build-clean`**

## Candidate review

`yui-agent-policy` offered a useful small reference pattern:

```text
normalized request → pure evaluator → deny / require_approval / auto_allow
```

Positive patterns retained conceptually:

- pure deterministic admission decision;
- fail-closed defaults;
- unknown fields rejected;
- immutable decision object;
- runtime policy separated from static repository scanning;
- audit producer remains wrapper-owned.

Why it was not imported or forked:

- repository policy, not a persistent human-principal covenant;
- no event-sourced capability leases;
- no expiry, revocation, action/byte/value budgets;
- no CCT temporal receipts or hash chain;
- no principal-alignment/effect-authority separation;
- no combined authorization gate;
- no bounded filesystem executor;
- runtime dependency on Pydantic conflicts with CCT's dependency-free core.

Other candidates had weaker feature match, unclear adoption, unsuitable domain focus, absent repository evidence, or license blockers.

## Reuse decision

**Build clean** inside the canonical CCT repository using the existing dependency-free models, `EventStore`, logical-key idempotency, hash receipts, and test conventions.

No candidate code was copied. No candidate tests were executed.
