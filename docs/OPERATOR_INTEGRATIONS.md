# Optional operator integrations

The `0.9.0a22` candidate contains more than the create-only executor described in [AUTONOMY.md](AUTONOMY.md). This guide distinguishes separate capability-limited routes from automatic permission expansion.

## Admission contract

```text
host-owned registration + principal alignment
→ bounded capability lease
→ exact, single-use execution ticket where required
→ fresh authority/kill-switch check
→ typed effect
→ independent readback
→ terminal receipt or explicit unknown/failure
```

A model proposal, saved dashboard preference, successful previous run, authenticated session, or `INTERESTED` reply is not a substitute for this authority. Registrations fix targets and supported actions outside model-controlled arguments. Policy overlap uses the stricter per-operation requirement.

## Effect families

- **Shell:** host-registered bounded argv in owned projects; constrained environment, output and duration.
- **Web research:** bounded public HTTPS with allowlists/pinned transport and redirect/SSRF protections; fetched content is untrusted evidence.
- **Project editing:** exact before-hash checks, confined paths, checkpoints, verified after-state and bounded rollback.
- **Deployment and public actions:** exact provider registration, artifact/target binding, durable dispatch and provider readback. Local fake adapters are tests, not production evidence.
- **Credentials:** opaque host brokerage and scoped consumer/purpose/expiry/use limits. Raw secret handling remains outside model payloads.
- **Finance and high-consequence effects:** typed account/action/value/loss budgets and additional principal decisions/acknowledgements. Their presence in source is not approval to transact.

See [authenticated access](AUTHENTICATED_ACCESS.md) for the separate session bridge. It establishes readiness or an authentication handoff, not arbitrary browser or desktop control.

## Standing autonomy

`cct_standing_autonomy_run` accepts registered action and run IDs, not command text, paths, recipients, accounts, budgets, or credentials. Host-owned authority/configuration binds exact projects and actions. Expiring leases, single-use tickets, serialized effects, readback, unchanged-trigger silence and a kill switch bound each run. Earned tiers cannot exceed the operator's ceiling.

`cct-standing-autonomy --help` describes the worker's installed interface. Use an isolated, explicitly configured profile and a pinned package before considering service activation. This documentation does not install or enable a worker.

## Owner workflows

These are separate integrations, not a widening of core create-only authority:

- [Owner connection](OWNER_CONNECTION.md): supervised owner-only messaging and answer ingestion.
- [Bounded test executor](BOUNDED_EXECUTOR.md): fixed diagnostic tasks rather than generic tools.
- [Dialogue](OWNER_DIALOGUE.md) and [discovery](OWNER_DISCOVERY.md): tool-free proposals from genuine owner input.
- [Work](OWNER_WORK.md): bounded research/plan handoff.
- [Private delivery](OWNER_DELIVERY_LOCAL.md), [builds](OWNER_BUILDS_RUNTIME.md), and [continuation](OWNER_CONTINUATION_RUNTIME.md): Linux-isolated private artifact pipelines.
- [Host services](OWNER_DELIVERY_SERVICES.md): opt-in, fixed service registrations rather than arbitrary service management.

## Host and platform limits

A native Hermes plugin executes inside its host process. It does not sandbox ordinary Hermes tools, confer root-wide mediation, or constrain other programs running as the same user. Trust the host, configured adapters, operating system, and independent verifiers within their stated assumptions.

Generated private code must run only in its supported networkless Linux sandbox, with Bubblewrap/seccomp and a compatible interpreter. A missing prerequisite is a blocked capability, not permission to run generated code on the host.

## Release acceptance

Source tests, installed-package tests, emulators, authenticated provider readback, and signed-in browser checks are separate evidence classes. [PUBLIC_RELEASE.md](../PUBLIC_RELEASE.md) tracks current candidate gates. No operator effect or live cloud guarantee is implied by this guide.
