# Verification guide

This is a reproducible validation guide, not a historical run log. Candidate `0.9.0a22` release status is tracked in [PUBLIC_RELEASE.md](../PUBLIC_RELEASE.md). No old test total, private rollout, or successful fixture is proof of the current candidate.

## Core checks

Use a fresh Python >=3.11 environment and a reviewed checkout:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e . pytest build twine
python -m pytest -o addopts= -q
python -m compileall -q cct_agent hermes_plugin scripts tests
python -m build --sdist --wheel
python -m twine check dist/*
```

`pytest`, `build`, and `twine` are verification tools, not mandatory core runtime dependencies. Keep actual passed/failed/skipped counts with source identity in a private receipt; do not substitute a prior release's totals.

Inspect both distribution archives for private config, cloud identifiers, credentials, absolute owner paths, operational logs, and missing public documentation. Test the installed wheel from a directory outside the checkout using a fresh scratch ledger. Confirm its version, import location, CLI help, cognitive demo, human status, and event-chain behavior.

## Behavioral matrix

| Area | Required checks |
|---|---|
| Kernel | Blockers before exploration, canonical `NO_OP`, deterministic replay, provenance |
| Ledger | Hash-chain validation, append-once logical keys, constitution continuity |
| Cognition and initiative | Bounded workspace, learned competence without permission, cooldown/caps/dedupe |
| Create-only executor | Exact hashes and inode claims, no replacement, fallback, rollback, concurrency, restart |
| Principal/capabilities | External grant, scope, expiry, revocation, atomic budget consumption |
| Operator integrations | Host registration, exact tickets, kill switch, per-class verifier and crash semantics |
| Owner workflows | Identity, intent/effective separation, charged budgets, paused/revoked/stale behavior |
| Private artifacts | Networkless sandbox, independent acceptance, immutable lineage, fail-closed prerequisites |
| Privacy | No secret/raw producer content in public projections; no private operational data in artifacts |

Run the source acceptance scripts in new temporary directories, never a live profile. `scripts/cct_phase10_demo.py`, `scripts/cct_phase11_demo.py`, and `scripts/cct_phase12_demo.py` exercise local contracts; inspect each result rather than treating process exit alone as success.

## Platform boundary

Hardened local effects need Linux/POSIX primitives. Real private artifact tests additionally need Bubblewrap, seccomp, usable namespaces, and an interpreter exposing `os.memfd_create`. Report unsupported platforms and skipped prerequisites explicitly. Do not remove isolation or weaken assertions to produce a passing result.

## Optional Firebase and frontend checks

Install the declared SDK extra when testing the bridge:

```bash
python -m pip install -e '.[firebase]'
python -m pytest -o addopts= -q tests/test_firebase_bridge.py tests/test_firebase_bridge_sdk.py
npm ci --prefix firebase/hosting
npm test --prefix firebase/hosting
npm run test:rules --prefix firebase/hosting
npm run build --prefix firebase/hosting
```

Emulator/browser tests require their declared tooling and synthetic identities. They must never target a production project by default. Check phone and desktop layouts, logged-out denial, owner/stranger/anonymous rules, control freshness, exact readback, and sign-out clearing. SDK tests with mocked RPCs establish SDK behavior, not live cloud recovery.

The [educational Pages site](https://five0nit.github.io/choice-chance-time-agency-engine/) is distinct from the Firebase owner UI. Its build, accessibility/layout checks, deployment, and exact public readback require separate evidence.

## Integration and live acceptance

Use the [Hermes integration guide](HERMES_INTEGRATION.md) and current host Plugin Doctor. Do not infer a live gateway upgrade from a local import test.

A live cloud/provider acceptance requires specific authorization, exact target identity, bounded effects, and independent readback. A reachable public shell is not a signed-in owner session; a queued message is not delivery; a successful send is not a human reply; a selected follow-up is not an executed artifact. Retain ambiguous results as unknown rather than replaying them blindly.

## Documentation checks

Validate retained Markdown file and fragment targets after removals. Recheck links from repository-level Markdown and the package manifest in the integration lane. Scan docs and built archives separately for personal emails, chat IDs, private profiles, absolute owner paths, cloud project IDs, secrets, raw discovery receipts, and stale publish claims. Generic API field names and explicit placeholders are not live configuration.
