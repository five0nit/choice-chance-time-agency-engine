# Contributing

Contributions are welcome. The project prioritizes behavioral invariants, causal evidence, and maintainable boundaries over feature count.

## Setup

```bash
git clone https://github.com/five0nit/choice-chance-time-agency-engine.git
cd choice-chance-time-agency-engine
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m pip install pytest ruff build
```

## Required checks

```bash
ruff check __init__.py cct_agent hermes_plugin scripts tests
python -m pytest -v --tb=short
python -m compileall -q cct_agent hermes_plugin scripts tests
python scripts/public_release_check.py
git diff --check
python -m build
```

For Hermes plugin changes:

```bash
hermes plugins doctor . --ci
```

## Development rules

### Keep proposals separate from authority

Model-callable schemas must not accept fields that mint `host_adapter`, `operator`, verified feedback, or another privileged source.

### Filter before sampling

Blocked options must be removed before any probability distribution or random draw.

### Preserve `NO_OP`

Every consequential decision must retain a reversible defer branch unless a narrower API explicitly documents a non-decision projection.

### Record rejected alternatives

Do not persist only the chosen branch. Replay and audit require the complete allowed candidate set and score breakdown.

### Learn only from observed outcomes

A plan, return code, or caller claim is not a verified outcome. Link capability learning to effect and verification receipts.

### Root policy cannot self-ratify

Reflection may propose a constitutional amendment. Adoption requires a separate endorsement boundary.

### New capabilities need a complete contract

Every effect kind must ship with:

- typed schema;
- source-authority rule;
- path/resource/effect limits;
- concurrency model;
- restart model;
- independent verifier;
- rollback or explicit irreversibility gate;
- status projection that avoids sensitive payloads; and
- behavioral tests.

### Maintain privacy distinctions

Document separately:

- automatic raw-conversation capture;
- caller-supplied persisted text;
- private plan content;
- digest/linkage data; and
- model-visible context.

Do not summarize these as one ambiguous `stores_conversation` flag.

## Test-driven changes

For bugs and new behavior:

1. add a failing behavior test;
2. verify it fails for the intended reason;
3. implement the smallest complete fix;
4. run targeted tests;
5. run the full suite; and
6. inspect the final diff.

Race, restart, and filesystem-boundary changes need repeated or synchronized tests, not only happy-path unit tests.

## Repository-first rule

Before adding a substantial subsystem, search existing libraries and repositories. Record whether the result is `use-as-library`, `fork`, `selective-reuse`, `reject`, or `build-clean`.

Do not execute untrusted candidate code during ordinary discovery.

## Public-safe fixtures

Tests and docs must use:

- temporary directories;
- generic identities;
- inert content;
- fake evidence identifiers; and
- no personal paths, tokens, account IDs, or private operator data.

## Pull requests

Include:

- problem and intended behavior;
- authority and trust-boundary impact;
- exact tests run;
- race/restart implications;
- privacy implications;
- migration implications; and
- known limitations.

Large capabilities should be split so reviewers can inspect schema, executor, verifier, recovery, and learning changes separately.

## Commit style

```text
feat: add typed registered-check capability
fix: reject ancestor substitution during verification
docs: clarify Hermes process boundary
```

## Code of conduct

Be precise, evidence-led, and respectful. Critique implementations and claims, not contributors. Security reports with live exploit details belong in private vulnerability reporting.
