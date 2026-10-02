# Public alpha `0.9.0a22`

This release packages the latest integrated September/October development snapshot with public-safe configuration templates, portable test fixtures and an educational GitHub Pages site. It is an alpha source release, not a hosted agent service or a claim of production readiness.

## Verified locally before publication

- Python 3.12 on Linux x86-64: **1,645 tests passed, 3 skipped; 97 subtests passed**. Real Bubblewrap/seccomp generated-code integrations executed successfully. Two Python fork deprecation warnings remain.
- The three skips are optional host/dependency integrations. The isolated public package does not certify a real Hermes provider connection.
- Ruff, Python compilation and the public-release privacy scanner passed.
- Firebase frontend unit/static tests and build passed; Firestore demo-emulator rules: **147 passed, zero failures/skips**.
- npm audit: **zero vulnerabilities** after pinning the patched transitive gRPC dependency.
- Education page: rendered and exercised at 1280px, 390px and 320px; no horizontal overflow or browser errors. ACT/WAIT/ASK scenarios work. Reduced-motion and no-JavaScript content remain readable.

Distribution hashes, artifact installation smoke results, publication identity and live Pages checks belong to the corresponding [GitHub release](https://github.com/five0nit/choice-chance-time-agency-engine/releases/tag/v0.9.0a22) and exact-commit Actions runs. A local test result alone is not publication proof.

## Public configuration boundary

Core Python has no mandatory runtime dependencies. Test tools and Firebase SDKs are optional extras. Cloud and executor examples are intentionally unconfigured. Read [PUBLIC_CONFIGURATION.md](docs/PUBLIC_CONFIGURATION.md); all real owner/project identifiers and production API configuration must be supplied through deliberate operator setup. Identity and path pins remain deny-by-default.

On interpreters without Linux x86-64 memfd/seal support, actual sandbox-integration tests skip explicitly; policy tests still run and runtime generated-code execution fails closed. Use a supported system interpreter to verify the real sandbox. A supported interpreter with broken Bubblewrap fails tests rather than silently weakening isolation.

No private worker, credential store, cloud service, agent profile or running service was replaced by this public release. Real provider/cloud acceptance remains a separate deployment gate.

## Install

```bash
python -m pip install 'git+https://github.com/five0nit/choice-chance-time-agency-engine.git@v0.9.0a22'
cct-agent --db ./cct-demo.db cognitive-demo --seed 7
```

The Git tag must exist before the command is usable. Wheel and source distributions are attached to the release with SHA-256 checksums. See [verification](docs/VERIFICATION.md) and [repository discovery](docs/REPOSITORY_DISCOVERY.md) for scope and reuse rationale.
