# Repository discovery and reuse policy

The public candidate uses **selective reuse** of the existing CCT Agency Engine rather than replacing its kernel or adopting a generic agent framework.

## Why this base

The existing implementation supplies the canonical event ledger, principal/capability split, typed effects, local verification, private artifact workflows, and optional dashboard adapters. New integrations should preserve those boundaries instead of treating tool availability as permission.

The repository's [MIT license](../LICENSE) is the licensing reference. Manual review of its standard grant and warranty terms resolved an automated license-normalization ambiguity during base selection. That review does not certify every dependency, prove freedom from vulnerabilities, or establish release readiness.

## Dependency boundaries

- The Python core uses the standard library.
- Firebase support is an optional package extra; its SDKs and frontend dependencies require their own license, version, and vulnerability review.
- Hermes model/provider integration uses the explicitly installed host environment.
- Linux sandbox tooling is a platform prerequisite, not a Python core dependency.

No third-party candidate is considered safe merely because discovery found or ranked it. Review its license, maintained API surface, transitive dependencies, and fit before execution or adoption.

## Public documentation policy

Public documentation preserves architecture, supported APIs, example placeholders, and reproducible verification procedures. It deliberately excludes raw discovery output, local candidate paths, private branch/profile details, rollout logs, owner identifiers, and per-machine service receipts.

Keep detailed operational evidence in private release storage. Publish only sanitized, source-bound conclusions after checking them. A discovery decision is not a test result, a deployment receipt, or a current publication claim.

See [verification](VERIFICATION.md) and the [public release gates](../PUBLIC_RELEASE.md).
