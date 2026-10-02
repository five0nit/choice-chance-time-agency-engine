# Brief2Ship discovery — CCTAE Firebase control plane

- Target: Firebase-hosted CCTAE administrative dashboard for Michael Costea, with exact verified Google owner access, Firestore request/receipt mediation, outbound-only local bridge, and no cloud access to canonical SQLite.
- Preflight: `/tmp/brief2ship-preflight-cctae-firebase-Ns1iC6`
- Sources: scoped local workspace, GitHub, PyPI, npm.
- Candidate execution: none.
- Receipt result: `build-clean`; top registry candidate `google-cloud-firestore` scored `59.66/100`; GitHub and npm query endpoints returned bounded input errors.
- Final inspected disposition: `selective-reuse`.

## Choice

Reuse exact reviewed CCTAE dashboard/control base at `daa997d16bc35ac8d63beac63726540e22163690`. Reuse official `firebase`, `@firebase/rules-unit-testing`, `firebase-admin`, and `google-cloud-firestore` libraries. Build Firebase-specific UI, rules, and local bridge cleanly inside the existing repository.

## Rejections

- Third-party authenticated-agent wrappers: no meaningful CCT ledger/control semantics, weak evidence, or irrelevant execution surface.
- `cct-visibility-plane`: separate stale local surface, ambiguous license, and no safe mutation contract.
- Cloud-hosted SQLite/control service: rejected because canonical authority and SQLite must remain local.
- Cloud Functions: rejected for this release because direct Firestore rules plus outbound bridge satisfy the requirement without a paid billing dependency.

## Hard boundaries

- Only `owner@example.invalid`, verified through `google.com`, may read data or create requests.
- Firebase never edits SQLite, issues leases/tickets, or creates provider effects.
- Local bridge revalidates Firebase Auth identity, preview state, expiry, and canonical readback.
- Only `SET_CAPABILITY_ADMINISTRATIVE_ACTIVE` for `operator.web` exists.
