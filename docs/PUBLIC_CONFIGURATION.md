# Public configuration templates

The public source is separate from any private operator deployment. The core cognitive demo needs no cloud configuration.

Optional Firebase examples use the non-deliverable email `owner@example.invalid`, synthetic project `demo-cctae`, and UID `replace-with-owner-firebase-uid`. No production API key, sender ID, app ID or owner identifier ships here. The browser config is a template, not a functioning hosted deployment.

Before using Firebase, an operator must deliberately set the same exact owner email and UID in the bridge policy (`cct_agent/firebase_bridge.py`), bridge config, Firestore rules, and frontend owner policy. Replace the Firebase project/app values and CSP auth-domain entry too. Preserve Google-provider and verified-email requirements, exact identity matching and deny-by-default rules. Re-run the rules emulator and static contract tests with synthetic identities. Never point tests at production.

The optional bounded executor's `PINNED_PROJECT_ROOT` is `/path/to/owner-approved/cct-project`; intentionally unusable until explicitly reviewed and configured in source. Do not replace the pin with an arbitrary cloud-supplied path. Release-host team-sync paths are examples too. No service is installed, started or granted new authority by installing the package.

Hermes-backed model adapter tests are separate host integrations. Core package tests do not claim real-provider acceptance. See [verification](VERIFICATION.md).
