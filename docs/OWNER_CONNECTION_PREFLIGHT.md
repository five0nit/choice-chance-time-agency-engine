# Owner connection and messaging preflight

Target: Python 3.11+ / WSL owner-only Firebase connection and bounded Telegram ask/send, using the existing MIT CCT workspace; no payments, broad execution, foreign gateway credentials or duplicate Telegram polling.

## Decision

Disposition: **selective-reuse**. Inspected base: `https://github.com/five0nit/choice-chance-time-agency-engine`, local `a593f02347eb99fed9bdc32c270d2eba64aa749d`, package `0.9.0a21`, MIT. Keep the exact owner-workspace validator/projection, Firestore SDK/backoff patterns, restrictive config reader, existing UI store, and existing gateway authorization/reply-binding patterns. Extend with an isolated owner messaging adapter; do not install this older branch over the repaired execution runtime.

Discovery receipt: `/tmp/brief2ship-preflight-cct-messaging-4aRwRB/{discovery.json,discovery.md,checkpoint.json}`. Sources local/github/pypi; per-source 3; limit 6; inspect 2; candidate tests disabled; no candidate dependencies installed. CLI exit 5 / inconclusive is retained, not represented as a selected candidate. Static follow-up resolves canonical-base selection: `pyproject.toml`, `LICENSE`, `owner_workspace.py`, `firebase_bridge.py`, `gateway_replies.py`, and the owner frontend read directly.

Candidate comparison (fit / 5, manual architectural evidence, not production-readiness scores):
- Existing CCT: 5. Exact owner schema, Firebase transport, timestamp/digest validation, tested reply authorization and existing UI. Requires new scoped adapter and tests.
- `claude-telegram-bridge@0.14.1`, source `796094cdbd39b93ae9fcce439f8a54fee0cedb54`: 1. MIT, but controls an interactive Claude session through tmux and owns Telegram polling. Wrong harness and polling would conflict with the running Hermes gateway. Do not execute/reuse.
- `claude-code-telegram-bridge@0.1.0`: 1. Claude-specific bridge; no evidence of this CCT/Firestore permission contract. Discovery license/source checks incomplete.
- `langgraph-runtime-firestore`: 1. Different runtime/state contract; discovery incomplete. Not evidence that CCT authorization exists.

Required checks before rollout: strict config and owner identity, fresh revision/digest checks at effect boundary, default deny and revocation, owner-only fixed recipient, quota/backoff, message size/rate caps, duplicate/crash delivery ambiguity, authenticated question replies, readback receipts, isolated process lock/state, unchanged legacy controls, frontend/rules/browser regressions, deployed bundle and live service/readback verification.

No blanket automatic authority follows from saving an answer, requesting full mode, or a successful message. The legacy runtime repair hold remains in force outside this separately scoped owner connection.
