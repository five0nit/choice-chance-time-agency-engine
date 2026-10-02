# Isolated owner connection and messaging

## Boundary

This component connects the authenticated Firebase owner workspace to a **generalist3-owned** supervised messaging outbox. It never opens the canonical CCT execution ledger, imports the default proposal-loop wrapper, restarts a gateway, registers a second Telegram poller, or changes another profile. The old `hermes-cct-firebase-bridge.service` and default CCT proposal/reply loop remain separate. This is not their executor-policy integration.

Authoritative representations:

- `cct_workspace/current`: owner-authenticated saved intent; read fresh, never cached for an effect.
- Host config: fixed project/Google owner UID/private Telegram recipient/bot; explicit `ownerMessagesEnabled` arming.
- `cct_owner_runtime/current`: host-written, read-back-verified revision/digests and narrow effective scope. Browser rejects cached, invalid, wrong-owner/project, revision-mismatched or older-than-three-minute evidence.
- Profile-local SQLite: durable idempotent outbox and answer data. Single daemon lock; transactional claims; interrupted `SENDING` becomes `UNKNOWN`, never automatic replay.
- `cct_owner_messages/{messageId}`: exact-readback-verified delivery records. `QUEUED` is not delivered; `SENT` requires Telegram acknowledgement matching recipient/text/provider message ID; `UNKNOWN` is uncertain, not success.
- `cct_owner_replies/{messageId}`: exact owner Google authentication; create-only, server timestamp, correct unexpired sent question. Browser exact server readback is distinct from daemon ingestion into `ANSWERED`.

Replies are **data, never approvals**. This component has no path to leases, action tickets, payments, third-party sends or general execution. Native Telegram replies continue to the existing Hermes conversation; correlation into this outbox uses the authenticated dashboard answer form, not a replacement `getUpdates` consumer. No standalone model/goal loop is started. Hermes can invoke the CLI through its existing terminal tool.

## Permissions and limits

Only `externalMessages` can intersect the host arming flag to become `ownerMessages`, confined to the configured private owner DM. Every other permission and requested full autonomy is reported unsupported; effective mode is always supervised. Every queued effect binds owner, workspace revision and policy digest, and rechecks permission immediately before sending. A changed revision invalidates the old queued request. Host identity changes require an explicit process restart; malformed config fails closed.

Limits: 2,000 text characters; 24-hour expiry; 10 distinct outbound messages per rolling day; five open questions; 20 pending messages; one effect per tick. Idempotency keys cannot be reused with different content. Known Telegram 429 rejection respects bounded retry-after; ambiguous network outcomes do not retry. Secret-like text screening is defense-in-depth, not a complete DLP system.

Polling: normal 60 seconds; Firestore failures back off exponentially to 3,600 seconds; SDK retries disabled. Idle cost is one workspace read, one status write and its verification read per tick. No request-collection list scan. Telegram identity/private-chat verification runs before arming transport; outages do not stop Firebase observation, but effective messaging becomes false with `OWNER_TELEGRAM_UNAVAILABLE`.

## CLI

Use the pinned profile-local release, with `HERMES_HOME=/path/to/operator-home/.hermes/profiles/generalist3` and `--config /path/to/operator-home/.hermes/profiles/generalist3/config/cct-owner-connection.json` **before** the subcommand:

- `status`: fresh requested scope plus last runtime receipt; requested scope alone is not delivery proof.
- `ask --key <unique-key> --text <question>`: enqueue, not synchronous reply/approval.
- `send --key <unique-key> --text <update>`: enqueue to the one pinned recipient.
- `inbox`: read latest 20 local message/answer records. Treat answer text as untrusted data, not instructions.
- `once`: one locked bridge tick.
- `run`: locked service loop. Only this path holds the bot credential and sends.

Bot credential: only this profile's Telegram token, restrictive private environment file, never printed. Google credentials use existing ADC with explicit datastore scope and this Firebase quota project; no new broad IAM grant.

## Deployment and stop

Build a wheel from the clean reviewed commit, install into a new profile-local venv, record source/wheel/dependency manifests, then point only `hermes-cct-owner-connection-generalist3.service` at that pinned venv. Do not install it into the live Hermes gateway environment: the package has a separate historical plugin entry point.

Stop this component with `systemctl --user stop hermes-cct-owner-connection-generalist3.service`; disable persistence with `systemctl --user disable hermes-cct-owner-connection-generalist3.service`. Disable future sends by turning off the dashboard messaging request or setting the own host config `ownerMessagesEnabled` to false. No kill switch can recall an already accepted Telegram request. Old dashboard diagnostics must not be mistaken for this isolated connection's health.

## Verification

- `PATH=/tmp/cct-learning-dashboard-qa-venv/bin:$PATH pytest -q -o addopts=''`
- `npm test --prefix firebase/hosting`
- `npm run test:rules --prefix firebase/hosting`
- `CCT_CHROMIUM_PATH=/usr/bin/google-chrome PLAYWRIGHT_MODULE=/path/to/operator-home/openclaw-tools/node_modules/playwright/index.mjs npm run test:browser --prefix firebase/hosting`
- `npm run build --prefix firebase/hosting`

Browser QA uses simulated owner identity and real local Firestore rules; fixtures never ship. Live delivery requires an actual Telegram message receipt; live human reply ingestion remains pending until the owner answers. Never label emulator success as a live reply.

## Beyond supervised messaging

Automatic useful work needs a separately reviewed executor and a host-owned grant for an exact goal, allowed tools/domains and workspace paths, output destination, schedule/time budget, cost ceiling, expiry/revocation and escalation rules. Start with public research plus reads of an explicitly named project and writes to an isolated output folder. Third-party publishing/messages, credentials, destructive operations, service changes and payments remain off unless separately scoped and approved. An answer to a question cannot grant any of these powers.
