# Dashboard-controlled bounded test executor

This is a **test lane**, not general-purpose agent autonomy. It does not run shell commands, edit projects, call an LLM, trade, spend, or post publicly. The legacy generalist proposal scheduler and workspace autonomy preferences are separate. Stopping this lane does not stop those other systems.

## Owner controls

Open the CCT dashboard and its **Bounded test executor** panel. Sign in with the configured owner account. Select `project-audit` (fixed local manifest/document inventory and security markers) or `public-docs-check` (fixed official Hermes documentation URLs). `Run once` authorizes one task; `Start` authorizes up to three tasks. `Stop` writes OFF. Each activation expires after one hour, has a hard three-attempt budget, and shares a six-attempt/day UTC host ceiling. There are no LLM charges. Firestore/network use remains subject to the Firebase project plan.

The daemon polls every 60 seconds when healthy. Cloud read/write failure fails closed and backs off. OFF is not acknowledged until the runtime reads it. Stop is checked before work, during each local file or network-chunk boundary, and before result publication. It cannot recall reads/results already completed. Tasks have a 60-second wall-time cap; in-flight cloud RPCs have bounded timeouts. Never treat a pending/stale heartbeat as proof that a requested action applied.

Results are owner-only bounded Firestore run records, plus private local report files with read-back-verified SHA-256. No source file contents or private paths are published. Static readiness markers are not a security certification.

## Host installation

Build and install a pinned wheel into an isolated release venv. Keep the working directory outside the source tree to prove wheel imports. Reuse the optional executor integration in `cct-owner-connection`:

```json
{
  "projectId": "YOUR_PROJECT",
  "ownerUid": "EXACT_OWNER_UID",
  "telegramChatId": "EXACT_OWNER_CHAT",
  "telegramBotUsername": "OWN_PROFILE_BOT",
  "ownerMessagesEnabled": true
}
```

The daemon discovers optional config at `<HERMES_HOME>/config/cct-owner-executor.json`; no custom path field is accepted. Executor config has exactly `projectId`, `ownerUid`, `hostEnabled` (boolean), `projectRoot`, and `outputRoot`. This release pins projectRoot to the CCT Generalist3 worktree in code and outputRoot to the current HERMES_HOME's `owner-connection/executor`. Cloud input cannot change paths, URLs, commands, permissions, maximum task time, or the daily ceiling. Config validation refuses symlinks and unknown fields. Use a service with read-only home/source access, only the private owner-connection state directory writable, and an explicit HERMES_HOME. No new cron or Hermes gateway restart is needed.

One profile-scoped daemon lock prevents duplicate workers. Claims are durable before effects. A crash leaves UNKNOWN, consumes the attempt, and halts the activation; it is never automatically replayed. Terminal failure and activation halt commit in one SQLite transaction. Recovery runs before every daemon tick, not just startup: failed SQLite finalization blocks further claims until the interrupted activation is durably halted. Recovery also halts legacy UNKNOWN/BLOCKED/STOPPED records whose halt write was interrupted. Fresh owner activation requires a monotonically increasing revision and new nonce. OFF preserves policy/nonce and increments revision. Old OFF remains OFF indefinitely; old ON expires.

## Firebase boundary

`cct_executor_control/current` is owner-writable under exact schema, monotonic revision, server timestamp, task enum and bounded integer validation. `cct_executor_runtime/current` and `cct_executor_runs/{runId}` are host-write-only, owner-readable; arbitrary signed-in users and unauthenticated clients cannot read/write them. Browser subscriptions are bounded and freshness/identity-aware.

The runtime ACK binds owner, project, revision, nonce and canonical control hash. The server timestamp canonical form is Python UTC ISO microseconds with `+00:00`. Admin transport probes are explicitly separate from owner-browser auth tests.

## Verification

- Python tests: real temp files, exact report/hash readback, invalid/replayed control, OFF/revoke, limits, host revocation, symlink input, crash recovery, HTTP loopback transport size/redirect/allowlist boundaries.
- Node model and browser tests: controls, stale/pending/readback identity, bounded history and mobile layout.
- Firestore emulator: owner/stranger/anonymous permissions and runtime forgery.
- Installed service: real production ON, useful output, hash verification, OFF acknowledgement and no later new run; leave OFF for the owner.

## Emergency host stop

For this deployment only:
`systemctl --user disable --now hermes-cct-owner-connection-generalist3.service`

This stops both the owner-messaging connection and this test executor. It does not stop Hermes Telegram gateways or the default generalist proposal scheduler. Prefer dashboard Stop for ordinary use so heartbeat/result visibility remains.
