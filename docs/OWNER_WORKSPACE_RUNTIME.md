# Owner workspace: observation-only runtime handoff

## Rollout hold

The active CCT runtime is under repair on `phase17-standing-autonomy`. This dashboard lane does **not** install, restart, merge into, or configure that runtime. Repair-owner reconciliation and a separately reviewed executor integration are prerequisites to enforcement and runtime acknowledgement. Saving a policy, selecting full autonomy, approving a suggestion, or observing a cloud revision is **not** execution authority.

This implementation reads `cct_workspace/current` and adds `snapshot.collaboration` to the existing Firebase dashboard envelope. It does not issue capabilities, leases, tickets, operator routes, tool calls, local events, credential access, or external effects. Existing preview/apply request authentication, confirmation, recovery, and administrative control behavior are unchanged. Those pre-existing controls remain separate from owner workspace intent.

## Observation boundary

`cct_agent.owner_workspace.normalize_owner_workspace(value, owner_uid=...)` validates the exact schema in `DASHBOARD_REWORK_CONTRACT.md`. Owner UID must be locally pinned and match exactly; the workspace cannot select the principal or override the bridge owner. Timestamp must already be a resolved, timezone-aware Firestore datetime. Revision must be an integer from 1 through 2147483647 (the rules' bound), not a boolean. All boolean fields require actual booleans. Unknown fields, permission keys, answers, decisions and autonomy modes reject the whole document. Full mode requires explicit `autonomyAcknowledged: true` and never toggles any permission. No free text, credentials, private local paths or raw error content is projected.

Decision card IDs use `[A-Za-z0-9_-]{1,80}` (1–80 ASCII characters, matching the frontend); at most 60 entries, each `approve`, `reject` or `later`. IDs are inert map keys, never paths or executable commands. Decisions are preference feedback, never administrative approvals. The server transaction/rules enforce revision increments and server timestamps; the read-only bridge validates a current document, not its edit history.

`FirestoreBridgeGateway.read_owner_workspace()` performs one read of the fixed collection/document with retries disabled and the existing RPC timeout. Missing documents project `MISSING`. A legacy gateway without this optional observation method projects `UNAVAILABLE`, preserving the existing control gateway contract. Invalid documents project `INVALID`; unpinned configuration projects `OWNER_NOT_PINNED`. No previous good document or permission value is reused after a missing/invalid read. SDK errors propagate to the existing outer retry/backoff owner: there is no new inner retry, swallowed quota error, or false successful/ONLINE tick. The last published snapshot remains subject to existing timestamp/staleness indicators.

## Additive dashboard projection

`snapshot.collaboration` is a JSON-safe object:

- `schemaVersion`: `cct.owner_workspace_projection.v1`
- `source`: `cct_workspace/current`
- `observationState`: `OBSERVED`, `MISSING`, `INVALID`, `OWNER_NOT_PINNED`, or `UNAVAILABLE`
- `reasonCode`: bounded validator/observation reason; no input/exception echo
- `observedAt`: this bridge's UTC observation time, not runtime acknowledgement
- `revision`, `workspaceUpdatedAt`: validated cloud metadata, or null
- `workspaceSha256`: digest of the entire normalized workspace, or null
- `policySha256`: digest of schema/owner/requested policy material, or null
- `requestedPolicy`: `{permissions, autonomyMode, autonomyAcknowledged}`
- `preferences`: `{learningEnabled, answers, decisions}`
- `runtimeAdapterState`: always `NOT_CONNECTED`
- `runtimeAcknowledgement`: always null
- `effectivePolicy`: always null (existing host policy is unknown here, not asserted disabled)
- `enforcementActive`: always false (this owner-workspace adapter does not enforce)

Missing/rejected/unavailable input projects default requested intent: all permissions false, supervised mode, no autonomy acknowledgement, learning enabled, empty answers/decisions. These are fail-closed **display defaults**, not a saved owner document or a change to host execution. Only `OBSERVED` means a validated saved document was read. `ownerUid` is validated and digest-bound but omitted from the collaboration object. The containing envelope retains its existing owner metadata.

## Digests and reset

Digests are lowercase SHA-256 of UTF-8 `canonical_json` (sorted keys, compact separators). `workspaceSha256` covers every normalized workspace field, including owner, revision, timestamp, preferences and policy. `updatedAt` is normalized to an ISO-8601 UTC string. `policySha256` covers exactly `{schemaVersion, ownerUid, permissions, autonomyMode, autonomyAcknowledged}`. It deliberately excludes revision/timestamp and learning preferences so answer reset or disabling learning does not change requested permission intent. A future acknowledgement must bind **both revision and policy digest**, not a digest alone; observe/reset is never acknowledgement.

The projection does not mutate or retain input dictionaries. Every read projects fresh values. Resetting learned answers/decision feedback, or disabling learning, changes preferences only. It cannot reset permission choices, confirm full autonomy, or create execution authority. Actual persistence/reset happens in the owner-authenticated frontend transaction, not this observer.

## Future host integration acceptance (not implemented)

After the repair owner releases the runtime hold:

1. Reconcile against the repaired executor's exact capability, consent, lease, ticket, budget, revocation and audit interfaces. Keep Firebase credentials and raw runtime context off the dashboard.
2. Specify a separate host-owned adapter acknowledgement schema and trust boundary. Owner-writable fields must never assert effective permission, consumed approval, runtime status or acknowledgement.
3. Validate a fresh pinned-owner workspace and bind any proposed policy to owner, project, schema, revision and policy digest. Re-read before activation; reject stale revisions, policy changes, mismatched identity or missing full-mode acknowledgement. Preserve existing per-effect CCT execution gates.
4. Translate each explicitly requested permission through reviewed host policy, never infer grants from learning answers, card decisions, an administrative capability switch or full mode. Full mode changes requested oversight, not the list of permitted effects. Credential access never means projecting credential values.
5. Only an installed executor may publish acknowledgement after canonical host readback proves the exact revision/digest was applied. Report rejected/unsupported scopes separately; no optimistic effective claim. Revocation, stop, expiry and rollback need their own verified semantics.
6. Exercise downgrade/revoke/full-mode/missing/invalid/offline/replay/conflict cases against an isolated ledger. Verify no effect before all local authorization and consent checks pass. Obtain runtime repair-owner approval before service changes or live execution.

Until this separate integration is accepted, **NOT_CONNECTED and no acknowledgement are the correct product state**, even when owner writes and bridge observation work.

## Verification

Offline tests use mocked Firestore and temporary ledgers only:

```sh
python3 -m pytest tests/test_owner_workspace.py tests/test_firebase_bridge.py tests/test_firebase_bridge_sdk.py -q
```

Coverage includes exact schema, malicious/extra fields, owner pinning, boolean-vs-integer typing, resolved timestamps, full-mode confirmation, unknown enums, bounded decisions, deterministic digests, preference reset/disable isolation, missing/invalid input after a good read, no workspace writes, additive hashing, and preservation of SDK backoff ownership. No Firebase SDK install, live read/write, service modification, or runtime deployment is required by these tests.
