# Owner Builds runtime

## User-facing behavior

`#owner-builds` manages private saved artifacts, immutable version lineage, text-only files/downloads, search and reversible archive/restore. Upgrade and steer create child artifacts through the existing private Python acceptance/sandbox/review pipeline. Explore creates a separately reviewed saved-evidence discovery brief; it is not fresh web research, executed code or independent factual verification. Any brief can become the parent of an executable upgrade.

Global rolling-24-hour limits are owner intent at `cct_owner_build_controls/current`. Host validates identity, revision and ceilings, preserves usage, applies the limits durably and publishes/read-verifies `cct_owner_build_controls_status/current`. Until an owner revision, existing jobs/provider defaults remain unchanged: live 1 job and 12 provider requests, plus the new 4 sandbox-dispatch cap. Available ceilings remain 4 jobs / 20 provider requests / 12 sandbox dispatches. Provider calls mean delivery-model requests, not all gateway/provider traffic. Sandbox calls mean driver dispatches, not individual test cases, generic shell tools, notifications or Firebase synchronization. Sandbox accounting begins with this release; older artifacts retain their actual verification evidence but no fabricated historical dispatch totals.

Model requests are durably charged before invocation, including errors/timeouts. Standard SDK retries are disabled. Hermes' exact Codex Responses adapter is preserved and rebuilt over a no-retry SDK leaf; unsupported wrappers fail closed. A real SDK/inert-HTTP test verifies a failed Codex response sends one request, not a hidden retry loop.

## Durable operations

SQLite tables `build_library`, `build_requests` and `tool_attempts` extend existing delivery state. Bundle digests define immutable revisions; repairs cannot erase previously saved source. Parent content and source evidence enter model prompts as untrusted data, separated from owner instructions. Original files are never edited or executed in place.

Immutable Firestore requests bind owner, request ID, parent ID/digest, control revision, action, instructions, expiry and per-request cumulative provider/sandbox caps. The host checks expiry at acceptance; accepted jobs waiting on quotas remain durable after that timestamp. Host revalidates current full-mode/acknowledgement/learning/read-write authority before activation and every model/sandbox/service effect. Daily-cap waiting preserves checkpoints; lifetime request exhaustion blocks that child until the owner submits a new explicitly budgeted follow-up. An accepted request ID deterministically maps to one child and does not reset usage on restart.

Owner intents and host-written runtime receipts occupy separate collections. Rules deny owner writes to build files, verification and usage. Budget writes use revision transactions; action previews freeze their exact payload and preserve ambiguous request nonces. Atomic stale budget/request combinations fail. Only the authenticated canonical Google owner can read private artifacts or submit requests.

## Verification and release

Implementation precedes tests. Tests cover real SQLite orchestration, private projection/backfill, upgrades/steering/briefs, immutable originals, archive/restore, budget raise/reduction/window reset, lifetime caps, stale/malformed requests, pagination, pause during control readback, projection loss and restart recovery. The real Bubblewrap driver exercises a complete fixture upgrade; generated code never runs on the host. Emulator rules tests use synthetic fixtures only. Exact Codex transport is tested against inert HTTP, separately from actual model semantic behavior.

Live release requires passing backend, UI and emulator checks, browser layout/interaction checks, a versioned package and rollback evidence. Reload only `hermes-cct-owner-delivery-generalist2.service`; do not restart the Telegram gateway or research workers. Verify live owner-only library/control projections and the unchanged current budget configuration by readback. A public logged-out shell check is not a signed-in owner-browser check.
