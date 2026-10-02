# Host-owned delivery services

## Scope and status

`ServiceDispatcher(config, state_dir, gateway=None, ticket_authority=None, ...)`
connects a fixed canonical Firebase owner/project and optional fixed GitHub target.
Construction performs no network requests. Model text cannot configure targets,
credentials, policies, tickets or financial routes. This is source capability, not
proof of installed, configured, authorized or live operation.

- `capabilities()` returns per-operation implementation/configuration/authority/readback evidence.
- `notify_owner(job)` writes one private `cct_owner_messages/msg-...` document,
  reads the exact target back, and returns `state`, `readVerified`, `documentPath`,
  and a receipt digest. Canonical dashboard notification only, not a Telegram send.
- `probe()` invokes configured read-only probes; callers must explicitly request it.
- `github_identity()` checks authenticated identity against pinned account ID/login.
- `github_create_intent(GitHubIssueCreate(...))` and `github_read_intent(number)`
  produce exact typed intents. Execution methods require existing host execution
  tickets, matching byte/value budgets, target binding and current policy gates.
- `public_quote()` fetches the fixed public Kraken XBTUSD ticker. Quotes are not
  fills, trades, wallet PnL or earnings.
- `execute_payment(PaymentCommand(...), ticket_id=...)` remains blocked: no payment driver, configured
  payment target or financial authority is supplied by this delivery lane.

## Configuration

Top-level keys include `projectId`, `ownerUid`, and `services`. Service options:
`ownerNotificationsEnabled`, `publicQuotesEnabled`, and optional `github` with
`accountLogin`, `accountId`, `repository`, `repositoryId`. Unknown options fail closed.
Owner notifications have no pause exemption. Every dispatch freshly checks the
canonical workspace after acquiring the service lock, again after target preflight
before the durable claim/write, and before readback/reconciliation. Require
`learningEnabled=true`, `autonomyMode=full`, `autonomyAcknowledged=true`, and both
`workspaceRead` and `workspaceWrite`. A bound global kill switch also blocks dispatch.
These are private owner-dashboard writes, not third-party messages; the separate
`externalMessages` permission is not required. A network-free capability snapshot
never asserts notification `authorized=true`, even after historical readback success.

Pause before claim leaves no effect claim or write. Pause observed after submission
returns `UNKNOWN`; resumption reads the exact claimed target without resending.
The final workspace observation is not a cross-system atomic transaction: a later
remote pause cannot retroactively cancel a request already issued. Local execution
also refreshes its effect gate after projection/readback, immediately before the
sandbox driver call. These checks close known I/O gaps, not OS preemption races.

GitHub additionally requires the host-created private `service-policy.json`, separate
credentials, current canonical workspace permissions and exact operation tickets.
Dashboard full mode is not a ticket and cannot activate payments.

Every credentialed GitHub stage freshly reads `cct_workspace/current` through the
canonical owner/project binding and strict workspace validator. Missing, malformed,
unavailable or mismatched workspace state fails closed. `learningEnabled` must be
`true`, `autonomyMode` must be `full`, and `autonomyAcknowledged` must be `true`.
Identity and issue reads require `credentialAccess` and `workspaceRead`; create
operations additionally require `workspaceWrite` and `externalMessages`. These
settings only restrict host policy and tickets; they never issue new authority.
Root policy, kill switch, workspace and exact ticket are rechecked between identity,
repository, issue submission and readback, including verified-create replay reads.
Revocation after submission yields `UNKNOWN` without further credentialed readback
or automatic resubmission; the returned target remains in the durable journal.

`capabilities()` stays network-free: all GitHub `authorized` flags are `false`
because cached workspace/identity evidence cannot prove current permission.
`rootPolicyEnabled` describes the separate host gate, not workspace permission;
`readVerified` remains historical evidence. Identity reports
`SERVICE_WORKSPACE_RECHECK_REQUIRED` when its host gates are otherwise available.

Do not place credentials in JSON examples, generated artifacts, reports or logs.
Never load service policy or credential material from model output.

## Effect and replay contract

The private SQLite journal durably claims an effect before outbound submission.
Provider exceptions can be ambiguous; claimed effects are read back, not blindly
resubmitted. Same operation ID with different intent fails closed. A lost first
write may therefore require operator reconciliation rather than an automatic send.
Verified receipts use actual provider readback, never a model success claim.
Private notification text uses a fixed host template and opaque job reference;
job titles, instructions, arbitrary URLs and error text are not copied into it.

## Verification and activation boundary

`tests/test_owner_delivery_services.py` uses offline transport/authority fixtures.
`tests/test_owner_delivery.py::test_real_local_and_service_driver_integration`
uses the real local sandbox and service journal with an in-memory Firestore gateway
and fixture model. Neither is an authenticated external-service canary.

Run `python3 -m pytest tests/test_owner_delivery*.py -v --tb=short` with a native
Linux Python exposing `os.memfd_create`; the sandbox fails closed without that
seccomp prerequisite. Do not replace the sandbox with unsandboxed execution.

Activation requires an exact reviewed package, profile-owned runtime, bounded
configuration and a separately recorded real canary/readback. Installing a wheel
or writing a systemd definition does not activate unattended execution.
