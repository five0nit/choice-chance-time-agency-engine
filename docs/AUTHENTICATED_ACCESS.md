# Authenticated browser and computer-use access

CCT keeps public browsing, signed-in web work, and native desktop control as separate routes.

## Routing policy

| Task | Default route | Identity | Visible activity |
|---|---|---|---|
| Public or untrusted web research | Isolated `browser_exec` session | Clean throwaway profile; logged into nothing | Usually headless; headed mode is optional |
| Signed-in web task | `browser_real_profile_snapshot` | Consent-gated managed snapshot of the selected real browser profile | Headless by default; headed mode is optional |
| Already-authenticated native desktop app | `computer_use_existing_session` | Existing app session only | Background-first; Windows may show the tinted agent cursor |
| Password, MFA, CAPTCHA, permission, payment, or account recovery prompt | `AUTH_HANDOFF_REQUIRED` | User completes the protected step | CCT performs zero UI actions and resumes only after readback |

A separate agent browser is not an activity indicator or a proof receipt. It is normally an isolation boundary. Activity proof comes from exact tool receipts and readback; optional headed mode or the CUA overlay is cosmetic.

Hermes currently routes signed-in browser work through the `browser` toolset, not `computer_use`. The legacy `computer_use.grant_existing_profile` key is ignored by current Hermes. Browser real-profile mode is off by default and requires explicit consent. On Windows, producing a real-profile snapshot may require the selected browser to be fully closed.

## CCT scaffold

`cct_agent.operator_authenticated_access` adds a host-only bridge from an independently verified `operator.credential_use.completed` event to one explicit authenticated-session route.

The bridge records:

- opaque credential handle ID;
- exact credential receipt event and digest;
- target, route, app, consumer, owner, and purpose bindings;
- separate action-scope digest;
- `host_ticket_required=true`;
- `execution_authority_granted=false`;
- `secret_input_allowed=false`;
- `auth_handoff_policy=user_required`;
- zero UI actions and zero external effects during preparation.

It accepts only two host readback states:

- `READY`: an existing session is available; foreground unchanged; no UI action or secret input occurred.
- `AUTH_HANDOFF_REQUIRED`: no session is ready; user action required; no UI action or secret input occurred.

The scaffold does not enable real-profile browsing, copy browser data, drive the desktop, or grant credential/effect authority.

## Executable Hermes bridge

`cct_agent.operator_authenticated_session_bridge` consumes the prepared envelope through a second exact `operator.credential` execution ticket. The CCT Hermes plugin exposes four tools only when the operator configures exact targets:

- `cct_authenticated_access_preview` — compute preparation hashes;
- `cct_authenticated_access_prepare` — persist the zero-effect envelope;
- `cct_authenticated_session_preview` — compute separately ticketed dispatch arguments;
- `operator_authenticated_session` — execute one fixed session probe; registered only when explicitly present in `mediated_tools`.

The effect tool cannot accept browser code, URLs, computer-use actions, coordinates, text, or secrets. Its host driver chooses one fixed dispatch:

- browser route: `browser_exec` with fixed `ensure_real_tab()` code and a CCT-owned named session; requires the host assertion `authenticated_access_browser_real_profile_enabled=true`;
- native route: `computer_use` with `action=list_apps`; it requires exactly one registered app identity with at least one window when the driver reports a window count.

Raw browser output and native app inventories are hashed and discarded. Only route/target bindings, status, dispatch count, receipt hashes, zero-secret flags, and zero-UI-action facts enter CCT. If browser real-profile mode is not host-enabled, the bridge returns verified `AUTH_HANDOFF_REQUIRED` without dispatching. A driver error or ambiguous/missing native app fails closed rather than becoming a handoff claim.

The outer CCT tool-execution middleware consumes the second ticket before the bridge handler runs. The bridge rechecks ticket/capability/scope/budgets, kill switch, prepared lineage, and event chain. A crash after durable driver/readback evidence is adopted without another host dispatch; a claim without complete readback remains uncertain and is not retried.

The bridge remains disabled until the target metadata, effect tool in `mediated_tools`, credential registration/receipt, lease, and exact execution ticket are all installed by the host/operator.

## Verification contract

Tests must prove:

1. a verified opaque credential receipt links exactly one host registration, ticket dispatch, credential claim, credential completion, verified mediation outcome, and terminal mediation completion;
2. malformed provider digests, duplicate claim/completion histories, and unregistered or incomplete credential histories fail closed;
3. consumer, owner, purpose, target, action scope, and receipt hashes are bound;
4. replay is idempotent and conflicting readback cannot replace canonical state;
5. preparation and readback both reject an invalid event chain;
6. extra/raw secret fields fail closed;
7. `AUTH_HANDOFF_REQUIRED` records zero UI actions;
8. raw secret bytes are absent from the ledger, resolver state, and returned envelopes;
9. browser dispatch uses only fixed no-navigation code and native dispatch uses only app inventory;
10. raw browser/UI driver output is absent from CCT events and returned bridge results;
11. an unmediated effect call is denied before host dispatch;
12. a post-readback crash reconciles without a second browser/computer-use call;
13. invalid target config suppresses bridge tools and leaves middleware fail-closed;
14. the event chain remains valid.

## Source references

- Hermes browser automation: https://hermes-agent.nousresearch.com/docs/user-guide/features/browser
- Hermes computer use: https://hermes-agent.nousresearch.com/docs/user-guide/features/computer-use
