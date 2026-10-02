# CCTAE Dashboard Controlled Permission Slice

## Target and constraints

Extend the existing CCTAE localhost administrative dashboard with one reversible configured-intent control for the operator: deterministic preview, authenticated confirmation, atomic host apply, canonical readback, and append-only audit; keep the browser away from direct SQLite/config writes, preserve fixed capability specifications, create no lease or ticket, install nothing live, and produce no external effect.

## Discovery

- Primary receipt: `/tmp/brief2ship-preflight-cctae-controls-eKSC1b/discovery.md`
- Initial noisy receipt: `/tmp/brief2ship-preflight-cctae-controls-K3qzV1/discovery.md`
- Candidate execution: none
- Public sources: GitHub, PyPI, npm
- Local source: existing `cct-admin-dashboard-generalist2` worktree

| Candidate | Observed score | Disposition | Reason |
|---|---:|---|---|
| Existing CCTAE dashboard at exact parent `77067c62fd272b526fff275de4a34317a32f997b` | canonical local base | `build-clean` extension | Already owns the event store, capability registry, fixed-spec semantics, read-only projection, tests, package, and operator UX. |
| `agentplane-control-plane` / `theagentplane/control-plane` at `df07aa350656ffb5baf9609546dd004869749496` | 67.15 | reject | Different young product surface; six dependencies; no evidence its policy semantics preserve CCTAE leases, tickets, chain, or fixed capability catalog. |
| `agent-control-plane-core` 0.6.3 | 63.00 | reject | JavaScript package with incomplete static inspection; would create a second authorization model and dependency boundary. |
| `oscarmackjr-twg/zt-infra-full` at `b802d06ac909ab25701cffb2cf8f4af2c5ab22ea` | 62.92 | reject | Infrastructure provisioning scope, 13 dependencies, and no fit with CCTAE's append-only Python governance kernel. |
| `inferadb/control` at `64b23b5d1633469ef3fc050bbbb5b6894b6113e5` | 58.07 | reject | Rust database control plane with 106 dependencies; provisional keyword fit but excessive adaptation cost and wrong authority domain. |

## Choice

**Disposition:** `build-clean` inside the canonical CCTAE repository.

No external candidate code or dependency is reused. The new control remains a small Python/vanilla-JavaScript extension of the reviewed read-only dashboard. Capability specifications remain fixed catalog ceilings; reversible pause/resume state is projected from a separate append-only `capability.control.state_changed` event family.
