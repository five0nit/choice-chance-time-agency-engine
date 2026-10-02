# Dashboard rework — base-selection record

Target: rework the existing owner-only Firebase CCT dashboard with permission intent, decision and goal cards, adaptive preference questions and explicit autonomy confirmation, without changing the runtime being repaired by another owner.

## Discovery evidence

The bounded, local-only Brief2Ship discovery completed before this isolated worktree was implemented. Receipt directory: `/tmp/brief2ship-preflight-cct-dashboard-20260912-2115` (`discovery.json`, `discovery.md`, `checkpoint.json`, three candidate records). No candidate execution occurred during discovery. Existing exact-owner dashboard code is the authorized base; no external package or replacement framework was needed.

Machine-scored candidates, preserved without recomputation:

- `local/cct-free-agent`: raw 64.35, decision 59.82. Canonical CCT source contains the generalist repair lane; avoid modifying the active lane.
- `local/cct-firebase-control-generalist2`: raw 63.81, decision 59.29. Exact deployed Firebase auth, build, CSP, receipt-bound control and bridge base at `9794a6b433ca9996ac7e3f8b071fb3e0306bf071`.
- `local/hosting`: raw 40.50, decision 30.86. Nested frontend of the same repository, not an independent replacement.

The automated receipt is inconclusive because it did not normalize the full repository MIT license text into its permissive allowlist. Manual inspection of the complete root `LICENSE` confirms the standard MIT grant and disclaimer with Michael Costea and contributors copyright, no additional restriction. The nested package inherits this repository license. This human-readable disposition records the actual base choice; it does not rewrite the machine receipt or claim the engine itself approved it.

## Disposition

Exactly one selected disposition: **selective-reuse**.

Reuse the existing Firebase control worktree's pinned `9794a6b` base in isolated branch `feat/cct-learning-dashboard`. Retain its exact Google owner gate, existing dependencies/lock, build/CSP configuration, cloud envelope and request/receipt authentication. Add modular preference modeling, transactional owner intent and observation-only projection. Do not merge, install or activate against the separate live runtime until its repair owner provides a compatible handoff.

No implementation dependency versions changed. Browser automation uses an already installed optional Playwright module and Chrome, not a new production dependency. Test-only identity simulation and fixture data are not emitted by the hosting build.
