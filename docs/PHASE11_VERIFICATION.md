# Phase 11 verification — personal agency `0.8.0a1`

## Disposition

**Local development candidate verified. Not publicly released. Not activated in a live Hermes profile.**

Branch: `phase11-personal-agency`

## Repository-first receipt

- discovery: `/tmp/brief2ship-preflight-cct-personal-agency-QikxIF/discovery.md/discovery.md`
- sources: GitHub, PyPI, crates.io
- candidate execution: disabled
- disposition: `build-clean`

See [`PHASE11_PREFLIGHT.md`](PHASE11_PREFLIGHT.md).

## Automated verification

```text
pytest:                         166 passed
Ruff:                          PASS
compileall:                    PASS
public release hygiene:        PUBLIC_RELEASE_CHECK_PASS files=70
git diff --check:              PASS
Hermes Plugin Doctor:          21 tools, 2 hooks
Phase 11 acceptance episode:   PASS
isolated wheel import/version: PASS
```

The acceptance episode proved:

- operator profile revision installed externally;
- `workspace.inspect` specification registered by a host adapter;
- two-action lease granted externally;
- safe UTF-8 read authorized and hash-receipted;
- suspicious instruction language marked untrusted and non-authoritative;
- inspected content absent from the canonical event ledger;
- third read denied after cumulative action budget exhaustion;
- self-created principal revision remained a non-applying proposal;
- event chain remained valid;
- high-power executors remained absent.

Acceptance receipt root:

```text
/tmp/cct-phase11-final-demo-i6n7Re
```

## Package verification

Artifacts:

```text
cct_agency_engine-0.8.0a1-py3-none-any.whl
cct_agency_engine-0.8.0a1.tar.gz
```

Final artifact checksums are generated after the source commit and published beside
immutable release assets. They are not embedded here because this document is
itself package input; embedding package hashes would make the checksum recursive.

The wheel was installed without dependencies into a fresh virtual environment
with `PYTHONPATH` removed. Distribution version, module version, principal model,
capability registry, and workspace inspector imports matched `0.8.0a1`.

## Security properties exercised

- principal profiles require `operator` or `host_adapter` authority;
- principal and capability-spec revisions are previous-digest-bound and atomic;
- model-created profile revisions cannot activate themselves;
- unknown JSON fields and type coercion fail closed;
- principal alignment does not grant capability authority;
- capability evaluation does not spend a lease budget;
- actual reservation atomically spends cumulative action, byte, and value budgets;
- concurrent requests cannot both consume the last lease action;
- reservations require and atomically recheck the evaluated principal-profile digest;
- reservations bind principal identity and canonical intent domain/action;
- effect consumption is single-use and rechecks live revocation and expiry;
- missing, expired, revoked, mismatched, out-of-scope, and over-budget leases deny;
- workspace paths reject absolute paths, traversal, wildcards, symlinks, sensitive
  path classes, non-regular files, multiply linked files, binary content, and
  byte overruns;
- root device/inode identity is pinned;
- the root is held by an open descriptor, resisting configured-path replacement;
- unauthorized requests are decided before filesystem traversal;
- directory traversal uses descriptor-relative `O_NOFOLLOW` opens where supported;
- target identity, size, and modification time are rechecked after reading;
- successful and failed reads receive bounded receipts without file content;
- returned content is always labelled `untrusted_workspace_content` with
  `instructions_authorized=false` and deterministic taint flags.

## Hermes surface

Six model-callable tools were added:

- `cct_principal_status`;
- `cct_principal_evaluate`;
- `cct_principal_propose`;
- `cct_capability_status`;
- `cct_capability_evaluate`;
- `cct_workspace_inspect`.

No model-callable tool can install a profile, register a specification, grant a
lease, revoke a lease, or endorse a principal revision.

## Deliberately absent

No executor exists in this candidate for:

- arbitrary shell;
- unrestricted network;
- credential use;
- autonomous publishing;
- finance;
- constitutional activation or self-ratification.

Prepared inactive example specifications do not grant authority and cannot
create an absent executor.

## Remaining gates

Before a public `0.8.0` release:

1. independent security and architecture review;
2. resolve all critical/high findings and material medium findings;
3. rebuild and re-run every receipt after final changes;
4. obtain explicit publication approval;
5. verify remote commit, CI, tag, source install, and release assets.
