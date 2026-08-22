# Verification

## Release candidate

- Public name: **Choice–Chance–Time Agency Engine**
- Distribution: `cct-agency-engine`
- Version: `0.7.0`
- Python namespace: `cct_agent`
- Hermes plugin: `cct-agency`
- Runtime dependencies: none

## Test suite

Command:

```bash
python3 -m pytest -v --tb=short
```

Result:

```text
collected 141 items
141 passed in 19.38s
```

Coverage families:

- autonomy executor, verification, rollback, race, and restart behavior;
- bounded cognition and global workspace;
- adaptive initiative and verified feedback;
- kernel choice, chance, temporal ledger, and Hermes registration;
- deterministic autonomy acceptance episode;
- proactive SEND/WAIT, caps, cooldown, deduplication, and crash boundaries;
- trusted sensor path, cursor, privacy, malformed-data, and scheduler behavior.

## Static checks

```bash
ruff check cct_agent hermes_plugin scripts tests
python3 -m compileall -q cct_agent hermes_plugin scripts tests
git diff --check
```

Result:

```text
All checks passed!
```

## Hermes Plugin Doctor

Command:

```bash
hermes plugins doctor . --ci
```

Result:

```text
Plugin Doctor: <repository>
  manifest: cct-agency 0.7.0 (standalone)
  OK: runtime discovery, manifest parsing, import, and registration passed
  registrations: 15 tool(s), 2 hook(s)
```

Doctor uses Hermes' real manifest parser, directory discovery, import path, plugin context, hook registry, and tool registry.

## Distribution build

Command:

```bash
uv build
```

Artifacts:

```text
dist/cct_agency_engine-0.7.0-py3-none-any.whl
dist/cct_agency_engine-0.7.0.tar.gz
```

Wheel SHA-256:

```text
c0c5d56bec9ede7feab46151cc63c88cd4aa20392072878a2ef106d94adcb2ec  cct_agency_engine-0.7.0-py3-none-any.whl
```

The wheel hash identifies the locally verified release-candidate artifact. The
source distribution includes this verification document, so its final checksum
is published alongside the immutable GitHub Release asset rather than embedded
recursively here. Source publication does not imply PyPI publication.

Wheel inspection confirmed `hermes_plugin/plugin.yaml` and the complete
`cct_agent` package. Source-distribution inspection confirmed the public README,
native plugin manifest, security policy, architecture documentation, scheduler
scripts, deterministic demo, and tests.

## Isolated wheel install

The wheel was installed without dependencies into a fresh temporary Python 3.11 virtual environment.

Verified:

- `cct_agent.__version__ == "0.7.0"`;
- distribution metadata version `0.7.0`;
- `hermes_agent.plugins` entry point `cct-agency` present;
- `cct-engine` console script available;
- new store identity `CCT-Agent`;
- cognitive demo event chain valid.

Receipt:

```text
ISOLATED_METADATA_PASS version=0.7.0 entrypoint=cct-agency
ISOLATED_WHEEL_RUNTIME_PASS identity=CCT-Agent chain=valid
```

## Deterministic autonomy episode

Command class:

```bash
python3 scripts/cct_phase10_demo.py \
  --db <temporary>/agency.sqlite \
  --workspace <temporary>/workspace \
  --state-root <temporary>/autonomy
```

Verified:

- first fragile opportunity selected;
- real primary collision detected;
- validated fallback completed;
- first artifact independently verified;
- capability quality changed later opportunity selection;
- stable second artifact independently verified;
- controlled terminal failure remained failed;
- prior temporary write rolled back;
- foreign collision file preserved;
- executable content absent from event payloads;
- event chain valid.

Receipt:

```text
SOURCE_AUTONOMY_DEMO_PASS chain=valid first=verified second=verified rollback=complete
```

## Public-safety scan

The public candidate file set is checked for:

- operator-local absolute paths;
- private profile identifiers;
- known personal routing IDs;
- common API-key/token/private-key shapes;
- raw token/password JSON values;
- broken relative Markdown links;
- ignored runtime/build/cache files.

Historical private development receipts are excluded from the clean public repository snapshot.

## Honest boundary

These results verify source behavior, packaging, plugin registration, deterministic demos, and public-snapshot hygiene.

They do not prove:

- phenomenal consciousness;
- arbitrary host-tool mediation;
- external platform exactly-once delivery;
- production suitability for credentials, money, legal effects, or irreversible actions;
- security against a fully compromised same-user host process.
