# Hermes Agent integration

## Supported integration

The repository provides a native Hermes plugin named `cct-agency`.

It can be loaded from a reviewed source checkout or through the Python package entry point.

Authoritative Hermes plugin documentation:

- <https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins>
- <https://hermes-agent.nousresearch.com/docs/developer-guide/plugins>

## Reviewed source install

Hermes 0.20.5's community-plugin scanner currently returns a dangerous verdict
for this repository. The findings are false positives caused by intentional
credential-path denylist terms and inert prompt-injection regression fixtures.
Hermes correctly refuses to let `--force` override a dangerous verdict.

Do not disable scanning solely to bypass this result. Review the repository,
then clone the exact release into the profile's user-plugin directory:

```bash
plugin_root="${HERMES_HOME:-$HOME/.hermes}/plugins/cct-agency"
git clone --branch v0.7.0 --depth 1 \
  https://github.com/five0nit/choice-chance-time-agency-engine.git \
  "$plugin_root"
```

Inspect and validate before enablement:

```bash
hermes plugins list
hermes plugins show cct-agency
hermes plugins capabilities cct-agency
hermes plugins doctor "$plugin_root" --ci
```

Configure optional non-secret settings:

```bash
hermes config set plugins.entries.cct-agency.settings.identity "My-CCT-Agent"
hermes config set plugins.entries.cct-agency.settings.team_sync_source "/absolute/path/to/project_changes.jsonl"
```

Then enable:

```bash
hermes plugins enable cct-agency
```

If Hermes asks whether `cct-agency` may replace built-in tools, answer **no**.
The plugin registers non-conflicting `cct_*` names and does not require
`tools.override` capability.

Start a new Hermes session so the tool definitions and hooks are loaded into a fresh prompt cache.

For an immutable source pin, clone normally and detach at the reviewed full
40-character commit before running Plugin Doctor:

```bash
git -C "$plugin_root" fetch origin <full-40-character-commit-sha>
git -C "$plugin_root" checkout --detach <full-40-character-commit-sha>
test "$(git -C "$plugin_root" rev-parse HEAD)" = <full-40-character-commit-sha>
```

The standard `hermes plugins install` path remains blocked for this release
until scanner false positives for denylist and inert security-test fixtures are
resolved upstream.

## Pip/editable install

The Python package registers this entry point:

```toml
[project.entry-points."hermes_agent.plugins"]
cct-agency = "hermes_plugin"
```

For development:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Pip entry-point discovery depends on the Python environment used by Hermes. For this release, the reviewed source-install path above is the most predictable profile-scoped installation method.

## State

CCT stores profile-scoped state under:

```text
$HERMES_HOME/cct-agency/
```

Key paths:

```text
agency.sqlite                 canonical CCT event ledger
workspace/                    autonomy workspace root
autonomy/                     private plans, claims, backups, quarantine
team-sync-sensor.json         optional bounded project filter
*.lock                        scheduler serialization
```

Private directories use mode `0700`; sensitive state files use mode `0600` where supported.

Do not copy a live SQLite file while its process is writing unless using SQLite-aware backup tooling.

## Configuration

### `identity`

Default: `CCT-Agent`.

The identity becomes part of the constitution fingerprint when a store is initialized. Root creation uses one SQLite logical-key transaction so concurrent processes converge on one canonical constitution even when trusted metadata predates kernel initialization. An existing store rehydrates its one exact initialized constitution only after hash-chain, payload-fingerprint, schema, configured-identity, and exact numeric-representation checks pass. Changing identity against an existing database still fails closed. Use a new state directory or an explicit future migration/endorsement path; do not edit the database.

### `team_sync_source`

Optional absolute path to an owner-controlled JSONL stream.

When unset:

- all core tools and hooks load;
- local autonomy remains available;
- continuity sensor status reports `not-configured`.

When set, source validation includes regular-file, ownership, permission, link-count, descriptor-identity, and trusted-root checks. Producer prose is not copied into trusted cognition.

### `inspection_root` — development `0.8.0a1`

Optional absolute root for the separately leased `cct_workspace_inspect` tool.

Configuration alone grants nothing. The same CCT event store must also contain:

- an externally installed principal profile;
- a host-registered `workspace.inspect` capability specification;
- an active matching capability lease.

New tools:

- `cct_principal_status`;
- `cct_principal_evaluate`;
- `cct_principal_propose`;
- `cct_capability_status`;
- `cct_capability_evaluate`;
- `cct_workspace_inspect`.

Use the local CLI for operator-only profile installation, specification
registration, lease grant, and revocation. These mutations are deliberately not
model-callable.

Standalone scripts also support environment configuration:

```bash
export HERMES_HOME="$HOME/.hermes"
export CCT_IDENTITY="My-CCT-Agent"
export CCT_TEAM_SYNC_SOURCE="/absolute/path/to/project_changes.jsonl"
```

For Hermes itself, prefer `hermes config set plugins.entries...settings...` for non-secret settings.

## Tools

Public `0.7.0` registers fifteen tools. Development `0.9.0a3` registers twenty-one:

### Status and cognition

- `cct_status`
- `cct_cognitive_status`
- `cct_self_model`
- `cct_verify_introspection`

### Goals and decisions

- `cct_form_goal`
- `cct_deliberate`
- `cct_record_outcome`
- `cct_reflect`

### Initiative

- `cct_proactive_status`
- `cct_topic_update`
- `cct_proactive_think`
- `cct_observe`

### Principal and typed capabilities — development

- `cct_principal_status`
- `cct_principal_evaluate`
- `cct_principal_propose`
- `cct_capability_status`
- `cct_capability_evaluate`
- `cct_workspace_inspect`

### Local autonomy

- `cct_autonomy_status`
- `cct_opportunity_propose`
- `cct_autonomy_run`

Model-created opportunities receive `self` authority and no executable plan.
They must link one active CCT goal and provide evidence. No model-callable tool
may assert operator opportunity feedback. Operator/host CLI feedback remains
available and cannot grant execution authority. Model-callable tools cannot
register host-authorized effects, install principal profiles, or issue leases.

## Hooks

### `pre_llm_call`

Advances one logical cognitive tick and injects at most 6,000 characters of structured active goals, beliefs, global-workspace state, self-model state, and topic continuity.

The context cap is fixed for the process and preserves the surrounding conversation's prompt-caching model.

### `post_llm_call`

Records a structured completion receipt containing hashes, character counts, model/platform metadata, and completion state.

CCT does not automatically store raw user messages, assistant responses, or hidden chain-of-thought. Unsalted SHA-256 content digests are linkage receipts, not anonymization guarantees for low-entropy content.

## Scheduler examples

### Proactive tick

```bash
HERMES_HOME="$HOME/.hermes" python scripts/cct_proactive_tick.py
```

Empty stdout means no message should be delivered.

Development `0.9.0a3` checks persistent principal-aligned task opportunities
before generic topic updates. Both lanes share the same cooldown, daily cap,
semantic dedupe, and atomic emission claim.

### Team-sync sensor tick

```bash
HERMES_HOME="$HOME/.hermes" \
python scripts/cct_team_sync_tick.py \
  --source /absolute/path/to/project_changes.jsonl \
  --report
```

Omit `--report` for silent success/idle operation.

### Autonomy tick

```bash
python scripts/cct_autonomy_tick.py \
  --db /tmp/cct.sqlite \
  --workspace /tmp/cct-workspace \
  --state-root /tmp/cct-autonomy \
  --seed 0 \
  --message-only
```

`NO_OP` returns empty stdout under `--message-only`.

## Trust and process boundary

A native Hermes plugin is trusted Python code running in the Hermes process with the current user's permissions. Hermes plugin enablement is opt-in, but it is not a process sandbox.

CCT's authority model constrains work that enters the CCT autonomous executor. It does not automatically mediate every ordinary Hermes tool call. Terminal, browser, file, messaging, and other Hermes tools retain their own host configuration and approval boundaries.

Read [`AUTHORITY_MODEL.md`](AUTHORITY_MODEL.md) before treating CCT as an authorization layer.

## Verification

Before enabling a source checkout:

```bash
python -m pytest -v --tb=short
python -m compileall -q cct_agent hermes_plugin scripts tests
hermes plugins doctor . --ci
```

After installation:

```bash
hermes plugins show cct-agency
hermes plugins list
```

Use a new CLI session for functional checks. Restart only the intended gateway profile if a long-running gateway must load the new plugin.
