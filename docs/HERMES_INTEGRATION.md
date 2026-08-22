# Hermes Agent integration

## Supported integration

The repository provides a native Hermes plugin named `cct-agency`.

It can be installed from Git or through the Python package entry point.

Authoritative Hermes plugin documentation:

- <https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins>
- <https://hermes-agent.nousresearch.com/docs/developer-guide/plugins>

## Git install

Install disabled first:

```bash
hermes plugins install five0nit/choice-chance-time-agency-engine --no-enable
```

Inspect and validate:

```bash
hermes plugins list
hermes plugins show cct-agency
hermes plugins capabilities cct-agency
hermes plugins doctor cct-agency --ci
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

Start a new Hermes session so the tool definitions and hooks are loaded into a fresh prompt cache.

For a reproducible install, pin an immutable 40-character commit:

```bash
hermes plugins install five0nit/choice-chance-time-agency-engine \
  --no-enable \
  --ref <full-40-character-commit-sha>
```

Hermes records the source and pinned revision. Updating a pinned plugin requires an explicit reinstall with a new exact commit.

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

Pip entry-point discovery depends on the Python environment used by Hermes. Git installation through `hermes plugins install` is the simpler profile-scoped path for most users.

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

The identity becomes part of the constitution fingerprint when a new store is initialized. Changing identity against an existing database fails closed as a constitution mismatch. Use a new state directory or an explicit future migration/endorsement path; do not edit the database.

### `team_sync_source`

Optional absolute path to an owner-controlled JSONL stream.

When unset:

- all core tools and hooks load;
- local autonomy remains available;
- continuity sensor status reports `not-configured`.

When set, source validation includes regular-file, ownership, permission, link-count, descriptor-identity, and trusted-root checks. Producer prose is not copied into trusted cognition.

Standalone scripts also support environment configuration:

```bash
export HERMES_HOME="$HOME/.hermes"
export CCT_IDENTITY="My-CCT-Agent"
export CCT_TEAM_SYNC_SOURCE="/absolute/path/to/project_changes.jsonl"
```

For Hermes itself, prefer `hermes config set plugins.entries...settings...` for non-secret settings.

## Tools

The plugin registers fifteen tools:

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

### Local autonomy

- `cct_autonomy_status`
- `cct_opportunity_propose`
- `cct_autonomy_run`

Model-created opportunities receive `self` authority and no executable plan. The model-callable tools cannot register host-authorized effects.

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
