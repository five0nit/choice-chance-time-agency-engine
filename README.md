# Choice–Chance–Time Agency Engine

**Verifiable autonomy that earns authority through proof.**

[![CI](https://github.com/five0nit/choice-chance-time-agency-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/five0nit/choice-chance-time-agency-engine/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](docs/ROADMAP.md)

The **Choice–Chance–Time Agency Engine** is a dependency-free Python architecture for AI agents that need more than prompt-level autonomy.

It gives an agent:

- persistent, attributable goals;
- genuine alternatives and a canonical `NO_OP`;
- seeded, replayable exploration that cannot bypass blockers;
- append-only temporal memory with SHA-256 event chaining;
- bounded global-workspace cognition;
- proactive initiative with cooldown, caps, deduplication, and `WAIT`;
- trusted metadata-only continuity sensors;
- hierarchical objectives and temporal plans;
- reversible local execution with independent verification;
- receipt-backed outcome learning; and
- authority that expands or contracts from demonstrated reliability.

It is designed around one rule:

> **Better reasoning does not silently become broader permission.**

## Naming

The project uses three related names deliberately:

| Name | Meaning |
|---|---|
| **Choice–Chance–Time** | The operational-agency model. |
| **CCT Kernel** | The hardened governance core: goals, alternatives, blockers, scoring, replay, provenance, and temporal consequences. |
| **CCT Agency Engine** | The complete system: kernel + cognition + initiative + sensors + planning + execution + verification + learning. |
| **CCT Agency** | The Hermes Agent plugin that exposes the engine as tools and lifecycle hooks. |

The Python import remains `cct_agent` and the compatibility CLI remains `cct-agent`. The preferred public CLI is `cct-engine`.

## Why Choice, Chance, and Time?

```text
Operational agency = Choice × Chance × Time
```

- **Choice** — real allowed alternatives, counterfactual predictions, named reasons, and visible rejected branches.
- **Chance** — bounded exploration that prevents one policy from becoming permanently frozen. Constraints are applied before probability.
- **Time** — persistent goals, identity, commitments, outcomes, calibration, and explicit reflective revision.

If one term is missing:

- no choice → compulsion;
- no chance → frozen policy;
- no time → stateless reaction;
- chance alone → randomness, not agency.

This is an engineering definition of **operational agency**. It does not establish consciousness, qualia, sentience, moral personhood, or metaphysical free will.

Read the complete model: [`docs/CHOICE_CHANCE_TIME.md`](docs/CHOICE_CHANCE_TIME.md).

## Closed-loop architecture

```text
observations / host adapters / model proposals
                     ↓
          bounded global workspace
                     ↓
     beliefs + goals + self-model + memory
                     ↓
                 CCT Kernel
   blockers → score → explore/exploit → NO_OP
                     ↓
             opportunity portfolio
                     ↓
    hierarchical objective + temporal plan
                     ↓
         progressive authority envelope
                     ↓
 reversible effect → independent verification
                     ↓
 receipt / fallback / rollback / realised outcome
                     ↓
 capability reliability + later choice
                     ↺
```

The model supplies imagination. The CCT Kernel supplies stable rules and replayability. The host supplies trusted authority. The temporal ledger supplies continuity. Verifiers supply causal truth.

Detailed architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## What makes it different?

Many agent systems provide tool access, a planner, or memory. CCT focuses on the missing governance loop between them:

1. **Proposals are not permissions.** Model-created opportunities persist with `self` authority and cannot make themselves executable.
2. **Blocked options never enter exploration.** Randomness cannot cross a constraint.
3. **`NO_OP` is first-class.** Doing nothing remains an explicit, replayable alternative.
4. **Every important decision is replayable.** Candidate ordering, scores, mode, seed, probabilities, draws, and chosen/rejected options are recorded.
5. **Execution requires exact verification.** Every executable branch binds action path and content hash to an independent verifier.
6. **Authority is earned per capability.** Success increases bounded throughput; failure contracts it. Promotion never creates a new effect kind by implication.
7. **History is canonical.** Goals, decisions, outcomes, reflections, sensor cursors, action claims, receipts, rollbacks, and promotions live in one append-only event chain.
8. **Idle autonomy is cheap.** Sensor, heartbeat, proactive, and autonomy ticks make zero model calls and stay silent when nothing changed.

## Current authority envelope

Version `0.7.0` starts at Level 1:

| Level | Name | Maximum actions | Maximum bytes | Replace files? |
|---:|---|---:|---:|---|
| 1 | `reversible_local_create` | 4 | 16,384 | No |
| 2 | `verified_local_batch_create` | 10 | 65,536 | No |
| 3 | `earned_local_create_throughput` | 24 | 262,144 | No |

All levels remain create-only `write_text` beneath one identity-pinned workspace root.

Structurally absent from the autonomous executor:

- arbitrary commands or process spawning;
- file deletion or replacement;
- network or browser actions;
- credential, wallet, token, or key access;
- publication or messaging tools;
- financial or legal effects;
- package installation; and
- irreversible actions.

Higher authority means **more proven throughput**, not a silent jump to shell or network access.

Read the exact boundary and threat assumptions: [`docs/AUTHORITY_MODEL.md`](docs/AUTHORITY_MODEL.md).

## Quick start

### Requirements

- Python 3.11+
- Linux for the full autonomy executor (`renameat2(RENAME_NOREPLACE)`, `fcntl`, inode and mode checks)
- no runtime Python dependencies

Core cognition and decision modules are portable Python. The hardened filesystem executor and scheduler scripts use POSIX/Linux primitives.

### Install locally

```bash
git clone https://github.com/five0nit/choice-chance-time-agency-engine.git
cd choice-chance-time-agency-engine
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

### Run a cognitive episode

```bash
cct-engine --db /tmp/cct-demo.sqlite cognitive-demo --seed 0
cct-engine --db /tmp/cct-demo.sqlite cognitive-status
cct-engine --db /tmp/cct-demo.sqlite events --limit 10
```

### Run the deterministic autonomy acceptance episode

```bash
receipt=$(mktemp -d /tmp/cct-autonomy-demo-XXXXXX)
python scripts/cct_phase10_demo.py \
  --db "$receipt/agency.sqlite" \
  --workspace "$receipt/workspace" \
  --state-root "$receipt/autonomy" \
  > "$receipt/result.json"
python -m json.tool "$receipt/result.json"
```

The episode proves:

- a fragile high-value opportunity initially wins;
- a real collision causes primary failure;
- a validated fallback creates and hash-verifies an artifact;
- realised outcome quality changes a later near-tie choice;
- a terminal failure rolls back a temporary write;
- foreign bytes remain untouched; and
- the event chain remains valid.

### Run verification

```bash
python -m pytest -v --tb=short
python -m compileall -q cct_agent hermes_plugin scripts tests
```

## Hermes Agent integration

CCT ships as the native Hermes plugin **`cct-agency`**.

```bash
hermes plugins install five0nit/choice-chance-time-agency-engine --no-enable
hermes plugins doctor cct-agency --ci
hermes plugins enable cct-agency
```

Start a new Hermes session after enabling so the tool surface is rebuilt.

The plugin exposes fifteen tools and two lifecycle hooks. It stores profile-scoped state under:

```text
$HERMES_HOME/cct-agency/
```

Optional configuration:

```bash
export CCT_IDENTITY="My-CCT-Agent"
export CCT_TEAM_SYNC_SOURCE="/absolute/path/to/project_changes.jsonl"
```

`CCT_TEAM_SYNC_SOURCE` is optional. Without it, core cognition, agency tools, and local autonomy remain available; the team-sync continuity sensor reports `not-configured`.

**Trust note:** native Hermes plugins execute in the Hermes process with the current user's permissions. CCT's narrow authority model constrains the **CCT autonomous executor**. It does not sandbox the surrounding Hermes process or automatically mediate every ordinary Hermes tool call.

Complete setup and integration notes: [`docs/HERMES_INTEGRATION.md`](docs/HERMES_INTEGRATION.md).

## Benefits

### For agent builders

- inspectable choice instead of hidden prompt heuristics;
- deterministic replay for incidents and evaluations;
- capability-specific reliability rather than one global trust bit;
- explicit separation between proposal, authorization, execution, and verification;
- stable event history across process restarts; and
- model-free idle operation.

### For operators

- visible reasons and rejected alternatives;
- named blockers and explicit uncertainty;
- bounded interruption policy;
- exact receipts for claimed effects;
- rollback rather than optimistic success claims; and
- progressive autonomy supported by evidence.

### For researchers

- an operational testbed for reasons-responsive choice;
- controlled exploration after constraint filtering;
- persistent consequence learning;
- lesion and replay experiments;
- causal initiative calibration; and
- a precise non-claim boundary around consciousness.

Full benefit analysis: [`docs/BENEFITS.md`](docs/BENEFITS.md).

## Repository map

```text
cct_agent/
  kernel.py              Choice, chance, constraints, scoring, replay
  store.py               Append-only SHA-256 event ledger
  cognitive_cycle.py     Recurrent bounded cognition
  attention.py           Deterministic workspace competition
  beliefs.py             Evidence-linked belief state
  self_model.py          Capabilities, commitments, uncertainty, calibration
  memory.py              Structured bounded consolidation and retrieval
  proactive.py           SEND / WAIT policy, cooldown, caps, deduplication
  initiative.py          Trusted promotion and verified-feedback calibration
  team_sync_sensor.py    Metadata-only trusted continuity
  autonomy.py            Portfolio, plans, executor, verification, learning
hermes_plugin/            Pip entry-point implementation
scripts/                  Model-free scheduler and acceptance entry points
tests/                    Behavioral, race, restart, privacy, and replay tests
docs/                     Theory, architecture, authority, benefits, roadmap
```

## Documentation

| Document | Purpose |
|---|---|
| [`CHOICE_CHANCE_TIME.md`](docs/CHOICE_CHANCE_TIME.md) | Theory, equations, operational tests, and non-claims |
| [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Full component and data-flow architecture |
| [`COGNITION.md`](docs/COGNITION.md) | Global workspace, beliefs, self-model, memory, metacognition |
| [`INITIATIVE.md`](docs/INITIATIVE.md) | Proactive dialogue and feedback calibration |
| [`TRUSTED_SENSORS.md`](docs/TRUSTED_SENSORS.md) | Metadata-only event ingestion and cursor semantics |
| [`AUTONOMY.md`](docs/AUTONOMY.md) | Opportunity-to-outcome execution loop |
| [`AUTHORITY_MODEL.md`](docs/AUTHORITY_MODEL.md) | Exact permissions, limits, verification, and rollback model |
| [`BENEFITS.md`](docs/BENEFITS.md) | Practical and research benefits |
| [`HERMES_INTEGRATION.md`](docs/HERMES_INTEGRATION.md) | Install, enable, configure, and verify the plugin |
| [`VERIFICATION.md`](docs/VERIFICATION.md) | Test matrix and release evidence |
| [`ROADMAP.md`](docs/ROADMAP.md) | Current limitations and next phases |
| [`REPOSITORY_DISCOVERY.md`](docs/REPOSITORY_DISCOVERY.md) | Repo-first evidence and reuse disposition |

## Honest scope

Implemented:

- operational choice, bounded chance, temporal continuity;
- deterministic global-workspace cognition;
- adaptive initiative and trusted local sensing;
- reversible create-only local autonomy;
- independent verification, rollback, and capability learning;
- Hermes plugin integration.

Not implemented:

- arbitrary autonomous shell, network, browser, or public action;
- a non-bypassable host policy over every external Hermes tool;
- proof of consciousness or subjective experience;
- multi-agent consensus or replication;
- automatic self-amendment of root commitments;
- transactional exactly-once delivery across external messaging platforms.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) before treating alpha behavior as production authorization infrastructure.

## Security

Read [`SECURITY.md`](SECURITY.md) before enabling the Hermes plugin or attaching a continuity source.

Security reports should use GitHub's private vulnerability reporting when available. Do not publish live credentials, private state, real prompt-injection payloads, or destructive reproduction steps in a public issue.

## Contributing

Contributions are welcome. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md).

Behavioral invariants matter more than implementation shape. New capabilities must ship with:

- a typed schema;
- explicit authority source;
- budget and path/effect limits;
- independent verification;
- restart and concurrency behavior;
- rollback or a documented irreversibility gate; and
- tests proving blocked options remain blocked.

## Attribution

Created by **Michael Costea** with Hermes Agent as an engineering collaborator.

Licensed under the [MIT License](LICENSE).
