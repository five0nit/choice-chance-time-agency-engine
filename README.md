# Choice–Chance–Time Agency Engine

**Verifiable autonomy that earns authority through proof.**

[![CI](https://github.com/five0nit/choice-chance-time-agency-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/five0nit/choice-chance-time-agency-engine/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

The **Choice–Chance–Time Agency Engine (CCTAE)** is a Python architecture for inspectable agent decisions, bounded execution, and receipt-backed learning. Its core uses only the Python standard library. Optional integrations have separate dependencies and host-controlled permissions.

**Public alpha: `0.9.0a22`.** This source tree is an alpha, not a hosted service or a claim of production readiness. Publication, package verification, and deployment are separate gates recorded in [PUBLIC_RELEASE.md](PUBLIC_RELEASE.md).

[Educational GitHub Pages overview](https://five0nit.github.io/choice-chance-time-agency-engine/) · [Architecture](docs/ARCHITECTURE.md) · [Authority model](docs/AUTHORITY_MODEL.md) · [Verification guide](docs/VERIFICATION.md)

The educational site explains the project; it is not the authenticated operator dashboard. Its deployment/readback status is a separate release gate.

## What it does

- Maintains persistent, attributable goals and a canonical `NO_OP` alternative.
- Filters blocked options before seeded, replayable exploration.
- Records decisions and outcomes in an append-only SHA-256 event chain.
- Bounds attention, working context, memory projections, and proactive interruptions.
- Separates principal alignment, host permission, execution, and verification.
- Learns capability reliability from completion evidence without inventing permissions.
- Projects technical events into concise human status without replaying raw payloads.
- Offers optional, explicitly configured operator and owner-workflow integrations.

> **Better reasoning does not silently become broader permission.**

## Choice, chance, and time

```text
Operational agency = Choice × Chance × Time
```

**Choice** means allowed alternatives with reasons and counterfactual predictions. **Chance** means constrained exploration rather than a permanently frozen policy. **Time** means persistent goals, identity, commitments, outcomes, and revision.

This is an engineering model of operational agency, not proof of consciousness, sentience, moral personhood, or metaphysical free will. See [the complete model](docs/CHOICE_CHANCE_TIME.md).

## Naming

| Name | Meaning |
|---|---|
| Choice–Chance–Time | The operational-agency model |
| CCT Kernel | Governance core: goals, alternatives, blockers, scoring, replay and provenance |
| CCT Agency Engine | Kernel plus cognition, initiative, planning, execution and verification |
| CCT Agency | Native Hermes plugin, ID `cct-agency` |

The distribution is `cct-agency-engine`, the Python import is `cct_agent`, and the preferred CLI is `cct-engine`. `cct-agent` remains a compatibility CLI.

## Authority in `0.9.0a22`

### Create-only core

The core local autonomy executor still supports only `write_text` beneath an identity-pinned workspace root. It starts at Level 1:

| Level | Name | Maximum actions | Maximum bytes | Replace files? |
|---:|---|---:|---:|---|
| 1 | `reversible_local_create` | 4 | 16,384 | No |
| 2 | `verified_local_batch_create` | 10 | 65,536 | No |
| 3 | `earned_local_create_throughput` | 24 | 262,144 | No |

Promotion increases verified create throughput, not effect vocabulary. This executor does not acquire shell, network, browser, credentials, publication, payments, deletion, or replacement authority. Work-autonomy suggestions use a create-only local evidence audit; they do not execute the suggested task's broader effects.

### Optional capability-limited integrations

The package also includes **separate, deny-by-default operator integrations**. It is no longer accurate to describe the entire package as having no network or process execution code.

- `workspace.inspect` requires principal alignment plus an externally issued, scoped lease.
- Typed operator routes can support bounded commands, public HTTPS research, expected-hash project edits, deployment, public actions, credential brokerage, finance, and high-consequence actions. Each requires its own host registration, exact authority, limits, and verifier; installation does not enable them.
- Standing autonomy accepts registered action IDs, not arbitrary command text or effect parameters. Learned tiers remain inside the operator's ceiling.
- Authenticated session access requires an explicitly mediated route and a separate scoped credential ticket. A ready session is not permission to act.
- Optional owner messaging, discovery, private builds, and continuation use their own configuration, identity checks, durable budgets, and effect boundaries.
- The local dashboard is read-only by default. Its explicitly bootstrapped control path can pause/resume `operator.web` administratively; resume creates no lease or ticket.
- The optional Firebase sidecar transports owner intent and host receipts. Cloud settings are not canonical CCT authority, and a saved preference is not execution proof.

These are not a universal sandbox over Hermes or arbitrary third-party tools. Native plugins run with their host process permissions. See [operator integrations](docs/OPERATOR_INTEGRATIONS.md), [authenticated access](docs/AUTHENTICATED_ACCESS.md), and [owner connection](docs/OWNER_CONNECTION.md).

## Install

### Requirements

- **Python >=3.11**; no mandatory third-party Python runtime dependencies for the core.
- **Linux/POSIX for hardened filesystem and owner execution paths.** They depend on ownership/mode/inode checks, descriptor-relative traversal, `fcntl`, and Linux no-replace publication where applicable.
- Private generated-code execution additionally requires a supported Linux Bubblewrap/seccomp environment and an interpreter exposing `os.memfd_create`. Unsupported environments fail closed; native Windows and macOS owner-sandbox parity is not promised. WSL support depends on its actual kernel and namespace policy.
- Firebase is optional. The `firebase` extra installs `firebase-admin` and `google-cloud-firestore`; the hosted UI has a separate Node/npm toolchain. Hermes-backed model adapters require an explicitly installed/configured Hermes environment.

### Version-pinned installation

Once the tag has been published and verified:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'git+https://github.com/five0nit/choice-chance-time-agency-engine.git@v0.9.0a22'
```

The command is the intended release install target, not a claim that the tag already exists. Before publication, use the reviewed candidate checkout:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Only if using Firebase, install the optional dependencies from that checkout:

```bash
python -m pip install -e '.[firebase]'
```

Installing an extra does not configure credentials, enroll an owner, create cloud resources, or start services. Public cloud and executor examples are deliberately unconfigured: read [public configuration](docs/PUBLIC_CONFIGURATION.md) before adapting them.

## Quick start

Use a fresh scratch ledger, not an existing operator database:

```bash
demo_dir=$(mktemp -d)
cct-engine --db "$demo_dir/agency.sqlite" cognitive-demo --seed 0
cct-engine --db "$demo_dir/agency.sqlite" cognitive-status
cct-engine --db "$demo_dir/agency.sqlite" human-status
cct-engine --db "$demo_dir/agency.sqlite" explain-latest
cct-engine --db "$demo_dir/agency.sqlite" digest --limit 8
```

`--json` provides structured narrative rows. The technical `status` and `events` commands can expose more detailed local state; do not publish private ledger output as release evidence.

From a source checkout, exercise the deterministic create-only acceptance episode:

```bash
receipt=$(mktemp -d)
python scripts/cct_phase10_demo.py \
  --db "$receipt/agency.sqlite" \
  --workspace "$receipt/workspace" \
  --state-root "$receipt/autonomy" \
  > "$receipt/result.json"
python -m json.tool "$receipt/result.json"
```

The episode exercises selection, collision, fallback, exact hash verification, rollback, learning, and chain validation. Run results must be checked; this example is not a pre-recorded pass receipt.

## Hermes integration

The native plugin is `cct-agency`; its tools use `cct_*` names. State is scoped to `$HERMES_HOME/cct-agency/`. Review the exact source and host permissions before enabling it. Optional settings and tools depend on the installed host and configuration; no fixed tool count is a compatibility promise.

See [Hermes integration](docs/HERMES_INTEGRATION.md) for installation, state, and trust boundaries. Installation does not authorize gateway restarts or broad mediation of every ordinary Hermes tool.

## Architecture

```text
observations / host adapters / model proposals
                   ↓
       bounded cognition + persistent goals
                   ↓
     blockers → score → exploration → NO_OP
                   ↓
      typed plan + explicit host authority
                   ↓
      bounded effect → independent verification
                   ↓
     receipt / rollback / realised outcome
                   ↓
      capability reliability + later choice
```

Models propose; the host grants authority; verifiers establish outcomes. See [architecture](docs/ARCHITECTURE.md) and [benefits](docs/BENEFITS.md).

## Documentation

| Guide | Purpose |
|---|---|
| [Choice–Chance–Time](docs/CHOICE_CHANCE_TIME.md) | Theory, operational tests and non-claims |
| [Cognition](docs/COGNITION.md) | Attention, beliefs, self-model, memory and stalls |
| [Initiative](docs/INITIATIVE.md) / [opportunities](docs/OPPORTUNITY_INITIATIVE.md) | Bounded proactive dialogue and task cards |
| [Trusted sensors](docs/TRUSTED_SENSORS.md) | Metadata ingestion and cursor semantics |
| [Local autonomy](docs/AUTONOMY.md) / [personal agency](docs/PERSONAL_AGENCY.md) | Create-only execution and separately leased inspection |
| [Operator integrations](docs/OPERATOR_INTEGRATIONS.md) | Optional effects, standing authority and non-goals |
| [Human narrative](docs/HUMAN_NARRATIVE.md) | Payload-safe event projections |
| [Local dashboard](docs/ADMIN_DASHBOARD.md) / [Firebase](docs/FIREBASE_CONTROL_PLANE.md) | Operator control surfaces and setup boundaries |
| [Owner connection](docs/OWNER_CONNECTION.md) / [bounded test executor](docs/BOUNDED_EXECUTOR.md) | Supervised messaging and diagnostic tasks |
| [Owner discovery](docs/OWNER_DISCOVERY.md) / [work](docs/OWNER_WORK.md) | Tool-free conversation and bounded research |
| [Private delivery](docs/OWNER_DELIVERY_LOCAL.md) / [builds](docs/OWNER_BUILDS_RUNTIME.md) / [continuation](docs/OWNER_CONTINUATION_RUNTIME.md) | Private artifact workflows and Linux sandbox requirements |
| [Verification](docs/VERIFICATION.md) / [release gates](PUBLIC_RELEASE.md) | Reproducible checks and pending release decisions |
| [Roadmap](docs/ROADMAP.md) / [reuse policy](docs/REPOSITORY_DISCOVERY.md) | Alpha limits and dependency decisions |

## Honest scope

Implemented source is not evidence of a configured, enabled, or live integration. No public cloud uptime, successful live owner conversation, deployed private build, or current release publication is asserted here. Fixture tests do not prove provider behavior; model review does not prove arbitrary correctness or revenue.

CCT does not establish consciousness, globally non-bypassable host policy, automatic self-amendment of root commitments, or exactly-once delivery across arbitrary external providers. See [the roadmap](docs/ROADMAP.md) before treating an alpha as production authorization infrastructure.

## Security and contributing

Read [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md). New effects need typed schemas, explicit authority, budgets, independent verification, restart/concurrency handling, and honest rollback or irreversibility semantics. Never include credentials, owner identifiers, private profiles, or raw operational logs in public issues.

Created by **Michael Costea** with Hermes Agent as an engineering collaborator. Licensed under the [MIT License](LICENSE).
