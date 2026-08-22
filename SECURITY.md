# Security policy

## Project status

Choice–Chance–Time Agency Engine is public alpha software. It is not a sandbox, credential vault, or complete authorization monitor for a surrounding agent runtime.

## Supported versions

| Version | Supported |
|---|---|
| `0.7.x` | Yes |
| Earlier private-development versions | No public support |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository when available.

Include:

- affected version and commit;
- operating system and Python version;
- minimal reproduction using temporary state;
- expected versus observed boundary;
- whether the issue can create an effect, corrupt provenance, bypass verification, duplicate a result, or escape rollback; and
- suggested severity.

Do not include:

- real API keys, tokens, cookies, wallets, or private keys;
- private Hermes state or conversation content;
- live destructive payloads;
- public self-propagation prompts tested against real agents; or
- personal data.

## Security model

### Protected properties

The project aims to preserve:

- blocked-option exclusion before stochastic choice;
- constitution continuity;
- event-chain integrity;
- goal and authority provenance;
- bounded context and persistence;
- model-proposal versus host-authorization separation;
- workspace confinement;
- no-replace publication;
- exact action verification;
- receipt authorship using inode identity plus digest;
- idempotent restart recovery;
- non-clobbering rollback; and
- capability-specific authority updates.

### Current autonomous effect

Only create-only `write_text` beneath one approved local workspace root.

The executor has no command, process, network, browser, delete, replacement, credential, publication, financial, legal, or irreversible effect type.

### Trusted computing base

The trusted computing base includes:

- Python interpreter and standard library;
- operating system and filesystem semantics;
- SQLite;
- CCT source code;
- host adapter or authenticated operator integration;
- local process owner; and
- surrounding Hermes process when the plugin is enabled.

A process with arbitrary code execution as the same user can alter code or state outside CCT's guarantees. CCT does not defend against a fully compromised host account.

### Hermes plugin boundary

Native Hermes plugins execute in-process. Enabling `cct-agency` grants its Python code the same operating-system permissions as Hermes.

CCT constrains its own autonomous executor. It does not sandbox Hermes and does not currently mediate every ordinary Hermes tool.

### Privacy

CCT does not automatically persist raw chat turns or hidden chain-of-thought.

It may persist:

- caller-supplied structured summaries when a caller invokes a persistence tool;
- content digests and character counts for completion receipts;
- private executable plan content under mode-controlled local state;
- metadata-only sensor receipts; and
- explicit evidence references supplied by callers.

SHA-256 digests are not anonymization for predictable or low-entropy text.

### Sensor boundary

A valid local owner and valid file permissions establish provenance, not semantic safety.

The team-sync sensor therefore stores opaque project/actor references, allowlisted kind, canonical time, and source-record digest. Producer summaries, operations, file lists, next steps, and source-supplied authority do not enter trusted cognition automatically.

## High-priority vulnerability classes

Please report privately if you find:

- blocked action sampled under any seed;
- model/caller self-promotion to host or operator authority;
- path escape, symlink traversal, ancestor substitution, or target overwrite;
- false receipt from foreign equal bytes;
- duplicate outcome or authority promotion after crash/retry;
- rollback clobbering a foreign or changed file;
- event-chain validation accepting tampered history;
- automatic raw-conversation persistence;
- unbounded schema/persistence mismatch;
- plugin status leaking private plan content, backup bytes, or absolute roots; or
- tainted external content persisting or propagating through a supposedly metadata-only path.

## Safe research practices

Use temporary profiles, temporary filesystems, fake outbound sinks, and inert fixtures.

Do not test published prompt-injection or self-propagation payloads against live profiles, shared agents, real messaging channels, or third-party systems.

## Dependencies

Runtime dependencies are intentionally empty. Build and test tools remain supply-chain dependencies and should be pinned or reviewed in release automation.
