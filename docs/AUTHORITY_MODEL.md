# Authority model

## Meaning of authority

In CCT, **authority** means permission to create a real effect. It is not the same as intelligence, confidence, preference, a stored goal, or a high-scoring plan.

The engine may reason broadly while acting narrowly.

```text
think ≠ propose ≠ authorize ≠ execute ≠ verify
```

Each transition has a separate gate and receipt.

## Authority layers

### 1. Cognitive authority

CCT may maintain:

- goals;
- beliefs;
- topics;
- counterfactual predictions;
- alternatives;
- decisions;
- outcomes;
- reflections; and
- capability reliability.

These are internal state transitions. They do not authorize external effects.

### 2. Proposal authority

Model and caller proposals may enter the portfolio with `source_authority: self`.

Self-authority proposals:

- are persistent and inspectable;
- may be compared and blocked;
- cannot attach an executable plan through the Hermes model-callable tool; and
- cannot promote their own authority.

Executable plans require `host_adapter` or authenticated `operator` provenance established outside the model-callable schema.

### 3. Effect authority

Version 0.7.0 allows one effect kind in the autonomous executor:

```text
create a new text file beneath an approved workspace root
```

The effect is represented by typed data, not a command string.

Not present:

- shell command execution;
- arbitrary Python imports;
- process spawning;
- network requests;
- browser automation;
- deletion;
- replacement;
- permission changes;
- package installation;
- messaging or publication;
- financial actions;
- credential access;
- legal effects.

Prompt wording cannot create an effect kind that is absent from the executor's vocabulary.

### 4. Spatial authority

Every action path must be:

- relative;
- normalized;
- beneath the identity-pinned workspace root;
- free of `..` traversal;
- reached through non-symlink parents;
- a new target; and
- outside blocked sensitive path classes.

Blocked path classes include `.git`, `.env`, credentials, tokens, wallets, private keys, service accounts, and key stores.

The executor rejects symlink roots, parent symlinks, target symlinks, directories, FIFOs, non-regular files, and multiply-linked files.

### 5. Quantitative authority

| Level | Name | Actions | Total bytes | Replace |
|---:|---|---:|---:|---|
| 1 | `reversible_local_create` | 4 | 16,384 | No |
| 2 | `verified_local_batch_create` | 10 | 65,536 | No |
| 3 | `earned_local_create_throughput` | 24 | 262,144 | No |

Promotion rules:

- begin at Level 1;
- Level 2 after three clean receipt-backed verified successes and no failures in the recent twenty-run window;
- Level 3 after ten clean verified successes and at least 90% success;
- latest failed run contracts authority to Level 1.

Every level remains create-only. Promotion changes throughput, not effect vocabulary.

### 6. Plan authority

An executable plan must satisfy all of these:

- approved source authority;
- known typed fields only;
- bounded step count and retry values;
- acyclic dependency graph;
- valid step dependencies;
- branch-local preconditions;
- exact action path and content-hash verification for every branch;
- final verification; and
- plan digest matching the private stored plan.

Executable artifact content remains under private mode-controlled state. Event projections expose hashes and bounded metadata, not content.

### 7. Verification authority

An action does not declare itself successful.

The verifier reopens the target and compares exact state. Every executed path receives a receipt-derived final recheck even if a caller's final verification list omits it.

A matching pre-existing artifact produces a satisfied-but-zero-effect result. It does not count as evidence that CCT caused the artifact and does not earn authority.

### 8. Atomic publication and authorship

CCT prepares a regular single-link inode, hashes its contents, records `(st_dev, st_ino)` in a durable claim, then publishes with Linux `renameat2(RENAME_NOREPLACE)`.

Consequences:

- a concurrent creator wins safely without being overwritten;
- equal foreign bytes cannot become a CCT receipt;
- restart reconciliation requires both inode identity and digest; and
- action authorship is stronger than hash equality alone.

### 9. Recovery authority

Rollback is narrow and receipt-bound.

For current create-only effects, rollback moves the claimed inode into a private quarantine directory using no-replace semantics.

Rollback never:

- deletes an unknown file;
- overwrites a reoccupied original path;
- treats a foreign inode as CCT-owned; or
- claims completion when hashes do not match before/after receipts.

### 10. Learning authority

Outcome learning may change:

- capability sample count;
- success rate;
- quality estimate;
- uncertainty;
- later opportunity scoring; and
- eligibility for higher throughput.

Outcome learning may not change:

- root constitution;
- blocked path classes;
- allowed effect kinds;
- host-authority requirements;
- verification requirements; or
- prohibition of irreversible effects.

Reflection can propose root changes. It cannot self-ratify them.

### 11. Communication authority

The proactive subsystem may emit one bounded scheduler message only after changed-state, threshold, cooldown, cap, and deduplication gates.

Current defaults:

- cooldown: three wakes;
- daily cap: four messages;
- maximum visible message: 700 characters;
- unchanged state: empty stdout.

This is not arbitrary access to email, social media, Telegram, Discord, or another messaging API. External delivery remains a host responsibility.

## CCT authority versus Hermes authority

This distinction is critical.

The CCT native Hermes plugin executes inside Hermes. The surrounding Hermes agent may have ordinary tools—terminal, browser, files, messaging, scheduling—under Hermes configuration, operator instructions, and host approval policy.

CCT 0.7.0 does **not** yet provide a non-bypassable policy mediator over every ordinary Hermes tool call.

Therefore:

- CCT autonomous execution is narrow and receipt-bound;
- Hermes as a whole may still have broader operator-granted tools; and
- installing CCT does not convert Hermes into a sandboxed process.

A future typed capability registry and host mediator can route additional autonomous effects through CCT. That work must not be confused with the current implemented boundary.

## Allowed example

A trusted host adapter observes that `reports/status.md` is absent. It registers:

- exact relative path;
- exact content;
- rationale and objective;
- value impacts;
- precondition `path_absent`;
- exact expected SHA-256; and
- final verification.

CCT compares the opportunity with alternatives and `NO_OP`, selects it, publishes the file atomically, verifies reopened bytes, records the receipt and outcome, then updates capability reliability.

## Rejected examples

CCT 0.7.0 cannot autonomously:

- edit an existing source file;
- create missing parent directories;
- run `pytest`;
- execute a script it created;
- clone a repository;
- call a web API;
- send a message;
- modify a scheduler;
- change Hermes configuration;
- install a model; or
- delete a temporary file.

These actions are rejected because the corresponding effect kinds do not exist—not because the prompt forgot to request permission.

## Why start narrow?

The purpose is measurable earned autonomy.

A narrow initial envelope makes it possible to attribute failures to:

- opportunity selection;
- plan construction;
- authority validation;
- execution;
- verification;
- recovery; or
- learning.

Broad tool access before those layers are proven would hide causal failures and turn authority growth into an unmeasurable binary switch.

The expansion rule is:

> Add one typed capability, with its own authority, budget, verifier, rollback semantics, and tests. Promote throughput only from real receipts.
