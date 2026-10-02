# Private local delivery: evidence boundary

## API

```python
LocalDeliveryDriver(root: Path).run(job_id: str, bundle: dict, *, acceptance: dict) -> dict
```

The bounded artifact bundle remains `{summary, files:[{path,content}], testCommand:'python-unittest'}`. The separate acceptance plan is NOT a bundle field. The orchestrator obtains it with a separate, tool-free `acceptance` model call after saving the bundle, saves it durably, then supplies it to the host driver. No generated code runs on the host.

## Why the v2 receipt is necessary

`cct-local-delivery/v1` could trust a generated module that printed passing unittest JSON and exited before running tests. Its counts are not trustworthy. Version 2 treats that entire generated report as untrusted diagnostics, even if syntactically valid. A successful diagnostic report remains a necessary check, never sufficient verification. The old installed canary and its extra in-process checks do not establish this new host guarantee.

`verification.tests` and both `testCount` fields now mean **host-compared CLI acceptance cases actually passed**, not authored unittest execution. `generatedTestsVerified` is always false. `generatedTestCountClaim` and `generatedTestReport` remain explicitly untrusted. `independentBehavior` must be true before the orchestrator proceeds to review. Model review is also not source-release approval or proof of external facts.

## Declarative acceptance

```json
{"schemaVersion":"cct.cli_acceptance.v1","cases":[
  {"id":"two","argv":["2"],"stdin":"","exitCode":0,"stdout":"4\n"},
  {"id":"negative","argv":["-3"],"stdin":"","exitCode":0,"stdout":"-6\n"}
]}
```

Two to eight cases; at least two distinct successful invocations; non-help nonempty arguments; substantive varying expected output. Exact stdout comparison or `jsonChecks:[{path:["field",0,"nested"],equals:"expected"}]`. JSON comparisons are type-exact, reject duplicate keys/nonfinite constants, and allow bounded primitive expectations (decimal strings rather than floats). At least one common observed output path must vary; reordering checks or checking different constant fields is insufficient.

Limits: 16 arguments, 2000 characters per argument, 8000 bytes each stdin/stdout, 16 JSON checks, eight path components, 64000 bytes per plan. No executable verification code. Plans are normalized and bound into the immutable job claim by SHA-256. A changed plan under the same job ID is rejected; v1 cached receipts do not upgrade themselves to v2.

Each acceptance invocation uses a fresh Bubblewrap sandbox with cwd `/tmp`. Input is supplied as `sys.stdin` and private `cct-input.txt`; file-based CLIs may use `argv:["cct-input.txt"]`. Artifact source remains read-only at `/workspace`. **Only module name, argv and stdin enter generated processes. Expected outputs and comparison logic stay on the host.** Captured process exit/output is compared outside the generated interpreter. The receipt binds case digests, observed output digests and acceptance-plan digest. Replay revalidates recorded comparisons.

These checks prove bounded observed behavior against an oracle, not universal correctness. A separate model-derived oracle can be wrong or incomplete; the final tool-free reviewer must independently assess objective coverage, expected-value correctness and unsupported factual claims. Official numerical or business claims require authoritative independent sources, not this model pipeline.

## Isolation and failure

Networkless Bubblewrap, clean environment, no host home/auth/network sockets, read-only runtime/source mounts, private bounded tmpfs, syscall denial of process/network creation, bounded resources/output. Path traversal, symlinks, hardlinks, unsafe ownership/modes, reserved names, and malformed inputs fail closed. Missing sandbox or missing independent acceptance never succeeds.

Successful artifacts remain immutable. Failed artifacts are quarantined and their path explicitly points into quarantine; it is not a publication path. Interrupted execution never becomes a pass on retry. Changed same-ID bundle/plan is denied. Receipt digests detect corruption, not a hostile same-UID host rewriting all files.

The orchestrator retains completed bundle/execution/review checkpoints across control-read, model or permission failures, with bounded recovery attempts. Concrete artifact failures trigger bounded repair; infrastructure denials do not justify throwing away good work.

## Verification

Run all delivery suites with the profile release interpreter in PATH:

```bash
python3 -m pytest tests/test_owner_delivery.py tests/test_owner_delivery_local.py tests/test_owner_delivery_services.py -v --tb=short
```

Regression tests include the original `os.write`/`os._exit` forgery through real Bubblewrap, correct behavior without false authored-count certification, missing/embedded acceptance denial, changed-plan replay denial, non-leakage of expected outputs, strict JSON type comparison, vacuous-plan rejection, network/host isolation, tampering, interrupted recovery, and quarantine.

Source tests, installed canaries, independent immutable-source review and live owner notification readback are separate gates. Nothing here activates a worker, enables account operations or deploys Firebase.
