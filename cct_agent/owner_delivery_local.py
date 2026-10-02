"""Private, fail-closed execution of bounded Python artifact bundles.

Public API: LocalDeliveryDriver(root: Path).run(job_id: str, bundle: dict) -> dict.
The caller, never the model, chooses an absolute private root. Bundles have exactly
summary, files ({path, content}), and testCommand='python-unittest'. A CLI entry
must be main.py, app.py, cli.py, __main__.py, or a package's __main__.py. Its default
invocation must exit zero and print something useful; --help must also exit zero
and print output. Dependencies are limited to the system Python standard library.

Generated Python is NEVER imported/executed on the host. Every compilation, test,
and CLI invocation uses mandatory bubblewrap isolation. Model-authored tests are
reported separately from host-observed CLI execution and byte-for-byte readback;
passing this gate is NOT proof that an arbitrary natural-language goal is met.
An interrupted job is quarantined and sealed as blocked, not silently replayed.
This is a local artifact driver, not a shell, repository editor, or deployment API.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import struct
import subprocess
import time
import uuid

SCHEMA = "cct-local-delivery/v2"
ACCEPTANCE_SCHEMA = "cct.cli_acceptance.v1"
MAX_FILES = 32
MAX_FILE_BYTES = 64 * 1024
MAX_BUNDLE_BYTES = 256 * 1024
MAX_SUMMARY_BYTES = 4000
MAX_LOG_BYTES = 16 * 1024  # combined stdout/stderr, per sandbox invocation
MAX_RECEIPT_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 15
BWRAP = Path("/usr/bin/bwrap")
PRLIMIT = Path("/usr/bin/prlimit")
PYTHON = Path("/usr/bin/python3")
_JOB = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}\Z", re.ASCII)
_COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_PRIVATE = re.compile(
    r"(?:^|[_.-])(?:config(?:uration)?|credentials?|secrets?|tokens?|passwords?|"
    r"passwd|shadow|auth|oauth|ssh|aws|gcloud|azure|kube|keys?|id_rsa|id_ed25519|"
    r"env|environment)(?:$|[_.-])", re.I,
)
_RESERVED = {
    "setup.py", "conftest.py", "sitecustomize.py", "usercustomize.py",
    "requirements.txt", "pip.conf", "pytest.ini", "tox.ini", "pyproject.toml",
    "manifest.json", "receipt.json", "claim.json",
    "unittest.py", "runpy.py", "json.py", "ast.py", "os.py", "sys.py",
    "signal.py", "resource.py", "subprocess.py", "selectors.py",
}
_ALLOWED_SUFFIXES = {".py", ".md", ".txt", ".csv", ".json"}

# This code is host-owned and supplied with -c, never taken from the bundle. The
# only interpolated value is canonical JSON encoded inside a Python string literal.
_COMPILE = """
import ast, json, pathlib
paths = json.loads(PAYLOAD)
for name in paths:
    source = pathlib.Path('/workspace', name).read_bytes()
    compile(source, name, 'exec', dont_inherit=True)
print(json.dumps({'compiled': len(paths)}))
"""
_TEST = """
import contextlib, importlib.util, io, json, os, sys, unittest
paths = json.loads(PAYLOAD)
sys.path.append('/workspace')
loader = unittest.TestLoader()
suite = unittest.TestSuite()
# Keep model prints out of the machine-readable result channel. This channel is
# diagnostic evidence, not a cryptographic attestation of untrusted assertions.
with contextlib.redirect_stdout(sys.stderr):
    for index, name in enumerate(paths):
        parent = os.path.dirname('/workspace/' + name)
        if parent not in sys.path:
            sys.path.append(parent)
        spec = importlib.util.spec_from_file_location('cct_test_' + str(index), '/workspace/' + name)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        suite.addTests(loader.loadTestsFromModule(module))
    discovered = suite.countTestCases()
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    count = result.testsRun - len(result.skipped)
    passed = (discovered > 0 and result.testsRun == discovered and count > 0
              and result.wasSuccessful() and not result.expectedFailures)
print(json.dumps({'discovered': discovered, 'testsRun': result.testsRun,
                  'testCount': count, 'skipped': len(result.skipped),
                  'failures': len(result.failures), 'errors': len(result.errors),
                  'expectedFailures': len(result.expectedFailures),
                  'unexpectedSuccesses': len(result.unexpectedSuccesses), 'passed': passed}))
sys.exit(0 if passed else 1)
"""
_CLI = """
import json, runpy, sys
module, arguments = json.loads(PAYLOAD)
sys.path.append('/workspace')
sys.argv = [module] + arguments
runpy.run_module(module, run_name='__main__', alter_sys=True)
"""


# Only invocation input enters this process. Expected values and comparison code
# stay on the host; generated imports cannot monkeypatch either or forge results.
_ACCEPT = """
import io, json, os, pathlib, runpy, sys
module, arguments, input_text = json.loads(PAYLOAD)
os.chdir('/tmp')
pathlib.Path('cct-input.txt').write_text(input_text, encoding='utf-8')
sys.stdin = io.StringIO(input_text)
sys.path.append('/workspace')
sys.argv = [module] + arguments
runpy.run_module(module, run_name='__main__', alter_sys=True)
"""


class DeliveryError(ValueError):
    """Stable, non-secret reason code for a denied delivery operation."""


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def validate_acceptance(value):
    """Bound declarative oracles, never executable verification code.

    The separate model/host caller supplies expectations, not the artifact bundle.
    Host comparison proves these cases ran, not that the oracle is infallible.
    """
    if (type(value) is not dict or set(value) != {"schemaVersion", "cases"}
            or value["schemaVersion"] != ACCEPTANCE_SCHEMA
            or type(value["cases"]) is not list or not 2 <= len(value["cases"]) <= 8):
        raise DeliveryError("INDEPENDENT_ACCEPTANCE_REQUIRED")
    if len(_json(value)) > 64000:
        raise DeliveryError("ACCEPTANCE_SIZE_LIMIT")
    ids, inputs, successful_inputs = set(), set(), set()
    varying_expectations = {}
    for case in value["cases"]:
        common = {"id", "argv", "stdin", "exitCode"}
        if type(case) is not dict or set(case) not in (common | {"stdout"}, common | {"jsonChecks"}):
            raise DeliveryError("INVALID_ACCEPTANCE_CASE")
        if (type(case["id"]) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", case["id"])
                or case["id"] in ids or type(case["argv"]) is not list
                or len(case["argv"]) > 16
                or any(type(x) is not str or len(x) > 2000 or "\x00" in x for x in case["argv"])
                or any(x in ("--help", "-h") for x in case["argv"])
                or type(case["stdin"]) is not str or len(case["stdin"].encode()) > 8000
                or (not case["argv"] and not case["stdin"].strip())
                or "\x00" in case["stdin"] or type(case["exitCode"]) is not int
                or not 0 <= case["exitCode"] <= 125):
            raise DeliveryError("INVALID_ACCEPTANCE_CASE")
        if "stdout" in case:
            if (type(case["stdout"]) is not str or len(case["stdout"].encode()) > 8000
                    or (case["exitCode"] == 0 and not case["stdout"].strip())):
                raise DeliveryError("INVALID_ACCEPTANCE_EXPECTATION")
        else:
            checks = case["jsonChecks"]
            if type(checks) is not list or not 1 <= len(checks) <= 16 or case["exitCode"] != 0:
                raise DeliveryError("INVALID_ACCEPTANCE_EXPECTATION")
            seen_paths = set()
            for check in checks:
                if (type(check) is not dict or set(check) != {"path", "equals"}
                        or type(check["path"]) is not list or not 1 <= len(check["path"]) <= 8
                        or any(not ((type(p) is str and 1 <= len(p) <= 120)
                                   or (type(p) is int and 0 <= p <= 100)) for p in check["path"])
                        or type(check["equals"]) not in (str, int, bool, type(None))
                        or len(_json(check["equals"])) > 2000):
                    raise DeliveryError("INVALID_ACCEPTANCE_EXPECTATION")
                path = _json(check["path"])
                if path in seen_paths:
                    raise DeliveryError("DUPLICATE_ACCEPTANCE_PATH")
                seen_paths.add(path)
        invocation = _json([case["argv"], case["stdin"]])
        if invocation in inputs:
            raise DeliveryError("DUPLICATE_ACCEPTANCE_INPUT")
        ids.add(case["id"])
        inputs.add(invocation)
        if case["exitCode"] == 0:
            successful_inputs.add(invocation)
            expectations = [(b"stdout", _json(case["stdout"]))] if "stdout" in case else [
                (_json(["json", c["path"]]), _json(c["equals"])) for c in case["jsonChecks"]]
            for path, expected in expectations:
                varying_expectations.setdefault(path, set()).add(expected)
    if len(successful_inputs) < 2 or not any(len(values) > 1 for values in varying_expectations.values()):
        raise DeliveryError("VACUOUS_ACCEPTANCE_PLAN")
    # Snapshot caller-owned mutable data before any side effect.
    return json.loads(_json(value))


def _matches_case(observed, case):
    if (observed.get("timedOut") or observed.get("outputLimitExceeded") or observed.get("sandboxError")
            or type(observed.get("returnCode")) is not int or observed["returnCode"] != case["exitCode"]):
        return False
    if "stdout" in case:
        return observed["stdout"] == case["stdout"]
    try:
        def unique(pairs):
            result = {}
            for key, val in pairs:
                if key in result:
                    raise ValueError("duplicate output key")
                result[key] = val
            return result
        result = json.loads(observed["stdout"], object_pairs_hook=unique,
                            parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
        for check in case["jsonChecks"]:
            current = result
            for part in check["path"]:
                if not ((type(current) is dict and type(part) is str)
                        or (type(current) is list and type(part) is int)):
                    return False
                current = current[part]
            if type(current) is not type(check["equals"]) or current != check["equals"]:
                return False
        return True
    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        return False


def _validate_bundle(bundle):
    if type(bundle) is not dict or set(bundle) != {"summary", "files", "testCommand"}:
        raise DeliveryError("INVALID_BUNDLE_SCHEMA")
    if bundle["testCommand"] != "python-unittest" or type(bundle["testCommand"]) is not str:
        raise DeliveryError("INVALID_TEST_COMMAND")
    summary = bundle["summary"]
    if type(summary) is not str or not summary.strip() or "\x00" in summary:
        raise DeliveryError("INVALID_SUMMARY")
    if len(summary.encode("utf-8")) > MAX_SUMMARY_BYTES:
        raise DeliveryError("SUMMARY_LIMIT")
    files = bundle["files"]
    if type(files) is not list or not 1 <= len(files) <= MAX_FILES:
        raise DeliveryError("FILE_COUNT_LIMIT")
    normalized, seen, total = [], set(), 0
    for item in files:
        if type(item) is not dict or set(item) != {"path", "content"}:
            raise DeliveryError("INVALID_FILE_SCHEMA")
        name, content = item["path"], item["content"]
        if type(name) is not str or type(content) is not str:
            raise DeliveryError("INVALID_FILE_TYPE")
        parts = name.split("/")
        if (not name or len(name) > 180 or len(parts) > 5
                or any(not _COMPONENT.fullmatch(part) or part in {".", ".."}
                       or part.startswith(".") or _PRIVATE.search(part) for part in parts)
                or any(part.lower() in _RESERVED for part in parts)
                or PurePosixPath(name).suffix.lower() not in _ALLOWED_SUFFIXES):
            raise DeliveryError("UNSAFE_ARTIFACT_PATH")
        # Case-fold collision checks make export to case-insensitive hosts safe.
        folded = name.casefold()
        if folded in seen:
            raise DeliveryError("DUPLICATE_ARTIFACT_PATH")
        seen.add(folded)
        data = content.encode("utf-8")
        if b"\x00" in data or len(data) > MAX_FILE_BYTES:
            raise DeliveryError("FILE_BYTES_LIMIT")
        total += len(data)
        if total > MAX_BUNDLE_BYTES:
            raise DeliveryError("BUNDLE_BYTES_LIMIT")
        normalized.append({"path": name, "content": content})
    for name in seen:
        if any(name.startswith(other + "/") for other in seen):
            raise DeliveryError("FILE_DIRECTORY_COLLISION")
    normalized.sort(key=lambda item: item["path"])
    value = {"summary": summary, "files": normalized, "testCommand": "python-unittest"}
    manifest = [{"path": item["path"], "bytes": len(item["content"].encode("utf-8")),
                 "sha256": sha256(item["content"].encode("utf-8")).hexdigest()}
                for item in normalized]
    return value, sha256(_json(value)).hexdigest(), manifest


def _entry(files):
    names = {item["path"] for item in files}
    for name in ("main.py", "app.py", "cli.py", "__main__.py"):
        if name in names:
            return name[:-3]
    for name in sorted(names):
        if name.endswith("/__main__.py"):
            parts = name.split("/")[:-1]
            if all(part.isidentifier() for part in parts) and all(
                "/".join(parts[:i]) + "/__init__.py" in names for i in range(1, len(parts) + 1)
            ):
                return ".".join(parts)
    raise DeliveryError("CLI_ENTRY_MISSING")


def _checked_dir(fd, *, private=True):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise DeliveryError("UNSAFE_DIRECTORY")
    if private and info.st_mode & 0o077:
        raise DeliveryError("DIRECTORY_NOT_PRIVATE")


def _open_dir(parent_fd, name, *, create=False, private=True):
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        _checked_dir(fd, private=private)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read(fd, name, limit):
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        before = os.fstat(handle)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid() or before.st_size > limit
                or before.st_mode & 0o222):
            raise DeliveryError("UNSAFE_FILE_READBACK")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(handle, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(handle)
        if (len(data) > limit or len(data) != before.st_size
                or (before.st_ino, before.st_dev, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_ino, after.st_dev, after.st_mtime_ns, after.st_ctime_ns)
                or after.st_nlink != 1):
            raise DeliveryError("READBACK_CHANGED_DURING_READ")
        return bytes(data)
    finally:
        os.close(handle)


def _atomic_json(fd, name, value):
    """Create, never replace, a durable immutable control record."""
    temporary = ".receipt-" + uuid.uuid4().hex
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=fd)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(_json(value))
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
        # link+unlink gives atomic no-clobber publication. The final file has one
        # link; a crash between these calls fails closed on subsequent readback.
        os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.unlink(temporary, dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


def _exists(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _host_binary(path):
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if (not resolved.is_relative_to("/usr") or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111):
        raise DeliveryError("UNTRUSTED_SANDBOX_BINARY")
    return resolved


class LocalDeliveryDriver:
    """One immutable attempt per job ID; same-ID retries independently read back.

    run() returns a JSON-serializable receipt, including on ordinary validation,
    integrity, sandbox, and execution failure. Constructor errors are ValueError
    or OSError because an unsafe root must never become an operational driver.
    The instance holds no open descriptors between calls and needs no close().
    """

    def __init__(self, root: Path):
        root = Path(root)
        if not root.is_absolute() or ".." in root.parts or root == Path("/"):
            raise DeliveryError("ROOT_MUST_BE_FIXED_ABSOLUTE_DIRECTORY")
        # Walk from / using directory descriptors. Never resolve through a link,
        # even in an ancestor, and never chmod an existing caller-owned directory.
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in root.parts[1:]:
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                except FileNotFoundError:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            _checked_dir(fd)
            info = os.fstat(fd)
            self._identity = (info.st_dev, info.st_ino)
        finally:
            os.close(fd)
        self.root = root

    @contextmanager
    def _root(self):
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in self.root.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            _checked_dir(fd)
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self._identity:
                raise DeliveryError("ROOT_IDENTITY_CHANGED")
            yield fd
        finally:
            os.close(fd)

    def run(self, job_id: str, bundle: dict, *, acceptance=None) -> dict:
        digest, manifest = None, []
        try:
            if type(job_id) is not str or not _JOB.fullmatch(job_id):
                raise DeliveryError("INVALID_JOB_ID")
            bundle, digest, manifest = _validate_bundle(bundle)
            acceptance = validate_acceptance(acceptance)
            with self._root() as root_fd:
                lock = os.open("driver.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                               0o600, dir_fd=root_fd)
                try:
                    info = os.fstat(lock)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or info.st_uid != os.geteuid() or info.st_mode & 0o077):
                        raise DeliveryError("UNSAFE_LOCK")
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        raise DeliveryError("DRIVER_BUSY") from None
                    return self._run_locked(root_fd, job_id, bundle, digest, manifest, acceptance)
                finally:
                    os.close(lock)
        except (DeliveryError, UnicodeError, OSError, ValueError, TypeError) as exc:
            reason = str(exc) if isinstance(exc, DeliveryError) else "LOCAL_IO_OR_STATE_ERROR"
            return self._receipt(job_id if type(job_id) is str and _JOB.fullmatch(job_id) else None,
                                 digest, manifest, reason=reason)

    def _receipt(self, job_id, digest, manifest, *, reason, artifact_root=None, verification=None, logs=None):
        verification = verification or {
            "status": "blocked", "compile": False, "tests": False, "testCount": 0,
            "readback": False, "cli": False, "semanticCompletion": False,
            "independentBehavior": False, "generatedTestsVerified": False,
            "testEvidence": "Host-compared acceptance cases; model-authored test reports are UNTRUSTED. Oracle quality requires separate review.",
        }
        receipt = {"schemaVersion": SCHEMA, "jobId": job_id, "bundleDigest": digest,
                "status": "completed" if verification["status"] == "passed" else "blocked",
                "artifactRoot": str(artifact_root) if artifact_root else None,
                "manifest": manifest, "verification": verification,
                "testCount": verification["testCount"], "logs": logs or [], "reason": reason,
                "sandbox": "bubblewrap-no-network", "private": True}
        # Corruption/tamper detection, not authentication against the host owner:
        # a same-UID writer can replace both the receipt and this commitment.
        receipt["receiptDigest"] = sha256(_json(receipt)).hexdigest()
        return receipt

    def _run_locked(self, root_fd, job_id, bundle, digest, manifest, acceptance):
        acceptance_digest = sha256(_json(acceptance)).hexdigest()
        identity = {"schemaVersion": SCHEMA, "jobId": job_id, "bundleDigest": digest,
                    "acceptanceDigest": acceptance_digest}
        jobs = _open_dir(root_fd, "jobs", create=True)
        quarantine = None
        job = None
        try:
            quarantine = _open_dir(root_fd, "quarantine", create=True)
            key = sha256(job_id.encode("utf-8")).hexdigest()
            fresh = not _exists(jobs, key)
            job = _open_dir(jobs, key, create=True)
            if not fresh:
                if not _exists(job, "claim.json"):
                    # A durable mkdir may precede the initial claim at a crash.
                    # Seal that orphan as interrupted; never execute it on retry.
                    if _exists(job, "receipt.json"):
                        raise DeliveryError("CLAIM_MISSING")
                    _atomic_json(job, "claim.json", identity)
                claim = json.loads(_read(job, "claim.json", MAX_RECEIPT_BYTES))
                if claim != identity:
                    raise DeliveryError("JOB_ID_BUNDLE_MISMATCH")
                if _exists(job, "receipt.json"):
                    receipt = json.loads(_read(job, "receipt.json", MAX_RECEIPT_BYTES))
                    self._verify_cached(job, quarantine, key, job_id, digest, manifest, receipt, acceptance)
                    return receipt
                # A crash never means success, and never authorizes a second run.
                artifact_root = self._quarantine(job, quarantine, key)
                receipt = self._receipt(job_id, digest, manifest, reason="INTERRUPTED_ATTEMPT",
                                        artifact_root=artifact_root)
                _atomic_json(job, "receipt.json", receipt)
                return json.loads(_read(job, "receipt.json", MAX_RECEIPT_BYTES))
            _atomic_json(job, "claim.json", identity)
            attempt = None
            artifacts = None
            logs = []
            verification = self._receipt(job_id, digest, manifest, reason="")["verification"]
            reason = "LOCAL_EXECUTION_FAILED"
            try:
                os.mkdir("attempt-0001", 0o700, dir_fd=job)
                os.fsync(job)
                attempt = _open_dir(job, "attempt-0001")
                os.mkdir("artifacts", 0o700, dir_fd=attempt)
                artifacts = _open_dir(attempt, "artifacts")
                self._materialize(artifacts, bundle["files"])
                self._readback(artifacts, manifest)
                verification["readback"] = True
                entry = _entry(bundle["files"])
                pyfiles = [item["path"] for item in manifest if item["path"].endswith(".py")]
                tests = [name for name in pyfiles if PurePosixPath(name).name.startswith("test_")]
                if not tests:
                    raise DeliveryError("ZERO_TESTS")
                compiled = self._sandbox(artifacts, _COMPILE, pyfiles, "compile")
                logs.append(compiled)
                if not self._ok(compiled) or self._result(compiled) != {"compiled": len(pyfiles)}:
                    raise DeliveryError(self._execution_reason(compiled, "COMPILE_FAILED"))
                verification["compile"] = True
                tested = self._sandbox(artifacts, _TEST, tests, "unittest")
                logs.append(tested)
                result = self._result(tested)
                count = result.get("testCount", 0) if isinstance(result, dict) else 0
                verification["generatedTestCountClaim"] = count if type(count) is int and 0 <= count <= 10000 else 0
                verification["generatedTestReport"] = result if isinstance(result, dict) else {}
                if not self._valid_test_result(tested, result):
                    failed = "ZERO_TESTS" if verification["generatedTestCountClaim"] == 0 else "TESTS_FAILED"
                    raise DeliveryError(self._execution_reason(tested, failed))
                # A syntactically valid self-report is only a diagnostic gate.
                # Never set tests/testCount from code running in this process.
                # Separate processes: tests cannot monkeypatch or manufacture this
                # host-observed exit status/output, or mutate read-only source.
                cli_evidence = []
                for label, args in (("cli-default", []), ("cli-help", ["--help"])):
                    observed = self._sandbox(artifacts, _CLI, [entry, args], label)
                    logs.append(observed)
                    if not self._ok(observed) or not observed["stdout"].strip():
                        raise DeliveryError(self._execution_reason(observed, "CLI_BEHAVIOR_FAILED"))
                    cli_evidence.append({"module": entry, "arguments": args,
                                         "returnCode": observed["returnCode"],
                                         "stdoutSha256": observed["stdoutSha256"],
                                         "stdoutBytes": observed["stdoutBytes"]})
                verification["cli"] = True
                verification["behavioralEvidence"] = cli_evidence
                verification["acceptanceDigest"] = acceptance_digest
                verification["acceptanceEvidence"] = []
                for case in acceptance["cases"]:
                    observed = self._sandbox(artifacts, _ACCEPT,
                                             [entry, case["argv"], case["stdin"]], "acceptance-" + case["id"])
                    logs.append(observed)
                    passed = _matches_case(observed, case)
                    verification["acceptanceEvidence"].append({
                        "id": case["id"], "passed": passed,
                        "caseDigest": sha256(_json(case)).hexdigest(),
                        "returnCode": observed["returnCode"], "stdoutSha256": observed["stdoutSha256"]})
                    if not passed:
                        raise DeliveryError(self._execution_reason(observed, "INDEPENDENT_BEHAVIOR_FAILED"))
                    verification["testCount"] += 1
                verification["tests"] = True
                verification["independentBehavior"] = True
                self._readback(artifacts, manifest)
                verification["status"] = "passed"
                reason = "VERIFIED_LOCAL_ARTIFACT"
            except (DeliveryError, OSError, ValueError, TypeError) as exc:
                reason = str(exc) if isinstance(exc, DeliveryError) else "LOCAL_IO_OR_STATE_ERROR"
            finally:
                if artifacts is not None:
                    os.close(artifacts)
                if attempt is not None:
                    os.close(attempt)
            if verification["status"] == "passed":
                artifact_root = self.root / "jobs" / key / "attempt-0001" / "artifacts"
            else:
                artifact_root = self._quarantine(job, quarantine, key)
            receipt = self._receipt(job_id, digest, manifest, reason=reason,
                                    artifact_root=artifact_root, verification=verification, logs=logs)
            _atomic_json(job, "receipt.json", receipt)
            actual = json.loads(_read(job, "receipt.json", MAX_RECEIPT_BYTES))
            if actual != receipt:
                raise DeliveryError("RECEIPT_READBACK_MISMATCH")
            self._verify_cached(job, quarantine, key, job_id, digest, manifest, actual, acceptance)
            return actual
        finally:
            if job is not None:
                os.close(job)
            if quarantine is not None:
                os.close(quarantine)
            os.close(jobs)

    def _quarantine(self, job, quarantine, key):
        if _exists(job, "attempt-0001"):
            if _exists(quarantine, key):
                raise DeliveryError("QUARANTINE_COLLISION")
            # Do not follow an injected link or move anything outside our own job.
            attempt = _open_dir(job, "attempt-0001")
            os.close(attempt)
            os.rename("attempt-0001", key, src_dir_fd=job, dst_dir_fd=quarantine)
            os.fsync(job)
            os.fsync(quarantine)
        if _exists(quarantine, key):
            return self._quarantined_root(quarantine, key)
        return None

    def _quarantined_root(self, quarantine, key):
        attempt = _open_dir(quarantine, key)
        try:
            if not _exists(attempt, "artifacts"):
                return None  # Interrupted before artifact-directory creation.
            artifacts = _open_dir(attempt, "artifacts", private=False)
            os.close(artifacts)
            return self.root / "quarantine" / key / "artifacts"
        finally:
            os.close(attempt)

    def _verify_cached(self, job, quarantine, key, job_id, digest, manifest, receipt, acceptance):
        if not isinstance(receipt, dict):
            raise DeliveryError("RECEIPT_IDENTITY_MISMATCH")
        committed = {k: v for k, v in receipt.items() if k != "receiptDigest"}
        if receipt.get("receiptDigest") != sha256(_json(committed)).hexdigest():
            raise DeliveryError("RECEIPT_DIGEST_MISMATCH")
        if (not isinstance(receipt, dict) or receipt.get("schemaVersion") != SCHEMA
                or receipt.get("jobId") != job_id or receipt.get("bundleDigest") != digest
                or receipt.get("manifest") != manifest
                or receipt.get("status") not in {"completed", "blocked"}):
            raise DeliveryError("RECEIPT_IDENTITY_MISMATCH")
        complete = receipt["status"] == "completed"
        expected = (self.root / "jobs" / key / "attempt-0001" / "artifacts" if complete
                    else self.root / "quarantine" / key / "artifacts")
        if receipt.get("artifactRoot") is not None and receipt["artifactRoot"] != str(expected):
            raise DeliveryError("RECEIPT_ROOT_MISMATCH")
        verification = receipt.get("verification", {})
        if (not isinstance(verification, dict) or receipt.get("private") is not True
                or receipt.get("sandbox") != "bubblewrap-no-network"
                or verification.get("semanticCompletion") is not False
                or type(receipt.get("testCount")) is not int
                or receipt["testCount"] != verification.get("testCount")):
            raise DeliveryError("RECEIPT_VERIFICATION_MISMATCH")
        if not complete:
            if verification.get("status") != "blocked":
                raise DeliveryError("RECEIPT_VERIFICATION_MISMATCH")
            actual = self._quarantined_root(quarantine, key) if _exists(quarantine, key) else None
            if receipt.get("artifactRoot") != (str(actual) if actual else None):
                raise DeliveryError("RECEIPT_ROOT_MISMATCH")
            return  # A partial quarantined attempt is never claimed to be verified.
        if (receipt.get("artifactRoot") is None or verification.get("status") != "passed"
                or any(verification.get(name) is not True for name in ("compile", "tests", "cli", "readback"))
                or type(receipt.get("testCount")) is not int or receipt["testCount"] <= 0
                or receipt["testCount"] != verification.get("testCount")):
            raise DeliveryError("RECEIPT_VERIFICATION_MISMATCH")
        expected_cases = acceptance["cases"]
        evidence = verification.get("acceptanceEvidence")
        if (verification.get("independentBehavior") is not True
                or verification.get("generatedTestsVerified") is not False
                or verification.get("acceptanceDigest") != sha256(_json(acceptance)).hexdigest()
                or receipt["testCount"] != len(expected_cases)
                or type(evidence) is not list or len(evidence) != len(expected_cases)):
            raise DeliveryError("RECEIPT_ACCEPTANCE_MISMATCH")
        logs = receipt.get("logs", [])
        for case, item in zip(expected_cases, evidence):
            stage_logs = [log for log in logs if log.get("stage") == "acceptance-" + case["id"]]
            if (len(stage_logs) != 1 or not _matches_case(stage_logs[0], case)
                    or item != {"id": case["id"], "passed": True,
                                "caseDigest": sha256(_json(case)).hexdigest(),
                                "returnCode": stage_logs[0]["returnCode"],
                                "stdoutSha256": stage_logs[0]["stdoutSha256"]}
                    or sha256(stage_logs[0]["stdout"].encode()).hexdigest() != item["stdoutSha256"]):
                raise DeliveryError("RECEIPT_ACCEPTANCE_MISMATCH")
        attempt = _open_dir(job, "attempt-0001")
        try:
            artifact = _open_dir(attempt, "artifacts", private=False)
            try:
                self._readback(artifact, manifest)
            finally:
                os.close(artifact)
        finally:
            os.close(attempt)

    @staticmethod
    def _materialize(root, files):
        for item in files:
            parts = item["path"].split("/")
            parent = os.dup(root)
            try:
                for component in parts[:-1]:
                    child = _open_dir(parent, component, create=True)
                    os.close(parent)
                    parent = child
                fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(item["content"].encode("utf-8"))
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o444)
                    os.fsync(stream.fileno())
                os.fsync(parent)
            finally:
                os.close(parent)
        def freeze(fd):
            for name in os.listdir(fd):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = _open_dir(fd, name)
                    try:
                        freeze(child)
                    finally:
                        os.close(child)
            os.fchmod(fd, 0o555)
            os.fsync(fd)
        freeze(root)

    @staticmethod
    def _readback(root, manifest):
        actual = []
        expected_directories = {""}
        for item in manifest:
            parts = item["path"].split("/")
            expected_directories.update("/".join(parts[:i]) for i in range(1, len(parts)))
        def visit(fd, prefix=""):
            if len(actual) > MAX_FILES:
                raise DeliveryError("READBACK_FILE_LIMIT")
            names = os.listdir(fd)
            if len(names) > MAX_FILES:
                raise DeliveryError("READBACK_ENTRY_LIMIT")
            for name in sorted(names):
                relative = prefix + name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if relative not in expected_directories or info.st_mode & 0o222:
                        raise DeliveryError("READBACK_DIRECTORY_MISMATCH")
                    child = _open_dir(fd, name, private=False)
                    try:
                        if os.fstat(child).st_mode & 0o222:
                            raise DeliveryError("READBACK_DIRECTORY_MISMATCH")
                        visit(child, relative + "/")
                    finally:
                        os.close(child)
                else:
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o222:
                        raise DeliveryError("READBACK_UNSAFE_FILE")
                    data = _read(fd, name, MAX_FILE_BYTES)
                    actual.append({"path": relative, "bytes": len(data), "sha256": sha256(data).hexdigest()})
        if os.fstat(root).st_mode & 0o222:
            raise DeliveryError("READBACK_WRITABLE_ROOT")
        visit(root)
        if sorted(actual, key=lambda item: item["path"]) != manifest:
            raise DeliveryError("READBACK_MANIFEST_MISMATCH")

    @staticmethod
    def _result(execution):
        try:
            return json.loads(execution["stdout"])
        except (ValueError, TypeError, KeyError):
            return None

    @staticmethod
    def _ok(execution):
        return (execution["returnCode"] == 0 and not execution["timedOut"]
                and not execution["outputLimitExceeded"] and not execution.get("sandboxError"))

    @classmethod
    def _valid_test_result(cls, execution, result):
        fields = {"discovered", "testsRun", "testCount", "skipped", "failures", "errors",
                  "expectedFailures", "unexpectedSuccesses", "passed"}
        return (cls._ok(execution) and type(result) is dict and set(result) == fields
                and all(type(result[k]) is int and 0 <= result[k] <= 10000 for k in fields - {"passed"})
                and result["passed"] is True and result["testCount"] > 0
                and result["discovered"] == result["testsRun"]
                and result["testsRun"] == result["testCount"] + result["skipped"]
                and all(result[k] == 0 for k in ("failures", "errors", "expectedFailures", "unexpectedSuccesses")))

    @staticmethod
    def _execution_reason(execution, default):
        if execution.get("sandboxError"):
            return "SANDBOX_UNAVAILABLE"
        if execution["timedOut"]:
            return "EXECUTION_TIMEOUT"
        if execution["outputLimitExceeded"]:
            return "EXECUTION_OUTPUT_LIMIT"
        return default

    def _sandbox(self, artifact_fd, program, payload, stage):
        """Fixed argv only, no shell, no inherited environment or auth mounts."""
        seccomp_fd = None
        try:
            bwrap, prlimit, python = (_host_binary(p) for p in (BWRAP, PRLIMIT, PYTHON))
            if not python.name.startswith("python3"):
                raise DeliveryError("UNTRUSTED_PYTHON")
            seccomp_fd = self._seccomp()
            command = [str(prlimit), "--cpu=8:8", "--as=536870912:536870912",
                       "--fsize=8388608:8388608", "--nofile=64:64", "--core=0:0", "--",
                       str(bwrap), "--unshare-all", "--unshare-user", "--unshare-pid", "--unshare-net",
                       "--disable-userns", "--assert-userns-disabled", "--new-session", "--die-with-parent",
                       "--hostname", "cct-local",
                       "--uid", "65534", "--gid", "65534", "--cap-drop", "ALL", "--clearenv",
                       "--dir", "/usr", "--dir", "/usr/bin", "--ro-bind", str(python), str(python)]
            # No /usr/local, /etc, /home, host /tmp, procfs, runtime sockets, or
            # credentials. Only system libraries and the interpreter are exposed.
            for source in ("/usr/lib", "/usr/lib64"):
                if Path(source).is_dir():
                    command += ["--ro-bind", source, source]
            command += ["--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib"]
            if Path("/usr/lib64").is_dir():
                command += ["--symlink", "usr/lib64", "/lib64"]
            command += ["--size", "16777216", "--tmpfs", "/tmp", "--dir", "/dev",
                        "--dev-bind", "/dev/null", "/dev/null", "--dev-bind", "/dev/urandom", "/dev/urandom",
                        "--ro-bind-fd", str(artifact_fd), "/workspace", "--chdir", "/workspace",
                        "--seccomp", str(seccomp_fd),
                        "--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp",
                        "--setenv", "LANG", "C.UTF-8", "--setenv", "PATH", "/usr/bin",
                        "--remount-ro", "/", "--", str(python), "-I", "-S", "-B", "-c",
                        # Explicitly close every inherited descriptor before any
                        # generated import, including the original writable-mount
                        # directory FD used by --ro-bind-fd during sandbox setup.
                        "import os; os.closerange(3, " + str(max(256, artifact_fd + 1, seccomp_fd + 1)) + ")\n"
                        + program.replace("PAYLOAD", repr(_json(payload).decode("utf-8")), 1)]
            return self._capture(command, (artifact_fd, seccomp_fd), stage)
        except (DeliveryError, OSError) as exc:
            return {"stage": stage, "returnCode": None, "timedOut": False, "outputLimitExceeded": False,
                    "stdout": "", "stderr": "", "stdoutBytes": 0, "stderrBytes": 0,
                    "stdoutSha256": sha256(b"").hexdigest(),
                    "sandboxError": str(exc) if isinstance(exc, DeliveryError) else type(exc).__name__}
        finally:
            if seccomp_fd is not None:
                os.close(seccomp_fd)

    @staticmethod
    def _seccomp():
        """Deny new processes/threads and high-risk kernel APIs after setup.

        RLIMIT_NPROC is per real UID on Linux, not per namespace; a small limit
        can prevent bwrap setup on a busy host. Do not apply it here. Seccomp
        prevents fork/clone bombs
        altogether. Generated code using threads/subprocess is unsupported.
        Only the reviewed x86-64 syscall table is supported; other hosts deny.
        """
        if os.uname().machine != "x86_64" or not hasattr(os, "memfd_create"):
            raise DeliveryError("SECCOMP_PLATFORM_UNSUPPORTED")
        # Classic BPF: validate AUDIT_ARCH_X86_64, kill x32/foreign ABI attempts,
        # return EPERM for denied calls, allow remaining standard-library calls.
        rules = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xC000003E), (0x06, 0, 0, 0x80000000),
                 (0x20, 0, 0, 0), (0x35, 0, 1, 0x40000000), (0x06, 0, 0, 0x80000000)]
        denied = (41, 42, 43, 49, 50, 53, 56, 57, 58, 101, 155, 165, 166,
                  175, 176, 246, 248, 249, 250, 272, 298, 303, 304, 308,
                  310, 311, 313, 321, 323, 425, 426, 427, 435, 438)
        for number in denied:
            rules.extend(((0x15, 0, 1, number), (0x06, 0, 0, 0x00050001)))
        rules.append((0x06, 0, 0, 0x7FFF0000))
        fd = os.memfd_create("cct-seccomp", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            data = b"".join(struct.pack("HBBI", *rule) for rule in rules)
            if os.write(fd, data) != len(data):
                raise DeliveryError("SECCOMP_WRITE_FAILED")
            os.lseek(fd, 0, os.SEEK_SET)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _capture(command, passed_fds, stage):
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env={}, cwd="/", shell=False,
                                   close_fds=True, pass_fds=passed_fds, start_new_session=True)
        assert process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        logs = {"stdout": bytearray(), "stderr": bytearray()}
        sizes = {"stdout": 0, "stderr": 0}
        hashes = {"stdout": sha256(), "stderr": sha256()}
        timed_out = exceeded = False
        killed = False
        deadline = time.monotonic() + TIMEOUT_SECONDS
        def kill():
            nonlocal killed
            if not killed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                killed = True
        try:
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    timed_out = True
                    kill()
                    break
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    name = key.data
                    sizes[name] += len(chunk)
                    hashes[name].update(chunk)
                    remaining = MAX_LOG_BYTES - sum(len(value) for value in logs.values())
                    logs[name].extend(chunk[:max(0, remaining)])
                    if sum(sizes.values()) > MAX_LOG_BYTES:
                        exceeded = True
                        kill()
                if killed:
                    break
            try:
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                kill()
                process.wait(timeout=3)
        finally:
            if process.poll() is None:
                kill()
                process.wait(timeout=3)
            selector.close()
            process.stdout.close()
            process.stderr.close()
        stderr = bytes(logs["stderr"]).decode("utf-8", "replace")
        return {"stage": stage, "returnCode": process.returncode, "timedOut": timed_out,
                "outputLimitExceeded": exceeded, "stdout": bytes(logs["stdout"]).decode("utf-8", "replace"),
                "stderr": stderr, "stdoutBytes": sizes["stdout"], "stderrBytes": sizes["stderr"],
                "stdoutSha256": hashes["stdout"].hexdigest(),
                "sandboxError": "setup-failed" if stderr.startswith(("bwrap:", "prlimit:")) else None}
