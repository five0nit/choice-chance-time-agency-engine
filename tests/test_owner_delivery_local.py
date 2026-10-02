"""Local-only driver contracts, including real Linux bubblewrap executions.

Run all tests with /usr/bin/python3 -m unittest discover -s tests
-p test_owner_delivery_local.py -v. No generated Python executes in this process.
The actual sandbox tests skip on interpreters lacking Linux memfd/seal support;
a supported interpreter with unavailable bubblewrap FAILS rather than skips.
"""

from __future__ import annotations

import copy
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch

import cct_agent.owner_delivery_local as local


MAIN = """import argparse

def double(value):
    return value * 2

def main():
    parser = argparse.ArgumentParser(description='Double an integer')
    parser.add_argument('value', type=int, nargs='?', default=21)
    args = parser.parse_args()
    print(double(args.value))

if __name__ == '__main__':
    main()
"""
TESTS = """import unittest
from main import double
class DoubleTests(unittest.TestCase):
    def test_positive(self): self.assertEqual(double(21), 42)
    def test_negative(self): self.assertEqual(double(-3), -6)
"""
CAN_SANDBOX = all(
    hasattr(os, name) for name in ("memfd_create", "MFD_ALLOW_SEALING")
) and hasattr(fcntl, "F_ADD_SEALS")


def bundle(main=MAIN, tests=TESTS, extra=()):
    return {
        "summary": "Private integer doubling CLI",
        "testCommand": "python-unittest",
        "files": [
            {"path": path, "content": content}
            for path, content in [("main.py", main), ("test_main.py", tests), *extra]
        ],
    }


def acceptance_plan():
    return {
        "schemaVersion": local.ACCEPTANCE_SCHEMA,
        "cases": [
            {
                "id": "positive",
                "argv": ["2"],
                "stdin": "",
                "exitCode": 0,
                "stdout": "4\n",
            },
            {
                "id": "negative",
                "argv": ["-3"],
                "stdin": "",
                "exitCode": 0,
                "stdout": "-6\n",
            },
            {
                "id": "invalid",
                "argv": ["not-an-integer"],
                "stdin": "",
                "exitCode": 2,
                "stdout": "",
            },
        ],
    }


class TestDriver(local.LocalDeliveryDriver):
    __test__ = False

    def run(self, job_id, value, *, acceptance=None):
        return super().run(
            job_id,
            value,
            acceptance=acceptance_plan() if acceptance is None else acceptance,
        )


def job_path(driver, job_id):
    return driver.root / "jobs" / sha256(job_id.encode()).hexdigest()


def replace_readonly(path, data):
    path.chmod(0o600)
    path.write_bytes(data)
    path.chmod(0o400)


class Fixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cct-local-tests-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.driver = TestDriver(self.base / "delivery")

    def blocked(self, receipt, reason=None):
        self.assertEqual(receipt["status"], "blocked", receipt)
        self.assertFalse(receipt["verification"]["semanticCompletion"])
        if reason is not None:
            self.assertEqual(receipt["reason"], reason, receipt)
        return receipt

    def completed(self, job="success", value=None):
        receipt = self.driver.run(job, bundle() if value is None else value)
        self.assertEqual(receipt["status"], "completed", receipt)
        return receipt

    def interrupted(self, job="interrupted"):
        with patch.object(self.driver, "_sandbox", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.driver.run(job, bundle())
        return job_path(self.driver, job)


class ValidationTests(Fixture):
    def test_exact_bundle_and_file_schemas(self):
        mutations = [
            lambda b: b.update(extra=True),
            lambda b: b.pop("summary"),
            lambda b: b["files"][0].update(mode="executable"),
            lambda b: b.update(files=()),
            lambda b: b.update(files=[]),
            lambda b: b.update(summary=" "),
            lambda b: b.update(summary="\x00"),
            lambda b: b.update(testCommand="python -m unittest"),
            lambda b: b["files"][0].update(content=123),
        ]
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not execute")
        ):
            for mutate in mutations:
                value = bundle()
                mutate(value)
                with self.subTest(value=value):
                    self.blocked(self.driver.run("invalid", value))
        self.assertFalse((self.driver.root / "jobs").exists())

    def test_unsafe_paths_are_denied_before_any_execution(self):
        paths = [
            "../outside.py",
            "/tmp/outside.py",
            "a/../outside.py",
            "./main.py",
            "a//b.py",
            "a\\b.py",
            "a:b.py",
            ".hidden.py",
            "a/.hidden/b.py",
            "config.json",
            "client-secrets.json",
            "auth/token.txt",
            "environment.py",
            "setup.py",
            "conftest.py",
            "sitecustomize.py",
            "os.py",
            "a/receipt.json",
            "main.sh",
            "main.py\x00",
            "main.py\n",
            "a/b/c/d/e/f.py",
            "é.py",
        ]
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not execute")
        ):
            for name in paths:
                with self.subTest(path=name):
                    self.blocked(
                        self.driver.run("bad-path", bundle(extra=[(name, "inert")])),
                        "UNSAFE_ARTIFACT_PATH",
                    )
        self.assertFalse((self.driver.root / "jobs").exists())

    def test_job_ids_are_literal_and_bounded(self):
        for job in (
            "../escape",
            "/tmp/escape",
            "job\n",
            "x" * 97,
            "",
            "é",
            None,
            3,
            True,
        ):
            with self.subTest(job=job):
                receipt = self.blocked(self.driver.run(job, bundle()), "INVALID_JOB_ID")
                self.assertIsNone(receipt["jobId"])
        self.assertFalse((self.driver.root / "jobs").exists())

    def test_case_and_file_directory_collisions(self):
        for extra, reason in [
            ([("MAIN.py", "x")], "DUPLICATE_ARTIFACT_PATH"),
            ([("main.py/child.py", "x")], "FILE_DIRECTORY_COLLISION"),
        ]:
            with self.subTest(reason=reason):
                self.blocked(self.driver.run("collision", bundle(extra=extra)), reason)

    def test_byte_count_and_summary_caps(self):
        values = []
        value = bundle()
        value["summary"] = "é" * (local.MAX_SUMMARY_BYTES // 2 + 1)
        values.append((value, "SUMMARY_LIMIT"))
        values.append(
            (
                bundle(extra=[("big.txt", "é" * (local.MAX_FILE_BYTES // 2 + 1))]),
                "FILE_BYTES_LIMIT",
            )
        )
        values.append((bundle(extra=[("nul.txt", "\x00")]), "FILE_BYTES_LIMIT"))
        values.append(
            (
                bundle(
                    extra=[
                        (f"blob{i}.txt", "x" * local.MAX_FILE_BYTES) for i in range(4)
                    ]
                ),
                "BUNDLE_BYTES_LIMIT",
            )
        )
        values.append(
            (
                bundle(extra=[(f"file{i}.txt", "x") for i in range(local.MAX_FILES)]),
                "FILE_COUNT_LIMIT",
            )
        )
        for value, reason in values:
            with self.subTest(reason=reason):
                self.blocked(self.driver.run("limit", value), reason)

    def test_bundle_order_does_not_change_digest(self):
        first = bundle()
        second = copy.deepcopy(first)
        second["files"].reverse()
        self.assertEqual(local._validate_bundle(first), local._validate_bundle(second))

    def test_cli_entry_is_required_without_host_execution(self):
        value = bundle()
        value["files"][0]["path"] = "library.py"
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not execute")
        ):
            self.blocked(self.driver.run("library-only", value), "CLI_ENTRY_MISSING")

    def test_missing_tests_is_blocked_without_host_execution(self):
        value = bundle()
        value["files"].pop()
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not execute")
        ):
            self.blocked(self.driver.run("missing-tests", value), "ZERO_TESTS")

    def test_constructor_rejects_unsafe_roots_without_chmod(self):
        for root in (Path("relative"), Path("/"), self.base / ".." / "escape"):
            with self.subTest(root=root), self.assertRaises(local.DeliveryError):
                local.LocalDeliveryDriver(root)
        for mode in (0o755, 0o750, 0o770, 0o707, 0o777):
            with self.subTest(mode=oct(mode)):
                public = self.base / f"public-{mode:o}"
                public.mkdir(mode=0o700)
                # Test setup must not inherit a restrictive worker umask. Only
                # this private temporary fixture is chmod'ed, never live roots.
                public.chmod(mode)
                self.assertEqual(public.stat().st_mode & 0o777, mode)
                with self.assertRaises(local.DeliveryError):
                    local.LocalDeliveryDriver(public)
                self.assertEqual(public.stat().st_mode & 0o777, mode)
        link = self.base / "alias"
        link.symlink_to(self.driver.root, target_is_directory=True)
        with self.assertRaises(OSError):
            local.LocalDeliveryDriver(link / "child")
        self.assertFalse((self.driver.root / "child").exists())

    def test_root_replacement_and_symlink_fail_closed(self):
        original = self.base / "original"
        self.driver.root.rename(original)
        self.driver.root.mkdir(mode=0o700)
        self.blocked(self.driver.run("replaced", bundle()), "ROOT_IDENTITY_CHANGED")
        self.driver.root.rmdir()
        self.driver.root.symlink_to(original, target_is_directory=True)
        self.blocked(self.driver.run("linked", bundle()), "LOCAL_IO_OR_STATE_ERROR")
        self.assertFalse((original / "jobs").exists())

    def test_control_directory_symlink_cannot_escape(self):
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        (self.driver.root / "jobs").symlink_to(outside, target_is_directory=True)
        self.blocked(self.driver.run("linked", bundle()), "LOCAL_IO_OR_STATE_ERROR")
        self.assertEqual(list(outside.iterdir()), [])

    def test_lock_symlink_hardlink_fifo_and_content_are_safe(self):
        sentinel = self.base / "sentinel"
        sentinel.write_text("unchanged")
        lock = self.driver.root / "driver.lock"
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    lock.symlink_to(sentinel)
                elif kind == "hardlink":
                    os.link(sentinel, lock)
                else:
                    os.mkfifo(lock, 0o600)
                self.blocked(self.driver.run("lock-attack", bundle()))
                lock.unlink()
                self.assertEqual(sentinel.read_text(), "unchanged")

    def test_busy_lock_does_not_make_an_attempt(self):
        lock = os.open(self.driver.root / "driver.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.blocked(self.driver.run("busy", bundle()), "DRIVER_BUSY")
            self.assertFalse((self.driver.root / "jobs").exists())
        finally:
            os.close(lock)

    def test_readback_rejects_writable_open_descriptor(self):
        path = self.base / "writable.json"
        path.write_text("{}")
        fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(local.DeliveryError, "UNSAFE_FILE_READBACK"):
                local._read(fd, path.name, 100)
        finally:
            os.close(fd)

    def test_test_result_channel_rejects_false_zero_and_inconsistent_counts(self):
        execution = {"returnCode": 0, "timedOut": False, "outputLimitExceeded": False}
        valid = {
            "discovered": 2,
            "testsRun": 2,
            "testCount": 2,
            "skipped": 0,
            "failures": 0,
            "errors": 0,
            "expectedFailures": 0,
            "unexpectedSuccesses": 0,
            "passed": True,
        }
        self.assertTrue(local.LocalDeliveryDriver._valid_test_result(execution, valid))
        for fields in (
            {"testCount": True},
            {"testCount": 0},
            {"discovered": 3},
            {"errors": 1},
            {"expectedFailures": 1},
            {"unexpectedSuccesses": 1},
            {"passed": "true"},
            {"extra": 1},
        ):
            with self.subTest(fields=fields):
                self.assertFalse(
                    local.LocalDeliveryDriver._valid_test_result(
                        execution, valid | fields
                    )
                )

    def test_sandbox_unavailable_is_blocked_and_never_falls_back(self):
        with patch.object(local, "BWRAP", self.base / "missing-bwrap"):
            receipt = self.blocked(
                self.driver.run("missing-bwrap", bundle()), "SANDBOX_UNAVAILABLE"
            )
        self.assertIsNone(receipt["logs"][0]["returnCode"])
        self.assertFalse(receipt["verification"]["compile"])
        self.assertIn("/quarantine/", receipt["artifactRoot"])
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not rerun")
        ):
            self.assertEqual(self.driver.run("missing-bwrap", bundle()), receipt)


class RecoveryTests(Fixture):
    def test_interrupted_materialization_is_quarantined_and_not_reexecuted(self):
        job = self.interrupted()
        self.assertFalse((job / "receipt.json").exists())
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not rerun")
        ):
            receipt = self.blocked(
                self.driver.run("interrupted", bundle()), "INTERRUPTED_ATTEMPT"
            )
            self.assertEqual(self.driver.run("interrupted", bundle()), receipt)
        self.assertFalse((job / "attempt-0001").exists())
        self.assertTrue(Path(receipt["artifactRoot"]).is_dir())

    def test_preclaim_crash_seals_orphan_without_executing(self):
        with patch.object(local, "_atomic_json", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.driver.run("preclaim", bundle())
        job = job_path(self.driver, "preclaim")
        self.assertTrue(job.is_dir())
        self.assertFalse((job / "claim.json").exists())
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not execute")
        ):
            receipt = self.blocked(
                self.driver.run("preclaim", bundle()), "INTERRUPTED_ATTEMPT"
            )
            self.assertIsNone(receipt["artifactRoot"])
            self.assertEqual(self.driver.run("preclaim", bundle()), receipt)

    def test_crash_after_quarantine_rename_adopts_blocked_attempt(self):
        self.interrupted()
        original = self.driver._quarantine

        def crash(*args):
            original(*args)
            raise KeyboardInterrupt

        with patch.object(self.driver, "_quarantine", side_effect=crash):
            with self.assertRaises(KeyboardInterrupt):
                self.driver.run("interrupted", bundle())
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not rerun")
        ):
            receipt = self.blocked(
                self.driver.run("interrupted", bundle()), "INTERRUPTED_ATTEMPT"
            )
            self.assertTrue(Path(receipt["artifactRoot"]).is_dir())
            self.assertEqual(self.driver.run("interrupted", bundle()), receipt)

    def test_crash_before_artifact_directory_has_no_dangling_root(self):
        real_mkdir = os.mkdir

        def crash(name, *args, **kwargs):
            if name == "artifacts":
                raise KeyboardInterrupt
            return real_mkdir(name, *args, **kwargs)

        with patch.object(local.os, "mkdir", side_effect=crash):
            with self.assertRaises(KeyboardInterrupt):
                self.driver.run("no-artifacts", bundle())
        receipt = self.blocked(
            self.driver.run("no-artifacts", bundle()), "INTERRUPTED_ATTEMPT"
        )
        self.assertIsNone(receipt["artifactRoot"])
        self.assertEqual(self.driver.run("no-artifacts", bundle()), receipt)

    def test_actual_sigkill_restart_does_not_execute_again(self):
        marker = self.base / "crash-ready"
        code = textwrap.dedent("""
            import os, signal, sys
            from pathlib import Path
            from cct_agent.owner_delivery_local import LocalDeliveryDriver
            import json
            driver = LocalDeliveryDriver(Path(sys.argv[1]))
            original = driver._materialize
            def stopped(*args):
                original(*args)
                Path(sys.argv[2]).write_text('ready')
                os.kill(os.getpid(), signal.SIGSTOP)
            driver._materialize = stopped
            driver.run('killed', json.loads(sys.argv[3]), acceptance=json.loads(sys.argv[4]))
        """)
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                code,
                str(self.driver.root),
                str(marker),
                json.dumps(bundle()),
                json.dumps(acceptance_plan()),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 8
            while (
                not marker.exists()
                and child.poll() is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.02)
            self.assertTrue(
                marker.exists(), "child did not reach durable materialization"
            )
            child.kill()
            self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            child.stderr.close()
        restarted = TestDriver(self.driver.root)
        with patch.object(
            restarted, "_sandbox", side_effect=AssertionError("must not execute")
        ):
            receipt = self.blocked(
                restarted.run("killed", bundle()), "INTERRUPTED_ATTEMPT"
            )
            self.assertEqual(restarted.run("killed", bundle()), receipt)

    def test_quarantine_symlink_tampering_is_not_advertised(self):
        self.interrupted()
        receipt = self.driver.run("interrupted", bundle())
        attempt = Path(receipt["artifactRoot"]).parent
        retained = self.base / "retained"
        attempt.rename(retained)
        attempt.symlink_to(retained, target_is_directory=True)
        result = self.blocked(
            self.driver.run("interrupted", bundle()), "LOCAL_IO_OR_STATE_ERROR"
        )
        self.assertIsNone(result["artifactRoot"])
        self.assertTrue((retained / "artifacts" / "main.py").exists())

    def test_blocked_receipt_digest_tamper_detected_without_reexecution(self):
        self.interrupted()
        receipt = self.driver.run("interrupted", bundle())
        receipt["reason"] = "forged reason"
        path = job_path(self.driver, "interrupted") / "receipt.json"
        replace_readonly(path, local._json(receipt))
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not execute")
        ):
            self.blocked(
                self.driver.run("interrupted", bundle()), "RECEIPT_DIGEST_MISMATCH"
            )

    def test_atomic_control_publication_never_overwrites(self):
        fd = os.open(self.driver.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            local._atomic_json(fd, "record.json", {"first": True})
            with self.assertRaises(FileExistsError):
                local._atomic_json(fd, "record.json", {"second": True})
            self.assertEqual(local._read(fd, "record.json", 100), b'{"first":true}')
            self.assertEqual(os.stat("record.json", dir_fd=fd).st_nlink, 1)
            self.assertEqual(os.listdir(fd), ["record.json"])
        finally:
            os.close(fd)


@unittest.skipUnless(
    CAN_SANDBOX, "host Python lacks Linux memfd/seal API; use /usr/bin/python3"
)
class RealSandboxTests(Fixture):
    def test_real_success_contract_and_independent_replay(self):
        receipt = self.completed()
        expected = {
            "schemaVersion",
            "jobId",
            "bundleDigest",
            "receiptDigest",
            "status",
            "artifactRoot",
            "manifest",
            "verification",
            "testCount",
            "logs",
            "reason",
            "sandbox",
            "private",
        }
        self.assertEqual(set(receipt), expected)
        self.assertEqual(receipt["schemaVersion"], local.SCHEMA)
        self.assertEqual(receipt["reason"], "VERIFIED_LOCAL_ARTIFACT")
        self.assertEqual(receipt["testCount"], 3)
        self.assertEqual(receipt["verification"]["generatedTestCountClaim"], 2)
        self.assertTrue(receipt["verification"]["independentBehavior"])
        self.assertFalse(receipt["verification"]["generatedTestsVerified"])
        self.assertEqual(receipt["verification"]["status"], "passed")
        self.assertFalse(receipt["verification"]["semanticCompletion"])
        self.assertEqual(
            [log["stage"] for log in receipt["logs"]],
            [
                "compile",
                "unittest",
                "cli-default",
                "cli-help",
                "acceptance-positive",
                "acceptance-negative",
                "acceptance-invalid",
            ],
        )
        self.assertTrue(
            all(local.LocalDeliveryDriver._ok(log) for log in receipt["logs"][:-1])
        )
        self.assertEqual(receipt["logs"][-1]["returnCode"], 2)
        self.assertEqual(receipt["logs"][2]["stdout"], "42\n")
        self.assertIn("Double an integer", receipt["logs"][3]["stdout"])
        root = Path(receipt["artifactRoot"])
        for item in receipt["manifest"]:
            data = (root / item["path"]).read_bytes()
            self.assertEqual(sha256(data).hexdigest(), item["sha256"])
            self.assertEqual(len(data), item["bytes"])
        receipt_path = job_path(self.driver, "success") / "receipt.json"
        before = receipt_path.read_bytes(), receipt_path.stat().st_mtime_ns
        reordered = bundle()
        reordered["files"].reverse()
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not execute")
        ):
            self.assertEqual(self.driver.run("success", reordered), receipt)
        self.assertEqual(
            (receipt_path.read_bytes(), receipt_path.stat().st_mtime_ns), before
        )
        self.assertEqual(root.stat().st_mode & 0o777, 0o555)
        self.assertTrue(
            all(
                (root / item["path"]).stat().st_mode & 0o777 == 0o444
                for item in receipt["manifest"]
            )
        )

    def test_nested_package_entrypoint_runs_in_real_sandbox(self):
        value = {
            "summary": "Package CLI",
            "testCommand": "python-unittest",
            "files": [
                {"path": "package/__init__.py", "content": "VALUE = 42\n"},
                {
                    "path": "package/__main__.py",
                    "content": MAIN.replace("default=21", "default=21"),
                },
                {
                    "path": "tests/test_package.py",
                    "content": "import unittest\nfrom package import VALUE\nclass T(unittest.TestCase):\n def test_value(self): self.assertEqual(VALUE, 42)\n",
                },
            ],
        }
        receipt = self.completed("package", value)
        self.assertEqual(
            receipt["verification"]["behavioralEvidence"][0]["module"], "package"
        )

    def test_real_failing_assertion_blocks_and_rolls_back(self):
        first = self.completed("prior")
        before = Path(first["artifactRoot"], "main.py").read_bytes()
        bad = bundle(main=MAIN.replace("value * 2", "value * 3"))
        receipt = self.blocked(self.driver.run("incorrect", bad), "TESTS_FAILED")
        self.assertEqual(receipt["testCount"], 0)
        self.assertEqual(receipt["verification"]["generatedTestReport"]["failures"], 2)
        self.assertFalse(receipt["verification"]["cli"])
        self.assertFalse((job_path(self.driver, "incorrect") / "attempt-0001").exists())
        self.assertIn("/quarantine/", receipt["artifactRoot"])
        self.assertEqual(
            Path(receipt["artifactRoot"], "main.py").read_text(),
            bad["files"][0]["content"],
        )
        self.assertEqual(Path(first["artifactRoot"], "main.py").read_bytes(), before)
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not rerun")
        ):
            self.assertEqual(self.driver.run("incorrect", bad), receipt)
            self.assertEqual(self.driver.run("prior", bundle()), first)

    def test_real_empty_skipped_expected_failure_and_import_error_do_not_pass(self):
        cases = [
            ("empty", "import unittest\n", "ZERO_TESTS"),
            (
                "skipped",
                'import unittest\n@unittest.skip("inert")\nclass T(unittest.TestCase):\n def test_skip(self): self.fail()\n',
                "ZERO_TESTS",
            ),
            (
                "expected",
                "import unittest\nclass T(unittest.TestCase):\n @unittest.expectedFailure\n def test_failure(self): self.fail()\n",
                "TESTS_FAILED",
            ),
            (
                "import-error",
                'raise RuntimeError("fixture import error")\n',
                "ZERO_TESTS",
            ),
        ]
        for job, source, reason in cases:
            with self.subTest(job=job):
                receipt = self.blocked(
                    self.driver.run(job, bundle(tests=source)), reason
                )
                self.assertFalse(receipt["verification"]["tests"])
                self.assertFalse(receipt["verification"]["cli"])

    def test_real_compile_failure_does_not_import_generated_code(self):
        receipt = self.blocked(
            self.driver.run("syntax", bundle(main="def invalid(:\n")), "COMPILE_FAILED"
        )
        self.assertEqual(len(receipt["logs"]), 1)
        self.assertFalse(receipt["verification"]["compile"])
        self.assertIn("SyntaxError", receipt["logs"][0]["stderr"])

    def test_cli_default_and_help_are_separate_required_processes(self):
        cases = [
            ("silent", "pass\n"),
            ("exit", "raise SystemExit(3)\n"),
            (
                "help-fails",
                'import sys\nprint("default")\nif "--help" in sys.argv: raise SystemExit(4)\n',
            ),
        ]
        inert_tests = "import unittest\nclass T(unittest.TestCase):\n def test_math(self): self.assertEqual(2 * 21, 42)\n"
        for job, source in cases:
            with self.subTest(job=job):
                receipt = self.blocked(
                    self.driver.run(job, bundle(main=source, tests=inert_tests)),
                    "CLI_BEHAVIOR_FAILED",
                )
                self.assertFalse(receipt["verification"]["tests"])
                self.assertFalse(receipt["verification"]["cli"])
        monkeypatch_tests = (
            inert_tests
            + '\nimport runpy\nrunpy.run_module = lambda *a, **k: print("fake CLI")\n'
        )
        self.blocked(
            self.driver.run(
                "separate",
                bundle(main="raise SystemExit(5)\n", tests=monkeypatch_tests),
            ),
            "CLI_BEHAVIOR_FAILED",
        )

    def test_real_network_environment_host_files_and_inherited_fds_are_unavailable(
        self,
    ):
        sentinel = self.base / "host-only-marker"
        sentinel.write_text("inert-host-marker-never-readable")
        descriptor = os.open(sentinel, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        probes = textwrap.dedent("""
            import errno, os, pathlib, socket, unittest
            class Isolation(unittest.TestCase):
                def test_environment(self):
                    self.assertEqual(dict(os.environ), {'HOME': '/tmp', 'TMPDIR': '/tmp', 'LANG': 'C.UTF-8', 'PATH': '/usr/bin', 'PWD': '/workspace'})
                    self.assertEqual(os.uname().nodename, 'cct-local')
                def test_host_paths(self):
                    for name in HOST_PATHS:
                        self.assertFalse(pathlib.Path(name).exists(), name)
                def test_network(self):
                    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
                        with self.assertRaises(PermissionError) as result:
                            socket.socket(family, socket.SOCK_STREAM)
                        self.assertEqual(result.exception.errno, errno.EPERM)
                def test_inherited_descriptors(self):
                    for fd in range(3, 64):
                        with self.assertRaises(OSError) as result: os.fstat(fd)
                        self.assertEqual(result.exception.errno, errno.EBADF)
                def test_workspace_readonly(self):
                    with self.assertRaises(OSError): pathlib.Path('/workspace/main.py').write_text('changed')
                    with self.assertRaises(OSError): os.chmod('/workspace/main.py', 0o666)
                    with self.assertRaises(OSError): pathlib.Path('/workspace/new.txt').write_text('new')
                    pathlib.Path('/tmp/probe.txt').write_text('private temporary file')
                    self.assertEqual(pathlib.Path('/tmp/probe.txt').read_text(), 'private temporary file')
        """).replace(
            "HOST_PATHS",
            repr(
                [
                    str(sentinel),
                    str(self.driver.root),
                    "/etc/passwd",
                    "/home",
                    "/root",
                    "/proc",
                    "/sys",
                    "/run",
                    "/mnt",
                    "/usr/local",
                ]
            ),
        )
        with patch.dict(
            os.environ,
            {
                "CCT_FAKE_TEST_SECRET": "inert-fixture-secret",
                "PYTHONPATH": str(self.base),
            },
        ):
            receipt = self.completed("isolation", bundle(tests=probes))
        self.assertEqual(receipt["testCount"], 3)
        self.assertEqual(receipt["verification"]["generatedTestCountClaim"], 5)
        self.assertEqual(sentinel.read_text(), "inert-host-marker-never-readable")
        self.assertNotIn("inert-fixture-secret", json.dumps(receipt))
        self.assertFalse((Path(receipt["artifactRoot"]) / "new.txt").exists())

    def test_real_seccomp_denies_processes_threads_namespaces_and_mounts(self):
        probes = textwrap.dedent("""
            import ctypes, errno, os, subprocess, sys, threading, unittest
            class KernelLimits(unittest.TestCase):
                def test_fork(self):
                    with self.assertRaises(PermissionError): os.fork()
                def test_subprocess(self):
                    with self.assertRaises(PermissionError): subprocess.run([sys.executable, '-c', 'pass'])
                def test_thread(self):
                    with self.assertRaises(RuntimeError): threading.Thread(target=lambda: None).start()
                def test_kernel_calls(self):
                    libc = ctypes.CDLL(None, use_errno=True)
                    for number in (272, 165, 321, 425, 435):
                        ctypes.set_errno(0)
                        self.assertEqual(libc.syscall(number, 0, 0, 0, 0, 0, 0), -1)
                        self.assertEqual(ctypes.get_errno(), errno.EPERM)
        """)
        receipt = self.completed("kernel-limits", bundle(tests=probes))
        self.assertEqual(receipt["testCount"], 3)
        self.assertEqual(receipt["verification"]["generatedTestCountClaim"], 4)

    def test_real_timeout_kills_and_quarantines(self):
        with patch.object(local, "TIMEOUT_SECONDS", 1):
            receipt = self.blocked(
                self.driver.run(
                    "timeout", bundle(main=MAIN + "\nimport time\ntime.sleep(30)\n")
                ),
                "EXECUTION_TIMEOUT",
            )
        self.assertTrue(any(log["timedOut"] for log in receipt["logs"]))
        self.assertFalse((job_path(self.driver, "timeout") / "attempt-0001").exists())

    def test_real_output_limit_kills_and_bounds_logs(self):
        source = TESTS + '\nimport os\nos.write(1, b"x" * 100000)\n'
        receipt = self.blocked(
            self.driver.run("noisy", bundle(tests=source)), "EXECUTION_OUTPUT_LIMIT"
        )
        self.assertTrue(any(log["outputLimitExceeded"] for log in receipt["logs"]))
        for log in receipt["logs"]:
            self.assertLessEqual(
                len(log["stdout"].encode()) + len(log["stderr"].encode()),
                local.MAX_LOG_BYTES,
            )

    def test_same_job_changed_bundle_never_replaces_immutable_attempt(self):
        receipt = self.completed("immutable")
        path = job_path(self.driver, "immutable") / "receipt.json"
        before = path.read_bytes()
        changed = bundle()
        changed["summary"] = "Different requested bundle"
        with patch.object(
            self.driver, "_sandbox", side_effect=AssertionError("must not run")
        ):
            self.blocked(
                self.driver.run("immutable", changed), "JOB_ID_BUNDLE_MISMATCH"
            )
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.driver.run("immutable", bundle()), receipt)

    def test_artifact_tamper_missing_extra_symlink_hardlink_and_write_modes(self):
        cases = (
            "content",
            "missing",
            "extra",
            "symlink",
            "hardlink",
            "writable-file",
            "writable-root",
            "extra-dir",
        )
        for kind in cases:
            with self.subTest(kind=kind):
                receipt = self.completed(kind)
                root = Path(receipt["artifactRoot"])
                path = root / "main.py"
                root.chmod(0o755)
                if kind == "content":
                    replace_readonly(path, b'print("tampered")\n')
                elif kind == "missing":
                    path.unlink()
                elif kind == "extra":
                    (root / "extra.txt").write_text("extra")
                    (root / "extra.txt").chmod(0o444)
                elif kind == "extra-dir":
                    (root / "extra").mkdir(mode=0o555)
                elif kind in ("symlink", "hardlink"):
                    outside = self.base / f"{kind}-outside"
                    outside.write_bytes(path.read_bytes())
                    outside.chmod(0o444)
                    path.unlink()
                    if kind == "symlink":
                        path.symlink_to(outside)
                    else:
                        os.link(outside, path)
                elif kind == "writable-file":
                    path.chmod(0o644)
                if kind != "writable-root":
                    root.chmod(0o555)
                with patch.object(
                    self.driver,
                    "_sandbox",
                    side_effect=AssertionError("must not rerun"),
                ):
                    result = self.blocked(self.driver.run(kind, bundle()))
                self.assertIsNone(result["artifactRoot"])

    def test_completed_receipt_tamper_covers_logs_flags_and_control_links(self):
        receipt = self.completed("receipt")
        path = job_path(self.driver, "receipt") / "receipt.json"
        original = path.read_bytes()
        for field, value in [
            ("reason", "forged"),
            ("private", False),
            ("logs", []),
            ("testCount", 999),
        ]:
            with self.subTest(field=field):
                changed = copy.deepcopy(receipt)
                changed[field] = value
                replace_readonly(path, local._json(changed))
                self.blocked(
                    self.driver.run("receipt", bundle()), "RECEIPT_DIGEST_MISMATCH"
                )
                replace_readonly(path, original)
        changed = copy.deepcopy(receipt)
        changed["verification"]["semanticCompletion"] = True
        changed.pop("receiptDigest")
        changed["receiptDigest"] = sha256(local._json(changed)).hexdigest()
        replace_readonly(path, local._json(changed))
        self.blocked(
            self.driver.run("receipt", bundle()), "RECEIPT_VERIFICATION_MISMATCH"
        )
        replace_readonly(path, original)
        outside = self.base / "receipt-copy"
        outside.write_bytes(original)
        outside.chmod(0o400)
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                path.unlink()
                if kind == "symlink":
                    path.symlink_to(outside)
                else:
                    os.link(outside, path)
                self.blocked(self.driver.run("receipt", bundle()))
                path.unlink()
                path.write_bytes(original)
                path.chmod(0o400)
        self.assertEqual(self.driver.run("receipt", bundle()), receipt)

    def test_claim_tamper_is_not_rebound_to_a_new_bundle(self):
        self.completed("claim")
        path = job_path(self.driver, "claim") / "claim.json"
        original = json.loads(path.read_bytes())
        original["jobId"] = "another-job"
        replace_readonly(path, local._json(original))
        self.blocked(self.driver.run("claim", bundle()), "JOB_ID_BUNDLE_MISMATCH")


class IndependentBehaviorTests(Fixture):
    def forged_bundle(self, main=None):
        report = dict(
            discovered=101,
            testsRun=101,
            testCount=101,
            skipped=0,
            failures=0,
            errors=0,
            expectedFailures=0,
            unexpectedSuccesses=0,
            passed=True,
        )
        payload = (
            "import os\nos.write(1, "
            + repr(json.dumps(report).encode())
            + ")\nos._exit(0)\n"
        )
        value = bundle()
        for item in value["files"]:
            if item["path"] == "test_main.py":
                item["content"] = payload
            if item["path"] == "main.py" and main is not None:
                item["content"] = main
        return value

    def test_original_zero_tests_forgery_cannot_verify_wrong_artifact(self):
        receipt = self.driver.run(
            "forged-wrong", self.forged_bundle('print("plausible output")\n')
        )
        self.assertEqual(receipt["status"], "blocked")
        self.assertFalse(receipt["verification"]["tests"])
        self.assertFalse(receipt["verification"]["independentBehavior"])
        self.assertEqual(receipt["testCount"], 0)
        self.assertIn("INDEPENDENT_BEHAVIOR_FAILED", receipt["reason"])
        self.assertIn("/quarantine/", receipt["artifactRoot"])

    def test_correct_behavior_does_not_certify_forged_authored_test_count(self):
        receipt = self.driver.run("forged-correct", self.forged_bundle())
        self.assertEqual(receipt["status"], "completed", receipt)
        self.assertEqual(receipt["testCount"], len(acceptance_plan()["cases"]))
        self.assertTrue(receipt["verification"]["independentBehavior"])
        self.assertFalse(receipt["verification"]["generatedTestsVerified"])
        self.assertEqual(
            receipt["verification"]["generatedTestReport"]["testCount"], 101
        )
        self.assertIn("untrusted", receipt["verification"]["testEvidence"].lower())

    def test_raw_driver_requires_separate_acceptance_not_bundle_supplied(self):
        driver = local.LocalDeliveryDriver(self.base / "raw")
        result = driver.run("missing-plan", bundle())
        self.assertEqual(result["status"], "blocked")
        self.assertIn("INDEPENDENT_ACCEPTANCE_REQUIRED", result["reason"])
        value = bundle()
        value["acceptance"] = acceptance_plan()
        result = driver.run("embedded-plan", value)
        self.assertEqual(result["status"], "blocked")

    def test_changed_acceptance_cannot_reuse_cached_pass(self):
        original = self.driver.run("acceptance-identity", bundle())
        self.assertEqual(original["status"], "completed")
        changed = acceptance_plan()
        changed["cases"][0]["stdout"] = "999\n"
        result = self.driver.run("acceptance-identity", bundle(), acceptance=changed)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], "JOB_ID_BUNDLE_MISMATCH")

    def test_expectations_never_enter_generated_process(self):
        real = self.driver._sandbox
        expected = []

        def capture(fd, program, payload, stage):
            if stage.startswith("acceptance-"):
                expected.append(stage)
                case = next(
                    c
                    for c in acceptance_plan()["cases"]
                    if stage == "acceptance-" + c["id"]
                )
                self.assertEqual(payload, ["main", case["argv"], case["stdin"]])
            return real(fd, program, payload, stage)

        with patch.object(self.driver, "_sandbox", side_effect=capture):
            self.assertEqual(
                self.driver.run("no-oracle-leak", bundle())["status"], "completed"
            )
        self.assertEqual(len(expected), 3)

    def test_json_comparator_preserves_types_and_missing_fields(self):
        good = {
            "returnCode": 0,
            "stdout": '{"n":2,"flag":false}',
            "timedOut": False,
            "outputLimitExceeded": False,
            "sandboxError": None,
        }
        case = {"exitCode": 0, "jsonChecks": [{"path": ["n"], "equals": 2}]}
        self.assertTrue(local._matches_case(good, case))
        for path, value in [
            (["n"], True),
            (["n"], "2"),
            (["missing"], None),
            (["flag"], 0),
        ]:
            case["jsonChecks"] = [{"path": path, "equals": value}]
            self.assertFalse(local._matches_case(good, case))

    def test_check_reordering_or_different_fields_cannot_fake_varying_behavior(self):
        cases = []
        for number, checks in enumerate(
            [
                [{"path": ["a"], "equals": 1}, {"path": ["b"], "equals": 2}],
                [{"path": ["b"], "equals": 2}, {"path": ["a"], "equals": 1}],
            ]
        ):
            cases.append(
                {
                    "id": str(number),
                    "argv": [str(number)],
                    "stdin": "",
                    "exitCode": 0,
                    "jsonChecks": checks,
                }
            )
        plan = {"schemaVersion": local.ACCEPTANCE_SCHEMA, "cases": cases}
        with self.assertRaises(local.DeliveryError):
            local.validate_acceptance(plan)
        cases[1]["jsonChecks"] = [{"path": ["different"], "equals": 999}]
        with self.assertRaises(local.DeliveryError):
            local.validate_acceptance(plan)
        cases[1]["jsonChecks"] = [{"path": ["a"], "equals": 999}]
        self.assertEqual(local.validate_acceptance(plan), plan)

    def test_invalid_or_vacuous_acceptance_rejected_before_execution(self):
        for value in [
            None,
            {},
            {"schemaVersion": local.ACCEPTANCE_SCHEMA, "cases": []},
            {
                "schemaVersion": local.ACCEPTANCE_SCHEMA,
                "cases": [acceptance_plan()["cases"][0]],
            },
        ]:
            with self.subTest(value=value):
                with self.assertRaises(local.DeliveryError):
                    local.validate_acceptance(value)


if __name__ == "__main__":
    unittest.main()
