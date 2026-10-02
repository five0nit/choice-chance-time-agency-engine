from __future__ import annotations

from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tarfile
from typing import Mapping

import pytest

from cct_agent.release_host import (
    Generalist2ReleaseHostAdapter,
    Generalist2ReleaseHostConfig,
    ReleaseActivationSpec,
    SystemdUserReleaseController,
)
from cct_agent.release_recovery import (
    ExactRebuildTicket,
    Generalist2RedeployTicket,
    IsolatedVerificationTicket,
    ReleaseRecoveryDenied,
    ReleaseRollbackTicket,
)
from cct_agent.store import EventStore


REPO = Path(__file__).resolve().parents[1]
PYTHON = Path(sys.executable).resolve()
UV = Path(shutil.which("uv") or "uv").absolute()
COMMIT = ""  # Populated from the disposable repository, never private history.
RELEASE_REPO = REPO
VERSION = "0.9.0a10"
RECOVERY_ID = "host-adapter-a10"


@pytest.fixture(scope="module", autouse=True)
def release_repository(tmp_path_factory):
    """Build a real, offline wheel from a tiny committed test package.

    The installed plugin exercises the real EventStore. Only the activation
    controller is inert; archive, build, install, entry-point load and hash
    verification all run through the production release adapter.
    """
    root = tmp_path_factory.mktemp("release-repository")
    package = root / "cct_agent"
    package.mkdir()
    package.joinpath("__init__.py").write_text(f"__version__ = {VERSION!r}\n")
    shutil.copy2(REPO / "cct_agent" / "store.py", package / "store.py")
    plugin = root / "hermes_plugin"
    plugin.mkdir()
    plugin.joinpath("__init__.py").write_text(
        "import json, os\nfrom pathlib import Path\n"
        "from cct_agent import __version__ as PLUGIN_VERSION\n"
        "from cct_agent.store import EventStore\n"
        "def register(context):\n"
        "    store = EventStore(Path(os.environ['HERMES_HOME']) / 'fixture.sqlite')\n"
        "    def status(args):\n"
        "        return json.dumps({'status': {'chain': store.verify_chain()}})\n"
        "    context.register_tool('cct_status', status)\n"
        "    for name in ('start', 'turn', 'stop'):\n"
        "        context.register_hook(name, status)\n"
        "    context.register_middleware('fixture', status)\n"
    )
    root.joinpath("pyproject.toml").write_text(
        '[build-system]\nrequires = []\nbuild-backend = "fixture_build"\n'
        'backend-path = ["."]\n'
    )
    root.joinpath("fixture_build.py").write_text(
        "from pathlib import Path\nimport base64, csv, hashlib, io, zipfile\n"
        f"VERSION = {VERSION!r}\n"
        "def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n"
        "    name = f'cct_agency_engine-{VERSION}-py3-none-any.whl'\n"
        "    info = f'cct_agency_engine-{VERSION}.dist-info'\n"
        "    files = {str(p): p.read_bytes() for package in ('cct_agent', 'hermes_plugin') "
        "for p in sorted(Path(package).glob('*.py'))}\n"
        "    files[info + '/METADATA'] = f'Metadata-Version: 2.1\\nName: cct-agency-engine\\nVersion: {VERSION}\\n'.encode()\n"
        "    files[info + '/WHEEL'] = b'Wheel-Version: 1.0\\nGenerator: offline-test-fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n'\n"
        "    files[info + '/entry_points.txt'] = b'[hermes_agent.plugins]\\ncct-agency = hermes_plugin\\n'\n"
        "    record = io.StringIO()\n    writer = csv.writer(record, lineterminator='\\n')\n"
        "    for path, content in sorted(files.items()):\n"
        "        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode()\n"
        "        writer.writerow((path, 'sha256=' + digest, len(content)))\n"
        "    writer.writerow((info + '/RECORD', '', ''))\n"
        "    files[info + '/RECORD'] = record.getvalue().encode()\n"
        "    with zipfile.ZipFile(Path(wheel_directory) / name, 'w') as wheel:\n"
        "        for path, content in sorted(files.items()):\n"
        "            member = zipfile.ZipInfo(path, (2020, 1, 1, 0, 0, 0))\n"
        "            member.external_attr = 0o100644 << 16\n"
        "            wheel.writestr(member, content)\n"
        "    return name\n"
    )
    environment = dict(
        os.environ,
        GIT_AUTHOR_DATE="2020-01-01T00:00:00+0000",
        GIT_COMMITTER_DATE="2020-01-01T00:00:00+0000",
    )
    for args in (
        ("init",),
        ("add", "."),
        (
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "Disposable release fixture",
        ),
    ):
        subprocess.run(
            ["git", *args], cwd=root, env=environment, check=True, capture_output=True
        )
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    with pytest.MonkeyPatch.context() as patch:
        # Managed Python installations can be group-writable. Use a private
        # fixture launcher without changing the live interpreter permissions.
        launcher = tmp_path_factory.mktemp("release-python") / "python"
        launcher.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n')
        launcher.chmod(0o700)
        patch.setattr(sys.modules[__name__], "PYTHON", launcher)
        patch.setattr(sys.modules[__name__], "COMMIT", commit)
        patch.setattr(sys.modules[__name__], "RELEASE_REPO", root)
        yield root


def digest(path: Path) -> str:
    value = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def build_expected_wheel(root: Path) -> tuple[Path, str]:
    source = root / "source"
    source.mkdir(parents=True)
    archive = subprocess.run(
        ["git", "archive", "--format=tar", COMMIT],
        cwd=RELEASE_REPO,
        check=True,
        capture_output=True,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        members = bundle.getmembers()
        bundle.extractall(source, members=members, filter="data")
        for member in members:
            target = source / member.name
            if member.isdir():
                os.chmod(target, 0o755)
            elif member.isfile():
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
    epoch = subprocess.run(
        ["git", "show", "-s", "--format=%ct", COMMIT],
        cwd=RELEASE_REPO,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    output = root / "dist"
    environment = dict(os.environ)
    environment.update(
        {
            "SOURCE_DATE_EPOCH": epoch,
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
            "UV_NO_CACHE": "1",
        }
    )
    subprocess.run(
        [str(UV), "build", "--wheel", "--out-dir", str(output), str(source)],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        umask=0o022,
    )
    wheels = list(output.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0], digest(wheels[0])


class FakeActivationController:
    def __init__(self) -> None:
        self.current_pid = 101
        self.environment: dict[str, str] = {}
        self.activations: list[ReleaseActivationSpec] = []
        self.fail_phase: str | None = None

    def pid(self, service_name: str) -> int:
        assert service_name == "hermes-gateway-generalist2.service"
        return self.current_pid

    def process_environment(self, pid: int) -> Mapping[str, str]:
        assert pid == self.current_pid
        return dict(self.environment)

    def activate(self, spec: ReleaseActivationSpec) -> None:
        assert spec.profile_name == "generalist2"
        assert spec.service_name == "hermes-gateway-generalist2.service"
        assert spec.restore_state_database is False
        self.activations.append(spec)
        if spec.phase == self.fail_phase:
            raise ReleaseRecoveryDenied("FAKE_POST_RELOAD_VERIFICATION_FAILED")
        self.current_pid += 101
        self.environment["PYTHONPATH"] = (
            f"{spec.release_root}/bootstrap:{spec.module_root}"
        )


def configured(
    tmp_path: Path,
) -> tuple[Generalist2ReleaseHostAdapter, FakeActivationController]:
    home = tmp_path / "home"
    profile = home / ".hermes" / "profiles" / "generalist2"
    staging = profile / "cct-agency-staging"
    state = profile / "cct-release-host"
    scripts = profile / "scripts"
    for directory in (home, profile, staging, state, scripts):
        directory.mkdir(parents=True, exist_ok=True)
    systemd_root = home / ".config" / "systemd" / "user"
    dropin = (
        systemd_root / "hermes-gateway-generalist2.service.d" / "cct-profile-local.conf"
    )
    dropin.parent.mkdir(parents=True)
    dropin.write_text('[Service]\nEnvironment="PYTHONPATH=/bad"\n', encoding="utf-8")
    team = scripts / "cct_team_sync_tick.sh"
    proactive = scripts / "cct_proactive_tick.sh"
    team.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    proactive.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    database = profile / "cct-agency" / "agency.sqlite"
    database.parent.mkdir()
    EventStore(database)
    controller = FakeActivationController()
    config = Generalist2ReleaseHostConfig(
        repository_root=RELEASE_REPO,
        host_home_root=home,
        profile_root=profile,
        staging_root=staging,
        adapter_state_root=state,
        systemd_user_root=systemd_root,
        dropin_path=dropin,
        team_wrapper_path=team,
        proactive_wrapper_path=proactive,
        database_path=database,
        python_executable=PYTHON,
        uv_executable=UV,
        expected_tools=1,
    )
    return Generalist2ReleaseHostAdapter(config, controller=controller), controller


def test_current_release_host_default_expects_a14_tool_count() -> None:
    assert (
        Generalist2ReleaseHostConfig.__dataclass_fields__["expected_tools"].default
        == 22
    )


def test_exact_build_is_umask_invariant(tmp_path: Path) -> None:
    _, wheel_sha256 = build_expected_wheel(tmp_path / "expected")
    adapter, _ = configured(tmp_path)
    previous = os.umask(0o077)
    try:
        artifact = adapter.rebuild_exact(
            ExactRebuildTicket(
                recovery_id="host-adapter-umask-invariant",
                authority_id="authority-generalist2-release-recovery",
                mismatch_receipt_sha256="a" * 64,
                source_commit=COMMIT,
                version=VERSION,
                expected_wheel_sha256=wheel_sha256,
            )
        )
    finally:
        os.umask(previous)

    assert artifact.wheel_sha256 == wheel_sha256
    assert artifact.wheel_source_exact is True


def test_team_sync_script_prefers_installed_package_without_mutating_release_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "release" / "source"
    shutil.copytree(
        REPO / "cct_agent",
        source / "cct_agent",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    scripts = source / "scripts"
    scripts.mkdir()
    script = scripts / "cct_team_sync_tick.py"
    shutil.copy2(REPO / "scripts" / "cct_team_sync_tick.py", script)

    installed = tmp_path / "site-packages" / "cct_agent"
    installed.mkdir(parents=True)
    installed.joinpath("__init__.py").write_text(
        "AgencyKernel = EventStore = TeamSyncSensor = TeamSyncSensorPolicy = object\n"
        "def resolve_constitution(*args, **kwargs): return object()\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(installed.parent)
    environment.pop("PYTHONDONTWRITEBYTECODE", None)

    result = subprocess.run(
        [str(PYTHON), "-P", str(script), "--help"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert not (source / "cct_agent" / "__pycache__").exists()


def test_release_candidate_preserves_work_autonomy_before_recurrent_fallback(
    tmp_path: Path,
) -> None:
    adapter, _ = configured(tmp_path)
    release_root = adapter.config.staging_root / "release-source-0.9.0a11"

    _, _, proactive = adapter._candidate_files(release_root, "0.9.0a11")
    text = proactive.decode("utf-8")

    assert 'WORK_ROOT="$STATE_ROOT/work-autonomy"' in text
    assert 'WAKE_ROOT="$STATE_ROOT/recurrent/slice31-b19d05d"' in text
    assert "from cct_agent.work_autonomy import main" in text
    assert '--workspace-root "$WORK_ROOT/workspace"' in text
    assert 'if [[ -n "$work_output" ]]' in text
    assert "-m cct_agent.recurrent" in text
    assert '--workspace-root "$WAKE_ROOT/workspace"' in text
    assert "--expected-package-version 0.9.0a11" in text


def test_host_config_rejects_any_other_profile_or_service(tmp_path: Path) -> None:
    home = tmp_path / "home"
    profile = home / ".hermes" / "profiles" / "generalist2"
    systemd_root = home / ".config" / "systemd" / "user"
    for path in (
        home,
        profile,
        profile / "stage",
        profile / "state",
        tmp_path / "repo",
        systemd_root,
    ):
        path.mkdir(parents=True, exist_ok=True)
    file_path = tmp_path / "file"
    file_path.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="exact Generalist2 service"):
        Generalist2ReleaseHostConfig(
            repository_root=tmp_path / "repo",
            host_home_root=home,
            profile_root=profile,
            staging_root=profile / "stage",
            adapter_state_root=profile / "state",
            systemd_user_root=systemd_root,
            dropin_path=file_path,
            team_wrapper_path=file_path,
            proactive_wrapper_path=file_path,
            database_path=file_path,
            python_executable=PYTHON,
            uv_executable=UV,
            service_name="hermes-gateway.service",
        )
    foreign = home / ".hermes" / "profiles" / "generalist1"
    foreign.mkdir(parents=True)
    with pytest.raises(
        ValueError, match="dropin_path must target exact Generalist2 path"
    ):
        Generalist2ReleaseHostConfig(
            repository_root=tmp_path / "repo",
            host_home_root=home,
            profile_root=profile,
            staging_root=profile / "stage",
            adapter_state_root=profile / "state",
            systemd_user_root=systemd_root,
            dropin_path=foreign / "dropin.conf",
            team_wrapper_path=foreign / "team.sh",
            proactive_wrapper_path=foreign / "proactive.sh",
            database_path=foreign / "agency.sqlite",
            python_executable=PYTHON,
            uv_executable=UV,
        )
    foreign_scripts = foreign / "scripts"
    foreign_scripts.mkdir()
    (foreign_scripts / "cct_team_sync_tick.sh").write_text("foreign", encoding="utf-8")
    (foreign_scripts / "cct_proactive_tick.sh").write_text("foreign", encoding="utf-8")
    (profile / "scripts").symlink_to(foreign_scripts, target_is_directory=True)
    profile_database = profile / "cct-agency" / "agency.sqlite"
    profile_database.parent.mkdir()
    EventStore(profile_database)
    exact_dropin = (
        systemd_root / "hermes-gateway-generalist2.service.d" / "cct-profile-local.conf"
    )
    exact_dropin.parent.mkdir()
    exact_dropin.write_text("[Service]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="team_wrapper_path parent chain"):
        Generalist2ReleaseHostConfig(
            repository_root=tmp_path / "repo",
            host_home_root=home,
            profile_root=profile,
            staging_root=profile / "stage",
            adapter_state_root=profile / "state",
            systemd_user_root=systemd_root,
            dropin_path=exact_dropin,
            team_wrapper_path=profile / "scripts" / "cct_team_sync_tick.sh",
            proactive_wrapper_path=profile / "scripts" / "cct_proactive_tick.sh",
            database_path=profile_database,
            python_executable=PYTHON,
            uv_executable=UV,
        )
    with pytest.raises(ValueError, match="exact Generalist2 service"):
        ReleaseRollbackTicket(
            recovery_id="wrong-target",
            authority_id="authority-generalist2-release-recovery",
            mismatch_receipt_sha256="a" * 64,
            profile_name="generalist1",
            service_name="hermes-gateway-generalist1.service",
            expected_observed_state_sha256="b" * 64,
            rollback_version=VERSION,
            rollback_module_root="/tmp/rollback/site-packages",
            rollback_wheel_sha256="c" * 64,
            rollback_source_commit="d" * 40,
        )
    with pytest.raises(ValueError, match="exact Generalist2 service"):
        Generalist2RedeployTicket(
            recovery_id="wrong-target",
            authority_id="authority-generalist2-release-recovery",
            profile_name="generalist1",
            service_name="hermes-gateway-generalist1.service",
            source_commit="d" * 40,
            version=VERSION,
            module_root="/tmp/redeploy/site-packages",
            wheel_sha256="c" * 64,
            verification_receipt_sha256="e" * 64,
            previous_pid=1,
        )


def test_systemd_controller_rejects_stale_verified_receipt_before_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = tmp_path / "post-reload.json"
    receipt.write_text('{"status":"VERIFIED"}\n', encoding="utf-8")
    calls: list[tuple[str, ...]] = []
    controller = SystemdUserReleaseController(timeout_seconds=30)
    monkeypatch.setattr(
        controller,
        "_run",
        lambda *args, **kwargs: calls.append(args),
    )
    spec = ReleaseActivationSpec(
        recovery_id="stale-receipt",
        phase="redeploy",
        profile_name="generalist2",
        service_name="hermes-gateway-generalist2.service",
        old_pid=101,
        release_root=str(tmp_path / "release"),
        module_root=str(tmp_path / "release" / "site-packages"),
        version=VERSION,
        source_commit=COMMIT,
        wheel_sha256="a" * 64,
        expected_tools=1,
        expected_hooks=3,
        expected_middleware=1,
        python_executable=str(PYTHON),
        profile_root=str(tmp_path / "generalist2"),
        database_path=str(tmp_path / "agency.sqlite"),
        dropin_path=str(tmp_path / "dropin.conf"),
        team_wrapper_path=str(tmp_path / "team.sh"),
        proactive_wrapper_path=str(tmp_path / "proactive.sh"),
        backup_dropin_path=str(tmp_path / "backup-dropin.conf"),
        backup_team_wrapper_path=str(tmp_path / "backup-team.sh"),
        backup_proactive_wrapper_path=str(tmp_path / "backup-proactive.sh"),
        receipt_path=str(receipt),
        unrelated_services=("hermes-gateway.service",),
    )

    with pytest.raises(ReleaseRecoveryDenied, match="POST_RELOAD_RECEIPT_COLLISION"):
        controller.activate(spec)
    assert calls == []

    failure = {
        "status": "ROLLED_BACK",
        "phase": spec.phase,
        "recovery_id": spec.recovery_id,
        "old_pid": spec.old_pid,
        "version": spec.version,
        "source_commit": spec.source_commit,
        "wheel_sha256": spec.wheel_sha256,
        "module_root": spec.module_root,
        "database_restored": False,
    }
    receipt.write_text(json.dumps(failure, sort_keys=True), encoding="utf-8")
    controller._archive_bound_failure_receipt(spec, receipt)
    assert not receipt.exists()
    archives = list(tmp_path.glob("post-reload-failure-*.json"))
    assert len(archives) == 1
    assert json.loads(archives[0].read_text(encoding="utf-8")) == failure


def test_exact_build_isolated_entrypoint_live_readback_and_scoped_redeploy(
    tmp_path: Path,
) -> None:
    expected_wheel, wheel_sha256 = build_expected_wheel(tmp_path / "expected")
    assert expected_wheel.stat().st_size > 0
    adapter, controller = configured(tmp_path)
    module_root = (
        adapter.config.staging_root
        / f"release-{COMMIT[:12]}-{VERSION}"
        / "site-packages"
    )

    artifact = adapter.rebuild_exact(
        ExactRebuildTicket(
            recovery_id=RECOVERY_ID,
            authority_id="authority-generalist2-release-recovery",
            mismatch_receipt_sha256="a" * 64,
            source_commit=COMMIT,
            version=VERSION,
            expected_wheel_sha256=wheel_sha256,
        )
    )
    verification = adapter.verify_isolated(
        IsolatedVerificationTicket(
            recovery_id=RECOVERY_ID,
            authority_id="authority-generalist2-release-recovery",
            source_commit=COMMIT,
            version=VERSION,
            wheel_sha256=wheel_sha256,
            expected_module_root=str(module_root),
        ),
        artifact,
    )

    assert artifact.wheel_source_exact is True
    assert verification.passed is True
    assert (verification.tools, verification.hooks, verification.middleware) == (
        1,
        3,
        1,
    )
    assert adapter.inspect_artifact(RECOVERY_ID) == artifact
    assert adapter.inspect_verification(RECOVERY_ID) == verification

    controller.environment["PYTHONPATH"] = (
        f"{module_root.parent}/bootstrap:{module_root}"
    )
    source_path = module_root.parent / "source" / "cct_agent" / "__init__.py"
    source_bytes = source_path.read_bytes()
    source_path.write_bytes(source_bytes + b"\nTAMPERED = True\n")
    with pytest.raises(ReleaseRecoveryDenied, match="RELEASE_SOURCE_TREE_MISMATCH"):
        adapter.inspect_runtime()
    source_path.write_bytes(source_bytes)
    before = adapter.inspect_runtime()
    assert before.pid == 101
    assert before.version == VERSION
    assert before.source_commit == COMMIT
    assert before.wheel_sha256 == wheel_sha256
    assert before.chain_valid is True

    after = adapter.redeploy(
        Generalist2RedeployTicket(
            recovery_id=RECOVERY_ID,
            authority_id="authority-generalist2-release-recovery",
            profile_name="generalist2",
            service_name="hermes-gateway-generalist2.service",
            source_commit=COMMIT,
            version=VERSION,
            module_root=str(module_root),
            wheel_sha256=wheel_sha256,
            verification_receipt_sha256=verification.receipt_sha256,
            previous_pid=before.pid,
            restore_state_database=False,
        ),
        artifact,
        verification,
    )

    assert after.pid == 202
    assert after.module_root == str(module_root)
    assert len(controller.activations) == 1
    assert controller.activations[0].phase == "redeploy"
    assert controller.activations[0].restore_state_database is False
    assert adapter.config.database_path.exists()
    assert not list(adapter.config.adapter_state_root.rglob("*.sqlite"))

    rollback_root = adapter.config.staging_root / "known-good-rollback"
    shutil.copytree(module_root.parent, rollback_root)
    rollback_module = rollback_root / "site-packages"
    manifest_path = rollback_root / "receipts" / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["module_root"] = str(rollback_module)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (rollback_root / "bootstrap" / "sitecustomize.py").write_text(
        "from pathlib import Path\n"
        "import sys\n"
        f"SITE = Path({str(rollback_module)!r}).resolve()\n"
        "text = str(SITE)\n"
        "if text in sys.path:\n    sys.path.remove(text)\n"
        "sys.path.insert(0, text)\n",
        encoding="utf-8",
    )
    before_rollback = adapter.inspect_runtime()
    controller.fail_phase = "rollback"
    with pytest.raises(
        ReleaseRecoveryDenied, match="FAKE_POST_RELOAD_VERIFICATION_FAILED"
    ):
        adapter.rollback(
            ReleaseRollbackTicket(
                recovery_id="host-adapter-rollback",
                authority_id="authority-generalist2-release-recovery",
                mismatch_receipt_sha256="a" * 64,
                profile_name="generalist2",
                service_name="hermes-gateway-generalist2.service",
                expected_observed_state_sha256=before_rollback.state_sha256,
                rollback_version=VERSION,
                rollback_module_root=str(rollback_module),
                rollback_wheel_sha256=wheel_sha256,
                rollback_source_commit=COMMIT,
                restore_state_database=False,
            )
        )
    assert str(rollback_root) in adapter.config.dropin_path.read_text(encoding="utf-8")
    controller.fail_phase = None
    rolled_back = adapter.rollback(
        ReleaseRollbackTicket(
            recovery_id="host-adapter-rollback",
            authority_id="authority-generalist2-release-recovery",
            mismatch_receipt_sha256="a" * 64,
            profile_name="generalist2",
            service_name="hermes-gateway-generalist2.service",
            expected_observed_state_sha256=before_rollback.state_sha256,
            rollback_version=VERSION,
            rollback_module_root=str(rollback_module),
            rollback_wheel_sha256=wheel_sha256,
            rollback_source_commit=COMMIT,
            restore_state_database=False,
        )
    )

    assert rolled_back.pid == 303
    assert rolled_back.module_root == str(rollback_module)
    assert [row.phase for row in controller.activations] == [
        "redeploy",
        "rollback",
        "rollback",
    ]
    assert not list(adapter.config.adapter_state_root.rglob("*.sqlite"))


def test_verification_receipt_tamper_fails_closed(tmp_path: Path) -> None:
    _, wheel_sha256 = build_expected_wheel(tmp_path / "expected")
    adapter, _ = configured(tmp_path)
    artifact = adapter.rebuild_exact(
        ExactRebuildTicket(
            recovery_id=RECOVERY_ID,
            authority_id="authority-generalist2-release-recovery",
            mismatch_receipt_sha256="a" * 64,
            source_commit=COMMIT,
            version=VERSION,
            expected_wheel_sha256=wheel_sha256,
        )
    )
    module_root = (
        adapter.config.staging_root
        / f"release-{COMMIT[:12]}-{VERSION}"
        / "site-packages"
    )
    adapter.verify_isolated(
        IsolatedVerificationTicket(
            recovery_id=RECOVERY_ID,
            authority_id="authority-generalist2-release-recovery",
            source_commit=COMMIT,
            version=VERSION,
            wheel_sha256=wheel_sha256,
            expected_module_root=str(module_root),
        ),
        artifact,
    )
    path = adapter.config.adapter_state_root / RECOVERY_ID / "verification.json"
    value = __import__("json").loads(path.read_text())
    value["verification"]["tools"] = 999
    path.write_text(__import__("json").dumps(value), encoding="utf-8")

    with pytest.raises(PermissionError, match="HOST_VERIFICATION_RECEIPT_MALFORMED"):
        adapter.inspect_verification(RECOVERY_ID)
