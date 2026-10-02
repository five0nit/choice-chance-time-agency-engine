from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess

import pytest

import cct_agent.standing_worker as standing_worker
from cct_agent.principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from cct_agent.standing_autonomy import (
    AUTOMATIC_ACTION_CLASSES,
    EARNED_ACTION_CLASSES,
    PER_OPERATION_ACTION_CLASSES,
)
from cct_agent.standing_worker import (
    AUTHORITY_SCHEMA_VERSION,
    CONFIG_SCHEMA_VERSION,
    StandingWorkerDenied,
    load_runner,
    run_from_config,
    status_from_config,
)
from cct_agent.store import EventStore


FUTURE = "2027-09-03T00:00:00+00:00"
EMPTY_SHA256 = sha256(b"").hexdigest()


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        env={
            "HOME": str(root),
            "GIT_AUTHOR_NAME": "CCT Test",
            "GIT_AUTHOR_EMAIL": "cct@example.invalid",
            "GIT_COMMITTER_NAME": "CCT Test",
            "GIT_COMMITTER_EMAIL": "cct@example.invalid",
        },
    ).stdout.strip()


def fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    profile = tmp_path / "profile"
    state = profile / "cct-agency"
    policy_root = profile / "standing-autonomy"
    workspace = tmp_path / "workspace"
    project = workspace / "project-alpha"
    state.mkdir(parents=True)
    policy_root.mkdir(parents=True)
    project.mkdir(parents=True)
    os.chmod(profile, 0o700)
    os.chmod(state, 0o700)
    os.chmod(policy_root, 0o700)
    git(project, "init", "-q")
    (project / "README.md").write_text("worker\n", encoding="utf-8")
    git(project, "add", "README.md")
    git(project, "commit", "-q", "-m", "Initial")

    store = EventStore(state / "agency.sqlite")
    PrincipalModel(store).install(
        PrincipalProfile(
            principal_id="mike",
            display_name="Mike",
            values={"autonomy": 1.0, "competence": 1.0, "truth": 1.0},
            directives=(
                PrincipalDirective(
                    id="standing-autonomy",
                    kind="grant",
                    statement="Allow bounded standing local autonomy.",
                    tags=("domain:operator", "action:shell"),
                    priority=100,
                ),
            ),
        ),
        authority="operator",
        evidence=("telegram://standing-autonomy",),
    )

    authority = {
        "schema_version": AUTHORITY_SCHEMA_VERSION,
        "principal_id": "mike",
        "source": "telegram:1000000001/session-digest",
        "authorized_at": "2026-09-03T00:00:00+00:00",
        "automatic_classes": list(AUTOMATIC_ACTION_CLASSES),
        "earned_classes": list(EARNED_ACTION_CLASSES),
        "per_operation_classes": list(PER_OPERATION_ACTION_CLASSES),
        "conflict_resolution": "per_operation_wins",
        "secret_entry_boundary": "opaque_host_broker_or_authenticated_human_handoff_only",
        "financial_boundary": "earned_class_inactive_without_explicit_venue_account_value_loss_and_unwind_budgets",
        "job_submission_boundary": "automatic_only_when_all_facts_and_declarations_are_verified_and_no_captcha_mfa_or_human_attestation_remains",
    }
    authority_path = policy_root / "authority.json"
    authority_bytes = (json.dumps(authority, sort_keys=True) + "\n").encode("utf-8")
    authority_path.write_bytes(authority_bytes)
    os.chmod(authority_path, 0o600)

    config = {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "authority_receipt_path": str(authority_path),
        "authority_receipt_sha256": sha256(authority_bytes).hexdigest(),
        "workspace_root": str(workspace),
        "policy": {
            "id": "mike-standing-autonomy-v1",
            "principal_id": "mike",
            "expires_at": FUTURE,
            "initial_tier": 3,
            "maximum_tier": 5,
            "promotion_verified_runs": 20,
            "min_expected_utility": 0.7,
            "max_uncertainty": 0.2,
            "max_actions": 24,
            "max_bytes": 262144,
            "max_value_microunits": 0,
        },
        "projects": [{"id": "project-alpha", "root": str(project)}],
        "actions": [
            {
                "id": "project-health",
                "action_class": "allowlisted_command",
                "project_id": "project-alpha",
                "cwd": ".",
                "argv": ["/usr/bin/git", "status", "--porcelain=v1"],
                "verifier_id": "project-health-readback",
                "expected_utility": 0.9,
                "uncertainty": 0.05,
                "timeout_ms": 60000,
                "max_stdout_bytes": 8192,
                "max_stderr_bytes": 8192,
                "expected_exit_status": 0,
                "expected_stdout_sha256": EMPTY_SHA256,
                "trigger_kind": "git_state",
                "required_tier": 3,
                "reversible": True,
            }
        ],
    }
    config_path = policy_root / "config.json"
    config_path.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(config_path, 0o600)
    return profile, config_path, project, authority_path


def test_worker_loads_private_bound_config_and_runs_without_fresh_approval(
    tmp_path: Path,
) -> None:
    profile, config_path, project, _authority = fixture(tmp_path)

    status = status_from_config(profile_root=profile, config_path=config_path)
    result = run_from_config(
        profile_root=profile,
        config_path=config_path,
        run_id="worker-run-1",
    )
    duplicate = run_from_config(
        profile_root=profile,
        config_path=config_path,
        run_id="worker-run-2",
    )

    assert status["current_tier"] == 3
    assert status["eligible_action_ids"] == ["project-health"]
    assert result["status"] == "VERIFIED"
    assert result["fresh_user_approval_required"] is False
    assert duplicate["status"] == "NO_OP"
    assert duplicate["reason"] == "UNCHANGED_TRIGGERS"
    assert git(project, "status", "--porcelain=v1") == ""
    store = EventStore(profile / "cct-agency" / "agency.sqlite")
    assert store.verify_chain()["valid"] is True


def test_config_and_authority_permissions_fail_closed(tmp_path: Path) -> None:
    profile, config_path, _project, authority_path = fixture(tmp_path)
    os.chmod(config_path, 0o644)
    with pytest.raises(StandingWorkerDenied, match="CONFIG_UNSAFE"):
        load_runner(profile_root=profile, config_path=config_path)

    os.chmod(config_path, 0o600)
    os.chmod(authority_path, 0o644)
    with pytest.raises(StandingWorkerDenied, match="CONFIG_UNSAFE"):
        load_runner(profile_root=profile, config_path=config_path)


def test_authority_digest_and_class_order_are_exact(tmp_path: Path) -> None:
    profile, config_path, _project, authority_path = fixture(tmp_path)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["authority_receipt_sha256"] = "0" * 64
    config_path.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(config_path, 0o600)
    with pytest.raises(StandingWorkerDenied, match="AUTHORITY_RECEIPT_DIGEST_MISMATCH"):
        load_runner(profile_root=profile, config_path=config_path)

    config["authority_receipt_sha256"] = sha256(authority_path.read_bytes()).hexdigest()
    config_path.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    authority["automatic_classes"] = list(reversed(authority["automatic_classes"]))
    body = (json.dumps(authority, sort_keys=True) + "\n").encode("utf-8")
    authority_path.write_bytes(body)
    os.chmod(authority_path, 0o600)
    config["authority_receipt_sha256"] = sha256(body).hexdigest()
    config_path.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(StandingWorkerDenied, match="AUTHORITY_RECEIPT_MISMATCH"):
        load_runner(profile_root=profile, config_path=config_path)


def test_project_must_stay_under_registered_workspace(tmp_path: Path) -> None:
    profile, config_path, _project, _authority = fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["projects"][0]["root"] = str(outside)
    config_path.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(config_path, 0o600)

    with pytest.raises(StandingWorkerDenied, match="PROJECT_ROOT_OUTSIDE_WORKSPACE"):
        load_runner(profile_root=profile, config_path=config_path)


def test_config_symlink_parent_and_hardlink_are_rejected(tmp_path: Path) -> None:
    profile, config_path, _project, _authority = fixture(tmp_path)
    real = config_path.with_name("config-real.json")
    config_path.rename(real)
    config_path.symlink_to(real)
    with pytest.raises(StandingWorkerDenied, match="CONFIG_OPEN_FAILED"):
        load_runner(profile_root=profile, config_path=config_path)

    config_path.unlink()
    real.rename(config_path)
    linked = config_path.with_name("config-hardlink.json")
    os.link(config_path, linked)
    with pytest.raises(StandingWorkerDenied, match="CONFIG_UNSAFE"):
        load_runner(profile_root=profile, config_path=config_path)

    linked.unlink()
    alias = profile / "standing-alias"
    alias.symlink_to(config_path.parent, target_is_directory=True)
    with pytest.raises(StandingWorkerDenied, match="CONFIG_OPEN_FAILED"):
        load_runner(profile_root=profile, config_path=alias / config_path.name)


def test_production_profile_binds_exact_config_and_authority_digests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, config_path, _project, authority_path = fixture(tmp_path)
    monkeypatch.setattr(
        standing_worker,
        "PRODUCTION_PROFILE_SHA256",
        sha256(str(profile.resolve()).encode("utf-8")).hexdigest(),
    )
    monkeypatch.setattr(standing_worker, "PRODUCTION_CONFIG_SHA256", "0" * 64)
    with pytest.raises(
        StandingWorkerDenied, match="PRODUCTION_CONFIG_BINDING_MISMATCH"
    ):
        load_runner(profile_root=profile, config_path=config_path)

    monkeypatch.setattr(
        standing_worker,
        "PRODUCTION_CONFIG_SHA256",
        sha256(config_path.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(standing_worker, "PRODUCTION_AUTHORITY_SHA256", "0" * 64)
    with pytest.raises(
        StandingWorkerDenied, match="PRODUCTION_AUTHORITY_BINDING_MISMATCH"
    ):
        load_runner(profile_root=profile, config_path=config_path)

    monkeypatch.setattr(
        standing_worker,
        "PRODUCTION_AUTHORITY_SHA256",
        sha256(authority_path.read_bytes()).hexdigest(),
    )
    runner, metadata = load_runner(profile_root=profile, config_path=config_path)
    assert runner.status()["current_tier"] == 3
    assert metadata["production_binding_enforced"] is True
