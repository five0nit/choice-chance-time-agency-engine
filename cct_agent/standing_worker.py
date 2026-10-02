"""Profile-local durable worker for operator-endorsed standing autonomy."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import stat
from typing import Any

from .commands import OwnedProjectShell
from .standing_autonomy import (
    AUTOMATIC_ACTION_CLASSES,
    EARNED_ACTION_CLASSES,
    PER_OPERATION_ACTION_CLASSES,
    StandingAutonomyPolicy,
    StandingAutonomyRunner,
    StandingShellAction,
)
from .store import EventStore


CONFIG_SCHEMA_VERSION = "cct.standing_autonomy.config.v1"
AUTHORITY_SCHEMA_VERSION = "cct.standing_autonomy.operator-authority.v1"
_MAX_CONFIG_BYTES = 262_144
PRODUCTION_PROFILE_SHA256 = "e88740b3661ff463fc7b7647dbcb1cd4547ef071a5a17c6ad01d68b7d27aefab"
PRODUCTION_AUTHORITY_SHA256 = "df39789e820282d8d8ad900728947d9dd9d967bea85fcd701081306436346e43"
PRODUCTION_CONFIG_SHA256 = "4ed61d59aef18d5eef290d1533f7525b2b03014f2f76084bdc291be1eb80ffa9"


class StandingWorkerDenied(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _safe_file(path: Path, *, root: Path) -> bytes:
    lexical = path.absolute()
    try:
        relative = lexical.relative_to(root)
    except ValueError as error:
        raise StandingWorkerDenied("CONFIG_OUTSIDE_PROFILE") from error
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise StandingWorkerDenied("CONFIG_PATH_INVALID")

    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    root_descriptor = -1
    directory_descriptor = -1
    file_descriptor = -1
    try:
        root_descriptor = os.open(root, directory_flags)
        root_metadata = os.fstat(root_descriptor)
        visible_root = os.stat(root, follow_symlinks=False)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
            or root_metadata.st_mode & 0o022
            or not os.path.samestat(root_metadata, visible_root)
        ):
            raise StandingWorkerDenied("PROFILE_ROOT_UNSAFE")
        directory_descriptor = root_descriptor
        for component in relative.parts[:-1]:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            metadata = os.fstat(next_descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o022
            ):
                os.close(next_descriptor)
                raise StandingWorkerDenied("CONFIG_PARENT_UNSAFE")
            if directory_descriptor != root_descriptor:
                os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        file_descriptor = os.open(
            relative.parts[-1],
            file_flags,
            dir_fd=directory_descriptor,
        )
        metadata = os.fstat(file_descriptor)
        visible = os.stat(lexical, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > _MAX_CONFIG_BYTES
            or not os.path.samestat(metadata, visible)
        ):
            raise StandingWorkerDenied("CONFIG_UNSAFE")
        with os.fdopen(file_descriptor, "rb", closefd=True) as stream:
            file_descriptor = -1
            body = stream.read(_MAX_CONFIG_BYTES + 1)
        if len(body) > _MAX_CONFIG_BYTES:
            raise StandingWorkerDenied("CONFIG_TOO_LARGE")
        return body
    except StandingWorkerDenied:
        raise
    except OSError as error:
        raise StandingWorkerDenied("CONFIG_OPEN_FAILED") from error
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if directory_descriptor >= 0 and directory_descriptor != root_descriptor:
            os.close(directory_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)


def _object(value: Any, *, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise StandingWorkerDenied(f"{name.upper()}_SCHEMA_MISMATCH")
    return value


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def runtime_provenance(
    *, expected_module_root: Path, expected_package_version: str
) -> dict[str, str]:
    module_root = Path(__file__).resolve().parents[1]
    try:
        expected_root = expected_module_root.resolve(strict=True)
    except OSError as error:
        raise StandingWorkerDenied("RUNTIME_MODULE_ROOT_INVALID") from error
    if module_root != expected_root:
        raise StandingWorkerDenied("RUNTIME_MODULE_ROOT_MISMATCH")
    try:
        distribution_version = version("cct-agency-engine")
    except PackageNotFoundError as error:
        raise StandingWorkerDenied("RUNTIME_DISTRIBUTION_MISSING") from error
    from . import __version__

    if distribution_version != expected_package_version or __version__ != expected_package_version:
        raise StandingWorkerDenied("RUNTIME_VERSION_MISMATCH")
    return {
        "distribution": "cct-agency-engine",
        "package_version": distribution_version,
        "module_root": str(module_root),
        "module_file": str(Path(__file__).resolve()),
        "module_sha256": _sha256_file(Path(__file__)),
    }


def load_runner(
    *, profile_root: Path, config_path: Path
) -> tuple[StandingAutonomyRunner, dict[str, Any]]:
    profile = profile_root.resolve(strict=True)
    if not profile.is_dir() or profile.is_symlink():
        raise StandingWorkerDenied("PROFILE_ROOT_INVALID")
    config_bytes = _safe_file(config_path, root=profile)
    config_sha256 = sha256(config_bytes).hexdigest()
    production_binding_enforced = (
        sha256(str(profile).encode("utf-8")).hexdigest()
        == PRODUCTION_PROFILE_SHA256
    )
    if production_binding_enforced and config_sha256 != PRODUCTION_CONFIG_SHA256:
        raise StandingWorkerDenied("PRODUCTION_CONFIG_BINDING_MISMATCH")
    try:
        raw = json.loads(config_bytes)
    except json.JSONDecodeError as error:
        raise StandingWorkerDenied("CONFIG_JSON_INVALID") from error
    config = _object(
        raw,
        fields={
            "schema_version",
            "authority_receipt_path",
            "authority_receipt_sha256",
            "workspace_root",
            "policy",
            "projects",
            "actions",
        },
        name="config",
    )
    if config["schema_version"] != CONFIG_SCHEMA_VERSION:
        raise StandingWorkerDenied("CONFIG_VERSION_MISMATCH")

    authority_path = Path(config["authority_receipt_path"])
    authority_bytes = _safe_file(authority_path, root=profile)
    authority_sha256 = sha256(authority_bytes).hexdigest()
    if authority_sha256 != config["authority_receipt_sha256"]:
        raise StandingWorkerDenied("AUTHORITY_RECEIPT_DIGEST_MISMATCH")
    if (
        production_binding_enforced
        and authority_sha256 != PRODUCTION_AUTHORITY_SHA256
    ):
        raise StandingWorkerDenied("PRODUCTION_AUTHORITY_BINDING_MISMATCH")
    try:
        authority = json.loads(authority_bytes)
    except json.JSONDecodeError as error:
        raise StandingWorkerDenied("AUTHORITY_RECEIPT_JSON_INVALID") from error
    authority = _object(
        authority,
        fields={
            "schema_version",
            "principal_id",
            "source",
            "authorized_at",
            "automatic_classes",
            "earned_classes",
            "per_operation_classes",
            "conflict_resolution",
            "secret_entry_boundary",
            "financial_boundary",
            "job_submission_boundary",
        },
        name="authority_receipt",
    )
    if (
        authority["schema_version"] != AUTHORITY_SCHEMA_VERSION
        or authority["principal_id"] != "mike"
        or tuple(authority["automatic_classes"]) != AUTOMATIC_ACTION_CLASSES
        or tuple(authority["earned_classes"]) != EARNED_ACTION_CLASSES
        or tuple(authority["per_operation_classes"]) != PER_OPERATION_ACTION_CLASSES
        or authority["conflict_resolution"] != "per_operation_wins"
        or authority["secret_entry_boundary"]
        != "opaque_host_broker_or_authenticated_human_handoff_only"
        or authority["financial_boundary"]
        != "earned_class_inactive_without_explicit_venue_account_value_loss_and_unwind_budgets"
        or authority["job_submission_boundary"]
        != "automatic_only_when_all_facts_and_declarations_are_verified_and_no_captcha_mfa_or_human_attestation_remains"
    ):
        raise StandingWorkerDenied("AUTHORITY_RECEIPT_MISMATCH")

    workspace_root = Path(config["workspace_root"])
    if not workspace_root.is_absolute() or workspace_root.is_symlink():
        raise StandingWorkerDenied("WORKSPACE_ROOT_INVALID")
    try:
        workspace = workspace_root.resolve(strict=True)
    except OSError as error:
        raise StandingWorkerDenied("WORKSPACE_ROOT_INVALID") from error
    if not workspace.is_dir() or workspace.stat().st_uid != os.geteuid():
        raise StandingWorkerDenied("WORKSPACE_ROOT_INVALID")

    policy_raw = _object(
        config["policy"],
        fields={
            "id",
            "principal_id",
            "expires_at",
            "initial_tier",
            "maximum_tier",
            "promotion_verified_runs",
            "min_expected_utility",
            "max_uncertainty",
            "max_actions",
            "max_bytes",
            "max_value_microunits",
        },
        name="policy",
    )
    policy = StandingAutonomyPolicy(**policy_raw)
    if policy.principal_id != authority["principal_id"]:
        raise StandingWorkerDenied("POLICY_PRINCIPAL_MISMATCH")

    raw_projects = config["projects"]
    if not isinstance(raw_projects, list) or not 1 <= len(raw_projects) <= 64:
        raise StandingWorkerDenied("PROJECTS_SCHEMA_MISMATCH")
    raw_actions = config["actions"]
    if not isinstance(raw_actions, list) or not 1 <= len(raw_actions) <= 64:
        raise StandingWorkerDenied("ACTIONS_SCHEMA_MISMATCH")

    actions: list[StandingShellAction] = []
    action_fields = {
        "id",
        "action_class",
        "project_id",
        "cwd",
        "argv",
        "verifier_id",
        "expected_utility",
        "uncertainty",
        "timeout_ms",
        "max_stdout_bytes",
        "max_stderr_bytes",
        "expected_exit_status",
        "expected_stdout_sha256",
        "trigger_kind",
        "required_tier",
        "reversible",
    }
    for index, raw_action in enumerate(raw_actions):
        row = _object(raw_action, fields=action_fields, name=f"action_{index}")
        argv = row["argv"]
        if not isinstance(argv, list):
            raise StandingWorkerDenied("ACTION_ARGV_SCHEMA_MISMATCH")
        actions.append(StandingShellAction(**{**row, "argv": tuple(argv)}))

    verifier_ids: dict[str, list[str]] = {}
    for action in actions:
        verifier_ids.setdefault(action.project_id, []).append(action.verifier_id)

    projects: list[OwnedProjectShell] = []
    for index, raw_project in enumerate(raw_projects):
        row = _object(raw_project, fields={"id", "root"}, name=f"project_{index}")
        project_root = Path(row["root"])
        if not project_root.is_absolute() or project_root.is_symlink():
            raise StandingWorkerDenied("PROJECT_ROOT_INVALID")
        try:
            resolved = project_root.resolve(strict=True)
            resolved.relative_to(workspace)
        except (OSError, ValueError) as error:
            raise StandingWorkerDenied("PROJECT_ROOT_OUTSIDE_WORKSPACE") from error
        projects.append(
            OwnedProjectShell(
                id=row["id"],
                root=resolved,
                verifier_ids=tuple(verifier_ids.get(row["id"], ())),
                direct_argv_enabled=True,
            )
        )

    database = profile / "cct-agency" / "agency.sqlite"
    store = EventStore(database)
    runner = StandingAutonomyRunner(
        store,
        policy=policy,
        projects=projects,
        actions=actions,
        authority_evidence=(
            f"authority-receipt:{authority_sha256}",
            f"source:{authority['source']}",
        ),
    )
    metadata = {
        "config_sha256": config_sha256,
        "authority_receipt_sha256": authority_sha256,
        "workspace_root_sha256": sha256(str(workspace).encode("utf-8")).hexdigest(),
        "production_binding_enforced": production_binding_enforced,
        "raw_authority_text_persisted": False,
    }
    return runner, metadata


def run_from_config(
    *,
    profile_root: Path,
    config_path: Path,
    run_id: str,
    action_id: str | None = None,
) -> dict[str, Any]:
    runner, metadata = load_runner(profile_root=profile_root, config_path=config_path)
    return {**runner.run_once(run_id=run_id, action_id=action_id), **metadata}


def status_from_config(*, profile_root: Path, config_path: Path) -> dict[str, Any]:
    runner, metadata = load_runner(profile_root=profile_root, config_path=config_path)
    return {**runner.status(), **metadata}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run one bounded standing-autonomy action")
    parser.add_argument("--profile-root", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--expected-module-root", required=True)
    parser.add_argument("--expected-package-version", required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--action-id")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--message-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    provenance = runtime_provenance(
        expected_module_root=Path(args.expected_module_root),
        expected_package_version=args.expected_package_version,
    )
    if args.status:
        result = status_from_config(
            profile_root=Path(args.profile_root), config_path=Path(args.config)
        )
    else:
        run_id = args.run_id or datetime.now(UTC).strftime("standing-%Y%m%dT%H%M%SZ")
        result = run_from_config(
            profile_root=Path(args.profile_root),
            config_path=Path(args.config),
            run_id=run_id,
            action_id=args.action_id,
        )
    result = {**result, "runtime": provenance}
    if not args.message_only or result.get("status") not in {"NO_OP"}:
        print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") != "FAILED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
