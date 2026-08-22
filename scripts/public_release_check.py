#!/usr/bin/env python3
"""Fail when the public Git candidate contains secrets or broken local links."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess


TEXT_SUFFIXES = {
    "",
    ".cff",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SECRET_PATTERNS = {
    "openai_key": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "google_token": re.compile(r"ya29\.[A-Za-z0-9_-]{20,}"),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
    "raw_secret_json": re.compile(
        r"(?i)[\"'](?:access_token|refresh_token|api_key|password)[\"']"
        r"\s*:\s*[\"'][^\"']{8,}[\"']"
    ),
}
PRIVATE_PATH = re.compile(r"(?:/home|/Users)/[^/\s]+/")
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
FORBIDDEN_TRACKED_PARTS = {
    ".pytest_cache",
    ".ruff_cache",
    ".runtime",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "state",
    "venv",
}
REPO_ROOT = Path(__file__).resolve().parents[1]


def git_paths(*arguments: str) -> list[Path]:
    raw = subprocess.check_output(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z", *arguments]
    )
    return [
        REPO_ROOT / item.decode("utf-8")
        for item in raw.split(b"\0")
        if item
    ]


def candidate_files() -> list[Path]:
    paths = set(git_paths())
    paths.update(git_paths("--others", "--exclude-standard"))
    return sorted(
        (path for path in paths if path.exists() and path.is_file()),
        key=str,
    )


def main() -> int:
    errors: list[str] = []
    files = candidate_files()

    for path in files:
        display_path = path.relative_to(REPO_ROOT)
        if set(path.parts) & FORBIDDEN_TRACKED_PARTS:
            errors.append(f"forbidden generated/runtime path: {display_path}")
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            if PRIVATE_PATH.search(line):
                errors.append(
                    f"absolute private path: {display_path}:{line_number}"
                )
            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(line):
                    errors.append(f"{label}: {display_path}:{line_number}")
        if path.suffix.lower() != ".md":
            continue
        for target in MARKDOWN_LINK.findall(text):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            relative = target.split("#", 1)[0]
            if relative and not (path.parent / relative).resolve().exists():
                errors.append(f"broken local link: {display_path} -> {target}")

    if errors:
        print("\n".join(errors))
        return 1
    print(f"PUBLIC_RELEASE_CHECK_PASS files={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
