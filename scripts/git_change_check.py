#!/usr/bin/env python3
"""Check whitespace errors in both committed branch changes and the worktree."""

import os
import subprocess
import sys


def _git(*args):
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def comparison_base():
    github_base = str(os.environ.get("GITHUB_BASE_REF") or "").strip()
    candidates = [f"origin/{github_base}"] if github_base else []
    branch = _git("branch", "--show-current").stdout.strip()
    if branch and branch not in {"main", "master"}:
        candidates.extend(("origin/main", "origin/master"))
    candidates.append("HEAD^")
    for candidate in candidates:
        if _git("rev-parse", "--verify", candidate).returncode == 0:
            return candidate
    return ""


def main():
    commands = [("git", "diff", "--check")]
    base = comparison_base()
    if base:
        commands.append(("git", "diff", "--check", f"{base}...HEAD"))
    failed = False
    for command in commands:
        completed = subprocess.run(command, check=False)
        failed = failed or completed.returncode != 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
