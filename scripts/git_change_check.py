#!/usr/bin/env python3
"""Check whitespace errors in both committed branch changes and the worktree."""

import os
import sys

from compat import git_cmd, run_cmd


def _git(*args):
    return run_cmd(git_cmd() + list(args), timeout=60)


def comparison_base():
    github_base = str(os.environ.get("GITHUB_BASE_REF") or "").strip()
    candidates = [f"origin/{github_base}"] if github_base else []
    branch, _stderr, _rc = _git("branch", "--show-current")
    branch = branch.strip()
    if branch and branch not in {"main", "master"}:
        candidates.extend(("origin/main", "origin/master"))
    candidates.append("HEAD^")
    for candidate in candidates:
        _stdout, _stderr, rc = _git("rev-parse", "--verify", candidate)
        if rc == 0:
            return candidate
    return ""


def main():
    commands = [("git", "diff", "--check")]
    base = comparison_base()
    if base:
        commands.append(("git", "diff", "--check", f"{base}...HEAD"))
    failed = False
    for command in commands:
        stdout, stderr, rc = run_cmd(
            git_cmd() + list(command[1:]), timeout=120,
        )
        if stdout:
            sys.stdout.write(stdout)
        if stderr:
            sys.stderr.write(stderr)
        failed = failed or rc != 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
