from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import git_change_check


class GitChangeCheckTest(unittest.TestCase):
    def test_comparison_base_prefers_verified_pull_request_base(self):
        calls = []

        def fake_git(*arguments):
            calls.append(arguments)
            if arguments == ("branch", "--show-current"):
                return "feature/change\n", "", 0
            if arguments == (
                "rev-parse", "--verify", "origin/release/1.x",
            ):
                return "sha\n", "", 0
            return "", "missing", 1

        with patch.dict(
            git_change_check.os.environ,
            {"GITHUB_BASE_REF": "release/1.x"},
            clear=False,
        ), patch.object(git_change_check, "_git", side_effect=fake_git):
            selected = git_change_check.comparison_base()

        self.assertEqual(selected, "origin/release/1.x")
        self.assertEqual(calls[-1], (
            "rev-parse", "--verify", "origin/release/1.x",
        ))

    def test_comparison_base_falls_back_in_deterministic_order(self):
        candidates = []

        def fake_git(*arguments):
            if arguments == ("branch", "--show-current"):
                return "feature/change", "", 0
            candidates.append(arguments[-1])
            return ("sha", "", 0) if arguments[-1] == "origin/master" else (
                "", "missing", 1
            )

        with patch.dict(
            git_change_check.os.environ, {"GITHUB_BASE_REF": ""}, clear=False,
        ), patch.object(git_change_check, "_git", side_effect=fake_git):
            selected = git_change_check.comparison_base()

        self.assertEqual(selected, "origin/master")
        self.assertEqual(candidates, ["origin/main", "origin/master"])

    def test_main_checks_worktree_and_committed_range_and_preserves_diagnostics(self):
        invocations = []

        def fake_run(command, *, timeout):
            invocations.append((command, timeout))
            if len(invocations) == 1:
                return "worktree.py:1: trailing whitespace\n", "", 1
            return "", "range warning\n", 0

        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.object(
            git_change_check, "comparison_base", return_value="origin/main",
        ), patch.object(
            git_change_check, "git_cmd", return_value=["/usr/bin/git"],
        ), patch.object(
            git_change_check, "run_cmd", side_effect=fake_run,
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = git_change_check.main()

        self.assertEqual(exit_code, 1)
        self.assertEqual(invocations, [
            (["/usr/bin/git", "diff", "--check"], 120),
            (["/usr/bin/git", "diff", "--check", "origin/main...HEAD"], 120),
        ])
        self.assertIn("trailing whitespace", stdout.getvalue())
        self.assertIn("range warning", stderr.getvalue())

    def test_main_without_comparison_base_checks_only_worktree(self):
        with patch.object(
            git_change_check, "comparison_base", return_value="",
        ), patch.object(
            git_change_check, "git_cmd", return_value=["git"],
        ), patch.object(
            git_change_check, "run_cmd", return_value=("", "", 0),
        ) as run:
            self.assertEqual(git_change_check.main(), 0)

        run.assert_called_once_with(
            ["git", "diff", "--check"], timeout=120,
        )


if __name__ == "__main__":
    unittest.main()
