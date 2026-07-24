import ast
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import compat  # noqa: E402
import error_handler  # noqa: E402
import s1_dep_diff  # noqa: E402
import s4_contract  # noqa: E402
import path_runtime  # noqa: E402
from compat import run_cmd  # noqa: E402


class PlatformContractTest(unittest.TestCase):
    def test_shared_path_policy_bounds_dynamic_components_without_collisions(self):
        first = "com.example:" + ("very-long-artifact-" * 20) + "one"
        second = "com.example:" + ("very-long-artifact-" * 20) + "two"

        first_component = path_runtime.bounded_path_component(first, max_length=48)
        second_component = path_runtime.bounded_path_component(second, max_length=48)
        first_filename = path_runtime.bounded_filename(first + ".jar", max_length=64)

        self.assertLessEqual(len(first_component), 48)
        self.assertLessEqual(len(second_component), 48)
        self.assertNotEqual(first_component, second_component)
        self.assertLessEqual(len(first_filename), 64)
        self.assertTrue(first_filename.endswith(".jar"))
        self.assertLessEqual(len(s4_contract.make_per_dependency_dirname(first)), 48)

    def test_windows_runtime_storage_uses_shared_short_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            configured_root = Path(tmp) / "w"
            long_report = Path(tmp) / (("deep-" * 20) + "report")
            with patch.object(path_runtime, "IS_WINDOWS", True), patch.dict(
                os.environ,
                {path_runtime.SHORT_TEMP_ROOT_ENV: str(configured_root)},
                clear=False,
            ):
                storage = path_runtime.runtime_storage_root(
                    long_report, "source_snapshots",
                )

        self.assertEqual(configured_root, storage.parents[2])
        self.assertNotIn(str(long_report), str(storage))

    def test_windows_git_policy_is_applied_at_the_shared_command_boundary(self):
        with patch.object(compat, "IS_WINDOWS", True), patch.object(
            compat, "find_executable", return_value=r"C:\Git\git.exe",
        ):
            command = compat.git_cmd()

        self.assertEqual(
            [r"C:\Git\git.exe", "-c", "core.longpaths=true"],
            command,
        )

    def test_path_expanding_temporary_directories_cannot_bypass_shared_runtime(self):
        for path in sorted((ROOT / "scripts").glob("*.py")):
            if path.name == "path_runtime.py":
                continue
            source = path.read_text(encoding="utf-8")
            self.assertNotRegex(
                source,
                r"tempfile\.(?:TemporaryDirectory|mkdtemp)\s*\(",
                f"{path.name} bypasses the shared short-path runtime",
            )

    def test_step1_real_worktree_round_trip_uses_short_generated_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "repository"
            repository.mkdir()

            def git(*arguments):
                completed = subprocess.run(
                    ["git", *arguments],
                    cwd=repository,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True,
                )
                return completed.stdout.strip()

            git("init")
            git("config", "user.email", "platform@example.invalid")
            git("config", "user.name", "Platform Contract")
            (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            git("add", "tracked.txt")
            git("commit", "-m", "initial")
            commit = git("rev-parse", "HEAD")
            worktree_root = root / "w"

            with patch.dict(
                os.environ,
                {path_runtime.SHORT_TEMP_ROOT_ENV: str(worktree_root)},
                clear=False,
            ):
                worktree = s1_dep_diff.create_branch_worktree(
                    commit,
                    repository,
                    side="base",
                )
                try:
                    self.assertEqual(worktree_root, worktree.parent)
                    self.assertTrue(worktree.name.startswith("s1-b-"))
                    self.assertNotIn(commit, worktree.name)
                    self.assertEqual(
                        commit,
                        subprocess.run(
                            ["git", "rev-parse", "HEAD"],
                            cwd=worktree,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            check=True,
                        ).stdout.strip(),
                    )
                finally:
                    s1_dep_diff.remove_branch_worktree(worktree, repository)

            self.assertFalse(worktree.exists())
            self.assertNotIn(
                str(worktree),
                git("worktree", "list", "--porcelain"),
            )

    def test_platform_only_stdlib_imports_are_guarded(self):
        platform_only_modules = {
            "fcntl", "grp", "posix", "pty", "pwd", "resource",
            "syslog", "termios", "tty",
        }
        for path in sorted((ROOT / "scripts").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            parents = {
                child: parent
                for parent in ast.walk(tree)
                for child in ast.iter_child_nodes(parent)
            }
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = {alias.name.split(".", 1)[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom):
                    imported = {(node.module or "").split(".", 1)[0]}
                else:
                    continue
                guarded_modules = imported & platform_only_modules
                if not guarded_modules:
                    continue
                ancestor = parents.get(node)
                protected = False
                while ancestor is not None:
                    if isinstance(ancestor, ast.Try):
                        caught = {
                            name.id
                            for handler in ancestor.handlers
                            for name in ast.walk(handler.type)
                            if isinstance(name, ast.Name)
                        }
                        if "ImportError" in caught:
                            protected = True
                            break
                    ancestor = parents.get(ancestor)
                self.assertTrue(
                    protected,
                    f"{path.relative_to(ROOT)}:{node.lineno} imports "
                    f"{sorted(guarded_modules)} without an ImportError fallback",
                )

    def test_diagnostic_commands_match_the_host_shell(self):
        expected_java_locator = (
            "where java" if os.name == "nt" else "command -v java"
        )
        expected_settings_reader = (
            'Get-Content "$HOME\\.m2\\settings.xml"'
            if os.name == "nt"
            else "cat ~/.m2/settings.xml"
        )

        self.assertEqual(error_handler.JAVA_LOCATION_COMMAND, expected_java_locator)
        self.assertEqual(
            error_handler.MAVEN_SETTINGS_COMMAND,
            expected_settings_reader,
        )

    def test_git_resolution_prefers_working_user_install_over_broken_system_git(self):
        user_git = Path("/Users/example/.local/bin/git")

        with patch.object(compat.Path, "home", return_value=Path("/Users/example")), \
                patch.object(compat.shutil, "which", return_value="/usr/bin/git"), \
                patch.object(
                    compat,
                    "_git_executable_works",
                    side_effect=lambda path: Path(path) == user_git,
                ), \
                patch.dict(os.environ, {"JUA_GIT_EXECUTABLE": ""}, clear=False):
            resolved = compat.find_executable("git")

        self.assertEqual(resolved, str(user_git))

    def test_bare_git_command_is_replaced_with_validated_absolute_path(self):
        with patch.object(
            compat, "find_executable", return_value="/Users/example/.local/bin/git"
        ):
            resolved = compat.resolve_command(["git", "status", "--short"])

        self.assertEqual(
            resolved,
            ["/Users/example/.local/bin/git", "status", "--short"],
        )

    def test_validated_git_is_cached_for_repeated_commands(self):
        compat._GIT_EXECUTABLE_CACHE.clear()
        with patch.object(compat.Path, "home", return_value=Path("/Users/cache-test")), \
                patch.object(compat.shutil, "which", return_value="/usr/bin/git"), \
                patch.object(compat, "_git_executable_works", return_value=True) as probe, \
                patch.dict(os.environ, {"JUA_GIT_EXECUTABLE": ""}, clear=False):
            first = compat.find_executable("git")
            second = compat.find_executable("git")

        self.assertEqual(first, second)
        probe.assert_called_once()

    def test_workflow_declares_mandatory_os_jdk_tool_and_evidence_matrix(self):
        workflow = ROOT / ".github" / "workflows" / "platform-contract.yml"
        text = workflow.read_text(encoding="utf-8")

        for value in ("ubuntu-latest", "macos-latest", "windows-latest"):
            self.assertIn(value, text)
        self.assertRegex(text, r'java:\s*\["11",\s*"17",\s*"21"\]')
        self.assertIn('python-version: "3.12"', text)
        self.assertIn("mvn -version", text)
        self.assertNotIn("cache: maven", text)
        self.assertIn("timeout-minutes:", text)
        self.assertIn("actions/upload-artifact@v4", text)
        self.assertIn("platform-contract.json", text)
        self.assertIn("push:", text)
        self.assertIn('- "main"', text)
        self.assertIn('- "codex/**"', text)
        self.assertIn("platform-evidence:", text)
        self.assertIn("needs: platform-contract", text)
        self.assertIn("always() && github.event_name == 'push'", text)
        self.assertIn("needs.platform-contract.result", text)
        self.assertIn("contents: write", text)
        self.assertIn("platform-contract-verified-${GITHUB_SHA}", text)
        self.assertIn("platform-contract-failed-${GITHUB_SHA}", text)
        self.assertIn("platform-contract-cell-${CELL_STATUS}-${MATRIX_OS}-jdk${MATRIX_JAVA}-${GITHUB_SHA}", text)
        self.assertIn("CELL_STATUS: ${{ job.status }}", text)
        self.assertIn("steps.quality_gate.outcome", text)
        self.assertIn("platform-contract-step-${STEP_OUTCOME}-${STEP_NAME}-${MATRIX_OS}-jdk${MATRIX_JAVA}-${GITHUB_SHA}", text)
        self.assertIn("platform-contract-gate-${GATE_STATUS}-${GATE_NAME}-${MATRIX_OS}-jdk${MATRIX_JAVA}-${GITHUB_SHA}", text)
        self.assertIn("platform-contract-benchmark-${BENCHMARK_STATUS}-${BENCHMARK_NAME}-${MATRIX_OS}-jdk${MATRIX_JAVA}-${GITHUB_SHA}", text)
        self.assertIn("platform-contract-smoke-${SMOKE_STATUS}-${SMOKE_CHECKPOINT}-${MATRIX_OS}-jdk${MATRIX_JAVA}-${GITHUB_SHA}", text)
        self.assertIn("steps.quality_gate.outcome == 'failure'", text)
        self.assertIn("steps.diag_jdeps_floor.outcome", text)
        self.assertIn("gate|quality-gate-report|missing", text)
        self.assertNotIn("continue-on-error", text)

    def test_run_cmd_preserves_unicode_space_and_metacharacter_arguments(self):
        with tempfile.TemporaryDirectory(prefix="jua 平台 ; ") as tmp:
            value = str(Path(tmp) / "参数 with spaces;not-shell")
            stdout, stderr, returncode = run_cmd(
                [sys.executable, "-c", "import sys; print(sys.argv[1])", value],
                timeout=10,
            )

        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stdout.strip(), value)

    def test_platform_workflow_has_no_shell_specific_absolute_tmp_path(self):
        text = (ROOT / ".github" / "workflows" / "platform-contract.yml").read_text(
            encoding="utf-8"
        )

        self.assertIsNone(re.search(r"(?:/tmp/|/private/tmp/|[A-Za-z]:\\\\)", text))


if __name__ == "__main__":
    unittest.main()
