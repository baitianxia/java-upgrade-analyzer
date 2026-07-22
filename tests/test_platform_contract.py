import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import compat  # noqa: E402
from compat import run_cmd  # noqa: E402


class PlatformContractTest(unittest.TestCase):
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
