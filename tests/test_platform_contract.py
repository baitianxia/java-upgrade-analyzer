import re
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from compat import run_cmd  # noqa: E402


class PlatformContractTest(unittest.TestCase):
    def test_workflow_declares_mandatory_os_jdk_tool_and_evidence_matrix(self):
        workflow = ROOT / ".github" / "workflows" / "platform-contract.yml"
        text = workflow.read_text(encoding="utf-8")

        for value in ("ubuntu-latest", "macos-latest", "windows-latest"):
            self.assertIn(value, text)
        self.assertRegex(text, r'java:\s*\["11",\s*"17",\s*"21"\]')
        self.assertIn('python-version: "3.12"', text)
        self.assertIn("mvn -version", text)
        self.assertIn("timeout-minutes:", text)
        self.assertIn("actions/upload-artifact@v4", text)
        self.assertIn("platform-contract.json", text)
        self.assertIn("push:", text)
        self.assertIn('- "main"', text)
        self.assertIn('- "codex/**"', text)
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
