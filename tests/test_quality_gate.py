import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import quality_gate  # noqa: E402


class QualityGateTest(unittest.TestCase):
    def test_quick_and_step5_profiles_target_only_current_binary_contracts(self):
        for profile in ("quick", "step5"):
            command = quality_gate.command_for(profile)
            rendered = " ".join(command)
            self.assertIn("test_binary_", rendered)
            self.assertNotIn("s4_jar_compare", rendered)
            self.assertNotIn("s5_call_chain_engine_integrated", rendered)

    def test_release_discovers_all_current_tests(self):
        command = quality_gate.command_for("release")
        self.assertEqual(command[-3:], ["discover", "-s", "tests"])

    def test_dry_run_is_non_mutating_and_exposes_exact_command(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts/quality_gate.py"),
             "--profile", "step5", "--dry-run"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("tests.test_binary_pipeline", completed.stdout)
        self.assertNotIn("source_first", completed.stdout)


if __name__ == "__main__":
    unittest.main()
