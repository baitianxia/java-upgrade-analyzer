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
            self.assertIn("tests.test_binary_result_truth", rendered)
            self.assertIn("tests.test_blackbox_harness", rendered)
            self.assertIn("tests.test_test_trust_gate", rendered)
            self.assertIn("tests.blackbox.test_public_binary_cli", rendered)
            self.assertIn("tests.test_ci_quality_contract", rendered)
            self.assertIn("tests.test_platform_contract", rendered)
            self.assertNotIn("s4_jar_compare", rendered)
            self.assertNotIn("s5_call_chain_engine_integrated", rendered)

    def test_release_discovers_all_current_tests(self):
        command = quality_gate.command_for("release")
        self.assertTrue(command[1].endswith("test_suite_runner.py"))
        self.assertEqual(command[-2:], ["--suite", "all"])
        self.assertTrue(
            quality_gate.test_health_command()[-1].endswith(
                "binary_test_health_gate.py"
            )
        )
        real = quality_gate.real_project_command(
            "/tmp/audit", cache_root="/tmp/cache", jdk_home="/tmp/jdk"
        )
        self.assertTrue(real[1].endswith("binary_real_project_guard.py"))
        self.assertIn("--download", real)
        performance = quality_gate.performance_command("/tmp/audit")
        self.assertTrue(performance[1].endswith("binary_performance_gate.py"))
        self.assertIn("--gate", performance)
        matrix = quality_gate.real_project_commands(
            "/tmp/audit", cache_root="/tmp/cache", jdk_home="/tmp/jdk"
        )
        self.assertGreaterEqual(len(matrix), 3)
        self.assertTrue(all("--manifest" in item for item in matrix))

    def test_named_test_suites_have_stable_quality_gate_profiles(self):
        for profile in ("blackbox", "whitebox", "performance"):
            command = quality_gate.command_for(profile)
            self.assertTrue(command[1].endswith("test_suite_runner.py"))
            self.assertEqual(command[-2:], ["--suite", profile])

    def test_release_authorization_requires_every_capability_replacement(self):
        migration = quality_gate.capability_migration_status(ROOT)
        self.assertTrue(migration["registry_structurally_valid"], migration["issues"])
        self.assertEqual(migration["release_status"], "passed")
        self.assertEqual(migration["incomplete_families"], [])
        self.assertEqual(migration["incomplete_mechanisms"], [])

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
