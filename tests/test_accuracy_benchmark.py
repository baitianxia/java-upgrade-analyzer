import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import accuracy_benchmark  # noqa: E402


class AccuracyBenchmarkTest(unittest.TestCase):
    def test_core_profile_contains_non_negotiable_accuracy_contracts(self):
        categories = accuracy_benchmark.build_plan("core")
        names = [category.name for category in categories]

        self.assertIn("jdeps_floor", names)
        self.assertIn("runtime_bytecode_reachability", names)
        self.assertIn("indirect_usage", names)
        self.assertIn("alerts_ledger", names)

    def test_step5_profile_is_broader_than_core_and_has_no_duplicate_tests(self):
        core = accuracy_benchmark.build_plan("core")
        step5 = accuracy_benchmark.build_plan("step5")

        core_names = {category.name for category in core}
        step5_names = {category.name for category in step5}
        self.assertLess(core_names, step5_names)

        test_ids = [test for category in step5 for test in category.tests]
        self.assertEqual(len(test_ids), len(set(test_ids)))
        accuracy_benchmark.validate_matrix()

    def test_dry_run_outputs_structured_plan_without_running_unittest(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "accuracy_benchmark.py"),
                "--profile",
                "core",
                "--dry-run",
            ],
            cwd=str(ROOT),
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)

        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["profile"], "core")
        self.assertGreaterEqual(payload["total_tests"], 20)
        self.assertEqual(
            [category["name"] for category in payload["categories"]],
            ["jdeps_floor", "runtime_bytecode_reachability", "indirect_usage", "alerts_ledger"],
        )

    def test_json_out_is_written_for_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "accuracy.json"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "accuracy_benchmark.py"),
                    "--profile",
                    "step5",
                    "--dry-run",
                    "--json-out",
                    str(output),
                ],
                cwd=str(ROOT),
                check=True,
                capture_output=True,
                text=True,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload["profile"], "step5")
        self.assertGreater(len(payload["categories"]), 4)

    def test_single_category_mode_is_available_for_platform_diagnostics(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "accuracy_benchmark.py"),
                "--category",
                "alerts_ledger",
                "--dry-run",
            ],
            cwd=str(ROOT),
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)

        self.assertEqual(
            [category["name"] for category in payload["categories"]],
            ["alerts_ledger"],
        )


if __name__ == "__main__":
    unittest.main()
