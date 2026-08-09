import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import accuracy_benchmark  # noqa: E402


class AccuracyBenchmarkTest(unittest.TestCase):
    def test_categories_cover_binary_facts_reconciliation_decision_and_trace(self):
        for name in (
            "artifact_facts", "runtime_reconciliation",
            "decision_projection", "runtime_bytecode_reachability",
        ):
            self.assertIn(name, accuracy_benchmark.CATEGORIES)
            self.assertTrue(accuracy_benchmark.CATEGORIES[name])

    def test_removed_engine_category_aliases_are_absent(self):
        for name in ("jdeps_floor", "indirect_usage", "alerts_ledger"):
            self.assertNotIn(name, accuracy_benchmark.CATEGORIES)

    def test_dry_run_exposes_selected_current_test_modules(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts/accuracy_benchmark.py"),
             "--category", "runtime_bytecode_reachability", "--dry-run"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("tests.test_binary_pipeline", completed.stdout)


if __name__ == "__main__":
    unittest.main()
