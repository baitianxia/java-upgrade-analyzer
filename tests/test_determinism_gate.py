import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from determinism_gate import (  # noqa: E402
    compare_semantic_runs,
    run_generated_determinism_matrix,
)


class DeterminismGateTest(unittest.TestCase):
    def test_generated_core_matrix_is_semantically_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = run_generated_determinism_matrix(
                ROOT,
                seed=41,
                report_root=Path(tmp),
                hash_seeds=(1, 7),
                workers=(1,),
                cache_modes=("cold",),
                order_modes=("normal", "reversed"),
            )

        self.assertEqual(report.status, "passed", report.first_difference)
        self.assertEqual(report.run_count, 4)

    def test_comparison_rejects_first_semantic_difference_with_reproducer(self):
        runs = [
            {"variant": {"hash_seed": 1}, "command": ["python", "one"], "ledger": {"apis": [{"identity": "a", "conclusion": "reachable"}], "edges": []}},
            {"variant": {"hash_seed": 7}, "command": ["python", "two"], "ledger": {"apis": [{"identity": "a", "conclusion": "uncertain"}], "edges": []}},
        ]

        report = compare_semantic_runs(runs)

        self.assertEqual(report.status, "failed")
        self.assertEqual(report.first_difference["path"], "apis[0].conclusion")
        self.assertEqual(report.reproduction_command, ("python", "two"))

    def test_generated_production_matrix_is_semantically_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = run_generated_determinism_matrix(
                ROOT,
                seed=41,
                report_root=Path(tmp),
                hash_seeds=(1, 7, 101),
                workers=(1, 2, 4),
                cache_modes=("cold", "warm"),
                order_modes=("normal", "reversed"),
            )

        self.assertEqual(report.status, "passed", report.first_difference)
        self.assertEqual(report.run_count, 36)


if __name__ == "__main__":
    unittest.main()
