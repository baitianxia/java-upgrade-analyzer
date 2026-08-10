import math
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from binary_test_health_gate import (  # noqa: E402
    branch_probe,
    mutation_probe,
    repeat_health_probe,
)


class BinaryTestHealthGateTest(unittest.TestCase):
    def test_core_branch_alternatives_are_exercised(self):
        result = branch_probe()
        self.assertEqual(result["status"], "passed", result)
        self.assertGreaterEqual(result["coverage_ratio"], 0.80)

    def test_contract_mutants_are_killed(self):
        result = mutation_probe()
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["mutation_count"], result["killed_count"])

    def test_repeat_health_requires_same_test_count_and_time_budget(self):
        result = repeat_health_probe(
            ("tests.test_binary_tool_execution",),
            repeats=2,
            timeout_seconds=30,
        )
        self.assertEqual(result["status"], "passed", result)
        self.assertTrue(result["stable_test_count"])


if __name__ == "__main__":
    unittest.main()
