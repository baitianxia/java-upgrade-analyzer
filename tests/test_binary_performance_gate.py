import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
from binary_performance_gate import evaluate_gate, run_benchmark  # noqa: E402


class BinaryPerformanceGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("java") or not shutil.which("javac"):
            raise unittest.SkipTest("full JDK required")
        try:
            binary_asm_helper.resolve_asm_jar()
        except Exception as error:
            raise unittest.SkipTest(str(error)) from error

    def test_small_fixture_enforces_class_conservation_and_zero_warm_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_benchmark(
                Path(tmp),
                jar_count=2,
                classes_per_jar=3,
                warm_samples=1,
                include_legacy=False,
            )

        self.assertEqual(result["measurement_protocol"]["class_count"], 6)
        self.assertEqual(result["measurements"]["cold"]["counts"]["classes"], 6)
        self.assertGreater(
            result["measurements"]["cold"]["parser_invocations"], 0
        )
        self.assertEqual(
            result["measurements"]["warm_runs"][0]["parser_invocations"], 0
        )
        self.assertEqual(
            result["measurements"]["warm_runs"][0]["cache_hits"], 2
        )
        protocol = result["measurement_protocol"]
        cold = result["measurements"]["cold"]
        gate = {
            "measurement_protocol": {
                "machine_identity": protocol["machine_identity"],
                "dataset_identity": protocol["dataset_identity"],
                "jar_count": 2,
                "class_count": 6,
            },
            "thresholds": {
                "cold_end_to_end_seconds": cold["end_to_end_seconds"] * 2,
                "warm_end_to_end_p95_seconds": result["measurements"]["warm_end_to_end_p95_seconds"] * 2,
                "peak_rss_bytes": result["measurements"]["peak_rss_bytes"] * 2,
                "disk_bytes": result["measurements"]["disk_bytes"] * 2,
                "cold_relative_legacy_ratio": 10,
                "warm_relative_legacy_ratio": 10,
                "stage_p95_seconds": {
                    "inventory": 10,
                    "parse_and_cache": 10,
                    "db_write_and_index": 10,
                    "batch_query_10000": 10,
                    "report_10000": 10,
                },
            },
        }
        # The small unit fixture intentionally skips the legacy comparator;
        # evaluation must fail rather than interpreting missing relative data as pass.
        self.assertEqual(evaluate_gate(result, gate)["status"], "failed")


if __name__ == "__main__":
    unittest.main()
