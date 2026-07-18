import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from complexity_gate import evaluate_scale_tiers, run_generated_scale_tiers  # noqa: E402


class ComplexityGateTest(unittest.TestCase):
    def setUp(self):
        self.budgets = json.loads(
            (ROOT / "tests" / "fixtures" / "complexity_budgets.json").read_text(
                encoding="utf-8"
            )
        )

    def _tier(self, scale, *, elapsed=None, duplicate_keys=()):
        identities = [f"api-{index}" for index in range(scale)]
        return {
            "scale": scale,
            "truth_identities": identities,
            "observed_identities": identities,
            "metrics": {
                "elapsed_sec": elapsed if elapsed is not None else scale * 0.1,
                "peak_rss_mb": 50 + scale,
                "temporary_bytes": scale * 100,
                "archive_scans": scale,
                "parsed_classes": scale * 10,
                "javap_calls": scale,
                "cache_hits": 0,
                "per_api_latency_ms": 100,
                "duplicate_work_keys": list(duplicate_keys),
            },
        }

    def test_accepts_linear_tiers_only_after_correctness_scope_matches(self):
        report = evaluate_scale_tiers(
            [self._tier(1), self._tier(2), self._tier(4)], self.budgets
        )

        self.assertEqual(report.status, "passed")

    def test_scope_loss_invalidates_performance_before_budget_evaluation(self):
        tiers = [self._tier(1), self._tier(2), self._tier(4, elapsed=0.001)]
        tiers[-1]["observed_identities"] = tiers[-1]["observed_identities"][:-1]

        report = evaluate_scale_tiers(tiers, self.budgets)

        self.assertEqual(report.status, "invalid")
        self.assertIn("scope_identity_mismatch:4", report.errors)

    def test_rejects_superlinear_growth_and_duplicate_archive_scan(self):
        tiers = [self._tier(1), self._tier(2), self._tier(4, elapsed=3.0, duplicate_keys=("step5:app.jar",))]

        report = evaluate_scale_tiers(tiers, self.budgets)

        self.assertEqual(report.status, "failed")
        self.assertIn("ratio_budget_exceeded:elapsed_sec:2->4", report.errors)
        self.assertIn("duplicate_work:step5:app.jar", report.errors)

    def test_real_generated_collector_produces_valid_1x_2x_4x_tiers(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tiers = run_generated_scale_tiers(ROOT, Path(tmp), scales=(1, 2, 4))
            report = evaluate_scale_tiers(tiers, self.budgets)

        self.assertEqual(report.status, "passed", report.errors)
        self.assertEqual([tier["scale"] for tier in tiers], [1, 2, 4])
        self.assertTrue(all(tier["metrics"]["parsed_classes"] > 0 for tier in tiers))


if __name__ == "__main__":
    unittest.main()
