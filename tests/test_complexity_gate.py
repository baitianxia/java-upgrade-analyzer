import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from complexity_gate import (  # noqa: E402
    REQUIRED_STAGE_METRICS,
    evaluate_scale_tiers,
    evaluate_production_stage_tiers,
    run_generated_scale_tiers,
    run_production_stage_scale_tiers,
)


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

    def _with_timing_trials(self, tier, elapsed_samples):
        trials = []
        for elapsed in elapsed_samples:
            trial_metrics = dict(tier["metrics"])
            trial_metrics["elapsed_sec"] = elapsed
            trial_metrics["per_api_latency_ms"] = (
                elapsed * 1000 / max(1, len(tier["truth_identities"]))
            )
            trials.append({
                "truth_identities": list(tier["truth_identities"]),
                "observed_identities": list(tier["observed_identities"]),
                "metrics": trial_metrics,
            })
        median_elapsed = sorted(elapsed_samples)[len(elapsed_samples) // 2]
        tier["metrics"]["elapsed_sec"] = median_elapsed
        tier["metrics"]["per_api_latency_ms"] = (
            median_elapsed * 1000 / max(1, len(tier["truth_identities"]))
        )
        tier["trials"] = trials
        return tier

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

    def test_complete_timing_trials_use_median_without_hiding_scope_loss(self):
        tiers = [
            self._with_timing_trials(self._tier(1), [0.10, 4.00, 0.11]),
            self._with_timing_trials(self._tier(2), [0.20, 0.21, 8.00]),
            self._with_timing_trials(self._tier(4), [0.40, 20.00, 0.42]),
        ]

        report = evaluate_scale_tiers(tiers, self.budgets)

        self.assertEqual(report.status, "passed", report.errors)
        tiers[-1]["trials"][1]["observed_identities"].pop()

        invalid = evaluate_scale_tiers(tiers, self.budgets)

        self.assertEqual(invalid.status, "invalid")
        self.assertIn("trial_scope_identity_mismatch:4:2", invalid.errors)

    def test_timing_trial_aggregate_must_be_the_observed_median(self):
        tier = self._with_timing_trials(
            self._tier(1), [0.10, 0.11, 9.00]
        )
        tier["metrics"]["elapsed_sec"] = 0.01

        report = evaluate_scale_tiers([tier], self.budgets)

        self.assertEqual(report.status, "invalid")
        self.assertIn("trial_elapsed_median_mismatch:1", report.errors)

    def test_two_slow_complete_trials_still_fail_the_ratio_budget(self):
        tiers = [
            self._with_timing_trials(self._tier(1), [0.10, 0.11, 5.00]),
            self._with_timing_trials(self._tier(2), [0.20, 0.21, 8.00]),
            self._with_timing_trials(self._tier(4), [0.40, 3.00, 3.10]),
        ]

        report = evaluate_scale_tiers(tiers, self.budgets)

        self.assertEqual(report.status, "failed")
        self.assertIn(
            "ratio_budget_exceeded:elapsed_sec:2->4", report.errors
        )

    def test_real_generated_collector_produces_valid_1x_2x_4x_tiers(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tiers = run_generated_scale_tiers(ROOT, Path(tmp), scales=(1, 2, 4))
            report = evaluate_scale_tiers(tiers, self.budgets)

        self.assertEqual(report.status, "passed", report.errors)
        self.assertEqual([tier["scale"] for tier in tiers], [1, 2, 4])
        self.assertTrue(all(tier["metrics"]["parsed_classes"] > 0 for tier in tiers))
        for tier in tiers:
            self.assertEqual(len(tier["trials"]), 3)
            samples = [
                trial["metrics"]["elapsed_sec"] for trial in tier["trials"]
            ]
            self.assertEqual(
                tier["metrics"]["elapsed_sec"], sorted(samples)[1]
            )
            self.assertTrue(all(
                set(trial["truth_identities"])
                == set(trial["observed_identities"])
                for trial in tier["trials"]
            ))

    def test_production_scale_tiers_measure_step1_step4_and_step5_separately(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tiers = run_production_stage_scale_tiers(
                ROOT, Path(tmp), scales=(1, 2, 4)
            )

        self.assertEqual([tier["scale"] for tier in tiers], [1, 2, 4])
        for tier in tiers:
            self.assertEqual(set(tier["stages"]), {"step1", "step4", "step5"})
            for stage in tier["stages"].values():
                self.assertEqual(
                    set(stage["truth_identities"]),
                    set(stage["observed_identities"]),
                )
                self.assertEqual(stage["scope_count"], tier["scale"])
                self.assertGreaterEqual(stage["elapsed_sec"], 0)
                self.assertTrue(
                    set(REQUIRED_STAGE_METRICS).issubset(stage["metrics"])
                )
                self.assertEqual(len(stage["trials"]), 3)
                samples = [
                    trial["metrics"]["elapsed_sec"]
                    for trial in stage["trials"]
                ]
                self.assertEqual(stage["elapsed_sec"], sorted(samples)[1])
        verdict = evaluate_production_stage_tiers(tiers, self.budgets)
        self.assertEqual(verdict.status, "passed", verdict.errors)

    def test_stage_complexity_is_invalid_before_timing_when_step4_scope_is_lost(self):
        stages = {
            name: {
                "truth_identities": [f"{name}-api"],
                "observed_identities": [f"{name}-api"],
                "scope_count": 1,
                "elapsed_sec": 0.1,
                "metrics": {
                    name: ([] if name == "duplicate_work_keys" else 0)
                    for name in REQUIRED_STAGE_METRICS
                },
            }
            for name in ("step1", "step4", "step5")
        }
        stages["step4"]["observed_identities"] = []
        stages["step4"]["scope_count"] = 0

        verdict = evaluate_production_stage_tiers(
            [{"scale": 1, "stages": stages}], self.budgets
        )

        self.assertEqual(verdict.status, "invalid")
        self.assertIn("stage_scope_identity_mismatch:step4:1", verdict.errors)


if __name__ == "__main__":
    unittest.main()
