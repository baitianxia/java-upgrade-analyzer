import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import quality_signal_audit  # noqa: E402


class QualitySignalAuditTest(unittest.TestCase):
    def test_normalize_quality_signal_defaults_blocking_from_type_and_severity(self):
        signal = quality_signal_audit.normalize_signal(
            {
                "signal_type": "capability_gap",
                "severity": "P1",
                "case": "dubbo",
                "step": "step5",
                "symbol": "org.example.Api.call(String)",
                "expected": "reachable from bytecode",
                "actual": "not_analyzed",
                "evidence": ["alerts.csv", "summary.json"],
                "fixture_status": "missing",
            }
        )

        self.assertEqual(signal.signal_type, "capability_gap")
        self.assertEqual(signal.severity, "P1")
        self.assertTrue(signal.blocking)
        self.assertEqual(signal.evidence, ("alerts.csv", "summary.json"))

    def test_performance_regression_is_blocking_when_severity_is_p1(self):
        signal = quality_signal_audit.normalize_signal(
            {
                "signal_type": "performance_regression",
                "severity": "P1",
                "case": "dubbo",
                "step": "step5",
                "expected": "elapsed <= 60s",
                "actual": "elapsed=92s",
            }
        )

        self.assertEqual(signal.signal_type, "performance_regression")
        self.assertTrue(signal.blocking)

    def test_project_asset_invalid_is_blocking_when_severity_is_p1(self):
        signal = quality_signal_audit.normalize_signal(
            {
                "signal_type": "project_asset_invalid",
                "severity": "P1",
                "case": "dubbo",
                "expected": "valid Git checkout with enough source files",
                "actual": "git metadata missing HEAD",
            }
        )

        self.assertEqual(signal.signal_type, "project_asset_invalid")
        self.assertTrue(signal.blocking)

    def test_audit_accepts_explicit_quality_signals_from_real_project_payload(self):
        payload = {
            "results": [
                {
                    "case": "dubbo",
                    "status": "passed",
                    "quality_signals": [
                        {
                            "signal_type": "evidence_weakness",
                            "severity": "P2",
                            "blocking": False,
                            "step": "step5",
                            "message": "path_text lacks consumer jar",
                        }
                    ],
                }
            ]
        }

        signals = quality_signal_audit.audit_real_project_payload(payload)

        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].signal_type, "evidence_weakness")
        self.assertFalse(signals[0].blocking)

    def test_audit_does_not_duplicate_legacy_summary_when_explicit_signals_exist(self):
        payload = {
            "results": [
                {
                    "case": "dubbo",
                    "status": "passed",
                    "summary": {"not_analyzed": 1},
                    "quality_signals": [
                        {
                            "signal_type": "capability_gap",
                            "severity": "P1",
                            "blocking": True,
                            "step": "step5",
                            "message": "dubbo summary has 1 not_analyzed item(s)",
                            "count": 1,
                        }
                    ],
                }
            ]
        }

        signals = quality_signal_audit.audit_real_project_payload(payload)

        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].signal_type, "capability_gap")

    def test_audit_does_not_add_generic_skip_when_runner_emits_specific_signal(self):
        payload = {
            "results": [
                {
                    "case": "dubbo",
                    "status": "skipped",
                    "reason": "project asset invalid",
                    "quality_signals": [
                        {
                            "signal_type": "project_asset_invalid",
                            "severity": "P1",
                            "blocking": True,
                            "message": "git checkout invalid",
                        }
                    ],
                }
            ]
        }

        signals = quality_signal_audit.audit_real_project_payload(payload)

        self.assertEqual([signal.signal_type for signal in signals], ["project_asset_invalid"])

    def test_audit_flags_non_gating_production_misses_and_not_analyzed(self):
        payload = {
            "status": "passed",
            "results": [
                {
                    "case": "commons-text",
                    "status": "passed",
                    "summary": {
                        "reachable": 5,
                        "uncertain": 0,
                        "not_analyzed": 1,
                        "not_found_in_static_analysis": 0,
                    },
                    "checks": [
                        {
                            "symbol": "org.apache.commons.lang3.ArrayUtils.isEmpty",
                            "gating": False,
                            "production_missing": 6,
                            "notes": "grep cannot distinguish overloads",
                        }
                    ],
                }
            ],
        }

        signals = quality_signal_audit.audit_real_project_payload(payload)
        kinds = {signal.kind for signal in signals}

        self.assertIn("summary_not_analyzed", kinds)
        self.assertIn("non_gating_production_missing", kinds)
        self.assertTrue(all(signal.severity == "P2" for signal in signals))

    def test_audit_flags_skipped_and_gating_misses_as_high(self):
        payload = {
            "results": [
                {"case": "dubbo", "status": "skipped", "reason": "project root missing"},
                {
                    "case": "seata",
                    "status": "failed",
                    "summary": {},
                    "checks": [
                        {
                            "symbol": "org.apache.seata.common.util.StringUtils.isBlank",
                            "gating": True,
                            "production_missing": 2,
                            "notes": "direct utility baseline",
                        }
                    ],
                },
            ],
        }

        signals = quality_signal_audit.audit_real_project_payload(payload)
        high_kinds = {signal.kind for signal in signals if signal.severity == "P1"}

        self.assertEqual(high_kinds, {"real_project_skipped", "gating_production_missing"})

    def test_cli_strict_exits_nonzero_when_signals_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "real.json"
            path.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "case": "commons-text",
                                "status": "passed",
                                "summary": {"not_analyzed": 0},
                                "checks": [
                                    {
                                        "symbol": "x",
                                        "gating": False,
                                        "production_missing": 1,
                                        "notes": "broad probe",
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "quality_signal_audit.py"),
                    str(path),
                    "--strict",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("non_gating_production_missing", completed.stdout)

    def test_cli_fail_on_blocking_exits_nonzero_only_for_blocking_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "real.json"
            path.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "case": "dubbo",
                                "status": "passed",
                                "quality_signals": [
                                    {
                                        "signal_type": "capability_gap",
                                        "severity": "P1",
                                        "blocking": True,
                                        "message": (
                                            "bytecode evidence exists but result is not_analyzed"
                                        ),
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "quality_signal_audit.py"),
                    str(path),
                    "--fail-on-blocking",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn('"blocking_signals": 1', completed.stdout)

    def test_summary_counts_blocking_fixture_debt(self):
        signals = [
            quality_signal_audit.normalize_signal(
                {
                    "signal_type": "correctness_failure",
                    "severity": "P1",
                    "blocking": True,
                    "case": "dubbo",
                    "fixture_status": "missing",
                }
            ),
            quality_signal_audit.normalize_signal(
                {
                    "signal_type": "capability_gap",
                    "severity": "P2",
                    "blocking": False,
                    "case": "seata",
                    "fixture_status": "planned",
                }
            ),
        ]

        summary = quality_signal_audit.summarize_signals(signals)

        self.assertEqual(summary["fixture_debt"], 1)


if __name__ == "__main__":
    unittest.main()
