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
        self.assertTrue(all(signal.severity == "medium" for signal in signals))

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
        high_kinds = {signal.kind for signal in signals if signal.severity == "high"}

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


if __name__ == "__main__":
    unittest.main()
