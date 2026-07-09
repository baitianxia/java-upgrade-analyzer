import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import context_compress  # noqa: E402


class ContextCompressTest(unittest.TestCase):
    def test_summarize_step3_includes_risk_candidate_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            static_dir = report_dir / "evidence" / "static_scan"
            static_dir.mkdir(parents=True)
            (static_dir / "s3_risk_candidates.csv").write_text(
                "coord,api_name\nsample:dep,com.example.Api\nsample:dep,com.example.Other\n",
                encoding="utf-8",
            )

            summary = context_compress.summarize_step3(report_dir)

            self.assertEqual(summary["risk_candidate_count"], 2)

    def test_summarize_step5_preserves_skipped_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            step5_dir = report_dir / "evidence" / "call_chain"
            step5_dir.mkdir(parents=True)
            (step5_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "status": "skipped",
                        "skip_reason": "no_changed_apis",
                        "total_apis": 0,
                        "reachable": 0,
                        "uncertain": 0,
                        "not_analyzed": 0,
                        "not_found_in_static_analysis": 0,
                        "reachable_apis": [],
                        "uncertain_apis": [],
                        "not_analyzed_apis": [],
                        "not_found_apis": [],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            summary = context_compress.summarize_step5(report_dir)

            self.assertEqual(summary["status"], "skipped")
            self.assertEqual(summary["skip_reason"], "no_changed_apis")
            self.assertEqual(summary["modules_affected"], 0)

    def test_summarize_step5_derives_module_count_and_severity_breakdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            step5_dir = report_dir / "evidence" / "call_chain"
            by_module_dir = step5_dir / "by_module"
            by_module_dir.mkdir(parents=True)
            (step5_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "status": "done",
                        "skip_reason": "",
                        "total_apis": 4,
                        "reachable": 1,
                        "uncertain": 1,
                        "not_analyzed": 1,
                        "not_found_in_static_analysis": 1,
                        "reachable_apis": [{"api": "a", "severity": "P0"}],
                        "uncertain_apis": [{"api": "b", "severity": "P1"}],
                        "not_analyzed_apis": [{"api": "c", "severity": "P2"}],
                        "not_found_apis": [{"api": "d", "severity": "P1"}],
                        "quality_gate": {"needs_input": 1},
                        "user_conclusion_summary": {"已确认影响": 1},
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (by_module_dir / "app_impacts.json").write_text(
                json.dumps({"module": "app", "impacts": [{"api": "a"}]}, ensure_ascii=False),
                encoding="utf-8",
            )
            (by_module_dir / "empty_impacts.json").write_text(
                json.dumps({"module": "empty", "impacts": []}, ensure_ascii=False),
                encoding="utf-8",
            )

            summary = context_compress.summarize_step5(report_dir)

            self.assertEqual(summary["status"], "done")
            self.assertEqual(summary["modules_affected"], 1)
            self.assertEqual(summary["severity_breakdown"], {"P0": 1, "P1": 2, "P2": 1})
            self.assertEqual(summary["quality_gate"], {"needs_input": 1})
            self.assertEqual(summary["user_conclusion_summary"], {"已确认影响": 1})


if __name__ == "__main__":
    unittest.main()
