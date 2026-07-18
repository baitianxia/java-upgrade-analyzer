import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from real_project_regression import canonical_step5_result_fingerprint  # noqa: E402


class Step5ResultFingerprintTest(unittest.TestCase):
    def _write_report(self, root, *, status="reachable", generated_at="now", rss=100.0):
        call_chain = root / "evidence" / "call_chain"
        call_chain.mkdir(parents=True)
        (call_chain / "summary.json").write_text(
            json.dumps({
                "generated_at": generated_at,
                "reachable": 1 if status == "reachable" else 0,
                "not_analyzed": 1 if status == "not_analyzed" else 0,
                "meta": {
                    "graph_stats": {
                        "step5_perf": {"main": {"peak_rss_mb": rss}},
                    },
                },
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        with (call_chain / "alerts.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "api_id", "api_status", "path_id", "path_text", "evidence_files",
            ])
            writer.writeheader()
            writer.writerow({
                "api_id": "API-1",
                "api_status": status,
                "path_id": "PATH-1",
                "path_text": "app.Entry.run() -> vendor.Target.call()",
                "evidence_files": str(root / "artifact.jar!/app/Entry.class"),
            })

    def test_ignores_only_volatile_runtime_values_and_report_root(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_root = Path(first)
            second_root = Path(second)
            self._write_report(first_root, generated_at="one", rss=100.0)
            self._write_report(second_root, generated_at="two", rss=250.0)

            self.assertEqual(
                canonical_step5_result_fingerprint(first_root),
                canonical_step5_result_fingerprint(second_root),
            )

    def test_changes_when_analysis_status_changes(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_root = Path(first)
            second_root = Path(second)
            self._write_report(first_root, status="reachable")
            self._write_report(second_root, status="not_analyzed")

            self.assertNotEqual(
                canonical_step5_result_fingerprint(first_root),
                canonical_step5_result_fingerprint(second_root),
            )


if __name__ == "__main__":
    unittest.main()
