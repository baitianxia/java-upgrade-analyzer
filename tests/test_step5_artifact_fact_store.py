import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from real_project_regression import (  # noqa: E402
    cold_run_metrics,
    step5_result_contract,
)


class Step5ColdRunContractTest(unittest.TestCase):
    def _write_report(self, root, *, status="reachable", path_text="A -> B"):
        root = Path(root)
        call_chain = root / "evidence" / "call_chain"
        call_chain.mkdir(parents=True)
        (call_chain / "summary.json").write_text(
            json.dumps({
                "generated_at": "volatile",
                "reachable": int(status == "reachable"),
                "meta": {"graph_stats": {"step5_perf": {"trace": {"elapsed_sec": 1.0}}}},
            }),
            encoding="utf-8",
        )
        with (call_chain / "alerts.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "api_id", "api_status", "path_text", "evidence_files",
            ])
            writer.writeheader()
            writer.writerow({
                "api_id": "API-1",
                "api_status": status,
                "path_text": path_text,
                "evidence_files": str(root / "current.jar!/example/A.class"),
            })

    def test_contract_ignores_report_root_and_runtime_telemetry(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            self._write_report(first)
            self._write_report(second)

            self.assertEqual(
                step5_result_contract(Path(first)),
                step5_result_contract(Path(second)),
            )

    def test_contract_changes_when_path_changes(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            self._write_report(first, path_text="A -> B")
            self._write_report(second, path_text="A -> C -> B")

            self.assertNotEqual(
                step5_result_contract(Path(first)),
                step5_result_contract(Path(second)),
            )

    def test_contract_rejects_missing_step5_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                step5_result_contract(Path(tmp))

    def test_cold_run_metrics_reads_utf8_bom_timing_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            timing = Path(tmp) / ".runtime" / "observability" / "step5_timing.csv"
            timing.parent.mkdir(parents=True)
            timing.write_text(
                "\ufeffsection,metric,value\nartifact_facts,inventory_builds,2\n",
                encoding="utf-8",
            )

            self.assertEqual(
                cold_run_metrics(Path(tmp)),
                {"artifact_facts.inventory_builds": "2"},
            )


if __name__ == "__main__":
    unittest.main()
