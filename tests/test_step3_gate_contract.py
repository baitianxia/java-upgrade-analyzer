import sys
import json
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import gate  # noqa: E402
import run_step  # noqa: E402


class Step3GateContractTest(unittest.TestCase):
    def test_gate_scan_does_not_require_legacy_risk_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            (report_dir / "s2_context.json").write_text("{}", encoding="utf-8")
            (report_dir / "s1_dep_changes.csv").write_text("coord\nsample:demo\n", encoding="utf-8")
            (report_dir / "s3_dependency_compat.csv").write_text("坐标\n", encoding="utf-8")
            (report_dir / "s3_dependency_classfile.csv").write_text("坐标\n", encoding="utf-8")

            gate.gate_scan(str(report_dir))

    def test_step3_manifest_does_not_declare_risk_candidates_output(self):
        manifest = run_step.read_json(run_step.DEFAULT_MANIFEST)
        step3 = next(item for item in manifest["steps"] if item["id"] == "step3")
        self.assertNotIn("s3_risk_candidates.csv", step3["outputs"])

    def test_gate_requires_database_contract_evidence_when_two_sided_artifacts_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            dependencies = report_dir / "evidence" / "dependencies"
            static_scan = report_dir / "evidence" / "static_scan"
            dependencies.mkdir(parents=True)
            static_scan.mkdir(parents=True)
            (dependencies / "dependency_jars.json").write_text(
                json.dumps({"schema": "java-upgrade-analyzer.step1-dependency-jars.v3"}),
                encoding="utf-8",
            )

            with self.assertRaises(SystemExit):
                gate.gate_scan(str(report_dir))

            (static_scan / "s3_database_contract_changes.csv").write_text(
                (
                    "依赖包,变化类型,契约类型,可信度,表,列,契约位置,"
                    "语句或字段,人工复核建议\n"
                ),
                encoding="utf-8",
            )
            (static_scan / "s3_database_contract_summary.json").write_text(
                json.dumps({
                    "schema": "java-upgrade-analyzer.database-contract-changes.v1",
                    "coverage_status": "complete",
                    "change_count": 0,
                }),
                encoding="utf-8",
            )
            (static_scan / "s3_database_contract_changes.md").write_text(
                "# 数据库契约变化明细\n", encoding="utf-8"
            )
            gate.gate_scan(str(report_dir))

            (static_scan / "s3_database_contract_summary.json").write_text(
                "{}", encoding="utf-8"
            )
            with self.assertRaises(SystemExit):
                gate.gate_scan(str(report_dir))


if __name__ == "__main__":
    unittest.main()
