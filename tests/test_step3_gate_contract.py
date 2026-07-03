import sys
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


if __name__ == "__main__":
    unittest.main()
