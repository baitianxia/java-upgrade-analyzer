import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import gate  # noqa: E402
import run_step  # noqa: E402


class Step3GateContractTest(unittest.TestCase):
    def test_gate_scan_requires_risk_candidates_when_dependency_inputs_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            (report_dir / "s2_context.json").write_text("{}", encoding="utf-8")
            (report_dir / "s1_dep_changes.csv").write_text("coord\nsample:demo\n", encoding="utf-8")
            (report_dir / "s3_dependency_compat.csv").write_text("坐标\n", encoding="utf-8")
            (report_dir / "s3_dependency_classfile.csv").write_text("坐标\n", encoding="utf-8")

            with self.assertRaises(SystemExit) as ctx:
                gate.gate_scan(str(report_dir))

            self.assertEqual(ctx.exception.code, 1)

    def test_step3_manifest_declares_risk_candidates_output(self):
        manifest = run_step.read_json(run_step.DEFAULT_MANIFEST)
        step3 = next(item for item in manifest["steps"] if item["id"] == "step3")
        self.assertIn("s3_risk_candidates.csv", step3["outputs"])


if __name__ == "__main__":
    unittest.main()
