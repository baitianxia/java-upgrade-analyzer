import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


class Step3SourceUsageTest(unittest.TestCase):
    def test_no_source_runs_binary_only_scans_and_records_coverage_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "static_scan"
            coverage = Path(tmp) / "s3_coverage.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT_DIR / "scripts" / "s3_scan.py"),
                    "--all",
                    "--no-source",
                    "--output-dir",
                    str(output),
                    "--coverage-output",
                    str(coverage),
                ],
                cwd=ROOT_DIR,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(coverage.read_text(encoding="utf-8"))
            self.assertEqual(payload["source_usage_decision"], "skip_source")
            self.assertEqual(payload["source_coverage_status"], "not_provided")
            self.assertEqual(
                payload["executed_scans"],
                ["dep_compat", "dep_classfile"],
            )
            self.assertTrue((output / "s3_dependency_compat.csv").is_file())
            self.assertTrue((output / "s3_dependency_classfile.csv").is_file())
            self.assertFalse((output / "s3_jdk_removed_api.csv").exists())

    def test_dependency_source_only_does_not_claim_user_skipped_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "static_scan"
            coverage = Path(tmp) / "s3_coverage.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT_DIR / "scripts" / "s3_scan.py"),
                    "--all",
                    "--no-business-source",
                    "--output-dir",
                    str(output),
                    "--coverage-output",
                    str(coverage),
                ],
                cwd=ROOT_DIR,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(coverage.read_text(encoding="utf-8"))
            self.assertEqual(payload["source_usage_decision"], "use_source")
            self.assertEqual(
                payload["source_coverage_status"], "dependency_source_only"
            )


if __name__ == "__main__":
    unittest.main()
