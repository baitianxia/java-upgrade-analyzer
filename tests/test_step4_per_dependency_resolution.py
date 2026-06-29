import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s4_jar_compare as step4  # noqa: E402


class Step4PerDependencyResolutionTest(unittest.TestCase):
    def test_write_per_dependency_outputs_generates_three_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            dep_row = {
                "coord": "com.example:legacy-lib",
                "change_type": "移除",
                "old_version": "1.0.0",
                "new_version": "-",
                "base_coord": "com.example:legacy-lib",
            }
            raw_rows = [
                {
                    "coord": "com.example:legacy-lib",
                    "old_version": "1.0.0",
                    "new_version": "-",
                    "change_type": "REMOVED",
                    "api_name": "com.example.LegacyApi.run",
                    "api_simple": "run",
                    "symbol_kind": "method",
                    "api_signature": "()",
                    "confirmed": "true",
                    "severity": "P0",
                    "source": "old_jar",
                }
            ]

            result = step4.write_per_dependency_outputs(
                report_dir=str(report_dir),
                dep_row=dep_row,
                raw_rows=raw_rows,
                removed_jar_export={
                    "old_coord": "com.example:legacy-lib",
                    "old_jar": "/tmp/legacy-lib-1.0.0.jar",
                },
            )

            per_dependency_dir = Path(result["per_dependency_dir"])
            removed_symbols = per_dependency_dir / step4.PER_DEPENDENCY_REMOVED_JAR_SYMBOLS_FILE
            resolved_targets = per_dependency_dir / step4.PER_DEPENDENCY_RESOLVED_TARGETS_FILE
            summary_path = per_dependency_dir / step4.PER_DEPENDENCY_SUMMARY_FILE

            self.assertTrue(removed_symbols.exists())
            self.assertTrue(resolved_targets.exists())
            self.assertTrue(summary_path.exists())
            self.assertIn("com.example.LegacyApi.run", removed_symbols.read_text(encoding="utf-8"))
            self.assertIn("com.example.LegacyApi.run", resolved_targets.read_text(encoding="utf-8"))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["step4"]["raw_target_count"], 1)
            self.assertEqual(summary["step4"]["resolved_target_count"], 1)
            self.assertEqual(summary["step4"]["removed_jar"]["old_coord"], "com.example:legacy-lib")


if __name__ == "__main__":
    unittest.main()
