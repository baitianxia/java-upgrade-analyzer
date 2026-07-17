import csv
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s3_scan  # noqa: E402
import s4_contract  # noqa: E402


class Step3CandidateOutputsTest(unittest.TestCase):
    @staticmethod
    def _prepare_current_artifact(report_dir, coord="sample:demo", version="2.0.0"):
        dependencies_dir = report_dir / "evidence" / "dependencies"
        dependencies_dir.mkdir(parents=True, exist_ok=True)
        nested_buffer = tempfile.SpooledTemporaryFile()
        with zipfile.ZipFile(nested_buffer, "w") as nested:
            nested.writestr("com/lib/TargetType.class", b"")
        nested_buffer.seek(0)
        nested_bytes = nested_buffer.read()
        nested_buffer.close()
        lib_entry = f"BOOT-INF/lib/demo-{version}.jar"
        artifact_path = dependencies_dir / "current.jar"
        with zipfile.ZipFile(artifact_path, "w") as outer:
            outer.writestr(lib_entry, nested_bytes)
        (dependencies_dir / "build_provenance.json").write_text(
            json.dumps({"sides": [{"side": "current", "artifact_path": str(artifact_path)}]}),
            encoding="utf-8",
        )
        (dependencies_dir / "deps_current_resolved.csv").write_text(
            "entry_id,lib_entry,lib_name,coord,version,scope,resolution_status\n"
            f"{lib_entry},{lib_entry},demo-{version}.jar,{coord},{version},runtime,resolved\n",
            encoding="utf-8",
        )

    def test_cleanup_step3_outputs_removes_candidate_artifacts_and_preserves_other_summary_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / ".upgrade-report"
            report_dir.mkdir(parents=True)
            aggregate_path = report_dir / s4_contract.STEP3_RISK_CANDIDATES_FILE
            aggregate_path.write_text("coord\n", encoding="utf-8")
            per_dep_dir = s4_contract.get_per_dependency_dir(str(report_dir), "sample:demo")
            per_dep_dir.mkdir(parents=True, exist_ok=True)
            candidate_hits_path = per_dep_dir / s4_contract.PER_DEPENDENCY_CANDIDATE_HITS_FILE
            candidate_hits_path.write_text("coord\nsample:demo\n", encoding="utf-8")
            summary_path = per_dep_dir / s4_contract.PER_DEPENDENCY_SUMMARY_FILE
            summary_path.write_text(
                json.dumps(
                    {
                        "coord": "sample:demo",
                        "step3": {"candidate_hit_count": 1},
                        "step4": {"target_count": 2},
                        "artifacts": {
                            "candidate_hits_csv": str(candidate_hits_path),
                            "resolved_targets_csv": "resolved_targets.csv",
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            s3_scan.cleanup_step3_outputs(str(report_dir))

            self.assertFalse(aggregate_path.exists())
            self.assertFalse(candidate_hits_path.exists())
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertNotIn("step3", summary)
            self.assertEqual(summary["step4"]["target_count"], 2)
            self.assertNotIn("candidate_hits_csv", summary["artifacts"])
            self.assertEqual(summary["artifacts"]["resolved_targets_csv"], "resolved_targets.csv")

    def test_build_per_dependency_candidate_outputs_writes_per_dependency_and_aggregate_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / ".upgrade-report"
            report_dir.mkdir(parents=True)
            source_dir = root / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            dep_changes_path = report_dir / "s1_dep_changes.csv"
            self._prepare_current_artifact(report_dir)
            (source_dir / "Entry.java").write_text(
                "class Entry { Class<?> type = com.lib.TargetType.class; }\n",
                encoding="utf-8",
            )
            dep_changes_path.write_text(
                "coord,old_version,new_version,change_type\nsample:demo,1.0.0,2.0.0,小版本升级\n",
                encoding="utf-8",
            )

            hit_count = s3_scan.build_per_dependency_candidate_outputs(
                [str(source_dir)],
                str(dep_changes_path),
                str(report_dir),
            )

            self.assertEqual(hit_count, 1)
            per_dep_dir = s4_contract.get_per_dependency_dir(str(report_dir), "sample:demo")
            candidate_hits_path = per_dep_dir / s4_contract.PER_DEPENDENCY_CANDIDATE_HITS_FILE
            summary_path = per_dep_dir / s4_contract.PER_DEPENDENCY_SUMMARY_FILE
            aggregate_path = report_dir / s4_contract.STEP3_RISK_CANDIDATES_FILE

            with candidate_hits_path.open(encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["candidate_bucket"], "system_source")
            self.assertEqual(rows[0]["candidate_kind"], "class_literal")
            self.assertEqual(rows[0]["matched_class"], "com.lib.TargetType")

            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["step3"]["candidate_hit_count"], 1)
            self.assertEqual(summary["step3"]["bucket_counts"], {"system_source": 1})
            self.assertTrue(summary["artifacts"]["candidate_hits_csv"].endswith("candidate_hits.csv"))

            with aggregate_path.open(encoding="utf-8-sig", newline="") as f:
                aggregate_rows = list(csv.DictReader(f))
            self.assertEqual(len(aggregate_rows), 1)
            self.assertEqual(aggregate_rows[0]["coord"], "sample:demo")

    def test_build_per_dependency_candidate_outputs_merges_dependency_without_source_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / ".upgrade-report"
            report_dir.mkdir(parents=True)
            dep_changes_path = report_dir / "s1_dep_changes.csv"
            dep_compat_path = report_dir / "s3_dependency_compat.csv"
            self._prepare_current_artifact(report_dir)
            dep_changes_path.write_text(
                "coord,old_version,new_version,change_type\nsample:demo,1.0.0,2.0.0,小版本升级\n",
                encoding="utf-8",
            )
            dep_compat_path.write_text(
                "坐标,版本,scope,风险类型,证据,jar路径\n"
                "sample:demo,1.0.0,compile,reflection_string,Class.forName(\"com.lib.TargetType\"),/tmp/demo.jar\n",
                encoding="utf-8",
            )

            hit_count = s3_scan.build_per_dependency_candidate_outputs(
                [],
                str(dep_changes_path),
                str(report_dir),
            )

            self.assertEqual(hit_count, 1)
            per_dep_dir = s4_contract.get_per_dependency_dir(str(report_dir), "sample:demo")
            candidate_hits_path = per_dep_dir / s4_contract.PER_DEPENDENCY_CANDIDATE_HITS_FILE
            with candidate_hits_path.open(encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(rows[0]["candidate_bucket"], "dependency_without_source")
            self.assertEqual(rows[0]["reason_code"], "RESOURCE_OR_REFLECTION")
            self.assertEqual(rows[0]["evidence_level"], "weak")


if __name__ == "__main__":
    unittest.main()
