import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_performance_gate  # noqa: E402
from binary_performance_gate import evaluate_gate, run_benchmark  # noqa: E402


class BinaryPerformanceGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("java") or not shutil.which("javac"):
            raise unittest.SkipTest("full JDK required")
        try:
            binary_asm_helper.resolve_asm_jar()
        except Exception as error:
            raise unittest.SkipTest(str(error)) from error

    def test_small_fixture_enforces_class_conservation_and_zero_warm_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_benchmark(
                Path(tmp),
                jar_count=2,
                classes_per_jar=3,
                warm_samples=1,
                include_legacy=False,
            )

        self.assertEqual(result["measurement_protocol"]["class_count"], 6)
        self.assertEqual(result["measurements"]["cold"]["counts"]["classes"], 6)
        self.assertGreater(
            result["measurements"]["cold"]["parser_invocations"], 0
        )
        self.assertEqual(
            result["measurements"]["warm_runs"][0]["parser_invocations"], 0
        )
        self.assertEqual(
            result["measurements"]["warm_runs"][0]["cache_hits"], 2
        )
        full_pipeline = result["measurements"]["full_pipeline_probe"]
        self.assertEqual(full_pipeline["status"], "passed")
        self.assertEqual(full_pipeline["jar_count"], 2)
        self.assertEqual(full_pipeline["class_count"], 6)
        self.assertEqual(full_pipeline["base_class_count"], 6)
        self.assertEqual(full_pipeline["current_class_count"], 6)
        self.assertEqual(full_pipeline["validation_issue_count"], 0)
        self.assertEqual(full_pipeline["authoritative_change_fact_count"], 0)
        self.assertEqual(full_pipeline["formal_api_result_count"], 0)
        self.assertGreater(full_pipeline["peak_rss_bytes"], 0)
        self.assertIn(
            "target_independent_runtime_reconciliation",
            full_pipeline["phase_seconds"],
        )
        self.assertIn("independent_validation", full_pipeline["phase_seconds"])
        self.assertEqual(
            set(full_pipeline["phase_peak_rss_bytes"]),
            set(full_pipeline["phase_seconds"]),
        )
        self.assertLessEqual(
            max(full_pipeline["phase_peak_rss_bytes"].values()),
            full_pipeline["peak_rss_bytes"],
        )
        changed_full_pipeline = result["measurements"][
            "changed_full_pipeline_probe"
        ]
        self.assertEqual(changed_full_pipeline["status"], "passed")
        self.assertEqual(
            changed_full_pipeline["comparison"],
            "nonidentical-base-current-cold-output",
        )
        self.assertEqual(changed_full_pipeline["base_class_count"], 6)
        self.assertEqual(changed_full_pipeline["current_class_count"], 6)
        self.assertEqual(changed_full_pipeline["validation_issue_count"], 0)
        self.assertEqual(
            changed_full_pipeline["authoritative_change_fact_count"], 3
        )
        self.assertEqual(
            changed_full_pipeline[
                "authoritative_member_change_kind_counts"
            ],
            {"implementation_changed": 3},
        )
        self.assertEqual(changed_full_pipeline["formal_api_result_count"], 3)
        self.assertEqual(
            changed_full_pipeline["formal_reachability_status_counts"],
            {"not_found_in_static_analysis": 3},
        )
        self.assertEqual(
            changed_full_pipeline["formal_impact_conclusion_counts"],
            {"inconclusive": 3},
        )
        self.assertEqual(
            changed_full_pipeline["artifact_snapshot_memory_hits"], 1
        )
        protocol = result["measurement_protocol"]
        cold = result["measurements"]["cold"]
        gate = {
            "measurement_protocol": {
                "machine_identity": protocol["machine_identity"],
                "dataset_identity": protocol["dataset_identity"],
                "jar_count": 2,
                "class_count": 6,
            },
            "thresholds": {
                "cold_end_to_end_seconds": cold["end_to_end_seconds"] * 2,
                "warm_end_to_end_p95_seconds": result["measurements"]["warm_end_to_end_p95_seconds"] * 2,
                "peak_rss_bytes": result["measurements"]["peak_rss_bytes"] * 2,
                "disk_bytes": result["measurements"]["disk_bytes"] * 2,
                "bytes_per_class": cold["bytes_per_class"] * 2,
                "bytes_per_edge": cold["bytes_per_edge"] * 2,
                "cold_relative_legacy_ratio": 10,
                "warm_relative_legacy_ratio": 10,
                "full_pipeline_end_to_end_seconds": (
                    full_pipeline["end_to_end_seconds"] * 2
                ),
                "full_pipeline_peak_rss_bytes": (
                    full_pipeline["peak_rss_bytes"] * 2
                ),
                "full_pipeline_phase_seconds": {
                    phase: seconds * 2 + 0.001
                    for phase, seconds in full_pipeline["phase_seconds"].items()
                },
                "changed_full_pipeline_end_to_end_seconds": (
                    changed_full_pipeline["end_to_end_seconds"] * 2
                ),
                "changed_full_pipeline_peak_rss_bytes": (
                    changed_full_pipeline["peak_rss_bytes"] * 2
                ),
                "changed_full_pipeline_phase_seconds": {
                    phase: seconds * 2 + 0.001
                    for phase, seconds in changed_full_pipeline[
                        "phase_seconds"
                    ].items()
                },
                "stage_p95_seconds": {
                    "inventory": 10,
                    "parse_and_cache": 10,
                    "db_write_and_index": 10,
                    "batch_query_10000": 10,
                    "report_10000": 10,
                },
            },
            "accuracy_invariants": {
                "expected_class_count": cold["counts"]["classes"],
                "expected_member_count": cold["counts"]["members"],
                "expected_edge_count": cold["counts"]["edges"],
                "warm_parser_invocations": 0,
                "full_pipeline_expected_class_count": 6,
                "full_pipeline_validation_issue_count": 0,
                "full_pipeline_expected_authoritative_change_fact_count": 0,
                "full_pipeline_expected_formal_api_result_count": 0,
                "full_pipeline_expected_authoritative_member_change_kind_counts": {},
                "full_pipeline_expected_formal_reachability_status_counts": {},
                "full_pipeline_expected_formal_impact_conclusion_counts": {},
                "changed_full_pipeline_expected_class_count": 6,
                "changed_full_pipeline_validation_issue_count": 0,
                "changed_full_pipeline_expected_authoritative_change_fact_count": 3,
                "changed_full_pipeline_expected_formal_api_result_count": 3,
                "changed_full_pipeline_expected_authoritative_member_change_kind_counts": {
                    "implementation_changed": 3,
                },
                "changed_full_pipeline_expected_formal_reachability_status_counts": {
                    "not_found_in_static_analysis": 3,
                },
                "changed_full_pipeline_expected_formal_impact_conclusion_counts": {
                    "inconclusive": 3,
                },
            },
        }
        # The small unit fixture intentionally skips the legacy comparator;
        # evaluation must fail rather than interpreting missing relative data as pass.
        self.assertEqual(evaluate_gate(result, gate)["status"], "failed")
        lost_edge = json.loads(json.dumps(result))
        lost_edge["measurements"]["cold"]["counts"]["edges"] -= 1
        lost_evaluation = evaluate_gate(lost_edge, gate)
        self.assertTrue(any(
            issue["reason_code"] == "BINARY_PERFORMANCE_FACT_CONSERVATION_FAILED"
            and issue["fact_kind"] == "edges"
            for issue in lost_evaluation["issues"]
        ))
        slow_pipeline = json.loads(json.dumps(result))
        slow_pipeline["measurements"]["full_pipeline_probe"][
            "end_to_end_seconds"
        ] = gate["thresholds"]["full_pipeline_end_to_end_seconds"] + 1
        slow_evaluation = evaluate_gate(slow_pipeline, gate)
        self.assertTrue(any(
            issue["reason_code"] == "BINARY_PERFORMANCE_THRESHOLD_EXCEEDED"
            and issue["metric"] == "full_pipeline_end_to_end_seconds"
            for issue in slow_evaluation["issues"]
        ))
        memory_heavy_pipeline = json.loads(json.dumps(result))
        memory_heavy_pipeline["measurements"]["full_pipeline_probe"][
            "peak_rss_bytes"
        ] = gate["thresholds"]["full_pipeline_peak_rss_bytes"] + 1
        memory_evaluation = evaluate_gate(memory_heavy_pipeline, gate)
        self.assertTrue(any(
            issue["reason_code"] == "BINARY_PERFORMANCE_THRESHOLD_EXCEEDED"
            and issue["metric"] == "full_pipeline_peak_rss_bytes"
            for issue in memory_evaluation["issues"]
        ))
        lost_pipeline_class = json.loads(json.dumps(result))
        lost_pipeline_class["measurements"]["full_pipeline_probe"][
            "current_class_count"
        ] -= 1
        class_evaluation = evaluate_gate(lost_pipeline_class, gate)
        self.assertTrue(any(
            issue["reason_code"]
            == "BINARY_PERFORMANCE_FULL_PIPELINE_CLASS_CONSERVATION_FAILED"
            and issue["side"] == "current"
            for issue in class_evaluation["issues"]
        ))
        invented_change = json.loads(json.dumps(result))
        invented_change["measurements"]["full_pipeline_probe"][
            "authoritative_change_fact_count"
        ] = 1
        change_evaluation = evaluate_gate(invented_change, gate)
        self.assertTrue(any(
            issue["reason_code"]
            == "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH"
            and issue["metric"] == "authoritative_change_fact_count"
            for issue in change_evaluation["issues"]
        ))
        lost_changed_result = json.loads(json.dumps(result))
        lost_changed_result["measurements"]["changed_full_pipeline_probe"][
            "formal_api_result_count"
        ] -= 1
        changed_evaluation = evaluate_gate(lost_changed_result, gate)
        self.assertTrue(any(
            issue["reason_code"]
            == "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH"
            and issue.get("probe") == "changed_full_pipeline_probe"
            and issue["metric"] == "formal_api_result_count"
            for issue in changed_evaluation["issues"]
        ))
        wrong_changed_kind = json.loads(json.dumps(result))
        wrong_changed_kind["measurements"]["changed_full_pipeline_probe"][
            "authoritative_member_change_kind_counts"
        ] = {"contract_changed": 3}
        kind_evaluation = evaluate_gate(wrong_changed_kind, gate)
        self.assertTrue(any(
            issue["reason_code"]
            == "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH"
            and issue.get("probe") == "changed_full_pipeline_probe"
            and issue["metric"]
            == "authoritative_member_change_kind_counts"
            for issue in kind_evaluation["issues"]
        ))

        with tempfile.TemporaryDirectory() as output_tmp:
            output = Path(output_tmp) / "result.json"
            gate_path = Path(output_tmp) / "gate.json"
            gate_path.write_text(json.dumps(gate), encoding="utf-8")
            with patch.object(binary_performance_gate, "run_benchmark", return_value=result):
                returncode = binary_performance_gate.main([
                    "--output", str(output),
                    "--gate", str(gate_path),
                ])
            persisted = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(returncode, 1)
        self.assertEqual(persisted["gate_evaluation"]["status"], "failed")

    def test_full_pipeline_probe_uses_every_artifact_by_default(self):
        artifacts = [
            {"path": f"/fixture/artifact-{index:04d}.jar"}
            for index in range(25)
        ]
        pipeline_result = {
            "total_elapsed_seconds": 1.25,
            "phase_timings": [{
                "phase": "independent_validation",
                "elapsed_seconds": 0.5,
                "peak_rss_bytes": 1024,
            }],
            "peak_rss_bytes": 1024,
            "cache_metrics": {
                "classfile_parser_invocations": 25,
                "artifact_snapshot_hits": 0,
            },
        }
        evidence = {
            "class_count": 75,
            "base_class_count": 75,
            "current_class_count": 75,
            "validation_status": "passed",
            "validation_issue_count": 0,
            "authoritative_change_fact_count": 0,
            "formal_api_result_count": 0,
        }
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_performance_gate, "_jdk_home", return_value=Path("/jdk")
        ), patch.object(
            binary_performance_gate,
            "_full_pipeline_evidence",
            return_value=evidence,
        ), patch(
            "binary_pipeline.run_pipeline", return_value=pipeline_result
        ) as run_pipeline:
            result = binary_performance_gate._full_pipeline_probe(
                artifacts,
                root=Path(tmp),
                asm_jar=Path("/asm.jar"),
                classes_per_jar=3,
            )

        submitted = run_pipeline.call_args.args[0]
        self.assertEqual(len(submitted["base"]["artifacts"]), 25)
        self.assertEqual(len(submitted["current"]["artifacts"]), 25)
        self.assertEqual(result["jar_count"], 25)
        self.assertEqual(result["class_count"], 75)

    def test_full_pipeline_probe_routes_nonidentical_current_side(self):
        base = [
            {"path": "/fixture/base-0.jar", "sha256": "a" * 64},
            {"path": "/fixture/shared-1.jar", "sha256": "b" * 64},
        ]
        current = [
            {"path": "/fixture/current-0.jar", "sha256": "c" * 64},
            {"path": "/fixture/shared-1.jar", "sha256": "b" * 64},
        ]
        pipeline_result = {
            "total_elapsed_seconds": 2.5,
            "phase_timings": [],
            "peak_rss_bytes": 2048,
            "cache_metrics": {
                "classfile_parser_invocations": 3,
                "artifact_snapshot_hits": 1,
            },
        }
        evidence = {
            "class_count": 6,
            "base_class_count": 6,
            "current_class_count": 6,
            "validation_status": "passed",
            "validation_issue_count": 0,
            "authoritative_change_fact_count": 3,
            "formal_api_result_count": 3,
        }
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_performance_gate, "_jdk_home", return_value=Path("/jdk")
        ), patch.object(
            binary_performance_gate,
            "_full_pipeline_evidence",
            return_value=evidence,
        ), patch(
            "binary_pipeline.run_pipeline", return_value=pipeline_result
        ) as run_pipeline:
            result = binary_performance_gate._full_pipeline_probe(
                base,
                current_artifacts=current,
                root=Path(tmp),
                asm_jar=Path("/asm.jar"),
                classes_per_jar=3,
            )

        submitted = run_pipeline.call_args.args[0]
        self.assertEqual(
            submitted["base"]["artifacts"][0]["path"], "/fixture/base-0.jar"
        )
        self.assertEqual(
            submitted["current"]["artifacts"][0]["path"],
            "/fixture/current-0.jar",
        )
        self.assertEqual(
            result["comparison"], "nonidentical-base-current-cold-output"
        )
        self.assertEqual(result["authoritative_change_fact_count"], 3)
        self.assertEqual(result["formal_api_result_count"], 3)


if __name__ == "__main__":
    unittest.main()
