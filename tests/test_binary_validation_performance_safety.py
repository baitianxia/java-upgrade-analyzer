import copy
import csv
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_validation_oracle as oracle  # noqa: E402


class BinaryValidationPerformanceSafetyTest(unittest.TestCase):
    @staticmethod
    def edge_connection():
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE artifact_instances (
                artifact_instance_identity TEXT PRIMARY KEY,
                content_sha256 TEXT NOT NULL,
                runtime_classpath_index INTEGER NOT NULL
            );
            CREATE TABLE members (
                member_identity TEXT PRIMARY KEY,
                class_name TEXT NOT NULL,
                member_name TEXT NOT NULL,
                descriptor TEXT NOT NULL
            );
            CREATE TABLE direct_edges (
                caller_artifact_instance_identity TEXT NOT NULL,
                caller_member_identity TEXT NOT NULL,
                edge_kind TEXT NOT NULL,
                symbolic_owner TEXT,
                symbolic_name TEXT,
                symbolic_descriptor TEXT,
                opcode INTEGER,
                bytecode_offset INTEGER NOT NULL,
                edge_json TEXT NOT NULL
            );
            """
        )
        return connection

    @staticmethod
    def completed_for(names):
        rows = [
            {
                "class_name": name.replace(".", "/"),
                "status": "definition_failed",
                "failure_phase": "class_load",
                "failure_kind": "fixture",
            }
            for name in names
        ]
        return SimpleNamespace(
            succeeded=True,
            stdout="\n".join(json.dumps(row) for row in rows) + "\n",
            failure=None,
        )

    def test_runtime_oracle_batches_every_class_without_sampling(self):
        observed_batches = []

        def execute(command, **_kwargs):
            names = Path(command[-1]).read_text(encoding="utf-8").splitlines()
            observed_batches.append(names)
            return self.completed_for(names)

        classes = [f"demo/C{index}" for index in range(5)]
        with patch.object(
            oracle, "MAX_CLASSES_PER_RUNTIME_ORACLE_PROCESS", 2
        ), patch.object(
            oracle, "_compile_oracle", return_value="helper-identity"
        ), patch.object(oracle, "execute_binary_tool", side_effect=execute):
            observations, helper_identity = oracle._observe_classes(
                Path("/fixture/jdk"),
                [{"path": "/fixture/app.jar"}],
                classes,
            )

        self.assertEqual([len(batch) for batch in observed_batches], [2, 2, 1])
        self.assertEqual(
            {name for batch in observed_batches for name in batch},
            {name.replace("/", ".") for name in classes},
        )
        self.assertEqual(set(observations), set(classes))
        self.assertEqual(helper_identity, "helper-identity")

    def test_runtime_oracle_fails_closed_on_incomplete_batch_output(self):
        def incomplete(command, **_kwargs):
            names = Path(command[-1]).read_text(encoding="utf-8").splitlines()
            return self.completed_for(names[:-1])

        with patch.object(
            oracle, "MAX_CLASSES_PER_RUNTIME_ORACLE_PROCESS", 2
        ), patch.object(
            oracle, "_compile_oracle", return_value="helper-identity"
        ), patch.object(
            oracle, "execute_binary_tool", side_effect=incomplete
        ), self.assertRaises(oracle.BinaryValidationError) as error:
            oracle._observe_classes(
                Path("/fixture/jdk"),
                [{"path": "/fixture/app.jar"}],
                ["demo/A", "demo/B"],
            )

        self.assertEqual(
            error.exception.reason_code, "BINARY_ORACLE_OUTPUT_INCOMPLETE"
        )

    def test_compressed_javap_cache_round_trips_all_evidence(self):
        evidence = {
            "complete": True,
            "artifact_sha256": "a" * 64,
            "edges": [{
                "caller_owner": "demo.A",
                "callee_owner": "demo.B",
                "instruction_offset": 7,
            }],
            "structural_facts": {
                "class_names": ["demo/A", "demo/B"],
                "type_edges": [["demo/A", "m", "()V", 7, "demo/B", "new"]],
            },
            "failures": [],
        }

        packed = oracle._pack_oracle_scan(evidence)

        self.assertIsInstance(packed, bytes)
        self.assertEqual(oracle._unpack_oracle_scan(packed), evidence)

    def test_equal_observation_sharing_preserves_type_exact_json_evidence(self):
        reference = {
            "demo/A": {
                "status": "definition_ready",
                "provider_url": "file:/same.jar",
                "declared_members": ["method|run|()V|1"],
                "flags": [1, True],
            },
            "demo/B": {
                "status": "definition_ready",
                "provider_url": "file:/base.jar",
                "declared_members": ["method|run|()V|1"],
            },
            "demo/C": {"flags": [1]},
        }
        candidate = copy.deepcopy(reference)
        candidate["demo/B"]["provider_url"] = "file:/current.jar"
        candidate["demo/C"]["flags"] = [True]
        before = json.dumps(
            candidate, sort_keys=True, separators=(",", ":")
        )

        shared_rows, shared_values = oracle._share_equal_observation_values(
            reference, candidate
        )

        self.assertEqual(
            json.dumps(candidate, sort_keys=True, separators=(",", ":")),
            before,
        )
        self.assertEqual(shared_rows, 1)
        self.assertGreaterEqual(shared_values, 3)
        self.assertIs(candidate["demo/A"], reference["demo/A"])
        self.assertIsNot(candidate["demo/B"], reference["demo/B"])
        self.assertIs(
            candidate["demo/B"]["declared_members"],
            reference["demo/B"]["declared_members"],
        )
        self.assertIsNot(
            candidate["demo/C"]["flags"], reference["demo/C"]["flags"]
        )

    def test_direct_truth_cache_reuses_only_oracle_facts_and_rechecks_database(self):
        artifact_sha = "a" * 64
        artifact = {
            "path": "/fixture/app.jar", "sha256": artifact_sha, "slot": 0,
        }
        scan_result = {
            "complete": True,
            "artifact_sha256": artifact_sha,
            "edges": [{
                "caller_owner": "demo.A", "caller_member": "run",
                "caller_descriptor": "()V", "callee_owner": "demo.B",
                "callee_member": "value", "callee_descriptor": "()I",
                "opcode_family": "invokevirtual", "instruction_offset": 7,
            }],
            "failures": [],
        }
        connection = self.edge_connection()
        self.addCleanup(connection.close)
        connection.execute(
            "INSERT INTO artifact_instances VALUES (?,?,?)",
            ("artifact-1", artifact_sha, 0),
        )
        connection.execute(
            "INSERT INTO members VALUES (?,?,?,?)",
            ("member-1", "demo/A", "run", "()V"),
        )
        connection.execute(
            "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "artifact-1", "member-1", "method", "demo/B", "value",
                "()I", 182, 7, "{}",
            ),
        )
        scan_cache = {}
        truth_cache = {}
        with patch.object(
            oracle, "scan_final_artifact", return_value=scan_result
        ) as scan:
            first_issues, first_truth = oracle._validate_direct_edges(
                connection, [artifact], javap="javap",
                scan_cache=scan_cache, truth_cache=truth_cache,
            )
            connection.execute(
                "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "artifact-1", "member-1", "method", "demo/C", "extra",
                    "()V", 184, 8, "{}",
                ),
            )
            second_issues, second_truth = oracle._validate_direct_edges(
                connection, [artifact], javap="javap",
                scan_cache=scan_cache, truth_cache=truth_cache,
            )

        scan.assert_called_once()
        self.assertEqual(first_issues, [])
        self.assertEqual(first_truth, second_truth)
        self.assertIn(
            "ORACLE_DIRECT_EDGE_EXTRA",
            {item["reason_code"] for item in second_issues},
        )

    def test_structural_truth_cache_rechecks_database_without_redecoding(self):
        with tempfile.TemporaryDirectory() as temp_text:
            artifact_path = Path(temp_text) / "app.jar"
            artifact_path.write_bytes(b"immutable-fixture")
            artifact_sha = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            artifact = {
                "path": str(artifact_path), "sha256": artifact_sha, "slot": 0,
            }
            inventory = {"classes": {"demo/A": "demo/A.class"}}
            direct_result = {
                "complete": True,
                "artifact_sha256": artifact_sha,
                "edges": [],
                "failures": [],
                "structural_facts": {
                    "class_names": ["demo/A"],
                    "type_edges": [["demo/A", "run", "()V", 7, "demo/B", "new"]],
                    "class_init_edges": [],
                    "clinit_classes": [],
                    "semantic_instructions": [],
                    "declared_members": [],
                },
            }
            connection = self.edge_connection()
            self.addCleanup(connection.close)
            connection.execute(
                "INSERT INTO artifact_instances VALUES (?,?,?)",
                ("artifact-1", artifact_sha, 0),
            )
            connection.execute(
                "INSERT INTO members VALUES (?,?,?,?)",
                ("member-1", "demo/A", "run", "()V"),
            )
            connection.execute(
                "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "artifact-1", "member-1", "type", "demo/B", "", "",
                    187, 7, json.dumps({"type_use_kind": "new"}),
                ),
            )
            direct_cache = {
                (artifact_sha, "javap"): oracle._pack_oracle_scan(direct_result)
            }
            structural_cache = {}
            original_unpack = oracle._unpack_oracle_scan
            with patch.object(
                oracle, "_unpack_oracle_scan", wraps=original_unpack
            ) as unpack:
                first_issues, first_truth = oracle._validate_structural_edges(
                    connection, [artifact], [inventory], javap="javap",
                    scan_cache=structural_cache,
                    direct_scan_cache=direct_cache,
                )
                connection.execute(
                    "INSERT INTO direct_edges VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        "artifact-1", "member-1", "type", "demo/C", "", "",
                        187, 8, json.dumps({"type_use_kind": "new"}),
                    ),
                )
                second_issues, second_truth = oracle._validate_structural_edges(
                    connection, [artifact], [inventory], javap="javap",
                    scan_cache=structural_cache,
                    direct_scan_cache=direct_cache,
                )

        self.assertEqual(unpack.call_count, 1)
        self.assertEqual(first_issues, [])
        self.assertEqual(first_truth, second_truth)
        self.assertIn(
            "ORACLE_TYPE_EDGE_EXTRA",
            {item["reason_code"] for item in second_issues},
        )

    @staticmethod
    def _write_closed_world_fixture(
        generation,
        *,
        entrypoint_gaps=(),
        trace_gaps=(),
        result_overrides=None,
    ):
        generation = Path(generation)
        analysis_context = "analysis-context"
        runtime_profile = "runtime-profile"
        decision = {
            "decision_identity": "decision-1",
            "change_fact_identity": "change-1",
            "fact_kind": "method",
            "fact_scope": {
                "initiating_loader_realm_identity": "application-loader",
                "class_name": "demo/Api",
                "member_kind": "method",
                "member_name": "changed",
                "descriptor": "()V",
            },
            "coverage_gaps": [],
            "dependency_artifacts": [],
        }
        assessment = {
            "projection_assessment_identity": "assessment-1",
            "decision_identity": decision["decision_identity"],
        }
        projection = {
            "projection_identity": "projection-1",
            "projection_assessment_identity": assessment[
                "projection_assessment_identity"
            ],
        }
        complete = not trace_gaps
        status = (
            "not_found_in_static_analysis" if complete else "not_analyzed"
        )
        result = {
            "projection_identity": projection["projection_identity"],
            "decision_identity": decision["decision_identity"],
            "change_fact_identity": decision["change_fact_identity"],
            "projection_assessment_identity": assessment[
                "projection_assessment_identity"
            ],
            "analysis_context_identity": analysis_context,
            "runtime_profile_identity": runtime_profile,
            "target_nodes": ["target-member"],
            "paths": [],
            "exact_path_exists": False,
            "possible_path_exists": False,
            "path_set_complete": complete,
            "trace_coverage_gaps": list(trace_gaps),
            "result_channel": "formal",
            "batch_graph_identity": "batch-graph",
            "static_linkage_status": "compatible_or_not_applicable",
            "member_resolution_statuses": [],
            "linkage_resolution_statuses": [],
            "change_fact_status": "confirmed",
            "reachability_status": status,
            "analysis_status": status,
            "is_reachable": False,
            "impact_conclusion": "inconclusive",
            "decision_bucket": "inconclusive",
            "runtime_verification_status": "undetermined",
            "runtime_verification_executed_by_system": False,
            "runtime_verification_evidence": [],
            "best_path_certainty": "none",
            "existence_proven": False,
        }
        result.update(result_overrides or {})
        result["trace_result_identity"] = oracle._identity(
            "binary_trace_result_identity",
            {
                key: value for key, value in result.items()
                if key != "trace_result_identity"
            },
        )
        reported_api_identity = oracle._identity("reported_api_identity", {
            "analysis_context_identity": analysis_context,
            "current_runtime_profile_identity": runtime_profile,
            "initiating_loader_realm_identity": "application-loader",
            "class_name": "demo/Api",
            "member_kind": "method",
            "member_name": "changed",
            "descriptor": "()V",
            "grouping_rule_version": "binary-reported-api-v1",
        })
        reported_api = {
            "reported_api_identity": reported_api_identity,
            "display_owner": "demo/Api",
            "display_member": "changed",
            "display_descriptor": "()V",
            "display_member_kind": "method",
            "reachability_status": status,
            "is_reachable": False,
            "impact_conclusion": "inconclusive",
            "runtime_verification_status": "required_not_executed",
            "runtime_verification_executed_by_system": False,
            "path_set_complete": complete,
            "exact_path_exists": False,
            "possible_path_exists": False,
            "contributing_projection_ids": [projection["projection_identity"]],
            "contributing_change_fact_ids": [decision["change_fact_identity"]],
            "base_dependency_coords": [],
            "current_dependency_coords": [],
        }
        payloads = {
            "binary_decisions.json": {
                "analysis_context_identity": analysis_context,
                "authoritative_change_facts": [decision],
                "diagnostic_candidate_facts": [],
            },
            "binary_projections.json": {
                "authoritative_projection_assessments": [assessment],
                "formal_projections": [projection],
            },
            "binary_formal_results.json": {
                "results": [result], "by_api": [reported_api],
            },
            "binary_entrypoints.json": {
                "records": [], "coverage_gaps": list(entrypoint_gaps),
            },
            "binary_runtime_semantic_overlay.json": {
                "rows": [], "coverage_gaps": [],
            },
            "binary_coverage.json": {
                "trace_coverage_gaps": list(trace_gaps),
            },
            "binary_summary.json": {
                "authoritative_change_fact_count": 1,
                "formal_projection_count": 1,
                "formal_trace_result_count": 1,
                "unique_reported_api_total": 1,
                "reachable_total": 0,
                "uncertain_total": 0,
                "not_found_in_static_analysis_total": int(complete),
                "not_analyzed_total": int(not complete),
                "probable_impact_total": 0,
            },
        }
        for name, payload in payloads.items():
            (generation / name).write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
        with (generation / "binary_formal_results.csv").open(
            "w", encoding="utf-8-sig", newline=""
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "reported_api_identity", "display_owner", "display_member",
                "display_descriptor", "reachability_status",
                "impact_conclusion", "runtime_verification_status",
            ])
            writer.writeheader()
            writer.writerow({key: reported_api.get(key, "") for key in writer.fieldnames})
        return result

    @staticmethod
    def _empty_entrypoint_truth():
        return {
            "exact_entrypoint_count": 0,
            "oracle_candidate_entrypoint_count": 0,
            "production_candidate_entrypoint_count": 0,
            "candidate_activation_gaps": [],
        }

    def test_closed_world_skips_graph_only_for_independently_verified_empty_roots(self):
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            self._write_closed_world_fixture(generation)
            with patch.object(
                oracle,
                "_load_closed_world_graph",
                side_effect=AssertionError("validated empty roots must not load graph"),
            ):
                issues, truth = oracle._validate_closed_world_results(
                    generation,
                    entrypoint_truth=self._empty_entrypoint_truth(),
                )

        self.assertEqual(issues, [])
        self.assertEqual(
            truth["reachability_rebuild_status"],
            "not_required_validated_empty_entrypoint_set",
        )
        self.assertTrue(truth["formal_identity_set_closed"])

    def test_closed_world_falls_back_when_empty_roots_are_not_verified(self):
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            self._write_closed_world_fixture(generation)
            empty_graph = ({}, {}, {}, {})
            with patch.object(
                oracle, "_load_closed_world_graph", return_value=empty_graph
            ) as load_graph:
                issues, truth = oracle._validate_closed_world_results(
                    generation,
                    entrypoint_validation_issues=[{"reason_code": "unverified"}],
                    entrypoint_truth=self._empty_entrypoint_truth(),
                )

        load_graph.assert_called_once()
        self.assertEqual(issues, [])
        self.assertEqual(
            truth["reachability_rebuild_status"], "completed_full_graph"
        )

    def test_closed_world_no_roots_with_coverage_gap_stays_not_analyzed(self):
        gap = "declared_entrypoint_coverage_incomplete"
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            self._write_closed_world_fixture(
                generation, entrypoint_gaps=[gap], trace_gaps=[gap]
            )
            with patch.object(
                oracle, "_load_closed_world_graph", return_value=({}, {}, {}, {})
            ) as load_graph:
                issues, truth = oracle._validate_closed_world_results(
                    generation,
                    entrypoint_truth=self._empty_entrypoint_truth(),
                )

        load_graph.assert_called_once()
        self.assertEqual(issues, [])
        self.assertEqual(
            truth["reachability_rebuild_status"], "completed_full_graph"
        )

    def test_closed_world_empty_root_fast_path_still_rejects_tampered_state(self):
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            self._write_closed_world_fixture(
                generation, result_overrides={"path_set_complete": False}
            )
            issues, _truth = oracle._validate_closed_world_results(
                generation,
                entrypoint_truth=self._empty_entrypoint_truth(),
            )

        self.assertIn(
            "ORACLE_FORMAL_STATE_MISMATCH",
            {item["reason_code"] for item in issues},
        )

    def test_closed_world_rejects_path_root_not_in_entrypoint_set(self):
        fake_path = {
            "entrypoint_member_identity": "forged-root",
            "entrypoint_records": [],
            "edges": [],
            "path_certainty": "exact",
        }
        fake_path["path_identity"] = oracle._identity(
            "binary_trace_path_identity",
            {
                "entrypoint_member_identity": "forged-root",
                "entrypoint_record_identities": [],
                "target_nodes": ["target-member"],
                "edge_identities": [],
                "path_certainty": "exact",
            },
        )
        with tempfile.TemporaryDirectory() as temp_text:
            generation = Path(temp_text)
            self._write_closed_world_fixture(
                generation, result_overrides={"paths": [fake_path]}
            )
            issues, _truth = oracle._validate_closed_world_results(
                generation,
                entrypoint_truth=self._empty_entrypoint_truth(),
            )

        self.assertIn(
            "ORACLE_TRACE_PATH_ENTRYPOINT_MISMATCH",
            {item["reason_code"] for item in issues},
        )


if __name__ == "__main__":
    unittest.main()
