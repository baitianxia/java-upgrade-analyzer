import sys
import json
import hashlib
from pathlib import Path
import unittest


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_first_contract as contract  # noqa: E402


class BinaryFirstContractTest(unittest.TestCase):
    def test_support_and_performance_manifests_allow_only_validated_authority_scope(self):
        support_path = ROOT_DIR / "scripts" / "binary_first_support_manifest.json"
        performance_path = (
            ROOT_DIR / "tests" / "fixtures" / "binary_first" / "performance_gate.json"
        )
        support = json.loads(
            support_path.read_text(encoding="utf-8")
        )
        performance = json.loads(
            performance_path.read_text(encoding="utf-8")
        )

        self.assertEqual(tuple(support["phase_contract"]), contract.PHASE_ORDER)
        self.assertEqual(support["authority"], "binary_first_only_fail_closed")
        self.assertNotIn("engine_modes", support)
        self.assertTrue(
            support["runtime_loader_support_manifest"][
                "authoritative_runtime_effective_decisions_allowed"
            ]
        )
        self.assertTrue(
            support["oracle_support_manifest"][
                "production_binary_authority_switch_allowed"
            ]
        )
        self.assertFalse(performance["blocks_binary_authority_switch"])
        self.assertEqual(performance["status"], "passed")
        self.assertGreater(performance["thresholds"]["cold_end_to_end_seconds"], 0)
        self.assertGreater(performance["thresholds"]["warm_end_to_end_p95_seconds"], 0)
        self.assertGreater(
            performance["thresholds"]["full_pipeline_end_to_end_seconds"], 0
        )
        self.assertGreater(
            performance["thresholds"]["full_pipeline_peak_rss_bytes"], 0
        )
        self.assertGreater(
            performance["thresholds"][
                "changed_full_pipeline_end_to_end_seconds"
            ],
            0,
        )
        self.assertGreater(
            performance["thresholds"][
                "changed_full_pipeline_peak_rss_bytes"
            ],
            0,
        )
        self.assertGreater(
            performance["recorded_measurements"]["full_pipeline_probe"][
                "peak_rss_bytes"
            ],
            0,
        )
        self.assertEqual(
            performance["measurement_protocol"]["full_pipeline_probe"][
                "class_count"
            ],
            performance["accuracy_invariants"][
                "full_pipeline_expected_class_count"
            ],
        )
        changed_protocol = performance["measurement_protocol"][
            "changed_full_pipeline_probe"
        ]
        self.assertEqual(changed_protocol["changed_jar_count"], 1)
        self.assertEqual(changed_protocol["changed_class_count"], 250)
        self.assertEqual(
            performance["recorded_measurements"][
                "changed_full_pipeline_probe"
            ]["authoritative_member_change_kind_counts"],
            {"implementation_changed": 250},
        )
        self.assertEqual(
            hashlib.sha256(performance_path.read_bytes()).hexdigest(),
            support["performance_gate"]["sha256"],
        )

    def test_canonical_identity_is_order_independent_but_list_order_sensitive(self):
        first = contract.canonical_identity(
            "example", {"b": 2, "a": ["first", "second"]}, schema_version="1"
        )
        reordered_keys = contract.canonical_identity(
            "example", {"a": ["first", "second"], "b": 2}, schema_version="1"
        )
        reordered_list = contract.canonical_identity(
            "example", {"a": ["second", "first"], "b": 2}, schema_version="1"
        )

        self.assertEqual(first, reordered_keys)
        self.assertNotEqual(first, reordered_list)

    def test_artifact_content_identity_rejects_non_sha_input(self):
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.artifact_content_identity("not-a-sha", 10)

        self.assertEqual(error.exception.reason_code, "ARTIFACT_CONTENT_SHA256_INVALID")

    def test_canonical_identity_rejects_non_string_object_keys(self):
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.canonical_identity(
                "example",
                {1: "would-collide-with-string-one", "1": "value"},
                schema_version="1",
            )

        self.assertEqual(error.exception.reason_code, "BINARY_IDENTITY_KEY_INVALID")

    def test_canonical_identity_rejects_non_finite_float(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                contract.canonical_identity(
                    "example", {"value": value}, schema_version="1"
                )

    def test_canonical_identity_supports_sets_and_rejects_unknown_values(self):
        first = contract.canonical_identity(
            "example", {"values": {"b", "a"}}, schema_version="1"
        )
        second = contract.canonical_identity(
            "example", {"values": {"a", "b"}}, schema_version="1"
        )
        self.assertEqual(first, second)
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.canonical_identity(
                "example", {"value": object()}, schema_version="1"
            )
        self.assertEqual(
            error.exception.reason_code, "BINARY_IDENTITY_VALUE_UNSUPPORTED"
        )

    def test_streaming_canonical_identity_is_byte_equivalent(self):
        payloads = (
            {},
            [],
            {"unicode": "运行时✓", "escaped": "line\n\"quoted\"\\"},
            {
                "nested": [
                    {"z": None, "a": (True, False, 1, -2, 3.25)},
                    {"set": {"beta", "alpha"}},
                ],
            },
            {"numbers": [0, -0.0, 1.0e-12, 1.0e20]},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertEqual(
                    contract.canonical_identity(
                        "example", payload, schema_version="1"
                    ),
                    contract.canonical_identity_streaming(
                        "example", payload, schema_version="1"
                    ),
                )

        for payload in ({1: "invalid-key"}, {"value": object()}):
            with self.subTest(payload=payload), self.assertRaises(
                contract.BinaryFirstContractError
            ):
                contract.canonical_identity_streaming(
                    "example", payload, schema_version="1"
                )
        with self.assertRaises(ValueError):
            contract.canonical_identity_streaming(
                "example", {"value": float("nan")}, schema_version="1"
            )

    def test_native_type_fast_paths_preserve_the_frozen_identity(self):
        class DictSubclass(dict):
            pass

        class ListSubclass(list):
            pass

        class IntSubclass(int):
            pass

        payload = DictSubclass({
            "z": ListSubclass([
                IntSubclass(7), None, True, {"values": {"beta", "alpha"}},
            ]),
            "a": {"unicode": "运行时✓", "tuple": ("x", -2, 3.25)},
        })
        expected = (
            "eef9286e35d4dcd144f938c71c5a4f6a"
            "c31c8a6540926bda9e47759b6eb92dc8"
        )

        self.assertEqual(
            contract.canonical_identity(
                "fast-path-regression", payload, schema_version="1"
            ),
            expected,
        )
        self.assertEqual(
            contract.canonical_identity_streaming(
                "fast-path-regression", payload, schema_version="1"
            ),
            expected,
        )

    def test_streaming_sequence_is_repeatable_and_byte_equivalent(self):
        values = ["first", "运行时", "third"]
        sequence = contract.StreamingCanonicalSequence(lambda: iter(values))
        payload = {"values": sequence}

        expected = contract.canonical_identity(
            "example", {"values": values}, schema_version="1"
        )
        self.assertEqual(
            contract.canonical_identity_streaming(
                "example", payload, schema_version="1"
            ),
            expected,
        )
        self.assertEqual(
            contract.canonical_identity_streaming(
                "example", payload, schema_version="1"
            ),
            expected,
        )
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.canonical_identity("example", payload, schema_version="1")
        self.assertEqual(
            error.exception.reason_code, "BINARY_IDENTITY_VALUE_UNSUPPORTED"
        )

    def test_artifact_content_identity_rejects_invalid_lengths(self):
        digest = "a" * 64
        for value in ("not-an-int", -1):
            with self.subTest(value=value), self.assertRaises(
                contract.BinaryFirstContractError
            ) as error:
                contract.artifact_content_identity(digest, value)
            self.assertEqual(
                error.exception.reason_code, "ARTIFACT_CONTENT_LENGTH_INVALID"
            )

    def test_observed_delta_is_shared_across_analysis_scopes(self):
        observed = contract.observed_delta_identity(
            delta_source_kind="artifact_local",
            comparison_or_runtime_scope={"runtime_comparison": "pair-1"},
            fact_or_mechanism_scope={"member": "com/acme/Api.run()V"},
            base_fingerprint="base-ir",
            current_fingerprint="current-ir",
        )
        first_context = contract.analysis_context_identity("pair-1", "scope-a")
        second_context = contract.analysis_context_identity("pair-1", "scope-b")

        self.assertNotEqual(
            contract.disposition_obligation_identity(observed, first_context),
            contract.disposition_obligation_identity(observed, second_context),
        )

    def test_contract_exposes_no_engine_selection_or_fallback_api(self):
        self.assertFalse(hasattr(contract, "ENGINE_MODES"))
        self.assertFalse(hasattr(contract, "IMPLEMENTED_ENGINE_MODES"))
        self.assertFalse(hasattr(contract, "require_implemented_engine_mode"))

    def test_reachable_truth_table_preserves_static_reachability(self):
        result = contract.derive_formal_result_state("reachable")

        self.assertEqual(result["analysis_status"], "reachable")
        self.assertTrue(result["is_reachable"])
        self.assertEqual(result["impact_conclusion"], "probable_impact")
        self.assertEqual(result["runtime_verification_status"], "required_not_executed")
        self.assertFalse(result["runtime_verification_executed_by_system"])
        self.assertEqual(result["runtime_verification_evidence"], [])
        self.assertEqual(result["best_path_certainty"], "exact_or_proven")
        self.assertTrue(contract.validate_formal_result_state(result))

    def test_reachable_truth_table_preserves_additional_possible_paths(self):
        result = contract.derive_formal_result_state(
            "reachable",
            possible_path_exists=True,
        )

        self.assertTrue(result["exact_path_exists"])
        self.assertTrue(result["possible_path_exists"])
        self.assertEqual(result["reachability_status"], "reachable")
        self.assertEqual(result["best_path_certainty"], "exact_or_proven")
        self.assertTrue(contract.validate_formal_result_state(result))

    def test_uncertain_truth_table_requires_a_complete_possible_path(self):
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.derive_formal_result_state(
                "uncertain",
                possible_path_exists=False,
            )

        self.assertEqual(
            error.exception.reason_code,
            "FORMAL_POSSIBLE_PATH_STATE_INVALID",
        )

    def test_uncertain_truth_table_cannot_claim_probable_impact(self):
        result = contract.derive_formal_result_state("uncertain")
        result["impact_conclusion"] = "probable_impact"

        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.validate_formal_result_state(result)

        self.assertEqual(error.exception.reason_code, "FORMAL_STATE_TRUTH_TABLE_VIOLATION")

    def test_formal_truth_table_rejects_invalid_status_certainty_and_possible_path(self):
        cases = (
            (("unknown",), {}, "FORMAL_REACHABILITY_STATUS_INVALID"),
            (("reachable",), {"best_path_certainty": "possible"},
             "FORMAL_BEST_PATH_CERTAINTY_INVALID"),
            (("not_found_in_static_analysis",), {"possible_path_exists": True},
             "FORMAL_POSSIBLE_PATH_STATE_INVALID"),
        )
        for args, kwargs, reason in cases:
            with self.subTest(reason=reason), self.assertRaises(
                contract.BinaryFirstContractError
            ) as error:
                contract.derive_formal_result_state(*args, **kwargs)
            self.assertEqual(error.exception.reason_code, reason)
        self.assertFalse(contract.derive_formal_result_state(
            "not_found_in_static_analysis"
        )["possible_path_exists"])

    def test_formal_validation_requires_confirmed_change_fact(self):
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.validate_formal_result_state({"change_fact_status": "candidate"})
        self.assertEqual(
            error.exception.reason_code, "FORMAL_CHANGE_FACT_NOT_CONFIRMED"
        )

    def test_static_v2_rejects_confirmed_impact(self):
        result = contract.derive_formal_result_state("reachable")
        result["decision_bucket"] = "confirmed_impact"

        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.validate_formal_result_state(result)

        self.assertEqual(error.exception.reason_code, "FORMAL_STATIC_V2_FORBIDDEN_STATE")

    def test_projection_assessment_requires_obligation_conservation(self):
        self.assertTrue(contract.validate_projection_assessment({
            "analysis_projection_status": "targetable",
            "projection_coverage_status": "partial",
            "target_count": 1,
            "projection_obligation_count": 2,
            "projection_count": 2,
            "partial_scopes": ["reflection-consumers"],
        }))
        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.validate_projection_assessment({
                "analysis_projection_status": "targetable",
                "projection_coverage_status": "complete",
                "target_count": 1,
                "projection_obligation_count": 2,
                "projection_count": 1,
            })

        self.assertEqual(error.exception.reason_code, "PROJECTION_OBLIGATION_COUNT_MISMATCH")

    def test_projection_assessment_exercises_all_invalid_contract_branches(self):
        self.assertTrue(contract.validate_projection_assessment({
            "analysis_projection_status": "unsupported",
            "projection_coverage_status": "unsupported",
        }))
        invalid = (
            ({"analysis_projection_status": "unsupported",
              "projection_coverage_status": "complete"},
             "UNSUPPORTED_PROJECTION_ASSESSMENT_INVALID"),
            ({"analysis_projection_status": "targetable",
              "projection_coverage_status": "unsupported",
              "target_count": 1, "projection_obligation_count": 1,
              "projection_count": 1}, "TARGETABLE_PROJECTION_COVERAGE_INVALID"),
            ({"analysis_projection_status": "targetable",
              "projection_coverage_status": "complete"},
             "TARGETABLE_PROJECTION_OBLIGATION_MISSING"),
            ({"analysis_projection_status": "targetable",
              "projection_coverage_status": "complete", "target_count": 1,
              "projection_obligation_count": 1, "projection_count": 1,
              "partial_scopes": ["gap"]}, "COMPLETE_PROJECTION_HAS_PARTIAL_SCOPE"),
            ({"analysis_projection_status": "targetable",
              "projection_coverage_status": "partial", "target_count": 1,
              "projection_obligation_count": 1, "projection_count": 1},
             "PARTIAL_PROJECTION_SCOPE_MISSING"),
            ({"analysis_projection_status": "other"},
             "PROJECTION_ASSESSMENT_STATUS_INVALID"),
        )
        for payload, reason in invalid:
            with self.subTest(reason=reason), self.assertRaises(
                contract.BinaryFirstContractError
            ) as error:
                contract.validate_projection_assessment(payload)
            self.assertEqual(error.exception.reason_code, reason)

    def test_possible_layer_controls_compatibility_completeness(self):
        self.assertTrue(contract.derive_path_set_complete(
            exact_path_set_complete=True,
            possible_path_layer_applicable=False,
            possible_path_set_complete=False,
        ))
        self.assertFalse(contract.derive_path_set_complete(
            exact_path_set_complete=True,
            possible_path_layer_applicable=True,
            possible_path_set_complete=False,
        ))

    def test_phase_manifest_is_one_way_and_digest_bound(self):
        result = contract.validate_phase_manifest([
            {
                "phase": "step4a_artifact_local_diff",
                "status": "completed",
                "input_digest": "input-a",
                "output_digest": "output-a",
            },
            {
                "phase": "step5a_target_independent_reconciliation",
                "status": "pending",
            },
        ])
        self.assertEqual(result["completed_phase_count"], 1)
        self.assertEqual(result["next_phase"], "step5a_target_independent_reconciliation")

        with self.assertRaises(contract.BinaryFirstContractError) as error:
            contract.validate_phase_manifest([{
                "phase": "step5a_target_independent_reconciliation",
                "status": "completed",
                "input_digest": "input-b",
                "output_digest": "output-b",
            }])
        self.assertEqual(error.exception.reason_code, "BINARY_PHASE_ORDER_INVALID")

    def test_phase_manifest_rejects_duplicate_status_digest_and_terminal_tail(self):
        invalid = (
            ([{"phase": "step4a_artifact_local_diff", "status": "completed",
               "input_digest": "in", "output_digest": "out"},
              {"phase": "step4a_artifact_local_diff", "status": "pending"}],
             "BINARY_PHASE_MANIFEST_INVALID"),
            ([{"phase": "step4a_artifact_local_diff", "status": "unknown"}],
             "BINARY_PHASE_STATUS_INVALID"),
            ([{"phase": "step4a_artifact_local_diff", "status": "completed"}],
             "BINARY_PHASE_DIGEST_MISSING"),
            ([{"phase": "step4a_artifact_local_diff", "status": "pending"},
              {"phase": "step5a_target_independent_reconciliation",
               "status": "pending"}], "BINARY_PHASE_AFTER_TERMINAL_STATE"),
        )
        for records, reason in invalid:
            with self.subTest(reason=reason), self.assertRaises(
                contract.BinaryFirstContractError
            ) as error:
                contract.validate_phase_manifest(records)
            self.assertEqual(error.exception.reason_code, reason)


if __name__ == "__main__":
    unittest.main()
