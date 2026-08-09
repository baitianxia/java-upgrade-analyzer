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
        self.assertEqual(
            set(support["engine_modes"]["implemented"]),
            set(contract.IMPLEMENTED_ENGINE_MODES),
        )
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

    def test_engine_modes_enable_strict_and_whole_generation_fallback(self):
        self.assertEqual(contract.require_implemented_engine_mode("shadow"), "shadow")
        self.assertEqual(
            contract.require_implemented_engine_mode("binary_strict"),
            "binary_strict",
        )
        self.assertEqual(
            contract.require_implemented_engine_mode("binary_with_legacy_fallback"),
            "binary_with_legacy_fallback",
        )

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


if __name__ == "__main__":
    unittest.main()
