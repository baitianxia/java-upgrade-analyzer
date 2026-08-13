import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from test_trust_gate import (  # noqa: E402
    audit_blackbox_sources,
    audit_public_capability_matrix,
    canonical_json_identity,
    run_trust_gate,
    source_tree_identity,
    validate_supplemental_truth_document,
    validate_truth_document,
)


POLICY_PATH = ROOT / "tests" / "fixtures" / "test_suite_policy.json"
CASE_ROOT = ROOT / "tests" / "fixtures" / "blackbox" / "removed-methods-v1"


class TestTrustGateTest(unittest.TestCase):
    def test_repository_test_trust_contract_passes(self):
        result = run_trust_gate(ROOT, POLICY_PATH)

        self.assertEqual(result["status"], "passed", result["issues"])
        self.assertGreaterEqual(result["counts"]["blackbox_cases"], 16)
        self.assertGreaterEqual(result["counts"]["closed_truth_results"], 53)
        self.assertGreaterEqual(result["counts"]["forbidden_truth_results"], 16)
        self.assertGreaterEqual(result["counts"]["blackbox_assertion_sites"], 621)
        self.assertGreaterEqual(
            result["counts"]["supplemental_expectation_leaves"], 1063
        )
        self.assertEqual(
            result["capability_readiness"]["status"], "complete"
        )
        self.assertEqual(result["counts"]["public_capabilities"], 89)
        self.assertEqual(result["counts"]["public_capabilities_covered"], 89)
        self.assertEqual(result["counts"]["public_capabilities_partial"], 0)
        self.assertEqual(result["counts"]["public_capabilities_missing"], 0)
        self.assertEqual(result["capability_readiness"]["blocking_capabilities"], [])
        self.assertEqual(result["counts"]["public_scenario_contracts"], 89)
        self.assertEqual(result["counts"]["public_scenario_dimensions"], 260)
        self.assertEqual(result["counts"]["public_support_claims"], 22)

    def test_capability_matrix_cannot_claim_coverage_without_blackbox_evidence(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        matrix_path = ROOT / policy["public_capability_matrix"]
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        target = next(
            item for item in matrix["capabilities"]
            if item["id"] == "artifact_inputs_end_to_end"
        )
        target["blackbox"] = {
            "status": "covered", "oracle": "unsupported assertion",
            "evidence": [],
        }
        case_capabilities = {}
        for case_path in (ROOT / "tests" / "fixtures" / "blackbox").glob(
            "*/case.json"
        ):
            case = json.loads(case_path.read_text(encoding="utf-8"))
            case_capabilities[case["case_id"]] = set(case["capabilities"])
        with tempfile.TemporaryDirectory() as temporary:
            bad_matrix = Path(temporary) / "matrix.json"
            bad_matrix.write_text(
                json.dumps(matrix, ensure_ascii=False), encoding="utf-8",
            )
            issues, readiness = audit_public_capability_matrix(
                ROOT, bad_matrix, policy, case_capabilities,
            )

        self.assertEqual(readiness["status"], "invalid")
        self.assertIn(
            "PUBLIC_CAPABILITY_COVERED_WITHOUT_ORACLE",
            {issue["code"] for issue in issues},
        )

    def test_capability_evidence_must_be_an_executable_asserting_test(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        matrix_path = ROOT / policy["public_capability_matrix"]
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        target = next(
            item for item in matrix["capabilities"]
            if item["id"] == "artifact_inputs_end_to_end"
        )
        target["blackbox"]["evidence"] = [{
            "kind": "test",
            "path": "tests/blackbox/test_public_framework_semantics.py",
            "test": "identity",
        }]
        case_capabilities = {
            json.loads(path.read_text(encoding="utf-8"))["case_id"]: set(
                json.loads(path.read_text(encoding="utf-8"))["capabilities"]
            )
            for path in (ROOT / "tests" / "fixtures" / "blackbox").glob(
                "*/case.json"
            )
        }
        with tempfile.TemporaryDirectory() as temporary:
            bad_matrix = Path(temporary) / "matrix.json"
            bad_matrix.write_text(
                json.dumps(matrix, ensure_ascii=False), encoding="utf-8",
            )
            issues, _readiness = audit_public_capability_matrix(
                ROOT, bad_matrix, policy, case_capabilities,
            )

        self.assertIn(
            "PUBLIC_CAPABILITY_EVIDENCE_NOT_A_TEST",
            {issue["code"] for issue in issues},
        )

    def test_repository_coverage_floors_cannot_be_silently_weakened(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        policy["minimum_blackbox_cases"] = 999
        policy["minimum_closed_truth_results"] = 999
        policy["minimum_forbidden_truth_results"] = 999
        policy["minimum_supplemental_blackbox_truth_documents"] = 999
        policy["minimum_blackbox_assertion_sites"] = 9999
        policy["minimum_supplemental_expectation_leaves"] = 9999
        policy["minimum_public_scenario_contracts"] = 999
        policy["minimum_public_scenario_dimensions"] = 999
        policy["minimum_public_support_claims"] = 999
        with tempfile.TemporaryDirectory() as temporary:
            policy_path = Path(temporary) / "policy.json"
            policy_path.write_text(
                json.dumps(policy, ensure_ascii=False), encoding="utf-8",
            )
            result = run_trust_gate(ROOT, policy_path)

        floor_issues = [
            issue for issue in result["issues"]
            if issue["code"] == "BLACKBOX_COVERAGE_FLOOR_NOT_MET"
        ]
        self.assertEqual(len(floor_issues), 9, floor_issues)

    def test_critical_capability_cannot_drop_required_scenario_dimension(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        contracts_path = ROOT / policy["public_scenario_contracts"]
        contracts = json.loads(contracts_path.read_text(encoding="utf-8"))
        target = next(
            item for item in contracts["capabilities"]
            if item["id"] == "typed_tool_failure_boundaries"
        )
        target["dimensions"].pop("failure_closed")
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            bad_contracts = temporary_root / "scenario-contracts.json"
            bad_contracts.write_text(
                json.dumps(contracts, ensure_ascii=False), encoding="utf-8",
            )
            policy["public_scenario_contracts"] = str(bad_contracts)
            policy_path = temporary_root / "policy.json"
            policy_path.write_text(
                json.dumps(policy, ensure_ascii=False), encoding="utf-8",
            )
            result = run_trust_gate(ROOT, policy_path)

        self.assertIn(
            "PUBLIC_SCENARIO_RISK_FLOOR_NOT_MET",
            {issue["code"] for issue in result["issues"]},
        )

    def test_scenario_truth_pointer_must_resolve_to_an_authored_value(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        contracts_path = ROOT / policy["public_scenario_contracts"]
        contracts = json.loads(contracts_path.read_text(encoding="utf-8"))
        target = next(
            item for item in contracts["capabilities"]
            if item["id"] == "public_cli_surface_contract"
        )
        target["dimensions"]["boundary"] = ["/not-authored"]
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            bad_contracts = temporary_root / "scenario-contracts.json"
            bad_contracts.write_text(
                json.dumps(contracts, ensure_ascii=False), encoding="utf-8",
            )
            policy["public_scenario_contracts"] = str(bad_contracts)
            policy_path = temporary_root / "policy.json"
            policy_path.write_text(
                json.dumps(policy, ensure_ascii=False), encoding="utf-8",
            )
            result = run_trust_gate(ROOT, policy_path)

        self.assertIn(
            "PUBLIC_SCENARIO_TRUTH_POINTER_MISSING",
            {issue["code"] for issue in result["issues"]},
        )

    def test_scenario_truth_pointer_must_be_asserted_by_its_exact_evidence(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        contracts_path = ROOT / policy["public_scenario_contracts"]
        contracts = json.loads(contracts_path.read_text(encoding="utf-8"))
        target = next(
            item for item in contracts["capabilities"]
            if item["id"] == "thin_artifact_fail_closed"
        )
        # This is a real authored value in the same truth document, but none of
        # this capability's exact evidence tests reads or asserts it.
        target["dimensions"]["boundary"] = ["/describe_contract"]
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            bad_contracts = temporary_root / "scenario-contracts.json"
            bad_contracts.write_text(
                json.dumps(contracts, ensure_ascii=False), encoding="utf-8",
            )
            policy["public_scenario_contracts"] = str(bad_contracts)
            policy_path = temporary_root / "policy.json"
            policy_path.write_text(
                json.dumps(policy, ensure_ascii=False), encoding="utf-8",
            )
            result = run_trust_gate(ROOT, policy_path)

        self.assertIn(
            "PUBLIC_SCENARIO_TRUTH_POINTER_NOT_ASSERTED",
            {issue["code"] for issue in result["issues"]},
        )

    def test_every_fine_grained_support_claim_must_remain_mapped(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        matrix_path = ROOT / policy["public_capability_matrix"]
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
        matrix["support_claim_coverage"].pop(
            "entrypoint_discovery_support_manifest.automatic_discovery[0]"
        )
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            bad_matrix = temporary_root / "matrix.json"
            bad_matrix.write_text(
                json.dumps(matrix, ensure_ascii=False), encoding="utf-8",
            )
            policy["public_capability_matrix"] = str(bad_matrix)
            policy_path = temporary_root / "policy.json"
            policy_path.write_text(
                json.dumps(policy, ensure_ascii=False), encoding="utf-8",
            )
            result = run_trust_gate(ROOT, policy_path)

        self.assertIn(
            "PUBLIC_SUPPORT_CLAIM_NOT_IN_CAPABILITY_MATRIX",
            {issue["code"] for issue in result["issues"]},
        )

    def test_every_case_and_capability_must_be_locked_by_policy(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        policy["required_blackbox_case_ids"].remove(
            "nestmate-private-path-v1"
        )
        policy["required_blackbox_capabilities"].remove(
            "jvm_nestmate_private_access"
        )
        with tempfile.TemporaryDirectory() as temporary:
            policy_path = Path(temporary) / "policy.json"
            policy_path.write_text(
                json.dumps(policy, ensure_ascii=False), encoding="utf-8",
            )
            result = run_trust_gate(ROOT, policy_path)

        codes = {issue["code"] for issue in result["issues"]}
        self.assertIn("BLACKBOX_CASE_NOT_REQUIRED_BY_POLICY", codes)
        self.assertIn("BLACKBOX_CAPABILITY_NOT_REQUIRED_BY_POLICY", codes)

    def test_blackbox_production_import_mock_skip_and_path_mutation_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            blackbox = root / "tests" / "blackbox"
            scripts.mkdir(parents=True)
            blackbox.mkdir(parents=True)
            (scripts / "binary_output.py").write_text("", encoding="utf-8")
            source = blackbox / "test_bad.py"
            source.write_text(
                "import binary_output\n"
                "from unittest import expectedFailure, mock, skip as disabled\n"
                "import sys\n"
                "sys.path.insert(0, 'scripts')\n"
                "@disabled('hidden')\n"
                "def test_hidden():\n"
                "    mock.patch('x')\n",
                encoding="utf-8",
            )

            issues = audit_blackbox_sources(root, [source])

        codes = {item["code"] for item in issues}
        self.assertIn("BLACKBOX_IMPORTS_PRODUCTION", codes)
        self.assertIn("BLACKBOX_USES_MOCK", codes)
        self.assertIn("BLACKBOX_USES_SKIP", codes)
        self.assertIn("BLACKBOX_MUTATES_IMPORT_PATH", codes)

    def test_generated_or_single_mechanism_truth_is_rejected(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        case = json.loads((CASE_ROOT / "case.json").read_text(encoding="utf-8"))
        truth = json.loads((CASE_ROOT / "truth.json").read_text(encoding="utf-8"))
        truth["system_generated"] = True
        truth["oracle_producers"] = truth["oracle_producers"][:1]
        digest, files = source_tree_identity(CASE_ROOT)

        issues = validate_truth_document(
            case, truth, policy,
            source_digest=digest,
            source_files=files,
        )

        codes = {item["code"] for item in issues}
        self.assertIn("TRUTH_SYSTEM_GENERATED", codes)
        self.assertIn("TRUTH_ORACLE_MECHANISMS_INSUFFICIENT", codes)

    def test_generated_or_single_mechanism_supplemental_truth_is_rejected(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        truth_path = (
            ROOT / "tests" / "fixtures" / "blackbox_runtime"
            / "runtime_dispatch_v1.json"
        )
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        truth["system_generated"] = True
        truth["oracle_producers"] = truth["oracle_producers"][:1]

        issues = validate_supplemental_truth_document(
            truth, policy, location="runtime_dispatch_v1.json"
        )

        codes = {item["code"] for item in issues}
        self.assertIn("SUPPLEMENTAL_TRUTH_SYSTEM_GENERATED", codes)
        self.assertIn(
            "SUPPLEMENTAL_TRUTH_ORACLE_MECHANISMS_INSUFFICIENT", codes
        )

    def test_truth_cannot_hide_input_or_state_changes(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        case = json.loads((CASE_ROOT / "case.json").read_text(encoding="utf-8"))
        truth = json.loads((CASE_ROOT / "truth.json").read_text(encoding="utf-8"))
        truth["input_evidence"]["source_tree_sha256"] = "0" * 64
        truth["input_evidence"]["case_sha256"] = "f" * 64
        truth["oracle_implementations"][0]["sha256"] = "e" * 64
        truth["expected_result_count"] = 99
        truth["expected_results"][1]["runtime_verification_status"] = (
            "required_not_executed"
        )
        digest, files = source_tree_identity(CASE_ROOT)

        issues = validate_truth_document(
            case, truth, policy,
            source_digest=digest,
            source_files=files,
        )

        codes = {item["code"] for item in issues}
        self.assertIn("TRUTH_INPUT_IDENTITY_MISMATCH", codes)
        self.assertIn("TRUTH_CASE_IDENTITY_MISMATCH", codes)
        self.assertIn(
            "TRUTH_ORACLE_IMPLEMENTATION_IDENTITY_MISMATCH", codes
        )
        self.assertIn("TRUTH_EXPECTED_RESULT_COUNT_MISMATCH", codes)
        self.assertIn("TRUTH_RESULT_STATE_INCONSISTENT", codes)

    def test_case_identity_is_key_order_independent_but_value_sensitive(self):
        first = {"case_id": "case", "entrypoints": ["a"], "version": 1}
        reordered = {"version": 1, "entrypoints": ["a"], "case_id": "case"}
        changed = {"case_id": "case", "entrypoints": ["b"], "version": 1}

        self.assertEqual(
            canonical_json_identity(first), canonical_json_identity(reordered)
        )
        self.assertNotEqual(
            canonical_json_identity(first), canonical_json_identity(changed)
        )

    def test_malformed_truth_fails_closed_without_crashing_gate(self):
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        case = json.loads((CASE_ROOT / "case.json").read_text(encoding="utf-8"))
        truth = json.loads((CASE_ROOT / "truth.json").read_text(encoding="utf-8"))
        truth.update({
            "oracle_producers": 1,
            "completeness": [],
            "human_review": "reviewed",
            "input_evidence": None,
            "expected_results": 1,
            "forbidden_results": 1,
        })
        digest, files = source_tree_identity(CASE_ROOT)

        issues = validate_truth_document(
            case, truth, policy,
            source_digest=digest,
            source_files=files,
        )

        codes = {item["code"] for item in issues}
        self.assertIn("TRUTH_ORACLE_PRODUCERS_INVALID", codes)
        self.assertIn("TRUTH_COMPLETENESS_ARGUMENT_MISSING", codes)
        self.assertIn("TRUTH_EXPECTED_RESULTS_INVALID", codes)
        self.assertIn("TRUTH_FORBIDDEN_RESULTS_INVALID", codes)


if __name__ == "__main__":
    unittest.main()
