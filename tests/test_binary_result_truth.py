import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from binary_result_truth import (  # noqa: E402
    evaluate_formal_result_truth,
    validate_result_truth,
)


def result_row(
    owner="demo/Api",
    member="run",
    descriptor="()V",
    *,
    reachability="reachable",
):
    return {
        "display_owner": owner,
        "display_member": member,
        "display_descriptor": descriptor,
        "display_member_kind": "method",
        "dependency_lineages": ["com.acme:demo"],
        "base_dependency_coords": ["com.acme:demo:1"],
        "current_dependency_coords": ["com.acme:demo:2"],
        "reachability_status": reachability,
        "static_linkage_status": "compatible_or_not_applicable",
        "impact_conclusion": (
            "probable_impact" if reachability == "reachable" else "inconclusive"
        ),
        "runtime_verification_status": "required_not_executed",
        "exact_path_exists": reachability == "reachable",
        "possible_path_exists": False,
        "path_set_complete": True,
        "paths": ([{
            "path_certainty": "exact",
            "path_text": "demo.Entry.main() → demo.Api.run()",
        }] if reachability == "reachable" else []),
    }


def expected_row(**overrides):
    row = {
        "owner": "demo/Api",
        "member": "run",
        "descriptor": "()V",
        "member_kind": "method",
        "dependency_lineages": ["com.acme:demo"],
        "base_dependency_coords": ["com.acme:demo:1"],
        "current_dependency_coords": ["com.acme:demo:2"],
        "reachability_status": "reachable",
        "static_linkage_status": "compatible_or_not_applicable",
        "impact_conclusion": "probable_impact",
        "runtime_verification_status": "required_not_executed",
        "exact_path_exists": True,
        "possible_path_exists": False,
        "path_set_complete": True,
        "required_paths": [{
            "certainty": "exact",
            "text": "demo.Entry.main() → demo.Api.run()",
        }],
    }
    row.update(overrides)
    return row


def truth(*expected, result_set_policy="exact", exact_reachability_statuses=()):
    return {
        "schema": "java-upgrade-analyzer.binary-result-truth.v1",
        "result_set_policy": result_set_policy,
        "exact_reachability_statuses": list(exact_reachability_statuses),
        "expected_results": list(expected),
        "forbidden_results": [],
    }


class BinaryResultTruthTest(unittest.TestCase):
    def test_repository_golden_truth_documents_are_structurally_valid(self):
        directory = (
            ROOT / "tests" / "fixtures" / "binary_first" / "golden_truth"
        )
        documents = sorted(directory.glob("*.json"))

        self.assertGreaterEqual(len(documents), 2)
        for path in documents:
            with self.subTest(path=path.name):
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(validate_result_truth(payload), ())

    def test_exact_truth_accepts_complete_identity_state_and_path_match(self):
        evaluation = evaluate_formal_result_truth(
            {"by_api": [result_row()]}, truth(expected_row())
        )

        self.assertEqual(evaluation["status"], "passed", evaluation["issues"])
        self.assertEqual(evaluation["metrics"]["true_positive_count"], 1)
        self.assertEqual(evaluation["metrics"]["false_positive_count"], 0)
        self.assertEqual(evaluation["metrics"]["false_negative_count"], 0)

    def test_exact_truth_rejects_unexpected_false_positive(self):
        unexpected = result_row("demo/Unexpected", "call", "(I)V")
        evaluation = evaluate_formal_result_truth(
            {"by_api": [result_row(), unexpected]}, truth(expected_row())
        )

        self.assertEqual(evaluation["status"], "failed")
        self.assertEqual(evaluation["metrics"]["false_positive_count"], 1)
        self.assertIn(
            "BINARY_TRUTH_UNEXPECTED_RESULT",
            {issue["reason_code"] for issue in evaluation["issues"]},
        )

    def test_provider_topology_identity_allows_intentionally_empty_member_fields(self):
        contract = truth({
            "owner": "demo/Provider",
            "member": "",
            "descriptor": "",
            "member_kind": "provider_topology",
        })
        actual = {
            "display_owner": "demo/Provider",
            "display_member": None,
            "display_descriptor": None,
            "display_member_kind": "provider_topology",
            "paths": [],
        }

        evaluation = evaluate_formal_result_truth({"by_api": [actual]}, contract)

        self.assertEqual(evaluation["status"], "passed", evaluation["issues"])

    def test_truth_rejects_wrong_overload_dependency_and_four_state_result(self):
        mutations = {
            "descriptor": lambda row: row.update(display_descriptor="(I)V"),
            "lineage": lambda row: row.update(dependency_lineages=["wrong:owner"]),
            "reachability": lambda row: row.update(
                reachability_status="uncertain", impact_conclusion="inconclusive"
            ),
            "linkage": lambda row: row.update(static_linkage_status="undetermined"),
            "impact": lambda row: row.update(impact_conclusion="inconclusive"),
            "runtime": lambda row: row.update(runtime_verification_status="undetermined"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                actual = result_row()
                mutate(actual)
                evaluation = evaluate_formal_result_truth(
                    {"by_api": [actual]}, truth(expected_row())
                )
                self.assertEqual(evaluation["status"], "failed")

    def test_truth_rejects_missing_or_incorrect_required_path(self):
        for name, paths in (
            ("missing", []),
            ("wrong", [{"path_certainty": "exact", "path_text": "wrong path"}]),
        ):
            with self.subTest(name=name):
                actual = result_row()
                actual["paths"] = paths
                evaluation = evaluate_formal_result_truth(
                    {"by_api": [actual]}, truth(expected_row())
                )
                self.assertEqual(evaluation["status"], "failed")
                self.assertIn(
                    "BINARY_TRUTH_REQUIRED_PATH_MISSING",
                    {issue["reason_code"] for issue in evaluation["issues"]},
                )

    def test_status_scoped_exactness_finds_unexpected_reachable_without_freezing_all_results(self):
        expected = expected_row()
        uncertain = result_row(
            "demo/NeedsReview", "call", "()V", reachability="uncertain"
        )
        evaluation = evaluate_formal_result_truth(
            {"by_api": [result_row(), uncertain]},
            truth(
                expected,
                result_set_policy="subset",
                exact_reachability_statuses=("reachable",),
            ),
        )
        self.assertEqual(evaluation["status"], "passed", evaluation["issues"])

        false_reachable = copy.deepcopy(uncertain)
        false_reachable.update(
            reachability_status="reachable", impact_conclusion="probable_impact"
        )
        evaluation = evaluate_formal_result_truth(
            {"by_api": [result_row(), false_reachable]},
            truth(
                expected,
                result_set_policy="subset",
                exact_reachability_statuses=("reachable",),
            ),
        )
        self.assertEqual(evaluation["status"], "failed")
        self.assertIn(
            "BINARY_TRUTH_UNEXPECTED_STATUS_RESULT",
            {issue["reason_code"] for issue in evaluation["issues"]},
        )

    def test_forbidden_result_rejects_known_false_positive(self):
        contract = truth(expected_row(), result_set_policy="subset")
        contract["forbidden_results"] = [{
            "owner": "demo/Forbidden",
            "member": "call",
            "descriptor": "()V",
            "member_kind": "method",
        }]
        evaluation = evaluate_formal_result_truth(
            {"by_api": [result_row(), result_row("demo/Forbidden", "call")]},
            contract,
        )

        self.assertEqual(evaluation["status"], "failed")
        self.assertIn(
            "BINARY_TRUTH_FORBIDDEN_RESULT_PRESENT",
            {issue["reason_code"] for issue in evaluation["issues"]},
        )

    def test_duplicate_actual_identity_fails_instead_of_last_row_winning(self):
        duplicate = result_row()
        duplicate["reachability_status"] = "uncertain"
        evaluation = evaluate_formal_result_truth(
            {"by_api": [result_row(), duplicate]}, truth(expected_row())
        )

        self.assertEqual(evaluation["status"], "failed")
        self.assertIn(
            "BINARY_TRUTH_DUPLICATE_ACTUAL_IDENTITY",
            {issue["reason_code"] for issue in evaluation["issues"]},
        )

    def test_truth_schema_rejects_invalid_typed_fields_before_comparison(self):
        expected = expected_row(
            dependency_lineages="com.acme:demo",
            exact_path_exists="true",
            impact_conclusion="maybe",
            minimum_path_count=True,
            required_paths={"text": "not-a-list"},
        )
        issues = validate_result_truth(truth(expected))
        reason_codes = {issue["reason_code"] for issue in issues}

        self.assertIn("BINARY_TRUTH_LIST_FIELD_INVALID", reason_codes)
        self.assertIn("BINARY_TRUTH_BOOLEAN_FIELD_INVALID", reason_codes)
        self.assertIn("BINARY_TRUTH_STATE_VALUE_INVALID", reason_codes)
        self.assertIn("BINARY_TRUTH_MINIMUM_PATH_COUNT_INVALID", reason_codes)
        self.assertIn("BINARY_TRUTH_REQUIRED_PATHS_INVALID", reason_codes)

    def test_truth_evaluation_fails_closed_on_malformed_actual_collections(self):
        actual = result_row()
        actual["dependency_lineages"] = "com.acme:demo"
        actual["paths"] = {"path_text": "not-a-list"}

        evaluation = evaluate_formal_result_truth(
            {"by_api": [actual]}, truth(expected_row())
        )
        reason_codes = {issue["reason_code"] for issue in evaluation["issues"]}

        self.assertEqual(evaluation["status"], "failed")
        self.assertIn("BINARY_TRUTH_ACTUAL_LIST_FIELD_INVALID", reason_codes)
        self.assertIn("BINARY_TRUTH_ACTUAL_PATHS_INVALID", reason_codes)

    def test_truth_evaluation_reports_invalid_documents_instead_of_raising(self):
        evaluation = evaluate_formal_result_truth([], [])

        self.assertEqual(evaluation["status"], "failed")
        self.assertIn(
            "BINARY_TRUTH_DOCUMENT_INVALID",
            {issue["reason_code"] for issue in evaluation["issues"]},
        )


if __name__ == "__main__":
    unittest.main()
