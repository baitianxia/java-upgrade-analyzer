import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from defect_regression_gate import (  # noqa: E402
    DEFAULT_REGISTRY,
    audit_defect_regressions,
)


class DefectRegressionGateTest(unittest.TestCase):
    def registry(self):
        return json.loads(DEFAULT_REGISTRY.read_text(encoding="utf-8"))

    def audit_mutation(self, mutate):
        registry = self.registry()
        mutate(registry)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "escaped-defects.json"
            path.write_text(
                json.dumps(registry, ensure_ascii=False), encoding="utf-8"
            )
            return audit_defect_regressions(ROOT, path)

    def test_every_documented_escaped_defect_has_executable_closure(self):
        result = audit_defect_regressions(ROOT, DEFAULT_REGISTRY)

        self.assertEqual(result["status"], "passed", result["issues"])
        self.assertGreaterEqual(result["counts"]["registered_defects"], 22)
        self.assertGreater(
            result["counts"]["regression_tests"],
            result["counts"]["registered_defects"],
        )
        self.assertGreaterEqual(
            result["counts"]["truth_bindings"],
            result["counts"]["registered_defects"],
        )
        self.assertGreaterEqual(
            result["counts"]["independent_truth_documents"], 18
        )
        self.assertGreaterEqual(
            result["counts"]["authored_control_values"],
            result["counts"]["registered_defects"],
        )

    def test_deleted_or_renamed_regression_is_rejected(self):
        result = self.audit_mutation(lambda registry: registry["defects"][0][
            "regressions"
        ][0].update({"selector": "tests.missing.NoTest.test_missing"}))

        self.assertIn(
            "DEFECT_REGRESSION_SELECTOR_INVALID",
            {issue["code"] for issue in result["issues"]},
        )

    def test_regression_declared_in_a_profile_that_does_not_run_it_is_rejected(self):
        result = self.audit_mutation(lambda registry: registry["defects"][0][
            "regressions"
        ][1].update({"required_profiles": ["performance"]}))

        self.assertIn(
            "DEFECT_REGRESSION_NOT_EXECUTED_BY_PROFILE",
            {issue["code"] for issue in result["issues"]},
        )

    def test_local_step5_profile_alone_does_not_count_as_premerge_protection(self):
        def leave_only_local_feedback(registry):
            for regression in registry["defects"][0]["regressions"]:
                regression["required_profiles"] = ["step5"]

        result = self.audit_mutation(leave_only_local_feedback)

        self.assertIn(
            "DEFECT_PRE_MERGE_REGRESSION_MISSING",
            {issue["code"] for issue in result["issues"]},
        )

    def test_system_output_cannot_replace_independent_defect_truth(self):
        result = self.audit_mutation(lambda registry: registry["defects"][0][
            "truth_evidence"
        ][0].update({
            "path": "tests/fixtures/test_suite_policy.json",
            "control_pointers": ["/minimum_blackbox_cases"],
        }))

        codes = {issue["code"] for issue in result["issues"]}
        self.assertIn("DEFECT_TRUTH_NOT_INDEPENDENT", codes)
        self.assertIn("DEFECT_TRUTH_ORACLE_DIVERSITY_INSUFFICIENT", codes)

    def test_missing_counterexample_pointer_is_rejected(self):
        result = self.audit_mutation(lambda registry: registry["defects"][0][
            "truth_evidence"
        ][0].update({"control_pointers": ["/not-authored"]}))

        self.assertIn(
            "DEFECT_TRUTH_POINTER_MISSING",
            {issue["code"] for issue in result["issues"]},
        )

    def test_independent_truth_document_floor_is_enforced(self):
        result = self.audit_mutation(lambda registry: registry.update({
            "minimum_independent_truth_documents": 19,
        }))

        self.assertIn(
            "DEFECT_TRUTH_DOCUMENT_FLOOR_NOT_MET",
            {issue["code"] for issue in result["issues"]},
        )


if __name__ == "__main__":
    unittest.main()
