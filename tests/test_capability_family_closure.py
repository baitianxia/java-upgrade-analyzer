import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import capability_family_closure as closure  # noqa: E402


def valid_family(**overrides):
    family = {
        "family_id": "evidence_identity",
        "invariant_id": "canonical_symbol_identity",
        "invariant": (
            "Equivalent symbols have one canonical owner, member, descriptor, "
            "kind, and change identity before evidence enters the graph."
        ),
        "root_cause_families": ["evidence_identity"],
        "state": "enforced",
        "production_paths": [
            "scripts/step5_evidence_ingestion.py",
            "scripts/step5_evidence_model.py",
        ],
        "positive_tests": [
            "tests.test_step5_evidence_model.EvidenceModelTest."
            "test_collector_batch_requires_identity_and_valid_sha"
        ],
        "negative_tests": [
            "tests.test_step5_evidence_model.EvidenceModelTest."
            "test_collector_batch_rejects_invalid_provenance"
        ],
        "mutation_tests": [
            "tests.test_real_project_regression.RealProjectRegressionTests."
            "test_fault_injection_detects_removed_analyzer_edge"
        ],
        "cross_project_guards": ["ruoyi-full-artifact-discovery"],
        "architecture_review_on_repeat": True,
    }
    family.update(overrides)
    return family


def valid_registry(*families):
    return {
        "schema_version": 1,
        "families": list(families or (valid_family(),)),
    }


def executable_family(**overrides):
    family = valid_family(
        production_paths=["scripts/step5_evidence_model.py"],
        positive_tests=[
            "tests.test_capability_family_closure."
            "CapabilityFamilyRegistryTest.test_valid_registry_has_no_contract_errors"
        ],
        negative_tests=[
            "tests.test_capability_family_closure."
            "CapabilityFamilyRegistryTest.test_empty_invariant_is_rejected"
        ],
        mutation_tests=[
            "tests.test_capability_family_closure."
            "CapabilityFamilyRegistryTest."
            "test_duplicate_test_reference_across_categories_is_rejected"
        ],
        cross_project_guards=["sample-guard"],
    )
    family.update(overrides)
    return family


def fixed_review(**overrides):
    review = {
        "finding_id": "finding-1",
        "root_cause_family": "evidence_identity",
        "capability_family": "evidence_identity",
        "invariant_id": "canonical_symbol_identity",
        "resolution_scope": "architecture",
        "status": "fixed",
        "audited_production_paths": ["scripts/step5_evidence_model.py"],
        "generalized_regression_tests": executable_family()["positive_tests"],
        "negative_regression_tests": executable_family()["negative_tests"],
        "mutation_tests": executable_family()["mutation_tests"],
        "cross_project_guards": ["sample-guard"],
        "architecture_decision": "All identity producers now use the canonical model.",
    }
    review.update(overrides)
    return review


def passing_real_payload():
    return {
        "status": "passed",
        "results": [{"case": "sample-guard", "status": "passed"}],
    }


class CapabilityFamilyRegistryTest(unittest.TestCase):
    def test_valid_registry_has_no_contract_errors(self):
        self.assertEqual(closure.validate_registry(valid_registry()), [])

    def test_load_registry_rejects_non_object_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(json.dumps([]), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "JSON object"):
                closure.load_registry(path)

    def test_duplicate_family_id_is_rejected(self):
        errors = closure.validate_registry(
            valid_registry(valid_family(), valid_family(invariant_id="other"))
        )

        self.assertIn("duplicate_family_id:evidence_identity", errors)

    def test_empty_invariant_is_rejected(self):
        errors = closure.validate_registry(valid_registry(valid_family(invariant="")))

        self.assertIn("missing_invariant:evidence_identity", errors)

    def test_family_without_production_paths_is_rejected(self):
        errors = closure.validate_registry(
            valid_registry(valid_family(production_paths=[]))
        )

        self.assertIn("missing_production_paths:evidence_identity", errors)

    def test_enforced_family_requires_every_test_category(self):
        for field in ("positive_tests", "negative_tests", "mutation_tests"):
            with self.subTest(field=field):
                errors = closure.validate_registry(
                    valid_registry(valid_family(**{field: []}))
                )
                self.assertIn(
                    f"missing_{field}:evidence_identity",
                    errors,
                )

    def test_duplicate_test_reference_across_categories_is_rejected(self):
        duplicate = valid_family()["positive_tests"][0]
        errors = closure.validate_registry(
            valid_registry(valid_family(negative_tests=[duplicate]))
        )

        self.assertIn(
            "duplicate_test_reference:evidence_identity:" + duplicate,
            errors,
        )

    def test_unknown_root_cause_mapping_is_rejected(self):
        errors = closure.validate_registry(
            valid_registry(valid_family(root_cause_families=["made_up_family"]))
        )

        self.assertIn(
            "unknown_root_cause_family:evidence_identity:made_up_family",
            errors,
        )


class CapabilityFamilyClosureTest(unittest.TestCase):
    def build(self, *, family=None, review=None, real=None, history=None):
        return closure.build_closure_report(
            valid_registry(family or executable_family()),
            real or passing_real_payload(),
            {"findings": [review or fixed_review()]},
            history or [],
            project_root=ROOT,
            retrospective_payload={
                "findings": [{"finding_id": (review or fixed_review())["finding_id"]}]
            },
        )

    def test_complete_architecture_closure_passes(self):
        report = self.build()

        self.assertEqual(closure.evaluate_closure(report), [])
        self.assertEqual(report["status"], "passed")

    def test_architecture_label_does_not_hide_partial_path_audit(self):
        family = executable_family(
            production_paths=[
                "scripts/step5_evidence_model.py",
                "scripts/step5_evidence_ingestion.py",
            ]
        )
        report = self.build(family=family)

        self.assertIn(
            "production_path_coverage_mismatch:finding-1",
            closure.evaluate_closure(report),
        )

    def test_extra_misspelled_path_is_rejected(self):
        review = fixed_review(
            audited_production_paths=[
                "scripts/step5_evidence_model.py",
                "scripts/step5_evidence_modle.py",
            ]
        )
        report = self.build(review=review)

        self.assertIn(
            "production_path_coverage_mismatch:finding-1",
            closure.evaluate_closure(report),
        )

    def test_unloadable_test_reference_reopens_finding(self):
        missing = "tests.missing_module.MissingTest.test_missing"
        family = executable_family(negative_tests=[missing])
        review = fixed_review(negative_regression_tests=[missing])
        report = self.build(family=family, review=review)

        self.assertIn(
            "unloadable_test_reference:finding-1:" + missing,
            closure.evaluate_closure(report),
        )

    def test_missing_mutation_test_reopens_finding(self):
        report = self.build(review=fixed_review(mutation_tests=[]))

        self.assertIn(
            "mutation_test_coverage_mismatch:finding-1",
            closure.evaluate_closure(report),
        )

    def test_non_passing_current_guard_reopens_finding(self):
        real = {
            "status": "failed",
            "results": [{"case": "sample-guard", "status": "failed"}],
        }
        report = self.build(real=real)

        self.assertIn(
            "cross_project_guard_not_passed:finding-1:sample-guard",
            closure.evaluate_closure(report),
        )

    def test_guard_with_incomplete_oracle_cannot_pass_by_status_label(self):
        real = {
            "status": "passed",
            "results": [{
                "case": "sample-guard",
                "status": "passed",
                "oracle_audit": {
                    "blocking": True,
                    "selected": 2185,
                    "verified": 2184,
                    "unverified": 1,
                    "incorrect": 0,
                    "oracle_conflicts": 0,
                },
            }],
        }

        report = self.build(real=real)

        self.assertIn(
            "cross_project_guard_oracle_incomplete:finding-1:sample-guard",
            closure.evaluate_closure(report),
        )

    def test_repeated_family_requires_architecture_decision(self):
        history = [{"root_cause_families": ["evidence_identity"]}]
        report = self.build(
            review=fixed_review(architecture_decision=""),
            history=history,
        )

        self.assertIn(
            "architecture_decision_required:finding-1:evidence_identity",
            closure.evaluate_closure(report),
        )

    def test_case_patch_is_rejected_even_when_all_evidence_is_present(self):
        report = self.build(review=fixed_review(resolution_scope="case_patch"))

        self.assertIn(
            "case_patch_forbidden:finding-1",
            closure.evaluate_closure(report),
        )

    def test_retrospective_finding_without_review_cannot_disappear(self):
        report = closure.build_closure_report(
            valid_registry(executable_family()),
            passing_real_payload(),
            {"findings": []},
            [],
            project_root=ROOT,
            retrospective_payload={"findings": [{"finding_id": "finding-missing"}]},
        )

        self.assertIn(
            "retrospective_finding_review_missing:finding-missing",
            closure.evaluate_closure(report),
        )


if __name__ == "__main__":
    unittest.main()
