import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generated_topology import GenerationDimensions, generate_topology  # noqa: E402
from generated_topology_regression import (  # noqa: E402
    AnalyzerLedgerRow,
    reconcile_generated_case,
    run_generated_case,
)


class GeneratedTopologyRegressionTest(unittest.TestCase):
    def setUp(self):
        self.case = generate_topology(41, GenerationDimensions.complete())
        self.clean_rows = tuple(
            AnalyzerLedgerRow(
                identity=edge.identity,
                conclusion=edge.expected_conclusion,
                evidence_complete=True,
                producer="production_classfile_or_typed_activation",
            )
            for edge in self.case.spec.truth_edges
        )

    def test_closed_world_rejects_omission_extra_descriptor_and_unsupported_strong_result(self):
        omitted = self.clean_rows[1:]
        extra = self.clean_rows + (
            AnalyzerLedgerRow("extra->edge@same_jar:bytecode", "reachable", True, "production"),
        )
        wrong = (
            replace(self.clean_rows[0], identity=self.clean_rows[0].identity + "X"),
            *self.clean_rows[1:],
        )
        unsupported = (
            replace(self.clean_rows[0], evidence_complete=False),
            *self.clean_rows[1:],
        )

        self.assertIn("missing_identity", reconcile_generated_case(self.case, omitted).errors)
        self.assertIn("extra_identity", reconcile_generated_case(self.case, extra).errors)
        wrong_result = reconcile_generated_case(self.case, wrong)
        self.assertIn("missing_identity", wrong_result.errors)
        self.assertIn("extra_identity", wrong_result.errors)
        self.assertIn(
            "unsupported_strong_conclusion",
            reconcile_generated_case(self.case, unsupported).errors,
        )

    def test_duplicate_and_conflicting_rows_are_blocking(self):
        duplicate = self.clean_rows + (self.clean_rows[0],)
        conflict = self.clean_rows + (
            replace(self.clean_rows[0], conclusion="uncertain"),
        )

        self.assertIn("duplicate_identity", reconcile_generated_case(self.case, duplicate).errors)
        self.assertIn("conflicting_identity", reconcile_generated_case(self.case, conflict).errors)

    def test_wrong_conclusion_is_blocking_even_when_identity_set_matches(self):
        wrong = (
            replace(self.clean_rows[0], conclusion="not_analyzed"),
            *self.clean_rows[1:],
        )

        self.assertIn("wrong_conclusion", reconcile_generated_case(self.case, wrong).errors)

    def test_runner_compiles_and_exercises_production_bytecode_collector(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_generated_case(self.case, Path(tmp))

        self.assertEqual(result.status, "passed")
        self.assertGreater(result.production_metrics["classes_scanned"], 0)
        self.assertGreater(result.production_metrics["edges_found"], 0)
        self.assertEqual(result.production_metrics["failures"], [])
        self.assertEqual(result.production_metrics["derived_rows"], 8)


if __name__ == "__main__":
    unittest.main()
