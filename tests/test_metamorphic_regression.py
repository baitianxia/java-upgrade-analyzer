import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from generated_topology import GenerationDimensions, generate_topology  # noqa: E402
from metamorphic_regression import (  # noqa: E402
    TRANSFORM_IDS,
    apply_transform,
    run_production_metamorphic_matrix,
    semantic_digest,
)


class MetamorphicRegressionTest(unittest.TestCase):
    def test_all_declared_transforms_preserve_closed_truth_identity(self):
        case = generate_topology(1729, GenerationDimensions.complete())
        expected = {edge.identity for edge in case.spec.truth_edges}

        for transform_id in TRANSFORM_IDS:
            with self.subTest(transform=transform_id):
                transformed = apply_transform(case, transform_id)
                self.assertEqual(
                    {edge.identity for edge in transformed.case.spec.truth_edges},
                    expected,
                )
                self.assertNotEqual(transformed.execution_variant, {})

    def test_semantic_digest_ignores_only_documented_volatility_and_order(self):
        first = {
            "apis": [{"identity": "b", "conclusion": "uncertain", "reason_codes": ["R2"]},
                     {"identity": "a", "conclusion": "reachable", "reason_codes": []}],
            "edges": [{"identity": "e2", "complete": True}, {"identity": "e1", "complete": True}],
            "elapsed_sec": 1.2,
            "report_path": "/tmp/one",
            "pid": 1,
            "generated_at": "now",
        }
        second = {
            "apis": list(reversed(first["apis"])),
            "edges": list(reversed(first["edges"])),
            "elapsed_sec": 99,
            "report_path": "/private/elsewhere",
            "pid": 999,
            "generated_at": "later",
        }

        self.assertEqual(semantic_digest(first), semantic_digest(second))

    def test_semantic_digest_changes_for_every_required_semantic_field(self):
        baseline = {
            "apis": [{"identity": "a", "conclusion": "reachable", "reason_codes": []}],
            "edges": [{"identity": "e", "complete": True}],
        }
        mutations = (
            {"apis": [{"identity": "a", "conclusion": "uncertain", "reason_codes": []}], "edges": baseline["edges"]},
            {"apis": [{"identity": "a", "conclusion": "reachable", "reason_codes": ["R"]}], "edges": baseline["edges"]},
            {"apis": baseline["apis"], "edges": [{"identity": "different", "complete": True}]},
            {"apis": baseline["apis"], "edges": [{"identity": "e", "complete": False}]},
        )

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertNotEqual(semantic_digest(baseline), semantic_digest(mutation))

    def test_every_transform_reexecutes_production_analysis_on_distinct_input(self):
        case = generate_topology(1729, GenerationDimensions.complete())
        with tempfile.TemporaryDirectory() as tmp:
            report = run_production_metamorphic_matrix(case, Path(tmp))

        self.assertEqual(report.status, "passed", report.errors)
        self.assertEqual(report.run_count, 1 + len(TRANSFORM_IDS))
        self.assertEqual(len(set(report.semantic_digests.values())), 1)
        baseline_sha = report.input_sha256["baseline"]
        self.assertTrue(
            all(
                value != baseline_sha
                for transform, value in report.input_sha256.items()
                if transform != "baseline"
            )
        )


if __name__ == "__main__":
    unittest.main()
