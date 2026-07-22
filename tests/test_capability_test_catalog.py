import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import branch_coverage_gate  # noqa: E402
import capability_test_catalog as catalog  # noqa: E402


class CapabilityTestCatalogTest(unittest.TestCase):
    def setUp(self):
        self.registry = json.loads(
            (ROOT / "tests/fixtures/capability_families.json").read_text(encoding="utf-8")
        )
        self.manifest = json.loads(
            (ROOT / "tests/fixtures/test_profiles.json").read_text(encoding="utf-8")
        )

    def test_every_enforced_capability_reference_is_automatically_loadable(self):
        self.assertEqual(catalog.validate_capability_references(self.registry), [])

    def test_quick_profile_is_generated_from_family_tags_and_explicit_properties(self):
        built = catalog.build_profile_catalog(self.registry, self.manifest, "quick")

        self.assertEqual(built["errors"], [])
        self.assertIn("canonical_evidence_identity", built["capability_families"])
        self.assertTrue(any("SemanticPropertyTest" in item for item in built["test_ids"]))
        self.assertGreaterEqual(len(built["test_ids"]), 20)

    def test_stable_shards_are_disjoint_and_exhaustive(self):
        tests = [f"tests.example.TestCase.test_{index}" for index in range(100)]
        first = [catalog.shard_test_ids(tests, index, 4) for index in range(4)]
        second = [catalog.shard_test_ids(reversed(tests), index, 4) for index in range(4)]

        self.assertEqual(first, second)
        self.assertEqual(sorted(item for shard in first for item in shard), sorted(tests))
        self.assertEqual(sum(len(set(shard)) for shard in first), len(tests))

    def test_repeat_runner_reports_flaky_outcomes_and_duration_ranking(self):
        test_id = "tests.synthetic.Case.test_value"

        class Result:
            def __init__(self, outcome, duration, success):
                self.outcomes = {test_id: outcome}
                self.durations = {test_id: duration}
                self._success = success

            def wasSuccessful(self):
                return self._success

        results = iter((Result("passed", 0.01, True), Result("failed", 0.02, False)))

        class Runner:
            def __init__(self, **_kwargs):
                pass

            def run(self, _suite):
                return next(results)

        with patch.object(catalog.unittest, "TextTestRunner", Runner):
            observed = catalog.run_catalog([test_id], repeat=2, max_test_seconds=1.0)

        self.assertEqual(observed["status"], "failed")
        self.assertEqual(observed["flaky_tests"], [test_id])
        self.assertEqual(observed["duration_ranking"][0]["mean_seconds"], 0.015)

    def test_branch_arc_model_counts_true_false_decisions_not_lines(self):
        source = (
            "def choose(value):\n"
            "    if value > 0:\n"
            "        return 'positive'\n"
            "    if value < 0:\n"
            "        return 'negative'\n"
            "    return 'zero'\n"
        )

        arcs = branch_coverage_gate.function_branch_arcs(source, ["choose"])["choose"]

        self.assertEqual(arcs, {(2, 3), (2, 4), (4, 5), (4, 6)})


if __name__ == "__main__":
    unittest.main()
