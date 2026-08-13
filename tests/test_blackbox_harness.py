import copy
import json
from pathlib import Path
import unittest

from tests.blackbox.harness import evaluate_closed_truth


ROOT = Path(__file__).resolve().parents[1]
TRUTH_PATH = (
    ROOT / "tests" / "fixtures" / "blackbox" / "removed-methods-v1"
    / "truth.json"
)


def actual_row(expected):
    return {
        "display_owner": expected["owner"],
        "display_member": expected["member"],
        "display_descriptor": expected["descriptor"],
        "display_member_kind": expected["member_kind"],
        **{
            field: copy.deepcopy(expected[field])
            for field in (
                "dependency_lineages", "base_dependency_coords",
                "current_dependency_coords", "reachability_status",
                "static_linkage_status", "impact_conclusion",
                "runtime_verification_status", "exact_path_exists",
                "possible_path_exists", "path_set_complete",
            )
        },
        "paths": [
            {
                "path_certainty": path["certainty"],
                "path_text": path["text"],
            }
            for path in expected["paths"]
        ],
    }


class BlackboxHarnessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.truth = json.loads(TRUTH_PATH.read_text(encoding="utf-8"))
        cls.formal = {
            "by_api": [actual_row(row) for row in cls.truth["expected_results"]]
        }

    def test_exact_comparator_reports_zero_error_metrics(self):
        evaluation = evaluate_closed_truth(self.formal, self.truth)

        self.assertEqual(evaluation["status"], "passed", evaluation["issues"])
        self.assertEqual(evaluation["metrics"], {
            "expected_result_count": 3,
            "actual_result_count": 3,
            "true_positive_count": 3,
            "false_positive_count": 0,
            "false_negative_count": 0,
            "state_mismatch_count": 0,
            "path_mismatch_count": 0,
            "forbidden_hit_count": 0,
        })

    def test_comparator_rejects_false_negative_false_positive_state_and_path(self):
        mutations = {}

        missing = copy.deepcopy(self.formal)
        missing["by_api"].pop()
        mutations["false_negative"] = (missing, "false_negative_count")

        extra = copy.deepcopy(self.formal)
        unexpected = copy.deepcopy(extra["by_api"][0])
        unexpected.update(
            display_owner="contract/Unexpected", display_member="invented"
        )
        extra["by_api"].append(unexpected)
        mutations["false_positive"] = (extra, "false_positive_count")

        state = copy.deepcopy(self.formal)
        state["by_api"][0]["impact_conclusion"] = "inconclusive"
        mutations["state"] = (state, "state_mismatch_count")

        path = copy.deepcopy(self.formal)
        path["by_api"][0]["paths"][0]["path_text"] = "wrong path"
        mutations["path"] = (path, "path_mismatch_count")

        forbidden = copy.deepcopy(self.formal)
        forbidden["by_api"].append({
            **copy.deepcopy(forbidden["by_api"][0]),
            "display_member": "select",
            "display_descriptor": "()Ljava/lang/String;",
        })
        mutations["forbidden"] = (forbidden, "forbidden_hit_count")

        for name, (formal, metric) in mutations.items():
            with self.subTest(name=name):
                evaluation = evaluate_closed_truth(formal, self.truth)
                self.assertEqual(evaluation["status"], "failed")
                self.assertGreater(evaluation["metrics"][metric], 0)

    def test_comparator_rejects_duplicate_actual_identity(self):
        duplicate = copy.deepcopy(self.formal)
        duplicate["by_api"].append(copy.deepcopy(duplicate["by_api"][0]))

        evaluation = evaluate_closed_truth(duplicate, self.truth)

        self.assertEqual(evaluation["status"], "failed")
        self.assertIn("duplicate_actual_identity", evaluation["issues"])


if __name__ == "__main__":
    unittest.main()
