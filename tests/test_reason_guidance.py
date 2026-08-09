import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from diagnostic_contract import DEPENDENCY_COORDINATES_UNRESOLVED  # noqa: E402
from reason_guidance import REASON_GUIDANCE_SCHEMA, guidance_for_reason_code  # noqa: E402


class ReasonGuidanceTest(unittest.TestCase):
    def test_dependency_identity_gap_has_human_action_and_verification(self):
        result = guidance_for_reason_code(
            DEPENDENCY_COORDINATES_UNRESOLVED, origin_step="step1"
        )
        self.assertEqual(result["schema"], REASON_GUIDANCE_SCHEMA)
        self.assertEqual(result["origin_step"], "step1")
        self.assertIn("依赖", result["title"])
        self.assertTrue(result["repair_actions"])
        self.assertTrue(result["verification_steps"])
        self.assertNotIn("降级", " ".join(result["repair_actions"]))

    def test_unknown_binary_failure_never_suggests_old_engine_or_ignoring_gap(self):
        result = guidance_for_reason_code(
            "BINARY_INDEPENDENT_VALIDATION_FAILED", origin_step="step4"
        )
        rendered = str(result)
        self.assertEqual(result["origin_step"], "step4")
        self.assertIn("重跑", rendered)
        self.assertIn("不会调用旧引擎", rendered)
        self.assertNotIn("批准降级", " ".join(result["repair_actions"]))

    def test_invalid_origin_is_not_fabricated(self):
        result = guidance_for_reason_code("UNKNOWN", origin_step="step9")
        self.assertEqual(result["origin_step"], "")


if __name__ == "__main__":
    unittest.main()
