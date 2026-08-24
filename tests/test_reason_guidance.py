import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from diagnostic_contract import DEPENDENCY_COORDINATES_UNRESOLVED  # noqa: E402
from reason_guidance import (  # noqa: E402
    REASON_GUIDANCE_SCHEMA,
    build_catalog_guidance,
    build_diagnostic_guidance_from_summary,
    guidance_for_reason_code,
)


class ReasonGuidanceTest(unittest.TestCase):
    def test_origin_normalization_and_empty_catalog_are_total(self):
        self.assertEqual(
            guidance_for_reason_code("UNKNOWN", origin_step=None)["origin_step"],
            "",
        )
        self.assertEqual(
            guidance_for_reason_code(
                "UNKNOWN", origin_step=" STEP6 "
            )["origin_step"],
            "step6",
        )
        self.assertEqual(build_catalog_guidance(None), [])

    def test_catalog_deduplicates_filters_and_projects_explicit_source_scope(self):
        rows = build_catalog_guidance(
            [None, "", " archive unsafe ", "ARCHIVE_UNSAFE"],
            origin_step="step3",
            observed_scope="artifact",
            source_components=["scanner", "oracle"],
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["reason_code"], "ARCHIVE_UNSAFE")
        self.assertEqual(rows[0]["origin_step"], "step3")
        self.assertEqual(rows[0]["observed_scope"], "artifact")
        self.assertEqual(rows[0]["source_components"], ["scanner", "oracle"])

        default_components = build_catalog_guidance(["UNKNOWN"])
        self.assertEqual(default_components[0]["source_components"], [])

    def test_empty_and_sparse_summary_use_explicit_unknown_defaults(self):
        self.assertEqual(build_diagnostic_guidance_from_summary(None), [])
        rows = build_diagnostic_guidance_from_summary({
            "uncertain_apis": [
                None,
                {"reason_code": "", "analysis_status": "", "api": ""},
                {
                    "reason_code": "UNKNOWN",
                    "analysis_status": "unknown",
                    "api": "demo.A.run()",
                },
                {
                    "reason_code": "UNKNOWN",
                    "analysis_status": "unknown",
                    "api": "demo.A.run()",
                },
            ],
            "not_analyzed_apis": None,
        })

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["origin_step"], "step5")
        self.assertEqual(row["affected_api_count"], 4)
        self.assertEqual(row["affected_status_counts"], {"unknown": 4})
        self.assertEqual(row["sample_apis"], ["demo.A.run()"])

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

    def test_summary_guidance_groups_canonical_codes_and_statuses(self):
        rows = build_diagnostic_guidance_from_summary({
            "origin_step": "step5",
            "uncertain_apis": [{
                "reason_code": "archive unsafe",
                "analysis_status": "uncertain",
                "api": "demo.A.run()",
            }],
            "not_analyzed_apis": [
                {
                    "reason_code": "ARCHIVE_UNSAFE",
                    "analysis_status": "not_analyzed",
                    "api": "demo.B.run()",
                },
                {
                    "reason_code": "binary pipeline timeout",
                    "analysis_status": "not_analyzed",
                    "api": "demo.C.run()",
                },
            ],
        })

        by_code = {row["reason_code"]: row for row in rows}
        self.assertEqual(by_code["ARCHIVE_UNSAFE"]["affected_api_count"], 2)
        self.assertEqual(
            by_code["ARCHIVE_UNSAFE"]["affected_status_counts"],
            {"uncertain": 1, "not_analyzed": 1},
        )
        self.assertEqual(
            by_code["ARCHIVE_UNSAFE"]["sample_apis"],
            ["demo.A.run()", "demo.B.run()"],
        )
        self.assertIn("BINARY_PIPELINE_TIMEOUT", by_code)


if __name__ == "__main__":
    unittest.main()
