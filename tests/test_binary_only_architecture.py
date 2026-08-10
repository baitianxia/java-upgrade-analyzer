import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


class BinaryOnlyArchitectureTest(unittest.TestCase):
    def test_removed_analysis_engines_are_physically_absent(self):
        removed = (
            "s4_jar_compare.py",
            "s5_call_chain.py",
            "s5_call_chain_engine_integrated.py",
            "binary_compat_output.py",
            "confidence_weighted_tracer.py",
            "enhanced_output_formatter.py",
        )
        self.assertEqual(
            [name for name in removed if (SCRIPTS / name).exists()],
            [],
        )
        self.assertTrue((SCRIPTS / "s6_report.py").is_file())

    def test_orchestrator_has_no_gray_release_or_legacy_engine_switch(self):
        source = (SCRIPTS / "run_step.py").read_text(encoding="utf-8")
        forbidden = (
            "--allow-degraded",
            "--engine-mode",
            "--japicmp-jar",
            "shadow_mode",
            "legacy_fallback",
        )
        self.assertEqual([item for item in forbidden if item in source], [])

    def test_step1_gate_uses_only_binary_runtime_closure_purpose(self):
        gate = (SCRIPTS / "gate.py").read_text(encoding="utf-8")
        materializer = (SCRIPTS / "s1_dep_diff.py").read_text(encoding="utf-8")
        self.assertIn('"binary_runtime"', gate)
        self.assertIn("'binary_runtime'", materializer)
        self.assertNotIn("step5_runtime", gate)
        self.assertNotIn("step5_runtime", materializer)

    def test_design_does_not_require_normal_users_to_handwrite_binary_config(self):
        design = (
            ROOT / "docs/developer/binary-first-source-overlay-design.md"
        ).read_text(encoding="utf-8")
        self.assertIn("正常用户流程不要求用户手写", design)
        self.assertIn("Step1", design)
        self.assertIn("仅用于高级集成", design)
        self.assertNotIn("Step4 必须接收显式 `binary_pipeline_config`", design)

    def test_step_manifest_routes_one_binary_generation_and_report_path(self):
        manifest = json.loads((SCRIPTS / "step_manifest.json").read_text())
        steps = {item["id"]: item for item in manifest["steps"]}
        self.assertEqual(steps["step4"]["gate"], "binary_generation")
        self.assertEqual(steps["step5"]["gate"], "binary_report")
        rendered = json.dumps(manifest, ensure_ascii=False)
        self.assertNotIn("s4_jar_compare", rendered)
        self.assertNotIn("s5_call_chain_engine_integrated", rendered)

    def test_publication_separates_user_evidence_internal_authority_and_deliverables(self):
        source = (SCRIPTS / "binary_report.py").read_text(encoding="utf-8")
        constants = (SCRIPTS / "pipeline_constants.py").read_text(encoding="utf-8")
        self.assertIn(".runtime/binary_authority", source)
        self.assertIn("EVIDENCE_API_CHANGES_DIRNAME", constants)
        self.assertIn("EVIDENCE_CALL_CHAIN_DIRNAME", constants)
        self.assertIn("DELIVERABLES_DIRNAME", constants)
        self.assertIn("changed_dependencies.md", source)
        self.assertIn("review.md", source)

    def test_human_projection_preserves_binary_authority_boundaries(self):
        source = (SCRIPTS / "binary_report.py").read_text(encoding="utf-8")
        self.assertIn("import s6_report", source)
        self.assertIn("s6_report.generate_report", source)
        self.assertIn("reachability_status", source)
        self.assertIn("runtime_verification_status", source)
        self.assertNotIn("confirmed_impact", source)
        self.assertNotIn("confirmed_no_impact", source)


if __name__ == "__main__":
    unittest.main()
