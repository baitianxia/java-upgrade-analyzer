import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from claude_skill_contract import (  # noqa: E402
    audit_public_contract,
    run_skill_contract,
    run_skill_contract_metamorphic_matrix,
)
from metamorphic_regression import TRANSFORM_IDS  # noqa: E402


class ClaudeSkillContractTest(unittest.TestCase):
    def test_static_audit_rejects_stale_command_and_wrong_output_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "SKILL.md").write_text(
                'python3 "${CLAUDE_SKILL_DIR}/scripts/missing.py" --report-dir wrong-report\n',
                encoding="utf-8",
            )

            errors = audit_public_contract(root)

        self.assertIn("stale_public_script:scripts/missing.py", errors)
        self.assertIn("public_report_path_must_be_upgrade_report", errors)

    def test_clean_copy_starts_and_stops_at_checkpoint_idempotently(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = run_skill_contract(ROOT, Path(tmp))

        self.assertEqual(report.status, "passed", report.errors)
        self.assertEqual(report.describe_returncode, 0)
        self.assertEqual(report.first_returncode, 4)
        self.assertEqual(report.rerun_returncode, 4)
        self.assertEqual(report.first_state_sha256, report.rerun_state_sha256)
        self.assertTrue(report.clean_copy_without_report_state)
        self.assertEqual(report.failed_resume_returncode, 1)

    def test_clean_copy_completes_public_step1_to_step6_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = run_skill_contract(ROOT, Path(tmp), complete_workflow=True)

        self.assertEqual(report.status, "passed", report.errors)
        self.assertEqual(report.completed_step, "step6")
        self.assertTrue(report.deliverables_verified)
        self.assertEqual(report.successful_rerun_returncode, 0)
        self.assertEqual(report.step4_api_count, 1)
        self.assertEqual(report.step5_accounted_api_count, 1)

    def test_repository_public_contract_has_no_undeclared_or_stale_entrypoint(self):
        self.assertEqual(audit_public_contract(ROOT), ())

    def test_all_metamorphic_variants_complete_step4_to_step5_closed_world(self):
        with tempfile.TemporaryDirectory() as tmp:
            reports = run_skill_contract_metamorphic_matrix(
                ROOT, Path(tmp), TRANSFORM_IDS
            )

        self.assertEqual(set(reports), set(TRANSFORM_IDS))
        self.assertTrue(all(report.status == "passed" for report in reports.values()))
        self.assertTrue(all(report.step4_api_count == 1 for report in reports.values()))
        self.assertTrue(
            all(report.step5_accounted_api_count == 1 for report in reports.values())
        )
        self.assertEqual(
            len({report.current_artifact_sha256 for report in reports.values()}),
            len(TRANSFORM_IDS),
        )


if __name__ == "__main__":
    unittest.main()
