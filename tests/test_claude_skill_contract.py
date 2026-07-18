import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from claude_skill_contract import audit_public_contract, run_skill_contract  # noqa: E402


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
        self.assertNotEqual(report.failed_resume_returncode, 0)

    def test_repository_public_contract_has_no_undeclared_or_stale_entrypoint(self):
        self.assertEqual(audit_public_contract(ROOT), ())


if __name__ == "__main__":
    unittest.main()
