import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from claude_skill_contract import (  # noqa: E402
    TRANSFORM_IDS,
    audit_public_contract,
    run_skill_contract,
    run_skill_contract_metamorphic_matrix,
)


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

    def test_static_audit_rejects_checkpoint_absent_from_manifest_state_machine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "run_step.py").write_text("", encoding="utf-8")
            (scripts / "step_manifest.json").write_text(json.dumps({
                "steps": [{
                    "id": "step5",
                    "auto_continue_on_success": True,
                    "interaction": None,
                }],
            }), encoding="utf-8")
            (root / "SKILL.md").write_text(
                "\n".join((
                    'python3 "${CLAUDE_SKILL_DIR}/scripts/run_step.py" '
                    '--report-dir .upgrade-report',
                    ".upgrade-report/.runtime/state/main_state.json",
                    ".upgrade-report/.runtime/state/interaction.json",
                    "--describe-step1-contract",
                    "--response-json",
                    "### Phase 8 [AUTO] Call Chain Analysis",
                    "- 对应步骤：`step5`",
                    "### Phase 9 [CHECKPOINT] Confirm Impact Judgment",
                    "- 对应步骤：`step5` 完成后进入",
                )),
                encoding="utf-8",
            )

            errors = audit_public_contract(root)

        self.assertIn(
            "skill_checkpoint_missing_manifest_interaction:step5",
            errors,
        )

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

    def test_terminal_status_and_checkpoint_docs_follow_manifest_contract(self):
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        rules = (ROOT / "CHECKPOINT_RULES.md").read_text(encoding="utf-8")

        self.assertNotIn("Confirm Impact Judgment", skill)
        self.assertIn("### Phase 9 [AUTO] Final Report", skill)
        self.assertIn("completed_with_limits", skill)
        self.assertIn("完整限制清单", rules)
        self.assertIn("Step5 成功后的例行复核", rules)

    def test_public_commands_avoid_windows_python3_alias_and_document_background_state(self):
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertNotRegex(skill, r"(?m)^\s*python3\s+")
        self.assertIn("--background", skill)
        self.assertIn(".upgrade-report/.runtime/background/status.json", skill)
        self.assertIn("启动命令返回 `0` 只表示后台进程创建成功", skill)

    def test_cross_session_startup_reads_compact_resume_snapshot_first(self):
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")

        last_summary = ".upgrade-report/.runtime/state/last_step_summary.json"
        resume_context = ".upgrade-report/.runtime/state/resume_context.md"
        main_state = ".upgrade-report/.runtime/state/main_state.json"
        execution_mode = skill[skill.index("## 执行模式"):]

        self.assertIn(last_summary, skill)
        self.assertIn(resume_context, skill)
        self.assertLess(
            execution_mode.index("last_step_summary = read"),
            execution_mode.index("main_state = read"),
        )
        self.assertIn("轻量摘要与主状态冲突时以主状态为准", skill)
        self.assertIn(main_state, skill)

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
