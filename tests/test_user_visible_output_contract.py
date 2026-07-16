import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


class UserVisibleOutputContractTest(unittest.TestCase):
    def read(self, relative):
        return (ROOT_DIR / relative).read_text(encoding="utf-8")

    def test_outputs_doc_explains_three_report_layers(self):
        text = self.read("docs/user/outputs.md")
        self.assertIn("deliverables/", text)
        self.assertIn("evidence/", text)
        self.assertIn(".runtime/", text)
        self.assertIn("交付", text)
        self.assertIn("复核", text)
        self.assertIn("程序", text)

    def test_outputs_doc_uses_reader_facing_conclusion_terms(self):
        text = self.read("docs/user/outputs.md")
        reading_section = text[text.index("建议按这个顺序阅读：") : text.index("每个用户可见文件")]

        self.assertIn("需人工复核", reading_section)
        self.assertIn("缺少依赖源码/构建产物", reading_section)
        self.assertNotIn("当前无法确认", reading_section)
        self.assertIn("本次未完成分析", text)
        self.assertNotIn("当前未完成有效分析", text)

    def test_outputs_doc_explains_dependency_level_step4_selection(self):
        text = self.read("docs/user/outputs.md")
        self.assertIn("changed_dependencies.md", text)
        self.assertIn("changed_dependencies.csv", text)
        self.assertIn("依赖包维度", text)
        self.assertIn("all_changed_apis.csv", text)
        self.assertIn("完整 API", text)

    def test_outputs_doc_separates_human_first_files_from_program_files(self):
        text = self.read("docs/user/outputs.md")
        self.assertIn("人工优先看的文件", text)
        self.assertIn("深度排查或程序使用的文件", text)
        step5_text = text[text.index("## 系统触达证据") : text.index("## 系统触达证据结论")]
        self.assertLess(step5_text.index("`alerts.csv` | 人工优先入口"), step5_text.index("`summary.json`"))
        self.assertIn("`.runtime/indexes/s5_query_index.json` | 程序使用", text)
        self.assertIn("`.runtime/findings/s6_findings.json` | 程序使用", text)
        self.assertIn(".runtime/observability/step1_progress.jsonl", text)
        self.assertIn(".runtime/observability/step4_timing.csv", text)
        self.assertIn(".runtime/observability/step5_timing.csv", text)

    def test_skill_doc_requires_user_facing_decision_card(self):
        text = self.read("SKILL.md")
        self.assertIn("决策卡片", text)
        self.assertIn("可直接回复", text)
        self.assertIn("不要把 action_requirements", text)
        self.assertIn("覆盖当前所有交互点", text)
        self.assertNotIn("原样转述", text)
        self.assertNotIn("原样列出", text)

    def test_claude_code_runtime_docs_exclude_developer_test_governance(self):
        skill = self.read("SKILL.md")
        runbook = self.read("RUNBOOK.md")
        quality = self.read("docs/developer/quality.md")

        self.assertIn("给 Claude Code 使用", skill)
        self.assertIn("${CLAUDE_SKILL_DIR}", skill)
        self.assertNotIn("$SKILL", skill)
        for maintenance_entry in (
            "scripts/accuracy_benchmark.py",
            "scripts/quality_signal_audit.py",
            "scripts/test_round_retrospective.py",
            "scripts/quality_gate.py --profile release",
        ):
            self.assertNotIn(maintenance_entry, skill)
            self.assertIn(maintenance_entry, quality)
        self.assertNotIn("## 开发者测试", runbook)
        self.assertNotIn("scripts/real_project_regression.py", runbook)
        self.assertNotIn("$SKILL", runbook)

    def test_checkpoint_rules_keep_internal_protocol_out_of_user_main_message(self):
        text = self.read("CHECKPOINT_RULES.md")
        self.assertIn("当前所有交互点", text)
        self.assertIn("用户主信息", text)
        self.assertIn("response_schema", text)
        self.assertNotIn("原样转述", text)

    def test_landing_docs_prefer_report_and_dependency_level_selection(self):
        readme = self.read("README.md")
        runbook = self.read("RUNBOOK.md")
        manifest = self.read("scripts/step_manifest.json")

        self.assertIn(".upgrade-report/README.md", readme)
        self.assertIn(".upgrade-report/evidence/context/review.md", readme)
        self.assertNotIn(".upgrade-report/evidence/*/README.md", readme)
        self.assertLess(
            readme.index(".upgrade-report/deliverables/report.md"),
            readme.index(".upgrade-report/evidence/api_changes/changed_dependencies.md"),
        )
        self.assertIn("README.md", runbook)
        self.assertNotIn("api_changes/\n      README.md", runbook)
        self.assertNotIn("call_chain/\n      README.md", runbook)
        self.assertIn("changed_dependencies.md", runbook)
        self.assertIn("changed_dependencies.csv", manifest)
        self.assertIn("selection_key", manifest)


if __name__ == "__main__":
    unittest.main()
