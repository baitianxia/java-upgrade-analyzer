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

    def test_outputs_doc_explains_dependency_level_step4_selection(self):
        text = self.read("docs/user/outputs.md")
        self.assertIn("changed_dependencies.md", text)
        self.assertIn("changed_dependencies.csv", text)
        self.assertIn("依赖包维度", text)
        self.assertIn("all_changed_apis.csv", text)
        self.assertIn("完整 API", text)

    def test_skill_doc_requires_user_facing_decision_card(self):
        text = self.read("SKILL.md")
        self.assertIn("决策卡片", text)
        self.assertIn("可直接回复", text)
        self.assertIn("不要把 action_requirements", text)
        self.assertIn("覆盖当前所有交互点", text)
        self.assertNotIn("原样转述", text)
        self.assertNotIn("原样列出", text)

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
        self.assertLess(
            readme.index(".upgrade-report/deliverables/report.md"),
            readme.index(".upgrade-report/evidence/api_changes/changed_dependencies.md"),
        )
        self.assertIn("README.md", runbook)
        self.assertIn("changed_dependencies.md", runbook)
        self.assertIn("changed_dependencies.csv", manifest)
        self.assertIn("selection_key", manifest)


if __name__ == "__main__":
    unittest.main()
