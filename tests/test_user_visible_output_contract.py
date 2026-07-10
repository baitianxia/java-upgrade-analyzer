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


if __name__ == "__main__":
    unittest.main()
