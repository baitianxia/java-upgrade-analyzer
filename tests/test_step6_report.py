import sys
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s6_report  # noqa: E402


class Step6ReportObjectivityTest(unittest.TestCase):
    def test_report_template_does_not_use_prescriptive_action_words(self):
        forbidden = [
            "建议修改",
            "建议验证",
            "应该修改",
            "应该验证",
            "发布建议",
            "处置建议",
        ]
        text = "\n".join(s6_report.build_report_sections_for_test_only())
        for phrase in forbidden:
            self.assertNotIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
