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

    def test_appendix_keeps_by_api_evidence_out_of_program_only_section(self):
        text = "\n".join(s6_report.render_report_appendix({"artifacts": {}}))

        self.assertIn("| `evidence/call_chain/by_api/*.json` | 单 API 原始链路证据；排查时按需读取 |", text)
        self.assertLess(text.index("#### 用户深入排查时看的产物"), text.index("`evidence/call_chain/by_api/*.json`"))
        self.assertLess(text.index("`evidence/call_chain/by_api/*.json`"), text.index("#### 程序使用的产物"))

    def test_bucket_detail_markdown_starts_with_reader_task_not_numeric_summary(self):
        config = {
            "title": "需人工复核清单",
            "conclusion": "需要人工复核",
            "note": "静态分析发现候选路径但存在歧义，需要人工核实。",
        }
        text = s6_report.build_bucket_detail_markdown(
            config,
            [
                {
                    "coord": "com.acme:demo",
                    "api": "com.acme.Demo.changed",
                    "change_type": "METHOD_CHANGED",
                    "symbol_kind": "method",
                    "severity": "P1",
                    "user_reason": "字节码命中但未确认业务入口",
                }
            ],
            "s6_uncertain_apis.csv",
        )

        self.assertIn("## 先看什么", text)
        self.assertIn("复核重点", text)
        self.assertLess(text.index("## 先看什么"), text.index("## 原因分类"))


if __name__ == "__main__":
    unittest.main()
