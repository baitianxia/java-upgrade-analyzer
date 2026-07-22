import sys
import tempfile
import csv
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s6_report  # noqa: E402


class Step6ReportObjectivityTest(unittest.TestCase):
    def test_report_link_keeps_external_absolute_path_valid(self):
        path = "/tmp/build/app-current.jar"

        self.assertEqual(
            s6_report._report_link(path),
            f"[{path}]({path})",
        )

    def test_scope_page_does_not_link_to_missing_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            (report_dir / "evidence" / "api_changes").mkdir(parents=True)
            (report_dir / "evidence" / "api_changes" / "all_changed_apis.csv").write_text(
                "coord\n", encoding="utf-8"
            )

            relative_path = s6_report.write_analysis_scope_artifact(
                report_dir,
                {"analysis_scope": {"mode": "full"}},
            )
            text = (report_dir / relative_path).read_text(encoding="utf-8")

        self.assertIn("[all_changed_apis.csv](../evidence/api_changes/all_changed_apis.csv)", text)
        self.assertIn("变化依赖摘要：本轮未生成，不作为结论依据", text)
        self.assertNotIn("[changed_dependencies.md]", text)

    def test_analysis_scope_artifact_exposes_partial_boundary_and_exact_dependencies(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = {
                "analysis_scope": {
                    "mode": "partial",
                    "included_dependency_count": 1,
                    "available_dependency_count": 3,
                    "analyzed_api_count": 7,
                    "total_api_count": 19,
                    "included_dependency_coords": ["com.acme:alpha"],
                    "excluded_dependency_coords": ["com.acme:beta", "com.acme:gamma"],
                }
            }

            relative_path = s6_report.write_analysis_scope_artifact(tmp, findings)
            text = (Path(tmp) / relative_path).read_text(encoding="utf-8")

        self.assertEqual(relative_path, "deliverables/analysis-scope.md")
        self.assertIn("**模式**：部分分析", text)
        self.assertIn("**已纳入变化依赖**：1/3", text)
        self.assertIn("**已纳入变化 API**：7/19", text)
        self.assertIn("`com.acme:alpha`", text)
        self.assertIn("`com.acme:beta`", text)
        self.assertIn("不得据此得出整个系统不受影响的结论", text)

    def test_analysis_scope_artifact_defines_what_full_means(self):
        with tempfile.TemporaryDirectory() as tmp:
            relative_path = s6_report.write_analysis_scope_artifact(
                tmp,
                {
                    "analysis_scope": {
                        "mode": "full",
                        "included_dependency_count": 2,
                        "available_dependency_count": 2,
                    }
                },
            )
            text = (Path(tmp) / relative_path).read_text(encoding="utf-8")

        self.assertIn("**模式**：全量分析", text)
        self.assertIn("依赖 API 变化分析识别出的全部变化依赖", text)
        self.assertIn("不等于覆盖所有未变化依赖", text)

    def test_partial_scope_is_explicit_in_conclusion_and_limitations(self):
        findings = {
            "scan_stats": {"call_chain_status": "done"},
            "coverage": {"overall_status": "complete"},
            "analysis_scope": {
                "mode": "partial",
                "included_dependency_count": 1,
                "available_dependency_count": 3,
                "excluded_dependency_coords": ["com.acme:beta", "com.acme:gamma"],
            },
        }

        conclusion = "\n".join(s6_report.render_core_conclusion(findings))
        limitations = "\n".join(s6_report.render_limitations_section(findings))

        self.assertIn("本次仅分析用户选择的部分依赖", conclusion)
        self.assertIn("| 分析范围 | 部分依赖（1/3） |", conclusion)
        self.assertIn("不得据此得出全局无影响结论", limitations)
        self.assertIn("com.acme:beta", limitations)

    def test_missing_scope_snapshot_is_not_reported_as_full_analysis(self):
        findings = {
            "scan_stats": {"call_chain_status": "done"},
            "coverage": {"overall_status": "complete"},
        }

        conclusion = "\n".join(s6_report.render_core_conclusion(findings))
        limitations = "\n".join(s6_report.render_limitations_section(findings))

        self.assertIn("未记录（不得按全量结论解释）", conclusion)
        self.assertIn("分析范围快照缺失", limitations)
        self.assertIn("不得按全量分析或全局无影响结论解释", limitations)

    def test_core_conclusion_links_to_human_scope_artifact(self):
        text = "\n".join(
            s6_report.render_core_conclusion(
                {
                    "scan_stats": {},
                    "coverage": {"overall_status": "complete"},
                    "analysis_scope": {"mode": "full"},
                    "artifacts": {"analysis_scope_md": "deliverables/analysis-scope.md"},
                }
            )
        )

        self.assertIn("[查看本轮分析范围](analysis-scope.md)", text)

    def test_csv_rows_can_be_consumed_without_materializing_a_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.csv"
            path.write_text("api,path_status\na,reached\nb,uncertain\n", encoding="utf-8")

            rows = s6_report.iter_csv_rows(path)
            first = next(rows)
            remaining = list(rows)

        self.assertNotIsInstance(rows, list)
        self.assertEqual(first["api"], "a")
        self.assertEqual([row["api"] for row in remaining], ["b"])

    def test_invalid_json_input_is_reported_as_a_findings_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.json"
            path.write_text("{not-json", encoding="utf-8")
            diagnostics = []

            value = s6_report.load_json(path, diagnostics=diagnostics, artifact="step5_summary")

        self.assertEqual(value, {})
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["artifact"], "step5_summary")
        self.assertEqual(diagnostics[0]["stage"], "json_load")
        self.assertEqual(diagnostics[0]["error_type"], "JSONDecodeError")

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
        self.assertIn("## API 明细（完整）", text)
        self.assertIn("## 附录：聚合统计", text)
        self.assertIn("### 原因分类", text)
        self.assertLess(text.index("## API 明细（完整）"), text.index("## 附录：聚合统计"))
        self.assertLess(text.index("## 附录：聚合统计"), text.index("### 原因分类"))

    def test_core_conclusion_translates_internal_call_chain_status(self):
        text = "\n".join(
            s6_report.render_core_conclusion(
                {
                    "scan_stats": {"call_chain_status": "partial"},
                    "coverage": {"overall_status": "partial"},
                }
            )
        )

        self.assertIn("| 调用链分析状态 | 部分完成 |", text)
        self.assertNotIn("| 调用链分析状态 | `partial` |", text)

    def test_report_separates_conclusion_certainty_from_risk_level(self):
        findings = {
            "scan_stats": {"call_chain_status": "done"},
            "coverage": {"overall_status": "complete"},
            "analysis_scope": {"mode": "full"},
            "p0": [{"coord": "com.acme:lib", "api": "com.acme.Api.run", "severity": "P0"}],
            "p2": [{"coord": "com.acme:lib", "api": "com.acme.Api.read", "severity": "P2"}],
        }

        conclusion = "\n".join(s6_report.render_core_conclusion(findings))
        result_table = "\n".join(s6_report.render_api_result_table(findings))

        self.assertIn("| 已确认影响项 | 2 |", conclusion)
        self.assertIn("| 其中高风险（P0/P1） | 1 |", conclusion)
        self.assertNotIn("已确认/高风险影响", conclusion + result_table)
        self.assertIn("严重级别：P0", result_table)

    def test_report_matches_display_coordinate_and_signed_symbol_to_reachable_evidence(self):
        findings = {
            "impact_overview": {
                "apis": [
                    {
                        "api_id": "api-1",
                        "coord": "com.vendor:legacy-lib（1.0.0 → -）",
                        "api": "com.vendor.LegacyApi.removed(String)",
                        "api_signature": "(String)",
                        "symbol_kind": "method",
                        "change_type": "METHOD_REMOVED",
                        "path_count": 3,
                        "paths": ["com.app.App.run → com.vendor.LegacyApi.removed"],
                        "paths_by_status": {
                            "reachable": [
                                "com.app.App.run → com.vendor.LegacyApi.removed"
                            ]
                        },
                        "path_counts_by_status": {"reachable": 3},
                    }
                ]
            },
            "p1": [
                {
                    "coord": "com.vendor:legacy-lib",
                    "api": "com.vendor.LegacyApi.removed",
                    "api_signature": "(String)",
                    "symbol_kind": "method",
                    "change_type": "METHOD_REMOVED",
                    "severity": "P1",
                }
            ],
        }

        rows = s6_report.build_api_result_rows(findings)
        report = "\n".join(s6_report.render_api_result_table(findings))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["confirmed_path_count"], 3)
        self.assertEqual(
            rows[0]["paths"],
            ["com.app.App.run → com.vendor.LegacyApi.removed"],
        )
        self.assertIn("已确认链路 3 条", report)
        self.assertNotIn("尚未回溯到业务入口", report)

    def test_next_review_steps_are_derived_from_evidence_boundaries(self):
        text = "\n".join(
            s6_report.render_next_review_steps(
                {
                    "coverage": {
                        "overall_status": "partial",
                        "critical_incomplete": ["behavior_diff"],
                    },
                    "analysis_scope": {"mode": "partial"},
                    "p1": [{"api": "com.acme.Api.run"}],
                    "uncertain": [{"api": "com.acme.Api.dynamic"}],
                    "needs_input": [{"api": "com.acme.Api.source"}],
                }
            )
        )

        self.assertIn("## 三、下一步复核顺序", text)
        self.assertIn("先处理结论边界", text)
        self.assertIn("复核 1 个已确认影响项", text)
        self.assertIn("收敛可能影响和需人工复核项", text)
        self.assertIn("补齐未完成证据", text)
        self.assertIn("完成标准", text)

    def test_core_conclusion_never_claims_complete_when_behavior_coverage_is_partial(self):
        text = "\n".join(
            s6_report.render_core_conclusion(
                {
                    "scan_stats": {"call_chain_status": "done", "call_chain_total": 1},
                    "coverage": {"overall_status": "partial"},
                    "not_impacted": [{"api": "com.acme.Api.run"}],
                }
            )
        )

        self.assertIn("分析覆盖仍不完整，当前结果不得解释为系统不受影响", text)
        self.assertIn("| 分析完整度 | 部分完整 |", text)
        self.assertNotIn("API 范围内完整", text)


if __name__ == "__main__":
    unittest.main()
