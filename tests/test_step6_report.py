import sys
import tempfile
import csv
import itertools
import json
import re
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s6_report  # noqa: E402


class Step6ReportObjectivityTest(unittest.TestCase):
    def test_count_lines_accepts_path_objects_used_by_collect_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "scan.csv"
            csv_path.write_text("name\nfirst\nsecond\n", encoding="utf-8")
            text_path = Path(tmp) / "scan.txt"
            text_path.write_text("# title\nfirst\n\nsecond\n", encoding="utf-8")

            self.assertEqual(s6_report.count_lines(csv_path), 2)
            self.assertEqual(s6_report.count_lines(text_path), 2)

    @staticmethod
    def _human_first_findings():
        return {
            "generated_at": "2026-07-25T10:00:00",
            "context": {"jdk": "17", "springboot": "3.3.0"},
            "scan_stats": {
                "call_chain_status": "done",
                "call_chain_total": 1,
            },
            "coverage": {
                "overall_status": "complete",
                "critical_incomplete": [],
                "components": [],
            },
            "analysis_scope": {
                "mode": "full",
                "included_dependency_count": 1,
                "available_dependency_count": 1,
            },
            "impact_overview": {
                "apis": [
                    {
                        "api_id": "api-payment-charge",
                        "coord": "com.acme:payments-client",
                        "api": "com.acme.payments.LegacyClient.charge",
                        "api_signature": "(Order)",
                        "symbol_kind": "method",
                        "change_type": "METHOD_REMOVED",
                        "path_count": 1,
                        "paths": [
                            "com.acme.checkout.PaymentService.submit → "
                            "com.acme.payments.LegacyClient.charge(Order)"
                        ],
                        "paths_by_status": {
                            "reachable": [
                                "com.acme.checkout.PaymentService.submit → "
                                "com.acme.payments.LegacyClient.charge(Order)"
                            ]
                        },
                        "path_counts_by_status": {"reachable": 1},
                        "sample_entries": [
                            "com.acme.checkout.PaymentService.submit"
                        ],
                    }
                ]
            },
            "p0": [
                {
                    "coord": "com.acme:payments-client",
                    "api": "com.acme.payments.LegacyClient.charge",
                    "api_signature": "(Order)",
                    "symbol_kind": "method",
                    "change_type": "METHOD_REMOVED",
                    "severity": "P0",
                    "user_conclusion": "已确认影响",
                    "user_reason": (
                        "支付提交流程已确认调用升级后删除的方法。"
                    ),
                    "business_entry": (
                        "com.acme.checkout.PaymentService.submit"
                    ),
                }
            ],
            "p1": [],
            "p2": [],
            "probable_impact": [],
            "uncertain": [],
            "not_impacted": [],
            "needs_input": [],
            "not_analyzed": [],
            "not_found": [],
            "diagnostic_guidance": [],
            "artifacts": {
                "alerts_csv": "evidence/call_chain/alerts.csv",
                "changed_apis_csv": (
                    "evidence/api_changes/all_changed_apis.csv"
                ),
            },
        }

    @staticmethod
    def _first_screen(report, line_limit=40):
        nonempty_lines = [
            line.strip() for line in report.splitlines() if line.strip()
        ]
        return "\n".join(nonempty_lines[:line_limit])

    @staticmethod
    def _write_collection_fixture(
        report_dir,
        *,
        summary,
        changed_rows,
        alert_rows,
        coverage=None,
        scope=None,
        context=None,
    ):
        report_dir = Path(report_dir)
        total = int(summary.get("total_apis") or 0)
        coverage_path = Path(s6_report._coverage_path(report_dir))
        coverage_path.parent.mkdir(parents=True, exist_ok=True)
        coverage_path.write_text(
            json.dumps(
                coverage
                or {
                    "overall_status": "complete",
                    "critical_incomplete": [],
                    "components": [],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        selection_path = Path(s6_report._step5_selection_path(report_dir))
        selection_path.parent.mkdir(parents=True, exist_ok=True)
        selection_path.write_text(
            json.dumps(
                scope
                or {
                    "mode": "full",
                    "available_dependency_count": 1 if total else 0,
                    "included_dependency_count": 1 if total else 0,
                    "total_api_count": total,
                    "analyzed_api_count": total,
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        if context is not None:
            context_path = Path(s6_report._context_path(report_dir))
            context_path.parent.mkdir(parents=True, exist_ok=True)
            context_path.write_text(
                json.dumps(context, ensure_ascii=False),
                encoding="utf-8",
            )

        call_chain_dir = report_dir / "evidence" / "call_chain"
        call_chain_dir.mkdir(parents=True, exist_ok=True)
        (call_chain_dir / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False),
            encoding="utf-8",
        )
        if alert_rows is not None:
            alert_fields = [
                "target_coord",
                "changed_symbol",
                "api_signature",
                "symbol_kind",
                "change_type",
                "severity",
                "old_version",
                "new_version",
                "path_status",
                "conclusion_level",
                "business_reachable",
                "business_entry",
                "chain_entry",
                "chain_target",
                "chain_hop_count",
                "path_text",
                "path_occurrence_count",
                "evidence_files",
                "review_reason",
                "reason",
            ]
            with (call_chain_dir / "alerts.csv").open(
                "w", encoding="utf-8", newline=""
            ) as output:
                writer = csv.DictWriter(
                    output, fieldnames=alert_fields
                )
                writer.writeheader()
                writer.writerows(alert_rows)

        changed_path = (
            report_dir
            / "evidence"
            / "api_changes"
            / "all_changed_apis.csv"
        )
        changed_path.parent.mkdir(parents=True, exist_ok=True)
        changed_fields = [
            "coord",
            "api_name",
            "api_signature",
            "symbol_kind",
            "change_type",
            "severity",
            "old_version",
            "new_version",
        ]
        with changed_path.open(
            "w", encoding="utf-8", newline=""
        ) as output:
            writer = csv.DictWriter(
                output,
                fieldnames=changed_fields,
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerows(changed_rows)

    def test_report_link_keeps_external_absolute_path_valid(self):
        path = "/tmp/build/app-current.jar"

        self.assertEqual(
            s6_report._report_link(path),
            f"[{path}]({path})",
        )

    def test_json_loader_rejects_utf8_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.json"
            path.write_bytes(
                b"\xef\xbb\xbf" + '{"message":"中文"}'.encode("utf-8")
            )
            diagnostics = []
            loaded = s6_report.load_json(
                path,
                diagnostics=diagnostics,
                artifact="call_chain_summary",
                required=True,
            )

        self.assertEqual(loaded, {})
        self.assertEqual(diagnostics[0]["stage"], "json_load")

    def test_call_summary_rejects_localized_conclusion_keys(self):
        summary = {
            "status": "skipped",
            "skip_reason": "no_changed_apis",
            "total_apis": 0,
            "reachable_apis": [],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
            "user_conclusion_summary": {"当前无法确定": 1},
        }
        diagnostics = []

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.json"
            path.write_text("{}", encoding="utf-8")
            s6_report._validate_call_summary_contract(
                path, summary, diagnostics
            )

        self.assertEqual(summary["user_conclusion_summary"], {})
        self.assertTrue(any(
            item.get("stage") == "json_contract"
            and "non-contract keys" in str(item.get("message") or "")
            for item in diagnostics
        ))

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
        self.assertIn(
            "**变化依赖**：总数 3；纳入本轮分析 1；未纳入 2",
            text,
        )
        self.assertIn(
            "**变化 API**：总数 19；纳入本轮分析 7；未纳入 12",
            text,
        )
        self.assertIn("`com.acme:alpha`", text)
        self.assertIn("`com.acme:beta`", text)
        self.assertIn(
            "用户指定的分析范围未包含该依赖",
            text,
        )
        self.assertIn("该范围不支持整个系统不受影响的结论", text)

    def test_partial_scope_requires_exact_included_dependency_coordinates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "step5_selection.json"
            path.write_text("{}", encoding="utf-8")
            scope = {
                "mode": "partial",
                "available_dependency_count": 2,
                "included_dependency_count": 1,
                "total_api_count": 2,
                "analyzed_api_count": 1,
                "included_dependency_coords": [],
                "excluded_dependency_coords": ["com.acme:beta"],
            }
            diagnostics = []

            s6_report._validate_analysis_scope_contract(
                path,
                scope,
                diagnostics,
            )

        self.assertEqual(scope["validation_status"], "invalid")
        self.assertEqual(scope["mode"], "")
        self.assertTrue(any(
            item.get("artifact") == "step5_selection"
            for item in diagnostics
        ))

    def test_partial_scope_requires_exact_excluded_dependency_coordinates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "step5_selection.json"
            path.write_text("{}", encoding="utf-8")
            scope = {
                "mode": "partial",
                "available_dependency_count": 3,
                "included_dependency_count": 1,
                "total_api_count": 3,
                "analyzed_api_count": 1,
                "included_dependency_coords": ["com.acme:alpha"],
                "excluded_dependency_coords": [],
            }
            diagnostics = []

            s6_report._validate_analysis_scope_contract(
                path,
                scope,
                diagnostics,
            )

        self.assertEqual(scope["validation_status"], "invalid")
        self.assertEqual(scope["mode"], "")
        self.assertTrue(any(
            item.get("artifact") == "step5_selection"
            for item in diagnostics
        ))

    def test_partial_scope_limits_all_step6_results_to_selected_dependencies(self):
        selected = {
            "coord": "com.acme:alpha",
            "api": "com.acme.AlphaApi.run",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
        }
        excluded = {
            "coord": "com.acme:beta",
            "api": "com.acme.BetaApi.run",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
        }
        with tempfile.TemporaryDirectory() as tmp:
            self._write_collection_fixture(
                tmp,
                summary={
                    "status": "done",
                    "total_apis": 1,
                    "reachable": 1,
                    "reachable_apis": [{
                        **selected,
                        "reason_code": "SYSTEM_CODE_REACHED",
                    }],
                },
                changed_rows=[
                    {**selected, "api_name": selected["api"]},
                    {**excluded, "api_name": excluded["api"]},
                ],
                alert_rows=[{
                    "target_coord": selected["coord"],
                    "changed_symbol": selected["api"],
                    "api_signature": selected["api_signature"],
                    "symbol_kind": selected["symbol_kind"],
                    "change_type": selected["change_type"],
                    "severity": selected["severity"],
                    "old_version": selected["old_version"],
                    "new_version": selected["new_version"],
                    "path_status": "reachable",
                    "conclusion_level": "confirmed",
                    "business_reachable": "true",
                    "business_entry": "com.app.Entry.run()",
                    "path_text": (
                        "com.app.Entry.run() -> "
                        "com.acme.AlphaApi.run()"
                    ),
                }],
                scope={
                    "mode": "partial",
                    "selection_basis": "explicit_targets",
                    "available_dependency_count": 2,
                    "included_dependency_count": 1,
                    "total_api_count": 2,
                    "analyzed_api_count": 1,
                    "included_dependency_coords": [
                        selected["coord"],
                    ],
                    "excluded_dependency_coords": [
                        excluded["coord"],
                    ],
                },
            )
            dependency_path = Path(s6_report._dep_changes_path(tmp))
            dependency_path.parent.mkdir(parents=True, exist_ok=True)
            with dependency_path.open(
                "w", encoding="utf-8", newline=""
            ) as output:
                writer = csv.DictWriter(
                    output,
                    fieldnames=[
                        "coord",
                        "old_version",
                        "new_version",
                        "change_type",
                    ],
                )
                writer.writeheader()
                writer.writerows([
                    {
                        "coord": item["coord"],
                        "old_version": item["old_version"],
                        "new_version": item["new_version"],
                        "change_type": "major",
                    }
                    for item in (selected, excluded)
                ])

            findings = s6_report.collect_findings(tmp)
            findings["artifacts"]["analysis_scope_md"] = (
                s6_report.write_analysis_scope_artifact(tmp, findings)
            )
            artifacts, api_model, dependency_model = (
                s6_report.write_primary_report_artifacts(tmp, findings)
            )
            findings["artifacts"].update(artifacts)
            report = s6_report.generate_report(findings)
            dependency_detail = (
                Path(tmp) / artifacts["full_dependency_analysis_md"]
            ).read_text(encoding="utf-8")
            api_detail = (
                Path(tmp) / artifacts["full_api_analysis_md"]
            ).read_text(encoding="utf-8")
            dependency_detail_csv = (
                Path(tmp) / artifacts["full_dependency_analysis_csv"]
            ).read_text(encoding="utf-8-sig")
            api_detail_csv = (
                Path(tmp) / artifacts["full_api_analysis_csv"]
            ).read_text(encoding="utf-8-sig")
            scope_detail = (
                Path(tmp) / findings["artifacts"]["analysis_scope_md"]
            ).read_text(encoding="utf-8")

        self.assertEqual(
            (
                dependency_model["total_count"],
                dependency_model["completed_count"],
                dependency_model["incomplete_count"],
                dependency_model["confirmed_any_count"],
            ),
            (1, 1, 0, 1),
        )
        self.assertEqual(
            (
                api_model["total_count"],
                api_model["completed_count"],
                api_model["incomplete_count"],
                api_model["confirmed_count"],
            ),
            (1, 1, 0, 1),
        )
        self.assertEqual(
            report.count("| 1 | 1 | 0 | 1 | 0 | 0 |"),
            2,
        )
        self.assertIn(
            "用户指定纳入 1/2 个变化依赖、1/2 个变化 API",
            report,
        )
        self.assertIn(
            "未纳入的 1 个依赖和 1 个 API 不计入“未完成分析”",
            report,
        )
        for result_text in (
            report,
            dependency_detail,
            dependency_detail_csv,
            api_detail,
            api_detail_csv,
        ):
            self.assertIn(selected["coord"], result_text)
            self.assertNotIn(excluded["coord"], result_text)
        self.assertIn(excluded["coord"], scope_detail)
        self.assertIn(
            "用户指定的分析范围未包含该依赖",
            scope_detail,
        )
        self.assertIn(
            "本轮分析范围内全部变化依赖",
            report,
        )
        self.assertIn(
            "本轮分析范围内全部变化 API",
            report,
        )
        self.assertEqual(
            report.count(
                "选择前原始记录全量 2 条；包含未纳入本轮分析的对象"
            ),
            2,
        )

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

        self.assertIn("部分分析（变化依赖 1/3）", conclusion)
        self.assertIn("只覆盖已选择的变化依赖", conclusion)
        self.assertIn("当前范围不支持全局无影响结论", limitations)
        self.assertIn("com.acme:beta", limitations)

    def test_missing_scope_snapshot_is_not_reported_as_full_analysis(self):
        findings = {
            "scan_stats": {"call_chain_status": "done"},
            "coverage": {"overall_status": "complete"},
        }

        conclusion = "\n".join(s6_report.render_core_conclusion(findings))
        limitations = "\n".join(s6_report.render_limitations_section(findings))

        self.assertIn("范围快照缺失，不能按全量分析解释", conclusion)
        self.assertIn("分析范围快照缺失", limitations)
        self.assertIn("报告不支持全量分析或全局无影响结论", limitations)

    def test_missing_scope_snapshot_does_not_label_report_details_as_complete_range(self):
        findings = self._human_first_findings()
        findings.pop("analysis_scope")

        with tempfile.TemporaryDirectory() as tmp:
            artifacts, _api_model, _dependency_model = (
                s6_report.write_primary_report_artifacts(tmp, findings)
            )
            findings["artifacts"].update(artifacts)
            report = s6_report.generate_report(findings)
            dependency_detail = (
                Path(tmp) / artifacts["full_dependency_analysis_md"]
            ).read_text(encoding="utf-8")
            api_detail = (
                Path(tmp) / artifacts["full_api_analysis_md"]
            ).read_text(encoding="utf-8")

        self.assertIn("**分析范围无法核验**", report)
        self.assertIn("现有记录中可识别", report)
        self.assertNotIn("本轮分析范围内全部", report)
        self.assertIn(
            "不能把本文件解释为本轮分析的完整依赖结果",
            dependency_detail,
        )
        self.assertIn(
            "不能把本文件解释为本轮分析的完整 API 结果",
            api_detail,
        )

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

        self.assertIn("[本轮分析范围](analysis-scope.md)", text)

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

    def test_csv_row_with_extra_values_is_diagnosed_without_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.csv"
            path.write_text(
                "coord,api_name\n"
                "com.acme:lib,com.acme.Api.run,unexpected\n",
                encoding="utf-8",
            )
            diagnostics = []

            rows = s6_report.load_csv(
                path,
                diagnostics=diagnostics,
                artifact="changed_apis",
            )

        self.assertEqual(rows, [])
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["artifact"], "changed_apis")
        self.assertEqual(diagnostics[0]["stage"], "csv_load")

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

    def test_report_states_objective_facts_without_advice_tasks_or_release_decisions(self):
        report = s6_report.generate_report(self._human_first_findings())

        self.assertIn("删除方法，参数：Order", report)
        self.assertIn("确认有影响", report)
        for non_objective_instruction in (
            "下一步复核顺序",
            "复核顺序",
            "完成标准",
            "待办",
            "建议",
            "修复动作",
            "可以直接发布",
            "建议直接发布",
            "无需验证即可发布",
            "本次升级可以放行",
            "保证兼容",
            "建议修改",
            "应该修改",
            "请修改",
            "需要修改",
            "必须修改",
            "建议发布",
            "应该发布",
            "请发布",
            "需要发布",
            "必须发布",
            "不替使用者决定",
            "具体代码修改",
            "发布动作",
        ):
            self.assertNotIn(non_objective_instruction, report)

    def test_report_first_screen_names_change_scope_certainty_dependency_api_entry_and_evidence(self):
        report = s6_report.generate_report(self._human_first_findings())
        first_screen = self._first_screen(report)

        for reader_fact in (
            "1 个变化依赖已确认存在当前系统调用关系",
            "变化依赖总数 | 已完成分析 | 未完成分析",
            "com.acme:payments-client",
            "com.acme.payments.LegacyClient.charge",
            "删除方法，参数：Order",
            "确认有影响",
            "com.acme.checkout.PaymentService.submit",
            (
                "com.acme.checkout.PaymentService.submit → "
                "com.acme.payments.LegacyClient.charge(Order)"
            ),
        ):
            self.assertIn(reader_fact, first_screen)
        self.assertIn("## 报告目录", first_screen)
        self.assertLess(
            first_screen.index("## 报告目录"),
            first_screen.index("1 个变化依赖已确认存在当前系统调用关系"),
        )
        self.assertNotIn("不替使用者决定", first_screen)

    def test_report_directory_uses_native_heading_links_without_html_tags(self):
        report = s6_report.generate_report(self._human_first_findings())
        toc = report[
            report.index("## 报告目录") : report.index("## 一、依赖层面结论")
        ]

        expected_links = (
            "[一、依赖层面结论](#一依赖层面结论)",
            "[已完成分析的依赖](#已完成分析的依赖展示-11)",
            "[二、API 及调用关系](#二api-及调用关系)",
            (
                "[已确认触达与结论未确定的 API]"
                "(#已确认触达与结论未确定的-api展示-11)"
            ),
            "[其他已完成状态统计](#其他已完成状态统计)",
            "[三、用户可见文件说明](#三用户可见文件说明)",
        )
        for link in expected_links:
            self.assertIn(link, toc)
        self.assertNotIn("[未完成分析的依赖]", toc)
        self.assertNotIn("[未完成分析的 API]", toc)
        self.assertNotIn("运行时资源变化及激活关系", toc)
        self.assertNotIn("all-affected-dependencies", toc)
        self.assertNotIn("all-impact-details", toc)

        targets = re.findall(r"\]\(#([^)]+)\)", toc)
        self.assertTrue(targets)
        heading_targets = {
            s6_report._markdown_heading_fragment(line)
            for line in report.splitlines()
            if re.match(r"^#{1,6}\s+", line)
        }
        for target in targets:
            self.assertIn(target, heading_targets)
        self.assertNotIn("<a ", report)
        self.assertLess(
            report.index("## 报告目录"),
            report.index("## 一、依赖层面结论"),
        )

    def test_report_directory_includes_rendered_conditional_sections(self):
        findings = self._human_first_findings()
        existing_api = findings["impact_overview"]["apis"][0]
        findings["changed_api_inventory"] = [
            dict(existing_api),
            {
                "coord": "com.acme:payments-client",
                "api": "com.acme.payments.NewClient.missing",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
                "old_version": "1.0",
                "new_version": "2.0",
            },
        ]
        findings["dependency_changes"] = [{
            "coord": "com.acme:payments-client",
            "old_version": "1.0",
            "new_version": "2.0",
            "change_type": "UPDATED",
        }]
        findings["resource_impacts"] = [{
            "coord": "com.acme:payments-client",
            "old_version": "1.0",
            "new_version": "2.0",
            "resource_name": "META-INF/services/com.acme.PaymentProvider",
            "activation_status": "reachable",
            "business_entries": ["com.acme.checkout.PaymentService.submit"],
        }]
        findings["analysis_scope"].update({
            "total_api_count": 2,
            "analyzed_api_count": 2,
        })

        report = s6_report.generate_report(findings)
        toc = report[
            report.index("## 报告目录") : report.index("## 一、依赖层面结论")
        ]

        for link in (
            "[未完成分析的依赖](#未完成分析的依赖展示-11)",
            "[未完成分析的 API](#未完成分析的-api展示-11)",
            (
                "[运行时资源变化及激活关系]"
                "(#运行时资源变化及激活关系展示-11)"
            ),
        ):
            self.assertIn(link, toc)
        self.assertNotIn("all-affected-dependencies", toc)
        self.assertNotIn("all-impact-details", toc)

    def test_detail_file_locations_are_beside_detail_sections_and_file_index_remains(self):
        report = s6_report.generate_report(self._human_first_findings())
        toc = report[
            report.index("## 报告目录") : report.index("## 一、依赖层面结论")
        ]
        dependency_section = report[
            report.index("## 一、依赖层面结论") : report.index("## 二、API 及调用关系")
        ]
        api_section = report[
            report.index("## 二、API 及调用关系") : report.index("## 三、用户可见文件说明")
        ]

        self.assertNotIn("all-affected-dependencies", toc)
        self.assertNotIn("all-impact-details", toc)
        for filename in (
            "all-affected-dependencies.md",
            "all-affected-dependencies.csv",
        ):
            self.assertIn(filename, dependency_section)
        for filename in (
            "all-impact-details.md",
            "all-impact-details.csv",
        ):
            self.assertIn(filename, api_section)
        self.assertIn("供人工逐项复核", report)
        self.assertIn("便于筛选", report)
        self.assertIn("## 三、用户可见文件说明", report)

    def test_main_report_limits_runtime_resource_detail_rows(self):
        findings = self._human_first_findings()
        findings["resource_impacts"] = [
            {
                "coord": f"com.acme:resource-{index:02d}",
                "old_version": "1.0",
                "new_version": "2.0",
                "resource_name": f"META-INF/services/com.acme.Provider{index:02d}",
                "activation_status": "reachable",
                "business_entries": [f"com.acme.Entry.load{index:02d}"],
            }
            for index in range(s6_report.S6_MAIN_RESOURCE_LIMIT + 1)
        ]

        rendered = "\n".join(s6_report.render_api_and_calls(findings))

        self.assertIn("运行时资源变化及激活关系（展示 12/13）", rendered)
        self.assertIn("未展开 1 个", rendered)
        self.assertIn("完整二进制变化裁决", rendered)
        self.assertIn("系统触达证据", rendered)
        self.assertNotIn("com.acme.Provider12", rendered)

    def test_report_reading_contract_keeps_navigation_focus_and_complete_details(self):
        dependency_count = s6_report.S6_MAIN_DEPENDENCY_LIMIT + 5
        api_count = s6_report.S6_MAIN_RESULT_LIMIT + 3
        resource_count = s6_report.S6_MAIN_RESOURCE_LIMIT + 1
        dependencies = [
            {
                "coord": f"com.acme:lib-{index:02d}",
                "old_version": "1.0",
                "new_version": "2.0",
                "change_type": "major",
            }
            for index in range(dependency_count)
        ]
        confirmed_apis = [
            {
                "coord": "com.acme:lib-00",
                "old_version": "1.0",
                "new_version": "2.0",
                "api": f"com.acme.Api.changed{index:02d}",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
                "severity": "P1",
                "business_entry": f"com.acme.Entry.call{index:02d}()",
                "reason": "SYSTEM_CODE_REACHED",
            }
            for index in range(api_count)
        ]
        findings = {
            "analysis_scope": {
                "mode": "full",
                "included_dependency_count": dependency_count,
                "available_dependency_count": dependency_count,
                "analyzed_api_count": api_count,
                "total_api_count": api_count,
            },
            "coverage": {"overall_status": "complete"},
            "dependency_changes": dependencies,
            "impact_overview": {"apis": []},
            "p0": [],
            "p1": confirmed_apis,
            "p2": [],
            "probable_impact": [],
            "uncertain": [],
            "not_impacted": [],
            "needs_input": [],
            "not_analyzed": [],
            "not_found": [],
            "resource_impacts": [
                {
                    **dependencies[index],
                    "resource_name": (
                        f"META-INF/services/com.acme.Provider{index:02d}"
                    ),
                    "activation_status": "reachable",
                    "business_entries": [f"com.acme.Entry.load{index:02d}"],
                }
                for index in range(resource_count)
            ],
            "artifacts": {},
        }

        with tempfile.TemporaryDirectory() as tmp:
            artifacts, _api_model, _dependency_model = (
                s6_report.write_primary_report_artifacts(tmp, findings)
            )
            findings["artifacts"].update(artifacts)
            report = s6_report.generate_report(findings)
            with (
                Path(tmp) / artifacts["full_dependency_analysis_csv"]
            ).open(encoding="utf-8-sig", newline="") as handle:
                full_dependency_rows = list(csv.DictReader(handle))
            with (
                Path(tmp) / artifacts["full_api_analysis_csv"]
            ).open(encoding="utf-8-sig", newline="") as handle:
                full_api_rows = list(csv.DictReader(handle))

        toc = report[
            report.index("## 报告目录") : report.index("## 一、依赖层面结论")
        ]
        dependency_section = report[
            report.index("## 一、依赖层面结论") : report.index("## 二、API 及调用关系")
        ]
        api_section = report[
            report.index("## 二、API 及调用关系") : report.index("## 三、用户可见文件说明")
        ]

        self.assertNotIn("all-affected-dependencies", toc)
        self.assertNotIn("all-impact-details", toc)
        self.assertIn("已完成分析的依赖（展示 20/25）", dependency_section)
        self.assertIn("运行时资源变化及激活关系（展示 12/13）", api_section)
        self.assertIn("API（展示 12/15）", api_section)
        self.assertIn("未展开 5 个", dependency_section)
        self.assertIn("未展开 3 个", api_section)
        self.assertIn("未展开 1 个", api_section)
        self.assertNotIn("com.acme.Provider12", api_section)
        for filename in (
            "all-affected-dependencies.md",
            "all-affected-dependencies.csv",
        ):
            self.assertIn(filename, dependency_section)
        for filename in (
            "all-impact-details.md",
            "all-impact-details.csv",
        ):
            self.assertIn(filename, api_section)
        self.assertIn("## 三、用户可见文件说明", report)
        self.assertEqual(len(full_dependency_rows), dependency_count)
        self.assertEqual(len(full_api_rows), api_count)

    def test_main_report_summarizes_diagnostics_without_internal_protocol(self):
        findings = self._human_first_findings()
        findings["coverage"] = {
            "overall_status": "partial",
            "critical_incomplete": ["behavior_diff"],
            "components": [
                {
                    "id": "behavior_diff",
                    "status": "partial",
                    "reason_codes": [
                        "DEPENDENCY_SOURCE_REF_UNAVAILABLE"
                    ],
                }
            ],
        }
        findings["diagnostic_guidance"] = [
            {
                "reason_code": "DEPENDENCY_SOURCE_REF_UNAVAILABLE",
                "origin_step": "step4",
                "title": "依赖源码版本不可用",
                "semantic_impact": (
                    "方法实现变化证据不完整，当前结论需要复核。"
                ),
                "repair_actions": ["补齐依赖源码版本后重新分析。"],
                "verification_steps": [
                    "依赖源码版本已固定，方法实现变化分析完整。"
                ],
            }
        ]
        findings["artifacts"]["diagnostic_detail_md"] = (
            "deliverables/analysis-diagnostics.md"
        )

        report = s6_report.generate_report(findings)

        self.assertIn("分析异常记录", report)
        self.assertIn("(analysis-diagnostics.md)", report)
        for internal_protocol in (
            "DEPENDENCY_SOURCE_REF_UNAVAILABLE",
            "reason_code",
            "origin_step",
            "来源步骤",
            "api_id",
            "API 编号",
            "path_status",
            ".runtime/",
            "`step4`",
            "触发条件",
            "可忽略条件",
        ):
            self.assertNotIn(internal_protocol, report)
        for non_objective_instruction in (
            "下一步复核顺序",
            "完成标准",
            "待办",
            "建议",
            "修复动作",
        ):
            self.assertNotIn(non_objective_instruction, report)

    def test_evidence_index_stays_short_and_excludes_deep_runtime_inventory(self):
        text = "\n".join(
            s6_report.render_report_appendix(
                {
                    "artifacts": {
                        "alerts_csv": "evidence/call_chain/alerts.csv",
                        "changed_apis_csv": (
                            "evidence/api_changes/all_changed_apis.csv"
                        ),
                    }
                }
            )
        )

        self.assertIn("`evidence/call_chain/alerts.csv`", text)
        self.assertNotIn("evidence/call_chain/by_api", text)
        self.assertNotIn("evidence/static_scan", text)
        self.assertNotIn("#### 程序使用的产物", text)
        self.assertNotIn(".runtime/", text)

    def test_bucket_detail_markdown_starts_with_objective_context_not_numeric_summary(self):
        config = {
            "title": "存在候选证据但结论未确定清单",
            "conclusion": "结论未确定（存在候选证据）",
            "note": "静态分析发现候选路径，但现有证据存在歧义。",
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

        self.assertIn("## 内容说明", text)
        self.assertIn("结论边界", text)
        self.assertNotIn("建议", text)
        self.assertNotIn("完成标准", text)
        self.assertIn("## API 明细（完整）", text)
        self.assertNotIn("## 附录：聚合统计", text)
        self.assertNotIn("### 原因分类", text)

    def test_uncertain_evidence_subtypes_are_reported_without_inventing_candidates(self):
        limitation = {
            "coord": "io.seata:seata-common",
            "api": "io.seata.common.Constants.DEFAULT_VALUE",
            "symbol_kind": "field",
            "change_type": "CONSTANT_VALUE_CHANGED",
            "severity": "P1",
            "uncertainty_kind": "analysis_limitation",
            "reason_code": "INLINED_CONSTANT_USAGE_UNDETECTABLE",
            "call_paths": [],
            "evidence_paths": [],
        }
        candidate = {
            "coord": "com.acme:bridge",
            "api": "com.acme.Bridge.call",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
            "uncertainty_kind": "candidate_evidence",
            "reason_code": "LOW_CONFIDENCE_EDGE",
            "call_paths": ["app.Entry.run -> com.acme.Bridge.call"],
        }
        findings = {
            "p0": [], "p1": [], "p2": [], "probable_impact": [],
            "uncertain": [limitation, candidate], "not_impacted": [],
            "needs_input": [], "not_analyzed": [], "not_found": [],
            "coverage": {"overall_status": "complete"},
            "analysis_scope": {"mode": "full"},
        }

        rows = s6_report.build_api_result_rows(findings)
        conclusions = {row["api"]: row["conclusion"] for row in rows}
        core = "\n".join(s6_report.render_core_conclusion(findings))
        detail = s6_report.build_bucket_detail_markdown(
            s6_report.S6_DETAIL_BUCKETS["uncertain"],
            [limitation, candidate],
            "s6_uncertain_apis.csv",
        )

        self.assertEqual(
            conclusions["io.seata.common.Constants.DEFAULT_VALUE"],
            "结论未确定（静态分析能力边界）",
        )
        self.assertEqual(
            conclusions["com.acme.Bridge.call"],
            "结论未确定（存在候选证据）",
        )
        self.assertIn("结论未确定（静态分析能力边界） 1", core)
        self.assertIn("结论未确定（候选证据） 1", core)
        self.assertIn("当前未发现候选调用证据", detail)
        self.assertIn("现有记录包含候选证据", detail)

    def test_uncertain_outputs_order_dependencies_then_apis_by_impact(self):
        low = {
            "coord": "com.acme:lib",
            "api": "com.acme.Api.low",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P0",
            "uncertainty_kind": "analysis_limitation",
            "priority_score": 4,
        }
        high = {
            **low,
            "api": "com.acme.Api.high",
            "severity": "P1",
            "uncertainty_kind": "candidate_evidence",
            "priority_score": 18,
        }
        medium = {
            **low,
            "coord": "com.beta:lib",
            "api": "com.beta.Api.medium",
            "severity": "P1",
            "uncertainty_kind": "candidate_evidence",
            "priority_score": 12,
        }
        peer = {
            **low,
            "coord": "com.gamma:lib",
            "api": "com.gamma.Api.high",
            "severity": "P1",
            "uncertainty_kind": "candidate_evidence",
            "priority_score": 18,
        }

        with tempfile.TemporaryDirectory() as tmp:
            artifacts = s6_report.write_bucket_detail_artifacts(
                tmp,
                {"uncertain": [peer, medium, low, high]},
                "uncertain",
            )
            csv_path = Path(tmp) / artifacts["uncertain_csv"]
            with csv_path.open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                rows = list(csv.DictReader(handle))
            markdown = (
                Path(tmp) / artifacts["uncertain_md"]
            ).read_text(encoding="utf-8")

        main_rows = s6_report._main_completed_api_rows([
            {**low, "conclusion": s6_report.UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION},
            {**high, "conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION},
            {**medium, "conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION},
            {**peer, "conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION},
        ])
        self.assertEqual(
            [row["api"] for row in rows],
            [
                "com.acme.Api.high",
                "com.acme.Api.low",
                "com.gamma.Api.high",
                "com.beta.Api.medium",
            ],
        )
        self.assertEqual(
            [row["coord"] for row in rows],
            [
                "com.acme:lib",
                "com.acme:lib",
                "com.gamma:lib",
                "com.beta:lib",
            ],
        )
        self.assertEqual(
            [row["priority_score"] for row in rows],
            ["18", "4", "18", "12"],
        )
        self.assertEqual(
            [row["dependency_priority_rank"] for row in rows],
            ["1", "1", "2", "3"],
        )
        self.assertEqual(
            [row["dependency_top_priority_score"] for row in rows],
            ["18", "18", "18", "12"],
        )
        self.assertEqual(
            [row["dependency_total_priority_score"] for row in rows],
            ["22", "22", "18", "12"],
        )
        self.assertEqual(
            [row["api"] for row in main_rows],
            [
                "com.acme.Api.high",
                "com.acme.Api.low",
                "com.gamma.Api.high",
                "com.beta.Api.medium",
            ],
        )
        self.assertIn("依赖复核顺序", markdown)
        self.assertIn("复核优先分数", markdown)
        self.assertLess(markdown.index("com.acme.Api.high"), markdown.index("com.acme.Api.low"))
        self.assertLess(markdown.index("com.acme.Api.low"), markdown.index("com.gamma.Api.high"))
        self.assertLess(markdown.index("com.gamma.Api.high"), markdown.index("com.beta.Api.medium"))

    def test_full_api_detail_dependency_sections_use_impact_order(self):
        def row(coord, api, score, severity="P1"):
            return {
                "coord": coord,
                "api": api,
                "api_signature": "()",
                "change_type": "REMOVED",
                "severity": severity,
                "conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION,
                "priority_score": score,
            }

        groups = s6_report._completed_api_rows_by_dependency({
            "completed": [
                row("com.beta:lib", "com.beta.Api.medium", 12, "P0"),
                row("com.acme:lib", "com.acme.Api.low", 4, "P0"),
                row("com.gamma:lib", "com.gamma.Api.high", 18),
                row("com.acme:lib", "com.acme.Api.high", 18),
            ]
        })

        self.assertEqual(
            [coord for coord, _rows in groups],
            ["com.acme:lib", "com.gamma:lib", "com.beta:lib"],
        )
        self.assertEqual(
            [item["api"] for item in groups[0][1]],
            ["com.acme.Api.high", "com.acme.Api.low"],
        )

    def test_main_report_uses_human_conclusions_for_confirmed_and_uncertain_apis(self):
        reachable = [
            {
                "coord": "com.acme:confirmed",
                "api": f"com.acme.Api.confirmed{index}",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "BEHAVIOR_CHANGED",
                "severity": "P1",
                "conclusion": "已确认影响",
                "path_count": 1,
            }
            for index in range(10)
        ]
        uncertain = [
            {
                "coord": "com.beta:review",
                "api": "com.beta.Api.low",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P0",
                "conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION,
                "priority_score": 3,
            },
            {
                "coord": "com.beta:review",
                "api": "com.beta.Api.high",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "BEHAVIOR_CHANGED",
                "severity": "P2",
                "conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION,
                "priority_score": 19,
            },
        ]
        not_found = {
            "coord": "com.gamma:not-found",
            "api": "com.gamma.Api.notFoundSentinel",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
            "conclusion": "未发现调用路径",
        }
        not_impacted = {
            "coord": "com.delta:not-impacted",
            "api": "com.delta.Api.notImpactedSentinel",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
            "conclusion": "已确认不受影响",
        }
        completed = [*reachable, *uncertain, not_found, not_impacted]
        api_model = {
            "rows": completed,
            "completed": completed,
            "incomplete": [],
            "total_count": len(completed),
            "completed_count": len(completed),
            "incomplete_count": 0,
            "confirmed_count": len(reachable),
            "confirmed_no_impact_count": 1,
            "unconfirmed_count": 3,
            "confirmed_relationship_count": len(reachable),
            "population_unconfirmed": False,
        }

        report = "\n".join(
            s6_report.render_api_and_calls({}, api_model=api_model)
        )

        self.assertNotIn("五态语义", report)
        self.assertNotIn("内部状态", report)
        self.assertNotIn("reachable", report)
        self.assertNotIn("uncertain", report)
        self.assertNotIn("not_found_in_static_analysis", report)
        self.assertNotIn("not_analyzed", report)
        self.assertIn("展示 12/12", report)
        self.assertIn("不表示运行时故障已经发生", report)
        for index in range(10):
            self.assertIn(f"com.acme.Api.confirmed{index}", report)
        self.assertLess(report.index("com.beta.Api.high"), report.index("com.beta.Api.low"))
        self.assertLess(report.index("`com.acme:confirmed`"), report.index("`com.beta:review`"))
        self.assertNotIn("notFoundSentinel", report)
        self.assertNotIn("notImpactedSentinel", report)
        self.assertIn(
            "| 静态分析未发现调用路径 | 1 | "
            "仅统计，不展开 API；未发现路径不等于确认不受影响。 |",
            report,
        )

    def test_core_conclusion_translates_partial_coverage_without_raw_status(self):
        text = "\n".join(
            s6_report.render_core_conclusion(
                {
                    "scan_stats": {"call_chain_status": "partial"},
                    "coverage": {"overall_status": "partial"},
                }
            )
        )

        self.assertIn("当前证据不足", text)
        self.assertNotIn("`partial`", text)

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

        self.assertIn("已确认影响 2", conclusion)
        self.assertIn("高风险（P0/P1） 1", conclusion)
        self.assertNotIn("已确认/高风险影响", conclusion + result_table)
        self.assertIn("| P0 |", result_table)
        self.assertNotIn("严重级别：P0", result_table)

    def test_large_other_results_show_fact_distribution_before_samples(self):
        coords = (
            ["com.acme:dep-a"] * 5
            + ["com.acme:dep-b"] * 3
            + ["com.acme:dep-c"] * 2
            + [
                "com.acme:dep-d",
                "com.acme:dep-e",
                "com.acme:dep-f",
            ]
        )
        severities = ["P0"] * 2 + ["P1"] * 3 + ["P2"] * 4 + [""] * 4
        change_types = (
            ["REMOVED"] * 7
            + ["METHOD_CHANGED"] * 3
            + ["DATA_FIELD_ADDED"] * 2
            + ["CLASS_ADDED"]
        )
        items = [
            {
                "coord": coord,
                "api": f"com.acme.Api.call{index}",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": change_types[index],
                "severity": severities[index],
            }
            for index, coord in enumerate(coords)
        ]
        for item in items[10:12]:
            item["uncertainty_kind"] = "candidate_evidence"
        findings = {
            "p0": [],
            "p1": [],
            "p2": [],
            "probable_impact": items[7:10],
            "uncertain": items[10:12],
            "not_impacted": [],
            "needs_input": items[12:],
            "not_analyzed": [],
            "not_found": items[:7],
        }

        rows = s6_report.build_api_result_rows(findings)
        distribution = "\n".join(
            s6_report.render_other_result_distribution(rows)
        )
        report = "\n".join(s6_report.render_api_result_table(findings))

        self.assertEqual(13, len(rows))
        self.assertIn("### 非“已确认影响”结果分布", distribution)
        self.assertIn("未发现调用路径 7", distribution)
        self.assertIn("可能影响 3", distribution)
        self.assertIn("结论未确定（存在候选证据） 2", distribution)
        self.assertIn("输入不足，结论未确定 1", distribution)
        self.assertIn(
            "**严重级别分布**：P0 2；P1 3；P2 4；未分级 4。",
            distribution,
        )
        self.assertIn("删除方法 7", distribution)
        self.assertIn("修改方法 3", distribution)
        self.assertIn("DTO 字段新增 2", distribution)
        self.assertIn("新增类 1", distribution)
        self.assertIn("前 5 个依赖包含 12/13 个结果（92.3%）", distribution)
        self.assertIn("| `com.acme:dep-a` | 5 |", distribution)
        self.assertIn("| `com.acme:dep-b` | 3 |", distribution)
        self.assertIn("| `com.acme:dep-c` | 2 |", distribution)
        self.assertIn("| 其他 1 个依赖 | 1 |", distribution)
        for forbidden in ("建议", "下一步", "待办", "优先", "需人工复核"):
            self.assertNotIn(forbidden, distribution)

        self.assertLess(
            report.index("## 三、未确认事实和其他结果"),
            report.index("### 非“已确认影响”结果分布"),
        )
        self.assertLess(
            report.index("### 非“已确认影响”结果分布"),
            report.index("本轮共有 13 个非“已确认影响”结果"),
        )
        self.assertEqual(
            [],
            s6_report.render_other_result_distribution(rows[:12]),
        )

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
        self.assertEqual(rows[0]["confirmed_path_count"], 1)
        self.assertEqual(rows[0]["confirmed_occurrence_count"], 3)
        self.assertEqual(
            rows[0]["paths"],
            ["com.app.App.run → com.vendor.LegacyApi.removed"],
        )
        self.assertIn("已确认调用链 1 条；证据命中 3 次", report)
        self.assertNotIn("尚未回溯到业务入口", report)

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

        self.assertIn(
            "当前证据不足以支持“系统不受影响”结论",
            text,
        )
        self.assertNotIn("API 范围内完整", text)

    def test_malformed_call_summary_is_visible_and_downgrades_complete_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            for path, payload in (
                (
                    s6_report._coverage_path(report_dir),
                    {
                        "overall_status": "complete",
                        "critical_incomplete": [],
                        "components": [],
                    },
                ),
                (
                    s6_report._step5_selection_path(report_dir),
                    {"mode": "full"},
                ),
            ):
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_text(
                    json.dumps(payload, ensure_ascii=False),
                    encoding="utf-8",
                )
            changed_apis = (
                report_dir
                / "evidence"
                / "api_changes"
                / "all_changed_apis.csv"
            )
            changed_apis.parent.mkdir(parents=True, exist_ok=True)
            changed_apis.write_text("coord,api\n", encoding="utf-8")
            alerts = (
                report_dir / "evidence" / "call_chain" / "alerts.csv"
            )
            alerts.parent.mkdir(parents=True, exist_ok=True)
            alerts.write_text("changed_symbol,target_coord\n", encoding="utf-8")
            (alerts.parent / "summary.json").write_text(
                "{not-valid-json",
                encoding="utf-8",
            )

            findings = s6_report.collect_findings(report_dir)
            report = s6_report.generate_report(findings)

        self.assertTrue(findings["diagnostics"])
        self.assertTrue(any(
            item.get("artifact") == "call_chain_summary"
            and item.get("error_type") == "JSONDecodeError"
            for item in findings["diagnostics"]
        ))
        self.assertNotIn("### 本轮分析输入记录", report)
        self.assertIn(
            "| 变化 API 总数 | 已完成分析 | 未完成分析 | 确认有影响 | 确认不受影响 | 尚未确认影响 |",
            report,
        )

    def test_missing_core_evidence_is_visible_and_not_linked(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            for path, payload in (
                (
                    s6_report._coverage_path(report_dir),
                    {
                        "overall_status": "complete",
                        "critical_incomplete": [],
                        "components": [],
                    },
                ),
                (
                    s6_report._step5_selection_path(report_dir),
                    {"mode": "full"},
                ),
            ):
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_text(
                    json.dumps(payload, ensure_ascii=False),
                    encoding="utf-8",
                )
            summary = report_dir / "evidence" / "call_chain" / "summary.json"
            summary.parent.mkdir(parents=True, exist_ok=True)
            summary.write_text(
                json.dumps(
                    {
                        "status": "done",
                        "reachable_apis": [
                            {
                                "coord": "com.acme:lib",
                                "api": "com.acme.Api.run",
                                "severity": "P1",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            findings = s6_report.collect_findings(report_dir)
            report = s6_report.generate_report(findings)

        missing_artifacts = {
            item["artifact"] for item in findings["diagnostics"]
            if item.get("error_type") == "FileNotFoundError"
        }
        self.assertEqual(
            missing_artifacts,
            {"changed_apis", "call_chain_alerts"},
        )
        self.assertNotIn("### 本轮分析输入记录", report)
        self.assertNotIn("../evidence/call_chain/alerts.csv", report)
        self.assertNotIn("../evidence/api_changes/all_changed_apis.csv", report)

    def test_invalid_summary_bucket_and_csv_schema_do_not_crash_or_claim_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            for path, payload in (
                (
                    s6_report._coverage_path(report_dir),
                    {
                        "overall_status": "complete",
                        "critical_incomplete": [],
                        "components": [],
                    },
                ),
                (
                    s6_report._step5_selection_path(report_dir),
                    {
                        "mode": "full",
                        "analyzed_api_count": 1,
                        "total_api_count": 1,
                    },
                ),
            ):
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_text(
                    json.dumps(payload, ensure_ascii=False),
                    encoding="utf-8",
                )
            call_chain_dir = report_dir / "evidence" / "call_chain"
            call_chain_dir.mkdir(parents=True)
            (call_chain_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "status": "done",
                        "total_apis": 1,
                        "reachable": 1,
                        "reachable_apis": "not-a-list",
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (call_chain_dir / "alerts.csv").write_text(
                "junk\nvalue\n",
                encoding="utf-8",
            )
            changed_path = (
                report_dir / "evidence" / "api_changes" / "all_changed_apis.csv"
            )
            changed_path.parent.mkdir(parents=True)
            changed_path.write_text("junk\nvalue\n", encoding="utf-8")

            findings = s6_report.collect_findings(report_dir)
            report = s6_report.generate_report(findings)

        artifacts = {item["artifact"] for item in findings["diagnostics"]}
        self.assertEqual(
            artifacts,
            {
                "call_chain_summary",
                "changed_apis",
                "call_chain_alerts",
            },
        )
        self.assertEqual(findings["p0"] + findings["p1"] + findings["p2"], [])
        self.assertNotIn("### 本轮分析输入记录", report)
        self.assertIn("| 1 | 0 | 1 |", report)

    def test_no_changed_api_skip_does_not_require_alerts_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            for path, payload in (
                (
                    s6_report._coverage_path(report_dir),
                    {
                        "overall_status": "complete",
                        "critical_incomplete": [],
                        "components": [],
                    },
                ),
                (
                    s6_report._step5_selection_path(report_dir),
                    {
                        "mode": "full",
                        "analyzed_api_count": 0,
                        "total_api_count": 0,
                    },
                ),
            ):
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_text(
                    json.dumps(payload, ensure_ascii=False),
                    encoding="utf-8",
                )
            summary = report_dir / "evidence" / "call_chain" / "summary.json"
            summary.parent.mkdir(parents=True)
            summary.write_text(
                json.dumps(
                    {
                        "status": "skipped",
                        "skip_reason": "no_changed_apis",
                        "total_apis": 0,
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            changed_path = (
                report_dir / "evidence" / "api_changes" / "all_changed_apis.csv"
            )
            changed_path.parent.mkdir(parents=True)
            changed_path.write_text(
                "coord,api_name\n",
                encoding="utf-8",
            )

            findings = s6_report.collect_findings(report_dir)
            report = s6_report.generate_report(findings)

        self.assertFalse(
            any(
                item.get("artifact") == "call_chain_alerts"
                for item in findings["diagnostics"]
            )
        )
        self.assertIn("| 0 | 0 | 0 |", report)
        self.assertNotIn("### 本轮分析输入记录", report)
        self.assertNotIn("逐链路证据台账未生成", report)

    def test_mismatched_alert_identity_does_not_preserve_confirmed_conclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            for path, payload in (
                (
                    s6_report._coverage_path(report_dir),
                    {
                        "overall_status": "complete",
                        "critical_incomplete": [],
                        "components": [],
                    },
                ),
                (
                    s6_report._step5_selection_path(report_dir),
                    {
                        "mode": "full",
                        "analyzed_api_count": 1,
                        "total_api_count": 1,
                    },
                ),
            ):
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_text(
                    json.dumps(payload, ensure_ascii=False),
                    encoding="utf-8",
                )
            call_chain_dir = report_dir / "evidence" / "call_chain"
            call_chain_dir.mkdir(parents=True)
            (call_chain_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "status": "done",
                        "total_apis": 1,
                        "reachable": 1,
                        "reachable_apis": [
                            {
                                "coord": "com.acme:lib",
                                "api": "com.acme.Api.a",
                                "api_signature": "()",
                                "symbol_kind": "method",
                                "change_type": "REMOVED",
                                "severity": "P1",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            with (call_chain_dir / "alerts.csv").open(
                "w", encoding="utf-8", newline=""
            ) as output:
                writer = csv.DictWriter(
                    output,
                    fieldnames=[
                        "target_coord",
                        "changed_symbol",
                        "api_signature",
                        "symbol_kind",
                        "change_type",
                        "path_status",
                    ],
                )
                writer.writeheader()
                writer.writerow({
                    "target_coord": "com.acme:lib",
                    "changed_symbol": "com.acme.Api.b",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "path_status": "reachable",
                })
            changed_path = (
                report_dir / "evidence" / "api_changes" / "all_changed_apis.csv"
            )
            changed_path.parent.mkdir(parents=True)
            changed_path.write_text(
                "coord,api_name,api_signature,symbol_kind,change_type\n"
                "com.acme:lib,com.acme.Api.a,(),method,REMOVED\n",
                encoding="utf-8",
            )

            findings = s6_report.collect_findings(report_dir)
            report = s6_report.generate_report(findings)

        self.assertEqual(
            findings["p0"] + findings["p1"] + findings["p2"],
            [],
        )
        self.assertEqual(len(findings["needs_input"]), 1)
        mismatch_guidance = next(
            item for item in findings["diagnostic_guidance"]
            if item.get("reason_code") == "S6_EVIDENCE_IDENTITY_MISMATCH"
        )
        self.assertEqual("step6", mismatch_guidance["origin_step"])
        self.assertIn(
            "变化 API 清单、系统触达汇总和逐链路台账未能共同确认该项",
            report,
        )
        self.assertIn("未完成分析", report)
        self.assertIn(
            "本轮没有变化依赖形成“确认对当前系统有影响”的结论",
            report,
        )

    def test_structural_bucket_overrides_contradictory_legacy_label(self):
        findings = {
            "p0": [],
            "p1": [],
            "p2": [],
            "probable_impact": [],
            "uncertain": [],
            "not_impacted": [],
            "needs_input": [],
            "not_analyzed": [
                {
                    "coord": "com.acme:lib",
                    "api": "com.acme.Api.run",
                    "user_conclusion": "已确认影响",
                }
            ],
            "not_found": [],
        }

        report = s6_report.generate_report(findings)

        self.assertIn("未完成分析", report)
        self.assertNotIn("未完成分析；确认有影响", report)

    def test_confirmed_overflow_has_a_complete_human_readable_markdown(self):
        findings = {
            "coverage": {"overall_status": "complete"},
            "analysis_scope": {"mode": "full"},
            "impact_overview": {"apis": []},
            "p0": [],
            "p1": [
                {
                    "coord": "com.acme:lib",
                    "old_version": "1.0.0",
                    "new_version": "2.0.0",
                    "api": f"com.acme.Api.method{index}",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "METHOD_REMOVED",
                    "severity": "P1",
                    "business_entry": f"com.app.Entry.call{index}()",
                    "reason": "SYSTEM_CODE_REACHED",
                }
                for index in range(15)
            ],
            "p2": [],
            "probable_impact": [],
            "uncertain": [],
            "not_impacted": [],
            "needs_input": [],
            "not_analyzed": [],
            "not_found": [],
            "artifacts": {},
        }
        with tempfile.TemporaryDirectory() as tmp:
            artifacts, _api_model, _dependency_model = (
                s6_report.write_primary_report_artifacts(tmp, findings)
            )
            findings["artifacts"].update(artifacts)
            report = s6_report.generate_report(findings)
            detail_path = (
                Path(tmp) / artifacts["full_api_analysis_md"]
            )
            detail = detail_path.read_text(encoding="utf-8")

        self.assertIn("完整 API 分析与调用关系明细", report)
        self.assertIn("展示 12/15", report)
        self.assertIn("未展开 3 个", report)
        self.assertEqual(
            report.count("| `com.acme:lib` | `com.acme.Api.method"),
            s6_report.S6_MAIN_RESULT_LIMIT,
        )
        self.assertIn("com.acme.Api.method14", detail)
        self.assertIn("com.acme.Api.method9", detail)
        self.assertIn("1.0.0 → 2.0.0", detail)
        self.assertNotIn("<a ", detail)

    def test_large_confirmed_markdown_is_bounded_and_keeps_full_csv(self):
        total = 1920
        alert_rows = []
        confirmed_items = []
        for index in range(total):
            coord = f"com.acme:lib-{index % 4}"
            api = f"com.acme.Api.method{index}"
            entry = f"com.app.Entry{index % 10}.run()"
            confirmed_items.append({
                "coord": coord,
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "api": api,
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
                "severity": "P1",
                "business_entry": entry,
                "reason_code": "SYSTEM_CODE_REACHED",
            })
            alert_rows.append({
                "target_coord": coord,
                "changed_symbol": api,
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
                "severity": "P1",
                "path_status": "reachable",
                "business_entry": entry,
                "path_text": f"{entry} -> {api}()",
                "path_occurrence_count": "1",
            })
        findings = {
            "coverage": {"overall_status": "complete"},
            "analysis_scope": {"mode": "full"},
            "impact_overview": s6_report.build_impact_overview(
                list(reversed(alert_rows))
            ),
            "p0": [],
            "p1": list(reversed(confirmed_items)),
            "p2": [],
            "probable_impact": [],
            "uncertain": [],
            "not_impacted": [],
            "needs_input": [],
            "not_analyzed": [],
            "not_found": [],
            "artifacts": {},
        }

        with tempfile.TemporaryDirectory() as tmp:
            artifacts = s6_report.write_s6_detail_artifacts(tmp, findings)
            detail_path = Path(tmp) / artifacts["confirmed_md"]
            csv_path = Path(tmp) / artifacts["confirmed_csv"]
            detail = detail_path.read_text(encoding="utf-8")
            with csv_path.open(encoding="utf-8-sig", newline="") as source:
                csv_rows = list(csv.DictReader(source))

        self.assertEqual(total, len(csv_rows))
        self.assertIn("逐链路台账包含 1920 条有效记录", detail)
        self.assertIn("归并为 1920 个变更 API", detail)
        self.assertIn("本文件展示 50/1920 项", detail)
        self.assertLess(
            detail.index("## 已确认影响分布"),
            detail.index("## 已确认影响明细"),
        )
        self.assertEqual(
            s6_report.S6_DETAIL_MD_SAMPLE_LIMIT,
            detail.count("`com.acme.Api.method"),
        )
        self.assertNotIn("严重级别：", detail)
        for forbidden in ("建议", "下一步", "待办", "需人工复核"):
            self.assertNotIn(forbidden, detail)

    def test_confirmed_csv_keeps_full_path_and_business_entry_counts(self):
        alert_rows = []
        confirmed_items = []
        for api_index in range(9):
            api = f"com.acme.Api.method{api_index}"
            confirmed_items.append({
                "coord": "com.acme:lib",
                "api": api,
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
                "severity": "P1",
                "reason_code": "SYSTEM_CODE_REACHED",
            })
            path_total = 12 if api_index == 0 else 1
            for path_index in range(path_total):
                entry = f"com.app.Entry{path_index}.run()"
                alert_rows.append({
                    "target_coord": "com.acme:lib",
                    "changed_symbol": api,
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "METHOD_REMOVED",
                    "severity": "P1",
                    "path_status": "reachable",
                    "business_entry": entry,
                    "path_text": f"{entry} -> {api}()",
                })
        findings = {
            "impact_overview": s6_report.build_impact_overview(alert_rows),
            "p0": [],
            "p1": confirmed_items,
            "p2": [],
            "probable_impact": [],
            "uncertain": [],
            "not_impacted": [],
            "needs_input": [],
            "not_analyzed": [],
            "not_found": [],
            "artifacts": {},
        }

        with tempfile.TemporaryDirectory() as tmp:
            artifacts = s6_report.write_s6_detail_artifacts(tmp, findings)
            csv_path = Path(tmp) / artifacts["confirmed_csv"]
            md_path = Path(tmp) / artifacts["confirmed_md"]
            with csv_path.open(
                encoding="utf-8-sig", newline=""
            ) as source:
                rows = list(csv.DictReader(source))
            markdown = md_path.read_text(encoding="utf-8")

        wide = next(
            row for row in rows
            if row["api"] == "com.acme.Api.method0"
        )
        self.assertEqual("12", wide["path_count"])
        self.assertEqual("12", wide["occurrence_count"])
        self.assertEqual(12, len(wide["business_entries"].split(" | ")))
        self.assertIn("…另 10 项", markdown)

    def test_result_order_uses_severity_entry_and_path_facts(self):
        alerts = [
            {
                "target_coord": "com.acme:lib",
                "changed_symbol": "com.acme.Api.small",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P1",
                "path_status": "reachable",
                "business_entry": "com.app.One.run()",
                "path_text": (
                    "com.app.One.run() -> com.acme.Api.small()"
                ),
            },
            *[
                {
                    "target_coord": "com.acme:lib",
                    "changed_symbol": "com.acme.Api.wide",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "severity": "P1",
                    "path_status": "reachable",
                    "business_entry": f"com.app.Wide{index}.run()",
                    "path_text": (
                        f"com.app.Wide{index}.run() -> "
                        "com.acme.Api.wide()"
                    ),
                }
                for index in range(3)
            ],
        ]
        base = {
            "coord": "com.acme:lib",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
            "reason_code": "SYSTEM_CODE_REACHED",
        }
        findings = {
            "impact_overview": s6_report.build_impact_overview(
                list(reversed(alerts))
            ),
            "p0": [],
            "p1": [
                {**base, "api": "com.acme.Api.small"},
                {**base, "api": "com.acme.Api.wide"},
            ],
            "p2": [],
            "probable_impact": [],
            "uncertain": [],
            "not_impacted": [],
            "needs_input": [],
            "not_analyzed": [],
            "not_found": [],
        }

        rows = [
            row for row in s6_report.build_api_result_rows(findings)
            if row["conclusion"] == "已确认影响"
        ]

        self.assertEqual(
            ["com.acme.Api.wide", "com.acme.Api.small"],
            [row["api"] for row in rows],
        )
        self.assertEqual(3, rows[0]["business_entry_count"])
        self.assertEqual(3, rows[0]["confirmed_path_count"])

    def test_human_lists_and_csv_share_dependency_result_and_path_order(self):
        def changed_api(coord, name):
            return {
                "coord": coord,
                "api": f"com.acme.Api.{name}",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
            }

        def overview(item, status, path_count):
            paths = [
                (
                    f"com.app.Entry{index}.run() → "
                    f"{item['api']}()"
                )
                for index in range(path_count)
            ]
            return {
                **item,
                "paths": paths,
                "paths_by_status": {status: paths},
                "path_counts_by_status": {status: path_count},
                "logical_path_counts_by_status": {
                    status: path_count,
                },
                "occurrence_counts_by_status": {
                    status: path_count,
                },
            }

        uncertain_many = changed_api("a:uncertain", "uncertainMany")
        uncertain_few = changed_api("a:uncertain", "uncertainFew")
        no_impact = changed_api("b:no-impact", "noImpact")
        confirmed_few = changed_api("y:confirmed-few", "confirmedFew")
        confirmed_many = changed_api(
            "z:confirmed-many",
            "confirmedMany",
        )
        changed_apis = [
            uncertain_few,
            no_impact,
            confirmed_few,
            confirmed_many,
            uncertain_many,
        ]
        findings = {
            "analysis_scope": {
                "mode": "full",
                "available_dependency_count": 4,
                "included_dependency_count": 4,
                "total_api_count": 5,
                "analyzed_api_count": 5,
            },
            "dependency_changes": [
                {
                    "coord": coord,
                    "old_version": "1.0.0",
                    "new_version": "2.0.0",
                    "change_type": "major",
                }
                for coord in (
                    "a:uncertain",
                    "b:no-impact",
                    "y:confirmed-few",
                    "z:confirmed-many",
                )
            ],
            "changed_api_inventory": changed_apis,
            "call_chain_target_count": 5,
            "impact_overview": {
                "apis": [
                    overview(uncertain_few, "uncertain", 2),
                    overview(no_impact, "not_impacted", 0),
                    overview(confirmed_few, "reachable", 1),
                    overview(confirmed_many, "reachable", 3),
                    overview(uncertain_many, "uncertain", 5),
                ]
            },
            "p0": [],
            "p1": [confirmed_few, confirmed_many],
            "p2": [],
            "probable_impact": [],
            "uncertain": [uncertain_few, uncertain_many],
            "not_impacted": [no_impact],
            "needs_input": [],
            "not_analyzed": [],
            "not_found": [],
            "artifacts": {},
        }

        with tempfile.TemporaryDirectory() as tmp:
            artifacts, api_model, dependency_model = (
                s6_report.write_primary_report_artifacts(tmp, findings)
            )
            dependency_markdown = (
                Path(tmp) / artifacts["full_dependency_analysis_md"]
            ).read_text(encoding="utf-8")
            api_markdown = (
                Path(tmp) / artifacts["full_api_analysis_md"]
            ).read_text(encoding="utf-8")
            with (
                Path(tmp) / artifacts["full_dependency_analysis_csv"]
            ).open(encoding="utf-8-sig", newline="") as source:
                dependency_csv_rows = list(csv.DictReader(source))
            with (
                Path(tmp) / artifacts["full_api_analysis_csv"]
            ).open(encoding="utf-8-sig", newline="") as source:
                api_csv_rows = list(csv.DictReader(source))

        expected_dependencies = [
            "z:confirmed-many",
            "y:confirmed-few",
            "a:uncertain",
            "b:no-impact",
        ]
        self.assertEqual(
            expected_dependencies,
            [row["coord"] for row in dependency_model["completed"]],
        )
        self.assertEqual(
            expected_dependencies,
            [row["依赖"] for row in dependency_csv_rows],
        )
        self.assertEqual(
            sorted(
                (
                    dependency_markdown.index(coord),
                    coord,
                )
                for coord in expected_dependencies
            ),
            [
                (
                    dependency_markdown.index(coord),
                    coord,
                )
                for coord in expected_dependencies
            ],
        )

        expected_apis = [
            "com.acme.Api.confirmedMany()",
            "com.acme.Api.confirmedFew()",
            "com.acme.Api.uncertainMany()",
            "com.acme.Api.uncertainFew()",
            "com.acme.Api.noImpact()",
        ]
        self.assertEqual(
            expected_apis,
            [
                s6_report._item_api_label(row)
                for row in api_model["completed"]
            ],
        )
        self.assertEqual(
            expected_apis,
            [row["API"] for row in api_csv_rows],
        )
        self.assertEqual(
            sorted(
                (api_markdown.index(api), api)
                for api in expected_apis
            ),
            [
                (api_markdown.index(api), api)
                for api in expected_apis
            ],
        )
        self.assertEqual(
            s6_report._FULL_DEPENDENCY_CSV_FIELDS,
            list(dependency_csv_rows[0]),
        )
        self.assertEqual(
            s6_report._FULL_API_CSV_FIELDS,
            list(api_csv_rows[0]),
        )

    def test_business_entry_aggregation_keeps_full_api_identity(self):
        entry = "com.app.Entry.run()"
        rows = []
        for coord, signature in (
            ("com.acme:first", "(String)"),
            ("com.acme:first", "(Integer)"),
            ("com.acme:second", "(String)"),
        ):
            rows.append({
                "target_coord": coord,
                "changed_symbol": "com.acme.Api.call",
                "api_signature": signature,
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "path_status": "reachable",
                "business_entry": entry,
                "path_text": (
                    f"{entry} -> com.acme.Api.call{signature}"
                ),
            })

        overview = s6_report.build_impact_overview(rows)

        self.assertEqual(3, overview["business_entries"][0]["api_count"])
        self.assertEqual(
            2,
            overview["business_entries"][0]["dependency_count"],
        )

    def test_path_count_merges_signatureless_duplicate_but_keeps_overloads(self):
        signatureless = (
            "com.app.App.run -> com.vendor.Api.removed(String)"
        )
        string_overload = (
            "com.app.App.run(String) -> com.vendor.Api.removed(String)"
        )
        integer_overload = (
            "com.app.App.run(Integer) -> com.vendor.Api.removed(String)"
        )

        self.assertEqual(
            s6_report._distinct_call_path_count(
                [signatureless, string_overload]
            ),
            1,
        )
        self.assertEqual(
            s6_report._distinct_call_path_count(
                [signatureless, string_overload, integer_overload]
            ),
            2,
        )

    def test_partial_path_signatures_count_is_stable_across_input_order(self):
        paths = [
            "A(x) -> B",
            "A -> B(y)",
            "A -> B(z)",
        ]

        self.assertEqual(
            {2},
            {
                s6_report._distinct_call_path_count(permutation)
                for permutation in itertools.permutations(paths)
            },
        )

    def test_partial_path_signature_grouping_uses_minimum_compatible_count(self):
        paths = [
            "A(a) -> B -> C",
            "A -> B(b) -> C(a)",
            "A(b) -> B(b) -> C",
            "A(b) -> B(a) -> C",
            "A -> B(c) -> C",
            "A(c) -> B -> C",
            "A -> B(b) -> C(b)",
            "A(b) -> B -> C(a)",
            "A -> B(c) -> C(b)",
            "A(b) -> B -> C(b)",
        ]

        self.assertEqual(4, s6_report._distinct_call_path_count(paths))

    def test_overview_samples_are_stable_and_full_counts_are_not_truncated(self):
        alerts = [
            {
                "target_coord": "com.acme:lib",
                "changed_symbol": "com.acme.Api.call",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "path_status": "reachable",
                "business_entry": f"com.app.Entry{index}.run()",
                "path_text": (
                    f"com.app.Entry{index}.run() -> "
                    "com.acme.Api.call()"
                ),
            }
            for index in range(15)
        ]
        forward = s6_report.build_impact_overview(alerts)
        reverse = s6_report.build_impact_overview(list(reversed(alerts)))

        self.assertEqual(forward, reverse)
        overview = forward["apis"][0]
        self.assertEqual(15, overview["path_count"])
        self.assertEqual(
            15,
            overview["logical_path_counts_by_status"]["reachable"],
        )
        self.assertEqual(10, len(overview["paths_by_status"]["reachable"]))
        findings = {
            "impact_overview": forward,
            "p0": [],
            "p1": [{
                "coord": "com.acme:lib",
                "api": "com.acme.Api.call",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "severity": "P1",
            }],
            "p2": [],
        }
        row = s6_report.build_api_result_rows(findings)[0]
        self.assertEqual(15, row["path_count"])
        self.assertEqual(15, row["confirmed_path_count"])
        self.assertEqual(15, len(row["business_entries"]))
        self.assertIn("…另 13 项", s6_report._business_scope_cell(row))

    def test_same_confirmed_api_in_two_severity_buckets_is_counted_once(self):
        identity = {
            "coord": "com.acme:lib",
            "api": "com.acme.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        findings = {
            "p0": [{**identity, "severity": "P0"}],
            "p1": [{**identity, "severity": "P1"}],
            "p2": [],
        }

        rows = s6_report.build_api_result_rows(findings)

        self.assertEqual(1, len(rows))
        self.assertEqual("P0", rows[0]["severity"])

    def test_entry_metadata_completion_does_not_duplicate_physical_hit(self):
        base = {
            "target_coord": "com.acme:lib",
            "changed_symbol": "com.acme.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "path_status": "reachable",
            "path_text": "com.app.Entry.run() -> com.acme.Api.call()",
            "evidence_files": "Entry.class",
        }

        overview = s6_report.build_impact_overview([
            base,
            {**base, "business_entry": "com.app.Entry.run()"},
        ])

        self.assertEqual(2, overview["record_count"])
        self.assertEqual(1, overview["logical_path_count"])
        self.assertEqual(1, overview["occurrence_count"])
        self.assertEqual(1, overview["business_entry_count"])

    def test_entry_occurrence_count_is_stable_when_metadata_is_completed(self):
        base = {
            "target_coord": "com.acme:lib",
            "changed_symbol": "com.acme.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "path_status": "reachable",
            "path_text": "com.app.Entry.run() -> com.acme.Api.call()",
            "path_occurrence_count": "3",
            "evidence_files": "Entry.class",
        }
        completed = {
            **base,
            "business_entry": "com.app.Entry.run()",
        }

        forward = s6_report.build_impact_overview([base, completed])
        reverse = s6_report.build_impact_overview([completed, base])

        self.assertEqual(
            3,
            forward["business_entries"][0]["occurrence_count"],
        )
        self.assertEqual(
            forward["business_entries"],
            reverse["business_entries"],
        )

    def test_api_identity_normalizes_multi_parameter_signature_spacing(self):
        compact = {
            "coord": "com.acme:lib",
            "api": "com.acme.Api.call",
            "api_signature": "(java.lang.String,java.lang.Object)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        spaced = {
            **compact,
            "api_signature": "(java.lang.String, java.lang.Object)",
        }

        self.assertEqual(
            s6_report.build_api_identity_key(compact),
            s6_report.build_api_identity_key(spaced),
        )

    def test_duplicate_result_facts_merge_deterministically(self):
        identity = {
            "coord": "g:a",
            "api": "pkg.Api.x",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
        }
        item_a = {
            **identity,
            "old_version": "1",
            "new_version": "2",
            "reason_code": "SYSTEM_CODE_REACHED",
        }
        item_b = {
            **identity,
            "old_version": "9",
            "new_version": "10",
            "reason_code": "RUNTIME_DEPENDENCY_USES_REMOVED_API",
        }

        def row_for(items):
            return s6_report.build_api_result_rows({
                "impact_overview": {"apis": []},
                "p0": [],
                "p1": items,
                "p2": [],
            })[0]

        forward = row_for([item_a, item_b])
        reverse = row_for([item_b, item_a])

        self.assertEqual(forward, reverse)
        self.assertEqual("", forward["old_version"])
        self.assertEqual("", forward["new_version"])
        self.assertIn(
            "当前最终制品中的运行时依赖仍引用已移除 API",
            forward["reason"],
        )
        self.assertIn(
            "调用链已从当前系统入口触达变更 API",
            forward["reason"],
        )

    def test_reachable_alert_rejects_wrong_overload_and_false_reachability(self):
        fieldnames = [
            "target_coord",
            "changed_symbol",
            "api_signature",
            "symbol_kind",
            "change_type",
            "path_status",
            "conclusion_level",
            "business_reachable",
            "path_text",
        ]
        rows = [
            {
                "target_coord": "com.acme:lib",
                "changed_symbol": "com.acme.Api.call",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "path_status": "reachable",
                "conclusion_level": "confirmed",
                "business_reachable": "true",
                "path_text": (
                    "com.app.Entry.run() -> com.acme.Api.call(Integer)"
                ),
            },
            {
                "target_coord": "com.acme:lib",
                "changed_symbol": "com.acme.Api.call",
                "api_signature": "(String)",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "path_status": "reachable",
                "conclusion_level": "confirmed",
                "business_reachable": "false",
                "path_text": (
                    "com.app.Entry.run() -> com.acme.Api.call(String)"
                ),
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.csv"
            with path.open("w", encoding="utf-8", newline="") as output:
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            diagnostics = []
            accepted = list(s6_report._validated_alert_rows(
                path,
                diagnostics=diagnostics,
            ))

        self.assertEqual([], accepted)
        self.assertEqual(1, len(diagnostics))

    def test_evidence_edges_render_as_one_non_repeating_chain(self):
        paths = s6_report._paths_for_report(
            {
                "coord": "com.acme:lib",
                "api": "com.acme.Api.run",
                "evidence_paths": [
                    [
                        {"caller_symbol": "A", "callee_key": "B"},
                        {"caller_symbol": "B", "callee_key": "C"},
                    ]
                ],
            },
            {},
        )

        self.assertEqual(paths, ["A → B → C"])

    def test_source_alignment_unverified_is_not_reported_as_mismatch(self):
        unverified = s6_report._coverage_impact_text(
            "source_artifact_alignment",
            ["source_revision_unavailable"],
        )
        mismatch = s6_report._coverage_impact_text(
            "source_artifact_alignment",
            ["source_revision_differs_from_build_revision"],
        )

        self.assertIn("一致性未验证", unverified)
        self.assertNotIn("修订版本不一致", unverified)
        self.assertIn("修订版本不一致", mismatch)

    def test_changed_inventory_overrides_stale_summary_severity_and_versions(self):
        identity = {
            "coord": "com.acme:lib",
            "api": "com.acme.Api.run",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        with tempfile.TemporaryDirectory() as tmp:
            self._write_collection_fixture(
                tmp,
                summary={
                    "status": "done",
                    "total_apis": 1,
                    "reachable": 1,
                    "reachable_apis": [{
                        **identity,
                        "severity": "P0",
                        "old_version": "1.0",
                        "new_version": "9.0",
                        "reason_code": "SYSTEM_CODE_REACHED",
                    }],
                },
                changed_rows=[{
                    **identity,
                    "api_name": identity["api"],
                    "severity": "P2",
                    "old_version": "1.0",
                    "new_version": "2.0",
                }],
                alert_rows=[{
                    "target_coord": identity["coord"],
                    "changed_symbol": identity["api"],
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "severity": "P2",
                    "old_version": "1.0",
                    "new_version": "2.0",
                    "path_status": "reachable",
                    "conclusion_level": "confirmed",
                    "business_reachable": "true",
                    "business_entry": "com.app.Entry.run()",
                    "path_text": (
                        "com.app.Entry.run() -> com.acme.Api.run()"
                    ),
                }],
            )

            findings = s6_report.collect_findings(tmp)
            report = s6_report.generate_report(findings)

        self.assertEqual(findings["p0"], [])
        self.assertEqual(len(findings["p2"]), 1)
        self.assertEqual(findings["p2"][0]["new_version"], "2.0")
        self.assertIn("1.0 → 2.0", report)
        self.assertNotIn("1.0 → 9.0", report)
        self.assertTrue(any(
            item.get("artifact") == "call_chain_summary"
            and item.get("stage") == "field_consistency"
            for item in findings["diagnostics"]
        ))

    def test_arbitrary_reason_text_cannot_contradict_or_instruct(self):
        findings = self._human_first_findings()
        findings["p0"][0].update({
            "reason_code": "SYSTEM_CODE_REACHED",
            "user_reason": "系统完全不受影响，最好先重跑分析。",
            "reason": "推荐优先修改代码。",
        })

        report = s6_report.generate_report(findings)

        self.assertIn("确认有影响", report)
        self.assertIn(
            "com.acme.checkout.PaymentService.submit → "
            "com.acme.payments.LegacyClient.charge(Order)",
            report,
        )
        self.assertNotIn("完全不受影响", report)
        self.assertNotIn("最好先", report)
        self.assertNotIn("推荐优先", report)

    def test_duplicate_alert_reason_does_not_duplicate_occurrence_count(self):
        base = {
            "target_coord": "com.acme:lib",
            "changed_symbol": "com.acme.Api.run",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "path_status": "reachable",
            "business_entry": "com.app.Entry.run",
            "path_text": "com.app.Entry.run -> com.acme.Api.run()",
            "path_occurrence_count": "3",
            "evidence_files": "src/main/java/com/app/Entry.java",
        }
        overview = s6_report.build_impact_overview([
            {**base, "reason": "first explanation"},
            {**base, "reason": "different explanation"},
        ])

        self.assertEqual(overview["apis"][0]["path_count"], 1)
        self.assertEqual(overview["apis"][0]["occurrence_count"], 3)

    def test_coverage_contradiction_and_non_text_component_are_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_collection_fixture(
                tmp,
                summary={
                    "status": "skipped",
                    "skip_reason": "no_changed_apis",
                    "total_apis": 0,
                },
                changed_rows=[],
                alert_rows=None,
                coverage={
                    "overall_status": "complete",
                    "critical_incomplete": [
                        {"broken": "scope"},
                        "business_reachability",
                    ],
                    "components": [{
                        "id": "business_reachability",
                        "status": "partial",
                        "reason_codes": [],
                        "evidence": [],
                    }],
                },
            )
            findings = s6_report.collect_findings(tmp)
            report = s6_report.generate_report(findings)

        self.assertEqual(
            findings["coverage"]["critical_incomplete"],
            ["business_reachability"],
        )
        self.assertEqual(
            s6_report._effective_coverage_status(findings),
            "partial",
        )
        self.assertNotIn("### 本轮分析输入记录", report)
        self.assertNotIn("{'broken': 'scope'}", report)

    def test_no_changed_api_skip_cannot_carry_confirmed_results(self):
        identity = {
            "coord": "com.acme:lib",
            "api": "com.acme.Api.run",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
        }
        with tempfile.TemporaryDirectory() as tmp:
            self._write_collection_fixture(
                tmp,
                summary={
                    "status": "skipped",
                    "skip_reason": "no_changed_apis",
                    "total_apis": 1,
                    "reachable": 1,
                    "reachable_apis": [identity],
                },
                changed_rows=[{
                    **identity,
                    "api_name": identity["api"],
                }],
                alert_rows=[{
                    "target_coord": identity["coord"],
                    "changed_symbol": identity["api"],
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "path_status": "reachable",
                    "path_text": (
                        "com.app.Entry.run() -> com.acme.Api.run()"
                    ),
                }],
            )
            findings = s6_report.collect_findings(tmp)
            report = s6_report.generate_report(findings)

        self.assertEqual(
            findings["p0"] + findings["p1"] + findings["p2"],
            [],
        )
        self.assertNotIn(
            "已确认当前系统受到升级影响",
            report,
        )
        self.assertTrue(any(
            item.get("artifact") == "call_chain_summary"
            for item in findings["diagnostics"]
        ))

    def test_invalid_context_and_guidance_text_do_not_leak_repr_or_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write_collection_fixture(
                tmp,
                summary={
                    "status": "skipped",
                    "skip_reason": "no_changed_apis",
                    "total_apis": 0,
                    "diagnostic_guidance": [{
                        "reason_code": "请重跑",
                        "origin_step": "推荐查看日志",
                        "observed_scope": "最好先修复",
                        "title": {"bad": "推荐先重新运行扫描"},
                        "trigger_condition": ["最好先补齐源码再重跑"],
                        "semantic_impact": "建议人工核对全部 API",
                        "failure_detail_summaries": [
                            "请查看日志后重试"
                        ],
                    }],
                },
                changed_rows=[],
                alert_rows=None,
                context={
                    "jdk_base": {"bad": 8},
                    "jdk_current": ["17"],
                    "springboot_base": {"bad": "2"},
                    "springboot_current": ["3"],
                    "build_tool": {"bad": "maven"},
                    "tech_flags": [],
                },
            )
            findings = s6_report.collect_findings(tmp)
            detail = s6_report.render_diagnostic_detail_artifact(
                findings
            )
            report = s6_report.generate_report(findings)

        visible = report + detail
        for forbidden in (
            "{'bad'",
            "['17']",
            "请重跑",
            "推荐查看日志",
            "最好先修复",
            "推荐先重新运行扫描",
            "最好先补齐源码再重跑",
            "建议人工核对全部 API",
            "请查看日志后重试",
        ):
            self.assertNotIn(forbidden, visible)

    def test_confirmed_detail_artifact_exists_only_for_main_table_overflow(self):
        findings = {
            "impact_overview": {"apis": []},
            "p0": [],
            "p1": [
                {
                    "coord": "com.acme:lib",
                    "api": f"com.acme.Api.m{index}",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "severity": "P1",
                    "reason_code": "SYSTEM_CODE_REACHED",
                }
                for index in range(8)
            ],
            "p2": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            artifacts = s6_report.write_bucket_detail_artifacts(
                tmp, findings, "confirmed"
            )

        self.assertEqual(artifacts, {})

    def test_invalid_by_api_evidence_paths_are_diagnosed_without_crash(self):
        identity = {
            "coord": "com.acme:lib",
            "api": "com.acme.Api.run",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
        }
        with tempfile.TemporaryDirectory() as tmp:
            self._write_collection_fixture(
                tmp,
                summary={
                    "status": "done",
                    "total_apis": 1,
                    "reachable": 1,
                    "reachable_apis": [{
                        **identity,
                        "reason_code": "SYSTEM_CODE_REACHED",
                    }],
                },
                changed_rows=[{
                    **identity,
                    "api_name": identity["api"],
                }],
                alert_rows=[{
                    "target_coord": identity["coord"],
                    "changed_symbol": identity["api"],
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "path_status": "reachable",
                    "path_text": (
                        "com.app.Entry.run() -> com.acme.Api.run()"
                    ),
                }],
            )
            by_api = (
                Path(tmp)
                / "evidence"
                / "call_chain"
                / "by_api"
                / "api.json"
            )
            by_api.parent.mkdir(parents=True)
            by_api.write_text(
                json.dumps({
                    **identity,
                    "evidence_paths": "not-a-list",
                }),
                encoding="utf-8",
            )

            findings = s6_report.collect_findings(tmp)
            report = s6_report.generate_report(findings)

        self.assertIn("确认有影响", report)
        self.assertTrue(any(
            str(item.get("artifact") or "").startswith(
                "call_chain_by_api:"
            )
            for item in findings["diagnostics"]
        ))

    def test_empty_or_unrelated_alert_path_cannot_confirm_impact(self):
        identity = {
            "coord": "com.acme:lib",
            "api": "com.acme.Api.run",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
        }
        with tempfile.TemporaryDirectory() as tmp:
            self._write_collection_fixture(
                tmp,
                summary={
                    "status": "done",
                    "total_apis": 1,
                    "reachable": 1,
                    "reachable_apis": [identity],
                },
                changed_rows=[{
                    **identity,
                    "api_name": identity["api"],
                }],
                alert_rows=[{
                    "target_coord": identity["coord"],
                    "changed_symbol": identity["api"],
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "path_status": "reachable",
                    "path_text": (
                        "fake.Entry.run() -> fake.Other.call()"
                    ),
                }],
            )
            findings = s6_report.collect_findings(tmp)

        self.assertEqual(
            findings["p0"] + findings["p1"] + findings["p2"],
            [],
        )
        self.assertEqual(len(findings["needs_input"]), 1)

    def test_same_count_different_changed_identity_invalidates_full_scope(self):
        summary_identity = {
            "coord": "com.acme:lib",
            "api": "com.acme.Api.a",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "severity": "P1",
        }
        with tempfile.TemporaryDirectory() as tmp:
            self._write_collection_fixture(
                tmp,
                summary={
                    "status": "done",
                    "total_apis": 1,
                    "not_found_in_static_analysis": 1,
                    "not_found_apis": [summary_identity],
                },
                changed_rows=[{
                    **summary_identity,
                    "api_name": "com.acme.Api.b",
                }],
                alert_rows=[{
                    "target_coord": summary_identity["coord"],
                    "changed_symbol": summary_identity["api"],
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "path_status": "not_found_in_static_analysis",
                }],
            )
            findings = s6_report.collect_findings(tmp)
            report = s6_report.generate_report(findings)

        self.assertEqual(findings["analysis_scope"]["mode"], "")
        self.assertIn("未完成分析", report)
        self.assertIn(
            "调用关系分析结果中没有对应记录",
            report,
        )
        self.assertNotIn("全量分析（变化 API 1/1）", report)

    def test_unrelated_input_diagnostic_is_not_used_as_an_api_failure_reason(self):
        findings = {
            "analysis_scope": {
                "mode": "full",
                "available_dependency_count": 1,
                "included_dependency_count": 1,
                "total_api_count": 1,
                "analyzed_api_count": 0,
            },
            "dependency_changes": [{
                "coord": "com.acme:lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
            }],
            "changed_api_inventory": [{
                "coord": "com.acme:lib",
                "api": "com.acme.Api.run",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }],
            "needs_input": [{
                "coord": "com.acme:lib",
                "api": "com.acme.Api.run",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
            }],
            "diagnostics": [{
                "artifact": "coverage",
                "stage": "json_missing",
                "path": ".runtime/coverage/coverage.json",
                "error_type": "FileNotFoundError",
            }],
        }

        report = s6_report.generate_report(findings)

        self.assertIn(
            "当前记录没有保存该 API 未完成调用关系分析的具体原因",
            report,
        )
        self.assertNotIn(
            "证据覆盖记录文件未生成，因此没有形成对应的调用关系分析结果",
            report,
        )

    def test_reachable_path_must_start_at_the_recorded_business_entry(self):
        base = {
            "changed_symbol": "com.vendor.Api.removed",
            "api_signature": "()",
            "business_entry": "com.app.Entry.run()",
            "path_status": "reachable",
        }

        self.assertTrue(
            s6_report._alert_row_has_reachable_path_evidence({
                **base,
                "path_text": (
                    "com.app.Entry.run() → com.vendor.Api.removed()"
                ),
            })
        )
        self.assertTrue(
            s6_report._alert_row_has_reachable_path_evidence({
                **base,
                "path_text": (
                    "业务制品：com.app.Entry.run() → com.vendor.Api.removed()"
                ),
            })
        )
        self.assertFalse(
            s6_report._alert_row_has_reachable_path_evidence({
                **base,
                "path_text": (
                    "third.party.Bridge.call() → com.vendor.Api.removed()"
                ),
            })
        )
        with tempfile.TemporaryDirectory() as tmp:
            alerts_path = (
                Path(tmp) / "evidence" / "call_chain" / "alerts.csv"
            )
            alerts_path.parent.mkdir(parents=True)
            rows = [
                {
                    **base,
                    "target_coord": "com.vendor:lib",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "path_text": (
                        "com.app.Entry.run() → com.vendor.Api.removed()"
                    ),
                },
                {
                    **base,
                    "target_coord": "com.vendor:lib",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                    "path_text": (
                        "third.party.Bridge.call() → com.vendor.Api.removed()"
                    ),
                },
            ]
            with alerts_path.open(
                "w", encoding="utf-8", newline=""
            ) as output:
                writer = csv.DictWriter(
                    output,
                    fieldnames=sorted({
                        key for row in rows for key in row
                    }),
                )
                writer.writeheader()
                writer.writerows(rows)

            details = s6_report._load_full_alert_details(tmp)

        identity = s6_report.build_api_identity_key({
            "coord": "com.vendor:lib",
            "api": "com.vendor.Api.removed",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        })
        reachable_paths = details[identity]["paths_by_status"]["reachable"]
        self.assertEqual(
            ["com.app.Entry.run() → com.vendor.Api.removed()"],
            list(reachable_paths),
        )

    def test_partially_analyzed_dependency_keeps_confirmed_facts_and_both_links(self):
        coord = "com.acme:mixed-lib"
        confirmed_api = {
            "coord": coord,
            "api": "com.acme.Api.confirmed",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
        }
        incomplete_api = {
            "coord": coord,
            "api": "com.acme.Api.incomplete",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "reason_code": "MISSING_API_SIGNATURE",
        }
        path = "com.app.Entry.run() → com.acme.Api.confirmed()"
        findings = {
            "analysis_scope": {
                "mode": "full",
                "available_dependency_count": 1,
                "included_dependency_count": 1,
                "total_api_count": 2,
                "analyzed_api_count": 1,
            },
            "dependency_changes": [{
                "coord": coord,
                "old_version": "1.0.0",
                "new_version": "2.0.0",
                "change_type": "major",
            }],
            "changed_api_inventory": [confirmed_api, incomplete_api],
            "impact_overview": {
                "apis": [{
                    **confirmed_api,
                    "paths": [path],
                    "paths_by_status": {"reachable": [path]},
                    "path_counts_by_status": {"reachable": 1},
                    "logical_path_counts_by_status": {"reachable": 1},
                    "occurrence_counts_by_status": {"reachable": 1},
                }]
            },
            "p1": [confirmed_api],
            "needs_input": [incomplete_api],
            "artifacts": {},
        }

        with tempfile.TemporaryDirectory() as tmp:
            artifacts, _api_model, _dependency_model = (
                s6_report.write_primary_report_artifacts(tmp, findings)
            )
            findings["artifacts"].update(artifacts)
            report = s6_report.generate_report(findings)
            dependency_detail = (
                Path(tmp) / artifacts["full_dependency_analysis_md"]
            ).read_text(encoding="utf-8")
            api_detail = (
                Path(tmp) / artifacts["full_api_analysis_md"]
            ).read_text(encoding="utf-8")

        self.assertIn("1/2", report)
        self.assertIn("| 1 | 0 | 1 | 1 | 0 | 0 |", report)
        self.assertIn("1 个变化 API<br>1 条调用关系", report)
        self.assertIn("部分结果确认有影响；分析未完成", report)
        self.assertIn("[已完成 API 及调用关系]", dependency_detail)
        self.assertIn("[未完成 API 及原因]", dependency_detail)
        self.assertNotIn("<a ", api_detail)
        detail_targets = {
            s6_report._markdown_heading_fragment(line)
            for line in api_detail.splitlines()
            if re.match(r"^#{1,6}\s+", line)
        }
        linked_targets = re.findall(
            r"all-impact-details\.md#([^\)]+)",
            dependency_detail,
        )
        self.assertTrue(linked_targets)
        for target in linked_targets:
            self.assertIn(target, detail_targets)

    def test_file_explanation_counts_input_and_analysis_diagnostics_separately(self):
        findings = self._human_first_findings()
        findings["diagnostics"] = [{
            "artifact": "coverage",
            "stage": "json_missing",
            "path": ".runtime/coverage/coverage.json",
            "error_type": "FileNotFoundError",
        }]
        findings["diagnostic_guidance"] = [{
            "reason_code": "BYTECODE_CALLER_UNRESOLVED",
            "origin_step": "step5",
            "title": "部分调用方未解析",
        }]
        findings["artifacts"]["diagnostic_detail_md"] = (
            "deliverables/analysis-diagnostics.md"
        )

        report = s6_report.generate_report(findings)

        self.assertIn("输入异常 1 项；分析诊断 1 项", report)
        self.assertIn("未完成分析原因与结论限制", report)

    def test_summary_classification_is_only_in_tables(self):
        report = s6_report.generate_report(self._human_first_findings())

        self.assertIn(
            "| 变化依赖总数 | 已完成分析 | 未完成分析 | 确认有影响 | 确认不受影响 | 尚未确认影响 |",
            report,
        )
        self.assertIn(
            "| 变化 API 总数 | 已完成分析 | 未完成分析 | 确认有影响 | 确认不受影响 | 尚未确认影响 |",
            report,
        )
        self.assertEqual(
            report.count("| 1 | 1 | 0 | 1 | 0 | 0 |"),
            2,
        )
        self.assertNotIn("已完成分析的 1 个依赖中", report)
        self.assertNotIn("已完成分析的 1 个 API 中", report)

    def test_completed_and_incomplete_detail_tables_share_headers(self):
        confirmed = {
            "coord": "com.acme:confirmed",
            "api": "com.acme.ConfirmedApi.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
        }
        incomplete = {
            "coord": "com.acme:incomplete",
            "api": "com.acme.IncompleteApi.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "reason_code": "MISSING_DEPENDENCY_SOURCE_MAPPING",
        }
        path = (
            "com.app.Entry.run() → com.acme.ConfirmedApi.call()"
        )
        findings = {
            "analysis_scope": {
                "mode": "full",
                "available_dependency_count": 2,
                "included_dependency_count": 2,
                "total_api_count": 2,
                "analyzed_api_count": 1,
            },
            "dependency_changes": [
                {
                    "coord": item["coord"],
                    "old_version": item["old_version"],
                    "new_version": item["new_version"],
                    "change_type": "major",
                }
                for item in (confirmed, incomplete)
            ],
            "changed_api_inventory": [confirmed, incomplete],
            "call_chain_target_count": 2,
            "impact_overview": {
                "apis": [{
                    **confirmed,
                    "paths": [path],
                    "paths_by_status": {"reachable": [path]},
                    "path_counts_by_status": {"reachable": 1},
                    "logical_path_counts_by_status": {"reachable": 1},
                    "occurrence_counts_by_status": {"reachable": 1},
                }]
            },
            "p1": [{**confirmed, "reason_code": "SYSTEM_CODE_REACHED"}],
            "needs_input": [incomplete],
            "artifacts": {},
        }
        dependency_header = (
            "| 依赖 | 版本变化 | API 分析（已完成/总数） | "
            "当前系统调用关系 | 分析结果 | 结果说明 |"
        )
        api_header = (
            "| 依赖 | API | 新版本中的变化 | 当前系统调用关系 | "
            "分析结果 | 结果说明 |"
        )

        with tempfile.TemporaryDirectory() as tmp:
            artifacts, _api_model, _dependency_model = (
                s6_report.write_primary_report_artifacts(tmp, findings)
            )
            findings["artifacts"].update(artifacts)
            report = s6_report.generate_report(findings)
            dependency_detail = (
                Path(tmp) / artifacts["full_dependency_analysis_md"]
            ).read_text(encoding="utf-8")
            api_detail = (
                Path(tmp) / artifacts["full_api_analysis_md"]
            ).read_text(encoding="utf-8")

        self.assertEqual(report.count(dependency_header), 2)
        self.assertEqual(report.count(api_header), 2)
        self.assertEqual(dependency_detail.count(dependency_header), 2)
        self.assertEqual(api_detail.count(api_header), 2)
        self.assertNotIn("分析状态 | 未完成原因", report)
        self.assertNotIn("分析结论 | 结论依据", report)
        self.assertIn("调用关系分析未完成", report)
        self.assertIn(
            "缺少依赖源码，跨依赖调用链未完整回溯",
            report,
        )

    def test_bytecode_caller_diagnostic_states_its_record_condition(self):
        detail = "\n".join(s6_report.render_diagnostic_guidance({
            "diagnostic_guidance": [{
                "reason_code": "BYTECODE_CALLER_UNRESOLVED",
                "origin_step": "step5",
                "observed_scope": "global",
                "blocking": True,
                "evidence_files": [
                    "evidence/call_chain/bytecode_unresolved.csv"
                ],
            }],
        }))

        self.assertIn(
            "现有源码方法索引无法将该调用方唯一对应到源码方法",
            detail,
        )
        self.assertNotIn("未记录更具体的触发条件", detail)
        self.assertIn(
            "../evidence/call_chain/bytecode_unresolved.csv",
            detail,
        )

    def test_collection_preserves_bytecode_instruction_evidence_pointer(self):
        summary = {
            "status": "done",
            "origin_step": "step5",
            "total_apis": 0,
            "reachable": 0,
            "not_impacted": 0,
            "uncertain": 0,
            "not_analyzed": 0,
            "not_found_in_static_analysis": 0,
            "reachable_apis": [],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
            "user_conclusion_summary": {
                "inconclusive": 2,
                "input_required": 1,
            },
            "diagnostic_guidance": [{
                "reason_code": "BYTECODE_CALLER_UNRESOLVED",
                "origin_step": "step5",
                "observed_scope": "api",
                "blocking": False,
                "evidence_files": [
                    "evidence/call_chain/bytecode_unresolved.csv"
                ],
            }],
        }
        with tempfile.TemporaryDirectory() as tmp:
            self._write_collection_fixture(
                tmp,
                summary=summary,
                changed_rows=[],
                alert_rows=[],
            )
            evidence = (
                Path(tmp)
                / "evidence"
                / "call_chain"
                / "bytecode_unresolved.csv"
            )
            evidence.write_text(
                "caller_class,caller_method,instruction_offset,unresolved_owner,unresolved_method\n",
                encoding="utf-8",
            )

            findings = s6_report.collect_findings(tmp)
            detail = s6_report.render_diagnostic_detail_artifact(findings)

        self.assertEqual(
            findings["artifacts"]["bytecode_unresolved_csv"],
            "evidence/call_chain/bytecode_unresolved.csv",
        )
        self.assertEqual(
            findings["diagnostic_guidance"][0]["evidence_files"],
            ["evidence/call_chain/bytecode_unresolved.csv"],
        )
        self.assertEqual(
            findings["diagnostic_guidance"][0]["evidence_file"],
            "evidence/call_chain/bytecode_unresolved.csv",
        )
        self.assertEqual(
            findings["user_conclusion_summary"],
            {"inconclusive": 2, "input_required": 1},
        )
        self.assertIn(
            "../evidence/call_chain/bytecode_unresolved.csv",
            detail,
        )

    def test_aggregated_missing_identities_use_the_same_display_count_everywhere(self):
        findings = {
            "analysis_scope": {
                "mode": "full",
                "available_dependency_count": 20,
                "included_dependency_count": 20,
                "total_api_count": 20,
                "analyzed_api_count": 0,
            },
            "call_chain_target_count": 20,
            "artifacts": {},
        }

        report = s6_report.generate_report(findings)

        self.assertIn("依赖汇总覆盖 20/20、逐项展示 20/20", report)
        self.assertIn("API 汇总覆盖 20/20、逐项展示 20/20", report)
        self.assertIn("`依赖身份未记录（20 个）`", report)
        self.assertNotIn("逐项展示 10/20", report)

    def test_missing_api_identities_do_not_mark_the_known_dependency_complete(self):
        findings = {
            "analysis_scope": {
                "mode": "full",
                "available_dependency_count": 1,
                "included_dependency_count": 1,
                "total_api_count": 5,
                "analyzed_api_count": 0,
            },
            "dependency_changes": [{
                "coord": "com.acme:lib",
                "old_version": "1.0.0",
                "new_version": "2.0.0",
            }],
            "call_chain_target_count": 5,
            "artifacts": {},
        }

        report = s6_report.generate_report(findings)

        self.assertIn("| 1 | 0 | 1 | 0 |", report)
        self.assertIn("0/5", report)
        self.assertIn(
            "其余 5 个 API 的身份没有记录",
            report,
        )
        self.assertNotIn("### 已完成分析的依赖", report)

    def test_duplicate_changed_api_records_do_not_create_an_anonymous_api(self):
        api = {
            "coord": "com.acme:lib",
            "api": "com.acme.Api.run",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
        }
        findings = {
            "analysis_scope": {"total_api_count": 2},
            "call_chain_target_count": 2,
            "scan_stats": {"changed_apis_total": 2},
            "changed_api_inventory": [dict(api), dict(api)],
        }

        model = s6_report.build_human_api_analysis(findings)

        self.assertEqual(model["total_count"], 1)
        self.assertEqual(model["completed_count"], 0)
        self.assertEqual(model["incomplete_count"], 1)
        self.assertEqual(model["rows"][0]["api"], "com.acme.Api.run")
        self.assertNotIn("API 身份未记录", str(model["rows"]))
        self.assertIn("使用相同 API 身份", model["count_note"])

    def test_duplicate_changed_api_with_result_is_counted_once(self):
        api = {
            "coord": "com.acme:lib",
            "api": "com.acme.Api.run",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
        }
        findings = {
            "analysis_scope": {"total_api_count": 2},
            "call_chain_target_count": 2,
            "scan_stats": {"changed_apis_total": 2},
            "changed_api_inventory": [dict(api), dict(api)],
            "p1": [dict(api)],
        }

        model = s6_report.build_human_api_analysis(findings)

        self.assertEqual(model["total_count"], 1)
        self.assertEqual(model["completed_count"], 1)
        self.assertEqual(model["incomplete_count"], 0)
        self.assertNotIn("API 身份未记录", str(model["rows"]))

    def test_conflicting_changed_api_records_are_reported_as_incomplete(self):
        first = {
            "coord": "com.acme:lib",
            "api": "com.acme.Api.run",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
        }
        second = {
            **first,
            "new_version": "3.0.0",
        }
        findings = {
            "analysis_scope": {"total_api_count": 2},
            "call_chain_target_count": 2,
            "scan_stats": {"changed_apis_total": 2},
            "changed_api_inventory": [first, second],
            "p1": [dict(first)],
        }

        model = s6_report.build_human_api_analysis(findings)

        self.assertEqual(model["total_count"], 1)
        self.assertEqual(model["completed_count"], 0)
        self.assertEqual(model["incomplete_count"], 1)
        self.assertEqual(model["rows"][0]["old_version"], "")
        self.assertEqual(model["rows"][0]["new_version"], "")
        self.assertIn("互相冲突", model["rows"][0]["incomplete_reason"])
        self.assertNotIn("API 身份未记录", str(model["rows"]))

    def test_conflicting_api_totals_do_not_invent_missing_api_identities(self):
        findings = {
            "analysis_scope": {"total_api_count": 2},
            "call_chain_target_count": 3,
            "scan_stats": {"changed_apis_total": 0},
        }

        model = s6_report.build_human_api_analysis(findings)
        report = s6_report.generate_report(findings)

        self.assertTrue(model["population_unconfirmed"])
        self.assertEqual(model["total_count"], 0)
        self.assertEqual(model["rows"], [])
        self.assertIn("变化 API 总数无法确认", model["count_note"])
        self.assertIn("分析范围记录 2 个", model["count_note"])
        self.assertIn("调用关系目标记录 3 个", model["count_note"])
        self.assertNotIn("API 身份未记录", report)

    def test_duplicate_dependency_records_do_not_create_an_anonymous_dependency(self):
        dependency = {
            "coord": "com.acme:lib",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "change_type": "major",
        }
        findings = {
            "analysis_scope": {"available_dependency_count": 2},
            "dep_changes_summary": {"major": 2},
            "dependency_changes": [dict(dependency), dict(dependency)],
        }

        model = s6_report.build_human_dependency_analysis(findings)

        self.assertEqual(model["total_count"], 1)
        self.assertEqual(model["completed_count"], 1)
        self.assertEqual(model["incomplete_count"], 0)
        self.assertEqual(model["rows"][0]["coord"], "com.acme:lib")
        self.assertNotIn("依赖身份未记录", str(model["rows"]))
        self.assertIn("使用相同依赖身份", model["count_note"])

    def test_conflicting_dependency_records_are_reported_as_incomplete(self):
        findings = {
            "analysis_scope": {"available_dependency_count": 2},
            "dep_changes_summary": {"major": 2},
            "dependency_changes": [
                {
                    "coord": "com.acme:lib",
                    "old_version": "1.0.0",
                    "new_version": "2.0.0",
                    "change_type": "major",
                },
                {
                    "coord": "com.acme:lib",
                    "old_version": "1.0.0",
                    "new_version": "3.0.0",
                    "change_type": "major",
                },
            ],
        }

        model = s6_report.build_human_dependency_analysis(findings)

        self.assertEqual(model["total_count"], 1)
        self.assertEqual(model["completed_count"], 0)
        self.assertEqual(model["incomplete_count"], 1)
        self.assertEqual(model["rows"][0]["change_type"], "变化记录冲突")
        self.assertIn("互相冲突", model["rows"][0]["incomplete_reason"])
        self.assertNotIn("依赖身份未记录", str(model["rows"]))

    def test_global_blocking_diagnostic_limits_global_conclusions(self):
        text = s6_report._diagnostic_objective_impact(
            {
                "blocking": True,
                "observed_scope": "global",
                "affected_api_count": 0,
            }
        )

        self.assertIn("全局作用域", text)
        self.assertIn("未完成、未确认和未命中结果", text)
        self.assertNotIn("不改变已由完整调用链", text)

    def test_unrelated_api_diagnostic_does_not_limit_global_conclusions(self):
        text = s6_report._diagnostic_objective_impact(
            {
                "reason_code": "BYTECODE_CALLER_UNRESOLVED",
                "blocking": False,
                "observed_scope": "api",
                "affected_api_count": 0,
                "potentially_affected_api_count": 0,
                "raw_blocking_failure_count": 2309,
                "relevant_blocking_failure_count": 0,
            }
        )

        self.assertIn("不限制本轮 API 结论", text)
        self.assertIn("覆盖遥测", text)
        self.assertNotIn("全局", text)

    def test_v2_diagnostic_counts_remain_compatible_with_v3_fields(self):
        summary = {
            "status": "done",
            "total_apis": 0,
            "reachable_apis": [],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
            "diagnostic_guidance": [{
                "reason_code": "BYTECODE_CALLER_UNRESOLVED",
                "origin_step": "step5",
                "observed_scope": "api",
                "affected_api_count": 3,
                "observed_failure_count": 2,
                "blocking": True,
            }],
        }
        diagnostics = []

        s6_report._validate_call_summary_contract(
            Path(__file__),
            summary,
            diagnostics,
        )

        guidance = summary["diagnostic_guidance"][0]
        self.assertEqual([], diagnostics)
        self.assertEqual(3, guidance["primary_reason_api_count"])
        self.assertEqual(3, guidance["potentially_affected_api_count"])
        self.assertEqual(2, guidance["failure_record_count"])
        self.assertEqual(0, guidance["failure_occurrence_count"])

    def test_database_contract_section_is_bounded_and_links_details_at_section(self):
        findings = self._human_first_findings()
        findings["database_contract"] = {
            "coverage_status": "complete",
            "coverage_gaps": [],
            "rows": [
                {
                    "依赖包": "com.acme:data-access",
                    "变化类型": "新增当前契约",
                    "契约类型": "MyBatis XML SELECT",
                    "可信度": "确认",
                    "表": "orders",
                    "列": f"column_{index}",
                    "契约位置": "com.acme.OrderMapper",
                    "语句或字段": f"find{index}",
                    "人工复核建议": "确认目标数据库结构满足当前契约。",
                }
                for index in range(12)
            ],
        }
        findings["artifacts"].update({
            "database_contract_review_md": (
                "evidence/static_scan/s3_database_contract_changes.md"
            ),
            "database_contract_csv": (
                "evidence/static_scan/s3_database_contract_changes.csv"
            ),
        })

        report = s6_report.generate_report(findings)
        section = report[
            report.index("### 数据库契约变化提醒"):
            report.index("## 二、API 及调用关系")
        ]
        toc = report[
            report.index("## 报告目录"):report.index("## 一、依赖层面结论")
        ]

        self.assertIn("[数据库契约变化提醒]", toc)
        self.assertIn("展示 10/12", section)
        self.assertIn("完整人工复核明细", section)
        self.assertIn("结构化明细 CSV", section)
        self.assertIn("不表示对应 DDL/迁移已经存在或已执行", section)
        self.assertIn("column_9", section)
        self.assertNotIn("column_10", section)
        self.assertIn("数据库契约完整复核明细", report)

    def test_database_contract_gap_does_not_render_false_clean_conclusion(self):
        lines = s6_report.render_database_contract_changes({
            "database_contract": {
                "coverage_status": "partial",
                "coverage_gaps": ["artifact_missing:current:com.acme:data-access"],
                "rows": [],
            },
            "artifacts": {},
        })
        text = "\n".join(lines)

        self.assertIn("不能解释为确认没有数据库契约变化", text)
        self.assertNotIn("本次未识别到升级前后数据访问契约变化", text)

    def test_collect_findings_loads_database_contract_and_rejects_bad_csv_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            dependencies = report_dir / "evidence" / "dependencies"
            static_scan = report_dir / "evidence" / "static_scan"
            dependencies.mkdir(parents=True)
            static_scan.mkdir(parents=True)
            (dependencies / "dependency_jars.json").write_text(
                json.dumps({"schema": "java-upgrade-analyzer.step1-dependency-jars.v3"}),
                encoding="utf-8",
            )
            (static_scan / "s3_database_contract_summary.json").write_text(
                json.dumps({
                    "schema": "java-upgrade-analyzer.database-contract-changes.v1",
                    "coverage_status": "complete",
                    "coverage_gaps": [],
                    "change_count": 1,
                }),
                encoding="utf-8",
            )
            (static_scan / "s3_database_contract_changes.md").write_text(
                "# 数据库契约变化明细\n", encoding="utf-8"
            )
            csv_path = static_scan / "s3_database_contract_changes.csv"
            csv_path.write_text("错误列\nvalue\n", encoding="utf-8")

            findings = s6_report.collect_findings(report_dir)

            self.assertEqual(
                findings["database_contract"]["coverage_status"], "partial"
            )
            self.assertEqual(findings["database_contract"]["rows"], [])
            self.assertIn(
                "database_contract_output_contract_invalid",
                findings["database_contract"]["coverage_gaps"],
            )
            self.assertTrue(any(
                item.get("artifact") == "step3_database_contract_changes"
                and item.get("stage") == "csv_contract"
                for item in findings["diagnostics"]
            ))


if __name__ == "__main__":
    unittest.main()
