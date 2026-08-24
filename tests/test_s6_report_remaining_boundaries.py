from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import s6_report


class Step6ReportRemainingBoundaryTest(unittest.TestCase):
    def test_dependency_cells_population_and_reason_projection_matrix(self):
        with patch.object(s6_report, "_change_summary", return_value="change"):
            self.assertEqual(s6_report._change_cell({"severity": "P0"}), "change")
            self.assertEqual(
                s6_report._change_cell(
                    {"severity": "P0"}, "P1", include_item_severity=False,
                ),
                "change",
            )
            self.assertEqual(
                s6_report._change_cell(
                    None, include_item_severity=False,
                ),
                "change",
            )

        self.assertEqual(
            s6_report._dependency_change_cell({"coord": "g:a"}),
            "`g:a`",
        )
        self.assertIn(
            "1 → 2",
            s6_report._dependency_change_cell({
                "coord": None, "old_version": "1", "new_version": "2",
            }),
        )
        self.assertEqual(
            s6_report._dependency_identity_cell({"coord": "g:a"}),
            "`g:a`",
        )
        self.assertEqual(
            s6_report._dependency_identity_cell({
                "coord": "g:a", "aggregate_count": 2,
            }),
            "`g:a（2 个）`",
        )
        self.assertIn(
            "大版本升级",
            s6_report._dependency_version_change_cell({
                "old_version": "1", "new_version": "2", "change_type": "major",
            }),
        )
        self.assertIn(
            "版本变化未记录",
            s6_report._dependency_version_change_cell({}),
        )

        self.assertEqual(
            s6_report._diagnostic_potential_api_count({
                "potentially_affected_api_count": 3,
            }),
            3,
        )
        self.assertEqual(
            s6_report._diagnostic_potential_api_count({
                "potentially_affected_api_count": -1,
                "affected_api_count": 9,
            }),
            0,
        )
        self.assertEqual(
            s6_report._diagnostic_potential_api_count({"affected_api_count": 2}),
            2,
        )
        self.assertEqual(s6_report._full_api_incomplete_heading(None), "## 未完成分析的 API（0）")
        self.assertEqual(s6_report._full_api_incomplete_heading(2), "## 未完成分析的 API（2）")

        scope = {"available_dependency_count": 2, "included_dependency_count": 1}
        self.assertIsNone(s6_report._invalidate_analysis_scope(scope, " bad "))
        self.assertEqual(scope["validation_status"], "invalid")
        self.assertEqual(scope["invalid_reason"], "bad")
        self.assertEqual(scope["available_dependency_count"], 0)
        empty_reason_scope = {}
        s6_report._invalidate_analysis_scope(empty_reason_scope, None)
        self.assertEqual(empty_reason_scope["invalid_reason"], "")

        self.assertEqual(
            s6_report._population_incomplete_cell({
                "population_unconfirmed": True, "incomplete_count": 2,
            }),
            "无法确认<br>已识别 2",
        )
        self.assertEqual(
            s6_report._population_incomplete_cell({
                "population_unconfirmed": True, "incomplete_count": 0,
            }),
            "无法确认<br>已识别 0",
        )
        self.assertEqual(s6_report._population_incomplete_cell({}), "0")
        self.assertEqual(s6_report._population_incomplete_cell({"incomplete_count": 2}), "2")
        self.assertEqual(
            s6_report._population_total_cell({
                "population_unconfirmed": True, "total_count": 4,
            }),
            "无法确认<br>已识别 4",
        )
        self.assertEqual(
            s6_report._population_total_cell({
                "population_unconfirmed": True, "total_count": 0,
            }),
            "无法确认<br>已识别 0",
        )
        self.assertEqual(s6_report._population_total_cell({}), "0")
        self.assertEqual(s6_report._population_total_cell({"total_count": 4}), "4")

        with patch.object(s6_report, "_objective_item_reason", return_value="objective"):
            self.assertEqual(s6_report._item_effect_text({}, {}, fallback="fallback"), "objective")
        with patch.object(s6_report, "_objective_item_reason", return_value=""):
            self.assertEqual(s6_report._item_effect_text({}, {}, fallback="fallback"), "fallback")
        with patch.object(s6_report, "_human_reason", return_value=""):
            self.assertEqual(s6_report._objective_reason_text("code"), "")
        with patch.object(s6_report, "_human_reason", return_value="reason"), patch.object(
            s6_report, "_reason_conflicts_with_conclusion", return_value=True,
        ):
            self.assertEqual(s6_report._objective_reason_text("code", "safe"), "")
        with patch.object(s6_report, "_human_reason", return_value="reason"), patch.object(
            s6_report, "_reason_conflicts_with_conclusion", return_value=False,
        ):
            self.assertEqual(s6_report._objective_reason_text("code"), "reason")
        with patch.object(s6_report, "_objective_reason_text", return_value="reason"):
            self.assertEqual(s6_report._objective_item_reason(None), "reason")
            self.assertEqual(s6_report._objective_item_reason({"reason_code": "X"}), "reason")

    def test_result_sort_summary_category_and_api_text_matrix(self):
        self.assertEqual(
            s6_report._report_reason_code_sort_key("SYSTEM_CODE_REACHED"),
            (1, "SYSTEM_CODE_REACHED"),
        )
        self.assertEqual(s6_report._report_reason_code_sort_key(None), (10, ""))
        with patch.object(s6_report, "_api_result_rank", return_value=2), patch.object(
            s6_report, "_api_call_relationship_count", return_value=3,
        ):
            self.assertEqual(
                s6_report._report_result_sort_key({
                    "coord": "g:a", "api": "A.m", "api_signature": "()V",
                    "change_type": "REMOVED",
                }),
                ("g:a", 2, -3, "A.m", "()V", "REMOVED"),
            )
            self.assertEqual(
                s6_report._report_result_sort_key({}),
                ("", 2, -3, "", "", ""),
            )
        self.assertEqual(
            s6_report._uncertain_item_sort_key({
                "priority_score": 4, "severity": "P1",
                "call_paths": [1, 2], "api": "A.m", "api_signature": "()V",
            }),
            (-4, 1, -2, "A.m", "()V"),
        )
        self.assertEqual(
            s6_report._uncertain_item_sort_key({"paths": [1], "api_name": "B.n"}),
            (0, 3, -1, "B.n", ""),
        )

        self.assertTrue(s6_report._api_result_is_incomplete({
            "conclusion": next(iter(s6_report._INCOMPLETE_API_CONCLUSIONS)),
        }))
        self.assertFalse(s6_report._api_result_is_incomplete(None))
        with patch.object(s6_report, "_api_result_is_incomplete", return_value=True):
            self.assertEqual(s6_report._api_human_category({}), "未完成分析")
        with patch.object(s6_report, "_api_result_is_incomplete", return_value=False):
            for conclusion, expected in (
                ("已确认影响", "确认有影响"),
                ("已确认不受影响", "确认不受影响"),
                ("未发现调用路径", "未发现调用路径"),
                ("future", "结论未确定"),
            ):
                self.assertEqual(
                    s6_report._api_human_category({"conclusion": conclusion}), expected,
                )
            self.assertEqual(s6_report._api_human_category(None), "结论未确定")
        with patch.object(s6_report, "_api_human_category", side_effect=["A", "A", "B"]):
            counts = s6_report._api_human_category_counts({"rows": [
                {"aggregate_count": 2}, {}, {"aggregate_count": 3},
            ]})
        self.assertEqual(dict(counts), {"A": 3, "B": 3})
        self.assertEqual(dict(s6_report._api_human_category_counts(None)), {})

        self.assertEqual(
            s6_report._business_scope_cell({"business_entries": ["A", "B", "C"]}),
            "`A`<br>`B`<br>…另 1 项",
        )
        self.assertEqual(
            s6_report._business_scope_cell({"modules": ["app", "core"]}),
            "模块：app<br>core",
        )
        self.assertEqual(s6_report._business_scope_cell({}), "未定位到业务入口")
        self.assertEqual(s6_report._dependency_api_change_text([]), "未记录变化 API")
        self.assertEqual(
            s6_report._dependency_api_change_text([
                {"change_type": "REMOVED", "symbol_kind": "method", "aggregate_count": 2},
            ]),
            "均为删除方法",
        )
        multi = s6_report._dependency_api_change_text([
            {"change_type": "REMOVED", "symbol_kind": "method"},
            {"change_type": "ADDED", "symbol_kind": "field"},
        ])
        self.assertIn("删除方法 1", multi)
        self.assertIn("新增字段 1", multi)
        self.assertEqual(
            s6_report._dependency_result_explanation({
                "analysis_complete": True, "conclusion_basis": " basis ",
            }),
            "basis",
        )
        self.assertEqual(
            s6_report._dependency_result_explanation({"incomplete_reason": " missing "}),
            "missing",
        )
        self.assertEqual(
            s6_report._dependency_result_explanation({"analysis_complete": True}),
            "",
        )
        self.assertEqual(s6_report._dependency_result_explanation({}), "")

        self.assertEqual(s6_report._item_api_label({"api": "A.m", "api_signature": "()V"}), "A.m()V")
        self.assertEqual(s6_report._item_api_label({"api_name": "A.m()", "api_signature": "()V"}), "A.m()")
        self.assertEqual(s6_report._item_api_label({}), "")
        self.assertEqual(
            s6_report._api_call_relationship_count({
                "confirmed_path_count": 2, "additional_review_path_count": 1,
                "uncertain_path_count": 4, "not_analyzed_path_count": 3,
                "path_count": 5,
            }),
            9,
        )
        self.assertEqual(s6_report._api_call_relationship_count(None), 0)

    def test_reason_summaries_uncertainty_bucket_and_dependency_lookup_matrix(self):
        with patch.object(s6_report, "canonical_reason_code", side_effect=lambda value: str(value).upper()):
            self.assertEqual(
                s6_report.summarize_item_reason_codes([
                    {"reason_code": "a"}, {"reason_code": "a"}, {},
                ]),
                {"A": 2, "UNKNOWN": 1},
            )
        self.assertEqual(s6_report.summarize_item_reason_codes(None), {})
        with patch.object(s6_report, "_objective_item_reason", side_effect=["reason", ""]):
            self.assertEqual(
                s6_report.summarize_item_reasons([{}, {}]),
                {"reason": 1, "未提供足够证据说明原因": 1},
            )
        self.assertEqual(s6_report.summarize_item_reasons(None), {})
        self.assertEqual(
            s6_report.summarize_item_coords([
                {"coord": "g:a"}, {"coord": "g:a"}, {},
            ]),
            {"g:a": 2, "UNKNOWN": 1},
        )
        self.assertEqual(s6_report.summarize_item_coords(None), {})

        with patch.object(s6_report, "_uncertainty_kind", return_value="fallback"):
            self.assertEqual(
                s6_report._uncertainty_kind_for_report(
                    {"uncertainty_kind": s6_report.UNCERTAINTY_KIND_CANDIDATE_EVIDENCE}, {},
                ),
                s6_report.UNCERTAINTY_KIND_CANDIDATE_EVIDENCE,
            )
            self.assertEqual(
                s6_report._uncertainty_kind_for_report({}, {
                    "paths_by_status": {"uncertain": [[1]]},
                }),
                s6_report.UNCERTAINTY_KIND_CANDIDATE_EVIDENCE,
            )
            self.assertEqual(
                s6_report._uncertainty_kind_for_report({}, {
                    "logical_path_counts_by_status": {"uncertain": 2},
                    "path_counts_by_status": {"uncertain": 1},
                }),
                s6_report.UNCERTAINTY_KIND_CANDIDATE_EVIDENCE,
            )
            self.assertEqual(s6_report._uncertainty_kind_for_report({}, {}), "fallback")

        with patch.object(s6_report, "_uncertain_conclusion", return_value="uncertain"):
            self.assertEqual(s6_report._bucket_csv_conclusion("uncertain", {}), "uncertain")
        self.assertEqual(s6_report._bucket_csv_conclusion("confirmed", {}), "已确认影响")
        self.assertEqual(
            s6_report._bucket_csv_conclusion("future", {"user_conclusion": " custom "}),
            "custom",
        )
        self.assertEqual(s6_report._bucket_csv_conclusion("future", {}), "结论未确定")

        with patch.object(s6_report, "_canonical_identity_coord", side_effect=lambda value: str(value or "").lower()):
            findings = {
                "impacted_dependencies": [{"coord": "G:A", "source": "impact"}],
                "per_dependency_results": [{"coord": "G:B", "source": "result"}],
            }
            self.assertEqual(s6_report._dependency_for_item(findings, {"coord": "g:a"})["source"], "impact")
            self.assertEqual(s6_report._dependency_for_item(findings, {"coord": "g:b"})["source"], "result")
            self.assertEqual(s6_report._dependency_for_item(findings, {"coord": "g:c"}), {})
            self.assertEqual(s6_report._dependency_for_item({}, {"coord": "g:c"}), {})

    def test_diagnostic_titles_impacts_context_and_occurrence_matrix(self):
        generic = {"title": "分析诊断", "semantic_impact": "impact"}
        with patch.object(s6_report, "_diagnostic_definition", return_value={"title": "Specific"}):
            self.assertEqual(s6_report._diagnostic_plain_title({"reason_code": "X"}), "Specific")
        with patch.object(s6_report, "_diagnostic_definition", return_value=generic):
            self.assertIn(
                "字节码",
                s6_report._diagnostic_plain_title({"reason_code": "BYTECODE_CALLER_UNRESOLVED"}),
            )
            self.assertEqual(s6_report._diagnostic_plain_title({"reason_code": "UNKNOWN"}), "分析过程记录了证据缺口")
        with patch.object(s6_report, "_diagnostic_definition", return_value={}):
            self.assertEqual(s6_report._diagnostic_plain_title({"reason_code": "UNKNOWN"}), "分析过程记录了证据缺口")

        with patch.object(s6_report, "_diagnostic_definition", return_value={"semantic_impact": "specific"}), patch.object(
            s6_report, "_objective_diagnostic_text", side_effect=lambda value, fallback: value or fallback,
        ):
            self.assertEqual(
                s6_report._diagnostic_objective_impact({
                    "reason_code": "X", "potentially_affected_api_count": 1,
                }),
                "specific",
            )
        telemetry = s6_report._diagnostic_objective_impact({
            "reason_code": "X", "observed_scope": "api",
            "raw_blocking_failure_count": 1, "relevant_blocking_failure_count": 0,
        })
        self.assertIn("不限制本轮 API 结论", telemetry)
        self.assertIn("不改变", s6_report._diagnostic_objective_impact({
            "reason_code": "X", "observed_scope": "api",
            "raw_blocking_failure_count": 0,
        }))
        self.assertIn("不改变", s6_report._diagnostic_objective_impact({
            "reason_code": "X", "observed_scope": "api",
            "raw_blocking_failure_count": 1, "relevant_blocking_failure_count": 1,
        }))
        self.assertIn("未映射", s6_report._diagnostic_objective_impact({
            "reason_code": "BYTECODE_CALLER_UNRESOLVED", "blocking": True,
        }))
        self.assertIn("全局作用域", s6_report._diagnostic_objective_impact({
            "reason_code": "OTHER", "blocking": True, "observed_scope": "global",
        }))
        self.assertIn("对应分析步骤", s6_report._diagnostic_objective_impact({
            "reason_code": "OTHER", "blocking": True, "observed_scope": "step",
        }))
        self.assertIn("不改变", s6_report._diagnostic_objective_impact({"reason_code": "OTHER"}))

        with patch.object(s6_report, "_input_diagnostic_artifact_label", return_value="证据"):
            self.assertEqual(
                s6_report._input_diagnostic_fact_label({"stage": "row_contract"}),
                "证据部分记录无效",
            )
            self.assertEqual(
                s6_report._input_diagnostic_fact_label({"error_type": "FileNotFoundError"}),
                "证据未生成",
            )
            self.assertEqual(
                s6_report._input_diagnostic_fact_label({"error_type": "ArtifactContentError"}),
                "证据结构无效",
            )
            self.assertEqual(s6_report._input_diagnostic_fact_label({}), "证据无法读取")
        self.assertEqual(
            s6_report._input_diagnostic_error_text({"stage": "identity_consistency"}),
            "部分记录的结构或关联关系校验未通过",
        )
        self.assertEqual(
            s6_report._input_diagnostic_error_text({"error_type": "JSONDecodeError"}),
            "JSON 内容无法解析",
        )
        self.assertEqual(s6_report._input_diagnostic_error_text({}), "文件内容无法读取")

        findings = {"context": {
            "jdk": "? → 17", "springboot": "2 → 3", "build_tool": "maven",
        }}
        self.assertEqual(s6_report._known_context_parts(findings), [
            "JDK 目标版本 17（基线版本未记录）", "Spring Boot 2 → 3", "构建工具 maven",
        ])
        self.assertEqual(s6_report._known_context_parts({"context": {
            "jdk": "?", "springboot": "? → ?", "build_tool": "?",
        }}), [])
        self.assertEqual(s6_report._known_context_parts({}), [])
        self.assertEqual(s6_report._known_context_parts({"context": {
            "jdk": "17", "springboot": "", "build_tool": "",
        }}), ["JDK 17"])

        with patch.object(s6_report, "_identity_without_severity", return_value=("id",)):
            lookup = {("id",): {
                "occurrence_counts_by_status": {"reachable": 2, "uncertain": 3},
                "occurrence_count": "7",
            }}
            self.assertEqual(
                s6_report._occurrence_count_for_report(
                    {}, lookup, 1, {"reachable", "uncertain"},
                ),
                5,
            )
            self.assertEqual(s6_report._occurrence_count_for_report({}, lookup, 8), 8)
            self.assertEqual(
                s6_report._occurrence_count_for_report({}, {("id",): {"occurrence_count": "bad"}}, 2),
                2,
            )
            self.assertEqual(
                s6_report._occurrence_count_for_report({}, {}, 0), 0,
            )
            self.assertEqual(
                s6_report._occurrence_count_for_report(
                    {}, {("id",): {"path_counts_by_status": {"reachable": 4}}},
                    0, {"reachable"},
                ),
                4,
            )
            self.assertEqual(
                s6_report._occurrence_count_for_report(
                    {}, {("id",): {}}, 0, {"missing"},
                ),
                0,
            )

    def test_alert_matching_scope_join_and_evidence_shape_matrix(self):
        row = {"changed_symbol": "a.C.m", "api_signature": "(I)V"}
        self.assertFalse(s6_report._alert_target_matches_changed_symbol(None, row))
        self.assertFalse(s6_report._alert_target_matches_changed_symbol("a.C.m", {}))
        self.assertFalse(s6_report._alert_target_matches_changed_symbol("a.C.n", row))
        self.assertTrue(s6_report._alert_target_matches_changed_symbol("变更 API: a.C.m", row))
        with patch.object(s6_report, "signatures_match_identity", return_value=True):
            self.assertTrue(s6_report._alert_target_matches_changed_symbol("a.C.m(int)", row))
        with patch.object(s6_report, "signatures_match_identity", return_value=False):
            self.assertFalse(s6_report._alert_target_matches_changed_symbol("a.C.m(long)", row))
        unsigned_row = {"changed_symbol": "a.C.m"}
        self.assertTrue(s6_report._alert_target_matches_changed_symbol("a.C.m(int)", unsigned_row))
        self.assertFalse(s6_report._alert_target_matches_changed_symbol("a.C.m(", unsigned_row))

        business = {"business_entry": "a.App.run(int)"}
        self.assertFalse(s6_report._alert_path_entry_matches_business_entry(None, business))
        self.assertFalse(s6_report._alert_path_entry_matches_business_entry("a.App.run", {}))
        self.assertFalse(s6_report._alert_path_entry_matches_business_entry("a.Other.run", business))
        self.assertTrue(s6_report._alert_path_entry_matches_business_entry("业务入口: a.App.run", business))
        with patch.object(s6_report, "signatures_match_identity", return_value=True):
            self.assertTrue(s6_report._alert_path_entry_matches_business_entry("a.App.run(int)", business))
        self.assertTrue(s6_report._alert_path_entry_matches_business_entry(
            "a.App.run(int)", {"business_entry": "a.App.run"},
        ))
        self.assertFalse(s6_report._alert_path_entry_matches_business_entry(
            "a.App.run(", {"business_entry": "a.App.run"},
        ))

        self.assertFalse(s6_report._alert_row_has_preserved_bytecode_evidence({}))
        preserved = {
            "evidence_files": "a.csv| |b.csv", "path_text": "A -> a.C.m",
            "changed_symbol": "a.C.m", "chain_detail": "类字节码完全一致",
        }
        self.assertTrue(s6_report._alert_row_has_preserved_bytecode_evidence(preserved))
        self.assertFalse(s6_report._alert_row_has_preserved_bytecode_evidence({
            **preserved, "path_text": "A",
        }))
        self.assertFalse(s6_report._alert_row_has_preserved_bytecode_evidence({
            **preserved, "chain_detail": "ordinary evidence",
        }))
        self.assertFalse(s6_report._alert_row_has_preserved_bytecode_evidence({
            **preserved, "chain_detail": "", "review_reason": "",
        }))
        self.assertFalse(s6_report._alert_row_has_preserved_bytecode_evidence({
            "evidence_files": "a.csv", "path_text": None,
        }))

        self.assertFalse(s6_report._has_uncertain_evidence_items(None))
        self.assertFalse(s6_report._has_uncertain_evidence_items([{}, [[]], [{"x": ""}]]))
        self.assertFalse(s6_report._has_uncertain_evidence_items([{"x": ""}]))
        self.assertFalse(s6_report._has_uncertain_evidence_items([None]))
        self.assertTrue(s6_report._has_uncertain_evidence_items([{"x": 1}]))
        self.assertTrue(s6_report._has_uncertain_evidence_items([[{"x": 1}]]))
        self.assertTrue(s6_report._has_uncertain_evidence_items([["evidence"]]))

        self.assertEqual(s6_report._join_inline([], empty="none"), "none")
        self.assertEqual(s6_report._join_inline([" a ", "", "b", "c"], limit=2), "a<br>b<br>…另 1 项")
        self.assertEqual(s6_report._join_report_links([], empty="none"), "none")
        self.assertEqual(s6_report._join_report_links([None], empty="none"), "none")
        self.assertEqual(s6_report._join_report_links(["a"], limit=2), "[a](../a)")
        self.assertIn("…另 1 项", s6_report._join_report_links(["a", "b", "c"], limit=2))

        self.assertEqual(s6_report._scope_text({
            "analysis_scope": {"validation_status": "invalid"},
        }), "分析范围无法核验，不能按全量分析解释")
        self.assertEqual(s6_report._scope_text({"analysis_scope": {
            "mode": "full", "available_dependency_count": 2,
            "included_dependency_count": 1, "total_api_count": 3,
            "analyzed_api_count": 2,
        }}), "全量分析（变化依赖 1/2，变化 API 2/3）")
        self.assertEqual(s6_report._scope_text({"analysis_scope": {"mode": "partial"}}), "部分分析")
        self.assertIn("范围快照缺失", s6_report._scope_text({}))

        with patch.object(s6_report, "_canonical_identity_coord", side_effect=lambda value: str(value or "").strip().lower()):
            self.assertIsNone(s6_report._report_scope_included_coords({}))
            self.assertIsNone(s6_report._report_scope_included_coords({
                "analysis_scope": {"mode": "partial", "validation_status": "invalid"},
            }))
            self.assertEqual(s6_report._report_scope_included_coords({
                "analysis_scope": {"mode": "partial", "included_dependency_coords": [], "included_dependency_count": 0},
            }), set())
            self.assertIsNone(s6_report._report_scope_included_coords({
                "analysis_scope": {"mode": "partial", "included_dependency_coords": ["G:A"], "included_dependency_count": 2},
            }))
            self.assertEqual(s6_report._report_scope_included_coords({
                "analysis_scope": {"mode": "partial", "included_dependency_coords": ["G:A", ""], "included_dependency_count": 1},
            }), {"g:a"})

    def test_scalar_label_rank_count_and_version_contract_matrix(self):
        self.assertEqual(
            [s6_report._bucket_rank(value) for value in (
                "confirmed", "review", "not_impacted", "not_found", None, "other",
            )],
            [0, 1, 2, 3, 4, 9],
        )
        self.assertEqual(s6_report._coverage_status_label("complete"), "完整")
        self.assertEqual(s6_report._coverage_status_label(None), "未记录")
        self.assertEqual(s6_report._coverage_status_label("new"), "未记录")
        self.assertEqual(s6_report._diagnostic_scope_label("api"), "单个 API")
        self.assertEqual(s6_report._diagnostic_scope_label(None), "未记录")
        self.assertEqual(s6_report._diagnostic_reason_code(" VALID_1 "), "VALID_1")
        self.assertEqual(s6_report._diagnostic_reason_code("bad-code"), "UNKNOWN")
        self.assertEqual(s6_report._diagnostic_reason_code(None), "UNKNOWN")
        self.assertEqual(s6_report._percentage(1, 4), "25.0%")
        self.assertEqual(s6_report._percentage(1, 0), "0.0%")
        self.assertEqual(
            [s6_report._severity_rank(value) for value in ("p0", " P1 ", "P2", None, "P9")],
            [0, 1, 2, 3, 3],
        )
        for value, expected in (
            (0, 0), (4, 4), (-1, None), (True, None), (1.0, None), (None, None),
        ):
            with self.subTest(non_negative=value):
                self.assertEqual(s6_report._strict_non_negative_int(value), expected)

        self.assertEqual(s6_report._strip_changed_api_marker("变更API: a.b.C.m"), "a.b.C.m")
        self.assertEqual(s6_report._strip_changed_api_marker("a.b.C.m"), "a.b.C.m")
        self.assertEqual(s6_report._strip_changed_api_marker(None), "")
        self.assertEqual(s6_report._call_chain_status_label(" done "), "已完成")
        self.assertEqual(s6_report._call_chain_status_label(""), "未知")
        self.assertEqual(s6_report._call_chain_status_label("   "), "未知")
        self.assertEqual(s6_report._call_chain_status_label("future"), "未知")
        self.assertEqual(s6_report._diagnostic_origin_label("step_4"), "Step 4")
        self.assertEqual(s6_report._diagnostic_origin_label("STEP-6"), "Step 6")
        self.assertEqual(s6_report._diagnostic_origin_label(None), "未记录")
        self.assertEqual(s6_report._diagnostic_origin_label("unknown"), "未记录")
        self.assertEqual(s6_report._diagnostic_origin_label("component"), "未记录")
        self.assertEqual(s6_report._valid_origin_step(" STEP4 ", "step2"), "step4")
        self.assertEqual(s6_report._valid_origin_step("bad", " STEP2 "), "step2")
        self.assertEqual(s6_report._valid_origin_step(None, "bad"), "")
        self.assertEqual(s6_report._valid_origin_step(None, None), "")

        self.assertEqual(s6_report._version_transition({}), "")
        self.assertEqual(
            s6_report._version_transition({"old_version": "-", "new_version": "2"}),
            "未引入 → 2",
        )
        self.assertEqual(
            s6_report._version_transition({"old_version": "1", "new_version": "-"}),
            "1 → 已移除",
        )
        self.assertEqual(
            s6_report._version_transition({"old_version": "", "new_version": "2"}),
            "未记录 → 2",
        )
        self.assertEqual(
            s6_report._version_transition({"old_version": "1", "new_version": ""}),
            "1 → 未记录",
        )
        self.assertEqual(
            s6_report._dependency_change_type({"change_type": "MAJOR"}),
            "大版本升级",
        )
        self.assertEqual(
            s6_report._dependency_change_type({"change_type": "custom"}),
            "custom",
        )
        self.assertEqual(s6_report._dependency_change_type({"old_version": "-"}), "新增")
        self.assertEqual(s6_report._dependency_change_type({"new_version": "-"}), "移除")
        self.assertEqual(s6_report._dependency_change_type({}), "版本变化")

        for change, kind, expected in (
            ("REMOVED", "method", "删除方法"),
            ("THING_REMOVED", "field", "删除字段"),
            ("THING_ADDED", "class", "新增类"),
            ("THING_CHANGED", "method", "修改方法"),
            ("THING_MODIFIED", "field", "修改字段"),
            ("custom_value", "", "Custom value"),
            (None, "class", "类变化"),
        ):
            with self.subTest(change=change, kind=kind):
                self.assertEqual(
                    s6_report._human_change_type(change, kind), expected,
                )

    def test_conclusion_impact_and_result_order_contract_matrix(self):
        self.assertEqual(
            s6_report._analysis_conclusion_label({"conclusion": "已确认影响"}),
            "确认有影响",
        )
        self.assertEqual(s6_report._analysis_conclusion_label({}), "未完成分析")
        self.assertEqual(
            s6_report._analysis_conclusion_label({"conclusion": "future"}),
            "future",
        )
        with patch.object(s6_report, "_report_result_sort_key", return_value=("key",)):
            self.assertEqual(
                s6_report._api_result_priority({"conclusion": "已确认影响"}),
                (0, ("key",)),
            )
            self.assertEqual(
                s6_report._api_result_priority({"conclusion": "future"}),
                (9, ("key",)),
            )
            self.assertEqual(s6_report._api_result_priority(None), (9, ("key",)))

        self.assertEqual(s6_report._api_result_rank({"conclusion": "已确认影响"}), 0)
        self.assertEqual(s6_report._api_result_rank({"conclusion": "已确认不受影响"}), 2)
        with patch.object(s6_report, "_api_result_is_incomplete", return_value=True):
            self.assertEqual(s6_report._api_result_rank({"conclusion": "other"}), 3)
        with patch.object(s6_report, "_api_result_is_incomplete", return_value=False):
            self.assertEqual(s6_report._api_result_rank({"conclusion": "other"}), 1)
            self.assertEqual(s6_report._api_result_rank(None), 1)

        for row, expected in (
            ({"path_status": "reachable"}, "confirmed"),
            ({"api_status": "not_impacted"}, "not_impacted"),
            ({"path_status": "uncertain"}, "review"),
            ({"path_status": "not_analyzed"}, "review"),
            ({"path_status": "not_found_in_static_analysis"}, "not_found"),
            ({"path_status": "not_reachable"}, "not_found"),
            ({}, "unknown"),
        ):
            with self.subTest(impact=row):
                self.assertEqual(s6_report._impact_bucket(row), expected)

        with patch.object(s6_report, "_uncertain_conclusion", return_value="candidate"):
            self.assertEqual(
                s6_report._conclusion_for_report(
                    {}, s6_report.UNCERTAIN_CANDIDATE_CONCLUSION,
                ),
                "candidate",
            )
        self.assertEqual(s6_report._conclusion_for_report({}, "已确认影响"), "已确认影响")
        self.assertEqual(
            s6_report._conclusion_for_report({"user_conclusion": "可能影响"}, ""),
            s6_report._display_label("可能影响"),
        )
        self.assertEqual(s6_report._conclusion_for_report({}, ""), "")

    def test_identity_scope_population_and_summary_contract_matrix(self):
        with patch.object(s6_report, "_canonical_identity_signature", return_value="(I)V"), patch.object(
            s6_report, "signatures_match_identity", return_value=True,
        ):
            self.assertEqual(
                s6_report._canonical_identity_api("a.C.m(int)", "(I)V"),
                "a.C.m",
            )
        with patch.object(s6_report, "_canonical_identity_signature", return_value="(I)V"), patch.object(
            s6_report, "signatures_match_identity", return_value=False,
        ):
            self.assertEqual(
                s6_report._canonical_identity_api("a.C.m(long)", "(I)V"),
                "a.C.m(long)",
            )
        with patch.object(s6_report, "_canonical_identity_signature", return_value=""):
            self.assertEqual(s6_report._canonical_identity_api(None, None), "")
        with patch.object(s6_report, "_canonical_identity_signature", return_value="(I)V"):
            self.assertEqual(s6_report._canonical_identity_api("a.C.field", "(I)V"), "a.C.field")
            self.assertEqual(s6_report._canonical_identity_api("a.C.m(", "(I)V"), "a.C.m(")

        logical = ("coord", "api", "sig", "kind", "change")
        with patch.object(s6_report, "build_logical_api_identity_key", return_value=logical):
            self.assertEqual(s6_report.build_api_identity_key({}), logical)
            self.assertEqual(
                s6_report.build_api_identity_key({"change_fact_identity": " fact "}),
                (*logical, "fact"),
            )
        with patch.object(s6_report, "_canonical_identity_signature", return_value="sig"), patch.object(
            s6_report, "_canonical_identity_coord", return_value="coord",
        ), patch.object(s6_report, "_canonical_identity_api", return_value="api"):
            self.assertEqual(
                s6_report._canonical_report_identity({
                    "api": "fallback", "symbol_kind": " method ",
                    "change_type": " removed ",
                }),
                ("coord", "api", "sig", "method", "removed"),
            )
            self.assertEqual(
                s6_report._canonical_report_identity(None),
                ("coord", "api", "sig", "", ""),
            )

        identity_fields = s6_report._step5_result_identity_fields({
            "api_identity": " api ", "reported_api_identity": None,
            "change_fact_identity": 7, "decision_identity": " decision ",
        })
        self.assertEqual(identity_fields, {
            "api_identity": "api", "reported_api_identity": "",
            "change_fact_identity": "7", "decision_identity": "decision",
        })
        self.assertEqual(
            s6_report._step5_result_identity_fields(None),
            {field: "" for field in identity_fields},
        )

        with patch.object(s6_report, "build_api_identity_key", side_effect=lambda item: (item["id"],)):
            rows = s6_report._summary_result_identity_rows({
                "reachable_apis": [{"id": "a"}, None],
                "not_impacted_apis": [{"id": "b"}],
                "uncertain_apis": [{"id": "c"}],
                "not_analyzed_apis": [{"id": "d"}],
                "not_found_apis": [{"id": "e"}],
            })
        self.assertEqual(rows, [
            (("a",), "confirmed"), (("b",), "not_impacted"),
            (("c",), "review"), (("d",), "review"), (("e",), "not_found"),
        ])
        self.assertEqual(s6_report._summary_result_identity_rows(None), [])

        self.assertTrue(s6_report._report_scope_is_verified({
            "analysis_scope": {"mode": "full", "validation_status": "valid"},
        }))
        self.assertTrue(s6_report._report_scope_is_verified({
            "analysis_scope": {"mode": "partial"},
        }))
        self.assertFalse(s6_report._report_scope_is_verified({
            "analysis_scope": {"mode": "full", "validation_status": "invalid"},
        }))
        self.assertFalse(s6_report._report_scope_is_verified({}))
        with patch.object(s6_report, "_canonical_identity_coord", side_effect=lambda value: str(value or "").strip().lower()):
            self.assertEqual(
                s6_report._scope_excluded_coords({
                    "analysis_scope": {"excluded_dependency_coords": [" G:A ", "", None]},
                }),
                {"g:a"},
            )
        self.assertEqual(s6_report._scope_excluded_coords({}), set())

        self.assertEqual(
            s6_report._effective_coverage_status({"coverage": {"overall_status": "complete"}}),
            "complete",
        )
        self.assertEqual(
            s6_report._effective_coverage_status({
                "coverage": {"overall_status": "not_applicable"},
                "diagnostics": [{}],
            }),
            "partial",
        )
        self.assertEqual(s6_report._effective_coverage_status({}), "unknown")
        self.assertEqual(
            s6_report._effective_coverage_status({
                "coverage": {"overall_status": "partial"},
                "diagnostics": [{}],
            }),
            "partial",
        )

        findings = {
            "not_analyzed": [
                {"id": "keep", "user_conclusion": "other"},
                {"id": "candidate", "user_conclusion": "可能影响"},
                {"id": "input", "user_conclusion": "需要补充输入"},
            ],
            "probable_impact": [{}], "uncertain": [{}, {}],
            "needs_input": [{}], "p0": [{"id": 0}], "p1": [{"id": 1}],
            "p2": [{"id": 2}],
        }
        self.assertEqual([item["id"] for item in s6_report._exclusive_not_analyzed(findings)], ["keep"])
        self.assertEqual(s6_report._unresolved_count(findings), 5)
        self.assertEqual(
            [item["id"] for item in s6_report._confirmed_items(findings)],
            [0, 1, 2],
        )
        self.assertEqual(s6_report._confirmed_items({}), [])
        self.assertEqual(s6_report._exclusive_not_analyzed({}), [])
        self.assertEqual(s6_report._unresolved_count({}), 0)

    def test_diagnostic_and_coverage_component_contract_matrix(self):
        diagnostics = [
            {},
            {"artifact": "changed_apis", "stage": None},
            {"artifact": "changed_apis", "stage": "csv_missing"},
            {"artifact": "other", "stage": "csv_load"},
            {"artifact": "changed_apis", "stage": "warning"},
        ]
        self.assertTrue(s6_report._artifact_has_diagnostic(diagnostics, "changed_apis"))
        self.assertFalse(s6_report._artifact_has_diagnostic(diagnostics, "absent"))
        self.assertFalse(s6_report._artifact_has_diagnostic(None, "absent"))
        self.assertTrue(
            s6_report._artifact_has_fatal_csv_diagnostic(diagnostics, "changed_apis")
        )
        self.assertFalse(
            s6_report._artifact_has_fatal_csv_diagnostic(diagnostics, "other-missing")
        )
        self.assertFalse(s6_report._artifact_has_fatal_csv_diagnostic([], "other"))
        self.assertTrue(s6_report._changed_api_diagnostic_invalidates_scope(diagnostics))
        self.assertFalse(s6_report._changed_api_diagnostic_invalidates_scope([
            {"artifact": "changed_apis", "stage": "warning"},
        ]))
        self.assertFalse(s6_report._changed_api_diagnostic_invalidates_scope(None))
        self.assertFalse(s6_report._changed_api_diagnostic_invalidates_scope([{}]))

        coverage = {"components": [
            {"id": "project_scope", "status": "complete"},
            {"id": ""}, {},
        ]}
        self.assertEqual(
            s6_report._coverage_component_lookup(coverage),
            {"project_scope": coverage["components"][0]},
        )
        self.assertEqual(s6_report._coverage_component_lookup({}), {})
        self.assertEqual(s6_report._coverage_item_label("project_scope"), "分析范围")
        self.assertEqual(
            s6_report._coverage_item_label("framework_adapter:spring"),
            "框架适配器",
        )
        self.assertEqual(s6_report._coverage_item_label("future"), "其他覆盖组件")
        self.assertEqual(s6_report._coverage_item_label(None), "其他覆盖组件")

        self.assertIn(
            "依赖坐标未解析",
            s6_report._coverage_impact_text(
                "dependency_diff", ["dependency_coordinates_unresolved"],
            ),
        )
        self.assertIn(
            "分析范围不完整",
            s6_report._coverage_impact_text("project_scope", []),
        )
        self.assertIn(
            "适用范围受到限制",
            s6_report._coverage_impact_text("future", None),
        )
        self.assertIn(
            "适用范围受到限制",
            s6_report._coverage_impact_text(None, ["UNKNOWN_REASON"]),
        )

    def test_call_path_evidence_markdown_and_display_contract_matrix(self):
        self.assertEqual(s6_report._call_path_shape(None), ((), ()))
        self.assertEqual(
            s6_report._call_path_shape(" A.m (int) -> B.n → C "),
            (("A.m", "B.n", "C"), ("(int)", None, None)),
        )
        self.assertEqual(
            s6_report._call_path_shape("A ->  -> B"),
            (("A", "B"), (None, None)),
        )
        self.assertEqual(s6_report._distinct_call_path_count(None), 0)
        self.assertEqual(s6_report._distinct_call_path_count([""]), 0)
        with patch.object(s6_report, "_minimum_compatible_variant_groups", return_value=0):
            self.assertEqual(s6_report._distinct_call_path_count(["A -> B"]), 1)
        with patch.object(s6_report, "_minimum_compatible_variant_groups", return_value=2):
            self.assertEqual(s6_report._distinct_call_path_count(["A -> B", "A -> B"]), 2)

        self.assertEqual(s6_report._normalize_evidence_paths(None), ([], True))
        self.assertEqual(s6_report._normalize_evidence_paths("invalid"), ([], False))
        normalized, valid = s6_report._normalize_evidence_paths([
            [{"from": "A", "to": "B"}],
            [],
            ["bad", {"from": "C", "to": "D"}],
            "bad-path",
        ])
        self.assertEqual(normalized, [
            [{"from": "A", "to": "B"}],
            [{"from": "C", "to": "D"}],
        ])
        self.assertFalse(valid)
        self.assertEqual(s6_report._normalize_evidence_paths([[]]), ([], True))
        self.assertEqual(s6_report._normalize_evidence_paths([["bad"]]), ([], False))

        self.assertEqual(s6_report._split_csv_chain_nodes(None), [])
        self.assertEqual(s6_report._split_csv_chain_nodes("A"), ["A"])
        self.assertEqual(s6_report._split_csv_chain_nodes(" -> "), ["->"])
        self.assertEqual(s6_report._split_csv_chain_nodes("A → B -> C"), ["A", "B", "C"])
        self.assertEqual(s6_report._short_path(None), "")
        self.assertEqual(s6_report._short_path("/a/b/c/d/e", parts=3), "c/d/e")
        self.assertEqual(s6_report._short_path("single", parts=0), "single")

        self.assertEqual(s6_report._display_label(None), "")
        with patch.dict(s6_report.DISPLAY_LABELS, {"raw": "显示"}, clear=False):
            self.assertEqual(
                s6_report._display_label(" raw ；； raw ； other "),
                "显示；other",
            )
        self.assertEqual(s6_report._human_signature(None), "")
        self.assertEqual(s6_report._human_signature("()"), "无参数")
        self.assertEqual(
            s6_report._human_signature("`(java.lang.String, java.util.List$Node,)`"),
            "String, List.Node",
        )
        self.assertEqual(s6_report._human_signature("(,,)"), "无参数")
        self.assertEqual(s6_report._human_signature("int"), "int")
        self.assertEqual(s6_report._human_signature("(int"), "(int")

        self.assertEqual(s6_report._markdown_heading_fragment("## Hello, World!"), "hello-world")
        self.assertEqual(s6_report._markdown_heading_fragment("### `API_Name`"), "api_name")
        self.assertEqual(s6_report._markdown_heading_fragment(None), "")
        self.assertEqual(s6_report._report_link(None), "-")
        self.assertEqual(
            s6_report._report_link("deliverables/details.md", "详情"),
            "[详情](details.md)",
        )
        self.assertEqual(
            s6_report._report_link("evidence/a.md"),
            "[evidence/a.md](../evidence/a.md)",
        )
        absolute = str(Path("/tmp/a.md"))
        self.assertEqual(s6_report._report_link(absolute), f"[{absolute}]({absolute})")

        self.assertEqual(s6_report._csv_text(" `a\\|b`<br>c "), "a|b\nc")
        self.assertEqual(s6_report._csv_text(None), "")
        self.assertEqual(s6_report._csv_cell(["a", 2]), "a | 2")
        self.assertEqual(s6_report._csv_cell(("a",)), "a")
        self.assertEqual(s6_report._csv_cell(None), "")
        self.assertEqual(s6_report._csv_cell("value"), "value")
        self.assertEqual(s6_report._md_cell("a|b\nc", limit=20), "a\\|b c")
        self.assertEqual(s6_report._md_cell("abcdef", limit=3), "abc…")
        self.assertEqual(s6_report._md_cell(None), "")
        self.assertEqual(s6_report._full_md_cell("a|b\nc"), "a\\|b c")
        self.assertEqual(s6_report._full_md_cell(None), "")
        self.assertEqual(s6_report._count_label("API", "总数"), "API 总数")
        self.assertEqual(s6_report._count_label("依赖", "总数"), "依赖总数")
        self.assertEqual(s6_report._count_label(None, "总数"), "None总数")

        verified = {"total_count": 3, "scope_verified": True, "population_unconfirmed": False}
        self.assertIn("3/3", s6_report._main_report_range(verified, "API", 2))
        self.assertIn(
            "总数无法确认",
            s6_report._main_report_range(
                {**verified, "population_unconfirmed": True}, "API", 2,
            ),
        )
        self.assertIn(
            "分析范围无法核验",
            s6_report._main_report_range(
                {**verified, "scope_verified": False}, "依赖", 2,
            ),
        )
        self.assertIn(
            "0/0",
            s6_report._main_report_range(
                {"scope_verified": True, "population_unconfirmed": False},
                "API", 0,
            ),
        )

    def test_explicit_total_and_bucket_fallback_count_contract(self):
        self.assertEqual(s6_report._call_summary_target_count({"total_apis": 4}), 4)
        self.assertEqual(s6_report._call_summary_target_count({"total_apis": 0}), 0)
        self.assertEqual(s6_report._call_summary_target_count({"total_apis": -2}), 0)
        self.assertEqual(s6_report._call_summary_target_count({"total_apis": "bad"}), 0)
        with patch.object(s6_report, "build_api_identity_key", side_effect=lambda item: (item["id"],)):
            self.assertEqual(
                s6_report._call_summary_target_count({
                    "reachable_apis": [{"id": "a"}, {"id": "a"}, None],
                    "uncertain_apis": [{"id": "b"}],
                }),
                2,
            )
        self.assertEqual(s6_report._call_summary_target_count(None), 0)


if __name__ == "__main__":
    unittest.main()
