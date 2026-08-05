import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import confidence_weighted_tracer as tracer  # noqa: E402
import enhanced_output_formatter as formatter  # noqa: E402
import s6_report  # noqa: E402
from reason_guidance import (  # noqa: E402
    REASON_GUIDANCE_SCHEMA,
    build_catalog_guidance,
    build_diagnostic_guidance,
    build_diagnostic_guidance_from_summary,
    guidance_for_reason_code,
)


class ReasonGuidanceTest(unittest.TestCase):
    @staticmethod
    def _render_diagnostic_detail(findings):
        rendered = s6_report.render_diagnostic_detail_artifact(findings)
        if isinstance(rendered, str):
            return rendered
        return "\n".join(rendered)

    @staticmethod
    def _result(reason_code, api_name):
        return tracer.TraceResult(
            coord="com.acme:demo",
            api_name=api_name,
            api_simple=api_name.rsplit(".", 1)[-1],
            api_signature="()",
            symbol_kind="method",
            change_type="REMOVED",
            severity="P1",
            confirmed=True,
            source="japicmp",
            analysis_scope="method",
            analysis_status="not_analyzed",
            direct_callers=0,
            is_reachable=None,
            reachable_note="框架证据不完整",
            business_reach_depth=0,
            dependency_chain_coords=[],
            call_paths=[],
            evidence_paths=[],
            reason_code=reason_code,
            verification_commands=[],
            hops=[],
            confidence_score=0.0,
            critical_nodes_hit=[],
        )

    @staticmethod
    def _graph_stats():
        occurrence_fields = [
            "caller_symbol",
            "caller_qualified_key",
            "artifact",
            "artifact_entry",
            "class_name",
            "line",
            "instruction_offset",
            "detail",
        ]
        spring_detail = {
            "reason_code": "SPRING_RUNTIME_CLASS_AMBIGUOUS",
            "class_name": "demo.Config",
            "candidates": [
                {
                    "artifact_path": "/runtime/a.jar",
                    "artifact_entry": "BOOT-INF/lib/a.jar!/demo/Config.class",
                    "coord": "com.acme:a",
                    "bytecode_sha256": "a" * 64,
                },
                {
                    "artifact_path": "/runtime/b.jar",
                    "artifact_entry": "BOOT-INF/lib/b.jar!/demo/Config.class",
                    "coord": "com.acme:b",
                    "bytecode_sha256": "b" * 64,
                },
            ],
        }
        return {
            "evidence_ingestion": {
                "failure_occurrence_fields": occurrence_fields,
                "failures": [
                    {
                        "collector": "spring_aop_activation",
                        "reason_code": "SPRING_RUNTIME_CLASS_AMBIGUOUS",
                        "blocking": True,
                        "artifact": "/runtime/a.jar",
                        "class_name": "demo.Config",
                        "detail": json.dumps(spring_detail, ensure_ascii=False),
                        "scope": "path",
                        "occurrences": [
                            (
                                "",
                                "",
                                "/runtime/a.jar",
                                "BOOT-INF/lib/a.jar!/demo/Config.class",
                                "demo.Config",
                                0,
                                -1,
                                "candidate",
                            ),
                            (
                                "",
                                "",
                                "/runtime/b.jar",
                                "BOOT-INF/lib/b.jar!/demo/Config.class",
                                "demo.Config",
                                0,
                                -1,
                                "candidate",
                            ),
                        ],
                    },
                    {
                        "collector": "mybatis_mapper_proxy",
                        "reason_code": "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED",
                        "blocking": True,
                        "artifact": "/runtime/mybatis-runtime.jar",
                        "class_name": "",
                        "detail": (
                            "/runtime/mybatis-runtime.jar:"
                            "mybatis_runtime_artifact_parse_failed:"
                            "mybatis_runtime:BadZipFile"
                        ),
                        "scope": "global",
                        "occurrences": [],
                    },
                ],
            }
        }

    def test_exact_guidance_explains_trigger_decision_and_ignore_boundary(self):
        spring = guidance_for_reason_code("SPRING_PACKAGED_CLASS_AMBIGUOUS")
        mybatis = guidance_for_reason_code(
            "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED"
        )

        self.assertEqual("exact", spring["catalog_match"])
        self.assertEqual("legacy_alias", spring["matched_via"])
        self.assertEqual(
            "SPRING_RUNTIME_CLASS_AMBIGUOUS", spring["reason_code"]
        )
        self.assertIn("BOOT-INF/classpath.idx", spring["trigger_condition"])
        self.assertIn("无关 API", spring["semantic_impact"])
        self.assertIn("受影响 API", spring["decision_text"])
        self.assertIn("MyBatis", mybatis["title"])
        self.assertIn("ZIP", mybatis["trigger_condition"])
        self.assertIn("不使用 MyBatis", mybatis["decision_text"])
        self.assertTrue(mybatis["repair_actions"])
        self.assertTrue(mybatis["verification_steps"])

    def test_family_fallback_keeps_future_parse_failures_self_explanatory(self):
        guidance = guidance_for_reason_code("FUTURE_ADAPTER_PARSE_FAILED")

        self.assertEqual("family_fallback", guidance["catalog_match"])
        self.assertEqual("artifact_parse", guidance["category"])
        self.assertIn("解析", guidance["trigger_condition"])
        self.assertTrue(guidance["repair_actions"])

    def test_cross_step_catalog_uses_one_vocabulary_and_origin_field(self):
        step1 = guidance_for_reason_code(
            "unresolved_dependency_coordinates_after_enrichment"
        )
        step4 = guidance_for_reason_code("DEPENDENCY_SOURCE_REF_UNAVAILABLE")
        japicmp = guidance_for_reason_code("JAPICMP_EXECUTION_FAILED")
        timeout = guidance_for_reason_code("JAPICMP_TIMEOUT")
        coverage_guidance = build_catalog_guidance(
            ["DEPENDENCY_SOURCE_REF_UNAVAILABLE"],
            origin_step="step4",
            source_components=["behavior_diff"],
        )

        self.assertEqual(
            "DEPENDENCY_COORDINATES_UNRESOLVED", step1["reason_code"]
        )
        self.assertEqual("step1", step1["origin_step"])
        self.assertEqual("step4", step4["origin_step"])
        self.assertEqual("source_ref", step4["subject"])
        self.assertEqual("step4", japicmp["origin_step"])
        self.assertTrue(japicmp["default_blocking"])
        self.assertIn("all_changed_apis.csv", japicmp["semantic_impact"])
        self.assertIn("step4_workers", timeout["repair_actions"][0])
        self.assertEqual(1, len(coverage_guidance))
        self.assertEqual(
            ["behavior_diff"], coverage_guidance[0]["source_components"]
        )

    def test_final_report_summarizes_step4_guidance_and_detail_keeps_protocol(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            coverage_path = report_dir / ".runtime" / "coverage" / "coverage.json"
            coverage_path.parent.mkdir(parents=True)
            coverage_path.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.coverage.v1",
                "overall_status": "partial",
                "critical_incomplete": ["behavior_diff"],
                "components": [{
                    "id": "behavior_diff",
                    "status": "partial",
                    "reason_codes": ["DEPENDENCY_SOURCE_REF_UNAVAILABLE"],
                }],
            }), encoding="utf-8")

            findings = s6_report.collect_findings(str(report_dir))
            diagnostic_path = (
                s6_report.write_diagnostic_detail_artifact(
                    report_dir, findings
                )
            )
            self.assertEqual(
                "deliverables/analysis-diagnostics.md",
                diagnostic_path,
            )
            findings.setdefault("artifacts", {})["diagnostic_detail_md"] = (
                diagnostic_path
            )
            report = s6_report.generate_report(findings)
            diagnostic_detail = (
                report_dir / diagnostic_path
            ).read_text(encoding="utf-8")

        by_code = {
            item["reason_code"]: item
            for item in findings["diagnostic_guidance"]
        }
        self.assertEqual(
            "step4",
            by_code["DEPENDENCY_SOURCE_REF_UNAVAILABLE"]["origin_step"],
        )
        self.assertIn(
            "[分析异常记录](analysis-diagnostics.md)",
            report,
        )
        self.assertNotIn("依赖源码版本不可用", report)
        self.assertNotIn("DEPENDENCY_SOURCE_REF_UNAVAILABLE", report)
        self.assertNotIn("来源步骤", report)
        self.assertNotIn("origin_step", report)
        self.assertNotIn(".runtime/", report)
        for non_objective_instruction in (
            "下一步复核顺序",
            "完成标准",
            "待办",
            "建议",
            "修复动作",
            "触发条件",
            "可忽略条件",
            "不替使用者决定",
        ):
            self.assertNotIn(non_objective_instruction, report)
        self.assertIn(
            "DEPENDENCY_SOURCE_REF_UNAVAILABLE", diagnostic_detail
        )
        self.assertIn("Step 4", diagnostic_detail)
        self.assertNotIn("可忽略条件", diagnostic_detail)
        self.assertNotIn("修复动作", diagnostic_detail)
        self.assertNotIn("完成标准", diagnostic_detail)

    def test_old_summary_can_be_upgraded_without_reading_collector_source(self):
        guidance = build_diagnostic_guidance_from_summary({
            "not_analyzed_apis": [{
                "analysis_status": "not_analyzed",
                "reason_code": "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED",
                "coord": "com.acme:demo",
                "api": "demo.Api.call",
                "api_signature": "()",
                "symbol_kind": "method",
            }],
        })

        self.assertEqual(1, len(guidance))
        self.assertEqual("exact", guidance[0]["catalog_match"])
        self.assertIn("MyBatis", guidance[0]["trigger_condition"])
        self.assertEqual(1, guidance[0]["affected_api_count"])

    def test_generic_step5_diagnostic_has_a_concrete_origin(self):
        guidance = build_diagnostic_guidance([
            self._result(
                "BYTECODE_CALLER_UNRESOLVED",
                "demo.Api.bytecode",
            )
        ])

        self.assertEqual(1, len(guidance))
        self.assertEqual(
            "BYTECODE_CALLER_UNRESOLVED",
            guidance[0]["reason_code"],
        )
        self.assertEqual("step5", guidance[0]["origin_step"])

    def test_old_unknown_item_origin_inherits_summary_origin(self):
        guidance = build_diagnostic_guidance_from_summary({
            "origin_step": "step5",
            "not_analyzed_apis": [{
                "analysis_status": "not_analyzed",
                "reason_code": "BYTECODE_CALLER_UNRESOLVED",
                "origin_step": "unknown",
                "coord": "com.acme:demo",
                "api": "demo.Api.bytecode",
                "api_signature": "()",
                "symbol_kind": "method",
            }],
        })

        self.assertEqual(1, len(guidance))
        self.assertEqual("step5", guidance[0]["origin_step"])

    def test_aggregation_reports_actual_failure_scope_and_evidence(self):
        results = [
            self._result(
                "SPRING_RUNTIME_CLASS_AMBIGUOUS", "demo.Api.spring"
            ),
            self._result(
                "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED", "demo.Api.mybatis"
            ),
        ]

        guidance = build_diagnostic_guidance(results, self._graph_stats())
        by_code = {item["reason_code"]: item for item in guidance}

        spring = by_code["SPRING_RUNTIME_CLASS_AMBIGUOUS"]
        self.assertTrue(spring["blocking"])
        self.assertEqual("path", spring["observed_scope"])
        self.assertEqual(1, spring["affected_api_count"])
        self.assertEqual(1, spring["primary_reason_api_count"])
        self.assertEqual(2, spring["failure_occurrence_count"])
        self.assertEqual(["demo.Config"], spring["affected_classes"])
        self.assertEqual(
            ["/runtime/a.jar", "/runtime/b.jar"],
            spring["affected_artifacts"],
        )
        self.assertEqual(2, len(spring["candidate_evidence"]))
        self.assertEqual(
            "a" * 64, spring["candidate_evidence"][0]["bytecode_sha256"]
        )
        self.assertIn("相关类或采集器", spring["scope_explanation"])

        mybatis = by_code["MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED"]
        self.assertEqual("global", mybatis["observed_scope"])
        self.assertEqual(2, mybatis["potentially_affected_api_count"])
        self.assertEqual(1, mybatis["primary_reason_api_count"])
        self.assertIn("全局阻断", mybatis["scope_explanation"])
        self.assertEqual(
            ["/runtime/mybatis-runtime.jar"],
            mybatis["affected_artifacts"],
        )
        self.assertIn(
            "BadZipFile", mybatis["failure_detail_summaries"][0]
        )

    def test_unrelated_api_scoped_bytecode_failure_is_coverage_telemetry(self):
        results = [self._result("NO_PATH_FOUND", "demo.Api.selected")]
        graph_stats = {
            "evidence_ingestion": {
                "failures": [
                    {
                        "collector": "business_bytecode",
                        "reason_code": "BYTECODE_CALLER_UNRESOLVED",
                        "blocking": True,
                        "api_identity": f"demo.Other{index}.call()",
                        "scope": "api",
                        "occurrences": [],
                    }
                    for index in range(2309)
                ],
            },
        }

        guidance = build_diagnostic_guidance(results, graph_stats)
        bytecode = next(
            item for item in guidance
            if item["reason_code"] == "BYTECODE_CALLER_UNRESOLVED"
        )
        rendered = "\n".join(s6_report.render_diagnostic_guidance({
            "diagnostic_guidance": [bytecode],
        }))

        self.assertEqual("api", bytecode["observed_scope"])
        self.assertEqual(0, bytecode["affected_api_count"])
        self.assertEqual(0, bytecode["primary_reason_api_count"])
        self.assertEqual(2309, bytecode["failure_record_count"])
        self.assertEqual(0, bytecode["failure_occurrence_count"])
        self.assertEqual(2309, bytecode["raw_blocking_failure_count"])
        self.assertEqual(0, bytecode["relevant_blocking_failure_count"])
        self.assertFalse(bytecode["blocking"])
        self.assertIn("未关联到本轮目标 API", rendered)
        self.assertIn("仅作为覆盖遥测保留", rendered)

    def test_api_scoped_bytecode_failure_counts_matching_target(self):
        results = [self._result("NO_PATH_FOUND", "demo.Api.selected")]
        graph_stats = {
            "evidence_ingestion": {
                "failures": [{
                    "collector": "business_bytecode",
                    "reason_code": "BYTECODE_CALLER_UNRESOLVED",
                    "blocking": True,
                    "api_identity": "demo.Api.selected()",
                    "scope": "api",
                    "occurrences": [],
                }],
            },
        }

        guidance = build_diagnostic_guidance(results, graph_stats)
        bytecode = next(
            item for item in guidance
            if item["reason_code"] == "BYTECODE_CALLER_UNRESOLVED"
        )

        self.assertEqual(1, bytecode["affected_api_count"])
        self.assertEqual(0, bytecode["primary_reason_api_count"])
        self.assertEqual(1, bytecode["potentially_affected_api_count"])
        self.assertEqual(1, bytecode["relevant_blocking_failure_count"])
        self.assertTrue(bytecode["blocking"])

    def test_summary_keeps_structured_guidance_while_report_stays_human_first(self):
        results = [
            self._result(
                "SPRING_RUNTIME_CLASS_AMBIGUOUS", "demo.Api.spring"
            ),
            self._result(
                "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED", "demo.Api.mybatis"
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            output = report_dir / "evidence" / "call_chain"
            output.mkdir(parents=True)
            formatter.generate_enhanced_summary(
                results, output, graph_stats=self._graph_stats()
            )
            summary = json.loads(
                (output / "summary.json").read_text(encoding="utf-8")
            )
            findings = s6_report.collect_findings(str(report_dir))
            findings.setdefault("artifacts", {})["diagnostic_detail_md"] = (
                "deliverables/analysis-diagnostics.md"
            )
            report = s6_report.generate_report(findings)
            diagnostic_detail = self._render_diagnostic_detail(findings)

        self.assertEqual(
            REASON_GUIDANCE_SCHEMA, summary["diagnostic_guidance_schema"]
        )
        self.assertEqual(2, len(summary["diagnostic_guidance"]))
        api_entries = {
            item["reason_code"]: item
            for item in summary["not_analyzed_apis"]
        }
        self.assertIn(
            "同一逻辑类",
            api_entries[
                "SPRING_RUNTIME_CLASS_AMBIGUOUS"
            ]["user_reason"],
        )
        self.assertIn(
            "MyBatis",
            api_entries[
                "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED"
            ]["user_reason"],
        )
        summary_by_code = {
            item["reason_code"]: item
            for item in summary["diagnostic_guidance"]
        }
        self.assertEqual(
            "path",
            summary_by_code[
                "SPRING_RUNTIME_CLASS_AMBIGUOUS"
            ]["observed_scope"],
        )
        self.assertEqual(
            "global",
            summary_by_code[
                "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED"
            ]["observed_scope"],
        )
        self.assertIn(
            "[分析异常记录](analysis-diagnostics.md)",
            report,
        )
        self.assertNotIn("Spring 运行时类选择歧义", report)
        self.assertNotIn("MyBatis 运行时制品解析失败", report)
        for internal_protocol in (
            "SPRING_RUNTIME_CLASS_AMBIGUOUS",
            "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED",
            "reason_code",
            "origin_step",
            "来源步骤",
            "api_id",
            "path_status",
            ".runtime/",
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
            "不替使用者决定",
        ):
            self.assertNotIn(non_objective_instruction, report)

        self.assertIn(
            "SPRING_RUNTIME_CLASS_AMBIGUOUS", diagnostic_detail
        )
        self.assertIn(
            "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED", diagnostic_detail
        )
        self.assertIn("**记录条件**", diagnostic_detail)
        self.assertNotIn("**可忽略条件**", diagnostic_detail)
        self.assertNotIn("建议", diagnostic_detail)
        self.assertNotIn("修复动作", diagnostic_detail)
        self.assertNotIn("完成标准", diagnostic_detail)
        self.assertIn("demo.Config", diagnostic_detail)
        self.assertIn("mybatis-runtime.jar", diagnostic_detail)


if __name__ == "__main__":
    unittest.main()
