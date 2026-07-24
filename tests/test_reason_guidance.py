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
    build_diagnostic_guidance,
    build_diagnostic_guidance_from_summary,
    guidance_for_reason_code,
)


class ReasonGuidanceTest(unittest.TestCase):
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
            "reason_code": "SPRING_PACKAGED_CLASS_AMBIGUOUS",
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
                        "reason_code": "SPRING_PACKAGED_CLASS_AMBIGUOUS",
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

    def test_aggregation_reports_actual_failure_scope_and_evidence(self):
        results = [
            self._result(
                "SPRING_PACKAGED_CLASS_AMBIGUOUS", "demo.Api.spring"
            ),
            self._result(
                "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED", "demo.Api.mybatis"
            ),
        ]

        guidance = build_diagnostic_guidance(results, self._graph_stats())
        by_code = {item["reason_code"]: item for item in guidance}

        spring = by_code["SPRING_PACKAGED_CLASS_AMBIGUOUS"]
        self.assertTrue(spring["blocking"])
        self.assertEqual("path", spring["observed_scope"])
        self.assertEqual(1, spring["affected_api_count"])
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
        self.assertIn("全局阻断", mybatis["scope_explanation"])
        self.assertEqual(
            ["/runtime/mybatis-runtime.jar"],
            mybatis["affected_artifacts"],
        )
        self.assertIn(
            "BadZipFile", mybatis["failure_detail_summaries"][0]
        )

    def test_summary_and_final_report_share_structured_guidance(self):
        results = [
            self._result(
                "SPRING_PACKAGED_CLASS_AMBIGUOUS", "demo.Api.spring"
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
            report = s6_report.generate_report(findings)

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
                "SPRING_PACKAGED_CLASS_AMBIGUOUS"
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
                "SPRING_PACKAGED_CLASS_AMBIGUOUS"
            ]["observed_scope"],
        )
        self.assertEqual(
            "global",
            summary_by_code[
                "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED"
            ]["observed_scope"],
        )
        self.assertIn("### 需要决策的分析诊断", report)
        self.assertIn("SPRING_PACKAGED_CLASS_AMBIGUOUS", report)
        self.assertIn("MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED", report)
        self.assertIn("**触发条件**", report)
        self.assertIn("**可忽略条件**", report)
        self.assertIn("**修复动作**", report)
        self.assertIn("demo.Config", report)
        self.assertIn("mybatis-runtime.jar", report)


if __name__ == "__main__":
    unittest.main()
