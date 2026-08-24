from __future__ import annotations

import csv
from contextlib import nullcontext
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import binary_report
import gate
import s5_query_call_chain
import s6_report


class Step6PresentationHelperContractTest(unittest.TestCase):
    def test_uncertain_evidence_detection_rejects_empty_placeholders(self):
        self.assertFalse(s6_report._has_uncertain_evidence_items([]))
        self.assertFalse(s6_report._has_uncertain_evidence_items([{}, [{"x": ""}]]))
        self.assertTrue(s6_report._has_uncertain_evidence_items([{"path": "evidence.csv"}]))
        self.assertTrue(s6_report._has_uncertain_evidence_items([[{"caller": "a"}]]))
        self.assertTrue(s6_report._has_uncertain_evidence_items([["edge"]]))

    def test_step5_summary_fallback_is_conservative_and_type_safe(self):
        self.assertEqual(s6_report._step5_summary_coverage_fallback({}), {})
        summary = {
            "total_apis": "2",
            "not_impacted": "invalid",
            "meta": {"graph_stats": {
                "truncated": True,
                "truncation_reasons": ("node_limit",),
                "edge_cap_hits": 1,
                "parser_fallback_reasons": {"java": 1},
                "source_artifact_alignment": {
                    "status": "complete", "artifact_path": "app.jar",
                },
                "artifact_bytecode": {"status": "complete"},
                "business_bytecode": {"status": "partial", "failures": ["one"]},
                "indirect_usage": {"status": "partial", "reason_codes": ["gap"]},
            }},
        }
        result = s6_report._step5_summary_coverage_fallback(summary)
        self.assertEqual(result["source"], "step5_summary_fallback")
        self.assertEqual(result["overall_status"], "partial")
        self.assertIn("business_reachability", result["critical_incomplete"])
        self.assertIn("indirect_usage_matrix", result["critical_incomplete"])
        self.assertNotIn("business_bytecode_graph", result["critical_incomplete"])
        business = next(item for item in result["components"] if item["id"] == "business_reachability")
        self.assertIn("edge_cap_hits", business["reason_codes"])
        self.assertIn("parser_fallback", business["reason_codes"])

    def test_alert_bytecode_evidence_requires_file_target_and_explicit_equivalence(self):
        base = {
            "evidence_files": "evidence/a.json|evidence/b.json",
            "path_text": "business.Entry.run -> changed.Api.call",
            "chain_detail": "类字节码完全一致",
        }
        with patch.object(s6_report, "_alert_target_matches_changed_symbol", return_value=True):
            self.assertTrue(s6_report._alert_row_has_preserved_bytecode_evidence(base))
            self.assertFalse(s6_report._alert_row_has_preserved_bytecode_evidence({
                **base, "evidence_files": "",
            }))
            self.assertFalse(s6_report._alert_row_has_preserved_bytecode_evidence({
                **base, "chain_detail": "仅发现候选",
            }))
        with patch.object(s6_report, "_alert_target_matches_changed_symbol", return_value=False):
            self.assertFalse(s6_report._alert_row_has_preserved_bytecode_evidence(base))

    def test_labels_summaries_and_context_projection_are_stable(self):
        reasons = s6_report.summarize_item_reason_codes([
            {"reason_code": "missing-source"},
            {"reason_code": "missing-source"},
            {},
        ])
        self.assertEqual(sum(reasons.values()), 3)
        self.assertEqual(s6_report._api_short_name({"api": "a.b.Type.call(String)"}), "call")
        self.assertEqual(s6_report._api_short_name({"api_name": "call"}), "call")
        self.assertEqual(s6_report._api_short_name({}), "")
        self.assertEqual(
            s6_report._known_context_parts({"context": {
                "jdk": "? → 21", "springboot": "2 → 3", "build_tool": "maven",
            }}),
            ["JDK 目标版本 21（基线版本未记录）", "Spring Boot 2 → 3", "构建工具 maven"],
        )
        self.assertEqual(s6_report._known_context_parts({"context": {"jdk": "?", "build_tool": "?"}}), [])

    def test_report_format_helpers_never_leak_internal_markers(self):
        self.assertEqual(s6_report._strip_changed_api_marker("变更API: a.b.C.m"), "a.b.C.m")
        self.assertEqual(s6_report._strip_changed_api_marker("a.b.C.m"), "a.b.C.m")
        self.assertEqual(s6_report._call_chain_status_label("done"), "已完成")
        self.assertEqual(s6_report._call_chain_status_label("not-real"), "未知")
        links = s6_report._join_report_links(["a.md", "b.md", "c.md"], limit=2)
        self.assertIn("另 1 项", links)
        self.assertEqual(s6_report._join_report_links([], empty="无"), "无")
        self.assertEqual(
            s6_report._self_contained_diagnostic_detail("读取失败；详见 occurrences"),
            "读取失败",
        )
        self.assertEqual(s6_report._self_contained_diagnostic_detail(""), "")
        self.assertEqual(
            s6_report._objective_diagnostic_text("当前结论需要复核；建议决策：停止"),
            "当前结论的适用范围受到限制；结论状态：停止",
        )
        self.assertEqual(s6_report._objective_diagnostic_text("", "fallback"), "fallback")

    def test_input_diagnostic_fact_labels_distinguish_partial_and_whole_artifacts(self):
        with patch.object(s6_report, "_input_diagnostic_artifact_label", return_value="调用链"):
            self.assertEqual(
                s6_report._input_diagnostic_fact_label({"stage": "row_contract"}),
                "调用链部分记录无效",
            )
            self.assertEqual(
                s6_report._input_diagnostic_fact_label({"error_type": "FileNotFoundError"}),
                "调用链未生成",
            )
            self.assertEqual(
                s6_report._input_diagnostic_fact_label({"error_type": "JSONRootTypeError"}),
                "调用链结构无效",
            )
            self.assertEqual(
                s6_report._input_diagnostic_fact_label({"error_type": "OSError"}),
                "调用链无法读取",
            )

    def test_test_sections_issue_format_and_detail_delegation_are_explicit(self):
        self.assertEqual(s6_report.build_report_sections_for_test_only(), [
            "报告目录", "依赖层面结论", "API 及调用关系", "用户可见文件说明",
        ])
        issue = {
            "api": "a.b.C.m", "coord": "g:a", "change_type": "removed",
            "direct_callers": 1, "user_conclusion": "已确认影响",
            "call_paths": ["entry -> target"],
            "evidence_paths": [[{
                "caller_symbol": "entry", "callee_key": "target",
                "evidence_type": "bytecode", "confidence": "high",
                "file": "/tmp/C.java", "line": 7,
            }]],
        }
        with patch.object(s6_report, "_change_summary", return_value="API 删除"):
            lines = s6_report._fmt_issue(issue)
        rendered = "\n".join(lines)
        self.assertIn("a.b.C.m", rendered)
        self.assertIn("entry -> target", rendered)
        self.assertIn("C.java:7", rendered)

        with patch.object(
            s6_report, "write_bucket_detail_artifacts", return_value={"not_found": "detail.md"},
        ) as write:
            self.assertEqual(
                s6_report.write_not_found_detail_artifacts("report", {"not_found": []}),
                {"not_found": "detail.md"},
            )
        write.assert_called_once_with("report", {"not_found": []}, "not_found")

    def test_cli_delegates_all_publication_to_binary_report_transaction(self):
        stderr = io.StringIO()
        argv = [
            "s6_report.py", "--report-dir", "report",
            "--output-findings", "findings.json", "--output-report", "report.md",
        ]
        with patch.object(binary_report, "publish_step6", return_value={"api_count": 2}) as publish, patch.object(
            s6_report.sys, "argv", argv,
        ), patch.object(s6_report.sys, "stderr", stderr):
            self.assertIsNone(s6_report.main())
        publish.assert_called_once_with("report", "findings.json", "report.md")
        self.assertIn("API 目标 2 个", stderr.getvalue())

    def test_internal_result_and_coverage_views_preserve_objective_boundaries(self):
        self.assertEqual(
            s6_report._uncertainty_kind({
                "evidence_paths": [[{"caller_symbol": "app.Entry"}]],
            }),
            s6_report.UNCERTAINTY_KIND_CANDIDATE_EVIDENCE,
        )
        self.assertEqual(
            s6_report._uncertainty_kind_for_report({}, {}),
            s6_report.UNCERTAINTY_KIND_ANALYSIS_LIMITATION,
        )

        coverage_rows = s6_report._coverage_gap_rows({
            "overall_status": "partial",
            "critical_incomplete": ["business_reachability"],
            "components": [{
                "id": "business_reachability",
                "status": "partial",
                "reason_codes": ["edge_cap_hits"],
                "evidence": ["evidence/call_chain/coverage.json"],
            }],
        })
        self.assertEqual(len(coverage_rows), 1)
        self.assertIn("调用", coverage_rows[0]["label"])
        self.assertTrue(coverage_rows[0]["impact"])

        unknown = {"coord": "g:a", "api": "p.C.m", "conclusion": "未知结果"}
        detail = s6_report._detail_row(1, unknown)
        self.assertIn("结论未确定", detail)
        self.assertEqual(
            s6_report._api_result_explanation(unknown),
            "当前记录没有保存更多结果说明。",
        )
        self.assertIn(
            "无法确认",
            s6_report._population_full_range({
                "scope_verified": True,
                "population_unconfirmed": True,
                "total_count": 3,
            }, "API"),
        )

    def test_csv_paths_diagnostics_and_logical_paths_use_real_helpers(self):
        chain = s6_report._csv_chain_view({
            "call_paths": ["app.Entry.run → 变更API: dep.Api.call"],
        })
        self.assertEqual(chain["entry"], "app.Entry.run")
        self.assertEqual(chain["target"], "dep.Api.call")
        evidence_chain = s6_report._csv_chain_view({
            "evidence_paths": [[
                {"caller_symbol": "app.Entry.run", "callee_key": "app.Service.go"},
                {"caller_symbol": "app.Service.go", "callee_key": "dep.Api.call"},
            ]],
        })
        self.assertEqual(evidence_chain["hop_count"], "2")

        labels = s6_report._logical_full_path_labels({
            "app.Entry.run() → dep.Api.call()": 2,
            "app.Entry.run → dep.Api.call()": 1,
        })
        self.assertEqual(len(labels), 1)
        self.assertIn("记录 3 次", labels[0])

        evidence = s6_report._diagnostic_evidence_text({
            "affected_artifacts": ["/var/data/libs/example.jar"],
        })
        self.assertIn("example.jar", evidence)
        impact = s6_report._diagnostic_objective_impact({
            "reason_code": "INCOMPLETE_EVIDENCE_COVERAGE",
            "potentially_affected_api_count": 2,
            "observed_scope": "global",
        })
        self.assertTrue(impact)

        findings = {
            "coverage": {"overall_status": "partial"},
            "diagnostics": [{
                "artifact": "coverage",
                "path": "/report/coverage.json",
                "error_type": "FileNotFoundError",
                "stage": "json_missing",
            }],
        }
        gap_rows = s6_report._input_diagnostic_gap_rows(findings)
        self.assertEqual(len(gap_rows), 1)
        self.assertIn("coverage.json", gap_rows[0]["evidence_text"])

        guidance_findings = {
            "diagnostic_guidance": [{
                "reason_code": "INCOMPLETE_EVIDENCE_COVERAGE",
                "origin_step": "step5",
                "observed_scope": "global",
                "potentially_affected_api_count": 2,
                "primary_reason_api_count": 1,
                "blocking": True,
            }],
            "artifacts": {"diagnostic_detail_md": "deliverables/diagnostics.md"},
        }
        rendered = "\n".join(s6_report.render_diagnostic_summary(guidance_findings))
        self.assertIn("2 个 API", rendered)
        self.assertIn("分析诊断明细", rendered)

    def test_alert_and_summary_validators_reject_contradictory_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            alerts = root / "alerts.csv"
            fields = [
                "path_status", "conclusion_level", "business_reachable",
                "evidence_files", "path_text", "chain_detail",
                "review_reason", "changed_symbol", "api_signature",
            ]
            with alerts.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow({
                    "path_status": "not_impacted",
                    "conclusion_level": "confirmed_no_impact",
                    "business_reachable": "false",
                    "evidence_files": "evidence/class.json",
                    "path_text": "app.Entry.run -> dep.Api.call",
                    "chain_detail": "类字节码完全一致",
                    "review_reason": "preserved",
                    "changed_symbol": "dep.Api.call",
                    "api_signature": "",
                })
            diagnostics = []
            rows = list(s6_report._validated_alert_rows(
                alerts, diagnostics=diagnostics, required=True,
            ))
            self.assertEqual(len(rows), 1)
            self.assertEqual(diagnostics, [])

            summary_path = root / "summary.json"
            summary_path.write_text("{}", encoding="utf-8")
            item = {
                "coord": "g:a", "api": "dep.Api.call",
                "api_signature": "()", "symbol_kind": "method",
                "change_type": "REMOVED",
            }
            summary = {
                "status": "done", "total_apis": 2,
                "reachable": 1, "reachable_apis": [item],
                "not_impacted": 0, "not_impacted_apis": [],
                "uncertain": 0, "uncertain_apis": [],
                "not_analyzed": 0, "not_analyzed_apis": [],
                "not_found_in_static_analysis": 0, "not_found_apis": [],
            }
            s6_report._validate_call_summary_contract(
                summary_path, summary, diagnostics,
            )
            self.assertTrue(any(
                item.get("artifact") == "call_chain_summary"
                for item in diagnostics
            ))

    def test_collect_findings_classifies_candidate_uncertainty_and_missing_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            call_chain = report / "evidence" / "call_chain"
            call_chain.mkdir(parents=True)
            static_scan = report / "evidence" / "static_scan"
            static_scan.mkdir(parents=True)
            (static_scan / "s3_database_contract_summary.json").write_text(
                json.dumps({"schema": "invalid", "change_count": 0}),
                encoding="utf-8",
            )
            uncertain = {
                "coord": "g:a", "api": "dep.Api.call",
                "api_signature": "()", "symbol_kind": "method",
                "change_type": "REMOVED", "reason_code": "UNKNOWN",
                "call_paths": ["app.Entry.run -> dep.Api.call"],
            }
            (call_chain / "summary.json").write_text(json.dumps({
                "status": "done", "total_apis": 1,
                "reachable": 0, "reachable_apis": [],
                "not_impacted": 0, "not_impacted_apis": [],
                "uncertain": 1, "uncertain_apis": [uncertain],
                "not_analyzed": 0, "not_analyzed_apis": [],
                "not_found_in_static_analysis": 0, "not_found_apis": [],
                "diagnostic_guidance": [],
            }), encoding="utf-8")
            findings = s6_report.collect_findings(report)
        self.assertEqual(len(findings["uncertain"]), 1)
        self.assertEqual(
            findings["uncertain"][0]["uncertainty_kind"],
            s6_report.UNCERTAINTY_KIND_CANDIDATE_EVIDENCE,
        )
        self.assertTrue(findings["diagnostics"])

    def test_report_builders_generate_complete_empty_population_artifacts(self):
        findings = {
            "analysis_scope": {"mode": "full"},
            "dependency_changes": [],
            "changed_api_inventory": [],
            "impact_overview": {"apis": []},
            "coverage": {"overall_status": "not_applicable"},
            "artifacts": {},
            "diagnostics": [],
        }
        dependency_lines = s6_report.render_dependency_conclusions(findings)
        self.assertTrue(any("依赖层面结论" in line for line in dependency_lines))
        visible_lines = s6_report.render_user_visible_files(findings)
        self.assertTrue(any("完整依赖分析" in line for line in visible_lines))

        with tempfile.TemporaryDirectory() as temporary:
            dependency_md = s6_report.write_full_dependency_analysis_artifact(
                temporary, findings,
            )
            api_md = s6_report.write_full_api_analysis_artifact(
                temporary, findings,
            )
            self.assertTrue((Path(temporary) / dependency_md).is_file())
            self.assertTrue((Path(temporary) / api_md).is_file())

    def test_confirmed_detail_and_main_table_link_full_evidence(self):
        rows = [{
            "coord": "g:a", "api": f"dep.Api.call{index}",
            "api_signature": "()", "conclusion": "已确认影响",
            "severity": "P1", "paths": ["app.Entry.run -> dep.Api.call"],
            "path_count": 1, "occurrence_count": 1,
        } for index in range(9)]
        findings = {
            "artifacts": {
                "alerts_csv": "evidence/call_chain/alerts.csv",
                "confirmed_csv": "deliverables/confirmed.csv",
                "confirmed_md": "deliverables/confirmed.md",
            },
            "impact_overview": {"apis": []},
        }
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            s6_report, "build_api_result_rows", return_value=rows,
        ):
            artifacts = s6_report._write_confirmed_detail_artifacts(
                temporary,
                findings,
                s6_report.S6_DETAIL_BUCKETS["confirmed"],
            )
            table = "\n".join(s6_report.render_api_result_table(findings))
        self.assertIn("confirmed_md", artifacts)
        self.assertIn("逐链路证据台账", table)

        cards = s6_report._render_path_sample_cards(rows[:1], findings)
        self.assertTrue(any("逐链路证据台账" in line for line in cards))


class BinaryReportAdapterContractTest(unittest.TestCase):
    def test_unlink_and_irreversible_publication_adapter_are_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "owned"
            path.write_text("x", encoding="utf-8")
            binary_report._unlink_missing_ok(path)
            binary_report._unlink_missing_ok(path)
            self.assertFalse(path.exists())

        with patch.object(binary_report, "_publication_transaction_action", return_value={"ok": True}) as action:
            self.assertTrue(binary_report.finalize_irreversible_report_publication(
                ["one"], expected_transaction_id="tx", expected_binding={"x": 1},
            ))
        action.assert_called_once_with(
            ["one"], "finalize_irreversible",
            expected_transaction_id="tx", expected_binding={"x": 1},
        )

    def test_legacy_coverage_preserves_unique_reason_codes(self):
        result = binary_report._legacy_coverage({
            "summary": {
                "decision_coverage_status": "complete",
                "trace_coverage_status": "partial",
                "trace_coverage_gaps": [
                    {"reason_code": "A"}, {"code": "A"}, "B",
                ],
            },
            "coverage": {"source": "legacy"},
        })
        self.assertEqual(result["overall_status"], "partial")
        self.assertEqual(result["critical_incomplete"], ["business_reachability"])
        trace = next(item for item in result["components"] if item["id"] == "business_reachability")
        self.assertEqual(trace["reason_codes"], ["A", "B"])

    def test_step5_index_adapter_returns_detached_public_shape(self):
        with patch.object(binary_report, "load_consistent_step5_query_inputs", return_value={
            "index": {"schema": "index.v1"}, "index_path": "/report/index.json",
        }):
            index, path = binary_report.load_consistent_step5_query_index("report")
        self.assertEqual(index, {"schema": "index.v1"})
        self.assertEqual(path, Path("/report/index.json"))

    def test_step6_reader_binds_snapshot_findings_and_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deliverables = root / "deliverables"
            findings_dir = root / "findings"
            deliverables.mkdir()
            findings_dir.mkdir()
            (deliverables / "report.md").write_text("report", encoding="utf-8")
            findings = {
                "schema": "java-upgrade-analyzer.binary-findings.v2",
                "result_generation_identity": "generation",
                "step5_publication_receipt_identity": "receipt5",
                "step6_publication_input_identity": "input6",
            }
            (findings_dir / "s6_findings.json").write_text(json.dumps(findings), encoding="utf-8")
            release = {
                "step5": {"committed_receipt_identity": "receipt5"},
                "step6": {
                    "committed_receipt_identity": "receipt6",
                    "publication_input_identity": "input6",
                },
                "active_core": {"result_generation_identity": "generation"},
                "release_identity": "release",
            }
            snapshot = {
                "snapshot_destinations": [str(deliverables), str(findings_dir)],
                "binding": {
                    "upstream_publication_receipt_identity": "receipt5",
                    "publication_input_identity": "input6",
                },
                "committed_receipt_identity": "receipt6",
            }
            with patch.object(binary_report, "_report_workflow_read_lock", return_value=nullcontext()), patch.object(
                binary_report, "_active_generation_publication_lock", return_value=nullcontext(),
            ), patch.object(binary_report, "require_current_release_stage", return_value=release), patch.object(
                binary_report, "short_temporary_directory", return_value=nullcontext(str(root / "snapshot")),
            ), patch.object(
                binary_report, "materialize_report_publication_committed_snapshot", return_value=snapshot,
            ):
                result = binary_report.load_consistent_step6_publication(root)
        self.assertEqual(result["findings"], findings)
        self.assertEqual(result["deliverable_names"], ("report.md",))
        self.assertEqual(result["committed_receipt_identity"], "receipt6")
        self.assertEqual(result["release_identity"], "release")

    def test_step6_candidate_validator_owns_parent_workflow_lock(self):
        sentinel = object()
        with patch.object(binary_report, "_report_workflow_read_lock", return_value=nullcontext()), patch.object(
            binary_report, "_validate_step6_candidate_under_parent_workflow_lock", return_value=sentinel,
        ) as validate:
            result = binary_report.validate_step6_publication_candidate(
                "report", candidate_deliverables_dir="deliverables",
                candidate_findings_dir="findings", candidate_publication_binding={"x": 1},
            )
        self.assertIs(result, sentinel)
        validate.assert_called_once_with(
            "report", candidate_deliverables_dir="deliverables",
            candidate_findings_dir="findings", candidate_publication_binding={"x": 1},
        )

    def test_step6_internal_inputs_attribute_protocol_and_path_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report"
            render = Path(temporary) / "render"
            invalid = report / "evidence" / "dependencies" / "dep_changes.csv"
            invalid.mkdir(parents=True)
            with patch.object(
                binary_report, "_step6_upstream_evidence_files",
                return_value={"evidence/dependencies/dep_changes.csv"},
            ):
                with self.assertRaises(binary_report.BinaryReportError):
                    binary_report._materialize_step6_upstream_evidence(
                        report, render,
                    )

            text_path = (
                report / "evidence" / "static_scan"
                / "s3_jdk_serialization.txt"
            )
            text_path.parent.mkdir(parents=True, exist_ok=True)
            text_path.write_text("fixture", encoding="utf-8")
            findings = {"diagnostics": []}
            with patch.object(
                Path, "open", side_effect=OSError("unreadable text"),
            ):
                binary_report._augment_step6_internal_input_diagnostics(
                    report, findings,
                )
        self.assertTrue(any(
            item.get("stage") == "text_load"
            for item in findings["diagnostics"]
        ))

    def test_private_report_readers_close_descriptors_after_open_wrapper_failure(self):
        class FdopenFailingOs:
            def __getattr__(self, name):
                return getattr(os, name)

            @staticmethod
            def fdopen(*_args, **_kwargs):
                raise OSError("fdopen failed")

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "value.json"
            path.write_text("{}", encoding="utf-8")
            with patch.object(binary_report, "os", FdopenFailingOs()):
                with self.assertRaises(binary_report.BinaryReportError):
                    binary_report._read_private_publication_json(path)
                with self.assertRaises(binary_report.BinaryReportError):
                    binary_report._report_file_sha256(path)

    def test_committed_recovery_verifies_content_before_finishing_receipt(self):
        destination = Path("/private/committed")
        payload = {
            "state": "committed", "transaction_id": "tx",
            "binding": {"scope": "one"},
        }
        records = [{"destination": destination}]
        with patch.object(
            binary_report, "_load_publication_transaction",
            return_value=(payload, records, "current"),
        ), patch.object(
            binary_report, "_publication_path_exists", return_value=True,
        ), patch.object(
            binary_report, "_verify_published_transaction_content",
        ) as verify, patch.object(
            binary_report, "_finish_committed_publication",
        ) as finish:
            self.assertTrue(binary_report._recover_publication_transaction(
                Path("transaction.json"),
                destinations=[destination],
                group_token="group",
                expected_transaction_id="tx",
                expected_binding={"scope": "one"},
            ))
        verify.assert_called_once_with(payload, records)
        finish.assert_called_once()

    def test_committed_snapshot_removes_partial_private_copy_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            destination = root / "published"
            destination.mkdir()
            snapshot_root = root / "snapshot"
            snapshot_root.mkdir()
            receipt = {
                "transaction_id": "tx",
                "binding": {},
                "destinations": [{
                    "destination": str(destination.resolve()),
                    "content_sha256": "a" * 64,
                }],
            }

            def fail_after_creating(_source, target):
                Path(target).mkdir()
                raise OSError("copy failed")

            with patch.object(
                binary_report, "_read_private_publication_json", return_value={},
            ), patch.object(
                binary_report, "_validate_committed_publication_receipt",
                return_value=(receipt, "current"),
            ), patch.object(
                binary_report, "_copy_report_directory_secure",
                side_effect=fail_after_creating,
            ):
                with self.assertRaisesRegex(OSError, "copy failed"):
                    binary_report.materialize_report_publication_committed_snapshot(
                        [destination], snapshot_root,
                    )
            self.assertEqual(list(snapshot_root.iterdir()), [])

    def test_step5_falls_back_to_exact_public_change_key(self):
        formal_item = {
            "display_owner": "dep/Api",
            "display_member": "call",
            "display_descriptor": "()V",
            "display_member_kind": "method",
            "reachability_status": "not_analyzed",
            "dependency_artifacts": [{
                "side": "current", "coord": "g:a:2",
                "logical_dependency_lineage": "g:a",
            }],
            "contributing_change_fact_ids": [],
        }
        change = {
            "coord": "g:a", "api_name": "dep.Api.call",
            "api_signature": "()", "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        loaded = {
            "formal": {"by_api": [formal_item], "resource_activation_results": []},
            "projections": {"authoritative_projection_assessments": []},
            "decisions": {"authoritative_change_facts": []},
            "summary": {},
            "manifest": {"result_generation_identity": "a" * 64},
            "active": {
                "validation_run_identity": "b" * 64,
                "validation_result_sha256": "c" * 64,
            },
        }
        expected_key = ("g:a", "dep.Api.call", "()", "method")
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            binary_report, "_change_rows_by_result",
            return_value=([change], {expected_key: change}),
        ):
            with self.assertRaises(binary_report.BinaryReportError) as raised:
                binary_report._publish_step5_from_snapshot(
                    temporary,
                    Path(temporary) / "evidence" / "call_chain",
                    loaded=loaded,
                    step4_api_changes_dir=Path(temporary),
                    step4_receipt={"committed_receipt_identity": "invalid"},
                )
        self.assertEqual(
            raised.exception.reason_code,
            "BINARY_STEP4_PUBLICATION_RECEIPT_INVALID",
        )

    def test_verify_step4_release_reads_snapshot_under_workflow_lock(self):
        loaded = {
            "manifest": {
                "result_generation_identity": "a" * 64,
                "analysis_context_identity": "d" * 64,
            },
            "active": {
                "validation_run_identity": "b" * 64,
                "validation_result_sha256": "c" * 64,
            },
        }
        binding = binary_report._loaded_step4_publication_binding(loaded)
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report"
            api_snapshot = Path(temporary) / "api"
            source_snapshot = Path(temporary) / "source"
            api_snapshot.mkdir()
            source_snapshot.mkdir()
            (api_snapshot / "summary.json").write_text(json.dumps({
                "schema": "java-upgrade-analyzer.binary-step4-summary.v1",
                "authority": "binary_first",
                "result_generation_identity": "a" * 64,
                "analysis_context_identity": "d" * 64,
            }), encoding="utf-8")
            snapshot = {
                "transaction_id": "tx", "binding": binding,
                "committed_receipt_identity": "e" * 64,
                "gate_receipt": {
                    "gate_name": "binary_generation",
                    "strict_risk_gate": False,
                },
                "snapshot_destinations": [
                    str(api_snapshot), str(source_snapshot),
                ],
            }
            with patch.object(
                binary_report, "_standalone_report_workflow_lock",
                return_value=nullcontext(),
            ), patch.object(
                binary_report, "load_validated_generation", return_value=loaded,
            ), patch.object(
                binary_report,
                "materialize_report_publication_committed_snapshot",
                return_value=snapshot,
            ), patch.object(
                binary_report, "require_current_release_stage",
                return_value={
                    "step4": {"committed_receipt_identity": "e" * 64},
                },
            ):
                result = binary_report.verify_current_step4_release(
                    report,
                    expected_gate_name="binary_generation",
                    expected_strict_risk_gate=False,
                    active_lock_held=True,
                )
        self.assertEqual(result["committed_receipt_identity"], "e" * 64)

    def test_pending_generation_reader_and_cli_phase_dispatch_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(binary_report.BinaryReportError):
                binary_report.load_validated_generation(
                    temporary, candidate_activation_identity="a" * 64,
                )
        for phase, publisher_args in (
            ("step4", ["--output-dir", "output"]),
            ("step5", ["--output-dir", "output"]),
        ):
            with self.subTest(phase=phase), patch.object(
                binary_report,
                f"publish_{phase}",
                return_value={"phase": phase},
            ) as publish, patch.object(binary_report.sys, "stdout", io.StringIO()):
                self.assertEqual(binary_report.main([
                    "--phase", phase, "--report-dir", "report", *publisher_args,
                ]), 0)
            publish.assert_called_once()

    def test_direct_step4_and_step5_failures_query_state_then_rollback(self):
        transaction = {
            "transaction_id": "tx", "binding": {"scope": "one"},
            "published_content_identity": "a" * 64,
        }
        for phase in ("step4", "step5"):
            prepare_name = f"prepare_{phase}_publication_candidate"
            publish = getattr(binary_report, f"publish_{phase}")
            with self.subTest(phase=phase), patch.object(
                binary_report, "_standalone_report_workflow_lock",
                return_value=nullcontext(),
            ), patch.object(
                binary_report, "_report_publication_prepare_capability",
                return_value=nullcontext(),
            ), patch.object(
                binary_report, prepare_name,
                return_value={"publication_transaction": transaction},
            ), patch.object(
                binary_report, "materialize_report_publication_gate_candidate",
                side_effect=OSError("candidate failed"),
            ), patch.object(
                binary_report, "report_publication_transaction_state",
                return_value="pending_gate",
            ) as state, patch.object(
                binary_report, "rollback_report_publication",
            ) as rollback:
                with self.assertRaisesRegex(OSError, "candidate failed"):
                    publish("report", "output")
            state.assert_called_once()
            rollback.assert_called_once()

    def test_step4_and_downstream_commit_failures_rollback_pending_transactions(self):
        with patch.object(
            binary_report, "_standalone_report_workflow_lock",
            return_value=nullcontext(),
        ), patch.object(
            binary_report, "_active_generation_publication_lock",
            return_value=nullcontext(),
        ), patch.object(
            binary_report, "report_publication_transaction_receipt",
            return_value={"state": "pending_gate", "binding": {}},
        ), patch.object(
            binary_report, "load_validated_generation", return_value={},
        ), patch.object(
            binary_report, "_step4_publication_binding_matches_loaded",
            return_value=True,
        ), patch.object(
            binary_report, "mark_report_publication_gate_passed",
            side_effect=OSError("commit failed"),
        ), patch.object(
            binary_report, "report_publication_transaction_state",
            return_value="pending_gate",
        ) as state, patch.object(
            binary_report, "rollback_report_publication",
        ) as rollback:
            with self.assertRaisesRegex(OSError, "commit failed"):
                binary_report.complete_step4_report_publication_after_gate(
                    "report",
                    expected_transaction_id="tx",
                    expected_binding={},
                    gate_name="binary_generation",
                    strict_risk_gate=False,
                )
        state.assert_called_once()
        rollback.assert_called_once()

        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            candidate.mkdir()
            (candidate / "selection.json").write_text(json.dumps({
                "schema": "java-upgrade-analyzer.binary-step5-selection.v1",
                "selected_coords": [], "selected_names": [],
            }), encoding="utf-8")
            binding = {
                "upstream_publication_receipt_identity": "receipt4",
                "publication_input_identity": "a" * 64,
            }
            with patch.object(
                binary_report, "_active_generation_publication_lock",
                return_value=nullcontext(),
            ), patch.object(
                binary_report, "report_publication_transaction_receipt",
                return_value={
                    "state": "pending_gate", "binding": binding,
                    "published_content_identity": "b" * 64,
                },
            ), patch.object(
                binary_report, "load_validated_generation", return_value={},
            ), patch.object(
                binary_report, "require_current_release_stage",
                return_value={
                    "step4": {"committed_receipt_identity": "receipt4"},
                },
            ), patch.object(
                binary_report, "report_publication_committed_receipt",
                return_value={"committed_receipt_identity": "receipt4"},
            ), patch.object(
                binary_report, "materialize_report_publication_gate_candidate",
                return_value={
                    "candidate_destinations": [
                        str(candidate), str(candidate), str(candidate),
                    ],
                },
            ), patch.object(
                binary_report, "_step5_publication_input_identity",
                return_value="a" * 64,
            ), patch.object(
                binary_report, "_downstream_publication_binding_matches_loaded",
                return_value=True,
            ), patch.object(
                binary_report, "mark_report_publication_gate_passed",
                side_effect=OSError("downstream commit failed"),
            ), patch.object(
                binary_report, "report_publication_transaction_state",
                return_value="pending_gate",
            ) as state, patch.object(
                binary_report, "rollback_report_publication",
            ) as rollback:
                with self.assertRaisesRegex(OSError, "downstream commit failed"):
                    binary_report.complete_downstream_report_publication_after_gate(
                        temporary,
                        "step5",
                        expected_transaction_id="tx",
                        expected_binding=binding,
                        gate_name="binary_report",
                        strict_risk_gate=False,
                        workflow_lock_held=True,
                    )
            state.assert_called_once()
            rollback.assert_called_once()

    def test_step6_direct_gate_failure_rolls_back_staged_publication(self):
        loaded = {
            "manifest": {
                "result_generation_identity": "a" * 64,
                "analysis_context_identity": "d" * 64,
            },
            "active": {
                "validation_run_identity": "b" * 64,
                "validation_result_sha256": "c" * 64,
            },
        }
        transaction = {
            "transaction_id": "tx", "binding": {"scope": "one"},
            "published_content_identity": "e" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            binary_report, "_bind_step6_findings_to_release",
        ), patch.object(
            binary_report, "_write_step6_artifact_set",
            return_value=(Path(temporary) / "report.md", Path(temporary) / "findings.json"),
        ), patch.object(
            binary_report, "_active_generation_publication_lock",
            return_value=nullcontext(),
        ), patch.object(
            binary_report, "load_validated_generation", return_value=loaded,
        ), patch.object(
            binary_report, "report_publication_committed_receipt",
            return_value={},
        ), patch.object(
            binary_report, "_stage_directory_group", return_value=transaction,
        ), patch.object(
            binary_report, "materialize_report_publication_gate_candidate",
            side_effect=OSError("step6 gate failed"),
        ), patch.object(
            binary_report, "report_publication_transaction_state",
            return_value="pending_gate",
        ) as state, patch.object(
            binary_report, "rollback_report_publication",
        ) as rollback:
            with self.assertRaisesRegex(OSError, "step6 gate failed"):
                binary_report._render_and_publish_step6_from_snapshots(
                    report_root=Path(temporary),
                    findings_path=Path(temporary) / "findings" / "s6.json",
                    report_path=Path(temporary) / "deliverables" / "report.md",
                    loaded=loaded,
                    render_root=Path(temporary) / "render",
                    findings={},
                    step4_snapshot={"transaction_id": "s4", "binding": {}},
                    step5_snapshot={
                        "transaction_id": "s5", "binding": {},
                        "committed_receipt_identity": "f" * 64,
                    },
                    step6_input_identity="1" * 64,
                    upstream_evidence_inputs={},
                    prepare_candidate_only=False,
                )
        state.assert_called_once()
        rollback.assert_called_once()

    def test_downstream_recovery_can_reconcile_global_release(self):
        with patch.object(
            binary_report, "_active_generation_publication_lock",
            return_value=nullcontext(),
        ), patch.object(
            binary_report, "report_publication_transaction_recovery_metadata",
            return_value={"state": "absent"},
        ), patch.object(
            binary_report, "reconcile_current_release",
            return_value={"release_identity": "current"},
        ) as reconcile:
            result = binary_report.recover_downstream_report_publications(
                "report", workflow_lock_held=True, reconcile_release=True,
            )
        reconcile.assert_called_once_with(
            Path("report").resolve(), workflow_lock_held=True,
        )
        self.assertEqual(result["global_release"]["release_identity"], "current")


class GateBoundaryContractTest(unittest.TestCase):
    def test_gate_paths_are_derived_from_pipeline_constants(self):
        report = Path("report")
        self.assertEqual(
            gate.evidence_call_chain_dir(report),
            report / gate.EVIDENCE_DIRNAME / gate.EVIDENCE_CALL_CHAIN_DIRNAME,
        )
        self.assertEqual(
            gate.runtime_coverage_dir(report),
            report / gate.RUNTIME_DIRNAME / gate.RUNTIME_COVERAGE_DIRNAME,
        )
        self.assertEqual(gate.provenance_path(report).name, "build_provenance.json")
        self.assertEqual(
            gate.dependency_jars_manifest_path(report).name,
            gate.STEP1_DEPENDENCY_JARS_MANIFEST_FILE,
        )
        self.assertEqual(gate.coverage_path(report).name, "coverage.json")

    def test_dependency_version_presence_and_archive_safety_are_fail_closed(self):
        self.assertTrue(gate.has_dep_versions({"old_version": "1", "new_version": "-"}))
        self.assertTrue(gate.has_dep_versions({"old_version": "-", "new_version": "2"}))
        self.assertFalse(gate.has_dep_versions({"old_version": "-", "new_version": ""}))
        with patch.object(gate, "require_safe_archive") as safety:
            gate.require_safe_step1_retained_archive("a.jar", "dependency")
        safety.assert_called_once_with(
            "a.jar", inspect_nested_archives=False, allow_duplicate_maven_metadata=True,
        )
        with patch.object(gate, "require_safe_archive", side_effect=ValueError("unsafe")), patch.object(
            gate, "fail", side_effect=RuntimeError("blocked"),
        ):
            with self.assertRaisesRegex(RuntimeError, "blocked"):
                gate.require_safe_step1_retained_archive("a.jar", "dependency")

    def test_step1_gate_refuses_to_infer_success_when_evidence_is_absent(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            gate.sys, "stderr", io.StringIO(),
        ):
            with self.assertRaises(SystemExit) as raised:
                gate.gate_step1_scope(temporary)
        self.assertEqual(raised.exception.code, 1)

    def test_step1_gate_validates_retained_archives_hashes_and_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            dependencies = gate.evidence_dependencies_dir(report)
            dependencies.mkdir(parents=True)
            base_jar = dependencies / "base.jar"
            current_jar = dependencies / "current.jar"
            for archive_path, value in ((base_jar, "base"), (current_jar, "current")):
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n\n")
                    archive.writestr(f"fixture/{value}.txt", value)

            dependency_fields = [
                "coord", "old_version", "new_version", "change_type", "risk",
                "scope", "resolution_status", "base_lib_entry",
                "current_lib_entry",
            ]
            with (dependencies / "dep_changes.csv").open(
                "w", encoding="utf-8", newline="",
            ) as handle:
                writer = csv.DictWriter(handle, fieldnames=dependency_fields)
                writer.writeheader()
                writer.writerow({
                    "coord": "g:a", "old_version": "1", "new_version": "2",
                    "change_type": "升级", "risk": "medium", "scope": "runtime",
                    "resolution_status": "resolved", "base_lib_entry": "base.jar",
                    "current_lib_entry": "current.jar",
                })
            current_fields = [
                "coord", "version", "scope", "remark", "lib_entry",
                "resolution_status",
            ]
            with (dependencies / "deps_current_resolved.csv").open(
                "w", encoding="utf-8", newline="",
            ) as handle:
                writer = csv.DictWriter(handle, fieldnames=current_fields)
                writer.writeheader()
                writer.writerow({
                    "coord": "g:a", "version": "2", "scope": "runtime",
                    "remark": "fixture", "lib_entry": "current.jar",
                    "resolution_status": "resolved",
                })
            (dependencies / "build_provenance.json").write_text(
                json.dumps({
                    "both_builds_succeeded": True,
                    "sides": [
                        {"side": "base", "artifact_sha256": "a" * 64},
                        {"side": "current", "artifact_sha256": "b" * 64},
                    ],
                }),
                encoding="utf-8",
            )

            def digest(path):
                return hashlib.sha256(path.read_bytes()).hexdigest()

            (dependencies / gate.STEP1_DEPENDENCY_JARS_MANIFEST_FILE).write_text(
                json.dumps({
                    "items": [
                        {
                            "side": "base", "coord": "g:a", "version": "1",
                            "lib_entry": "base.jar", "retained_path": str(base_jar),
                            "nested_jar_sha256": digest(base_jar),
                            "purposes": ["binary_diff"],
                        },
                        {
                            "side": "current", "coord": "g:a", "version": "2",
                            "lib_entry": "current.jar", "retained_path": str(current_jar),
                            "nested_jar_sha256": digest(current_jar),
                            "purposes": ["binary_diff", "binary_runtime"],
                        },
                    ],
                    "business_artifacts": [],
                }),
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with patch.object(gate.sys, "stderr", stderr):
                gate.gate_step1_scope(report)
        self.assertIn("step1_scope 门控通过", stderr.getvalue())

    def test_csv_context_and_committed_final_gate_fail_closed_at_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            gate.sys, "stderr", io.StringIO(),
        ):
            root = Path(temporary)
            malformed = root / "malformed.csv"
            malformed.write_text("wrong\nvalue\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                gate.read_csv_dicts(malformed, ["required"])
            with self.assertRaises(SystemExit):
                gate.gate_context(root)
            with patch.object(
                gate, "materialize_report_publication_committed_snapshot",
                return_value={"snapshot_destinations": []},
            ):
                with self.assertRaises(SystemExit):
                    gate.gate_binary_final_report(root)
            with patch.object(
                gate, "materialize_report_publication_committed_snapshot",
                return_value={
                    "committed_receipt_identity": "wrong",
                    "snapshot_destinations": [],
                },
            ):
                with self.assertRaises(SystemExit):
                    gate._load_current_step4_api_rows(root, "expected")

    def test_main_executes_real_binary_gate_dispatch_and_candidate_failures(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            gate.sys, "stderr", io.StringIO(),
        ):
            root = Path(temporary)
            for step in ("binary_generation", "binary_report"):
                with self.subTest(step=step), patch.object(
                    gate.sys, "argv", [
                        "gate.py", "--step", step, "--report-dir", str(root),
                    ],
                ):
                    with self.assertRaises(SystemExit):
                        gate.main()

            candidate_args = [
                "--report-dir", str(root),
                "--publication-transaction-id", "1" * 32,
                "--publication-binding-json", "{}",
                "--publication-content-identity", "2" * 64,
            ]
            with patch.object(
                gate.sys, "argv", [
                    "gate.py", "--step", "binary_generation",
                    *candidate_args,
                    "--candidate-activation-identity", "",
                ],
            ), patch.object(
                gate, "materialize_report_publication_gate_candidate",
                return_value={"candidate_destinations": []},
            ):
                with self.assertRaises(SystemExit):
                    gate.main()

            with patch.object(
                gate.sys, "argv", [
                    "gate.py", "--step", "binary_report", *candidate_args,
                ],
            ), patch.object(
                gate, "materialize_report_publication_gate_candidate",
                return_value={
                    "candidate_destinations": ["call", "analysis", "index"],
                },
            ):
                with self.assertRaises(SystemExit):
                    gate.main()


class QueryRenderingContractTest(unittest.TestCase):
    def test_coordinate_projection_and_query_rendering_are_unambiguous(self):
        self.assertEqual(s5_query_call_chain._coord_ga("g:a:test-fixtures"), "g:a")
        self.assertEqual(s5_query_call_chain._coord_ga("broken"), "")
        self.assertEqual(
            s5_query_call_chain.render_query_result({
                "chains": ["entry → target"], "warnings": ["候选结果"],
            }),
            "找到 1 条调用链：\n\n1. entry → target\n\n候选结果",
        )
        self.assertEqual(
            s5_query_call_chain.render_query_result({"chains": [], "warnings": ["未找到"]}),
            "未找到",
        )
        self.assertEqual(
            s5_query_call_chain.render_query_result({"chains": [], "warnings": []}),
            "未找到精确匹配的调用链。",
        )


if __name__ == "__main__":
    unittest.main()
