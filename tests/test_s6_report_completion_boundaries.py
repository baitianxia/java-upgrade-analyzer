from __future__ import annotations

import copy
import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import s6_report


class Step6ReportCompletionBoundaryTest(unittest.TestCase):
    @staticmethod
    def _step5_item(
        name,
        *,
        coord="g:a",
        severity="P2",
        conclusion="",
        reason_code="SYSTEM_CODE_REACHED",
        **extra,
    ):
        return {
            "api_identity": f"api-{name}",
            "reported_api_identity": f"reported-{name}",
            "change_fact_identity": f"fact-{name}",
            "decision_identity": f"decision-{name}",
            "coord": coord,
            "api": f"demo.{name}.call",
            "api_signature": "()V",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "severity": severity,
            "old_version": "1",
            "new_version": "2",
            "reason_code": reason_code,
            "reason": f"reason-{name}",
            "user_conclusion": conclusion,
            "user_reason": f"user-reason-{name}",
            "recommended_action": f"action-{name}",
            "key_evidence": f"evidence-{name}",
            "call_paths": [f"app.Entry.start -> demo.{name}.call"],
            "dependency_chain_coords": [coord] if coord else [],
            "verification": [f"verify-{name}"],
            **extra,
        }

    @classmethod
    def _rich_findings(cls):
        confirmed = []
        for index in range(12):
            severity = ("P0", "P1", "P2", "")[index % 4]
            confirmed.append(
                cls._step5_item(
                    f"confirmed_{index}",
                    coord=f"g:dep{index % 8}",
                    severity=severity,
                    conclusion="已确认影响",
                    old_value="old" if index == 0 else "",
                    new_value="new" if index == 0 else "",
                    direct_callers=index,
                    business_reach_depth=index % 3,
                )
            )
        probable = [
            cls._step5_item(
                "probable",
                coord="g:dep0",
                conclusion="可能影响",
                reason_code="BEHAVIOR_CHANGED_RUNTIME_VERIFICATION",
            )
        ]
        uncertain = [
            cls._step5_item(
                "uncertain_candidate",
                coord="g:dep1",
                uncertainty_kind=s6_report.UNCERTAINTY_KIND_CANDIDATE_EVIDENCE,
                reason_code="LOW_CONFIDENCE_EDGE",
                priority_score=9,
                priority_factors={"business": 3},
            ),
            cls._step5_item(
                "uncertain_limit",
                coord="g:dep2",
                uncertainty_kind=s6_report.UNCERTAINTY_KIND_ANALYSIS_LIMITATION,
                reason_code="CALL_GRAPH_LIMITATION_SYMBOL_KIND",
                call_paths=[],
                evidence_paths=[],
            ),
        ]
        not_impacted = [
            cls._step5_item(
                "preserved",
                coord="g:dep3",
                conclusion="已确认不受影响",
                reason_code="PACKAGED_DEPENDENCY_BYTECODE_USAGE",
            )
        ]
        needs_input = [
            cls._step5_item(
                "needs_input",
                coord="g:dep4",
                conclusion="需要补充输入",
                reason_code="MISSING_DEPENDENCY_SOURCE_MAPPING",
            )
        ]
        incomplete = [
            cls._step5_item(
                "incomplete",
                coord="g:dep5",
                conclusion="本次未完成分析",
                reason_code="ANALYSIS_INCOMPLETE",
            )
        ]
        not_found = [
            cls._step5_item(
                "not_found",
                coord="g:dep6",
                conclusion="未发现调用路径",
                reason_code="NO_STATIC_PATH",
            )
        ]
        all_results = [
            *confirmed,
            *probable,
            *uncertain,
            *not_impacted,
            *needs_input,
            *incomplete,
            *not_found,
        ]

        alert_rows = []
        for index, item in enumerate(all_results):
            if item in confirmed:
                status = "reachable"
            elif item in probable:
                status = "uncertain"
            elif item in uncertain:
                status = "uncertain"
            elif item in not_impacted:
                status = "not_impacted"
            elif item in not_found:
                status = "not_found_in_static_analysis"
            else:
                status = "not_analyzed"
            alert_rows.append({
                "api_identity": item["api_identity"],
                "reported_api_identity": item["reported_api_identity"],
                "change_fact_identity": item["change_fact_identity"],
                "decision_identity": item["decision_identity"],
                "target_coord": item["coord"],
                "changed_symbol": item["api"],
                "api_signature": item["api_signature"],
                "symbol_kind": item["symbol_kind"],
                "change_type": item["change_type"],
                "severity": item.get("severity", ""),
                "old_version": item["old_version"],
                "new_version": item["new_version"],
                "path_status": status,
                "business_entry": f"app.Entry{index}.start",
                "path_text": f"app.Entry{index}.start -> {item['api']}",
                "path_occurrence_count": str(index % 3 + 1),
                "evidence_files": f"module-{index % 6}/src/main/java/App.java|lib/dep{index}.jar",
                "review_focus": f"focus-{index}",
                "review_reason": item["reason_code"],
            })
        # Confirmed rows may also carry lower-certainty evidence; this must not
        # erase their exact reachable relationship.
        alert_rows.extend([
            {
                **alert_rows[0],
                "path_status": "uncertain",
                "path_text": "app.Entry0.start -> proxy -> demo.confirmed_0.call",
                "path_occurrence_count": "4",
            },
            {
                **alert_rows[1],
                "path_status": "not_analyzed",
                "path_text": "app.Entry1.start -> reflective -> demo.confirmed_1.call",
            },
        ])
        overview = s6_report.build_impact_overview(alert_rows)

        inventory = [dict(item) for item in all_results]
        inventory.extend([
            {**confirmed[0], "new_version": "3", "severity": "P2"},
            {
                "coord": "",
                "api_name": "identity.missing",
                "api_signature": "()V",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
            },
        ])
        dependencies = [
            {
                "coord": f"g:dep{index}",
                "old_version": "1",
                "new_version": "2",
                "change_type": "major" if index % 2 == 0 else "minor",
            }
            for index in range(8)
        ]
        dependencies.extend([
            {**dependencies[0], "new_version": "4", "change_type": "changed"},
            {"coord": "", "old_version": "1", "new_version": "2"},
        ])
        impacted_dependencies = []
        for index in range(8):
            impacted_dependencies.append({
                **dependencies[index],
                "p0": 1 if index < 3 else 0,
                "p1": 1 if 3 <= index < 6 else 0,
                "p2": 1 if index >= 6 else 0,
                "uncertain": 1 if index in {1, 2} else 0,
                "probable_impact": 1 if index == 0 else 0,
                "needs_input": 1 if index == 4 else 0,
                "not_analyzed": 1 if index == 5 else 0,
                "not_found": 1 if index == 6 else 0,
                "api_count": 2,
                "apis": [f"demo.Api{index}.call"],
                "reaches_system_source": index % 2 == 0,
                "final_status": "reachable" if index % 2 == 0 else "blocked",
                "blocked_at": "" if index % 2 == 0 else "source",
                "blocked_reason": "" if index % 2 == 0 else "missing",
                "evidence_level": "exact" if index % 2 == 0 else "candidate",
                "selected_api": f"demo.Api{index}.call",
            })
        per_dependency = [
            {
                **dependencies[index],
                "reaches_system_source": index % 2 == 0,
                "final_status": "reachable" if index % 2 == 0 else "blocked",
                "blocked_at": "" if index % 2 == 0 else "source",
                "blocked_reason": "" if index % 2 == 0 else "missing",
                "evidence_level": "exact" if index % 2 == 0 else "candidate",
                "selected_api": f"demo.Api{index}.call",
                "step4": {"changed_api_count": 2},
                "step5": {"sample_results": []},
            }
            for index in range(8)
        ]
        diagnostics = [
            {
                "artifact": artifact,
                "stage": stage,
                "path": f"/tmp/{artifact}-{index}.json",
                "error_type": error_type,
                "message": f"failure-{index}",
            }
            for index, (artifact, stage, error_type) in enumerate((
                ("call_chain_summary", "json_contract", "ArtifactContentError"),
                ("call_chain_alerts", "row_contract", "ArtifactContentError"),
                ("changed_apis", "identity_consistency", "ArtifactContentError"),
                ("coverage", "json_missing", "FileNotFoundError"),
                ("step5_selection", "json_load", "JSONDecodeError"),
                ("context", "json_load", "UnicodeDecodeError"),
                ("dependency_changes", "csv_load", "Error"),
                ("call_chain_by_api:a.json", "json_load", "OSError"),
                ("call_chain_by_module:app.json", "json_contract", "JSONRootTypeError"),
                ("other", "json_load", "PermissionError"),
                ("other", "json_load", "UnknownError"),
            ))
        ]
        guidance = [
            {
                "reason_code": "BYTECODE_CALLER_UNRESOLVED",
                "origin_step": "step5",
                "observed_scope": "api",
                "potentially_affected_api_count": 2,
                "primary_reason_api_count": 1,
                "failure_record_count": 2,
                "failure_occurrence_count": 4,
                "raw_blocking_failure_count": 2,
                "relevant_blocking_failure_count": 1,
                "blocking": True,
                "affected_classes": ["demo.A", "demo.B"],
                "affected_artifacts": ["/repo/build/app.jar"],
                "affected_artifact_entries": ["demo/A.class"],
                "collectors": ["asm"],
                "candidate_evidence": [{
                    "coord": "g:dep0",
                    "artifact": "/repo/lib/dep.jar",
                    "artifact_entry": "demo/A.class",
                    "bytecode_sha256": "a" * 64,
                }],
                "source_components": ["business_reachability"],
                "evidence_files": ["evidence/call_chain/bytecode.json"],
                "sample_apis": ["demo.A.call", "demo.B.call"],
            },
            {
                "reason_code": "INCOMPLETE_EVIDENCE_COVERAGE",
                "origin_step": "step4",
                "observed_scope": "global",
                "potentially_affected_api_count": 0,
                "primary_reason_api_count": 0,
                "failure_record_count": 1,
                "failure_occurrence_count": 1,
                "blocking": True,
                "affected_classes": [],
                "affected_artifacts": [],
                "affected_artifact_entries": [],
                "collectors": [],
                "candidate_evidence": [],
                "source_components": ["artifact_bytecode_dependencies"],
                "evidence_file": "evidence/coverage.json",
                "sample_apis": [],
            },
            {
                "reason_code": "UNKNOWN_REASON",
                "origin_step": "unknown",
                "observed_scope": "step",
                "affected_api_count": 0,
                "observed_failure_count": 0,
                "blocking": False,
            },
        ]
        return {
            "generated_at": "2026-08-23T12:00:00",
            "context": {
                "jdk": "8 → 17",
                "springboot": "2.7 → 3.2",
                "build_tool": "maven",
                "jdk_upgraded": True,
                "sb_major": True,
                "tech_flags": ["spring", "mybatis"],
            },
            "scan_stats": {
                "call_chain_status": "done",
                "call_chain_total": len(all_results),
                "call_chain_reachable": len(confirmed),
                "call_chain_uncertain": len(uncertain),
                "call_chain_not_analyzed": len(incomplete),
                "call_chain_not_found_in_static_analysis": len(not_found),
                "alerts_raw_record_count": overview["record_count"] + 2,
                "changed_apis_total": len(inventory),
                "jdk_removed_api": 2,
                "jdk_javax_refs": 3,
                "jdk_internal_api": 1,
                "jdk_reflection": 4,
                "jdk_serialization": 5,
                "sb_config": 6,
                "sb_autoconfig": 7,
                "dep_compat": 3,
                "database_contract_changes": 2,
            },
            "coverage": {
                "overall_status": "partial",
                "critical_incomplete": ["business_reachability"],
                "components": [
                    {
                        "id": "business_reachability",
                        "status": "partial",
                        "reason_codes": ["CALL_GRAPH_TRUNCATED"],
                        "evidence": ["evidence/call_chain/alerts.csv"],
                    },
                    {
                        "id": "project_scope",
                        "status": "complete",
                        "reason_codes": [],
                        "evidence": [],
                    },
                ],
            },
            "analysis_scope": {
                "mode": "full",
                "validation_status": "valid",
                "available_dependency_count": 8,
                "included_dependency_count": 8,
                "total_api_count": len(all_results),
                "analyzed_api_count": len(all_results),
                "included_dependency_coords": [f"g:dep{i}" for i in range(8)],
                "excluded_dependency_coords": [],
                "selected_names": [f"g:dep{i}" for i in range(8)],
            },
            "call_chain_target_count": len(all_results),
            "p0": [item for item in confirmed if item.get("severity") == "P0"],
            "p1": [item for item in confirmed if item.get("severity") == "P1"],
            "p2": [item for item in confirmed if item.get("severity") not in {"P0", "P1"}],
            "probable_impact": probable,
            "uncertain": uncertain,
            "not_impacted": not_impacted,
            "needs_input": needs_input,
            "not_analyzed": [*needs_input, *incomplete],
            "not_found": not_found,
            "impact_overview": overview,
            "impacted_dependencies": impacted_dependencies,
            "per_dependency_results": per_dependency,
            "dependency_changes": dependencies,
            "dep_changes_summary": {"major": 4, "minor": 4, "unknown": 2},
            "changed_api_inventory": inventory,
            "module_impacts": {
                "app": {"p0": 2, "p1": 2, "p2": 2, "uncertain": 1},
                "core": {"p0": 1, "p1": 1, "p2": 1, "not_found": 1},
            },
            "dep_compat_summary": {
                "total": 3,
                "compile_scope": 2,
                "by_type": {"binary": 2, "source": 1},
                "top_coords": [("g:dep0", 2), ("g:dep1", 1)],
                "top_rows": [{"坐标": "g:dep0", "风险类型": "binary"}],
                "impacted_total": 2,
                "impacted_by_type": {"binary": 2},
                "impacted_coords": [("g:dep0", 2)],
            },
            "background_signals": {
                "dep_compat_total": 1,
                "dep_compat_top_coords": [("g:other", 1)],
            },
            "database_contract": {
                "schema": "java-upgrade-analyzer.database-contract-changes.v1",
                "coverage_status": "partial",
                "coverage_gaps": ["dynamic_sql"],
                "dependency_count": 2,
                "change_count": 2,
                "rows": [
                    {
                        "依赖包": "g:dep0",
                        "变化类型": "removed",
                        "契约类型": "table",
                        "可信度": "high",
                        "表": "orders",
                        "列": "id",
                        "契约位置": "schema.sql",
                        "语句或字段": "drop table",
                        "人工复核建议": "review",
                    },
                    {
                        "依赖包": "g:dep1",
                        "变化类型": "changed",
                        "契约类型": "column",
                        "可信度": "medium",
                        "表": "users",
                        "列": "name",
                        "契约位置": "mapper.xml",
                        "语句或字段": "select",
                        "人工复核建议": "test",
                    },
                ],
            },
            "diagnostics": diagnostics,
            "diagnostic_guidance": guidance,
            "uncertain_reason_summary": {"LOW_CONFIDENCE_EDGE": 1},
            "uncertainty_kind_summary": {
                s6_report.UNCERTAINTY_KIND_CANDIDATE_EVIDENCE: 1,
                s6_report.UNCERTAINTY_KIND_ANALYSIS_LIMITATION: 1,
            },
            "not_analyzed_reason_summary": {"ANALYSIS_INCOMPLETE": 1},
            "not_found_reason_summary": {"NO_STATIC_PATH": 1},
            "user_conclusion_summary": {"confirmed_impact": len(confirmed)},
            "artifacts": {
                "alerts_csv": "evidence/call_chain/alerts.csv",
                "dependency_changes_csv": "evidence/dependencies/dep_changes.csv",
                "database_contract_review_md": "evidence/static_scan/database.md",
                "database_contract_csv": "evidence/static_scan/database.csv",
                "changed_apis_csv": "evidence/api_changes/all_changed_apis.csv",
                "binary_change_review_md": "evidence/api_changes/binary-review.md",
                "source_analysis_review_md": "evidence/source/review.md",
                "build_provenance_json": "evidence/dependencies/build.json",
                "analysis_scope_md": "deliverables/analysis-scope.md",
                "diagnostic_detail_md": "deliverables/analysis-diagnostics.md",
                "confirmed_detail_csv": "deliverables/s6_confirmed_impact_apis.csv",
                "confirmed_detail_md": "deliverables/s6_confirmed_impact_apis.md",
                "uncertain_detail_csv": "deliverables/s6_uncertain_apis.csv",
                "uncertain_detail_md": "deliverables/s6_uncertain_apis.md",
            },
            "available_evidence_paths": [
                "evidence/call_chain/alerts.csv",
                "evidence/static_scan/database.csv",
            ],
        }

    def test_uncertainty_and_step5_fallback_complete_matrix(self):
        candidate = s6_report.UNCERTAINTY_KIND_CANDIDATE_EVIDENCE
        limitation = s6_report.UNCERTAINTY_KIND_ANALYSIS_LIMITATION
        cases = (
            (None, limitation),
            ({"uncertainty_kind": candidate}, candidate),
            ({"uncertainty_kind": limitation}, limitation),
            ({"uncertainty_kind": "future", "call_paths": ["", "A -> B"]}, candidate),
            ({"evidence_paths": [{"path": "A"}]}, candidate),
            ({"evidence_paths": [[{}, {"path": "A"}]]}, candidate),
            ({"evidence_paths": [[{}, "A"]]}, candidate),
            ({"path_details": [None, {"path_text": "A -> B"}]}, candidate),
            ({"path_details": [{"evidence": [{"path": "A"}]}]}, candidate),
            ({"path_details": [{"path_text": "", "evidence": []}]}, limitation),
        )
        for payload, expected in cases:
            with self.subTest(payload=payload):
                self.assertEqual(s6_report._uncertainty_kind(payload), expected)

        evidence_cases = (
            (None, False),
            ([], False),
            ([{}], False),
            ([[{}]], False),
            ([["", None]], False),
            ([{"value": 0}], True),
            ([[{"value": False}]], True),
            ([["evidence"]], True),
        )
        for payload, expected in evidence_cases:
            with self.subTest(evidence=payload):
                self.assertEqual(
                    s6_report._has_uncertain_evidence_items(payload), expected
                )
        self.assertEqual(
            dict(s6_report._uncertainty_counts([{}, {"call_paths": ["A"]}])),
            {limitation: 1, candidate: 1},
        )

        self.assertEqual(s6_report._step5_summary_coverage_fallback(None), {})
        self.assertEqual(
            s6_report._step5_summary_coverage_fallback(
                {"meta": {"graph_stats": "invalid"}}
            ),
            {},
        )

        rich_stats = {
            "truncated": True,
            "truncation_reasons": ("node_cap", "depth_cap"),
            "edge_cap_hits": 2,
            "parser_fallback_reasons": {"java": 1},
            "source_artifact_alignment": {
                "status": "partial",
                "reason_codes": ["SOURCE_MISMATCH"],
                "artifact_path": "",
                "git_root": "/repo",
            },
            "artifact_bytecode": {
                "status": "unknown",
                "reason_codes": ["BYTECODE_MISSING"],
            },
            "business_bytecode": {
                "status": "partial",
                "failures": ["parse_failed"],
            },
            "indirect_usage": {
                "status": "partial",
                "reason_codes": ["REFLECTION"],
            },
        }
        partial = s6_report._step5_summary_coverage_fallback(
            {"total_apis": "2", "not_impacted": "0", "meta": {"graph_stats": rich_stats}}
        )
        self.assertEqual(partial["overall_status"], "partial")
        self.assertEqual(
            {item["id"] for item in partial["components"]},
            {
                "business_reachability",
                "source_artifact_alignment",
                "artifact_bytecode_dependencies",
                "business_bytecode_graph",
                "indirect_usage_matrix",
            },
        )
        self.assertIn("business_reachability", partial["critical_incomplete"])
        self.assertNotIn("business_bytecode_graph", partial["critical_incomplete"])

        preserved = s6_report._step5_summary_coverage_fallback(
            {
                "total_apis": 2,
                "not_impacted": 2,
                "meta": {
                    "graph_stats": {
                        **rich_stats,
                        "truncated": False,
                        "truncation_reasons": "invalid",
                        "edge_cap_hits": 0,
                        "parser_fallback_reasons": {},
                        "artifact_bytecode": {
                            "status": "complete",
                            "reason_codes": [],
                        },
                    }
                },
            }
        )
        self.assertEqual(preserved["overall_status"], "complete")
        self.assertEqual(preserved["critical_incomplete"], [])
        self.assertTrue(
            all(
                item["status"] == "not_applicable"
                for item in preserved["components"]
                if item["id"] != "artifact_bytecode_dependencies"
            )
        )

        unknown = s6_report._step5_summary_coverage_fallback(
            {
                "total_apis": object(),
                "meta": {
                    "graph_stats": {
                        "business_bytecode": {"status": "unknown"},
                    }
                },
            }
        )
        self.assertEqual(unknown["overall_status"], "unknown")

    def test_json_csv_loaders_and_contract_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.json"
            diagnostics = []
            self.assertEqual(s6_report.load_json(missing), {})
            self.assertEqual(
                s6_report.load_json(
                    missing,
                    diagnostics=diagnostics,
                    artifact="required_json",
                    required=True,
                ),
                {},
            )
            self.assertEqual(diagnostics[-1]["stage"], "json_missing")

            object_path = root / "object.json"
            object_path.write_text('{"value": 1}', encoding="utf-8")
            self.assertEqual(s6_report.load_json(object_path), {"value": 1})
            list_path = root / "list.json"
            list_path.write_text("[]", encoding="utf-8")
            self.assertEqual(
                s6_report.load_json(
                    list_path,
                    diagnostics=diagnostics,
                    artifact="list_json",
                ),
                {},
            )
            self.assertEqual(diagnostics[-1]["stage"], "json_contract")
            broken_path = root / "broken.json"
            broken_path.write_text("{", encoding="utf-8")
            self.assertEqual(
                s6_report.load_json(
                    broken_path,
                    diagnostics=diagnostics,
                    artifact="broken_json",
                ),
                {},
            )
            self.assertEqual(diagnostics[-1]["stage"], "json_load")
            with patch.object(
                s6_report, "open_text", side_effect=OSError("unreadable")
            ):
                self.assertEqual(
                    s6_report.load_json(
                        object_path,
                        diagnostics=diagnostics,
                        artifact="unreadable_json",
                    ),
                    {},
                )

            self.assertEqual(
                s6_report._normalize_csv_dict_row({" name ": " value "}),
                {" name ": "value"},
            )
            with self.assertRaises(s6_report.ArtifactContentError):
                s6_report._normalize_csv_dict_row({None: "overflow"})
            with self.assertRaises(s6_report.ArtifactContentError):
                s6_report._normalize_csv_dict_row({"name": 1})

            missing_csv = root / "missing.csv"
            self.assertEqual(s6_report.load_csv(missing_csv), [])
            self.assertEqual(
                s6_report.load_csv(
                    missing_csv,
                    diagnostics=diagnostics,
                    artifact="required_csv",
                    required=True,
                ),
                [],
            )
            self.assertEqual(diagnostics[-1]["stage"], "csv_missing")
            self.assertEqual(
                list(
                    s6_report.iter_csv_rows(
                        missing_csv,
                        diagnostics=diagnostics,
                        artifact="required_stream",
                        required=True,
                    )
                ),
                [],
            )
            self.assertEqual(diagnostics[-1]["stage"], "csv_missing")

            valid_csv = root / "valid.csv"
            valid_csv.write_text("name,value\n alpha , 1 \n,\n", encoding="utf-8")
            self.assertEqual(
                s6_report.load_csv(valid_csv),
                [{"name": "alpha", "value": "1"}, {"name": "", "value": ""}],
            )
            self.assertEqual(
                list(s6_report.iter_csv_rows(valid_csv)),
                [{"name": "alpha", "value": "1"}, {"name": "", "value": ""}],
            )

            overflow_csv = root / "overflow.csv"
            overflow_csv.write_text("name\na,b\n", encoding="utf-8")
            self.assertEqual(
                s6_report.load_csv(
                    overflow_csv,
                    diagnostics=diagnostics,
                    artifact="overflow",
                ),
                [],
            )
            self.assertEqual(diagnostics[-1]["stage"], "csv_load")
            self.assertEqual(
                list(
                    s6_report.iter_csv_rows(
                        overflow_csv,
                        diagnostics=diagnostics,
                        artifact="overflow_stream",
                    )
                ),
                [],
            )
            self.assertEqual(diagnostics[-1]["stage"], "csv_stream")

            no_header = root / "no-header.csv"
            no_header.write_text("", encoding="utf-8")
            s6_report._validate_csv_contract(
                no_header,
                diagnostics=diagnostics,
                artifact="no_header",
                required_column_groups=({"name"},),
            )
            self.assertEqual(diagnostics[-1]["stage"], "csv_contract")
            missing_column = root / "missing-column.csv"
            missing_column.write_text("other\nvalue\n", encoding="utf-8")
            s6_report._validate_csv_contract(
                missing_column,
                diagnostics=diagnostics,
                artifact="missing_column",
                required_column_groups=({"name", "alias"},),
            )
            self.assertEqual(diagnostics[-1]["stage"], "csv_contract")
            empty_data = root / "empty-data.csv"
            empty_data.write_text("name\n\n", encoding="utf-8")
            s6_report._validate_csv_contract(
                empty_data,
                diagnostics=diagnostics,
                artifact="empty_data",
                required_column_groups=({"name"},),
                require_data=True,
            )
            self.assertEqual(diagnostics[-1]["stage"], "csv_contract")
            before = len(diagnostics)
            s6_report._validate_csv_contract(
                valid_csv,
                diagnostics=diagnostics,
                artifact="valid",
                required_column_groups=({"name"}, {"value"}),
                require_data=True,
            )
            s6_report._validate_csv_contract(
                root / "absent.csv",
                diagnostics=diagnostics,
                artifact="absent",
                required_column_groups=({"name"},),
            )
            self.assertEqual(len(diagnostics), before)

            duplicate = []
            s6_report._record_content_diagnostic(
                duplicate,
                artifact="artifact",
                stage="stage",
                path=valid_csv,
                message="first",
            )
            s6_report._record_content_diagnostic(
                duplicate,
                artifact="artifact",
                stage="stage",
                path=valid_csv,
                message="second",
            )
            self.assertEqual(len(duplicate), 1)
            s6_report._record_diagnostic(
                None,
                artifact="ignored",
                stage="ignored",
                path=valid_csv,
                error=ValueError("ignored"),
            )

    def test_call_summary_contract_invalid_and_valid_matrices(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.json"
            path.write_text("{}", encoding="utf-8")

            diagnostics = []
            s6_report._validate_call_summary_contract(
                Path(tmp) / "missing.json", {}, diagnostics
            )
            self.assertEqual(diagnostics, [])
            for prior_stage in ("json_load", "json_contract", "json_missing"):
                prior = [{"artifact": "call_chain_summary", "stage": prior_stage}]
                s6_report._validate_call_summary_contract(path, {}, prior)
                self.assertEqual(len(prior), 1)

            invalid_guidance = {
                "reason_code": 7,
                "origin_step": "step9",
                "title": 7,
                "trigger_condition": 7,
                "semantic_impact": 7,
                "observed_scope": "elsewhere",
                "affected_classes": "not-a-list",
                "affected_artifacts": [" ok ", 7, ""],
                "affected_artifact_entries": None,
                "collectors": [7],
                "failure_detail_summaries": {},
                "source_components": [" source "],
                "sample_apis": [None],
                "repair_actions": [" repair "],
                "verification_steps": [" verify ", 8],
                "candidate_evidence": [
                    None,
                    {
                        "coord": 1,
                        "artifact": 2,
                        "artifact_entry": 3,
                        "bytecode_sha256": 4,
                    },
                ],
                "affected_api_count": -1,
                "primary_reason_api_count": "bad",
                "potentially_affected_api_count": None,
                "observed_failure_count": True,
                "failure_record_count": -2,
                "failure_occurrence_count": "bad",
                "raw_blocking_failure_count": -3,
                "relevant_blocking_failure_count": object(),
                "blocking": "yes",
            }
            invalid_item = {
                "id": "same",
                "coord": 7,
                "api": 8,
                "api_name": 9,
                "api_signature": 10,
                "symbol_kind": 11,
                "change_type": 12,
                "severity": 13,
                "old_version": 14,
                "new_version": 15,
                "reason_code": 16,
                "reason": 17,
                "user_conclusion": 18,
                "user_reason": 19,
                "key_evidence": 20,
                "business_entry": 21,
                "impact_mode": 22,
                "call_paths": "not-a-list",
                "dependency_chain_coords": ["ok", 1],
                "verification": [2],
            }
            invalid = {
                "status": 7,
                "total_apis": -1,
                "reachable": "bad",
                "reachable_apis": [invalid_item, None],
                "not_impacted_apis": "not-a-list",
                "uncertain_apis": [{"id": "same"}],
                "not_analyzed_apis": [{"id": "incomplete"}],
                "not_found_apis": [],
                "user_conclusion_summary": {"已确认影响": 1, "confirmed_impact": 1},
                "graph_stats": "invalid",
                "meta": {"graph_stats": {
                    "parser_fallback_reasons": [],
                    "source_artifact_alignment": [],
                    "artifact_bytecode": [],
                    "business_bytecode": [],
                    "indirect_usage": [],
                    "truncation_reasons": "bad",
                }},
                "diagnostic_guidance": [None, invalid_guidance],
            }
            diagnostics = []
            with patch.object(
                s6_report,
                "build_api_identity_key",
                side_effect=lambda item: (str((item or {}).get("id") or ""),),
            ), patch.object(
                s6_report,
                "_identity_is_complete",
                side_effect=lambda identity: bool(identity[0] and identity[0] != "incomplete"),
            ):
                s6_report._validate_call_summary_contract(path, invalid, diagnostics)
            self.assertTrue(diagnostics)
            self.assertEqual(invalid["status"], 7)
            self.assertEqual(invalid["not_impacted_apis"], [])
            self.assertEqual(invalid["meta"]["graph_stats"]["truncation_reasons"], [])
            self.assertEqual(invalid["diagnostic_guidance"][0]["origin_step"], "unknown")
            self.assertFalse(invalid["diagnostic_guidance"][0]["blocking"])

            status_cases = (
                ({}, "missing"),
                ({"status": "future"}, "future"),
                ({"status": "skipped", "skip_reason": "other"}, "skip-reason"),
                ({
                    "status": "skipped",
                    "skip_reason": "no_changed_apis",
                    "total_apis": 1,
                    "reachable": 1,
                    "reachable_apis": [{"id": "a"}],
                }, "invalid-skip"),
            )
            for payload, label in status_cases:
                with self.subTest(status=label), patch.object(
                    s6_report,
                    "build_api_identity_key",
                    side_effect=lambda item: (str((item or {}).get("id") or ""),),
                ), patch.object(
                    s6_report,
                    "_identity_is_complete",
                    side_effect=lambda identity: bool(identity[0]),
                ):
                    case = {
                        "reachable_apis": [],
                        "not_impacted_apis": [],
                        "uncertain_apis": [],
                        "not_analyzed_apis": [],
                        "not_found_apis": [],
                        **payload,
                    }
                    case_diagnostics = []
                    s6_report._validate_call_summary_contract(path, case, case_diagnostics)
                    self.assertTrue(case_diagnostics)
                    if label == "invalid-skip":
                        self.assertEqual(case["total_apis"], 0)
                        self.assertEqual(case["reachable_apis"], [])

            valid_item = {
                "id": "valid",
                "coord": "g:a",
                "api": "a.C.m",
                "api_signature": "()V",
                "symbol_kind": "method",
                "change_type": "removed",
                "call_paths": ["A -> B"],
                "dependency_chain_coords": ["g:a"],
                "verification": ["run probe"],
            }
            valid = {
                "status": "done",
                "total_apis": 1,
                "reachable": 1,
                "reachable_apis": [valid_item],
                "not_impacted": 0,
                "not_impacted_apis": [],
                "uncertain": 0,
                "uncertain_apis": [],
                "not_analyzed": 0,
                "not_analyzed_apis": [],
                "not_found_in_static_analysis": 0,
                "not_found_apis": [],
                "user_conclusion_summary": {"confirmed_impact": 1},
                "meta": {"graph_stats": {"truncation_reasons": []}},
                "diagnostic_guidance": [{
                    "reason_code": "VALID_REASON",
                    "origin_step": "step5",
                    "observed_scope": "api",
                    "affected_classes": ["a.C"],
                    "affected_artifacts": [],
                    "affected_artifact_entries": [],
                    "collectors": [],
                    "failure_detail_summaries": [],
                    "source_components": [],
                    "sample_apis": [],
                    "repair_actions": [],
                    "verification_steps": [],
                    "candidate_evidence": [{"coord": "g:a"}],
                    "affected_api_count": 1,
                    "blocking": True,
                }],
            }
            diagnostics = []
            with patch.object(
                s6_report, "build_api_identity_key", return_value=("valid",)
            ), patch.object(s6_report, "_identity_is_complete", return_value=True):
                s6_report._validate_call_summary_contract(path, valid, diagnostics)
            self.assertEqual(diagnostics, [])

    def test_coverage_scope_and_context_contract_matrices(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "contract.json"
            path.write_text("{}", encoding="utf-8")

            coverage = {
                "overall_status": 7,
                "critical_incomplete": [" bad ", 7, ""],
                "components": [
                    None,
                    {},
                    {
                        "id": " component ",
                        "status": "future",
                        "reason_codes": "bad",
                        "evidence": [" evidence ", 7, ""],
                    },
                    {
                        "id": "complete_but_critical",
                        "status": "complete",
                    },
                ],
            }
            diagnostics = []
            s6_report._validate_coverage_contract(path, coverage, diagnostics)
            self.assertTrue(diagnostics)
            self.assertEqual(coverage["overall_status"], "unknown")
            self.assertEqual(coverage["critical_incomplete"], ["bad"])
            self.assertEqual(coverage["components"][0]["id"], "component")
            self.assertEqual(coverage["components"][0]["status"], "unknown")

            conflict = {
                "overall_status": "complete",
                "critical_incomplete": ["done", "partial"],
                "components": [
                    {"id": "done", "status": "complete"},
                    {"id": "partial", "status": "partial"},
                ],
            }
            conflict_diagnostics = []
            s6_report._validate_coverage_contract(path, conflict, conflict_diagnostics)
            self.assertEqual(conflict["overall_status"], "partial")
            self.assertTrue(conflict_diagnostics)

            for prior in (
                [{"artifact": "coverage", "stage": "json_contract"}],
                [],
            ):
                before = len(prior)
                s6_report._validate_coverage_contract(
                    Path(tmp) / "missing.json", {}, prior
                )
                self.assertEqual(len(prior), before)

            scope = {
                "mode": "partial",
                "available_dependency_count": 2,
                "included_dependency_count": 3,
                "total_api_count": "bad",
                "analyzed_api_count": -1,
                "included_dependency_coords": [" a ", "a", 7, ""],
                "excluded_dependency_coords": ["a", " b "],
                "selected_names": "bad",
            }
            scope_diagnostics = []
            s6_report._validate_analysis_scope_contract(path, scope, scope_diagnostics)
            self.assertTrue(scope_diagnostics)
            self.assertEqual(scope["validation_status"], "invalid")
            self.assertEqual(scope["available_dependency_count"], 0)

            full_bad = {
                "mode": "full",
                "available_dependency_count": 2,
                "included_dependency_count": 1,
                "total_api_count": 0,
                "analyzed_api_count": 0,
                "included_dependency_coords": ["a"],
                "excluded_dependency_coords": ["b"],
                "selected_names": [],
            }
            full_diagnostics = []
            s6_report._validate_analysis_scope_contract(
                path, full_bad, full_diagnostics
            )
            self.assertTrue(full_diagnostics)

            valid_scope = {
                "mode": "partial",
                "available_dependency_count": 2,
                "included_dependency_count": 1,
                "total_api_count": 1,
                "analyzed_api_count": 1,
                "included_dependency_coords": ["a"],
                "excluded_dependency_coords": ["b"],
                "selected_names": ["a"],
            }
            valid_scope_diagnostics = []
            s6_report._validate_analysis_scope_contract(
                path, valid_scope, valid_scope_diagnostics
            )
            self.assertEqual(valid_scope_diagnostics, [])

            context = {
                "jdk_base": 8,
                "jdk_current": "17",
                "springboot_base": None,
                "springboot_current": 3,
                "build_tool": [],
                "jdk_upgraded": "yes",
                "springboot_major_upgrade": 1,
                "tech_flags": {"valid": True, 7: False, "bad": "yes"},
            }
            context_diagnostics = []
            s6_report._validate_context_contract(path, context, context_diagnostics)
            self.assertTrue(context_diagnostics)
            self.assertEqual(context["jdk_base"], "")
            self.assertFalse(context["jdk_upgraded"])
            self.assertEqual(context["tech_flags"], {"valid": True})

            invalid_flags = {"tech_flags": []}
            invalid_flag_diagnostics = []
            s6_report._validate_context_contract(
                path, invalid_flags, invalid_flag_diagnostics
            )
            self.assertEqual(invalid_flags["tech_flags"], {})
            self.assertTrue(invalid_flag_diagnostics)

            valid_context = {
                "jdk_base": "8",
                "jdk_current": "17",
                "springboot_base": "2.7",
                "springboot_current": "3.2",
                "build_tool": "maven",
                "jdk_upgraded": True,
                "springboot_major_upgrade": True,
                "tech_flags": {"spring": True},
            }
            valid_context_diagnostics = []
            s6_report._validate_context_contract(
                path, valid_context, valid_context_diagnostics
            )
            self.assertEqual(valid_context_diagnostics, [])

    def test_collect_findings_all_result_buckets_and_artifact_relations(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            dependencies = report / "evidence" / "dependencies"
            context_dir = report / "evidence" / "context"
            static_dir = report / "evidence" / "static_scan"
            api_dir = report / "evidence" / "api_changes"
            call_dir = report / "evidence" / "call_chain"
            by_api_dir = call_dir / "by_api"
            by_module_dir = call_dir / "by_module"
            for directory in (
                dependencies,
                context_dir,
                static_dir,
                api_dir,
                call_dir,
                by_api_dir,
                by_module_dir,
            ):
                directory.mkdir(parents=True, exist_ok=True)
            for path in (
                dependencies / "dep_changes.csv",
                dependencies / "build_provenance.json",
                dependencies / "dependency_jars.json",
                context_dir / "context.json",
                static_dir / "s3_dependency_compat.csv",
                static_dir / "s3_database_contract_summary.json",
                static_dir / "s3_database_contract_changes.csv",
                static_dir / "s3_database_contract_changes.md",
                api_dir / "all_changed_apis.csv",
                call_dir / "alerts.csv",
                call_dir / "bytecode_unresolved.csv",
                call_dir / "summary.json",
                call_dir / "coverage.json",
                call_dir / "selection.json",
                by_api_dir / "matched.json",
                by_api_dir / "invalid.json",
                by_module_dir / "app_impacts.json",
                by_module_dir / "empty_impacts.json",
                by_module_dir / "ignored.json",
            ):
                path.write_text("{}", encoding="utf-8")
            for name in (
                "s3_jdk_removed_api.csv",
                "s3_jdk_javax_refs.csv",
                "s3_jdk_internal_api.csv",
                "s3_jdk_reflection.csv",
                "s3_jdk_serialization.txt",
                "s3_springboot_config.csv",
                "s3_springboot_autoconfig.txt",
            ):
                (static_dir / name).write_text("header\nrow\n", encoding="utf-8")

            reachable = [
                self._step5_item("explicit_p0", severity="P0", conclusion="已确认影响"),
                self._step5_item("explicit_p1", severity="P1", conclusion="已确认影响"),
                self._step5_item("explicit_p2", severity="P2", conclusion="已确认影响"),
                self._step5_item("probable", conclusion="可能影响"),
                self._step5_item(
                    "decision_probable",
                    conclusion="",
                    decision_bucket="probable_impact",
                ),
                self._step5_item("fallback_p0", severity="P0"),
                self._step5_item("fallback_p1", severity="P1"),
                self._step5_item("fallback_p2", severity="P2", coord=""),
            ]
            uncertain = [
                self._step5_item(
                    "uncertain_candidate",
                    call_paths=["app.Entry.start -> demo.uncertain_candidate.call"],
                    uncertainty_kind=s6_report.UNCERTAINTY_KIND_CANDIDATE_EVIDENCE,
                    path_details=[{"path_text": "app.Entry.start -> target"}],
                    priority_score="7",
                    priority_factors={"business": 1},
                    compile_impact="possible",
                    runtime_link_impact="unknown",
                    origin_step="step5",
                ),
                self._step5_item(
                    "uncertain_limit",
                    coord="g:b",
                    call_paths=[],
                    uncertainty_kind=s6_report.UNCERTAINTY_KIND_ANALYSIS_LIMITATION,
                    evidence_paths=[],
                    priority_score=0,
                ),
            ]
            not_analyzed = [
                self._step5_item("na_probable", conclusion="可能影响"),
                self._step5_item("na_input", coord="g:b", conclusion="需要补充输入"),
                self._step5_item("na_other", coord="", conclusion="本次未完成分析"),
            ]
            not_found = [self._step5_item("not_found", coord="g:c")]
            not_impacted = [self._step5_item("preserved", coord="g:d", conclusion="已确认不受影响")]
            all_items = reachable + uncertain + not_analyzed + not_found + not_impacted
            call_summary = {
                "status": "done",
                "origin_step": "bad-step",
                "total_apis": 6,
                "reachable": len(reachable),
                "not_impacted": len(not_impacted),
                "uncertain": len(uncertain),
                "not_analyzed": len(not_analyzed),
                "not_found_in_static_analysis": len(not_found),
                "reachable_apis": reachable,
                "not_impacted_apis": not_impacted,
                "uncertain_apis": uncertain,
                "not_analyzed_apis": not_analyzed,
                "not_found_apis": not_found,
                "user_conclusion_summary": {"confirmed_impact": 3},
                "uncertain_dependency_summary": [{"coord": "g:b"}],
                "diagnostic_guidance": [
                    None,
                    {
                        "reason_code": "SYSTEM_CODE_REACHED",
                        "origin_step": "step5",
                        "observed_scope": "api",
                        "affected_api_count": 2,
                        "affected_api_count_semantics": "primary",
                        "primary_reason_api_count": 1,
                        "potentially_affected_api_count": 2,
                        "observed_failure_count": 3,
                        "failure_record_count": 2,
                        "failure_occurrence_count": 4,
                        "raw_blocking_failure_count": 1,
                        "relevant_blocking_failure_count": 1,
                        "blocking_semantics": "relevant",
                        "blocking": True,
                        "affected_classes": ["demo.A"],
                        "affected_artifacts": ["app.jar"],
                        "affected_artifact_entries": ["demo/A.class"],
                        "evidence_file": "evidence/call_chain/alerts.csv",
                        "evidence_files": [],
                        "collectors": ["asm"],
                        "candidate_evidence": [{"coord": "g:a"}],
                        "source_components": ["business_reachability"],
                        "sample_apis": ["demo.A.call"],
                    },
                    {
                        "reason_code": "UNKNOWN_REASON",
                        "origin_step": "bad",
                        "observed_scope": "",
                        "affected_api_count": 0,
                        "observed_failure_count": 0,
                        "evidence_file": "",
                        "evidence_files": ["evidence/other.json"],
                    },
                ],
                "meta": {
                    "graph_stats": {
                        "truncated": False,
                    }
                },
            }
            coverage = {
                "overall_status": "partial",
                "critical_incomplete": ["business_reachability"],
                "components": [
                    {
                        "id": "business_reachability",
                        "status": "partial",
                        "reason_codes": ["CALL_GRAPH_TRUNCATED", ""],
                        "evidence": ["evidence/call_chain/alerts.csv"],
                    },
                    {"id": "complete", "status": "complete", "reason_codes": []},
                ],
            }
            scope = {
                "mode": "full",
                "available_dependency_count": 4,
                "included_dependency_count": 4,
                "total_api_count": 6,
                "analyzed_api_count": 6,
            }
            context = {
                "jdk_base": "8",
                "jdk_current": "17",
                "springboot_base": "2.7",
                "springboot_current": "3.2",
                "build_tool": "maven",
                "jdk_upgraded": True,
                "springboot_major_upgrade": True,
                "tech_flags": {"spring": True, "unused": False},
            }
            dep_rows = [
                {"coord": "g:a", "change_type": "major", "old_version": "1", "new_version": "2"},
                {"coord": "g:b", "change_type": "minor", "old_version": "1", "new_version": "1.1"},
                {"coord": "", "change_type": "unknown", "old_version": "", "new_version": ""},
            ]
            changed_rows = [
                {
                    "coord": item["coord"] or "g:unknown",
                    "api_name": item["api"],
                    "api_signature": item["api_signature"],
                    "symbol_kind": item["symbol_kind"],
                    "change_type": item["change_type"],
                    "severity": item["severity"],
                    "change_fact_identity": item["change_fact_identity"],
                }
                for item in all_items[:6]
            ]
            dep_compat_rows = [
                {"坐标": "g:a", "风险类型": "binary", "依赖范围": "compile"},
                {"坐标": "g:a", "风险类型": "source", "scope": "runtime"},
                {"坐标": "g:z", "风险类型": "background", "依赖范围": "runtime"},
            ]
            database_rows = [{
                "依赖包": "g:a",
                "变化类型": "removed",
                "契约类型": "table",
                "可信度": "high",
                "表": "orders",
                "列": "id",
                "契约位置": "schema.sql",
                "语句或字段": "drop table",
                "人工复核建议": "review",
            }]

            def alert(name, status, **extra):
                return {
                    "api_identity": f"api-{name}",
                    "reported_api_identity": f"reported-{name}",
                    "change_fact_identity": f"fact-{name}",
                    "decision_identity": f"decision-{name}",
                    "target_coord": extra.pop("target_coord", "g:a"),
                    "changed_symbol": f"demo.{name}.call",
                    "api_signature": "()V",
                    "symbol_kind": "method",
                    "change_type": "METHOD_REMOVED",
                    "severity": extra.pop("severity", "P1"),
                    "old_version": "1",
                    "new_version": "2",
                    "path_status": status,
                    "business_entry": extra.pop("business_entry", "app.Entry.start"),
                    "path_text": extra.pop("path_text", f"app.Entry.start -> demo.{name}.call"),
                    "path_occurrence_count": extra.pop("path_occurrence_count", "1"),
                    "evidence_files": extra.pop("evidence_files", "module-a/src/A.java|lib/app.jar"),
                    "action": extra.pop("action", "review"),
                    "reason": extra.pop("reason", "reason"),
                    **extra,
                }

            alert_rows = [
                alert("explicit_p0", "reachable", api_id="one", path_occurrence_count="2"),
                alert("explicit_p0", "uncertain", api_id="two", path_occurrence_count="bad"),
                alert(
                    "explicit_p1",
                    "not_impacted",
                    business_entry="",
                    consumer_class="app.Consumer",
                    consumer_method="run",
                    path_text="",
                    action="",
                    review_focus="inspect",
                    reason="",
                    review_reason="review-reason",
                    evidence_files="",
                ),
                alert("explicit_p2", "not_found_in_static_analysis", target_coord="g:b"),
                alert("probable", "not_analyzed", target_coord="g:c"),
                alert("decision_probable", "not_reachable", target_coord="g:d"),
            ]
            alert_rows.extend([copy.deepcopy(alert_rows[0]), {"changed_symbol": ""}])

            database_summary = {
                "schema": "java-upgrade-analyzer.database-contract-changes.v1",
                "change_count": 1,
                "coverage_status": "complete",
                "coverage_gaps": [],
            }
            by_api_payloads = {
                "matched.json": {
                    **reachable[0],
                    "reason_code": "",
                    "reachable_note": "matched-note",
                    "evidence_paths": [[{"from": "app.Entry", "to": "demo.explicit_p0.call"}]],
                },
                "invalid.json": {
                    "coord": "",
                    "api": "",
                    "evidence_paths": ["invalid"],
                },
            }
            module_payloads = {
                "app_impacts.json": {
                    "module": "app",
                    "impacts": [{}],
                    "p0_count": 1,
                    "p1_count": 2,
                    "p2_count": 3,
                    "uncertain_count": 4,
                    "probable_impact_count": 5,
                    "needs_input_count": 6,
                    "not_analyzed_count": 7,
                    "not_found_in_static_analysis_count": 8,
                },
                "empty_impacts.json": {"impacts": []},
            }
            per_dependency = [
                {"coord": ""},
                {
                    "coord": "g:a",
                    "change_type": "",
                    "old_version": "",
                    "new_version": "",
                    "step4": {"changed": 3},
                    "step5": {
                        "sample_results": [{
                            "change_type": "sample",
                            "old_version": "0",
                            "new_version": "3",
                        }],
                        "reaches_system_source": True,
                        "final_status": "reachable",
                        "blocked_at": "",
                        "blocked_reason": "",
                        "evidence_level": "exact",
                        "selected_api": "demo.A.call",
                    },
                },
                {
                    "coord": "g:e",
                    "change_type": "added",
                    "old_version": "-",
                    "new_version": "1",
                    "step4": None,
                    "step5": {
                        "sample_results": [],
                        "reaches_system_source": False,
                        "selected_status": "blocked",
                        "blocked_at": "bytecode",
                        "blocked_reason": "missing",
                    },
                },
            ]

            def fake_load_json(path, *, diagnostics=None, artifact="", required=False):
                if artifact == "coverage":
                    return copy.deepcopy(coverage)
                if artifact == "step5_selection":
                    return copy.deepcopy(scope)
                if artifact == "context":
                    return copy.deepcopy(context)
                if artifact == "step3_database_contract_summary":
                    return copy.deepcopy(database_summary)
                if artifact == "call_chain_summary":
                    return copy.deepcopy(call_summary)
                if artifact.startswith("call_chain_by_api:"):
                    return copy.deepcopy(by_api_payloads.get(Path(path).name, {}))
                if artifact.startswith("call_chain_by_module:"):
                    return copy.deepcopy(module_payloads.get(Path(path).name, {}))
                return {}

            def fake_load_csv(path, *, diagnostics=None, artifact="", required=False):
                return copy.deepcopy({
                    "dependency_changes": dep_rows,
                    "step3_dependency_compat": dep_compat_rows,
                    "step3_database_contract_changes": database_rows,
                    "changed_apis": changed_rows,
                }.get(artifact, []))

            with patch.object(s6_report, "load_json", side_effect=fake_load_json), patch.object(
                s6_report, "load_csv", side_effect=fake_load_csv
            ), patch.object(
                s6_report, "iter_csv_rows", return_value=iter(alert_rows)
            ), patch.object(
                s6_report, "_validated_alert_rows", return_value=alert_rows
            ), patch.object(
                s6_report, "count_lines", side_effect=lambda path: 1 if Path(path).exists() else -1
            ), patch.object(
                s6_report, "_validate_coverage_contract"
            ), patch.object(
                s6_report, "_validate_analysis_scope_contract"
            ), patch.object(
                s6_report, "_validate_context_contract"
            ), patch.object(
                s6_report, "_validate_csv_contract"
            ), patch.object(
                s6_report, "_validate_scope_consistency"
            ), patch.object(
                s6_report, "_validate_cross_artifact_identities"
            ), patch.object(
                s6_report, "_validate_call_summary_contract"
            ), patch.object(
                s6_report,
                "load_per_dependency_summaries",
                return_value=per_dependency,
            ), patch.object(
                s6_report,
                "_collect_available_evidence_paths",
                return_value=["evidence/call_chain/alerts.csv"],
            ):
                findings = s6_report.collect_findings(report)

            self.assertGreaterEqual(len(findings["p0"]), 2)
            self.assertGreaterEqual(len(findings["p1"]), 2)
            self.assertGreaterEqual(len(findings["p2"]), 2)
            self.assertEqual(len(findings["probable_impact"]), 3)
            self.assertEqual(len(findings["uncertain"]), 2)
            self.assertEqual(len(findings["needs_input"]), 1)
            self.assertEqual(len(findings["not_found"]), 1)
            self.assertEqual(findings["module_impacts"]["app"]["not_found"], 8)
            self.assertEqual(findings["database_contract"]["rows"], database_rows)
            self.assertEqual(findings["background_signals"]["dep_compat_total"], 1)
            self.assertEqual(findings["available_evidence_paths"], ["evidence/call_chain/alerts.csv"])
            self.assertTrue(findings["impact_overview"]["apis"])
            self.assertTrue(findings["impacted_dependencies"])
            self.assertEqual(findings["per_dependency_results"][0]["coord"], "g:a")

            overview = findings["impact_overview"]
            self.assertEqual(overview["record_count"], 6)
            self.assertEqual(overview["business_entry_count"], 2)
            self.assertGreaterEqual(overview["occurrence_count"], 6)

    def test_rich_human_models_and_report_rendering_matrix(self):
        findings = self._rich_findings()
        rows = s6_report.build_api_result_rows(findings)
        conclusions = {row["conclusion"] for row in rows}
        self.assertTrue({
            "已确认影响",
            "可能影响",
            s6_report.UNCERTAIN_CANDIDATE_CONCLUSION,
            s6_report.UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION,
            "已确认不受影响",
            "输入不足，结论未确定",
            "本次未完成分析",
            "未发现调用路径",
        }.issubset(conclusions))

        distribution = s6_report._confirmed_impact_distribution(findings, rows)
        self.assertGreaterEqual(distribution["confirmed_count"], 10)
        self.assertGreater(len(distribution["dependency_rows"]), 1)
        self.assertGreater(len(distribution["entry_rows"]), 3)
        rendered_distribution = s6_report.render_impact_distribution(
            findings, heading_level=1, force=True
        )
        self.assertIn("已确认影响分布", "\n".join(rendered_distribution))
        self.assertEqual(s6_report.render_impact_distribution({}, force=True), [])
        self.assertEqual(s6_report.render_other_result_distribution(rows[:2]), [])
        many_other_rows = [
            {
                **row,
                "coord": f"g:other{index}",
                "conclusion": "可能影响" if index % 2 else "未发现调用路径",
                "severity": ("P0", "P1", "P2", "")[index % 4],
                "change_type": f"TYPE_{index}",
            }
            for index, row in enumerate((rows * 2)[: s6_report.S6_MAIN_RESULT_LIMIT + 8])
        ]
        other_distribution = s6_report.render_other_result_distribution(
            many_other_rows, heading_level=9
        )
        self.assertIn("非“已确认影响”结果分布", "\n".join(other_distribution))

        api_model = s6_report.build_human_api_analysis(findings)
        dependency_model = s6_report.build_human_dependency_analysis(
            findings, api_model
        )
        self.assertEqual(
            api_model["total_count"],
            api_model["completed_count"] + api_model["incomplete_count"],
        )
        self.assertEqual(
            dependency_model["total_count"],
            dependency_model["completed_count"] + dependency_model["incomplete_count"],
        )
        self.assertTrue(api_model["count_note"])
        self.assertTrue(dependency_model["count_note"])

        rendered_sections = {
            "core": s6_report.render_core_conclusion(findings),
            "api_table": s6_report.render_api_result_table(findings),
            "input": s6_report.render_input_diagnostics(findings),
            "guidance": s6_report.render_diagnostic_guidance(findings),
            "diagnostic_summary": s6_report.render_diagnostic_summary(findings),
            "limitations": s6_report.render_limitations_section(findings),
            "appendix": s6_report.render_report_appendix(findings),
            "scope": s6_report.render_report_scope_notice(findings),
            "database": s6_report.render_database_contract_changes(findings, limit=1),
            "dependencies": s6_report.render_dependency_conclusions(
                findings, dependency_model
            ),
            "apis": s6_report.render_api_and_calls(findings, api_model),
            "files": s6_report.render_user_visible_files(
                findings, api_model, dependency_model
            ),
        }
        for name, section in rendered_sections.items():
            with self.subTest(section=name):
                self.assertIsInstance(section, list)
                if name == "scope":
                    self.assertEqual(section, [])
                else:
                    self.assertTrue(section)
        report_text = s6_report.generate_report(findings)
        self.assertIn("依赖层面结论", report_text)
        self.assertIn("API 及调用关系", report_text)
        self.assertIn("用户可见文件说明", report_text)
        diagnostic_detail = s6_report.render_diagnostic_detail_artifact(findings)
        self.assertIn("分析诊断明细", diagnostic_detail)
        self.assertIn("BYTECODE_CALLER_UNRESOLVED", diagnostic_detail)

        verdict_cases = (
            ({"coverage": {"overall_status": "complete"}}, "可展示"),
            ({
                "coverage": {"overall_status": "complete"},
                "not_impacted": [self._step5_item("safe")],
            }, "相同类字节码"),
            ({
                "coverage": {"overall_status": "complete"},
                "not_found": [self._step5_item("missing")],
            }, "未发现"),
            ({
                "coverage": {"overall_status": "partial"},
            }, "证据不足"),
            ({
                "coverage": {"overall_status": "complete"},
                "uncertain": [self._step5_item("review")],
            }, "尚未确定"),
        )
        for payload, expected in verdict_cases:
            with self.subTest(verdict=expected):
                rendered = "\n".join(s6_report.render_core_conclusion(payload))
                self.assertIn(expected, rendered)

        partial = copy.deepcopy(findings)
        partial["analysis_scope"] = {
            "mode": "partial",
            "validation_status": "valid",
            "available_dependency_count": 8,
            "included_dependency_count": 2,
            "included_dependency_coords": ["g:dep0", "g:dep1"],
            "excluded_dependency_coords": [f"g:dep{i}" for i in range(2, 8)],
            "total_api_count": len(findings["changed_api_inventory"]),
            "analyzed_api_count": 5,
        }
        partial_api = s6_report.build_human_api_analysis(partial)
        partial_dependency = s6_report.build_human_dependency_analysis(
            partial, partial_api
        )
        self.assertTrue(partial_api["scope_verified"])
        self.assertTrue(partial_dependency["scope_verified"])
        self.assertIn(
            "只覆盖",
            "\n".join(s6_report.render_core_conclusion(partial)),
        )
        self.assertTrue(s6_report.render_report_scope_notice(partial))
        self.assertIn(
            "包含未纳入本轮分析的对象",
            "\n".join(
                s6_report.render_user_visible_files(
                    partial, partial_api, partial_dependency
                )
            ),
        )

        invalid_scope = copy.deepcopy(findings)
        invalid_scope["analysis_scope"] = {
            "mode": "",
            "validation_status": "invalid",
        }
        self.assertIn(
            "无法核验",
            "\n".join(s6_report.render_core_conclusion(invalid_scope)),
        )
        self.assertTrue(s6_report.render_report_scope_notice(invalid_scope))
        missing_scope = copy.deepcopy(findings)
        missing_scope["analysis_scope"] = {}
        self.assertIn(
            "快照缺失",
            "\n".join(s6_report.render_core_conclusion(missing_scope)),
        )
        self.assertTrue(s6_report.render_report_scope_notice(missing_scope))

        no_inventory = copy.deepcopy(findings)
        no_inventory["changed_api_inventory"] = []
        no_inventory["dependency_changes"] = []
        no_inventory["analysis_scope"].update({
            "available_dependency_count": 20,
            "included_dependency_count": 20,
            "total_api_count": 21,
            "analyzed_api_count": 21,
        })
        no_inventory["call_chain_target_count"] = 19
        no_inventory["scan_stats"]["changed_apis_total"] = 17
        no_inventory["dep_changes_summary"] = {"major": 18}
        uncertain_api_model = s6_report.build_human_api_analysis(no_inventory)
        uncertain_dependency_model = s6_report.build_human_dependency_analysis(
            no_inventory, uncertain_api_model
        )
        self.assertTrue(uncertain_api_model["population_unconfirmed"])
        self.assertTrue(uncertain_dependency_model["population_unconfirmed"])

    def test_alert_physical_evidence_and_row_contract_matrix(self):
        base = {
            "changed_symbol": "demo.Api.call",
            "api_signature": "(int)",
            "business_entry": "app.Entry.start()V",
        }
        reachable_cases = (
            ({
                **base,
                "path_text": "业务入口: app.Entry.start()V -> 变更 API: demo.Api.call(int)",
            }, True),
            ({
                "changed_symbol": "app.Entry.start()V",
                "api_signature": "()V",
                "business_entry": "app.Entry.start()V",
                "path_text": "app.Entry.start()V",
            }, True),
            ({
                **base,
                "path_text": "",
                "chain_entry": "chain entry: app.Entry.start()V",
                "chain_target": "changed api: demo.Api.call(int)",
                "chain_hop_count": "0",
            }, True),
            ({**base, "path_text": ""}, False),
            ({**base, "path_text": "other.Entry.start()V -> demo.Api.call(int)"}, False),
            ({**base, "path_text": "app.Entry.start()V -> demo.Other.call(int)"}, False),
            ({**base, "path_text": "app.Entry.start()V"}, False),
            ({
                **base,
                "path_text": "",
                "chain_entry": "app.Entry.start()V",
                "chain_target": "demo.Api.call(int)",
                "chain_hop_count": "bad",
            }, True),
            ({
                **base,
                "path_text": "",
                "chain_entry": "app.Entry.start()V",
                "chain_target": "demo.Api.call(int)",
                "chain_hop_count": "-1",
            }, False),
            ({
                **base,
                "path_text": "",
                "chain_entry": "other.Entry.start()V",
                "chain_target": "demo.Api.call(int)",
                "chain_hop_count": "1",
            }, False),
            ({
                **base,
                "path_text": "",
                "chain_entry": "app.Entry.start()V",
                "chain_target": "demo.Other.call(int)",
                "chain_hop_count": "1",
            }, False),
        )
        for row, expected in reachable_cases:
            with self.subTest(reachable=row):
                self.assertEqual(
                    s6_report._alert_row_has_reachable_path_evidence(row),
                    expected,
                )

        preserved_cases = (
            ({**base, "evidence_files": ""}, False),
            ({
                **base,
                "evidence_files": "evidence/a.json",
                "path_text": "app.Entry.start()V -> demo.Api.call(int)",
                "review_reason": "class 字节码完全一致",
            }, True),
            ({
                **base,
                "evidence_files": "evidence/a.json",
                "path_text": "app.Entry.start()V -> demo.Other.call(int)",
                "chain_detail": "类字节码相同",
            }, False),
            ({
                **base,
                "evidence_files": "evidence/a.json",
                "path_text": "app.Entry.start()V -> demo.Api.call(int)",
                "review_reason": "unrelated",
            }, False),
        )
        for row, expected in preserved_cases:
            with self.subTest(preserved=row):
                self.assertEqual(
                    s6_report._alert_row_has_preserved_bytecode_evidence(row),
                    expected,
                )

        valid_reachable = {
            **base,
            "path_status": "reachable",
            "conclusion_level": "confirmed",
            "business_reachable": "true",
            "path_text": "app.Entry.start()V -> demo.Api.call(int)",
        }
        valid_not_impacted = {
            **base,
            "path_status": "not_impacted",
            "conclusion_level": "confirmed_no_impact",
            "business_reachable": "false",
            "path_text": "app.Entry.start()V -> demo.Api.call(int)",
            "evidence_files": "evidence/a.json",
            "review_reason": "class 字节码完全一致",
        }
        input_rows = [
            {"path_status": "future"},
            {**valid_reachable, "conclusion_level": "candidate"},
            {
                **valid_not_impacted,
                "business_reachable": "true",
            },
            {**valid_reachable, "business_reachable": "false"},
            {**valid_reachable, "path_text": "broken"},
            {**valid_not_impacted, "review_reason": "unrelated"},
            valid_reachable,
            valid_not_impacted,
            {
                "path_status": "uncertain",
                "conclusion_level": "candidate",
                "business_reachable": "false",
            },
            {
                "api_status": "not_analyzed",
                "conclusion_level": "incomplete",
            },
        ]
        diagnostics = []
        with patch.object(
            s6_report,
            "iter_csv_rows",
            return_value=iter(input_rows),
        ):
            accepted = list(
                s6_report._validated_alert_rows(
                    "/tmp/alerts.csv",
                    diagnostics=diagnostics,
                    required=True,
                )
            )
        self.assertEqual(len(accepted), 4)
        self.assertTrue(diagnostics)
        self.assertEqual(diagnostics[0]["stage"], "row_contract")

    def test_scope_downgrade_and_cross_artifact_identity_matrices(self):
        path = Path("/tmp/selection.json")

        def identity(item):
            item = item or {}
            return (str(item.get("id") or ""), str(item.get("api") or ""))

        with patch.object(s6_report, "build_api_identity_key", side_effect=identity), patch.object(
            s6_report,
            "_identity_is_complete",
            side_effect=lambda value: bool(value and value[0] and value[1]),
        ):
            valid_changed = [{"id": "a", "api": "A"}, {"id": "b", "api": "B"}]
            valid_scope = {
                "mode": "full",
                "analyzed_api_count": 2,
                "total_api_count": 2,
            }
            diagnostics = []
            s6_report._validate_scope_consistency(
                scope=valid_scope,
                target_api_count=2,
                changed_apis=valid_changed,
                diagnostics=diagnostics,
                selection_path=path,
            )
            self.assertEqual(diagnostics, [])

            cases = (
                ({"mode": "full", "analyzed_api_count": 1, "total_api_count": 2}, 2, valid_changed),
                ({"mode": "partial", "analyzed_api_count": 1, "total_api_count": 0}, 2, valid_changed),
                ({"mode": "partial", "analyzed_api_count": 1, "total_api_count": 2}, 1, valid_changed[:1]),
                ({"mode": "future", "analyzed_api_count": 0, "total_api_count": 1}, 0, []),
            )
            for scope, target_count, changed in cases:
                with self.subTest(scope=scope):
                    case_diagnostics = []
                    s6_report._validate_scope_consistency(
                        scope=scope,
                        target_api_count=target_count,
                        changed_apis=changed,
                        diagnostics=case_diagnostics,
                        selection_path=path,
                    )
                    if scope.get("mode") in {"full", "partial"}:
                        self.assertTrue(case_diagnostics)

            suppressed_scope = {
                "mode": "full",
                "analyzed_api_count": 1,
                "total_api_count": 9,
            }
            suppressed = [{"artifact": "step5_selection", "stage": "json_contract"}]
            s6_report._validate_scope_consistency(
                scope=suppressed_scope,
                target_api_count=2,
                changed_apis=valid_changed,
                diagnostics=suppressed,
                selection_path=path,
            )
            self.assertEqual(len(suppressed), 1)

        verified = {("verified", "A")}
        summary = {
            "reachable_apis": [
                {"id": "verified", "api": "A"},
                {"id": "move", "api": "B", "call_paths": ["A -> B"], "key_evidence": "key"},
            ],
            "not_impacted_apis": [{"id": "move-safe", "api": "C"}],
            "not_analyzed_apis": [
                {"id": "move", "api": "B"},
                None,
            ],
            "diagnostic_guidance": [None],
        }
        with patch.object(s6_report, "build_api_identity_key", side_effect=identity):
            s6_report._downgrade_unverified_certain_results(summary, verified)
        self.assertEqual([item["id"] for item in summary["reachable_apis"]], ["verified"])
        self.assertEqual(summary["not_impacted_apis"], [])
        moved_safe = next(
            item for item in summary["not_analyzed_apis"]
            if isinstance(item, dict) and item.get("id") == "move-safe"
        )
        self.assertEqual(moved_safe["reason_code"], "S6_EVIDENCE_IDENTITY_MISMATCH")
        self.assertEqual(moved_safe["call_paths"], [])
        self.assertEqual(summary["reachable"], 1)
        self.assertEqual(summary["not_impacted"], 0)
        self.assertTrue(any(
            isinstance(item, dict)
            and item.get("reason_code") == "S6_EVIDENCE_IDENTITY_MISMATCH"
            for item in summary["diagnostic_guidance"]
        ))

        already_guided = {
            "reachable_apis": [{"id": "move", "api": "B"}],
            "not_impacted_apis": [],
            "not_analyzed_apis": [],
            "diagnostic_guidance": [{
                "reason_code": "S6_EVIDENCE_IDENTITY_MISMATCH"
            }],
        }
        with patch.object(s6_report, "build_api_identity_key", side_effect=identity):
            s6_report._downgrade_unverified_certain_results(already_guided, set())
        self.assertEqual(len(already_guided["diagnostic_guidance"]), 1)

        exact_summary_item = {
            "id": "a",
            "api": "A",
            "severity": "P2",
            "old_version": "stale",
            "new_version": "stale",
        }
        exact_changed = [{
            "id": "a",
            "api": "A",
            "severity": "P0",
            "old_version": "1",
            "new_version": "2",
        }]
        exact_overview = {
            "fact_apis": [{
                "id": "a",
                "api": "A",
                "bucket": "confirmed",
                "severity_values": ["P1"],
                "old_version_values": ["0"],
                "new_version_values": ["3"],
            }]
        }
        exact_summary = {
            "reachable_apis": [exact_summary_item],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
        }
        diagnostics = []
        with patch.object(s6_report, "build_api_identity_key", side_effect=identity), patch.object(
            s6_report,
            "_identity_is_complete",
            side_effect=lambda value: bool(value and value[0] and value[1]),
        ), patch.object(s6_report, "_downgrade_unverified_certain_results") as downgrade:
            s6_report._validate_cross_artifact_identities(
                call_summary=exact_summary,
                changed_apis=exact_changed,
                impact_overview=exact_overview,
                scope_mode="full",
                diagnostics=diagnostics,
                changed_apis_path="/tmp/changed.csv",
                alerts_path="/tmp/alerts.csv",
            )
        self.assertEqual(exact_summary_item["severity"], "P0")
        self.assertEqual(exact_overview["fact_apis"][0]["severity_values"], ["P0"])
        self.assertEqual(downgrade.call_args.args[1], {("a", "A")})
        self.assertEqual(
            {item["artifact"] for item in diagnostics},
            {"call_chain_summary", "call_chain_alerts"},
        )

        conflicting_changed = [
            {"id": "a", "api": "A", "severity": "P0", "old_version": "1", "new_version": "2"},
            {"id": "a", "api": "A", "severity": "P1", "old_version": "3", "new_version": "4"},
            {"id": "b", "api": "B", "severity": "P2", "old_version": "1", "new_version": "2"},
        ]
        mismatched_summary = {
            "reachable_apis": [{"id": "a", "api": "A"}],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
        }
        mismatched_overview = {
            "apis": [{"id": "b", "api": "B", "bucket": "review"}]
        }
        mismatch_diagnostics = []
        with patch.object(s6_report, "build_api_identity_key", side_effect=identity), patch.object(
            s6_report,
            "_identity_is_complete",
            side_effect=lambda value: bool(value and value[0] and value[1]),
        ), patch.object(s6_report, "_downgrade_unverified_certain_results"):
            s6_report._validate_cross_artifact_identities(
                call_summary=mismatched_summary,
                changed_apis=conflicting_changed,
                impact_overview=mismatched_overview,
                scope_mode="full",
                diagnostics=mismatch_diagnostics,
                changed_apis_path="/tmp/changed.csv",
                alerts_path="/tmp/alerts.csv",
            )
        self.assertTrue(any(
            item["artifact"] == "changed_apis"
            and item["stage"] in {"identity_consistency", "field_consistency"}
            for item in mismatch_diagnostics
        ))
        self.assertTrue(any(
            item["artifact"] == "call_chain_alerts"
            and item["stage"] == "identity_consistency"
            for item in mismatch_diagnostics
        ))

    def test_change_detail_markdown_and_bucket_artifact_matrix(self):
        change_cases = (
            ({"change_type": "REMOVED", "symbol_kind": "method"}, "删除方法"),
            ({
                "change_type": "DATA_FIELD_ADDED",
                "symbol_kind": "field",
                "api_signature": "(java.lang.String)",
                "new_value": "String",
                "severity": "P1",
            }, "字段类型：String"),
            ({
                "change_type": "DATA_FIELD_REMOVED",
                "symbol_kind": "field",
                "old_value": "Long",
            }, "原字段类型：Long"),
            ({
                "change_type": "MEMBER_RESOLUTION_CHANGED",
                "old_value": "a/Old.m",
                "new_value": "b/New.m",
            }, "a.Old.m → b.New.m"),
            ({
                "change_type": "MEMBER_RESOLUTION_CHANGED",
                "old_value": "",
                "new_value": "b/New.m",
            }, "- → b.New.m"),
            ({
                "change_type": "DATA_FIELD_TYPE_CHANGED",
                "old_value": "",
                "new_value": "String",
            }, "未知 → String"),
        )
        for item, expected in change_cases:
            with self.subTest(change=item):
                self.assertIn(expected, s6_report._change_summary(item))

        items = [
            self._step5_item(
                f"detail_{index}",
                coord=f"g:detail{index}",
                severity=("P0", "P1", "P2", "")[index % 4],
                priority_score=10 - index,
                uncertainty_kind=(
                    s6_report.UNCERTAINTY_KIND_CANDIDATE_EVIDENCE
                    if index % 2
                    else s6_report.UNCERTAINTY_KIND_ANALYSIS_LIMITATION
                ),
            )
            for index in range(5)
        ]
        priority_config = {
            "title": "Priority details",
            "conclusion": "",
            "note": "note",
            "show_priority": True,
        }
        plain_config = {
            "title": "Plain details",
            "conclusion": "本次未完成分析",
            "note": "note",
        }
        with patch.object(s6_report, "S6_DETAIL_MD_FULL_LIMIT", 3), patch.object(
            s6_report, "S6_DETAIL_MD_SAMPLE_LIMIT", 2
        ), patch.object(s6_report, "S6_DETAIL_MD_DEP_SUMMARY_LIMIT", 2):
            priority_md = s6_report.build_bucket_detail_markdown(
                priority_config,
                items,
                "details.csv",
                alerts_available=True,
            )
            plain_md = s6_report.build_bucket_detail_markdown(
                plain_config,
                items,
                "details.csv",
                alerts_available=False,
            )
        self.assertIn("依赖复核顺序", priority_md)
        self.assertIn("其他 3 个依赖", priority_md)
        self.assertIn("明细样例", priority_md)
        self.assertIn("依赖坐标分布", plain_md)
        self.assertIn("严重级别分布", plain_md)
        self.assertIn("原因分类", plain_md)
        complete_md = s6_report.build_bucket_detail_markdown(
            plain_config, items[:1], "details.csv"
        )
        self.assertIn("API 明细（完整）", complete_md)

        focus_cases = (
            ("已确认影响", "完整链路"),
            ("可能影响", "运行时"),
            (s6_report.UNCERTAIN_CANDIDATE_CONCLUSION, "候选证据"),
            ("结论未确定（候选证据）", "候选证据"),
            (s6_report.UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION, "能力边界"),
            ("需要补充输入", "缺少源码"),
            ("缺少依赖源码/构建产物", "缺少源码"),
            ("输入不足，结论未确定", "缺少源码"),
            ("本次未完成分析", "不能按未影响"),
            ("已确认不受影响", "API 字节码"),
            ("未找到调用路径", "不等同"),
            ("future", "没有更多"),
        )
        for conclusion, expected in focus_cases:
            with self.subTest(focus=conclusion):
                self.assertIn(
                    expected,
                    s6_report._detail_review_focus({}, conclusion),
                )

        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            rich = self._rich_findings()
            with patch.object(s6_report, "S6_DETAIL_MD_FULL_LIMIT", 3), patch.object(
                s6_report, "S6_DETAIL_MD_SAMPLE_LIMIT", 2
            ):
                confirmed_artifacts = s6_report.write_bucket_detail_artifacts(
                    report, rich, "confirmed"
                )
                uncertain_artifacts = s6_report.write_bucket_detail_artifacts(
                    report, rich, "uncertain"
                )
                not_analyzed_artifacts = s6_report.write_bucket_detail_artifacts(
                    report, rich, "not_analyzed"
                )
                not_found_artifacts = s6_report.write_not_found_detail_artifacts(
                    report, rich
                )
            for artifact_set in (
                confirmed_artifacts,
                uncertain_artifacts,
                not_analyzed_artifacts,
                not_found_artifacts,
            ):
                self.assertTrue(artifact_set)
                for relative_path in artifact_set.values():
                    self.assertTrue((report / relative_path).is_file())

            unknown_findings = {"future": items[:1], "artifacts": {}}
            unknown_artifacts = s6_report.write_bucket_detail_artifacts(
                report, unknown_findings, "future"
            )
            self.assertTrue(unknown_artifacts)

            stale_csv = report / "deliverables" / "s6_probable_impact_apis.csv"
            stale_md = report / "deliverables" / "s6_probable_impact_apis.md"
            stale_csv.write_text("stale", encoding="utf-8")
            stale_md.write_text("stale", encoding="utf-8")
            empty_artifacts = s6_report.write_bucket_detail_artifacts(
                report, {"probable_impact": []}, "probable_impact"
            )
            self.assertEqual(empty_artifacts, {})
            self.assertFalse(stale_csv.exists())
            self.assertFalse(stale_md.exists())

            small_confirmed = copy.deepcopy(rich)
            small_confirmed["p0"] = small_confirmed["p0"][:1]
            small_confirmed["p1"] = []
            small_confirmed["p2"] = []
            confirmed_csv = report / "deliverables" / "s6_confirmed_impact_apis.csv"
            confirmed_md = report / "deliverables" / "s6_confirmed_impact_apis.md"
            self.assertTrue(confirmed_csv.exists())
            self.assertTrue(confirmed_md.exists())
            self.assertEqual(
                s6_report.write_bucket_detail_artifacts(
                    report, small_confirmed, "confirmed"
                ),
                {},
            )
            self.assertFalse(confirmed_csv.exists())
            self.assertFalse(confirmed_md.exists())

    def test_scope_split_and_per_dependency_artifact_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            evidence_api = report / "evidence" / "api_changes"
            evidence_call = report / "evidence" / "call_chain"
            source_review = report / "evidence" / "source_analysis" / "review.md"
            evidence_api.mkdir(parents=True)
            evidence_call.mkdir(parents=True)
            source_review.parent.mkdir(parents=True)
            source_review.write_text("review", encoding="utf-8")
            (evidence_api / "changed_dependencies.md").write_text("deps", encoding="utf-8")
            (evidence_api / "all_changed_apis.csv").write_text(
                "coord,api_name\ng:a,A\n", encoding="utf-8"
            )
            (evidence_call / "alerts.csv").write_text("alerts", encoding="utf-8")

            scope_cases = (
                ({
                    "mode": "full",
                    "available_dependency_count": 2,
                    "included_dependency_count": 2,
                    "total_api_count": 3,
                    "analyzed_api_count": 3,
                    "included_dependency_coords": [" g:a ", "g:b", "g:a", ""],
                    "excluded_dependency_coords": [],
                    "selected_names": ["A", "B"],
                }, "全量分析"),
                ({
                    "mode": "partial",
                    "available_dependency_count": 3,
                    "included_dependency_count": 1,
                    "total_api_count": 4,
                    "analyzed_api_count": 2,
                    "included_dependency_coords": ["g:a"],
                    "excluded_dependency_coords": ["g:b", "g:c"],
                    "selected_names": ["A"],
                }, "部分分析"),
                ({"mode": "", "validation_status": "invalid"}, "范围无法核验"),
                ({}, "范围未记录"),
            )
            for scope, expected in scope_cases:
                with self.subTest(scope=expected):
                    findings = {
                        "analysis_scope": scope,
                        "source_inputs": {
                            "label": "业务与依赖源码",
                            "effect": "辅助映射",
                            "mapped_count": 2,
                            "coverage_status": "complete",
                        },
                    }
                    relative = s6_report.write_analysis_scope_artifact(
                        report, findings
                    )
                    content = (report / relative).read_text(encoding="utf-8")
                    self.assertIn(expected, content)
                    self.assertIn("源码辅助证据", content)
                    self.assertIn("逐 API 系统触达台账", content)

            missing_evidence_report = report / "missing-evidence"
            relative = s6_report.write_analysis_scope_artifact(
                missing_evidence_report,
                {"analysis_scope": {}, "source_inputs": {}},
            )
            content = (missing_evidence_report / relative).read_text(encoding="utf-8")
            self.assertIn("本轮未生成", content)

            source = evidence_api / "all_changed_apis.csv"
            split_dir = report / "deliverables" / "changed-api-parts"
            split_dir.mkdir(parents=True, exist_ok=True)
            stale = split_dir / "all_changed_apis_part_999.csv"
            stale.write_text("stale", encoding="utf-8")
            source.write_text(
                "coord,api_name\ng:a,A\ng:b,B\ng:c,C\n",
                encoding="utf-8",
            )
            with patch.object(s6_report, "S6_CHANGED_API_SPLIT_ROWS", 2):
                split = s6_report.write_changed_api_split_artifacts(report)
            self.assertEqual(split["changed_apis_split_count"], 2)
            self.assertFalse(stale.exists())
            self.assertEqual(
                len(list(split_dir.glob("all_changed_apis_part_*.csv"))), 2
            )

            source.write_text("", encoding="utf-8")
            self.assertEqual(
                s6_report.write_changed_api_split_artifacts(report), {}
            )
            source.write_text("coord,api_name\n", encoding="utf-8")
            self.assertEqual(
                s6_report.write_changed_api_split_artifacts(report), {}
            )
            source.unlink()
            self.assertEqual(
                s6_report.write_changed_api_split_artifacts(report), {}
            )

            per_root = evidence_api / s6_report.PER_DEPENDENCY_DIRNAME
            self.assertEqual(s6_report.load_per_dependency_summaries(report), [])
            per_root.mkdir()
            (per_root / "not-a-directory.json").write_text("{}", encoding="utf-8")
            empty_child = per_root / "empty"
            empty_child.mkdir()
            (empty_child / s6_report.PER_DEPENDENCY_SUMMARY_FILE).write_text(
                "{}", encoding="utf-8"
            )
            valid_child = per_root / "valid"
            valid_child.mkdir()
            (valid_child / s6_report.PER_DEPENDENCY_SUMMARY_FILE).write_text(
                '{"coord": "g:a"}', encoding="utf-8"
            )
            self.assertEqual(
                s6_report.load_per_dependency_summaries(report),
                [{"coord": "g:a"}],
            )

        artifacts = {
            "confirmed_csv": "confirmed.csv",
            "confirmed_md": "confirmed.md",
            "uncertain_csv": "uncertain.csv",
        }
        available = s6_report.available_s6_detail_artifacts(
            {"artifacts": artifacts}
        )
        self.assertEqual([row["bucket"] for row in available], ["confirmed"])
        self.assertEqual(s6_report.available_s6_detail_artifacts(None), [])

    def test_evidence_entry_path_reason_and_diagnostic_helper_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            outside = Path(tmp) / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            dependency_file = report / "evidence" / "dependencies" / "dep.json"
            context_file = report / "evidence" / "context" / "context.json"
            state_file = report / ".runtime" / "state" / "state.json"
            for path in (dependency_file, context_file, state_file):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}", encoding="utf-8")

            findings = {
                "artifacts": {
                    "dependency": "evidence/dependencies/dep.json",
                    "context": "evidence\\context\\context.json",
                    "absolute": str(outside),
                    "traversal": "../outside.txt",
                    "blank": " ",
                    "none": None,
                },
                "coverage": {"components": [{"evidence": [
                    "evidence/dependencies/dep.json#row-1",
                    ".runtime/state/state.json",
                    "evidence/call_chain/missing.csv",
                    "evidence/unsupported/value.json",
                    "single-file.json",
                    "../outside.txt",
                    str(outside),
                    "#missing-path",
                    "",
                ]}]},
            }
            available = s6_report._collect_available_evidence_paths(report, findings)
            self.assertEqual(available, sorted([
                ".runtime/state/state.json",
                "evidence/context/context.json",
                "evidence/dependencies/dep.json",
                "evidence/dependencies/dep.json#row-1",
                str(outside),
            ]))
            self.assertFalse(s6_report._evidence_is_available({}, ""))
            self.assertTrue(s6_report._evidence_is_available({}, "legacy/path.json"))
            self.assertFalse(s6_report._evidence_is_available(
                {"available_evidence_paths": []}, "missing.json"
            ))
            tracked = {
                "available_evidence_paths": [" evidence/context/context.json ", None],
                "artifacts": {"dep": "evidence\\dependencies\\dep.json", "blank": ""},
            }
            self.assertTrue(s6_report._evidence_is_available(
                tracked, "evidence\\context\\context.json"
            ))
            self.assertTrue(s6_report._evidence_is_available(
                tracked, "evidence/dependencies/dep.json"
            ))

        item = {"business_entry": "direct.Entry", "call_paths": ["fallback.Entry -> T"]}
        overview = {
            "entries_by_status": {
                "reachable": ["direct.Entry", "plain.Entry", "plain.Entry()", "", None],
                "uncertain": ["candidate.Entry"],
            },
            "sample_entries": ["sample.Entry", "sample.Entry", " "],
            "sample_modules": ["app", "", "app", "core", None],
        }
        with patch.object(s6_report, "_overview_for_item", return_value=overview):
            self.assertEqual(
                s6_report._item_business_entries(
                    {}, item, limit=None, statuses=("reachable", "uncertain")
                ),
                ["direct.Entry", "plain.Entry()", "candidate.Entry"],
            )
            self.assertEqual(
                s6_report._item_business_entries({}, {}, limit=1),
                ["sample.Entry"],
            )
            self.assertEqual(s6_report._item_modules({}, {}, limit=5), ["app", "core"])
            self.assertEqual(s6_report._item_modules({}, {}, limit=1), ["app"])

        path_overview = {
            "paths_by_status": {"reachable": [" A -> B ", "A -> B", "", None]},
            "paths": ["P -> Q"],
        }
        with patch.object(s6_report, "_overview_for_item", return_value={
            "paths_by_status": {},
            "paths": ["  entry(java.lang.String) -> target  ", ""],
        }):
            self.assertEqual(
                s6_report._item_business_entries({}, {"call_paths": ["other -> target"]}),
                ["entry(String)", "other"],
            )
        with patch.object(s6_report, "_overview_for_item", return_value={}):
            self.assertEqual(
                s6_report._item_business_entries(
                    {}, {"call_paths": [" item.Entry -> target ", None]}
                ),
                ["item.Entry"],
            )

        identity_item = {"coord": "g:a", "api": "A.m", "api_signature": "()V"}
        identity = s6_report._identity_without_severity(identity_item)
        self.assertEqual(
            s6_report._paths_for_report(
                identity_item, {identity: path_overview}, ("reachable",)
            ),
            ["A -> B"],
        )
        self.assertEqual(
            s6_report._paths_for_report(identity_item, {identity: path_overview}),
            ["P -> Q"],
        )
        fallback_item = {
            **identity_item,
            "call_paths": [" C -> D ", "C -> D", ""],
        }
        self.assertEqual(
            s6_report._paths_for_report(fallback_item, {}, ("reachable",)),
            ["C -> D"],
        )
        evidence_item = {
            **identity_item,
            "evidence_paths": [
                "invalid",
                [None, {"caller_symbol": "E", "callee_key": "F"}],
                [{"caller_symbol": "only", "callee_key": ""}],
            ],
        }
        self.assertEqual(
            s6_report._paths_for_report(evidence_item, {identity: {}}, ("reachable",)),
            ["E → F"],
        )
        self.assertEqual(s6_report._nodes_from_csv_evidence("invalid"), [])
        self.assertEqual(
            s6_report._nodes_from_csv_evidence([
                None,
                {"caller_symbol": " A ", "callee_key": "A"},
                {"caller_symbol": "A", "callee_key": " B "},
                {"caller_symbol": "", "callee_key": "B"},
                {"caller_symbol": "C", "callee_key": ""},
            ]),
            ["A", "B", "C"],
        )

        count_cases = (
            ({"logical_path_counts_by_status": {"reachable": 3}}, ("reachable",), [], 3),
            ({"paths_by_status": {"reachable": ["A -> B", "A → B", "A -> C"]}}, ("reachable",), [], 2),
            ({"path_counts_by_status": {"reachable": 4, "uncertain": 2}}, ("reachable", "uncertain"), [], 6),
            ({"paths": ["A -> B", "A → B", "A -> C"]}, None, [], 2),
            ({"path_count": "bad"}, None, ["A -> B"], 1),
            ({"path_count": 1}, None, ["A -> B", "A -> C"], 2),
        )
        for overview_value, statuses, sampled, expected in count_cases:
            with self.subTest(path_count=expected, statuses=statuses):
                self.assertEqual(
                    s6_report._path_count_for_report(
                        identity_item, {identity: overview_value}, sampled, statuses
                    ),
                    expected,
                )

        impacts = (
            ({"artifact": "call_chain_summary", "error_type": "ArtifactContentError"}, {}, "结构或数量"),
            ({"artifact": "call_chain_summary", "error_type": "OSError"}, {}, "系统触达汇总未被采用"),
            ({"artifact": "call_chain_alerts", "stage": "row_contract"}, {}, "未通过校验"),
            ({"artifact": "call_chain_alerts"}, {}, "逐链路记录未被采用"),
            ({"artifact": "changed_apis", "stage": "csv_consistency"}, {}, "未通过校验"),
            ({"artifact": "changed_apis"}, {}, "变化 API 全集未被采用"),
            ({"artifact": "coverage"}, {"coverage": {"overall_status": "partial"}}, "覆盖不完整"),
            ({"artifact": "coverage"}, {"coverage": {"overall_status": "complete"}}, "证据覆盖完整"),
            ({"artifact": "coverage"}, {"coverage": {"overall_status": "not_applicable"}}, "证据覆盖不适用"),
            ({"artifact": "coverage"}, {"coverage": {}}, "无法确认"),
            ({"artifact": "step5_selection"}, {}, "范围无法确认"),
            ({"artifact": "context"}, {}, "构建环境"),
            ({"artifact": "dependency_changes"}, {}, "依赖版本变化"),
            ({"artifact": "call_chain_by_api:a"}, {}, "物理调用边"),
            ({"artifact": "call_chain_by_module:m"}, {}, "模块的影响汇总"),
            ({"artifact": "other"}, {}, "统计或结论"),
        )
        for diagnostic, matrix_findings, expected in impacts:
            with self.subTest(diagnostic=diagnostic):
                self.assertIn(
                    expected,
                    s6_report._input_diagnostic_impact(diagnostic, matrix_findings),
                )

        evidence_cases = (
            ({"confirmed_path_count": 2, "confirmed_occurrence_count": 4}, "证据命中 4 次"),
            ({"confirmed_path_count": 2, "confirmed_occurrence_count": 2}, "已确认调用链 2 条"),
            ({"conclusion": "已确认影响", "path_count": 2, "occurrence_count": 3}, "证据命中 3 次"),
            ({"conclusion": "已确认影响", "path_count": 2, "occurrence_count": 2}, "已确认调用链 2 条"),
            ({"conclusion": "已确认不受影响", "path_count": 1}, "相同类字节码"),
            ({"conclusion": "可能影响", "path_count": 1}, "候选或未完成"),
            ({"reason": "SYSTEM_CODE_REACHED"}, "系统入口触达"),
            ({}, "未记录"),
        )
        for row, expected in evidence_cases:
            with self.subTest(evidence=row):
                self.assertIn(expected, s6_report._row_evidence_text(row))

        self.assertEqual(
            s6_report._result_boundary_text({}),
            "当前记录未提供更多结论边界。",
        )
        self.assertIn(
            "不能按未影响解释",
            s6_report._result_boundary_text({
                "conclusion": "本次未完成分析",
                "reason": "ANALYSIS_INCOMPLETE",
            }),
        )
        self.assertEqual(
            s6_report._result_boundary_text({
                "conclusion": "可能影响",
                "reason": "已有相关证据，但当前证据不能确认运行时是否会触发该影响。",
            }),
            "已有相关证据，但当前证据不能确认运行时是否会触发该影响。",
        )
        self.assertEqual(
            s6_report._result_boundary_text({"conclusion": "unknown", "reason": "中文原因"}),
            "中文原因",
        )

        conflict_cases = (
            ("", "已确认影响", False),
            ("没有影响", "", False),
            ("完全兼容", "已确认影响", True),
            ("已确认存在影响", "已确认不受影响", True),
            ("加载时存在错误风险", "已确认不受影响", True),
            ("调用链已经触达变更API", "已确认不受影响", True),
            ("确认系统受到影响", "可能影响", True),
            ("不存在影响", s6_report.UNCERTAIN_CANDIDATE_CONCLUSION, True),
            ("中性描述", s6_report.UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION, False),
            ("完全兼容", "其他结论", False),
        )
        for reason, conclusion, expected in conflict_cases:
            with self.subTest(reason=reason, conclusion=conclusion):
                self.assertEqual(
                    s6_report._reason_conflicts_with_conclusion(reason, conclusion),
                    expected,
                )

    def test_dependency_relationship_and_full_detail_helper_matrix(self):
        basis_cases = (
            ([{"conclusion": "已确认影响", "aggregate_count": 2}], "数量未记录"),
            ([{"conclusion": "已确认影响", "confirmed_path_count": 3}], "共 3 条"),
            ([{"conclusion": "未发现调用路径", "aggregate_count": 2}], "均未发现"),
            ([{"conclusion": "已确认不受影响", "aggregate_count": 2}], "相同类字节码"),
            ([{"conclusion": "可能影响", "confirmed_path_count": 2}], "静态可执行调用关系"),
            ([], "没有进入"),
            ([
                {"conclusion": "已确认不受影响"},
                {"conclusion": "可能影响"},
                {"conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION},
                {"conclusion": s6_report.UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION},
                {"conclusion": "未发现调用路径"},
                {"conclusion": "本次未完成分析"},
            ], "静态分析能力边界 1"),
        )
        for rows, expected in basis_cases:
            with self.subTest(basis=expected):
                self.assertIn(expected, s6_report._dependency_basis(rows))

        rank_cases = (
            ({"analysis_conclusion": "确认有影响"}, 0),
            ({"confirmed_api_count": 1}, 0),
            ({"analysis_conclusion": "确认不受 API 调用影响", "analysis_complete": True}, 2),
            ({"analysis_conclusion": "其他", "analysis_complete": False}, 3),
            ({"analysis_conclusion": "其他", "analysis_complete": True}, 1),
            (None, 3),
        )
        for row, expected in rank_cases:
            self.assertEqual(s6_report._dependency_result_rank(row), expected)

        relation_cases = (
            ({"conclusion": "已确认影响", "paths": ["A.m -> B.n", "A.m() -> B.n()"], "confirmed_path_count": 2}, "共 2 条"),
            ({"conclusion": "已确认影响"}, "完整关系未记录"),
            ({"conclusion": "可能影响", "paths": ["A -> B"], "confirmed_path_count": 1}, "已确认调用关系"),
            ({"conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION, "paths": ["A -> B"]}, "候选关系"),
            ({"conclusion": "已确认不受影响"}, "无已确认"),
            ({"conclusion": "未发现调用路径"}, "未发现"),
        )
        for row, expected in relation_cases:
            with self.subTest(relation=expected):
                self.assertIn(expected, s6_report._main_relationship_cell(row))

        explanation_cases = (
            ({"conclusion": "已确认影响", "reason": "RUNTIME_VERIFICATION_REQUIRED"}, "不表示运行时故障"),
            ({"conclusion": "已确认影响", "reason": "SYSTEM_CODE_REACHED"}, "定向测试"),
            ({"conclusion": "已确认影响", "confirmed_path_count": 2}, "2 条"),
            ({"conclusion": "已确认影响"}, "已有证据"),
            ({"conclusion": "已确认不受影响"}, "相同类字节码"),
            ({"conclusion": "未发现调用路径"}, "不等于确认不受影响"),
            ({"conclusion": "可能影响", "confirmed_path_count": 2}, "静态可执行"),
            ({"conclusion": "可能影响"}, "不能确认"),
            ({"conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION, "priority_score": 7}, "复核优先分数 7"),
            ({"conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION}, "候选调用关系"),
            ({"conclusion": s6_report.UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION, "priority_score": 5}, "复核优先分数 5"),
            ({"conclusion": s6_report.UNCERTAIN_ANALYSIS_LIMITATION_CONCLUSION}, "静态分析能力边界"),
            ({"conclusion": "本次未完成分析", "reason": "ANALYSIS_INCOMPLETE"}, "未完整完成"),
            ({"conclusion": "unknown"}, "没有保存更多"),
        )
        for row, expected in explanation_cases:
            with self.subTest(explanation=expected):
                self.assertIn(expected, s6_report._api_result_explanation(row))
        with patch.object(s6_report, "_api_result_is_incomplete", return_value=True), patch.object(
            s6_report, "_incomplete_api_reason", return_value="incomplete-boundary"
        ):
            self.assertEqual(
                s6_report._api_result_explanation({"conclusion": "已确认影响"}),
                "incomplete-boundary",
            )

        rows = [
            {"id": "bad", "path_text": "ignored"},
            {"id": "api", "path_status": "reachable", "path_text": "A -> B", "path_occurrence_count": "0", "review_reason": "r1"},
            {"id": "api", "api_status": "reachable", "path_text": "A -> B", "path_occurrence_count": "4", "review_reason": "r1"},
            {"id": "api", "path_status": "uncertain", "business_entry": "C", "chain_target": "D", "path_occurrence_count": "bad", "review_reason": "r2"},
            {"id": "api", "path_status": "not_analyzed", "chain_entry": "E", "changed_symbol": "F", "review_reason": ""},
            {"id": "api", "path_status": "uncertain", "business_entry": "only-entry"},
        ]

        def logical_key(value):
            return (str((value or {}).get("id") or "api"),)

        with patch.object(s6_report, "_validated_alert_rows", return_value=rows), patch.object(
            s6_report, "build_logical_api_identity_key", side_effect=logical_key
        ), patch.object(
            s6_report, "_identity_is_complete", side_effect=lambda identity: identity != ("bad",)
        ):
            details = s6_report._load_full_alert_details(Path("unused"))
        self.assertEqual(details[("api",)]["paths_by_status"]["reachable"]["A → B"], 4)
        self.assertEqual(details[("api",)]["paths_by_status"]["uncertain"]["C → D"], 1)
        self.assertEqual(details[("api",)]["paths_by_status"]["not_analyzed"]["E → F"], 1)
        self.assertEqual(details[("api",)]["reasons_by_status"]["reachable"], ["r1"])

        detail_payload = {
            ("api",): {
                "paths_by_status": {
                    "reachable": {"A.m() → B.n()": 2},
                    "uncertain": {"C → D": 1},
                    "not_analyzed": {"E → F": 1},
                }
            }
        }
        full_cases = (
            ({"id": "api", "conclusion": "已确认影响"}, "A.m()"),
            ({"id": "api", "conclusion": "可能影响"}, "已确认调用关系"),
            ({"id": "api", "conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION}, "已确认调用关系"),
            ({"id": "other", "conclusion": "可能影响", "paths": ["X -> Y", "X -> Y", ""]}, "候选关系"),
            ({"id": "other", "conclusion": "已确认影响"}, "完整关系未记录"),
            ({"id": "other", "conclusion": "已确认不受影响"}, "无已确认"),
            ({"id": "other", "conclusion": "未发现调用路径"}, "未发现"),
        )
        with patch.object(s6_report, "build_logical_api_identity_key", side_effect=logical_key):
            for row, expected in full_cases:
                with self.subTest(full=expected):
                    self.assertIn(expected, s6_report._full_relationship_cell(row, detail_payload))

        labels = s6_report._logical_full_path_labels({
            "A.m → B.n": 1,
            "A.m() → B.n()": 2,
            "A.m(int) → B.n()": 1,
            "": 9,
        })
        self.assertGreaterEqual(len(labels), 1)
        self.assertTrue(any("记录" in label for label in labels))
        self.assertEqual(s6_report._logical_full_path_labels({}), [])

        alert_row = {
            "business_entry": "A",
            "changed_symbol": "C",
            "path_text": "A -> B",
        }
        self.assertFalse(s6_report._alert_row_has_reachable_path_evidence(alert_row))
        self.assertTrue(s6_report._alert_row_has_reachable_path_evidence({
            "business_entry": "A", "changed_symbol": "A", "path_text": "A"
        }))

        dependency_csv = s6_report._dependency_csv_row({
            "coord": "g:a",
            "api_completed": 2,
            "api_total": 3,
            "api_change_text": "2 removed",
            "analysis_conclusion": "确认有影响",
        })
        self.assertEqual(dependency_csv["依赖"], "g:a")
        self.assertIn("2/3\n2 removed", dependency_csv["API 分析（已完成/总数）"])
        missing_dependency_csv = s6_report._dependency_csv_row({})
        self.assertEqual(missing_dependency_csv["依赖"], "依赖身份未记录")

        base_api_row = {
            "coord": "g:a",
            "api": "A.m",
            "api_signature": "()V",
            "aggregate_count": 2,
            "conclusion": "已确认影响",
            "paths": ["A -> B"],
            "change_without_severity": "removed",
        }
        with patch.object(s6_report, "build_logical_api_identity_key", side_effect=logical_key):
            api_csv = s6_report._api_csv_row(base_api_row, {}, {})
        self.assertEqual(api_csv["API"], "A.m()V（2 个）")
        self.assertEqual(api_csv["依赖"], "g:a")
        with patch.object(s6_report, "_api_result_is_incomplete", return_value=True), patch.object(
            s6_report, "_incomplete_api_reason", return_value="not completed"
        ):
            incomplete_csv = s6_report._api_csv_row(
                {"conclusion": "本次未完成分析", "change_without_severity": ""},
                {},
                {},
            )
        self.assertEqual(incomplete_csv["API"], "API 身份未记录")
        self.assertEqual(incomplete_csv["依赖"], "依赖身份未记录")
        self.assertEqual(incomplete_csv["当前系统调用关系"], "调用关系分析未完成")

    def test_report_text_projection_and_failure_fallback_helper_matrix(self):
        minimal_issue = "\n".join(s6_report._fmt_issue({}))
        self.assertIn("`?`", minimal_issue)
        rich_issue = "\n".join(s6_report._fmt_issue({
            "api": "A.m",
            "coord": "g:a",
            "user_conclusion": "已确认影响",
            "user_reason": "用户原因",
            "reason": "内部原因",
            "key_evidence": "evidence.csv",
            "business_reach_depth": 2,
            "dependency_chain_coords": ["g:a", "g:b"],
            "call_paths": ["A -> B", "C -> D", "E -> F", "ignored -> path"],
            "evidence_paths": [[
                {
                    "caller_symbol": "A",
                    "callee_key": "B",
                    "evidence_type": "source",
                    "confidence": "high",
                    "file": "/repo/A.java",
                    "line": 7,
                },
                {},
            ]],
        }))
        for expected in ("用户原因", "evidence.csv", "第 2 跳", "g:a -> g:b", "A.java:7"):
            self.assertIn(expected, rich_issue)
        reason_only = "\n".join(s6_report._fmt_issue({"reason": "fallback reason"}))
        self.assertIn("fallback reason", reason_only)
        self.assertNotIn("证据边", "\n".join(s6_report._fmt_issue({"evidence_paths": [[]]})))

        coverage_cases = (
            ({"overall_status": "complete"}, []),
            ({"overall_status": "not_applicable"}, []),
            ({}, ["证据覆盖状态未记录"]),
            ({"overall_status": "partial"}, ["证据覆盖存在未展开缺口"]),
            ({
                "overall_status": "partial",
                "critical_incomplete": ["missing", "business_reachability"],
                "components": [{
                    "id": "business_reachability",
                    "status": "partial",
                    "reason_codes": ["CALL_GRAPH_TRUNCATED"],
                    "evidence": ["evidence/call_chain/alerts.csv"],
                }],
            }, ["其他覆盖组件", "业务调用链回溯"]),
        )
        for coverage, labels in coverage_cases:
            rows = s6_report._coverage_gap_rows(coverage)
            self.assertEqual([row["label"] for row in rows], labels)

        findings = {
            "analysis_scope": {"excluded_dependency_coords": ["g:excluded"]}
        }
        self.assertIn(
            "未包含该依赖",
            s6_report._dependency_incomplete_reason([], findings, excluded=True),
        )
        self.assertIn(
            "没有保存",
            s6_report._dependency_incomplete_reason(
                [{"conclusion": "已确认影响"}], findings
            ),
        )
        one_reason = s6_report._dependency_incomplete_reason([
            {
                "conclusion": "本次未完成分析",
                "aggregate_count": 2,
                "incomplete_reason": "输入缺失",
            },
            {
                "conclusion": "本次未完成分析",
                "incomplete_reason": "输入缺失",
            },
        ], findings)
        self.assertIn("3 个变化 API", one_reason)
        self.assertEqual(one_reason.count("输入缺失"), 1)
        many_reasons = s6_report._dependency_incomplete_reason([
            {"conclusion": "本次未完成分析", "incomplete_reason": f"原因{i}"}
            for i in range(5)
        ], findings)
        self.assertIn("原因0；原因1；原因2", many_reasons)
        self.assertNotIn("原因4", many_reasons)

        diagnostic = {
            "affected_classes": ["A", "B"],
            "affected_artifacts": ["/repo/lib/a.jar"],
            "affected_artifact_entries": ["A.class"],
            "collectors": ["asm"],
            "candidate_evidence": [
                {
                    "coord": "g:a",
                    "artifact_entry": "A.class",
                    "bytecode_sha256": "a" * 64,
                },
                {"artifact": "/repo/lib/b.jar", "artifact_entry": "B.class"},
                {"artifact_entry": "C.class"},
                {},
            ],
            "source_components": ["business_reachability", "framework_adapter:spring"],
            "evidence_file": "evidence/call_chain/detail.json",
        }
        diagnostic_text = s6_report._diagnostic_evidence_text(diagnostic)
        for expected in ("类：A", "制品：", "物理条目", "采集器", "g:a@A.class", "class sha256", "覆盖组件", "指令级明细"):
            self.assertIn(expected, diagnostic_text)
        self.assertIn(
            "API 级原因",
            s6_report._diagnostic_evidence_text({"candidate_evidence": [{}]}),
        )

        scope_with_api = s6_report._diagnostic_observed_scope_text({
            "potentially_affected_api_count": 3,
            "primary_reason_api_count": 2,
            "failure_record_count": 2,
            "failure_occurrence_count": 5,
            "observed_scope": "api",
        })
        self.assertIn("其中 2 个", scope_with_api)
        self.assertIn("5 个物理位置", scope_with_api)
        scope_without_api = s6_report._diagnostic_observed_scope_text({
            "affected_api_count": 0,
            "observed_failure_count": 2,
            "failure_occurrence_count": 2,
            "observed_scope": "global",
        })
        self.assertIn("未关联", scope_without_api)
        self.assertNotIn("物理位置", scope_without_api)
        self.assertIsInstance(
            s6_report._diagnostic_definition({"reason_code": "UNKNOWN", "origin_step": "step5"}),
            dict,
        )
        self.assertIsInstance(s6_report._diagnostic_definition(None), dict)

        human_reason_cases = (
            (None, ""),
            ("NO_STATIC_PATH", "未找到调用路径"),
            ("UNREGISTERED_REASON", "没有可展示"),
            ("plain english reason", "未提供可直接"),
            ("建议执行回归测试", ""),
            ("需要人工复核此处", ""),
            ("这是客观中文事实", "这是客观中文事实"),
        )
        for value, expected in human_reason_cases:
            actual = s6_report._human_reason(value)
            if expected:
                self.assertIn(expected, actual)
            else:
                self.assertEqual(actual, "")

        self.assertEqual(s6_report._human_chain_node(None), "")
        self.assertEqual(
            s6_report._human_chain_node("com.example:artifact:java.lang.A.m -> B.n"),
            "A.m → B.n",
        )
        self.assertEqual(s6_report._human_chain(None), "")
        self.assertEqual(s6_report._human_chain(" A -> -> java.lang.B "), "A → B")

        self.assertEqual(
            s6_report._csv_chain_view({"api": "A.m"})["target"], "A.m"
        )
        self.assertEqual(s6_report._csv_chain_view({})["target"], "")
        one_node = s6_report._csv_chain_view({"call_paths": ["变更API: A.m"]})
        self.assertEqual(one_node["target"], "A.m")
        self.assertEqual(one_node["entry"], "")
        full_chain = s6_report._csv_chain_view({
            "call_paths": ["", " Entry -> 变更API: Target "],
        })
        self.assertEqual(full_chain["entry"], "Entry")
        self.assertEqual(full_chain["target"], "Target")
        evidence_chain = s6_report._csv_chain_view({
            "evidence_paths": [[{"caller_symbol": "A", "callee_key": "B"}]]
        })
        self.assertEqual(evidence_chain["hop_count"], "1")

        module_cases = (
            ("", ""),
            ("module-a/src/main/java/A.java", "module-a"),
            ("repo/module-b/src/test/java/B.java", "repo/module-b"),
            ("/tmp/jua-real-project-1/module-c/src/main/java/C.java", "module-c"),
            ("/repo/a.txt", "repo/a.txt"),
        )
        for value, expected in module_cases:
            self.assertEqual(s6_report._module_from_evidence_file(value), expected)

        incomplete_cases = (
            ({"incomplete_reason": "explicit"}, {}, "explicit"),
            ({"coord": "g:excluded"}, findings, "未包含该依赖"),
            ({"reason_code": "MISSING_API_NAME"}, {}, "缺少完整 API 名称"),
            ({"reason": "ANALYSIS_INCOMPLETE"}, {}, "未完整完成"),
            ({}, {}, "没有保存"),
        )
        for row, context, expected in incomplete_cases:
            self.assertIn(expected, s6_report._incomplete_api_reason(row, context))

        label_cases = (
            ("coverage", "证据覆盖记录"),
            ("step3_dependency_compat", "依赖兼容扫描记录"),
            ("call_chain_by_api:a", "单个 API"),
            ("call_chain_by_module:a", "模块影响"),
            ("other", "分析输入证据"),
        )
        for artifact, expected in label_cases:
            self.assertIn(expected, s6_report._input_diagnostic_artifact_label({"artifact": artifact}))

        many_diagnostics = [{
            "artifact": "other",
            "path": "" if index == 0 else f"/tmp/input-{index}.json",
            "error_type": "OSError",
        } for index in range(s6_report.S6_MAIN_DIAGNOSTIC_LIMIT + 2)]
        gap_rows = s6_report._input_diagnostic_gap_rows({"diagnostics": many_diagnostics})
        self.assertEqual(len(gap_rows), s6_report.S6_MAIN_DIAGNOSTIC_LIMIT + 1)
        self.assertIn("文件名未记录", gap_rows[0]["evidence_text"])
        self.assertIn("另有 2 个", gap_rows[-1]["label"])

        diagnostics = []
        s6_report._record_diagnostic(
            diagnostics,
            artifact="",
            stage="load",
            path="/tmp/source.json",
            error=ValueError("bad"),
        )
        self.assertEqual(diagnostics[0]["artifact"], "source.json")
        s6_report._record_content_diagnostic(
            diagnostics,
            artifact="other",
            stage="contract",
            path="/tmp/source.json",
            message="bad",
        )
        self.assertEqual(len(diagnostics), 2)
        self.assertEqual(s6_report._normalize_csv_dict_row(None), {})
        self.assertEqual(s6_report._normalize_csv_dict_row({"a": None}), {"a": ""})

        row = {}
        s6_report._set_report_row_reasons(
            row,
            ["", None, "SYSTEM_CODE_REACHED", "SYSTEM_CODE_REACHED", "UNKNOWN_CODE"],
            "已确认影响",
        )
        self.assertEqual(row["reason_codes"], ["SYSTEM_CODE_REACHED", "UNKNOWN_CODE"])
        self.assertEqual(row["reason_code"], "SYSTEM_CODE_REACHED")
        self.assertIn("系统入口触达", row["reason"])
        empty_row = {}
        s6_report._set_report_row_reasons(empty_row, [], "")
        self.assertEqual(empty_row, {"reason_codes": [], "reason_code": "", "reason": ""})

        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            deliverables = report / "deliverables"
            deliverables.mkdir()
            for config in s6_report.S6_DETAIL_BUCKETS.values():
                for key in ("csv", "md"):
                    filename = str(config.get(key) or "").strip()
                    if filename:
                        (deliverables / filename).write_text("stale", encoding="utf-8")
            s6_report.cleanup_legacy_s6_detail_artifacts(report)
            self.assertEqual(list(deliverables.iterdir()), [])
            s6_report.cleanup_legacy_s6_detail_artifacts(report)

        incomplete_artifacts = s6_report.available_s6_detail_artifacts({
            "artifacts": {"confirmed_csv": "confirmed.csv"}
        })
        self.assertEqual(incomplete_artifacts, [])

    def test_authoritative_api_and_dependency_population_model_matrix(self):
        def api_row(name, coord="g:a", conclusion="已确认影响", **extra):
            return {
                "coord": coord,
                "api": f"demo.{name}.call",
                "api_signature": "()V",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
                "severity": "P1",
                "old_version": "",
                "new_version": "",
                "conclusion": conclusion,
                "paths": [],
                "business_entries": [],
                "path_count": 0,
                "confirmed_path_count": 0,
                "aggregate_count": 1,
                **extra,
            }

        inventory = [
            {**api_row("matched", "g:a"), "old_version": "1", "new_version": "2"},
            {**api_row("matched", "g:a"), "old_version": "1", "new_version": "2"},
            {**api_row("conflict", "g:b"), "old_version": "1", "new_version": "2"},
            {**api_row("conflict", "g:b"), "old_version": "0", "new_version": "3"},
            {**api_row("missing_result", "g:excluded"), "old_version": "1", "new_version": "2"},
            {"coord": "", "api": "identity.missing"},
        ]
        results = [
            api_row(
                "matched",
                "g:a",
                old_version="",
                new_version="",
                symbol_kind="",
                change_type="",
                api_signature="()V",
                change_without_severity="",
            ),
            api_row("result_not_in_inventory", "g:extra"),
            {"coord": "", "api": "invalid", "conclusion": "已确认影响"},
        ]
        population_findings = {
            "changed_api_inventory": inventory,
            "analysis_scope": {
                "excluded_dependency_coords": ["g:excluded"],
                "total_api_count": 9,
            },
            "call_chain_target_count": 8,
            "scan_stats": {"changed_apis_total": len(inventory)},
        }
        with patch.object(s6_report, "build_api_result_rows", return_value=results):
            model = s6_report.build_human_api_analysis(population_findings)
        self.assertTrue(model["count_note"])
        self.assertFalse(model["population_unconfirmed"])
        self.assertFalse(any(row.get("coord") == "g:extra" for row in model["rows"]))
        conflict = next(row for row in model["rows"] if row.get("coord") == "g:b")
        self.assertTrue(conflict["input_record_conflict"])
        self.assertEqual(conflict["old_version"], "")
        excluded = next(
            row for row in model["rows"] if row.get("coord") == "g:excluded"
        )
        self.assertIn("未包含该依赖", excluded["incomplete_reason"])
        self.assertTrue(any(row.get("api") == "API 身份未记录" for row in model["rows"]))

        no_inventory_results = [
            api_row("known", "g:known", confirmed_path_count=1),
            api_row("unknown_identity", "", conclusion="本次未完成分析"),
        ]
        with patch.object(
            s6_report, "build_api_result_rows", return_value=no_inventory_results
        ):
            conflicting_counts = s6_report.build_human_api_analysis({
                "analysis_scope": {"total_api_count": 5},
                "call_chain_target_count": 4,
                "scan_stats": {"changed_apis_total": 3},
            })
        self.assertTrue(conflicting_counts["population_unconfirmed"])
        self.assertIn("总数无法确认", conflicting_counts["count_note"])

        with patch.object(
            s6_report,
            "build_api_result_rows",
            return_value=[api_row("known", "g:known")],
        ):
            missing_identity = s6_report.build_human_api_analysis({
                "analysis_scope": {"total_api_count": 3},
                "call_chain_target_count": 3,
                "scan_stats": {"changed_apis_total": 3},
            })
        self.assertFalse(missing_identity["population_unconfirmed"])
        self.assertEqual(missing_identity["total_count"], 3)
        self.assertEqual(missing_identity["incomplete_count"], 2)
        self.assertIn("其余 2 个", missing_identity["incomplete"][0]["incomplete_reason"])

        scoped_findings = {
            "analysis_scope": {
                "mode": "partial",
                "validation_status": "valid",
                "included_dependency_count": 1,
                "available_dependency_count": 2,
                "included_dependency_coords": ["g:included"],
                "excluded_dependency_coords": ["g:excluded"],
                "analyzed_api_count": 1,
                "total_api_count": 2,
            },
            "call_chain_target_count": 1,
            "changed_api_inventory": [
                api_row("included", "g:included"),
                api_row("excluded", "g:excluded"),
            ],
        }
        with patch.object(s6_report, "build_api_result_rows", return_value=[
            api_row("included", "g:included"),
            api_row("excluded", "g:excluded"),
        ]):
            scoped_api_model = s6_report.build_human_api_analysis(scoped_findings)
        self.assertEqual(scoped_api_model["total_count"], 1)
        self.assertEqual(scoped_api_model["rows"][0]["coord"], "g:included")

        completed_api_model = {
            "rows": [
                api_row("impact", "g:impact", confirmed_path_count=2),
                api_row("safe", "g:safe", "已确认不受影响"),
                api_row("review", "g:review", "可能影响", priority_score=7),
            ],
            "population_unconfirmed": False,
        }
        completed_dependency = s6_report.build_human_dependency_analysis(
            {
                "resource_impacts": [
                    {
                        "coord": "g:resource",
                        "old_version": "1",
                        "new_version": "2",
                        "activation_status": "reachable",
                        "activation_callers": ["A", "B"],
                    }
                ],
                "per_dependency_results": [
                    {"coord": "", "old_version": "ignored"},
                    {"coord": "g:impact", "old_version": "1", "new_version": "2", "change_type": "major"},
                ],
            },
            completed_api_model,
        )
        conclusions = {row["analysis_conclusion"] for row in completed_dependency["rows"]}
        self.assertIn("确认有影响", conclusions)
        self.assertIn("确认不受 API 调用影响", conclusions)
        self.assertIn("未确认影响", conclusions)
        resource_dependency = next(
            row for row in completed_dependency["rows"]
            if row["coord"] == "g:resource"
        )
        self.assertEqual(resource_dependency["confirmed_resource_count"], 1)
        self.assertEqual(resource_dependency["confirmed_relationship_count"], 2)

        one_dependency_model = {
            "rows": [api_row("unassigned", "", "可能影响", aggregate_count=2)],
            "population_unconfirmed": False,
        }
        assigned = s6_report.build_human_dependency_analysis({
            "dependency_changes": [{
                "coord": "g:only", "old_version": "1", "new_version": "2",
                "change_type": "major",
            }],
        }, one_dependency_model)
        self.assertEqual(assigned["rows"][0]["coord"], "g:only")
        self.assertEqual(assigned["rows"][0]["api_total"], 2)
        self.assertEqual(assigned["rows"][0]["unassigned_api_count"], 0)

        conflicting_dependency_findings = {
            "dependency_changes": [
                {"coord": "g:a", "old_version": "1", "new_version": "2", "change_type": "major"},
                {"coord": "g:a", "old_version": "0", "new_version": "3", "change_type": "minor"},
                {"coord": "g:b", "old_version": "1", "new_version": "2", "change_type": "minor"},
                {"coord": "", "old_version": "1", "new_version": "2"},
            ],
            "analysis_scope": {"available_dependency_count": 6},
            "dep_changes_summary": {"major": 5},
            "per_dependency_results": [
                {"coord": "g:outside", "old_version": "x"},
                {"coord": "g:b", "old_version": "", "new_version": "", "change_type": ""},
            ],
            "resource_impacts": [
                {"coord": "g:b", "activation_status": "uncertain", "old_version": "1", "new_version": "2"},
                {"coord": "g:outside", "activation_status": "reachable"},
            ],
        }
        conflict_api_model = {
            "rows": [
                api_row("a", "g:a", confirmed_path_count=1),
                api_row("b", "g:b", "本次未完成分析", incomplete_reason="api failed"),
                api_row("outside", "g:outside"),
                api_row("unassigned", "", "本次未完成分析", aggregate_count=2),
            ],
            "population_unconfirmed": True,
        }
        dependency_conflict = s6_report.build_human_dependency_analysis(
            conflicting_dependency_findings,
            conflict_api_model,
        )
        self.assertTrue(dependency_conflict["count_note"])
        self.assertFalse(any(row["coord"] == "g:outside" for row in dependency_conflict["rows"]))
        conflict_row = next(row for row in dependency_conflict["rows"] if row["coord"] == "g:a")
        self.assertTrue(conflict_row["input_record_conflict"])
        self.assertIn("互相冲突", conflict_row["incomplete_reason"])
        b_row = next(row for row in dependency_conflict["rows"] if row["coord"] == "g:b")
        self.assertIn("运行时资源变化", b_row["api_change_text"])
        self.assertIn("依赖归属没有记录", b_row["incomplete_reason"])
        self.assertTrue(any(row["coord"] == "依赖身份未记录" for row in dependency_conflict["rows"]))

    def test_distribution_scope_database_and_user_file_rendering_matrix(self):
        rows = []
        overview_apis = []
        for index in range(s6_report.S6_CONCENTRATION_LIMIT + 3):
            row = {
                "coord": "" if index == 0 else f"g:dep{index}",
                "api": f"demo.Api{index}.call",
                "api_signature": "()V",
                "symbol_kind": "method",
                "change_type": f"CHANGE_{index}",
                "severity": ("P0", "P1", "P2", "")[index % 4],
                "conclusion": "已确认影响",
                "business_entries": [f"app.Entry{index}", "app.Shared"],
                "confirmed_path_count": index + 1,
                "confirmed_occurrence_count": index + 2,
                "paths": [f"app.Entry{index} -> demo.Api{index}.call"],
            }
            rows.append(row)
            overview_apis.append({
                **row,
                "all_entries_by_status": {
                    "reachable": [f"app.Entry{index}", "app.Shared", "", None]
                },
            })
        # A duplicate presentation row must not double count the same
        # API-entry relationship in the concentration model.
        distribution = s6_report._confirmed_impact_distribution(
            {"impact_overview": {"apis": overview_apis}},
            [*rows, dict(rows[0])],
        )
        self.assertEqual(distribution["confirmed_count"], len(rows) + 1)
        shared = next(row for row in distribution["entry_rows"] if row["entry"] == "app.Shared")
        self.assertEqual(shared["api_count"], len(rows))
        self.assertTrue(any(row["coord"] == "未知依赖" for row in distribution["dependency_rows"]))

        render_findings = {
            "p0": rows,
            "p1": [],
            "p2": [],
            "impact_overview": {
                "record_count": len(rows) + 4,
                "apis": overview_apis,
            },
        }
        rendered = "\n".join(
            s6_report.render_impact_distribution(render_findings, heading_level=0, force=True)
        )
        self.assertIn("其他变化", rendered)
        self.assertIn("其他 3 个依赖", rendered)
        self.assertIn("其他 4 个业务入口", rendered)
        self.assertIn("证据归并", rendered)
        self.assertEqual(
            s6_report.render_impact_distribution({"p0": [rows[0]]}),
            [],
        )

        self.assertEqual(s6_report.render_database_contract_changes({}), [])
        complete_empty = "\n".join(s6_report.render_database_contract_changes({
            "database_contract": {"coverage_status": "complete", "rows": []},
        }))
        self.assertIn("本次未识别到", complete_empty)
        partial_empty = "\n".join(s6_report.render_database_contract_changes({
            "database_contract": {
                "coverage_status": "partial",
                "coverage_gaps": ["missing"],
                "rows": [],
            },
            "artifacts": {"database_contract_review_md": "review.md"},
        }))
        self.assertIn("现有证据中未识别", partial_empty)
        self.assertIn("证据边界", partial_empty)
        database_rows = [
            {
                "依赖包": "g:a", "变化类型": "removed", "契约类型": "table",
                "可信度": "high", "表": "orders", "列": "id",
                "契约位置": "schema.sql", "语句或字段": "drop",
                "人工复核建议": "review",
            },
            {},
        ]
        database_text = "\n".join(s6_report.render_database_contract_changes({
            "database_contract": {"coverage_status": "insufficient", "rows": database_rows},
            "artifacts": {"database_contract_csv": "changes.csv"},
        }, limit=1))
        self.assertIn("证据不足", database_text)
        self.assertIn("未展开 1 条", database_text)
        missing_cells = "\n".join(s6_report.render_database_contract_changes({
            "database_contract": {"coverage_status": "future", "rows": [{}]},
        }))
        self.assertIn("未记录", missing_cells)
        self.assertIn("-#-", missing_cells)

        full_scope = {
            "analysis_scope": {
                "mode": "full", "validation_status": "valid",
                "available_dependency_count": 1, "included_dependency_count": 1,
                "total_api_count": 1, "analyzed_api_count": 1,
            },
            "source_inputs": {"label": "已提供", "effect": "仅作辅助"},
        }
        self.assertIn("源码辅助分析", "\n".join(s6_report.render_report_scope_notice(full_scope)))
        self.assertIn(
            "源码输入状态缺失",
            "\n".join(s6_report.render_report_scope_notice({
                **full_scope, "source_inputs": {"label": "", "effect": ""}
            })),
        )
        self.assertIn(
            "一致性校验",
            "\n".join(s6_report.render_report_scope_notice({
                "analysis_scope": {"validation_status": "invalid"}
            })),
        )
        self.assertIn(
            "记录缺失",
            "\n".join(s6_report.render_report_scope_notice({})),
        )
        partial_scope = {
            "analysis_scope": {
                "mode": "partial", "validation_status": "valid",
                "available_dependency_count": 7, "included_dependency_count": 1,
                "total_api_count": 9, "analyzed_api_count": 2,
                "included_dependency_coords": ["g:a"],
                "excluded_dependency_coords": [f"g:x{i}" for i in range(6)],
            },
        }
        partial_notice = "\n".join(s6_report.render_report_scope_notice(partial_scope))
        self.assertIn("6 个依赖和 7 个 API", partial_notice)
        self.assertNotIn("[分析范围记录]", partial_notice)
        partial_linked = copy.deepcopy(partial_scope)
        partial_linked["artifacts"] = {"analysis_scope_md": "deliverables/analysis-scope.md"}
        self.assertIn(
            "[分析范围记录]",
            "\n".join(s6_report.render_report_scope_notice(partial_linked)),
        )

        limitations_findings = copy.deepcopy(partial_scope)
        limitations_findings.update({
            "coverage": {
                "overall_status": "partial",
                "critical_incomplete": ["business_reachability"],
                "components": [{
                    "id": "business_reachability",
                    "status": "partial",
                    "reason_codes": [],
                    "evidence": [
                        "", ".runtime/state/private.json", "missing.json",
                        "/tmp/absolute-evidence.json",
                    ],
                }],
            },
            "available_evidence_paths": ["/tmp/absolute-evidence.json"],
            "p0": [rows[0]],
            "not_impacted": [{"api": "safe"}],
        })
        limitations_text = "\n".join(s6_report.render_limitations_section(limitations_findings))
        self.assertIn("等 6 个依赖", limitations_text)
        self.assertIn("不推翻", limitations_text)
        self.assertIn("absolute-evidence.json", limitations_text)
        self.assertNotIn("private.json", limitations_text)
        complete_limitations = "\n".join(s6_report.render_limitations_section({
            "analysis_scope": full_scope["analysis_scope"],
            "coverage": {"overall_status": "complete"},
        }))
        self.assertIn("未记录会改变结论", complete_limitations)

        appendix_empty = "\n".join(s6_report.render_report_appendix({}))
        self.assertIn("没有记录可用", appendix_empty)
        appendix_full = "\n".join(s6_report.render_report_appendix({
            "artifacts": {
                "analysis_scope_md": "deliverables/analysis-scope.md",
                "alerts_csv": "evidence/call_chain/alerts.csv",
                "changed_apis_csv": "evidence/api_changes/all.csv",
                "diagnostic_detail_md": "deliverables/analysis-diagnostics.md",
                "confirmed_csv": "deliverables/confirmed.csv",
                "confirmed_md": "deliverables/confirmed.md",
            }
        }))
        self.assertIn("完整逐链路", appendix_full)
        self.assertIn("完整 CSV", appendix_full)

        api_model = {
            "rows": rows,
            "completed": rows,
            "incomplete": [],
            "total_count": len(rows),
            "completed_count": len(rows),
            "incomplete_count": 0,
            "confirmed_count": len(rows),
            "confirmed_no_impact_count": 0,
            "unconfirmed_count": 0,
            "confirmed_relationship_count": 5,
            "population_unconfirmed": False,
            "scope_verified": False,
        }
        dependency_model = {
            "rows": [], "completed": [], "incomplete": [],
            "total_count": 0, "completed_count": 0, "incomplete_count": 0,
            "confirmed_any_count": 0,
            "confirmed_no_impact_completed_count": 0,
            "unconfirmed_completed_count": 0,
            "population_unconfirmed": True,
            "scope_verified": False,
        }
        minimal_files = "\n".join(s6_report.render_user_visible_files(
            {}, api_model, dependency_model
        ))
        self.assertIn("分析范围无法核验", minimal_files)
        all_artifacts = copy.deepcopy(partial_scope)
        all_artifacts.update({
            "dependency_changes": [{"coord": "g:a"}, {"coord": "g:b"}],
            "changed_api_inventory": [{"api": "A"}],
            "impact_overview": {"record_count": 1},
            "scan_stats": {"alerts_raw_record_count": 3},
            "database_contract": {"rows": database_rows},
            "diagnostics": [{"artifact": "x"}],
            "diagnostic_guidance": [{"reason_code": "x"}],
            "artifacts": {
                "alerts_csv": "evidence/call_chain/alerts.csv",
                "dependency_changes_csv": "evidence/dependencies/dep.csv",
                "database_contract_review_md": "evidence/static_scan/db.md",
                "database_contract_csv": "evidence/static_scan/db.csv",
                "changed_apis_csv": "evidence/api_changes/apis.csv",
                "binary_change_review_md": "evidence/api_changes/binary.md",
                "source_analysis_review_md": "evidence/source/review.md",
                "build_provenance_json": "evidence/dependencies/build.json",
                "analysis_scope_md": "deliverables/analysis-scope.md",
                "diagnostic_detail_md": "deliverables/diagnostics.md",
            },
        })
        all_files_text = "\n".join(s6_report.render_user_visible_files(
            all_artifacts, api_model, dependency_model
        ))
        for expected in (
            "未采用 2 条", "包含未纳入", "数据库契约", "二进制变化",
            "源码辅助", "构建来源", "分析范围记录", "输入异常 1 项",
        ):
            self.assertIn(expected, all_files_text)

        no_drop_artifacts = copy.deepcopy(all_artifacts)
        no_drop_artifacts["scan_stats"] = {"alerts_raw_record_count": 0}
        self.assertIn(
            "原始分析记录全量 1 条",
            "\n".join(s6_report.render_user_visible_files(
                no_drop_artifacts, api_model, dependency_model
            )),
        )

    def test_summary_coverage_scope_and_cross_artifact_fault_injection_matrix(self):
        def identity_item(name="A", **extra):
            return {
                "coord": "g:a",
                "api": f"demo.{name}.call",
                "api_signature": "()V",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
                **extra,
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary_path = root / "summary.json"
            coverage_path = root / "coverage.json"
            scope_path = root / "selection.json"
            context_path = root / "context.json"
            for path in (summary_path, coverage_path, scope_path, context_path):
                path.write_text("{}", encoding="utf-8")

            no_contract = {"unrelated": True}
            diagnostics = []
            s6_report._validate_call_summary_contract(
                summary_path, no_contract, diagnostics
            )
            self.assertTrue(diagnostics)

            empty_status = {
                "status": "",
                "user_conclusion_summary": None,
                "graph_stats": None,
                "meta": None,
                "diagnostic_guidance": None,
            }
            diagnostics = []
            s6_report._validate_call_summary_contract(
                summary_path, empty_status, diagnostics
            )
            self.assertTrue(diagnostics)
            self.assertIsNone(empty_status["user_conclusion_summary"])
            self.assertIsNone(empty_status["graph_stats"])

            skipped_missing_reason = {
                "status": "skipped",
                "skip_reason": "",
                "total_apis": 0,
                "reachable_apis": [],
                "not_impacted_apis": [],
                "uncertain_apis": [],
                "not_analyzed_apis": [],
                "not_found_apis": [],
            }
            diagnostics = []
            s6_report._validate_call_summary_contract(
                summary_path, skipped_missing_reason, diagnostics
            )
            self.assertTrue(diagnostics)

            valid_skip = {
                "status": "skipped",
                "skip_reason": "no_changed_apis",
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
                "meta": {"graph_stats": None},
                "diagnostic_guidance": [{
                    "reason_code": "",
                    "origin_step": "",
                    "observed_scope": "",
                    "affected_classes": None,
                    "affected_artifacts": [],
                    "affected_artifact_entries": [],
                    "collectors": [],
                    "failure_detail_summaries": [],
                    "source_components": [],
                    "sample_apis": [],
                    "repair_actions": [],
                    "verification_steps": [],
                    "candidate_evidence": None,
                    "blocking": False,
                }],
            }
            diagnostics = []
            s6_report._validate_call_summary_contract(
                summary_path, valid_skip, diagnostics
            )
            self.assertTrue(diagnostics)
            guidance = valid_skip["diagnostic_guidance"][0]
            self.assertEqual(guidance["reason_code"], "UNKNOWN")
            self.assertEqual(guidance["origin_step"], "unknown")
            self.assertEqual(guidance["observed_scope"], "unknown")
            self.assertEqual(guidance["candidate_evidence"], [])

            sanitized_summary = {
                "status": "done",
                "total_apis": 5,
                "reachable": 4,
                "reachable_apis": [
                    identity_item("unique", reason="remove me", call_paths=["A -> B"]),
                    identity_item("duplicate"),
                    identity_item("duplicate"),
                    {"coord": "", "api": "incomplete"},
                ],
                "not_impacted": 1,
                "not_impacted_apis": [identity_item("conflict")],
                "uncertain": 1,
                "uncertain_apis": [identity_item("conflict")],
                "not_analyzed_apis": [],
                "not_found_apis": [],
            }
            diagnostics = []
            s6_report._validate_call_summary_contract(
                summary_path, sanitized_summary, diagnostics
            )
            self.assertTrue(diagnostics)
            self.assertEqual(
                [item["api"] for item in sanitized_summary["reachable_apis"]],
                ["demo.unique.call", "demo.duplicate.call"],
            )
            self.assertNotIn("reason", sanitized_summary["reachable_apis"][0])
            self.assertEqual(sanitized_summary["not_impacted_apis"], [])
            self.assertEqual(sanitized_summary["uncertain_apis"], [])

            invalid_skip_by_count = {
                **valid_skip,
                "diagnostic_guidance": [],
                "total_apis": None,
                "reachable": 1,
            }
            diagnostics = []
            s6_report._validate_call_summary_contract(
                summary_path, invalid_skip_by_count, diagnostics
            )
            self.assertEqual(invalid_skip_by_count["total_apis"], 0)
            self.assertEqual(invalid_skip_by_count["reachable"], 0)

            prior_other = [{"artifact": "other", "stage": "json_load"}]
            s6_report._validate_call_summary_contract(
                summary_path, {"status": "done"}, prior_other
            )
            self.assertEqual(len(prior_other), 1)
            missing_diagnostics = []
            s6_report._validate_call_summary_contract(
                root / "absent.json", {"status": "done"}, missing_diagnostics
            )
            self.assertEqual(missing_diagnostics, [])

            coverage_variants = [
                {"overall_status": "", "critical_incomplete": "bad", "components": "bad"},
                {"overall_status": "complete", "critical_incomplete": [], "components": []},
                {
                    "overall_status": "not_applicable",
                    "critical_incomplete": ["done"],
                    "components": [
                        None,
                        {"id": "", "status": "complete"},
                        {"id": "done", "status": "not_applicable", "reason_codes": None, "evidence": []},
                        {"id": "unknown", "status": None, "reason_codes": [], "evidence": []},
                    ],
                },
            ]
            for index, coverage in enumerate(coverage_variants):
                with self.subTest(coverage=index):
                    diagnostics = []
                    s6_report._validate_coverage_contract(
                        coverage_path, coverage, diagnostics
                    )
                    if index == 1:
                        self.assertEqual(diagnostics, [])
                    else:
                        self.assertTrue(diagnostics)
            prior_coverage = [{"artifact": "coverage", "stage": "json_load"}]
            s6_report._validate_coverage_contract(
                coverage_path, {"overall_status": "complete"}, prior_coverage
            )
            self.assertEqual(len(prior_coverage), 1)
            no_coverage_file = []
            s6_report._validate_coverage_contract(
                root / "absent-coverage.json", {}, no_coverage_file
            )
            self.assertEqual(no_coverage_file, [])

            scope_variants = [
                {
                    "mode": "future",
                    "available_dependency_count": 1,
                    "included_dependency_count": 0,
                    "total_api_count": 0,
                    "analyzed_api_count": 0,
                    "included_dependency_coords": [],
                    "excluded_dependency_coords": [],
                    "selected_names": [],
                },
                {
                    "mode": "full",
                    "available_dependency_count": 1,
                    "included_dependency_count": 1,
                    "total_api_count": 1,
                    "analyzed_api_count": 1,
                    "included_dependency_coords": [" ", "g:a", "g:a"],
                    "excluded_dependency_coords": [" "],
                    "selected_names": [" ", "g:a"],
                },
                {
                    "mode": "partial",
                    "available_dependency_count": 2,
                    "included_dependency_count": 1,
                    "total_api_count": 2,
                    "analyzed_api_count": 1,
                    "included_dependency_coords": [],
                    "excluded_dependency_coords": [],
                    "selected_names": [],
                },
            ]
            for index, scope in enumerate(scope_variants):
                diagnostics = []
                s6_report._validate_analysis_scope_contract(
                    scope_path, scope, diagnostics
                )
                self.assertEqual(bool(diagnostics), index != 1)
            valid_scope = {
                "mode": "full",
                "available_dependency_count": 0,
                "included_dependency_count": 0,
                "total_api_count": 0,
                "analyzed_api_count": 0,
            }
            diagnostics = []
            s6_report._validate_analysis_scope_contract(
                scope_path, valid_scope, diagnostics
            )
            self.assertEqual(diagnostics, [])
            prior_scope = [{"artifact": "step5_selection", "stage": "json_load"}]
            s6_report._validate_analysis_scope_contract(
                scope_path, valid_scope, prior_scope
            )
            self.assertEqual(len(prior_scope), 1)
            missing_scope_diagnostics = []
            s6_report._validate_analysis_scope_contract(
                root / "absent-scope.json", {}, missing_scope_diagnostics
            )
            self.assertEqual(missing_scope_diagnostics, [])

            prior_context = [{"artifact": "context", "stage": "json_load"}]
            s6_report._validate_context_contract(
                context_path, {}, prior_context
            )
            self.assertEqual(len(prior_context), 1)
            missing_context = []
            s6_report._validate_context_contract(
                root / "absent-context.json", {}, missing_context
            )
            self.assertEqual(missing_context, [])

            scope_consistency_cases = (
                ({}, 0, [], False),
                ({"mode": "partial", "analyzed_api_count": 1, "total_api_count": 1}, 1, [identity_item()], False),
                ({"mode": "partial", "analyzed_api_count": 1, "total_api_count": 0}, 1, [], True),
                ({"mode": "full", "analyzed_api_count": 1, "total_api_count": 1}, 2, [identity_item()], True),
            )
            for index, (scope, target, changed, expect_diagnostic) in enumerate(scope_consistency_cases):
                diagnostics = []
                s6_report._validate_scope_consistency(
                    scope=scope,
                    target_api_count=target,
                    changed_apis=changed,
                    diagnostics=diagnostics,
                    selection_path=scope_path,
                )
                self.assertEqual(bool(diagnostics), expect_diagnostic, index)

            prior_changed = [{"artifact": "changed_apis", "stage": "csv_load"}]
            scope = {"mode": "full", "analyzed_api_count": 0, "total_api_count": 0}
            s6_report._validate_scope_consistency(
                scope=scope,
                target_api_count=0,
                changed_apis=[identity_item()],
                diagnostics=prior_changed,
                selection_path=scope_path,
            )
            self.assertEqual(len(prior_changed), 1)

        exact = identity_item(
            severity="P1", old_version="1", new_version="2"
        )
        exact_overview = {
            **identity_item(),
            "bucket": "confirmed",
            "severity_values": ["P1"],
            "old_version_values": ["1"],
            "new_version_values": ["2"],
        }
        exact_summary = {
            "reachable_apis": [dict(exact)],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
        }
        diagnostics = []
        s6_report._validate_cross_artifact_identities(
            call_summary=exact_summary,
            changed_apis=[dict(exact)],
            impact_overview={"fact_apis": [exact_overview]},
            scope_mode="full",
            diagnostics=diagnostics,
            changed_apis_path="changed.csv",
            alerts_path="alerts.csv",
        )
        self.assertEqual(diagnostics, [])
        self.assertEqual(exact_summary["reachable_apis"][0]["severity"], "P1")

        mismatch_summary = {
            "reachable_apis": [identity_item(
                "A", severity="P0", old_version="0", new_version="9"
            ), None],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
        }
        conflicting_changed = [
            identity_item("A", severity="P1", old_version="1", new_version="2"),
            identity_item("A", severity="P2", old_version="1", new_version="2"),
            identity_item("inventory_only", severity="", old_version="", new_version=""),
            {"coord": "", "api": "invalid"},
        ]
        mismatch_overview = {
            "apis": [
                {
                    **identity_item("A"),
                    "bucket": "review",
                    "severity_values": ["P0", ""],
                    "old_version_values": ["0"],
                    "new_version_values": ["9"],
                },
                {"coord": "", "api": "invalid", "bucket": "confirmed"},
            ]
        }
        diagnostics = []
        # The non-object row exercises this helper's defensive branch.  Its
        # normal caller has already sanitized summary buckets, so isolate the
        # downstream downgrade routine rather than duplicating that contract.
        with patch.object(s6_report, "_downgrade_unverified_certain_results"):
            s6_report._validate_cross_artifact_identities(
                call_summary=mismatch_summary,
                changed_apis=conflicting_changed,
                impact_overview=mismatch_overview,
                scope_mode="full",
                diagnostics=diagnostics,
                changed_apis_path="changed.csv",
                alerts_path="alerts.csv",
            )
        artifacts = {item["artifact"] for item in diagnostics}
        self.assertIn("changed_apis", artifacts)
        self.assertIn("call_chain_alerts", artifacts)

        field_mismatch_summary = {
            "reachable_apis": [identity_item(
                "A", severity="P0", old_version="0", new_version="9"
            )],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
        }
        field_mismatch_overview = {
            "fact_apis": [{
                **identity_item("A"),
                "bucket": "confirmed",
                "severity_values": ["P0"],
                "old_version_values": ["0"],
                "new_version_values": ["9"],
            }]
        }
        diagnostics = []
        s6_report._validate_cross_artifact_identities(
            call_summary=field_mismatch_summary,
            changed_apis=[dict(exact)],
            impact_overview=field_mismatch_overview,
            scope_mode="partial",
            diagnostics=diagnostics,
            changed_apis_path="changed.csv",
            alerts_path="alerts.csv",
        )
        stages = {(item["artifact"], item["stage"]) for item in diagnostics}
        self.assertIn(("call_chain_summary", "field_consistency"), stages)
        self.assertIn(("call_chain_alerts", "field_consistency"), stages)
        self.assertEqual(field_mismatch_summary["reachable_apis"][0]["severity"], "P1")
        self.assertEqual(field_mismatch_overview["fact_apis"][0]["severity_values"], ["P1"])

        suppressed = [
            {"artifact": "changed_apis", "stage": "csv_load"},
            {"artifact": "call_chain_summary", "stage": "json_contract"},
            {"artifact": "call_chain_alerts", "stage": "csv_contract"},
        ]
        s6_report._validate_cross_artifact_identities(
            call_summary=field_mismatch_summary,
            changed_apis=[dict(exact), {**dict(exact), "severity": "P2"}],
            impact_overview=field_mismatch_overview,
            scope_mode="full",
            diagnostics=suppressed,
            changed_apis_path="changed.csv",
            alerts_path="alerts.csv",
        )
        self.assertEqual(len(suppressed), 3)

    def test_collect_findings_missing_fatal_and_fallback_input_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            directories = (
                report / "evidence" / "dependencies",
                report / "evidence" / "context",
                report / "evidence" / "static_scan",
                report / "evidence" / "api_changes",
                report / "evidence" / "call_chain",
                report / "evidence" / "call_chain" / "by_api",
                report / "evidence" / "call_chain" / "by_module",
            )
            for directory in directories:
                directory.mkdir(parents=True, exist_ok=True)
            for relative in (
                "evidence/dependencies/dep_changes.csv",
                "evidence/dependencies/dependency_jars.json",
                "evidence/call_chain/alerts.csv",
                "evidence/call_chain/bytecode_unresolved.csv",
                "evidence/api_changes/all_changed_apis.csv",
                "evidence/static_scan/s3_database_contract_changes.csv",
                "evidence/static_scan/s3_database_contract_changes.md",
                "evidence/static_scan/s3_database_contract_summary.json",
            ):
                path = report / relative
                path.write_text("placeholder", encoding="utf-8")
            (report / "evidence/call_chain/by_api/ignored.txt").write_text(
                "ignored", encoding="utf-8"
            )
            (report / "evidence/call_chain/by_api/coord-only.json").write_text(
                "{}", encoding="utf-8"
            )
            (report / "evidence/call_chain/by_api/invalid-with-diagnostic.json").write_text(
                "{}", encoding="utf-8"
            )
            (report / "evidence/call_chain/by_module/ignored.json").write_text(
                "{}", encoding="utf-8"
            )

            scenario = {"name": "fatal-empty"}

            blank_item = self._step5_item(
                "blank",
                coord="",
                conclusion="",
                reason_code="",
                api="",
            )
            summary_with_fallbacks = {
                "status": "done",
                "total_apis": 4,
                "origin_step": "",
                "reachable": 1,
                "not_impacted": 1,
                "uncertain": 1,
                "not_analyzed": 1,
                "not_found_in_static_analysis": 1,
                "reachable_apis": [{
                    **blank_item,
                    "coord": "g:a",
                    "user_conclusion": "",
                    "decision_bucket": "other",
                    "old_version": "",
                    "new_version": "",
                }],
                "not_impacted_apis": [{**blank_item, "coord": "g:a"}],
                "uncertain_apis": [dict(blank_item)],
                "not_analyzed_apis": [dict(blank_item)],
                "not_found_apis": [dict(blank_item)],
                "diagnostic_guidance": [{
                    "reason_code": "",
                    "origin_step": "",
                    "observed_scope": "",
                    "blocking": False,
                }],
                "meta": {"graph_stats": {
                    "truncated": True,
                    "truncation_reasons": ["CALL_GRAPH_TRUNCATED"],
                }},
            }

            def fake_load_json(path, *, diagnostics=None, artifact="", required=False):
                if artifact == "coverage":
                    return {} if scenario["name"] == "fallback-summary" else {
                        "overall_status": "partial",
                        "critical_incomplete": [],
                        "components": [
                            {"id": "", "reason_codes": ["DUPLICATE", ""]},
                            {"id": "component", "reason_codes": ["DUPLICATE", "DUPLICATE"]},
                        ],
                    }
                if artifact == "step5_selection":
                    return {} if scenario["name"] == "fatal-empty" else {
                        "mode": "full"
                    }
                if artifact == "call_chain_summary":
                    return {} if scenario["name"] == "fatal-empty" else copy.deepcopy(
                        summary_with_fallbacks
                    )
                if artifact == "step3_database_contract_summary":
                    if scenario["name"] == "fatal-empty":
                        return {
                            "schema": "unsupported",
                            "change_count": 2,
                            "coverage_status": "complete",
                            "coverage_gaps": [],
                        }
                    return {
                        "schema": "java-upgrade-analyzer.database-contract-changes.v1",
                        "change_count": 0,
                        "coverage_status": "complete",
                    }
                if artifact == "call_chain_by_api:coord-only.json":
                    return {"coord": "g:a", "api": "", "evidence_paths": []}
                if artifact == "call_chain_by_api:invalid-with-diagnostic.json":
                    s6_report._record_content_diagnostic(
                        diagnostics,
                        artifact=artifact,
                        stage="json_contract",
                        path=path,
                        message="preexisting",
                    )
                    return {"coord": "", "api": "", "evidence_paths": "bad"}
                return {}

            def fake_load_csv(path, *, diagnostics=None, artifact="", required=False):
                if artifact == "step3_database_contract_changes":
                    return [{"依赖包": "g:a"}] if scenario["name"] == "fatal-empty" else []
                if artifact == "step3_dependency_compat":
                    if scenario["name"] == "fatal-empty":
                        return [{"坐标": "g:background", "风险类型": "binary"}]
                    return [{"坐标": "g:a", "风险类型": "binary"}]
                if artifact == "dependency_changes":
                    return [{"coord": "g:a", "change_type": "major"}]
                if artifact == "changed_apis":
                    return []
                return []

            def fake_validate_csv(path, *, diagnostics=None, artifact="", **kwargs):
                if scenario["name"] == "fatal-empty" and artifact in {
                    "step3_database_contract_changes",
                    "call_chain_alerts",
                    "changed_apis",
                }:
                    s6_report._record_content_diagnostic(
                        diagnostics,
                        artifact=artifact,
                        stage="csv_contract",
                        path=path,
                        message="fatal contract",
                    )

            def fake_overview(_rows):
                if scenario["name"] == "fatal-empty":
                    return {
                        "record_count": 0,
                        "fact_apis": [],
                        "apis": [{"coord": "g:fallback", "api": "fallback"}],
                    }
                return {"record_count": 0, "fact_apis": [], "apis": []}

            per_dependency = [
                {"coord": "", "step5": {}},
                {
                    "coord": "g:a",
                    "old_version": "",
                    "new_version": "",
                    "change_type": "",
                    "step4": None,
                    "step5": None,
                },
            ]

            common_patches = (
                patch.object(s6_report, "load_json", side_effect=fake_load_json),
                patch.object(s6_report, "load_csv", side_effect=fake_load_csv),
                patch.object(s6_report, "iter_csv_rows", return_value=iter(())),
                patch.object(s6_report, "_validated_alert_rows", return_value=[]),
                patch.object(s6_report, "build_impact_overview", side_effect=fake_overview),
                patch.object(s6_report, "_validate_csv_contract", side_effect=fake_validate_csv),
                patch.object(s6_report, "_validate_coverage_contract"),
                patch.object(s6_report, "_validate_analysis_scope_contract"),
                patch.object(s6_report, "_validate_context_contract"),
                patch.object(s6_report, "_validate_call_summary_contract"),
                patch.object(s6_report, "_validate_scope_consistency"),
                patch.object(s6_report, "_validate_cross_artifact_identities"),
                patch.object(s6_report, "load_per_dependency_summaries", return_value=per_dependency),
                patch.object(s6_report, "count_lines", return_value=-1),
                patch.object(s6_report, "_collect_available_evidence_paths", return_value=[]),
            )
            for active in common_patches:
                active.start()
            try:
                fatal = s6_report.collect_findings(report)
                self.assertNotIn("alerts_csv", fatal["artifacts"])
                self.assertNotIn("changed_apis_csv", fatal["artifacts"])
                self.assertEqual(fatal["database_contract"]["rows"], [])
                self.assertEqual(fatal["database_contract"]["coverage_status"], "partial")
                self.assertEqual(fatal["background_signals"]["dep_compat_total"], 1)
                self.assertEqual(fatal["p0"], [])

                scenario["name"] = "fallback-summary"
                # iterators returned by mocks are single-use; replace it for
                # the second independent collection.
                s6_report.iter_csv_rows.return_value = iter(())
                fallback = s6_report.collect_findings(report)
                self.assertTrue(fallback["coverage"])
                self.assertNotIn("alerts_csv", fallback["artifacts"])
                self.assertNotIn("changed_apis_csv", fallback["artifacts"])
                self.assertEqual(fallback["dep_compat_summary"]["impacted_total"], 1)
                self.assertEqual(fallback["background_signals"]["dep_compat_total"], 0)
                self.assertTrue(fallback["p2"])
                self.assertTrue(fallback["uncertain"])
                self.assertTrue(fallback["not_found"])
            finally:
                for active in reversed(common_patches):
                    active.stop()

    def test_impact_overview_precedence_deduplication_and_empty_field_matrix(self):
        base = {
            "target_coord": "",
            "changed_symbol": "demo.Api.call",
            "api_signature": "()V",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "change_fact_identity": "fact-1",
            "business_entry": "app.Entry.start",
            "evidence_files": "module/src/main/java/App.java|",
        }
        rows = [
            {},
            {"changed_symbol": ""},
            {
                **base,
                "path_status": "uncertain",
                "path_text": "",
                "path_occurrence_count": "1",
                "api_id": "one",
                "severity": "",
                "old_version": "",
                "new_version": "",
                "action": "",
                "review_focus": "review",
                "reason": "",
                "review_reason": "reason",
            },
            {
                **base,
                "path_status": "reachable",
                "path_text": "",
                "path_occurrence_count": "3",
                "api_id": "one",
                "severity": "P0",
                "old_version": "1",
                "new_version": "2",
                "action": "act",
                "reason": "fact",
            },
            {
                **base,
                "path_status": "",
                "api_status": "not_impacted",
                "path_text": "app.Entry.start -> demo.Api.call",
                "path_occurrence_count": "bad",
                "api_id": "two",
            },
            {
                **base,
                "path_status": "",
                "api_status": "",
                "business_entry": "",
                "chain_entry": "",
                "consumer_class": "app.Consumer",
                "consumer_method": "run",
                "path_text": "consumer -> target",
                "evidence_files": "",
                "stop_reason": "stopped",
            },
            {
                **base,
                "target_coord": "g:a",
                "changed_symbol": "demo.Other.call",
                "change_fact_identity": "fact-2",
                "path_status": "reachable",
                "business_entry": "app.Other.start",
                "path_text": "app.Other.start -> demo.Other.call",
                "evidence_files": "",
            },
        ]
        overview = s6_report.build_impact_overview(rows)
        self.assertEqual(overview["record_count"], len(rows) - 2)
        api = next(item for item in overview["apis"] if item["api"] == "demo.Api.call")
        self.assertEqual(api["bucket"], "confirmed")
        self.assertEqual(api["api_id"], "")
        self.assertEqual(api["occurrence_counts_by_status"]["reachable"], 3)
        self.assertIn("app.Consumer.run", api["sample_entries"])
        self.assertIn("unknown", api["status_counts"])
        self.assertEqual(overview["dependency_count"], 1)
        blank_coord_entry = next(
            item for item in overview["business_entries"]
            if item["entry"] == "app.Entry.start"
        )
        self.assertEqual(blank_coord_entry["dependency_count"], 0)
        self.assertEqual(blank_coord_entry["path_count"], 0)

        with patch.object(s6_report, "_module_from_evidence_file", return_value=""):
            no_module = s6_report.build_impact_overview([{
                **base,
                "path_status": "reachable",
                "path_text": "A -> B",
                "evidence_files": "unmappable",
            }])
        self.assertEqual(no_module["apis"][0]["module_count"], 0)
        self.assertEqual(no_module["business_entries"][0]["sample_modules"], [])

    def test_step5_fallback_and_population_default_value_matrix(self):
        graph_variants = (
            ({"truncated": False}, {}, "complete"),
            ({"truncated": False, "edge_cap_hits": 2}, {}, "partial"),
            ({"truncated": False, "parser_fallback_reasons": {"javap": 1}}, {}, "partial"),
            ({
                "truncated": False,
                "source_artifact_alignment": {"status": "", "artifact_path": "", "git_root": "repo"},
                "artifact_bytecode": {"status": "", "reason_codes": []},
                "business_bytecode": {"status": "", "failures": []},
                "indirect_usage": {"status": "", "reason_codes": []},
            }, {}, "partial"),
            ({
                "truncated": False,
                "source_artifact_alignment": {"status": "partial", "artifact_path": "artifact"},
                "artifact_bytecode": {"status": "complete"},
                "business_bytecode": {"status": "complete"},
                "indirect_usage": {"status": "complete"},
            }, {"total_apis": 2, "not_impacted": 2}, "complete"),
        )
        for graph_stats, summary_values, expected_status in graph_variants:
            summary = {
                **summary_values,
                "meta": {"graph_stats": graph_stats},
            }
            result = s6_report._step5_summary_coverage_fallback(summary)
            self.assertEqual(result["overall_status"], expected_status)
        self.assertEqual(
            s6_report._step5_summary_coverage_fallback({"meta": []}), {}
        )
        unknown_integer = s6_report._step5_summary_coverage_fallback({
            "total_apis": object(),
            "meta": {"graph_stats": {"truncated": False}},
        })
        self.assertEqual(unknown_integer["overall_status"], "complete")

        def api(name, coord="g:a", conclusion="可能影响", **extra):
            return {
                "coord": coord,
                "api": f"demo.{name}.call",
                "api_signature": "()V",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
                "severity": "",
                "old_version": "",
                "new_version": "",
                "conclusion": conclusion,
                "aggregate_count": 0,
                **extra,
            }

        exact_inventory = [api("exact")]
        exact_findings = {
            "changed_api_inventory": exact_inventory,
            "analysis_scope": {"total_api_count": 1},
            "call_chain_target_count": 1,
            "scan_stats": {"changed_apis_total": 1},
        }
        with patch.object(
            s6_report, "build_api_result_rows", return_value=[api("exact")]
        ):
            exact_api_model = s6_report.build_human_api_analysis(exact_findings)
        self.assertEqual(exact_api_model["count_note"], "")
        self.assertEqual(exact_api_model["total_count"], 1)
        self.assertEqual(exact_api_model["unconfirmed_count"], 1)

        scoped_zero = {
            "mode": "full",
            "validation_status": "valid",
            "available_dependency_count": 0,
            "included_dependency_count": 0,
            "total_api_count": 0,
            "analyzed_api_count": 0,
            "included_dependency_coords": [],
            "excluded_dependency_coords": [],
        }
        with patch.object(s6_report, "build_api_result_rows", return_value=[]):
            zero_api_model = s6_report.build_human_api_analysis({
                "analysis_scope": scoped_zero,
                "call_chain_target_count": 0,
            })
        self.assertEqual(zero_api_model["total_count"], 0)
        self.assertTrue(zero_api_model["scope_verified"])

        dependency_api_model = {
            "rows": [
                api("blank_conclusion", "g:blank", ""),
                api("multi_a", "g:multi", old_version="1", new_version="2"),
                api("multi_b", "g:multi", old_version="0", new_version="3"),
                api("incomplete", "g:resource", "本次未完成分析", incomplete_reason="failed"),
            ],
            "population_unconfirmed": False,
        }
        dependency_findings = {
            "per_dependency_results": [
                {"coord": "g:blank", "old_version": "1", "new_version": "2", "change_type": "minor"},
                {"coord": "g:blank", "old_version": "ignored", "new_version": "ignored", "change_type": "ignored"},
            ],
            "resource_impacts": [
                {"coord": "", "activation_status": "reachable"},
                {"coord": "g:resource", "activation_status": "reachable", "activation_callers": []},
                {"coord": "g:resource", "activation_status": "uncertain"},
                {"coord": "g:resource_only", "activation_status": "uncertain", "old_version": "", "new_version": ""},
            ],
            "analysis_scope": {"available_dependency_count": 5},
            "dep_changes_summary": {"unknown": 0},
        }
        default_dependency_model = s6_report.build_human_dependency_analysis(
            dependency_findings,
            dependency_api_model,
        )
        resource = next(
            row for row in default_dependency_model["rows"]
            if row["coord"] == "g:resource"
        )
        self.assertIn("部分结果确认有影响", resource["analysis_conclusion"])
        self.assertIn("运行时资源变化", resource["incomplete_reason"])
        resource_only = next(
            row for row in default_dependency_model["rows"]
            if row["coord"] == "g:resource_only"
        )
        self.assertEqual(
            resource_only["api_change_text"],
            "未记录变化 API；运行时资源变化 1 个，已确认当前系统激活 0 个",
        )
        multi = next(
            row for row in default_dependency_model["rows"]
            if row["coord"] == "g:multi"
        )
        self.assertEqual(multi.get("old_version", ""), "")
        self.assertEqual(multi.get("new_version", ""), "")
        self.assertFalse(default_dependency_model["population_unconfirmed"])
        self.assertTrue(any(
            row["coord"] == "依赖身份未记录"
            for row in default_dependency_model["rows"]
        ))

        exact_dependency_model = s6_report.build_human_dependency_analysis({
            "dependency_changes": [{
                "coord": "g:one", "old_version": "", "new_version": "", "change_type": ""
            }],
            "analysis_scope": {"available_dependency_count": 1},
            "dep_changes_summary": {"changed": 1},
        }, {
            "rows": [api("one", "g:one", "已确认不受影响")],
            "population_unconfirmed": False,
        })
        self.assertEqual(exact_dependency_model["count_note"], "")
        self.assertEqual(exact_dependency_model["confirmed_no_impact_completed_count"], 1)

    def test_remaining_low_level_normalization_grouping_and_downgrade_matrix(self):
        with self.assertRaises(s6_report.ArtifactContentError):
            s6_report._normalize_csv_dict_row({1: "value"})

        diagnostics = [
            {"artifact": "other", "stage": "same"},
            {"artifact": "target", "stage": "other"},
        ]
        s6_report._record_content_diagnostic(
            diagnostics,
            artifact="target",
            stage="same",
            path="/tmp/a.json",
            message="new",
        )
        self.assertEqual(len(diagnostics), 3)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.csv"
            path.write_text(",name\n,value\n", encoding="utf-8")
            contract_diagnostics = []
            s6_report._validate_csv_contract(
                path,
                diagnostics=contract_diagnostics,
                artifact="blank_header_cell",
                required_column_groups=({"name"},),
                require_data=True,
            )
            self.assertEqual(contract_diagnostics, [])

            class Reader:
                def __iter__(self):
                    return iter(({}, {"name": " value "}))

            with patch.object(s6_report.csv, "DictReader", return_value=Reader()):
                self.assertEqual(
                    s6_report.load_csv(path), [{"name": "value"}]
                )
            with patch.object(s6_report.csv, "DictReader", return_value=Reader()):
                self.assertEqual(
                    list(s6_report.iter_csv_rows(path)), [{"name": "value"}]
                )

        self.assertEqual(s6_report._minimum_compatible_variant_groups([]), 0)
        exact_search_variants = [
            (None, None, "(A)", "(A)", None),
            (None, "(C)", "(A)", "(B)", "(B)"),
            ("(A)", "(C)", "(A)", None, "(B)"),
            ("(B)", None, None, None, "(B)"),
            ("(B)", "(C)", "(A)", None, "(A)"),
            ("(B)", "(C)", "(B)", "(B)", "(A)"),
        ]
        exact_groups = s6_report._minimum_compatible_variant_groups(
            exact_search_variants
        )
        self.assertGreaterEqual(exact_groups, 3)
        self.assertLessEqual(exact_groups, 4)
        large_variants = [
            (None, None, None, "(C)", None),
            (None, None, "(C)", "(A)", "(A)"),
            (None, None, "(C)", "(B)", "(C)"),
            (None, None, "(C)", "(C)", "(B)"),
            (None, "(B)", None, "(C)", "(B)"),
            (None, "(B)", "(C)", "(B)", "(C)"),
            (None, "(C)", "(A)", "(C)", "(A)"),
            (None, "(C)", "(B)", "(B)", "(C)"),
            ("(A)", None, "(B)", None, "(B)"),
            ("(A)", None, "(B)", "(A)", "(A)"),
            ("(A)", "(A)", None, None, "(B)"),
            ("(A)", "(A)", "(C)", None, "(A)"),
            ("(A)", "(A)", "(C)", None, "(C)"),
            ("(A)", "(B)", "(C)", "(B)", None),
            ("(A)", "(C)", None, "(B)", "(C)"),
            ("(A)", "(C)", None, "(C)", "(C)"),
            ("(B)", None, "(B)", None, "(C)"),
            ("(B)", None, "(B)", "(C)", "(C)"),
            ("(B)", None, "(C)", "(B)", "(B)"),
            ("(B)", "(A)", "(C)", "(B)", None),
            ("(B)", "(A)", "(C)", "(C)", "(B)"),
            ("(B)", "(B)", "(C)", "(A)", "(C)"),
            ("(B)", "(B)", "(C)", "(B)", "(B)"),
            ("(B)", "(C)", None, "(C)", "(A)"),
            ("(B)", "(C)", None, "(C)", "(B)"),
            ("(B)", "(C)", "(C)", None, None),
            ("(B)", "(C)", "(C)", "(A)", "(A)"),
            ("(C)", None, None, None, "(B)"),
            ("(C)", None, "(C)", "(A)", None),
            ("(C)", "(A)", "(A)", "(B)", "(C)"),
            ("(C)", "(A)", "(B)", "(C)", "(B)"),
            ("(C)", "(B)", "(B)", None, "(A)"),
            ("(C)", "(C)", "(A)", "(B)", "(C)"),
        ]
        self.assertEqual(
            s6_report._minimum_compatible_variant_groups(large_variants), 21
        )

        verified = self._step5_item("verified")
        moved = self._step5_item("moved", api="", api_signature="")
        moved_identity = s6_report.build_api_identity_key(moved)
        existing_moved = {**moved, "reason": "already present"}
        summary = {
            "reachable_apis": [verified, moved],
            "not_impacted_apis": [],
            "not_analyzed_apis": [existing_moved],
            "diagnostic_guidance": [],
        }
        s6_report._downgrade_unverified_certain_results(
            summary,
            {s6_report.build_api_identity_key(verified)},
        )
        self.assertEqual(len(summary["reachable_apis"]), 1)
        self.assertEqual(
            sum(
                s6_report.build_api_identity_key(item) == moved_identity
                for item in summary["not_analyzed_apis"]
            ),
            1,
        )
        self.assertEqual(summary["not_impacted"], 0)
        self.assertEqual(summary["diagnostic_guidance"][0]["reason_code"], "S6_EVIDENCE_IDENTITY_MISMATCH")

        second = {
            "reachable_apis": [],
            "not_impacted_apis": [self._step5_item("safe")],
            "not_analyzed_apis": [],
            "diagnostic_guidance": [{
                "reason_code": "S6_EVIDENCE_IDENTITY_MISMATCH"
            }],
        }
        s6_report._downgrade_unverified_certain_results(second, set())
        self.assertEqual(len(second["diagnostic_guidance"]), 1)

        change_defaults = (
            {"change_type": "DATA_FIELD_ADDED"},
            {"change_type": "DATA_FIELD_REMOVED"},
            {"change_type": "MEMBER_RESOLUTION_CHANGED"},
            {"change_type": "DATA_FIELD_TYPE_CHANGED"},
        )
        for item in change_defaults:
            self.assertTrue(s6_report._change_summary(item))

        ordered = s6_report._order_uncertain_items_by_dependency([
            {"coord": "", "priority_score": 0, "api": "blank"},
            {"priority_score": "", "paths": []},
            {"coord": "g:a", "priority_score": 2},
        ])
        self.assertEqual(len(ordered), 3)
        self.assertEqual(ordered[0]["coord"], "g:a")
        self.assertEqual(ordered[-1].get("coord", ""), "")

        detail = s6_report._detail_row(
            1,
            {"user_conclusion": "可能影响", "reason_code": "LOW_CONFIDENCE_EDGE"},
        )
        self.assertIn("可能影响", detail)
        uncertainty_detail = s6_report._detail_row(1, {
            "uncertainty_kind": s6_report.UNCERTAINTY_KIND_ANALYSIS_LIMITATION,
        })
        self.assertIn("静态分析能力边界", uncertainty_detail)
        self.assertIn(
            "没有更多",
            s6_report._detail_review_focus({"user_conclusion": "future"}),
        )

        with patch.object(
            s6_report, "_normalize_evidence_paths", return_value=([[]], True)
        ):
            self.assertNotIn("证据边", "\n".join(s6_report._fmt_issue({})))

    def test_artifact_writers_default_empty_and_complete_state_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)

            no_findings_scope = s6_report.write_analysis_scope_artifact(
                report / "none", None
            )
            no_findings_text = (
                report / "none" / no_findings_scope
            ).read_text(encoding="utf-8")
            self.assertIn("范围未记录", no_findings_text)

            default_source_report = report / "default-source"
            default_source_scope = s6_report.write_analysis_scope_artifact(
                default_source_report,
                {
                    "analysis_scope": {
                        "excluded_dependency_coords": ["", "g:excluded"],
                        "selected_names": ["", "alias"],
                    },
                    "source_inputs": {
                        "label": "",
                        "effect": "",
                        "mapped_count": None,
                        "coverage_status": "",
                    },
                },
            )
            default_source_text = (
                default_source_report / default_source_scope
            ).read_text(encoding="utf-8")
            self.assertIn("`g:excluded`", default_source_text)
            self.assertIn("`alias`", default_source_text)
            self.assertIn("源码输入状态缺失", default_source_text)
            self.assertIn("作用和边界**：未记录", default_source_text)
            self.assertIn("覆盖状态**：`not_provided`", default_source_text)
            self.assertNotIn("源码辅助证据](", default_source_text)

            diagnostic_path = (
                report / "diagnostics" / "deliverables" /
                "analysis-diagnostics.md"
            )
            diagnostic_path.parent.mkdir(parents=True)
            diagnostic_path.write_text("stale", encoding="utf-8")
            self.assertEqual(
                s6_report.write_diagnostic_detail_artifact(
                    report / "diagnostics", {}
                ),
                "",
            )
            self.assertFalse(diagnostic_path.exists())

            diagnostic_cases = (
                {
                    "diagnostic_guidance": [{
                        "reason_code": "UNKNOWN_REASON",
                        "origin_step": "step6",
                    }],
                    "diagnostics": [],
                },
                {
                    "diagnostic_guidance": [],
                    "diagnostics": [{
                        "artifact": "context",
                        "stage": "json_load",
                        "path": "",
                        "error_type": "OSError",
                    }],
                },
                {
                    "diagnostic_guidance": [{
                        "reason_code": "UNKNOWN_REASON",
                    }],
                    "diagnostics": [{
                        "artifact": "context",
                        "stage": "json_load",
                        "path": "/tmp/context.json",
                        "error_type": "OSError",
                    }],
                },
            )
            for index, findings in enumerate(diagnostic_cases):
                case_report = report / f"diagnostic-case-{index}"
                relative = s6_report.write_diagnostic_detail_artifact(
                    case_report, findings
                )
                self.assertEqual(
                    relative, "deliverables/analysis-diagnostics.md"
                )
                self.assertTrue((case_report / relative).is_file())

            with patch.object(s6_report, "S6_DETAIL_BUCKETS", {
                "future": {"title": ""},
            }):
                available = s6_report.available_s6_detail_artifacts({
                    "artifacts": {
                        "future_csv": "future.csv",
                        "future_md": "future.md",
                    }
                })
            self.assertEqual(available[0]["title"], "future")

            blank_bucket = s6_report.write_bucket_detail_artifacts(
                report / "blank-bucket",
                {"future": [{}], "artifacts": {}},
                "future",
            )
            self.assertTrue(blank_bucket)
            blank_csv = report / "blank-bucket" / blank_bucket["future_csv"]
            with blank_csv.open(encoding="utf-8-sig", newline="") as stream:
                blank_rows = list(csv.DictReader(stream))
            self.assertEqual(blank_rows[0]["conclusion"], "结论未确定")
            self.assertEqual(blank_rows[0]["coord"], "")

            confirmed_rows = [
                {
                    "coord": "" if index == 0 else "g:a",
                    "api": "" if index == 0 else f"demo.Api.call{index}",
                    "api_signature": "",
                    "conclusion": "已确认影响",
                    "severity": "",
                    "business_entries": [],
                    "modules": [],
                    "change_without_severity": "",
                    "reason": "",
                    "path_count": 0,
                    "occurrence_count": 0,
                }
                for index in range(9)
            ]
            with patch.object(
                s6_report, "build_api_result_rows", return_value=confirmed_rows
            ):
                confirmed_artifacts = (
                    s6_report._write_confirmed_detail_artifacts(
                        report / "confirmed-defaults",
                        {"impact_overview": {}, "artifacts": {}},
                        s6_report.S6_DETAIL_BUCKETS["confirmed"],
                    )
                )
            self.assertTrue(confirmed_artifacts)
            confirmed_md = (
                report / "confirmed-defaults" /
                confirmed_artifacts["confirmed_md"]
            ).read_text(encoding="utf-8")
            self.assertIn("未分级", confirmed_md)
            self.assertIn("调用链已触达当前系统", confirmed_md)

            base_api_model = {
                "rows": [],
                "completed": [],
                "incomplete": [],
                "total_count": 0,
                "completed_count": 0,
                "incomplete_count": 0,
                "confirmed_count": 0,
                "confirmed_no_impact_count": 0,
                "unconfirmed_count": 0,
                "confirmed_relationship_count": 0,
                "population_unconfirmed": True,
                "count_note": "API 总量来自不完整输入。",
            }
            base_dependency_model = {
                "rows": [],
                "completed": [],
                "incomplete": [],
                "total_count": 0,
                "completed_count": 0,
                "incomplete_count": 0,
                "confirmed_any_count": 0,
                "confirmed_no_impact_completed_count": 0,
                "unconfirmed_completed_count": 0,
                "population_unconfirmed": True,
                "count_note": "依赖总量来自不完整输入。",
            }
            dep_relative = s6_report.write_full_dependency_analysis_artifact(
                report / "full-dependency",
                {},
                dependency_model=base_dependency_model,
                api_model=base_api_model,
            )
            self.assertIn(
                "依赖总量来自不完整输入",
                (report / "full-dependency" / dep_relative).read_text(
                    encoding="utf-8"
                ),
            )

            completed_api_model = {
                **base_api_model,
                "completed": [{
                    "coord": "g:missing",
                    "api": "demo.Api.call",
                    "api_signature": "()V",
                    "change_type": "METHOD_REMOVED",
                    "conclusion": "已确认不受影响",
                    "aggregate_count": 0,
                }],
                "completed_count": 1,
                "total_count": 1,
                "confirmed_no_impact_count": 1,
            }
            api_relative = s6_report.write_full_api_analysis_artifact(
                report / "full-api",
                {},
                api_model=completed_api_model,
                dependency_model=base_dependency_model,
            )
            api_text = (report / "full-api" / api_relative).read_text(
                encoding="utf-8"
            )
            self.assertIn("API 总量来自不完整输入", api_text)
            self.assertIn("g:missing", api_text)
            self.assertIn("本依赖有 1 个", api_text)

    def test_report_rendering_zero_truncation_and_attachment_matrix(self):
        confirmed_rows = [
            {
                "coord": "" if index == 0 else f"g:c{index}",
                "api": "" if index == 0 else f"demo.Confirmed.call{index}",
                "api_signature": "",
                "change_type": "",
                "symbol_kind": "",
                "severity": "" if index == 0 else "P2",
                "conclusion": "已确认影响",
                "business_entries": [],
                "modules": [],
                "change_without_severity": "",
                "change": "",
                "reason": "",
                "path_count": 0,
                "occurrence_count": 0,
            }
            for index in range(10)
        ]
        other_rows = [
            {
                "coord": "" if index == 0 else f"g:o{index}",
                "api": "" if index == 0 else f"demo.Other.call{index}",
                "api_signature": "",
                "change_type": "",
                "symbol_kind": "",
                "severity": "",
                "conclusion": "本次未完成分析",
                "business_entries": [],
                "modules": [],
                "change": "",
                "reason": "",
            }
            for index in range(s6_report.S6_MAIN_RESULT_LIMIT + 3)
        ]
        detail_artifacts = [
            {
                "bucket": "uncertain",
                "csv_path": "deliverables/uncertain.csv",
                "md_path": "deliverables/uncertain.md",
                "title": "不确定项",
            },
            {
                "bucket": "confirmed",
                "csv_path": "deliverables/confirmed.csv",
                "md_path": "deliverables/confirmed.md",
                "title": "确认项",
            },
            {
                "bucket": "not_analyzed",
                "csv_path": "deliverables/incomplete.csv",
                "md_path": "deliverables/incomplete.md",
                "title": "未完成项",
            },
        ]
        with patch.object(
            s6_report,
            "build_api_result_rows",
            return_value=[*confirmed_rows, *other_rows],
        ), patch.object(
            s6_report,
            "available_s6_detail_artifacts",
            return_value=detail_artifacts,
        ):
            table_text = "\n".join(s6_report.render_api_result_table({}))
        self.assertIn("其余 2 个", table_text)
        self.assertIn("其余", table_text)
        self.assertIn("分类完整清单", table_text)
        self.assertIn("未分级", table_text)

        with patch.object(
            s6_report, "build_api_result_rows", return_value=[other_rows[0]]
        ), patch.object(
            s6_report, "available_s6_detail_artifacts", return_value=[]
        ):
            one_other_text = "\n".join(s6_report.render_api_result_table({}))
        self.assertIn("下表展示 1 个。", one_other_text)
        self.assertNotIn("分类完整清单", one_other_text)

        with patch.object(
            s6_report, "build_api_result_rows", return_value=[]
        ), patch.object(
            s6_report, "available_s6_detail_artifacts", return_value=[]
        ):
            empty_result_text = "\n".join(
                s6_report.render_api_result_table({})
            )
        self.assertIn("没有形成", empty_result_text)
        self.assertIn("没有未确认项", empty_result_text)

        sort_rows = [
            {
                "coord": "g:sort",
                "api": "",
                "api_signature": "",
                "change_type": "",
                "conclusion": "已确认影响",
            },
            {
                "coord": "g:sort",
                "api": "",
                "api_signature": "",
                "change_type": "",
                "conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION,
                "priority_score": 0,
            },
            {
                "coord": "g:sort",
                "api": "",
                "api_signature": "",
                "change_type": "",
                "conclusion": "已确认不受影响",
            },
        ]
        grouped = s6_report._completed_api_rows_by_dependency({
            "completed": sort_rows
        })
        self.assertEqual(len(grouped), 1)
        self.assertEqual(len(grouped[0][1]), 3)

        zero_distribution = {
            "confirmed_count": 1,
            "dependency_rows": [{
                "coord": "",
                "p0": 0,
                "p1": 0,
                "p2": 0,
                "api_count": 0,
                "business_entry_count": 0,
                "path_count": 0,
                "occurrence_count": 0,
            }],
            "entry_rows": [],
            "entry_api_relation_count": 0,
            "change_types": {},
            "logical_path_count": 0,
            "occurrence_count": 0,
        }
        with patch.object(
            s6_report,
            "_confirmed_impact_distribution",
            return_value=zero_distribution,
        ):
            zero_distribution_text = "\n".join(
                s6_report.render_impact_distribution({}, force=True)
            )
        self.assertIn("已确认范围", zero_distribution_text)
        self.assertNotIn("变化类型分布", zero_distribution_text)
        self.assertNotIn("依赖集中度", zero_distribution_text)

        limit = s6_report.S6_CONCENTRATION_LIMIT
        truncated_distribution = {
            "confirmed_count": limit + 2,
            "dependency_rows": [
                {
                    "coord": "" if index == 0 else f"g:d{index}",
                    "p0": 0,
                    "p1": 0,
                    "p2": 0,
                    "api_count": 0,
                    "business_entry_count": 0,
                    "path_count": 0,
                    "occurrence_count": 0,
                }
                for index in range(limit + 2)
            ],
            "entry_rows": [
                {
                    "entry": "" if index == 0 else f"app.Entry{index}",
                    "p0": 0,
                    "p1": 0,
                    "p2": 0,
                    "api_count": 0,
                    "dependency_count": 0,
                }
                for index in range(limit + 2)
            ],
            "entry_api_relation_count": 0,
            "change_types": {"未知变化": 1},
            "logical_path_count": 0,
            "occurrence_count": 0,
        }
        with patch.object(
            s6_report,
            "_confirmed_impact_distribution",
            return_value=truncated_distribution,
        ):
            truncated_distribution_text = "\n".join(
                s6_report.render_impact_distribution({}, force=True)
            )
        self.assertIn("其他 2 个依赖", truncated_distribution_text)
        self.assertIn("其他 2 个业务入口", truncated_distribution_text)

        other_distribution_rows = [
            {
                "coord": "" if index < 3 else f"g:other{index}",
                "conclusion": "" if index == 0 else "本次未完成分析",
                "severity": "",
                "change_type": f"TYPE_{index}",
                "symbol_kind": "",
            }
            for index in range(
                max(
                    s6_report.S6_MAIN_RESULT_LIMIT,
                    s6_report.S6_CONCENTRATION_LIMIT,
                )
                + 3
            )
        ]
        other_distribution_text = "\n".join(
            s6_report.render_other_result_distribution(
                other_distribution_rows,
                heading_level=0,
            )
        )
        self.assertIn("未记录结论状态", other_distribution_text)
        self.assertIn("未知依赖", other_distribution_text)
        self.assertIn("其他 ", other_distribution_text)

        partial_zero = {
            "analysis_scope": {
                "mode": "partial",
                "validation_status": "valid",
                "included_dependency_count": 0,
                "available_dependency_count": 0,
                "analyzed_api_count": 0,
                "total_api_count": 0,
            }
        }
        partial_zero_text = "\n".join(
            s6_report.render_report_scope_notice(partial_zero)
        )
        self.assertIn("0/0 个变化依赖", partial_zero_text)
        self.assertIn("0/0 个变化 API", partial_zero_text)
        full_invalid_text = "\n".join(s6_report.render_report_scope_notice({
            "analysis_scope": {
                "mode": "full",
                "validation_status": "invalid",
            }
        }))
        self.assertIn("一致性校验", full_invalid_text)

        base_api_model = {
            "rows": [],
            "completed": [],
            "incomplete": [],
            "total_count": 0,
            "completed_count": 0,
            "incomplete_count": 0,
            "confirmed_count": 0,
            "confirmed_no_impact_count": 0,
            "unconfirmed_count": 0,
            "confirmed_relationship_count": 0,
            "population_unconfirmed": False,
            "scope_verified": False,
            "count_note": "",
        }
        resource_text = "\n".join(s6_report.render_api_and_calls(
            {"resource_impacts": [{}]}, base_api_model
        ))
        self.assertIn("版本变化未记录", resource_text)
        self.assertIn("未知", resource_text)

        incomplete_model = {
            **base_api_model,
            "rows": [{"aggregate_count": 0}],
            "incomplete": [{"aggregate_count": 0}],
            "total_count": 1,
            "incomplete_count": 1,
        }
        incomplete_text = "\n".join(
            s6_report.render_api_and_calls({}, incomplete_model)
        )
        self.assertIn("展示 1/1", incomplete_text)

        safe_completed = {
            **base_api_model,
            "rows": [{
                "coord": "g:safe",
                "conclusion": "已确认不受影响",
            }],
            "completed": [{
                "coord": "g:safe",
                "conclusion": "已确认不受影响",
            }],
            "total_count": 1,
            "completed_count": 1,
            "confirmed_no_impact_count": 1,
        }
        safe_text = "\n".join(
            s6_report.render_api_and_calls({}, safe_completed)
        )
        self.assertIn("没有已确认调用关系", safe_text)

        blank_coord_completed = {
            **base_api_model,
            "rows": [{
                "coord": "",
                "api": "demo.Unknown.call",
                "conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION,
                "aggregate_count": 0,
            }],
            "completed": [{
                "coord": "",
                "api": "demo.Unknown.call",
                "conclusion": s6_report.UNCERTAIN_CANDIDATE_CONCLUSION,
                "aggregate_count": 0,
            }],
            "total_count": 1,
            "completed_count": 1,
            "unconfirmed_count": 1,
        }
        blank_coord_text = "\n".join(
            s6_report.render_api_and_calls({}, blank_coord_completed)
        )
        self.assertIn("依赖身份未记录", blank_coord_text)

        zero_visible_api_model = {
            **base_api_model,
            "incomplete": [{"aggregate_count": 0}],
            "completed": [{
                "aggregate_count": 0,
                "conclusion": "已确认不受影响",
            }],
        }
        zero_visible_dependency_model = {
            "rows": [],
            "incomplete": [{"aggregate_count": 0}],
            "completed": [{"aggregate_count": 0}],
            "total_count": 2,
            "completed_count": 1,
            "incomplete_count": 1,
            "confirmed_any_count": 0,
            "confirmed_no_impact_completed_count": 0,
            "unconfirmed_completed_count": 0,
            "population_unconfirmed": False,
            "scope_verified": False,
        }
        visible_common = {
            "analysis_scope": partial_zero["analysis_scope"],
            "artifacts": {
                "alerts_csv": "evidence/call_chain/alerts.csv",
                "analysis_scope_md": "deliverables/analysis-scope.md",
                "diagnostic_detail_md": "deliverables/diagnostics.md",
            },
        }
        zero_visible_text = "\n".join(s6_report.render_user_visible_files(
            visible_common,
            zero_visible_api_model,
            zero_visible_dependency_model,
        ))
        self.assertIn("原始分析记录全量 0 条", zero_visible_text)
        self.assertIn("变化依赖 0/0", zero_visible_text)
        self.assertIn("分析诊断 0 项", zero_visible_text)

        review_only = copy.deepcopy(visible_common)
        review_only["artifacts"] = {
            "database_contract_review_md": "evidence/db-review.md",
        }
        review_only_text = "\n".join(s6_report.render_user_visible_files(
            review_only,
            base_api_model,
            {**zero_visible_dependency_model, "incomplete": [], "completed": []},
        ))
        self.assertIn("数据库契约完整复核明细", review_only_text)
        self.assertNotIn("数据库契约明细 CSV", review_only_text)

        csv_only = copy.deepcopy(visible_common)
        csv_only["artifacts"] = {
            "database_contract_csv": "evidence/db.csv",
        }
        csv_only_text = "\n".join(s6_report.render_user_visible_files(
            csv_only,
            base_api_model,
            {**zero_visible_dependency_model, "incomplete": [], "completed": []},
        ))
        self.assertIn("数据库契约明细 CSV", csv_only_text)
        self.assertNotIn("数据库契约完整复核明细", csv_only_text)

    def test_contract_validators_empty_present_and_existing_diagnostic_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary_path = root / "summary.json"
            coverage_path = root / "coverage.json"
            scope_path = root / "selection.json"
            for path in (summary_path, coverage_path, scope_path):
                path.write_text("{}", encoding="utf-8")

            diagnostics = [{
                "artifact": "other",
                "stage": "json_contract",
            }]
            summary = {
                "unrelated": True,
                "meta": None,
                "diagnostic_guidance": None,
                "user_conclusion_summary": None,
                "graph_stats": None,
            }
            s6_report._validate_call_summary_contract(
                summary_path, summary, diagnostics
            )
            self.assertTrue(any(
                item.get("artifact") == "call_chain_summary"
                for item in diagnostics
            ))
            self.assertIsNone(summary["diagnostic_guidance"])

            nested_none = {
                "status": "done",
                "total_apis": 0,
                "meta": {
                    "graph_stats": {
                        "parser_fallback_reasons": None,
                        "source_artifact_alignment": None,
                        "artifact_bytecode": None,
                        "business_bytecode": None,
                        "indirect_usage": None,
                    }
                },
                "diagnostic_guidance": [],
            }
            nested_diagnostics = []
            s6_report._validate_call_summary_contract(
                summary_path, nested_none, nested_diagnostics
            )
            self.assertFalse(nested_diagnostics)

            graph_none = {
                "status": "done",
                "total_apis": 0,
                "meta": {"graph_stats": None},
            }
            graph_none_diagnostics = []
            s6_report._validate_call_summary_contract(
                summary_path, graph_none, graph_none_diagnostics
            )
            self.assertFalse(graph_none_diagnostics)

            prediagnosed = [{
                "artifact": "call_chain_summary",
                "stage": "json_load",
            }]
            untouched = {"status": 1}
            s6_report._validate_call_summary_contract(
                summary_path, untouched, prediagnosed
            )
            self.assertEqual(untouched, {"status": 1})

            invalid_status_coverage = {
                "overall_status": "future",
                "critical_incomplete": [],
                "components": [],
            }
            invalid_status_diagnostics = []
            s6_report._validate_coverage_contract(
                coverage_path,
                invalid_status_coverage,
                invalid_status_diagnostics,
            )
            self.assertEqual(
                invalid_status_coverage["overall_status"], "unknown"
            )
            self.assertTrue(invalid_status_diagnostics)

            partial_incomplete_coverage = {
                "overall_status": "partial",
                "critical_incomplete": ["component"],
                "components": [{
                    "id": "component",
                    "status": "partial",
                    "reason_codes": [],
                    "evidence": [],
                }],
            }
            partial_diagnostics = []
            s6_report._validate_coverage_contract(
                coverage_path,
                partial_incomplete_coverage,
                partial_diagnostics,
            )
            self.assertEqual(
                partial_incomplete_coverage["overall_status"], "partial"
            )

            for mode in (None, "future"):
                with self.subTest(scope_mode=mode):
                    scope = {
                        "mode": mode,
                        "available_dependency_count": 0,
                        "included_dependency_count": 0,
                        "total_api_count": 0,
                        "analyzed_api_count": 0,
                        "included_dependency_coords": [],
                        "excluded_dependency_coords": [],
                        "selected_names": [],
                    }
                    scope_diagnostics = []
                    s6_report._validate_analysis_scope_contract(
                        scope_path, scope, scope_diagnostics
                    )
                    self.assertEqual(scope["mode"], "")
                    self.assertTrue(scope_diagnostics)

            valid_empty_scope = {
                "mode": "full",
                "available_dependency_count": 0,
                "included_dependency_count": 0,
                "total_api_count": 0,
                "analyzed_api_count": 0,
                "included_dependency_coords": [],
                "excluded_dependency_coords": [],
                "selected_names": [],
            }
            valid_scope_diagnostics = []
            s6_report._validate_analysis_scope_contract(
                scope_path, valid_empty_scope, valid_scope_diagnostics
            )
            self.assertFalse(valid_scope_diagnostics)

    def test_cross_artifact_identity_empty_blank_and_prediagnosed_matrix(self):
        incomplete_summary = {
            "reachable_apis": [{
                "coord": "",
                "api": "",
                "severity": "",
                "old_version": "",
                "new_version": "",
            }],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
        }
        diagnostics = []
        s6_report._validate_cross_artifact_identities(
            call_summary=incomplete_summary,
            changed_apis=[{
                "coord": "",
                "api": "",
                "severity": "",
                "old_version": "",
                "new_version": "",
            }],
            impact_overview={"fact_apis": [], "apis": []},
            scope_mode="full",
            diagnostics=diagnostics,
            changed_apis_path="changed.csv",
            alerts_path="alerts.csv",
        )
        self.assertFalse(diagnostics)

        source = self._step5_item(
            "source",
            severity="P1",
            old_version="1",
            new_version="2",
        )
        blank_repeat = {
            **source,
            "severity": "",
            "old_version": "",
            "new_version": "",
        }
        fact_overview = {
            **source,
            "bucket": "confirmed",
            "severity_values": ["", None, "P1"],
            "old_version_values": ["", None, "1"],
            "new_version_values": ["", None, "2"],
        }
        normalized_summary = {
            "reachable_apis": [blank_repeat],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
        }
        normalized_diagnostics = []
        s6_report._validate_cross_artifact_identities(
            call_summary=normalized_summary,
            changed_apis=[source],
            impact_overview={
                "fact_apis": [fact_overview],
                "apis": [{**fact_overview, "bucket": "wrong"}],
            },
            scope_mode="full",
            diagnostics=normalized_diagnostics,
            changed_apis_path="changed.csv",
            alerts_path="alerts.csv",
        )
        self.assertFalse(normalized_diagnostics)
        self.assertEqual(blank_repeat["severity"], "P1")
        self.assertEqual(fact_overview["severity_values"], ["P1"])

        conflict_source = {**source, "severity": "P0"}
        mismatched_repeat = {**source, "severity": "P2"}
        mismatched_overview = {
            **source,
            "bucket": "confirmed",
            "severity_values": ["P2"],
            "old_version_values": ["1"],
            "new_version_values": ["2"],
        }
        prediagnosed_conflicts = [
            {"artifact": "changed_apis", "stage": "csv_load"},
            {"artifact": "call_chain_summary", "stage": "json_load"},
            {"artifact": "call_chain_alerts", "stage": "csv_load"},
        ]
        with patch.object(
            s6_report, "_downgrade_unverified_certain_results"
        ):
            s6_report._validate_cross_artifact_identities(
                call_summary={
                    "reachable_apis": [mismatched_repeat],
                    "not_impacted_apis": [],
                    "uncertain_apis": [],
                    "not_analyzed_apis": [],
                    "not_found_apis": [],
                },
                changed_apis=[source, conflict_source],
                impact_overview={"apis": [mismatched_overview]},
                scope_mode="full",
                diagnostics=prediagnosed_conflicts,
                changed_apis_path="changed.csv",
                alerts_path="alerts.csv",
            )
        self.assertEqual(len(prediagnosed_conflicts), 3)

    def test_human_population_duplicate_missing_and_count_source_matrix(self):
        inventory_item = self._step5_item("inventory")

        partial_empty = s6_report.build_human_api_analysis({
            "analysis_scope": {
                "mode": "partial",
                "validation_status": "valid",
                "included_dependency_count": 0,
                "included_dependency_coords": [],
                "analyzed_api_count": 0,
                "total_api_count": 1,
            },
            "call_chain_target_count": 0,
            "changed_api_inventory": [inventory_item],
        })
        self.assertEqual(partial_empty["total_count"], 0)

        duplicate_only = s6_report.build_human_api_analysis({
            "analysis_scope": {"total_api_count": 1},
            "call_chain_target_count": 1,
            "scan_stats": {"changed_apis_total": 2},
            "changed_api_inventory": [inventory_item, dict(inventory_item)],
        })
        self.assertIn("相同 API 身份", duplicate_only["count_note"])
        self.assertNotIn("没有完整 API 身份", duplicate_only["count_note"])

        incomplete_inventory_only = s6_report.build_human_api_analysis({
            "analysis_scope": {"total_api_count": 1},
            "call_chain_target_count": 1,
            "scan_stats": {"changed_apis_total": 1},
            "changed_api_inventory": [{
                "coord": "",
                "api": "",
                "api_signature": "",
                "symbol_kind": "method",
                "change_type": "METHOD_REMOVED",
            }],
        })
        self.assertEqual(incomplete_inventory_only["total_count"], 1)
        self.assertEqual(incomplete_inventory_only["incomplete_count"], 1)
        self.assertIn(
            "没有完整 API 身份", incomplete_inventory_only["count_note"]
        )

        mismatched_inventory_count = s6_report.build_human_api_analysis({
            "analysis_scope": {"total_api_count": 2},
            "call_chain_target_count": 2,
            "scan_stats": {"changed_apis_total": 1},
            "changed_api_inventory": [inventory_item],
        })
        self.assertIn("其他产物记录的数量", mismatched_inventory_count["count_note"])

        result_only_item = self._step5_item(
            "result_only", conclusion="已确认影响"
        )
        declared_without_inventory = s6_report.build_human_api_analysis({
            "analysis_scope": {"total_api_count": 3},
            "call_chain_target_count": 3,
            "p0": [result_only_item],
            "impact_overview": {"apis": []},
        })
        self.assertEqual(declared_without_inventory["total_count"], 3)
        self.assertEqual(declared_without_inventory["incomplete_count"], 2)
        self.assertTrue(any(
            row.get("api") == "API 身份未记录"
            for row in declared_without_inventory["incomplete"]
        ))

        zero_aggregate_result = {
            "coord": "g:zero",
            "api": "demo.Zero.call",
            "api_signature": "()V",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "conclusion": "已确认影响",
            "aggregate_count": 0,
        }
        with patch.object(
            s6_report,
            "build_api_result_rows",
            return_value=[zero_aggregate_result],
        ):
            zero_aggregate_model = s6_report.build_human_api_analysis({})
        self.assertEqual(zero_aggregate_model["total_count"], 1)
        self.assertEqual(zero_aggregate_model["confirmed_count"], 1)

        dependency_duplicate = s6_report.build_human_dependency_analysis(
            {
                "analysis_scope": {"available_dependency_count": 1},
                "dep_changes_summary": {"changed": 1},
                "dependency_changes": [
                    {
                        "coord": "g:dup",
                        "old_version": "1",
                        "new_version": "2",
                        "change_type": "major",
                    },
                    {
                        "coord": "g:dup",
                        "old_version": "1",
                        "new_version": "2",
                        "change_type": "major",
                    },
                ],
            },
            {
                "rows": [],
                "population_unconfirmed": False,
            },
        )
        self.assertIn("相同依赖身份", dependency_duplicate["count_note"])

        dependency_incomplete_identity = (
            s6_report.build_human_dependency_analysis(
                {
                    "analysis_scope": {"available_dependency_count": 1},
                    "dep_changes_summary": {"changed": 1},
                    "dependency_changes": [{
                        "coord": "",
                        "old_version": "1",
                        "new_version": "2",
                    }],
                },
                {"rows": [], "population_unconfirmed": False},
            )
        )
        self.assertEqual(dependency_incomplete_identity["total_count"], 1)
        self.assertIn(
            "没有完整依赖身份",
            dependency_incomplete_identity["count_note"],
        )

        dependency_mismatch = s6_report.build_human_dependency_analysis(
            {
                "analysis_scope": {"available_dependency_count": 2},
                "dep_changes_summary": {"changed": 2},
                "dependency_changes": [{
                    "coord": "g:one",
                    "old_version": "1",
                    "new_version": "2",
                }],
            },
            {"rows": [], "population_unconfirmed": False},
        )
        self.assertIn("其他产物记录的数量", dependency_mismatch["count_note"])

        dependency_declared_without_inventory = (
            s6_report.build_human_dependency_analysis(
                {
                    "analysis_scope": {"available_dependency_count": 3},
                    "dep_changes_summary": {"changed": 3},
                    "per_dependency_results": [{
                        "coord": "g:known",
                        "old_version": "",
                        "new_version": "2",
                        "change_type": "",
                    }],
                },
                {"rows": [], "population_unconfirmed": False},
            )
        )
        self.assertEqual(dependency_declared_without_inventory["total_count"], 3)
        self.assertEqual(
            dependency_declared_without_inventory["incomplete_count"], 2
        )

        dependency_from_api_and_resource = (
            s6_report.build_human_dependency_analysis(
                {
                    "per_dependency_results": [{
                        "coord": "g:mixed",
                        "old_version": "already",
                        "new_version": "",
                        "change_type": "",
                    }],
                    "resource_impacts": [{
                        "coord": "g:mixed",
                        "old_version": "resource-old",
                        "new_version": "resource-new",
                        "activation_status": "reachable",
                        "activation_callers": [],
                    }],
                },
                {
                    "rows": [{
                        "coord": "g:mixed",
                        "old_version": "api-old",
                        "new_version": "api-new",
                        "change_type": "METHOD_REMOVED",
                        "symbol_kind": "method",
                        "conclusion": "已确认不受影响",
                        "aggregate_count": 0,
                    }],
                    "population_unconfirmed": False,
                },
            )
        )
        mixed_row = dependency_from_api_and_resource["rows"][0]
        self.assertEqual(mixed_row["old_version"], "already")
        self.assertEqual(mixed_row["new_version"], "api-new")
        self.assertIn("运行时资源变化", mixed_row["api_change_text"])

    def test_collect_findings_database_count_gap_and_payload_reason_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            for relative in (
                "evidence/dependencies",
                "evidence/context",
                "evidence/static_scan",
                "evidence/api_changes",
                "evidence/call_chain/by_api",
                "evidence/call_chain/by_module",
            ):
                (report / relative).mkdir(parents=True, exist_ok=True)
            for relative in (
                "evidence/dependencies/dep_changes.csv",
                "evidence/context/context.json",
                "evidence/static_scan/s3_database_contract_summary.json",
                "evidence/static_scan/s3_database_contract_changes.csv",
                "evidence/api_changes/all_changed_apis.csv",
                "evidence/call_chain/alerts.csv",
                "evidence/call_chain/summary.json",
                "evidence/call_chain/coverage.json",
                "evidence/call_chain/selection.json",
                "evidence/call_chain/by_api/matched.json",
                "evidence/call_chain/by_api/unknown.json",
            ):
                path = report / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("placeholder", encoding="utf-8")

            reachable = self._step5_item(
                "payload_reason",
                conclusion="已确认影响",
                reason_code="",
            )
            reachable_other = self._step5_item(
                "payload_unknown",
                conclusion="unexpected",
                reason_code="",
            )
            uncertain = self._step5_item(
                "uncertain_blank_api",
                coord="g:u",
                api="",
                reason_code="",
            )
            not_analyzed = [
                self._step5_item(
                    "input_one",
                    coord="g:n",
                    conclusion="需要补充输入",
                    old_version="old-n",
                    new_version="new-n",
                    reason_code="",
                ),
                self._step5_item(
                    "incomplete_two",
                    coord="g:n",
                    conclusion="本次未完成分析",
                    old_version="older-n",
                    new_version="newer-n",
                    reason_code="",
                ),
                self._step5_item(
                    "incomplete_blank_api",
                    coord="g:n",
                    api="",
                    conclusion="本次未完成分析",
                    old_version="",
                    new_version="",
                    reason_code="",
                ),
            ]
            not_found = self._step5_item(
                "not_found_blank_api",
                coord="g:f",
                api="",
                reason_code="",
            )
            not_found_known = [
                self._step5_item(
                    "not_found_known_one",
                    coord="g:k",
                    old_version="first-old",
                    new_version="first-new",
                    reason_code="",
                ),
                self._step5_item(
                    "not_found_known_two",
                    coord="g:k",
                    old_version="second-old",
                    new_version="second-new",
                    reason_code="",
                ),
            ]
            summary = {
                "status": "done",
                "total_apis": 9,
                "reachable": 2,
                "not_impacted": 0,
                "uncertain": 1,
                "not_analyzed": 3,
                "not_found_in_static_analysis": 3,
                "reachable_apis": [reachable, reachable_other],
                "not_impacted_apis": [],
                "uncertain_apis": [uncertain],
                "not_analyzed_apis": not_analyzed,
                "not_found_apis": [not_found, *not_found_known],
                "diagnostic_guidance": [],
            }
            changed_rows = [
                {
                    "coord": item.get("coord", ""),
                    "api_name": item.get("api", ""),
                    "api_signature": item.get("api_signature", ""),
                    "symbol_kind": item.get("symbol_kind", ""),
                    "change_type": item.get("change_type", ""),
                    "severity": item.get("severity", ""),
                }
                for item in [
                    reachable,
                    reachable_other,
                    uncertain,
                    *not_analyzed,
                    not_found,
                    *not_found_known,
                ]
            ]

            def fake_load_json(path, *, diagnostics=None, artifact="", required=False):
                if artifact == "call_chain_summary":
                    return copy.deepcopy(summary)
                if artifact == "coverage":
                    return {}
                if artifact == "step5_selection":
                    return {"mode": "", "total_api_count": 9}
                if artifact == "context":
                    return {}
                if artifact == "step3_database_contract_summary":
                    return {
                        "schema": "java-upgrade-analyzer.database-contract-changes.v1",
                        "change_count": 2,
                        "coverage_status": "complete",
                        "coverage_gaps": ["preexisting_gap"],
                    }
                if artifact == "call_chain_by_api:matched.json":
                    return {
                        **reachable,
                        "reason_code": "SYSTEM_CODE_REACHED",
                        "evidence_paths": [],
                    }
                if artifact == "call_chain_by_api:unknown.json":
                    return {
                        **reachable_other,
                        "reason_code": "",
                        "evidence_paths": [],
                    }
                return {}

            def fake_load_csv(path, *, diagnostics=None, artifact="", required=False):
                return copy.deepcopy({
                    "dependency_changes": [
                        {"coord": "g:a"},
                        {"coord": "g:u"},
                        {"coord": "g:n"},
                        {"coord": "g:f"},
                        {"coord": "g:k"},
                    ],
                    "step3_database_contract_changes": [{"依赖包": "g:a"}],
                    "changed_apis": changed_rows,
                }.get(artifact, []))

            overview = {
                "record_count": 0,
                "fact_apis": [],
                "apis": [
                    {"coord": f"g:{index}", "api": f"A{index}"}
                    for index in range(9)
                ],
            }
            with patch.object(
                s6_report, "load_json", side_effect=fake_load_json
            ), patch.object(
                s6_report, "load_csv", side_effect=fake_load_csv
            ), patch.object(
                s6_report, "iter_csv_rows", return_value=iter(())
            ), patch.object(
                s6_report, "_validated_alert_rows", return_value=[]
            ), patch.object(
                s6_report, "build_impact_overview", return_value=overview
            ), patch.object(
                s6_report, "_validate_csv_contract"
            ), patch.object(
                s6_report, "_validate_coverage_contract"
            ), patch.object(
                s6_report, "_validate_analysis_scope_contract"
            ), patch.object(
                s6_report, "_validate_context_contract"
            ), patch.object(
                s6_report, "_validate_call_summary_contract"
            ), patch.object(
                s6_report, "_validate_scope_consistency"
            ), patch.object(
                s6_report, "_validate_cross_artifact_identities"
            ), patch.object(
                s6_report, "load_per_dependency_summaries", return_value=[]
            ), patch.object(
                s6_report, "count_lines", return_value=-1
            ), patch.object(
                s6_report, "_collect_available_evidence_paths", return_value=[]
            ):
                findings = s6_report.collect_findings(report)

            self.assertEqual(
                findings["database_contract"]["coverage_status"], "partial"
            )
            self.assertIn(
                "preexisting_gap",
                findings["database_contract"]["coverage_gaps"],
            )
            self.assertIn(
                "database_contract_output_contract_invalid",
                findings["database_contract"]["coverage_gaps"],
            )
            self.assertTrue(any(
                item.get("stage") == "cross_artifact_contract"
                for item in findings["diagnostics"]
            ))
            collected_reachable = [
                *findings["p0"], *findings["p1"], *findings["p2"]
            ]
            self.assertEqual(
                collected_reachable[0]["reason_code"], "SYSTEM_CODE_REACHED"
            )
            unknown_payload_row = next(
                item for item in collected_reachable
                if item["api"] == reachable_other["api"]
            )
            self.assertEqual(unknown_payload_row["reason_code"], "UNKNOWN")
            n_dependency = next(
                item for item in findings["impacted_dependencies"]
                if item["coord"] == "g:n"
            )
            self.assertEqual(n_dependency["old_version"], "old-n")
            self.assertEqual(n_dependency["new_version"], "new-n")
            self.assertEqual(n_dependency["needs_input"], 1)
            self.assertEqual(n_dependency["not_analyzed"], 2)
            known_not_found_dependency = next(
                item for item in findings["impacted_dependencies"]
                if item["coord"] == "g:k"
            )
            self.assertEqual(
                known_not_found_dependency["old_version"], "first-old"
            )
            self.assertEqual(
                known_not_found_dependency["new_version"], "first-new"
            )
            self.assertEqual(known_not_found_dependency["api_count"], 2)

    def test_residual_helper_truth_tables_have_observable_results(self):
        alert_base = {
            "business_entry": "app.Entry.start()V",
            "changed_symbol": "demo.Api.call",
            "api_signature": "(int)",
            "path_text": "",
        }
        self.assertFalse(s6_report._alert_row_has_reachable_path_evidence({
            **alert_base,
            "chain_entry": "app.Entry.start()V",
            "chain_target": "",
            "chain_hop_count": "1",
        }))

        self.assertIn("- → demo.New.call", s6_report._change_summary({
            "change_type": "MEMBER_RESOLUTION_CHANGED",
            "new_value": "demo/New/call",
        }))
        self.assertIn("demo.Old.call → -", s6_report._change_summary({
            "change_type": "MEMBER_RESOLUTION_CHANGED",
            "old_value": "demo/Old/call",
        }))
        self.assertIn("未知 → java.lang.String", s6_report._change_summary({
            "change_type": "DATA_FIELD_TYPE_CHANGED",
            "new_value": "java.lang.String",
        }))
        self.assertIn("long → 未知", s6_report._change_summary({
            "change_type": "DATA_FIELD_TYPE_CHANGED",
            "old_value": "long",
        }))

        self.assertEqual(
            s6_report._coverage_gap_rows({
                "overall_status": "",
                "critical_incomplete": ["missing-component"],
                "components": [],
            })[0]["status"],
            "未记录",
        )
        chain = s6_report._csv_chain_view({
            "call_paths": ["", "A.start -> B.call"],
        })
        self.assertEqual(chain["entry"], "A.start")
        self.assertEqual(chain["target"], "B.call")

        duplicate_incomplete = [
            {
                "conclusion": "本次未完成分析",
                "reason_code": "ANALYSIS_INCOMPLETE",
            },
            {
                "conclusion": "本次未完成分析",
                "reason_code": "ANALYSIS_INCOMPLETE",
            },
        ]
        incomplete_reason = s6_report._dependency_incomplete_reason(
            duplicate_incomplete, {}
        )
        self.assertEqual(incomplete_reason.count("分析未完整完成"), 1)
        self.assertIn(
            "存在候选关系",
            s6_report._dependency_basis([{
                "conclusion": "可能影响",
                "confirmed_path_count": 0,
            }]),
        )

        self.assertEqual(
            s6_report._human_chain_node("group:artifact:demo.Api.call"),
            "group:artifact:demo.Api.call",
        )
        self.assertEqual(
            s6_report._human_chain_node("group.name::demo.Api.call"),
            "group.name::demo.Api.call",
        )
        self.assertEqual(
            s6_report._nodes_from_csv_evidence([{
                "caller_symbol": "",
                "callee_key": "B.call",
            }]),
            ["B.call"],
        )

        identity_item = {
            "coord": "g:a",
            "api": "demo.Api.call",
            "api_signature": "()V",
        }
        with patch.object(
            s6_report,
            "_normalize_evidence_paths",
            return_value=([
                [{"caller_symbol": "A", "callee_key": "B"}],
                [{"caller_symbol": "A", "callee_key": "B"}],
            ], True),
        ):
            self.assertEqual(
                s6_report._paths_for_report(identity_item, {}),
                ["A → B"],
            )

        diagnostics = [
            {"artifact": "target", "stage": "other"},
            {"artifact": "other", "stage": "same"},
        ]
        s6_report._record_content_diagnostic(
            diagnostics,
            artifact="target",
            stage="same",
            path="/tmp/target.json",
            message="first",
        )
        s6_report._record_content_diagnostic(
            diagnostics,
            artifact="target",
            stage="same",
            path="/tmp/target.json",
            message="duplicate",
        )
        self.assertEqual(len(diagnostics), 3)

        reason_row = {}
        s6_report._set_report_row_reasons(
            reason_row,
            [None, "", "SYSTEM_CODE_REACHED", "SYSTEM_CODE_REACHED"],
            "已确认影响",
        )
        self.assertEqual(reason_row["reason_codes"], ["SYSTEM_CODE_REACHED"])
        self.assertTrue(reason_row["reason"].endswith("。"))

        with patch.object(s6_report, "_overview_for_item", return_value={}):
            self.assertEqual(
                s6_report._item_business_entries(
                    {},
                    {"call_paths": ["A.start -> B", "A.start -> C"]},
                    limit=None,
                ),
                ["A.start"],
            )

        cards = s6_report._render_path_sample_cards([
            {"paths": ["ignored"], "conclusion": "可能影响"},
            {
                "paths": ["A -> B"],
                "conclusion": "已确认影响",
                "api": "B",
                "coord": "g:a",
                "path_count": 0,
                "occurrence_count": 0,
            },
        ], findings={"artifacts": {}})
        self.assertIn("以下链路来自", "\n".join(cards))
        linked_cards = s6_report._render_path_sample_cards([{
            "paths": ["A -> B"],
            "conclusion": "已确认不受影响",
            "api": "B",
            "path_count": 1,
            "occurrence_count": 2,
        }], findings={"artifacts": {"alerts_csv": "evidence/alerts.csv"}})
        self.assertIn("逐链路证据台账", "\n".join(linked_cards))
        self.assertIn(
            "未记录",
            s6_report._row_evidence_text({
                "conclusion": "已确认不受影响",
                "path_count": 0,
            }),
        )

        self.assertIn(
            "中文原因",
            s6_report._api_result_explanation({
                "conclusion": "future",
                "reason": "中文原因",
            }),
        )
        self.assertIn(
            "依赖身份未记录",
            "\n".join(s6_report._api_detail_table([{
                "coord": "",
                "api": "A.m",
                "conclusion": "已确认不受影响",
                "change_without_severity": "unchanged",
            }])),
        )

        with patch.object(
            s6_report,
            "build_logical_api_identity_key",
            return_value=("api",),
        ):
            relation = s6_report._full_relationship_cell(
                {"conclusion": "可能影响"},
                {("api",): {"paths_by_status": {
                    "reachable": {"A -> B": 0},
                    "uncertain": {"A -> B": 3},
                }}},
            )
        self.assertIn("已确认调用关系", relation)
        self.assertIn(
            "共 2 条",
            s6_report._main_relationship_cell({
                "conclusion": "已确认影响",
                "paths": ["A -> B"],
                "path_count": 2,
            }),
        )
        labels = s6_report._logical_full_path_labels({
            "A -> B": 0,
            "A() -> B()": 2,
        })
        self.assertTrue(labels)

        self.assertEqual(
            s6_report._input_diagnostic_artifact_label({}),
            "分析输入证据",
        )
        self.assertIn(
            "无法确认",
            s6_report._input_diagnostic_impact(
                {"artifact": "coverage"}, None
            ),
        )
        scope_cases = [
            {
                "potentially_affected_api_count": 2,
                "primary_reason_api_count": 0,
                "failure_record_count": 2,
                "failure_occurrence_count": 2,
            },
            {
                "potentially_affected_api_count": 2,
                "primary_reason_api_count": 1,
                "failure_record_count": 2,
                "failure_occurrence_count": 0,
            },
            {
                "potentially_affected_api_count": 0,
                "failure_record_count": 2,
                "failure_occurrence_count": 2,
            },
            {
                "potentially_affected_api_count": 0,
                "failure_record_count": 2,
                "failure_occurrence_count": 0,
            },
        ]
        for item in scope_cases:
            self.assertTrue(s6_report._diagnostic_observed_scope_text(item))

        fallback = s6_report._step5_summary_coverage_fallback({
            "total_apis": 1,
            "meta": {"graph_stats": {
                "source_artifact_alignment": {"status": "complete"},
            }},
        })
        self.assertEqual(fallback["overall_status"], "complete")
        no_not_impacted = {
            "reachable_apis": [self._step5_item("unverified")],
            "not_analyzed_apis": [],
        }
        s6_report._downgrade_unverified_certain_results(
            no_not_impacted, set()
        )
        self.assertEqual(no_not_impacted["not_impacted"], 0)

    def test_residual_validator_truth_tables_preserve_contract_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.json"
            path.write_text("{}", encoding="utf-8")

            unrelated = {"unrelated": 1}
            unrelated_diagnostics = []
            s6_report._validate_call_summary_contract(
                path, unrelated, unrelated_diagnostics
            )
            self.assertTrue(unrelated_diagnostics)

            nullable = {
                "status": "done",
                "total_apis": 0,
                "reachable": 0,
                "reachable_apis": [],
                "not_impacted_apis": [],
                "uncertain_apis": [],
                "not_analyzed_apis": [],
                "not_found_apis": [],
                "meta": None,
                "graph_stats": None,
                "diagnostic_guidance": None,
            }
            nullable_diagnostics = []
            s6_report._validate_call_summary_contract(
                path, nullable, nullable_diagnostics
            )
            self.assertEqual(nullable_diagnostics, [])

            graph_nullable = copy.deepcopy(nullable)
            graph_nullable["meta"] = {"graph_stats": {
                "parser_fallback_reasons": None,
                "source_artifact_alignment": None,
                "artifact_bytecode": None,
                "business_bytecode": None,
                "indirect_usage": None,
                "truncation_reasons": None,
            }}
            graph_nullable_diagnostics = []
            s6_report._validate_call_summary_contract(
                path, graph_nullable, graph_nullable_diagnostics
            )
            self.assertEqual(graph_nullable_diagnostics, [])

            prior_diagnostics = [
                {"artifact": "call_chain_summary", "stage": "other"},
                {"artifact": "other", "stage": "json_load"},
            ]
            s6_report._validate_call_summary_contract(
                path, copy.deepcopy(nullable), prior_diagnostics
            )
            self.assertEqual(len(prior_diagnostics), 2)

            coverage = {
                "overall_status": "complete",
                "critical_incomplete": [],
                "components": [],
            }
            coverage_diagnostics = []
            s6_report._validate_coverage_contract(
                path, coverage, coverage_diagnostics
            )
            self.assertEqual(coverage_diagnostics, [])

        def identity(item):
            return (str((item or {}).get("id") or ""), "api")

        base_summary = {
            "reachable_apis": [{"id": "same", "severity": "P2"}],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
        }
        with patch.object(
            s6_report, "build_api_identity_key", side_effect=identity
        ), patch.object(
            s6_report,
            "_identity_is_complete",
            side_effect=lambda value: bool(value[0]),
        ):
            clean_diagnostics = []
            s6_report._validate_cross_artifact_identities(
                call_summary=copy.deepcopy(base_summary),
                changed_apis=[{"id": "same", "severity": "P2"}],
                impact_overview={"fact_apis": [], "apis": [{
                    "id": "same",
                    "bucket": "confirmed",
                    "severity_values": ["P2"],
                }]},
                scope_mode="full",
                diagnostics=clean_diagnostics,
                changed_apis_path="changed.csv",
                alerts_path="alerts.csv",
            )
            self.assertEqual(clean_diagnostics, [])

            mismatch_with_prior = [
                {"artifact": "call_chain_alerts", "stage": "existing"}
            ]
            s6_report._validate_cross_artifact_identities(
                call_summary=copy.deepcopy(base_summary),
                changed_apis=[{"id": "same", "severity": "P2"}],
                impact_overview={"fact_apis": [{
                    "id": "other", "bucket": "", "severity_values": []
                }]},
                scope_mode="partial",
                diagnostics=mismatch_with_prior,
                changed_apis_path="changed.csv",
                alerts_path="alerts.csv",
            )
            self.assertEqual(len(mismatch_with_prior), 1)

            conflict_with_prior = [
                {"artifact": "changed_apis", "stage": "existing"},
                {"artifact": "call_chain_summary", "stage": "existing"},
            ]
            s6_report._validate_cross_artifact_identities(
                call_summary=copy.deepcopy(base_summary),
                changed_apis=[
                    {"id": "same", "severity": "P0"},
                    {"id": "same", "severity": "P2"},
                ],
                impact_overview={},
                scope_mode="partial",
                diagnostics=conflict_with_prior,
                changed_apis_path="changed.csv",
                alerts_path="alerts.csv",
            )
            self.assertEqual(len(conflict_with_prior), 3)

    def test_remaining_structural_paths_validate_rendered_evidence(self):
        full_table = "\n".join(s6_report._api_detail_table([
            {
                "coord": "g:full",
                "api": "A.m",
                "conclusion": "已确认不受影响",
                "change_without_severity": "same bytecode",
            },
            {
                "coord": "",
                "api": "B.m",
                "conclusion": "已确认不受影响",
                "change_without_severity": "same bytecode",
            },
        ], full=True, alert_details={}))
        self.assertIn("g:full", full_table)
        self.assertIn("依赖身份未记录", full_table)

        with patch.object(
            s6_report,
            "_normalize_evidence_paths",
            return_value=([[{
                "caller_symbol": "A.start",
                "callee_key": "B.call",
            }]], True),
        ):
            evidence_chain = s6_report._csv_chain_view({
                "call_paths": [],
                "evidence_paths": [[]],
            })
        self.assertEqual(evidence_chain["entry"], "A.start")

        dependency_rows = [
            {
                "coord": "g:complete",
                "old_version": "1",
                "new_version": "2",
                "api_total": 2,
                "api_completed": 2,
                "api_incomplete": 0,
                "unassigned_api_count": 0,
                "api_change_text": "均为删除方法",
                "resource_total": 1,
                "resource_completed": 0,
                "analysis_complete": True,
                "analysis_conclusion": "确认有影响",
                "conclusion_basis": "2 条关系",
                "aggregate_count": 1,
            },
            {
                "coord": "g:incomplete",
                "api_total": 1,
                "api_completed": 1,
                "api_incomplete": 0,
                "unassigned_api_count": 1,
                "api_change_text": "变化未完整",
                "resource_total": 1,
                "resource_completed": 1,
                "analysis_complete": False,
                "analysis_conclusion": "未完成分析",
                "incomplete_reason": "有 API 未归属",
                "aggregate_count": 1,
            },
        ]
        dependency_table = "\n".join(s6_report._dependency_detail_table(
            dependency_rows,
            include_link=True,
            incomplete_api_count=1,
        ))
        self.assertIn("该依赖的 2 个 API", dependency_table)
        self.assertIn("未完成 API 及原因", dependency_table)

        scope_text = s6_report._diagnostic_observed_scope_text({
            "potentially_affected_api_count": 0,
            "failure_record_count": 2,
            "failure_occurrence_count": 3,
        })
        self.assertIn("3 个物理位置", scope_text)
        self.assertIn(
            "统计或结论",
            s6_report._input_diagnostic_impact({}, {}),
        )
        self.assertIn(
            "系统触达汇总未被采用",
            s6_report._input_diagnostic_impact({
                "artifact": "call_chain_summary",
                "error_type": "",
            }),
        )

        rows = [
            {"id": "invalid"},
            {
                "id": "entry-only",
                "changed_symbol": "EntryOnly.m",
                "business_entry": "A",
                "chain_target": "",
            },
            {
                "id": "target-only",
                "changed_symbol": "TargetOnly.m",
                "business_entry": "",
                "chain_target": "B",
            },
            {
                "id": "valid",
                "changed_symbol": "Valid.m",
                "business_entry": "A",
                "chain_target": "B",
            },
        ]
        with patch.object(
            s6_report, "_validated_alert_rows", return_value=rows
        ), patch.object(
            s6_report,
            "build_logical_api_identity_key",
            side_effect=lambda row: (str(row.get("api") or ""),),
        ), patch.object(
            s6_report,
            "_identity_is_complete",
            side_effect=lambda identity: bool(identity[0]),
        ):
            loaded = s6_report._load_full_alert_details("unused")
        self.assertIn(
            "A → B",
            loaded[("Valid.m",)]["paths_by_status"][""],
        )

        diagnostics = [{}, {"artifact": "target", "stage": "other"}]
        s6_report._record_content_diagnostic(
            diagnostics,
            artifact="target",
            stage="same",
            path="/tmp/a",
            message="new",
        )
        self.assertEqual(len(diagnostics), 3)

        no_path_cards = s6_report._render_path_sample_cards([
            {"paths": [], "conclusion": "已确认影响"},
            {"paths": ["A -> B"], "conclusion": "已确认影响", "api": "B"},
        ], findings=None)
        self.assertIn("以下链路来自", "\n".join(no_path_cards))
        self.assertIn(
            "已确认调用链 2 条",
            s6_report._row_evidence_text({
                "conclusion": "已确认影响",
                "path_count": 2,
            }),
        )
        conflicting_reason_row = {}
        s6_report._set_report_row_reasons(
            conflicting_reason_row,
            ["完全兼容"],
            "已确认影响",
        )
        self.assertEqual(conflicting_reason_row["reason"], "")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.json"
            path.write_text("{}", encoding="utf-8")
            invalid_types = {
                "status": "done",
                "total_apis": 0,
                "reachable_apis": [],
                "not_impacted_apis": [],
                "uncertain_apis": [],
                "not_analyzed_apis": [],
                "not_found_apis": [],
                "meta": "invalid",
                "diagnostic_guidance": "invalid",
            }
            invalid_diagnostics = []
            s6_report._validate_call_summary_contract(
                path, invalid_types, invalid_diagnostics
            )
            self.assertTrue(invalid_diagnostics)

            invalid_graph = {
                **invalid_types,
                "meta": {"graph_stats": "invalid"},
                "diagnostic_guidance": [],
            }
            invalid_graph_diagnostics = []
            s6_report._validate_call_summary_contract(
                path, invalid_graph, invalid_graph_diagnostics
            )
            self.assertTrue(invalid_graph_diagnostics)

            incomplete_only = {
                "overall_status": "complete",
                "critical_incomplete": [],
                "components": [{"id": "partial", "status": "partial"}],
            }
            coverage_diagnostics = []
            s6_report._validate_coverage_contract(
                path, incomplete_only, coverage_diagnostics
            )
            self.assertEqual(incomplete_only["overall_status"], "partial")

        def identity(item):
            return (str((item or {}).get("id") or ""), "api")

        summary = {
            "reachable_apis": [{"id": "same", "severity": "P1"}],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
        }
        bucket_diagnostics = []
        with patch.object(
            s6_report, "build_api_identity_key", side_effect=identity
        ), patch.object(
            s6_report,
            "_identity_is_complete",
            side_effect=lambda value: bool(value[0]),
        ):
            s6_report._validate_cross_artifact_identities(
                call_summary=summary,
                changed_apis=[{"id": "same", "severity": "P1"}],
                impact_overview={"fact_apis": [{
                    "id": "same", "bucket": "", "severity_values": ["P1"]
                }]},
                scope_mode="full",
                diagnostics=bucket_diagnostics,
                changed_apis_path="changed.csv",
                alerts_path="alerts.csv",
            )
        self.assertTrue(any(
            item.get("artifact") == "call_chain_alerts"
            for item in bucket_diagnostics
        ))

        item = self._step5_item("counts", conclusion="已确认影响")
        item_identity = s6_report._identity_without_severity(item)
        for logical_count, legacy_count in ((0, 0), (2, 3)):
            findings = {
                "p0": [item],
                "impact_overview": {"apis": [{
                    **item,
                    "logical_path_counts_by_status": {"reachable": logical_count},
                    "path_counts_by_status": {"reachable": legacy_count},
                    "paths_by_status": {},
                    "occurrence_counts_by_status": {},
                }]},
            }
            rows = s6_report.build_api_result_rows(findings)
            self.assertEqual(
                rows[0]["confirmed_path_count"], logical_count
            )
            self.assertEqual(
                s6_report._identity_without_severity(rows[0]), item_identity
            )

        overview = s6_report.build_impact_overview([{
            "target_coord": "g:a",
            "changed_symbol": "A.m",
            "path_status": " ",
            "api_status": "",
            "api_id": "api-1",
            "path_occurrence_count": "1",
        }])
        self.assertEqual(overview["apis"][0]["api_id"], "api-1")
        self.assertIn("unknown", overview["apis"][0]["status_counts"])

        nonpriority = s6_report.build_bucket_detail_markdown(
            {"title": "normal", "show_priority": False},
            [{"coord": "g:a"}, {"coord": "g:b"}],
            "normal.csv",
        )
        self.assertIn("依赖坐标分布", nonpriority)
        many = [
            {"coord": f"g:d{index}", "priority_score": index}
            for index in range(s6_report.S6_DETAIL_MD_DEP_SUMMARY_LIMIT + 2)
        ]
        priority = s6_report.build_bucket_detail_markdown(
            {"title": "priority", "show_priority": True},
            many,
            "priority.csv",
        )
        self.assertIn("其他 2 个依赖", priority)

        no_impact_rows = [{
            "coord": "g:safe",
            "api": "A.m",
            "api_signature": "()V",
            "symbol_kind": "method",
            "change_type": "METHOD_REMOVED",
            "conclusion": "已确认不受影响",
            "aggregate_count": 1,
        }]
        with patch.object(
            s6_report, "build_api_result_rows", return_value=no_impact_rows
        ):
            api_model = s6_report.build_human_api_analysis({})
        self.assertEqual(api_model["confirmed_no_impact_count"], 1)

        dependency_model = s6_report.build_human_dependency_analysis(
            {
                "analysis_scope": {"available_dependency_count": 1},
                "dependency_changes": [{"coord": "g:safe"}],
            },
            {
                "rows": [{
                    **no_impact_rows[0],
                    "aggregate_count": 1,
                }],
                "population_unconfirmed": False,
            },
        )
        self.assertEqual(dependency_model["completed_count"], 1)

    def test_final_renderer_condition_matrix_reports_exact_boundaries(self):
        self.assertIn(
            "依赖身份未记录",
            s6_report._full_api_dependency_heading({}),
        )

        with patch.object(
            s6_report,
            "build_logical_api_identity_key",
            return_value=("api",),
        ):
            candidate = s6_report._full_relationship_cell(
                {"conclusion": "可能影响"},
                {("api",): {"paths_by_status": {
                    "uncertain": {"C -> D": 1},
                }}},
            )
            repeated = s6_report._full_relationship_cell(
                {"conclusion": "可能影响"},
                {("api",): {"paths_by_status": {
                    "reachable": {"A -> B": 2},
                    "uncertain": {"A -> B": 3},
                }}},
            )
            empty_conclusion = s6_report._full_relationship_cell({}, {})
        self.assertIn("候选关系", candidate)
        self.assertIn("记录 3 次", repeated)
        self.assertIn("未发现", empty_conclusion)

        with patch.object(
            s6_report,
            "_normalize_evidence_paths",
            return_value=([[], [{
                "caller_symbol": "A",
                "callee_key": "B",
            }]], True),
        ):
            self.assertEqual(
                s6_report._csv_chain_view({"evidence_paths": [[], []]})[
                    "target"
                ],
                "B",
            )

        zero_api_link = "\n".join(s6_report._dependency_detail_table([{
            "coord": "g:zero",
            "api_total": 0,
            "api_completed": 1,
            "api_incomplete": 0,
            "unassigned_api_count": 0,
            "api_change_text": "none",
            "resource_total": 0,
            "analysis_complete": True,
            "analysis_conclusion": "未确认影响",
            "conclusion_basis": "none",
        }], include_link=True))
        self.assertIn("已完成 API 及调用关系", zero_api_link)

        duplicate_reason_row = {}
        s6_report._set_report_row_reasons(
            duplicate_reason_row,
            ["NO_STATIC_PATH", "NOT_FOUND_IN_STATIC_ANALYSIS"],
            "未发现调用路径",
        )
        self.assertEqual(
            duplicate_reason_row["reason"].count("当前源码中未找到调用路径"),
            1,
        )

        positive_distribution = {
            "confirmed_count": 3,
            "dependency_rows": [
                {
                    "coord": f"g:d{index}",
                    "p0": 0,
                    "p1": index,
                    "p2": index + 1,
                    "api_count": 1,
                    "business_entry_count": 1,
                    "path_count": 1,
                    "occurrence_count": 1,
                }
                for index in range(s6_report.S6_CONCENTRATION_LIMIT + 1)
            ],
            "entry_rows": [{
                "entry": "app.Entry",
                "p0": 0,
                "p1": 1,
                "p2": 1,
                "api_count": 1,
                "dependency_count": 1,
            }],
            "entry_api_relation_count": 1,
            "change_types": {"删除方法": 3},
            "logical_path_count": 3,
            "occurrence_count": 3,
        }
        with patch.object(
            s6_report,
            "_confirmed_impact_distribution",
            return_value=positive_distribution,
        ):
            distribution_text = "\n".join(
                s6_report.render_impact_distribution({}, force=True)
            )
        self.assertIn("依赖集中度", distribution_text)
        self.assertIn("业务入口分布", distribution_text)
        self.assertIn("其他 1 个依赖", distribution_text)

        compact_other_rows = [
            {
                "coord": f"g:{index % 2}",
                "conclusion": "本次未完成分析",
                "severity": "P2",
                "change_type": "METHOD_REMOVED",
                "symbol_kind": "method",
            }
            for index in range(s6_report.S6_MAIN_RESULT_LIMIT + 1)
        ]
        self.assertEqual(s6_report.render_other_result_distribution(None), [])
        compact_text = "\n".join(
            s6_report.render_other_result_distribution(compact_other_rows)
        )
        self.assertNotIn("其他 1 个依赖", compact_text)

        empty_detail = s6_report.render_diagnostic_detail_artifact({})
        self.assertIn("没有分析诊断", empty_detail)
        input_detail = s6_report.render_diagnostic_detail_artifact({
            "diagnostics": [{
                "artifact": "other",
                "stage": "json_load",
                "path": "/tmp/input.json",
                "error_type": "OSError",
            }],
        })
        self.assertIn("输入证据", input_detail)

        guidance_item = {
            "reason_code": "UNKNOWN",
            "observed_scope": "step",
            "potentially_affected_api_count": 0,
            "failure_record_count": 0,
            "blocking": False,
            "sample_apis": [],
        }
        with patch.dict(
            s6_report._OBJECTIVE_DIAGNOSTIC_TRIGGER_CONDITIONS,
            {"UNKNOWN": "具体触发证据见本条"},
            clear=False,
        ):
            guidance_text = "\n".join(
                s6_report.render_diagnostic_guidance({
                    "diagnostic_guidance": [guidance_item],
                })
            )
        self.assertIn("未记录更具体", guidance_text)

        summary_without_path = "\n".join(s6_report.render_diagnostic_summary({
            "diagnostic_guidance": [guidance_item],
            "artifacts": {},
        }))
        self.assertNotIn("analysis-diagnostics.md", summary_without_path)
        many_guidance = [
            {**guidance_item, "reason_code": f"UNKNOWN_{index}"}
            for index in range(s6_report.S6_MAIN_DIAGNOSTIC_LIMIT + 1)
        ]
        summary_with_path = "\n".join(s6_report.render_diagnostic_summary({
            "diagnostic_guidance": many_guidance,
            "artifacts": {
                "diagnostic_detail_md": "deliverables/analysis-diagnostics.md"
            },
        }))
        self.assertIn("其他 1 条诊断", summary_with_path)
        self.assertIn("analysis-diagnostics.md", summary_with_path)

        with tempfile.TemporaryDirectory() as tmp:
            diagnostics_only = s6_report.write_diagnostic_detail_artifact(
                tmp,
                {"diagnostic_guidance": [], "diagnostics": [{
                    "artifact": "other",
                    "stage": "json_load",
                    "path": "/tmp/a",
                    "error_type": "OSError",
                }]},
            )
            guidance_only = s6_report.write_diagnostic_detail_artifact(
                tmp,
                {"diagnostic_guidance": [guidance_item], "diagnostics": []},
            )
        self.assertTrue(diagnostics_only)
        self.assertTrue(guidance_only)

        base_limitations = {
            "coverage": {
                "overall_status": "complete",
                "critical_incomplete": [],
                "components": [],
            },
            "diagnostics": [],
            "not_impacted": [],
        }
        partial_without_names = "\n".join(s6_report.render_limitations_section({
            **base_limitations,
            "analysis_scope": {
                "mode": "partial",
                "excluded_dependency_coords": [],
            },
        }))
        partial_with_names = "\n".join(s6_report.render_limitations_section({
            **base_limitations,
            "analysis_scope": {
                "mode": "partial",
                "excluded_dependency_coords": ["g:a"],
            },
        }))
        invalid_scope = "\n".join(s6_report.render_limitations_section({
            **base_limitations,
            "analysis_scope": {"mode": "", "validation_status": "invalid"},
        }))
        missing_scope = "\n".join(s6_report.render_limitations_section({
            **base_limitations,
            "analysis_scope": {},
        }))
        self.assertNotIn("未分析：", partial_without_names)
        self.assertIn("未分析：g:a", partial_with_names)
        self.assertIn("一致性校验", invalid_scope)
        self.assertIn("快照缺失", missing_scope)

        self.assertEqual(s6_report.render_database_contract_changes({}), [])
        review_only = "\n".join(s6_report.render_database_contract_changes({
            "artifacts": {"database_contract_review_md": "review.md"},
        }))
        csv_only = "\n".join(s6_report.render_database_contract_changes({
            "artifacts": {"database_contract_csv": "rows.csv"},
        }))
        blank_status = "\n".join(s6_report.render_database_contract_changes({
            "database_contract": {"coverage_status": "", "rows": []},
        }))
        self.assertIn("review.md", review_only)
        self.assertIn("rows.csv", csv_only)
        self.assertIn("未记录", blank_status)

        with patch.object(
            s6_report, "build_api_result_rows", return_value=[]
        ), patch.object(
            s6_report, "render_impact_distribution", return_value=[]
        ):
            safe_core = "\n".join(s6_report.render_core_conclusion({
                "coverage": {"overall_status": "complete"},
                "analysis_scope": {"mode": "full"},
                "not_impacted": [{}],
            }))
            not_found_core = "\n".join(s6_report.render_core_conclusion({
                "coverage": {"overall_status": "complete"},
                "analysis_scope": {"mode": "full"},
                "not_impacted": [{}],
                "not_found": [{}],
            }))
        self.assertIn("相同类字节码", safe_core)
        self.assertIn("不等同于", not_found_core)

        confirmed_row = {
            "coord": "",
            "api": "",
            "conclusion": "已确认影响",
            "reason_code": "SYSTEM_CODE_REACHED",
        }
        with patch.object(
            s6_report, "build_api_result_rows", return_value=[confirmed_row]
        ), patch.object(
            s6_report, "render_impact_distribution", return_value=[]
        ), patch.object(
            s6_report, "_dependency_for_item", return_value={}
        ):
            unknown_core = "\n".join(s6_report.render_core_conclusion({
                "coverage": {"overall_status": "complete"},
                "analysis_scope": {"mode": "full"},
            }))
        self.assertIn("未知依赖", unknown_core)
        self.assertIn("未知 API", unknown_core)

        partial_invalid_notice = "\n".join(s6_report.render_report_scope_notice({
            "analysis_scope": {
                "mode": "partial",
                "validation_status": "invalid",
            },
        }))
        self.assertIn("无法核验", partial_invalid_notice)

        api_incomplete_row = {
            "aggregate_count": 1,
            "conclusion": "本次未完成分析",
        }
        api_model = {
            "rows": [api_incomplete_row],
            "completed": [],
            "incomplete": [api_incomplete_row],
            "total_count": 2,
            "completed_count": 0,
            "incomplete_count": 2,
            "confirmed_count": 0,
            "confirmed_no_impact_count": 0,
            "unconfirmed_count": 0,
            "population_unconfirmed": False,
            "scope_verified": False,
        }
        self.assertIn(
            "未展开 1 个",
            "\n".join(s6_report.render_api_and_calls({}, api_model)),
        )

        dependency_incomplete = {
            "coord": "g:incomplete",
            "aggregate_count": 1,
            "api_total": 0,
            "api_completed": 0,
            "api_incomplete": 0,
            "unassigned_api_count": 0,
            "api_change_text": "unknown",
            "analysis_complete": False,
            "analysis_conclusion": "未完成分析",
            "incomplete_reason": "missing",
            "call_relationship_count": 0,
        }
        dependency_complete = {
            **dependency_incomplete,
            "coord": "g:complete",
            "analysis_complete": True,
            "analysis_conclusion": "未确认影响",
            "conclusion_basis": "none",
        }
        dependency_model = {
            "rows": [dependency_incomplete, dependency_complete],
            "completed": [dependency_complete],
            "incomplete": [dependency_incomplete],
            "total_count": 4,
            "completed_count": 2,
            "incomplete_count": 2,
            "confirmed_any_count": 0,
            "confirmed_no_impact_completed_count": 0,
            "unconfirmed_completed_count": 2,
            "population_unconfirmed": False,
            "scope_verified": False,
        }
        dependency_text = "\n".join(
            s6_report.render_dependency_conclusions({}, dependency_model)
        )
        self.assertIn("未展开 1 个", dependency_text)

    def test_last_model_and_identity_alternatives_are_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.json"
            path.write_text("{}", encoding="utf-8")
            summary = {
                "status": "done",
                "total_apis": 0,
                "reachable_apis": [],
                "not_impacted_apis": [],
                "uncertain_apis": [],
                "not_analyzed_apis": [],
                "not_found_apis": [],
                "meta": {"graph_stats": {
                    "parser_fallback_reasons": {},
                }},
                "diagnostic_guidance": [],
            }
            diagnostics = []
            s6_report._validate_call_summary_contract(
                path, summary, diagnostics
            )
            self.assertEqual(diagnostics, [])

        def identity(item):
            return (str((item or {}).get("id") or ""), "api")

        base_summary = {
            "reachable_apis": [{"id": "same", "severity": "P0"}],
            "not_impacted_apis": [],
            "uncertain_apis": [],
            "not_analyzed_apis": [],
            "not_found_apis": [],
        }
        with patch.object(
            s6_report, "build_api_identity_key", side_effect=identity
        ), patch.object(
            s6_report,
            "_identity_is_complete",
            side_effect=lambda value: bool(value[0]),
        ):
            conflict_diagnostics = []
            s6_report._validate_cross_artifact_identities(
                call_summary=copy.deepcopy(base_summary),
                changed_apis=[
                    {"id": "same", "severity": "P0"},
                    {"id": "same", "severity": "P2"},
                ],
                impact_overview={"fact_apis": [{
                    "id": "same", "bucket": "confirmed"
                }]},
                scope_mode="full",
                diagnostics=conflict_diagnostics,
                changed_apis_path="changed.csv",
                alerts_path="alerts.csv",
            )
            self.assertTrue(any(
                item.get("artifact") == "changed_apis"
                and item.get("stage") == "field_consistency"
                for item in conflict_diagnostics
            ))

            prior_summary = [{
                "artifact": "call_chain_summary", "stage": "existing"
            }]
            s6_report._validate_cross_artifact_identities(
                call_summary=copy.deepcopy(base_summary),
                changed_apis=[{"id": "same", "severity": "P1"}],
                impact_overview={"fact_apis": [{
                    "id": "same",
                    "bucket": "confirmed",
                    "severity_values": ["P1"],
                }]},
                scope_mode="full",
                diagnostics=prior_summary,
                changed_apis_path="changed.csv",
                alerts_path="alerts.csv",
            )
            self.assertEqual(len(prior_summary), 1)

        item = self._step5_item("legacy_count", conclusion="已确认影响")
        for legacy_count in (0, 2):
            findings = {
                "p0": [item],
                "impact_overview": {"apis": [{
                    **item,
                    "path_counts_by_status": {"reachable": legacy_count},
                    "paths_by_status": {},
                    "occurrence_counts_by_status": {},
                }]},
            }
            row = s6_report.build_api_result_rows(findings)[0]
            self.assertEqual(row["confirmed_path_count"], legacy_count)

        inventory_item = self._step5_item("scan_mismatch")
        inventory_mismatch = s6_report.build_human_api_analysis({
            "analysis_scope": {"total_api_count": 1},
            "call_chain_target_count": 1,
            "scan_stats": {"changed_apis_total": 3},
            "changed_api_inventory": [
                inventory_item,
                dict(inventory_item),
            ],
        })
        self.assertIn(
            "变化 API 清单行数 3", inventory_mismatch["count_note"]
        )

        excluded_dependency = s6_report.build_human_dependency_analysis(
            {
                "analysis_scope": {
                    "mode": "",
                    "excluded_dependency_coords": ["g:excluded"],
                },
                "dependency_changes": [{"coord": "g:excluded"}],
            },
            {"rows": [], "population_unconfirmed": False},
        )
        self.assertFalse(excluded_dependency["rows"][0]["analysis_complete"])
        self.assertIn(
            "未包含该依赖",
            excluded_dependency["rows"][0]["incomplete_reason"],
        )

        incomplete_dependency = s6_report.build_human_dependency_analysis(
            {"dependency_changes": [{"coord": "g:incomplete"}]},
            {
                "rows": [{
                    "coord": "g:incomplete",
                    "api": "A.m",
                    "api_signature": "()V",
                    "symbol_kind": "method",
                    "change_type": "METHOD_REMOVED",
                    "conclusion": "本次未完成分析",
                    "aggregate_count": 1,
                }],
                "population_unconfirmed": False,
            },
        )
        self.assertFalse(incomplete_dependency["rows"][0]["analysis_complete"])
        self.assertTrue(incomplete_dependency["rows"][0]["incomplete_reason"])


if __name__ == "__main__":
    unittest.main()
