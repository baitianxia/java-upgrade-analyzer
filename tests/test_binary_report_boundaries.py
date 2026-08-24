from __future__ import annotations

import json
import os
from contextlib import nullcontext
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import binary_report


class _OsProxy:
    def __init__(self, **overrides):
        self._overrides = overrides

    def __getattr__(self, name):
        if name in self._overrides:
            return self._overrides[name]
        return getattr(os, name)


class _StatView:
    def __init__(self, original, **overrides):
        self._original = original
        self._overrides = overrides

    def __getattr__(self, name):
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._original, name)


def _transaction_fixture(
    destinations: list[Path],
    *,
    state: str = "staging",
    schema: str | None = None,
    binding: dict[str, str] | None = None,
) -> tuple[dict, list[dict], str]:
    schema = schema or binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA
    transaction_id = "1" * 32
    group_token = binary_report._publication_group_token(destinations)
    if binding is None:
        binding = (
            {
                binary_report._REPORT_IMPLEMENTATION_IDENTITY_FIELD:
                    binary_report.report_implementation_identity(),
            }
            if schema == binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA
            else {}
        )
    records = []
    for index, destination in enumerate(destinations):
        records.append({
            "destination": str(destination),
            "stage": str(destination.parent / f".jua-br-{group_token}-{transaction_id}-{index}.stage"),
            "backup": str(destination.parent / f".jua-br-{group_token}-{transaction_id}-{index}.backup"),
            "had_destination": False,
            "content_sha256": "" if state == "staging" else chr(ord("a") + index) * 64,
        })
    normalized_records = [
        {
            **record,
            "destination": Path(record["destination"]),
            "stage": Path(record["stage"]),
            "backup": Path(record["backup"]),
        }
        for record in records
    ]
    payload = {
        "schema": schema,
        "transaction_id": transaction_id,
        "state": state,
        "binding": dict(binding),
        "published_content_identity": (
            "" if state == "staging"
            else binary_report._transaction_content_identity(normalized_records)
        ),
        "destinations": records,
    }
    if schema == binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA:
        payload["gate_receipt"] = None
        if state not in {"staging", "prepared", "pending_gate"}:
            payload["gate_receipt"] = binary_report._new_report_gate_receipt(
                payload, gate_name="binary_report", strict_risk_gate=True,
            )
    return payload, normalized_records, group_token


class _BrokenNoteTarget:
    __slots__ = ()

    def add_note(self, _note: str) -> None:
        raise RuntimeError("note sink failed")


class _FallbackNoteTarget:
    def __init__(self, notes=None):
        self.__notes__ = notes

    def add_note(self, _note: str) -> None:
        raise RuntimeError("note sink failed")


class BinaryReportPureBoundaryTest(unittest.TestCase):
    def test_api_dependency_and_change_display_empty_and_populated_matrix(self):
        self.assertEqual(binary_report._api_display({}), ("", "", ""))
        self.assertEqual(
            binary_report._api_display({
                "class_name": "a/b/Type",
                "member_name": "<class>",
                "descriptor": "LType;",
            }),
            ("a.b.Type", "<class>", "LType;"),
        )
        self.assertEqual(
            binary_report._api_display({
                "class_name": "a/b/Type", "member_name": "run",
                "descriptor": "()V",
            }),
            ("a.b.Type.run", "run", "()V"),
        )

        self.assertEqual(binary_report._dependency_view({}), {
            "dependency": "未绑定制品（需查看裁决证据）",
            "dependency_lineage": "",
            "base_dependency": "-",
            "current_dependency": "-",
        })
        populated = {
            "dependency_artifacts": [
                {
                    "side": "base", "logical_dependency_lineage": "g:a",
                    "coord": "g:a:1",
                },
                {
                    "side": "current", "logical_dependency_lineage": "g:a",
                    "coord": "g:a:2",
                },
                {"side": "base", "runtime_code_source_origin_identity": "origin-z"},
                {"side": "ignored", "coord": "g:ignored:9"},
            ]
        }
        self.assertEqual(binary_report._dependency_view(populated), {
            "dependency": "g:a",
            "dependency_lineage": "g:a",
            "base_dependency": "g:a:1|origin-z",
            "current_dependency": "g:a:2",
        })
        self.assertEqual(
            binary_report._dependency_view({
                "dependency_artifacts": [{
                    "runtime_code_source_origin_identity": "runtime-origin",
                }],
            })["dependency"],
            "runtime-origin",
        )

        self.assertEqual(binary_report._change_object({}), "未知对象")
        self.assertEqual(
            binary_report._change_object({"fact_scope": {"resource_name": "META-INF/services/X"}}),
            "META-INF/services/X",
        )
        self.assertEqual(
            binary_report._change_object({
                "fact_scope": {"class_name": "p/C", "member_name": "m", "descriptor": "()V"},
            }),
            "p.C.m()V",
        )
        self.assertEqual(binary_report._change_label({}), "changed")
        self.assertEqual(
            binary_report._change_label({"fact_scope": {"member_change_kind": "removed"}}),
            "删除",
        )

    def test_source_views_cover_absence_filtering_and_complete_rows(self):
        empty = binary_report._source_inputs_view({})
        self.assertEqual(empty["purpose_version"], "missing")
        self.assertEqual(empty["label"], "业务源码：未提供；依赖源码：未提供")
        self.assertEqual(empty["coverage_status"], "not_provided")
        self.assertEqual(empty["mapped_count"], 0)
        self.assertEqual(empty["language_file_counts"], {})
        self.assertEqual(empty["coverage_gaps"], [])

        available = binary_report._source_inputs_view({
            "coverage": {
                "source_inputs": {
                    "purpose_version": "v2",
                    "business": {"status": "available", "origin": "checkout_build"},
                    "dependencies": {"status": "available"},
                },
                "source_overlay": {
                    "coverage_status": "partial", "mapped_count": "2",
                    "ambiguous_count": 1, "conflict_count": 3,
                },
            },
            "source_attestation": {
                "language_file_counts": {"java": 2},
                "coverage_gaps": ["missing-debug-lines"],
            },
        })
        self.assertEqual(available["label"], "业务源码：构建输入已具备并直接使用；依赖源码：已提供并直接使用")
        self.assertEqual(available["mapped_count"], 2)
        self.assertEqual(available["coverage_gaps"], ["missing-debug-lines"])
        externally_provided = binary_report._source_inputs_view({
            "coverage": {"source_inputs": {"business": {"status": "available"}}},
        })
        self.assertIn("业务源码：已提供并直接使用", externally_provided["label"])

        self.assertEqual(binary_report._source_review_rows({}), [])
        loaded = {
            "coverage": {"source_overlay": {"rows": [
                {"mapping_status": "ambiguous"},
                {"mapping_status": "mapped"},
                {
                    "mapping_status": "mapped",
                    "overlay_identity": "overlay-1",
                    "binary_member": {
                        "artifact_coord": "g:a:2", "class_name": "p/C",
                        "member_name": "run", "descriptor": "(I)V",
                    },
                    "source_location": {
                        "owner_coord": "g:a:2:sources", "owner_type": "dependency",
                        "logical_path": "src/p/C.java", "line": 7, "end_line": 9,
                        "module": "core", "language": "java",
                    },
                },
            ]}},
            "source_explanations": {"declarations": [
                {
                    "overlay_identity": "overlay-1",
                    "declared_signature": "void run(int value)",
                    "annotations": ["Override"], "modifiers": ["public"],
                },
                {"overlay_identity": "", "declared_signature": "fallback"},
            ]},
        }
        rows = binary_report._source_review_rows(loaded)
        self.assertEqual(len(rows), 2)
        fallback_row = next(item for item in rows if item["源码归属"] == "未标识")
        complete_row = next(item for item in rows if item["源码归属"] == "g:a:2:sources")
        self.assertEqual(fallback_row, {
            "源码归属": "未标识", "归属类型": "unknown", "二进制制品": "未标识",
            "二进制方法": ".", "源码位置": "未知:0", "模块": "", "语言": "",
            "源码声明": "fallback", "注解": "", "修饰符": "",
        })
        self.assertEqual(complete_row["源码位置"], "src/p/C.java:7-9")
        self.assertEqual(complete_row["二进制方法"], "p.C.run(int)")
        self.assertEqual(complete_row["源码声明"], "void run(int value)")
        self.assertEqual(complete_row["注解"], "Override")

        self.assertEqual(binary_report._source_candidate_review_rows({}), [])
        candidates = binary_report._source_candidate_review_rows({
            "source_explanations": {"candidate_relationships": [{}, {
                "caller_binary_descriptor": "(I)V",
                "caller_binary_class_name": "p/C", "caller_binary_member_name": "run",
                "source_owner_coord": "g:a:sources", "binary_artifact_coord": "g:a:2",
                "caller_logical_path": "src/p/C.java", "source_line": 8,
                "callee_key": "q/D#call()V", "evidence_type": "source_ast",
                "confidence": "candidate",
            }]},
        })
        self.assertEqual(candidates[0]["调用方"], ".")
        self.assertEqual(candidates[0]["源码位置"], "未知:0")
        self.assertEqual(candidates[1]["调用方"], "p.C.run(int)")
        self.assertEqual(candidates[1]["权威边界"], "源码候选关系，不是可执行调用边")

    def test_review_product_type_and_artifact_coordinate_decision_matrix(self):
        self.assertEqual(binary_report._visibility_rank(None), 1)
        self.assertEqual(binary_report._visibility_rank(0x0001), 3)
        self.assertEqual(binary_report._visibility_rank(0x0004), 2)
        self.assertEqual(binary_report._visibility_rank(0x0002), 0)

        cases = [
            ({"fact_kind": "member_resolution"}, "MEMBER_RESOLUTION_CHANGED"),
            ({"fact_kind": "provider_topology", "evidence": {
                "base_provider": {"class_provider_status": "resolved"},
                "current_provider": {"class_provider_status": "missing"},
            }}, "CLASS_REMOVED"),
            ({"fact_kind": "provider_topology", "evidence": {
                "base_provider": {"class_provider_status": "missing"},
                "current_provider": {"class_provider_status": "resolved"},
            }}, "CLASS_ADDED"),
            ({"fact_kind": "provider_topology"}, "BEHAVIOR_CHANGED"),
            ({"fact_kind": "class", "fact_scope": {"member_change_kind": "added"}}, "CLASS_ADDED"),
            ({"fact_kind": "field", "fact_scope": {"member_change_kind": "added"}}, "DATA_FIELD_ADDED"),
            ({"fact_kind": "field", "fact_scope": {"member_change_kind": "removed"}}, "DATA_FIELD_REMOVED"),
            ({"fact_kind": "method", "fact_scope": {"member_change_kind": "removed"}}, "REMOVED"),
            ({"fact_kind": "method", "fact_scope": {"member_change_kind": "unknown"}}, "BEHAVIOR_CHANGED"),
            ({"fact_kind": "method", "fact_scope": {"member_change_kind": "contract_changed"},
              "evidence": {"base_contract": {"access": 1}, "current_contract": {"access": 2}}},
             "ACCESS_REDUCED"),
            ({"fact_kind": "field", "fact_scope": {"member_change_kind": "contract_changed"},
              "evidence": {"base_contract": {"access": 1, "descriptor": "I"},
                           "current_contract": {"access": 1, "descriptor": "J"}}},
             "DATA_FIELD_TYPE_CHANGED"),
            ({"fact_kind": "field", "fact_scope": {"member_change_kind": "contract_changed"},
              "evidence": {"base_contract": {"access": 1, "descriptor": "I", "constant": 1},
                           "current_contract": {"access": 1, "descriptor": "I", "constant": 2}}},
             "CONSTANT_VALUE_CHANGED"),
            ({"fact_kind": "method", "fact_scope": {"member_change_kind": "contract_changed"},
              "evidence": {"base_contract": {"access": 1, "descriptor": "()I"},
                           "current_contract": {"access": 1, "descriptor": "()J"}}},
             "SIGNATURE_CHANGED"),
            ({"fact_kind": "method", "fact_scope": {"member_change_kind": "contract_changed"},
              "evidence": {"base_contract": {"access": 1, "descriptor": "()I"},
                           "current_contract": {"access": 1, "descriptor": "()I"}}},
             "CONTRACT_CHANGED"),
            ({"fact_kind": "method", "fact_scope": {"member_change_kind": "contract_changed"},
              "evidence": {"base_contract": "invalid", "current_contract": {}}},
             "BEHAVIOR_CHANGED"),
        ]
        for decision, expected in cases:
            with self.subTest(expected=expected, decision=decision):
                self.assertEqual(binary_report._product_change_type(decision), expected)

        coordinate_cases = [
            ({}, ("UNBOUND_RUNTIME_ARTIFACT", "-", "-")),
            ({"dependency_artifacts": [{"runtime_code_source_origin_identity": "runtime-id"}]},
             ("runtime-id", "-", "-")),
            ({"dependency_artifacts": [{"side": "base", "coord": "short"}]},
             ("short", "short", "-")),
            ({"dependency_artifacts": [
                {"side": "base", "coord": "g:a:1"},
                {"side": "current", "coord": "g:a:2"},
            ]}, ("g:a", "1", "2")),
            ({"dependency_artifacts": [
                {"logical_dependency_lineage": "  g:a  ", "side": "base", "coord": "g:a:1"},
            ]}, ("g:a", "1", "-")),
        ]
        for record, expected in coordinate_cases:
            with self.subTest(record=record):
                self.assertEqual(binary_report._artifact_coord_parts(record), expected)

        empty_review = binary_report._review_row({}, None, conclusion="候选变化")
        self.assertEqual(empty_review["依赖包"], "未绑定制品（需查看裁决证据）")
        self.assertEqual(empty_review["覆盖状态"], "完整")
        self.assertEqual(empty_review["需人工复核"], "是")
        self.assertEqual(empty_review["升级前证据"], "{}")
        formal_review = binary_report._review_row({
            "reason_code": "R", "decision_identity": "D",
            "coverage_gaps": ["gap"],
            "evidence": {"base_member_fingerprint": {"x": 1}, "current_contract": {"x": 2}},
        }, {"analysis_projection_status": "done", "projection_coverage_status": "partial"}, conclusion="正式变化")
        self.assertEqual(formal_review["覆盖状态"], "partial")
        self.assertEqual(formal_review["需人工复核"], "是")
        self.assertEqual(formal_review["证据缺口"], "gap")

    def test_resource_product_rows_result_items_and_trace_metrics(self):
        resource = binary_report._resource_activation_item({
            "activation_callers": [
                {"path_certainty": "unrelated"},
                {"path_certainty": "possible"},
                {
                    "path_certainty": "exact", "caller_class_name": "p/C",
                    "caller_member_name": "run", "caller_descriptor": "(I)V",
                },
            ],
        })
        self.assertEqual(resource["coord"], "UNBOUND_RUNTIME_ARTIFACT")
        self.assertEqual(len(resource["activation_callers"]), 2)
        self.assertEqual(resource["activation_callers"][0]["display_caller"], ".()")
        self.assertEqual(resource["activation_callers"][1]["display_caller"], "p.C.run(int)")
        self.assertEqual(resource["business_entries"], [".()", "p.C.run(int)"])

        empty = binary_report._product_change_row({}, {}, evidence_path="evidence.json")
        self.assertEqual(empty["coord"], "UNBOUND_RUNTIME_ARTIFACT")
        self.assertEqual(empty["symbol_kind"], "class")
        self.assertEqual(empty["api_signature"], "")
        self.assertEqual(empty["old_value"], '""')
        self.assertEqual(empty["review_reason"], "依赖 UNBOUND_RUNTIME_ARTIFACT 的运行时有效制品发生变化；裁决原因 -")

        constructor = binary_report._product_change_row({
            "fact_kind": "method", "reason_code": "REMOVED", "decision_identity": "D",
            "change_fact_identity": "F",
            "fact_scope": {
                "class_name": "p/C", "member_name": "<init>", "member_kind": "invalid",
                "descriptor": "(I)V", "member_change_kind": "removed",
            },
            "evidence": {"base_member_fingerprint": {"digest": "old"}},
        }, {"analysis_projection_status": "targetable", "projection_coverage_status": "complete"}, evidence_path="e.json")
        self.assertEqual(constructor["symbol_kind"], "constructor")
        self.assertEqual(constructor["api_signature"], "(int)")
        self.assertEqual(constructor["binary_compatible"], "false")
        self.assertEqual(constructor["source_compatible"], "false")
        self.assertEqual(constructor["old_value"], '{"digest": "old"}')
        self.assertEqual(constructor["_projection_status"], "targetable")

        resolution = binary_report._product_change_row({
            "fact_kind": "member_resolution",
            "fact_scope": {"member_kind": "method"},
            "evidence": {
                "base_resolution": {"member_resolution_status": "missing"},
                "current_resolution": {"resolved_owner": "p/Base"},
            },
        }, {}, evidence_path="e.json")
        self.assertEqual(resolution["old_value"], "missing")
        self.assertEqual(resolution["new_value"], "p/Base")

        no_paths = binary_report._result_item({})
        self.assertEqual(no_paths["api"], "")
        self.assertEqual(no_paths["path_text"], "")
        self.assertEqual(no_paths["paths"], [])
        possible = binary_report._result_item({
            "display_owner": "p/C", "display_member": "<class>",
            "display_descriptor": "not-a-method", "paths": [{"path_text": "possible", "path_certainty": "possible"}],
        })
        self.assertEqual(possible["api"], "p.C")
        self.assertEqual(possible["path_text"], "possible")
        exact = binary_report._result_item({
            "display_owner": "p/C", "display_member": "run", "display_descriptor": "(I)V",
            "paths": [
                {"path_text": "possible", "path_certainty": "possible"},
                {"path_text": "exact", "path_certainty": "exact"},
            ],
        })
        self.assertEqual(exact["api"], "p.C.run")
        self.assertEqual(exact["api_signature"], "(int)")
        self.assertEqual(exact["path_text"], "exact")

        self.assertEqual(binary_report._trace_metrics_by_change({"formal": {}}), {})
        metrics = binary_report._trace_metrics_by_change({"formal": {"results": [
            {
                "change_fact_identity": "F", "exact_path_exists": True,
                "paths": [{"path_certainty": "exact"}, {"path_certainty": "possible"}, {}],
            },
            {"change_fact_identity": "F", "possible_path_exists": True, "paths": [{"path_certainty": "possible"}]},
            {},
        ]}})
        self.assertEqual(metrics["F"], {"exact_api": 1, "possible_api": 1, "exact_paths": 1, "possible_paths": 2})
        self.assertEqual(metrics[""], {"exact_api": 0, "possible_api": 0, "exact_paths": 0, "possible_paths": 0})

    def test_legacy_result_state_path_and_change_fallback_matrix(self):
        states = [
            ("reachable", "已确认影响", "RUNTIME_VERIFICATION_REQUIRED", "probable_impact"),
            ("uncertain", "结论未确定（静态分析能力边界）", "BINARY_REACHABILITY_UNCERTAIN", "uncertain"),
            ("not_found_in_static_analysis", "未发现调用路径", "NOT_FOUND_IN_STATIC_ANALYSIS", "not_found_in_static_analysis"),
            ("other", "本次未完成分析", "BINARY_TRACE_NOT_ANALYZED", "other"),
        ]
        for state, conclusion, reason, bucket in states:
            with self.subTest(state=state):
                result = binary_report._legacy_result_item({"reachability_status": state}, None)
                self.assertEqual(result["user_conclusion"], conclusion)
                self.assertEqual(result["reason_code"], reason)
                self.assertEqual(result["decision_bucket"], bucket)
                self.assertEqual(result["call_paths"], [])
                self.assertEqual(result["verification"], ["执行相关单元测试、集成测试或运行时回归验证。"] if state == "reachable" else [])

        uncertain = binary_report._legacy_result_item({
            "api": "p.C.run", "api_signature": "(int)", "symbol_kind": "method",
            "reachability_status": "uncertain", "path_text": "app.Entry.go → p.C.run",
        }, {})
        self.assertEqual(uncertain["user_conclusion"], "结论未确定（存在候选证据）")
        self.assertEqual(uncertain["uncertainty_kind"], "candidate_evidence")
        self.assertEqual(uncertain["business_entry"], "app.Entry.go")
        self.assertEqual(uncertain["business_reach_depth"], 1)
        self.assertEqual(uncertain["path_details"][0]["path_certainty"], "")

        rich_paths = [{
            "path_text": "app.Entry.run() → p.C.run(int)", "path_certainty": "exact",
            "entry_kinds": ["cli"], "entry_kind_labels": ["命令行"],
            "entrypoint_dependency_coords": ["app:main:1"],
            "entrypoint_activation_reasons": ["main_method"],
            "mechanism_kinds": ["method"], "mechanism_labels": ["字节码调用"],
        }, {"path_text": "app.Other.go → p.C.run(int)"}, {"path_text": "   "}]
        changed = binary_report._legacy_result_item({
            "api": "p.C.run", "api_signature": "(int)", "symbol_kind": "item-kind",
            "coord": "item:coord", "reachability_status": "reachable", "paths": rich_paths,
        }, {
            "coord": "change:coord", "symbol_kind": "method", "change_type": "REMOVED",
            "change_fact_identity": "F", "decision_identity": "D", "old_version": "1",
            "new_version": "2", "severity": "P0", "confirmed": "false", "source": "oracle",
            "change_summary": "removed", "old_value": "old", "new_value": "new",
            "review_reason": "review",
        })
        self.assertEqual(changed["coord"], "change:coord")
        self.assertEqual(changed["call_paths"], [
            "app.Entry.run() → p.C.run(int)", "app.Other.go → p.C.run(int)",
        ])
        self.assertEqual(changed["path_details"][0]["entry_kind_labels"], ["命令行"])
        self.assertEqual(changed["path_details"][1]["entry_kind_labels"], [])
        self.assertEqual(changed["entry_kind"], "命令行")
        self.assertEqual(changed["entrypoint_dependency"], "app:main:1")
        self.assertEqual(changed["api_identity"], "change:coord|p.C.run|(int)|method|REMOVED|F")
        self.assertEqual(changed["recommended_action"], "根据已定位调用关系执行定向回归验证。")

    def test_legacy_alert_and_coverage_output_matrix(self):
        empty_row = binary_report._legacy_alert_rows([{}])[0]
        self.assertEqual(empty_row["chain_summary"], "未形成完整链路；目标 API：")
        self.assertEqual(empty_row["business_reachable"], "unknown")
        self.assertEqual(empty_row["consumer_coord"], "")
        self.assertEqual(empty_row["entry_kind"], "")
        self.assertEqual(empty_row["reach_kind"], "")

        items = [{
            "api_identity": "ID", "api": "dep.Api.call", "api_signature": "()",
            "analysis_status": "reachable", "call_paths": [
                "PlainEntry", "app.Entry.run(int) → dep.Api.call()",
            ],
            "path_details": [{
                "path_text": "PlainEntry", "entry_kind_labels": ["", "作业"],
                "entrypoint_dependency_coords": ["", "app:job:1"],
                "mechanism_labels": ["", "反射调用"],
            }],
            "user_conclusion": "已确认影响", "recommended_action": "test",
            "review_reason": "", "user_reason": "fallback reason", "severity": "",
        }]
        rows = binary_report._legacy_alert_rows(items)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["consumer_class"], "PlainEntry")
        self.assertEqual(rows[0]["consumer_method"], "")
        self.assertEqual(rows[0]["entry_kind"], "作业")
        self.assertEqual(rows[0]["consumer_coord"], "app:job:1")
        self.assertEqual(rows[0]["reach_kind"], "反射调用")
        self.assertEqual(rows[0]["business_reachable"], "true")
        self.assertEqual(rows[0]["review_reason"], "fallback reason")
        self.assertEqual(rows[0]["severity"], "P1")
        self.assertEqual(rows[1]["consumer_class"], "app.Entry")
        self.assertEqual(rows[1]["consumer_method"], "run")
        self.assertEqual(rows[1]["consumer_signature"], "(int)")
        self.assertEqual(rows[1]["entry_kind"], "业务字节码入口")
        self.assertEqual(rows[1]["reach_kind"], "字节码直接调用")
        self.assertEqual(rows[1]["chain_hop_count"], "1")
        self.assertNotEqual(rows[0]["path_id"], rows[1]["path_id"])

        self.assertEqual(binary_report._legacy_alert_rows([]), [])
        empty_coverage = binary_report._legacy_coverage({})
        self.assertEqual(empty_coverage["overall_status"], "partial")
        self.assertEqual(empty_coverage["critical_incomplete"], ["binary_api_diff", "business_reachability"])
        complete = binary_report._legacy_coverage({
            "summary": {
                "decision_coverage_status": "complete", "trace_coverage_status": "complete",
                "decision_coverage_gaps": [
                    {"reason_code": "A"}, {"code": "B"}, "A", "", {},
                ],
            },
            "coverage": {"trace_coverage_gaps": [{"code": "T"}, "T", "U"]},
        })
        self.assertEqual(complete["overall_status"], "complete")
        self.assertEqual(complete["critical_incomplete"], [])
        self.assertEqual(complete["components"][0]["reason_codes"], ["A", "B"])
        self.assertEqual(complete["components"][1]["reason_codes"], ["T", "U"])

        self.assertEqual(binary_report._change_row_key({}), ("", "", "", ""))
        self.assertEqual(binary_report._change_row_key({
            "coord": " g:a ", "api": " p.C.m ", "api_signature": " () ", "symbol_kind": " method ",
        }), ("g:a", "p.C.m", "()", "method"))
        filename = binary_report._safe_detail_filename({"api_identity": " 复杂/API identity "})
        self.assertTrue(filename.startswith("API_identity_"))
        self.assertTrue(filename.endswith(".json"))
        self.assertEqual(len(filename.rsplit("_", 1)[-1]), 17)

    def test_pure_transform_residual_fallback_and_populated_field_matrix(self):
        dependency = binary_report._dependency_view({
            "dependency_artifacts": [
                {"side": "base"},
                {"side": "current", "runtime_code_source_origin_identity": "current-origin"},
                {"logical_dependency_lineage": " g:a "},
            ],
        })
        self.assertEqual(dependency["dependency"], "g:a")
        self.assertEqual(dependency["base_dependency"], "-")
        self.assertEqual(dependency["current_dependency"], "current-origin")
        self.assertEqual(
            binary_report._artifact_coord_parts({
                "dependency_artifacts": [
                    {"logical_dependency_lineage": "   "},
                    {"side": "base", "coord": "base-only"},
                    {"runtime_code_source_origin_identity": "runtime-fallback"},
                ],
            }),
            ("base-only", "base-only", "-"),
        )
        self.assertEqual(
            binary_report._artifact_coord_parts({
                "dependency_artifacts": [
                    {"side": "current", "coord": "g:a:jar:2"},
                ],
            }),
            ("g:a:jar", "-", "2"),
        )

        source_rows = binary_report._source_review_rows({
            "coverage": {"source_overlay": {"rows": [
                {},
                {"mapping_status": "mapped", "source_location": {
                    "logical_path": "A.java", "line": 7, "end_line": 7,
                }},
                {"mapping_status": "mapped", "overlay_identity": "declared",
                 "source_location": {"logical_path": "B.java", "line": 0, "end_line": 2}},
            ]}},
            "source_explanations": {"declarations": [{
                "overlay_identity": "declared", "declared_signature": "void run()",
                "annotations": [], "modifiers": [],
            }]},
        })
        self.assertEqual(len(source_rows), 2)
        self.assertEqual({row["源码位置"] for row in source_rows}, {"A.java:7", "B.java:0-2"})

        no_review = binary_report._review_row({}, {}, conclusion="正式变化")
        self.assertEqual(no_review["需人工复核"], "否")
        self.assertEqual(no_review["覆盖状态"], "完整")
        projected = binary_report._review_row(
            {}, {"projection_coverage_status": "complete"}, conclusion="正式变化",
        )
        self.assertEqual(projected["覆盖状态"], "complete")
        incomplete_review = binary_report._review_row(
            {"coverage_gaps": ["gap"]}, None, conclusion="正式变化",
        )
        self.assertEqual(incomplete_review["覆盖状态"], "不完整")
        self.assertEqual(incomplete_review["需人工复核"], "是")

        product_type_cases = [
            ({"fact_kind": "provider_topology", "evidence": {
                "base_provider": {"class_provider_status": "resolved"},
                "current_provider": {"class_provider_status": "resolved"},
            }}, "BEHAVIOR_CHANGED"),
            ({"fact_kind": "provider_topology", "evidence": {
                "base_provider": {"class_provider_status": "other"},
                "current_provider": {"class_provider_status": "resolved"},
            }}, "BEHAVIOR_CHANGED"),
            ({"fact_kind": "method", "fact_scope": {"member_change_kind": "added"}},
             "METHOD_ADDED"),
            ({"fact_kind": "class", "fact_scope": {"member_change_kind": "removed"}},
             "REMOVED"),
            ({"fact_kind": "method", "fact_scope": {"member_change_kind": "contract_changed"},
              "evidence": {"base_contract": {}, "current_contract": {"descriptor": "()V"}}},
             "SIGNATURE_CHANGED"),
            ({"fact_kind": "field", "fact_scope": {"member_change_kind": "contract_changed"},
              "evidence": {"base_contract": {"descriptor": "I", "constant": None},
                           "current_contract": {"descriptor": "I", "constant": None}}},
             "CONTRACT_CHANGED"),
            ({"fact_kind": "method", "fact_scope": {"member_change_kind": "contract_changed"},
              "evidence": {"base_contract": {}, "current_contract": "invalid"}},
             "BEHAVIOR_CHANGED"),
        ]
        for decision, expected in product_type_cases:
            with self.subTest(product_type=decision):
                self.assertEqual(binary_report._product_change_type(decision), expected)

        normal_product = binary_report._product_change_row({
            "fact_kind": "method",
            "fact_scope": {"member_kind": "method", "member_name": "run", "descriptor": "()V"},
            "evidence": {"base_contract": {}, "current_member_fingerprint": {"digest": "new"}},
            "reason_code": "CHANGED",
        }, {}, evidence_path="evidence.json")
        self.assertEqual(normal_product["symbol_kind"], "method")
        self.assertEqual(normal_product["new_value"], '{"digest": "new"}')
        fallback_resolution = binary_report._product_change_row({
            "fact_kind": "member_resolution", "fact_scope": {"member_kind": "field"},
            "evidence": {
                "base_resolution": {"resolved_owner": "p/Base"},
                "current_resolution": {"member_resolution_status": "missing"},
            },
        }, {}, evidence_path="evidence.json")
        self.assertEqual(fallback_resolution["old_value"], "p/Base")
        self.assertEqual(fallback_resolution["new_value"], "missing")
        empty_resolution = binary_report._product_change_row({
            "fact_kind": "member_resolution",
            "fact_scope": {"member_kind": "unsupported"},
        }, {}, evidence_path="evidence.json")
        self.assertEqual(empty_resolution["symbol_kind"], "class")
        self.assertEqual(empty_resolution["old_value"], "")
        self.assertEqual(empty_resolution["new_value"], "")

        result = binary_report._result_item({
            "display_owner": "p/C", "display_member_kind": "method",
            "contributing_change_fact_ids": ["F"],
            "paths": [{"path_text": "fallback", "path_certainty": "possible"}],
        })
        self.assertEqual(result["symbol_kind"], "method")
        self.assertEqual(result["contributing_change_fact_ids"], ["F"])
        self.assertEqual(
            binary_report._resource_activation_item({})["business_entries"],
            [],
        )

        for provided in (None, Path("explicit")):
            rows = [] if provided is None else [{"coord": "g:a"}, {"coord": "g:a"}]
            with self.subTest(api_changes_dir=provided), patch.object(
                binary_report, "_read_csv_rows", return_value=rows,
            ) as read:
                loaded_rows, lookup = binary_report._change_rows_by_result(
                    "report", api_changes_dir=provided,
                )
            self.assertEqual(loaded_rows, rows)
            self.assertEqual(len(lookup), 0 if provided is None else 1)
            self.assertEqual(read.call_args.args[0].name, "all_changed_apis.csv")

        legacy = binary_report._legacy_result_item({
            "api": "p.C.run", "api_signature": "()", "reachability_status": "uncertain",
            "paths": [
                {"path_text": ""},
                {"path_text": "entry → p.C.run", "path_certainty": "possible",
                 "entry_kind_labels": ["入口"], "entrypoint_dependency_coords": ["app:main:1"]},
            ],
        }, None)
        self.assertEqual(legacy["call_paths"], ["entry → p.C.run"])
        self.assertEqual(legacy["entry_kind"], "入口")
        self.assertEqual(
            binary_report._legacy_result_item({}, None)["analysis_status"],
            "not_analyzed",
        )
        whitespace_path = binary_report._legacy_result_item({
            "reachability_status": "uncertain",
            "paths": [{"path_text": "  entry → p.C.run  "}],
        }, None)
        self.assertEqual(whitespace_path["call_paths"], ["entry → p.C.run"])
        self.assertEqual(whitespace_path["entry_kind"], "")
        blank_candidate = binary_report._legacy_result_item({
            "paths": [{"path_text": ""}],
        }, None)
        self.assertEqual(blank_candidate["call_paths"], [])

        fully_populated = {
            "api_identity": "ID", "reported_api_identity": "RID",
            "change_fact_identity": "F", "decision_identity": "D",
            "coord": "g:a", "api": "p.C.run", "api_signature": "()",
            "symbol_kind": "method", "static_linkage_status": "linked",
            "impact_conclusion": "impact", "change_type": "REMOVED", "severity": "P0",
            "uncertainty_kind": "candidate", "analysis_status": "uncertain",
            "change_summary": "change", "review_reason": "review",
            "recommended_action": "act", "call_paths": ["entry → p.C.run()"],
            "path_details": [{
                "path_text": "entry → p.C.run()", "entry_kind_labels": ["入口"],
                "entrypoint_dependency_coords": ["app:main:1"],
                "mechanism_labels": ["反射"],
            }],
        }
        alert = binary_report._legacy_alert_rows([fully_populated])[0]
        self.assertEqual(alert["reported_api_identity"], "RID")
        self.assertEqual(alert["severity"], "P0")
        self.assertEqual(alert["reach_kind"], "反射")
        fallback_alert = binary_report._legacy_alert_rows([{
            "business_entry": "fallback.Entry.run()",
            "api": "p.C.run", "api_signature": "()",
            "path_details": [{}],
        }])[0]
        self.assertEqual(fallback_alert["chain_entry"], "fallback.Entry.run()")
        self.assertEqual(fallback_alert["chain_target"], "p.C.run()")

        coverage = binary_report._legacy_coverage({
            "summary": {
                "decision_coverage_status": "complete",
                "trace_coverage_status": "partial",
                "trace_coverage_gaps": ["summary-gap"],
            },
            "coverage": {"trace_coverage_gaps": ["fallback-gap"]},
        })
        self.assertEqual(coverage["components"][1]["reason_codes"], ["summary-gap"])
        self.assertTrue(binary_report._safe_detail_filename({}).startswith("api_"))
        self.assertTrue(binary_report._safe_detail_filename({"api_identity": "///"}).startswith("api_"))


class BinaryReportValidationBoundaryTest(unittest.TestCase):
    def assert_reason(self, expected: str, action) -> binary_report.BinaryReportError:
        with self.assertRaises(binary_report.BinaryReportError) as captured:
            action()
        self.assertEqual(captured.exception.reason_code, expected)
        return captured.exception

    def test_gate_and_pending_candidate_short_circuit_matrix(self):
        self.assertEqual(
            binary_report._require_formal_publication_gate("step4", "binary_generation"),
            "binary_generation",
        )
        for stage, gate in [("", ""), ("unknown", "x"), ("step4", "wrong")]:
            with self.subTest(stage=stage, gate=gate):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_GATE_POLICY_INVALID",
                    lambda stage=stage, gate=gate: binary_report._require_formal_publication_gate(stage, gate),
                )

        valid = {
            "phase": "step5",
            "publication_transaction": {"state": "pending_gate", "gate_receipt": None},
            "publication_receipt": None,
            "global_release": None,
        }
        self.assertIs(binary_report._require_pending_publication_candidate("step5", valid), valid)
        mutations = [
            {"phase": "step4"},
            {"publication_transaction": {"state": "committed", "gate_receipt": None}},
            {"publication_transaction": {"state": "pending_gate", "gate_receipt": {}}},
            {"publication_receipt": {}},
            {"global_release": {}},
        ]
        for mutation in mutations:
            candidate = {**valid, **mutation}
            with self.subTest(mutation=mutation):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_PREPARE_CONTRACT_INVALID",
                    lambda candidate=candidate: binary_report._require_pending_publication_candidate("step5", candidate),
                )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_PREPARE_CONTRACT_INVALID",
            lambda: binary_report._require_pending_publication_candidate("step5", {}),
        )

    def test_prepare_capability_phase_nested_replay_and_binding_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assert_reason(
                "BINARY_REPORT_PREPARE_CAPABILITY_PHASE_INVALID",
                lambda: binary_report._report_publication_prepare_capability(root, "invalid").__enter__(),
            )
            with binary_report._report_publication_prepare_capability(root, "step4"):
                self.assert_reason(
                    "BINARY_REPORT_PREPARE_CAPABILITY_NESTED",
                    lambda: binary_report._report_publication_prepare_capability(root, "step5").__enter__(),
                )
                binary_report._consume_report_publication_prepare_capability(root, "step4")
                self.assert_reason(
                    "BINARY_REPORT_PREPARE_CAPABILITY_REPLAYED",
                    lambda: binary_report._consume_report_publication_prepare_capability(root, "step4"),
                )
            self.assert_reason(
                "BINARY_REPORT_PREPARE_CAPABILITY_REQUIRED",
                lambda: binary_report._consume_report_publication_prepare_capability(root, "step4"),
            )

            mismatch_actions = [
                lambda: binary_report._consume_report_publication_prepare_capability(root / "other", "step4"),
                lambda: binary_report._consume_report_publication_prepare_capability(root, "step5"),
            ]
            for action in mismatch_actions:
                with self.subTest(action=action):
                    with binary_report._report_publication_prepare_capability(root, "step4"):
                        self.assert_reason("BINARY_REPORT_PREPARE_CAPABILITY_BINDING_MISMATCH", action)

            with binary_report._report_publication_prepare_capability(root, "step4"):
                with patch.object(binary_report.os, "getpid", return_value=-1):
                    self.assert_reason(
                        "BINARY_REPORT_PREPARE_CAPABILITY_BINDING_MISMATCH",
                        lambda: binary_report._consume_report_publication_prepare_capability(root, "step4"),
                    )
            with binary_report._report_publication_prepare_capability(root, "step4"):
                with patch.object(binary_report.threading, "get_ident", return_value=-1):
                    self.assert_reason(
                        "BINARY_REPORT_PREPARE_CAPABILITY_BINDING_MISMATCH",
                        lambda: binary_report._consume_report_publication_prepare_capability(root, "step4"),
                    )

    def test_capability_falsy_inputs_wrong_authority_runtime_and_atomic_io_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_GATE_POLICY_INVALID",
                lambda: binary_report._require_formal_publication_gate("step4", None),
            )
            self.assert_reason(
                "BINARY_REPORT_PREPARE_CAPABILITY_PHASE_INVALID",
                lambda: binary_report._report_publication_prepare_capability(root, None).__enter__(),
            )
            self.assert_reason(
                "BINARY_REPORT_PREPARE_CAPABILITY_REQUIRED",
                lambda: binary_report._consume_report_publication_prepare_capability(root, None),
            )

            capability = binary_report._ReportPrepareCapability(root, "step4")
            capability.authority = object()
            token = binary_report._REPORT_PREPARE_CAPABILITY_CONTEXT.set(capability)
            try:
                self.assert_reason(
                    "BINARY_REPORT_PREPARE_CAPABILITY_REQUIRED",
                    lambda: binary_report._consume_report_publication_prepare_capability(root, "step4"),
                )
            finally:
                binary_report._REPORT_PREPARE_CAPABILITY_CONTEXT.reset(token)

            with binary_report._report_publication_prepare_capability(root, "step4"):
                self.assert_reason(
                    "BINARY_REPORT_PREPARE_CAPABILITY_BINDING_MISMATCH",
                    lambda: binary_report._consume_report_publication_prepare_capability(root, None),
                )
            with binary_report._report_publication_prepare_capability(root, "step4"):
                binary_report._consume_report_publication_prepare_capability(root, "step4")
                self.assert_reason(
                    "BINARY_REPORT_PREPARE_CAPABILITY_REPLAYED",
                    lambda: binary_report._consume_report_publication_prepare_capability(root, None),
                )

            runtime_proxy = SimpleNamespace(
                implementation=SimpleNamespace(name="fixture", cache_tag=None),
                version_info=SimpleNamespace(major=3, minor=99, micro=1),
                platform="fixture-platform",
            )
            with patch.object(binary_report, "sys", runtime_proxy):
                runtime = binary_report._report_runtime_identity()
            self.assertEqual(runtime["cache_tag"], "")
            self.assertEqual(runtime["version"], [3, 99, 1])
            self.assertTrue(binary_report._report_runtime_identity()["cache_tag"])

            binary_report._add_cleanup_note(_FallbackNoteTarget([]), "append")
            populated_notes = _FallbackNoteTarget(["existing"])
            binary_report._add_cleanup_note(populated_notes, "append")
            self.assertEqual(populated_notes.__notes__, ["existing", "append"])

            json_path = root / "atomic" / "value.json"
            text_path = root / "atomic" / "value.txt"
            binary_report._atomic_json(json_path, {"a": 1})
            binary_report._atomic_text(text_path, "value")
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), {"a": 1})
            self.assertEqual(text_path.read_text(encoding="utf-8"), "value")
            for writer, target, value in (
                (binary_report._atomic_json, root / "failed.json", {"a": 1}),
                (binary_report._atomic_text, root / "failed.txt", "value"),
            ):
                with self.subTest(writer=writer.__name__), patch.object(
                    binary_report.os, "replace", side_effect=OSError("replace failed"),
                ):
                    with self.assertRaisesRegex(OSError, "replace failed"):
                        writer(target, value)
                self.assertFalse(target.exists())

            empty = root / "empty.bin"
            populated = root / "populated.bin"
            empty.write_bytes(b"")
            populated.write_bytes(b"content")
            self.assertNotEqual(binary_report._sha256(empty), binary_report._sha256(populated))

            missing_csv = root / "missing.csv"
            empty_csv = root / "empty.csv"
            rows_csv = root / "rows.csv"
            empty_csv.write_text("a,b\n", encoding="utf-8")
            rows_csv.write_text("a,b\n1,2\n", encoding="utf-8")
            self.assertEqual(binary_report._read_csv_rows(missing_csv), [])
            self.assertEqual(binary_report._read_csv_rows(empty_csv), [])
            self.assertEqual(binary_report._read_csv_rows(rows_csv), [{"a": "1", "b": "2"}])

    def test_cleanup_aggregation_preserves_primary_and_secondary_failures(self):
        binary_report._attempt_cleanups([("ok", lambda: None)], primary=None)

        primary = RuntimeError("primary")
        binary_report._attempt_cleanups(
            [("one", lambda: (_ for _ in ()).throw(ValueError("cleanup")))],
            primary=primary,
        )
        self.assertIn("cleanup failed (one): ValueError: cleanup", primary.__notes__[0])

        def fail_one():
            raise ValueError("first")

        def fail_two():
            raise OSError("second")

        with self.assertRaisesRegex(ValueError, "first") as captured:
            binary_report._attempt_cleanups(
                [("first-op", fail_one), ("second-op", fail_two)], primary=None,
            )
        notes = "\n".join(captured.exception.__notes__)
        self.assertIn("additional cleanup failed (second-op): OSError: second", notes)
        self.assertIn("cleanup operation: first-op", notes)

        target = _FallbackNoteTarget(None)
        binary_report._add_cleanup_note(target, "fallback")
        self.assertEqual(target.__notes__, ["fallback"])
        binary_report._add_cleanup_note(_BrokenNoteTarget(), "ignored")
        plain = type("PlainTarget", (), {"add_note": None})()
        binary_report._add_cleanup_note(plain, "plain")
        self.assertEqual(plain.__notes__, ["plain"])

    def test_json_identity_sidecar_and_generation_path_validation_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid_json = root / "valid.json"
            valid_json.write_text('{"a": 1}', encoding="utf-8")
            self.assertEqual(binary_report._load_json(valid_json), {"a": 1})
            list_json = root / "list.json"
            list_json.write_text("[]", encoding="utf-8")
            self.assert_reason("BINARY_REPORT_JSON_INVALID", lambda: binary_report._load_json(list_json))
            invalid_json = root / "invalid.json"
            invalid_json.write_text("{", encoding="utf-8")
            self.assert_reason("BINARY_REPORT_JSON_INVALID", lambda: binary_report._load_json(invalid_json))
            self.assert_reason("BINARY_REPORT_JSON_INVALID", lambda: binary_report._load_json(root / "missing.json"))

            self.assertEqual(
                binary_report._generation_within_root(root, "generation/a"),
                root.resolve() / "generation" / "a",
            )
            self.assert_reason(
                "BINARY_ACTIVE_GENERATION_PATH_ESCAPE",
                lambda: binary_report._generation_within_root(root, "../escape"),
            )

        valid_digest = "a" * 64
        for value, expected in [
            (valid_digest, True), ("A" * 64, False), ("a" * 63, False),
            ("g" * 64, False), (None, False), (64, False),
        ]:
            with self.subTest(identity=value):
                self.assertEqual(binary_report._is_sha256_identity(value), expected)
        for value, expected in [
            ("sidecar.json", True), ("", False), (".", False), ("..", False),
            ("a/b", False), ("a\\b", False), ("a\0b", False), (None, False),
        ]:
            with self.subTest(sidecar=value):
                self.assertEqual(binary_report._safe_sidecar_name(value), expected)

    def test_result_generation_manifest_rejects_every_invalid_contract_dimension(self):
        manifest = {
            "authority": "binary_first",
            "analysis_context_identity": "context",
            "trace_result_set_digest": "trace",
            "active_snapshot_identities": {
                name: f"snapshot-{name}"
                for name in binary_report._RESULT_GENERATION_SNAPSHOT_LAYERS
            },
            "sidecar_content_identities": {
                name: f"sidecar-{name}"
                for name in binary_report._REQUIRED_CORE_GENERATION_SIDECARS
            },
            "policy_identities": {},
        }
        identity = binary_report._result_generation_identity_from_manifest(manifest)
        self.assertTrue(binary_report._is_sha256_identity(identity))

        invalid_manifests = [
            {**manifest, "authority": "source_first"},
            {**manifest, "analysis_context_identity": None},
            {**manifest, "analysis_context_identity": ""},
            {**manifest, "trace_result_set_digest": None},
            {**manifest, "trace_result_set_digest": ""},
            {**manifest, "active_snapshot_identities": []},
            {**manifest, "active_snapshot_identities": {}},
            {**manifest, "active_snapshot_identities": {
                **manifest["active_snapshot_identities"], "extra": "x",
            }},
            {**manifest, "active_snapshot_identities": {
                **manifest["active_snapshot_identities"],
                next(iter(binary_report._RESULT_GENERATION_SNAPSHOT_LAYERS)): "",
            }},
            {**manifest, "active_snapshot_identities": {
                **manifest["active_snapshot_identities"],
                next(iter(binary_report._RESULT_GENERATION_SNAPSHOT_LAYERS)): 1,
            }},
            {**manifest, "sidecar_content_identities": []},
            {**manifest, "sidecar_content_identities": {}},
            {**manifest, "policy_identities": []},
        ]
        for invalid in invalid_manifests:
            with self.subTest(invalid=invalid):
                self.assertEqual(binary_report._result_generation_identity_from_manifest(invalid), "")

    def test_new_and_stored_publication_binding_contract_matrix(self):
        implementation_field = binary_report._REPORT_IMPLEMENTATION_IDENTITY_FIELD
        current_identity = binary_report.report_implementation_identity()
        self.assertEqual(binary_report._new_publication_binding(None), {
            implementation_field: current_identity,
        })
        self.assertEqual(binary_report._new_publication_binding({}), {
            implementation_field: current_identity,
        })
        self.assertEqual(binary_report._new_publication_binding({
            implementation_field: "f" * 64,
        }), {implementation_field: current_identity})

        accepted_sets = [
            binary_report._REPORT_PUBLICATION_SEALED_CONTEXT_BINDING_FIELDS,
            binary_report._REPORT_PUBLICATION_CONTEXT_BINDING_FIELDS,
            binary_report._REPORT_PUBLICATION_SEALED_DOWNSTREAM_CONTEXT_BINDING_FIELDS,
            binary_report._REPORT_PUBLICATION_DOWNSTREAM_CONTEXT_BINDING_FIELDS,
        ]
        for index, fields in enumerate(accepted_sets):
            raw = {field: chr(ord("a") + index) * 64 for field in fields}
            with self.subTest(new_fields=sorted(fields)):
                result = binary_report._new_publication_binding(raw)
                self.assertEqual(set(result), set(fields) | {implementation_field})
                self.assertEqual(result[implementation_field], current_identity)
                for field in fields:
                    self.assertEqual(result[field], raw[field])

        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
            lambda: binary_report._new_publication_binding([]),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
            lambda: binary_report._new_publication_binding({"unknown": "a" * 64}),
        )
        incomplete = {
            next(iter(binary_report._REPORT_PUBLICATION_CONTEXT_BINDING_FIELDS)): "a" * 64,
        }
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
            lambda: binary_report._new_publication_binding(incomplete),
        )
        bad_values = {
            field: "a" * 64
            for field in binary_report._REPORT_PUBLICATION_CONTEXT_BINDING_FIELDS
        }
        bad_values[next(iter(bad_values))] = "INVALID"
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
            lambda: binary_report._new_publication_binding(bad_values),
        )

        current_sets = [
            {implementation_field},
            binary_report._REPORT_PUBLICATION_SEALED_BINDING_FIELDS,
            binary_report._REPORT_PUBLICATION_BINDING_FIELDS,
            binary_report._REPORT_PUBLICATION_SEALED_DOWNSTREAM_BINDING_FIELDS,
            binary_report._REPORT_PUBLICATION_DOWNSTREAM_BINDING_FIELDS,
        ]
        for fields in current_sets:
            value = {field: "a" * 64 for field in fields}
            with self.subTest(stored_current=sorted(fields)):
                self.assertEqual(
                    binary_report._stored_publication_binding(
                        value, schema=binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA,
                    ),
                    {field: value[field] for field in sorted(fields)},
                )
        for fields in [set(), binary_report._REPORT_PUBLICATION_CONTEXT_BINDING_FIELDS]:
            value = {field: "b" * 64 for field in fields}
            with self.subTest(stored_legacy=sorted(fields)):
                self.assertEqual(
                    binary_report._stored_publication_binding(
                        value, schema=binary_report._LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA,
                    ),
                    {field: value[field] for field in sorted(fields)},
                )
        invalid_stored = [
            ([], binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA),
            ({}, binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA),
            ({implementation_field: "invalid"}, binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA),
            ({"extra": "a" * 64}, binary_report._LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA),
        ]
        for value, schema in invalid_stored:
            with self.subTest(value=value, schema=schema):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
                    lambda value=value, schema=schema: binary_report._stored_publication_binding(value, schema=schema),
                )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            lambda: binary_report._stored_publication_binding({}, schema="unsupported"),
        )
        self.assertEqual(
            binary_report._publication_implementation_status(
                binary_report._LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA, {},
            ),
            "legacy",
        )
        self.assertEqual(
            binary_report._publication_implementation_status(
                binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA,
                {implementation_field: current_identity},
            ),
            "current",
        )
        self.assertEqual(
            binary_report._publication_implementation_status(
                binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA,
                {implementation_field: "0" * 64},
            ),
            "mismatch",
        )

    def test_gate_receipt_creation_and_every_content_binding_dimension(self):
        payload, _records, _token = _transaction_fixture(
            [Path("/unmaterialized/report")], state="prepared",
        )
        for gate_name, strict in [("", True), ("   ", True), ("gate", 1), ("gate", None)]:
            with self.subTest(gate_name=gate_name, strict=strict):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_GATE_POLICY_INVALID",
                    lambda gate_name=gate_name, strict=strict: binary_report._new_report_gate_receipt(
                        payload, gate_name=gate_name, strict_risk_gate=strict,
                    ),
                )
        receipt = binary_report._new_report_gate_receipt(
            payload, gate_name=" binary_report ", strict_risk_gate=False,
        )
        self.assertEqual(receipt["gate_name"], "binary_report")
        self.assertFalse(receipt["strict_risk_gate"])
        self.assertEqual(binary_report._validate_report_gate_receipt(receipt, payload=payload), receipt)

        mutations = [
            {**receipt, "extra": "x"},
            {**receipt, "schema": "bad"},
            {**receipt, "transaction_id": "2" * 32},
            {**receipt, "transaction_binding_identity": "0" * 64},
            {**receipt, "published_content_identity": "0" * 64},
            {**receipt, "gate_name": None},
            {**receipt, "gate_name": ""},
            {**receipt, "strict_risk_gate": 1},
            {**receipt, "gate_implementation_identity": "0" * 64},
            {**receipt, "gate_receipt_identity": "0" * 64},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    lambda mutation=mutation: binary_report._validate_report_gate_receipt(mutation, payload=payload),
                )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            lambda: binary_report._validate_report_gate_receipt([], payload=payload),
        )

    def test_publication_transaction_validation_state_header_and_record_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            destinations = [root / "one", root / "two"]
            current_states = ["staging", "prepared", "pending_gate", "gate_passed", "published", "committed"]
            for state in current_states:
                payload, expected_records, token = _transaction_fixture(destinations, state=state)
                with self.subTest(current_state=state):
                    records, binding, status = binary_report._validate_publication_transaction(
                        payload, destinations=destinations, group_token=token,
                    )
                    self.assertEqual(records, expected_records)
                    self.assertEqual(binding, payload["binding"])
                    self.assertEqual(status, "current")
            for state in ["staging", "prepared", "pending_gate", "gate_passed", "committed"]:
                payload, expected_records, token = _transaction_fixture(
                    destinations, state=state,
                    schema=binary_report._LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA,
                )
                with self.subTest(legacy_state=state):
                    records, binding, status = binary_report._validate_publication_transaction(
                        payload, destinations=destinations, group_token=token,
                    )
                    self.assertEqual(records, expected_records)
                    self.assertEqual(binding, {})
                    self.assertEqual(status, "legacy")

            valid, _records, token = _transaction_fixture(destinations, state="prepared")
            header_mutations = [
                {**valid, "extra": "x"},
                {**valid, "state": "invalid"},
                {**valid, "transaction_id": None},
                {**valid, "transaction_id": "1" * 31},
                {**valid, "transaction_id": "z" * 32},
                {**valid, "destinations": {}},
                {**valid, "destinations": valid["destinations"][:1]},
            ]
            legacy_published, _unused, _unused_token = _transaction_fixture(
                destinations, state="published",
                schema=binary_report._LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA,
            )
            header_mutations.append(legacy_published)
            for mutation in header_mutations:
                with self.subTest(header=mutation):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                        lambda mutation=mutation: binary_report._validate_publication_transaction(
                            mutation, destinations=destinations, group_token=token,
                        ),
                    )

            unsupported = {**valid, "schema": "unsupported"}
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_publication_transaction(
                    unsupported, destinations=destinations, group_token=token,
                ),
            )
            bad_binding = {**valid, "binding": {}}
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_publication_transaction(
                    bad_binding, destinations=destinations, group_token=token,
                ),
            )

            staging, _unused, token = _transaction_fixture(destinations, state="staging")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_publication_transaction(
                    {**staging, "published_content_identity": "a" * 64},
                    destinations=destinations, group_token=token,
                ),
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_publication_transaction(
                    {**valid, "published_content_identity": "bad"},
                    destinations=destinations, group_token=token,
                ),
            )

            record_mutations = [
                [None, valid["destinations"][1]],
                [{**valid["destinations"][0], "destination": str(root / "unbound")}, valid["destinations"][1]],
                [valid["destinations"][0], {**valid["destinations"][1], "destination": str(destinations[0])}],
                [{**valid["destinations"][0], "extra": "x"}, valid["destinations"][1]],
                [{**valid["destinations"][0], "stage": "wrong"}, valid["destinations"][1]],
                [{**valid["destinations"][0], "backup": "wrong"}, valid["destinations"][1]],
                [{**valid["destinations"][0], "had_destination": 1}, valid["destinations"][1]],
                [{**valid["destinations"][0], "content_sha256": "bad"}, valid["destinations"][1]],
            ]
            for records in record_mutations:
                mutation = {**valid, "destinations": records}
                with self.subTest(records=records):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                        lambda mutation=mutation: binary_report._validate_publication_transaction(
                            mutation, destinations=destinations, group_token=token,
                        ),
                    )

            staging_bad_record = {
                **staging,
                "destinations": [
                    {**staging["destinations"][0], "content_sha256": "a" * 64},
                    staging["destinations"][1],
                ],
            }
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_publication_transaction(
                    staging_bad_record, destinations=destinations, group_token=token,
                ),
            )
            inconsistent = {**valid, "published_content_identity": "0" * 64}
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_publication_transaction(
                    inconsistent, destinations=destinations, group_token=token,
                ),
            )
            pre_gate_receipt = {**valid, "gate_receipt": {}}
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_publication_transaction(
                    pre_gate_receipt, destinations=destinations, group_token=token,
                ),
            )
            post_gate, _unused, token = _transaction_fixture(destinations, state="gate_passed")
            post_gate["gate_receipt"] = None
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_publication_transaction(
                    post_gate, destinations=destinations, group_token=token,
                ),
            )

            file_destination = root / "file-destination"
            file_destination.write_text("not a directory", encoding="utf-8")
            file_payload, _unused, file_token = _transaction_fixture([file_destination], state="staging")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_publication_transaction(
                    file_payload, destinations=[file_destination], group_token=file_token,
                ),
            )

    def test_publication_transaction_validation_empty_paths_and_existing_path_kinds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            destinations = [root / "one", root / "two"]
            valid, _records, token = _transaction_fixture(
                destinations, state="prepared",
            )

            no_schema = {**valid, "schema": None}
            no_schema.pop("gate_receipt")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_publication_transaction(
                    no_schema, destinations=destinations, group_token=token,
                ),
            )

            for field in ("destination", "stage", "backup"):
                records = [dict(item) for item in valid["destinations"]]
                records[0][field] = None
                mutation = {**valid, "destinations": records}
                with self.subTest(empty_record_field=field):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                        lambda mutation=mutation: binary_report._validate_publication_transaction(
                            mutation,
                            destinations=destinations,
                            group_token=token,
                        ),
                    )

            existing_directory = root / "existing-directory"
            existing_directory.mkdir()
            directory_payload, expected, directory_token = _transaction_fixture(
                [existing_directory], state="staging",
            )
            records, _binding, _status = (
                binary_report._validate_publication_transaction(
                    directory_payload,
                    destinations=[existing_directory],
                    group_token=directory_token,
                )
            )
            self.assertEqual(records, expected)

            symlink_target = root / "symlink-target"
            symlink_target.mkdir()
            symlink_destination = root / "symlink-destination"
            symlink_destination.symlink_to(
                symlink_target, target_is_directory=True,
            )
            symlink_payload, _expected, symlink_token = _transaction_fixture(
                [symlink_destination], state="staging",
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_publication_transaction(
                    symlink_payload,
                    destinations=[symlink_destination],
                    group_token=symlink_token,
                ),
            )

    def test_committed_receipt_validation_header_records_identity_and_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            destinations = [root / "one", root / "two"]
            payload, records, _token = _transaction_fixture(destinations, state="committed")
            receipt = binary_report._new_committed_publication_receipt(payload, records)
            validated, status = binary_report._validate_committed_publication_receipt(
                receipt, destinations=destinations, verify_content=False,
            )
            self.assertEqual(validated, receipt)
            self.assertEqual(status, "current")

            header_mutations = [
                {**receipt, "extra": "x"},
                {**receipt, "schema": "bad"},
                {**receipt, "transaction_id": None},
                {**receipt, "transaction_id": "1" * 31},
                {**receipt, "transaction_id": "z" * 32},
                {**receipt, "destinations": {}},
                {**receipt, "destinations": receipt["destinations"][:1]},
            ]
            for mutation in header_mutations:
                with self.subTest(header=mutation):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                        lambda mutation=mutation: binary_report._validate_committed_publication_receipt(
                            mutation, destinations=destinations, verify_content=False,
                        ),
                    )

            record_mutations = [
                [None, receipt["destinations"][1]],
                [{**receipt["destinations"][0], "extra": "x"}, receipt["destinations"][1]],
                [{**receipt["destinations"][0], "destination": str(root / "other")}, receipt["destinations"][1]],
                [receipt["destinations"][0], {**receipt["destinations"][1], "destination": str(destinations[0])}],
                [{**receipt["destinations"][0], "content_sha256": "bad"}, receipt["destinations"][1]],
            ]
            for records_value in record_mutations:
                mutation = {**receipt, "destinations": records_value}
                mutation["committed_receipt_identity"] = binary_report._committed_publication_receipt_identity(mutation)
                with self.subTest(records=records_value):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                        lambda mutation=mutation: binary_report._validate_committed_publication_receipt(
                            mutation, destinations=destinations, verify_content=False,
                        ),
                    )

            for field, value in [
                ("published_content_identity", "0" * 64),
                ("committed_receipt_identity", "0" * 64),
                ("gate_receipt", None),
            ]:
                mutation = {**receipt, field: value}
                if field != "committed_receipt_identity":
                    mutation["committed_receipt_identity"] = binary_report._committed_publication_receipt_identity(mutation)
                with self.subTest(field=field):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                        lambda mutation=mutation: binary_report._validate_committed_publication_receipt(
                            mutation, destinations=destinations, verify_content=False,
                        ),
                    )

            with patch.object(
                binary_report, "_directory_content_identity",
                side_effect=[records[0]["content_sha256"], "0" * 64],
            ) as content:
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                    lambda: binary_report._validate_committed_publication_receipt(
                        receipt, destinations=destinations, verify_content=True,
                    ),
                )
            self.assertEqual(content.call_count, 2)

            with patch.object(
                binary_report, "_directory_content_identity",
                side_effect=[record["content_sha256"] for record in records],
            ):
                validated, _status = binary_report._validate_committed_publication_receipt(
                    receipt, destinations=destinations, verify_content=True,
                )
            self.assertEqual(validated["published_content_identity"], receipt["published_content_identity"])

            empty_destination_records = [
                dict(item) for item in receipt["destinations"]
            ]
            empty_destination_records[0]["destination"] = None
            empty_destination = {
                **receipt, "destinations": empty_destination_records,
            }
            empty_destination["committed_receipt_identity"] = (
                binary_report._committed_publication_receipt_identity(
                    empty_destination,
                )
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._validate_committed_publication_receipt(
                    empty_destination,
                    destinations=destinations,
                    verify_content=False,
                ),
            )

    def test_transaction_paths_receipt_path_and_published_content_verification(self):
        destinations = [Path("/z/report"), Path("/a/report")]
        transaction_path, token = binary_report._publication_transaction_path(destinations)
        self.assertEqual(transaction_path.parent, Path("/a"))
        self.assertEqual(transaction_path.name, f".jua-br-{token}.transaction.json")
        self.assertEqual(token, binary_report._publication_group_token(list(reversed(destinations))))
        self.assertEqual(
            binary_report._committed_publication_receipt_path(transaction_path),
            transaction_path.with_name(f".jua-br-{token}.committed.json"),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            lambda: binary_report._committed_publication_receipt_path(Path("wrong.json")),
        )

        payload, records, _token = _transaction_fixture(destinations, state="pending_gate")
        with patch.object(
            binary_report, "_directory_content_identity",
            side_effect=[record["content_sha256"] for record in records],
        ) as content:
            binary_report._verify_published_transaction_content(payload, records)
        self.assertEqual(
            [call.args[0] for call in content.call_args_list],
            [record["stage"] for record in records],
        )

        committed, records, _token = _transaction_fixture(destinations, state="committed")
        with patch.object(
            binary_report, "_directory_content_identity",
            side_effect=[records[0]["content_sha256"], "0" * 64],
        ):
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                lambda: binary_report._verify_published_transaction_content(committed, records),
            )
        bad_identity = {**committed, "published_content_identity": "0" * 64}
        with patch.object(
            binary_report, "_directory_content_identity",
            side_effect=[record["content_sha256"] for record in records],
        ):
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                lambda: binary_report._verify_published_transaction_content(bad_identity, records),
            )

        legacy, legacy_records, _token = _transaction_fixture(
            destinations,
            state="prepared",
            schema=binary_report._LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA,
        )
        with patch.object(
            binary_report,
            "_directory_content_identity",
            side_effect=[record["content_sha256"] for record in legacy_records],
        ) as content:
            binary_report._verify_published_transaction_content(
                legacy, legacy_records,
            )
        self.assertEqual(
            [call.args[0] for call in content.call_args_list],
            [record["destination"] for record in legacy_records],
        )


class BinaryReportFilesystemBoundaryTest(unittest.TestCase):
    def assert_reason(self, expected: str, action) -> binary_report.BinaryReportError:
        with self.assertRaises(binary_report.BinaryReportError) as captured:
            action()
        self.assertEqual(captured.exception.reason_code, expected)
        return captured.exception

    def _assert_stat_race_matrix(self, path: Path, operation, expected_reason: str) -> None:
        opening_mutations = [
            ("fstat", 1, {"st_mode": stat.S_IFDIR | 0o700}),
            ("fstat", 1, {"st_nlink": 2}),
            ("lstat", 2, {"st_nlink": 2}),
            ("fstat", 1, {"st_dev": os.lstat(path).st_dev + 1}),
            ("lstat", 2, {"st_ino": os.lstat(path).st_ino + 1}),
        ]
        final_mutations = [
            ("fstat", 2, {"st_dev": os.lstat(path).st_dev + 1}),
            ("lstat", 3, {"st_ino": os.lstat(path).st_ino + 1}),
            ("fstat", 2, {"st_nlink": 2}),
            ("lstat", 3, {"st_nlink": 2}),
            ("fstat", 2, {"st_size": os.lstat(path).st_size + 1}),
            ("fstat", 2, {"st_mtime_ns": os.lstat(path).st_mtime_ns + 1}),
            ("fstat", 2, {"st_ctime_ns": os.lstat(path).st_ctime_ns + 1}),
        ]
        for function_name, call_number, overrides in opening_mutations + final_mutations:
            counts = {"lstat": 0, "fstat": 0}

            def controlled_lstat(candidate):
                value = os.lstat(candidate)
                if Path(candidate) == path:
                    counts["lstat"] += 1
                    if function_name == "lstat" and counts["lstat"] == call_number:
                        return _StatView(value, **overrides)
                return value

            def controlled_fstat(descriptor):
                value = os.fstat(descriptor)
                counts["fstat"] += 1
                if function_name == "fstat" and counts["fstat"] == call_number:
                    return _StatView(value, **overrides)
                return value

            with self.subTest(function=function_name, call=call_number, overrides=overrides), patch.object(
                binary_report,
                "os",
                _OsProxy(lstat=controlled_lstat, fstat=controlled_fstat),
            ):
                self.assert_reason(expected_reason, operation)

    def test_report_file_hash_rejects_unsafe_entries_and_every_identity_race(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "report.json"
            content = b'{"value":1}\n'
            target.write_bytes(content)
            self.assertEqual(
                binary_report._report_file_sha256(target),
                __import__("hashlib").sha256(content).hexdigest(),
            )
            self.assertEqual(
                binary_report._report_file_sha256(target, make_durable=True),
                __import__("hashlib").sha256(content).hexdigest(),
            )

            captured_flags = []

            def windows_open(path, flags, *args):
                captured_flags.append(flags)
                return os.open(path, flags, *args)

            with patch.object(
                binary_report, "os", _OsProxy(name="nt", open=windows_open),
            ):
                self.assertEqual(
                    binary_report._report_file_sha256(target, make_durable=True),
                    __import__("hashlib").sha256(content).hexdigest(),
                )
            self.assertTrue(captured_flags[0] & os.O_RDWR)

            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._report_file_sha256(root / "missing"),
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._report_file_sha256(root),
            )
            symlink = root / "report-link"
            symlink.symlink_to(target)
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._report_file_sha256(symlink),
            )
            hardlink = root / "report-hardlink"
            os.link(target, hardlink)
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._report_file_sha256(target),
            )
            hardlink.unlink()

            self._assert_stat_race_matrix(
                target,
                lambda: binary_report._report_file_sha256(target),
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
            )

            def denied_open(candidate, _flags, *_args):
                if Path(candidate) == target:
                    raise PermissionError("denied")
                return os.open(candidate, _flags, *_args)

            with patch.object(binary_report, "os", _OsProxy(open=denied_open)):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                    lambda: binary_report._report_file_sha256(target),
                )

    def test_private_receipt_reader_rejects_entry_types_parse_failures_and_stat_races(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "receipt.json"
            target.write_text('{"value": 1}', encoding="utf-8")
            self.assertEqual(binary_report._read_private_publication_json(target), {"value": 1})
            self.assertIsNone(binary_report._read_private_publication_json(root / "missing"))

            invalid = root / "invalid.json"
            invalid.write_text("{", encoding="utf-8")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._read_private_publication_json(invalid),
            )
            array = root / "array.json"
            array.write_text("[]", encoding="utf-8")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._read_private_publication_json(array),
            )
            symlink = root / "receipt-link"
            symlink.symlink_to(target)
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._read_private_publication_json(symlink),
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._read_private_publication_json(root),
            )
            hardlink = root / "receipt-hardlink"
            os.link(target, hardlink)
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._read_private_publication_json(target),
            )
            hardlink.unlink()

            self._assert_stat_race_matrix(
                target,
                lambda: binary_report._read_private_publication_json(target),
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            )

            def denied_lstat(candidate):
                if Path(candidate) == target:
                    raise PermissionError("denied")
                return os.lstat(candidate)

            with patch.object(binary_report, "os", _OsProxy(lstat=denied_lstat)):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    lambda: binary_report._read_private_publication_json(target),
                )

    def test_transaction_reader_rejects_entry_types_parse_failures_and_stat_races(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            destination = root / "published"
            payload, expected_records, token = _transaction_fixture([destination], state="staging")
            target = root / "transaction.json"
            target.write_text(json.dumps(payload), encoding="utf-8")
            loaded = binary_report._load_publication_transaction(
                target, destinations=[destination], group_token=token,
            )
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded[0], payload)
            self.assertEqual(loaded[1], expected_records)
            self.assertEqual(loaded[2], "current")
            self.assertIsNone(binary_report._load_publication_transaction(
                root / "missing", destinations=[destination], group_token=token,
            ))

            invalid = root / "invalid.json"
            invalid.write_text("{", encoding="utf-8")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._load_publication_transaction(
                    invalid, destinations=[destination], group_token=token,
                ),
            )
            array = root / "array.json"
            array.write_text("[]", encoding="utf-8")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._load_publication_transaction(
                    array, destinations=[destination], group_token=token,
                ),
            )
            symlink = root / "transaction-link"
            symlink.symlink_to(target)
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._load_publication_transaction(
                    symlink, destinations=[destination], group_token=token,
                ),
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._load_publication_transaction(
                    root, destinations=[destination], group_token=token,
                ),
            )
            hardlink = root / "transaction-hardlink"
            os.link(target, hardlink)
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._load_publication_transaction(
                    target, destinations=[destination], group_token=token,
                ),
            )
            hardlink.unlink()

            self._assert_stat_race_matrix(
                target,
                lambda: binary_report._load_publication_transaction(
                    target, destinations=[destination], group_token=token,
                ),
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            )

            def denied_lstat(candidate):
                if Path(candidate) == target:
                    raise PermissionError("denied")
                return os.lstat(candidate)

            with patch.object(binary_report, "os", _OsProxy(lstat=denied_lstat)):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    lambda: binary_report._load_publication_transaction(
                        target, destinations=[destination], group_token=token,
                    ),
                )

    def test_transaction_reader_marker_metadata_and_final_identity_races(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            destination = root / "published"
            payload, _records, token = _transaction_fixture(
                [destination], state="staging",
            )
            target = root / "transaction.json"
            target.write_text(json.dumps(payload), encoding="utf-8")
            baseline = os.lstat(target)

            def invoke(*, fstat_call=None, lstat_call=None, overrides=None, name=os.name):
                counts = {"fstat": 0, "lstat": 0}
                overrides = dict(overrides or {})

                def controlled_fstat(descriptor):
                    value = os.fstat(descriptor)
                    counts["fstat"] += 1
                    if counts["fstat"] == fstat_call:
                        return _StatView(value, **overrides)
                    return value

                def controlled_lstat(path):
                    value = os.lstat(path)
                    if Path(path) == target:
                        counts["lstat"] += 1
                        if counts["lstat"] == lstat_call:
                            return _StatView(value, **overrides)
                    return value

                with patch.object(
                    binary_report,
                    "os",
                    _OsProxy(
                        name=name,
                        fstat=controlled_fstat,
                        lstat=controlled_lstat,
                    ),
                ):
                    return binary_report._load_publication_transaction(
                        target,
                        destinations=[destination],
                        group_token=token,
                    )

            for field, value in [
                ("st_size", baseline.st_size + 1),
                ("st_mtime_ns", baseline.st_mtime_ns + 1),
                ("st_ctime_ns", baseline.st_ctime_ns + 1),
            ]:
                with self.subTest(opened_marker_field=field):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                        lambda field=field, value=value: invoke(
                            fstat_call=1, overrides={field: value},
                        ),
                    )

            loaded = invoke(
                fstat_call=1,
                overrides={"st_ctime_ns": baseline.st_ctime_ns + 1},
                name="nt",
            )
            self.assertEqual(loaded[0], payload)

            for source, field, value in [
                ("fstat", "st_ino", baseline.st_ino + 1),
                ("lstat", "st_dev", baseline.st_dev + 1),
            ]:
                with self.subTest(final_identity_source=source, field=field):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                        lambda source=source, field=field, value=value: invoke(
                            fstat_call=2 if source == "fstat" else None,
                            lstat_call=3 if source == "lstat" else None,
                            overrides={field: value},
                        ),
                    )

    def test_secure_file_copy_handles_empty_partial_write_and_identity_races(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source.bin"
            source.write_bytes(b"abcdefghij")
            os.chmod(source, 0o640)
            destination = root / "destination.bin"
            binary_report._copy_report_file_secure(source, destination)
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o640)

            empty = root / "empty.bin"
            empty.write_bytes(b"")
            empty_copy = root / "empty-copy.bin"
            binary_report._copy_report_file_secure(empty, empty_copy)
            self.assertEqual(empty_copy.read_bytes(), b"")

            partial_destination = root / "partial.bin"
            write_calls = []

            def partial_write(descriptor, value):
                size = max(len(value) // 2, 1)
                written = os.write(descriptor, value[:size])
                write_calls.append(written)
                return written

            with patch.object(binary_report, "os", _OsProxy(write=partial_write)):
                binary_report._copy_report_file_secure(source, partial_destination)
            self.assertGreater(len(write_calls), 1)
            self.assertEqual(partial_destination.read_bytes(), source.read_bytes())

            windows_destination = root / "windows-copy.bin"
            with patch.object(binary_report, "os", _OsProxy(name="nt")):
                binary_report._copy_report_file_secure(source, windows_destination)
            self.assertEqual(windows_destination.read_bytes(), source.read_bytes())

            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._copy_report_file_secure(root / "missing", root / "missing-copy"),
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._copy_report_file_secure(root, root / "directory-copy"),
            )
            hardlink = root / "source-hardlink"
            os.link(source, hardlink)
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._copy_report_file_secure(source, root / "hardlink-copy"),
            )
            hardlink.unlink()
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._copy_report_file_secure(source, destination),
            )

            race_destination = root / "race-copy.bin"

            def race_copy():
                race_destination.unlink(missing_ok=True)
                binary_report._copy_report_file_secure(source, race_destination)

            self._assert_stat_race_matrix(
                source, race_copy, "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
            )

            original_open = os.open

            def fail_destination_open(path, flags, *args):
                if Path(path) == race_destination:
                    raise PermissionError("destination denied")
                return original_open(path, flags, *args)

            race_destination.unlink(missing_ok=True)
            with patch.object(binary_report, "os", _OsProxy(open=fail_destination_open)):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                    lambda: binary_report._copy_report_file_secure(source, race_destination),
                )

    def test_zero_optional_open_flags_and_windows_ctime_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            content = root / "content.json"
            content.write_text('{"value": 1}', encoding="utf-8")
            destination = root / "copied.json"
            transaction_destination = root / "published"
            payload, _records, token = _transaction_fixture(
                [transaction_destination], state="staging",
            )
            transaction = root / "transaction.json"
            transaction.write_text(json.dumps(payload), encoding="utf-8")
            proxy = _OsProxy(
                name="nt", O_NOFOLLOW=0, O_NONBLOCK=0,
                O_BINARY=int(getattr(os, "O_NONBLOCK", 0) or getattr(os, "O_CLOEXEC", 0)),
            )
            with patch.object(binary_report, "os", proxy):
                self.assertEqual(
                    binary_report._read_private_publication_json(content),
                    {"value": 1},
                )
                loaded = binary_report._load_publication_transaction(
                    transaction,
                    destinations=[transaction_destination],
                    group_token=token,
                )
                self.assertEqual(loaded[0], payload)
                self.assertTrue(binary_report._is_sha256_identity(
                    binary_report._report_file_sha256(content, make_durable=True),
                ))
                self.assertTrue(binary_report._is_sha256_identity(
                    binary_report._report_file_sha256(content, make_durable=False),
                ))
                binary_report._copy_report_file_secure(content, destination)
            self.assertEqual(destination.read_bytes(), content.read_bytes())

            source_dir = root / "source-dir"
            source_dir.mkdir()
            (source_dir / "file.txt").write_text("value", encoding="utf-8")
            copied_dir = root / "copied-dir"
            with patch.object(binary_report, "os", _OsProxy(name="nt")):
                binary_report._copy_report_directory_secure(source_dir, copied_dir)
            self.assertEqual((copied_dir / "file.txt").read_text(encoding="utf-8"), "value")

            denied_destination = root / "source-open-denied.json"
            original_open = os.open

            def deny_source(path, flags, *args):
                if Path(path) == content:
                    raise PermissionError("source denied")
                return original_open(path, flags, *args)

            with patch.object(binary_report, "os", _OsProxy(open=deny_source)):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                    lambda: binary_report._copy_report_file_secure(
                        content, denied_destination,
                    ),
                )

    def test_directory_identity_and_secure_copy_cover_tree_entry_types_and_races(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            (source / "nested").mkdir(parents=True)
            (source / "z.txt").write_text("z", encoding="utf-8")
            (source / "nested" / "a.txt").write_text("a", encoding="utf-8")
            identity = binary_report._directory_content_identity(source)
            self.assertTrue(binary_report._is_sha256_identity(identity))
            self.assertEqual(
                binary_report._directory_content_identity(source, make_durable=True),
                identity,
            )

            equivalent = root / "equivalent"
            (equivalent / "nested").mkdir(parents=True)
            (equivalent / "nested" / "a.txt").write_text("a", encoding="utf-8")
            (equivalent / "z.txt").write_text("z", encoding="utf-8")
            self.assertEqual(binary_report._directory_content_identity(equivalent), identity)

            destination = root / "copied"
            binary_report._copy_report_directory_secure(source, destination)
            self.assertEqual(binary_report._directory_content_identity(destination), identity)
            existing_empty = root / "existing-empty"
            existing_empty.mkdir()
            binary_report._copy_report_directory_secure(
                source, existing_empty, destination_exists=True,
            )
            self.assertEqual(binary_report._directory_content_identity(existing_empty), identity)

            for bad_destination_kind in ["file", "nonempty", "symlink"]:
                candidate = root / f"bad-{bad_destination_kind}"
                if bad_destination_kind == "file":
                    candidate.write_text("file", encoding="utf-8")
                elif bad_destination_kind == "nonempty":
                    candidate.mkdir()
                    (candidate / "entry").write_text("x", encoding="utf-8")
                else:
                    candidate.symlink_to(destination, target_is_directory=True)
                with self.subTest(destination_kind=bad_destination_kind):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                        lambda candidate=candidate: binary_report._copy_report_directory_secure(
                            source, candidate, destination_exists=True,
                        ),
                    )

            source_link = root / "source-link"
            source_link.symlink_to(source, target_is_directory=True)
            for unsafe_source in [root / "missing", source / "z.txt", source_link]:
                with self.subTest(source=unsafe_source):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                        lambda unsafe_source=unsafe_source: binary_report._directory_content_identity(unsafe_source),
                    )
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                        lambda unsafe_source=unsafe_source: binary_report._copy_report_directory_secure(
                            unsafe_source, root / f"copy-{unsafe_source.name}",
                        ),
                    )

            symlink_tree = root / "symlink-tree"
            symlink_tree.mkdir()
            (symlink_tree / "link").symlink_to(source / "z.txt")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._directory_content_identity(symlink_tree),
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._copy_report_directory_secure(symlink_tree, root / "symlink-copy"),
            )

            fifo_tree = root / "fifo-tree"
            fifo_tree.mkdir()
            os.mkfifo(fifo_tree / "pipe")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._directory_content_identity(fifo_tree),
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._copy_report_directory_secure(fifo_tree, root / "fifo-copy"),
            )

            original_scandir = os.scandir

            def denied_scandir(path):
                if Path(path) == source:
                    raise PermissionError("scan denied")
                return original_scandir(path)

            with patch.object(binary_report, "os", _OsProxy(scandir=denied_scandir)):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                    lambda: binary_report._directory_content_identity(source),
                )
            denied_copy = root / "denied-copy"
            with patch.object(binary_report, "os", _OsProxy(scandir=denied_scandir)):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                    lambda: binary_report._copy_report_directory_secure(source, denied_copy),
                )

            race_mutations = [
                {"st_dev": os.lstat(source).st_dev + 1},
                {"st_ino": os.lstat(source).st_ino + 1},
                {"st_mtime_ns": os.lstat(source).st_mtime_ns + 1},
                {"st_ctime_ns": os.lstat(source).st_ctime_ns + 1},
            ]
            for index, overrides in enumerate(race_mutations):
                calls = 0

                def controlled_lstat(path, overrides=overrides):
                    nonlocal calls
                    value = os.lstat(path)
                    if Path(path) == source:
                        calls += 1
                        if calls == 2:
                            return _StatView(value, **overrides)
                    return value

                race_copy = root / f"race-directory-{index}"
                with self.subTest(overrides=overrides), patch.object(
                    binary_report, "os", _OsProxy(lstat=controlled_lstat),
                ):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                        lambda race_copy=race_copy: binary_report._copy_report_directory_secure(source, race_copy),
                    )

    def test_remove_publication_path_distinguishes_file_link_directory_and_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            file_path = root / "file"
            file_path.write_text("x", encoding="utf-8")
            binary_report._remove_publication_path(file_path)
            self.assertFalse(file_path.exists())

            target = root / "target"
            target.write_text("target", encoding="utf-8")
            link = root / "link"
            link.symlink_to(target)
            binary_report._remove_publication_path(link)
            self.assertFalse(link.exists())
            self.assertEqual(target.read_text(encoding="utf-8"), "target")

            tree = root / "tree"
            tree.mkdir()
            (tree / "entry").write_text("x", encoding="utf-8")
            binary_report._remove_publication_path(tree)
            self.assertFalse(tree.exists())

            missing = root / "missing"
            binary_report._remove_publication_path(missing)
            self.assertFalse(missing.exists())

    def test_prepare_physical_parent_trusted_root_creation_race_and_unsafe_components(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            untrusted_parent = root / "untrusted" / "nested"
            self.assertEqual(
                binary_report._prepare_physical_publication_parent(untrusted_parent),
                untrusted_parent,
            )
            self.assertTrue(untrusted_parent.is_dir())

            trusted = root / "trusted"
            trusted.mkdir()
            trusted_parent = trusted / "one" / "two"
            self.assertEqual(
                binary_report._prepare_physical_publication_parent(
                    trusted_parent, trusted_root=trusted,
                ),
                trusted_parent,
            )
            self.assertTrue(trusted_parent.is_dir())

            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._prepare_physical_publication_parent(
                    root / "x", trusted_root=Path("."),
                ),
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._prepare_physical_publication_parent(
                    root / "x", trusted_root=root / "missing-root",
                ),
            )
            trusted_file = root / "trusted-file"
            trusted_file.write_text("x", encoding="utf-8")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._prepare_physical_publication_parent(
                    trusted_file / "child", trusted_root=trusted_file,
                ),
            )
            trusted_link = root / "trusted-link"
            trusted_link.symlink_to(trusted, target_is_directory=True)
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._prepare_physical_publication_parent(
                    trusted_link / "child", trusted_root=trusted_link,
                ),
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._prepare_physical_publication_parent(
                    root / "outside", trusted_root=trusted,
                ),
            )

            component_file = trusted / "component-file"
            component_file.write_text("x", encoding="utf-8")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._prepare_physical_publication_parent(
                    component_file / "child", trusted_root=trusted,
                ),
            )
            component_link = trusted / "component-link"
            component_link.symlink_to(trusted_parent, target_is_directory=True)
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._prepare_physical_publication_parent(
                    component_link / "child", trusted_root=trusted,
                ),
            )

            raced = trusted / "raced"

            def raced_mkdir(path, *args, **kwargs):
                if Path(path) == raced:
                    os.mkdir(path, *args, **kwargs)
                    raise FileExistsError("created concurrently")
                return os.mkdir(path, *args, **kwargs)

            with patch.object(binary_report, "os", _OsProxy(mkdir=raced_mkdir)):
                self.assertEqual(
                    binary_report._prepare_physical_publication_parent(
                        raced, trusted_root=trusted,
                    ),
                    raced,
                )
            self.assertTrue(raced.is_dir())

    def test_normalize_publication_destination_trusted_boundary_and_symlink_races(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            trusted = root / "trusted"
            trusted.mkdir()
            destination = trusted / "nested" / "report"
            self.assertEqual(
                binary_report._normalize_publication_destination(destination),
                destination,
            )
            second = trusted / "other" / "report"
            self.assertEqual(
                binary_report._normalize_publication_destination(
                    second, trusted_root=trusted,
                ),
                second,
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._normalize_publication_destination(
                    root / "outside", trusted_root=trusted,
                ),
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._normalize_publication_destination(
                    root / "outside", trusted_root=Path("."),
                ),
            )

            target_dir = trusted / "target-dir"
            target_dir.mkdir()
            destination_link = trusted / "destination-link"
            destination_link.symlink_to(target_dir, target_is_directory=True)
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._normalize_publication_destination(destination_link),
            )
            parent_link = trusted / "parent-link"
            parent_link.symlink_to(target_dir, target_is_directory=True)
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._normalize_publication_destination(parent_link / "report"),
            )

            raced_destination = trusted / "race-parent" / "report"
            original_is_symlink = Path.is_symlink
            calls = 0

            def race_is_symlink(path):
                nonlocal calls
                if Path(path) == raced_destination:
                    calls += 1
                    return calls == 2
                return original_is_symlink(path)

            with patch.object(Path, "is_symlink", race_is_symlink):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                    lambda: binary_report._normalize_publication_destination(raced_destination),
                )
            self.assertEqual(calls, 2)

            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._normalize_publication_destination(
                    destination, trusted_root=Path("/"),
                ),
            )

            resolved_target = trusted / "resolved-parent"
            resolved_target.mkdir()
            raced_parent = trusted / "raced-parent-link"
            raced_parent.symlink_to(resolved_target, target_is_directory=True)
            with patch.object(
                binary_report,
                "_prepare_physical_publication_parent",
                return_value=raced_parent,
            ):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                    lambda: binary_report._normalize_publication_destination(
                        raced_parent / "report",
                    ),
                )


class BinaryReportTransactionRecoveryBoundaryTest(unittest.TestCase):
    def assert_reason(self, expected: str, action) -> binary_report.BinaryReportError:
        with self.assertRaises(binary_report.BinaryReportError) as captured:
            action()
        self.assertEqual(captured.exception.reason_code, expected)
        return captured.exception

    def test_publish_transaction_record_layout_state_machine(self):
        destination = Path("/virtual/report")
        stage = Path("/virtual/.stage")
        backup = Path("/virtual/.backup")
        digest = "a" * 64

        def record(had_destination: bool) -> dict:
            return {
                "destination": destination, "stage": stage, "backup": backup,
                "had_destination": had_destination, "content_sha256": digest,
            }

        def execute(
            *, had_destination: bool, destination_exists: bool,
            stage_exists: bool, backup_exists: bool,
            identities: dict[Path, str] | None = None,
        ):
            exists = {
                destination: destination_exists, stage: stage_exists,
                backup: backup_exists,
            }
            replacements = []
            fsyncs = []
            proxy = _OsProxy(
                replace=lambda source, target: replacements.append((Path(source), Path(target))),
            )
            with patch.object(
                binary_report, "_publication_path_exists",
                side_effect=lambda path: exists[Path(path)],
            ), patch.object(
                binary_report, "_directory_content_identity",
                side_effect=lambda path: (identities or {}).get(Path(path), digest),
            ), patch.object(
                binary_report, "_fsync_directory",
                side_effect=lambda path: fsyncs.append(Path(path)),
            ), patch.object(binary_report, "os", proxy):
                result = binary_report._publish_transaction_record(record(had_destination))
            return result, replacements, fsyncs

        invalid_completed = [
            dict(had_destination=False, destination_exists=False, stage_exists=False, backup_exists=False),
            dict(had_destination=True, destination_exists=True, stage_exists=False, backup_exists=False),
            dict(had_destination=False, destination_exists=True, stage_exists=False, backup_exists=True),
        ]
        for layout in invalid_completed:
            with self.subTest(completed=layout):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    lambda layout=layout: execute(**layout),
                )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            lambda: execute(
                had_destination=False, destination_exists=True,
                stage_exists=False, backup_exists=False,
                identities={destination: "0" * 64},
            ),
        )
        for layout in [
            dict(had_destination=False, destination_exists=True, stage_exists=False, backup_exists=False),
            dict(had_destination=True, destination_exists=True, stage_exists=False, backup_exists=True),
        ]:
            with self.subTest(valid_completed=layout):
                result, replacements, fsyncs = execute(**layout)
                self.assertIsNone(result)
                self.assertEqual(replacements, [])
                self.assertEqual(fsyncs, [])

        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
            lambda: execute(
                had_destination=False, destination_exists=False,
                stage_exists=True, backup_exists=False,
                identities={stage: "0" * 64},
            ),
        )
        invalid_staged = [
            dict(had_destination=True, destination_exists=True, stage_exists=True, backup_exists=True),
            dict(had_destination=True, destination_exists=False, stage_exists=True, backup_exists=False),
            dict(had_destination=False, destination_exists=False, stage_exists=True, backup_exists=True),
            dict(had_destination=False, destination_exists=True, stage_exists=True, backup_exists=False),
        ]
        for layout in invalid_staged:
            with self.subTest(staged=layout):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                    lambda layout=layout: execute(**layout),
                )

        _result, replacements, fsyncs = execute(
            had_destination=True, destination_exists=False,
            stage_exists=True, backup_exists=True,
        )
        self.assertEqual(replacements, [(stage, destination)])
        self.assertEqual(fsyncs, [destination.parent])

        _result, replacements, fsyncs = execute(
            had_destination=True, destination_exists=True,
            stage_exists=True, backup_exists=False,
        )
        self.assertEqual(replacements, [(destination, backup), (stage, destination)])
        self.assertEqual(fsyncs, [destination.parent, destination.parent])

        _result, replacements, fsyncs = execute(
            had_destination=False, destination_exists=False,
            stage_exists=True, backup_exists=False,
        )
        self.assertEqual(replacements, [(stage, destination)])
        self.assertEqual(fsyncs, [destination.parent])

        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
            lambda: execute(
                had_destination=False, destination_exists=False,
                stage_exists=True, backup_exists=False,
                identities={stage: digest, destination: "0" * 64},
            ),
        )

    def test_recovery_none_expected_bindings_committed_and_staging_matrix(self):
        destination = Path("/virtual/report")
        record = {
            "destination": destination, "stage": Path("/virtual/stage"),
            "backup": Path("/virtual/backup"), "had_destination": False,
            "content_sha256": "a" * 64,
        }
        transaction = Path("/virtual/transaction.json")

        with patch.object(binary_report, "_load_publication_transaction", return_value=None):
            self.assertFalse(binary_report._recover_publication_transaction(
                transaction, destinations=[destination], group_token="group",
            ))
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
                lambda: binary_report._recover_publication_transaction(
                    transaction, destinations=[destination], group_token="group",
                    expected_transaction_id="expected",
                ),
            )

        base_payload = {
            "transaction_id": "actual", "binding": {"scope": "one"},
            "state": "staging", "schema": binary_report._LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA,
        }
        with patch.object(
            binary_report, "_load_publication_transaction",
            return_value=(base_payload, [record], "legacy"),
        ):
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
                lambda: binary_report._recover_publication_transaction(
                    transaction, destinations=[destination], group_token="group",
                    expected_transaction_id="different",
                ),
            )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_BINDING_MISMATCH",
                lambda: binary_report._recover_publication_transaction(
                    transaction, destinations=[destination], group_token="group",
                    expected_transaction_id="actual", expected_binding={"scope": "two"},
                ),
            )
            mismatch = self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_BINDING_MISMATCH",
                lambda: binary_report._recover_publication_transaction(
                    transaction,
                    destinations=[destination],
                    group_token="group",
                    expected_binding={"scope": "two"},
                ),
            )
            self.assertEqual(str(mismatch), "")

        empty_binding_payload = {**base_payload, "binding": {}}
        empty_binding_record = {**record, "had_destination": False}
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "transaction.json"
            marker.write_text("marker", encoding="utf-8")
            with patch.object(
                binary_report,
                "_load_publication_transaction",
                return_value=(
                    empty_binding_payload, [empty_binding_record], "legacy",
                ),
            ), patch.object(
                binary_report,
                "_publication_path_exists",
                return_value=False,
            ), patch.object(binary_report, "_fsync_directory"):
                self.assertTrue(
                    binary_report._recover_publication_transaction(
                        marker,
                        destinations=[destination],
                        group_token="group",
                        expected_transaction_id="actual",
                        expected_binding={},
                    )
                )
            self.assertFalse(marker.exists())

        committed = {**base_payload, "state": "committed"}
        with patch.object(
            binary_report, "_load_publication_transaction",
            return_value=(committed, [record], "legacy"),
        ), patch.object(
            binary_report, "_publication_path_exists", return_value=False,
        ):
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                lambda: binary_report._recover_publication_transaction(
                    transaction, destinations=[destination], group_token="group",
                ),
            )
        with patch.object(
            binary_report, "_load_publication_transaction",
            return_value=(committed, [record], "legacy"),
        ), patch.object(
            binary_report, "_publication_path_exists", return_value=True,
        ), patch.object(binary_report, "_verify_published_transaction_content") as verify, patch.object(
            binary_report, "_finish_committed_publication", return_value=True,
        ) as finish:
            self.assertTrue(binary_report._recover_publication_transaction(
                transaction, destinations=[destination], group_token="group",
                expected_transaction_id="actual", expected_binding={"scope": "one"},
            ))
        verify.assert_called_once_with(committed, [record])
        finish.assert_called_once_with(
            transaction, committed, [record], suppress_errors=False,
        )

        staging_layouts = [
            ({record["backup"]: True, destination: False, record["stage"]: False}, True),
            ({record["backup"]: False, destination: True, record["stage"]: False}, True),
            ({record["backup"]: False, destination: False, record["stage"]: False}, False),
        ]
        for exists, invalid in staging_layouts:
            with self.subTest(staging=exists):
                with tempfile.TemporaryDirectory() as directory:
                    marker = Path(directory) / "transaction.json"
                    marker.write_text("marker", encoding="utf-8")
                    removed = []
                    with patch.object(
                        binary_report, "_load_publication_transaction",
                        return_value=(base_payload, [record], "legacy"),
                    ), patch.object(
                        binary_report, "_publication_path_exists",
                        side_effect=lambda path, exists=exists: exists.get(Path(path), False),
                    ), patch.object(
                        binary_report, "_remove_publication_path",
                        side_effect=lambda path: removed.append(Path(path)),
                    ), patch.object(binary_report, "_fsync_directory"):
                        if invalid:
                            self.assert_reason(
                                "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
                                lambda: binary_report._recover_publication_transaction(
                                    marker, destinations=[destination], group_token="group",
                                ),
                            )
                            self.assertTrue(marker.exists())
                        else:
                            self.assertTrue(binary_report._recover_publication_transaction(
                                marker, destinations=[destination], group_token="group",
                            ))
                            self.assertFalse(marker.exists())
                            self.assertEqual(removed, [])

    def test_recovery_rollback_layout_matrix_and_oserror_classification(self):
        destination = Path("/virtual/report")
        stage = Path("/virtual/stage")
        backup = Path("/virtual/backup")
        transaction_payload = {
            "transaction_id": "tx", "binding": {}, "state": "prepared",
            "schema": binary_report._LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA,
        }

        def recover_layout(*, had_destination, destination_exists, stage_exists, backup_exists, fail_replace=False):
            record = {
                "destination": destination, "stage": stage, "backup": backup,
                "had_destination": had_destination, "content_sha256": "a" * 64,
            }
            exists = {destination: destination_exists, stage: stage_exists, backup: backup_exists}
            removed = []
            replacements = []
            fsyncs = []
            with tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "transaction.json"
                marker.write_text("marker", encoding="utf-8")

                def replace(source, target):
                    if fail_replace:
                        raise OSError("replace failed")
                    replacements.append((Path(source), Path(target)))

                with patch.object(
                    binary_report, "_load_publication_transaction",
                    return_value=(transaction_payload, [record], "legacy"),
                ), patch.object(
                    binary_report, "_publication_path_exists",
                    side_effect=lambda path: exists[Path(path)],
                ), patch.object(
                    binary_report, "_remove_publication_path",
                    side_effect=lambda path: removed.append(Path(path)),
                ), patch.object(
                    binary_report, "_fsync_directory",
                    side_effect=lambda path: fsyncs.append(Path(path)),
                ), patch.object(binary_report, "os", _OsProxy(replace=replace)):
                    result = binary_report._recover_publication_transaction(
                        marker, destinations=[destination], group_token="group",
                    )
            return result, removed, replacements, fsyncs

        result, removed, replacements, _fsyncs = recover_layout(
            had_destination=True, destination_exists=True,
            stage_exists=True, backup_exists=True,
        )
        self.assertTrue(result)
        self.assertEqual(removed, [destination, stage])
        self.assertEqual(replacements, [(backup, destination)])

        result, removed, replacements, _fsyncs = recover_layout(
            had_destination=True, destination_exists=False,
            stage_exists=False, backup_exists=True,
        )
        self.assertTrue(result)
        self.assertEqual(removed, [])
        self.assertEqual(replacements, [(backup, destination)])

        result, removed, replacements, _fsyncs = recover_layout(
            had_destination=True, destination_exists=True,
            stage_exists=False, backup_exists=False,
        )
        self.assertTrue(result)
        self.assertEqual(removed, [])
        self.assertEqual(replacements, [])

        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            lambda: recover_layout(
                had_destination=True, destination_exists=False,
                stage_exists=False, backup_exists=False,
            ),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            lambda: recover_layout(
                had_destination=False, destination_exists=False,
                stage_exists=False, backup_exists=True,
            ),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
            lambda: recover_layout(
                had_destination=False, destination_exists=True,
                stage_exists=True, backup_exists=False,
            ),
        )

        result, removed, replacements, _fsyncs = recover_layout(
            had_destination=False, destination_exists=True,
            stage_exists=False, backup_exists=False,
        )
        self.assertTrue(result)
        self.assertEqual(removed, [destination])
        self.assertEqual(replacements, [])
        result, removed, replacements, _fsyncs = recover_layout(
            had_destination=False, destination_exists=False,
            stage_exists=True, backup_exists=False,
        )
        self.assertTrue(result)
        self.assertEqual(removed, [stage])
        self.assertEqual(replacements, [])

        result, removed, replacements, _fsyncs = recover_layout(
            had_destination=False, destination_exists=False,
            stage_exists=False, backup_exists=False,
        )
        self.assertTrue(result)
        self.assertEqual(removed, [])
        self.assertEqual(replacements, [])

        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_ROLLBACK_FAILED",
            lambda: recover_layout(
                had_destination=True, destination_exists=False,
                stage_exists=False, backup_exists=True, fail_replace=True,
            ),
        )

    def test_finish_committed_cleanup_current_legacy_and_suppression(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            transaction = root / ".jua-br-group.transaction.json"
            transaction.write_text("marker", encoding="utf-8")
            record = {
                "destination": root / "destination", "stage": root / "stage",
                "backup": root / "backup", "had_destination": True,
                "content_sha256": "a" * 64,
            }
            current = {
                "schema": binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA,
                "transaction_id": "1" * 32, "binding": {}, "gate_receipt": {},
                "published_content_identity": "a" * 64,
            }
            removed = []
            with patch.object(binary_report, "_atomic_json") as atomic, patch.object(
                binary_report, "_publication_path_exists", return_value=True,
            ), patch.object(
                binary_report, "_remove_publication_path",
                side_effect=lambda path: removed.append(Path(path)),
            ), patch.object(binary_report, "_fsync_directory") as fsync:
                self.assertTrue(binary_report._finish_committed_publication(
                    transaction, current, [record], suppress_errors=False,
                ))
            self.assertEqual(removed, [record["backup"], record["stage"]])
            atomic.assert_called_once()
            self.assertFalse(transaction.exists())
            self.assertGreaterEqual(fsync.call_count, 2)

            transaction.write_text("marker", encoding="utf-8")
            legacy = {**current, "schema": binary_report._LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA}
            with patch.object(binary_report, "_atomic_json") as atomic, patch.object(
                binary_report, "_publication_path_exists", return_value=False,
            ), patch.object(binary_report, "_fsync_directory"):
                self.assertTrue(binary_report._finish_committed_publication(
                    transaction, legacy, [record], suppress_errors=False,
                ))
            atomic.assert_not_called()

            transaction.write_text("marker", encoding="utf-8")
            with patch.object(binary_report, "_atomic_json"), patch.object(
                binary_report, "_publication_path_exists", return_value=True,
            ), patch.object(
                binary_report, "_remove_publication_path", side_effect=OSError("cleanup"),
            ):
                self.assertFalse(binary_report._finish_committed_publication(
                    transaction, current, [record], suppress_errors=True,
                ))
                with self.assertRaisesRegex(OSError, "cleanup"):
                    binary_report._finish_committed_publication(
                        transaction, current, [record], suppress_errors=False,
                    )

    def _transaction_action(self, destinations, action, *, loaded, **kwargs):
        with patch.object(
            binary_report, "_normalize_publication_destination",
            side_effect=lambda value: Path(value),
        ), patch.object(
            binary_report, "exclusive_file_lock",
            side_effect=lambda *_args, **_kwargs: nullcontext(),
        ), patch.object(
            binary_report, "_load_publication_transaction", return_value=loaded,
        ):
            return binary_report._publication_transaction_action(
                destinations, action, **kwargs,
            )

    def test_transaction_action_target_lock_cas_state_and_metadata_matrix(self):
        destination = Path("/virtual/report")
        transaction_id = "1" * 32
        binding = {"report_implementation_identity": "a" * 64}
        payload = {
            "schema": binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA,
            "transaction_id": transaction_id, "state": "pending_gate",
            "binding": binding, "gate_receipt": None,
            "published_content_identity": "b" * 64,
        }
        loaded = (payload, [], "current")

        for destinations in [[], [destination, destination]]:
            with self.subTest(destinations=destinations):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_TARGET_DUPLICATE",
                    lambda destinations=destinations: self._transaction_action(
                        destinations, "state", loaded=None,
                    ),
                )

        with patch.object(
            binary_report, "_normalize_publication_destination",
            side_effect=lambda value: Path(value),
        ), patch.object(
            binary_report, "exclusive_file_lock", side_effect=TimeoutError("busy"),
        ):
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_LOCK_TIMEOUT",
                lambda: binary_report._publication_transaction_action([destination], "state"),
            )

        for invalid_id in [1, "1" * 31, "z" * 32]:
            with self.subTest(transaction_id=invalid_id):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_INVALID",
                    lambda invalid_id=invalid_id: self._transaction_action(
                        [destination], "state", loaded=loaded,
                        expected_transaction_id=invalid_id,
                    ),
                )

        for action in [
            "rollback", "gate_candidate", "gate_passed", "publish",
            "commit", "finalize_irreversible", "recover",
        ]:
            with self.subTest(action=action):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_CAS_REQUIRED",
                    lambda action=action: self._transaction_action(
                        [destination], action, loaded=loaded,
                    ),
                )

        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_CAS_REQUIRED",
            lambda: self._transaction_action(
                [destination], "rollback", loaded=loaded,
                expected_transaction_id=transaction_id,
            ),
        )

        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_BINDING_INVALID",
            lambda: self._transaction_action(
                [destination], "state", loaded=loaded,
                expected_transaction_id=transaction_id, expected_binding=[],
            ),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_CAS_REQUIRED",
            lambda: self._transaction_action(
                [destination], "state", loaded=loaded, expected_binding=binding,
            ),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
            lambda: self._transaction_action(
                [destination], "state", loaded=None,
                expected_transaction_id=transaction_id,
            ),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
            lambda: self._transaction_action(
                [destination], "state", loaded=loaded,
                expected_transaction_id="2" * 32,
            ),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_TRANSACTION_BINDING_MISMATCH",
            lambda: self._transaction_action(
                [destination], "state", loaded=loaded,
                expected_transaction_id=transaction_id,
                expected_binding={"report_implementation_identity": "0" * 64},
            ),
        )

        self.assertEqual(
            self._transaction_action(
                [destination], "state", loaded=loaded,
                expected_transaction_id=transaction_id,
            ),
            "pending_gate",
        )
        empty_binding_payload = {**payload, "binding": {}}
        self.assertEqual(
            self._transaction_action(
                [destination], "state",
                loaded=(empty_binding_payload, [], "legacy"),
                expected_transaction_id=transaction_id,
                expected_binding={},
            ),
            "pending_gate",
        )

        self.assertEqual(self._transaction_action(
            [destination], "state", loaded=None,
        ), "absent")
        self.assertEqual(self._transaction_action(
            [destination], "state", loaded=loaded,
            expected_transaction_id=transaction_id, expected_binding=binding,
        ), "pending_gate")
        self.assertEqual(self._transaction_action(
            [destination], "recovery_metadata", loaded=None,
        ), {
            "transaction_id": "", "state": "absent",
            "implementation_status": "absent", "binding": {}, "gate_receipt": None,
        })
        metadata = self._transaction_action(
            [destination], "recovery_metadata", loaded=loaded,
        )
        self.assertEqual(metadata["implementation_status"], "current")
        self.assertIsNone(metadata["gate_receipt"])
        receipt_payload = {**payload, "gate_receipt": {"gate": "passed"}}
        metadata = self._transaction_action(
            [destination], "recovery_metadata",
            loaded=(receipt_payload, [], "mismatch"),
        )
        self.assertEqual(metadata["gate_receipt"], {"gate": "passed"})
        self.assertEqual(metadata["implementation_status"], "mismatch")

    def test_transaction_action_receipt_rollback_and_transition_matrix(self):
        destination = Path("/virtual/report")
        transaction_id = "1" * 32
        binding = {"report_implementation_identity": "a" * 64}
        record = {
            "destination": destination, "stage": Path("/virtual/stage"),
            "backup": Path("/virtual/backup"), "had_destination": False,
            "content_sha256": "c" * 64,
        }

        def payload(state, gate_receipt=None):
            return {
                "schema": binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA,
                "transaction_id": transaction_id, "state": state,
                "binding": binding, "gate_receipt": gate_receipt,
                "published_content_identity": "b" * 64,
            }

        cas = {"expected_transaction_id": transaction_id, "expected_binding": binding}
        self.assertEqual(self._transaction_action(
            [destination], "receipt", loaded=None,
        ), {})
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_STATE_INVALID",
            lambda: self._transaction_action(
                [destination], "receipt", loaded=(payload("staging"), [record], "current"),
            ),
        )
        for state in ["prepared", "pending_gate", "gate_passed", "published", "committed"]:
            gate = {"gate": state} if state in {"gate_passed", "published", "committed"} else None
            current_payload = payload(state, gate)
            with self.subTest(receipt_state=state), patch.object(
                binary_report, "_verify_published_transaction_content",
            ) as verify:
                receipt = self._transaction_action(
                    [destination], "receipt",
                    loaded=(current_payload, [record], "current"),
                )
            verify.assert_called_once_with(current_payload, [record])
            self.assertEqual(receipt["state"], state)
            self.assertEqual(receipt["gate_receipt"], gate)
            self.assertEqual(
                receipt["candidate_destinations"],
                [str(record["stage"])] if state in {"prepared", "pending_gate", "gate_passed"} else [],
            )

        self.assertFalse(self._transaction_action(
            [destination], "unknown", loaded=None,
        ))
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_ALREADY_COMMITTED",
            lambda: self._transaction_action(
                [destination], "rollback",
                loaded=(payload("committed"), [record], "current"), **cas,
            ),
        )
        with patch.object(
            binary_report, "_recover_publication_transaction", return_value=True,
        ) as recover:
            self.assertTrue(self._transaction_action(
                [destination], "rollback",
                loaded=(payload("prepared"), [record], "current"), **cas,
            ))
        self.assertEqual(recover.call_args.kwargs["expected_transaction_id"], transaction_id)

        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_STATE_INVALID",
            lambda: self._transaction_action(
                [destination], "gate_passed",
                loaded=(payload("prepared"), [record], "current"), **cas,
                gate_name="gate", strict_risk_gate=True,
            ),
        )
        pending = payload("pending_gate")
        gate_receipt = {"gate_receipt_identity": "d" * 64}
        with patch.object(
            binary_report, "_verify_published_transaction_content",
        ) as verify, patch.object(
            binary_report, "_new_report_gate_receipt", return_value=gate_receipt,
        ) as create, patch.object(binary_report, "_atomic_json") as atomic:
            result = self._transaction_action(
                [destination], "gate_passed",
                loaded=(pending, [record], "current"), **cas,
                gate_name="gate", strict_risk_gate=True,
            )
        self.assertEqual(result, gate_receipt)
        self.assertEqual(pending["state"], "gate_passed")
        verify.assert_called_once()
        create.assert_called_once()
        atomic.assert_called_once()

        pending_without_gate_name = payload("pending_gate")
        with patch.object(
            binary_report, "_verify_published_transaction_content",
        ), patch.object(
            binary_report,
            "_new_report_gate_receipt",
            return_value=gate_receipt,
        ) as create, patch.object(binary_report, "_atomic_json"):
            self.assertEqual(
                self._transaction_action(
                    [destination], "gate_passed",
                    loaded=(pending_without_gate_name, [record], "current"),
                    **cas, gate_name=None, strict_risk_gate=False,
                ),
                gate_receipt,
            )
        self.assertEqual(create.call_args.kwargs["gate_name"], "")

        for invalid_state in ["pending_gate", "prepared"]:
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_STATE_INVALID",
                lambda invalid_state=invalid_state: self._transaction_action(
                    [destination], "publish",
                    loaded=(payload(invalid_state), [record], "current"), **cas,
                ),
            )
        gate_passed = payload("gate_passed", {"gate": "ok"})
        with patch.object(binary_report, "_publish_transaction_record") as publish, patch.object(
            binary_report, "_verify_published_transaction_content",
        ) as verify, patch.object(binary_report, "_atomic_json") as atomic:
            self.assertTrue(self._transaction_action(
                [destination], "publish",
                loaded=(gate_passed, [record], "current"), **cas,
            ))
        publish.assert_called_once_with(record)
        self.assertEqual(gate_passed["state"], "published")
        atomic.assert_called_once()
        verify.assert_called_once()

        gate_passed = payload("gate_passed", {"gate": "ok"})
        with patch.object(
            binary_report, "_publish_transaction_record", side_effect=OSError("rename"),
        ):
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_PUBLISH_FAILED",
                lambda: self._transaction_action(
                    [destination], "publish",
                    loaded=(gate_passed, [record], "current"), **cas,
                ),
            )
        published = payload("published", {"gate": "ok"})
        with patch.object(binary_report, "_publish_transaction_record") as publish, patch.object(
            binary_report, "_verify_published_transaction_content",
        ):
            self.assertTrue(self._transaction_action(
                [destination], "publish",
                loaded=(published, [record], "current"), **cas,
            ))
        publish.assert_not_called()

        for action in ["commit", "finalize_irreversible"]:
            with self.subTest(action=action):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_STATE_INVALID",
                    lambda action=action: self._transaction_action(
                        [destination], action,
                        loaded=(payload("gate_passed"), [record], "current"), **cas,
                    ),
                )
            for state in ["published", "committed"]:
                current_payload = payload(state, {"gate": "ok"})
                with self.subTest(action=action, state=state), patch.object(
                    binary_report, "_verify_published_transaction_content",
                ), patch.object(binary_report, "_atomic_json") as atomic, patch.object(
                    binary_report, "_finish_committed_publication", return_value=True,
                ) as finish:
                    self.assertTrue(self._transaction_action(
                        [destination], action,
                        loaded=(current_payload, [record], "current"), **cas,
                    ))
                self.assertEqual(current_payload["state"], "committed")
                self.assertEqual(atomic.call_count, 1 if state == "published" else 0)
                finish.assert_called_once()

        with patch.object(
            binary_report, "_recover_publication_transaction", return_value=True,
        ) as recover:
            self.assertTrue(self._transaction_action(
                [destination], "recover",
                loaded=(payload("prepared"), [record], "current"), **cas,
            ))
        recover.assert_called_once()
        with self.assertRaisesRegex(ValueError, "unknown publication transaction action"):
            self._transaction_action(
                [destination], "unknown", loaded=(payload("prepared"), [record], "current"),
            )

    def test_publication_mapping_wrappers_preserve_mapping_and_reject_other_results(self):
        destinations = [Path("/virtual/report")]
        transaction_id = "1" * 32
        binding = {"report_implementation_identity": "a" * 64}

        for value, expected in [({"value": 1}, {"value": 1}), (False, {})]:
            with self.subTest(wrapper="receipt", value=value), patch.object(
                binary_report,
                "_publication_transaction_action",
                return_value=value,
            ) as action:
                self.assertEqual(
                    binary_report.report_publication_transaction_receipt(
                        destinations,
                        expected_transaction_id=transaction_id,
                        expected_binding=binding,
                    ),
                    expected,
                )
            self.assertEqual(action.call_args.args, (destinations, "receipt"))

            with self.subTest(wrapper="recovery_metadata", value=value), patch.object(
                binary_report,
                "_publication_transaction_action",
                return_value=value,
            ) as action:
                self.assertEqual(
                    binary_report.report_publication_transaction_recovery_metadata(
                        destinations,
                    ),
                    expected,
                )
            self.assertEqual(
                action.call_args.args, (destinations, "recovery_metadata"),
            )

            with self.subTest(wrapper="gate_candidate", value=value), patch.object(
                binary_report,
                "_publication_transaction_action",
                return_value=value,
            ) as action:
                self.assertEqual(
                    binary_report.materialize_report_publication_gate_candidate(
                        destinations,
                        "/virtual/snapshot",
                        expected_transaction_id=transaction_id,
                        expected_binding=binding,
                        expected_published_content_identity="b" * 64,
                    ),
                    expected,
                )
            self.assertEqual(action.call_args.args, (destinations, "gate_candidate"))

            with self.subTest(wrapper="gate_passed", value=value), patch.object(
                binary_report,
                "_publication_transaction_action",
                return_value=value,
            ) as action:
                self.assertEqual(
                    binary_report.mark_report_publication_gate_passed(
                        destinations,
                        expected_transaction_id=transaction_id,
                        expected_binding=binding,
                        gate_name="gate",
                        strict_risk_gate=True,
                    ),
                    expected,
                )
            self.assertEqual(action.call_args.args, (destinations, "gate_passed"))

    def test_gate_candidate_snapshot_contract_and_copy_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            destination = root / "report"
            transaction_id = "1" * 32
            binding = {"report_implementation_identity": "a" * 64}
            digest = "c" * 64
            record = {
                "destination": destination, "stage": root / "stage",
                "backup": root / "backup", "had_destination": False,
                "content_sha256": digest,
            }

            def payload(state="pending_gate"):
                return {
                    "schema": binary_report._REPORT_PUBLICATION_TRANSACTION_SCHEMA,
                    "transaction_id": transaction_id, "state": state,
                    "binding": binding, "gate_receipt": None,
                    "published_content_identity": "b" * 64,
                }

            loaded = (payload(), [record], "current")
            base = {
                "expected_transaction_id": transaction_id,
                "expected_binding": binding,
                "expected_published_content_identity": "b" * 64,
            }
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_STATE_INVALID",
                lambda: self._transaction_action(
                    [destination], "gate_candidate",
                    loaded=(payload("prepared"), [record], "current"),
                    candidate_snapshot_root=root / "snapshot", **base,
                ),
            )
            for identity in [None, "bad", "0" * 64]:
                with self.subTest(identity=identity):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                        lambda identity=identity: self._transaction_action(
                            [destination], "gate_candidate", loaded=loaded,
                            candidate_snapshot_root=root / "snapshot",
                            **{**base, "expected_published_content_identity": identity},
                        ),
                    )
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_GATE_SNAPSHOT_INVALID",
                lambda: self._transaction_action(
                    [destination], "gate_candidate", loaded=loaded,
                    candidate_snapshot_root=None, **base,
                ),
            )

            invalid_roots = []
            missing = root / "missing"
            invalid_roots.append(missing)
            file_root = root / "file"
            file_root.write_text("x", encoding="utf-8")
            invalid_roots.append(file_root)
            nonempty = root / "nonempty"
            nonempty.mkdir()
            (nonempty / "entry").write_text("x", encoding="utf-8")
            invalid_roots.append(nonempty)
            link = root / "link"
            link.symlink_to(nonempty, target_is_directory=True)
            invalid_roots.append(link)
            holder = root / "holder"
            holder.mkdir()
            normalized_snapshot = root / "normalized-snapshot"
            normalized_snapshot.mkdir()
            invalid_roots.append(holder / ".." / "normalized-snapshot")
            for snapshot_root in invalid_roots:
                with self.subTest(snapshot_root=snapshot_root):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_GATE_SNAPSHOT_INVALID",
                        lambda snapshot_root=snapshot_root: self._transaction_action(
                            [destination], "gate_candidate", loaded=loaded,
                            candidate_snapshot_root=snapshot_root, **base,
                        ),
                    )

            snapshot = root / "snapshot-copy-error"
            snapshot.mkdir()
            with patch.object(
                binary_report, "_verify_published_transaction_content",
            ), patch.object(
                binary_report, "_copy_report_directory_secure", side_effect=OSError("copy"),
            ):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_GATE_SNAPSHOT_INVALID",
                    lambda: self._transaction_action(
                        [destination], "gate_candidate", loaded=loaded,
                        candidate_snapshot_root=snapshot, **base,
                    ),
                )

            snapshot = root / "snapshot-digest-error"
            snapshot.mkdir()

            def materialize(_source, target):
                Path(target).mkdir()

            with patch.object(
                binary_report, "_verify_published_transaction_content",
            ), patch.object(
                binary_report, "_copy_report_directory_secure", side_effect=materialize,
            ), patch.object(
                binary_report, "_directory_content_identity", return_value="0" * 64,
            ):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                    lambda: self._transaction_action(
                        [destination], "gate_candidate", loaded=loaded,
                        candidate_snapshot_root=snapshot, **base,
                    ),
                )

            snapshot = root / "snapshot-success"
            snapshot.mkdir()
            with patch.object(
                binary_report, "_verify_published_transaction_content",
            ) as verify, patch.object(
                binary_report, "_copy_report_directory_secure", side_effect=materialize,
            ), patch.object(
                binary_report, "_directory_content_identity", return_value=digest,
            ):
                result = self._transaction_action(
                    [destination], "gate_candidate", loaded=loaded,
                    candidate_snapshot_root=snapshot, **base,
                )
            self.assertEqual(result, {
                "transaction_id": transaction_id,
                "binding": binding,
                "published_content_identity": "b" * 64,
                "candidate_destinations": [str(snapshot / "0")],
            })
            self.assertEqual(verify.call_count, 2)

    def test_committed_receipt_public_reader_cas_absence_lock_and_success_matrix(self):
        destination = Path("/virtual/report")
        transaction_id = "1" * 32
        binding = {"report_implementation_identity": "a" * 64}
        receipt = {
            "transaction_id": transaction_id, "binding": binding,
            "published_content_identity": "b" * 64,
        }

        def read(*, destinations=None, raw=receipt, validated=receipt, **kwargs):
            destinations = [destination] if destinations is None else destinations
            with patch.object(
                binary_report, "_normalize_publication_destination",
                side_effect=lambda value: Path(value),
            ), patch.object(
                binary_report, "exclusive_file_lock",
                side_effect=lambda *_args, **_kwargs: nullcontext(),
            ), patch.object(
                binary_report, "_read_private_publication_json", return_value=raw,
            ), patch.object(
                binary_report, "_validate_committed_publication_receipt",
                return_value=(validated, "current"),
            ) as validate:
                result = binary_report.report_publication_committed_receipt(
                    destinations, **kwargs,
                )
            return result, validate

        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_CAS_REQUIRED",
            lambda: binary_report.report_publication_committed_receipt(
                [destination], expected_binding=binding,
            ),
        )
        for destinations in [[], [destination, destination]]:
            with self.subTest(destinations=destinations):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_TARGET_DUPLICATE",
                    lambda destinations=destinations: read(destinations=destinations),
                )
        with patch.object(
            binary_report, "_normalize_publication_destination",
            side_effect=lambda value: Path(value),
        ), patch.object(
            binary_report, "exclusive_file_lock", side_effect=TimeoutError("busy"),
        ):
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_LOCK_TIMEOUT",
                lambda: binary_report.report_publication_committed_receipt([destination]),
            )

        result, validate = read(raw=None)
        self.assertEqual(result, {})
        validate.assert_not_called()
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
            lambda: read(raw=None, expected_transaction_id=transaction_id),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
            lambda: read(expected_transaction_id="2" * 32),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_TRANSACTION_BINDING_MISMATCH",
            lambda: read(
                expected_transaction_id=transaction_id,
                expected_binding={"report_implementation_identity": "0" * 64},
            ),
        )
        empty_binding_receipt = {**receipt, "binding": {}}
        result, _validate = read(
            validated=empty_binding_receipt,
            expected_transaction_id=transaction_id,
            expected_binding={},
        )
        self.assertEqual(
            result, {**empty_binding_receipt, "state": "committed"},
        )
        result, validate = read(
            expected_transaction_id=transaction_id,
            expected_binding=binding,
            verify_content=0,
        )
        self.assertEqual(result, {**receipt, "state": "committed"})
        self.assertFalse(validate.call_args.kwargs["verify_content"])
        result, validate = read(verify_content="yes")
        self.assertTrue(validate.call_args.kwargs["verify_content"])

    def test_committed_snapshot_reader_validation_copy_recheck_and_cleanup_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            destinations = [root / "one", root / "two"]
            transaction_id = "1" * 32
            binding = {"report_implementation_identity": "a" * 64}
            digests = ["a" * 64, "b" * 64]
            raw = {"raw": "receipt"}
            receipt = {
                "transaction_id": transaction_id, "binding": binding,
                "published_content_identity": "c" * 64,
                "destinations": [
                    {"destination": str(destination), "content_sha256": digest}
                    for destination, digest in zip(destinations, digests)
                ],
            }

            def invoke(snapshot_root, *, raw_values=None, validated=receipt, copy=None, identities=None, exists=None, remove=None, **kwargs):
                raw_values = [raw, raw] if raw_values is None else raw_values
                copy = copy or (lambda _source, target: Path(target).mkdir())
                identities = iter(identities or [*digests, *digests])
                exists = exists or (lambda path: Path(path).exists())
                remove = remove or binary_report._remove_publication_path
                with patch.object(
                    binary_report, "_normalize_publication_destination",
                    side_effect=lambda value: Path(value),
                ), patch.object(
                    binary_report, "exclusive_file_lock",
                    side_effect=lambda *_args, **_kwargs: nullcontext(),
                ), patch.object(
                    binary_report, "_read_private_publication_json",
                    side_effect=raw_values,
                ), patch.object(
                    binary_report, "_validate_committed_publication_receipt",
                    return_value=(validated, "current"),
                ), patch.object(
                    binary_report, "_copy_report_directory_secure", side_effect=copy,
                ), patch.object(
                    binary_report, "_directory_content_identity",
                    side_effect=lambda _path: next(identities),
                ), patch.object(
                    binary_report, "_publication_path_exists", side_effect=exists,
                ), patch.object(
                    binary_report, "_remove_publication_path", side_effect=remove,
                ):
                    return binary_report.materialize_report_publication_committed_snapshot(
                        destinations, snapshot_root, **kwargs,
                    )

            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CAS_REQUIRED",
                lambda: binary_report.materialize_report_publication_committed_snapshot(
                    destinations, root / "unused", expected_binding=binding,
                ),
            )
            for bad_destinations in [[], [destinations[0], destinations[0]]]:
                with self.subTest(destinations=bad_destinations), patch.object(
                    binary_report, "_normalize_publication_destination",
                    side_effect=lambda value: Path(value),
                ):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_TARGET_DUPLICATE",
                        lambda bad_destinations=bad_destinations: binary_report.materialize_report_publication_committed_snapshot(
                            bad_destinations, root / "unused",
                        ),
                    )

            invalid_roots = [root / "missing"]
            file_root = root / "file"
            file_root.write_text("x", encoding="utf-8")
            invalid_roots.append(file_root)
            nonempty = root / "nonempty"
            nonempty.mkdir()
            (nonempty / "entry").write_text("x", encoding="utf-8")
            invalid_roots.append(nonempty)
            link = root / "link"
            link.symlink_to(nonempty, target_is_directory=True)
            invalid_roots.append(link)
            holder = root / "snapshot-holder"
            holder.mkdir()
            normalized_snapshot = root / "normalized-reader-snapshot"
            normalized_snapshot.mkdir()
            invalid_roots.append(
                holder / ".." / "normalized-reader-snapshot"
            )
            for snapshot_root in invalid_roots:
                with self.subTest(snapshot_root=snapshot_root), patch.object(
                    binary_report, "_normalize_publication_destination",
                    side_effect=lambda value: Path(value),
                ):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_READER_SNAPSHOT_INVALID",
                        lambda snapshot_root=snapshot_root: binary_report.materialize_report_publication_committed_snapshot(
                            destinations, snapshot_root,
                        ),
                    )

            snapshot = root / "lock-timeout"
            snapshot.mkdir()
            with patch.object(
                binary_report, "_normalize_publication_destination",
                side_effect=lambda value: Path(value),
            ), patch.object(
                binary_report, "exclusive_file_lock", side_effect=TimeoutError("busy"),
            ):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_LOCK_TIMEOUT",
                    lambda: binary_report.materialize_report_publication_committed_snapshot(
                        destinations, snapshot,
                    ),
                )

            snapshot = root / "missing-receipt"
            snapshot.mkdir()
            with patch.object(
                binary_report, "_normalize_publication_destination",
                side_effect=lambda value: Path(value),
            ), patch.object(
                binary_report, "exclusive_file_lock",
                side_effect=lambda *_args, **_kwargs: nullcontext(),
            ), patch.object(
                binary_report, "_read_private_publication_json", return_value=None,
            ):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_COMMITTED_RECEIPT_MISSING",
                    lambda: binary_report.materialize_report_publication_committed_snapshot(
                        destinations, snapshot,
                    ),
                )

            snapshot = root / "id-mismatch"
            snapshot.mkdir()
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_ID_MISMATCH",
                lambda: invoke(
                    snapshot, raw_values=[raw],
                    expected_transaction_id="2" * 32,
                ),
            )
            snapshot = root / "binding-mismatch"
            snapshot.mkdir()
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TRANSACTION_BINDING_MISMATCH",
                lambda: invoke(
                    snapshot, raw_values=[raw],
                    expected_transaction_id=transaction_id,
                    expected_binding={"report_implementation_identity": "0" * 64},
                ),
            )

            snapshot = root / "empty-binding"
            snapshot.mkdir()
            empty_binding_receipt = {**receipt, "binding": {}}
            result = invoke(
                snapshot,
                validated=empty_binding_receipt,
                expected_transaction_id=transaction_id,
                expected_binding={},
            )
            self.assertEqual(result["binding"], {})

            snapshot = root / "first-copy-failure"
            snapshot.mkdir()
            removed = []
            with self.assertRaisesRegex(OSError, "first copy failed"):
                invoke(
                    snapshot,
                    raw_values=[raw],
                    copy=lambda _source, _target: (_ for _ in ()).throw(
                        OSError("first copy failed")
                    ),
                    exists=lambda _path: False,
                    remove=lambda path: removed.append(Path(path)),
                )
            self.assertEqual(removed, [])

            removed = []

            def fail_second_copy(_source, target):
                target = Path(target)
                target.mkdir()
                if target.name == "1":
                    raise OSError("copy failed")

            snapshot = root / "copy-failure"
            snapshot.mkdir()
            with self.assertRaisesRegex(OSError, "copy failed"):
                invoke(
                    snapshot, raw_values=[raw], copy=fail_second_copy,
                    identities=digests[:1],
                    remove=lambda path: removed.append(Path(path)),
                )
            self.assertEqual(removed, [snapshot / "0", snapshot / "1"])

            snapshot = root / "snapshot-digest-mismatch"
            snapshot.mkdir()
            removed = []
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                lambda: invoke(
                    snapshot, raw_values=[raw], identities=["0" * 64],
                    remove=lambda path: removed.append(Path(path)),
                ),
            )
            self.assertEqual(removed, [snapshot / "0"])

            snapshot = root / "destination-digest-mismatch"
            snapshot.mkdir()
            removed = []
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
                lambda: invoke(
                    snapshot, raw_values=[raw],
                    identities=[*digests, "0" * 64],
                    remove=lambda path: removed.append(Path(path)),
                ),
            )
            self.assertEqual(removed, [snapshot / "0", snapshot / "1"])

            snapshot = root / "receipt-changed"
            snapshot.mkdir()
            removed = []
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_READER_SNAPSHOT_INVALID",
                lambda: invoke(
                    snapshot, raw_values=[raw, {"changed": True}],
                    remove=lambda path: removed.append(Path(path)),
                ),
            )
            self.assertEqual(removed, [snapshot / "0", snapshot / "1"])

            snapshot = root / "success"
            snapshot.mkdir()
            result = invoke(
                snapshot,
                expected_transaction_id=transaction_id,
                expected_binding=binding,
            )
            self.assertEqual(result["state"], "committed")
            self.assertEqual(result["snapshot_destinations"], [
                str(snapshot / "0"), str(snapshot / "1"),
            ])


class BinaryReportStep6SemanticBoundaryTest(unittest.TestCase):
    LIST_FIELDS = (
        "dependency_changes", "changed_api_inventory", "probable_impact",
        "uncertain", "not_impacted", "not_analyzed", "not_found",
        "diagnostics",
    )
    COUNT_FIELDS = (
        "available_dependency_count", "included_dependency_count",
        "total_api_count", "analyzed_api_count", "included_api_count",
        "excluded_api_count",
    )

    def assert_reason(self, expected: str, action) -> binary_report.BinaryReportError:
        with self.assertRaises(binary_report.BinaryReportError) as captured:
            action()
        self.assertEqual(captured.exception.reason_code, expected)
        return captured.exception

    @staticmethod
    def _dimensions(*, reachable=0, uncertain=0, not_found=0, not_analyzed=0, probable=0, inconclusive=0):
        return {
            "reachability_status": {
                "reachable": reachable,
                "uncertain": uncertain,
                "not_found_in_static_analysis": not_found,
                "not_analyzed": not_analyzed,
            },
            "impact_conclusion": {
                "probable_impact": probable,
                "inconclusive": inconclusive,
            },
            "runtime_verification_status": "not_executed",
        }

    def _findings(self) -> dict:
        findings = {field: [] for field in self.LIST_FIELDS}
        findings.update({
            "analysis_scope": {
                "available_dependency_count": 0,
                "included_dependency_count": 0,
                "total_api_count": 0,
                "analyzed_api_count": 0,
                "included_api_count": 0,
                "excluded_api_count": 0,
                "included_reported_api_identities": [],
                "included_dependency_coords": [],
                "excluded_dependency_coords": [],
            },
            "binary_dimensions": self._dimensions(),
            "generation_binary_dimensions": self._dimensions(),
            "resource_impacts": [],
            "report_population": {
                "schema": "java-upgrade-analyzer.step6-report-population.v1",
                "apis": {
                    "total_count": 0, "completed_count": 0,
                    "incomplete_count": 0, "population_unconfirmed": False,
                },
                "dependencies": {
                    "total_count": 0, "completed_count": 0,
                    "incomplete_count": 0, "population_unconfirmed": False,
                },
            },
        })
        return findings

    @staticmethod
    def _model(*, total=0, completed=0, incomplete=0, unconfirmed=False, completed_rows=None, incomplete_rows=None):
        return {
            "total_count": total, "completed_count": completed,
            "incomplete_count": incomplete,
            "population_unconfirmed": unconfirmed,
            "completed": list(completed_rows or ()),
            "incomplete": list(incomplete_rows or ()),
        }

    @staticmethod
    def _write_minimal_deliverables(root: Path, *, api_completed=0, dependency_completed=0, scope=None):
        scope = scope or {
            "available_dependency_count": 0, "included_dependency_count": 0,
            "total_api_count": 0, "analyzed_api_count": 0,
            "included_dependency_coords": [], "excluded_dependency_coords": [],
        }
        (root / "all-affected-dependencies.md").write_text(
            f"# 完整依赖分析明细\n| {dependency_completed} |\n",
            encoding="utf-8",
        )
        (root / "all-impact-details.md").write_text(
            f"# 完整 API 分析与调用关系明细\n| {api_completed} |\n",
            encoding="utf-8",
        )
        (root / "report.md").write_text(
            "# Java 依赖升级影响报告\n"
            "all-affected-dependencies.md all-affected-dependencies.csv "
            "all-impact-details.md all-impact-details.csv analysis-scope.md\n",
            encoding="utf-8",
        )
        coords = [
            *scope.get("included_dependency_coords", ()),
            *scope.get("excluded_dependency_coords", ()),
        ]
        (root / "analysis-scope.md").write_text(
            "# 本轮分析范围\n"
            f"总数 {scope['available_dependency_count']}；纳入本轮分析 {scope['included_dependency_count']}；\n"
            f"总数 {scope['total_api_count']}；纳入本轮分析 {scope['analyzed_api_count']}；\n"
            + "\n".join(map(str, coords)),
            encoding="utf-8",
        )

    def _validate(
        self,
        deliverables: Path,
        findings: dict,
        *,
        api_model=None,
        dependency_model=None,
        dependency_rows=None,
        api_rows=None,
        completed_groups=None,
    ):
        api_model = api_model or self._model()
        dependency_model = dependency_model or self._model()
        rows = iter([
            list(dependency_rows or ()), list(api_rows or ()),
        ])
        if completed_groups is None:
            completed_groups = [("all", api_model.get("completed") or [])]
        with patch.object(
            binary_report.s6_report, "build_human_api_analysis",
            return_value=api_model,
        ), patch.object(
            binary_report.s6_report, "build_human_dependency_analysis",
            return_value=dependency_model,
        ), patch.object(
            binary_report.s6_report, "_completed_api_rows_by_dependency",
            return_value=completed_groups,
        ), patch.object(
            binary_report, "_read_step6_contract_csv",
            side_effect=lambda *_args, **_kwargs: next(rows),
        ), patch.object(binary_report, "_report_file_sha256"):
            return binary_report._validate_step6_deliverable_semantics(
                deliverables, findings,
            )

    def test_findings_lists_scope_counts_equations_and_identity_sets(self):
        with tempfile.TemporaryDirectory() as directory:
            deliverables = Path(directory).resolve()
            self._write_minimal_deliverables(deliverables)
            for field in self.LIST_FIELDS:
                findings = self._findings()
                findings[field] = None
                with self.subTest(list_field=field):
                    self.assert_reason(
                        "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                        lambda findings=findings: self._validate(deliverables, findings),
                    )
            findings = self._findings()
            findings["analysis_scope"] = []
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: self._validate(deliverables, findings),
            )

            for field in self.COUNT_FIELDS:
                for invalid in [None, "1", -1, True]:
                    findings = self._findings()
                    findings["analysis_scope"][field] = invalid
                    with self.subTest(count_field=field, invalid=invalid):
                        self.assert_reason(
                            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                            lambda findings=findings: self._validate(deliverables, findings),
                        )

            boolean_counts = self._findings()
            boolean_counts["analysis_scope"].update({
                field: False for field in self.COUNT_FIELDS
            })
            self._write_minimal_deliverables(
                deliverables, scope=boolean_counts["analysis_scope"],
            )
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: self._validate(deliverables, boolean_counts),
            )
            self._write_minimal_deliverables(deliverables)

            equation_mutations = [
                {"available_dependency_count": 0, "included_dependency_count": 1},
                {"analyzed_api_count": 1, "included_api_count": 0},
                {"total_api_count": 1, "included_api_count": 0, "excluded_api_count": 0},
            ]
            for mutation in equation_mutations:
                findings = self._findings()
                findings["analysis_scope"].update(mutation)
                with self.subTest(equation=mutation):
                    self.assert_reason(
                        "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                        lambda findings=findings: self._validate(deliverables, findings),
                    )

            invalid_identities = [None, [1], [""], ["   "], ["A", "A"]]
            for identities in invalid_identities:
                findings = self._findings()
                findings["analysis_scope"]["included_reported_api_identities"] = identities
                with self.subTest(identities=identities):
                    self.assert_reason(
                        "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                        lambda findings=findings: self._validate(deliverables, findings),
                    )

    def test_binary_dimension_schema_value_totals_and_population_relations(self):
        with tempfile.TemporaryDirectory() as directory:
            deliverables = Path(directory).resolve()
            self._write_minimal_deliverables(deliverables)
            mutations = [
                [],
                {"reachability_status": [], "impact_conclusion": {}, "runtime_verification_status": "not_executed"},
                {"reachability_status": {}, "impact_conclusion": {}, "runtime_verification_status": "not_executed"},
                {"reachability_status": self._dimensions()["reachability_status"], "impact_conclusion": [], "runtime_verification_status": "not_executed"},
                {"reachability_status": self._dimensions()["reachability_status"], "impact_conclusion": {}, "runtime_verification_status": "not_executed"},
                {**self._dimensions(), "reachability_status": {**self._dimensions()["reachability_status"], "extra": 0}},
                {**self._dimensions(), "impact_conclusion": {**self._dimensions()["impact_conclusion"], "extra": 0}},
                {**self._dimensions(), "reachability_status": {**self._dimensions()["reachability_status"], "reachable": True}},
                {**self._dimensions(), "impact_conclusion": {**self._dimensions()["impact_conclusion"], "inconclusive": -1}},
                {**self._dimensions(), "runtime_verification_status": "executed"},
                self._dimensions(reachable=1, probable=0, inconclusive=0),
            ]
            for name in ["binary_dimensions", "generation_binary_dimensions"]:
                for mutation in mutations:
                    findings = self._findings()
                    findings[name] = mutation
                    with self.subTest(name=name, mutation=mutation):
                        self.assert_reason(
                            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                            lambda findings=findings: self._validate(deliverables, findings),
                        )

            findings = self._findings()
            findings["analysis_scope"]["included_reported_api_identities"] = ["A"]
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: self._validate(deliverables, findings),
            )
            findings = self._findings()
            findings["analysis_scope"].update({
                "included_reported_api_identities": ["A"],
                "total_api_count": 1, "analyzed_api_count": 1,
                "included_api_count": 1,
            })
            findings["binary_dimensions"] = self._dimensions(reachable=1, probable=1)
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: self._validate(deliverables, findings),
            )

    def test_dependency_selection_resources_population_and_model_equations(self):
        with tempfile.TemporaryDirectory() as directory:
            deliverables = Path(directory).resolve()
            self._write_minimal_deliverables(deliverables)
            for coords in [None, [1], [""], ["A", "A"]]:
                findings = self._findings()
                findings["analysis_scope"]["included_dependency_coords"] = coords
                with self.subTest(coords=coords):
                    self.assert_reason(
                        "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                        lambda findings=findings: self._validate(deliverables, findings),
                    )

            base = self._findings()
            base["analysis_scope"].update({
                "available_dependency_count": 1,
                "included_dependency_count": 1,
                "included_dependency_coords": ["g:a"],
            })
            for resources in [None, [1], [{"coord": "g:other"}]]:
                findings = json.loads(json.dumps(base))
                findings["resource_impacts"] = resources
                with self.subTest(resources=resources):
                    self.assert_reason(
                        "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                        lambda findings=findings: self._validate(deliverables, findings),
                    )

            findings = self._findings()
            findings["report_population"] = {}
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: self._validate(deliverables, findings),
            )
            for model_name in ["api", "dependency"]:
                bad_model = self._model(total=1, completed=1, incomplete=1)
                findings = self._findings()
                key = "apis" if model_name == "api" else "dependencies"
                findings["report_population"][key] = {
                    "total_count": 1, "completed_count": 1,
                    "incomplete_count": 1, "population_unconfirmed": False,
                }
                with self.subTest(model=model_name):
                    self.assert_reason(
                        "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                        lambda findings=findings, model_name=model_name, bad_model=bad_model: self._validate(
                            deliverables, findings,
                            api_model=bad_model if model_name == "api" else self._model(),
                            dependency_model=bad_model if model_name == "dependency" else self._model(),
                        ),
                    )

    def test_csv_semantics_and_api_label_projection_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            deliverables = Path(directory).resolve()
            findings = self._findings()
            self._write_minimal_deliverables(deliverables)
            dependency_item = {"coord": "g:a", "analysis_conclusion": "未完成"}
            dependency_model = self._model(
                total=1, incomplete=1, incomplete_rows=[dependency_item],
            )
            findings["report_population"]["dependencies"].update({
                "total_count": 1, "incomplete_count": 1,
            })
            invalid_dependency_rows = [
                [],
                [{"依赖": "wrong", "分析结果": "未完成", "版本变化": "1→2", "API 分析（已完成/总数）": "0/1", "当前系统调用关系": "无", "结果说明": "说明"}],
                [{"依赖": "g:a", "分析结果": "未完成", "版本变化": "", "API 分析（已完成/总数）": "0/1", "当前系统调用关系": "无", "结果说明": "说明"}],
            ]
            for rows in invalid_dependency_rows:
                with self.subTest(dependency_rows=rows):
                    self.assert_reason(
                        "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                        lambda rows=rows: self._validate(
                            deliverables, findings,
                            dependency_model=dependency_model,
                            dependency_rows=rows,
                        ),
                    )

            api_items = [
                {"coord": "g:a", "api": "p.C.m", "api_signature": "(int)", "conclusion": "已确认影响"},
                {"coord": "g:a", "api": "p.C.m()", "api_signature": "(int)", "conclusion": "未发现调用路径"},
                {"coord": "g:a", "api_name": "p.C.n", "aggregate_count": 2, "conclusion": "可能影响"},
                {"coord": "", "conclusion": ""},
            ]
            api_model = self._model(total=4, completed=4, completed_rows=api_items)
            findings = self._findings()
            findings["analysis_scope"].update({
                "available_dependency_count": 1,
                "included_dependency_count": 1,
                "included_dependency_coords": ["g:a"],
                "total_api_count": 4, "analyzed_api_count": 4,
                "included_api_count": 4,
                "included_reported_api_identities": ["A", "B", "C", "D"],
            })
            findings["binary_dimensions"] = self._dimensions(reachable=4, probable=4)
            findings["generation_binary_dimensions"] = self._dimensions(reachable=4, probable=4)
            findings["report_population"]["apis"].update({
                "total_count": 4, "completed_count": 4,
            })
            api_rows = [
                {"依赖": "g:a", "API": "p.C.m(int)", "分析结果": "确认有影响", "新版本中的变化": "变化", "当前系统调用关系": "有", "结果说明": "说明"},
                {"依赖": "g:a", "API": "p.C.m()", "分析结果": "未确认影响", "新版本中的变化": "变化", "当前系统调用关系": "无", "结果说明": "说明"},
                {"依赖": "g:a", "API": "p.C.n（2 个）", "分析结果": "未确认影响（存在候选关系）", "新版本中的变化": "变化", "当前系统调用关系": "候选", "结果说明": "说明"},
                {"依赖": "依赖身份未记录", "API": "API 身份未记录", "分析结果": "未完成分析", "新版本中的变化": "未知", "当前系统调用关系": "未知", "结果说明": "说明"},
            ]
            self._write_minimal_deliverables(
                deliverables, api_completed=4,
                scope=findings["analysis_scope"],
            )
            with (deliverables / "all-impact-details.md").open("a", encoding="utf-8") as handle:
                handle.write("\ng:a\n依赖身份未记录\n")
            self._validate(
                deliverables, findings,
                api_model=api_model,
                dependency_rows=[], api_rows=api_rows,
                completed_groups=[("g:a", api_items)],
            )

            for mutation in [
                api_rows[:3],
                [{**api_rows[0], "API": "wrong"}, *api_rows[1:]],
                [{**api_rows[0], "结果说明": ""}, *api_rows[1:]],
            ]:
                with self.subTest(api_rows=mutation):
                    self.assert_reason(
                        "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                        lambda mutation=mutation: self._validate(
                            deliverables, findings, api_model=api_model,
                            api_rows=mutation,
                            completed_groups=[("g:a", api_items)],
                        ),
                    )

    def test_remaining_semantic_fallback_markdown_and_scope_projection_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            deliverables = Path(directory).resolve()

            resource_findings = self._findings()
            resource_findings["analysis_scope"].update({
                "available_dependency_count": 1,
                "included_dependency_count": 1,
                "included_dependency_coords": ["g:a"],
            })
            resource_findings["resource_impacts"] = [{}]
            self._write_minimal_deliverables(
                deliverables, scope=resource_findings["analysis_scope"],
            )
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: self._validate(deliverables, resource_findings),
            )

            def dependency_case(*, conclusion, include_markdown_identity):
                findings = self._findings()
                findings["analysis_scope"].update({
                    "available_dependency_count": 1,
                    "included_dependency_count": 1,
                    "included_dependency_coords": ["g:a"],
                })
                item = {"coord": "", "analysis_conclusion": conclusion}
                model = self._model(
                    total=1, incomplete=1, incomplete_rows=[item],
                )
                findings["report_population"]["dependencies"].update({
                    "total_count": 1, "incomplete_count": 1,
                })
                row = {
                    "依赖": "依赖身份未记录",
                    "版本变化": "unknown",
                    "API 分析（已完成/总数）": "0/0",
                    "当前系统调用关系": "未确认",
                    "分析结果": conclusion,
                    "结果说明": "说明",
                }
                self._write_minimal_deliverables(
                    deliverables, scope=findings["analysis_scope"],
                )
                if include_markdown_identity:
                    with (deliverables / "all-affected-dependencies.md").open(
                        "a", encoding="utf-8",
                    ) as handle:
                        handle.write("依赖身份未记录\n")
                return findings, model, [row]

            findings, model, rows = dependency_case(
                conclusion="结论", include_markdown_identity=True,
            )
            self._validate(
                deliverables, findings,
                dependency_model=model, dependency_rows=rows,
            )

            findings, model, rows = dependency_case(
                conclusion="", include_markdown_identity=True,
            )
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: self._validate(
                    deliverables, findings,
                    dependency_model=model, dependency_rows=rows,
                ),
            )

            findings, model, rows = dependency_case(
                conclusion="结论", include_markdown_identity=False,
            )
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: self._validate(
                    deliverables, findings,
                    dependency_model=model, dependency_rows=rows,
                ),
            )

            findings = self._findings()
            findings["analysis_scope"].update({
                "available_dependency_count": 1,
                "included_dependency_count": 1,
                "included_dependency_coords": ["g:a"],
                "total_api_count": 1,
                "analyzed_api_count": 1,
                "included_api_count": 1,
                "included_reported_api_identities": ["api-1"],
            })
            findings["binary_dimensions"] = self._dimensions(
                not_analyzed=1, inconclusive=1,
            )
            findings["generation_binary_dimensions"] = self._dimensions(
                not_analyzed=1, inconclusive=1,
            )
            findings["report_population"]["apis"].update({
                "total_count": 1, "incomplete_count": 1,
            })
            api_item = {
                "coord": "g:a", "api": "p.C.m()",
                "conclusion": "本次未完成分析",
            }
            api_model = self._model(
                total=1, incomplete=1, incomplete_rows=[api_item],
            )
            api_rows = [{
                "依赖": "g:a", "API": "p.C.m()",
                "新版本中的变化": "未知",
                "当前系统调用关系": "未确认",
                "分析结果": "未完成分析", "结果说明": "说明",
            }]
            self._write_minimal_deliverables(
                deliverables, scope=findings["analysis_scope"],
            )
            with (deliverables / "all-impact-details.md").open(
                "a", encoding="utf-8",
            ) as handle:
                handle.write("g:a\n")
            self._validate(
                deliverables, findings, api_model=api_model,
                api_rows=api_rows, completed_groups=[],
            )

            findings = self._findings()
            findings["analysis_scope"].update({
                "available_dependency_count": 1,
                "included_dependency_count": 1,
                "included_dependency_coords": ["g:a"],
            })
            self._write_minimal_deliverables(
                deliverables, scope=findings["analysis_scope"],
            )
            (deliverables / "analysis-scope.md").write_text(
                "# 本轮分析范围\n总数 1；纳入本轮分析 1；\n",
                encoding="utf-8",
            )
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: self._validate(deliverables, findings),
            )

            findings = self._findings()
            findings["analysis_scope"].update({
                "available_dependency_count": 1,
                "included_dependency_count": 1,
                "included_dependency_coords": ["g:a"],
            })
            self._write_minimal_deliverables(
                deliverables, scope=findings["analysis_scope"],
            )
            (deliverables / "analysis-scope.md").write_text(
                "# 本轮分析范围\n"
                "总数 1；纳入本轮分析 1；\n"
                "总数 0；纳入本轮分析 0；\n",
                encoding="utf-8",
            )
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: self._validate(deliverables, findings),
            )

            findings["analysis_scope"]["excluded_dependency_coords"] = [
                "g:excluded",
            ]
            self._write_minimal_deliverables(
                deliverables, scope=findings["analysis_scope"],
            )
            self._validate(deliverables, findings)

    def test_markdown_report_scope_structure_and_read_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            deliverables = Path(directory).resolve()
            findings = self._findings()
            self._write_minimal_deliverables(deliverables)
            self._validate(deliverables, findings)

            mutations = [
                ("all-affected-dependencies.md", "wrong\n| 0 |\n"),
                ("all-affected-dependencies.md", "# 完整依赖分析明细\n"),
                ("all-impact-details.md", "wrong\n| 0 |\n"),
                ("report.md", "wrong"),
                ("report.md", "# Java 依赖升级影响报告\nanalysis-scope.md"),
                ("analysis-scope.md", "wrong"),
                ("analysis-scope.md", "# 本轮分析范围\n"),
            ]
            for filename, text in mutations:
                self._write_minimal_deliverables(deliverables)
                (deliverables / filename).write_text(text, encoding="utf-8")
                with self.subTest(filename=filename, text=text):
                    self.assert_reason(
                        "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                        lambda: self._validate(deliverables, findings),
                    )

            self._write_minimal_deliverables(deliverables)
            with patch.object(Path, "read_text", side_effect=OSError("unreadable")):
                self.assert_reason(
                    "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                    lambda: self._validate(deliverables, findings),
                )


class BinaryReportGenerationLoadingBoundaryTest(unittest.TestCase):
    def assert_reason(self, expected: str, action) -> binary_report.BinaryReportError:
        with self.assertRaises(binary_report.BinaryReportError) as captured:
            action()
        self.assertEqual(captured.exception.reason_code, expected)
        return captured.exception

    def _fixture(self, directory: str):
        report = Path(directory).resolve() / "report"
        root = report / binary_report.BINARY_OUTPUT_RELATIVE_PATH
        identity = "a" * 64
        generation = root / "binary_generations" / identity
        validation_identity = "b" * 64
        validation_digest = "c" * 64
        generation.mkdir(parents=True)
        validation_dir = generation / "validation"
        validation_dir.mkdir()
        validation_path = validation_dir / f"{validation_identity}.json"
        validation_path.write_text("{}", encoding="utf-8")
        summary = generation / "binary_summary.json"
        summary.write_text("{}", encoding="utf-8")
        active = {
            "schema": binary_report.ACTIVE_GENERATION_SCHEMA,
            "result_generation_identity": identity,
            "generation_directory": f"binary_generations/{identity}",
            "validation_run_identity": validation_identity,
            "validation_result_sha256": validation_digest,
        }
        manifest = {
            "schema": binary_report.RESULT_GENERATION_SCHEMA,
            "result_generation_identity": identity,
            "authority": "binary_first",
            "sidecar_content_identities": {"binary_summary.json": "d" * 64},
        }
        validation = {"validation_run_identity": validation_identity}
        return {
            "report": report, "root": root, "identity": identity,
            "generation": generation, "validation_path": validation_path,
            "active": active, "manifest": manifest, "validation": validation,
            "validation_digest": validation_digest,
        }

    def _load(
        self,
        fixture,
        *,
        active=None,
        manifest=None,
        validation=None,
        active_error=None,
        candidate_identity="",
        validation_complete=True,
        digest_overrides=None,
    ):
        active = dict(fixture["active"] if active is None else active)
        manifest = dict(fixture["manifest"] if manifest is None else manifest)
        validation = dict(fixture["validation"] if validation is None else validation)
        digest_overrides = dict(digest_overrides or {})

        def load_json(path):
            path = Path(path)
            if path.name == "result_generation.json":
                return manifest
            if path == fixture["validation_path"]:
                return validation
            if path.name == "binary_source_explanations.json":
                return {"declared": "source-explanations"}
            if path.name == "binary_source_attestation.json":
                return {"declared": "source-attestation"}
            return {"loaded": path.name}

        def digest(path):
            path = Path(path)
            if path in digest_overrides:
                return digest_overrides[path]
            if path == fixture["validation_path"]:
                return fixture["validation_digest"]
            return str(manifest["sidecar_content_identities"].get(path.name, "e" * 64))

        active_patch = (
            patch.object(binary_report, "read_active_binary_generation", side_effect=active_error)
            if active_error is not None
            else patch.object(binary_report, "read_active_binary_generation", return_value=active)
        )
        pending_patch = (
            patch.object(binary_report, "read_pending_binary_generation", side_effect=active_error)
            if active_error is not None
            else patch.object(binary_report, "read_pending_binary_generation", return_value=active)
        )
        with active_patch as read_active, pending_patch as read_pending, patch.object(
            binary_report, "_load_json", side_effect=load_json,
        ), patch.object(
            binary_report, "_sha256", side_effect=digest,
        ), patch.object(
            binary_report, "_result_generation_identity_from_manifest",
            return_value=fixture["identity"],
        ), patch.object(
            binary_report, "is_complete_v3_validation_result",
            return_value=validation_complete,
        ):
            result = binary_report.load_validated_generation(
                fixture["report"],
                candidate_activation_identity=candidate_identity,
            )
        return result, read_active, read_pending

    def test_active_and_pending_selection_success_defaults_and_declared_optional_sidecars(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            loaded, read_active, read_pending = self._load(fixture)
            read_active.assert_called_once_with(fixture["root"])
            read_pending.assert_not_called()
            self.assertEqual(loaded["generation"], fixture["generation"])
            self.assertEqual(loaded["summary"], {"loaded": "binary_summary.json"})
            self.assertEqual(loaded["source_explanations"], {
                "authority": "not_provided", "declarations": [],
                "candidate_relationships": [],
            })
            self.assertEqual(loaded["source_attestation"], {
                "coverage_gaps": [], "language_file_counts": {},
            })

            loaded, read_active, read_pending = self._load(
                fixture, candidate_identity="activation",
            )
            read_active.assert_not_called()
            read_pending.assert_called_once_with(
                fixture["root"], expected_activation_identity="activation",
            )

            for filename in [
                "binary_source_explanations.json",
                "binary_source_attestation.json",
            ]:
                path = fixture["generation"] / filename
                path.write_text("{}", encoding="utf-8")
                fixture["manifest"]["sidecar_content_identities"][filename] = "f" * 64
            loaded, _read_active, _read_pending = self._load(fixture)
            self.assertEqual(loaded["source_explanations"], {"declared": "source-explanations"})
            self.assertEqual(loaded["source_attestation"], {"declared": "source-attestation"})

    def test_binary_output_errors_preserve_authority_and_classify_descriptor_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            cases = [
                ("BINARY_GENERATION_MANIFEST_INVALID", "BINARY_GENERATION_MANIFEST_MISMATCH"),
                ("BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID", "BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID"),
                ("BINARY_GENERATION_PUBLICATION_AUTHORITY_FORBIDDEN", "BINARY_GENERATION_PUBLICATION_AUTHORITY_FORBIDDEN"),
                ("BINARY_GENERATION_PUBLICATION_AUTHORITY_REQUIRED", "BINARY_GENERATION_PUBLICATION_AUTHORITY_REQUIRED"),
                ("BINARY_ACTIVE_DESCRIPTOR_INVALID", "BINARY_ACTIVE_GENERATION_INVALID"),
                ("", "BINARY_ACTIVE_GENERATION_INVALID"),
            ]
            for source_reason, expected in cases:
                error = binary_report.BinaryOutputError(source_reason, "detail")
                with self.subTest(source_reason=source_reason):
                    self.assert_reason(
                        expected,
                        lambda error=error: self._load(fixture, active_error=error),
                    )

    def test_active_generation_path_and_manifest_contract_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            active_mutations = [
                {**fixture["active"], "schema": "invalid"},
                {**fixture["active"], "result_generation_identity": "bad"},
                {**fixture["active"], "generation_directory": "binary_generations/other"},
                {**fixture["active"], "generation_directory": "../escape"},
            ]
            for active in active_mutations:
                with self.subTest(active=active):
                    expected = (
                        "BINARY_ACTIVE_GENERATION_PATH_ESCAPE"
                        if active.get("generation_directory") == "../escape"
                        else "BINARY_ACTIVE_GENERATION_INVALID"
                    )
                    self.assert_reason(
                        expected,
                        lambda active=active: self._load(fixture, active=active),
                    )

            manifest_mutations = [
                {**fixture["manifest"], "schema": "invalid"},
                {**fixture["manifest"], "result_generation_identity": "0" * 64},
                {**fixture["manifest"], "authority": "source_first"},
            ]
            for manifest in manifest_mutations:
                with self.subTest(manifest=manifest):
                    self.assert_reason(
                        "BINARY_GENERATION_MANIFEST_MISMATCH",
                        lambda manifest=manifest: self._load(fixture, manifest=manifest),
                    )
            with patch.object(
                binary_report, "_result_generation_identity_from_manifest",
                return_value="0" * 64,
            ), patch.object(
                binary_report, "read_active_binary_generation",
                return_value=fixture["active"],
            ), patch.object(
                binary_report, "_load_json", return_value=fixture["manifest"],
            ):
                self.assert_reason(
                    "BINARY_GENERATION_MANIFEST_MISMATCH",
                    lambda: binary_report.load_validated_generation(fixture["report"]),
                )

            manifest = {**fixture["manifest"], "sidecar_content_identities": []}
            self.assert_reason(
                "BINARY_GENERATION_MANIFEST_MISMATCH",
                lambda: self._load(fixture, manifest=manifest),
            )

    def test_sidecar_name_digest_file_and_optional_declaration_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            invalid_sidecars = [
                {"../escape": "d" * 64},
                {"binary_summary.json": "invalid"},
            ]
            for sidecars in invalid_sidecars:
                manifest = {**fixture["manifest"], "sidecar_content_identities": sidecars}
                with self.subTest(sidecars=sidecars):
                    self.assert_reason(
                        "BINARY_GENERATION_SIDECAR_NAME_INVALID",
                        lambda manifest=manifest: self._load(fixture, manifest=manifest),
                    )

            summary = fixture["generation"] / "binary_summary.json"
            digest_mismatch = {summary: "0" * 64}
            self.assert_reason(
                "BINARY_GENERATION_SIDECAR_INTEGRITY_FAILED",
                lambda: self._load(fixture, digest_overrides=digest_mismatch),
            )
            summary.unlink()
            self.assert_reason(
                "BINARY_GENERATION_SIDECAR_INTEGRITY_FAILED",
                lambda: self._load(fixture),
            )
            summary.symlink_to(fixture["validation_path"])
            self.assert_reason(
                "BINARY_GENERATION_SIDECAR_INTEGRITY_FAILED",
                lambda: self._load(fixture),
            )
            summary.unlink()
            summary.write_text("{}", encoding="utf-8")

            optional = fixture["generation"] / "binary_source_explanations.json"
            optional.write_text("{}", encoding="utf-8")
            self.assert_reason(
                "BINARY_GENERATION_UNDECLARED_SIDECAR",
                lambda: self._load(fixture),
            )
            optional.unlink()
            optional.symlink_to(summary)
            self.assert_reason(
                "BINARY_GENERATION_UNDECLARED_SIDECAR",
                lambda: self._load(fixture),
            )

    def test_validation_identity_path_digest_and_semantic_contract_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            for field in ["validation_run_identity", "validation_result_sha256"]:
                active = {**fixture["active"], field: "invalid"}
                with self.subTest(field=field):
                    self.assert_reason(
                        "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
                        lambda active=active: self._load(fixture, active=active),
                    )

            self.assert_reason(
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INTEGRITY_FAILED",
                lambda: self._load(
                    fixture,
                    digest_overrides={fixture["validation_path"]: "0" * 64},
                ),
            )
            invalid_validation = {"validation_run_identity": "0" * 64}
            self.assert_reason(
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
                lambda: self._load(fixture, validation=invalid_validation),
            )
            self.assert_reason(
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
                lambda: self._load(fixture, validation_complete=False),
            )
            fixture["validation_path"].unlink()
            self.assert_reason(
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
                lambda: self._load(fixture),
            )

    def test_physical_generation_and_validation_path_shape_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            error = binary_report.BinaryOutputError("X", "detail")
            error.reason_code = ""
            self.assert_reason(
                "BINARY_ACTIVE_GENERATION_INVALID",
                lambda: self._load(fixture, active_error=error),
            )
            for field in ("schema", "result_generation_identity", "generation_directory"):
                active = {**fixture["active"], field: None}
                with self.subTest(empty_active_field=field):
                    self.assert_reason(
                        "BINARY_ACTIVE_GENERATION_INVALID",
                        lambda active=active: self._load(fixture, active=active),
                    )
            active = {**fixture["active"], "validation_run_identity": None}
            self.assert_reason(
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
                lambda: self._load(fixture, active=active),
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            generations = fixture["root"] / "binary_generations"
            relocated = fixture["root"] / "relocated-generations"
            generations.rename(relocated)
            try:
                generations.symlink_to(relocated, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            self.assert_reason(
                "BINARY_ACTIVE_GENERATION_INVALID",
                lambda: self._load(fixture),
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            generation = fixture["generation"]
            relocated = generation.with_name("relocated-generation")
            generation.rename(relocated)
            try:
                generation.symlink_to(relocated, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            self.assert_reason(
                "BINARY_ACTIVE_GENERATION_INVALID",
                lambda: self._load(fixture),
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            generation = fixture["generation"]
            backup = generation.with_name("generation-backup")
            generation.rename(backup)
            generation.write_text("not a directory", encoding="utf-8")
            self.assert_reason(
                "BINARY_ACTIVE_GENERATION_INVALID",
                lambda: self._load(fixture),
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            generations = fixture["root"] / "binary_generations"
            generations.rename(fixture["root"] / "missing-generations-backup")
            self.assert_reason(
                "BINARY_ACTIVE_GENERATION_INVALID",
                lambda: self._load(fixture),
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            validation = fixture["generation"] / "validation"
            relocated = validation.with_name("validation-real")
            validation.rename(relocated)
            try:
                validation.symlink_to(relocated, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            self.assert_reason(
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
                lambda: self._load(fixture),
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            validation_path = fixture["validation_path"]
            relocated = validation_path.with_name("validation-real.json")
            validation_path.rename(relocated)
            try:
                validation_path.symlink_to(relocated)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            self.assert_reason(
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
                lambda: self._load(fixture),
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = self._fixture(directory)
            validation_path = fixture["validation_path"]
            validation_path.rename(validation_path.with_suffix(".backup"))
            validation_path.mkdir()
            self.assert_reason(
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
                lambda: self._load(fixture),
            )


class BinaryReportReleaseBoundaryTest(unittest.TestCase):
    def assert_reason(self, expected: str, action) -> binary_report.BinaryReportError:
        with self.assertRaises(binary_report.BinaryReportError) as captured:
            action()
        self.assertEqual(captured.exception.reason_code, expected)
        return captured.exception

    @staticmethod
    def _receipt(stage: str, *, digit: str = "a") -> dict:
        binding = {"publication_input_identity": "d" * 64}
        if stage != "step4":
            binding["upstream_publication_receipt_identity"] = "e" * 64
        return {
            "transaction_id": digit * 32,
            "committed_receipt_identity": "b" * 64,
            "published_content_identity": "c" * 64,
            "binding": binding,
        }

    def _release(self) -> dict:
        release = {
            "schema": binary_report._GLOBAL_RELEASE_SCHEMA,
            "release_sequence": 1,
            "active_core": {
                field: chr(ord("a") + index) * 64
                for index, field in enumerate(sorted(
                    binary_report._REPORT_PUBLICATION_SEALED_CONTEXT_BINDING_FIELDS
                ))
            },
            "step4": binary_report._release_stage_from_receipt(
                "step4", self._receipt("step4")
            ),
            "step5": binary_report._stale_release_stage(),
            "step6": binary_report._stale_release_stage(),
            "previous_complete": None,
        }
        release["release_identity"] = binary_report._global_release_identity(release)
        return release

    def test_protocol_marker_creation_validation_and_monotonic_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            marker = binary_report._publication_protocol_marker_path(report)
            binary_report._ensure_publication_protocol_marker(report)
            self.assertEqual(binary_report._read_private_publication_json(marker), {
                "schema": binary_report._REPORT_PUBLICATION_PROTOCOL_MARKER_SCHEMA,
                "protocol_version": 1,
            })
            binary_report._ensure_publication_protocol_marker(report)
            marker.write_text("{}", encoding="utf-8")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_PROTOCOL_MARKER_INVALID",
                lambda: binary_report._ensure_publication_protocol_marker(report),
            )

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            self.assertFalse(binary_report.report_uses_release_protocol(report))
            direct_paths = [
                binary_report._publication_protocol_marker_path(report),
                binary_report._global_release_path(report),
            ]
            for path in direct_paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("invalid is still protocol evidence", encoding="utf-8")
                with self.subTest(direct=path):
                    self.assertTrue(binary_report.report_uses_release_protocol(report))
                path.unlink()

            for destinations in [
                binary_report._step4_report_publication_destinations(report),
                binary_report._step5_report_publication_destinations(report),
                binary_report._step6_report_publication_destinations(report),
            ]:
                transaction, _token = binary_report._publication_transaction_path(destinations)
                for path in [
                    transaction,
                    binary_report._committed_publication_receipt_path(transaction),
                ]:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("evidence", encoding="utf-8")
                    with self.subTest(transaction_evidence=path):
                        self.assertTrue(binary_report.report_uses_release_protocol(report))
                    path.unlink()

            structured = report / ".runtime" / "indexes" / "s5_query_index.json"
            structured.parent.mkdir(parents=True, exist_ok=True)
            structured.write_text("{", encoding="utf-8")
            self.assertTrue(binary_report.report_uses_release_protocol(report))
            structured.write_text(json.dumps({
                "step4_publication_receipt_identity": "a" * 64,
                "step5_publication_input_identity": "b" * 64,
            }), encoding="utf-8")
            self.assertTrue(binary_report.report_uses_release_protocol(report))
            structured.write_text(json.dumps({
                "step4_publication_receipt_identity": "invalid",
                "step5_publication_input_identity": "b" * 64,
            }), encoding="utf-8")
            self.assertFalse(binary_report.report_uses_release_protocol(report))

    def test_release_stage_receipt_validation_and_canonical_fallback(self):
        step4 = binary_report._release_stage_from_receipt(
            "step4", self._receipt("step4")
        )
        self.assertEqual(step4["status"], "current")
        self.assertEqual(step4["upstream_publication_receipt_identity"], "")
        self.assertEqual(step4["publication_input_identity"], "d" * 64)
        fallback_receipt = self._receipt("step4")
        fallback_receipt["binding"] = {}
        fallback = binary_report._release_stage_from_receipt("step4", fallback_receipt)
        self.assertTrue(binary_report._is_sha256_identity(fallback["publication_input_identity"]))

        base = self._receipt("step5")
        mutations = [
            {**base, "transaction_id": "1" * 31},
            {**base, "transaction_id": "z" * 32},
            {**base, "committed_receipt_identity": "invalid"},
            {**base, "published_content_identity": "invalid"},
            {**base, "binding": {**base["binding"], "publication_input_identity": "invalid"}},
            {**base, "binding": {**base["binding"], "upstream_publication_receipt_identity": "invalid"}},
        ]
        for mutation in mutations:
            with self.subTest(receipt=mutation):
                self.assert_reason(
                    "BINARY_GLOBAL_RELEASE_RECEIPT_INVALID",
                    lambda mutation=mutation: binary_report._release_stage_from_receipt("step5", mutation),
                )
        step4_with_upstream = self._receipt("step4")
        step4_with_upstream["binding"]["upstream_publication_receipt_identity"] = "e" * 64
        self.assert_reason(
            "BINARY_GLOBAL_RELEASE_RECEIPT_INVALID",
            lambda: binary_report._release_stage_from_receipt("step4", step4_with_upstream),
        )

    def test_global_release_header_core_stage_previous_and_identity_matrix(self):
        release = self._release()
        self.assertEqual(binary_report._validate_global_release(release), release)
        header_mutations = [
            [],
            {**release, "extra": "x"},
            {**release, "schema": "invalid"},
            {**release, "release_sequence": True},
            {**release, "release_sequence": 0},
            {**release, "active_core": []},
            {**release, "active_core": {}},
            {**release, "active_core": {
                **release["active_core"], "extra": "a" * 64,
            }},
            {**release, "active_core": {
                **release["active_core"],
                next(iter(release["active_core"])): "invalid",
            }},
        ]
        for mutation in header_mutations:
            with self.subTest(mutation=mutation):
                self.assert_reason(
                    "BINARY_GLOBAL_RELEASE_INVALID",
                    lambda mutation=mutation: binary_report._validate_global_release(mutation),
                )

        stage_mutations = [
            [],
            {"status": "stale"},
            {**binary_report._stale_release_stage(), "transaction_id": "x"},
            {**binary_report._stale_release_stage(), "status": "unknown"},
        ]
        for stage in ["step4", "step5", "step6"]:
            for item in stage_mutations:
                mutation = {**release, stage: item}
                with self.subTest(stage=stage, item=item):
                    self.assert_reason(
                        "BINARY_GLOBAL_RELEASE_INVALID",
                        lambda mutation=mutation: binary_report._validate_global_release(mutation),
                    )

        current_step5 = binary_report._release_stage_from_receipt(
            "step5", self._receipt("step5")
        )
        current_release = {**release, "step5": current_step5}
        current_release["release_identity"] = binary_report._global_release_identity(current_release)
        self.assertEqual(
            binary_report._validate_global_release(current_release)["step5"],
            current_step5,
        )

        previous_mutations = [
            [],
            {},
            {"active_core": {}, "step4": {}, "step5": {}, "step6": {}, "release_identity": "invalid"},
        ]
        for previous in previous_mutations:
            mutation = {**release, "previous_complete": previous}
            mutation["release_identity"] = binary_report._global_release_identity(mutation)
            with self.subTest(previous=previous):
                self.assert_reason(
                    "BINARY_GLOBAL_RELEASE_INVALID",
                    lambda mutation=mutation: binary_report._validate_global_release(mutation),
                )
        mismatch = {**release, "release_identity": "0" * 64}
        self.assert_reason(
            "BINARY_GLOBAL_RELEASE_INVALID",
            lambda: binary_report._validate_global_release(mismatch),
        )

    def test_active_core_receipt_predicates_complete_snapshot_and_required_stage(self):
        loaded = {
            "manifest": {"result_generation_identity": "a" * 64},
            "active": {
                "validation_run_identity": "b" * 64,
                "validation_result_sha256": "c" * 64,
            },
        }
        core = binary_report._active_release_core(loaded)
        self.assertEqual(set(core), set(
            binary_report._REPORT_PUBLICATION_SEALED_CONTEXT_BINDING_FIELDS
        ))
        for section, field in [
            ("manifest", "result_generation_identity"),
            ("active", "validation_run_identity"),
            ("active", "validation_result_sha256"),
        ]:
            invalid = json.loads(json.dumps(loaded))
            invalid[section][field] = "invalid"
            with self.subTest(section=section, field=field):
                self.assert_reason(
                    "BINARY_GLOBAL_RELEASE_ACTIVE_INVALID",
                    lambda invalid=invalid: binary_report._active_release_core(invalid),
                )

        self.assertTrue(binary_report._receipt_matches_release_core({
            "binding": core,
        }, core))
        self.assertFalse(binary_report._receipt_matches_release_core({
            "binding": {**core, next(iter(core)): "0" * 64},
        }, core))
        self.assertTrue(binary_report._receipt_has_formal_gate({
            "gate_receipt": {"gate_name": "gate"},
        }, "gate"))
        self.assertFalse(binary_report._receipt_has_formal_gate(None, "gate"))

        release = self._release()
        self.assertIsNone(binary_report._complete_release_snapshot(release))
        complete = dict(release)
        complete["step5"] = binary_report._release_stage_from_receipt(
            "step5", self._receipt("step5")
        )
        complete["step6"] = binary_report._release_stage_from_receipt(
            "step6", self._receipt("step6")
        )
        snapshot = binary_report._complete_release_snapshot(complete)
        self.assertEqual(snapshot["release_identity"], release["release_identity"])
        self.assertIsNot(snapshot["active_core"], complete["active_core"])

        with self.assertRaisesRegex(ValueError, "unsupported release stage"):
            binary_report.require_current_release_stage("report", "invalid")
        for stage, stale_stage in [("step4", "step4"), ("step5", "step5"), ("step6", "step6")]:
            candidate = self._release()
            for required in ("step4", "step5", "step6"):
                candidate[required] = (
                    binary_report._stale_release_stage()
                    if required == stale_stage
                    else binary_report._release_stage_from_receipt(
                        required, self._receipt(required)
                    )
                )
            with self.subTest(stage=stage), patch.object(
                binary_report, "reconcile_current_release", return_value=candidate,
            ):
                self.assert_reason(
                    "BINARY_GLOBAL_RELEASE_STAGE_STALE",
                    lambda stage=stage: binary_report.require_current_release_stage("report", stage),
                )
        with patch.object(binary_report, "reconcile_current_release", return_value=complete):
            self.assertIs(binary_report.require_current_release_stage("report", "step6"), complete)

    def test_reconcile_lock_routing_calls_exact_internal_boundary(self):
        expected = {"release": "ok"}
        with patch.object(
            binary_report, "_standalone_report_workflow_lock",
            return_value=nullcontext(),
        ), patch.object(
            binary_report, "_active_generation_publication_lock",
            return_value=nullcontext(),
        ), patch.object(
            binary_report, "_reconcile_current_release_with_workflow_lock",
            return_value=expected,
        ) as reconcile:
            self.assertEqual(binary_report.reconcile_current_release("report"), expected)
            self.assertEqual(binary_report.reconcile_current_release(
                "report", workflow_lock_held=True,
            ), expected)
            self.assertEqual(binary_report.reconcile_current_release(
                "report", workflow_lock_held=True, active_lock_held=True,
            ), expected)
        self.assertEqual(reconcile.call_count, 3)


class BinaryReportStep6InputBoundaryTest(unittest.TestCase):
    def assert_reason(self, expected: str, action) -> binary_report.BinaryReportError:
        with self.assertRaises(binary_report.BinaryReportError) as captured:
            action()
        self.assertEqual(captured.exception.reason_code, expected)
        return captured.exception

    def test_upstream_evidence_path_normalization_allowlist_and_dynamic_limits(self):
        valid = [
            ("evidence/context/context.json", "evidence/context/context.json"),
            (" evidence\\static_scan\\custom.json#row ", "evidence/static_scan/custom.json"),
            (".runtime/coverage/custom.CSV", ".runtime/coverage/custom.CSV"),
            (".runtime/coverage/./bad.json", ".runtime/coverage/bad.json"),
        ]
        for raw, expected in valid:
            with self.subTest(raw=raw):
                self.assertEqual(
                    binary_report._normalized_step6_upstream_evidence_path(raw),
                    expected,
                )
        ignored = [None, "", "one", "/absolute/file.json", "other/path.json", "a/../b.json", "a/./b.json", "evidence/s1_artifacts/x.json"]
        for raw in ignored:
            with self.subTest(ignored=raw):
                self.assertEqual(binary_report._normalized_step6_upstream_evidence_path(raw), "")
        invalid_dynamic = [
            "evidence/static_scan/../escape.json",
            "evidence/static_scan/a/b/c/d/e/f.json",
            "evidence/static_scan/custom.exe",
            "evidence/static_scan/a\0b.json",
        ]
        for raw in invalid_dynamic:
            with self.subTest(invalid=raw):
                self.assert_reason(
                    "BINARY_STEP6_UPSTREAM_EVIDENCE_PATH_INVALID",
                    lambda raw=raw: binary_report._normalized_step6_upstream_evidence_path(raw),
                )

    def test_upstream_evidence_file_discovery_schema_references_and_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            coverage = report / "evidence" / "call_chain" / "coverage.json"
            self.assertEqual(
                binary_report._step6_upstream_evidence_files(report),
                set(binary_report._STEP6_UPSTREAM_EVIDENCE_FILES),
            )
            coverage.parent.mkdir(parents=True)

            for components in [{}, [None]]:
                coverage.write_text(json.dumps({"components": components}), encoding="utf-8")
                with self.subTest(components=components):
                    self.assert_reason(
                        "BINARY_STEP6_UPSTREAM_EVIDENCE_PATH_INVALID",
                        lambda: binary_report._step6_upstream_evidence_files(report),
                    )
            for evidence in [{}, [1]]:
                coverage.write_text(json.dumps({"components": [{"evidence": evidence}]}), encoding="utf-8")
                with self.subTest(evidence=evidence):
                    self.assert_reason(
                        "BINARY_STEP6_UPSTREAM_EVIDENCE_PATH_INVALID",
                        lambda: binary_report._step6_upstream_evidence_files(report),
                    )

            dynamic_relative = "evidence/static_scan/custom.json"
            dynamic = report / dynamic_relative
            dynamic.parent.mkdir(parents=True, exist_ok=True)
            dynamic.write_text("{}", encoding="utf-8")
            missing_relative = "evidence/static_scan/missing.json"
            coverage.write_text(json.dumps({"components": [{"evidence": [
                dynamic_relative, missing_relative, "other/ignored.json",
            ]}]}), encoding="utf-8")
            referenced = set()
            files = binary_report._step6_upstream_evidence_files(
                report, referenced_files_out=referenced,
            )
            self.assertIn(dynamic_relative, files)
            self.assertIn(missing_relative, files)
            self.assertEqual(referenced, {dynamic_relative, missing_relative})

            many = [f"evidence/static_scan/dynamic-{index}.json" for index in range(3)]
            coverage.write_text(json.dumps({"components": [{"evidence": many}]}), encoding="utf-8")
            with patch.object(binary_report, "_STEP6_DYNAMIC_UPSTREAM_MAX_PATHS", 2):
                error = self.assert_reason(
                    "BINARY_STEP6_UPSTREAM_EVIDENCE_BUDGET_EXCEEDED",
                    lambda: binary_report._step6_upstream_evidence_files(report),
                )
            self.assertIn('"kind":"path_count"', str(error))

            coverage.write_text(json.dumps({"components": [{"evidence": [dynamic_relative]}]}), encoding="utf-8")
            with patch.object(binary_report, "_STEP6_DYNAMIC_UPSTREAM_MAX_FILE_BYTES", 1):
                error = self.assert_reason(
                    "BINARY_STEP6_UPSTREAM_EVIDENCE_BUDGET_EXCEEDED",
                    lambda: binary_report._step6_upstream_evidence_files(report),
                )
            self.assertIn('"kind":"file_bytes"', str(error))

            second_relative = "evidence/static_scan/second.json"
            (report / second_relative).write_text("{}", encoding="utf-8")
            coverage.write_text(json.dumps({"components": [{"evidence": [dynamic_relative, second_relative]}]}), encoding="utf-8")
            with patch.object(binary_report, "_STEP6_DYNAMIC_UPSTREAM_MAX_TOTAL_BYTES", 3):
                error = self.assert_reason(
                    "BINARY_STEP6_UPSTREAM_EVIDENCE_BUDGET_EXCEEDED",
                    lambda: binary_report._step6_upstream_evidence_files(report),
                )
            self.assertIn('"kind":"total_bytes"', str(error))

    def test_require_upstream_regular_file_root_parent_and_leaf_contracts(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "report"
            leaf = root / "evidence" / "context" / "context.json"
            leaf.parent.mkdir(parents=True)
            leaf.write_text("{}", encoding="utf-8")
            relative = "evidence/context/context.json"
            self.assertEqual(
                binary_report._require_step6_upstream_regular_file(root, relative),
                leaf,
            )

            missing_root = base / "missing"
            error = self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._require_step6_upstream_regular_file(missing_root, relative),
            )
            # A missing root is an unavailable input, not evidence that an
            # existing parent chain was redirected or replaced.
            self.assertFalse(error.unsafe_parent_path)
            file_root = base / "file-root"
            file_root.write_text("x", encoding="utf-8")
            error = self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._require_step6_upstream_regular_file(file_root, relative),
            )
            self.assertTrue(error.unsafe_parent_path)
            link_root = base / "link-root"
            link_root.symlink_to(root, target_is_directory=True)
            error = self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._require_step6_upstream_regular_file(link_root, relative),
            )
            self.assertTrue(error.unsafe_parent_path)

            bad_parent_root = base / "bad-parent"
            bad_parent_root.mkdir()
            (bad_parent_root / "evidence").write_text("x", encoding="utf-8")
            error = self.assert_reason(
                "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                lambda: binary_report._require_step6_upstream_regular_file(bad_parent_root, relative),
            )
            self.assertTrue(error.unsafe_parent_path)

            for leaf_kind in ["missing", "directory", "symlink", "hardlink"]:
                leaf_root = base / f"leaf-{leaf_kind}"
                candidate = leaf_root / "evidence" / "context" / "context.json"
                candidate.parent.mkdir(parents=True)
                if leaf_kind == "directory":
                    candidate.mkdir()
                elif leaf_kind == "symlink":
                    candidate.symlink_to(leaf)
                elif leaf_kind == "hardlink":
                    os.link(leaf, candidate)
                with self.subTest(leaf_kind=leaf_kind):
                    error = self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
                        lambda leaf_root=leaf_root: binary_report._require_step6_upstream_regular_file(leaf_root, relative),
                    )
                    self.assertFalse(error.unsafe_parent_path)

    def test_required_upstream_set_context_and_available_dependency_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            base = binary_report._required_step6_upstream_evidence_files(report)
            self.assertEqual(base, set(binary_report._STEP6_REQUIRED_UPSTREAM_EVIDENCE_FILES))
            jdk = binary_report._required_step6_upstream_evidence_files(
                report, context={"jdk_upgraded": True},
            )
            self.assertIn("evidence/static_scan/s3_jdk_removed_api.csv", jdk)
            spring = binary_report._required_step6_upstream_evidence_files(
                report, context={"springboot_major_upgrade": True},
            )
            self.assertIn("evidence/static_scan/s3_springboot_config.csv", spring)
            deps = report / "evidence" / "dependencies"
            deps.mkdir(parents=True)
            (deps / "dep_changes.csv").write_text("header\n", encoding="utf-8")
            dependency_required = binary_report._required_step6_upstream_evidence_files(report)
            self.assertIn("evidence/static_scan/s3_dependency_compat.csv", dependency_required)
            (deps / "dependency_jars.json").write_text("{}", encoding="utf-8")
            database_required = binary_report._required_step6_upstream_evidence_files(report)
            self.assertIn("evidence/static_scan/s3_database_contract_summary.json", database_required)

    def test_input_owner_diagnostic_dedup_failure_contract_and_error_taxonomy(self):
        owners = [
            ("./evidence\\dependencies/x.json", "step1"),
            ("evidence/context/context.json", "step2"),
            ("evidence/static_scan/x.csv", "step3"),
            (".runtime/coverage/x.json", "step3"),
            ("other/path", None),
        ]
        for path, owner in owners:
            with self.subTest(path=path):
                self.assertEqual(binary_report.step6_internal_input_owner_for_path(path), owner)

        diagnostics = [
            {"artifact": "dependency_changes", "stage": "csv_contract", "path": "z", "message": "bad"},
            {"artifact": "context", "stage": "json_contract", "owner_step": "step3", "path": "a", "message": "bad"},
            {"artifact": "step3_scan", "stage": "text_contract", "path": "b", "message": "bad"},
            {"artifact": "ignored", "stage": "coverage_gap", "owner_step": "step1"},
            "invalid",
        ]
        findings = {"diagnostics": diagnostics + [dict(diagnostics[0])]}
        failures = binary_report.step6_internal_input_contract_failures(findings)
        self.assertEqual([item["owner_step"] for item in failures], ["step1", "step3", "step3"])
        self.assertEqual(len(failures), 3)
        self.assertEqual(binary_report.step6_internal_input_failure_owner(findings), "step1")
        contract = binary_report.step6_internal_input_failure_contract(findings)
        self.assertEqual(contract["status"], "failed")
        self.assertEqual(contract["owner_step"], "step1")
        self.assertEqual(binary_report.step6_internal_input_failure_contract({})["status"], "passed")
        self.assertIsNone(binary_report.step6_internal_input_failure_owner({}))

        binary_report._raise_step6_internal_input_failure({})
        missing = {"diagnostics": [{
            "artifact": "context", "stage": "artifact_missing",
            "path": "context.json", "message": "missing",
        }]}
        error = self.assert_reason(
            "BINARY_STEP6_UPSTREAM_EVIDENCE_MISSING",
            lambda: binary_report._raise_step6_internal_input_failure(missing),
        )
        self.assertEqual(error.owner_step, "step2")
        self.assertEqual(error.failure_contract["status"], "failed")
        mixed = {"diagnostics": [
            *missing["diagnostics"],
            {"artifact": "dependency_changes", "stage": "csv_contract", "message": "bad"},
        ]}
        self.assert_reason(
            "BINARY_STEP6_INTERNAL_INPUT_INVALID",
            lambda: binary_report._raise_step6_internal_input_failure(mixed),
        )

        accumulated = {"diagnostics": ["invalid"]}
        kwargs = {
            "artifact": "context", "stage": "json_contract",
            "path": Path("context.json"), "error_type": "ValueError",
            "message": "bad", "owner_step": "step2",
        }
        binary_report._append_step6_internal_input_diagnostic(accumulated, **kwargs)
        binary_report._append_step6_internal_input_diagnostic(accumulated, **kwargs)
        self.assertEqual(len(accumulated["diagnostics"]), 2)
        self.assertEqual(accumulated["diagnostics"][1]["owner_step"], "step2")
        binary_report._append_step6_internal_input_diagnostic(
            accumulated, **{**kwargs, "message": "different", "owner_step": "invalid"},
        )
        self.assertNotIn("owner_step", accumulated["diagnostics"][2])

    def test_json_input_missing_path_parse_root_validator_and_deduplicated_issues(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            relative = "evidence/context/context.json"
            path = report / relative
            findings = {"diagnostics": []}
            binary_report._validate_step6_internal_json_input(
                report, relative, "context", lambda _payload: [], findings,
            )
            self.assertEqual(findings["diagnostics"], [])
            path.parent.mkdir(parents=True)

            path.write_text("{", encoding="utf-8")
            binary_report._validate_step6_internal_json_input(
                report, relative, "context", lambda _payload: [], findings,
            )
            self.assertEqual(findings["diagnostics"][-1]["stage"], "json_load")
            path.write_text("[]", encoding="utf-8")
            binary_report._validate_step6_internal_json_input(
                report, relative, "context", lambda _payload: [], findings,
            )
            self.assertIn("expected object root", findings["diagnostics"][-1]["message"])
            path.write_text("{}", encoding="utf-8")
            binary_report._validate_step6_internal_json_input(
                report, relative, "context", lambda _payload: ["A", "A", "B"], findings,
            )
            self.assertEqual(findings["diagnostics"][-1]["message"], "A; B")
            before = len(findings["diagnostics"])
            binary_report._validate_step6_internal_json_input(
                report, relative, "context", lambda _payload: [], findings,
            )
            self.assertEqual(len(findings["diagnostics"]), before)

            path.unlink()
            path.symlink_to(report / "missing-target")
            binary_report._validate_step6_internal_json_input(
                report, relative, "context", lambda _payload: [], findings,
            )
            self.assertEqual(findings["diagnostics"][-1]["stage"], "json_load")

            unsafe_report = report / "unsafe"
            unsafe_report.mkdir()
            (unsafe_report / "evidence").symlink_to(report / "evidence", target_is_directory=True)
            with self.assertRaises(binary_report.BinaryReportError) as captured:
                binary_report._validate_step6_internal_json_input(
                    unsafe_report, relative, "context", lambda _payload: [], {"diagnostics": []},
                )
            self.assertTrue(captured.exception.unsafe_parent_path)

    def test_csv_input_header_row_contracts_valid_and_io_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            relative = "evidence/dependencies/test.csv"
            path = report / relative
            findings = {"diagnostics": []}
            groups = ({"a"}, {"b", "c"})
            binary_report._validate_step6_internal_csv_input(
                report, relative, "test", groups, findings,
            )
            self.assertEqual(findings["diagnostics"], [])
            path.parent.mkdir(parents=True)
            invalid_values = [
                "", "a,,b\n", "a,a\n", "a,x\n", "a,b\n1,2,3\n", "a,b\n1,nu\0l\n",
            ]
            for content in invalid_values:
                path.write_text(content, encoding="utf-8")
                current = {"diagnostics": []}
                binary_report._validate_step6_internal_csv_input(
                    report, relative, "test", groups, current,
                )
                with self.subTest(content=content):
                    self.assertEqual(len(current["diagnostics"]), 1)
                    self.assertEqual(current["diagnostics"][0]["stage"], "csv_contract")
            path.write_text("a,b\n1,2\n", encoding="utf-8")
            current = {"diagnostics": []}
            binary_report._validate_step6_internal_csv_input(
                report, relative, "test", groups, current,
            )
            self.assertEqual(current["diagnostics"], [])

            path.unlink()
            path.mkdir()
            current = {"diagnostics": []}
            binary_report._validate_step6_internal_csv_input(
                report, relative, "test", groups, current,
            )
            self.assertEqual(current["diagnostics"][0]["stage"], "csv_load")

    def test_step6_contract_csv_api_labels_and_publication_failure_serialization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "rows.csv"
            path.write_text("a,b\n1,2\n", encoding="utf-8")
            self.assertEqual(
                binary_report._read_step6_contract_csv(path, ("a", "b")),
                [{"a": "1", "b": "2"}],
            )
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: binary_report._read_step6_contract_csv(path, ("a",)),
            )
            path.write_text("a,b\n1,2,3\n", encoding="utf-8")
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: binary_report._read_step6_contract_csv(path, ("a", "b")),
            )

        labels = {
            "已确认影响": "确认有影响",
            "已确认不受影响": "确认不受影响",
            "可能影响": "未确认影响（存在候选关系）",
            "结论未确定（存在候选证据）": "未确认影响（存在候选关系）",
            "结论未确定（静态分析能力边界）": "未确认影响（静态分析能力边界）",
            "未发现调用路径": "未确认影响",
            "输入不足，结论未确定": "未完成分析",
            "本次未完成分析": "未完成分析",
            "custom": "custom",
            "": "未完成分析",
        }
        for conclusion, expected in labels.items():
            with self.subTest(conclusion=conclusion):
                self.assertEqual(
                    binary_report._step6_api_result_label({"conclusion": conclusion}),
                    expected,
                )

        error = binary_report.BinaryReportError("REASON", "detail")
        error.owner_step = "step2"
        error.failure_contract = {"status": "failed", "custom": True}
        serialized = binary_report.binary_report_publication_failure_result(
            error, phase="step6",
        )
        self.assertEqual(serialized["reason_code"], "REASON")
        self.assertEqual(serialized["owner_step"], "step2")
        self.assertEqual(serialized["failure_contract"], {"status": "failed", "custom": True})
        fallback = binary_report.binary_report_publication_failure_result(
            binary_report.BinaryReportError("R", "d"), phase="",
        )
        self.assertIsNone(fallback["owner_step"])
        self.assertEqual(fallback["failure_contract"]["failures"], [])


class BinaryReportReleaseReadDecisionBoundaryTest(unittest.TestCase):
    @staticmethod
    def _loaded(*, activation: str | None = "d" * 64) -> dict:
        active = {
            "validation_run_identity": "b" * 64,
            "validation_result_sha256": "c" * 64,
        }
        if activation is not None:
            active["activation_identity"] = activation
        return {
            "manifest": {
                "result_generation_identity": "a" * 64,
                "analysis_context_identity": "9" * 64,
            },
            "active": active,
        }

    def assert_reason(self, expected: str, action) -> binary_report.BinaryReportError:
        with self.assertRaises(binary_report.BinaryReportError) as captured:
            action()
        self.assertEqual(captured.exception.reason_code, expected)
        return captured.exception

    def _step5_snapshot_fixture(self, *, activation: str | None = "d" * 64):
        loaded = self._loaded(activation=activation)
        step4_receipt = {"committed_receipt_identity": "e" * 64}
        binding = {
            "result_generation_identity": "a" * 64,
            "validation_run_identity": "b" * 64,
            "validation_result_sha256": "c" * 64,
            "upstream_publication_receipt_identity": "e" * 64,
            "publication_input_identity": "f" * 64,
        }
        if activation is not None:
            binding["activation_identity"] = activation
        snapshot = {
            "transaction_id": "1" * 32,
            "binding": binding,
            "gate_receipt": {"gate_name": "binary_report"},
            "snapshot_destinations": ["one", "two", "three"],
        }
        summary = {
            "schema": "java-upgrade-analyzer.binary-step5-summary.v1",
            "result_generation_identity": "a" * 64,
            "step4_publication_receipt_identity": "e" * 64,
            "step5_publication_input_identity": "f" * 64,
        }
        selection = {
            "schema": "java-upgrade-analyzer.binary-step5-selection.v1",
            "step5_publication_input_identity": "f" * 64,
            "step4_publication_receipt_identity": "e" * 64,
        }
        return loaded, step4_receipt, snapshot, summary, selection

    def test_step5_snapshot_binding_field_by_field_decision_matrix(self):
        loaded, step4, snapshot, summary, selection = self._step5_snapshot_fixture()

        def invoke(
            *, loaded_value=loaded, step4_value=step4,
            snapshot_value=snapshot, summary_value=summary,
            selection_value=selection,
        ):
            def load(path):
                return summary_value if Path(path).name == "summary.json" else selection_value

            with patch.object(binary_report, "_load_json", side_effect=load):
                return binary_report._require_step5_snapshot_binding(
                    loaded_value, step4_value, snapshot_value,
                )

        self.assertEqual(invoke(), (Path("one"), Path("two"), Path("three")))

        for key in (
            "result_generation_identity",
            "validation_run_identity",
            "validation_result_sha256",
            "upstream_publication_receipt_identity",
        ):
            candidate = {**snapshot, "binding": {**snapshot["binding"], key: "wrong"}}
            with self.subTest(binding_key=key):
                self.assert_reason(
                    "BINARY_STEP5_PUBLICATION_BINDING_MISMATCH",
                    lambda candidate=candidate: invoke(snapshot_value=candidate),
                )

        missing_binding = {**snapshot, "binding": None, "transaction_id": ""}
        self.assert_reason(
            "BINARY_STEP5_PUBLICATION_BINDING_MISMATCH",
            lambda: invoke(snapshot_value=missing_binding),
        )

        active_without_identity, step4_no_activation, no_activation, summary_no_activation, selection_no_activation = (
            self._step5_snapshot_fixture(activation=None)
        )
        with patch.object(binary_report, "_load_json", side_effect=[summary_no_activation, selection_no_activation]):
            self.assertEqual(
                binary_report._require_step5_snapshot_binding(
                    active_without_identity, step4_no_activation, no_activation,
                ),
                (Path("one"), Path("two"), Path("three")),
            )
        explicit_wrong_activation = {
            **no_activation,
            "binding": {**no_activation["binding"], "activation_identity": "wrong"},
        }
        self.assert_reason(
            "BINARY_STEP5_PUBLICATION_BINDING_MISMATCH",
            lambda: invoke(
                loaded_value=active_without_identity,
                step4_value=step4_no_activation,
                snapshot_value=explicit_wrong_activation,
                summary_value=summary_no_activation,
                selection_value=selection_no_activation,
            ),
        )
        missing_required_activation = {
            **snapshot,
            "binding": {
                key: value for key, value in snapshot["binding"].items()
                if key != "activation_identity"
            },
        }
        self.assert_reason(
            "BINARY_STEP5_PUBLICATION_BINDING_MISMATCH",
            lambda: invoke(snapshot_value=missing_required_activation),
        )

        for mutation, reason in (
            ({"binding": {**snapshot["binding"], "publication_input_identity": "invalid"}},
             "BINARY_STEP5_PUBLICATION_BINDING_MISMATCH"),
            ({"gate_receipt": None}, "BINARY_STEP5_PUBLICATION_GATE_POLICY_MISMATCH"),
            ({"gate_receipt": {"gate_name": "wrong"}},
             "BINARY_STEP5_PUBLICATION_GATE_POLICY_MISMATCH"),
            ({"snapshot_destinations": None}, "BINARY_STEP5_PUBLICATION_SNAPSHOT_INVALID"),
            ({"snapshot_destinations": ["one", "two"]},
             "BINARY_STEP5_PUBLICATION_SNAPSHOT_INVALID"),
        ):
            candidate = {**snapshot, **mutation}
            with self.subTest(mutation=mutation):
                self.assert_reason(reason, lambda candidate=candidate: invoke(snapshot_value=candidate))

        summary_fields = (
            "schema",
            "result_generation_identity",
            "step4_publication_receipt_identity",
            "step5_publication_input_identity",
        )
        selection_fields = (
            "schema",
            "step5_publication_input_identity",
            "step4_publication_receipt_identity",
        )
        for field in summary_fields:
            damaged = {**summary, field: "wrong"}
            with self.subTest(summary_field=field):
                self.assert_reason(
                    "BINARY_STEP5_PUBLICATION_CONTENT_MISMATCH",
                    lambda damaged=damaged: invoke(summary_value=damaged),
                )
        for field in selection_fields:
            damaged = {**selection, field: "wrong"}
            with self.subTest(selection_field=field):
                self.assert_reason(
                    "BINARY_STEP5_PUBLICATION_CONTENT_MISMATCH",
                    lambda damaged=damaged: invoke(selection_value=damaged),
                )

    def test_loaded_step4_binding_and_semantic_match_matrix(self):
        loaded = self._loaded()
        binding = binary_report._loaded_step4_publication_binding(loaded)
        self.assertEqual(binding["activation_identity"], "d" * 64)
        self.assertTrue(binary_report._step4_publication_binding_matches_loaded(binding, loaded))
        self.assertFalse(binary_report._step4_publication_binding_matches_loaded([], loaded))
        self.assertFalse(binary_report._step4_publication_binding_matches_loaded(
            {**binding, "result_generation_identity": "wrong"}, loaded,
        ))

        sealed = self._loaded(activation=None)
        sealed_binding = binary_report._loaded_step4_publication_binding(sealed)
        self.assertNotIn("activation_identity", sealed_binding)
        historical = {**sealed_binding, "activation_identity": "d" * 64}
        self.assertTrue(binary_report._step4_publication_binding_matches_loaded(historical, sealed))
        self.assertFalse(binary_report._step4_publication_binding_matches_loaded(
            {**sealed_binding, "activation_identity": "invalid"}, sealed,
        ))
        self.assertFalse(binary_report._step4_publication_binding_matches_loaded(
            {**historical, "result_generation_identity": "wrong"}, sealed,
        ))

        for section, key in (
            ("manifest", "result_generation_identity"),
            ("active", "validation_run_identity"),
            ("active", "validation_result_sha256"),
        ):
            damaged = self._loaded(activation=None)
            damaged[section][key] = "invalid"
            with self.subTest(section=section, key=key):
                self.assert_reason(
                    "BINARY_STEP4_PUBLICATION_BINDING_INVALID",
                    lambda damaged=damaged: binary_report._loaded_step4_publication_binding(damaged),
                )

        with patch.object(binary_report, "canonical_identity", return_value="identity") as identity:
            binary_report._step5_publication_input_identity(
                loaded=loaded,
                step4_receipt={"committed_receipt_identity": "receipt"},
                selected_coords=["", " b:a ", "a:a", "a:a"],
                selected_names=["", " beta ", "alpha", "alpha"],
            )
        payload = identity.call_args.args[1]
        self.assertEqual(payload["selected_coords"], ["a:a", "b:a"])
        self.assertEqual(payload["selected_names"], ["alpha", "beta"])

    def test_step6_internal_json_contract_decision_matrices(self):
        def diagnostics_for(relative: str, payload: object) -> list[dict]:
            with tempfile.TemporaryDirectory() as directory:
                report = Path(directory).resolve()
                path = report / relative
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(payload), encoding="utf-8")
                findings = {"diagnostics": []}
                binary_report._augment_step6_internal_input_diagnostics(
                    report, findings,
                )
                return [
                    item for item in findings["diagnostics"]
                    if isinstance(item, dict)
                ]

        context_path = "evidence/context/context.json"
        valid_context = {
            "build_tool": "maven",
            "base_branch": "main",
            "current_branch": "upgrade",
            "jdk_base": "8",
            "jdk_current": "17",
            "springboot_base": "2.7.18",
            "springboot_current": "3.2.5",
            "jdk_upgraded": True,
            "springboot_major_upgrade": True,
            "tech_flags": {"spring": True},
        }
        self.assertEqual(diagnostics_for(context_path, valid_context), [])
        context_cases = [
            ({"build_tool": 1}, True),
            ({"build_tool": "   "}, True),
            ({"jdk_base": None}, True),
            ({"jdk_base": 8}, True),
            ({"springboot_base": 2.7}, True),
            ({"springboot_base": None, "springboot_current": None,
              "springboot_major_upgrade": False}, False),
            ({"jdk_upgraded": None}, True),
            ({"springboot_major_upgrade": 1}, True),
            ({"tech_flags": []}, True),
            # JSON canonicalizes object keys to text; only flag values are a
            # meaningful contract boundary.
            ({"tech_flags": {1: True}}, False),
            ({"tech_flags": {"spring": 1}}, True),
            ({"tech_flags": {}}, False),
            ({"jdk_base": "", "jdk_current": "17", "jdk_upgraded": False}, False),
            ({"jdk_base": "8", "jdk_current": "", "jdk_upgraded": False}, False),
            ({"jdk_base": "17", "jdk_current": "17", "jdk_upgraded": False}, False),
            ({"jdk_base": "unknown", "jdk_current": "17", "jdk_upgraded": False}, False),
            ({"jdk_base": "8", "jdk_current": "unknown", "jdk_upgraded": False}, False),
            ({"jdk_upgraded": False}, True),
            ({"springboot_base": "", "springboot_current": "3.2",
              "springboot_major_upgrade": False}, False),
            ({"springboot_base": "2.7", "springboot_current": "",
              "springboot_major_upgrade": False}, False),
            ({"springboot_base": "3.2", "springboot_current": "3.2",
              "springboot_major_upgrade": False}, False),
            ({"springboot_base": "-", "springboot_current": "3.2",
              "springboot_major_upgrade": False}, False),
            ({"springboot_base": "2.7", "springboot_current": "-",
              "springboot_major_upgrade": False}, False),
            ({"springboot_base": "2.7", "springboot_current": "3.2",
              "springboot_major_upgrade": False}, True),
            ({"springboot_base": "3.2", "springboot_current": "2.7",
              "springboot_major_upgrade": False}, False),
            ({"springboot_base": "invalid", "springboot_current": "3.x",
              "springboot_major_upgrade": False}, False),
            ({"springboot_base": "unknown", "springboot_current": "3.2",
              "springboot_major_upgrade": False}, False),
        ]
        for changes, expected_issue in context_cases:
            candidate = {**valid_context, **changes}
            result = diagnostics_for(context_path, candidate)
            with self.subTest(context_changes=changes):
                self.assertEqual(bool(result), expected_issue)
        for missing_field in ("jdk_base", "jdk_upgraded"):
            candidate = dict(valid_context)
            candidate.pop(missing_field)
            with self.subTest(missing_context_field=missing_field):
                self.assertTrue(diagnostics_for(context_path, candidate))

        provenance_path = "evidence/dependencies/build_provenance.json"
        valid_side = {"side": "base", "artifact_sha256": "a" * 64}
        valid_provenance = {
            "schema": "java-upgrade-analyzer.build-provenance.v2",
            "both_builds_succeeded": True,
            "sides": [valid_side, {"side": "current", "artifact_sha256": "b" * 64}],
        }
        self.assertEqual(diagnostics_for(provenance_path, valid_provenance), [])
        provenance_cases = [
            {**valid_provenance, "schema": "wrong"},
            {**valid_provenance, "both_builds_succeeded": False},
            {**valid_provenance, "sides": None},
            {**valid_provenance, "sides": []},
            {**valid_provenance, "sides": [valid_side, None]},
            {**valid_provenance, "sides": [
                {"artifact_sha256": "a" * 64},
                {"side": "current", "artifact_sha256": "b" * 64},
            ]},
            {**valid_provenance, "sides": [valid_side, {**valid_side}]},
            {**valid_provenance, "sides": [
                {**valid_side, "artifact_sha256": "invalid"},
                {"side": "current", "artifact_sha256": "b" * 64},
            ]},
            {**valid_provenance, "sides": [
                valid_side,
                {"side": "current", "artifact_sha256": "invalid"},
            ]},
        ]
        for candidate in provenance_cases:
            with self.subTest(provenance=candidate):
                self.assertTrue(diagnostics_for(provenance_path, candidate))

        jars_path = "evidence/dependencies/dependency_jars.json"
        valid_jars = {
            "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
            "items": [{}], "business_artifacts": [], "runtime_closure": {},
        }
        self.assertEqual(diagnostics_for(jars_path, valid_jars), [])
        for candidate in (
            {**valid_jars, "schema": "wrong"},
            {**valid_jars, "items": None},
            {**valid_jars, "items": [None]},
            {**valid_jars, "business_artifacts": None},
            {**valid_jars, "business_artifacts": [None]},
            {**valid_jars, "runtime_closure": []},
        ):
            with self.subTest(dependency_jars=candidate):
                self.assertTrue(diagnostics_for(jars_path, candidate))

        coverage_path = ".runtime/coverage/s3_coverage.json"
        valid_coverage = {
            "schema": "java-upgrade-analyzer.step3-coverage.v1",
            "status": "complete",
            "reason_codes": [], "planned_scans": ["one"], "executed_scans": ["one"],
        }
        self.assertEqual(diagnostics_for(coverage_path, valid_coverage), [])
        for candidate in (
            {**valid_coverage, "schema": "wrong"},
            {**valid_coverage, "status": "wrong"},
            {**valid_coverage, "reason_codes": None},
            {**valid_coverage, "reason_codes": [1]},
            {**valid_coverage, "planned_scans": None},
            {**valid_coverage, "planned_scans": [1]},
            {**valid_coverage, "executed_scans": None},
            {**valid_coverage, "executed_scans": [1]},
        ):
            with self.subTest(step3_coverage=candidate):
                self.assertTrue(diagnostics_for(coverage_path, candidate))

        database_path = "evidence/static_scan/s3_database_contract_summary.json"
        valid_database = {
            "schema": "java-upgrade-analyzer.database-contract-changes.v1",
            "coverage_status": "complete", "change_count": 0, "coverage_gaps": [],
        }
        self.assertEqual(diagnostics_for(database_path, valid_database), [])
        for candidate in (
            {**valid_database, "schema": "wrong"},
            {**valid_database, "coverage_status": "wrong"},
            {**valid_database, "change_count": False},
            {**valid_database, "change_count": -1},
            {**valid_database, "coverage_gaps": None},
            {**valid_database, "coverage_gaps": [1]},
        ):
            with self.subTest(database_summary=candidate):
                self.assertTrue(diagnostics_for(database_path, candidate))
        self.assertEqual(
            diagnostics_for(database_path, {
                **valid_database, "coverage_gaps": ["known-gap"],
            }),
            [],
        )

    def test_step6_internal_csv_iterator_and_text_path_failure_matrix(self):
        class Rows:
            fieldnames = ["a", "b"]

            def __iter__(self):
                return iter((None, {"a": None, "b": "value"}))

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            relative = "evidence/dependencies/rows.csv"
            path = report / relative
            path.parent.mkdir(parents=True)
            path.write_text("a,b\n", encoding="utf-8")
            findings = {"diagnostics": []}
            with patch.object(binary_report.csv, "DictReader", return_value=Rows()):
                binary_report._validate_step6_internal_csv_input(
                    report, relative, "rows", ({"a"}, {"b"}), findings,
                )
            self.assertEqual(findings["diagnostics"], [])

            with patch.object(binary_report, "open_csv_read", side_effect=OSError("unreadable")):
                binary_report._validate_step6_internal_csv_input(
                    report, relative, "rows", ({"a"},), findings,
                )
            self.assertEqual(findings["diagnostics"][-1]["stage"], "csv_load")

            for content in ("", "one line\n"):
                text_regular = report / "evidence/static_scan/s3_jdk_serialization.txt"
                text_regular.parent.mkdir(parents=True, exist_ok=True)
                text_regular.write_text(content, encoding="utf-8")
                binary_report._augment_step6_internal_input_diagnostics(
                    report, {"diagnostics": []},
                )
                text_regular.unlink()

            text_relative = "evidence/static_scan/s3_jdk_serialization.txt"
            text = report / text_relative
            text.parent.mkdir(parents=True, exist_ok=True)
            text.mkdir()
            binary_report._augment_step6_internal_input_diagnostics(report, findings)
            self.assertTrue(any(
                item.get("artifact") == "step3_jdk_serialization"
                and item.get("stage") == "text_load"
                for item in findings["diagnostics"]
            ))

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            external = report / "external"
            external.mkdir(parents=True)
            evidence = report / "evidence"
            evidence.mkdir()
            try:
                (evidence / "static_scan").symlink_to(external, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            text = external / "s3_jdk_serialization.txt"
            text.write_text("value", encoding="utf-8")
            with self.assertRaises(binary_report.BinaryReportError) as captured:
                binary_report._augment_step6_internal_input_diagnostics(
                    report, {"diagnostics": []},
                )
            self.assertTrue(captured.exception.unsafe_parent_path)

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            external = report / "external"
            external.mkdir(parents=True)
            evidence = report / "evidence"
            evidence.mkdir()
            try:
                (evidence / "dependencies").symlink_to(
                    external, target_is_directory=True,
                )
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            (external / "rows.csv").write_text("a\n1\n", encoding="utf-8")
            with self.assertRaises(binary_report.BinaryReportError) as captured:
                binary_report._validate_step6_internal_csv_input(
                    report, "evidence/dependencies/rows.csv", "rows",
                    ({"a"},), {"diagnostics": []},
                )
            self.assertTrue(captured.exception.unsafe_parent_path)

    def test_consistent_step5_reader_release_and_payload_matrix(self):
        release = {
            "step4": {"committed_receipt_identity": "receipt4"},
            "step5": {
                "committed_receipt_identity": "receipt5",
                "publication_input_identity": "input5",
            },
            "active_core": {"result_generation_identity": "generation"},
        }
        snapshot = {
            "snapshot_destinations": ["call", "binary", "index"],
            "binding": {
                "upstream_publication_receipt_identity": "receipt4",
                "publication_input_identity": "input5",
            },
            "committed_receipt_identity": "receipt5",
        }
        data = {
            "result_generation_identity": "generation",
            "step4_publication_receipt_identity": "receipt4",
            "step5_publication_input_identity": "input5",
        }

        def invoke(*, receipt={"present": True}, protocol=True,
                   snapshot_value=snapshot, data_value=data, release_value=release):
            with patch.object(binary_report, "_report_workflow_read_lock", return_value=nullcontext()), patch.object(
                binary_report, "_active_generation_publication_lock", return_value=nullcontext(),
            ), patch.object(binary_report, "report_publication_committed_receipt", return_value=receipt), patch.object(
                binary_report, "report_uses_release_protocol", return_value=protocol,
            ), patch.object(binary_report, "require_current_release_stage", return_value=release_value), patch.object(
                binary_report, "short_temporary_directory", return_value=nullcontext("snapshot-root"),
            ), patch.object(
                binary_report, "materialize_report_publication_committed_snapshot", return_value=snapshot_value,
            ), patch.object(binary_report, "_load_json", return_value=data_value), patch.object(
                binary_report, "_read_csv_rows", return_value=[{"row": "one"}],
            ):
                return binary_report.load_consistent_step5_query_inputs("report")

        legacy = invoke(receipt={}, protocol=False, data_value={"legacy": True})
        self.assertEqual(legacy["index"], {"legacy": True})
        self.assertEqual(legacy["committed_receipt_identity"], "")

        malformed_snapshots = [
            {**snapshot, "snapshot_destinations": None, "binding": None},
            {**snapshot, "committed_receipt_identity": "wrong"},
            {**snapshot, "binding": {**snapshot["binding"], "upstream_publication_receipt_identity": "wrong"}},
            {**snapshot, "binding": {**snapshot["binding"], "publication_input_identity": "wrong"}},
        ]
        for candidate in malformed_snapshots:
            with self.subTest(snapshot=candidate):
                self.assert_reason(
                    "BINARY_STEP5_QUERY_INDEX_RELEASE_MISMATCH",
                    lambda candidate=candidate: invoke(snapshot_value=candidate),
                )
        for field in (
            "result_generation_identity",
            "step4_publication_receipt_identity",
            "step5_publication_input_identity",
        ):
            damaged = {**data, field: "wrong"}
            with self.subTest(index_field=field):
                self.assert_reason(
                    "BINARY_STEP5_QUERY_INDEX_BINDING_MISMATCH",
                    lambda damaged=damaged: invoke(data_value=damaged),
                )
        loaded = invoke()
        self.assertEqual(loaded["alerts"], ({"row": "one"},))
        self.assertEqual(loaded["committed_receipt_identity"], "receipt5")
        empty_receipt_release = {
            **release,
            "step5": {**release["step5"], "committed_receipt_identity": ""},
        }
        self.assertEqual(invoke(
            receipt={}, protocol=True,
            snapshot_value={**snapshot, "committed_receipt_identity": ""},
            release_value=empty_receipt_release,
        )["committed_receipt_identity"], "")

    def test_consistent_step6_reader_release_payload_and_tree_matrix(self):
        release = {
            "step5": {"committed_receipt_identity": "receipt5"},
            "step6": {
                "committed_receipt_identity": "receipt6",
                "publication_input_identity": "input6",
            },
            "active_core": {"result_generation_identity": "generation"},
            "release_identity": "release",
        }
        findings = {
            "schema": "java-upgrade-analyzer.binary-findings.v2",
            "result_generation_identity": "generation",
            "step5_publication_receipt_identity": "receipt5",
            "step6_publication_input_identity": "input6",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            deliverables = root / "deliverables"
            runtime = root / "findings"
            deliverables.mkdir()
            runtime.mkdir()
            (deliverables / "report.md").write_text("report", encoding="utf-8")
            (deliverables / "nested").mkdir()
            link = deliverables / "linked.md"
            try:
                link.symlink_to(deliverables / "report.md")
            except OSError:
                link = None
            snapshot = {
                "snapshot_destinations": [str(deliverables), str(runtime)],
                "binding": {
                    "upstream_publication_receipt_identity": "receipt5",
                    "publication_input_identity": "input6",
                },
                "committed_receipt_identity": "receipt6",
            }

            def invoke(*, snapshot_value=snapshot, findings_value=findings, release_value=release):
                with patch.object(binary_report, "_report_workflow_read_lock", return_value=nullcontext()), patch.object(
                    binary_report, "_active_generation_publication_lock", return_value=nullcontext(),
                ), patch.object(binary_report, "require_current_release_stage", return_value=release_value), patch.object(
                    binary_report, "short_temporary_directory", return_value=nullcontext(str(root / "snapshot")),
                ), patch.object(
                    binary_report, "materialize_report_publication_committed_snapshot", return_value=snapshot_value,
                ), patch.object(binary_report, "_load_json", return_value=findings_value):
                    return binary_report.load_consistent_step6_publication(root)

            malformed = [
                {**snapshot, "snapshot_destinations": None, "binding": None},
                {**snapshot, "committed_receipt_identity": "wrong"},
                {**snapshot, "binding": {**snapshot["binding"], "upstream_publication_receipt_identity": "wrong"}},
                {**snapshot, "binding": {**snapshot["binding"], "publication_input_identity": "wrong"}},
            ]
            for candidate in malformed:
                with self.subTest(snapshot=candidate):
                    self.assert_reason(
                        "BINARY_STEP6_READER_RELEASE_MISMATCH",
                        lambda candidate=candidate: invoke(snapshot_value=candidate),
                    )
            for field in (
                "schema",
                "result_generation_identity",
                "step5_publication_receipt_identity",
                "step6_publication_input_identity",
            ):
                damaged = {**findings, field: "wrong"}
                with self.subTest(findings_field=field):
                    self.assert_reason(
                        "BINARY_STEP6_READER_BINDING_MISMATCH",
                        lambda damaged=damaged: invoke(findings_value=damaged),
                    )
            loaded = invoke()
            self.assertEqual(loaded["deliverable_names"], ("report.md",))
            self.assertEqual(loaded["release_identity"], "release")
            empty_release = {**release, "release_identity": ""}
            empty_release["step6"] = {**release["step6"], "committed_receipt_identity": ""}
            empty_snapshot = {**snapshot, "committed_receipt_identity": ""}
            empty = invoke(snapshot_value=empty_snapshot, release_value=empty_release)
            self.assertEqual(empty["release_identity"], "")
            self.assertEqual(empty["committed_receipt_identity"], "")

    def test_verify_current_step4_release_field_by_field_matrix(self):
        loaded = self._loaded()
        binding = binary_report._loaded_step4_publication_binding(loaded)
        snapshot = {
            "transaction_id": "1" * 32,
            "binding": binding,
            "committed_receipt_identity": "e" * 64,
            "gate_receipt": {
                "gate_name": "binary_generation",
                "strict_risk_gate": False,
            },
            "snapshot_destinations": ["api", "source"],
        }
        summary = {
            "schema": "java-upgrade-analyzer.binary-step4-summary.v1",
            "authority": "binary_first",
            "result_generation_identity": "a" * 64,
            "analysis_context_identity": "9" * 64,
        }
        release = {"step4": {"committed_receipt_identity": "e" * 64}}

        def invoke(*, snapshot_value=snapshot, summary_value=summary,
                   release_value=release, gate="binary_generation", strict=False,
                   workflow=True, active=True):
            with patch.object(binary_report, "_standalone_report_workflow_lock", return_value=nullcontext()), patch.object(
                binary_report, "_active_generation_publication_lock", return_value=nullcontext(),
            ), patch.object(binary_report, "load_validated_generation", return_value=loaded), patch.object(
                binary_report, "short_temporary_directory", return_value=nullcontext("snapshot-root"),
            ), patch.object(
                binary_report, "materialize_report_publication_committed_snapshot", return_value=snapshot_value,
            ), patch.object(binary_report, "_load_json", return_value=summary_value), patch.object(
                binary_report, "require_current_release_stage", return_value=release_value,
            ):
                return binary_report.verify_current_step4_release(
                    "report", expected_gate_name=gate,
                    expected_strict_risk_gate=strict,
                    workflow_lock_held=workflow, active_lock_held=active,
                )

        self.assertEqual(invoke()["committed_receipt_identity"], "e" * 64)
        self.assertEqual(invoke(gate=None, strict=None)["transaction_id"], "1" * 32)
        self.assertEqual(invoke(workflow=False, active=False)["transaction_id"], "1" * 32)
        strict_snapshot = {
            **snapshot,
            "gate_receipt": {
                "gate_name": "binary_generation",
                "strict_risk_gate": True,
            },
        }
        self.assertEqual(
            invoke(snapshot_value=strict_snapshot, strict=True)["transaction_id"],
            "1" * 32,
        )

        for mutation, reason in (
            ({"binding": None, "transaction_id": ""}, "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH"),
            ({"gate_receipt": None}, "BINARY_REPORT_PUBLICATION_GATE_POLICY_MISMATCH"),
            ({"gate_receipt": {"gate_name": "binary_generation", "strict_risk_gate": True}},
             "BINARY_REPORT_PUBLICATION_GATE_POLICY_MISMATCH"),
            ({"snapshot_destinations": None}, "BINARY_STEP4_PUBLICATION_SNAPSHOT_INVALID"),
        ):
            candidate = {**snapshot, **mutation}
            with self.subTest(snapshot_mutation=mutation):
                self.assert_reason(reason, lambda candidate=candidate: invoke(snapshot_value=candidate))
        self.assert_reason(
            "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH",
            lambda: invoke(snapshot_value={**snapshot, "binding": None}),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_GATE_POLICY_MISMATCH",
            lambda: invoke(gate="wrong"),
        )
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_GATE_POLICY_MISMATCH",
            lambda: invoke(strict=True),
        )
        strict_mismatch_without_transaction = {
            **snapshot,
            "transaction_id": "",
        }
        self.assert_reason(
            "BINARY_REPORT_PUBLICATION_GATE_POLICY_MISMATCH",
            lambda: invoke(
                snapshot_value=strict_mismatch_without_transaction,
                strict=True,
            ),
        )
        for field in (
            "schema", "authority", "result_generation_identity", "analysis_context_identity",
        ):
            damaged = {**summary, field: "wrong"}
            with self.subTest(summary_field=field):
                self.assert_reason(
                    "BINARY_STEP4_PUBLICATION_SUMMARY_MISMATCH",
                    lambda damaged=damaged: invoke(summary_value=damaged),
                )
        self.assert_reason(
            "BINARY_GLOBAL_RELEASE_STEP4_RECEIPT_MISMATCH",
            lambda: invoke(release_value={"step4": {"committed_receipt_identity": "wrong"}}),
        )


if __name__ == "__main__":
    unittest.main()
