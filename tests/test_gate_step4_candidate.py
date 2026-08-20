import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import gate  # noqa: E402
from s4_contract import ALL_CHANGED_APIS_FIELDS, make_per_dependency_dirname  # noqa: E402


class Step4CandidateGateTest(unittest.TestCase):
    def _write_csv(self, path, fields, rows=()):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def _fixture(self, root):
        generation = "a" * 64
        analysis_context = "d" * 64
        change_fact_identity = "f" * 64
        decision_identity = "e" * 64
        api = root / "candidate-api"
        source = root / "candidate-source"
        api.mkdir()
        source.mkdir()
        coord = "com.acme:api"
        decision = {
            "decision_identity": decision_identity,
            "change_fact_identity": change_fact_identity,
            "fact_kind": "method",
            "reason_code": "BINARY_MEMBER_REMOVED",
            "fact_scope": {
                "class_name": "com/acme/Api",
                "member_name": "work",
                "member_kind": "method",
                "descriptor": "()V",
                "member_change_kind": "removed",
            },
            "dependency_artifacts": [
                {
                    "side": "base",
                    "coord": "com.acme:api:1.0",
                    "logical_dependency_lineage": coord,
                },
                {
                    "side": "current",
                    "coord": "com.acme:api:2.0",
                    "logical_dependency_lineage": coord,
                },
            ],
            "evidence": {},
        }
        assessment = {
            "decision_identity": decision_identity,
            "change_fact_identity": change_fact_identity,
            "analysis_projection_status": "targetable",
            "projection_coverage_status": "complete",
        }
        loaded = {
            "manifest": {
                "result_generation_identity": generation,
                "analysis_context_identity": analysis_context,
            },
            "summary": {
                "decision_coverage_status": "complete",
                "trace_coverage_status": "complete",
            },
            "decisions": {
                "authoritative_change_facts": [decision],
                "diagnostic_candidate_facts": [],
                "excluded_decisions": [],
            },
            "projections": {
                "authoritative_projection_assessments": [assessment],
                "confirmed_unprojectable_facts": [],
            },
            "coverage": {},
            "source_attestation": {},
            "source_explanations": {
                "declarations": [],
                "candidate_relationships": [],
            },
        }
        api_row = {field: "" for field in ALL_CHANGED_APIS_FIELDS}
        api_row.update(gate._step4_decision_projection(decision))
        api_row["evidence_path"] = (
            ".runtime/binary_generations/current/binary_decisions.json"
        )
        self._write_csv(api / "all_changed_apis.csv", ALL_CHANGED_APIS_FIELDS, (api_row,))
        detail = (
            f"s4_per_dependency/{make_per_dependency_dirname(coord)}/summary.md"
        )
        self._write_csv(
            api / "changed_dependencies.csv",
            ("coord", "changed_api_count", "detail"),
            ({"coord": coord, "changed_api_count": "1", "detail": detail},),
        )
        (api / "changed_dependencies.md").write_text("# dependencies\n", encoding="utf-8")
        (api / "summary.md").write_text("# summary\n", encoding="utf-8")
        (api / "review.md").write_text("# review\n", encoding="utf-8")
        self._write_csv(
            api / "business_bytecode_changed_api_refs.csv", ("coord",)
        )
        (api / "business_bytecode_priority_evidence.json").write_text(
            "{}\n", encoding="utf-8"
        )
        detail_path = api / detail
        detail_path.parent.mkdir(parents=True)
        detail_path.write_text("# detail\n", encoding="utf-8")
        summary = {
            "schema": "java-upgrade-analyzer.binary-step4-summary.v1",
            "authority": "binary_first",
            "result_generation_identity": generation,
            "analysis_context_identity": analysis_context,
            "published_api_change_count": 1,
            "dependency_count": 1,
            "authoritative_change_fact_count": 1,
            "targetable_change_fact_count": 1,
            "confirmed_unprojectable_fact_count": 0,
            "diagnostic_candidate_fact_count": 0,
            "excluded_decision_count": 0,
            "decision_coverage_status": "complete",
            "trace_coverage_status": "complete",
            "coverage": {},
        }
        source_inputs, method_rows, candidate_rows, gap_rows = (
            gate._step4_source_truth(loaded)
        )
        summary["source_inputs"] = source_inputs
        (api / "summary.json").write_text(
            json.dumps(summary), encoding="utf-8"
        )

        (source / "review.md").write_text(
            gate._step4_expected_source_review(
                source_inputs, method_rows, candidate_rows
            ),
            encoding="utf-8",
        )
        self._write_csv(
            source / "method_mappings.csv",
            ("源码归属", "归属类型", "二进制制品", "二进制方法", "源码位置", "模块", "语言",
             "源码声明", "注解", "修饰符"),
        )
        self._write_csv(
            source / "candidate_relationships.csv",
            ("源码归属", "二进制制品", "调用方", "源码位置", "候选目标", "证据类型", "置信度", "权威边界"),
        )
        self._write_csv(
            source / "coverage_gaps.csv",
            ("原因", "语言", "源码归属", "模块", "源码文件", "解析器", "错误节点"),
        )
        (source / "source_snapshot.json").write_text("{}\n", encoding="utf-8")
        return api, source, loaded

    def test_candidate_gate_validates_both_private_destinations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            api, source, loaded = self._fixture(root)
            with patch.object(gate, "load_validated_generation", return_value=loaded), patch.object(gate, "ok"):
                gate.gate_binary_generation(
                    root,
                    candidate_api_dir=api,
                    candidate_source_dir=source,
                    candidate_activation_identity="b" * 64,
                )

    def test_candidate_gate_rejects_missing_or_unbound_source_evidence(self):
        for mutation in ("missing_review", "snapshot_mismatch", "missing_dependency_detail"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                api, source, loaded = self._fixture(root)
                if mutation == "missing_review":
                    (source / "review.md").unlink()
                elif mutation == "snapshot_mismatch":
                    (source / "source_snapshot.json").write_text(
                        '{"forged":true}\n', encoding="utf-8"
                    )
                else:
                    next((api / "s4_per_dependency").glob("*/summary.md")).unlink()
                with patch.object(
                    gate, "load_validated_generation", return_value=loaded
                ), self.assertRaises(SystemExit):
                    gate.gate_binary_generation(
                        root,
                        candidate_api_dir=api,
                        candidate_source_dir=source,
                        candidate_activation_identity="b" * 64,
                    )

    def test_candidate_gate_rejects_self_consistent_but_forged_truth(self):
        for mutation in (
            "api_semantics",
            "summary_truth_count",
            "source_review",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                api, source, loaded = self._fixture(root)
                if mutation == "api_semantics":
                    with (api / "all_changed_apis.csv").open(
                        encoding="utf-8-sig", newline=""
                    ) as handle:
                        rows = list(csv.DictReader(handle))
                    rows[0]["api_name"] = "forged.Api.call"
                    rows[0]["change_type"] = "BEHAVIOR_CHANGED"
                    rows[0]["severity"] = "P9"
                    self._write_csv(
                        api / "all_changed_apis.csv",
                        ALL_CHANGED_APIS_FIELDS,
                        rows,
                    )
                elif mutation == "summary_truth_count":
                    path = api / "summary.json"
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    payload["authoritative_change_fact_count"] = 99
                    path.write_text(json.dumps(payload), encoding="utf-8")
                else:
                    (source / "review.md").write_text(
                        "# 看起来正常但不是事实渲染\n", encoding="utf-8"
                    )
                with patch.object(
                    gate, "load_validated_generation", return_value=loaded
                ), self.assertRaises(SystemExit):
                    gate.gate_binary_generation(
                        root,
                        candidate_api_dir=api,
                        candidate_source_dir=source,
                        candidate_activation_identity="b" * 64,
                    )


class Step5CandidateGateTest(unittest.TestCase):
    def _fixture(self, root):
        generation = "a" * 64
        upstream = "b" * 64
        publication_input = "c" * 64
        reported_identity = "r" * 64
        change_fact_identity = "f" * 64
        decision_identity = "e" * 64
        identity = (
            "com.acme:api|com.acme.Api.work|()|method|REMOVED|"
            + change_fact_identity
        )
        call_chain = root / "candidate-call-chain"
        binary_analysis = root / "candidate-binary-analysis"
        indexes = root / "candidate-indexes"
        by_api = call_chain / "by_api"
        by_api.mkdir(parents=True)
        binary_analysis.mkdir()
        indexes.mkdir()
        item = {
            "api_identity": identity,
            "reported_api_identity": reported_identity,
            "coord": "com.acme:api",
            "api": "com.acme.Api.work",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "change_fact_identity": change_fact_identity,
            "decision_identity": decision_identity,
            "old_version": "",
            "new_version": "",
            "analysis_status": "reachable",
            "call_paths": [
                "biz.Main.run() → com.acme.Api.work()"
            ],
            "path_details": [{
                "path_status": "reachable",
                "path_text": "biz.Main.run() → com.acme.Api.work()",
                "path_certainty": "",
                "entry_kinds": [],
                "entry_kind_labels": [],
                "entrypoint_dependency_coords": [],
                "entrypoint_activation_reasons": [],
                "mechanism_kinds": [],
                "mechanism_labels": [],
            }],
            "path_set_complete": False,
            "exact_path_exists": False,
            "possible_path_exists": False,
            "impact_conclusion": "",
            "static_linkage_status": "",
            "runtime_verification_status": "",
        }
        scope = {
            "schema": "java-upgrade-analyzer.binary-step5-selection.v1",
            "result_generation_identity": generation,
            "step4_publication_receipt_identity": upstream,
            "step5_publication_input_identity": publication_input,
            "included_reported_api_identities": [reported_identity],
            "included_api_count": 1,
            "analyzed_api_count": 1,
            "total_api_count": 1,
            "excluded_api_count": 0,
            "mode": "full",
            "validation_status": "passed",
            "selected_coords": [],
            "selected_names": [],
            "included_dependency_coords": ["com.acme:api"],
            "excluded_dependency_coords": [],
            "available_dependency_count": 1,
            "included_dependency_count": 1,
        }
        summary = {
            "schema": "java-upgrade-analyzer.binary-step5-summary.v1",
            "authority": "binary_first",
            "result_generation_identity": generation,
            "step4_publication_receipt_identity": upstream,
            "step5_publication_input_identity": publication_input,
            "total_apis": 1,
            "reachable": 1,
            "uncertain": 0,
            "not_found_in_static_analysis": 0,
            "not_analyzed": 0,
            "not_impacted": 0,
            "reachable_apis": [item],
            "uncertain_apis": [],
            "not_found_apis": [],
            "not_analyzed_apis": [],
            "not_impacted_apis": [],
            "resource_activation_results": [],
            "analysis_scope": scope,
        }
        for name, value in (
            ("summary.json", summary),
            ("selection.json", scope),
            ("coverage.json", {
                "schema": "java-upgrade-analyzer.coverage.v1"
            }),
        ):
            (call_chain / name).write_text(
                json.dumps(value), encoding="utf-8"
            )
        count_text = (
            "# summary\n"
            "- 变化 API：1\n"
            "- 已发现静态可执行路径：1\n"
            "- 结论不确定：0\n"
            "- 未完成分析：0\n"
        )
        (call_chain / "summary.md").write_text(count_text, encoding="utf-8")
        with (call_chain / "alerts.csv").open(
            "w", encoding="utf-8-sig", newline=""
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=(
                "api_identity", "target_coord", "changed_symbol",
                "api_signature", "symbol_kind", "change_type",
                "reported_api_identity", "change_fact_identity",
                "decision_identity",
                "path_status", "path_text",
            ))
            writer.writeheader()
            writer.writerow({
                "api_identity": identity,
                "target_coord": "com.acme:api",
                "changed_symbol": "com.acme.Api.work",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "reported_api_identity": reported_identity,
                "change_fact_identity": change_fact_identity,
                "decision_identity": decision_identity,
                "path_status": "reachable",
                "path_text": "biz.Main.run() → com.acme.Api.work()",
            })
        (by_api / "item.json").write_text(
            json.dumps(item), encoding="utf-8"
        )
        (binary_analysis / "system-reachability.md").write_text(
            count_text.replace("# summary", "# binary"), encoding="utf-8"
        )
        query_index = {
            "schema": "java-upgrade-analyzer.s5-query-index.v1",
            "result_generation_identity": generation,
            "step4_publication_receipt_identity": upstream,
            "step5_publication_input_identity": publication_input,
            "target_apis": [{
                "coord": "com.acme:api",
                "api_name": "com.acme.Api.work",
                "api_signature": "()",
                "symbol_kind": "method",
                "api_identity": identity,
                "reported_api_identity": reported_identity,
                "change_fact_identity": change_fact_identity,
                "decision_identity": decision_identity,
                "change_type": "REMOVED",
            }],
        }
        (indexes / "s5_query_index.json").write_text(
            json.dumps(query_index), encoding="utf-8"
        )
        loaded = {
            "manifest": {"result_generation_identity": generation},
            "active": {
                "validation_run_identity": "1" * 64,
                "validation_result_sha256": "2" * 64,
                "activation_identity": "3" * 64,
            },
            "summary": {"trace_coverage_status": "complete"},
            "formal": {"by_api": [{
                "reported_api_identity": reported_identity,
                "display_owner": "com/acme/Api",
                "display_member": "work",
                "display_descriptor": "()V",
                "display_member_kind": "method",
                "reachability_status": "reachable",
                "contributing_change_fact_ids": [change_fact_identity],
                "dependency_artifacts": [{
                    "logical_dependency_lineage": "com.acme:api",
                }],
                "paths": [{
                    "path_text": "biz.Main.run() → com.acme.Api.work()",
                }],
            }], "resource_activation_results": []},
        }
        loaded["_test_step4_rows"] = [{
            **{field: "" for field in ALL_CHANGED_APIS_FIELDS},
            "coord": "com.acme:api",
            "api_name": "com.acme.Api.work",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
            "change_fact_identity": change_fact_identity,
            "decision_identity": decision_identity,
        }]
        binding = {
            "upstream_publication_receipt_identity": upstream,
            "publication_input_identity": publication_input,
        }
        return call_chain, binary_analysis, indexes, loaded, binding

    def test_candidate_gate_validates_every_step5_transaction_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            call_chain, binary_analysis, indexes, loaded, binding = (
                self._fixture(root)
            )
            with patch.object(
                gate, "load_validated_generation", return_value=loaded
            ), patch.object(
                gate,
                "_load_current_step4_api_rows",
                return_value=(
                    loaded["_test_step4_rows"],
                    {"committed_receipt_identity": "b" * 64},
                ),
            ), patch.object(
                gate,
                "_step5_publication_input_identity",
                return_value=binding["publication_input_identity"],
            ), patch.object(gate, "ok"):
                gate.gate_binary_report(
                    root,
                    candidate_call_chain_dir=call_chain,
                    candidate_binary_analysis_dir=binary_analysis,
                    candidate_index_dir=indexes,
                    candidate_publication_binding=binding,
                )

    def test_step5_gate_uses_step4_public_symbol_kind_for_fact_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            call_chain, binary_analysis, indexes, loaded, binding = (
                self._fixture(root)
            )
            fact_identity = loaded["_test_step4_rows"][0][
                "change_fact_identity"
            ]
            loaded["_test_step4_rows"][0]["symbol_kind"] = "constructor"
            expected_identity = (
                "com.acme:api|com.acme.Api.work|()|constructor|REMOVED|"
                + fact_identity
            )

            summary_path = call_chain / "summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary_item = summary["reachable_apis"][0]
            summary_item["symbol_kind"] = "constructor"
            summary_item["api_identity"] = expected_identity
            summary_path.write_text(json.dumps(summary), encoding="utf-8")

            detail_path = next((call_chain / "by_api").glob("*.json"))
            detail = json.loads(detail_path.read_text(encoding="utf-8"))
            detail["symbol_kind"] = "constructor"
            detail["api_identity"] = expected_identity
            detail_path.write_text(json.dumps(detail), encoding="utf-8")

            alerts_path = call_chain / "alerts.csv"
            with alerts_path.open(
                encoding="utf-8-sig", newline=""
            ) as handle:
                reader = csv.DictReader(handle)
                alert_fields = list(reader.fieldnames or ())
                alert_rows = list(reader)
            alert_rows[0]["symbol_kind"] = "constructor"
            alert_rows[0]["api_identity"] = expected_identity
            with alerts_path.open(
                "w", encoding="utf-8-sig", newline=""
            ) as handle:
                writer = csv.DictWriter(handle, fieldnames=alert_fields)
                writer.writeheader()
                writer.writerows(alert_rows)

            index_path = indexes / "s5_query_index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["target_apis"][0]["symbol_kind"] = "constructor"
            index["target_apis"][0]["api_identity"] = expected_identity
            index_path.write_text(json.dumps(index), encoding="utf-8")

            with patch.object(
                gate, "load_validated_generation", return_value=loaded
            ), patch.object(
                gate,
                "_load_current_step4_api_rows",
                return_value=(
                    loaded["_test_step4_rows"],
                    {"committed_receipt_identity": "b" * 64},
                ),
            ), patch.object(
                gate,
                "_step5_publication_input_identity",
                return_value=binding["publication_input_identity"],
            ), patch.object(gate, "ok"):
                gate.gate_binary_report(
                    root,
                    candidate_call_chain_dir=call_chain,
                    candidate_binary_analysis_dir=binary_analysis,
                    candidate_index_dir=indexes,
                    candidate_publication_binding=binding,
                )

    def test_candidate_gate_rejects_cross_view_identity_mismatch(self):
        for mutation in (
            "by_api", "index", "binding", "coverage_path",
            "mode", "unmatched_selector", "not_impacted",
            "formal_path_semantics", "generation_omission",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                call_chain, binary_analysis, indexes, loaded, binding = (
                    self._fixture(root)
                )
                if mutation == "by_api":
                    detail = next((call_chain / "by_api").glob("*.json"))
                    payload = json.loads(detail.read_text(encoding="utf-8"))
                    payload["api_identity"] = "forged"
                    detail.write_text(json.dumps(payload), encoding="utf-8")
                elif mutation == "index":
                    index = indexes / "s5_query_index.json"
                    payload = json.loads(index.read_text(encoding="utf-8"))
                    payload["target_apis"] = []
                    index.write_text(json.dumps(payload), encoding="utf-8")
                elif mutation == "binding":
                    binding = {**binding, "publication_input_identity": "d" * 64}
                elif mutation == "coverage_path":
                    coverage_path = call_chain / "coverage.json"
                    payload = json.loads(
                        coverage_path.read_text(encoding="utf-8")
                    )
                    payload["components"] = [{
                        "id": "forged",
                        "evidence": ["../outside-secret"],
                    }]
                    coverage_path.write_text(
                        json.dumps(payload), encoding="utf-8"
                    )
                elif mutation in {"mode", "unmatched_selector"}:
                    selection_path = call_chain / "selection.json"
                    selection = json.loads(
                        selection_path.read_text(encoding="utf-8")
                    )
                    if mutation == "mode":
                        selection["mode"] = "garbage"
                    else:
                        selection["mode"] = "partial"
                        selection["selected_coords"] = [
                            "com.acme:api", "typo:missing"
                        ]
                    selection_path.write_text(
                        json.dumps(selection), encoding="utf-8"
                    )
                    summary_path = call_chain / "summary.json"
                    summary = json.loads(
                        summary_path.read_text(encoding="utf-8")
                    )
                    summary["analysis_scope"] = selection
                    summary_path.write_text(
                        json.dumps(summary), encoding="utf-8"
                    )
                elif mutation == "not_impacted":
                    summary_path = call_chain / "summary.json"
                    summary = json.loads(
                        summary_path.read_text(encoding="utf-8")
                    )
                    summary["not_impacted"] = 1
                    summary["not_impacted_apis"] = [
                        dict(summary["reachable_apis"][0])
                    ]
                    summary_path.write_text(
                        json.dumps(summary), encoding="utf-8"
                    )
                elif mutation == "formal_path_semantics":
                    summary_path = call_chain / "summary.json"
                    summary = json.loads(
                        summary_path.read_text(encoding="utf-8")
                    )
                    forged = summary["reachable_apis"][0]
                    forged["path_details"][0]["path_certainty"] = "possible"
                    forged["possible_path_exists"] = True
                    forged["impact_conclusion"] = "forged"
                    summary_path.write_text(
                        json.dumps(summary), encoding="utf-8"
                    )
                    detail = next((call_chain / "by_api").glob("*.json"))
                    detail.write_text(json.dumps(forged), encoding="utf-8")
                else:
                    second_reported = "9" * 64
                    second_fact = "8" * 64
                    loaded["formal"]["by_api"].append({
                        **loaded["formal"]["by_api"][0],
                        "reported_api_identity": second_reported,
                        "contributing_change_fact_ids": [second_fact],
                    })
                    loaded["_test_step4_rows"].append({
                        **loaded["_test_step4_rows"][0],
                        "change_fact_identity": second_fact,
                        "decision_identity": "7" * 64,
                    })
                with patch.object(
                    gate, "load_validated_generation", return_value=loaded
                ), patch.object(
                    gate,
                    "_load_current_step4_api_rows",
                    return_value=(
                        loaded["_test_step4_rows"],
                        {"committed_receipt_identity": "b" * 64},
                    ),
                ), patch.object(
                    gate,
                    "_step5_publication_input_identity",
                    return_value="c" * 64,
                ), self.assertRaises(SystemExit):
                    gate.gate_binary_report(
                        root,
                        candidate_call_chain_dir=call_chain,
                        candidate_binary_analysis_dir=binary_analysis,
                        candidate_index_dir=indexes,
                        candidate_publication_binding=binding,
                    )


class Step6CandidateGateCliTest(unittest.TestCase):
    def test_cli_persists_step6_owner_when_candidate_validation_fails(self):
        binding = {
            "result_generation_identity": "a" * 64,
            "validation_run_identity": "b" * 64,
            "validation_result_sha256": "c" * 64,
            "upstream_publication_receipt_identity": "d" * 64,
            "publication_input_identity": "e" * 64,
            "report_implementation_identity": "f" * 64,
        }
        failure = gate.BinaryFirstContractError(
            "BINARY_STEP6_INTERNAL_INPUT_INVALID",
            "context changed after render",
        )
        failure.owner_step = "step2"
        failure.failure_contract = {
            "schema": "java-upgrade-analyzer.step6-internal-input-failure.v1",
            "status": "failed",
            "owner_step": "step2",
            "failures": [{"owner_step": "step2"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            deliverables = root / "candidate-deliverables"
            findings = root / "candidate-findings"
            result_path = root / "gate-result.json"
            deliverables.mkdir()
            findings.mkdir()
            with patch.object(
                sys,
                "argv",
                [
                    "gate.py",
                    "--step", "binary_final_report",
                    "--report-dir", str(root),
                    "--publication-transaction-id", "1" * 32,
                    "--publication-binding-json", json.dumps(binding),
                    "--publication-content-identity", "2" * 64,
                    "--result-json", str(result_path),
                ],
            ), patch.object(
                gate,
                "materialize_report_publication_gate_candidate",
                return_value={
                    "candidate_destinations": [
                        str(deliverables), str(findings)
                    ]
                },
            ), patch.object(
                gate,
                "_validate_step6_candidate_under_parent_workflow_lock",
                side_effect=failure,
            ), self.assertRaises(SystemExit):
                gate.main()
            result = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertEqual(result["owner_step"], "step2")
        self.assertEqual(result["failure_contract"], failure.failure_contract)

    def test_cli_routes_cas_bound_step6_candidate_to_final_report_gate(self):
        binding = {
            "result_generation_identity": "a" * 64,
            "validation_run_identity": "b" * 64,
            "validation_result_sha256": "c" * 64,
            "upstream_publication_receipt_identity": "d" * 64,
            "publication_input_identity": "e" * 64,
            "report_implementation_identity": "f" * 64,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            deliverables = root / "candidate-deliverables"
            findings = root / "candidate-findings"
            deliverables.mkdir()
            findings.mkdir()
            with patch.object(
                sys,
                "argv",
                [
                    "gate.py",
                    "--step", "binary_final_report",
                    "--report-dir", str(root),
                    "--publication-transaction-id", "1" * 32,
                    "--publication-binding-json", json.dumps(binding),
                    "--publication-content-identity", "2" * 64,
                ],
            ), patch.object(
                gate,
                "materialize_report_publication_gate_candidate",
                return_value={
                    "candidate_destinations": [
                        str(deliverables), str(findings)
                    ]
                },
            ), patch.object(
                gate, "gate_binary_final_report"
            ) as final_gate:
                gate.main()

        final_gate.assert_called_once_with(
            root,
            candidate_deliverables_dir=str(deliverables),
            candidate_findings_dir=str(findings),
            candidate_publication_binding=binding,
        )

    def test_candidate_final_gate_uses_explicit_parent_lock_validator(self):
        binding = {"publication_input_identity": "a" * 64}
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            gate,
            "_validate_step6_candidate_under_parent_workflow_lock",
        ) as under_parent, patch.object(
            gate, "validate_step6_publication_candidate"
        ) as public_validator, patch.object(gate, "ok"):
            root = Path(tmp).resolve()
            gate.gate_binary_final_report(
                root,
                candidate_deliverables_dir=root / "deliverables",
                candidate_findings_dir=root / "findings",
                candidate_publication_binding=binding,
            )

        under_parent.assert_called_once_with(
            root,
            candidate_deliverables_dir=root / "deliverables",
            candidate_findings_dir=root / "findings",
            candidate_publication_binding=binding,
        )
        public_validator.assert_not_called()

    def test_committed_final_gate_uses_public_locking_validator(self):
        binding = {"publication_input_identity": "a" * 64}
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            gate,
            "materialize_report_publication_committed_snapshot",
            return_value={
                "snapshot_destinations": [
                    str(Path(tmp) / "deliverables"),
                    str(Path(tmp) / "findings"),
                ],
                "binding": binding,
            },
        ), patch.object(
            gate, "validate_step6_publication_candidate"
        ) as public_validator, patch.object(
            gate,
            "_validate_step6_candidate_under_parent_workflow_lock",
        ) as under_parent, patch.object(gate, "ok"):
            root = Path(tmp).resolve()
            gate.gate_binary_final_report(root)

        public_validator.assert_called_once_with(
            root,
            candidate_deliverables_dir=Path(tmp) / "deliverables",
            candidate_findings_dir=Path(tmp) / "findings",
            candidate_publication_binding=binding,
        )
        under_parent.assert_not_called()


if __name__ == "__main__":
    unittest.main()
