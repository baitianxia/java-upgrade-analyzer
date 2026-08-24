import csv
import json
import sys
import tempfile
import unittest
from copy import deepcopy
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

    def _assert_candidate_rejected(
        self, root, api, source, loaded, *, strict_risk_gate=False,
    ):
        with patch.object(
            gate, "load_validated_generation", return_value=loaded
        ), patch.object(gate.sys, "stderr"), self.assertRaises(SystemExit):
            gate.gate_binary_generation(
                root,
                strict_risk_gate=strict_risk_gate,
                candidate_api_dir=api,
                candidate_source_dir=source,
                candidate_activation_identity="b" * 64,
            )

    @staticmethod
    def _json(path):
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _write_json(path, payload):
        path.write_text(json.dumps(payload), encoding="utf-8")

    @staticmethod
    def _csv(path):
        with path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            return list(reader.fieldnames or ()), list(reader)

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

    def test_candidate_gate_accepts_default_empty_and_strict_views(self):
        for variant in (
            "default_locations", "empty_generation", "diagnostic_sets",
            "strict_complete",
        ):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                api, source, loaded = self._fixture(root)
                if variant == "default_locations":
                    expected_api = gate.evidence_api_changes_dir(root)
                    expected_source = root / gate.EVIDENCE_DIRNAME / "source_analysis"
                    expected_api.parent.mkdir(parents=True, exist_ok=True)
                    api.rename(expected_api)
                    source.rename(expected_source)
                    api, source = expected_api, expected_source
                    candidate_api = candidate_source = None
                else:
                    candidate_api, candidate_source = api, source
                if variant == "empty_generation":
                    loaded["decisions"]["authoritative_change_facts"] = []
                    loaded["projections"][
                        "authoritative_projection_assessments"
                    ] = []
                    self._write_csv(
                        api / "all_changed_apis.csv", ALL_CHANGED_APIS_FIELDS, ()
                    )
                    self._write_csv(
                        api / "changed_dependencies.csv",
                        ("coord", "changed_api_count", "detail"), (),
                    )
                    summary_path = api / "summary.json"
                    summary = self._json(summary_path)
                    for key in (
                        "published_api_change_count", "dependency_count",
                        "authoritative_change_fact_count",
                        "targetable_change_fact_count",
                        "confirmed_unprojectable_fact_count",
                        "diagnostic_candidate_fact_count",
                        "excluded_decision_count",
                    ):
                        summary[key] = 0
                    self._write_json(summary_path, summary)
                    detail = next(
                        (api / "s4_per_dependency").glob("*/summary.md")
                    )
                    detail.unlink()
                    detail.parent.rmdir()
                elif variant == "diagnostic_sets":
                    loaded["decisions"]["diagnostic_candidate_facts"] = [
                        {"decision_identity": "diagnostic"}
                    ]
                    loaded["decisions"]["excluded_decisions"] = [
                        {"decision_identity": "excluded"}
                    ]
                    summary_path = api / "summary.json"
                    summary = self._json(summary_path)
                    summary["diagnostic_candidate_fact_count"] = 1
                    summary["excluded_decision_count"] = 1
                    self._write_json(summary_path, summary)
                elif variant == "strict_complete":
                    # A non-file lookalike must not be counted as a published detail.
                    (api / "s4_per_dependency" / "ignored" / "summary.md").mkdir(
                        parents=True
                    )
                    linked = api / "s4_per_dependency" / "linked" / "summary.md"
                    linked.parent.mkdir(parents=True)
                    try:
                        linked.symlink_to(api / "summary.md")
                    except OSError:
                        # Native Windows may forbid unprivileged symlink creation.
                        pass
                with patch.object(
                    gate, "load_validated_generation", return_value=loaded
                ), patch.object(gate, "ok"):
                    gate.gate_binary_generation(
                        root,
                        strict_risk_gate=(variant == "strict_complete"),
                        candidate_api_dir=candidate_api,
                        candidate_source_dir=candidate_source,
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

    def test_candidate_gate_rejects_every_generation_contract_boundary(self):
        mutations = (
            "summary_schema", "summary_authority", "summary_generation",
            "summary_context", "decisions_missing", "projections_missing",
            "truth_not_list", "truth_non_object", "empty_decision_identity",
            "empty_fact_identity", "duplicate_decision_identity",
            "duplicate_fact_identity", "empty_assessment_identity",
            "duplicate_assessment_identity", "assessment_set_mismatch",
            "unsupported_partition", "invalid_projection_status",
            "unprojectable_partition_mismatch", "empty_unprojectable_identity",
            "duplicate_dependency_coord",
            "empty_api_coord", "unbound_api_coord", "coord_set_mismatch",
            "published_api_count", "published_api_count_zero",
            "published_dependency_count", "published_dependency_count_zero",
            "changed_api_count_not_integer", "changed_api_count_empty",
            "changed_api_count_mismatch",
            "empty_api_fact_identity", "duplicate_api_fact_identity",
            "evidence_path_missing", "per_dependency_not_directory",
            "per_dependency_symlink", "detail_is_directory",
            "detail_is_symlink", "declared_detail_mismatch",
            "source_inputs_mismatch", "source_inputs_empty",
            "method_mapping_mismatch",
            "candidate_relationship_mismatch", "coverage_gap_mismatch",
            "strict_incomplete_coverage",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                api, source, loaded = self._fixture(root)
                summary_path = api / "summary.json"
                summary = self._json(summary_path)
                api_path = api / "all_changed_apis.csv"
                api_fields, api_rows = self._csv(api_path)
                dependency_path = api / "changed_dependencies.csv"
                dependency_fields, dependency_rows = self._csv(dependency_path)
                decision = loaded["decisions"]["authoritative_change_facts"][0]
                assessment = loaded["projections"][
                    "authoritative_projection_assessments"
                ][0]

                if mutation.startswith("summary_"):
                    key = mutation.removeprefix("summary_")
                    field = {
                        "schema": "schema", "authority": "authority",
                        "generation": "result_generation_identity",
                        "context": "analysis_context_identity",
                    }[key]
                    summary[field] = "forged"
                    self._write_json(summary_path, summary)
                elif mutation == "decisions_missing":
                    loaded["decisions"] = None
                elif mutation == "projections_missing":
                    loaded["projections"] = None
                elif mutation == "truth_not_list":
                    loaded["decisions"]["diagnostic_candidate_facts"] = {}
                elif mutation == "truth_non_object":
                    loaded["decisions"]["excluded_decisions"] = [None]
                elif mutation == "empty_decision_identity":
                    decision["decision_identity"] = ""
                elif mutation == "empty_fact_identity":
                    decision["change_fact_identity"] = ""
                elif mutation == "duplicate_decision_identity":
                    duplicate = deepcopy(decision)
                    duplicate["change_fact_identity"] = "9" * 64
                    loaded["decisions"]["authoritative_change_facts"].append(
                        duplicate
                    )
                elif mutation == "duplicate_fact_identity":
                    duplicate = deepcopy(decision)
                    duplicate["decision_identity"] = "9" * 64
                    loaded["decisions"]["authoritative_change_facts"].append(
                        duplicate
                    )
                elif mutation == "empty_assessment_identity":
                    assessment["decision_identity"] = ""
                elif mutation == "duplicate_assessment_identity":
                    loaded["projections"][
                        "authoritative_projection_assessments"
                    ].append(deepcopy(assessment))
                elif mutation == "assessment_set_mismatch":
                    assessment["decision_identity"] = "9" * 64
                elif mutation == "unsupported_partition":
                    assessment["analysis_projection_status"] = "unsupported"
                    loaded["projections"][
                        "confirmed_unprojectable_facts"
                    ] = [{"decision_identity": decision["decision_identity"]}]
                elif mutation == "invalid_projection_status":
                    assessment["analysis_projection_status"] = "invalid"
                elif mutation == "unprojectable_partition_mismatch":
                    loaded["projections"][
                        "confirmed_unprojectable_facts"
                    ] = [{"decision_identity": "9" * 64}]
                elif mutation == "empty_unprojectable_identity":
                    loaded["projections"][
                        "confirmed_unprojectable_facts"
                    ] = [{"decision_identity": ""}]
                elif mutation == "duplicate_dependency_coord":
                    dependency_rows.append(deepcopy(dependency_rows[0]))
                    self._write_csv(
                        dependency_path, dependency_fields, dependency_rows
                    )
                elif mutation in {"empty_api_coord", "unbound_api_coord"}:
                    api_rows[0]["coord"] = (
                        "" if mutation == "empty_api_coord"
                        else "UNBOUND_RUNTIME_ARTIFACT"
                    )
                    self._write_csv(api_path, api_fields, api_rows)
                elif mutation == "coord_set_mismatch":
                    dependency_rows[0]["coord"] = "forged:coord"
                    self._write_csv(
                        dependency_path, dependency_fields, dependency_rows
                    )
                elif mutation == "published_api_count":
                    summary["published_api_change_count"] = 2
                    self._write_json(summary_path, summary)
                elif mutation == "published_api_count_zero":
                    summary["published_api_change_count"] = 0
                    self._write_json(summary_path, summary)
                elif mutation == "published_dependency_count":
                    summary["dependency_count"] = 2
                    self._write_json(summary_path, summary)
                elif mutation == "published_dependency_count_zero":
                    summary["dependency_count"] = 0
                    self._write_json(summary_path, summary)
                elif mutation in {
                    "changed_api_count_not_integer", "changed_api_count_empty",
                    "changed_api_count_mismatch",
                }:
                    dependency_rows[0]["changed_api_count"] = (
                        "not-an-int"
                        if mutation == "changed_api_count_not_integer" else "2"
                    )
                    if mutation == "changed_api_count_empty":
                        dependency_rows[0]["changed_api_count"] = ""
                    self._write_csv(
                        dependency_path, dependency_fields, dependency_rows
                    )
                elif mutation == "empty_api_fact_identity":
                    api_rows[0]["change_fact_identity"] = ""
                    self._write_csv(api_path, api_fields, api_rows)
                elif mutation == "duplicate_api_fact_identity":
                    api_rows.append(deepcopy(api_rows[0]))
                    summary["published_api_change_count"] = 2
                    dependency_rows[0]["changed_api_count"] = "2"
                    self._write_csv(api_path, api_fields, api_rows)
                    self._write_csv(
                        dependency_path, dependency_fields, dependency_rows
                    )
                    self._write_json(summary_path, summary)
                elif mutation == "evidence_path_missing":
                    api_rows[0]["evidence_path"] = ""
                    self._write_csv(api_path, api_fields, api_rows)
                elif mutation == "per_dependency_not_directory":
                    detail = next(
                        (api / "s4_per_dependency").glob("*/summary.md")
                    )
                    detail.unlink()
                    detail.parent.rmdir()
                    detail.parent.parent.rmdir()
                    detail.parent.parent.write_text("not-a-directory", encoding="utf-8")
                elif mutation == "per_dependency_symlink":
                    symlink_patch = patch.object(
                        Path, "is_symlink", autospec=True,
                        side_effect=lambda path: path == api / "s4_per_dependency",
                    )
                elif mutation in {"detail_is_directory", "detail_is_symlink"}:
                    detail = next(
                        (api / "s4_per_dependency").glob("*/summary.md")
                    )
                    detail.unlink()
                    if mutation == "detail_is_directory":
                        detail.mkdir()
                    else:
                        detail_patch = patch.object(
                            Path, "is_symlink", autospec=True,
                            side_effect=lambda path: path == detail,
                        )
                elif mutation == "declared_detail_mismatch":
                    dependency_rows[0]["detail"] = "s4_per_dependency/forged/summary.md"
                    self._write_csv(
                        dependency_path, dependency_fields, dependency_rows
                    )
                elif mutation == "source_inputs_mismatch":
                    summary["source_inputs"] = {"coverage_status": "forged"}
                    self._write_json(summary_path, summary)
                elif mutation == "source_inputs_empty":
                    summary["source_inputs"] = {}
                    self._write_json(summary_path, summary)
                elif mutation == "method_mapping_mismatch":
                    path = source / "method_mappings.csv"
                    fields, rows = self._csv(path)
                    rows.append({field: "forged" for field in fields})
                    self._write_csv(path, fields, rows)
                elif mutation == "candidate_relationship_mismatch":
                    path = source / "candidate_relationships.csv"
                    fields, rows = self._csv(path)
                    rows.append({field: "forged" for field in fields})
                    self._write_csv(path, fields, rows)
                elif mutation == "coverage_gap_mismatch":
                    path = source / "coverage_gaps.csv"
                    fields, rows = self._csv(path)
                    rows.append({field: "forged" for field in fields})
                    self._write_csv(path, fields, rows)
                elif mutation == "strict_incomplete_coverage":
                    loaded["summary"]["decision_coverage_status"] = "partial"
                    summary["decision_coverage_status"] = "partial"
                    self._write_json(summary_path, summary)

                if mutation == "per_dependency_symlink":
                    with symlink_patch:
                        self._assert_candidate_rejected(
                            root, api, source, loaded,
                            strict_risk_gate=False,
                        )
                elif mutation == "detail_is_symlink":
                    with detail_patch:
                        self._assert_candidate_rejected(
                            root, api, source, loaded,
                            strict_risk_gate=False,
                        )
                else:
                    self._assert_candidate_rejected(
                        root, api, source, loaded,
                        strict_risk_gate=(mutation == "strict_incomplete_coverage"),
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

    @staticmethod
    def _json(path):
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _write_json(path, payload):
        path.write_text(json.dumps(payload), encoding="utf-8")

    @staticmethod
    def _csv(path):
        with path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            return list(reader.fieldnames or ()), list(reader)

    @staticmethod
    def _write_csv(path, fields, rows):
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def _gate_context(
        self, root, loaded, binding, *, live_input_identity=None,
        load_side_effect=None,
    ):
        load_patch = patch.object(
            gate,
            "load_validated_generation",
            side_effect=load_side_effect,
        ) if load_side_effect is not None else patch.object(
            gate, "load_validated_generation", return_value=loaded,
        )
        return (
            load_patch,
            patch.object(
                gate,
                "_load_current_step4_api_rows",
                return_value=(
                    loaded.get("_test_step4_rows", []),
                    {"committed_receipt_identity": "b" * 64},
                ),
            ),
            patch.object(
                gate,
                "_step5_publication_input_identity",
                return_value=(
                    live_input_identity
                    if live_input_identity is not None
                    else binding.get("publication_input_identity", "")
                    if isinstance(binding, dict) else ""
                ),
            ),
            patch.object(gate.sys, "stderr"),
        )

    def _assert_candidate_rejected(
        self, root, call_chain, binary_analysis, indexes, loaded, binding,
        *, strict_risk_gate=False, live_input_identity=None,
        load_side_effect=None, candidate_binding=True,
    ):
        contexts = self._gate_context(
            root, loaded, binding,
            live_input_identity=live_input_identity,
            load_side_effect=load_side_effect,
        )
        with contexts[0], contexts[1], contexts[2], contexts[3], self.assertRaises(SystemExit):
            gate.gate_binary_report(
                root,
                strict_risk_gate=strict_risk_gate,
                candidate_call_chain_dir=call_chain,
                candidate_binary_analysis_dir=binary_analysis,
                candidate_index_dir=indexes,
                candidate_publication_binding=(binding if candidate_binding else None),
            )

    def _assert_candidate_accepted(
        self, root, call_chain, binary_analysis, indexes, loaded, binding,
        *, strict_risk_gate=False, candidate_binding=True,
    ):
        contexts = self._gate_context(root, loaded, binding)
        with contexts[0], contexts[1], contexts[2], contexts[3], patch.object(gate, "ok"):
            gate.gate_binary_report(
                root,
                strict_risk_gate=strict_risk_gate,
                candidate_call_chain_dir=call_chain,
                candidate_binary_analysis_dir=binary_analysis,
                candidate_index_dir=indexes,
                candidate_publication_binding=(binding if candidate_binding else None),
            )

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

    def test_candidate_gate_accepts_unbound_and_partial_selection_views(self):
        for mode in ("without_candidate_binding", "selected_coord", "selected_name"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                call_chain, binary_analysis, indexes, loaded, binding = (
                    self._fixture(root)
                )
                if mode != "without_candidate_binding":
                    selection_path = call_chain / "selection.json"
                    selection = self._json(selection_path)
                    selection["mode"] = "partial"
                    if mode == "selected_coord":
                        selection["selected_coords"] = ["com.acme:api"]
                    else:
                        selection["selected_names"] = ["api"]
                    self._write_json(selection_path, selection)
                    summary_path = call_chain / "summary.json"
                    summary = self._json(summary_path)
                    summary["analysis_scope"] = selection
                    self._write_json(summary_path, summary)
                self._assert_candidate_accepted(
                    root, call_chain, binary_analysis, indexes, loaded, binding,
                    candidate_binding=(mode != "without_candidate_binding"),
                )

    def test_candidate_gate_accepts_pathless_exact_and_resource_truth(self):
        variants = ("pathless", "exact", "resource")
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                call_chain, binary_analysis, indexes, loaded, binding = (
                    self._fixture(root)
                )
                summary_path = call_chain / "summary.json"
                summary = self._json(summary_path)
                item = summary["reachable_apis"][0]
                detail_path = next((call_chain / "by_api").glob("*.json"))
                alert_path = call_chain / "alerts.csv"
                alert_fields, alert_rows = self._csv(alert_path)
                if variant == "pathless":
                    loaded["formal"]["by_api"][0]["paths"] = []
                    item["call_paths"] = []
                    item["path_details"] = []
                    alert_rows[0]["path_text"] = ""
                elif variant == "exact":
                    loaded["formal"]["by_api"][0].update({
                        "path_set_complete": True,
                        "exact_path_exists": True,
                        "possible_path_exists": True,
                    })
                    item.update({
                        "path_set_complete": True,
                        "exact_path_exists": True,
                        "possible_path_exists": True,
                    })
                else:
                    resource_truth = {
                        "dependency_artifacts": [
                            {"side": "base", "coord": "com.acme:api:1.0"},
                            {"side": "current", "coord": "com.acme:api:2.0"},
                        ],
                        "activation_callers": [],
                    }
                    loaded["formal"]["resource_activation_results"] = [
                        resource_truth
                    ]
                    summary["resource_activation_results"] = [
                        gate._formal_step5_resource(resource_truth)
                    ]
                self._write_json(summary_path, summary)
                self._write_json(detail_path, item)
                self._write_csv(alert_path, alert_fields, alert_rows)
                self._assert_candidate_accepted(
                    root, call_chain, binary_analysis, indexes, loaded, binding,
                )

    def test_candidate_gate_accepts_empty_default_strict_and_rich_views(self):
        variants = (
            "empty", "default_locations", "strict_complete", "rich_truth",
            "valid_coverage_evidence", "missing_resource_collection",
            "empty_coverage_component", "mixed_empty_paths",
        )
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                call_chain, binary_analysis, indexes, loaded, binding = (
                    self._fixture(root)
                )
                summary_path = call_chain / "summary.json"
                selection_path = call_chain / "selection.json"
                coverage_path = call_chain / "coverage.json"
                alerts_path = call_chain / "alerts.csv"
                detail_path = next((call_chain / "by_api").glob("*.json"))
                query_path = indexes / "s5_query_index.json"
                summary = self._json(summary_path)
                selection = self._json(selection_path)
                alert_fields, alert_rows = self._csv(alerts_path)

                if variant == "empty":
                    loaded["formal"]["by_api"] = []
                    loaded["formal"]["resource_activation_results"] = []
                    loaded["_test_step4_rows"] = []
                    for key in (
                        "reachable_apis", "uncertain_apis", "not_found_apis",
                        "not_analyzed_apis", "not_impacted_apis",
                    ):
                        summary[key] = []
                    for key in (
                        "total_apis", "reachable", "uncertain",
                        "not_found_in_static_analysis", "not_analyzed",
                        "not_impacted",
                    ):
                        summary[key] = 0
                    summary["resource_activation_results"] = []
                    selection.update({
                        "included_reported_api_identities": [],
                        "included_dependency_coords": [],
                        "excluded_dependency_coords": [],
                        "available_dependency_count": 0,
                        "included_dependency_count": 0,
                        "included_api_count": 0,
                        "analyzed_api_count": 0,
                        "total_api_count": 0,
                        "excluded_api_count": 0,
                    })
                    summary["analysis_scope"] = selection
                    self._write_csv(alerts_path, alert_fields, ())
                    detail_path.unlink()
                    self._write_json(query_path, {
                        **self._json(query_path), "target_apis": [],
                    })
                    count_text = (
                        "# summary\n- 变化 API：0\n- 已发现静态可执行路径：0\n"
                        "- 结论不确定：0\n- 未完成分析：0\n"
                    )
                    (call_chain / "summary.md").write_text(
                        count_text, encoding="utf-8"
                    )
                    (binary_analysis / "system-reachability.md").write_text(
                        count_text, encoding="utf-8"
                    )
                    self._write_json(selection_path, selection)
                    self._write_json(summary_path, summary)
                elif variant == "rich_truth":
                    formal = loaded["formal"]["by_api"][0]
                    formal.update({
                        "path_set_complete": True,
                        "exact_path_exists": True,
                        "possible_path_exists": True,
                        "impact_conclusion": "affected",
                        "static_linkage_status": "linked",
                        "runtime_verification_status": "verified",
                    })
                    formal["paths"][0].update({
                        "path_certainty": "exact", "entry_kinds": ["main"],
                        "entry_kind_labels": ["Main"],
                        "entrypoint_dependency_coords": ["app:main"],
                        "entrypoint_activation_reasons": ["manifest"],
                        "mechanism_kinds": ["invokevirtual"],
                        "mechanism_labels": ["virtual"],
                    })
                    expected = gate._formal_step5_target(formal)
                    item = summary["reachable_apis"][0]
                    item.update({
                        key: expected[key] for key in (
                            "analysis_status", "call_paths", "path_details",
                            "path_set_complete", "exact_path_exists",
                            "possible_path_exists", "impact_conclusion",
                            "static_linkage_status", "runtime_verification_status",
                        )
                    })
                    loaded["_test_step4_rows"][0].update({
                        "old_version": "1.0", "new_version": "2.0",
                    })
                    item.update({"old_version": "1.0", "new_version": "2.0"})
                    self._write_json(summary_path, summary)
                    self._write_json(detail_path, item)
                elif variant == "valid_coverage_evidence":
                    coverage = self._json(coverage_path)
                    coverage["components"] = [{
                        "evidence": [
                            "evidence/dependencies/a.json#row=1",
                            "evidence\\context\\context.json",
                            ".runtime/state/current.json",
                        ],
                    }]
                    self._write_json(coverage_path, coverage)
                elif variant == "empty_coverage_component":
                    coverage = self._json(coverage_path)
                    coverage["components"] = [{}]
                    self._write_json(coverage_path, coverage)
                elif variant == "missing_resource_collection":
                    loaded["formal"].pop("resource_activation_results")
                elif variant == "mixed_empty_paths":
                    loaded["formal"]["by_api"][0]["paths"] = [
                        None, {"path_text": ""},
                        *loaded["formal"]["by_api"][0]["paths"],
                    ]
                    summary["reachable_apis"][0]["call_paths"].insert(0, "")
                    self._write_json(summary_path, summary)
                    self._write_json(detail_path, summary["reachable_apis"][0])

                if variant == "default_locations":
                    expected_chain = gate.evidence_call_chain_dir(root)
                    expected_binary = root / gate.EVIDENCE_DIRNAME / "binary_analysis"
                    expected_indexes = root / gate.RUNTIME_DIRNAME / "indexes"
                    expected_chain.parent.mkdir(parents=True, exist_ok=True)
                    expected_indexes.parent.mkdir(parents=True, exist_ok=True)
                    call_chain.rename(expected_chain)
                    binary_analysis.rename(expected_binary)
                    indexes.rename(expected_indexes)
                    contexts = self._gate_context(root, loaded, binding)
                    with contexts[0], contexts[1], contexts[2], contexts[3], patch.object(gate, "ok"):
                        gate.gate_binary_report(
                            root,
                            candidate_publication_binding=binding,
                        )
                else:
                    self._assert_candidate_accepted(
                        root, call_chain, binary_analysis, indexes, loaded, binding,
                        strict_risk_gate=(variant == "strict_complete"),
                    )

    def test_candidate_strict_gate_rejects_each_incomplete_status_bucket(self):
        for status, bucket, count_key in (
            ("uncertain", "uncertain_apis", "uncertain"),
            ("not_analyzed", "not_analyzed_apis", "not_analyzed"),
        ):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                call_chain, binary_analysis, indexes, loaded, binding = (
                    self._fixture(root)
                )
                summary_path = call_chain / "summary.json"
                summary = self._json(summary_path)
                item = summary["reachable_apis"].pop()
                item["analysis_status"] = status
                item["path_details"][0]["path_status"] = status
                summary[bucket] = [item]
                summary["reachable"] = 0
                summary[count_key] = 1
                loaded["formal"]["by_api"][0]["reachability_status"] = status
                detail_path = next((call_chain / "by_api").glob("*.json"))
                self._write_json(detail_path, item)
                alert_fields, alert_rows = self._csv(call_chain / "alerts.csv")
                alert_rows[0]["path_status"] = status
                self._write_csv(call_chain / "alerts.csv", alert_fields, alert_rows)
                count_text = (
                    "# summary\n- 变化 API：1\n- 已发现静态可执行路径：0\n"
                    f"- 结论不确定：{summary['uncertain']}\n"
                    f"- 未完成分析：{summary['not_analyzed']}\n"
                )
                (call_chain / "summary.md").write_text(count_text, encoding="utf-8")
                (binary_analysis / "system-reachability.md").write_text(
                    count_text, encoding="utf-8"
                )
                self._write_json(summary_path, summary)
                contexts = self._gate_context(root, loaded, binding)
                def reject(message, *_commands):
                    raise RuntimeError(message)
                with contexts[0], contexts[1], contexts[2], contexts[3], patch.object(
                    gate, "fail", side_effect=reject,
                ), self.assertRaisesRegex(
                    RuntimeError, "严格门禁不允许未完成结果",
                ):
                    gate.gate_binary_report(
                        root,
                        strict_risk_gate=True,
                        candidate_call_chain_dir=call_chain,
                        candidate_binary_analysis_dir=binary_analysis,
                        candidate_index_dir=indexes,
                        candidate_publication_binding=binding,
                    )

    def test_candidate_gate_accepts_not_found_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            call_chain, binary_analysis, indexes, loaded, binding = self._fixture(root)
            summary_path = call_chain / "summary.json"
            summary = self._json(summary_path)
            item = summary["reachable_apis"].pop()
            item["analysis_status"] = "not_found_in_static_analysis"
            item["path_details"][0][
                "path_status"
            ] = "not_found_in_static_analysis"
            summary["not_found_apis"] = [item]
            summary["reachable"] = 0
            summary["not_found_in_static_analysis"] = 1
            loaded["formal"]["by_api"][0][
                "reachability_status"
            ] = "not_found_in_static_analysis"
            detail_path = next((call_chain / "by_api").glob("*.json"))
            self._write_json(detail_path, item)
            alert_fields, alert_rows = self._csv(call_chain / "alerts.csv")
            alert_rows[0]["path_status"] = "not_found_in_static_analysis"
            self._write_csv(call_chain / "alerts.csv", alert_fields, alert_rows)
            count_text = (
                "# summary\n- 变化 API：1\n- 已发现静态可执行路径：0\n"
                "- 结论不确定：0\n- 未完成分析：0\n"
            )
            (call_chain / "summary.md").write_text(count_text, encoding="utf-8")
            (binary_analysis / "system-reachability.md").write_text(
                count_text, encoding="utf-8"
            )
            self._write_json(summary_path, summary)
            self._assert_candidate_accepted(
                root, call_chain, binary_analysis, indexes, loaded, binding,
                strict_risk_gate=True,
            )

    def test_candidate_gate_accepts_api_and_resource_only_partitions(self):
        for selected in ("api", "resource"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                call_chain, binary_analysis, indexes, loaded, binding = self._fixture(root)
                resource_truth = {
                    "dependency_artifacts": [
                        {"side": "base", "coord": "g:resource:1"},
                        {"side": "current", "coord": "g:resource:2"},
                    ],
                    "activation_callers": [],
                }
                expected_resource = gate._formal_step5_resource(resource_truth)
                loaded["formal"]["resource_activation_results"] = [resource_truth]
                summary_path = call_chain / "summary.json"
                selection_path = call_chain / "selection.json"
                summary = self._json(summary_path)
                selection = self._json(selection_path)
                selected_coord = (
                    "com.acme:api" if selected == "api" else "g:resource"
                )
                excluded_coord = (
                    "g:resource" if selected == "api" else "com.acme:api"
                )
                selection.update({
                    "mode": "partial", "selected_coords": [selected_coord],
                    "included_dependency_coords": [selected_coord],
                    "excluded_dependency_coords": [excluded_coord],
                    "available_dependency_count": 2,
                    "included_dependency_count": 1,
                })
                if selected == "api":
                    summary["resource_activation_results"] = []
                else:
                    summary["reachable_apis"] = []
                    summary.update({
                        "total_apis": 0, "reachable": 0,
                        "resource_activation_results": [expected_resource],
                    })
                    selection.update({
                        "included_reported_api_identities": [],
                        "included_api_count": 0, "analyzed_api_count": 0,
                        "excluded_api_count": 1,
                    })
                    alert_fields, _rows = self._csv(call_chain / "alerts.csv")
                    self._write_csv(call_chain / "alerts.csv", alert_fields, ())
                    next((call_chain / "by_api").glob("*.json")).unlink()
                    query_path = indexes / "s5_query_index.json"
                    query = self._json(query_path)
                    query["target_apis"] = []
                    self._write_json(query_path, query)
                    count_text = (
                        "# summary\n- 变化 API：0\n- 已发现静态可执行路径：0\n"
                        "- 结论不确定：0\n- 未完成分析：0\n"
                    )
                    (call_chain / "summary.md").write_text(
                        count_text, encoding="utf-8"
                    )
                    (binary_analysis / "system-reachability.md").write_text(
                        count_text, encoding="utf-8"
                    )
                summary["analysis_scope"] = selection
                self._write_json(selection_path, selection)
                self._write_json(summary_path, summary)
                self._assert_candidate_accepted(
                    root, call_chain, binary_analysis, indexes, loaded, binding,
                )

    def test_candidate_gate_rejects_every_step5_contract_boundary(self):
        mutations = (
            "summary_missing", "generation_contract_error", "summary_invalid_json",
            "summary_schema", "summary_authority", "summary_generation",
            "summary_empty_receipt", "summary_empty_input",
            "summary_receipt_non_string", "summary_input_non_string",
            "summary_total_not_integer", "summary_total_negative",
            "binding_non_object", "binding_receipt", "binding_input", "user_file_missing",
            "alert_empty_identity", "alert_extra_empty_identity",
            "alert_total_count", "alert_empty_coord", "alert_empty_status",
            "alert_conflicting_status", "bucket_not_list", "bucket_non_object",
            "bucket_wrong_status", "bucket_empty_status",
            "summary_detail_count", "not_impacted_list_only",
            "summary_empty_identity", "summary_duplicate_identity",
            "summary_alert_identity_set", "summary_empty_reported_identity",
            "status_count", "by_api_count", "by_api_non_object",
            "by_api_empty_identity",
            "by_api_content", "transaction_json_invalid", "selection_schema",
            "selection_generation", "selection_receipt", "selection_input",
            "selection_summary_copy", "selection_reported_identities",
            "formal_container_missing", "formal_container_non_object",
            "formal_not_list", "formal_non_object",
            "formal_empty_identity",
            "formal_duplicate_identity", "step4_empty_fact", "step4_duplicate_fact",
            "formal_empty_fact_ids", "formal_duplicate_fact_ids",
            "formal_unknown_fact_id", "resource_not_list", "resource_non_object",
            "selected_values_not_list", "selected_value_non_string",
            "selected_value_blank", "selected_values_unsorted",
            "unmatched_selected_name", "scope_mode", "scope_validation",
            "scope_included_coords", "scope_excluded_coords",
            "scope_available_count", "scope_included_count", "scope_total_api_count",
            "scope_included_api_count", "scope_analyzed_api_count",
            "scope_excluded_api_count", "scope_total_vs_fact_count",
            "live_input_identity", "candidate_pairs",
            "candidate_pair_empty_fact",
            "core_projection", "call_paths_projection", "path_details_projection",
            "boolean_projection", "resource_projection",
            "resource_projection_list", "alert_path_count",
            "alert_path_text", "alert_core", "alert_signature",
            "alert_symbol_kind", "alert_change_type", "alert_reported_identity",
            "alert_fact_identity", "alert_decision_identity", "summary_markdown",
            "binary_markdown", "coverage_schema", "coverage_non_object_component",
            "coverage_empty_evidence", "coverage_absolute_evidence",
            "coverage_short_evidence", "coverage_unsupported_evidence",
            "query_index_missing", "query_index_schema",
            "query_index_generation", "query_index_receipt", "query_index_input",
            "query_targets_not_list", "query_target_non_object",
            "query_target_empty_fields", "query_target_mismatch",
            "strict_trace_incomplete",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                call_chain, binary_analysis, indexes, loaded, binding = (
                    self._fixture(root)
                )
                summary_path = call_chain / "summary.json"
                selection_path = call_chain / "selection.json"
                coverage_path = call_chain / "coverage.json"
                detail_path = next((call_chain / "by_api").glob("*.json"))
                alerts_path = call_chain / "alerts.csv"
                query_path = indexes / "s5_query_index.json"
                summary = self._json(summary_path)
                selection = self._json(selection_path)
                coverage = self._json(coverage_path)
                alert_fields, alert_rows = self._csv(alerts_path)
                query = self._json(query_path)
                item = summary["reachable_apis"][0]
                load_error = None
                live_identity = None

                if mutation == "summary_missing":
                    summary_path.unlink()
                elif mutation == "generation_contract_error":
                    load_error = gate.BinaryFirstContractError("BROKEN", "broken")
                elif mutation == "summary_invalid_json":
                    summary_path.write_text("{", encoding="utf-8")
                elif mutation.startswith("summary_") and mutation in {
                    "summary_schema", "summary_authority", "summary_generation",
                }:
                    field = {
                        "summary_schema": "schema",
                        "summary_authority": "authority",
                        "summary_generation": "result_generation_identity",
                    }[mutation]
                    summary[field] = "forged"
                    self._write_json(summary_path, summary)
                elif mutation in {
                    "summary_empty_receipt", "summary_empty_input",
                    "summary_receipt_non_string", "summary_input_non_string",
                }:
                    field = {
                        "summary_empty_receipt": "step4_publication_receipt_identity",
                        "summary_empty_input": "step5_publication_input_identity",
                        "summary_receipt_non_string": "step4_publication_receipt_identity",
                        "summary_input_non_string": "step5_publication_input_identity",
                    }[mutation]
                    summary[field] = (
                        [] if mutation.endswith("non_string") else ""
                    )
                    self._write_json(summary_path, summary)
                elif mutation in {
                    "summary_total_not_integer", "summary_total_negative",
                }:
                    summary["total_apis"] = (
                        "not-an-integer"
                        if mutation == "summary_total_not_integer" else -1
                    )
                    self._write_json(summary_path, summary)
                elif mutation == "binding_non_object":
                    binding = []
                elif mutation == "binding_receipt":
                    binding["upstream_publication_receipt_identity"] = "9" * 64
                elif mutation == "binding_input":
                    binding["publication_input_identity"] = "9" * 64
                elif mutation == "user_file_missing":
                    coverage_path.unlink()
                elif mutation == "alert_empty_identity":
                    alert_rows[0]["api_identity"] = ""
                    self._write_csv(alerts_path, alert_fields, alert_rows)
                elif mutation == "alert_extra_empty_identity":
                    extra = deepcopy(alert_rows[0])
                    extra["api_identity"] = ""
                    alert_rows.append(extra)
                    self._write_csv(alerts_path, alert_fields, alert_rows)
                elif mutation == "alert_total_count":
                    summary["total_apis"] = 2
                    self._write_json(summary_path, summary)
                elif mutation == "alert_empty_coord":
                    alert_rows[0]["target_coord"] = ""
                    self._write_csv(alerts_path, alert_fields, alert_rows)
                elif mutation == "alert_empty_status":
                    alert_rows[0]["path_status"] = ""
                    self._write_csv(alerts_path, alert_fields, alert_rows)
                elif mutation == "alert_conflicting_status":
                    extra = deepcopy(alert_rows[0])
                    extra["path_status"] = "uncertain"
                    alert_rows.append(extra)
                    self._write_csv(alerts_path, alert_fields, alert_rows)
                elif mutation == "bucket_not_list":
                    summary["uncertain_apis"] = {}
                    self._write_json(summary_path, summary)
                elif mutation == "bucket_non_object":
                    summary["uncertain_apis"] = [None]
                    self._write_json(summary_path, summary)
                elif mutation == "bucket_wrong_status":
                    item["analysis_status"] = "uncertain"
                    self._write_json(summary_path, summary)
                elif mutation == "bucket_empty_status":
                    item["analysis_status"] = ""
                    self._write_json(summary_path, summary)
                elif mutation == "summary_detail_count":
                    summary["total_apis"] = 2
                    alert_rows.append({**alert_rows[0], "api_identity": "second"})
                    self._write_json(summary_path, summary)
                    self._write_csv(alerts_path, alert_fields, alert_rows)
                elif mutation == "not_impacted_list_only":
                    summary["not_impacted_apis"] = [deepcopy(item)]
                    self._write_json(summary_path, summary)
                elif mutation == "summary_empty_identity":
                    item["api_identity"] = ""
                    self._write_json(summary_path, summary)
                elif mutation == "summary_duplicate_identity":
                    summary["reachable_apis"].append(deepcopy(item))
                    summary["total_apis"] = 2
                    alert_rows.append({**alert_rows[0], "api_identity": "second"})
                    self._write_json(summary_path, summary)
                    self._write_csv(alerts_path, alert_fields, alert_rows)
                elif mutation == "summary_alert_identity_set":
                    item["api_identity"] = "forged"
                    self._write_json(summary_path, summary)
                elif mutation == "summary_empty_reported_identity":
                    item["reported_api_identity"] = ""
                    self._write_json(summary_path, summary)
                    self._write_json(detail_path, item)
                elif mutation == "status_count":
                    summary["reachable"] = 2
                    self._write_json(summary_path, summary)
                elif mutation == "by_api_count":
                    detail_path.unlink()
                elif mutation == "by_api_non_object":
                    self._write_json(detail_path, [])
                elif mutation == "by_api_empty_identity":
                    detail = self._json(detail_path)
                    detail["api_identity"] = ""
                    self._write_json(detail_path, detail)
                elif mutation == "by_api_content":
                    detail = self._json(detail_path)
                    detail["coord"] = "forged"
                    self._write_json(detail_path, detail)
                elif mutation == "transaction_json_invalid":
                    selection_path.write_text("{", encoding="utf-8")
                elif mutation.startswith("selection_"):
                    if mutation == "selection_summary_copy":
                        summary["analysis_scope"] = {}
                        self._write_json(summary_path, summary)
                    else:
                        field = {
                            "selection_schema": "schema",
                            "selection_generation": "result_generation_identity",
                            "selection_receipt": "step4_publication_receipt_identity",
                            "selection_input": "step5_publication_input_identity",
                            "selection_reported_identities": "included_reported_api_identities",
                        }[mutation]
                        selection[field] = [] if mutation == "selection_reported_identities" else "forged"
                        self._write_json(selection_path, selection)
                        if mutation == "selection_reported_identities":
                            summary["analysis_scope"] = selection
                            self._write_json(summary_path, summary)
                elif mutation == "formal_container_missing":
                    loaded["formal"] = None
                elif mutation == "formal_container_non_object":
                    loaded["formal"] = []
                elif mutation == "formal_not_list":
                    loaded["formal"]["by_api"] = {}
                elif mutation == "formal_non_object":
                    loaded["formal"]["by_api"] = [None]
                elif mutation == "formal_empty_identity":
                    loaded["formal"]["by_api"][0]["reported_api_identity"] = ""
                elif mutation == "formal_duplicate_identity":
                    loaded["formal"]["by_api"].append(
                        deepcopy(loaded["formal"]["by_api"][0])
                    )
                elif mutation == "step4_empty_fact":
                    loaded["_test_step4_rows"][0]["change_fact_identity"] = ""
                elif mutation == "step4_duplicate_fact":
                    loaded["_test_step4_rows"].append(
                        deepcopy(loaded["_test_step4_rows"][0])
                    )
                elif mutation == "formal_empty_fact_ids":
                    loaded["formal"]["by_api"][0]["contributing_change_fact_ids"] = []
                elif mutation == "formal_duplicate_fact_ids":
                    fact = loaded["formal"]["by_api"][0][
                        "contributing_change_fact_ids"
                    ][0]
                    loaded["formal"]["by_api"][0][
                        "contributing_change_fact_ids"
                    ] = [fact, fact]
                elif mutation == "formal_unknown_fact_id":
                    loaded["formal"]["by_api"][0][
                        "contributing_change_fact_ids"
                    ] = ["9" * 64]
                elif mutation == "resource_not_list":
                    loaded["formal"]["resource_activation_results"] = {}
                elif mutation == "resource_non_object":
                    loaded["formal"]["resource_activation_results"] = [None]
                elif mutation.startswith("selected_"):
                    selection["selected_coords"] = {
                        "selected_values_not_list": {},
                        "selected_value_non_string": [1],
                        "selected_value_blank": [""],
                        "selected_values_unsorted": ["z:z", "a:a"],
                    }[mutation]
                    self._write_json(selection_path, selection)
                    summary["analysis_scope"] = selection
                    self._write_json(summary_path, summary)
                elif mutation == "unmatched_selected_name":
                    selection.update({
                        "mode": "partial", "selected_names": ["missing"],
                    })
                    self._write_json(selection_path, selection)
                    summary["analysis_scope"] = selection
                    self._write_json(summary_path, summary)
                elif (
                    mutation.startswith("scope_")
                    and mutation != "scope_total_vs_fact_count"
                ):
                    field, value = {
                        "scope_mode": ("mode", "partial"),
                        "scope_validation": ("validation_status", "failed"),
                        "scope_included_coords": ("included_dependency_coords", []),
                        "scope_excluded_coords": ("excluded_dependency_coords", ["com.acme:api"]),
                        "scope_available_count": ("available_dependency_count", 2),
                        "scope_included_count": ("included_dependency_count", 2),
                        "scope_total_api_count": ("total_api_count", 2),
                        "scope_included_api_count": ("included_api_count", 2),
                        "scope_analyzed_api_count": ("analyzed_api_count", 2),
                        "scope_excluded_api_count": ("excluded_api_count", 1),
                    }[mutation]
                    selection[field] = value
                    self._write_json(selection_path, selection)
                    summary["analysis_scope"] = selection
                    self._write_json(summary_path, summary)
                elif mutation == "scope_total_vs_fact_count":
                    second_fact = "8" * 64
                    loaded["formal"]["by_api"][0][
                        "contributing_change_fact_ids"
                    ].append(second_fact)
                    loaded["_test_step4_rows"].append({
                        **loaded["_test_step4_rows"][0],
                        "change_fact_identity": second_fact,
                    })
                    selection.update({
                        "total_api_count": 2,
                        "included_api_count": 2,
                        "analyzed_api_count": 2,
                    })
                    summary["analysis_scope"] = selection
                    self._write_json(selection_path, selection)
                    self._write_json(summary_path, summary)
                elif mutation == "live_input_identity":
                    live_identity = "9" * 64
                elif mutation == "candidate_pairs":
                    item["change_fact_identity"] = "9" * 64
                    self._write_json(summary_path, summary)
                    self._write_json(detail_path, item)
                elif mutation == "candidate_pair_empty_fact":
                    item["change_fact_identity"] = ""
                    self._write_json(summary_path, summary)
                    self._write_json(detail_path, item)
                elif mutation in {
                    "core_projection", "call_paths_projection",
                    "path_details_projection", "boolean_projection",
                }:
                    if mutation == "core_projection":
                        item["coord"] = "forged"
                    elif mutation == "call_paths_projection":
                        item["call_paths"] = ["forged"]
                    elif mutation == "path_details_projection":
                        item["path_details"] = []
                    else:
                        item["path_set_complete"] = True
                    self._write_json(summary_path, summary)
                    self._write_json(detail_path, item)
                elif mutation == "resource_projection":
                    summary["resource_activation_results"] = {}
                    self._write_json(summary_path, summary)
                elif mutation == "resource_projection_list":
                    summary["resource_activation_results"] = [{}]
                    self._write_json(summary_path, summary)
                elif mutation.startswith("alert_"):
                    if mutation == "alert_path_count":
                        alert_rows.append(deepcopy(alert_rows[0]))
                    elif mutation == "alert_path_text":
                        alert_rows[0]["path_text"] = "forged"
                    elif mutation == "alert_core":
                        alert_rows[0]["changed_symbol"] = "forged"
                    else:
                        field = {
                            "alert_signature": "api_signature",
                            "alert_symbol_kind": "symbol_kind",
                            "alert_change_type": "change_type",
                            "alert_reported_identity": "reported_api_identity",
                            "alert_fact_identity": "change_fact_identity",
                            "alert_decision_identity": "decision_identity",
                        }[mutation]
                        alert_rows[0][field] = ""
                    self._write_csv(alerts_path, alert_fields, alert_rows)
                elif mutation == "summary_markdown":
                    (call_chain / "summary.md").write_text("# forged\n", encoding="utf-8")
                elif mutation == "binary_markdown":
                    (binary_analysis / "system-reachability.md").write_text(
                        "# forged\n", encoding="utf-8"
                    )
                elif mutation == "coverage_schema":
                    coverage["schema"] = "forged"
                    self._write_json(coverage_path, coverage)
                elif mutation == "coverage_non_object_component":
                    coverage["components"] = [None]
                    self._write_json(coverage_path, coverage)
                elif mutation.startswith("coverage_"):
                    raw = {
                        "coverage_empty_evidence": "",
                        "coverage_absolute_evidence": "/outside",
                        "coverage_short_evidence": "evidence",
                        "coverage_unsupported_evidence": "evidence/unsupported/a.json",
                    }[mutation]
                    coverage["components"] = [{"evidence": [raw]}]
                    self._write_json(coverage_path, coverage)
                elif mutation == "query_index_missing":
                    query_path.unlink()
                elif mutation.startswith("query_index_"):
                    field = {
                        "query_index_schema": "schema",
                        "query_index_generation": "result_generation_identity",
                        "query_index_receipt": "step4_publication_receipt_identity",
                        "query_index_input": "step5_publication_input_identity",
                    }[mutation]
                    query[field] = "forged"
                    self._write_json(query_path, query)
                elif mutation == "query_targets_not_list":
                    query["target_apis"] = {}
                    self._write_json(query_path, query)
                elif mutation == "query_target_non_object":
                    query["target_apis"] = [None]
                    self._write_json(query_path, query)
                elif mutation == "query_target_empty_fields":
                    query["target_apis"][0] = {
                        key: "" for key in (
                            "coord", "api_name", "api_signature", "symbol_kind",
                            "api_identity", "reported_api_identity",
                            "change_fact_identity", "decision_identity", "change_type",
                        )
                    }
                    self._write_json(query_path, query)
                elif mutation == "query_target_mismatch":
                    query["target_apis"][0]["api_name"] = "forged"
                    self._write_json(query_path, query)
                elif mutation == "strict_trace_incomplete":
                    loaded["summary"]["trace_coverage_status"] = "partial"

                self._assert_candidate_rejected(
                    root, call_chain, binary_analysis, indexes, loaded, binding,
                    strict_risk_gate=(mutation == "strict_trace_incomplete"),
                    live_input_identity=live_identity,
                    load_side_effect=load_error,
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
