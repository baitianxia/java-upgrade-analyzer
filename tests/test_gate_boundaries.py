import csv
import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import gate  # noqa: E402


class GateProjectionBoundaryTest(unittest.TestCase):
    def test_terminal_markers_are_ascii_safe_on_gbk_streams(self):
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="gbk", write_through=True)

        with patch.object(sys, "stderr", stream):
            with self.assertRaises(SystemExit):
                gate.fail("测试失败原因")

        self.assertIn(b"[FAILED]", raw.getvalue())

    def test_formal_api_target_projection_source_and_path_matrix(self):
        rich = {
            "reported_api_identity": "reported",
            "display_owner": "p/C",
            "display_member": "call",
            "display_descriptor": "(Ljava/lang/String;I)V",
            "display_member_kind": "method",
            "reachability_status": "reachable",
            "path_set_complete": True,
            "exact_path_exists": True,
            "possible_path_exists": False,
            "impact_conclusion": "affected",
            "static_linkage_status": "linked",
            "runtime_verification_status": "verified",
            "contributing_change_fact_ids": ["", "fact"],
            "dependency_artifacts": [
                {
                    "side": "base", "coord": "g:a:1",
                    "logical_dependency_lineage": "g:a",
                    "runtime_code_source_origin_identity": "origin",
                },
                {
                    "side": "current", "coord": "g:a:2",
                    "logical_dependency_lineage": "g:a",
                },
            ],
            "paths": [
                None,
                {"path_text": ""},
                {
                    "path_text": "Entry.call -> C.call",
                    "path_certainty": "exact",
                    "entry_kinds": ["main"],
                    "entry_kind_labels": ["Main"],
                    "entrypoint_dependency_coords": ["app:main"],
                    "entrypoint_activation_reasons": ["manifest"],
                    "mechanism_kinds": ["invokevirtual"],
                    "mechanism_labels": ["virtual"],
                },
            ],
        }
        projected = gate._formal_step5_target(rich)
        self.assertEqual(projected["coord"], "g:a")
        self.assertEqual(projected["api"], "p.C.call")
        self.assertEqual(projected["api_signature"], "(java.lang.String,int)")
        self.assertEqual(projected["call_paths"], ["Entry.call -> C.call"])
        self.assertEqual(projected["contributing_change_fact_ids"], ["fact"])

        declared = gate._formal_step5_target({
            "display_owner": "p/C",
            "display_member": "<class>",
            "base_dependency_coords": ["g:declared:1"],
            "current_dependency_coords": ["", "g:declared:2"],
        })
        self.assertEqual(declared["coord"], "g:declared")
        self.assertEqual(declared["api"], "p.C")

        declared_short = gate._formal_step5_target({
            "display_owner": "p/C", "base_dependency_coords": ["short"],
        })
        self.assertEqual(declared_short["coord"], "short")

        short_coord = gate._formal_step5_target({
            "display_owner": "p/C",
            "dependency_artifacts": [
                {"side": "base", "coord": "short"},
            ],
        })
        self.assertEqual(short_coord["coord"], "short")

        origin = gate._formal_step5_target({
            "dependency_artifacts": [{
                "runtime_code_source_origin_identity": "runtime-origin",
            }],
        })
        self.assertEqual(origin["coord"], "runtime-origin")
        self.assertEqual(
            gate._formal_step5_target({})["coord"],
            "未绑定制品（需查看裁决证据）",
        )
        sparse = gate._formal_step5_target({
            "dependency_artifacts": [
                {"logical_dependency_lineage": ""},
                {"side": "base", "coord": ""},
                {"runtime_code_source_origin_identity": ""},
            ],
            "base_dependency_coords": [None, ""],
            "current_dependency_coords": [],
            "paths": [{"path_text": ""}],
            "contributing_change_fact_ids": [None, ""],
        })
        self.assertEqual(sparse["api"], "")
        self.assertEqual(sparse["call_paths"], [])
        self.assertEqual(sparse["contributing_change_fact_ids"], [])
        path_without_metadata = gate._formal_step5_target({
            "paths": [{"path_text": "Entry.call"}],
        })
        self.assertEqual(path_without_metadata["path_details"][0]["path_status"], "")

    def test_formal_resource_projection_filters_callers_and_versions(self):
        self.assertEqual(
            gate._formal_step5_resource({})["coord"],
            "未绑定制品（需查看裁决证据）",
        )
        item = {
            "dependency_artifacts": [
                {"side": "base", "coord": "g:a:1"},
                {"side": "current", "coord": "g:a:2"},
            ],
            "activation_callers": [
                None,
                {"path_certainty": "candidate"},
                {
                    "path_certainty": "exact",
                    "caller_class_name": "p/Entry",
                    "caller_member_name": "run",
                    "caller_descriptor": "()V",
                },
                {
                    "path_certainty": "possible",
                    "caller_class_name": "p/Other",
                    "caller_member_name": "start",
                    "caller_descriptor": "field",
                },
            ],
        }
        resource = gate._formal_step5_resource(item)
        self.assertEqual((resource["old_version"], resource["new_version"]), ("1", "2"))
        self.assertEqual(len(resource["activation_callers"]), 2)
        self.assertEqual(
            resource["business_entries"],
            ["p.Entry.run()", "p.Other.start()"],
        )
        unversioned = gate._formal_step5_resource({
            "dependency_artifacts": [
                {"side": "base", "coord": "short"},
            ],
        })
        self.assertEqual((unversioned["old_version"], unversioned["new_version"]), ("short", "-"))
        blank_caller = gate._formal_step5_resource({
            "dependency_artifacts": [
                {"side": "base", "coord": ""},
                {"side": "current", "coord": ""},
            ],
            "activation_callers": [{
                "path_certainty": "exact", "caller_class_name": "",
                "caller_member_name": "", "caller_descriptor": "",
            }],
        })
        self.assertEqual(blank_caller["activation_callers"][0]["display_caller"], ".()")

    def test_step4_change_type_exhaustive_semantic_matrix(self):
        def decision(kind="method", change="implementation_changed", **evidence):
            return {
                "fact_kind": kind,
                "fact_scope": {"member_change_kind": change},
                "evidence": evidence,
            }

        cases = [
            ({}, "BEHAVIOR_CHANGED"),
            (decision("member_resolution"), "MEMBER_RESOLUTION_CHANGED"),
            (decision(
                "provider_topology", base_provider={"class_provider_status": "resolved"},
                current_provider={"class_provider_status": "missing"},
            ), "CLASS_REMOVED"),
            (decision(
                "provider_topology", base_provider={"class_provider_status": "missing"},
                current_provider={"class_provider_status": "resolved"},
            ), "CLASS_ADDED"),
            (decision("provider_topology"), "BEHAVIOR_CHANGED"),
            (decision(
                "provider_topology", base_provider={"class_provider_status": "resolved"},
                current_provider={"class_provider_status": "resolved"},
            ), "BEHAVIOR_CHANGED"),
            (decision(
                "provider_topology", base_provider={"class_provider_status": "other"},
                current_provider={"class_provider_status": "resolved"},
            ), "BEHAVIOR_CHANGED"),
            (decision("class", "added"), "CLASS_ADDED"),
            (decision("field", "added"), "DATA_FIELD_ADDED"),
            (decision("field", "removed"), "DATA_FIELD_REMOVED"),
            (decision(
                "method", "contract_changed",
                base_contract={"access": 0x0001, "descriptor": "()V"},
                current_contract={"access": 0x0004, "descriptor": "()V"},
            ), "ACCESS_REDUCED"),
            (decision(
                "method", "contract_changed",
                base_contract={"access": 0x0004, "descriptor": "()V"},
                current_contract={"access": 0, "descriptor": "()V"},
            ), "ACCESS_REDUCED"),
            (decision(
                "method", "contract_changed",
                base_contract={"access": 0, "descriptor": "()V"},
                current_contract={"access": 0x0002, "descriptor": "()V"},
            ), "ACCESS_REDUCED"),
            (decision(
                "field", "contract_changed",
                base_contract={"access": 1, "descriptor": "I"},
                current_contract={"access": 1, "descriptor": "J"},
            ), "DATA_FIELD_TYPE_CHANGED"),
            (decision(
                "field", "contract_changed",
                base_contract={"access": 1, "descriptor": "I", "constant": 1},
                current_contract={"access": 1, "descriptor": "I", "constant": 2},
            ), "CONSTANT_VALUE_CHANGED"),
            (decision(
                "field", "contract_changed",
                base_contract={"access": 1, "descriptor": "I", "constant": 1},
                current_contract={"access": 1, "descriptor": "I", "constant": 1},
            ), "CONTRACT_CHANGED"),
            (decision(
                "method", "contract_changed",
                base_contract={"access": 1, "descriptor": "()V"},
                current_contract={"access": 1, "descriptor": "(I)V"},
            ), "SIGNATURE_CHANGED"),
            (decision(
                "method", "contract_changed",
                base_contract={"access": 1, "descriptor": "()V"},
                current_contract={"access": 1, "descriptor": "()V"},
            ), "CONTRACT_CHANGED"),
            (decision("method", "contract_changed", base_contract=[]), "BEHAVIOR_CHANGED"),
            (decision(
                "method", "contract_changed",
                base_contract={}, current_contract=[],
            ), "BEHAVIOR_CHANGED"),
        ]
        cases.extend(
            (decision("method", change), expected)
            for change, expected in (
                ("removed", "REMOVED"),
                ("descriptor_changed", "SIGNATURE_CHANGED"),
                ("access_changed", "ACCESS_REDUCED"),
                ("constant_value_changed", "CONSTANT_VALUE_CHANGED"),
                ("added", "METHOD_ADDED"),
                ("implementation_changed", "BEHAVIOR_CHANGED"),
                ("contract_changed", "BEHAVIOR_CHANGED"),
                ("unknown", "BEHAVIOR_CHANGED"),
            )
        )
        for value, expected in cases:
            with self.subTest(expected=expected, value=value):
                self.assertEqual(gate._step4_change_type(value), expected)

    def test_step4_decision_projection_identity_value_and_symbol_matrix(self):
        base = {
            "decision_identity": "decision",
            "change_fact_identity": "fact",
            "reason_code": "REASON",
            "fact_kind": "method",
            "fact_scope": {
                "class_name": "p/C", "member_name": "call",
                "member_kind": "method", "descriptor": "(I)V",
                "member_change_kind": "removed",
            },
            "dependency_artifacts": [
                {"side": "base", "coord": "g:a:1", "logical_dependency_lineage": "g:a"},
                {"side": "current", "coord": "g:a:2", "logical_dependency_lineage": "g:a"},
            ],
            "evidence": {
                "base_contract": {"descriptor": "(I)V"},
                "current_contract": {"descriptor": "(J)V"},
            },
        }
        projection = gate._step4_decision_projection(base)
        self.assertEqual(projection["coord"], "g:a")
        self.assertEqual(projection["api_signature"], "(int)")
        self.assertEqual(projection["binary_compatible"], "false")

        variants = []
        constructor = deepcopy(base)
        constructor["fact_scope"].update({
            "member_name": "<init>", "member_kind": "unexpected",
        })
        constructor["dependency_artifacts"] = [
            {"side": "current", "coord": "short"},
        ]
        variants.append(constructor)
        class_item = deepcopy(base)
        class_item["fact_scope"].update({
            "member_name": "<class>", "member_kind": "unknown",
            "descriptor": "field",
        })
        class_item["dependency_artifacts"] = [{
            "runtime_code_source_origin_identity": "origin",
        }]
        variants.append(class_item)
        field_item = deepcopy(base)
        field_item["fact_kind"] = "field"
        field_item["fact_scope"].update({
            "member_name": "VALUE", "member_kind": "field",
            "descriptor": "I",
        })
        variants.append(field_item)
        unbound = deepcopy(base)
        unbound["fact_scope"] = {}
        unbound["dependency_artifacts"] = []
        unbound["evidence"] = {
            "base_member_fingerprint": {"x": 1},
            "current_member_fingerprint": {"x": 2},
        }
        variants.append(unbound)
        variants.append({})
        variants.append({
            "dependency_artifacts": [
                {"logical_dependency_lineage": "", "coord": "", "side": "base"},
                {"runtime_code_source_origin_identity": ""},
            ],
            "fact_scope": {"member_name": "", "descriptor": ""},
        })
        current_versioned = deepcopy(base)
        current_versioned["dependency_artifacts"] = [
            {"side": "current", "coord": "g:a:2"},
        ]
        variants.append(current_versioned)
        resolution = deepcopy(base)
        resolution["fact_kind"] = "member_resolution"
        resolution["evidence"] = {
            "base_resolution": {"resolved_owner": "p/Base"},
            "current_resolution": {"member_resolution_status": "missing"},
        }
        variants.append(resolution)
        empty_resolution = deepcopy(resolution)
        empty_resolution["evidence"] = {}
        variants.append(empty_resolution)
        for value in variants:
            projected = gate._step4_decision_projection(value)
            self.assertIn(projected["symbol_kind"], {"method", "field", "class", "constructor"})
            self.assertTrue(projected["coord"])

    def test_source_truth_and_review_render_all_declared_boundaries(self):
        empty = gate._step4_source_truth({})
        self.assertEqual(empty[0]["coverage_status"], "not_provided")
        self.assertIn("没有可用源码", gate._step4_expected_source_review(*empty[:3]))

        loaded = {
            "coverage": {
                "source_inputs": {
                    "purpose_version": "v1",
                    "business": {"status": "available", "origin": "checkout_build"},
                    "dependencies": {"status": "available"},
                },
                "source_overlay": {
                    "coverage_status": "partial",
                    "mapped_count": 2,
                    "ambiguous_count": 1,
                    "conflict_count": 1,
                    "rows": [
                        None,
                        {},
                        {"mapping_status": "ambiguous"},
                        {
                            "mapping_status": "mapped", "overlay_identity": "",
                            "source_location": {}, "binary_member": {},
                        },
                        {
                            "mapping_status": "mapped", "overlay_identity": "one",
                            "source_location": {
                                "owner_coord": "app", "owner_type": "business",
                                "logical_path": "src/C.java", "line": 7,
                                "end_line": 9, "module": "app", "language": "java",
                            },
                            "binary_member": {
                                "artifact_coord": "app:main", "class_name": "p/C",
                                "member_name": "call", "descriptor": "(I)V",
                            },
                        },
                        {
                            "mapping_status": "mapped", "overlay_identity": "two",
                            "source_location": {"logical_path": "src/C.kt", "line": 3, "end_line": 3},
                            "binary_member": {"class_name": "p/C", "member_name": "field", "descriptor": "I"},
                        },
                        {
                            "mapping_status": "mapped", "overlay_identity": "no-end",
                            "source_location": {"line": 5},
                            "binary_member": {"class_name": "p/NoEnd", "member_name": "call", "descriptor": "()V"},
                        },
                        {
                            "mapping_status": "mapped", "overlay_identity": "no-line",
                            "source_location": {"logical_path": "src/NoLine.java", "line": 0},
                            "binary_member": {"class_name": "p/NoLine", "member_name": "call", "descriptor": "()V"},
                        },
                    ],
                },
            },
            "source_attestation": {
                "language_file_counts": {"java": 1, "kotlin": 1},
                "coverage_gaps": [
                    None,
                    {},
                    {"reason_code": "BINARY_SOURCE_LANGUAGE_NOT_MAPPED", "language": "kotlin"},
                    {"reason_code": "PARSE_FAILED", "language": "java", "error_nodes": 1},
                    {
                        "reason_code": "PARSE_FAILED", "language": "scala",
                        "owner_coord": "app", "module": "core",
                        "logical_path": "src/C.scala", "actual_parser": "fallback",
                        "error_nodes": 2,
                    },
                ],
            },
            "source_explanations": {
                "declarations": [
                    None,
                    {},
                    {"overlay_identity": "one", "declared_signature": "void call(int)", "annotations": ["A"], "modifiers": ["public"]},
                ],
                "candidate_relationships": [
                    None,
                    {},
                    {
                        "source_owner_coord": "app", "binary_artifact_coord": "app:main",
                        "caller_binary_class_name": "p/C", "caller_binary_member_name": "call",
                        "caller_binary_descriptor": "(I)V", "caller_logical_path": "src/C.java",
                        "source_line": 7, "callee_key": "p/T.target()V",
                        "evidence_type": "source", "confidence": "possible",
                    },
                    {
                        "caller_binary_class_name": "p/C", "caller_binary_member_name": "field",
                        "caller_binary_descriptor": "I",
                    },
                ],
            },
        }
        source_inputs, methods, candidates, gaps = gate._step4_source_truth(loaded)
        self.assertEqual(len(methods), 5)
        self.assertEqual(len(candidates), 3)
        self.assertEqual(len(gaps), 4)
        empty_method = next(row for row in methods if row["二进制方法"] == ".")
        self.assertEqual(empty_method["源码位置"], "未知")
        no_end = next(row for row in methods if row["二进制方法"] == "p.NoEnd.call()")
        self.assertEqual(no_end["源码位置"], "未知:5")
        no_line = next(row for row in methods if row["二进制方法"] == "p.NoLine.call()")
        self.assertEqual(no_line["源码位置"], "src/NoLine.java")
        rendered = gate._step4_expected_source_review(source_inputs, methods, candidates)
        self.assertIn("源码候选关系", rendered)
        self.assertIn("void call(int)", rendered)

        available_without_mapping = deepcopy(source_inputs)
        available_without_mapping["coverage_status"] = "partial"
        review = gate._step4_expected_source_review(
            available_without_mapping, [], [],
        )
        self.assertIn("没有方法完成精确", review)

        provided = deepcopy(loaded)
        provided["coverage"]["source_inputs"]["business"] = {
            "status": "available", "origin": "uploaded",
        }
        middle = gate._step4_source_truth(provided)[0]
        self.assertIn("已提供并直接使用", middle["label"])


class GateInputBoundaryTest(unittest.TestCase):
    @staticmethod
    def _write_csv(path, fields, rows=()):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def _step1_fixture(self, root):
        dependencies = gate.evidence_dependencies_dir(root)
        dependencies.mkdir(parents=True)
        base_jar = dependencies / "base.jar"
        current_jar = dependencies / "current.jar"
        base_jar.write_bytes(b"base")
        current_jar.write_bytes(b"current")
        self._write_csv(
            gate.dep_changes_path(root),
            (
                "coord", "old_version", "new_version", "change_type", "risk",
                "scope", "resolution_status", "base_lib_entry",
                "current_lib_entry",
            ),
            ({
                "coord": "g:a", "old_version": "1", "new_version": "2",
                "change_type": "升级", "risk": "medium", "scope": "runtime",
                "resolution_status": "resolved", "base_lib_entry": "base.jar",
                "current_lib_entry": "current.jar",
            },),
        )
        self._write_csv(
            gate.current_resolved_path(root),
            ("coord", "version", "scope", "remark", "lib_entry", "resolution_status"),
            ({
                "coord": "g:a", "version": "2", "scope": "runtime",
                "remark": "fixture", "lib_entry": "current.jar",
                "resolution_status": "resolved",
            },),
        )
        gate.provenance_path(root).write_text(json.dumps({
            "both_builds_succeeded": True,
            "sides": [
                {"side": "base", "artifact_sha256": "a" * 64},
                {"side": "current", "artifact_sha256": "b" * 64},
            ],
        }), encoding="utf-8")
        manifest = {
            "items": [
                {
                    "side": "base", "coord": "g:a", "version": "1",
                    "lib_entry": "base.jar", "retained_path": str(base_jar),
                    "nested_jar_sha256": hashlib.sha256(b"base").hexdigest(),
                    "purposes": ["binary_diff"],
                },
                {
                    "side": "current", "coord": "g:a", "version": "2",
                    "lib_entry": "current.jar", "retained_path": str(current_jar),
                    "nested_jar_sha256": hashlib.sha256(b"current").hexdigest(),
                    "purposes": ["binary_diff", "binary_runtime"],
                },
            ],
            "business_artifacts": [],
        }
        gate.dependency_jars_manifest_path(root).write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        return dependencies, manifest, base_jar, current_jar

    def _assert_step1_rejected(self, root):
        with patch.object(gate.sys, "stderr", io.StringIO()), patch.object(
            gate, "require_safe_step1_retained_archive",
        ), self.assertRaises(SystemExit):
            gate.gate_step1_scope(root)

    def test_step1_gate_accepts_complete_classifier_skip_and_business_views(self):
        for variant in (
            "complete", "classifier", "short_coord", "missing_optional_sets",
            "skips", "business",
        ):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                dependencies, manifest, _base, current = self._step1_fixture(root)
                if variant == "classifier":
                    manifest["items"][0]["coord"] = "g:a:test-fixtures"
                    manifest["items"][0]["classifier"] = ""
                    manifest["items"][1]["classifier"] = "runtime"
                elif variant == "short_coord":
                    for item in manifest["items"]:
                        item["coord"] = "short"
                    fields, rows = self._read_csv_for_mutation(
                        gate.dep_changes_path(root)
                    )
                    rows[0]["coord"] = "short"
                    self._write_csv(gate.dep_changes_path(root), fields, rows)
                    fields, rows = self._read_csv_for_mutation(
                        gate.current_resolved_path(root)
                    )
                    rows[0]["coord"] = "short"
                    self._write_csv(gate.current_resolved_path(root), fields, rows)
                elif variant == "missing_optional_sets":
                    manifest.pop("business_artifacts")
                elif variant == "skips":
                    dep_fields = (
                        "coord", "old_version", "new_version", "change_type", "risk",
                        "scope", "resolution_status", "base_lib_entry",
                        "current_lib_entry",
                    )
                    self._write_csv(gate.dep_changes_path(root), dep_fields, (
                        {
                            "coord": "g:a", "old_version": "1", "new_version": "2",
                            "change_type": "升级", "resolution_status": "resolved",
                            "base_lib_entry": "base.jar", "current_lib_entry": "current.jar",
                        },
                        {
                            "coord": "skip:unresolved", "old_version": "1", "new_version": "2",
                            "change_type": "升级", "resolution_status": "unresolved",
                        },
                        {
                            "coord": "skip:empty-status", "old_version": "1", "new_version": "2",
                            "change_type": "升级", "resolution_status": "",
                        },
                        {
                            "coord": "skip:unchanged", "old_version": "1", "new_version": "1",
                            "change_type": "未变", "resolution_status": "resolved",
                        },
                        {
                            "coord": "g:a", "old_version": "-", "new_version": "2",
                            "change_type": "升级", "resolution_status": "resolved",
                            "current_lib_entry": "current.jar",
                        },
                        {
                            "coord": "skip:empty-versions", "old_version": "", "new_version": "-",
                            "change_type": "", "resolution_status": "resolved",
                        },
                    ))
                    current_fields = (
                        "coord", "version", "scope", "remark", "lib_entry", "resolution_status",
                    )
                    self._write_csv(gate.current_resolved_path(root), current_fields, (
                        {
                            "coord": "g:a", "version": "2", "scope": "",
                            "lib_entry": "current.jar", "resolution_status": "resolved",
                        },
                        {"coord": "skip:unresolved", "version": "1", "resolution_status": "unresolved"},
                        {"coord": "skip:empty-status", "version": "1", "resolution_status": ""},
                        {"coord": "skip:test", "version": "1", "scope": "test", "resolution_status": "resolved"},
                        {"coord": "skip:provided", "version": "1", "scope": "provided", "resolution_status": "resolved"},
                        {"coord": "skip:optional", "version": "1", "scope": "optional", "resolution_status": "resolved"},
                        {"coord": "", "version": "-", "scope": "runtime", "resolution_status": "resolved"},
                        {"coord": "", "version": "2", "scope": "runtime", "resolution_status": "resolved"},
                        {"coord": "skip:empty-version", "version": "", "scope": "runtime", "resolution_status": "resolved"},
                    ))
                elif variant == "business":
                    manifest["business_artifacts"] = [{
                        "side": "current", "retained_path": str(current),
                        "sha256": hashlib.sha256(b"current").hexdigest(),
                    }, {"side": "base"}]
                gate.dependency_jars_manifest_path(root).write_text(
                    json.dumps(manifest), encoding="utf-8"
                )
                with patch.object(gate, "require_safe_step1_retained_archive") as safety, patch.object(
                    gate, "ok",
                ):
                    gate.gate_step1_scope(root)
                self.assertGreaterEqual(safety.call_count, 2)

    def test_step1_gate_rejects_every_provenance_and_archive_boundary(self):
        mutations = (
            "dep_changes_missing", "dep_rows_empty", "dep_coord_empty",
            "dep_additional_empty_coord", "dep_versions_empty",
            "current_missing", "current_rows_empty",
            "current_coord_empty", "current_version_empty", "provenance_missing",
            "provenance_invalid_json", "provenance_root_not_object",
            "provenance_sides_missing", "both_builds_failed", "side_set_incomplete",
            "artifact_hash_missing", "manifest_missing", "manifest_invalid_json",
            "manifest_root_not_object", "manifest_items_not_list",
            "manifest_items_missing", "manifest_item_non_object", "business_items_not_list",
            "business_item_non_object", "duplicate_gav_bytes",
            "duplicate_gav_classifier", "duplicate_lib_entry", "base_entry_missing",
            "base_manifest_item_missing", "base_manifest_coord_mismatch",
            "base_manifest_version_mismatch", "base_retained_missing", "base_hash_missing",
            "base_hash_mismatch", "current_entry_missing", "current_purpose_missing",
            "current_manifest_item_missing", "current_manifest_coord_mismatch",
            "current_manifest_version_mismatch",
            "current_retained_missing", "current_hash_missing", "current_hash_mismatch",
            "business_retained_missing", "business_retained_empty",
            "business_hash_missing",
            "business_hash_mismatch", "manifest_empty_coord", "manifest_empty_side",
            "manifest_empty_version", "manifest_empty_lib_entry",
            "base_retained_empty", "current_retained_empty",
            "current_purposes_missing", "business_side_missing",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                dependencies, manifest, base, current = self._step1_fixture(root)
                dep_path = gate.dep_changes_path(root)
                current_path = gate.current_resolved_path(root)
                provenance = gate.provenance_path(root)
                manifest_path = gate.dependency_jars_manifest_path(root)
                dep_fields = (
                    "coord", "old_version", "new_version", "change_type", "risk",
                    "scope", "resolution_status", "base_lib_entry", "current_lib_entry",
                )
                current_fields = (
                    "coord", "version", "scope", "remark", "lib_entry", "resolution_status",
                )
                if mutation == "dep_changes_missing":
                    dep_path.unlink()
                elif mutation in {"dep_rows_empty", "dep_coord_empty", "dep_versions_empty"}:
                    row = {
                        "coord": "" if mutation == "dep_coord_empty" else "g:a",
                        "old_version": "-" if mutation == "dep_versions_empty" else "1",
                        "new_version": "-" if mutation == "dep_versions_empty" else "2",
                    }
                    self._write_csv(dep_path, dep_fields, () if mutation == "dep_rows_empty" else (row,))
                elif mutation == "dep_additional_empty_coord":
                    fields, rows = self._read_csv_for_mutation(dep_path)
                    rows.append({
                        **rows[0],
                        "coord": "",
                    })
                    self._write_csv(dep_path, fields, rows)
                elif mutation == "current_missing":
                    current_path.unlink()
                elif mutation in {"current_rows_empty", "current_coord_empty", "current_version_empty"}:
                    row = {
                        "coord": "" if mutation == "current_coord_empty" else "g:a",
                        "version": "-" if mutation == "current_version_empty" else "2",
                    }
                    self._write_csv(current_path, current_fields, () if mutation == "current_rows_empty" else (row,))
                elif mutation == "provenance_missing":
                    provenance.unlink()
                elif mutation == "provenance_invalid_json":
                    provenance.write_text("{", encoding="utf-8")
                elif mutation == "provenance_root_not_object":
                    provenance.write_text("[]", encoding="utf-8")
                elif mutation == "provenance_sides_missing":
                    payload = json.loads(provenance.read_text(encoding="utf-8"))
                    payload.pop("sides")
                    provenance.write_text(json.dumps(payload), encoding="utf-8")
                elif mutation in {"both_builds_failed", "side_set_incomplete", "artifact_hash_missing"}:
                    payload = json.loads(provenance.read_text(encoding="utf-8"))
                    if mutation == "both_builds_failed":
                        payload["both_builds_succeeded"] = False
                    elif mutation == "side_set_incomplete":
                        payload["sides"] = payload["sides"][:1]
                    else:
                        payload["sides"][0]["artifact_sha256"] = ""
                    provenance.write_text(json.dumps(payload), encoding="utf-8")
                elif mutation == "manifest_missing":
                    manifest_path.unlink()
                elif mutation == "manifest_invalid_json":
                    manifest_path.write_text("{", encoding="utf-8")
                elif mutation == "manifest_root_not_object":
                    manifest_path.write_text("[]", encoding="utf-8")
                elif mutation == "manifest_items_not_list":
                    manifest["items"] = {}
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "manifest_items_missing":
                    manifest.pop("items")
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "manifest_item_non_object":
                    manifest["items"] = [None]
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "business_items_not_list":
                    manifest["business_artifacts"] = {}
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "business_item_non_object":
                    manifest["business_artifacts"] = [None]
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "duplicate_gav_bytes":
                    duplicate = deepcopy(manifest["items"][0])
                    duplicate["lib_entry"] = "other.jar"
                    duplicate["nested_jar_sha256"] = "9" * 64
                    manifest["items"].append(duplicate)
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "duplicate_gav_classifier":
                    manifest["items"][0]["classifier"] = "tests"
                    duplicate = deepcopy(manifest["items"][0])
                    duplicate["lib_entry"] = "other.jar"
                    duplicate["nested_jar_sha256"] = "9" * 64
                    manifest["items"].append(duplicate)
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "duplicate_lib_entry":
                    duplicate = deepcopy(manifest["items"][0])
                    duplicate.update({"coord": "other:artifact", "version": "9"})
                    manifest["items"].append(duplicate)
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation in {
                    "manifest_empty_coord", "manifest_empty_side", "manifest_empty_version",
                    "manifest_empty_lib_entry",
                }:
                    field = mutation.removeprefix("manifest_empty_")
                    manifest["items"][0][field] = ""
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "base_entry_missing":
                    fields, rows = self._read_csv_for_mutation(dep_path)
                    rows[0]["base_lib_entry"] = ""
                    self._write_csv(dep_path, fields, rows)
                elif mutation == "base_manifest_item_missing":
                    manifest["items"] = manifest["items"][1:]
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation in {
                    "base_manifest_coord_mismatch", "base_manifest_version_mismatch",
                }:
                    field = mutation.removeprefix("base_manifest_").removesuffix(
                        "_mismatch"
                    )
                    manifest["items"][0][field] = "other:value"
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation in {"base_retained_missing", "base_hash_missing", "base_hash_mismatch"}:
                    if mutation == "base_retained_missing":
                        manifest["items"][0]["retained_path"] = str(dependencies / "missing.jar")
                    elif mutation == "base_hash_missing":
                        manifest["items"][0]["nested_jar_sha256"] = ""
                    else:
                        manifest["items"][0]["nested_jar_sha256"] = "9" * 64
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "base_retained_empty":
                    manifest["items"][0]["retained_path"] = ""
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "current_entry_missing":
                    fields, rows = self._read_csv_for_mutation(current_path)
                    rows[0]["lib_entry"] = ""
                    self._write_csv(current_path, fields, rows)
                elif mutation == "current_purpose_missing":
                    manifest["items"][1]["purposes"] = ["binary_diff"]
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "current_purposes_missing":
                    manifest["items"][1].pop("purposes")
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "current_manifest_item_missing":
                    manifest["items"] = manifest["items"][:1]
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation in {
                    "current_manifest_coord_mismatch",
                    "current_manifest_version_mismatch",
                }:
                    field = mutation.removeprefix("current_manifest_").removesuffix(
                        "_mismatch"
                    )
                    manifest["items"][1][field] = "other:value"
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation in {"current_retained_missing", "current_hash_missing", "current_hash_mismatch"}:
                    if mutation == "current_retained_missing":
                        manifest["items"][1]["retained_path"] = str(dependencies / "missing.jar")
                    elif mutation == "current_hash_missing":
                        manifest["items"][1]["nested_jar_sha256"] = ""
                    else:
                        manifest["items"][1]["nested_jar_sha256"] = "9" * 64
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                elif mutation == "current_retained_empty":
                    manifest["items"][1]["retained_path"] = ""
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                else:
                    manifest["business_artifacts"] = [{
                        "side": "current",
                        "retained_path": (
                            "" if mutation == "business_retained_empty"
                            else str(dependencies / "missing.jar")
                            if mutation == "business_retained_missing"
                            else str(current)
                        ),
                        "sha256": (
                            "" if mutation == "business_hash_missing"
                            else "9" * 64 if mutation == "business_hash_mismatch"
                            else hashlib.sha256(b"current").hexdigest()
                        ),
                    }]
                    if mutation == "business_side_missing":
                        manifest["business_artifacts"][0]["side"] = ""
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                if mutation in {
                    "current_manifest_item_missing",
                    "current_manifest_coord_mismatch",
                    "current_manifest_version_mismatch",
                    "current_retained_missing", "current_retained_empty",
                    "current_hash_missing", "current_hash_mismatch",
                }:
                    fields, rows = self._read_csv_for_mutation(dep_path)
                    rows[0]["change_type"] = "未变"
                    self._write_csv(dep_path, fields, rows)
                self._assert_step1_rejected(root)

    @staticmethod
    def _read_csv_for_mutation(path):
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            return list(reader.fieldnames or ()), list(reader)

    def test_platform_commands_csv_rows_and_version_presence_matrix(self):
        with patch.object(gate.sys, "platform", "win32"):
            self.assertEqual(gate.python_cmds(), ["python", "py -3"])
        with patch.object(gate.sys, "platform", "linux"):
            self.assertEqual(gate.python_cmds(), ["python3", "python"])

        for row, expected in (
            ({}, False),
            ({"old_version": "1", "new_version": "-"}, True),
            ({"old_version": "-", "new_version": "2"}, True),
        ):
            self.assertEqual(gate.has_dep_versions(row), expected)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rows.csv"
            path.write_text("a,b\n  one  ,  two  \n,\n", encoding="utf-8")
            self.assertEqual(
                gate.read_csv_dicts(path, ("a", "b")),
                [{"a": "one", "b": "two"}, {"a": "", "b": ""}],
            )
            with self.assertRaises(SystemExit):
                gate.read_csv_dicts(path, ("a", "b", "missing"))
        with patch.object(
            gate, "open_csv_read", return_value=nullcontext(io.StringIO("a\nvalue\n")),
        ), patch.object(
            gate.csv, "DictReader", side_effect=csv.Error("malformed"),
        ), self.assertRaises(SystemExit):
            gate.read_csv_dicts("bad.csv", ("a",))

        class SparseReader:
            fieldnames = None

            def __iter__(self):
                return iter(({}, {"a": None}, {"a": " value "}))

        with patch.object(
            gate, "open_csv_read", return_value=nullcontext(io.StringIO()),
        ), patch.object(gate.csv, "DictReader", return_value=SparseReader()):
            self.assertEqual(
                gate.read_csv_dicts("sparse.csv", ()),
                [{"a": ""}, {"a": "value"}],
            )

    def test_current_step4_snapshot_success_and_shape_failures(self):
        rows = [{"change_fact_identity": "fact"}]
        for label, snapshot, should_pass in (
            (
                "valid",
                {
                    "committed_receipt_identity": "receipt",
                    "snapshot_destinations": ["api", "source"],
                    "binding": {},
                },
                True,
            ),
            (
                "identity",
                {
                    "committed_receipt_identity": "wrong",
                    "snapshot_destinations": ["api", "source"],
                },
                False,
            ),
            (
                "destinations",
                {
                    "committed_receipt_identity": "receipt",
                    "snapshot_destinations": ["api"],
                },
                False,
            ),
            (
                "destinations_missing",
                {
                    "committed_receipt_identity": "receipt",
                    "snapshot_destinations": None,
                },
                False,
            ),
        ):
            with self.subTest(label=label), patch.object(
                gate, "materialize_report_publication_committed_snapshot",
                return_value=snapshot,
            ), patch.object(gate, "read_csv_dicts", return_value=rows):
                if should_pass:
                    loaded_rows, loaded_snapshot = gate._load_current_step4_api_rows(
                        "report", "receipt",
                    )
                    self.assertEqual(loaded_rows, rows)
                    self.assertEqual(loaded_snapshot["snapshot_destinations"], ())
                else:
                    with self.assertRaises(SystemExit):
                        gate._load_current_step4_api_rows("report", "receipt")

    def test_context_missing_unknown_and_complete_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            context = gate.context_path(report)
            context.parent.mkdir(parents=True)
            with self.assertRaises(SystemExit):
                gate.gate_context(report)
            context.write_text("{}", encoding="utf-8")
            with self.assertRaises(SystemExit):
                gate.gate_context(report)
            context.write_text(json.dumps({
                "build_tool": "maven", "base_branch": "main",
                "current_branch": "upgrade", "jdk_base": "unknown",
                "jdk_current": "",
            }), encoding="utf-8")
            stderr = io.StringIO()
            with patch.object(gate.sys, "stderr", stderr):
                gate.gate_context(report)
            self.assertIn("jdk_base", stderr.getvalue())
            context.write_text(json.dumps({
                "build_tool": "maven", "base_branch": "main",
                "current_branch": "upgrade", "jdk_base": "",
                "jdk_current": "unknown",
            }), encoding="utf-8")
            with patch.object(gate.sys, "stderr", io.StringIO()):
                gate.gate_context(report)
            context.write_text(json.dumps({
                "build_tool": "maven", "base_branch": "main",
                "current_branch": "upgrade", "jdk_base": "8",
                "jdk_current": "17",
            }), encoding="utf-8")
            with patch.object(gate, "ok") as ok:
                gate.gate_context(report)
            ok.assert_called_once()

    def test_final_report_direct_and_committed_validation_matrix(self):
        with patch.object(
            gate, "_validate_step6_candidate_under_parent_workflow_lock",
        ) as validate, patch.object(gate, "ok"):
            gate.gate_binary_final_report(
                "report", candidate_deliverables_dir="deliverables",
                candidate_findings_dir="findings",
                candidate_publication_binding={"identity": "binding"},
            )
        validate.assert_called_once()

        without_binding = {
            "snapshot_destinations": ["deliverables", "findings"],
        }
        with patch.object(
            gate, "materialize_report_publication_committed_snapshot",
            return_value=without_binding,
        ), patch.object(gate, "validate_step6_publication_candidate") as validate, patch.object(
            gate, "ok",
        ):
            gate.gate_binary_final_report("report")
        self.assertEqual(validate.call_args.kwargs["candidate_publication_binding"], {})

        with patch.object(
            gate, "_validate_step6_candidate_under_parent_workflow_lock",
        ) as validate, patch.object(gate, "ok"):
            gate.gate_binary_final_report(
                "report", candidate_deliverables_dir="deliverables",
                candidate_findings_dir=None, candidate_publication_binding=None,
            )
        self.assertEqual(validate.call_args.kwargs["candidate_publication_binding"], {})

        valid_snapshot = {
            "snapshot_destinations": ["deliverables", "findings"],
            "binding": {"identity": "binding"},
        }
        with patch.object(
            gate, "materialize_report_publication_committed_snapshot",
            return_value=valid_snapshot,
        ), patch.object(gate, "validate_step6_publication_candidate") as validate, patch.object(
            gate, "ok",
        ):
            gate.gate_binary_final_report("report")
        validate.assert_called_once()

        for invalid_snapshot in (
            {"snapshot_destinations": []},
            {"snapshot_destinations": None},
        ):
            with self.subTest(invalid_snapshot=invalid_snapshot), patch.object(
                gate, "materialize_report_publication_committed_snapshot",
                return_value=invalid_snapshot,
            ), self.assertRaises(SystemExit):
                gate.gate_binary_final_report("report")

        failure = gate.BinaryFirstContractError("INVALID", "invalid")
        for direct in (False, True):
            with self.subTest(direct=direct), patch.object(
                gate,
                (
                    "_validate_step6_candidate_under_parent_workflow_lock"
                    if direct else "validate_step6_publication_candidate"
                ),
                side_effect=failure,
            ), patch.object(
                gate, "materialize_report_publication_committed_snapshot",
                return_value=valid_snapshot,
            ), patch.object(
                gate, "fail_binary_report_contract", side_effect=RuntimeError("blocked"),
            ), self.assertRaisesRegex(RuntimeError, "blocked"):
                gate.gate_binary_final_report(
                    "report",
                    candidate_deliverables_dir="deliverables" if direct else None,
                    candidate_findings_dir="findings" if direct else None,
                )

    def test_binary_report_failure_result_is_optional_and_bound(self):
        error = gate.BinaryFirstContractError("BROKEN", "broken")
        for result_path in ("", "result.json"):
            with self.subTest(result_path=result_path), patch.object(
                gate, "_GATE_RESULT_JSON_PATH", result_path,
            ), patch.object(
                gate, "write_binary_report_publication_failure_result",
            ) as write, patch.object(
                gate, "fail", side_effect=RuntimeError("failed"),
            ), self.assertRaisesRegex(RuntimeError, "failed"):
                gate.fail_binary_report_contract("message", error)
            if result_path:
                write.assert_called_once_with(result_path, error, phase="step6")
            else:
                write.assert_not_called()


class GateScanBoundaryTest(unittest.TestCase):
    JDK_FILES = (
        "s3_jdk_removed_api.csv", "s3_jdk_javax_refs.csv",
        "s3_jdk_internal_api.csv", "s3_jdk_reflection.csv",
        "s3_jdk_serialization.txt", "s3_jdk_runtime_flags.csv",
    )
    CONTRACT_FIELDS = (
        "依赖包", "变化类型", "契约类型", "可信度", "表", "列",
        "契约位置", "语句或字段", "人工复核建议",
    )

    @staticmethod
    def _touch(path, text="\n"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _context(self, root, **values):
        path = gate.context_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(values), encoding="utf-8")

    def _database_contract(self, root, *, rows=()):
        dependencies = gate.evidence_dependencies_dir(root)
        scan = gate.evidence_static_scan_dir(root)
        dependencies.mkdir(parents=True, exist_ok=True)
        scan.mkdir(parents=True, exist_ok=True)
        (dependencies / "dependency_jars.json").write_text("{}", encoding="utf-8")
        with (scan / "s3_database_contract_changes.csv").open(
            "w", encoding="utf-8", newline="",
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=self.CONTRACT_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        (scan / "s3_database_contract_summary.json").write_text(json.dumps({
            "schema": "java-upgrade-analyzer.database-contract-changes.v1",
            "coverage_status": "complete", "change_count": len(tuple(rows)),
        }), encoding="utf-8")
        (scan / "s3_database_contract_changes.md").write_text(
            "# 数据库契约变化明细\n", encoding="utf-8",
        )
        return dependencies, scan

    def test_scan_gate_accepts_absent_optional_and_complete_conditional_views(self):
        for variant in ("optional_absent", "jdk_spring", "dependencies", "database"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                scan = gate.evidence_static_scan_dir(root)
                if variant == "jdk_spring":
                    self._context(
                        root, jdk_upgraded=True, springboot_major_upgrade=True,
                    )
                    for name in self.JDK_FILES + (
                        "s3_springboot_config.csv", "s3_springboot_autoconfig.txt",
                    ):
                        self._touch(scan / name)
                elif variant == "dependencies":
                    self._touch(gate.dep_changes_path(root), "coord\ng:a\n")
                    self._touch(scan / "s3_dependency_compat.csv")
                    self._touch(scan / "s3_dependency_classfile.csv")
                elif variant == "database":
                    self._database_contract(root)
                with patch.object(gate, "ok") as ok:
                    gate.gate_scan(root)
                ok.assert_called_once()

    def test_scan_gate_rejects_every_conditional_output_boundary(self):
        mutations = (
            "jdk_missing", "spring_javax_missing", "spring_config_missing",
            "spring_autoconfig_missing", "dependency_compat_missing",
            "dependency_classfile_missing", "contract_files_missing",
            "contract_schema", "contract_coverage", "contract_count_type",
            "contract_header", "contract_empty_csv", "contract_empty_row",
            "contract_row_count", "contract_review",
            "contract_invalid_json", "contract_csv_error", "issues_and_invalid",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                scan = gate.evidence_static_scan_dir(root)
                csv_patch = nullcontext()
                if mutation == "jdk_missing":
                    self._context(root, jdk_upgraded=True)
                    for name in self.JDK_FILES[1:]:
                        self._touch(scan / name)
                elif mutation.startswith("spring_"):
                    self._context(root, springboot_major_upgrade=True)
                    for name in (
                        "s3_jdk_javax_refs.csv", "s3_springboot_config.csv",
                        "s3_springboot_autoconfig.txt",
                    ):
                        self._touch(scan / name)
                    missing = {
                        "spring_javax_missing": "s3_jdk_javax_refs.csv",
                        "spring_config_missing": "s3_springboot_config.csv",
                        "spring_autoconfig_missing": "s3_springboot_autoconfig.txt",
                    }[mutation]
                    (scan / missing).unlink()
                elif mutation.startswith("dependency_"):
                    self._touch(gate.current_resolved_path(root), "coord\ng:a\n")
                    self._touch(scan / "s3_dependency_compat.csv")
                    self._touch(scan / "s3_dependency_classfile.csv")
                    missing = {
                        "dependency_compat_missing": "s3_dependency_compat.csv",
                        "dependency_classfile_missing": "s3_dependency_classfile.csv",
                    }[mutation]
                    (scan / missing).unlink()
                elif mutation == "contract_files_missing":
                    dependencies = gate.evidence_dependencies_dir(root)
                    dependencies.mkdir(parents=True)
                    (dependencies / "dependency_jars.json").write_text("{}", encoding="utf-8")
                else:
                    _dependencies, scan = self._database_contract(root)
                    summary_path = scan / "s3_database_contract_summary.json"
                    csv_path = scan / "s3_database_contract_changes.csv"
                    review_path = scan / "s3_database_contract_changes.md"
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    if mutation == "contract_schema":
                        summary["schema"] = "forged"
                    elif mutation == "contract_coverage":
                        summary["coverage_status"] = "unknown"
                    elif mutation == "contract_count_type":
                        summary["change_count"] = None
                    elif mutation == "contract_header":
                        csv_path.write_text("wrong\nvalue\n", encoding="utf-8")
                    elif mutation == "contract_empty_csv":
                        csv_path.write_text("", encoding="utf-8")
                    elif mutation == "contract_empty_row":
                        class EmptyRowReader:
                            fieldnames = list(self.CONTRACT_FIELDS)

                            def __iter__(self):
                                return iter(({},))

                        csv_patch = patch.object(
                            gate.csv, "DictReader", return_value=EmptyRowReader(),
                        )
                        review_path.write_text("# forged\n", encoding="utf-8")
                    elif mutation == "contract_row_count":
                        summary["change_count"] = 1
                    elif mutation == "contract_review":
                        review_path.write_text("# forged\n", encoding="utf-8")
                    elif mutation == "contract_invalid_json":
                        summary_path.write_text("{", encoding="utf-8")
                    elif mutation == "contract_csv_error":
                        csv_patch = patch.object(
                            gate.csv, "DictReader", side_effect=csv.Error("bad csv"),
                        )
                    elif mutation == "issues_and_invalid":
                        self._context(root, jdk_upgraded=True)
                        summary["schema"] = "forged"
                    if mutation not in {"contract_invalid_json", "contract_csv_error"}:
                        summary_path.write_text(json.dumps(summary), encoding="utf-8")
                with csv_patch, patch.object(
                    gate.sys, "stderr", io.StringIO(),
                ), self.assertRaises(SystemExit):
                    gate.gate_scan(root)


class GateMainBoundaryTest(unittest.TestCase):
    def tearDown(self):
        gate._GATE_RESULT_JSON_PATH = ""

    def _candidate_args(self, step, binding, *, activation=""):
        args = [
            "gate.py", "--step", step, "--report-dir", "report",
            "--publication-transaction-id", "1" * 32,
            "--publication-binding-json", json.dumps(binding),
            "--publication-content-identity", "2" * 64,
        ]
        if activation:
            args.extend(("--candidate-activation-identity", activation))
        return args

    def test_main_dispatches_every_committed_gate_and_strict_flag(self):
        for step in gate.GATES:
            with self.subTest(step=step), patch.object(
                sys, "argv", [
                    "gate.py", "--step", step, "--report-dir", "report",
                    "--strict-risk-gate",
                ],
            ), patch.object(gate, "gate_step1_scope") as step1, patch.object(
                gate, "gate_context",
            ) as context, patch.object(gate, "gate_scan") as scan, patch.object(
                gate, "gate_binary_generation",
            ) as generation, patch.object(
                gate, "gate_binary_report",
            ) as report, patch.object(
                gate, "gate_binary_final_report",
            ) as final, patch.object(gate.sys, "stderr", io.StringIO()):
                gate.main()
            selected = {
                "step1_scope": step1, "context": context, "scan": scan,
                "binary_generation": generation, "binary_report": report,
                "binary_final_report": final,
            }[step]
            selected.assert_called_once()
            if step in {"binary_generation", "binary_report"}:
                self.assertTrue(selected.call_args.kwargs["strict_risk_gate"])

    def test_main_rejects_every_candidate_argument_shape(self):
        valid = {
            "activation_identity": "a" * 64,
        }
        cases = (
            (
                "unsupported_step",
                ["gate.py", "--step", "context", "--publication-transaction-id", "id"],
            ),
            (
                "partial_tokens",
                ["gate.py", "--step", "binary_report", "--publication-transaction-id", "id"],
            ),
            (
                "activation_only",
                [
                    "gate.py", "--step", "binary_generation",
                    "--candidate-activation-identity", "a",
                ],
            ),
            (
                "invalid_json",
                [
                    "gate.py", "--step", "binary_report",
                    "--publication-transaction-id", "id",
                    "--publication-binding-json", "{",
                    "--publication-content-identity", "content",
                ],
            ),
            (
                "non_object_binding",
                [
                    "gate.py", "--step", "binary_report",
                    "--publication-transaction-id", "id",
                    "--publication-binding-json", "[]",
                    "--publication-content-identity", "content",
                ],
            ),
            (
                "activation_mismatch",
                self._candidate_args(
                    "binary_generation", valid, activation="b" * 64,
                ),
            ),
            (
                "downstream_activation",
                self._candidate_args(
                    "binary_report", valid, activation="a" * 64,
                ),
            ),
        )
        for label, argv in cases:
            with self.subTest(label=label), patch.object(
                sys, "argv", argv,
            ), patch.object(gate.sys, "stderr", io.StringIO()), self.assertRaises(SystemExit):
                gate.main()

    def test_main_dispatches_every_candidate_gate(self):
        generation_binding = {"activation_identity": "a" * 64}
        active_binding = {
            "result_generation_identity": "g" * 64,
            "validation_run_identity": "r" * 64,
            "validation_result_sha256": "h" * 64,
            "activation_identity": "a" * 64,
        }
        loaded = {
            "manifest": {
                "result_generation_identity": active_binding[
                    "result_generation_identity"
                ],
            },
            "active": {
                "validation_run_identity": active_binding[
                    "validation_run_identity"
                ],
                "validation_result_sha256": active_binding[
                    "validation_result_sha256"
                ],
                "activation_identity": active_binding["activation_identity"],
            },
        }
        for step, binding, destinations, activation in (
            (
                "binary_generation", generation_binding,
                ["api", "source"], generation_binding["activation_identity"],
            ),
            ("binary_generation", {}, ["api", "source"], ""),
            ("binary_report", active_binding, ["chain", "analysis", "index"], ""),
            ("binary_final_report", active_binding, ["deliverables", "findings"], ""),
        ):
            with self.subTest(step=step), patch.object(
                sys, "argv", self._candidate_args(
                    step, binding, activation=activation,
                ),
            ), patch.object(
                gate, "materialize_report_publication_gate_candidate",
                return_value={"candidate_destinations": destinations},
            ), patch.object(
                gate, "load_validated_generation", return_value=loaded,
            ), patch.object(
                gate, "gate_binary_generation",
            ) as generation, patch.object(
                gate, "gate_binary_report",
            ) as report, patch.object(
                gate, "gate_binary_final_report",
            ) as final, patch.object(gate.sys, "stderr", io.StringIO()):
                gate.main()
            {"binary_generation": generation, "binary_report": report,
             "binary_final_report": final}[step].assert_called_once()

    def test_main_rejects_incomplete_snapshot_generation_failure_and_each_binding(self):
        binding = {
            "result_generation_identity": "g" * 64,
            "validation_run_identity": "r" * 64,
            "validation_result_sha256": "h" * 64,
            "activation_identity": "a" * 64,
        }
        loaded = {
            "manifest": {"result_generation_identity": "g" * 64},
            "active": {
                "validation_run_identity": "r" * 64,
                "validation_result_sha256": "h" * 64,
                "activation_identity": "a" * 64,
            },
        }
        cases = (
            ("snapshot", binding, loaded, None),
            (
                "load_failure", binding, loaded,
                gate.BinaryFirstContractError("BROKEN", "broken"),
            ),
            ("generation", {**binding, "result_generation_identity": "x"}, loaded, None),
            ("run", {**binding, "validation_run_identity": "x"}, loaded, None),
            ("result", {**binding, "validation_result_sha256": "x"}, loaded, None),
            ("activation", {**binding, "activation_identity": "x"}, loaded, None),
        )
        for label, candidate_binding, candidate_loaded, load_error in cases:
            snapshot = (
                {"candidate_destinations": []}
                if label == "snapshot"
                else {"candidate_destinations": ["chain", "analysis", "index"]}
            )
            load_patch = patch.object(
                gate, "load_validated_generation", side_effect=load_error,
            ) if load_error is not None else patch.object(
                gate, "load_validated_generation", return_value=candidate_loaded,
            )
            with self.subTest(label=label), patch.object(
                sys, "argv", self._candidate_args("binary_report", candidate_binding),
            ), patch.object(
                gate, "materialize_report_publication_gate_candidate",
                return_value=snapshot,
            ), load_patch, patch.object(
                gate.sys, "stderr", io.StringIO(),
            ), self.assertRaises(SystemExit):
                gate.main()

    def test_main_accepts_binding_when_active_activation_is_absent(self):
        binding = {
            "result_generation_identity": "g", "validation_run_identity": "r",
            "validation_result_sha256": "h", "activation_identity": "ignored",
        }
        loaded = {
            "manifest": {"result_generation_identity": "g"},
            "active": {
                "validation_run_identity": "r", "validation_result_sha256": "h",
                "activation_identity": "",
            },
        }
        with patch.object(
            sys, "argv", self._candidate_args("binary_report", binding),
        ), patch.object(
            gate, "materialize_report_publication_gate_candidate",
            return_value={"candidate_destinations": ["chain", "analysis", "index"]},
        ), patch.object(
            gate, "load_validated_generation", return_value=loaded,
        ), patch.object(gate, "gate_binary_report") as report, patch.object(
            gate.sys, "stderr", io.StringIO(),
        ):
            gate.main()
        report.assert_called_once()


if __name__ == "__main__":
    unittest.main()
