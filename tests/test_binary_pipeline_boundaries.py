import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_pipeline  # noqa: E402
import binary_performance_gate  # noqa: E402


class BinaryPipelineStaticBoundaryTest(unittest.TestCase):
    def assert_pipeline_error(self, reason_code, callback):
        with self.assertRaises(binary_pipeline.BinaryPipelineError) as caught:
            callback()
        self.assertEqual(caught.exception.reason_code, reason_code)

    def test_source_input_contract_covers_declared_and_observed_matrix(self):
        expected_empty = binary_pipeline._source_inputs_contract({})
        self.assertEqual(expected_empty["business"]["status"], "not_provided")
        self.assertEqual(expected_empty["dependencies"]["origin"], "not_provided")

        self.assert_pipeline_error(
            "BINARY_SOURCE_INPUTS_INVALID",
            lambda: binary_pipeline._source_inputs_contract({"source_inputs": []}),
        )
        self.assert_pipeline_error(
            "BINARY_SOURCE_INPUT_PURPOSE_VERSION_MISMATCH",
            lambda: binary_pipeline._source_inputs_contract({
                "source_inputs": {"purpose_version": "stale"},
            }),
        )
        self.assert_pipeline_error(
            "BINARY_SOURCE_INPUTS_INVALID",
            lambda: binary_pipeline._source_inputs_contract({
                "source_inputs": {"business": []},
            }),
        )
        self.assert_pipeline_error(
            "BINARY_SOURCE_INPUTS_INVALID",
            lambda: binary_pipeline._source_inputs_contract({
                "source_inputs": {"dependencies": []},
            }),
        )

        overlay = {
            "source_sets": [
                None,
                {},
                {"owner_type": "business"},
                {"owner_type": "dependency"},
            ],
        }
        observed = binary_pipeline._source_inputs_contract({
            "source_overlay": overlay,
            "source_inputs": {
                "purpose_version": binary_pipeline.SOURCE_INPUT_PURPOSE_VERSION,
                "business": {"status": "available", "origin": "checkout"},
                "dependencies": {"status": "available", "origin": "uploaded"},
            },
        })
        self.assertEqual(observed["business"], {
            "status": "available", "origin": "checkout",
        })
        self.assertEqual(observed["dependencies"], {
            "status": "available", "origin": "uploaded",
        })

        inferred = binary_pipeline._source_inputs_contract({
            "source_overlay": overlay,
            "source_inputs": {"business": {}, "dependencies": {}},
        })
        self.assertEqual(inferred["business"]["origin"], "provided")
        self.assertEqual(inferred["dependencies"]["origin"], "provided")

        for field, reason in (
            ("business", "BINARY_BUSINESS_SOURCE_STATUS_MISMATCH"),
            ("dependencies", "BINARY_DEPENDENCY_SOURCE_STATUS_MISMATCH"),
        ):
            self.assert_pipeline_error(
                reason,
                lambda field=field: binary_pipeline._source_inputs_contract({
                    "source_overlay": overlay,
                    "source_inputs": {field: {"origin": "declared-without-status"}},
                }),
            )

        for field, status, reason in (
            ("business", "not_provided", "BINARY_BUSINESS_SOURCE_STATUS_MISMATCH"),
            ("dependencies", "not_provided", "BINARY_DEPENDENCY_SOURCE_STATUS_MISMATCH"),
        ):
            with self.subTest(field=field):
                self.assert_pipeline_error(
                    reason,
                    lambda field=field, status=status: (
                        binary_pipeline._source_inputs_contract({
                            "source_overlay": overlay,
                            "source_inputs": {field: {"status": status}},
                        })
                    ),
                )

    @staticmethod
    def _artifact_safety_support():
        defaults = {
            "max_archive_entries": 100,
            "max_total_uncompressed_bytes": 1000,
            "max_expansion_ratio": 20.0,
            "max_nested_depth": 5,
            "max_nested_archive_bytes": 500,
            "max_class_bytes": 200,
            "max_protocol_frame_bytes": 300,
            "max_fact_records": 400,
            "helper_timeout_seconds": 30.0,
            "helper_max_heap": "512m",
        }
        return {
            "artifact_diff_support_manifest": {
                "artifact_safety_policy": defaults,
            },
        }

    def test_artifact_safety_policy_exhausts_limit_boundaries(self):
        support = self._artifact_safety_support()
        defaults = support["artifact_diff_support_manifest"][
            "artifact_safety_policy"
        ]
        self.assertEqual(binary_pipeline._artifact_safety_policy({}, support), defaults)
        for value in ([], "limits"):
            self.assert_pipeline_error(
                "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID",
                lambda value=value: binary_pipeline._artifact_safety_policy(
                    {"artifact_safety_limits": value}, support,
                ),
            )
        self.assert_pipeline_error(
            "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID",
            lambda: binary_pipeline._artifact_safety_policy(
                {"artifact_safety_limits": {"unknown": 1}}, support,
            ),
        )

        integer_fields = set(defaults) - {
            "max_expansion_ratio", "helper_timeout_seconds", "helper_max_heap",
        }
        for field in sorted(integer_fields):
            minimum = 0 if field == "max_nested_depth" else 1
            accepted = binary_pipeline._artifact_safety_policy({
                "artifact_safety_limits": {field: minimum},
            }, support)
            self.assertEqual(accepted[field], minimum)
            for value in (True, "1", minimum - 1, defaults[field] + 1):
                with self.subTest(field=field, value=value):
                    self.assert_pipeline_error(
                        "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID",
                        lambda field=field, value=value: (
                            binary_pipeline._artifact_safety_policy({
                                "artifact_safety_limits": {field: value},
                            }, support)
                        ),
                    )

        for field, minimum in (
            ("max_expansion_ratio", 1.0),
            ("helper_timeout_seconds", 0.01),
        ):
            accepted = binary_pipeline._artifact_safety_policy({
                "artifact_safety_limits": {field: minimum},
            }, support)
            self.assertEqual(accepted[field], minimum)
            for value in (True, "1", minimum / 2, defaults[field] + 1):
                with self.subTest(field=field, value=value):
                    self.assert_pipeline_error(
                        "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID",
                        lambda field=field, value=value: (
                            binary_pipeline._artifact_safety_policy({
                                "artifact_safety_limits": {field: value},
                            }, support)
                        ),
                    )

        self.assertEqual(
            binary_pipeline._artifact_safety_policy({
                "artifact_safety_limits": {"helper_max_heap": "16m"},
            }, support)["helper_max_heap"],
            "16m",
        )
        for value in (None, "", "15m", "513m", "512", "0m"):
            with self.subTest(helper_max_heap=value):
                self.assert_pipeline_error(
                    "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID",
                    lambda value=value: binary_pipeline._artifact_safety_policy({
                        "artifact_safety_limits": {"helper_max_heap": value},
                    }, support),
                )
        invalid_default = self._artifact_safety_support()
        invalid_default["artifact_diff_support_manifest"][
            "artifact_safety_policy"
        ]["helper_max_heap"] = "invalid"
        self.assert_pipeline_error(
            "BINARY_ARTIFACT_SAFETY_LIMITS_INVALID",
            lambda: binary_pipeline._artifact_safety_policy({
                "artifact_safety_limits": {"helper_max_heap": "16m"},
            }, invalid_default),
        )

    def test_static_source_overlay_rejects_every_shape_and_path_boundary(self):
        binary_pipeline._validate_static_source_overlay({})
        binary_pipeline._validate_static_source_overlay({"source_overlay": {}})
        self.assert_pipeline_error(
            "BINARY_SOURCE_OVERLAY_INVALID",
            lambda: binary_pipeline._validate_static_source_overlay({
                "source_overlay": [],
            }),
        )
        for source_sets in (None, [], {}, [None]):
            expected = (
                "BINARY_SOURCE_SET_INVALID"
                if source_sets == [None] else "BINARY_SOURCE_SETS_REQUIRED"
            )
            self.assert_pipeline_error(
                expected,
                lambda source_sets=source_sets: (
                    binary_pipeline._validate_static_source_overlay({
                        "source_overlay": {"source_sets": source_sets},
                    })
                ),
            )

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            first = base / "first"
            second = base / "second"
            first.mkdir()
            second.mkdir()

            def validate(source_set):
                return binary_pipeline._validate_static_source_overlay({
                    "source_overlay": {"source_sets": [source_set]},
                })

            validate({
                "source_dirs": [str(first)],
                "owner_type": "business", "owner_coord": "app",
            })
            validate({
                "source_root": str(base),
                "source_dirs": [str(first), str(second)],
                "owner_type": "dependency", "owner_coord": "g:a",
            })
            for roots in (None, [], {}):
                self.assert_pipeline_error(
                    "BINARY_SOURCE_ROOT_MISSING",
                    lambda roots=roots: validate({"source_dirs": roots}),
                )
            self.assert_pipeline_error(
                "BINARY_SOURCE_COMMON_ROOT_REQUIRED",
                lambda: validate({
                    "source_dirs": [str(first), str(second)],
                    "owner_type": "business", "owner_coord": "app",
                }),
            )
            self.assert_pipeline_error(
                "BINARY_SOURCE_ROOT_MISSING",
                lambda: validate({
                    "source_root": str(base / "missing"),
                    "source_dirs": [str(first)],
                    "owner_type": "business", "owner_coord": "app",
                }),
            )
            for owner_type, owner_coord in (("other", "app"), ("business", "")):
                self.assert_pipeline_error(
                    "BINARY_SOURCE_OWNER_REQUIRED",
                    lambda owner_type=owner_type, owner_coord=owner_coord: validate({
                        "source_dirs": [str(first)],
                        "owner_type": owner_type, "owner_coord": owner_coord,
                    }),
                )
            self.assert_pipeline_error(
                "BINARY_SOURCE_OWNER_REQUIRED",
                lambda: validate({
                    "source_dirs": [str(first)], "owner_coord": "app",
                }),
            )
            self.assert_pipeline_error(
                "BINARY_SOURCE_ROOT_MISSING",
                lambda: validate({
                    "source_root": str(base),
                    "source_dirs": [str(base / "missing")],
                    "owner_type": "business", "owner_coord": "app",
                }),
            )
            with tempfile.TemporaryDirectory() as outside:
                outside_root = Path(outside).resolve()
                self.assert_pipeline_error(
                    "BINARY_SOURCE_ROOT_OUTSIDE_SNAPSHOT",
                    lambda: validate({
                        "source_root": str(base),
                        "source_dirs": [str(outside_root)],
                        "owner_type": "business", "owner_coord": "app",
                    }),
                )

    @staticmethod
    def _artifact_config(path):
        item = {
            "path": str(path),
            "logical_location": "lib/app.jar",
            "loader_realm": "application-loader",
            "path_kind": "classpath",
            "slot": 0,
            "lineage": "app",
            "runtime_code_source_origin_identity": "deployment-app",
        }
        return {"base": {"artifacts": [deepcopy(item)]},
                "current": {"artifacts": [deepcopy(item)]}}

    def test_static_artifact_input_matrix_binds_every_runtime_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifact = root / "app.jar"
            outer = root / "outer.jar"
            artifact.write_bytes(b"artifact")
            outer.write_bytes(b"outer")
            baseline = self._artifact_config(artifact)
            binary_pipeline._validate_static_artifact_inputs(baseline)

            def rejected(reason, mutate):
                config = deepcopy(baseline)
                mutate(config)
                self.assert_pipeline_error(
                    reason,
                    lambda: binary_pipeline._validate_static_artifact_inputs(config),
                )

            rejected("BINARY_PIPELINE_SIDE_CONFIG_INVALID", lambda c: c.update(base=[]))
            for value in (None, [], {}):
                rejected(
                    "BINARY_PIPELINE_ARTIFACTS_REQUIRED",
                    lambda c, value=value: c["base"].update(artifacts=value),
                )
            rejected(
                "BINARY_PIPELINE_ARTIFACT_CONFIG_INVALID",
                lambda c: c["base"].update(artifacts=[None]),
            )
            rejected(
                "BINARY_PIPELINE_ARTIFACT_MISSING",
                lambda c: c["base"]["artifacts"][0].update(path=""),
            )
            rejected(
                "BINARY_PIPELINE_ARTIFACT_MISSING",
                lambda c: c["base"]["artifacts"][0].update(path=str(root / "missing")),
            )
            rejected(
                "BINARY_PIPELINE_ARTIFACT_MISSING",
                lambda c: c["base"]["artifacts"][0].update(
                    outer_artifact_path=str(root / "missing-outer")
                ),
            )
            valid_outer = deepcopy(baseline)
            valid_outer["base"]["artifacts"][0]["outer_artifact_path"] = str(outer)
            binary_pipeline._validate_static_artifact_inputs(valid_outer)
            for field in ("content_sha256", "outer_artifact_sha256"):
                rejected(
                    "BINARY_PIPELINE_ARTIFACT_SHA256_INVALID",
                    lambda c, field=field: c["base"]["artifacts"][0].update(
                        {field: "not-a-digest"}
                    ),
                )
                valid_digest = deepcopy(baseline)
                valid_digest["base"]["artifacts"][0][field] = "a" * 64
                binary_pipeline._validate_static_artifact_inputs(valid_digest)
            for value in (True, "0", -1):
                rejected(
                    "BINARY_PIPELINE_RUNTIME_SLOT_INVALID",
                    lambda c, value=value: c["base"]["artifacts"][0].update(slot=value),
                )
            for field in ("loader_realm", "logical_location"):
                rejected(
                    "BINARY_PIPELINE_ARTIFACT_CONFIG_INVALID",
                    lambda c, field=field: c["base"]["artifacts"][0].update({field: ""}),
                )
            for logical in ("/absolute.jar", "C:\\absolute.jar"):
                rejected(
                    "RUNTIME_PROFILE_PATH_NOT_REPRODUCIBLE",
                    lambda c, logical=logical: c["base"]["artifacts"][0].update(
                        logical_location=logical
                    ),
                )
            rejected(
                "ARTIFACT_INSTANCE_PATH_KIND_INVALID",
                lambda c: c["base"]["artifacts"][0].update(path_kind="unsupported"),
            )
            rejected(
                "ARTIFACT_INSTANCE_FIELD_MISSING",
                lambda c: c["base"]["artifacts"][0].update(
                    runtime_code_source_origin_identity=""
                ),
            )

            for duplicate_field, reason in (
                ("logical_location", "BINARY_PIPELINE_LOGICAL_LOCATION_AMBIGUOUS"),
                ("slot", "BINARY_PIPELINE_RUNTIME_SLOT_INVALID"),
                ("lineage", "BINARY_ARTIFACT_LINEAGE_AMBIGUOUS"),
            ):
                def duplicate(c, duplicate_field=duplicate_field):
                    first = c["base"]["artifacts"][0]
                    second = deepcopy(first)
                    second.update({
                        "logical_location": "lib/second.jar",
                        "slot": 1,
                        "lineage": "second",
                    })
                    second[duplicate_field] = first[duplicate_field]
                    c["base"]["artifacts"].append(second)

                rejected(reason, duplicate)

            for lineage_update in (
                {"lineage": "", "coord": "g:a"},
                {"lineage": "", "coord": ""},
            ):
                config = deepcopy(baseline)
                config["base"]["artifacts"][0].update(lineage_update)
                binary_pipeline._validate_static_artifact_inputs(config)
            default_kind = deepcopy(baseline)
            default_kind["base"]["artifacts"][0].pop("path_kind")
            binary_pipeline._validate_static_artifact_inputs(default_kind)

    @staticmethod
    def _runtime_support():
        supported = {}
        for manifest_field in binary_pipeline._RUNTIME_CAPABILITY_LIST_FIELDS.values():
            supported[manifest_field] = ["one", "two"]
        for field in binary_pipeline._RUNTIME_CAPABILITY_BOOLEAN_FIELDS:
            supported[field] = True
        return {
            "runtime_loader_support_manifest": {
                "policy_version": "runtime-policy-v1",
                "supported": supported,
            },
        }

    def test_runtime_capability_policy_restricts_but_never_expands_release(self):
        support = self._runtime_support()
        default = binary_pipeline._runtime_capability_policy({}, support)
        self.assertEqual(default.policy_version, "runtime-policy-v1")
        restricted_raw = {
            field: ["one"]
            for field in binary_pipeline._RUNTIME_CAPABILITY_LIST_FIELDS
        }
        restricted_raw.update({
            field: False for field in binary_pipeline._RUNTIME_CAPABILITY_BOOLEAN_FIELDS
        })
        restricted = binary_pipeline._runtime_capability_policy({
            "runtime_capability_policy": restricted_raw,
        }, support)
        self.assertFalse(restricted.closed_world_dispatch)

        for raw in ([], "policy"):
            self.assert_pipeline_error(
                "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
                lambda raw=raw: binary_pipeline._runtime_capability_policy(
                    {"runtime_capability_policy": raw}, support,
                ),
            )
        self.assert_pipeline_error(
            "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
            lambda: binary_pipeline._runtime_capability_policy({
                "runtime_capability_policy": {"unknown": True},
            }, support),
        )
        for loader_value in (None, []):
            broken = deepcopy(support)
            broken["runtime_loader_support_manifest"] = loader_value
            self.assert_pipeline_error(
                "BINARY_AUTHORITY_MANIFEST_INVALID",
                lambda broken=broken: binary_pipeline._runtime_capability_policy({}, broken),
            )
        broken = deepcopy(support)
        broken["runtime_loader_support_manifest"]["supported"] = []
        self.assert_pipeline_error(
            "BINARY_AUTHORITY_MANIFEST_INVALID",
            lambda: binary_pipeline._runtime_capability_policy({}, broken),
        )

        policy_field, manifest_field = next(iter(
            binary_pipeline._RUNTIME_CAPABILITY_LIST_FIELDS.items()
        ))
        for value in (None, {}, [1], [""], ["one", "one"]):
            broken = deepcopy(support)
            broken["runtime_loader_support_manifest"]["supported"][
                manifest_field
            ] = value
            self.assert_pipeline_error(
                "BINARY_AUTHORITY_MANIFEST_INVALID",
                lambda broken=broken: binary_pipeline._runtime_capability_policy({}, broken),
            )
        for value in ({}, [1], [""], ["one", "one"], ["outside"]):
            self.assert_pipeline_error(
                "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
                lambda value=value: binary_pipeline._runtime_capability_policy({
                    "runtime_capability_policy": {policy_field: value},
                }, support),
            )

        boolean_field = binary_pipeline._RUNTIME_CAPABILITY_BOOLEAN_FIELDS[0]
        broken = deepcopy(support)
        broken["runtime_loader_support_manifest"]["supported"][boolean_field] = "yes"
        self.assert_pipeline_error(
            "BINARY_AUTHORITY_MANIFEST_INVALID",
            lambda: binary_pipeline._runtime_capability_policy({}, broken),
        )
        self.assert_pipeline_error(
            "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
            lambda: binary_pipeline._runtime_capability_policy({
                "runtime_capability_policy": {boolean_field: "false"},
            }, support),
        )
        unsupported = deepcopy(support)
        unsupported["runtime_loader_support_manifest"]["supported"][
            boolean_field
        ] = False
        self.assert_pipeline_error(
            "BINARY_RUNTIME_CAPABILITY_POLICY_INVALID",
            lambda: binary_pipeline._runtime_capability_policy({
                "runtime_capability_policy": {boolean_field: True},
            }, unsupported),
        )
        self.assertFalse(binary_pipeline._runtime_capability_policy({
            "runtime_capability_policy": {boolean_field: False},
        }, unsupported).__getattribute__(boolean_field))

        for version in (None, "", 1):
            broken = deepcopy(support)
            broken["runtime_loader_support_manifest"]["policy_version"] = version
            self.assert_pipeline_error(
                "BINARY_AUTHORITY_MANIFEST_INVALID",
                lambda broken=broken: binary_pipeline._runtime_capability_policy({}, broken),
            )
        with patch.object(
            binary_pipeline, "RuntimeCapabilityPolicy", side_effect=TypeError("bad")
        ):
            self.assert_pipeline_error(
                "BINARY_AUTHORITY_MANIFEST_INVALID",
                lambda: binary_pipeline._runtime_capability_policy({}, support),
            )

    def test_source_methods_cover_language_diagnostics_and_snapshot_boundaries(self):
        self.assert_pipeline_error(
            "BINARY_SOURCE_SETS_REQUIRED",
            lambda: binary_pipeline._source_methods({}),
        )
        self.assert_pipeline_error(
            "BINARY_SOURCE_COMMON_ROOT_REQUIRED",
            lambda: binary_pipeline._source_methods({"source_sets": [None]}),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = root / "first"
            second = root / "second"
            outside = root / "outside"
            first.mkdir()
            second.mkdir()
            outside.mkdir()
            (first / "A.java").write_text("class A {}\n", encoding="utf-8")
            (first / "B.kt").write_text("class B\n", encoding="utf-8")
            (first / "ignored.txt").write_text("ignored\n", encoding="utf-8")

            def run(source_set, diagnostics=None):
                with patch.object(
                    binary_pipeline,
                    "analyze_file",
                    return_value=(["method"], diagnostics),
                ), patch.object(
                    binary_pipeline,
                    "install_global_type_knowledge",
                    side_effect=lambda methods: list(methods),
                ):
                    return binary_pipeline._source_methods({
                        "source_sets": [source_set],
                    })

            complete = run({
                "source_dirs": [str(first)],
                "owner_type": "business", "owner_coord": "app",
                "snapshot_revision": "revision",
            }, diagnostics=None)
            self.assertEqual(complete[2], "partial")
            self.assertEqual(complete[3]["file_count"], 2)
            self.assertEqual(complete[3]["source_sets"][0]["snapshot_revision"], "revision")

            java_only = root / "java-only"
            java_only.mkdir()
            (java_only / "A.java").write_text("class A {}\n", encoding="utf-8")
            complete_java = run({
                "source_dirs": [str(java_only)],
                "owner_type": "dependency", "owner_coord": "g:a",
                "module": "core",
            }, diagnostics={
                "preferred_parser": "tree-sitter",
                "actual_parser": "tree-sitter",
                "fallback_reason": "",
                "tree_sitter_available": True,
                "language": "java",
                "error_nodes": 0,
            })
            self.assertEqual(complete_java[2], "complete")
            self.assertEqual(
                complete_java[3]["source_sets"][0]["snapshot_revision"],
                "content-addressed-only",
            )

            partial = run({
                "source_dirs": [str(java_only)],
                "owner_type": "business", "owner_coord": "app",
            }, diagnostics={
                "actual_parser": "skipped", "error_nodes": 1,
            })
            self.assertEqual(partial[2], "partial")
            self.assertEqual(
                partial[3]["coverage_gaps"][0]["reason_code"],
                "BINARY_SOURCE_PARSE_PARTIAL",
            )
            partial_error_nodes = run({
                "source_dirs": [str(java_only)],
                "owner_type": "business", "owner_coord": "app",
            }, diagnostics={
                "actual_parser": "tree-sitter", "error_nodes": 1,
            })
            self.assertEqual(partial_error_nodes[2], "partial")
            partial_sparse = run({
                "source_dirs": [str(java_only)],
                "owner_type": "business", "owner_coord": "app",
            }, diagnostics={
                "actual_parser": "", "error_nodes": 1,
            })
            self.assertEqual(
                partial_sparse[3]["coverage_gaps"][0]["actual_parser"], ""
            )
            skipped_without_errors = run({
                "source_dirs": [str(java_only)],
                "owner_type": "business", "owner_coord": "app",
            }, diagnostics={"actual_parser": "skipped", "error_nodes": None})
            self.assertEqual(
                skipped_without_errors[3]["coverage_gaps"][0]["error_nodes"], 0
            )

            for source_set, reason in (
                ({"source_dirs": [str(first), str(second)]},
                 "BINARY_SOURCE_COMMON_ROOT_REQUIRED"),
                ({"source_root": str(root / "missing"), "source_dirs": [str(first)],
                  "owner_type": "business", "owner_coord": "app"},
                 "BINARY_SOURCE_ROOT_MISSING"),
                ({"source_dirs": [str(first)], "owner_type": "invalid", "owner_coord": "app"},
                 "BINARY_SOURCE_OWNER_REQUIRED"),
                ({"source_dirs": [str(first)], "owner_coord": "app"},
                 "BINARY_SOURCE_OWNER_REQUIRED"),
                ({"source_dirs": [str(first)], "owner_type": "business", "owner_coord": ""},
                 "BINARY_SOURCE_OWNER_REQUIRED"),
                ({"source_root": str(root), "source_dirs": [str(root / "missing")],
                  "owner_type": "business", "owner_coord": "app"},
                 "BINARY_SOURCE_ROOT_MISSING"),
            ):
                self.assert_pipeline_error(
                    reason,
                    lambda source_set=source_set: run(source_set),
                )
            with tempfile.TemporaryDirectory() as other:
                self.assert_pipeline_error(
                    "BINARY_SOURCE_ROOT_OUTSIDE_SNAPSHOT",
                    lambda: run({
                        "source_root": str(root),
                        "source_dirs": [str(Path(other).resolve())],
                        "owner_type": "business", "owner_coord": "app",
                    }),
                )

    def test_source_explanations_project_sparse_and_complete_method_views(self):
        rows = [
            None,
            {"mapping_status": "ambiguous", "source_location": {"source_symbol_id": "x"}},
            {"mapping_status": "mapped", "source_location": {}},
            {"mapping_status": "mapped", "source_location": None},
            {
                "mapping_status": "mapped",
                "overlay_identity": "overlay-full",
                "source_location": {
                    "source_symbol_id": "full", "owner_type": "business",
                    "owner_coord": "app", "logical_path": "A.java",
                    "line": 1, "end_line": 2,
                },
                "binary_member": {
                    "artifact_coord": "app", "class_name": "p/A",
                    "member_name": "run", "descriptor": "(I)V",
                },
            },
            {
                "mapping_status": "mapped",
                "overlay_identity": None,
                "source_location": {"source_symbol_id": "sparse"},
                "binary_member": None,
            },
            {
                "mapping_status": "mapped",
                "overlay_identity": "overlay-fallback",
                "source_location": {"source_symbol_id": "fallback"},
                "binary_member": {},
            },
            {
                "mapping_status": "mapped",
                "overlay_identity": "overlay-empty",
                "source_location": {"source_symbol_id": "empty"},
                "binary_member": {},
            },
        ]
        methods = [
            SimpleNamespace(symbol_id="missing"),
            SimpleNamespace(
                symbol_id="full", declared_signature="void run(int)",
                annotations=("A",), modifiers=("public",),
                throws_declared_types=("Exception",), method_name="run",
            ),
            SimpleNamespace(
                symbol_id="sparse", declared_signature="",
                param_declared_types={"a": "String"}, param_types={"a": "Object"},
                return_declared_type="Result", return_type="Object",
                annotations=(), modifiers=(), throws_declared_types=(),
                method_name="call",
            ),
            SimpleNamespace(
                symbol_id="fallback", declared_signature="",
                param_declared_types={}, param_types={"a": "Object"},
                return_declared_type="", return_type="Object",
                annotations=None, modifiers=("public",), throws_declared_types=None,
                method_name="fallback",
            ),
            SimpleNamespace(
                symbol_id="empty", declared_signature="",
                param_declared_types=None, param_types=None,
                return_declared_type=None, return_type=None,
                annotations=None, modifiers=None, throws_declared_types=None,
                method_name="empty",
            ),
            SimpleNamespace(symbol_id=""),
        ]
        edges = [
            SimpleNamespace(
                line=7, callee_key="p/B.call()V", callee_simple_key="B.call",
                evidence_type="source", confidence="possible",
            ),
            SimpleNamespace(
                line=None, callee_key=None, callee_simple_key=None,
                evidence_type=None, confidence=None,
            ),
        ]
        overlay = SimpleNamespace(rows=rows)
        with patch.object(
            binary_pipeline, "extract_call_edges_enhanced", return_value=edges,
        ):
            result = binary_pipeline._source_explanations(
                methods, overlay, analysis_context_identity="context",
            )
        self.assertEqual(result["declaration_count"], 4)
        self.assertEqual(result["candidate_relationship_count"], 8)
        signatures = {
            item["declared_signature"] for item in result["declarations"]
        }
        self.assertIn("Result call(String)", signatures)
        self.assertIn("public Object fallback(Object)", signatures)
        self.assertIn("empty()", signatures)
        self.assertEqual(result["analysis_context_identity"], "context")


class BinaryPipelineResumeBoundaryTest(unittest.TestCase):
    def assert_pipeline_error(self, reason_code, callback):
        with self.assertRaises(binary_pipeline.BinaryPipelineError) as caught:
            callback()
        self.assertEqual(caught.exception.reason_code, reason_code)

    @staticmethod
    def _generation_manifest(root, *, sidecar_payloads=None):
        snapshots = {
            key: str(index + 1) * 64
            for index, key in enumerate(
                sorted(binary_pipeline._RESULT_GENERATION_SNAPSHOT_LAYERS)
            )
        }
        policies = {
            "analysis_scope": "5" * 64,
            "runtime_comparison": "6" * 64,
            "base_jdk_preflight_identity": "e" * 64,
            "current_jdk_preflight_identity": "f" * 64,
        }
        if sidecar_payloads is None:
            sidecar_payloads = {
                name: f"fixture:{name}\n".encode()
                for name in binary_pipeline._REQUIRED_PIPELINE_GENERATION_SIDECARS
            }
        sidecars = {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in sidecar_payloads.items()
        }
        manifest = {
            "schema": "java-upgrade-analyzer.binary-result-generation.v1",
            "authority": "binary_first",
            "analysis_context_identity": "7" * 64,
            "active_snapshot_identities": snapshots,
            "trace_result_set_digest": "8" * 64,
            "sidecar_content_identities": sidecars,
            "policy_identities": policies,
        }
        generation_identity = binary_pipeline._identity(
            "result_generation_identity",
            {
                "analysis_context_identity": manifest["analysis_context_identity"],
                "authority": "binary_first",
                "snapshot_identities": snapshots,
                "trace_result_set_digest": manifest["trace_result_set_digest"],
                "sidecar_content_identities": sidecars,
                "policy_identities": policies,
            },
        )
        manifest["result_generation_identity"] = generation_identity
        generation = root / generation_identity
        generation.mkdir(parents=True)
        for name, payload in sidecar_payloads.items():
            path = generation / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        return generation, manifest

    def test_resume_generation_integrity_rejects_every_manifest_and_sidecar_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            generation, manifest = self._generation_manifest(root / "valid")
            self.assertTrue(
                binary_pipeline._resume_generation_integrity_valid(
                    generation, manifest
                )
            )

            mutations = {
                "schema": lambda value: value.update(schema="wrong"),
                "authority": lambda value: value.update(authority="other"),
                "snapshots_type": lambda value: value.update(
                    active_snapshot_identities=[]
                ),
                "snapshot_keys": lambda value: value[
                    "active_snapshot_identities"
                ].pop(next(iter(value["active_snapshot_identities"]))),
                "snapshot_identity": lambda value: value[
                    "active_snapshot_identities"
                ].update({next(iter(value["active_snapshot_identities"])): "bad"}),
                "sidecars_type": lambda value: value.update(
                    sidecar_content_identities=[]
                ),
                "sidecars_required": lambda value: value[
                    "sidecar_content_identities"
                ].pop(next(iter(binary_pipeline._REQUIRED_PIPELINE_GENERATION_SIDECARS))),
                "policies_type": lambda value: value.update(policy_identities=[]),
                "base_policy": lambda value: value["policy_identities"].update(
                    base_jdk_preflight_identity="bad"
                ),
                "current_policy": lambda value: value["policy_identities"].update(
                    current_jdk_preflight_identity="bad"
                ),
                "context_type": lambda value: value.update(
                    analysis_context_identity=1
                ),
                "context_empty": lambda value: value.update(
                    analysis_context_identity=""
                ),
                "trace_type": lambda value: value.update(
                    trace_result_set_digest=1
                ),
                "trace_empty": lambda value: value.update(
                    trace_result_set_digest=""
                ),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    changed = deepcopy(manifest)
                    mutate(changed)
                    self.assertFalse(
                        binary_pipeline._resume_generation_integrity_valid(
                            generation, changed
                        )
                    )

            wrong_identity = deepcopy(manifest)
            wrong_identity["result_generation_identity"] = "0" * 64
            self.assertFalse(
                binary_pipeline._resume_generation_integrity_valid(
                    generation, wrong_identity
                )
            )
            other_generation = generation.parent / ("9" * 64)
            other_generation.mkdir()
            self.assertFalse(
                binary_pipeline._resume_generation_integrity_valid(
                    other_generation, manifest
                )
            )

            for index, (name, digest) in enumerate((
                ("", "a" * 64),
                (".", "a" * 64),
                ("..", "a" * 64),
                ("sub/file", "a" * 64),
                ("sub\\file", "a" * 64),
                ("bad\x00name", "a" * 64),
                ("extra.json", "bad"),
            )):
                with self.subTest(sidecar_name=repr(name)):
                    changed = deepcopy(manifest)
                    changed["sidecar_content_identities"][name] = digest
                    with patch.object(
                        binary_pipeline, "_identity",
                        return_value=generation.name,
                    ):
                        self.assertFalse(
                            binary_pipeline._resume_generation_integrity_valid(
                                generation, changed
                            )
                        )
            changed = deepcopy(manifest)
            changed["sidecar_content_identities"][1] = "a" * 64
            with patch.object(
                binary_pipeline, "_identity", return_value=generation.name,
            ):
                self.assertFalse(
                    binary_pipeline._resume_generation_integrity_valid(
                        generation, changed
                    )
                )

            sidecar_name = next(iter(manifest["sidecar_content_identities"]))
            sidecar = generation / sidecar_name
            original = sidecar.read_bytes()
            sidecar.unlink()
            self.assertFalse(
                binary_pipeline._resume_generation_integrity_valid(
                    generation, manifest
                )
            )
            sidecar.write_bytes(b"forged")
            self.assertFalse(
                binary_pipeline._resume_generation_integrity_valid(
                    generation, manifest
                )
            )
            sidecar.write_bytes(original)
            link_target = generation / "link-target"
            link_target.write_bytes(original)
            sidecar.unlink()
            try:
                sidecar.symlink_to(link_target)
            except OSError:
                pass
            else:
                self.assertFalse(
                    binary_pipeline._resume_generation_integrity_valid(
                        generation, manifest
                    )
                )

    @staticmethod
    def _failed_validation(manifest):
        issues = [{
            "domain": "direct_edge",
            "reason_code": "ORACLE_DIRECT_EDGE_MISSING",
            "evidence": {"edge": ["caller", "callee"]},
        }]
        helper_identities = {"base": "e" * 64}
        validation = {
            "schema": "java-upgrade-analyzer.binary-validation-result.v1",
            "result_generation_identity": manifest["result_generation_identity"],
            "oracle_support_manifest_identity": (
                binary_pipeline._current_oracle_support_manifest_identity()
            ),
            "truth_set_identity": "1" * 64,
            "issue_set_identity": binary_pipeline.canonical_identity_streaming(
                "binary_validation_issue_set_identity", issues,
                schema_version="1",
            ),
            "validation_policy_version": binary_pipeline._VALIDATION_POLICY_VERSION,
            "validator_implementation_identity": (
                binary_pipeline._current_validator_implementation_identity()
            ),
            "status": "failed",
            "issue_count": 1,
            "issues": issues,
            "domain_summary": {"direct_edge": {"issues": 1}},
            "helper_identities": helper_identities,
            "skipped_domains": [{"domain": "optional", "reason_code": "NOT_RUN"}],
            "production_identity_influence": "none_validation_attachment_only",
        }
        BinaryPipelineResumeBoundaryTest._rebind_validation_identity(
            validation, manifest
        )
        return validation

    @staticmethod
    def _rebind_validation_identity(validation, manifest):
        validation["validation_run_identity"] = binary_pipeline._identity(
            "binary_validation_run_identity",
            {
                "result_generation_identity": manifest[
                    "result_generation_identity"
                ],
                "active_snapshot_identities": dict(
                    manifest["active_snapshot_identities"]
                ),
                "oracle_support_manifest_identity": validation[
                    "oracle_support_manifest_identity"
                ],
                "truth_set_identity": validation["truth_set_identity"],
                "issue_set_identity": validation["issue_set_identity"],
                "validation_policy_version": validation[
                    "validation_policy_version"
                ],
                "validator_implementation_identity": validation[
                    "validator_implementation_identity"
                ],
                "helper_identities": dict(validation["helper_identities"]),
            },
        )

    @staticmethod
    def _write_validation_attachment(
        generation, validation, *, content=None, filename=None,
    ):
        validation_dir = generation / "validation"
        validation_dir.mkdir(parents=True, exist_ok=True)
        path = validation_dir / (
            filename or f"{validation['validation_run_identity']}.json"
        )
        payload = (
            binary_pipeline._canonical_json_bytes(validation)
            if content is None else content
        )
        path.write_bytes(payload)
        return path, hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _minimal_checkpoint(manifest, *, status=None):
        checkpoint = {
            "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
            "status": status or binary_pipeline._RESUME_AWAITING_VALIDATION,
            "result_generation_identity": manifest[
                "result_generation_identity"
            ],
        }
        checkpoint["checkpoint_content_identity"] = (
            binary_pipeline._resume_checkpoint_content_identity(checkpoint)
        )
        return checkpoint

    @staticmethod
    def _performance_binding(label):
        binding = {
            "schema": "java-upgrade-analyzer.performance-authority-binding.v2",
            "authority_mode": binary_pipeline._PERFORMANCE_RELEASE_AUTHORITY_MODE,
            "support_contract_identity": hashlib.sha256(
                f"support:{label}".encode()
            ).hexdigest(),
            "evidence_sha256": hashlib.sha256(
                f"evidence:{label}".encode()
            ).hexdigest(),
            "source_implementation_identity": hashlib.sha256(
                f"source:{label}".encode()
            ).hexdigest(),
        }
        binding["binding_identity"] = binary_pipeline._identity(
            "binary_performance_authority_binding_identity",
            {
                field: binding[field]
                for field in (
                    "support_contract_identity", "evidence_sha256",
                    "source_implementation_identity", "authority_mode",
                )
            },
        )
        return binding

    @staticmethod
    def _performance_binding_for_mode(label, mode):
        binding = BinaryPipelineResumeBoundaryTest._performance_binding(label)
        binding["authority_mode"] = mode
        binding["binding_identity"] = binary_pipeline._identity(
            "binary_performance_authority_binding_identity",
            {
                field: binding[field]
                for field in (
                    "support_contract_identity", "evidence_sha256",
                    "source_implementation_identity", "authority_mode",
                )
            },
        )
        return binding

    @staticmethod
    def _performance_authority_evidence():
        current = {
            "generation_source_identity": "1" * 64,
            "validator_source_identity": "2" * 64,
            "oracle_support_manifest_identity": "3" * 64,
            "harness_source_identity": "4" * 64,
            "source_implementation_identity": "5" * 64,
        }
        evidence = {
            "schema": "java-upgrade-analyzer.binary-first-performance-gate.v1",
            "status": "passed",
            "blocks_binary_authority_switch": False,
            "recorded_measurements": {"warm_parser_invocations": 0},
            "accuracy_invariants": {"warm_parser_invocations": 0},
            "measurement_protocol": {
                "implementation": dict(current),
                "source_implementation_identity": current[
                    "source_implementation_identity"
                ],
            },
        }
        return evidence, current

    def _invoke_performance_authority(
        self,
        root,
        evidence,
        current,
        *,
        support_mutation=None,
        generation_source_records=(),
        reuse_verified_generation_records_for_runtime=False,
        recorded_result=None,
        provisional_result=None,
        runtime_implementation=None,
    ):
        content = json.dumps(
            evidence,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        evidence_path = root / "performance.json"
        evidence_path.write_bytes(content)
        support = {
            "performance_gate": {
                "status": "passed",
                "blocks_binary_authority_switch": False,
                "path": binary_pipeline.PERFORMANCE_GATE_CONTRACT_PATH,
                "sha256": hashlib.sha256(content).hexdigest(),
                "warm_parser_invocations": 0,
                "source_implementation_identity": current[
                    "source_implementation_identity"
                ],
            },
        }
        if support_mutation is not None:
            support_mutation(support)
        recorded_result = (
            {"status": "passed", "issues": []}
            if recorded_result is None else recorded_result
        )
        provisional_result = (
            {"status": "passed", "issues": []}
            if provisional_result is None else provisional_result
        )
        runtime_implementation = (
            dict(current)
            if runtime_implementation is None else runtime_implementation
        )

        def recorded_evaluator(*_args, **_kwargs):
            if isinstance(recorded_result, BaseException):
                raise recorded_result
            return recorded_result

        def provisional_evaluator(*_args, **_kwargs):
            if isinstance(provisional_result, BaseException):
                raise provisional_result
            return provisional_result

        with patch.object(
            binary_pipeline, "PERFORMANCE_GATE_PATH", evidence_path,
        ), patch.object(
            binary_pipeline,
            "_verify_captured_generation_sources",
            return_value=[],
        ), patch.object(
            binary_pipeline,
            "performance_generation_source_identity",
            return_value=current["generation_source_identity"],
        ), patch.object(
            binary_pipeline,
            "validator_source_identity",
            return_value=current["validator_source_identity"],
        ), patch.object(
            binary_pipeline,
            "oracle_support_manifest_identity",
            return_value=current["oracle_support_manifest_identity"],
        ), patch.object(
            binary_pipeline,
            "performance_harness_source_identity",
            return_value=current["harness_source_identity"],
        ), patch.object(
            binary_pipeline,
            "performance_source_implementation_identity",
            return_value=current["source_implementation_identity"],
        ), patch.object(
            binary_pipeline, "resolve_asm_jar", return_value=root / "asm.jar",
        ), patch.object(
            binary_performance_gate,
            "_performance_implementation_protocol",
            return_value=runtime_implementation,
        ), patch.object(
            binary_performance_gate,
            "evaluate_recorded_gate",
            side_effect=recorded_evaluator,
        ), patch.object(
            binary_performance_gate,
            "evaluate_provisional_gate",
            side_effect=provisional_evaluator,
        ):
            return binary_pipeline._performance_authority_gate_binding(
                support,
                generation_source_records=generation_source_records,
                asm_jar=root / "asm.jar",
                reuse_verified_generation_records_for_runtime=(
                    reuse_verified_generation_records_for_runtime
                ),
            )

    @staticmethod
    def _checkpoint_fixture(*, performance_binding=None):
        config = {}
        support = binary_pipeline._load_support_manifest_snapshot()
        policies = {
            "analysis_scope": "5" * 64,
            "runtime_comparison": "6" * 64,
            "base_jdk_preflight_identity": "e" * 64,
            "current_jdk_preflight_identity": "f" * 64,
        }
        manifest = {
            "result_generation_identity": "a" * 64,
            "analysis_context_identity": "7" * 64,
            "policy_identities": policies,
        }
        summary = {
            "base_runtime_reconciliation_identity": "9" * 64,
            "current_runtime_reconciliation_identity": "a" * 64,
            "decision_bundle_identity": "b" * 64,
            "trace_bundle_identity": "c" * 64,
            "decision_coverage_status": "complete",
            "trace_coverage_status": "complete",
            "authoritative_change_fact_count": 1,
            "diagnostic_candidate_fact_count": 0,
        }
        validation_index = binary_pipeline._PhaseTimingRecorder.ORDER.index(
            "independent_validation"
        )
        checkpoint = {
            "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
            "status": binary_pipeline._RESUME_AWAITING_VALIDATION,
            "created_at": "2026-08-23T00:00:00+00:00",
            "config_identity": "1" * 64,
            "implementation_identity": "2" * 64,
            "input_artifact_identity": "3" * 64,
            "source_input_identity": (
                binary_pipeline._resume_source_input_identity(config)
            ),
            "result_generation_identity": manifest[
                "result_generation_identity"
            ],
            "runtime_comparison_identity": policies["runtime_comparison"],
            "analysis_scope_identity": policies["analysis_scope"],
            "analysis_context_identity": manifest[
                "analysis_context_identity"
            ],
            "base_jdk_preflight_identity": policies[
                "base_jdk_preflight_identity"
            ],
            "current_jdk_preflight_identity": policies[
                "current_jdk_preflight_identity"
            ],
            "result_summary": summary,
            "source_inputs": {},
            "artifact_safety_policy": binary_pipeline._artifact_safety_policy(
                config, support
            ),
            "cache_metrics": {},
            "phase_timings_before_validation": [
                {"phase": phase, "elapsed_seconds": float(index)}
                for index, phase in enumerate(
                    binary_pipeline._PhaseTimingRecorder.ORDER[:validation_index]
                )
            ],
            "performance_authority_gate_binding": (
                dict(performance_binding)
                if performance_binding is not None else None
            ),
        }
        checkpoint = binary_pipeline._normalized_resume_checkpoint(checkpoint)
        toolchain = {
            "base": {"jdk_preflight_identity": "e" * 64},
            "current": {"jdk_preflight_identity": "f" * 64},
        }
        return checkpoint, manifest, config, support, toolchain

    @staticmethod
    def _rebind_checkpoint(checkpoint):
        checkpoint["checkpoint_content_identity"] = (
            binary_pipeline._resume_checkpoint_content_identity(checkpoint)
        )

    def test_resume_checkpoint_metadata_exhausts_integrity_shape_and_binding_matrix(self):
        checkpoint, manifest, config, support, toolchain = (
            self._checkpoint_fixture()
        )

        def evaluate(
            candidate=checkpoint, manifest_value=manifest,
            config_value=config, source_inputs=None,
            toolchain_value=toolchain, performance_binding=None,
        ):
            with patch.object(
                binary_pipeline, "_load_support_manifest_snapshot",
                return_value=deepcopy(support),
            ):
                return binary_pipeline._resume_checkpoint_metadata(
                    candidate,
                    manifest_value,
                    config_value,
                    {} if source_inputs is None else source_inputs,
                    toolchain_value,
                    performance_binding,
                )

        reason, metadata = evaluate()
        self.assertEqual(reason, "")
        self.assertEqual(metadata["result_summary"], checkpoint["result_summary"])

        invalid_integrity = deepcopy(checkpoint)
        invalid_integrity["checkpoint_content_identity"] = "bad"
        self.assertEqual(
            evaluate(invalid_integrity)[0],
            "BINARY_RESUME_CHECKPOINT_INTEGRITY_INVALID",
        )
        mismatched_integrity = deepcopy(checkpoint)
        mismatched_integrity["created_at"] = "changed"
        self.assertEqual(
            evaluate(mismatched_integrity)[0],
            "BINARY_RESUME_CHECKPOINT_INTEGRITY_INVALID",
        )
        with patch.object(
            binary_pipeline, "_resume_checkpoint_content_identity",
            side_effect=ValueError("broken"),
        ):
            self.assertEqual(
                binary_pipeline._resume_checkpoint_metadata(
                    checkpoint, manifest, config, {}, toolchain, None,
                )[0],
                "BINARY_RESUME_CHECKPOINT_INTEGRITY_INVALID",
            )

        def rejected(expected_reason, mutate, **kwargs):
            changed = deepcopy(checkpoint)
            mutate(changed)
            self._rebind_checkpoint(changed)
            self.assertEqual(evaluate(changed, **kwargs)[0], expected_reason)

        rejected(
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
            lambda value: value.pop("cache_metrics"),
        )
        rejected(
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
            lambda value: value.update(created_at=1),
        )
        rejected(
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
            lambda value: value.update(created_at=""),
        )
        for field in (
            "config_identity", "implementation_identity",
            "input_artifact_identity", "source_input_identity",
            "result_generation_identity", "runtime_comparison_identity",
            "analysis_scope_identity", "analysis_context_identity",
            "base_jdk_preflight_identity", "current_jdk_preflight_identity",
        ):
            rejected(
                "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
                lambda value, field=field: value.update({field: "bad"}),
            )
        rejected(
            "BINARY_RESUME_VALIDATION_STATE_INVALID",
            lambda value: value.update(status="unknown"),
        )
        rejected(
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
            lambda value: value.update(extra="unexpected"),
        )

        for status in (
            binary_pipeline._RESUME_VALIDATION_FAILED,
            binary_pipeline._RESUME_VALIDATION_PASSED,
        ):
            changed = deepcopy(checkpoint)
            changed.update({
                "status": status,
                "validation_run_identity": "d" * 64,
                "validation_result_sha256": "e" * 64,
            })
            if status == binary_pipeline._RESUME_VALIDATION_PASSED:
                changed["activation_identity"] = "f" * 64
            self._rebind_checkpoint(changed)
            self.assertEqual(evaluate(changed)[0], "")
            for field in ("validation_run_identity", "validation_result_sha256"):
                invalid = deepcopy(changed)
                invalid[field] = "bad"
                self._rebind_checkpoint(invalid)
                self.assertEqual(
                    evaluate(invalid)[0],
                    "BINARY_RESUME_VALIDATION_STATE_INVALID",
                )
            if status == binary_pipeline._RESUME_VALIDATION_PASSED:
                invalid = deepcopy(changed)
                invalid["activation_identity"] = "bad"
                self._rebind_checkpoint(invalid)
                self.assertEqual(
                    evaluate(invalid)[0],
                    "BINARY_RESUME_VALIDATION_STATE_INVALID",
                )

        broken_toolchain = deepcopy(toolchain)
        broken_toolchain["base"] = []
        self.assertEqual(
            evaluate(toolchain_value=broken_toolchain)[0],
            "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH",
        )
        broken_toolchain = deepcopy(toolchain)
        broken_toolchain["current"]["jdk_preflight_identity"] = ""
        self.assertEqual(
            evaluate(toolchain_value=broken_toolchain)[0],
            "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH",
        )
        broken_manifest = deepcopy(manifest)
        broken_manifest["policy_identities"] = []
        self.assertEqual(
            evaluate(manifest_value=broken_manifest)[0],
            "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH",
        )
        for checkpoint_field, policy_field in (
            ("analysis_context_identity", None),
            ("analysis_scope_identity", "analysis_scope"),
            ("runtime_comparison_identity", "runtime_comparison"),
            ("base_jdk_preflight_identity", "base_jdk_preflight_identity"),
            ("current_jdk_preflight_identity", "current_jdk_preflight_identity"),
        ):
            broken_manifest = deepcopy(manifest)
            if policy_field is None:
                broken_manifest["analysis_context_identity"] = "0" * 64
            else:
                broken_manifest["policy_identities"][policy_field] = "0" * 64
            self.assertEqual(
                evaluate(manifest_value=broken_manifest)[0],
                "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH",
                checkpoint_field,
            )

        rejected(
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
            lambda value: value.update(result_summary=[]),
        )
        rejected(
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
            lambda value: value["result_summary"].pop(
                "trace_coverage_status"
            ),
        )
        for field in (
            "base_runtime_reconciliation_identity",
            "current_runtime_reconciliation_identity",
            "decision_bundle_identity", "trace_bundle_identity",
        ):
            rejected(
                "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
                lambda value, field=field: value["result_summary"].update(
                    {field: "bad"}
                ),
            )
        for field in ("decision_coverage_status", "trace_coverage_status"):
            for invalid in (1, ""):
                rejected(
                    "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
                    lambda value, field=field, invalid=invalid: value[
                        "result_summary"
                    ].update({field: invalid}),
                )
        for field in (
            "authoritative_change_fact_count",
            "diagnostic_candidate_fact_count",
        ):
            for invalid in (True, -1):
                rejected(
                    "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
                    lambda value, field=field, invalid=invalid: value[
                        "result_summary"
                    ].update({field: invalid}),
                )

        for field, invalid in (
            ("source_inputs", []),
            ("artifact_safety_policy", []),
            ("cache_metrics", []),
            ("phase_timings_before_validation", ()),
        ):
            rejected(
                "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
                lambda value, field=field, invalid=invalid: value.update(
                    {field: invalid}
                ),
            )
        rejected(
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
            lambda value: value.update(performance_authority_gate_binding={}),
        )

        first_binding = self._performance_binding("first")
        second_binding = self._performance_binding("second")
        bound_checkpoint, bound_manifest, bound_config, bound_support, bound_toolchain = (
            self._checkpoint_fixture(performance_binding=first_binding)
        )
        with patch.object(
            binary_pipeline, "_load_support_manifest_snapshot",
            return_value=deepcopy(bound_support),
        ):
            reason, bound_metadata = binary_pipeline._resume_checkpoint_metadata(
                bound_checkpoint, bound_manifest, bound_config, {},
                bound_toolchain, first_binding,
            )
            self.assertEqual(reason, "")
            self.assertFalse(
                bound_metadata["performance_authority_rebind_required"]
            )
            reason, rebound_metadata = binary_pipeline._resume_checkpoint_metadata(
                bound_checkpoint, bound_manifest, bound_config, {},
                bound_toolchain, second_binding,
            )
            self.assertEqual(reason, "")
            self.assertTrue(
                rebound_metadata["performance_authority_rebind_required"]
            )
            self.assertEqual(
                binary_pipeline._resume_checkpoint_metadata(
                    bound_checkpoint, bound_manifest, bound_config, {},
                    bound_toolchain, None,
                )[0],
                "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
            )
        self.assertEqual(
            evaluate(performance_binding=first_binding)[0],
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
        )

        rejected(
            "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH",
            lambda value: value.update(source_inputs={"forged": True}),
        )
        rejected(
            "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH",
            lambda value: value.update(source_input_identity="0" * 64),
        )
        rejected(
            "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH",
            lambda value: value["artifact_safety_policy"].update(
                max_archive_entries=1
            ),
        )
        rejected(
            "BINARY_RESUME_CHECKPOINT_FIELDS_INVALID",
            lambda value: value.update(phase_timings_before_validation=[]),
        )
        with patch.object(
            binary_pipeline, "_load_support_manifest_snapshot",
            side_effect=OSError("broken"),
        ):
            self.assertEqual(
                binary_pipeline._resume_checkpoint_metadata(
                    checkpoint, manifest, config, {}, toolchain, None,
                )[0],
                "BINARY_RESUME_CHECKPOINT_BINDING_MISMATCH",
            )

    def test_failed_validation_attachment_requires_exact_canonical_binding(self):
        manifest = {
            "result_generation_identity": "a" * 64,
            "active_snapshot_identities": {"decision": "b" * 64},
        }
        valid = self._failed_validation(manifest)
        self.assertEqual(set(valid), binary_pipeline._VALIDATION_ATTACHMENT_FIELDS)
        self.assertTrue(
            binary_pipeline._failed_validation_attachment_is_bound(valid, manifest)
        )

        def rejected(mutate, *, rebind=False):
            changed = deepcopy(valid)
            mutate(changed)
            if rebind:
                self._rebind_validation_identity(changed, manifest)
            self.assertFalse(
                binary_pipeline._failed_validation_attachment_is_bound(
                    changed, manifest
                )
            )

        early_mutations = (
            lambda value: value.update(extra=True),
            lambda value: value.update(schema="wrong"),
            lambda value: value.update(status="passed"),
            lambda value: value.update(result_generation_identity="c" * 64),
            lambda value: value.update(issue_count=True),
            lambda value: value.update(issue_count=0),
            lambda value: value.update(issues={}),
            lambda value: value["issues"].append(deepcopy(value["issues"][0])),
            lambda value: value.update(domain_summary=[]),
            lambda value: value.update(skipped_domains={}),
            lambda value: value.update(helper_identities=[]),
            lambda value: value.update(helper_identities={"other": "e" * 64}),
            lambda value: value.update(validation_policy_version="old"),
            lambda value: value.update(production_identity_influence="facts"),
            lambda value: value.update(issues=[None]),
            lambda value: value["issues"][0].update(domain=1),
            lambda value: value["issues"][0].update(domain=""),
            lambda value: value.update(domain_summary={}),
        )
        for index, mutate in enumerate(early_mutations):
            with self.subTest(early=index):
                rejected(mutate)

        skipped_mutations = (
            lambda value: value.update(skipped_domains=[None]),
            lambda value: value["skipped_domains"][0].update(extra="x"),
            lambda value: value["skipped_domains"][0].update(domain=1),
            lambda value: value["skipped_domains"][0].update(domain=""),
            lambda value: value["skipped_domains"][0].update(reason_code=1),
            lambda value: value["skipped_domains"][0].update(reason_code=""),
            lambda value: value.update(skipped_domains=[
                {"domain": "z", "reason_code": "Z"},
                {"domain": "a", "reason_code": "A"},
            ]),
            lambda value: value.update(
                skipped_domains=[deepcopy(value["skipped_domains"][0])] * 2
            ),
        )
        for index, mutate in enumerate(skipped_mutations):
            with self.subTest(skipped=index):
                rejected(mutate)

        for field in (
            "validation_run_identity", "oracle_support_manifest_identity",
            "truth_set_identity", "issue_set_identity",
            "validator_implementation_identity",
        ):
            rejected(lambda value, field=field: value.update({field: "bad"}))
        rejected(
            lambda value: value["helper_identities"].update(base="bad")
        )

        with patch.object(
            binary_pipeline, "canonical_identity_streaming",
            side_effect=ValueError("broken"),
        ):
            self.assertFalse(
                binary_pipeline._failed_validation_attachment_is_bound(
                    valid, manifest
                )
            )

        rejected(
            lambda value: value.update(issue_set_identity="2" * 64),
            rebind=True,
        )
        rejected(
            lambda value: value.update(oracle_support_manifest_identity="3" * 64),
            rebind=True,
        )
        rejected(
            lambda value: value.update(validator_implementation_identity="4" * 64),
            rebind=True,
        )
        rejected(
            lambda value: value.update(validation_run_identity="5" * 64)
        )

    def test_resume_source_identity_binds_logical_roots_and_source_bytes(self):
        empty = binary_pipeline._resume_source_input_identity({})
        self.assertEqual(
            empty,
            binary_pipeline._resume_source_input_identity({"source_overlay": []}),
        )
        self.assert_pipeline_error(
            "BINARY_RESUME_SOURCE_COMMON_ROOT_REQUIRED",
            lambda: binary_pipeline._resume_source_input_identity({
                "source_overlay": {"source_sets": [None]},
            }),
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            (first / "A.java").write_text("class A {}\n", encoding="utf-8")
            (first / "B.kt").write_text("class B\n", encoding="utf-8")
            (first / "ignored.txt").write_text("ignored\n", encoding="utf-8")

            implicit = binary_pipeline._resume_source_input_identity({
                "source_overlay": {"source_sets": [{
                    "source_dirs": [str(first)],
                }]},
            })
            explicit = binary_pipeline._resume_source_input_identity({
                "source_overlay": {"source_sets": [{
                    "source_root": str(root),
                    "source_dirs": [str(first), str(second)],
                    "owner_type": "business", "owner_coord": "app",
                    "module": "core", "snapshot_revision": "revision",
                }]},
            })
            self.assertNotEqual(implicit, explicit)
            first_identity = implicit
            (first / "A.java").write_text("class A { int x; }\n", encoding="utf-8")
            self.assertNotEqual(
                first_identity,
                binary_pipeline._resume_source_input_identity({
                    "source_overlay": {"source_sets": [{
                        "source_dirs": [str(first)],
                    }]},
                }),
            )
            self.assert_pipeline_error(
                "BINARY_RESUME_SOURCE_COMMON_ROOT_REQUIRED",
                lambda: binary_pipeline._resume_source_input_identity({
                    "source_overlay": {"source_sets": [{
                        "source_dirs": [str(first), str(second)],
                        "owner_coord": "g:a",
                    }]},
                }),
            )
            self.assert_pipeline_error(
                "BINARY_RESUME_SOURCE_ROOT_MISSING",
                lambda: binary_pipeline._resume_source_input_identity({
                    "source_overlay": {"source_sets": [{
                        "source_dirs": [str(root / "missing")],
                    }]},
                }),
            )
            with tempfile.TemporaryDirectory() as other:
                outside = Path(other).resolve()
                self.assert_pipeline_error(
                    "BINARY_RESUME_SOURCE_ROOT_OUTSIDE_SNAPSHOT",
                    lambda: binary_pipeline._resume_source_input_identity({
                        "source_overlay": {"source_sets": [{
                            "source_root": str(root),
                            "source_dirs": [str(outside)],
                            "owner_coord": "outside",
                        }]},
                    }),
                )

    def test_runtime_profile_derives_defaults_and_rejects_identity_drift(self):
        required = binary_pipeline.RuntimeProfile.REQUIRED_FIELDS

        class CaptureRuntimeProfile:
            REQUIRED_FIELDS = required

            def __init__(self, payload):
                self.payload = dict(payload)

        platform = SimpleNamespace(
            identity="platform-identity",
            java_major=21,
            release={
                "IMPLEMENTOR": "Vendor", "JAVA_VERSION": "21",
                "OS_NAME": "TestOS", "OS_ARCH": "test-arch",
            },
        )
        descriptors = [{"logical_location": "lib/app.jar"}]
        artifact = {
            "logical_location": "lib/app.jar",
            "runtime_code_source_origin_identity": "origin",
        }

        def runtime(side, path_descriptors=descriptors):
            with patch.object(
                binary_pipeline, "_validate_multi_release_runtime_contract",
            ), patch.object(
                binary_pipeline, "RuntimeProfile", CaptureRuntimeProfile,
            ):
                return binary_pipeline._runtime_profile(
                    side, platform, path_descriptors,
                ).payload

        defaults = runtime({"artifacts": [artifact]})
        self.assertEqual(defaults["target_jvm"]["major"], 21)
        self.assertEqual(defaults["target_os"], "TestOS")
        self.assertEqual(defaults["target_arch"], "test-arch")
        self.assertTrue(defaults["runtime_code_source_origin_mapping_identity"])
        self.assertEqual(defaults["field_coverage"]["target_jvm"], "known")
        self.assertEqual(
            defaults["field_coverage"]["container_and_launcher_kind"],
            "unknown",
        )

        explicit = runtime({
            "artifacts": [artifact],
            "runtime_profile": {
                "runtime_platform_image_identity": platform.identity,
                "target_jvm": {"major": 21},
                "target_os": "ExplicitOS", "target_arch": "explicit-arch",
                "runtime_code_source_origin_mapping_identity": "mapping",
                "field_coverage": {
                    "target_jvm": "declared",
                    "target_os": "",
                },
            },
        }, [])
        self.assertEqual(explicit["target_os"], "ExplicitOS")
        self.assertEqual(explicit["target_arch"], "explicit-arch")
        self.assertEqual(
            explicit["runtime_code_source_origin_mapping_identity"], "mapping"
        )
        self.assertEqual(explicit["field_coverage"]["target_jvm"], "declared")
        self.assertEqual(explicit["field_coverage"]["target_os"], "known")

        sparse_origins = runtime({
            "artifacts": [
                {"logical_location": "other", "runtime_code_source_origin_identity": "x"},
                {"logical_location": "", "runtime_code_source_origin_identity": ""},
                {"logical_location": "target", "runtime_code_source_origin_identity": "target-origin"},
            ],
        }, [
            {"logical_location": ""},
            {"logical_location": "target"},
        ])
        self.assertTrue(
            sparse_origins["runtime_code_source_origin_mapping_identity"]
        )
        runtime({"artifacts": None}, [])
        with self.assertRaises(StopIteration):
            runtime({"artifacts": None}, [{"logical_location": "missing"}])

        self.assert_pipeline_error(
            "BINARY_PIPELINE_PLATFORM_IDENTITY_MISMATCH",
            lambda: runtime({
                "runtime_profile": {
                    "runtime_platform_image_identity": "other",
                    "target_jvm": {"major": 21},
                },
            }, []),
        )
        self.assertEqual(
            runtime({"runtime_profile": {"target_jvm": []}}, [])["target_jvm"][
                "major"
            ],
            21,
        )
        for target_jvm in ({"major": 17}, {"major": None}, "21"):
            self.assert_pipeline_error(
                "BINARY_PIPELINE_TARGET_JVM_MISMATCH",
                lambda target_jvm=target_jvm: runtime({
                    "runtime_profile": {"target_jvm": target_jvm},
                }, []),
            )

        sparse_platform = SimpleNamespace(
            identity="sparse", java_major=21, release={},
        )
        with patch.object(
            binary_pipeline, "_validate_multi_release_runtime_contract",
        ), patch.object(
            binary_pipeline, "RuntimeProfile", CaptureRuntimeProfile,
        ):
            sparse = binary_pipeline._runtime_profile(
                {}, sparse_platform, [],
            ).payload
        self.assertEqual(sparse["target_jvm"]["vendor"], "unknown")
        self.assertEqual(sparse["target_os"], "unknown")

    def test_definition_verification_summary_covers_memory_store_and_failure_cap(self):
        platform = SimpleNamespace(manifest=lambda: {"identity": "platform"})

        def reconciliation(records):
            return SimpleNamespace(
                class_definitions=records,
                runtime_profile_identity="profile",
                identity="reconciliation",
                coverage_status="complete",
                coverage_gaps=(),
            )

        empty = binary_pipeline._definition_verification_summary(
            reconciliation([]), platform,
        )
        self.assertEqual(empty["class_definition_count"], 0)

        store_records = [{
            "class_definition_status": "definition_ready",
            "class_name": "java/lang/String",
            "evidence": {
                "verification": "target_platform_image",
                "target_jvm_verification": {
                    "status": "definition_ready",
                    "class_definition_verifier_identity": "verifier",
                },
            },
            "initiating_loader_realm_identity": "bootstrap",
        }]
        store = SimpleNamespace(
            reconciliation_payloads=lambda kind: (
                store_records if kind == "class_definition" else []
            )
        )
        from_store = binary_pipeline._definition_verification_summary(
            reconciliation([]), platform, store,
        )
        self.assertEqual(from_store["platform_definition_ready_count"], 1)
        self.assertEqual(
            from_store["class_definition_verifier_identities"], ["verifier"]
        )

        records = list(store_records)
        records.append({
            "class_definition_status": "definition_ready",
            "class_name": "app/Ready",
            "evidence": {
                "target_jvm_verification": {
                    "status": "definition_ready",
                    "class_definition_verifier_identity": "",
                },
            },
            "initiating_loader_realm_identity": "",
        })
        records.append({
            "class_definition_status": "definition_ready",
            "class_name": "app/UnknownTargetStatus",
            "evidence": {"target_jvm_verification": {"detail": "present"}},
        })
        records.extend({
            "class_definition_status": "definition_failed",
            "class_name": f"app/Failed{index}",
            "evidence": (
                {"reason": "linkage", "parse_failure_kind": "format"}
                if index == 0 else {}
            ),
        } for index in range(22))
        records.append({"evidence": None, "class_name": None})
        summary = binary_pipeline._definition_verification_summary(
            reconciliation(records), platform,
        )
        self.assertEqual(summary["class_definition_count"], len(records))
        self.assertEqual(summary["failure_count"], 23)
        self.assertEqual(len(summary["failure_samples"]), 20)
        self.assertEqual(
            summary["definition_status_counts"]["definition_ready"], 3
        )
        self.assertEqual(summary["target_jvm_status_counts"]["unknown"], 1)
        self.assertEqual(summary["runtime_platform_image"], {"identity": "platform"})

    def test_checkpoint_validation_attachment_exhausts_file_and_payload_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            generation, manifest = self._generation_manifest(root)
            validation = self._failed_validation(manifest)
            path, digest = self._write_validation_attachment(
                generation, validation,
            )

            loaded = binary_pipeline._checkpoint_validation_attachment(
                generation,
                manifest,
                validation_run_identity=validation["validation_run_identity"],
                validation_result_sha256=digest,
                expected_status="failed",
            )
            self.assertEqual(loaded["validation_result_path"], str(path))

            def rejected(
                payload=validation, *, content=None, expected_status="failed",
                digest_override=None,
            ):
                written_path, written_digest = self._write_validation_attachment(
                    generation, payload, content=content,
                    filename=f"{validation['validation_run_identity']}.json",
                )
                self.assertEqual(written_path, path)
                self.assert_pipeline_error(
                    "BINARY_RESUME_VALIDATION_ATTACHMENT_INVALID",
                    lambda: binary_pipeline._checkpoint_validation_attachment(
                        generation,
                        manifest,
                        validation_run_identity=validation[
                            "validation_run_identity"
                        ],
                        validation_result_sha256=(
                            written_digest
                            if digest_override is None else digest_override
                        ),
                        expected_status=expected_status,
                    ),
                )

            rejected(digest_override="0" * 64)
            rejected(content=b"not-json")
            rejected(payload=[])
            changed = deepcopy(validation)
            changed["extra"] = True
            rejected(changed)
            pretty = json.dumps(validation, indent=2).encode()
            rejected(content=pretty)
            changed = deepcopy(validation)
            changed["validation_run_identity"] = "0" * 64
            rejected(changed)
            rejected(validation, expected_status="passed")

            passed = deepcopy(validation)
            passed["status"] = "passed"
            with patch.object(
                binary_pipeline,
                "is_complete_v3_validation_result",
                return_value=False,
            ):
                rejected(passed, expected_status="passed")
            with patch.object(
                binary_pipeline,
                "is_complete_v3_validation_result",
                return_value=True,
            ):
                loaded = binary_pipeline._checkpoint_validation_attachment(
                    generation,
                    manifest,
                    validation_run_identity=validation[
                        "validation_run_identity"
                    ],
                    validation_result_sha256=self._write_validation_attachment(
                        generation,
                        passed,
                        filename=f"{validation['validation_run_identity']}.json",
                    )[1],
                    expected_status="passed",
                )
            self.assertEqual(loaded["status"], "passed")

            self._write_validation_attachment(
                generation, validation,
                filename=f"{validation['validation_run_identity']}.json",
            )
            with patch.object(
                binary_pipeline,
                "_failed_validation_attachment_is_bound",
                return_value=False,
            ):
                rejected(validation)

            path.unlink()
            path.mkdir()
            rejected_call = lambda: binary_pipeline._checkpoint_validation_attachment(
                generation,
                manifest,
                validation_run_identity=validation["validation_run_identity"],
                validation_result_sha256=digest,
                expected_status="failed",
            )
            self.assert_pipeline_error(
                "BINARY_RESUME_VALIDATION_ATTACHMENT_INVALID", rejected_call,
            )
            path.rmdir()
            with patch.object(
                Path, "resolve", return_value=root / "other",
            ):
                self.assert_pipeline_error(
                    "BINARY_RESUME_VALIDATION_ATTACHMENT_INVALID", rejected_call,
                )
            with patch.object(
                Path,
                "resolve",
                side_effect=[generation / "validation", root / "other"],
            ):
                self.assert_pipeline_error(
                    "BINARY_RESUME_VALIDATION_ATTACHMENT_INVALID", rejected_call,
                )

    def test_stale_validator_attachment_exhausts_binding_and_identity_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            generation, manifest = self._generation_manifest(root)
            current = self._failed_validation(manifest)

            self.assertFalse(
                binary_pipeline._checkpoint_validator_attachment_is_stale(
                    generation, {}, expected_status="failed",
                )
            )
            self.assertFalse(
                binary_pipeline._checkpoint_validator_attachment_is_stale(
                    generation,
                    {"validation_run_identity": current[
                        "validation_run_identity"
                    ]},
                    expected_status="failed",
                )
            )

            def evaluate(payload, *, content=None, checkpoint_mutation=None):
                path, digest = self._write_validation_attachment(
                    generation,
                    payload,
                    content=content,
                    filename=f"{current['validation_run_identity']}.json",
                )
                checkpoint = {
                    "validation_run_identity": current[
                        "validation_run_identity"
                    ],
                    "validation_result_sha256": digest,
                }
                if checkpoint_mutation is not None:
                    checkpoint_mutation(checkpoint)
                return binary_pipeline._checkpoint_validator_attachment_is_stale(
                    generation, checkpoint, expected_status="failed",
                )

            stale = deepcopy(current)
            stale["validator_implementation_identity"] = "0" * 64
            self.assertTrue(evaluate(stale))
            stale_oracle = deepcopy(current)
            stale_oracle["oracle_support_manifest_identity"] = "0" * 64
            self.assertTrue(evaluate(stale_oracle))
            self.assertFalse(evaluate(current))

            for field in (
                "validation_run_identity", "validation_result_sha256",
            ):
                with self.subTest(checkpoint_field=field):
                    self.assertFalse(evaluate(
                        current,
                        checkpoint_mutation=lambda value, field=field: (
                            value.update({field: "bad"})
                        ),
                    ))
            self.assertFalse(evaluate(
                current,
                checkpoint_mutation=lambda value: value.update(
                    validation_result_sha256="0" * 64
                ),
            ))
            self.assertFalse(evaluate([], content=b"[]"))
            self.assertFalse(evaluate(current, content=json.dumps(current).encode()))
            for field, value in (
                ("extra", True),
                ("validation_run_identity", "0" * 64),
                ("result_generation_identity", "0" * 64),
                ("status", "passed"),
            ):
                changed = deepcopy(current)
                changed[field] = value
                self.assertFalse(evaluate(changed))
            for field in (
                "validator_implementation_identity",
                "oracle_support_manifest_identity",
            ):
                changed = deepcopy(current)
                changed[field] = "bad"
                self.assertFalse(evaluate(changed))

            with patch.object(
                binary_pipeline,
                "_current_validator_implementation_identity",
                side_effect=ValueError("unavailable"),
            ):
                self.assertFalse(evaluate(current))

            path = generation / "validation" / (
                f"{current['validation_run_identity']}.json"
            )
            path.unlink()
            path.mkdir()
            checkpoint = {
                "validation_run_identity": current["validation_run_identity"],
                "validation_result_sha256": "0" * 64,
            }
            self.assertFalse(
                binary_pipeline._checkpoint_validator_attachment_is_stale(
                    generation, checkpoint, expected_status="failed",
                )
            )
            with patch.object(
                Path, "resolve", return_value=root / "other",
            ):
                self.assertFalse(
                    binary_pipeline._checkpoint_validator_attachment_is_stale(
                        generation, checkpoint, expected_status="failed",
                    )
                )
            with patch.object(
                Path,
                "resolve",
                side_effect=[generation / "validation", root / "other"],
            ):
                self.assertFalse(
                    binary_pipeline._checkpoint_validator_attachment_is_stale(
                        generation, checkpoint, expected_status="failed",
                    )
                )

    def test_discover_validation_attachment_exhausts_scan_and_ambiguity_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            generation, manifest = self._generation_manifest(root)
            self.assertIsNone(
                binary_pipeline._discover_current_validation_attachment(
                    generation, manifest,
                )
            )
            validation_dir = generation / "validation"
            validation_dir.mkdir()
            (validation_dir / "ignored.txt").write_text("ignored")
            (validation_dir / f"{'0' * 64}.json").write_bytes(b"not-json")
            directory_candidate = validation_dir / f"{'1' * 64}.json"
            directory_candidate.mkdir()
            self.assertIsNone(
                binary_pipeline._discover_current_validation_attachment(
                    generation, manifest,
                )
            )
            directory_candidate.rmdir()
            real_resolve = Path.resolve

            def mismatched_validation_directory(candidate, *args, **kwargs):
                if candidate == validation_dir:
                    return root / "other"
                return real_resolve(candidate, *args, **kwargs)

            with patch.object(
                Path,
                "resolve",
                autospec=True,
                side_effect=mismatched_validation_directory,
            ):
                self.assertIsNone(
                    binary_pipeline._discover_current_validation_attachment(
                        generation, manifest,
                    )
                )
            mismatched_candidate = validation_dir / f"{'2' * 64}.json"
            mismatched_candidate.write_bytes(b"[]")

            def mismatched_validation_file(candidate, *args, **kwargs):
                if candidate == mismatched_candidate:
                    return root / "other-file"
                return real_resolve(candidate, *args, **kwargs)

            with patch.object(
                Path,
                "resolve",
                autospec=True,
                side_effect=mismatched_validation_file,
            ):
                self.assertIsNone(
                    binary_pipeline._discover_current_validation_attachment(
                        generation, manifest,
                    )
                )
            mismatched_candidate.unlink()

            validation = self._failed_validation(manifest)
            path, _ = self._write_validation_attachment(
                generation, validation,
            )
            discovered = binary_pipeline._discover_current_validation_attachment(
                generation, manifest,
            )
            self.assertEqual(
                discovered["validation_run_identity"],
                validation["validation_run_identity"],
            )
            self.assertEqual(discovered["validation_result_path"], str(path))

            def undiscovered(payload, *, content=None):
                self._write_validation_attachment(
                    generation,
                    payload,
                    content=content,
                    filename=f"{validation['validation_run_identity']}.json",
                )
                self.assertIsNone(
                    binary_pipeline._discover_current_validation_attachment(
                        generation, manifest,
                    )
                )

            path.unlink()
            undiscovered([], content=b"[]")
            changed = deepcopy(validation)
            changed["extra"] = True
            undiscovered(changed)
            undiscovered(validation, content=json.dumps(validation).encode())
            changed = deepcopy(validation)
            changed["validation_run_identity"] = "0" * 64
            undiscovered(changed)
            changed = deepcopy(validation)
            changed["result_generation_identity"] = "0" * 64
            undiscovered(changed)
            changed = deepcopy(validation)
            changed["status"] = "unknown"
            undiscovered(changed)

            passed = deepcopy(validation)
            passed["status"] = "passed"
            self._write_validation_attachment(
                generation,
                passed,
                filename=f"{validation['validation_run_identity']}.json",
            )
            with patch.object(
                binary_pipeline,
                "is_complete_v3_validation_result",
                return_value=True,
            ):
                self.assertIsNotNone(
                    binary_pipeline._discover_current_validation_attachment(
                        generation, manifest,
                    )
                )
            with patch.object(
                binary_pipeline,
                "is_complete_v3_validation_result",
                return_value=False,
            ):
                self.assertIsNone(
                    binary_pipeline._discover_current_validation_attachment(
                        generation, manifest,
                    )
                )

            self._write_validation_attachment(
                generation,
                validation,
                filename=f"{validation['validation_run_identity']}.json",
            )
            with patch.object(
                binary_pipeline,
                "_failed_validation_attachment_is_bound",
                return_value=False,
            ):
                self.assertIsNone(
                    binary_pipeline._discover_current_validation_attachment(
                        generation, manifest,
                    )
                )
            with patch.object(
                binary_pipeline,
                "_failed_validation_attachment_is_reusable",
                return_value=False,
            ):
                self.assertIsNone(
                    binary_pipeline._discover_current_validation_attachment(
                        generation, manifest,
                    )
                )

            second = deepcopy(validation)
            second["truth_set_identity"] = "2" * 64
            self._rebind_validation_identity(second, manifest)
            self._write_validation_attachment(generation, second)
            self.assert_pipeline_error(
                "BINARY_RESUME_VALIDATION_ATTACHMENT_AMBIGUOUS",
                lambda: binary_pipeline._discover_current_validation_attachment(
                    generation, manifest,
                ),
            )

            for child in validation_dir.iterdir():
                if child.is_file():
                    child.unlink()
            validation_dir.rmdir()
            target = root / "outside-validation"
            target.mkdir()
            try:
                validation_dir.symlink_to(target, target_is_directory=True)
            except OSError:
                pass
            else:
                self.assertIsNone(
                    binary_pipeline._discover_current_validation_attachment(
                        generation, manifest,
                    )
                )

    def test_persist_validation_checkpoint_exhausts_state_and_attachment_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            generation, manifest = self._generation_manifest(root)
            validation = self._failed_validation(manifest)
            path, _ = self._write_validation_attachment(
                generation, validation,
            )
            supplied = {**validation, "validation_result_path": str(path)}
            checkpoint = self._minimal_checkpoint(manifest)

            def persist(checkpoint_value=checkpoint, validation_value=supplied):
                with patch.object(
                    binary_pipeline,
                    "_write_resume_checkpoint_roundtrip",
                    side_effect=lambda _root, payload, **_kwargs: payload,
                ):
                    return binary_pipeline._persist_validation_checkpoint(
                        root,
                        generation,
                        manifest,
                        checkpoint_value,
                        validation_value,
                    )

            failed = persist()
            self.assertEqual(
                failed["status"], binary_pipeline._RESUME_VALIDATION_FAILED,
            )
            self.assertNotIn("activation_identity", failed)

            for label, mutate in (
                ("schema", lambda value: value.update(schema="wrong")),
                ("status", lambda value: value.update(status="wrong")),
                ("generation", lambda value: value.update(
                    result_generation_identity="0" * 64
                )),
                ("integrity", lambda value: value.update(
                    checkpoint_content_identity="0" * 64
                )),
            ):
                changed = deepcopy(checkpoint)
                mutate(changed)
                with self.subTest(checkpoint=label):
                    self.assert_pipeline_error(
                        "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
                        lambda changed=changed: persist(changed),
                    )

            changed_validation = deepcopy(supplied)
            changed_validation["status"] = "unknown"
            self.assert_pipeline_error(
                "BINARY_VALIDATION_RESULT_STATUS_INVALID",
                lambda: persist(validation_value=changed_validation),
            )
            changed_validation = deepcopy(supplied)
            changed_validation.pop("status")
            self.assert_pipeline_error(
                "BINARY_VALIDATION_RESULT_STATUS_INVALID",
                lambda: persist(validation_value=changed_validation),
            )
            changed_validation = deepcopy(supplied)
            changed_validation["validation_run_identity"] = "bad"
            self.assert_pipeline_error(
                "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
                lambda: persist(validation_value=changed_validation),
            )
            changed_validation = deepcopy(supplied)
            changed_validation.pop("validation_run_identity")
            self.assert_pipeline_error(
                "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
                lambda: persist(validation_value=changed_validation),
            )
            changed_validation = deepcopy(supplied)
            changed_validation["validation_result_path"] = None
            self.assert_pipeline_error(
                "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
                lambda: persist(validation_value=changed_validation),
            )
            changed_validation = deepcopy(supplied)
            changed_validation["validation_result_path"] = str(root / "missing")
            self.assert_pipeline_error(
                "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
                lambda: persist(validation_value=changed_validation),
            )
            changed_validation = deepcopy(supplied)
            changed_validation["issue_count"] = 2
            self.assert_pipeline_error(
                "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
                lambda: persist(validation_value=changed_validation),
            )
            with patch.object(
                binary_pipeline,
                "_failed_validation_attachment_is_bound",
                return_value=False,
            ):
                self.assert_pipeline_error(
                    "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
                    lambda: persist(),
                )

            path.unlink()
            self.assert_pipeline_error(
                "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
                lambda: persist(),
            )

            passed = deepcopy(validation)
            passed["status"] = "passed"
            passed_path, _ = self._write_validation_attachment(
                generation,
                passed,
                filename=f"{passed['validation_run_identity']}.json",
            )
            passed_supplied = {
                **passed, "validation_result_path": str(passed_path),
            }
            with patch.object(
                binary_pipeline,
                "is_complete_v3_validation_result",
                return_value=False,
            ):
                self.assert_pipeline_error(
                    "BINARY_VALIDATION_CHECKPOINT_ATTACHMENT_INVALID",
                    lambda: persist(validation_value=passed_supplied),
                )
            with patch.object(
                binary_pipeline,
                "is_complete_v3_validation_result",
                return_value=True,
            ):
                passed_checkpoint = persist(
                    validation_value=passed_supplied,
                )
                self.assertTrue(binary_pipeline._is_sha256_identity(
                    passed_checkpoint["activation_identity"]
                ))
                preserved_input = self._minimal_checkpoint(manifest)
                preserved_input["activation_identity"] = "f" * 64
                preserved_input["checkpoint_content_identity"] = (
                    binary_pipeline._resume_checkpoint_content_identity(
                        preserved_input
                    )
                )
                preserved = persist(
                    preserved_input, passed_supplied,
                )
                self.assertEqual(
                    preserved["activation_identity"], "f" * 64,
                )

    def test_validation_checkpoint_receipt_exhausts_durable_binding_matrix(self):
        output = Path("/physical/output")
        generation_identity = "a" * 64
        activation_identity = "b" * 64
        binding = self._performance_binding("receipt")
        manifest = {"result_generation_identity": generation_identity}
        activation = {"activation_identity": activation_identity}
        checkpoint = {
            "status": binary_pipeline._RESUME_VALIDATION_PASSED,
            "result_generation_identity": generation_identity,
            "activation_identity": activation_identity,
            "performance_authority_gate_binding": binding,
        }
        pending = {
            "result_generation_identity": generation_identity,
            "activation_identity": activation_identity,
            "activation_state": "pending",
        }
        regular = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_nlink=1,
        )

        def receipt(
            *, checkpoint_value=checkpoint, pending_value=pending,
            binding_value=binding, stat_value=regular,
        ):
            with patch.object(
                binary_pipeline.os, "lstat", return_value=stat_value,
            ), patch.object(
                binary_pipeline,
                "_read_resume_checkpoint",
                return_value=checkpoint_value,
            ), patch.object(
                binary_pipeline,
                "read_pending_binary_generation",
                return_value=pending_value,
            ):
                return binary_pipeline._validation_checkpoint_result_receipt(
                    output,
                    manifest,
                    activation,
                    binding_value,
                    retain_requested=True,
                    candidate_discarded=False,
                )

        self.assertTrue(receipt()["validation_checkpoint_retained"])
        with patch.dict(manifest, {}, clear=True):
            self.assert_pipeline_error(
                "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID", receipt,
            )
        with patch.dict(activation, {}, clear=True):
            self.assert_pipeline_error(
                "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID", receipt,
            )
        for retain, discarded in ((False, False), (True, True), (False, True)):
            self.assertEqual(
                binary_pipeline._validation_checkpoint_result_receipt(
                    output,
                    manifest,
                    activation,
                    binding,
                    retain_requested=retain,
                    candidate_discarded=discarded,
                ),
                {},
            )

        for invalid_stat in (
            None,
            SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_nlink=1),
            SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_nlink=1),
            SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=2),
        ):
            if invalid_stat is None:
                effect = FileNotFoundError()
                context = patch.object(
                    binary_pipeline.os, "lstat", side_effect=effect,
                )
            else:
                context = patch.object(
                    binary_pipeline.os, "lstat", return_value=invalid_stat,
                )
            with context:
                self.assert_pipeline_error(
                    "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
                    lambda: binary_pipeline._validation_checkpoint_result_receipt(
                        output,
                        manifest,
                        activation,
                        binding,
                        retain_requested=True,
                        candidate_discarded=False,
                    ),
                )
        with patch.object(
            binary_pipeline.os, "lstat", side_effect=OSError("unreadable"),
        ):
            self.assert_pipeline_error(
                "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
                lambda: binary_pipeline._validation_checkpoint_result_receipt(
                    output,
                    manifest,
                    activation,
                    binding,
                    retain_requested=True,
                    candidate_discarded=False,
                ),
            )

        checkpoint_mutations = (
            lambda value: value.clear(),
            lambda value: value.update(status="failed"),
            lambda value: value.update(result_generation_identity="0" * 64),
            lambda value: value.update(activation_identity="0" * 64),
            lambda value: value.update(
                performance_authority_gate_binding=None
            ),
        )
        for mutate in checkpoint_mutations:
            changed = deepcopy(checkpoint)
            mutate(changed)
            self.assert_pipeline_error(
                "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
                lambda changed=changed: receipt(checkpoint_value=changed),
            )
        for mutate in (
            lambda value: value.update(result_generation_identity="0" * 64),
            lambda value: value.update(activation_identity="0" * 64),
            lambda value: value.update(activation_state="active"),
        ):
            changed = deepcopy(pending)
            mutate(changed)
            self.assert_pipeline_error(
                "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
                lambda changed=changed: receipt(pending_value=changed),
            )
        self.assert_pipeline_error(
            "BINARY_VALIDATION_CHECKPOINT_STATE_INVALID",
            lambda: receipt(pending_value=None),
        )
        unbound_checkpoint = deepcopy(checkpoint)
        unbound_checkpoint["performance_authority_gate_binding"] = None
        self.assertTrue(receipt(
            checkpoint_value=unbound_checkpoint,
            binding_value=None,
        )["validation_checkpoint_retained"])

    def test_validation_failure_projection_and_reuse_exhaust_boundaries(self):
        empty = binary_pipeline._validation_failure_detail({})
        self.assertEqual(empty["issue_count"], 0)
        self.assertFalse(empty["issues_truncated"])

        issues = [None, {"domain": "", "reason_code": ""}]
        detail = binary_pipeline._validation_failure_detail({
            "issue_count": "invalid",
            "issues": issues,
            "domain_summary": None,
        })
        self.assertEqual(detail["issue_count"], 2)
        self.assertEqual(detail["reason_code_counts"], {"": 2})

        repeated = [{
            "domain": "domain",
            "reason_code": "ORACLE_DIRECT_EDGE_MISSING",
            "index": index,
        } for index in range(25)]
        detail = binary_pipeline._validation_failure_detail({
            "issue_count": 1,
            "issues": repeated,
        })
        self.assertEqual(detail["issue_count"], 25)
        self.assertEqual(detail["issues_preview_count"], 20)
        self.assertTrue(detail["issues_truncated"])

        distinct = [{
            "domain": f"domain-{index}",
            "reason_code": f"REASON_{index}",
        } for index in range(25)]
        detail = binary_pipeline._validation_failure_detail({
            "validation_run_identity": "run",
            "validation_result_path": "/result.json",
            "issue_count": 25,
            "domain_summary": {"all": 25},
            "issues": distinct,
        })
        self.assertEqual(detail["issues_preview_count"], 20)
        self.assertEqual(detail["validation_run_identity"], "run")
        self.assertEqual(detail["validation_result_path"], "/result.json")
        self.assertEqual(detail["domain_summary"], {"all": 25})

        for issues_value in (None, [], [None], [{}], [{"reason_code": "UNKNOWN"}]):
            self.assertFalse(
                binary_pipeline._failed_validation_attachment_is_reusable({
                    "issues": issues_value,
                })
            )
        reusable = [
            {"reason_code": "ORACLE_DIRECT_EDGE_MISSING"},
            {"reason_code": "ORACLE_DYNAMIC_HANDLE_EXTRA"},
        ]
        self.assertTrue(
            binary_pipeline._failed_validation_attachment_is_reusable({
                "issues": reusable,
            })
        )
        self.assertFalse(
            binary_pipeline._failed_validation_attachment_is_reusable({
                "issues": reusable + [{"reason_code": "UNKNOWN"}],
            })
        )

    def test_performance_authority_exhausts_contract_and_implementation_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evidence, current = self._performance_authority_evidence()

            release = self._invoke_performance_authority(
                root, evidence, current,
            )
            self.assertEqual(
                release["authority_mode"],
                binary_pipeline._PERFORMANCE_RELEASE_AUTHORITY_MODE,
            )
            self.assertTrue(
                binary_pipeline._performance_authority_binding_is_valid(
                    release
                )
            )
            self._invoke_performance_authority(
                root, evidence, current, generation_source_records=None,
            )

            for invalid in (None, [], "gate"):
                self.assert_pipeline_error(
                    "BINARY_PERFORMANCE_AUTHORITY_GATE_BLOCKED",
                    lambda invalid=invalid: (
                        binary_pipeline._performance_authority_gate_binding({
                            "performance_gate": invalid,
                        })
                    ),
                )
            for invalid in (0, 1, None, "true"):
                self.assert_pipeline_error(
                    "BINARY_PERFORMANCE_AUTHORITY_BINDING_INVALID",
                    lambda invalid=invalid: (
                        binary_pipeline._performance_authority_gate_binding(
                            {},
                            reuse_verified_generation_records_for_runtime=(
                                invalid
                            ),
                        )
                    ),
                )

            missing = root / "missing-performance.json"
            with patch.object(
                binary_pipeline, "PERFORMANCE_GATE_PATH", missing,
            ):
                self.assert_pipeline_error(
                    "BINARY_PERFORMANCE_GATE_UNAVAILABLE",
                    lambda: binary_pipeline._performance_authority_gate_binding({
                        "performance_gate": {},
                    }),
                )
            malformed = root / "malformed-performance.json"
            malformed.write_bytes(b"not-json")
            with patch.object(
                binary_pipeline, "PERFORMANCE_GATE_PATH", malformed,
            ):
                self.assert_pipeline_error(
                    "BINARY_PERFORMANCE_GATE_UNAVAILABLE",
                    lambda: binary_pipeline._performance_authority_gate_binding({
                        "performance_gate": {},
                    }),
                )

            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_IMPLEMENTATION_IDENTITY_UNAVAILABLE",
                lambda: self._invoke_performance_authority(
                    root,
                    evidence,
                    current,
                    generation_source_records=[None],
                ),
            )

            support_mutations = (
                lambda value: value["performance_gate"].update(status="failed"),
                lambda value: value["performance_gate"].update(
                    blocks_binary_authority_switch=True
                ),
                lambda value: value["performance_gate"].update(path="wrong"),
                lambda value: value["performance_gate"].update(sha256="0" * 64),
                lambda value: value["performance_gate"].update(
                    warm_parser_invocations=True
                ),
                lambda value: value["performance_gate"].update(
                    warm_parser_invocations=1
                ),
            )
            for index, mutate in enumerate(support_mutations):
                with self.subTest(support_gate=index):
                    self.assert_pipeline_error(
                        "BINARY_PERFORMANCE_AUTHORITY_GATE_BLOCKED",
                        lambda mutate=mutate: self._invoke_performance_authority(
                            root,
                            evidence,
                            current,
                            support_mutation=mutate,
                        ),
                    )

            evidence_mutations = (
                lambda value: value.update(schema="wrong"),
                lambda value: value.update(status="failed"),
                lambda value: value.update(
                    blocks_binary_authority_switch=True
                ),
                lambda value: value.update(recorded_measurements=[]),
                lambda value: value["recorded_measurements"].update(
                    warm_parser_invocations=True
                ),
                lambda value: value["recorded_measurements"].update(
                    warm_parser_invocations=1
                ),
                lambda value: value.update(accuracy_invariants=[]),
                lambda value: value["accuracy_invariants"].update(
                    warm_parser_invocations=True
                ),
                lambda value: value["accuracy_invariants"].update(
                    warm_parser_invocations=1
                ),
            )
            for index, mutate in enumerate(evidence_mutations):
                changed = deepcopy(evidence)
                mutate(changed)
                with self.subTest(evidence_gate=index):
                    self.assert_pipeline_error(
                        "BINARY_PERFORMANCE_AUTHORITY_GATE_BLOCKED",
                        lambda changed=changed: self._invoke_performance_authority(
                            root, changed, current,
                        ),
                    )

            protocol_shapes = (None, [], "protocol")
            for shape in protocol_shapes:
                changed = deepcopy(evidence)
                changed["measurement_protocol"] = shape
                self.assert_pipeline_error(
                    "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
                    lambda changed=changed: self._invoke_performance_authority(
                        root, changed, current,
                    ),
                )
            for shape in (None, [], "implementation"):
                changed = deepcopy(evidence)
                changed["measurement_protocol"]["implementation"] = shape
                self.assert_pipeline_error(
                    "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
                    lambda changed=changed: self._invoke_performance_authority(
                        root, changed, current,
                    ),
                )
            for field in current:
                for invalid in ("bad", "0" * 64):
                    changed = deepcopy(evidence)
                    changed["measurement_protocol"]["implementation"][
                        field
                    ] = invalid
                    with self.subTest(implementation_field=field, value=invalid):
                        self.assert_pipeline_error(
                            "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
                            lambda changed=changed: (
                                self._invoke_performance_authority(
                                    root, changed, current,
                                )
                            ),
                        )
            changed = deepcopy(evidence)
            changed["measurement_protocol"][
                "source_implementation_identity"
            ] = "0" * 64
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
                lambda: self._invoke_performance_authority(
                    root, changed, current,
                ),
            )
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH",
                lambda: self._invoke_performance_authority(
                    root,
                    evidence,
                    current,
                    support_mutation=lambda value: value[
                        "performance_gate"
                    ].update(source_implementation_identity="0" * 64),
                ),
            )

    def test_performance_authority_exhausts_candidate_recapture_and_replay_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evidence, current = self._performance_authority_evidence()
            expected_bootstrap = {
                "mode": "candidate_source_measurement",
                "source_implementation_identity": current[
                    "source_implementation_identity"
                ],
                "not_release_evidence": True,
            }

            both = deepcopy(evidence)
            both["measurement_bootstrap"] = dict(expected_bootstrap)
            both["measurement_provisional"] = {}
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_MEASUREMENT_BOOTSTRAP_FORBIDDEN",
                lambda: self._invoke_performance_authority(
                    root, both, current,
                ),
            )
            bootstrap = deepcopy(evidence)
            bootstrap["measurement_bootstrap"] = dict(expected_bootstrap)
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_MEASUREMENT_BOOTSTRAP_FORBIDDEN",
                lambda: self._invoke_performance_authority(
                    root, bootstrap, current,
                ),
            )

            token = binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.set(
                binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY
            )
            try:
                candidate = self._invoke_performance_authority(
                    root, bootstrap, current,
                )
                self.assertEqual(
                    candidate["authority_mode"],
                    binary_pipeline._PERFORMANCE_CANDIDATE_AUTHORITY_MODE,
                )
                invalid_markers = (
                    None,
                    [],
                    {},
                    {**expected_bootstrap, "extra": True},
                    {**expected_bootstrap, "mode": "wrong"},
                    {
                        **expected_bootstrap,
                        "source_implementation_identity": "0" * 64,
                    },
                    {**expected_bootstrap, "not_release_evidence": False},
                )
                for marker in invalid_markers:
                    changed = deepcopy(evidence)
                    changed["measurement_bootstrap"] = marker
                    self.assert_pipeline_error(
                        "BINARY_PERFORMANCE_MEASUREMENT_BOOTSTRAP_FORBIDDEN",
                        lambda changed=changed: self._invoke_performance_authority(
                            root, changed, current,
                        ),
                    )
            finally:
                binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.reset(
                    token
                )

            provisional = deepcopy(evidence)
            provisional["measurement_provisional"] = {}
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_PROVISIONAL_RECAPTURE_FORBIDDEN",
                lambda: self._invoke_performance_authority(
                    root, provisional, current,
                ),
            )
            token = binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.set(
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
            )
            try:
                malformed = deepcopy(evidence)
                malformed["measurement_provisional"] = []
                self.assert_pipeline_error(
                    "BINARY_PERFORMANCE_PROVISIONAL_RECAPTURE_FORBIDDEN",
                    lambda: self._invoke_performance_authority(
                        root, malformed, current,
                    ),
                )

                mismatched_runtime = dict(current)
                mismatched_runtime["validator_source_identity"] = "0" * 64
                self.assert_pipeline_error(
                    "BINARY_PERFORMANCE_IMPLEMENTATION_IDENTITY_UNAVAILABLE",
                    lambda: self._invoke_performance_authority(
                        root,
                        provisional,
                        current,
                        runtime_implementation=mismatched_runtime,
                    ),
                )
                self.assert_pipeline_error(
                    "BINARY_PERFORMANCE_PROVISIONAL_VERIFICATION_UNAVAILABLE",
                    lambda: self._invoke_performance_authority(
                        root,
                        provisional,
                        current,
                        provisional_result=RuntimeError("unavailable"),
                    ),
                )
                for issues in (None, [{"reason_code": "FAILED"}]):
                    self.assert_pipeline_error(
                        "BINARY_PERFORMANCE_PROVISIONAL_EVIDENCE_INVALID",
                        lambda issues=issues: self._invoke_performance_authority(
                            root,
                            provisional,
                            current,
                            provisional_result={
                                "status": "failed", "issues": issues,
                            },
                        ),
                    )
                for reuse in (False, True):
                    recapture = self._invoke_performance_authority(
                        root,
                        provisional,
                        current,
                        reuse_verified_generation_records_for_runtime=reuse,
                    )
                    self.assertEqual(
                        recapture["authority_mode"],
                        binary_pipeline._PERFORMANCE_RECAPTURE_AUTHORITY_MODE,
                    )
            finally:
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.reset(
                    token
                )

            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_RECORDED_VERIFICATION_UNAVAILABLE",
                lambda: self._invoke_performance_authority(
                    root,
                    evidence,
                    current,
                    recorded_result=RuntimeError("unavailable"),
                ),
            )
            for issues in (None, [{"reason_code": "FAILED"}]):
                self.assert_pipeline_error(
                    "BINARY_PERFORMANCE_RECORDED_EVIDENCE_INVALID",
                    lambda issues=issues: self._invoke_performance_authority(
                        root,
                        evidence,
                        current,
                        recorded_result={
                            "status": "failed", "issues": issues,
                        },
                    ),
                )

    def test_performance_binding_and_activation_exhaust_authority_modes(self):
        release = self._performance_binding_for_mode(
            "release", binary_pipeline._PERFORMANCE_RELEASE_AUTHORITY_MODE,
        )
        self.assertTrue(
            binary_pipeline._performance_authority_binding_is_valid(release)
        )
        for invalid in (None, [], "binding", {}):
            self.assertFalse(
                binary_pipeline._performance_authority_binding_is_valid(
                    invalid
                )
            )
        mutations = (
            lambda value: value.update(extra=True),
            lambda value: value.update(schema="wrong"),
            lambda value: value.update(authority_mode="wrong"),
            lambda value: value.update(support_contract_identity="bad"),
            lambda value: value.update(evidence_sha256="bad"),
            lambda value: value.update(source_implementation_identity="bad"),
            lambda value: value.update(binding_identity="bad"),
        )
        for mutate in mutations:
            changed = deepcopy(release)
            mutate(changed)
            self.assertFalse(
                binary_pipeline._performance_authority_binding_is_valid(
                    changed
                )
            )

        output = Path("/private/performance-activation")
        manifest = {"result_generation_identity": "a" * 64}
        validation = {"validation_run_identity": "b" * 64}
        activation_record = {}
        with patch.object(
            binary_pipeline,
            "activate_binary_generation",
            return_value="active",
        ) as activate:
            self.assertEqual(
                binary_pipeline._activate_validated_generation_with_authority_binding(
                    output,
                    manifest,
                    validation,
                    activation_identity="c" * 64,
                    activation_record=activation_record,
                    defer_publication=False,
                    performance_authority_gate_binding=None,
                ),
                "active",
            )
            self.assertNotIn("publication_guard", activate.call_args.kwargs)

        self.assert_pipeline_error(
            "BINARY_PERFORMANCE_AUTHORITY_BINDING_INVALID",
            lambda: binary_pipeline._activate_validated_generation_with_authority_binding(
                output,
                manifest,
                validation,
                activation_identity="c" * 64,
                activation_record={},
                defer_publication=False,
                performance_authority_gate_binding={},
            ),
        )

        candidate = self._performance_binding_for_mode(
            "candidate", binary_pipeline._PERFORMANCE_CANDIDATE_AUTHORITY_MODE,
        )
        self.assert_pipeline_error(
            "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_FORBIDDEN",
            lambda: binary_pipeline._activate_validated_generation_with_authority_binding(
                output,
                manifest,
                validation,
                activation_identity="c" * 64,
                activation_record={},
                defer_publication=False,
                performance_authority_gate_binding=candidate,
            ),
        )
        with patch.object(
            binary_pipeline,
            "activate_binary_generation",
            return_value="candidate",
        ) as activate, patch.object(
            binary_pipeline,
            "_activation_publication_guard_value",
            return_value=candidate,
        ) as guard:
            self.assertEqual(
                binary_pipeline._activate_validated_generation_with_authority_binding(
                    output,
                    manifest,
                    validation,
                    activation_identity="c" * 64,
                    activation_record={},
                    defer_publication=True,
                    performance_authority_gate_binding=candidate,
                ),
                "candidate",
            )
            self.assertTrue(activate.call_args.kwargs["publication_dry_run"])
            self.assertEqual(
                activate.call_args.kwargs["publication_guard"](), candidate,
            )
            guard.assert_called_once()

        recapture = self._performance_binding_for_mode(
            "recapture", binary_pipeline._PERFORMANCE_RECAPTURE_AUTHORITY_MODE,
        )
        self.assert_pipeline_error(
            "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
            lambda: binary_pipeline._activate_validated_generation_with_authority_binding(
                output,
                manifest,
                validation,
                activation_identity="c" * 64,
                activation_record={},
                defer_publication=True,
                performance_authority_gate_binding=recapture,
            ),
        )
        wrong_root_token = (
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.set(
                Path("/private/other-performance-root")
            )
        )
        wrong_capability_token = (
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.set(
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
            )
        )
        try:
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
                lambda: binary_pipeline._activate_validated_generation_with_authority_binding(
                    output,
                    manifest,
                    validation,
                    activation_identity="c" * 64,
                    activation_record={},
                    defer_publication=False,
                    performance_authority_gate_binding=recapture,
                ),
            )
        finally:
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.reset(
                wrong_capability_token
            )
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.reset(
                wrong_root_token
            )
        self.assert_pipeline_error(
            "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
            lambda: binary_pipeline._activate_validated_generation_with_authority_binding(
                output,
                manifest,
                validation,
                activation_identity="c" * 64,
                activation_record={},
                defer_publication=False,
                performance_authority_gate_binding=recapture,
            ),
        )

        root_token = binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.set(
            output.resolve()
        )
        capability_token = (
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.set(
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
            )
        )
        try:
            with patch.object(
                binary_pipeline,
                "_release_recapture_publication",
                return_value=nullcontext(),
            ), patch.object(
                binary_pipeline,
                "activate_binary_generation",
                return_value="recaptured",
            ) as activate:
                self.assertEqual(
                    binary_pipeline._activate_validated_generation_with_authority_binding(
                        output,
                        manifest,
                        validation,
                        activation_identity="c" * 64,
                        activation_record={},
                        defer_publication=False,
                        performance_authority_gate_binding=recapture,
                    ),
                    "recaptured",
                )
                self.assertFalse(activate.call_args.kwargs["defer_publication"])
        finally:
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.reset(
                capability_token
            )
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.reset(
                root_token
            )

        with patch.object(
            binary_pipeline,
            "activate_binary_generation",
            return_value="release",
        ) as activate:
            self.assertEqual(
                binary_pipeline._activate_validated_generation_with_authority_binding(
                    output,
                    manifest,
                    validation,
                    activation_identity="c" * 64,
                    activation_record={},
                    defer_publication=True,
                    performance_authority_gate_binding=release,
                ),
                "release",
            )
            self.assertTrue(callable(
                activate.call_args.kwargs["publication_guard"]
            ))

    def test_candidate_discard_and_activation_seal_exhaust_failure_boundaries(self):
        output = Path("/private/performance-finalize")
        manifest = {"result_generation_identity": "a" * 64}
        validation = {"validation_run_identity": "b" * 64}
        activation_identity = "c" * 64
        candidate = self._performance_binding_for_mode(
            "discard", binary_pipeline._PERFORMANCE_CANDIDATE_AUTHORITY_MODE,
        )
        release = self._performance_binding_for_mode(
            "seal", binary_pipeline._PERFORMANCE_RELEASE_AUTHORITY_MODE,
        )
        recapture = self._performance_binding_for_mode(
            "recapture-seal",
            binary_pipeline._PERFORMANCE_RECAPTURE_AUTHORITY_MODE,
        )

        for binding in (None, release):
            self.assertFalse(
                binary_pipeline._discard_measurement_candidate_activation(
                    output, manifest, {}, binding,
                )
            )

        activation = {
            "activation_identity": activation_identity,
            "activation_candidate_private": True,
            "activation_candidate_nonpublishable": True,
        }
        checkpoint = {
            "result_generation_identity": manifest[
                "result_generation_identity"
            ],
            "activation_identity": activation_identity,
            "performance_authority_gate_binding": dict(candidate),
        }

        def discard(activation_value=activation, checkpoint_value=checkpoint,
                    pending=None):
            with patch.object(
                binary_pipeline,
                "read_pending_binary_generation",
                return_value=pending,
            ), patch.object(
                binary_pipeline,
                "_read_resume_checkpoint",
                return_value=checkpoint_value,
            ), patch.object(
                binary_pipeline, "_delete_resume_checkpoint_durable",
            ) as delete:
                result = binary_pipeline._discard_measurement_candidate_activation(
                    output, manifest, activation_value, candidate,
                )
                return result, delete

        discarded, delete = discard()
        self.assertTrue(discarded)
        self.assertTrue(activation["activation_candidate_discarded"])
        delete.assert_called_once_with(output)

        activation_mutations = (
            lambda value: value.update(activation_identity="bad"),
            lambda value: value.pop("activation_identity"),
            lambda value: value.update(activation_candidate_private=False),
            lambda value: value.update(
                activation_candidate_nonpublishable=False
            ),
        )
        for mutate in activation_mutations:
            changed = deepcopy(activation)
            changed.pop("activation_candidate_discarded", None)
            mutate(changed)
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_DISCARD_FAILED",
                lambda changed=changed: discard(changed),
            )
        self.assert_pipeline_error(
            "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_DISCARD_FAILED",
            lambda: discard(pending={}),
        )
        checkpoint_mutations = (
            lambda value: value.clear(),
            lambda value: value.update(result_generation_identity="0" * 64),
            lambda value: value.update(activation_identity="0" * 64),
            lambda value: value.update(
                performance_authority_gate_binding={}
            ),
        )
        for mutate in checkpoint_mutations:
            changed = deepcopy(checkpoint)
            mutate(changed)
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_DISCARD_FAILED",
                lambda changed=changed: discard(checkpoint_value=changed),
            )

        self.assertFalse(
            binary_pipeline._seal_and_finalize_measured_activation(
                output, manifest, validation, {}, release,
            )
        )
        normal_activation = {"activation_identity": activation_identity}
        with patch.object(
            binary_pipeline,
            "seal_active_binary_generation",
            return_value=True,
        ) as seal:
            self.assertFalse(
                binary_pipeline._seal_and_finalize_measured_activation(
                    output,
                    manifest,
                    validation,
                    normal_activation,
                    None,
                )
            )
            self.assertIsNone(seal.call_args.kwargs["publication_guard"])
            self.assertFalse(
                binary_pipeline._seal_and_finalize_measured_activation(
                    output,
                    {},
                    validation,
                    {"unrelated": True},
                    None,
                )
            )
        with patch.object(
            binary_pipeline,
            "seal_active_binary_generation",
            return_value=True,
        ) as seal:
            self.assertFalse(
                binary_pipeline._seal_and_finalize_measured_activation(
                    output,
                    manifest,
                    validation,
                    normal_activation,
                    release,
                )
            )
            self.assertTrue(callable(
                seal.call_args.kwargs["publication_guard"]
            ))
        with patch.object(
            binary_pipeline,
            "seal_active_binary_generation",
            return_value=False,
        ):
            self.assert_pipeline_error(
                "BINARY_GENERATION_ACTIVATION_SEAL_FAILED",
                lambda: binary_pipeline._seal_and_finalize_measured_activation(
                    output,
                    manifest,
                    validation,
                    normal_activation,
                    release,
                ),
            )

        self.assert_pipeline_error(
            "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
            lambda: binary_pipeline._seal_and_finalize_measured_activation(
                output,
                manifest,
                validation,
                normal_activation,
                recapture,
            ),
        )
        wrong_root_token = (
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.set(
                Path("/private/other-seal-root")
            )
        )
        wrong_capability_token = (
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.set(
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
            )
        )
        try:
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
                lambda: binary_pipeline._seal_and_finalize_measured_activation(
                    output,
                    manifest,
                    validation,
                    normal_activation,
                    recapture,
                ),
            )
        finally:
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.reset(
                wrong_capability_token
            )
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.reset(
                wrong_root_token
            )
        root_token = binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.set(
            output.resolve()
        )
        capability_token = (
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.set(
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
            )
        )
        try:
            predecessor = {
                **normal_activation, "activation_predecessor": {},
            }
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
                lambda: binary_pipeline._seal_and_finalize_measured_activation(
                    output,
                    manifest,
                    validation,
                    predecessor,
                    recapture,
                ),
            )

            for sealed, discarded, reason in (
                (False, True, "BINARY_GENERATION_ACTIVATION_SEAL_FAILED"),
                (
                    True,
                    False,
                    "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
                ),
            ):
                with patch.object(
                    binary_pipeline,
                    "_release_recapture_publication",
                    return_value=nullcontext(),
                ), patch.object(
                    binary_pipeline,
                    "seal_active_binary_generation",
                    return_value=sealed,
                ), patch.object(
                    binary_pipeline,
                    "_discard_release_recapture_activation",
                    return_value=discarded,
                ):
                    self.assert_pipeline_error(
                        reason,
                        lambda: binary_pipeline._seal_and_finalize_measured_activation(
                            output,
                            manifest,
                            validation,
                            dict(normal_activation),
                            recapture,
                        ),
                    )
            successful_activation = dict(normal_activation)
            with patch.object(
                binary_pipeline,
                "_release_recapture_publication",
                return_value=nullcontext(),
            ), patch.object(
                binary_pipeline,
                "seal_active_binary_generation",
                return_value=True,
            ), patch.object(
                binary_pipeline,
                "_discard_release_recapture_activation",
                return_value=True,
            ):
                self.assertTrue(
                    binary_pipeline._seal_and_finalize_measured_activation(
                        output,
                        manifest,
                        validation,
                        successful_activation,
                        recapture,
                    )
                )
                self.assertTrue(
                    successful_activation["activation_recapture_discarded"]
                )
        finally:
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.reset(
                capability_token
            )
            binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.reset(
                root_token
            )

    def test_candidate_cleanup_exhausts_capability_checkpoint_and_residual_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            missing = parent / "missing"
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_MEASUREMENT_CLEANUP_FORBIDDEN",
                lambda: binary_pipeline._cleanup_performance_measurement_state(
                    missing
                ),
            )
            token = binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.set(
                binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY
            )
            try:
                binary_pipeline._cleanup_performance_measurement_state(missing)
                root = parent / "candidate"
                root.mkdir()
                with patch.object(
                    binary_pipeline,
                    "read_pending_binary_generation",
                    return_value={},
                ):
                    self.assert_pipeline_error(
                        "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_DISCARD_FAILED",
                        lambda: binary_pipeline._cleanup_performance_measurement_state(
                            root
                        ),
                    )

                with patch.object(
                    binary_pipeline,
                    "read_pending_binary_generation",
                    return_value=None,
                ), patch.object(
                    binary_pipeline,
                    "_read_resume_checkpoint",
                    return_value={},
                ), patch.object(
                    binary_pipeline,
                    "_filesystem_entry_absent",
                    return_value=True,
                ):
                    binary_pipeline._cleanup_performance_measurement_state(root)

                candidate = self._performance_binding_for_mode(
                    "candidate-cleanup",
                    binary_pipeline._PERFORMANCE_CANDIDATE_AUTHORITY_MODE,
                )
                release = self._performance_binding_for_mode(
                    "release-cleanup",
                    binary_pipeline._PERFORMANCE_RELEASE_AUTHORITY_MODE,
                )
                for checkpoint, should_delete in (
                    ({"performance_authority_gate_binding": {}}, False),
                    ({"performance_authority_gate_binding": release}, False),
                    ({"performance_authority_gate_binding": candidate}, True),
                ):
                    with patch.object(
                        binary_pipeline,
                        "read_pending_binary_generation",
                        return_value=None,
                    ), patch.object(
                        binary_pipeline,
                        "_read_resume_checkpoint",
                        return_value=checkpoint,
                    ), patch.object(
                        binary_pipeline,
                        "_delete_resume_checkpoint_durable",
                    ) as delete, patch.object(
                        binary_pipeline,
                        "_filesystem_entry_absent",
                        return_value=True,
                    ):
                        binary_pipeline._cleanup_performance_measurement_state(
                            root
                        )
                    self.assertEqual(delete.called, should_delete)

                with patch.object(
                    binary_pipeline,
                    "read_pending_binary_generation",
                    return_value=None,
                ), patch.object(
                    binary_pipeline,
                    "_read_resume_checkpoint",
                    return_value={},
                ), patch.object(
                    binary_pipeline,
                    "_filesystem_entry_absent",
                    return_value=False,
                ):
                    self.assert_pipeline_error(
                        "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_DISCARD_FAILED",
                        lambda: binary_pipeline._cleanup_performance_measurement_state(
                            root
                        ),
                    )
            finally:
                binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.reset(
                    token
                )

    def test_recapture_cleanup_exhausts_identity_discard_and_residual_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            root = parent / "recapture"
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_RECAPTURE_CLEANUP_FORBIDDEN",
                lambda: binary_pipeline._cleanup_performance_recapture_state(
                    root
                ),
            )
            capability_token = (
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.set(
                    binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
                )
            )
            wrong_root_token = (
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.set(
                    parent / "other"
                )
            )
            try:
                self.assert_pipeline_error(
                    "BINARY_PERFORMANCE_RECAPTURE_CLEANUP_FORBIDDEN",
                    lambda: binary_pipeline._cleanup_performance_recapture_state(
                        root
                    ),
                )
            finally:
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.reset(
                    wrong_root_token
                )

            root_token = (
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.set(
                    root.resolve()
                )
            )
            try:
                binary_pipeline._cleanup_performance_recapture_state(root)
                root.mkdir()
                with patch.object(
                    binary_pipeline,
                    "read_pending_binary_generation",
                    return_value={},
                ):
                    self.assert_pipeline_error(
                        "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
                        lambda: binary_pipeline._cleanup_performance_recapture_state(
                            root
                        ),
                    )

                recapture = self._performance_binding_for_mode(
                    "recapture-cleanup",
                    binary_pipeline._PERFORMANCE_RECAPTURE_AUTHORITY_MODE,
                )
                checkpoint = {
                    "performance_authority_gate_binding": recapture,
                    "result_generation_identity": "a" * 64,
                    "activation_identity": "b" * 64,
                }

                invalid_checkpoints = []
                for mutate in (
                    lambda value: value.update(
                        performance_authority_gate_binding={}
                    ),
                    lambda value: value.update(
                        performance_authority_gate_binding=(
                            self._performance_binding_for_mode(
                                "wrong-mode",
                                binary_pipeline._PERFORMANCE_RELEASE_AUTHORITY_MODE,
                            )
                        )
                    ),
                    lambda value: value.update(
                        result_generation_identity="bad"
                    ),
                    lambda value: value.pop("result_generation_identity"),
                    lambda value: value.update(activation_identity="bad"),
                    lambda value: value.pop("activation_identity"),
                ):
                    changed = deepcopy(checkpoint)
                    mutate(changed)
                    invalid_checkpoints.append(changed)
                for changed in invalid_checkpoints:
                    with patch.object(
                        binary_pipeline,
                        "read_pending_binary_generation",
                        return_value=None,
                    ), patch.object(
                        binary_pipeline,
                        "_read_resume_checkpoint",
                        return_value=changed,
                    ):
                        self.assert_pipeline_error(
                            "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
                            lambda: binary_pipeline._cleanup_performance_recapture_state(
                                root
                            ),
                        )

                with patch.object(
                    binary_pipeline,
                    "read_pending_binary_generation",
                    return_value=None,
                ), patch.object(
                    binary_pipeline,
                    "_read_resume_checkpoint",
                    return_value=checkpoint,
                ), patch.object(
                    binary_pipeline,
                    "_delete_resume_checkpoint_durable",
                ) as delete, patch.object(
                    binary_pipeline,
                    "_filesystem_entry_absent",
                    return_value=True,
                ):
                    binary_pipeline._cleanup_performance_recapture_state(root)
                delete.assert_called_once_with(root)

                active = root / "active_binary_generation.json"
                active.write_text("active")

                def discard_active(*_args, **_kwargs):
                    active.unlink()
                    return True

                with patch.object(
                    binary_pipeline,
                    "read_pending_binary_generation",
                    return_value=None,
                ), patch.object(
                    binary_pipeline,
                    "_read_resume_checkpoint",
                    return_value=checkpoint,
                ), patch.object(
                    binary_pipeline,
                    "_release_recapture_publication",
                    return_value=nullcontext(),
                ), patch.object(
                    binary_pipeline,
                    "_discard_release_recapture_activation",
                    side_effect=discard_active,
                ), patch.object(
                    binary_pipeline, "_delete_resume_checkpoint_durable",
                ), patch.object(
                    binary_pipeline,
                    "_filesystem_entry_absent",
                    return_value=True,
                ):
                    binary_pipeline._cleanup_performance_recapture_state(root)

                dangling_target = parent / "missing-active-target"
                try:
                    active.symlink_to(dangling_target)
                except OSError:
                    pass
                else:
                    def discard_symlink(*_args, **_kwargs):
                        active.unlink()
                        return True

                    with patch.object(
                        binary_pipeline,
                        "read_pending_binary_generation",
                        return_value=None,
                    ), patch.object(
                        binary_pipeline,
                        "_read_resume_checkpoint",
                        return_value=checkpoint,
                    ), patch.object(
                        binary_pipeline,
                        "_release_recapture_publication",
                        return_value=nullcontext(),
                    ), patch.object(
                        binary_pipeline,
                        "_discard_release_recapture_activation",
                        side_effect=discard_symlink,
                    ), patch.object(
                        binary_pipeline,
                        "_delete_resume_checkpoint_durable",
                    ), patch.object(
                        binary_pipeline,
                        "_filesystem_entry_absent",
                        return_value=True,
                    ):
                        binary_pipeline._cleanup_performance_recapture_state(
                            root
                        )

                active.write_text("active")
                with patch.object(
                    binary_pipeline,
                    "read_pending_binary_generation",
                    return_value=None,
                ), patch.object(
                    binary_pipeline,
                    "_read_resume_checkpoint",
                    return_value=checkpoint,
                ), patch.object(
                    binary_pipeline,
                    "_release_recapture_publication",
                    return_value=nullcontext(),
                ), patch.object(
                    binary_pipeline,
                    "_discard_release_recapture_activation",
                    return_value=False,
                ):
                    self.assert_pipeline_error(
                        "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
                        lambda: binary_pipeline._cleanup_performance_recapture_state(
                            root
                        ),
                    )
                active.unlink()

                active.write_text("residual")
                with patch.object(
                    binary_pipeline,
                    "read_pending_binary_generation",
                    return_value=None,
                ), patch.object(
                    binary_pipeline,
                    "_read_resume_checkpoint",
                    return_value={},
                ):
                    self.assert_pipeline_error(
                        "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
                        lambda: binary_pipeline._cleanup_performance_recapture_state(
                            root
                        ),
                    )
                active.unlink()

                target = parent / "deleted-target"
                try:
                    active.symlink_to(target)
                except OSError:
                    pass
                else:
                    with patch.object(
                        binary_pipeline,
                        "read_pending_binary_generation",
                        return_value=None,
                    ), patch.object(
                        binary_pipeline,
                        "_read_resume_checkpoint",
                        return_value={},
                    ):
                        self.assert_pipeline_error(
                            "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
                            lambda: binary_pipeline._cleanup_performance_recapture_state(
                                root
                            ),
                        )
                    active.unlink()

                with patch.object(
                    binary_pipeline,
                    "read_pending_binary_generation",
                    side_effect=[None, {}],
                ), patch.object(
                    binary_pipeline,
                    "_read_resume_checkpoint",
                    return_value={},
                ):
                    self.assert_pipeline_error(
                        "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
                        lambda: binary_pipeline._cleanup_performance_recapture_state(
                            root
                        ),
                    )
                with patch.object(
                    binary_pipeline,
                    "read_pending_binary_generation",
                    return_value=None,
                ), patch.object(
                    binary_pipeline,
                    "_read_resume_checkpoint",
                    return_value={},
                ), patch.object(
                    binary_pipeline,
                    "_filesystem_entry_absent",
                    return_value=False,
                ):
                    self.assert_pipeline_error(
                        "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_DISCARD_FAILED",
                        lambda: binary_pipeline._cleanup_performance_recapture_state(
                            root
                        ),
                    )
            finally:
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.reset(
                    root_token
                )
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.reset(
                    capability_token
                )

    def test_performance_measurement_dispatch_and_live_verifier_exhaust_modes(self):
        support = {"support": True}
        self.assertIsNone(
            binary_pipeline._performance_measurement_binding(support)
        )
        expected = self._performance_binding_for_mode(
            "measurement-dispatch",
            binary_pipeline._PERFORMANCE_CANDIDATE_AUTHORITY_MODE,
        )
        with patch.object(
            binary_pipeline,
            "_performance_authority_gate_binding",
            return_value=expected,
        ) as derive:
            token = (
                binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.set(
                    binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY
                )
            )
            try:
                self.assertEqual(
                    binary_pipeline._performance_measurement_binding(
                        support,
                        generation_source_records=[{"path": "source"}],
                        asm_jar="asm.jar",
                    ),
                    expected,
                )
            finally:
                binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.reset(
                    token
                )
            derive.assert_called_once_with(
                support,
                generation_source_records=[{"path": "source"}],
                asm_jar="asm.jar",
            )

        recapture_expected = self._performance_binding_for_mode(
            "measurement-recapture",
            binary_pipeline._PERFORMANCE_RECAPTURE_AUTHORITY_MODE,
        )
        with patch.object(
            binary_pipeline,
            "_performance_authority_gate_binding",
            return_value=recapture_expected,
        ):
            token = binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.set(
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
            )
            try:
                self.assertEqual(
                    binary_pipeline._performance_measurement_binding(support),
                    recapture_expected,
                )
            finally:
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.reset(
                    token
                )

        release = self._performance_binding_for_mode(
            "live-verifier",
            binary_pipeline._PERFORMANCE_RELEASE_AUTHORITY_MODE,
        )
        with patch.object(
            binary_pipeline,
            "_load_support_manifest_snapshot",
            return_value=support,
        ), patch.object(
            binary_pipeline,
            "_performance_authority_gate_binding",
            return_value=dict(release),
        ):
            self.assertEqual(
                binary_pipeline._verify_performance_authority_gate_binding(
                    release
                ),
                release,
            )

        changed = deepcopy(release)
        changed["evidence_sha256"] = "0" * 64
        with patch.object(
            binary_pipeline,
            "_load_support_manifest_snapshot",
            return_value=support,
        ), patch.object(
            binary_pipeline,
            "_performance_authority_gate_binding",
            return_value=dict(release),
        ):
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_AUTHORITY_GATE_CHANGED_DURING_RUN",
                lambda: binary_pipeline._verify_performance_authority_gate_binding(
                    changed
                ),
            )

        contract_error = binary_pipeline.BinaryFirstContractError(
            "BINARY_SOURCE_IDENTITY_INVALID", "invalid source identity",
        )
        with patch.object(
            binary_pipeline,
            "_load_support_manifest_snapshot",
            return_value=support,
        ), patch.object(
            binary_pipeline,
            "_performance_authority_gate_binding",
            side_effect=contract_error,
        ):
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_AUTHORITY_GATE_CHANGED_DURING_RUN",
                lambda: binary_pipeline._verify_performance_authority_gate_binding(
                    release
                ),
            )

    def test_strict_json_and_optional_config_readers_exhaust_input_shapes(self):
        self.assertEqual(
            binary_pipeline._strict_json_object_from_bytes(b'{"value":1}'),
            {"value": 1},
        )
        for content in (
            "not-bytes",
            b"[]",
            b'{"value":NaN}',
            b'{"value":1,"value":2}',
            b"\xff",
        ):
            with self.subTest(content=repr(content)), self.assertRaises(
                (ValueError, UnicodeError, json.JSONDecodeError)
            ):
                binary_pipeline._strict_json_object_from_bytes(content)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            missing = root / "missing.json"
            self.assertEqual(
                binary_pipeline._read_optional_json_object(missing), {}
            )
            for content, expected in (
                ("not-json", {}),
                ("[]", {}),
                ('{"value":1}', {"value": 1}),
            ):
                path = root / f"optional-{len(content)}.json"
                path.write_text(content)
                self.assertEqual(
                    binary_pipeline._read_optional_json_object(path), expected,
                )

            for content in ("not-json", "[]"):
                path = root / f"required-{len(content)}.json"
                path.write_text(content)
                self.assert_pipeline_error(
                    "BINARY_PIPELINE_CONFIG_INVALID",
                    lambda path=path: binary_pipeline._load_json(path),
                )
            self.assert_pipeline_error(
                "BINARY_PIPELINE_CONFIG_INVALID",
                lambda: binary_pipeline._load_json(missing),
            )
            valid = root / "required-valid.json"
            valid.write_text('{"value":1}')
            self.assertEqual(binary_pipeline._load_json(valid), {"value": 1})

    def test_cli_bounded_value_exhausts_types_limits_and_receipt_dispositions(self):
        bound = binary_pipeline._cli_bounded_json_value
        self.assertIsNone(bound(None))
        self.assertTrue(bound(True))
        self.assertEqual(bound("short"), "short")
        self.assertTrue(bound("x" * 20, max_text_chars=8).endswith(
            "...[truncated]"
        ))
        self.assertEqual(bound(2**62), 2**62)
        huge = bound(2**200)
        self.assertEqual(huge["value_status"], "integer_out_of_range")
        self.assertEqual(bound(1.5), 1.5)
        self.assertEqual(
            bound(float("nan"))["value_status"], "non_finite_float",
        )
        self.assertEqual(
            bound([[[1]]], max_depth=2)[0][0]["value_status"],
            "depth_limit_exceeded",
        )
        limited_list = bound([1, 2, 3], max_items=2)
        self.assertEqual(
            limited_list[-1]["value_status"], "item_limit_exceeded",
        )
        limited_tuple = bound((1, 2, 3), max_items=1)
        self.assertEqual(limited_tuple[-1]["omitted_count"], 2)
        limited_dict = bound({"a": 1, "b": 2}, max_items=1)
        self.assertIn("__truncated__", limited_dict)
        duplicate_keys = bound({1: "non-string", "__non_string_key_0__": 2})
        self.assertIn("__non_string_key_0__", duplicate_keys)
        self.assertIn("__duplicate_key_1__", duplicate_keys)
        node_limited = bound([1, 2], max_nodes=1)
        self.assertEqual(
            node_limited[0]["value_status"], "node_limit_exceeded",
        )

        class GoodPath:
            def __fspath__(self):
                return "/bounded/path"

        class BrokenPath:
            def __fspath__(self):
                raise RuntimeError("broken path")

        self.assertEqual(bound(GoodPath()), "/bounded/path")
        self.assertEqual(
            bound(BrokenPath())["value_status"],
            "non_json_value_omitted",
        )
        self.assertEqual(
            bound(object())["value_status"], "non_json_value_omitted",
        )

        class EmptyName:
            pass

        EmptyName.__name__ = ""
        self.assertEqual(binary_pipeline._cli_type_name(EmptyName()), "unknown")

        class BrokenText:
            def __str__(self):
                raise RuntimeError("cannot format")

        self.assertIn(
            "detail unavailable",
            binary_pipeline._cli_safe_error_text(BrokenText()),
        )
        self.assertEqual(binary_pipeline._cli_safe_error_text("short"), "short")
        self.assertTrue(
            binary_pipeline._cli_safe_error_text("x" * 100, limit=20).endswith(
                "...[truncated]"
            )
        )
        self.assertTrue(
            binary_pipeline._cli_safe_error_text("x", limit=-1).endswith(
                "...[truncated]"
            )
        )

        dispositions = (
            (
                {"activation_candidate_private": True},
                "private_candidate_pending_parent_commit",
            ),
            (
                {"activation_candidate_discarded": True},
                "candidate_measurement_discarded",
            ),
            (
                {"activation_recapture_discarded": True},
                "release_recapture_discarded",
            ),
            (
                {"active_generation_descriptor": "/active.json"},
                "active_generation_committed",
            ),
            ({}, "core_completed_without_active_descriptor_receipt"),
        )
        for payload, expected in dispositions:
            self.assertEqual(
                binary_pipeline._cli_core_result_receipt(payload)[
                    "activation_disposition"
                ],
                expected,
            )
        self.assertEqual(
            binary_pipeline._cli_core_result_receipt({
                "active_generation_descriptor": "",
            })["activation_disposition"],
            "core_completed_without_active_descriptor_receipt",
        )

        class BrokenReceipt(dict):
            def __contains__(self, key):
                if key == "schema":
                    raise RuntimeError("unavailable")
                return super().__contains__(key)

        broken = binary_pipeline._cli_core_result_receipt(BrokenReceipt())
        self.assertEqual(
            broken["schema"]["value_status"],
            "receipt_field_unavailable",
        )

    def test_cli_progress_and_failure_emission_exhaust_observability_boundaries(self):
        self.assertEqual(binary_pipeline._cli_attempt_progress(None, "id"), {})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            progress_path = (
                root / "binary_observability" / "latest_in_progress.json"
            )
            self.assertEqual(
                binary_pipeline._cli_attempt_progress(root, "id"), {}
            )
            progress_path.parent.mkdir()
            for content in (b"not-json", b"[]", b"\xff"):
                progress_path.write_bytes(content)
                self.assertEqual(
                    binary_pipeline._cli_attempt_progress(root, "id"), {}
                )
            progress_path.write_bytes(
                b"x" * (binary_pipeline._CLI_PROGRESS_MAX_BYTES + 1)
            )
            self.assertEqual(
                binary_pipeline._cli_attempt_progress(root, "id"), {}
            )
            progress_path.write_text(json.dumps({
                "attempt_identity": "other", "current_phase": "phase",
            }))
            self.assertEqual(
                binary_pipeline._cli_attempt_progress(root, "id"), {}
            )
            progress_path.write_text(json.dumps({
                "attempt_identity": "id",
                "current_phase": "phase",
                "nested": {"value": "x" * 2000},
            }))
            progress = binary_pipeline._cli_attempt_progress(root, "id")
            self.assertEqual(progress["current_phase"], "phase")
            with patch.object(
                binary_pipeline,
                "_cli_bounded_json_value",
                return_value=[],
            ):
                self.assertEqual(
                    binary_pipeline._cli_attempt_progress(root, "id"), {}
                )

            failure = {
                "schema": "java-upgrade-analyzer.binary-pipeline-failure.v1",
                "status": "failed",
                "reason_code": "TEST_FAILURE",
                "traceback": "private",
            }
            with patch.object(
                binary_pipeline.sys, "stderr", new=io.StringIO(),
            ):
                self.assertEqual(
                    binary_pipeline._emit_cli_failure(
                        failure,
                        diagnostic_root=None,
                        result_json="",
                    ),
                    1,
                )
            with patch.object(
                binary_pipeline.sys, "stderr", new=io.StringIO(),
            ), patch.object(
                binary_pipeline,
                "_cli_bounded_json_value",
                return_value=[],
            ):
                self.assertEqual(
                    binary_pipeline._emit_cli_failure(
                        failure,
                        diagnostic_root=None,
                        result_json="",
                    ),
                    1,
                )

            result_path = root / "result.json"
            with patch.object(
                binary_pipeline.sys, "stderr", new=io.StringIO(),
            ), patch.object(
                binary_pipeline,
                "_write_text_atomic_durable",
            ) as persist, patch.object(
                binary_pipeline,
                "_write_non_authoritative_json",
            ) as diagnostic:
                binary_pipeline._emit_cli_failure(
                    failure,
                    diagnostic_root=root,
                    result_json=str(result_path),
                )
            persist.assert_called_once()
            diagnostic.assert_called_once()

            with patch.object(
                binary_pipeline.sys, "stderr", new=io.StringIO(),
            ), patch.object(
                binary_pipeline,
                "_write_text_atomic_durable",
                side_effect=OSError("sink unavailable"),
            ), patch.object(
                binary_pipeline,
                "_write_non_authoritative_json",
                side_effect=OSError("diagnostic unavailable"),
            ):
                binary_pipeline._emit_cli_failure(
                    failure,
                    diagnostic_root=root,
                    result_json=str(result_path),
                )
            with patch.object(
                binary_pipeline.sys, "stderr", new=io.StringIO(),
            ), patch.object(
                binary_pipeline,
                "_write_text_atomic_durable",
            ) as persist:
                binary_pipeline._emit_cli_failure(
                    failure,
                    diagnostic_root=None,
                    result_json=str(result_path),
                    prior_result_sink_error=OSError("prior failure"),
                )
            persist.assert_not_called()

    def test_cli_failure_payload_exhausts_error_and_delivery_classification(self):
        attempt = "a" * 64
        with patch.object(
            binary_pipeline,
            "_cli_attempt_progress",
            return_value={},
        ):
            generic = binary_pipeline._cli_failure_payload(
                RuntimeError("plain failure"),
                diagnostic_root=None,
                attempt_identity=attempt,
            )
        self.assertEqual(
            generic["reason_code"], "BINARY_PIPELINE_UNHANDLED_FAILURE",
        )
        self.assertIsNone(generic["cause"])
        self.assertFalse(generic["progress_bound_to_attempt"])
        self.assertEqual(generic["failed_phase"], "")

        with patch.object(
            binary_pipeline,
            "_cli_attempt_progress",
            return_value={"current_phase": "generation"},
        ):
            structured = binary_pipeline._cli_failure_payload(
                RuntimeError('{"reason":"structured"}'),
                diagnostic_root=Path("/diagnostic"),
                attempt_identity=attempt,
            )
        self.assertEqual(structured["cause"], {"reason": "structured"})
        self.assertTrue(structured["progress_bound_to_attempt"])
        self.assertEqual(structured["failed_phase"], "generation")

        with patch.object(
            binary_pipeline,
            "_cli_attempt_progress",
            return_value={},
        ):
            structured_list = binary_pipeline._cli_failure_payload(
                RuntimeError('["structured"]'),
                diagnostic_root=None,
                attempt_identity=attempt,
            )
        self.assertEqual(structured_list["cause"], ["structured"])

        contract_error = binary_pipeline.BinaryFirstContractError(
            "BINARY_CONTRACT_FAILED", "contract failed",
        )
        contract = binary_pipeline._cli_failure_payload(
            contract_error,
            diagnostic_root=None,
            attempt_identity=attempt,
        )
        self.assertEqual(contract["reason_code"], "BINARY_CONTRACT_FAILED")
        memory = binary_pipeline._cli_failure_payload(
            MemoryError("memory"),
            diagnostic_root=None,
            attempt_identity=attempt,
        )
        self.assertEqual(
            memory["reason_code"], "BINARY_PIPELINE_MEMORY_EXHAUSTED",
        )

        core_result = {
            "schema": "result",
            "active_generation_descriptor": "/active.json",
        }
        serialized = binary_pipeline._cli_failure_payload(
            TypeError("cannot encode"),
            diagnostic_root=None,
            attempt_identity=attempt,
            core_result=core_result,
            failure_stage="result_serialization",
        )
        self.assertEqual(
            serialized["reason_code"],
            "BINARY_PIPELINE_RESULT_SERIALIZATION_FAILED",
        )
        self.assertEqual(serialized["failed_phase"], "result_delivery")
        self.assertTrue(serialized["core_transaction_succeeded"])
        self.assertEqual(
            serialized["core_result_receipt"]["activation_disposition"],
            "active_generation_committed",
        )
        persisted = binary_pipeline._cli_failure_payload(
            OSError("cannot persist"),
            diagnostic_root=None,
            attempt_identity=attempt,
            core_result={},
            failure_stage="result_persist",
        )
        self.assertEqual(
            persisted["reason_code"],
            "BINARY_PIPELINE_RESULT_PERSIST_FAILED",
        )

    def test_resume_checkpoint_byte_reader_exhausts_file_identity_races(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "checkpoint.json"
            path.write_bytes(b'{"ok":true}')
            self.assertEqual(
                binary_pipeline._read_resume_checkpoint_bytes(path),
                b'{"ok":true}',
            )
            directory_fd = binary_pipeline.os.open(
                root, binary_pipeline.os.O_RDONLY,
            )
            try:
                self.assertEqual(
                    binary_pipeline._read_resume_checkpoint_bytes(
                        path, parent_fd=directory_fd,
                    ),
                    b'{"ok":true}',
                )
            finally:
                binary_pipeline.os.close(directory_fd)
            self.assertIsNone(
                binary_pipeline._read_resume_checkpoint_bytes(
                    root / "missing.json"
                )
            )
            self.assertIsNone(
                binary_pipeline._read_resume_checkpoint_bytes(root)
            )
            hardlink = root / "checkpoint-hardlink.json"
            try:
                binary_pipeline.os.link(path, hardlink)
            except OSError:
                pass
            else:
                self.assertIsNone(
                    binary_pipeline._read_resume_checkpoint_bytes(path)
                )
                hardlink.unlink()

            def observed(
                *, mode=stat.S_IFREG | 0o600, nlink=1, size=2, inode=1,
            ):
                return SimpleNamespace(
                    st_dev=1,
                    st_ino=inode,
                    st_mode=mode,
                    st_nlink=nlink,
                    st_size=size,
                    st_mtime=1.0,
                    st_mtime_ns=1,
                )

            good = observed()

            def mocked_read(
                *, path_before=good, descriptor_before=good,
                descriptor_after=good, path_after=good,
                reads=(b"{}", b""), open_error=None, close_error=None,
            ):
                open_kwargs = (
                    {"side_effect": open_error}
                    if open_error is not None else {"return_value": 7}
                )
                real_lstat = binary_pipeline.os.lstat
                target_stats = iter((path_before, path_after))

                def target_lstat(entry, *args, **kwargs):
                    if entry == path or str(entry) == str(path):
                        return next(target_stats)
                    return real_lstat(entry, *args, **kwargs)

                with patch.object(
                    binary_pipeline.os,
                    "lstat",
                    side_effect=target_lstat,
                ), patch.object(
                    binary_pipeline.os, "open", **open_kwargs,
                ), patch.object(
                    binary_pipeline.os,
                    "fstat",
                    side_effect=[descriptor_before, descriptor_after],
                ), patch.object(
                    binary_pipeline.os, "read", side_effect=list(reads),
                ), patch.object(
                    binary_pipeline.os,
                    "close",
                    side_effect=close_error,
                ):
                    return binary_pipeline._read_resume_checkpoint_bytes(path)

            for before in (
                observed(mode=stat.S_IFDIR | 0o700),
                observed(size=binary_pipeline._MAX_RESUME_CHECKPOINT_BYTES + 1),
            ):
                self.assertIsNone(mocked_read(path_before=before))
            self.assertIsNone(mocked_read(open_error=OSError("open failed")))
            for descriptor in (
                observed(mode=stat.S_IFDIR | 0o700),
                observed(size=binary_pipeline._MAX_RESUME_CHECKPOINT_BYTES + 1),
                observed(inode=2),
            ):
                self.assertIsNone(
                    mocked_read(descriptor_before=descriptor)
                )

            self.assertIsNone(mocked_read(
                descriptor_after=observed(size=3),
            ))
            self.assertIsNone(mocked_read(
                descriptor_after=observed(mode=stat.S_IFDIR | 0o700),
            ))
            self.assertIsNone(mocked_read(
                descriptor_after=observed(inode=2),
            ))
            self.assertIsNone(mocked_read(
                path_after=observed(mode=stat.S_IFDIR | 0o700),
            ))
            self.assertIsNone(mocked_read(
                path_after=observed(inode=2),
            ))
            real_lstat = binary_pipeline.os.lstat
            target_stats = iter((good, OSError("replaced")))

            def replaced_target_lstat(entry, *args, **kwargs):
                if entry == path or str(entry) == str(path):
                    value = next(target_stats)
                    if isinstance(value, BaseException):
                        raise value
                    return value
                return real_lstat(entry, *args, **kwargs)

            with patch.object(
                binary_pipeline.os,
                "lstat",
                side_effect=replaced_target_lstat,
            ), patch.object(
                binary_pipeline.os, "open", return_value=7,
            ), patch.object(
                binary_pipeline.os, "fstat", side_effect=[good, good],
            ), patch.object(
                binary_pipeline.os, "read", side_effect=[b"{}", b""],
            ), patch.object(binary_pipeline.os, "close"):
                self.assertIsNone(
                    binary_pipeline._read_resume_checkpoint_bytes(path)
                )
            self.assertEqual(
                mocked_read(close_error=OSError("close failed")), b"{}",
            )

            large_content = b"x" * (
                binary_pipeline._MAX_RESUME_CHECKPOINT_BYTES + 1
            )
            self.assertIsNone(mocked_read(
                path_before=observed(size=0),
                descriptor_before=observed(size=0),
                descriptor_after=observed(size=len(large_content)),
                reads=(large_content,),
            ))

    def test_resume_config_and_artifact_identities_exhaust_path_normalization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first_root = root / "snapshot-a"
            second_root = root / "snapshot-b"
            (first_root / "src").mkdir(parents=True)
            (second_root / "src").mkdir(parents=True)
            first = {
                "source_overlay": {"source_sets": [
                    None,
                    {
                        "source_root": str(first_root),
                        "source_dirs": [
                            str(first_root), str(first_root / "src"),
                        ],
                    },
                ]},
            }
            second = {
                "source_overlay": {"source_sets": [
                    None,
                    {
                        "source_root": str(second_root),
                        "source_dirs": [
                            str(second_root), str(second_root / "src"),
                        ],
                    },
                ]},
            }
            self.assertEqual(
                binary_pipeline._resume_config_identity(first),
                binary_pipeline._resume_config_identity(second),
            )
            absolute = {
                "source_overlay": {"source_sets": [{
                    "source_dirs": [str(first_root / "src")],
                }]},
            }
            self.assertNotEqual(
                binary_pipeline._resume_config_identity(absolute),
                binary_pipeline._resume_config_identity(second),
            )
            outside = deepcopy(first)
            outside["source_overlay"]["source_sets"][1]["source_dirs"] = [
                str(second_root / "src")
            ]
            self.assertNotEqual(
                binary_pipeline._resume_config_identity(first),
                binary_pipeline._resume_config_identity(outside),
            )
            binary_pipeline._resume_config_identity({})
            binary_pipeline._resume_config_identity({"source_overlay": {}})
            binary_pipeline._resume_config_identity({
                "source_overlay": {"source_sets": None},
            })

            artifact = root / "artifact.jar"
            outer = root / "outer.jar"
            artifact.write_bytes(b"artifact")
            outer.write_bytes(b"outer")
            config = {
                "base": {"artifacts": [
                    None,
                    {"path": "", "outer_artifact_path": ""},
                    {
                        "path": str(artifact),
                        "outer_artifact_path": str(outer),
                    },
                ]},
                "current": {"artifacts": [{
                    "path": str(artifact),
                    "outer_artifact_path": str(artifact),
                }]},
            }
            direct = binary_pipeline._resume_input_artifact_identity(config)
            records = {
                artifact: SimpleNamespace(
                    content_sha256=hashlib.sha256(b"artifact").hexdigest(),
                    byte_length=len(b"artifact"),
                ),
                outer: SimpleNamespace(
                    content_sha256=hashlib.sha256(b"outer").hexdigest(),
                    byte_length=len(b"outer"),
                ),
            }
            cached = binary_pipeline._resume_input_artifact_identity(
                config,
                digest_session=SimpleNamespace(_records=records),
            )
            self.assertEqual(direct, cached)
            self.assertNotEqual(
                direct,
                binary_pipeline._resume_input_artifact_identity({}),
            )
            missing = root / "missing.jar"
            self.assert_pipeline_error(
                "BINARY_RESUME_INPUT_ARTIFACT_MISSING",
                lambda: binary_pipeline._resume_input_artifact_identity({
                    "base": {"artifacts": [{"path": str(missing)}]},
                }),
            )

    def test_restorable_timings_exhaust_shape_order_and_numeric_boundaries(self):
        validation_index = binary_pipeline._PhaseTimingRecorder.ORDER.index(
            "independent_validation"
        )
        expected = binary_pipeline._PhaseTimingRecorder.ORDER[
            :validation_index
        ]
        valid = [
            {"phase": phase, "elapsed_seconds": index}
            for index, phase in enumerate(expected)
        ]
        restored = binary_pipeline._restorable_prevalidation_phase_timings({
            "phase_timings_before_validation": valid,
        })
        self.assertEqual([item["phase"] for item in restored], list(expected))
        self.assertTrue(all(
            item["restored_from_generation_checkpoint"]
            for item in restored
        ))

        for raw in (None, {}, (), valid[:-1], valid + [valid[-1]]):
            self.assertEqual(
                binary_pipeline._restorable_prevalidation_phase_timings({
                    "phase_timings_before_validation": raw,
                }),
                [],
            )
        changed = deepcopy(valid)
        changed[0] = []
        self.assertEqual(
            binary_pipeline._restorable_prevalidation_phase_timings({
                "phase_timings_before_validation": changed,
            }),
            [],
        )
        changed = deepcopy(valid)
        changed[0].pop("phase")
        self.assertEqual(
            binary_pipeline._restorable_prevalidation_phase_timings({
                "phase_timings_before_validation": changed,
            }),
            [],
        )
        changed = deepcopy(valid)
        changed[0]["phase"] = "wrong"
        self.assertEqual(
            binary_pipeline._restorable_prevalidation_phase_timings({
                "phase_timings_before_validation": changed,
            }),
            [],
        )

        class BadFloat(float):
            def __float__(self):
                raise OverflowError("cannot convert")

        for elapsed in (
            True, "1", None, BadFloat(1), float("nan"),
            float("inf"), -1,
        ):
            changed = deepcopy(valid)
            changed[0]["elapsed_seconds"] = elapsed
            with self.subTest(elapsed=repr(elapsed)):
                self.assertEqual(
                    binary_pipeline._restorable_prevalidation_phase_timings({
                        "phase_timings_before_validation": changed,
                    }),
                    [],
                )

    def test_resume_performance_rebind_and_consumed_cleanup_exhaust_transactions(self):
        output = Path("/private/rebind-output")
        old = self._performance_binding_for_mode(
            "old-rebind", binary_pipeline._PERFORMANCE_RELEASE_AUTHORITY_MODE,
        )
        current = self._performance_binding_for_mode(
            "current-rebind",
            binary_pipeline._PERFORMANCE_RELEASE_AUTHORITY_MODE,
        )
        checkpoint = {
            "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
            "performance_authority_gate_binding": old,
        }
        checkpoint["checkpoint_content_identity"] = (
            binary_pipeline._resume_checkpoint_content_identity(checkpoint)
        )
        for old_value, current_value in (({}, current), (old, {})):
            changed = deepcopy(checkpoint)
            changed["performance_authority_gate_binding"] = old_value
            self.assert_pipeline_error(
                "BINARY_RESUME_PERFORMANCE_AUTHORITY_REBIND_INVALID",
                lambda changed=changed, current_value=current_value: (
                    binary_pipeline._rebind_resume_checkpoint_performance_authority(
                        output, changed, current_value,
                    )
                ),
            )
        self.assertEqual(
            binary_pipeline._rebind_resume_checkpoint_performance_authority(
                output, checkpoint, old,
            ),
            checkpoint,
        )
        corrupt = deepcopy(checkpoint)
        corrupt["checkpoint_content_identity"] = "0" * 64
        self.assert_pipeline_error(
            "BINARY_RESUME_CHECKPOINT_INTEGRITY_INVALID",
            lambda: binary_pipeline._rebind_resume_checkpoint_performance_authority(
                output, corrupt, current,
            ),
        )
        with patch.object(
            binary_pipeline,
            "_read_resume_checkpoint",
            return_value={},
        ):
            self.assert_pipeline_error(
                "BINARY_RESUME_CHECKPOINT_CHANGED_DURING_REBIND",
                lambda: binary_pipeline._rebind_resume_checkpoint_performance_authority(
                    output, checkpoint, current,
                ),
            )
        with patch.object(
            binary_pipeline,
            "_read_resume_checkpoint",
            return_value=checkpoint,
        ), patch.object(
            binary_pipeline,
            "_write_resume_checkpoint_roundtrip",
            side_effect=lambda _root, payload, **_kwargs: payload,
        ):
            rebound = (
                binary_pipeline._rebind_resume_checkpoint_performance_authority(
                    output, checkpoint, current,
                )
            )
        self.assertEqual(
            rebound["performance_authority_gate_binding"], current,
        )

        with patch.object(
            binary_pipeline,
            "_delete_resume_checkpoint_durable",
            return_value=True,
        ):
            self.assertTrue(
                binary_pipeline._cleanup_consumed_resume_checkpoint(
                    output, None,
                )
            )
        cleanup_error = binary_pipeline.BinaryPipelineError(
            "BINARY_RESUME_CHECKPOINT_UNLINK_FAILED", "failed",
        )
        with patch.object(
            binary_pipeline,
            "_delete_resume_checkpoint_durable",
            side_effect=cleanup_error,
        ):
            self.assertFalse(
                binary_pipeline._cleanup_consumed_resume_checkpoint(
                    output, None,
                )
            )
            self.assert_pipeline_error(
                "BINARY_RESUME_CHECKPOINT_UNLINK_FAILED",
                lambda: binary_pipeline._cleanup_consumed_resume_checkpoint(
                    output, current,
                ),
            )

    def test_resume_checkpoint_object_reader_exhausts_posix_windows_and_fallbacks(self):
        output = Path("/private/read-checkpoint")
        binding = SimpleNamespace(
            observability_fd=13, root_fd=12, parent_fd=11,
        )

        def secure_read(
            *, binding_value=binding, content=b'{"value":1}',
            open_error=None, verify_error=None, close_error=None,
        ):
            open_kwargs = (
                {"side_effect": open_error}
                if open_error is not None
                else {"return_value": binding_value}
            )
            verify_kwargs = (
                {"side_effect": verify_error}
                if verify_error is not None else {"return_value": None}
            )
            with patch.object(
                binary_pipeline,
                "_secure_resume_checkpoint_dirfd_supported",
                return_value=True,
            ), patch.object(
                binary_pipeline,
                "_open_bound_checkpoint_directories",
                **open_kwargs,
            ), patch.object(
                binary_pipeline,
                "_read_resume_checkpoint_bytes",
                return_value=content,
            ), patch.object(
                binary_pipeline,
                "_verify_checkpoint_directory_tree_binding",
                **verify_kwargs,
            ), patch.object(
                binary_pipeline.os,
                "close",
                side_effect=close_error,
            ):
                return binary_pipeline._read_resume_checkpoint(output)

        self.assertEqual(secure_read(), {"value": 1})
        self.assertEqual(secure_read(binding_value=None), {})
        self.assertEqual(secure_read(open_error=OSError("open")), {})
        self.assertEqual(secure_read(content=None), {})
        self.assertEqual(secure_read(verify_error=OSError("replaced")), {})
        self.assertEqual(secure_read(content=b"not-json"), {})
        self.assertEqual(
            secure_read(close_error=OSError("close")), {"value": 1},
        )

        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=False,
        ), patch.object(
            binary_pipeline, "os", SimpleNamespace(name="other"),
        ):
            self.assertEqual(binary_pipeline._read_resume_checkpoint(output), {})

        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=False,
        ), patch.object(
            binary_pipeline, "os", SimpleNamespace(name="nt"),
        ), patch.object(
            binary_pipeline,
            "_physical_observability_directory",
            return_value=output / "binary_observability",
        ), patch.object(
            binary_pipeline,
            "_read_resume_checkpoint_bytes",
            return_value=b'{"windows":true}',
        ):
            self.assertEqual(
                binary_pipeline._read_resume_checkpoint(output),
                {"windows": True},
            )
        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=False,
        ), patch.object(
            binary_pipeline, "os", SimpleNamespace(name="nt"),
        ), patch.object(
            binary_pipeline,
            "_physical_observability_directory",
            side_effect=OSError("unavailable"),
        ):
            self.assertEqual(binary_pipeline._read_resume_checkpoint(output), {})
        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=False,
        ), patch.object(
            binary_pipeline.os, "name", "nt",
        ), patch.object(
            binary_pipeline,
            "_physical_observability_directory",
            return_value=output / "binary_observability",
        ), patch.object(
            binary_pipeline,
            "_read_resume_checkpoint_bytes",
            return_value=None,
        ):
            self.assertEqual(binary_pipeline._read_resume_checkpoint(output), {})

    def test_resume_generation_source_records_fail_closed_on_missing_inputs(self):
        with patch.object(
            binary_pipeline,
            "_validate_generation_source_import_closure",
        ), patch.object(
            binary_pipeline,
            "_GENERATION_IMPLEMENTATION_SOURCE_PATHS",
            ("missing-generation-source.py",),
        ):
            self.assert_pipeline_error(
                "BINARY_GENERATION_IMPLEMENTATION_SOURCE_MISSING",
                binary_pipeline._resume_generation_source_records,
            )
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing-requirements.txt"
            with patch.object(
                binary_pipeline,
                "RUNTIME_REQUIREMENTS_PATH",
                missing,
            ), patch.object(
                binary_pipeline,
                "_validate_generation_source_import_closure",
            ):
                self.assert_pipeline_error(
                    "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                    binary_pipeline._resume_generation_source_records,
                )

    def test_resume_generation_validation_exhausts_rejection_and_activation_state_machine(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            generation_identity = "a" * 64
            performance_binding = self._performance_binding_for_mode(
                "resume-validation",
                binary_pipeline._PERFORMANCE_RELEASE_AUTHORITY_MODE,
            )

            def fixture(label, *, generation_kind="directory", manifest_kind="file"):
                output = root / label
                generations = output / "binary_generations"
                generations.mkdir(parents=True)
                generation_path = generations / generation_identity
                if generation_kind == "directory":
                    generation_path.mkdir()
                elif generation_kind == "file":
                    generation_path.write_text("not-directory")
                elif generation_kind == "symlink":
                    external = root / f"{label}-external"
                    external.mkdir()
                    generation_path.symlink_to(external, target_is_directory=True)
                manifest_path = generation_path / "result_generation.json"
                if generation_kind == "directory":
                    if manifest_kind == "file":
                        manifest_path.write_text("{}")
                    elif manifest_kind == "symlink":
                        target = root / f"{label}-manifest-target.json"
                        target.write_text("{}")
                        manifest_path.symlink_to(target)
                checkpoint = {
                    "schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA,
                    "status": binary_pipeline._RESUME_AWAITING_VALIDATION,
                    "config_identity": "config",
                    "input_artifact_identity": "input",
                    "result_generation_identity": generation_identity,
                    "implementation_identity": "implementation",
                    "activation_identity": "b" * 64,
                }
                manifest = {
                    "result_generation_identity": generation_identity,
                    "policy_identities": {
                        "runtime_comparison": "c" * 64,
                        "analysis_scope": "d" * 64,
                    },
                    "analysis_context_identity": "e" * 64,
                }
                return output.resolve(), checkpoint, manifest

            def execute(
                output,
                checkpoint,
                manifest,
                *,
                config_identity="config",
                input_identity="input",
                input_error=None,
                integrity=True,
                metadata_reason="",
                metadata_rebind=False,
                performance=None,
                generation_implementation_identity="implementation",
                live_implementation_identity="implementation",
                retain=False,
                candidate_discarded=False,
                seal_discarded=False,
                receipt=None,
                quarantine_error=None,
            ):
                phase_timings = []
                metadata = {
                    "performance_authority_rebind_required": metadata_rebind,
                    "cache_metrics": {},
                    "result_summary": {},
                    "source_inputs": {},
                    "artifact_safety_policy": {},
                }
                validation = {
                    "status": "passed",
                    "validation_run_identity": "f" * 64,
                    "validation_result_path": "/validation.json",
                }
                input_patch = (
                    patch.object(
                        binary_pipeline,
                        "_resume_input_artifact_identity",
                        side_effect=input_error,
                    )
                    if input_error is not None else patch.object(
                        binary_pipeline,
                        "_resume_input_artifact_identity",
                        return_value=input_identity,
                    )
                )
                quarantine_patch = (
                    patch.object(
                        binary_pipeline,
                        "_quarantine_resume_generation",
                        side_effect=quarantine_error,
                    )
                    if quarantine_error is not None else patch.object(
                        binary_pipeline,
                        "_quarantine_resume_generation",
                        return_value=output / "quarantine",
                    )
                )

                def activate(*_args, **kwargs):
                    kwargs["activation_record"].update({
                        "activation_identity": kwargs["activation_identity"],
                    })
                    return "/active.json"

                with patch.object(
                    binary_pipeline,
                    "_read_resume_checkpoint",
                    return_value=deepcopy(checkpoint),
                ), patch.object(
                    binary_pipeline,
                    "_resume_config_identity",
                    return_value=config_identity,
                ), input_patch, patch.object(
                    binary_pipeline,
                    "_record_resume_decision",
                ) as decision, quarantine_patch, patch.object(
                    binary_pipeline,
                    "_read_optional_json_object",
                    return_value=deepcopy(manifest),
                ), patch.object(
                    binary_pipeline,
                    "_resume_generation_integrity_valid",
                    return_value=integrity,
                ), patch.object(
                    binary_pipeline,
                    "_resume_checkpoint_metadata",
                    return_value=(metadata_reason, deepcopy(metadata)),
                ), patch.object(
                    binary_pipeline,
                    "_rebind_resume_checkpoint_performance_authority",
                    side_effect=lambda _root, value, _binding: value,
                ) as rebind, patch.object(
                    binary_pipeline,
                    "_restorable_prevalidation_phase_timings",
                    return_value=[{"phase": "restored"}],
                ), patch.object(
                    binary_pipeline,
                    "_validate_or_reuse_checkpoint_attachment",
                    return_value=(validation, deepcopy(checkpoint)),
                ), patch.object(
                    binary_pipeline,
                    "_resume_implementation_identity",
                    return_value=live_implementation_identity,
                ), patch.object(
                    binary_pipeline,
                    "_activate_validated_generation_with_authority_binding",
                    side_effect=activate,
                ), patch.object(
                    binary_pipeline,
                    "_peak_rss_bytes",
                    side_effect=[10, 20],
                ), patch.object(
                    binary_pipeline,
                    "_discard_measurement_candidate_activation",
                    return_value=candidate_discarded,
                ), patch.object(
                    binary_pipeline,
                    "_seal_and_finalize_measured_activation",
                    return_value=seal_discarded,
                ) as seal, patch.object(
                    binary_pipeline,
                    "_cleanup_consumed_resume_checkpoint",
                ) as cleanup, patch.object(
                    binary_pipeline,
                    "_validation_checkpoint_result_receipt",
                    return_value={} if receipt is None else receipt,
                ), patch.object(
                    binary_pipeline,
                    "_write_non_authoritative_json",
                    return_value=True,
                ):
                    result = binary_pipeline._resume_generation_validation(
                        {},
                        output_root=output,
                        source_inputs={},
                        toolchain_preflight={},
                        asm_jar="asm.jar",
                        phase_timings=phase_timings,
                        pipeline_started=binary_pipeline.time.perf_counter(),
                        retain_checkpoint=retain,
                        generation_implementation_identity=(
                            generation_implementation_identity
                        ),
                        performance_authority_gate_binding=performance,
                    )
                reasons = [
                    call.kwargs.get("reason_code")
                    for call in decision.call_args_list
                ]
                return result, reasons, rebind, seal, cleanup, phase_timings

            output, checkpoint, manifest = fixture("empty-checkpoint")
            empty = deepcopy(checkpoint)
            empty.clear()
            result, *_ = execute(output, empty, manifest)
            self.assertIsNone(result)

            for label, mutate, expected_reason in (
                (
                    "schema", lambda value: value.update(schema="wrong"),
                    "BINARY_RESUME_CHECKPOINT_SCHEMA_MISMATCH",
                ),
                (
                    "config", lambda value: value.update(config_identity="wrong"),
                    "BINARY_RESUME_CONFIG_CHANGED",
                ),
            ):
                output, checkpoint, manifest = fixture(label)
                mutate(checkpoint)
                result, reasons, *_ = execute(output, checkpoint, manifest)
                self.assertIsNone(result)
                self.assertIn(expected_reason, reasons)

            output, checkpoint, manifest = fixture("implementation")
            checkpoint["implementation_identity"] = "wrong"
            result, reasons, *_ = execute(
                output,
                checkpoint,
                manifest,
                performance=performance_binding,
                generation_implementation_identity="implementation",
            )
            self.assertIsNone(result)
            self.assertIn("BINARY_RESUME_IMPLEMENTATION_CHANGED", reasons)

            output, checkpoint, manifest = fixture("input-error")
            unavailable = binary_pipeline.BinaryFirstContractError(
                "BINARY_INPUT_UNAVAILABLE", "unavailable",
            )
            result, reasons, *_ = execute(
                output, checkpoint, manifest, input_error=unavailable,
            )
            self.assertIsNone(result)
            self.assertIn("BINARY_RESUME_INPUT_ARTIFACT_UNAVAILABLE", reasons)
            output, checkpoint, manifest = fixture("input-drift")
            result, reasons, *_ = execute(
                output, checkpoint, manifest, input_identity="changed",
            )
            self.assertIsNone(result)
            self.assertIn("BINARY_RESUME_INPUT_ARTIFACT_CHANGED", reasons)

            output, checkpoint, manifest = fixture("identity-invalid")
            checkpoint.pop("result_generation_identity")
            result, reasons, *_ = execute(output, checkpoint, manifest)
            self.assertIsNone(result)
            self.assertIn("BINARY_RESUME_GENERATION_IDENTITY_INVALID", reasons)

            for label, kind in (
                ("generation-missing", "missing"),
                ("generation-file", "file"),
                ("generation-symlink", "symlink"),
            ):
                output, checkpoint, manifest = fixture(
                    label, generation_kind=kind,
                )
                result, reasons, *_ = execute(output, checkpoint, manifest)
                self.assertIsNone(result)
                self.assertIn("BINARY_RESUME_GENERATION_MISSING", reasons)

            for label, manifest_kind in (
                ("manifest-missing", "missing"),
                ("manifest-symlink", "symlink"),
            ):
                output, checkpoint, manifest = fixture(
                    label, manifest_kind=manifest_kind,
                )
                result, reasons, *_ = execute(output, checkpoint, manifest)
                self.assertIsNone(result)
                self.assertIn(
                    "BINARY_RESUME_GENERATION_MANIFEST_INVALID", reasons,
                )

            output, checkpoint, manifest = fixture("manifest-empty")
            with patch.object(
                binary_pipeline,
                "_read_optional_json_object",
                return_value={},
            ):
                result, reasons, *_ = execute(output, checkpoint, manifest)
            # execute owns the authoritative reader patch, so exercise the
            # same branch through an empty manifest fixture instead.
            empty_manifest = {}
            result, reasons, *_ = execute(
                output, checkpoint, empty_manifest,
            )
            self.assertIsNone(result)
            self.assertIn(
                "BINARY_RESUME_GENERATION_MANIFEST_INVALID", reasons,
            )

            output, checkpoint, manifest = fixture("manifest-identity")
            manifest["result_generation_identity"] = "0" * 64
            result, reasons, *_ = execute(output, checkpoint, manifest)
            self.assertIsNone(result)
            self.assertIn("BINARY_RESUME_GENERATION_IDENTITY_MISMATCH", reasons)
            output, checkpoint, manifest = fixture("manifest-integrity")
            result, reasons, *_ = execute(
                output, checkpoint, manifest, integrity=False,
            )
            self.assertIsNone(result)
            self.assertIn("BINARY_RESUME_GENERATION_INTEGRITY_INVALID", reasons)

            output, checkpoint, manifest = fixture("metadata")
            result, reasons, *_ = execute(
                output,
                checkpoint,
                manifest,
                metadata_reason="BINARY_RESUME_BINDING_CHANGED",
            )
            self.assertIsNone(result)
            self.assertIn("BINARY_RESUME_BINDING_CHANGED", reasons)

            output, checkpoint, manifest = fixture("quarantine-failure")
            manifest["result_generation_identity"] = "0" * 64
            self.assert_pipeline_error(
                "BINARY_RESUME_GENERATION_QUARANTINE_FAILED",
                lambda: execute(
                    output,
                    checkpoint,
                    manifest,
                    quarantine_error=OSError("cannot quarantine"),
                ),
            )

            output, checkpoint, manifest = fixture("valid-normal")
            result, reasons, rebind, seal, cleanup, timings = execute(
                output, checkpoint, manifest,
            )
            self.assertTrue(result["resumed_from_generation_checkpoint"])
            self.assertEqual(result["peak_rss_bytes"], 20)
            self.assertIn("BINARY_RESUME_VALIDATION_ONLY", reasons)
            self.assertFalse(rebind.called)
            seal.assert_called_once()
            cleanup.assert_called_once()
            self.assertEqual(timings[0]["phase"], "restored")

            output, checkpoint, manifest = fixture("valid-rebind")
            checkpoint["status"] = binary_pipeline._RESUME_VALIDATION_PASSED
            result, reasons, rebind, *_ = execute(
                output,
                checkpoint,
                manifest,
                metadata_rebind=True,
                performance=performance_binding,
                generation_implementation_identity="",
            )
            self.assertIsNotNone(result)
            self.assertIn("BINARY_RESUME_VALIDATION_ATTACHMENT", reasons)
            rebind.assert_called_once()
            self.assertEqual(
                result["performance_authority_gate_binding"],
                performance_binding,
            )

            output, checkpoint, manifest = fixture("implementation-drift")
            self.assert_pipeline_error(
                "BINARY_PIPELINE_IMPLEMENTATION_CHANGED_DURING_RUN",
                lambda: execute(
                    output,
                    checkpoint,
                    manifest,
                    performance=performance_binding,
                    generation_implementation_identity="implementation",
                    live_implementation_identity="changed",
                ),
            )

            output, checkpoint, manifest = fixture("candidate-discarded")
            result, _, _, seal, cleanup, _ = execute(
                output,
                checkpoint,
                manifest,
                candidate_discarded=True,
                retain=True,
            )
            self.assertEqual(result["active_generation_descriptor"], "")
            seal.assert_not_called()
            cleanup.assert_not_called()

            output, checkpoint, manifest = fixture("retained-checkpoint")
            checkpoint.pop("activation_identity")
            result, _, _, seal, cleanup, _ = execute(
                output,
                checkpoint,
                manifest,
                retain=True,
                receipt={"validation_checkpoint_retained": True},
            )
            self.assertTrue(result["validation_checkpoint_retained"])
            self.assertTrue(result["phase_timings"][-1]["publication_deferred"])
            seal.assert_not_called()
            cleanup.assert_not_called()

            output, checkpoint, manifest = fixture("recapture-discarded")
            result, *_ = execute(
                output,
                checkpoint,
                manifest,
                seal_discarded=True,
            )
            self.assertEqual(result["active_generation_descriptor"], "")

    def test_artifact_worker_counts_and_digest_session_exhaust_boundaries(self):
        for function, reason in (
            (
                binary_pipeline._artifact_snapshot_worker_count,
                "BINARY_ARTIFACT_WORKER_COUNT_INVALID",
            ),
            (
                binary_pipeline._artifact_hash_worker_count,
                "BINARY_ARTIFACT_HASH_WORKER_COUNT_INVALID",
            ),
        ):
            self.assertEqual(function(None, 0), 0)
            self.assertEqual(function("", 0), 0)
            with patch.object(binary_pipeline.os, "cpu_count", return_value=None):
                self.assertEqual(function(None, 3), 1)
            with patch.object(binary_pipeline.os, "cpu_count", return_value=64):
                self.assertGreaterEqual(function(None, 3), 1)
            self.assertEqual(function(8, 2), 2)
            self.assertEqual(function("2", 5), 2)
            for invalid in (True, 1.0, "invalid", object(), 0, 9, -1):
                with self.subTest(function=function.__name__, invalid=invalid):
                    self.assert_pipeline_error(
                        reason,
                        lambda function=function, invalid=invalid: function(
                            invalid, 3
                        ),
                    )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = root / "first.jar"
            second = root / "second.jar"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            first_sha = hashlib.sha256(b"first").hexdigest()
            second_sha = hashlib.sha256(b"second").hexdigest()
            session = binary_pipeline._ArtifactDigestSession()

            self.assertEqual(
                session._expected_sha256(None, path=first), ""
            )
            self.assertEqual(
                session._expected_sha256(first_sha.upper(), path=first),
                first_sha,
            )
            for invalid in ("x", "g" * 64, "0" * 63, "0" * 65):
                self.assert_pipeline_error(
                    "BINARY_PIPELINE_ARTIFACT_SHA256_INVALID",
                    lambda invalid=invalid: session._expected_sha256(
                        invalid, path=first,
                    ),
                )

            session.prime([], configured_workers=None)
            session.prime([(first, first_sha)], configured_workers=1)
            self.assertEqual(session.hash_execution_count, 1)
            session.prime(
                [(first, first_sha), (first, ""), (second, second_sha)],
                configured_workers=2,
            )
            self.assertEqual(session.parallel_hash_file_count, 2)
            self.assert_pipeline_error(
                "BINARY_PIPELINE_ARTIFACT_SHA256_MISMATCH",
                lambda: session.prime(
                    [(first, "0" * 64)], configured_workers=1,
                ),
            )
            changed_prime = binary_pipeline._ArtifactDigestSession()
            changed_prime._records[first.resolve()] = (
                binary_pipeline._ArtifactDigestRecord(
                    content_sha256="0" * 64,
                    byte_length=5,
                    file_identity=(1, 1, 5, 1),
                )
            )
            self.assert_pipeline_error(
                "BINARY_PIPELINE_ARTIFACT_CHANGED_DURING_PROFILE",
                lambda: changed_prime.prime(
                    [(first, "")], configured_workers=1,
                ),
            )

            reused = session.digest(first, expected_sha256=first_sha)
            self.assertEqual(reused.content_sha256, first_sha)
            self.assertGreaterEqual(session.hash_reuse_count, 1)
            session.digest(
                second,
                expected_sha256=second_sha,
                revalidate_at_end=True,
            )
            session.revalidate_marked()
            self.assertEqual(session.final_verification_hash_count, 1)
            self.assert_pipeline_error(
                "BINARY_PIPELINE_ARTIFACT_SHA256_MISMATCH",
                lambda: session.digest(first, expected_sha256="0" * 64),
            )
            self.assert_pipeline_error(
                "BINARY_PIPELINE_ARTIFACT_MISSING",
                lambda: session.digest(root / "missing.jar"),
            )
            self.assert_pipeline_error(
                "BINARY_PIPELINE_ARTIFACT_MISSING",
                lambda: session._hash_stable_record(root),
            )

            changed_session = binary_pipeline._ArtifactDigestSession()
            original = changed_session.digest(first)
            changed_session._records[first.resolve()] = (
                binary_pipeline._ArtifactDigestRecord(
                    content_sha256=original.content_sha256,
                    byte_length=original.byte_length,
                    file_identity=tuple(
                        value + 1 for value in original.file_identity
                    ),
                )
            )
            changed_record = binary_pipeline._ArtifactDigestRecord(
                content_sha256="0" * 64,
                byte_length=original.byte_length,
                file_identity=tuple(value + 1 for value in original.file_identity),
            )
            with patch.object(
                changed_session,
                "_hash_stable",
                return_value=changed_record,
            ):
                self.assert_pipeline_error(
                    "BINARY_PIPELINE_ARTIFACT_CHANGED_DURING_PROFILE",
                    lambda: changed_session.digest(first),
                )

            stable_change_session = binary_pipeline._ArtifactDigestSession()
            stable_record = stable_change_session.digest(first)
            stable_change_session._records[first.resolve()] = (
                binary_pipeline._ArtifactDigestRecord(
                    content_sha256=stable_record.content_sha256,
                    byte_length=stable_record.byte_length,
                    file_identity=tuple(
                        value + 1 for value in stable_record.file_identity
                    ),
                )
            )
            with patch.object(
                stable_change_session,
                "_hash_stable",
                return_value=stable_record,
            ):
                self.assertEqual(
                    stable_change_session.digest(first).content_sha256,
                    first_sha,
                )

            first_stat = first.stat()
            before = SimpleNamespace(
                st_dev=first_stat.st_dev,
                st_ino=first_stat.st_ino,
                st_size=first_stat.st_size,
                st_mtime=first_stat.st_mtime,
                st_mtime_ns=first_stat.st_mtime_ns,
            )
            after = SimpleNamespace(
                st_dev=first_stat.st_dev,
                st_ino=first_stat.st_ino + 1,
                st_size=first_stat.st_size,
                st_mtime=first_stat.st_mtime,
                st_mtime_ns=first_stat.st_mtime_ns,
            )

            class ChangingPath:
                def __init__(self):
                    self.stats = iter((before, after))

                def stat(self):
                    return next(self.stats)

                def is_file(self):
                    return True

                def __str__(self):
                    return str(first)

            with patch.object(
                binary_pipeline, "_sha256_file", return_value=first_sha,
            ):
                self.assert_pipeline_error(
                    "BINARY_PIPELINE_ARTIFACT_CHANGED_DURING_HASH",
                    lambda: session._hash_stable_record(ChangingPath()),
                )

            revalidate_session = binary_pipeline._ArtifactDigestSession()
            revalidate_session.digest(first, revalidate_at_end=True)
            with patch.object(
                revalidate_session,
                "_hash_stable",
                return_value=binary_pipeline._ArtifactDigestRecord(
                    content_sha256="0" * 64,
                    byte_length=5,
                    file_identity=(1, 1, 5, 1),
                ),
            ):
                self.assert_pipeline_error(
                    "BINARY_PIPELINE_OUTER_ARTIFACT_CHANGED_DURING_PROFILE",
                    revalidate_session.revalidate_marked,
                )

    def test_runtime_requirement_pins_and_multi_release_contract_exhaust_matrix(self):
        valid_content = (
            b"# exact runtime\n"
            b"tree-sitter==1.2.3\n"
            b"\n"
            b"tree-sitter-java==4.5.6\n"
        )
        self.assertEqual(
            binary_pipeline._runtime_requirement_pins(valid_content),
            {"tree-sitter": "1.2.3", "tree-sitter-java": "4.5.6"},
        )
        invalid_contents = (
            b"\xff",
            b"tree-sitter\ntree-sitter-java==1\n",
            b"==1\ntree-sitter==1\ntree-sitter-java==1\n",
            b"tree-sitter==\ntree-sitter-java==1\n",
            b"tree-sitter==1\ntree-sitter==2\ntree-sitter-java==1\n",
            b"tree-sitter== 1\ntree-sitter-java==1\n",
            b"tree-sitter==1\n",
            b"tree-sitter==1\ntree-sitter-java==1\nextra==1\n",
        )
        for content in invalid_contents:
            self.assert_pipeline_error(
                "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                lambda content=content: binary_pipeline._runtime_requirement_pins(
                    content
                ),
            )

        valid_policy = {
            "policy_identity": "openjdk-jarfile-default-properties-v1",
            "target_runtime_feature": 21,
            "jdk.util.jar.enableMultiRelease": "true",
            "jdk.util.jar.version": "target-runtime-feature",
            "non_default_behavior": "fail_closed",
        }
        binary_pipeline._validate_multi_release_runtime_contract({}, {}, 21)
        binary_pipeline._validate_multi_release_runtime_contract(
            {
                "runtime_system_properties": {"unrelated": "value"},
                "runtime_jvm_arguments": ["-Xmx1g", "-Dunrelated=value"],
            },
            {},
            21,
        )
        binary_pipeline._validate_multi_release_runtime_contract(
            {"runtime_system_properties": {
                "jdk.util.jar.enableMultiRelease": "true",
            }},
            {},
            21,
        )
        for location in ("side", "profile", "nested"):
            side = {}
            profile = {}
            if location == "side":
                side["multi_release_jar_runtime_policy"] = dict(valid_policy)
            elif location == "profile":
                profile["multi_release_jar_runtime_policy"] = dict(valid_policy)
            else:
                profile["loader_topology"] = {
                    "multi_release_jar_runtime_policy": dict(valid_policy),
                }
            binary_pipeline._validate_multi_release_runtime_contract(
                side, profile, 21,
            )

        unsupported_inputs = (
            (
                {"runtime_system_properties": {
                    "jdk.util.jar.enableMultiRelease": "false",
                }},
                {},
            ),
            (
                {},
                {"jvm_system_properties": {
                    "jdk.util.jar.version": "17",
                }},
            ),
            (
                {"jvm_arguments": "-Djdk.util.jar.enableMultiRelease"},
                {},
            ),
            (
                {},
                {"JAVA_TOOL_OPTIONS": [
                    "-Djdk.util.jar.version=target-runtime-feature",
                ]},
            ),
        )
        for side, profile in unsupported_inputs:
            self.assert_pipeline_error(
                "BINARY_PIPELINE_MULTI_RELEASE_JVM_PROPERTY_UNSUPPORTED",
                lambda side=side, profile=profile: (
                    binary_pipeline._validate_multi_release_runtime_contract(
                        side, profile, 21,
                    )
                ),
            )
        for policy in ([], {}, {**valid_policy, "target_runtime_feature": 17}):
            self.assert_pipeline_error(
                "BINARY_PIPELINE_MULTI_RELEASE_POLICY_UNSUPPORTED",
                lambda policy=policy: (
                    binary_pipeline._validate_multi_release_runtime_contract(
                        {"multi_release_jar_runtime_policy": policy}, {}, 21,
                    )
                ),
            )

    def test_static_runtime_and_build_identity_validators_exhaust_container_shapes(self):
        binary_pipeline._validate_static_runtime_profile_inputs({})
        binary_pipeline._validate_static_runtime_profile_inputs({
            "base": [], "current": None,
        })
        binary_pipeline._validate_static_runtime_profile_inputs({
            "base": {}, "current": {"runtime_profile": {}},
        })
        for invalid in ([], "profile"):
            self.assert_pipeline_error(
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                lambda invalid=invalid: (
                    binary_pipeline._validate_static_runtime_profile_inputs({
                        "base": {"runtime_profile": invalid},
                    })
                ),
            )
        mapping_fields = (
            "target_jvm", "loader_topology", "business_entrypoint_profile",
            "resolved_configuration_properties", "field_coverage",
        )
        for field in mapping_fields:
            self.assert_pipeline_error(
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                lambda field=field: (
                    binary_pipeline._validate_static_runtime_profile_inputs({
                        "base": {"runtime_profile": {field: []}},
                    })
                ),
            )
        sequence_fields = (
            "active_profile_identities",
            "external_config_snapshot_identities",
            "agent_transformer_plugin_profile_identities",
            "runtime_configuration_coverage_gaps",
            "entrypoint_discovery_coverage_gaps",
        )
        for field in sequence_fields:
            self.assert_pipeline_error(
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                lambda field=field: (
                    binary_pipeline._validate_static_runtime_profile_inputs({
                        "base": {"runtime_profile": {field: {}}},
                    })
                ),
            )
        binary_pipeline._validate_static_runtime_profile_inputs({
            "base": {"runtime_profile": {
                "active_profile_identities": [],
            }},
        })
        business_fields = (
            "methods", "activated_frameworks", "activated_classes",
            "activated_entity_classes", "activated_resource_names",
            "activated_component_scan_packages", "coverage_gaps",
        )
        for field in business_fields:
            self.assert_pipeline_error(
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                lambda field=field: (
                    binary_pipeline._validate_static_runtime_profile_inputs({
                        "base": {"runtime_profile": {
                            "business_entrypoint_profile": {field: {}},
                        }},
                    })
                ),
            )
        self.assert_pipeline_error(
            "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
            lambda: binary_pipeline._validate_static_runtime_profile_inputs({
                "base": {"runtime_profile": {
                    "business_entrypoint_profile": {"methods": [None]},
                }},
            }),
        )
        for realms in ({}, [None]):
            self.assert_pipeline_error(
                "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
                lambda realms=realms: (
                    binary_pipeline._validate_static_runtime_profile_inputs({
                        "base": {"runtime_profile": {
                            "loader_topology": {"realms": realms},
                        }},
                    })
                ),
            )
        self.assert_pipeline_error(
            "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
            lambda: binary_pipeline._validate_static_runtime_profile_inputs({
                "base": {"runtime_profile": {
                    "loader_topology": {"entrypoint_realms": {}},
                }},
            }),
        )
        binary_pipeline._validate_static_runtime_profile_inputs({
            "base": {
                "jvm_arguments": ["-Xmx1g"],
                "runtime_profile": {
                    "business_entrypoint_profile": {"methods": [{}]},
                    "loader_topology": {
                        "realms": [{}], "entrypoint_realms": (),
                    },
                    "runtime_jvm_arguments": "-Xms128m",
                },
            },
        })

        binary_pipeline._validate_static_build_identity_inputs({})
        binary_pipeline._validate_static_build_identity_inputs({"base": []})
        binary_pipeline._validate_static_build_identity_inputs({
            "base": {}, "current": {"build_identity": {}},
        })
        self.assert_pipeline_error(
            "BINARY_BUILD_IDENTITY_CONFIG_INVALID",
            lambda: binary_pipeline._validate_static_build_identity_inputs({
                "base": {"build_identity": []},
            }),
        )
        for field in (
            "build_environment", "build_input_manifest",
            "artifact_build_provenance",
        ):
            self.assert_pipeline_error(
                "BINARY_BUILD_IDENTITY_CONFIG_INVALID",
                lambda field=field: (
                    binary_pipeline._validate_static_build_identity_inputs({
                        "base": {"build_identity": {field: []}},
                    })
                ),
            )
        binary_pipeline._validate_static_build_identity_inputs({
            "base": {"build_identity": {"artifact_build_provenance": {}}},
        })
        with patch.object(
            binary_pipeline,
            "BuildIdentityBundle",
        ) as bundle:
            binary_pipeline._validate_static_build_identity_inputs({
                "base": {"build_identity": {
                    "artifact_build_provenance": {"input_mode": "provided"},
                }},
            })
            bundle.assert_called_once()
        with patch.object(
            binary_pipeline,
            "BuildIdentityBundle",
        ) as bundle:
            binary_pipeline._validate_static_build_identity_inputs({
                "base": {"build_identity": {
                    "build_environment": {"jdk": "21"},
                    "build_input_manifest": {"source": "fixed"},
                    "artifact_build_provenance": {"input_mode": "provided"},
                }},
            })
            bundle.assert_called_once()
        contract_error = binary_pipeline.BinaryFirstContractError(
            "BUILD_IDENTITY_INVALID", "invalid",
        )
        with patch.object(
            binary_pipeline,
            "BuildIdentityBundle",
            side_effect=contract_error,
        ):
            self.assert_pipeline_error(
                "BUILD_IDENTITY_INVALID",
                lambda: binary_pipeline._validate_static_build_identity_inputs({
                    "base": {"build_identity": {
                        "artifact_build_provenance": {"input_mode": "provided"},
                    }},
                }),
            )

    def test_artifact_descriptors_instances_and_build_bundle_exhaust_defaults_and_ordering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = root / "first.jar"
            second = root / "second.jar"
            outer = root / "outer.jar"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            outer.write_bytes(b"outer")
            raw = [
                {
                    "path": str(second), "slot": 1,
                    "loader_realm": "app", "logical_location": "lib/b.jar",
                    "runtime_code_source_origin_identity": "origin-b",
                },
                {
                    "path": str(first), "slot": 0,
                    "loader_realm": "app", "logical_location": "lib/a.jar",
                    "runtime_code_source_origin_identity": "origin-a",
                },
            ]
            normalized, descriptors = binary_pipeline._artifact_descriptors(raw)
            self.assertEqual(
                [item["logical_location"] for item in normalized],
                ["lib/a.jar", "lib/b.jar"],
            )
            self.assertEqual(descriptors[0]["path_kind"], "classpath")
            self.assertEqual(binary_pipeline._artifact_descriptors([]), ([], []))
            supplied_digest_session = binary_pipeline._ArtifactDigestSession()
            explicit_raw = deepcopy(raw)
            explicit_raw[0]["path_kind"] = "module_path"
            explicit_raw[0]["loader_realm"] = ""
            binary_pipeline._artifact_descriptors(
                explicit_raw,
                digest_session=supplied_digest_session,
            )
            self.assert_pipeline_error(
                "BINARY_PIPELINE_ARTIFACT_MISSING",
                lambda: binary_pipeline._artifact_descriptors([{
                    "path": str(root / "missing.jar"),
                    "slot": 0,
                }]),
            )
            self.assert_pipeline_error(
                "BINARY_PIPELINE_ARTIFACT_MISSING",
                lambda: binary_pipeline._artifact_descriptors([{
                    "path": "", "slot": 0,
                }]),
            )
            self.assert_pipeline_error(
                "BINARY_PIPELINE_RUNTIME_SLOT_INVALID",
                lambda: binary_pipeline._artifact_descriptors([{
                    "path": str(first), "slot": -1,
                    "loader_realm": "app",
                }]),
            )
            self.assert_pipeline_error(
                "BINARY_PIPELINE_RUNTIME_SLOT_INVALID",
                lambda: binary_pipeline._artifact_descriptors([
                    {"path": str(first), "slot": 0, "loader_realm": "app"},
                    {"path": str(second), "slot": 0, "loader_realm": "app"},
                ]),
            )

            class FakeDigestSession:
                def __init__(self):
                    self.calls = []
                    self.revalidated = 0

                def digest(
                    self, path, *, expected_sha256=None,
                    revalidate_at_end=False,
                ):
                    self.calls.append((Path(path), revalidate_at_end))
                    return SimpleNamespace(
                        content_sha256=hashlib.sha256(
                            Path(path).read_bytes()
                        ).hexdigest(),
                        byte_length=Path(path).stat().st_size,
                    )

                def revalidate_marked(self):
                    self.revalidated += 1

            profile = SimpleNamespace(identity="profile")
            artifacts = [{
                "path": str(first),
                "outer_artifact_path": str(outer),
                "content_sha256": hashlib.sha256(b"first").hexdigest(),
                "slot": 0,
                "loader_realm": "app",
                "runtime_code_source_origin_identity": "origin",
            }, {
                "path": str(second),
                "content_sha256": hashlib.sha256(b"second").hexdigest(),
                "slot": 1,
                "loader_realm": "bootstrap",
                "runtime_code_source_origin_identity": "origin-2",
                "container_entry": "nested.jar",
                "path_kind": "module_path",
                "container_loader_policy_version": "policy",
                "coord": "g:a:1",
            }]
            supplied_session = FakeDigestSession()
            instances = binary_pipeline._artifact_instances(
                artifacts,
                profile,
                digest_session=supplied_session,
            )
            self.assertEqual(len(instances), 2)
            self.assertTrue(supplied_session.calls[0][1])
            self.assertFalse(supplied_session.calls[1][1])
            self.assertEqual(supplied_session.revalidated, 0)
            owned_session = FakeDigestSession()
            with patch.object(
                binary_pipeline,
                "_ArtifactDigestSession",
                return_value=owned_session,
            ):
                binary_pipeline._artifact_instances(
                    artifacts, profile,
                )
            self.assertEqual(owned_session.revalidated, 1)
            self.assertEqual(
                binary_pipeline._artifact_instances(
                    [], profile, digest_session=FakeDigestSession(),
                ),
                [],
            )
            for missing_field in (
                "loader_realm", "runtime_code_source_origin_identity",
            ):
                invalid = deepcopy(artifacts[0])
                invalid.pop(missing_field)
                with self.assertRaises(
                    binary_pipeline.BinaryFirstContractError
                ):
                    binary_pipeline._artifact_instances(
                        [invalid], profile, digest_session=FakeDigestSession(),
                    )

            with patch.object(
                binary_pipeline,
                "BuildIdentityBundle",
                side_effect=lambda environment, inputs, provenance: {
                    "environment": environment,
                    "inputs": inputs,
                    "provenance": provenance,
                },
            ):
                default_bundle = binary_pipeline._build_identity_bundle(
                    {}, normalized,
                )
                self.assertEqual(
                    default_bundle["provenance"]["input_mode"],
                    "provided_artifact",
                )
                explicit_bundle = binary_pipeline._build_identity_bundle({
                    "build_identity": {
                        "build_environment": {"jdk": "21"},
                        "build_input_manifest": {"source": "fixed"},
                        "artifact_build_provenance": {
                            "input_mode": "built",
                        },
                    },
                }, normalized)
                self.assertEqual(
                    explicit_bundle["provenance"]["input_mode"], "built",
                )

    def test_runtime_distribution_and_stable_file_record_exhaust_filesystem_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            module = root / "module"
            module.mkdir()
            runtime_file = module / "runtime.py"
            runtime_file.write_bytes(b"runtime")
            record = binary_pipeline._stable_runtime_file_record(
                runtime_file,
                root=root,
                relative="module/runtime.py",
            )
            self.assertEqual(record["size_bytes"], len(b"runtime"))

            outside = root.parent / "outside-runtime.py"
            outside.write_bytes(b"outside")
            try:
                self.assert_pipeline_error(
                    "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                    lambda: binary_pipeline._stable_runtime_file_record(
                        outside, root=root, relative="outside.py",
                    ),
                )
            finally:
                outside.unlink()
            self.assert_pipeline_error(
                "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                lambda: binary_pipeline._stable_runtime_file_record(
                    module, root=root, relative="module",
                ),
            )
            link = module / "link.py"
            try:
                link.symlink_to(runtime_file)
            except OSError:
                pass
            else:
                self.assert_pipeline_error(
                    "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                    lambda: binary_pipeline._stable_runtime_file_record(
                        link, root=root, relative="module/link.py",
                    ),
                )

            file_stat = runtime_file.stat()

            def observed(
                *, mode=stat.S_IFREG | 0o600, inode=file_stat.st_ino,
                size=len(b"runtime"), mtime=file_stat.st_mtime_ns,
            ):
                return SimpleNamespace(
                    st_dev=file_stat.st_dev,
                    st_ino=inode,
                    st_mode=mode,
                    st_size=size,
                    st_mtime_ns=mtime,
                )

            class RuntimePath:
                def __init__(self, stats, *, symlink=False):
                    self.stats = iter(stats)
                    self.symlink = symlink

                def absolute(self):
                    return self

                def resolve(self, *, strict=False):
                    return runtime_file

                def lstat(self):
                    return next(self.stats)

                def is_symlink(self):
                    return self.symlink

                def __str__(self):
                    return str(runtime_file)

            before = observed()

            def mocked_stable(
                path_value,
                *, opened=before, after=before, reads=(b"runtime", b""),
            ):
                with patch.object(
                    binary_pipeline.os, "open", return_value=7,
                ), patch.object(
                    binary_pipeline.os,
                    "fstat",
                    side_effect=[opened, after],
                ), patch.object(
                    binary_pipeline.os, "read", side_effect=list(reads),
                ), patch.object(binary_pipeline.os, "close"):
                    return binary_pipeline._stable_runtime_file_record(
                        path_value,
                        root=root,
                        relative="module/runtime.py",
                    )

            for opened in (
                observed(mode=stat.S_IFDIR | 0o700),
                observed(inode=file_stat.st_ino + 1),
            ):
                self.assert_pipeline_error(
                    "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                    lambda opened=opened: mocked_stable(
                        RuntimePath([before]), opened=opened,
                    ),
                )
            self.assert_pipeline_error(
                "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                lambda: mocked_stable(
                    RuntimePath([before, observed(inode=file_stat.st_ino + 1)]),
                ),
            )
            self.assert_pipeline_error(
                "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                lambda: mocked_stable(
                    RuntimePath([before, before]),
                    after=observed(size=len(b"runtime") + 1),
                ),
            )
            self.assert_pipeline_error(
                "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                lambda: mocked_stable(
                    RuntimePath([before, before]), reads=(b"short", b""),
                ),
            )

            class Distribution:
                def __init__(self, version="1", files=()):
                    self.version = version
                    self.files = files

                def locate_file(self, relative):
                    return root / str(relative)

            with patch.object(
                binary_pipeline.metadata,
                "distribution",
                side_effect=binary_pipeline.metadata.PackageNotFoundError(
                    "missing"
                ),
            ):
                self.assert_pipeline_error(
                    "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                    lambda: binary_pipeline._runtime_distribution_record(
                        "dist", "module", "1",
                    ),
                )
            for distribution in (
                Distribution(version="2", files=[]),
                Distribution(version="", files=[]),
                Distribution(version="1", files=None),
            ):
                with patch.object(
                    binary_pipeline.metadata,
                    "distribution",
                    return_value=distribution,
                ):
                    self.assert_pipeline_error(
                        "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                        lambda: binary_pipeline._runtime_distribution_record(
                            "dist", "module", "1",
                        ),
                    )
            with patch.object(
                binary_pipeline.metadata,
                "distribution",
                return_value=Distribution(files=[
                    "", "other/file.py", "module/__pycache__/cached.py",
                    "module/cached.pyc", "module/native.pyo",
                ]),
            ):
                self.assert_pipeline_error(
                    "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                    lambda: binary_pipeline._runtime_distribution_record(
                        "dist", "module", "1",
                    ),
                )
            with patch.object(
                binary_pipeline.metadata,
                "distribution",
                return_value=Distribution(files=["module/../escape.py"]),
            ):
                self.assert_pipeline_error(
                    "BINARY_GENERATION_RUNTIME_IDENTITY_UNAVAILABLE",
                    lambda: binary_pipeline._runtime_distribution_record(
                        "dist", "module", "1",
                    ),
                )
            with patch.object(
                binary_pipeline.metadata,
                "distribution",
                return_value=Distribution(files=["module/runtime.py"]),
            ), patch.object(
                binary_pipeline,
                "_stable_runtime_file_record",
                return_value=record,
            ):
                distribution_record = (
                    binary_pipeline._runtime_distribution_record(
                        "dist", "module", "1",
                    )
                )
            self.assertEqual(distribution_record["runtime_files"], [record])

    def test_resource_usage_snapshot_exhausts_platform_backends_and_units(self):
        with patch.object(binary_pipeline.sys, "platform", "darwin"):
            self.assertEqual(binary_pipeline._rss_bytes_from_rusage(12), 12)
            self.assertEqual(binary_pipeline._rss_bytes_from_rusage(None), 0)
        with patch.object(binary_pipeline.sys, "platform", "linux"):
            self.assertEqual(binary_pipeline._rss_bytes_from_rusage(12), 12288)

        with patch.object(binary_pipeline, "resource", None), patch.object(
            binary_pipeline,
            "windows_current_process_usage",
            side_effect=OSError("unavailable"),
        ):
            self.assertIsNone(binary_pipeline._resource_usage_snapshot())
        with patch.object(binary_pipeline, "resource", None), patch.object(
            binary_pipeline,
            "windows_current_process_usage",
            return_value=None,
        ):
            self.assertIsNone(binary_pipeline._resource_usage_snapshot())
        windows_usage = SimpleNamespace(
            user_seconds=1.0, system_seconds=2.0, peak_rss_bytes=3,
        )
        with patch.object(binary_pipeline, "resource", None), patch.object(
            binary_pipeline,
            "windows_current_process_usage",
            return_value=windows_usage,
        ):
            snapshot = binary_pipeline._resource_usage_snapshot()
        self.assertEqual(snapshot.self_peak_rss_bytes, 3)
        self.assertEqual(snapshot.child_user_seconds, 0.0)

        own = SimpleNamespace(
            ru_utime=1.0, ru_stime=2.0, ru_maxrss=3,
        )
        children = SimpleNamespace(
            ru_utime=0.0, ru_stime=0.0, ru_maxrss=0,
        )
        fake_resource = SimpleNamespace(
            RUSAGE_SELF=1,
            RUSAGE_CHILDREN=2,
            getrusage=lambda which: own if which == 1 else children,
        )
        with patch.object(
            binary_pipeline, "resource", fake_resource,
        ), patch.object(binary_pipeline.sys, "platform", "linux"):
            snapshot = binary_pipeline._resource_usage_snapshot()
        self.assertEqual(snapshot.self_user_seconds, 1.0)
        self.assertEqual(snapshot.child_user_seconds, 0.0)
        self.assertEqual(snapshot.self_peak_rss_bytes, 3072)
        own_zero = SimpleNamespace(
            ru_utime=0.0, ru_stime=0.0, ru_maxrss=0,
        )
        children_used = SimpleNamespace(
            ru_utime=3.0, ru_stime=4.0, ru_maxrss=5,
        )
        fake_resource = SimpleNamespace(
            RUSAGE_SELF=1,
            RUSAGE_CHILDREN=2,
            getrusage=lambda which: own_zero if which == 1 else children_used,
        )
        with patch.object(
            binary_pipeline, "resource", fake_resource,
        ), patch.object(binary_pipeline.sys, "platform", "linux"):
            snapshot = binary_pipeline._resource_usage_snapshot()
        self.assertEqual(snapshot.self_user_seconds, 0.0)
        self.assertEqual(snapshot.child_user_seconds, 3.0)
        self.assertEqual(snapshot.child_system_seconds, 4.0)

    def test_phase_timing_recorder_exhausts_resource_and_transition_states(self):
        usage_before = binary_pipeline._ResourceUsageSnapshot(
            self_user_seconds=5.0,
            self_system_seconds=4.0,
            child_user_seconds=3.0,
            child_system_seconds=2.0,
            self_peak_rss_bytes=100,
            completed_child_peak_rss_bytes=200,
        )
        usage_after = binary_pipeline._ResourceUsageSnapshot(
            self_user_seconds=7.0,
            self_system_seconds=6.0,
            child_user_seconds=5.0,
            child_system_seconds=4.0,
            self_peak_rss_bytes=300,
            completed_child_peak_rss_bytes=400,
        )
        with patch.object(
            binary_pipeline,
            "_non_authoritative_resource_usage_snapshot",
            return_value=None,
        ):
            recorder = binary_pipeline._PhaseTimingRecorder(
                Path("/unused"), 1.0, attempt_identity="attempt",
            )
            unavailable = recorder._with_resource_usage(None)
        self.assertEqual(unavailable["peak_rss_bytes"], 0)
        self.assertEqual(unavailable["average_cpu_cores"], 0.0)

        recorder._previous_usage = None
        with patch.object(
            binary_pipeline,
            "_non_authoritative_resource_usage_snapshot",
            return_value=usage_after,
        ):
            first = recorder._with_resource_usage({
                "peak_rss_bytes": 999,
                "elapsed_seconds": 2.0,
            })
        self.assertEqual(first["peak_rss_bytes"], 999)
        self.assertNotIn("self_cpu_seconds", first)

        recorder._previous_usage = usage_before
        with patch.object(
            binary_pipeline,
            "_non_authoritative_resource_usage_snapshot",
            return_value=usage_after,
        ):
            measured = recorder._with_resource_usage({"elapsed_seconds": 2.0})
        self.assertEqual(measured["self_cpu_seconds"], 4.0)
        self.assertEqual(measured["child_cpu_seconds"], 4.0)
        self.assertEqual(measured["process_tree_cpu_seconds"], 8.0)
        self.assertEqual(measured["average_cpu_cores"], 4.0)

        recorder._previous_usage = usage_after
        with patch.object(
            binary_pipeline,
            "_non_authoritative_resource_usage_snapshot",
            return_value=usage_before,
        ):
            zero_wall = recorder._with_resource_usage({"elapsed_seconds": 0})
        self.assertEqual(zero_wall["process_tree_cpu_seconds"], 0.0)
        self.assertEqual(zero_wall["average_cpu_cores"], 0.0)

        writes = []
        with patch.object(
            recorder,
            "_with_resource_usage",
            side_effect=lambda item: dict(item or {}),
        ), patch.object(
            binary_pipeline,
            "_write_non_authoritative_json",
            side_effect=lambda _path, payload: writes.append(payload) or True,
        ):
            recorder.start("")
            recorder.append({})
            recorder.append({"phase": "static_preflight"})
            recorder.append({"phase": recorder.ORDER[-1]})
            recorder.start("binary_trace", source="test")
            recorder.fail({})
            recorder.fail({"phase": "binary_trace"})
        self.assertEqual(writes[0]["last_completed_phase"], "")
        self.assertEqual(writes[0]["current_phase"], "unknown")
        self.assertEqual(writes[1]["current_phase"], "unknown")
        self.assertEqual(writes[2]["current_phase"], "input_and_runtime_profile")
        self.assertEqual(writes[3]["status"], "completed")
        self.assertEqual(writes[-2]["current_phase"], "unknown")
        self.assertEqual(writes[-1]["current_phase"], "binary_trace")

    def test_cleanup_notes_exhaust_native_fallback_and_failure_paths(self):
        native = RuntimeError("native")
        binary_pipeline._add_cleanup_note(native, "first")
        self.assertEqual(native.__notes__, ["first"])

        class RaisingAddNote(RuntimeError):
            def add_note(self, note):
                raise RuntimeError("native add_note unavailable")

        fallback = RaisingAddNote("fallback")
        fallback.__notes__ = ["existing"]
        binary_pipeline._add_cleanup_note(fallback, "second")
        self.assertEqual(fallback.__notes__, ["existing", "second"])

        class NoAddNote(RuntimeError):
            add_note = None

        no_native = NoAddNote("no-native")
        binary_pipeline._add_cleanup_note(no_native, "fallback")
        self.assertEqual(no_native.__notes__, ["fallback"])

        class RejectNotes(RuntimeError):
            add_note = None

            def __setattr__(self, name, value):
                if name == "__notes__":
                    raise RuntimeError("read-only")
                super().__setattr__(name, value)

        binary_pipeline._add_cleanup_note(RejectNotes("reject"), "ignored")

    def test_non_authoritative_json_exhausts_destination_and_backend_matrix(self):
        destination = Path("/private/output/binary_observability/progress.json")
        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=True,
        ), patch.object(
            binary_pipeline,
            "_write_bound_observability_text_posix",
        ) as writer:
            self.assertTrue(binary_pipeline._write_non_authoritative_json(
                destination, {"value": 1}, durable=True,
            ))
        writer.assert_called_once()

        for invalid in (
            Path("/private/output/progress.json"),
            Path("/private/output/binary_observability/.."),
        ):
            with self.subTest(invalid=str(invalid)):
                self.assertFalse(binary_pipeline._write_non_authoritative_json(
                    invalid, {"value": 1},
                ))
        self.assertFalse(binary_pipeline._write_non_authoritative_json(
            destination, {"value": float("nan")},
        ))

        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=False,
        ), patch.object(
            binary_pipeline, "os", SimpleNamespace(name="other"),
        ):
            self.assertFalse(binary_pipeline._write_non_authoritative_json(
                destination, {"value": 1},
            ))

        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=False,
        ), patch.object(
            binary_pipeline, "os", SimpleNamespace(name="nt"),
        ), patch.object(
            binary_pipeline,
            "_physical_observability_directory",
            return_value=destination.parent,
        ), patch.object(
            binary_pipeline,
            "_write_observability_text_windows_compat",
        ) as windows_writer:
            self.assertTrue(binary_pipeline._write_non_authoritative_json(
                destination, {"value": 1},
            ))
        windows_writer.assert_called_once()

    def test_small_identity_and_preflight_helpers_exhaust_boolean_boundaries(self):
        self.assertTrue(binary_pipeline._is_sha256_identity("a" * 64))
        for value in (None, 1, "", "g" * 64):
            self.assertFalse(binary_pipeline._is_sha256_identity(value))

        imports = binary_pipeline._local_python_imports_from_exact_bytes(
            "imports.py",
            b"import os.path\nfrom json import loads\nfrom . import sibling\n",
        )
        self.assertEqual(imports, frozenset({"os", "json"}))

        for value in (True, 1.5, "1", 0, -1):
            with self.subTest(limit=value):
                self.assert_pipeline_error(
                    "BINARY_PIPELINE_TRACE_LIMIT_INVALID",
                    lambda value=value: binary_pipeline._positive_pipeline_limit(
                        {"limit": value}, "limit", 10,
                    ),
                )
        self.assertEqual(
            binary_pipeline._positive_pipeline_limit({"limit": 1}, "limit", 10),
            1,
        )
        self.assertEqual(
            binary_pipeline._positive_pipeline_limit({}, "limit", 10), 10,
        )

        invalid_comparisons = (
            [],
            {"comparison_intent": "unsupported"},
            {"controlled_profile_fields": "not-a-list"},
            {"declared_upgrade_payload_scope": {}},
            {"changed_or_unknown_profile_fields": 1},
        )
        for comparison in invalid_comparisons:
            with self.subTest(comparison=comparison), patch.object(
                binary_pipeline,
                "validate_oracle_tool_execution_policy",
            ), patch.object(
                binary_pipeline,
                "_validate_static_source_overlay",
            ), patch.object(
                binary_pipeline,
                "_validate_static_artifact_inputs",
            ), patch.object(
                binary_pipeline,
                "_validate_static_runtime_profile_inputs",
            ), patch.object(
                binary_pipeline,
                "_validate_static_build_identity_inputs",
            ):
                with self.assertRaises(binary_pipeline.BinaryPipelineError):
                    binary_pipeline._static_pipeline_preflight({
                        "runtime_comparison": comparison,
                    })

        for invalid in (Path("."), Path(".."), Path("/")):
            self.assert_pipeline_error(
                "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
                lambda invalid=invalid: (
                    binary_pipeline._canonical_output_root_preserving_leaf(
                        invalid
                    )
                ),
            )

        captured = []
        with patch.object(
            binary_pipeline,
            "_write_non_authoritative_json",
            side_effect=lambda _path, payload: captured.append(payload) or True,
        ):
            binary_pipeline._record_resume_decision(
                Path("/unused"), status="rejected", reason_code="reason",
                checkpoint={},
            )
            binary_pipeline._record_resume_decision(
                Path("/unused"), status="resumed", reason_code="",
                checkpoint={"result_generation_identity": "a" * 64},
            )
        self.assertEqual(captured[0]["result_generation_identity"], "")
        self.assertEqual(captured[1]["result_generation_identity"], "a" * 64)

        self.assert_pipeline_error(
            "BINARY_PERFORMANCE_AUTHORITY_BINDING_INVALID",
            lambda: binary_pipeline._activation_publication_guard_value(
                Path("/unused"), {}, {}, activation_identity="",
                captured_binding={},
            ),
        )

    def test_checkpoint_platform_feature_detection_and_reparse_matrix(self):
        required_dir_fd = {
            binary_pipeline.os.open,
            binary_pipeline.os.mkdir,
            binary_pipeline.os.stat,
            binary_pipeline.os.unlink,
            binary_pipeline.os.rename,
        }
        def feature_os(
            *, name="posix", directory=1, nofollow=1,
            dir_fd=required_dir_fd, follow={binary_pipeline.os.stat},
        ):
            return SimpleNamespace(
                name=name,
                O_DIRECTORY=directory,
                O_NOFOLLOW=nofollow,
                open=binary_pipeline.os.open,
                mkdir=binary_pipeline.os.mkdir,
                stat=binary_pipeline.os.stat,
                unlink=binary_pipeline.os.unlink,
                rename=binary_pipeline.os.rename,
                supports_dir_fd=dir_fd,
                supports_follow_symlinks=follow,
            )

        with patch.object(binary_pipeline, "os", feature_os(name="nt")):
            self.assertFalse(
                binary_pipeline._secure_resume_checkpoint_dirfd_supported()
            )
        with patch.object(binary_pipeline, "os", feature_os(directory=0)):
            self.assertFalse(
                binary_pipeline._secure_resume_checkpoint_dirfd_supported()
            )
        with patch.object(binary_pipeline, "os", feature_os(nofollow=0)):
            self.assertFalse(
                binary_pipeline._secure_resume_checkpoint_dirfd_supported()
            )
        with patch.object(binary_pipeline, "os", feature_os(dir_fd=set())):
            self.assertFalse(
                binary_pipeline._secure_resume_checkpoint_dirfd_supported()
            )
        with patch.object(binary_pipeline, "os", feature_os(follow=set())):
            self.assertFalse(
                binary_pipeline._secure_resume_checkpoint_dirfd_supported()
            )
        with patch.object(binary_pipeline, "os", feature_os()):
            self.assertTrue(
                binary_pipeline._secure_resume_checkpoint_dirfd_supported()
            )

        regular = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0)
        symbolic = SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
        self.assertTrue(binary_pipeline._checkpoint_directory_is_reparse_point(
            Path("symbolic"), symbolic,
        ))
        with patch.object(
            binary_pipeline.stat,
            "FILE_ATTRIBUTE_REPARSE_POINT",
            0x400,
            create=True,
        ):
            reparse = SimpleNamespace(
                st_mode=stat.S_IFDIR, st_file_attributes=0x400,
            )
            self.assertTrue(
                binary_pipeline._checkpoint_directory_is_reparse_point(
                    Path("reparse"), reparse,
                )
            )
            self.assertTrue(
                binary_pipeline._checkpoint_directory_is_reparse_point(
                    SimpleNamespace(is_junction=lambda: True), regular,
                )
            )
            self.assertFalse(
                binary_pipeline._checkpoint_directory_is_reparse_point(
                    SimpleNamespace(is_junction=None), regular,
                )
            )

        for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_BINARY"):
            with self.subTest(flag=name), patch.object(
                binary_pipeline.os, name, 0, create=True,
            ):
                self.assertIsInstance(
                    binary_pipeline._checkpoint_directory_open_flags(), int,
                )

    def test_physical_observability_directory_exhausts_leaf_storage_matrix(self):
        for invalid in (Path("."), Path(".."), Path("/")):
            self.assert_pipeline_error(
                "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
                lambda invalid=invalid: (
                    binary_pipeline._physical_observability_directory(
                        invalid, create=False,
                    )
                ),
            )

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            missing = parent / "missing-output"
            self.assert_pipeline_error(
                "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
                lambda: binary_pipeline._physical_observability_directory(
                    missing, create=False,
                ),
            )
            observability = (
                binary_pipeline._physical_observability_directory(
                    missing, create=True,
                )
            )
            self.assertEqual(observability, missing / "binary_observability")
            self.assertTrue(observability.is_dir())
            self.assertEqual(
                binary_pipeline._physical_observability_directory(
                    missing, create=True,
                ),
                observability,
            )

            file_root = parent / "file-output"
            file_root.write_bytes(b"file")
            self.assert_pipeline_error(
                "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
                lambda: binary_pipeline._physical_observability_directory(
                    file_root, create=True,
                ),
            )

            bad_child_root = parent / "bad-child-output"
            bad_child_root.mkdir()
            (bad_child_root / "binary_observability").write_bytes(b"file")
            self.assert_pipeline_error(
                "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
                lambda: binary_pipeline._physical_observability_directory(
                    bad_child_root, create=True,
                ),
            )

            symlink_root = parent / "symlink-output"
            try:
                symlink_root.symlink_to(missing, target_is_directory=True)
            except OSError:
                pass
            else:
                self.assert_pipeline_error(
                    "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
                    lambda: binary_pipeline._physical_observability_directory(
                        symlink_root, create=True,
                    ),
                )

            child_link_root = parent / "child-link-output"
            child_link_root.mkdir()
            try:
                (child_link_root / "binary_observability").symlink_to(
                    observability, target_is_directory=True,
                )
            except OSError:
                pass
            else:
                self.assert_pipeline_error(
                    "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
                    lambda: binary_pipeline._physical_observability_directory(
                        child_link_root, create=True,
                    ),
                )

    def test_bound_checkpoint_directories_exhaust_creation_and_rejection_matrix(self):
        def close_binding(binding):
            if binding is not None:
                binary_pipeline._attempt_cleanups(
                    binary_pipeline._checkpoint_binding_close_actions(binding),
                    primary=None,
                )

        with self.assertRaises(OSError):
            binary_pipeline._open_bound_checkpoint_directories(
                Path(".."), create=False,
            )

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            missing = parent / "missing"
            self.assertIsNone(
                binary_pipeline._open_bound_checkpoint_directories(
                    missing, create=False,
                )
            )
            binding = binary_pipeline._open_bound_checkpoint_directories(
                missing, create=True,
            )
            try:
                self.assertTrue(binding.root_created)
                self.assertTrue(binding.observability_created)
            finally:
                close_binding(binding)

            binding = binary_pipeline._open_bound_checkpoint_directories(
                missing, create=True,
            )
            try:
                self.assertFalse(binding.root_created)
                self.assertFalse(binding.observability_created)
            finally:
                close_binding(binding)

            root_only = parent / "root-only"
            root_only.mkdir()
            self.assertIsNone(
                binary_pipeline._open_bound_checkpoint_directories(
                    root_only, create=False,
                )
            )

            file_root = parent / "file-root"
            file_root.write_bytes(b"file")
            with self.assertRaises(
                binary_pipeline._CheckpointObservabilityStorageError
            ):
                binary_pipeline._open_bound_checkpoint_directories(
                    file_root, create=True,
                )

            file_child_root = parent / "file-child-root"
            file_child_root.mkdir()
            (file_child_root / "binary_observability").write_bytes(b"file")
            with self.assertRaises(
                binary_pipeline._CheckpointObservabilityStorageError
            ):
                binary_pipeline._open_bound_checkpoint_directories(
                    file_child_root, create=True,
                )

        preserved = binary_pipeline._CheckpointObservabilityStorageError(
            "already classified"
        )
        with patch.object(
            binary_pipeline,
            "_validated_checkpoint_directory_stat",
            side_effect=preserved,
        ):
            with self.assertRaises(
                binary_pipeline._CheckpointObservabilityStorageError
            ) as caught:
                binary_pipeline._open_bound_checkpoint_directories(
                    Path("/private/output"), create=True,
                )
        self.assertIs(caught.exception, preserved)

        with patch.object(
            binary_pipeline,
            "_validated_checkpoint_directory_stat",
            side_effect=RuntimeError("unexpected"),
        ):
            with self.assertRaisesRegex(RuntimeError, "unexpected"):
                binary_pipeline._open_bound_checkpoint_directories(
                    Path("/private/output"), create=True,
                )

    def test_checkpoint_directory_binding_exhausts_descriptor_identity_matrix(self):
        def observed(inode, *, mode=stat.S_IFDIR | 0o700):
            return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode)

        expected = observed(1)
        current = observed(1)
        with patch.object(
            binary_pipeline,
            "_validated_checkpoint_directory_stat",
            return_value=current,
        ):
            binary_pipeline._verify_checkpoint_directory_binding(
                Path("/bound"), expected,
            )
        with patch.object(
            binary_pipeline,
            "_validated_checkpoint_directory_stat",
            return_value=observed(2),
        ):
            with self.assertRaises(OSError):
                binary_pipeline._verify_checkpoint_directory_binding(
                    Path("/changed"), expected,
                )
        for opened in (
            observed(1, mode=stat.S_IFREG | 0o600),
            observed(2),
            observed(1),
        ):
            with self.subTest(opened=opened), patch.object(
                binary_pipeline,
                "_validated_checkpoint_directory_stat",
                return_value=current,
            ), patch.object(binary_pipeline.os, "fstat", return_value=opened):
                if opened.st_ino == 1 and stat.S_ISDIR(opened.st_mode):
                    binary_pipeline._verify_checkpoint_directory_binding(
                        Path("/bound"), expected, descriptor=7,
                    )
                else:
                    with self.assertRaises(OSError):
                        binary_pipeline._verify_checkpoint_directory_binding(
                            Path("/bound"), expected, descriptor=7,
                        )

        with patch.object(
            binary_pipeline.os, "lstat", return_value=observed(1),
        ), patch.object(
            binary_pipeline,
            "_checkpoint_directory_is_reparse_point",
            return_value=False,
        ):
            self.assertEqual(
                binary_pipeline._validated_checkpoint_directory_stat(
                    Path("/directory")
                ).st_ino,
                1,
            )
        for directory_stat, reparse in (
            (observed(1, mode=stat.S_IFREG), False),
            (observed(1), True),
        ):
            with patch.object(
                binary_pipeline.os, "lstat", return_value=directory_stat,
            ), patch.object(
                binary_pipeline,
                "_checkpoint_directory_is_reparse_point",
                return_value=reparse,
            ):
                with self.assertRaises(OSError):
                    binary_pipeline._validated_checkpoint_directory_stat(
                        Path("/invalid")
                    )

        samestat = os.path.samestat

        def open_at(opened, current_value, expected_value=expected):
            closed = []
            fake_os = SimpleNamespace(
                open=lambda *_args, **_kwargs: 17,
                fstat=lambda _fd: opened,
                stat=lambda *_args, **_kwargs: current_value,
                close=lambda fd: closed.append(fd),
                path=SimpleNamespace(samestat=samestat),
            )
            with patch.object(binary_pipeline, "os", fake_os), patch.object(
                binary_pipeline, "_checkpoint_directory_open_flags",
                return_value=0,
            ):
                try:
                    result = binary_pipeline._open_checkpoint_directory_at(
                        3, "child", Path("/child"), expected_value,
                    )
                except OSError:
                    return None, closed
                return result, closed

        for opened, current_value in (
            (observed(1, mode=stat.S_IFREG), observed(1)),
            (observed(1), observed(1, mode=stat.S_IFREG)),
            (observed(2), observed(1)),
            (observed(1), observed(2)),
        ):
            result, closed = open_at(opened, current_value)
            self.assertIsNone(result)
            self.assertEqual(closed, [17])
        result, closed = open_at(observed(1), observed(1))
        self.assertEqual(result, 17)
        self.assertEqual(closed, [])

    def test_checkpoint_tree_binding_exhausts_each_replacement_boundary(self):
        def observed(inode, *, mode=stat.S_IFDIR | 0o700):
            return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode)

        expected_root = observed(1)
        expected_observability = observed(2)
        binding = SimpleNamespace(
            canonical_parent=Path("/parent"),
            parent_expected=observed(0),
            parent_fd=10,
            root_name="output",
            root_fd=11,
            root_expected=expected_root,
            observability_name="binary_observability",
            observability_fd=12,
            observability_expected=expected_observability,
        )
        samestat = os.path.samestat

        def verify(current_root, opened_root, current_obs, opened_obs):
            stat_values = iter((current_root, current_obs))
            fstat_values = iter((opened_root, opened_obs))
            fake_os = SimpleNamespace(
                stat=lambda *_args, **_kwargs: next(stat_values),
                fstat=lambda _fd: next(fstat_values),
                path=SimpleNamespace(samestat=samestat),
            )
            with patch.object(binary_pipeline, "os", fake_os), patch.object(
                binary_pipeline, "_verify_checkpoint_directory_binding",
            ):
                binary_pipeline._verify_checkpoint_directory_tree_binding(binding)

        failures = (
            (observed(1, mode=stat.S_IFREG), observed(1), observed(2), observed(2)),
            (observed(3), observed(1), observed(2), observed(2)),
            (observed(1), observed(3), observed(2), observed(2)),
            (observed(1), observed(1), observed(2, mode=stat.S_IFREG), observed(2)),
            (observed(1), observed(1), observed(3), observed(2)),
            (observed(1), observed(1), observed(2), observed(3)),
        )
        for values in failures:
            with self.subTest(values=values), self.assertRaises(OSError):
                verify(*values)
        verify(observed(1), observed(1), observed(2), observed(2))

    def test_bound_observability_write_exhausts_atomic_publication_matrix(self):
        with patch.object(
            binary_pipeline,
            "_open_bound_checkpoint_directories",
            return_value=None,
        ):
            with self.assertRaises(OSError):
                binary_pipeline._write_bound_observability_text_posix(
                    Path("/unused"), "progress.json", "{}\n", durable=False,
                )

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            first_root = parent / "first"
            destination = binary_pipeline._write_bound_observability_text_posix(
                first_root, "progress.json", "first\n", durable=False,
            )
            self.assertEqual(destination.read_text(), "first\n")
            self.assertEqual(
                binary_pipeline._write_bound_observability_text_posix(
                    first_root, "progress.json", "second\n", durable=True,
                ).read_text(),
                "second\n",
            )

            created_durable = parent / "created-durable"
            binary_pipeline._write_bound_observability_text_posix(
                created_durable, "progress.json", "durable\n", durable=True,
            )

            invalid_destination_root = parent / "invalid-destination"
            invalid_observability = (
                invalid_destination_root / "binary_observability"
            )
            invalid_observability.mkdir(parents=True)
            (invalid_observability / "progress.json").mkdir()
            with self.assertRaises(OSError):
                binary_pipeline._write_bound_observability_text_posix(
                    invalid_destination_root,
                    "progress.json",
                    "invalid\n",
                    durable=False,
                )

            temporary_invalid_root = parent / "temporary-invalid"
            with patch.object(
                binary_pipeline,
                "_private_regular_checkpoint_stat",
                return_value=False,
            ):
                with self.assertRaises(OSError):
                    binary_pipeline._write_bound_observability_text_posix(
                        temporary_invalid_root,
                        "progress.json",
                        "invalid\n",
                        durable=False,
                    )
            self.assertEqual(
                list((temporary_invalid_root / "binary_observability").iterdir()),
                [],
            )

            fdopen_failure_root = parent / "fdopen-failure"
            with patch.object(
                binary_pipeline.os,
                "fdopen",
                side_effect=OSError("fdopen failed"),
            ):
                with self.assertRaises(OSError):
                    binary_pipeline._write_bound_observability_text_posix(
                        fdopen_failure_root,
                        "progress.json",
                        "failure\n",
                        durable=False,
                    )
            self.assertEqual(
                list((fdopen_failure_root / "binary_observability").iterdir()),
                [],
            )

            for flag in ("O_NOFOLLOW", "O_CLOEXEC", "O_BINARY"):
                flag_root = parent / f"zero-{flag.lower()}"
                with self.subTest(flag=flag), patch.object(
                    binary_pipeline.os, flag, 0, create=True,
                ):
                    binary_pipeline._write_bound_observability_text_posix(
                        flag_root,
                        "progress.json",
                        "zero-flag\n",
                        durable=False,
                    )

    def test_windows_observability_write_exhausts_durability_and_type_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            destination = parent / "progress.json"
            self.assertEqual(
                binary_pipeline._write_observability_text_windows_compat(
                    destination, "first\n", durable=False,
                ),
                destination,
            )
            self.assertEqual(destination.read_text(), "first\n")
            self.assertEqual(
                binary_pipeline._write_observability_text_windows_compat(
                    destination, "second\n", durable=True,
                ),
                destination,
            )
            self.assertEqual(destination.read_text(), "second\n")

            invalid = parent / "invalid.json"
            invalid.mkdir()
            with self.assertRaises(OSError):
                binary_pipeline._write_observability_text_windows_compat(
                    invalid, "invalid\n", durable=False,
                )

            with patch.object(
                binary_pipeline,
                "_verify_checkpoint_directory_binding",
                side_effect=[None, OSError("parent replaced"), None],
            ):
                with self.assertRaisesRegex(OSError, "parent replaced"):
                    binary_pipeline._write_observability_text_windows_compat(
                        parent / "replaced.json", "content\n", durable=False,
                    )

    def test_checkpoint_delete_exhausts_posix_and_windows_transactions(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            missing_root = parent / "missing"
            self.assertFalse(
                binary_pipeline._delete_resume_checkpoint_posix(missing_root)
            )

            no_checkpoint = parent / "no-checkpoint"
            (no_checkpoint / "binary_observability").mkdir(parents=True)
            self.assertFalse(
                binary_pipeline._delete_resume_checkpoint_posix(no_checkpoint)
            )

            valid_root = parent / "valid"
            valid_observability = valid_root / "binary_observability"
            valid_observability.mkdir(parents=True)
            valid_checkpoint = (
                valid_observability / binary_pipeline._RESUME_CHECKPOINT_NAME
            )
            valid_checkpoint.write_bytes(b"{}\n")
            valid_checkpoint.chmod(0o600)
            self.assertTrue(
                binary_pipeline._delete_resume_checkpoint_posix(valid_root)
            )
            self.assertFalse(valid_checkpoint.exists())

            invalid_root = parent / "invalid"
            invalid_observability = invalid_root / "binary_observability"
            invalid_observability.mkdir(parents=True)
            invalid_checkpoint = (
                invalid_observability / binary_pipeline._RESUME_CHECKPOINT_NAME
            )
            invalid_checkpoint.mkdir()
            with self.assertRaises(OSError):
                binary_pipeline._delete_resume_checkpoint_posix(invalid_root)

            fsync_root = parent / "fsync-failure"
            fsync_observability = fsync_root / "binary_observability"
            fsync_observability.mkdir(parents=True)
            fsync_checkpoint = (
                fsync_observability / binary_pipeline._RESUME_CHECKPOINT_NAME
            )
            fsync_checkpoint.write_bytes(b"{}\n")
            fsync_checkpoint.chmod(0o600)
            with patch.object(
                binary_pipeline.os,
                "fsync",
                side_effect=OSError("directory fsync failed"),
            ):
                with self.assertRaises(
                    binary_pipeline._ResumeCheckpointDirectoryFsyncError
                ):
                    binary_pipeline._delete_resume_checkpoint_posix(fsync_root)

            windows_missing = parent / "windows-missing.json"
            self.assertFalse(
                binary_pipeline._delete_resume_checkpoint_windows_compat(
                    windows_missing
                )
            )
            windows_invalid = parent / "windows-invalid.json"
            windows_invalid.mkdir()
            with self.assertRaises(OSError):
                binary_pipeline._delete_resume_checkpoint_windows_compat(
                    windows_invalid
                )
            windows_valid = parent / "windows-valid.json"
            windows_valid.write_bytes(b"{}\n")
            windows_valid.chmod(0o600)
            self.assertTrue(
                binary_pipeline._delete_resume_checkpoint_windows_compat(
                    windows_valid
                )
            )
            windows_fsync = parent / "windows-fsync.json"
            windows_fsync.write_bytes(b"{}\n")
            windows_fsync.chmod(0o600)
            with patch.object(
                binary_pipeline,
                "fsync_directory",
                side_effect=OSError("directory fsync failed"),
            ):
                with self.assertRaises(
                    binary_pipeline._ResumeCheckpointDirectoryFsyncError
                ):
                    binary_pipeline._delete_resume_checkpoint_windows_compat(
                        windows_fsync
                    )

    def test_checkpoint_dispatch_exhausts_supported_and_unavailable_backends(self):
        output = Path("/private/output")
        payload = {"schema": binary_pipeline.RESUME_CHECKPOINT_SCHEMA}
        posix_path = Path("/private/output/posix.json")
        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=True,
        ), patch.object(
            binary_pipeline,
            "_write_resume_checkpoint_posix",
            return_value=posix_path,
        ):
            self.assertEqual(
                binary_pipeline._write_resume_checkpoint(output, payload),
                posix_path,
            )

        windows_directory = output / "binary_observability"
        windows_path = windows_directory / binary_pipeline._RESUME_CHECKPOINT_NAME
        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=False,
        ), patch.object(
            binary_pipeline, "os", SimpleNamespace(name="nt"),
        ), patch.object(
            binary_pipeline,
            "_physical_observability_directory",
            return_value=windows_directory,
        ), patch.object(
            binary_pipeline,
            "_write_resume_checkpoint_windows_compat",
            return_value=windows_path,
        ):
            self.assertEqual(
                binary_pipeline._write_resume_checkpoint(output, payload),
                windows_path,
            )

        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=False,
        ), patch.object(
            binary_pipeline, "os", SimpleNamespace(name="other"),
        ):
            self.assert_pipeline_error(
                "BINARY_RESUME_CHECKPOINT_WRITE_FAILED",
                lambda: binary_pipeline._write_resume_checkpoint(output, payload),
            )

        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=True,
        ), patch.object(
            binary_pipeline,
            "_delete_resume_checkpoint_posix",
            return_value=True,
        ):
            self.assertTrue(
                binary_pipeline._delete_resume_checkpoint_durable(output)
            )

        windows_os_missing = SimpleNamespace(
            name="nt",
            lstat=lambda _path: (_ for _ in ()).throw(FileNotFoundError()),
        )
        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=False,
        ), patch.object(binary_pipeline, "os", windows_os_missing):
            self.assertFalse(
                binary_pipeline._delete_resume_checkpoint_durable(output)
            )

        with patch.object(
            binary_pipeline,
            "_secure_resume_checkpoint_dirfd_supported",
            return_value=False,
        ), patch.object(
            binary_pipeline, "os", SimpleNamespace(name="other"),
        ):
            self.assert_pipeline_error(
                "BINARY_RESUME_CHECKPOINT_UNLINK_FAILED",
                lambda: binary_pipeline._delete_resume_checkpoint_durable(output),
            )

    def test_remaining_observability_branches_cover_existing_and_raced_entries(self):
        with patch.object(
            binary_pipeline,
            "_non_authoritative_resource_usage_snapshot",
            return_value=None,
        ), patch.object(binary_pipeline.os, "urandom", return_value=b"x" * 32):
            generated_attempt = binary_pipeline._PhaseTimingRecorder(
                Path("/unused"), 0.0, attempt_identity="",
            )
        self.assertRegex(generated_attempt.attempt_identity, r"^[0-9a-f]{64}$")
        with patch.object(
            binary_pipeline,
            "_write_non_authoritative_json",
            return_value=False,
        ):
            generated_attempt._write_progress(
                status="running",
                last_completed_phase="",
                current_phase="unknown",
            )
        self.assertEqual(generated_attempt.write_failure_count, 1)

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            physical_root = parent / "physical-existing"
            (physical_root / "binary_observability").mkdir(parents=True)
            self.assertEqual(
                binary_pipeline._physical_observability_directory(
                    physical_root, create=False,
                ),
                physical_root / "binary_observability",
            )

            root_reparse = parent / "root-reparse"
            root_reparse.mkdir()

            def root_only_reparse(path, observed):
                if Path(path) == root_reparse:
                    return True
                return binary_pipeline.stat.S_ISLNK(observed.st_mode)

            with patch.object(
                binary_pipeline,
                "_checkpoint_directory_is_reparse_point",
                new=root_only_reparse,
            ):
                with self.assertRaises(
                    binary_pipeline._CheckpointObservabilityStorageError
                ):
                    binary_pipeline._open_bound_checkpoint_directories(
                        root_reparse, create=True,
                    )

            observability_reparse = parent / "observability-reparse"
            (observability_reparse / "binary_observability").mkdir(
                parents=True
            )
            real_reparse = binary_pipeline._checkpoint_directory_is_reparse_point

            def child_only_reparse(path, observed):
                if Path(path).name == "binary_observability":
                    return True
                return real_reparse(path, observed)

            with patch.object(
                binary_pipeline,
                "_checkpoint_directory_is_reparse_point",
                new=child_only_reparse,
            ):
                with self.assertRaises(
                    binary_pipeline._CheckpointObservabilityStorageError
                ):
                    binary_pipeline._open_bound_checkpoint_directories(
                        observability_reparse, create=True,
                    )

            binary_flag_root = parent / "binary-flag"
            with patch.object(
                binary_pipeline.os,
                "O_BINARY",
                binary_pipeline.os.O_CLOEXEC,
                create=True,
            ):
                binary_pipeline._checkpoint_directory_open_flags()
                binary_pipeline._write_bound_observability_text_posix(
                    binary_flag_root,
                    "progress.json",
                    "binary-flag\n",
                    durable=False,
                )

            replacement_root = parent / "replacement"
            original_samestat = os.path.samestat
            with patch.object(
                binary_pipeline.os.path,
                "samestat",
                side_effect=lambda left, right: (
                    False
                    if stat.S_ISREG(left.st_mode)
                    and stat.S_ISREG(right.st_mode)
                    else original_samestat(left, right)
                ),
            ):
                with self.assertRaises(OSError):
                    binary_pipeline._write_bound_observability_text_posix(
                        replacement_root,
                        "progress.json",
                        "replacement\n",
                        durable=False,
                    )

    def test_pipeline_entry_exhausts_authority_jdk_and_resume_decision_matrix(self):
        class StopAfterEarlyPhases(RuntimeError):
            pass

        class EarlyTimings(list):
            def start(self, phase, **metadata):
                self.last_start = (phase, metadata)

            def fail(self, item):
                self.last_failure = dict(item)

        base_config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {"jdk_home": "/jdk/base"},
            "current": {"jdk_home": "/jdk/current"},
        }

        def invoke(
            config=None,
            *,
            authority_mode="analysis_result",
            retain=False,
            recapture=False,
            recapture_root=None,
            resume_result=None,
            preflight=None,
            output=Path("/private/test-output"),
            pruned=None,
        ):
            actual_config = deepcopy(base_config if config is None else config)
            calls = [] if pruned is None else pruned
            binding = (
                None
                if authority_mode == "analysis_result"
                else {"authority_mode": authority_mode}
            )
            preflight_impl = preflight or (
                lambda home: {
                    "jdk_preflight_identity": f"identity:{home}",
                    "java_major": 17,
                }
            )
            recapture_value = (
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
                if recapture else None
            )
            with patch.multiple(
                binary_pipeline,
                _verify_captured_generation_sources=lambda: [],
                _preflight_output_root=lambda _root: None,
                _PhaseTimingRecorder=lambda *_args, **_kwargs: EarlyTimings(),
                _static_pipeline_preflight=lambda *_args, **_kwargs: {
                    "performance_authority_gate_binding": binding,
                },
                _source_inputs_contract=lambda _config: {},
                preflight_jdk_home=preflight_impl,
                _validate_multi_release_runtime_contract=(
                    lambda *_args, **_kwargs: None
                ),
                resolve_asm_jar=lambda _path: Path("/asm.jar"),
                _resume_implementation_identity=(
                    lambda *_args, **_kwargs: "implementation"
                ),
                _resume_generation_validation=(
                    lambda *_args, **_kwargs: resume_result
                ),
                _delete_resume_checkpoint_durable=lambda _root: False,
                _prune_unreferenced_generations_best_effort=(
                    lambda _root, **_kwargs: calls.append(Path(_root)) or {}
                ),
                JdkPlatformImage=(
                    lambda *_args, **_kwargs: (_ for _ in ()).throw(
                        StopAfterEarlyPhases()
                    )
                ),
                _PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT=SimpleNamespace(
                    get=lambda: None
                ),
                _PERFORMANCE_RELEASE_RECAPTURE_CONTEXT=SimpleNamespace(
                    get=lambda: recapture_value
                ),
                _PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT=SimpleNamespace(
                    get=lambda: recapture_root
                ),
            ):
                result = binary_pipeline._run_pipeline_under_lock(
                    actual_config,
                    output_root=output,
                    retain_validation_checkpoint=retain,
                )
            return result, calls

        self.assert_pipeline_error(
            "BINARY_PIPELINE_CONFIG_SCHEMA_INVALID",
            lambda: binary_pipeline._run_pipeline_under_lock(
                {}, output_root=Path("/unused"),
            ),
        )

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            private_root = parent / "private-recapture"
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_RECAPTURE_ROOT_NOT_PRIVATE",
                lambda: invoke(
                    recapture=True,
                    recapture_root=None,
                    output=private_root,
                ),
            )
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_RECAPTURE_ROOT_NOT_PRIVATE",
                lambda: invoke(
                    recapture=True,
                    recapture_root=parent / "different",
                    output=private_root,
                ),
            )
            private_root.mkdir()
            (private_root / "unexpected").write_bytes(b"occupied")
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_RECAPTURE_ROOT_NOT_PRIVATE",
                lambda: invoke(
                    recapture=True,
                    recapture_root=private_root,
                    output=private_root,
                ),
            )
            private_root.joinpath("unexpected").unlink()
            private_root.joinpath(".binary-pipeline-run.lock").write_bytes(b"")
            with self.assertRaises(StopAfterEarlyPhases):
                invoke(
                    recapture=True,
                    recapture_root=private_root,
                    output=private_root,
                )

        self.assert_pipeline_error(
            "BINARY_PERFORMANCE_CANDIDATE_ACTIVATION_FORBIDDEN",
            lambda: invoke(
                authority_mode=(
                    binary_pipeline._PERFORMANCE_CANDIDATE_AUTHORITY_MODE
                ),
                retain=False,
            ),
        )
        self.assert_pipeline_error(
            "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
            lambda: invoke(
                authority_mode=(
                    binary_pipeline._PERFORMANCE_RECAPTURE_AUTHORITY_MODE
                ),
                recapture=False,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            recapture_root = Path(temporary).resolve() / "recapture"
            self.assert_pipeline_error(
                "BINARY_PERFORMANCE_RECAPTURE_ACTIVATION_FORBIDDEN",
                lambda: invoke(
                    authority_mode=(
                        binary_pipeline._PERFORMANCE_RECAPTURE_AUTHORITY_MODE
                    ),
                    retain=True,
                    recapture=True,
                    recapture_root=recapture_root,
                    output=recapture_root,
                ),
            )

        jdk_error = binary_pipeline.JdkPreflightError(
            "JDK_INVALID", "invalid JDK", diagnostic={"probe": "failed"},
        )
        self.assert_pipeline_error(
            "BINARY_JDK_PREFLIGHT_FAILED",
            lambda: invoke(preflight=lambda _home: (_ for _ in ()).throw(jdk_error)),
        )

        mismatch = deepcopy(base_config)
        mismatch["base"]["jdk_preflight_identity"] = "stale"
        self.assert_pipeline_error(
            "BINARY_JDK_CHANGED_SINCE_STEP0",
            lambda: invoke(mismatch),
        )

        invalid_profile = deepcopy(base_config)
        invalid_profile["base"]["runtime_profile"] = []
        self.assert_pipeline_error(
            "BINARY_RUNTIME_PROFILE_CONFIG_INVALID",
            lambda: invoke(invalid_profile),
        )

        invalid_target = deepcopy(base_config)
        invalid_target["base"]["runtime_profile"] = {"target_jvm": []}
        self.assert_pipeline_error(
            "BINARY_PIPELINE_TARGET_JVM_MISMATCH",
            lambda: invoke(invalid_target),
        )
        for major in ("invalid", {}, 8):
            target = deepcopy(base_config)
            target["base"]["runtime_profile"] = {
                "target_jvm": {"major": major},
            }
            with self.subTest(target_major=major):
                self.assert_pipeline_error(
                    "BINARY_PIPELINE_TARGET_JVM_MISMATCH",
                    lambda target=target: invoke(target),
                )

        valid_target = deepcopy(base_config)
        valid_target["base"]["runtime_profile"] = {
            "target_jvm": {"major": 17},
        }
        with self.assertRaises(StopAfterEarlyPhases):
            invoke(valid_target)

        configured_paths = deepcopy(base_config)
        configured_paths["cache_root"] = "/configured/cache"
        configured_paths["asm_jar"] = "/configured/asm.jar"
        with self.assertRaises(StopAfterEarlyPhases):
            invoke(configured_paths)

        empty_sides = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "base": {},
            "current": {},
        }
        with self.assertRaises(StopAfterEarlyPhases):
            invoke(empty_sides)

        matching_identity = deepcopy(base_config)
        for side in ("base", "current"):
            resolved_home = str(
                Path(matching_identity[side]["jdk_home"]).resolve()
            )
            matching_identity[side]["jdk_preflight_identity"] = (
                f"identity:{resolved_home}"
            )
        with self.assertRaises(StopAfterEarlyPhases):
            invoke(matching_identity)

        same_jdk = deepcopy(base_config)
        same_jdk["current"]["jdk_home"] = same_jdk["base"]["jdk_home"]
        preflight_homes = []

        def count_preflight(home):
            preflight_homes.append(home)
            return {
                "jdk_preflight_identity": f"identity:{home}",
                "java_major": 17,
            }

        with self.assertRaises(StopAfterEarlyPhases):
            invoke(same_jdk, preflight=count_preflight)
        self.assertEqual(preflight_homes, [str(Path("/jdk/base").resolve())])

        for retain, discarded, expected_prunes in (
            (False, False, 1),
            (True, True, 1),
            (True, False, 0),
        ):
            resumed = {"activation_candidate_discarded": discarded}
            pruned = []
            result, observed_prunes = invoke(
                retain=retain,
                resume_result=resumed,
                pruned=pruned,
            )
            self.assertIs(result, resumed)
            self.assertEqual(len(observed_prunes), expected_prunes)

    def test_remaining_small_pipeline_helpers_exhaust_failure_and_default_matrix(self):
        with patch.object(
            binary_pipeline,
            "_non_authoritative_resource_usage_snapshot",
            return_value=None,
        ), patch.object(
            binary_pipeline,
            "_write_non_authoritative_json",
            return_value=True,
        ):
            empty = binary_pipeline._PhaseTimingRecorder(
                Path("/unused"), 0.0, attempt_identity="attempt",
            )
            empty.fail({})
            list.append(empty, {})
            empty.start("")
            empty.fail({"phase": ""})
        self.assertEqual(empty.write_failure_count, 0)

        for support in ([], "invalid", 1):
            self.assert_pipeline_error(
                "BINARY_AUTHORITY_MANIFEST_INVALID",
                lambda support=support: (
                    binary_pipeline._generation_support_manifest_identity(support)
                ),
            )

        fake_sys = SimpleNamespace(
            implementation=SimpleNamespace(name="cpython", cache_tag=None),
            version_info=SimpleNamespace(
                major=3, minor=14, micro=0, releaselevel="final", serial=0,
            ),
            version="3.14-test",
            byteorder="little",
            platform="test-platform",
        )
        with patch.object(binary_pipeline, "sys", fake_sys), patch.object(
            binary_pipeline, "_GENERATION_RUNTIME_DISTRIBUTIONS", (),
        ):
            self.assertRegex(
                binary_pipeline._generation_runtime_identity({}),
                r"^[0-9a-f]{64}$",
            )

        captured_gc = []

        class CleanupFailure(RuntimeError):
            def __init__(self, reason_code):
                super().__init__("cleanup failed")
                self.reason_code = reason_code

        for reason_code in (None, "", "GC_FAILED"):
            with patch.object(
                binary_pipeline,
                "prune_unreferenced_binary_generations",
                side_effect=CleanupFailure(reason_code),
            ), patch.object(
                binary_pipeline,
                "_write_non_authoritative_json",
                side_effect=lambda _path, payload: captured_gc.append(payload) or True,
            ):
                summary = (
                    binary_pipeline._prune_unreferenced_generations_best_effort(
                        Path("/unused")
                    )
                )
            self.assertEqual(summary["failure_count"], 1)
            self.assertEqual(
                summary["failures"][0]["reason_code"], reason_code or "",
            )

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            output = parent / "output"
            binary_pipeline._preflight_output_root(output)
            self.assertTrue(output.is_dir())

            file_output = parent / "file-output"
            file_output.write_bytes(b"file")
            self.assert_pipeline_error(
                "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
                lambda: binary_pipeline._preflight_output_root(file_output),
            )

            class NonDirectoryRoot:
                def __truediv__(self, _name):
                    return parent / "non-directory-probe"

                def mkdir(self, **_kwargs):
                    return None

                def is_dir(self):
                    return False

                def __str__(self):
                    return "non-directory-root"

            self.assert_pipeline_error(
                "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
                lambda: binary_pipeline._preflight_output_root(
                    NonDirectoryRoot()
                ),
            )

            mismatch_output = parent / "mismatch-output"

            def write_mismatch(path, _content):
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_bytes(b"wrong")
                return Path(path)

            with patch.object(
                binary_pipeline,
                "_write_text_atomic_durable",
                side_effect=write_mismatch,
            ):
                self.assert_pipeline_error(
                    "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
                    lambda: binary_pipeline._preflight_output_root(
                        mismatch_output
                    ),
                )

            existing = parent / "existing"
            existing.mkdir()
            self.assertEqual(
                binary_pipeline._canonical_output_root_preserving_leaf(existing),
                existing,
            )
            missing = parent / "missing"
            self.assertEqual(
                binary_pipeline._canonical_output_root_preserving_leaf(missing),
                missing,
            )
            invalid_file = parent / "invalid-file"
            invalid_file.write_bytes(b"file")
            self.assert_pipeline_error(
                "BINARY_PIPELINE_OUTPUT_STORAGE_UNAVAILABLE",
                lambda: binary_pipeline._canonical_output_root_preserving_leaf(
                    invalid_file
                ),
            )

    def test_physical_directory_junction_resolution_is_rejected(self):
        directory_stat = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700)

        class FakePath:
            def __init__(self, name):
                self.name = name
                self.parent = None
                self.child = None
                self.resolved = self

            def expanduser(self):
                return self

            def resolve(self, *, strict=False):
                return self.resolved

            def __truediv__(self, _name):
                return self.child

            def __str__(self):
                return self.name

        def fake_paths(*, root_moves, observability_moves):
            lexical = FakePath("output")
            parent = FakePath("parent")
            canonical_parent = FakePath("canonical-parent")
            root = FakePath("root")
            observability = FakePath("binary_observability")
            lexical.parent = parent
            parent.resolved = canonical_parent
            canonical_parent.child = root
            root.child = observability
            root.resolved = FakePath("moved-root") if root_moves else root
            observability.resolved = (
                FakePath("moved-observability")
                if observability_moves else observability
            )
            return lexical, root, observability

        original_lstat = os.lstat
        lexical, root, observability = fake_paths(
            root_moves=True, observability_moves=False,
        )

        def root_lstat(path, *args, **kwargs):
            if path is root or path is observability:
                return directory_stat
            return original_lstat(path, *args, **kwargs)

        with patch.object(binary_pipeline, "Path", new=lambda _path: lexical), patch.object(
            binary_pipeline.os, "lstat", side_effect=root_lstat,
        ):
            self.assert_pipeline_error(
                "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
                lambda: binary_pipeline._physical_observability_directory(
                    "output", create=False,
                ),
            )

        lexical, root, observability = fake_paths(
            root_moves=False, observability_moves=True,
        )

        def observability_lstat(path, *args, **kwargs):
            if path is root or path is observability:
                return directory_stat
            return original_lstat(path, *args, **kwargs)

        with patch.object(binary_pipeline, "Path", new=lambda _path: lexical), patch.object(
            binary_pipeline.os,
            "lstat",
            side_effect=observability_lstat,
        ):
            self.assert_pipeline_error(
                "BINARY_PIPELINE_OBSERVABILITY_STORAGE_INVALID",
                lambda: binary_pipeline._physical_observability_directory(
                    "output", create=False,
                ),
            )

    def test_checkpoint_reparse_detection_exhausts_attribute_and_junction_truth_table(self):
        regular = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700)
        for reparse_attribute, file_attributes, junction, expected in (
            (0, 0, None, False),
            (0, 0, lambda: False, False),
            (0, 0, lambda: True, True),
            (0x400, 0, lambda: False, False),
            (0x400, 0x400, lambda: False, True),
        ):
            observed = SimpleNamespace(
                st_mode=regular.st_mode,
                st_file_attributes=file_attributes,
            )
            path = SimpleNamespace(is_junction=junction)
            with self.subTest(
                reparse_attribute=reparse_attribute,
                file_attributes=file_attributes,
                junction=junction,
            ), patch.object(
                binary_pipeline.stat,
                "FILE_ATTRIBUTE_REPARSE_POINT",
                reparse_attribute,
                create=True,
            ):
                self.assertEqual(
                    binary_pipeline._checkpoint_directory_is_reparse_point(
                        path, observed,
                    ),
                    expected,
                )

    def test_validation_attachment_defaults_empty_checkpoint_identities(self):
        class Timings(list):
            def start(self, phase, **metadata):
                self.started = (phase, metadata)

            def fail(self, item):
                self.failed = dict(item)

        passed = {
            "status": "passed",
            "issue_count": 0,
            "validation_run_identity": "v" * 64,
        }
        timings = Timings()
        with patch.object(
            binary_pipeline,
            "validate_generation",
            return_value=passed,
        ), patch.object(
            binary_pipeline,
            "_persist_validation_checkpoint",
            side_effect=lambda *_args: {"persisted": True},
        ):
            validation, checkpoint = (
                binary_pipeline._validate_or_reuse_checkpoint_attachment(
                    {},
                    output_root=Path("/output"),
                    generation=Path("/generation"),
                    manifest={},
                    checkpoint={},
                    phase_timings=timings,
                    resumed=False,
                )
            )
        self.assertEqual(validation, passed)
        self.assertEqual(checkpoint, {"persisted": True})

        checkpoint = {"status": binary_pipeline._RESUME_VALIDATION_PASSED}
        timings = Timings()
        with patch.object(
            binary_pipeline,
            "_checkpoint_validator_attachment_is_stale",
            return_value=False,
        ), patch.object(
            binary_pipeline,
            "_checkpoint_validation_attachment",
            return_value=passed,
        ) as attachment:
            validation, returned = (
                binary_pipeline._validate_or_reuse_checkpoint_attachment(
                    {},
                    output_root=Path("/output"),
                    generation=Path("/generation"),
                    manifest={},
                    checkpoint=checkpoint,
                    phase_timings=timings,
                    resumed=True,
                )
            )
        self.assertEqual(validation, passed)
        self.assertEqual(returned, checkpoint)
        attachment.assert_called_once_with(
            Path("/generation"),
            {},
            validation_run_identity="",
            validation_result_sha256="",
            expected_status="passed",
        )

    def test_cli_success_without_result_sink_uses_stdout_only(self):
        stdout = io.StringIO()
        result = {"status": "passed"}
        with patch.object(
            binary_pipeline,
            "_canonical_output_root_preserving_leaf",
            return_value=Path("/output"),
        ), patch.object(
            binary_pipeline,
            "_load_json",
            return_value={},
        ), patch.object(
            binary_pipeline,
            "run_pipeline",
            return_value=result,
        ), patch("sys.stdout", stdout):
            status = binary_pipeline.main([
                "--config", "/config.json",
                "--output-root", "/output",
            ])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout.getvalue()), result)

    def test_pipeline_mid_transaction_exhausts_platform_lineage_and_store_matrix(self):
        class StopAtIndexes(RuntimeError):
            pass

        class Timings(list):
            def start(self, phase, **metadata):
                self.last_start = (phase, metadata)

            def fail(self, item):
                self.last_failure = dict(item)

        class DigestSession:
            def prime(self, requests, *, configured_workers=None):
                self.requests = list(requests)
                self.configured_workers = configured_workers

            def revalidate_marked(self):
                self.revalidated = True

            def metrics(self):
                return {"digest_fixture": True}

        class Scope:
            REQUIRED_FIELDS = ()

            def __init__(self, _fields):
                self.identity = "scope"

        class Context:
            def __init__(self, _comparison, _scope):
                self.identity = "context"

        class Comparison:
            def __init__(self, *_args):
                self.identity = "comparison"

        class Memo:
            def clear(self):
                self.cleared = True

        class Store:
            def __init__(self, name, *, stop_at_indexes=False):
                self.name = name
                self.stop_at_indexes = stop_at_indexes
                self.closed = 0
                self.snapshots = []

            def ensure_secondary_indexes(self):
                if self.stop_at_indexes:
                    raise StopAtIndexes(self.name)

            def add_artifact_snapshot(self, instance, snapshot):
                self.snapshots.append((instance, snapshot))

            def close(self):
                self.closed += 1

        capability = SimpleNamespace(
            identity="capability",
            supported_transformer_profile_identities=(),
        )
        support = {
            "artifact_diff_support_manifest": {
                "resource_policy": {},
                "parser_contract": {},
            },
            "runtime_loader_support_manifest": {},
            "class_definition_support_manifest": {},
            "entrypoint_discovery_support_manifest": {},
        }
        build = SimpleNamespace(
            environment_identity="environment",
            input_identity="input",
            provenance_identity="provenance",
        )

        def run_fixture(
            config,
            *,
            platforms,
            profiles,
            base_descriptors=(),
            current_descriptors=(),
            base_instances=(),
            current_instances=(),
            stores=None,
            artifact_workers=1,
            current_store_error=None,
            outcome_factory=None,
        ):
            platforms = list(platforms)
            profiles = list(profiles)
            stores = list(stores or (
                Store("base", stop_at_indexes=True),
                Store("current"),
            ))
            captures = {
                "platform_homes": [],
                "profile_platforms": [],
                "stores": stores,
            }
            platform_values = iter(platforms)
            profile_values = iter(profiles)
            store_index = 0

            def platform_factory(home, **_kwargs):
                captures["platform_homes"].append(Path(home))
                return next(platform_values)

            def profile_factory(_config, platform_value, _paths):
                captures["profile_platforms"].append(platform_value)
                return next(profile_values)

            def store_factory(*_args, **_kwargs):
                nonlocal store_index
                if store_index == 1 and current_store_error is not None:
                    raise current_store_error
                value = stores[store_index]
                store_index += 1
                return value

            def cached_snapshot(path, **_kwargs):
                if outcome_factory is not None:
                    return outcome_factory(Path(path))
                raise AssertionError("snapshot loading was not expected")

            def pairing(
                status, lineage, _base_profile, _current_profile, _evidence,
                _policy, base_identity, current_identity,
            ):
                return SimpleNamespace(
                    identity=f"pairing:{lineage}",
                    status=status,
                    logical_dependency_lineage=lineage,
                    base_artifact_instance_identity=base_identity,
                    current_artifact_instance_identity=current_identity,
                )

            descriptors = [
                (list(base_descriptors), []),
                (list(current_descriptors), []),
            ]
            instances = [list(base_instances), list(current_instances)]
            with patch.multiple(
                binary_pipeline,
                _preflight_output_root=lambda _root: None,
                _PhaseTimingRecorder=lambda *_args, **_kwargs: Timings(),
                _static_pipeline_preflight=lambda *_args, **_kwargs: {
                    "performance_authority_gate_binding": None,
                    "runtime_capability_policy": capability,
                    "support": support,
                    "artifact_safety_policy": {},
                    "max_trace_nodes": 100,
                    "max_paths_per_target": 2,
                },
                _source_inputs_contract=lambda _config: {},
                preflight_jdk_home=lambda home: {
                    "jdk_preflight_identity": f"jdk:{home}",
                    "java_major": 17,
                },
                _validate_multi_release_runtime_contract=(
                    lambda *_args, **_kwargs: None
                ),
                resolve_asm_jar=lambda _path: Path("/asm.jar"),
                _resume_generation_validation=lambda *_args, **_kwargs: None,
                _delete_resume_checkpoint_durable=lambda _root: False,
                _prune_unreferenced_generations_best_effort=(
                    lambda *_args, **_kwargs: {}
                ),
                JdkPlatformImage=platform_factory,
                _ArtifactDigestSession=DigestSession,
                _runtime_profile=profile_factory,
                _build_identity_bundle=lambda *_args, **_kwargs: build,
                RuntimeComparison=Comparison,
                AnalysisScope=Scope,
                AnalysisContext=Context,
                BinaryFactStore=store_factory,
                _artifact_snapshot_worker_count=(
                    lambda _configured, _count: artifact_workers
                ),
                SnapshotTemplateMemo=Memo,
                cached_snapshot_archive=cached_snapshot,
                _absent_snapshot=lambda label, parser: SimpleNamespace(
                    parser_identity=parser,
                    absent_label=label,
                ),
                CrossVersionArtifactPairing=pairing,
                compare_artifact_snapshots=lambda *_args, **_kwargs: {
                    "artifact_local_result_identity": "diff"
                },
            ), patch.object(
                binary_pipeline,
                "_artifact_descriptors",
                side_effect=descriptors,
            ), patch.object(
                binary_pipeline,
                "_artifact_instances",
                side_effect=instances,
            ):
                binary_pipeline._run_pipeline_under_lock(
                    config,
                    output_root=Path("/private/mid-pipeline-output"),
                )
            return captures

        schema = "java-upgrade-analyzer.binary-pipeline-input.v1"
        same_platform = SimpleNamespace(
            identity="platform", jdk_home=Path("/jdk"), java_major=17,
        )
        same_profile = SimpleNamespace(identity="profile")
        empty_stores = (
            Store("empty-base", stop_at_indexes=True),
            Store("empty-current"),
        )
        with self.assertRaises(StopAtIndexes):
            run_fixture(
                {"schema": schema, "base": {}, "current": {}},
                platforms=(same_platform,),
                profiles=(same_profile, same_profile),
                stores=empty_stores,
            )
        self.assertEqual(empty_stores[0].closed, 1)
        self.assertEqual(empty_stores[1].closed, 1)

        equivalent_platforms = (
            SimpleNamespace(
                identity="same-image", jdk_home=Path("/base"), java_major=17,
            ),
            SimpleNamespace(
                identity="same-image", jdk_home=Path("/current"), java_major=17,
            ),
        )
        equivalent_profiles = (
            SimpleNamespace(identity="base-profile"),
            SimpleNamespace(identity="current-profile"),
        )
        captures = {}
        try:
            run_fixture(
                {
                    "schema": schema,
                    "base": {"jdk_home": "/base"},
                    "current": {"jdk_home": "/current"},
                    "analysis_observability_scope": "configured-scope",
                },
                platforms=equivalent_platforms,
                profiles=equivalent_profiles,
            )
        except StopAtIndexes:
            pass

        distinct_platforms = (
            SimpleNamespace(
                identity="base-image", jdk_home=Path("/base"), java_major=17,
            ),
            SimpleNamespace(
                identity="current-image", jdk_home=Path("/current"), java_major=17,
            ),
        )
        with self.assertRaises(StopAtIndexes):
            run_fixture(
                {
                    "schema": schema,
                    "base": {"jdk_home": "/base"},
                    "current": {"jdk_home": "/current"},
                },
                platforms=distinct_platforms,
                profiles=equivalent_profiles,
            )

        instance_a = SimpleNamespace(
            identity="instance-a", content_sha256="a" * 64,
        )
        instance_b = SimpleNamespace(
            identity="instance-b", content_sha256="b" * 64,
        )
        base_duplicate = (
            ({"lineage": "duplicate", "path": "/a.jar"}, instance_a),
            ({"coord": "duplicate", "path": "/b.jar"}, instance_b),
        )
        with self.assertRaises(binary_pipeline.BinaryPipelineError) as caught:
            run_fixture(
                {
                    "schema": schema,
                    "base": {"artifacts": [
                        {"path": "", "outer_artifact_path": ""},
                    ]},
                    "current": {"artifacts": []},
                },
                platforms=(same_platform,),
                profiles=(same_profile, same_profile),
                base_instances=base_duplicate,
            )
        self.assertEqual(
            caught.exception.reason_code, "BINARY_ARTIFACT_LINEAGE_AMBIGUOUS"
        )

        current_duplicate = (
            ({"logical_location": "duplicate", "path": "/c.jar"}, instance_a),
            ({
                "lineage": "", "coord": "",
                "logical_location": "duplicate", "path": "/d.jar",
            }, instance_b),
        )
        with self.assertRaises(binary_pipeline.BinaryPipelineError) as caught:
            run_fixture(
                {
                    "schema": schema,
                    "base": {"artifacts": []},
                    "current": {"artifacts": [{"path": "/current.jar"}]},
                },
                platforms=(same_platform,),
                profiles=(same_profile, same_profile),
                current_instances=current_duplicate,
            )
        self.assertEqual(
            caught.exception.reason_code, "BINARY_ARTIFACT_LINEAGE_AMBIGUOUS"
        )

        constructor_stores = (Store("constructor-base"), Store("unused"))
        with self.assertRaisesRegex(OSError, "current store failed"):
            run_fixture(
                {"schema": schema, "base": {}, "current": {}},
                platforms=(same_platform,),
                profiles=(same_profile, same_profile),
                stores=constructor_stores,
                current_store_error=OSError("current store failed"),
            )
        self.assertEqual(constructor_stores[0].closed, 1)
        self.assertEqual(constructor_stores[1].closed, 0)

        def outcome(path):
            status = "corrupt_rebuilt" if path.name == "base.jar" else "hit"
            tier = "disk" if path.name == "base.jar" else "memory"
            return SimpleNamespace(
                snapshot=SimpleNamespace(parser_identity="parser"),
                cache_status=status,
                cache_tier=tier,
                parser_invocation_count=1,
            )

        base_only_instance = SimpleNamespace(
            identity="base-only-instance", content_sha256="c" * 64,
        )
        current_only_instance = SimpleNamespace(
            identity="current-only-instance", content_sha256="d" * 64,
        )
        nested_stores = (
            Store("nested-base", stop_at_indexes=True),
            Store("nested-current"),
        )
        with self.assertRaises(StopAtIndexes):
            run_fixture(
                {"schema": schema, "base": {}, "current": {}},
                platforms=(same_platform,),
                profiles=(same_profile, same_profile),
                base_instances=(({
                    "lineage": "base-only", "path": "/base.jar",
                }, base_only_instance),),
                current_instances=(({
                    "lineage": "current-only", "path": "/current.jar",
                }, current_only_instance),),
                stores=nested_stores,
                artifact_workers=1,
                outcome_factory=outcome,
            )
        self.assertEqual(len(nested_stores[0].snapshots), 1)
        self.assertEqual(len(nested_stores[1].snapshots), 1)

        exact_pairs = []
        for index in range(4):
            instance = SimpleNamespace(
                identity=f"exact-{index}", content_sha256=f"{index:x}" * 64,
            )
            raw = {
                "lineage": f"exact-{index}",
                "path": f"/exact-{index}.jar",
            }
            exact_pairs.append((raw, instance))
        parallel_stores = (
            Store("parallel-base", stop_at_indexes=True),
            Store("parallel-current"),
        )
        with self.assertRaises(StopAtIndexes):
            run_fixture(
                {"schema": schema, "base": {}, "current": {}},
                platforms=(same_platform,),
                profiles=(same_profile, same_profile),
                base_instances=exact_pairs,
                current_instances=exact_pairs,
                stores=parallel_stores,
                artifact_workers=2,
                outcome_factory=outcome,
            )
        self.assertEqual(len(parallel_stores[0].snapshots), 4)

    def test_extracted_pipeline_invariants_exhaust_all_outcomes(self):
        self.assertEqual(
            binary_pipeline._source_mapping_status_counts(()), {}
        )
        self.assertEqual(
            binary_pipeline._source_mapping_status_counts((
                {},
                {"mapping_status": ""},
                {"mapping_status": "mapped"},
                {"mapping_status": "mapped"},
                {"mapping_status": "unbound"},
            )),
            {"mapped": 2, "unbound": 1, "unknown": 2},
        )
        self.assertEqual(
            binary_pipeline._nonempty_first_column((
                (None,), ("",), ("A",), ("A",), ("B",),
            )),
            {"A", "B"},
        )
        self.assertEqual(binary_pipeline._nonempty_first_column(()), set())

        self.assertEqual(
            binary_pipeline._single_parser_identity(("parser", "parser")),
            "parser",
        )
        for identities in ((), ("first", "second")):
            self.assert_pipeline_error(
                "BINARY_PIPELINE_PARSER_IDENTITY_SET_INVALID",
                lambda identities=identities: (
                    binary_pipeline._single_parser_identity(identities)
                ),
            )

        for measurement in (False, True):
            for receipt in ({}, {"retained": True}):
                for discarded in (False, True):
                    with self.subTest(
                        measurement=measurement,
                        receipt=bool(receipt),
                        discarded=discarded,
                    ):
                        self.assertEqual(
                            binary_pipeline._should_prune_generation_after_result(
                                performance_measurement_run=measurement,
                                checkpoint_receipt=receipt,
                                candidate_discarded=discarded,
                            ),
                            (
                                not measurement
                                and (not receipt or discarded)
                            ),
                        )
