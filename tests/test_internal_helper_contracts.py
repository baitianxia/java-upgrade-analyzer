from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import artifact_coordinates
import artifact_safety
import binary_decision_engine
import binary_performance_identity
import binary_report
from binary_entrypoint_discovery import BinaryEntrypointDiscoveryResult
from binary_fact_store import BinaryFactStore
import binary_output
from binary_platform_image import JdkPlatformImage
import binary_runtime_reconciler
import binary_semantic_overlay
import binary_validation_contract
import diagnostic_contract
import path_runtime
import process_lock
import progress_logging
import run_step
import runtime_contract
import s4_contract
import signature_utils


class InternalIdentityHelperContractTest(unittest.TestCase):
    def test_performance_identity_rejects_every_structural_boundary(self):
        valid_sha = "a" * 64
        valid_source_components = {
            "generation_source_identity": "1" * 64,
            "validator_source_identity": "2" * 64,
            "oracle_support_manifest_identity": "3" * 64,
            "harness_source_identity": "4" * 64,
        }
        valid_runtime_components = {
            "source_implementation_identity": "5" * 64,
            "pipeline_generation_implementation_identity": "6" * 64,
            "validator_implementation_identity": "7" * 64,
            "jdk_preflight_identity": "8" * 64,
        }

        invalid_record_sets = (
            [None],
            [{"path": "", "sha256": valid_sha}],
            [{"path": "@runtime/jdk", "sha256": valid_sha}],
        )
        for records in invalid_record_sets:
            with self.subTest(records=records), self.assertRaises(ValueError):
                binary_performance_identity.generation_source_identity(records)

        for builder, components in (
            (
                binary_performance_identity.source_implementation_identity,
                valid_source_components,
            ),
            (
                binary_performance_identity.runtime_implementation_identity,
                valid_runtime_components,
            ),
        ):
            with self.subTest(builder=builder.__name__), self.assertRaises(
                ValueError
            ):
                builder(None)

    def test_validation_identity_rejects_incomplete_sources_and_manifest_shape(self):
        incomplete = dict(
            binary_validation_contract._CAPTURED_VALIDATOR_SOURCE_DIGESTS
        )
        incomplete.pop(next(iter(incomplete)))

        for builder, args in (
            (
                binary_validation_contract._validator_implementation_payload,
                (
                    incomplete,
                    binary_validation_contract._CAPTURED_PYTHON_RUNTIME_IDENTITY,
                ),
            ),
            (
                binary_validation_contract._validator_source_identity_from_inputs,
                (incomplete,),
            ),
        ):
            with self.subTest(builder=builder.__name__), self.assertRaises(
                binary_validation_contract.BinaryValidationContractError
            ):
                builder(*args)

        with patch.object(
            binary_validation_contract.sys,
            "implementation",
            SimpleNamespace(name="cpython", cache_tag=None),
        ):
            self.assertEqual(
                binary_validation_contract._python_runtime_identity()["cache_tag"],
                "",
            )

        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "support.json"
            manifest.write_text(
                '{"oracle_support_manifest": []}',
                encoding="utf-8",
            )
            with patch.object(
                binary_validation_contract,
                "SUPPORT_MANIFEST_PATH",
                manifest,
            ), self.assertRaises(
                binary_validation_contract.BinaryValidationContractError
            ):
                binary_validation_contract._load_oracle_support_manifest()

    def test_runtime_and_checkpoint_configuration_loaders_are_deterministic(self):
        runtime_identity = binary_report._report_runtime_identity()
        self.assertEqual(runtime_identity["implementation"], sys.implementation.name)
        self.assertEqual(
            runtime_identity["version"],
            [sys.version_info.major, sys.version_info.minor, sys.version_info.micro],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            requirements = root / "requirements.txt"
            requirements.write_text(
                "# exact runtime truth\nalpha-package==1.2.3\n\n"
                "beta-package==4.5.6\n",
                encoding="utf-8",
            )
            self.assertEqual(
                runtime_contract._load_required_packages(requirements),
                {
                    "alpha-package": "1.2.3",
                    "beta-package": "4.5.6",
                },
            )

            rules = root / "CHECKPOINT_RULES.md"
            rules.write_text(
                "# ignored heading\nfirst rule\n\nsecond rule\n",
                encoding="utf-8",
            )
            with patch.object(run_step, "CHECKPOINT_RULES_FILE", rules):
                self.assertEqual(
                    run_step.load_checkpoint_rules(),
                    ["first rule", "second rule"],
                )

    def test_classifier_boolean_and_constructor_normalization_boundaries(self):
        self.assertEqual(
            artifact_coordinates.artifact_classifier("g:a:test-fixtures"),
            "test-fixtures",
        )
        self.assertEqual(artifact_coordinates.artifact_classifier("g:a"), "")
        self.assertEqual(artifact_coordinates.artifact_classifier("broken"), "")

        coordinate_cases = (
            (None, ("", "", ""), "", ""),
            ("", ("", "", ""), "", ""),
            ("single", ("", "", ""), "", "single"),
            (":artifact", ("", "", ""), "", ":artifact"),
            ("group:", ("", "", ""), "", "group:"),
            (" group : artifact ", ("group", "artifact", ""), "group:artifact", "group:artifact"),
            (
                "group:artifact::tests:",
                ("group", "artifact", "tests"),
                "group:artifact",
                "group:artifact:tests",
            ),
        )
        for raw, split, ga, normalized in coordinate_cases:
            with self.subTest(coordinate=raw):
                self.assertEqual(artifact_coordinates.split_artifact_coord(raw), split)
                self.assertEqual(artifact_coordinates.artifact_ga(raw), ga)
                self.assertEqual(
                    artifact_coordinates.normalize_artifact_coord(raw),
                    normalized,
                )
        self.assertEqual(
            artifact_coordinates.normalize_artifact_coord(
                "group:artifact:declared", "ignored",
            ),
            "group:artifact:declared",
        )
        self.assertEqual(
            artifact_coordinates.normalize_artifact_coord(
                "group:artifact", " runtime ",
            ),
            "group:artifact:runtime",
        )
        self.assertEqual(
            artifact_coordinates.normalize_artifact_coord("group:artifact", ""),
            "group:artifact",
        )

        for value in (True, 1, -2, "TRUE", " yes ", "on"):
            self.assertTrue(binary_semantic_overlay._as_bool(value))
        for value in (False, 0, 0.0, None, "false", "off", ""):
            self.assertFalse(binary_semantic_overlay._as_bool(value))

        self.assertEqual(
            signature_utils._canonical_constructor_name("a.b.Widget.Widget"),
            "a.b.Widget.<init>",
        )
        self.assertEqual(
            signature_utils._canonical_constructor_name("a.b.Widget.<init>"),
            "a.b.Widget.<init>",
        )
        self.assertEqual(
            signature_utils._canonical_constructor_name("a.b.Outer$Inner"),
            "a.b.Outer.Inner.<init>",
        )
        self.assertEqual(signature_utils._canonical_constructor_name(""), "")
        self.assertEqual(
            signature_utils.canonical_api_identity_tuple({
                "coord": "g:a:1",
                "symbol_kind": "constructor",
                "api_name": "demo.Widget.Widget",
                "api_signature": "( java.lang.String )",
                "change_type": "removed",
            }),
            (
                "g:a:1",
                "demo.Widget.<init>",
                "(java.lang.String)",
                "constructor",
                "REMOVED",
            ),
        )

    def test_entrypoint_payload_is_a_stable_public_projection(self):
        result = BinaryEntrypointDiscoveryResult(
            exact_member_identities=("exact-1", "exact-2"),
            possible_member_identities=("possible-1",),
            records=({"kind": "main", "identity": "exact-1"},),
            coverage_status="partial",
            coverage_gaps=("FRAMEWORK_PROFILE_INCOMPLETE",),
            identity="discovery-identity",
        )

        self.assertEqual(result.as_payload(), {
            "schema": "java-upgrade-analyzer.binary-entrypoint-discovery.v1",
            "discovery_policy_version": (
                __import__("binary_entrypoint_discovery")
                .DISCOVERY_POLICY_VERSION
            ),
            "entrypoint_discovery_identity": "discovery-identity",
            "coverage_status": "partial",
            "coverage_gaps": ["FRAMEWORK_PROFILE_INCOMPLETE"],
            "exact_entrypoint_count": 2,
            "possible_entrypoint_count": 1,
            "records": [{"kind": "main", "identity": "exact-1"}],
        })

    def test_compact_rows_preserve_missing_values_and_mapping_union_order(self):
        class Row(binary_runtime_reconciler._CompactRow):
            FIELDS = ("left", "missing", "right")
            INDEX = {name: index for index, name in enumerate(FIELDS)}

        row = Row((1, binary_runtime_reconciler._MISSING_COMPACT_VALUE, 3))

        self.assertEqual(list(row), ["left", "right"])
        self.assertEqual(dict(row), {"left": 1, "right": 3})
        self.assertEqual(row | {"right": 4, "new": 5}, {
            "left": 1, "right": 4, "new": 5,
        })
        self.assertEqual({"left": 0, "first": -1} | row, {
            "left": 1, "first": -1, "right": 3,
        })
        with self.assertRaises(KeyError):
            _ = row["missing"]


class InternalFailureHelperContractTest(unittest.TestCase):
    def test_archive_changed_result_and_cache_reset_fail_closed(self):
        result = artifact_safety._changed_during_scan_result()
        self.assertFalse(result.safe)
        self.assertEqual(result.reason_codes, ("ARCHIVE_CHANGED_DURING_SCAN",))
        self.assertEqual(result.entry_count, 0)

        with artifact_safety._ARCHIVE_CACHE_CONDITION:
            before = artifact_safety._ARCHIVE_CACHE_GENERATION
            artifact_safety._ARCHIVE_SAFETY_CACHE[("x", "y", ())] = result
        artifact_safety.clear_archive_safety_cache()
        self.assertEqual(artifact_safety._ARCHIVE_SAFETY_CACHE, {})
        self.assertEqual(artifact_safety._ARCHIVE_CACHE_GENERATION, before + 1)

    def test_cached_archive_scan_rejects_post_scan_digest_change(self):
        safe = artifact_safety.ArchiveSafetyResult(
            safe=True,
            reason_codes=(),
            entry_count=1,
            total_uncompressed_bytes=1,
            nested_archives=0,
            max_observed_depth=0,
        )
        artifact_safety.clear_archive_safety_cache()
        try:
            with patch.object(
                artifact_safety, "_inspect_archive_source", return_value=safe,
            ), patch.object(
                artifact_safety, "_sha256_file", return_value="changed",
            ):
                result = artifact_safety._cached_archive_inspection(
                    "/definitely/not/read/by/the/patched/scanner.jar",
                    "expected",
                    (),
                )
        finally:
            artifact_safety.clear_archive_safety_cache()

        self.assertFalse(result.safe)
        self.assertEqual(
            result.reason_codes, ("ARCHIVE_CHANGED_DURING_SCAN",),
        )

    def test_require_safe_archive_inspects_missing_input_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.jar"
            with self.assertRaisesRegex(
                ValueError, "artifact_safety_violation:ARCHIVE_READ_FAILED",
            ):
                artifact_safety.require_safe_archive(missing)

    def test_unlink_helper_accepts_existing_and_already_missing_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "owned.txt"
            path.write_text("owned", encoding="utf-8")
            binary_output._unlink_missing_ok(path)
            self.assertFalse(path.exists())
            binary_output._unlink_missing_ok(path)

    def test_platform_failure_normalizes_class_name_before_lookup(self):
        image = object.__new__(JdkPlatformImage)
        image._failures = {"java/lang/Missing": {"reason": "not found"}}
        image.ensure_classes = MagicMock()

        self.assertEqual(
            image.failure("java.lang.Missing"), {"reason": "not found"},
        )
        image.ensure_classes.assert_called_once_with(("java/lang/Missing",))

    def test_diagnostic_mapping_is_shallow_immutable_and_canonical(self):
        source = {
            "reason_code": "binary pipeline timeout",
            "reason_codes": ["archive unsafe", "ARCHIVE_UNSAFE"],
            "nested": {"reason_code": "leave-me"},
        }
        normalized = diagnostic_contract.normalize_diagnostic_mapping(source)

        self.assertIsNot(normalized, source)
        self.assertEqual(source["reason_code"], "binary pipeline timeout")
        self.assertEqual(
            normalized["reason_code"],
            diagnostic_contract.canonical_reason_code(
                "binary pipeline timeout"
            ),
        )
        self.assertEqual(normalized["nested"], {"reason_code": "leave-me"})
        self.assertEqual(
            diagnostic_contract.normalize_diagnostic_mapping("raw"), "raw",
        )

        payload = diagnostic_contract.normalize_diagnostic_payload({
            "reason_codes": ["archive unsafe", "ARCHIVE_UNSAFE"],
        })
        self.assertEqual(payload["reason_codes"], ["ARCHIVE_UNSAFE"])

    def test_conditional_property_default_is_evaluated_through_boolean_policy(self):
        builder = object.__new__(binary_semantic_overlay._Builder)
        builder.profile = SimpleNamespace(payload={
            "active_profile_identities": [],
            "resolved_configuration_properties": {},
            "runtime_configuration_coverage_status": "complete",
        })
        builder.selected = {}
        fact = {
            "annotations": [{
                "descriptor": (
                    "Lorg/springframework/boot/autoconfigure/condition/"
                    "ConditionalOnProperty;"
                ),
                "visible": True,
                "values": [
                    ["name", "feature.enabled"],
                    ["matchIfMissing", True],
                ],
            }],
        }

        self.assertEqual(builder._condition_certainty("application", fact), "exact")

    def test_lock_open_preserves_primary_validation_error_and_close_failure(self):
        regular = SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=stat.S_IFREG | 0o600,
            st_nlink=1,
            st_size=0,
        )
        lock_os = SimpleNamespace(
            O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0),
            O_RDWR=os.O_RDWR,
            O_CREAT=os.O_CREAT,
            O_EXCL=os.O_EXCL,
            SEEK_SET=os.SEEK_SET,
            lstat=MagicMock(
                side_effect=[FileNotFoundError(), FileNotFoundError()],
            ),
            open=MagicMock(return_value=17),
            fstat=MagicMock(return_value=regular),
            close=MagicMock(side_effect=OSError("close denied")),
        )
        with patch.object(process_lock, "os", lock_os):
            with self.assertRaises(OSError) as raised:
                process_lock._open_validated_lock_file(Path("owned.lock"))

        self.assertEqual(raised.exception.errno, process_lock.errno.ESTALE)
        self.assertIn(
            "cleanup failed (close rejected lock descriptor): "
            "OSError: close denied",
            "\n".join(getattr(raised.exception, "__notes__", ()) or ()),
        )


class InternalPersistenceHelperContractTest(unittest.TestCase):
    def test_direct_seal_registry_replaces_same_operation_and_invalidates_root(self):
        root = Path("/private/test-output").resolve()
        snapshot = (1, 2, stat.S_IFREG | 0o600, 1, 10, 20)

        def capability(identity):
            return binary_output._DirectSealCapability(
                sequence=0,
                owner_process_identity=os.getpid(),
                owner_thread_identity=1,
                canonical_root=root,
                root_identity=(1, 2),
                probed_device=1,
                operation_key=("seal", "same-operation"),
                result_generation_identity=identity,
                validation_run_identity="b" * 64,
                validation_result_sha256="c" * 64,
                activation_identity="d" * 64,
                unsealed_descriptor_bytes=b"{}\n",
                predecessor_bytes=None,
                descriptor_before_identity=None,
                descriptor_after_identity=(3, 4),
                descriptor_snapshot=snapshot,
                publication_authority_bytes=None,
                directory_snapshots=(),
                file_snapshots=(),
            )

        binary_output._reset_direct_seal_fast_path_after_fork()
        try:
            binary_output._install_direct_seal_capability(capability("a" * 64))
            binary_output._DIRECT_SEAL_FAST_PATH_CONTEXT.set(None)
            binary_output._install_direct_seal_capability(capability("e" * 64))
            self.assertEqual(
                len(binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY), 1,
            )

            binary_output._DIRECT_SEAL_FAST_PATH_CONTEXT.set(None)
            binary_output._invalidate_direct_seal_capabilities_for_root(root)
            self.assertEqual(binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY, {})
            self.assertEqual(binary_output._DIRECT_SEAL_FAST_PATH_BY_OPERATION, {})
        finally:
            binary_output._reset_direct_seal_fast_path_after_fork()

    def test_runtime_accumulator_flushes_at_the_configured_chunk_boundary(self):
        store = SimpleNamespace(add_reconciliation_payloads=MagicMock())
        with patch.object(
            binary_runtime_reconciler._ReconciliationAccumulator,
            "CHUNK_SIZE",
            1,
        ):
            accumulator = binary_runtime_reconciler._ReconciliationAccumulator(
                store,
                "analysis-context",
                retained_kinds={"linkage_resolution"},
            )
            accumulator.add("linkage_resolution", {
                "linkage_status": "resolved",
                "linkage_resolution_identity": "a" * 64,
            })

        store.add_reconciliation_payloads.assert_called_once()
        self.assertEqual(accumulator.pending["linkage_resolution"], [])

    def test_resource_selection_uses_platform_realm_when_parent_is_implicit(self):
        reconciler = object.__new__(binary_runtime_reconciler.RuntimeReconciler)
        reconciler.realms = {
            "platform-loader": {"kind": "platform"},
            "application-loader": {
                "kind": "application",
                "delegation": "parent_first",
            },
        }
        reconciler.resource_candidates_by_realm_name = {
            ("application-loader", "META-INF/services/demo.Service"): [
                {"physical_entry_identity": "resource-1"},
            ],
        }

        rows, gaps = reconciler._selected_resources(
            "application-loader",
            "META-INF/services/demo.Service",
            "ordered_all",
        )

        self.assertEqual(
            [row["physical_entry_identity"] for row in rows], ["resource-1"],
        )
        self.assertEqual(gaps, [])

    def test_symbolic_member_visited_path_delegates_to_cycle_safe_resolver(self):
        reconciler = object.__new__(binary_runtime_reconciler.RuntimeReconciler)

        self.assertEqual(
            reconciler._resolve_symbolic_member(
                "application-loader",
                "demo/Api",
                "method",
                "run",
                "()V",
                visited=(("application-loader", "demo/Api"),),
            ),
            (None, None),
        )

    def test_constant_dynamic_edge_payload_is_decoded_and_persisted(self):
        edge = {
            "direct_edge_identity": "edge-1",
            "caller_member_identity": "member-1",
            "caller_artifact_instance_identity": "artifact-1",
            "instruction_index": 0,
            "bytecode_offset": 0,
            "edge_kind": "ldc_constant_dynamic",
            "opcode": 18,
            "symbolic_owner": "",
            "symbolic_name": "constant",
            "symbolic_descriptor": "Ljava/lang/String;",
            "edge_json": '{"bootstrap":{"owner":"demo/Bootstrap"}}',
        }
        reconciler = object.__new__(binary_runtime_reconciler.RuntimeReconciler)
        reconciler.classes = [{
            "artifact_instance_identity": "artifact-1",
            "class_variant_identity": "variant-1",
            "class_name": "demo/Caller",
        }]
        reconciler.artifacts = {
            "artifact-1": {"loader_realm_identity": "application-loader"},
        }
        reconciler.member_by_identity = {
            "member-1": {"class_variant_identity": "variant-1"},
        }
        reconciler.profile = SimpleNamespace(
            complete=True,
            payload={"runtime_class_closure_coverage_status": "complete"},
        )
        reconciler.capability = SimpleNamespace(closed_world_dispatch=True)
        reconciler.coverage_gaps = set()
        reconciler.store = SimpleNamespace(
            connection=SimpleNamespace(execute=MagicMock(return_value=[edge])),
        )
        reconciler._provider = MagicMock(return_value={
            "class_provider_status": "resolved",
            "selected_class_variant_identity": "variant-1",
            "selected_defining_loader_realm_identity": "application-loader",
        })
        accumulator = SimpleNamespace(add=MagicMock())

        reconciler._resolve_edges((), accumulator)

        kind, record = accumulator.add.call_args.args
        self.assertEqual(kind, "linkage_resolution")
        self.assertEqual(record["payload"], {
            "bootstrap": {"owner": "demo/Bootstrap"},
        })
        self.assertEqual(record["linkage_status"], "represented_by_bootstrap_handles")

    def test_fact_store_descriptor_and_member_insert_contract(self):
        self.assertEqual(BinaryFactStore._descriptor_owner("[[Ldemo/Thing;"), "demo/Thing")
        self.assertEqual(BinaryFactStore._descriptor_owner("[I"), "")
        self.assertEqual(BinaryFactStore._descriptor_owner("Lbroken"), "")

        store = object.__new__(BinaryFactStore)
        store.connection = MagicMock()
        values = tuple(range(10))
        with patch.object(
            BinaryFactStore,
            "_member_values",
            return_value=("member-id", values),
        ) as member_values:
            identity = store._insert_member(
                "variant", "artifact", "demo/Thing", "method",
                {"name": "run", "descriptor": "()V"}, "digest",
            )

        self.assertEqual(identity, "member-id")
        member_values.assert_called_once()
        store.connection.execute.assert_called_once_with(
            "INSERT INTO members VALUES(?,?,?,?,?,?,?,?,?,?)", values,
        )

    def test_provider_fingerprint_distinguishes_absent_and_exact_payload(self):
        engine = object.__new__(binary_decision_engine.BinaryDecisionEngine)
        with patch.object(
            binary_decision_engine.BinaryDecisionEngine,
            "_provider_outcome_payload",
            return_value=None,
        ):
            self.assertEqual(engine._provider_fingerprint(None, None, {}), "ABSENT")

        payload = {"status": "resolved", "class_name": "demo/Thing"}
        with patch.object(
            binary_decision_engine.BinaryDecisionEngine,
            "_provider_outcome_payload",
            return_value=payload,
        ):
            self.assertEqual(
                engine._provider_fingerprint(None, {}, {}),
                binary_decision_engine._identity(
                    "provider_outcome_fingerprint", payload,
                ),
            )

    def test_short_temporary_file_policy_bounds_prefix_and_returns_owned_fd(self):
        descriptor, name = path_runtime.make_temporary_file(
            prefix="x" * 200,
        )
        try:
            os.write(descriptor, b"owned")
            self.assertLessEqual(len(Path(name).name.split("-", 1)[0]), 24)
            self.assertEqual(Path(name).read_bytes(), b"owned")
        finally:
            os.close(descriptor)
            Path(name).unlink(missing_ok=True)


class InternalPresentationHelperContractTest(unittest.TestCase):
    def test_progress_interval_and_boundary_decisions_are_total(self):
        self.assertEqual(progress_logging.suggest_log_interval(None), 1)
        self.assertEqual(progress_logging.suggest_log_interval("bad", minimum=3), 3)
        self.assertEqual(progress_logging.suggest_log_interval(100, target_updates=10), 10)
        self.assertTrue(progress_logging.should_log_progress(1, 100, 10))
        self.assertTrue(progress_logging.should_log_progress(100, 100, 10))
        self.assertTrue(progress_logging.should_log_progress(20, 100, 10))
        self.assertFalse(progress_logging.should_log_progress(21, 100, 10))
        self.assertFalse(progress_logging.should_log_progress("bad", 100, 10))

    def test_step4_contract_rejects_invalid_rows_and_generates_safe_names(self):
        valid = {
            field: "value" for field in s4_contract.ALL_CHANGED_APIS_FIELDS
            if field not in s4_contract.OPTIONAL_FIELDS
        }
        valid.update({
            "change_type": "REMOVED",
            "severity": "P0",
            "source": "classfile_contract",
            "symbol_kind": "method",
            "confirmed": "true",
        })
        self.assertEqual(s4_contract.validate_row(valid), [])

        invalid = dict(valid, change_type="UNKNOWN", severity="P9")
        errors = s4_contract.validate_row(invalid)
        self.assertTrue(any("change_type" in error for error in errors))
        self.assertTrue(any("severity" in error for error in errors))

        api_name = s4_contract.make_api_filename(
            "demo.Thing.<init>()", "REMOVED",
        )
        self.assertEqual(api_name, "Thing_init_REMOVED.json")
        self.assertEqual(
            s4_contract.make_module_filename("CON"), "_CON_impacts.json",
        )
        self.assertNotIn("/", s4_contract.make_module_filename("a/b:c"))


if __name__ == "__main__":
    unittest.main()
