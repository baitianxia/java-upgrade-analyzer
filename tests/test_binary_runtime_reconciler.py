import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import weakref
from pathlib import Path
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_artifact_diff  # noqa: E402
import binary_runtime_reconciler as runtime_reconciler  # noqa: E402
from binary_fact_store import BinaryFactStore  # noqa: E402
from binary_first_model import ArtifactInstance, RuntimeProfile  # noqa: E402
from binary_platform_image import JdkPlatformImage  # noqa: E402
from binary_runtime_reconciler import (  # noqa: E402
    RuntimeReconciler,
    hydrate_runtime_reconciliation,
)


def current_jdk_home():
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"^\s*java\.home\s*=\s*(.+)$", completed.stderr, re.MULTILINE)
    return Path(match.group(1).strip()) if match else None


class BinaryRuntimeReconcilerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("java") or not shutil.which("javac"):
            raise unittest.SkipTest("full JDK required")
        jdk_home = current_jdk_home()
        if not jdk_home or not (jdk_home / "jmods").is_dir():
            raise unittest.SkipTest("target JDK jmods are required")
        try:
            cls.asm_jar = binary_asm_helper.resolve_asm_jar()
            cls.platform = JdkPlatformImage(jdk_home, asm_jar=cls.asm_jar)
        except Exception as error:
            raise unittest.SkipTest(str(error)) from error

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        sources = {
            "module-info.java": "module demo.module { exports demo; }",
            "demo/Api.java": "package demo; public interface Api { String value(); }",
            "demo/Impl.java": (
                "package demo; public class Impl implements Api { "
                "public String value(){ return \"ok\"; } "
                "public Missing optional() { return null; } }"
            ),
            "demo/OptionalEnum.java": (
                "package demo; public enum OptionalEnum { A; "
                "public Missing optional() { return null; } } class Missing {}"
            ),
            "demo/FinalApi.java": "package demo; public final class FinalApi { public String value(){ return \"ok\"; } }",
            "demo/Init.java": """
                package demo;
                public class Init {
                  public static int VALUE = 1;
                  public static int value() { return VALUE; }
                }
            """,
            "demo/Caller.java": """
                package demo;
                public class Caller {
                  public String call(Api api) { return api.value().trim(); }
                  public String finalCall(FinalApi api) { return api.value(); }
                  public Runnable dynamic(Api api) { return api::value; }
                  public Object[] cloneArray(Object[] values) { return values.clone(); }
                  public OptionalEnum[] cloneOptional(OptionalEnum[] values) { return values.clone(); }
                  public Init create() { return new Init(); }
                  public int staticCall() { return Init.value(); }
                  public int staticField() { return Init.VALUE; }
                  public Class<?> literal() { return Init.class; }
                }
            """,
            "demo/NestHost.java": """
                package demo;
                public class NestHost {
                  private String privateValue() { return "nested"; }
                  public static class Member {
                    public String call(NestHost host) {
                      return host.privateValue();
                    }
                  }
                }
            """,
        }
        source_paths = []
        for relative, content in sources.items():
            path = self.root / "src" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            source_paths.append(path)
        classes = self.root / "classes"
        classes.mkdir()
        self.classes = classes
        completed = subprocess.run(
            ["javac", "-g", "-d", str(classes), *map(str, source_paths)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.jar = self.root / "app.jar"
        with zipfile.ZipFile(self.jar, "w") as archive:
            for class_file in sorted(classes.rglob("*.class")):
                if class_file.relative_to(classes).as_posix() == "demo/Missing.class":
                    continue
                archive.write(class_file, class_file.relative_to(classes).as_posix())
        self.jar_sha = binary_artifact_diff._sha256_file(self.jar)
        required = RuntimeProfile.REQUIRED_FIELDS
        self.profile = RuntimeProfile({
            "target_jvm": {
                "vendor": self.platform.release.get("IMPLEMENTOR"),
                "major": self.platform.java_major,
                "version": self.platform.release.get("JAVA_VERSION"),
            },
            "runtime_platform_image_identity": self.platform.identity,
            "target_os": "test-os",
            "target_arch": self.platform.release.get("OS_ARCH", "unknown"),
            "container_and_launcher_kind": "java-classpath",
            "ordered_runtime_path_entry_descriptors": [{
                "logical_location": "lib/app.jar",
                "content_sha256": self.jar_sha,
                "path_kind": "classpath",
                "slot": 0,
                "loader_realm": "application-loader",
            }],
            "loader_topology": {
                "coverage_status": "complete",
                "entrypoint_realms": ["application-loader"],
                "realms": [
                    {
                        "identity": "platform-loader",
                        "kind": "platform",
                        "delegation": "parent_first",
                        "module_mode": "named-platform",
                    },
                    {
                        "identity": "application-loader",
                        "kind": "application",
                        "parent": "platform-loader",
                        "delegation": "parent_first",
                        "module_mode": "unnamed",
                    },
                ],
            },
            "runtime_code_source_origin_mapping_identity": "deployment-origins-1",
            "runtime_security_and_package_sealing_policy_identity": "standard-unsealed-unsigned-v1",
            "active_profile_identities": ["default"],
            "external_config_snapshot_identities": [],
            "agent_transformer_plugin_profile_identities": [],
            "business_entrypoint_profile": {"classes": ["demo/Caller"]},
            "runtime_class_closure_coverage_status": "complete",
            "resource_selection_coverage_status": "complete",
            "field_coverage": {key: "known" for key in required},
        })
        self.instance = ArtifactInstance(
            outer_artifact_sha256=self.jar_sha,
            container_entry="<artifact>",
            content_sha256=self.jar_sha,
            runtime_profile_identity=self.profile.identity,
            path_owner_loader_realm_identity="application-loader",
            runtime_path_kind="classpath",
            runtime_classpath_index=0,
            container_loader_policy_version="flat-parent-first-v1",
            runtime_code_source_origin_identity="deployment-app-jar",
            coord="com.acme:app:1",
        )

    def tearDown(self):
        self.temp.cleanup()

    def build_store(self):
        store = BinaryFactStore()
        snapshot = binary_artifact_diff.snapshot_archive(
            self.jar,
            artifact_instance_identity=self.instance.identity,
            expected_sha256=self.jar_sha,
            asm_jar=self.asm_jar,
        )
        store.add_artifact_snapshot(self.instance, snapshot)
        return store

    def test_edge_payload_cache_is_bounded_and_keeps_fact_validation(self):
        runtime_reconciler._load_small_edge_json.cache_clear()
        runtime_reconciler._loading_constraint_type_owners_from_edge_json.cache_clear()
        payload = (
            '{"interface":false,"loading_constraint_type_owners":'
            '["demo/A","demo/B"]}'
        )

        first = runtime_reconciler._load_edge_json(payload)
        second = runtime_reconciler._load_edge_json(payload)
        owners = (
            runtime_reconciler._loading_constraint_type_owners_from_edge_json(
                payload
            )
        )
        owners_again = (
            runtime_reconciler._loading_constraint_type_owners_from_edge_json(
                payload
            )
        )
        cache = runtime_reconciler._load_small_edge_json.cache_info()
        owner_cache = (
            runtime_reconciler.
            _loading_constraint_type_owners_from_edge_json.cache_info()
        )

        self.assertIs(first, second)
        self.assertEqual(owners, ("demo/A", "demo/B"))
        self.assertIs(owners, owners_again)
        self.assertGreaterEqual(cache.hits, 1)
        self.assertEqual(cache.maxsize, 16_384)
        self.assertEqual(owner_cache.hits, 1)
        oversized = '{"value":"' + (
            "x" * (runtime_reconciler._EDGE_JSON_CACHE_MAX_VALUE_BYTES + 1)
        ) + '"}'
        before = runtime_reconciler._load_small_edge_json.cache_info()
        self.assertEqual(
            runtime_reconciler._load_edge_json(oversized),
            runtime_reconciler._load_edge_json(oversized),
        )
        after = runtime_reconciler._load_small_edge_json.cache_info()
        self.assertEqual(after, before)
        with self.assertRaises(
            runtime_reconciler.RuntimeReconciliationError
        ):
            runtime_reconciler._loading_constraint_type_owners_from_edge_json(
                '{"loading_constraint_type_owners":["demo/B","demo/A"]}'
            )

    def test_initialization_reads_normalized_headers_not_full_fact_blobs(self):
        with self.build_store() as store:
            statements = []
            store.connection.set_trace_callback(statements.append)
            reconciler = RuntimeReconciler(
                store,
                self.profile,
                self.platform,
                analysis_context_identity="analysis-context-header-read",
            )
            store.connection.set_trace_callback(None)
            caller = next(
                row for row in reconciler.classes
                if row["class_name"] == "demo/Caller"
            )

        self.assertEqual(caller["class_name"], "demo/Caller")
        self.assertEqual(caller["super_name"], "java/lang/Object")
        self.assertFalse(any(
            "fact_zlib" in statement.lower() for statement in statements
        ))

    def test_provider_definition_member_resolution_and_dispatch_are_physical(self):
        with self.build_store() as store:
            traced_statements = []
            store.connection.set_trace_callback(traced_statements.append)
            reconciler = RuntimeReconciler(
                store,
                self.profile,
                self.platform,
                analysis_context_identity="analysis-context-1",
            )
            result = reconciler.reconcile()
            store.connection.set_trace_callback(None)
            cache_before = (
                reconciler._symbolic_member_cache_hits,
                reconciler._symbolic_member_cache_misses,
            )
            first_resolution = reconciler._resolve_symbolic_member(
                "application-loader",
                "demo/FinalApi",
                "method",
                "value",
                "()Ljava/lang/String;",
            )
            second_resolution = reconciler._resolve_symbolic_member(
                "application-loader",
                "demo/FinalApi",
                "method",
                "value",
                "()Ljava/lang/String;",
            )
            cache_after = (
                reconciler._symbolic_member_cache_hits,
                reconciler._symbolic_member_cache_misses,
            )
            stored = store.counts()["reconciliation_records"]
            init_member = next(
                item for item in store.rows("members")
                if item["class_name"] == "demo/Init"
                and item["member_name"] == "<clinit>"
            )
            final_call_edge_id = next(
                item["direct_edge_identity"]
                for item in store.rows("direct_edges")
                if item["symbolic_owner"] == "demo/FinalApi"
                and item["symbolic_name"] == "value"
            )
            impl_value_member = next(
                item["member_identity"]
                for item in store.rows("members")
                if item["class_name"] == "demo/Impl"
                and item["member_name"] == "value"
            )
            edges_by_identity = {
                item["direct_edge_identity"]: item
                for item in store.rows("direct_edges")
            }
            members_by_identity = {
                item["member_identity"]: item
                for item in store.rows("members")
            }
            resolved_initialization_sites = {
                (
                    members_by_identity[
                        edges_by_identity[item["direct_edge_identity"]][
                            "caller_member_identity"
                        ]
                    ]["class_name"],
                    members_by_identity[
                        edges_by_identity[item["direct_edge_identity"]][
                            "caller_member_identity"
                        ]
                    ]["member_name"],
                    item["initialized_owner"],
                    item["trigger"]["trigger_kind"],
                )
                for item in result.class_initialization_resolutions
                if item["class_initialization_status"] == "resolved"
            }

        providers = {
            (item["initiating_loader_realm_identity"], item["class_name"]): item
            for item in result.provider_bindings
        }
        self.assertEqual(result.coverage_status, "complete")
        self.assertEqual(first_resolution, second_resolution)
        self.assertEqual(cache_after[1], cache_before[1] + 1)
        self.assertEqual(cache_after[0], cache_before[0] + 1)
        self.assertLessEqual(
            len(reconciler._symbolic_member_root_cache),
            runtime_reconciler._SYMBOLIC_MEMBER_CACHE_MAX_ENTRIES,
        )
        self.assertEqual(
            runtime_reconciler._SYMBOLIC_MEMBER_CACHE_MAX_ENTRIES, 16_384
        )
        self.assertEqual(
            sum(
                statement.strip().upper() == "COMMIT"
                for statement in traced_statements
            ),
            1,
        )
        self.assertEqual(
            providers[("application-loader", "demo/Caller")]["selected_artifact_instance_identity"],
            self.instance.identity,
        )
        self.assertTrue(
            providers[("application-loader", "java/lang/String")][
                "selected_artifact_instance_identity"
            ].startswith("platform-image:")
        )
        self.assertNotIn(("application-loader", "module-info"), providers)
        caller_definition = next(
            item for item in result.class_definitions
            if item["initiating_loader_realm_identity"] == "application-loader"
            and item["class_name"] == "demo/Caller"
        )
        self.assertEqual(caller_definition["class_definition_status"], "definition_ready")
        optional_definition = next(
            item for item in result.class_definitions
            if item["initiating_loader_realm_identity"] == "application-loader"
            and item["class_name"] == "demo/OptionalEnum"
        )
        self.assertEqual(
            optional_definition["evidence"]["target_jvm_verification"][
                "failure_phase"
            ],
            "member_linkage",
        )
        impl_definition = next(
            item for item in result.class_definitions
            if item["initiating_loader_realm_identity"] == "application-loader"
            and item["class_name"] == "demo/Impl"
        )
        self.assertNotEqual(
            impl_definition["class_definition_status"], "definition_ready"
        )
        self.assertEqual(impl_definition["class_load_status"], "ready")
        self.assertTrue(result.member_resolutions)
        self.assertTrue(all(
            item["member_resolution_status"] == "resolved"
            for item in result.member_resolutions
        ))
        array_clones = [
            item for item in result.member_resolutions
            if item["symbolic_owner"].startswith("[L")
            and item["symbolic_name"] == "clone"
        ]
        self.assertTrue({
            "[Ljava/lang/Object;", "[Ldemo/OptionalEnum;",
        }.issubset({item["symbolic_owner"] for item in array_clones}))
        self.assertTrue(all(
            item["resolved_owner"] == "java/lang/Object"
            and item["jvm_array_member_semantics"] == "public_clone"
            for item in array_clones
        ))
        interface_dispatch = [
            item for item in result.dispatch_resolutions
            if item["dispatch_status"] == "exact"
            and item["implementation_target_identities"]
        ]
        self.assertTrue(interface_dispatch)
        self.assertTrue(any(
            impl_value_member in item["implementation_target_identities"]
            for item in interface_dispatch
        ))
        self.assertTrue(reconciler.concrete_subtype_index_built)
        self.assertIn(
            ("application-loader", "demo/Impl"),
            reconciler.concrete_subtype_cache["demo/Api"],
        )
        self.assertEqual(
            reconciler.artifact_security_unsupported_cache,
            {self.instance.identity: False},
        )
        final_dispatch = next(
            item for item in result.dispatch_resolutions
            if item["direct_edge_identity"] == final_call_edge_id
        )
        self.assertEqual(final_dispatch["dispatch_status"], "exact")
        self.assertEqual(len(final_dispatch["implementation_target_identities"]), 1)
        self.assertTrue(result.linkage_resolutions)
        self.assertTrue(all(
            item["type_resolution_status"] in {"resolved", "primitive_or_array_type"}
            for item in result.type_resolutions
        ))
        self.assertEqual(
            stored,
            len(result.provider_bindings)
            + len(result.class_definitions)
            + len(result.member_resolutions)
            + len(result.dispatch_resolutions)
            + len(result.type_resolutions)
            + len(result.class_initialization_resolutions)
            + len(result.linkage_resolutions)
            + len(result.resource_selections),
        )
        init_targets = {
            target
            for item in result.class_initialization_resolutions
            for target in item["initializer_target_identities"]
        }
        self.assertIn(init_member["member_identity"], init_targets)
        self.assertEqual(resolved_initialization_sites, {
            ("demo/Caller", "create", "demo/Init", "new"),
            ("demo/Caller", "staticCall", "demo/Init", "invokestatic"),
            ("demo/Caller", "staticField", "demo/Init", "getstatic"),
            (
                "demo/OptionalEnum", "valueOf", "java/lang/Enum",
                "invokestatic",
            ),
        })
        reconciler_reference = weakref.ref(reconciler)
        del reconciler
        self.assertIsNone(reconciler_reference())

    def test_reconciliation_failure_rolls_back_all_persisted_chunks(self):
        with self.build_store() as store:
            reconciler = RuntimeReconciler(
                store,
                self.profile,
                self.platform,
                analysis_context_identity="analysis-context-rollback",
            )
            original = store.add_reconciliation_payloads
            calls = 0

            def fail_after_write(*args, **kwargs):
                nonlocal calls
                calls += 1
                result = original(*args, **kwargs)
                if calls == 2:
                    raise RuntimeError("synthetic reconciliation failure")
                return result

            with patch.object(
                store,
                "add_reconciliation_payloads",
                side_effect=fail_after_write,
            ), self.assertRaisesRegex(
                RuntimeError, "synthetic reconciliation failure"
            ):
                reconciler.reconcile()

            self.assertGreaterEqual(calls, 2)
            self.assertEqual(store.counts()["reconciliation_records"], 0)
            context = store.connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                ("reconciliation_analysis_context_identity",),
            ).fetchone()
            self.assertIsNone(context)

    def test_parent_first_platform_provider_shadows_same_named_application_class(self):
        # The application artifact cannot define java.lang.String through javac,
        # but provider selection is independently testable by duplicating the
        # platform class row's symbolic name in a physical class fact.
        with self.build_store() as store:
            store.connection.execute(
                "UPDATE classes SET class_name='java/lang/String' WHERE class_name='demo/Impl'"
            )
            store.connection.commit()
            result = RuntimeReconciler(
                store,
                self.profile,
                self.platform,
                analysis_context_identity="analysis-context-shadow",
            ).reconcile()

        provider = next(
            item for item in result.provider_bindings
            if item["initiating_loader_realm_identity"] == "application-loader"
            and item["class_name"] == "java/lang/String"
        )
        self.assertTrue(provider["selected_artifact_instance_identity"].startswith("platform-image:"))

    def test_selective_retention_preserves_identity_and_persisted_evidence(self):
        retained = {
            "provider_binding", "class_definition", "resource_selection",
        }
        with self.build_store() as full_store, self.build_store() as compact_store:
            full = RuntimeReconciler(
                full_store,
                self.profile,
                self.platform,
                analysis_context_identity="analysis-context-retention",
            ).reconcile()
            compact = RuntimeReconciler(
                compact_store,
                self.profile,
                self.platform,
                analysis_context_identity="analysis-context-retention",
            ).reconcile(retain_record_kinds=retained)
            hydrated = hydrate_runtime_reconciliation(
                compact_store,
                compact,
                (
                    "member_resolution",
                    "dispatch_resolution",
                    "type_resolution",
                    "class_initialization_resolution",
                    "linkage_resolution",
                ),
            )
            full_evidence = sorted(
                full_store.rows("reconciliation_records"),
                key=lambda item: item["record_identity"],
            )
            compact_evidence = sorted(
                compact_store.rows("reconciliation_records"),
                key=lambda item: item["record_identity"],
            )

        self.assertEqual(compact.identity, full.identity)
        self.assertEqual(compact.provider_bindings, full.provider_bindings)
        self.assertEqual(compact.class_definitions, full.class_definitions)
        self.assertEqual(compact.resource_selections, full.resource_selections)
        self.assertEqual(compact.member_resolutions, ())
        self.assertEqual(compact.dispatch_resolutions, ())
        self.assertEqual(compact.type_resolutions, ())
        self.assertEqual(compact.class_initialization_resolutions, ())
        self.assertEqual(compact.linkage_resolutions, ())
        self.assertEqual(hydrated.member_resolutions, full.member_resolutions)
        self.assertEqual(hydrated.dispatch_resolutions, full.dispatch_resolutions)
        self.assertEqual(hydrated.type_resolutions, full.type_resolutions)
        self.assertEqual(
            hydrated.class_initialization_resolutions,
            full.class_initialization_resolutions,
        )
        self.assertEqual(hydrated.linkage_resolutions, full.linkage_resolutions)
        self.assertEqual(hydrated.identity, compact.identity)
        self.assertEqual(compact_evidence, full_evidence)

    def test_sequential_edge_scan_preserves_every_reconciliation_record(self):
        with (
            self.build_store() as sequential_store,
            self.build_store() as legacy_store,
        ):
            sequential = RuntimeReconciler(
                sequential_store,
                self.profile,
                self.platform,
                analysis_context_identity="analysis-context-edge-order",
            ).reconcile()
            with patch.object(
                RuntimeReconciler,
                "DIRECT_EDGE_SCAN_ORDER",
                "direct_edge_identity",
            ):
                legacy = RuntimeReconciler(
                    legacy_store,
                    self.profile,
                    self.platform,
                    analysis_context_identity="analysis-context-edge-order",
                ).reconcile()
            sequential_records = sorted(
                sequential_store.rows("reconciliation_records"),
                key=lambda item: item["record_identity"],
            )
            legacy_records = sorted(
                legacy_store.rows("reconciliation_records"),
                key=lambda item: item["record_identity"],
            )

        self.assertEqual(sequential_records, legacy_records)
        self.assertEqual(sequential.universe_identity, legacy.universe_identity)
        self.assertEqual(sequential.coverage_status, legacy.coverage_status)
        self.assertEqual(sequential.coverage_gaps, legacy.coverage_gaps)

    def test_member_resolution_remains_resolved_when_access_linkage_fails(self):
        current_source = self.root / "current-src" / "demo" / "FinalApi.java"
        current_source.parent.mkdir(parents=True)
        current_source.write_text(
            "package demo; public final class FinalApi { private String value(){ return \"new\"; } }",
            encoding="utf-8",
        )
        current_classes = self.root / "current-classes"
        current_classes.mkdir()
        completed = subprocess.run(
            ["javac", "-g", "-d", str(current_classes), str(current_source)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        current_jar = self.root / "current-app.jar"
        with zipfile.ZipFile(current_jar, "w") as archive:
            for class_file in sorted(self.classes.rglob("*.class")):
                relative = class_file.relative_to(self.classes).as_posix()
                replacement = current_classes / relative
                archive.write(replacement if replacement.is_file() else class_file, relative)
        current_sha = binary_artifact_diff._sha256_file(current_jar)
        profile_payload = dict(self.profile.payload)
        profile_payload["ordered_runtime_path_entry_descriptors"] = [{
            "logical_location": "lib/app.jar",
            "content_sha256": current_sha,
            "path_kind": "classpath",
            "slot": 0,
            "loader_realm": "application-loader",
        }]
        current_profile = RuntimeProfile(profile_payload)
        current_instance = ArtifactInstance(
            outer_artifact_sha256=current_sha,
            container_entry="<artifact>",
            content_sha256=current_sha,
            runtime_profile_identity=current_profile.identity,
            path_owner_loader_realm_identity="application-loader",
            runtime_path_kind="classpath",
            runtime_classpath_index=0,
            container_loader_policy_version="flat-parent-first-v1",
            runtime_code_source_origin_identity="deployment-app-jar",
            coord="com.acme:app:2",
        )
        snapshot = binary_artifact_diff.snapshot_archive(
            current_jar,
            artifact_instance_identity=current_instance.identity,
            expected_sha256=current_sha,
            asm_jar=self.asm_jar,
        )
        with BinaryFactStore() as store:
            store.add_artifact_snapshot(current_instance, snapshot)
            edge_id = next(
                row["direct_edge_identity"]
                for row in store.rows("direct_edges")
                if row["symbolic_owner"] == "demo/FinalApi"
                and row["symbolic_name"] == "value"
            )
            result = RuntimeReconciler(
                store,
                current_profile,
                self.platform,
                analysis_context_identity="analysis-context-access-reduced",
            ).reconcile()

        member = next(
            item for item in result.member_resolutions
            if item["direct_edge_identity"] == edge_id
        )
        linkage = next(
            item for item in result.linkage_resolutions
            if item["direct_edge_identity"] == edge_id
        )
        dispatch = next(
            item for item in result.dispatch_resolutions
            if item["direct_edge_identity"] == edge_id
        )
        self.assertEqual(member["member_resolution_status"], "resolved")
        self.assertTrue(member["resolved_member_identity"])
        self.assertEqual(linkage["linkage_status"], "illegal_access")
        self.assertEqual(dispatch["dispatch_status"], "exact")
        self.assertEqual(len(dispatch["implementation_target_identities"]), 1)

    def test_private_access_between_validated_nestmates_is_linkage_compatible(self):
        with self.build_store() as store:
            edge_id = next(
                row["direct_edge_identity"]
                for row in store.rows("direct_edges")
                if row["symbolic_owner"] == "demo/NestHost"
                and row["symbolic_name"] == "privateValue"
            )
            result = RuntimeReconciler(
                store,
                self.profile,
                self.platform,
                analysis_context_identity="analysis-context-nestmate-access",
            ).reconcile()

        member = next(
            item for item in result.member_resolutions
            if item["direct_edge_identity"] == edge_id
        )
        linkage = next(
            item for item in result.linkage_resolutions
            if item["direct_edge_identity"] == edge_id
        )
        self.assertEqual(member["member_resolution_status"], "resolved")
        self.assertEqual(member["resolved_owner"], "demo/NestHost")
        self.assertEqual(linkage["linkage_status"], "resolved")

    def test_nestmate_access_fails_closed_for_invalid_runtime_nest_metadata(self):
        with self.build_store() as store:
            reconciler = RuntimeReconciler(
                store,
                self.profile,
                self.platform,
                analysis_context_identity="analysis-context-invalid-nestmates",
            )
            reconciler.reconcile()
            host_provider = reconciler._provider(
                "application-loader", "demo/NestHost"
            )
            host_info = reconciler._class_info(host_provider)
            self.assertIsNotNone(host_info)
            original_members = host_info["nest_members"]

            self.assertFalse(reconciler._validated_nestmates(
                "demo/NestHost$Member", "other-loader",
                "demo/NestHost", "application-loader",
            ))
            self.assertFalse(reconciler._validated_nestmates(
                "other/NestHost$Member", "application-loader",
                "demo/NestHost", "application-loader",
            ))
            self.assertFalse(reconciler._validated_nestmates(
                "demo/Caller", "application-loader",
                "demo/NestHost", "application-loader",
            ))

            host_info["nest_members"] = ()
            self.assertFalse(reconciler._validated_nestmates(
                "demo/NestHost$Member", "application-loader",
                "demo/NestHost", "application-loader",
            ))
            host_info["nest_members"] = original_members
            host_info["nest_host"] = "demo/OtherHost"
            self.assertFalse(reconciler._validated_nestmates(
                "demo/NestHost$Member", "application-loader",
                "demo/NestHost", "application-loader",
            ))


if __name__ == "__main__":
    unittest.main()
