import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_artifact_diff  # noqa: E402
import binary_trace_engine  # noqa: E402
from binary_decision_engine import BinaryDecisionEngine  # noqa: E402
from binary_fact_store import BinaryFactStore  # noqa: E402
from binary_first_model import (  # noqa: E402
    AnalysisContext, AnalysisScope, ArtifactInstance, RuntimeComparison, RuntimeProfile,
)
from binary_platform_image import JdkPlatformImage  # noqa: E402
from binary_runtime_reconciler import RuntimeReconciler  # noqa: E402
from binary_trace_engine import BinaryTraceEngine, build_binary_traces  # noqa: E402


def current_jdk_home():
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"^\s*java\.home\s*=\s*(.+)$", completed.stderr, re.MULTILINE)
    return Path(match.group(1).strip()) if match else None


class BinaryTraceFastPathTest(unittest.TestCase):
    def discovery(self):
        return SimpleNamespace(
            exact_member_identities=("entry-member",),
            possible_member_identities=(),
            identity="entrypoint-discovery-1",
            coverage_gaps=(),
            records=({"member_identity": "entry-member"},),
        )

    def empty_discovery(self, *, coverage_gaps=()):
        return SimpleNamespace(
            exact_member_identities=(),
            possible_member_identities=(),
            identity="entrypoint-discovery-empty",
            coverage_gaps=tuple(coverage_gaps),
            records=(),
        )

    def decisions(self, **overrides):
        values = {
            "formal_projections": (),
            "candidate_projection_plans": (),
            "authoritative_decisions": (),
            "analysis_context_identity": "analysis-context-1",
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_no_target_fast_path_preserves_empty_results_and_entrypoints(self):
        discovery = self.discovery()
        runtime = SimpleNamespace(coverage_gaps=())
        with patch.object(
            binary_trace_engine,
            "discover_binary_entrypoints",
            return_value=discovery,
        ), patch.object(binary_trace_engine, "BinaryTraceEngine") as engine:
            result = build_binary_traces(
                object(), object(), runtime, self.decisions()
            )

        engine.assert_not_called()
        self.assertEqual(result.formal_results, ())
        self.assertEqual(result.candidate_results, ())
        self.assertEqual(result.resource_activation_results, ())
        self.assertEqual(result.entrypoint_records, discovery.records)
        self.assertEqual(result.coverage_status, "complete")
        self.assertEqual(
            result.graph_stats["graph_materialization_status"], "not_required"
        )

    def test_contract_access_reduction_is_linkage_incompatible_without_a_path(self):
        decision = {
            "fact_scope": {"member_change_kind": "contract_changed"},
            "evidence": {
                "base_contract": {"access": 0x0001},
                "current_contract": {"access": 0x0002},
            },
        }

        self.assertTrue(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )
        decision["evidence"]["current_contract"]["access"] = 0x0001
        self.assertFalse(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )

    def test_observed_legal_protected_path_refines_access_reduction(self):
        decision = {
            "fact_scope": {
                "member_kind": "method",
                "member_change_kind": "contract_changed",
            },
            "evidence": {
                "base_contract": {"access": 0x0001},
                "current_contract": {"access": 0x0004},
            },
        }

        self.assertTrue(
            binary_trace_engine._access_reduction_is_legal_on_observed_paths(
                decision,
                has_path=True,
                resolution_statuses={"resolved"},
                linkage_statuses={"resolved"},
                caller_definition_statuses={"definition_ready"},
            )
        )
        for has_path, resolutions, linkages in (
            (False, {"resolved"}, {"resolved"}),
            (True, {"illegal_access"}, {"illegal_access"}),
            (True, {"resolved"}, {"illegal_access"}),
        ):
            with self.subTest(
                has_path=has_path,
                resolutions=resolutions,
                linkages=linkages,
            ):
                self.assertFalse(
                    binary_trace_engine._access_reduction_is_legal_on_observed_paths(
                        decision,
                        has_path=has_path,
                        resolution_statuses=resolutions,
                        linkage_statuses=linkages,
                        caller_definition_statuses={"definition_ready"},
                    )
                )

        decision["evidence"]["current_contract"]["access"] |= 0x0010
        self.assertFalse(
            binary_trace_engine._access_reduction_is_legal_on_observed_paths(
                decision,
                has_path=True,
                resolution_statuses={"resolved"},
                linkage_statuses={"resolved"},
                caller_definition_statuses={"definition_ready"},
            )
        )

        decision["evidence"]["current_contract"]["access"] = 0x0004
        self.assertFalse(
            binary_trace_engine._access_reduction_is_legal_on_observed_paths(
                decision,
                has_path=True,
                resolution_statuses={"resolved"},
                linkage_statuses={"resolved"},
                caller_definition_statuses={"verification_failed"},
            )
        )

    def test_concrete_method_becoming_abstract_breaks_binary_compatibility(self):
        decision = {
            "fact_scope": {"member_change_kind": "contract_changed"},
            "evidence": {
                "base_contract": {"access": 0x0001},
                "current_contract": {"access": 0x0001 | 0x0400},
            },
        }

        self.assertTrue(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )
        decision["evidence"]["base_contract"]["access"] |= 0x0400
        self.assertFalse(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )

    def test_non_final_method_becoming_final_breaks_binary_compatibility(self):
        decision = {
            "fact_scope": {
                "member_kind": "method",
                "member_change_kind": "contract_changed",
            },
            "evidence": {
                "base_contract": {"access": 0x0001},
                "current_contract": {"access": 0x0001 | 0x0010},
            },
        }

        self.assertTrue(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )
        decision["fact_scope"]["member_kind"] = "field"
        self.assertFalse(
            binary_trace_engine._contract_change_breaks_linkage(decision)
        )

    def test_definitive_missing_linkage_edges_are_exact(self):
        self.assertEqual(
            binary_trace_engine._unresolved_edge_certainty("no_such_member"),
            "exact",
        )
        for status in ("no_class_definition", "class_definition_failed"):
            with self.subTest(status=status):
                self.assertEqual(
                    binary_trace_engine._unresolved_edge_certainty(
                        status, paired_artifact_change=True,
                    ),
                    "exact",
                )
                self.assertEqual(
                    binary_trace_engine._unresolved_edge_certainty(status),
                    "possible",
                )
        for status in ("ambiguous", "unresolved", "unsupported"):
            with self.subTest(status=status):
                self.assertEqual(
                    binary_trace_engine._unresolved_edge_certainty(status),
                    "possible",
                )

    def test_every_trace_consumer_routes_to_full_graph_builder(self):
        cases = {
            "formal": self.decisions(formal_projections=({"identity": "p"},)),
            "targetable_candidate": self.decisions(
                candidate_projection_plans=({"planning_status": "targetable"},)
            ),
            "service_activation": self.decisions(authoritative_decisions=({
                "fact_kind": "resource",
                "fact_scope": {"resource_name": "META-INF/services/demo.Api"},
            },)),
        }
        for name, decisions in cases.items():
            with self.subTest(name=name), patch.object(
                binary_trace_engine,
                "discover_binary_entrypoints",
                return_value=self.discovery(),
            ), patch.object(binary_trace_engine, "BinaryTraceEngine") as engine:
                expected = object()
                engine.return_value.build.return_value = expected
                actual = build_binary_traces(
                    object(), object(), SimpleNamespace(coverage_gaps=()), decisions
                )

            self.assertIs(actual, expected)
            engine.assert_called_once()

    def test_formal_results_with_no_entrypoints_route_to_graph_free_builder(self):
        decisions = self.decisions(formal_projections=({"identity": "p"},))
        with patch.object(
            binary_trace_engine,
            "discover_binary_entrypoints",
            return_value=self.empty_discovery(),
        ), patch.object(binary_trace_engine, "BinaryTraceEngine") as engine:
            expected = object()
            engine.return_value.build.return_value = expected
            actual = build_binary_traces(
                object(), object(), SimpleNamespace(coverage_gaps=()), decisions
            )

        self.assertIs(actual, expected)
        engine.assert_called_once()
        self.assertFalse(engine.call_args.kwargs["materialize_graph"])

    def test_service_activation_with_no_entrypoints_still_uses_full_graph(self):
        decisions = self.decisions(authoritative_decisions=({
            "fact_kind": "resource",
            "fact_scope": {"resource_name": "META-INF/services/demo.Api"},
        },))
        with patch.object(
            binary_trace_engine,
            "discover_binary_entrypoints",
            return_value=self.empty_discovery(),
        ), patch.object(binary_trace_engine, "BinaryTraceEngine") as engine:
            expected = object()
            engine.return_value.build.return_value = expected
            actual = build_binary_traces(
                object(), object(), SimpleNamespace(coverage_gaps=()), decisions
            )

        self.assertIs(actual, expected)
        engine.assert_called_once()
        self.assertNotIn("materialize_graph", engine.call_args.kwargs)


class BinaryTraceEngineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        home = current_jdk_home()
        if not shutil.which("javac") or not home or not (home / "jmods").is_dir():
            raise unittest.SkipTest("full JDK required")
        cls.asm_jar = binary_asm_helper.resolve_asm_jar()
        cls.platform = JdkPlatformImage(home, asm_jar=cls.asm_jar)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def compile_side(self, side, value):
        vendor_source = self.root / side / "vendor-src" / "vendor" / "Api.java"
        vendor_source.parent.mkdir(parents=True)
        vendor_source.write_text(
            f"package vendor; public final class Api {{ public static int work(){{ return {value}; }} }}",
            encoding="utf-8",
        )
        vendor_classes = self.root / side / "vendor-classes"
        vendor_classes.mkdir()
        subprocess.run(
            ["javac", "-g", "-d", str(vendor_classes), str(vendor_source)],
            check=True,
            capture_output=True,
        )
        vendor_jar = self.root / side / "vendor.jar"
        with zipfile.ZipFile(vendor_jar, "w") as archive:
            archive.write(vendor_classes / "vendor" / "Api.class", "vendor/Api.class")

        business_source = self.root / side / "business-src" / "biz" / "Main.java"
        business_source.parent.mkdir(parents=True)
        business_source.write_text(
            "package biz; public class Main { public int entry(){ return vendor.Api.work(); } }",
            encoding="utf-8",
        )
        business_classes = self.root / side / "business-classes"
        business_classes.mkdir()
        subprocess.run(
            ["javac", "-g", "-cp", str(vendor_jar), "-d", str(business_classes), str(business_source)],
            check=True,
            capture_output=True,
        )
        business_jar = self.root / side / "business.jar"
        with zipfile.ZipFile(business_jar, "w") as archive:
            archive.write(business_classes / "biz" / "Main.class", "biz/Main.class")
        return business_jar, vendor_jar

    def profile(self, business_sha, vendor_sha):
        required = RuntimeProfile.REQUIRED_FIELDS
        return RuntimeProfile({
            "target_jvm": {
                "vendor": self.platform.release.get("IMPLEMENTOR"),
                "major": self.platform.java_major,
                "version": self.platform.release.get("JAVA_VERSION"),
            },
            "runtime_platform_image_identity": self.platform.identity,
            "target_os": "test-os",
            "target_arch": self.platform.release.get("OS_ARCH", "unknown"),
            "container_and_launcher_kind": "java-classpath",
            "ordered_runtime_path_entry_descriptors": [
                {
                    "logical_location": "app/business.jar", "content_sha256": business_sha,
                    "path_kind": "business_classes", "slot": 0, "loader_realm": "application-loader",
                },
                {
                    "logical_location": "lib/vendor.jar", "content_sha256": vendor_sha,
                    "path_kind": "classpath", "slot": 1, "loader_realm": "application-loader",
                },
            ],
            "loader_topology": {
                "coverage_status": "complete",
                "entrypoint_realms": ["application-loader"],
                "realms": [
                    {"identity": "platform-loader", "kind": "platform", "module_mode": "named-platform"},
                    {
                        "identity": "application-loader", "kind": "application",
                        "parent": "platform-loader", "delegation": "parent_first", "module_mode": "unnamed",
                    },
                ],
            },
            "runtime_code_source_origin_mapping_identity": "origins-1",
            "runtime_security_and_package_sealing_policy_identity": "standard-unsealed-unsigned-v1",
            "active_profile_identities": ["default"],
            "external_config_snapshot_identities": [],
            "agent_transformer_plugin_profile_identities": [],
            "business_entrypoint_profile": {
                "coverage_status": "complete",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "biz/Main",
                    "member_name": "entry",
                    "descriptor": "()I",
                }],
            },
            "runtime_class_closure_coverage_status": "complete",
            "resource_selection_coverage_status": "complete",
            "field_coverage": {key: "known" for key in required},
        })

    def instance(self, artifact, profile, slot, kind, origin, coord):
        sha = binary_artifact_diff._sha256_file(artifact)
        return ArtifactInstance(
            outer_artifact_sha256=sha,
            container_entry="<artifact>",
            content_sha256=sha,
            runtime_profile_identity=profile.identity,
            path_owner_loader_realm_identity="application-loader",
            runtime_path_kind=kind,
            runtime_classpath_index=slot,
            container_loader_policy_version="flat-parent-first-v1",
            runtime_code_source_origin_identity=origin,
            coord=coord,
        )

    def build_store(self, artifacts, profile):
        store = BinaryFactStore()
        snapshots = {}
        for artifact, instance in artifacts:
            snapshot = binary_artifact_diff.snapshot_archive(
                artifact,
                artifact_instance_identity=instance.identity,
                expected_sha256=instance.content_sha256,
                asm_jar=self.asm_jar,
            )
            store.add_artifact_snapshot(instance, snapshot)
            snapshots[instance.coord] = snapshot
        return store, snapshots

    def test_exact_business_entry_path_reaches_changed_dependency_method(self):
        base_business, base_vendor = self.compile_side("base", 1)
        current_business, current_vendor = self.compile_side("current", 2)
        base_profile = self.profile(
            binary_artifact_diff._sha256_file(base_business),
            binary_artifact_diff._sha256_file(base_vendor),
        )
        current_profile = self.profile(
            binary_artifact_diff._sha256_file(current_business),
            binary_artifact_diff._sha256_file(current_vendor),
        )
        comparison = RuntimeComparison(
            base_profile, current_profile, "same_deployment_profile", "v1",
            ("target_jvm", "loader_topology"), ("dependency-artifacts",), (),
        )
        scope_required = AnalysisScope.REQUIRED_FIELDS
        scope = AnalysisScope({
            "analysis_observability_scope": "binary-static-v1",
            "artifact_diff_support_manifest_identity": "artifact-v1",
            "runtime_loader_support_manifest_identity": "loader-v1",
            "class_definition_support_manifest_identity": "definition-v1",
            "runtime_fact_semantic_capability_identity": "semantic-v1",
            "runtime_fact_dynamic_capability_identity": "dynamic-v1",
            "runtime_fact_transformer_capability_identity": "transformer-none",
            "environment_equivalence_capability_identity": "equivalence-v1",
            "field_coverage": {key: "known" for key in scope_required},
        })
        context = AnalysisContext(comparison, scope)
        base_business_instance = self.instance(
            base_business, base_profile, 0, "business_classes", "origin-business", "business",
        )
        base_vendor_instance = self.instance(
            base_vendor, base_profile, 1, "classpath", "origin-vendor", "vendor",
        )
        current_business_instance = self.instance(
            current_business, current_profile, 0, "business_classes", "origin-business", "business",
        )
        current_vendor_instance = self.instance(
            current_vendor, current_profile, 1, "classpath", "origin-vendor", "vendor",
        )
        base_store, base_snapshots = self.build_store(
            ((base_business, base_business_instance), (base_vendor, base_vendor_instance)), base_profile
        )
        current_store, current_snapshots = self.build_store(
            ((current_business, current_business_instance), (current_vendor, current_vendor_instance)), current_profile
        )
        try:
            artifact_diff = binary_artifact_diff.compare_artifact_snapshots(
                base_snapshots["vendor"], current_snapshots["vendor"],
                comparison_or_runtime_scope={"runtime_comparison_identity": comparison.identity},
            )
            base_runtime = RuntimeReconciler(
                base_store, base_profile, self.platform,
                analysis_context_identity=context.identity,
            ).reconcile()
            current_runtime = RuntimeReconciler(
                current_store, current_profile, self.platform,
                analysis_context_identity=context.identity,
            ).reconcile()
            decisions = BinaryDecisionEngine(
                analysis_context_identity=context.identity,
                runtime_comparison_identity=comparison.identity,
                base_store=base_store,
                current_store=current_store,
                base_reconciliation=base_runtime,
                current_reconciliation=current_runtime,
                artifact_local_diffs=(artifact_diff,),
            ).build()
            traces = BinaryTraceEngine(
                current_store, current_profile, current_runtime, decisions
            ).build()
        finally:
            base_store.close()
            current_store.close()

        work_decision = next(
            item for item in decisions.authoritative_decisions
            if item["fact_kind"] == "method" and item["fact_scope"]["member_name"] == "work"
        )
        work_assessment = next(
            item for item in decisions.projection_assessments
            if item["decision_identity"] == work_decision["decision_identity"]
        )
        result = next(
            item for item in traces.formal_results
            if item["projection_assessment_identity"] == work_assessment["projection_assessment_identity"]
        )
        self.assertEqual(traces.coverage_status, "complete")
        self.assertEqual(result["reachability_status"], "reachable")
        self.assertTrue(result["is_reachable"])
        self.assertTrue(result["exact_path_exists"])
        self.assertEqual(result["impact_conclusion"], "probable_impact")
        self.assertEqual(
            result["static_linkage_status"], "compatible_or_not_applicable"
        )
        self.assertEqual(result["runtime_verification_status"], "required_not_executed")
        self.assertFalse(result["runtime_verification_executed_by_system"])
        self.assertEqual(len(result["paths"]), 1)
        self.assertEqual(
            result["batch_graph_identity"],
            traces.formal_results[0]["batch_graph_identity"],
        )
        self.assertEqual(
            traces.graph_stats["batch_transition_build"],
            "shared_target_independent_v1",
        )
        self.assertGreater(traces.graph_stats["exact_scc_count"], 0)
        self.assertGreater(traces.graph_stats["possible_scc_count"], 0)


if __name__ == "__main__":
    unittest.main()
