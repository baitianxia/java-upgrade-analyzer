import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_artifact_diff  # noqa: E402
from binary_decision_engine import BinaryDecisionEngine  # noqa: E402
from binary_fact_store import BinaryFactStore  # noqa: E402
from binary_first_contract import observed_delta_identity  # noqa: E402
from binary_first_model import (  # noqa: E402
    AnalysisContext,
    AnalysisScope,
    ArtifactInstance,
    RuntimeComparison,
    RuntimeProfile,
)
from binary_platform_image import JdkPlatformImage  # noqa: E402
from binary_runtime_reconciler import RuntimeReconciler  # noqa: E402


def jdk_home():
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"^\s*java\.home\s*=\s*(.+)$", completed.stderr, re.MULTILINE)
    return Path(match.group(1).strip()) if match else None


class BinaryDecisionIdentityRegressionTest(unittest.TestCase):
    def setUp(self):
        self.base_store = BinaryFactStore()
        self.current_store = BinaryFactStore()

    def tearDown(self):
        self.base_store.close()
        self.current_store.close()

    @staticmethod
    def runtime(*, providers=(), definitions=()):
        return SimpleNamespace(
            identity="unchanged-runtime",
            provider_bindings=tuple(providers),
            class_definitions=tuple(definitions),
            member_resolutions=(),
            resource_selections=(),
            coverage_status="complete",
            coverage_gaps=(),
        )

    @staticmethod
    def artifact_observation(pairing, scope, old, new):
        return observed_delta_identity(
            delta_source_kind="artifact_local",
            comparison_or_runtime_scope={
                "runtime_comparison_identity": "runtime-comparison",
                "cross_version_artifact_pairing_identity": pairing,
            },
            fact_or_mechanism_scope=scope,
            base_fingerprint=old,
            current_fingerprint=new,
        )

    def build(self, diffs, runtime):
        return BinaryDecisionEngine(
            analysis_context_identity="analysis-context",
            runtime_comparison_identity="runtime-comparison",
            base_store=self.base_store,
            current_store=self.current_store,
            base_reconciliation=runtime,
            current_reconciliation=runtime,
            artifact_local_diffs=diffs,
        ).build()

    def test_same_resource_delta_in_two_pairings_has_two_obligations(self):
        scope = {
            "entry_name": "META-INF/LICENSE",
            "name_ordinal": 0,
            "entry_kind": "resource",
        }
        diffs = []
        upstream = []
        for suffix in ("a", "b"):
            observed = self.artifact_observation(
                f"pairing-{suffix}", scope, "old-license", "new-license"
            )
            upstream.append(observed)
            diffs.append({
                "base_artifact_instance_identity": f"base-{suffix}",
                "current_artifact_instance_identity": f"current-{suffix}",
                "logical_dependency_lineage": f"dependency:{suffix}",
                "class_comparison_coverage_status": "complete",
                "entry_deltas": [{
                    "entry_scope": dict(scope),
                    "base_content_sha256": "old-license",
                    "current_content_sha256": "new-license",
                    "resource_change_category": "distribution_metadata",
                    "observed_delta_identity": observed,
                }],
            })

        bundle = self.build(diffs, self.runtime())

        self.assertEqual(len(bundle.excluded_decisions), 2)
        self.assertEqual(
            {row["observed_delta_identity"] for row in bundle.excluded_decisions},
            set(upstream),
        )
        self.assertEqual(len({
            row["disposition_obligation_identity"]
            for row in bundle.excluded_decisions
        }), 2)

    def test_same_member_delta_in_selected_and_shadowed_pairings_is_distinct(self):
        realm = "application-loader"
        class_name = "demo/Api"
        selected = "selected-artifact"
        provider = {
            "initiating_loader_realm_identity": realm,
            "class_name": class_name,
            "class_provider_status": "resolved",
            "selected_artifact_instance_identity": selected,
            "provider_binding_identity": "provider-binding",
        }
        definition = {
            "initiating_loader_realm_identity": realm,
            "class_name": class_name,
            "class_definition_status": "definition_ready",
        }
        member_scope = {
            "entry_name": f"{class_name}.class",
            "name_ordinal": 0,
            "entry_kind": "class",
            "member_kind": "method",
            "member_name": "value",
            "descriptor": "()I",
        }
        diffs = []
        upstream = []
        for suffix, artifact in (("selected", selected), ("shadowed", "shadowed-artifact")):
            entry_scope = {
                "entry_name": f"{class_name}.class",
                "name_ordinal": 0,
                "entry_kind": "class",
            }
            entry_observed = self.artifact_observation(
                f"pairing-{suffix}", entry_scope, "old-class", "new-class"
            )
            member_observed = self.artifact_observation(
                f"pairing-{suffix}", member_scope, "old-member", "new-member"
            )
            upstream.append(member_observed)
            diffs.append({
                "base_artifact_instance_identity": artifact,
                "current_artifact_instance_identity": artifact,
                "logical_dependency_lineage": f"dependency:{suffix}",
                "class_comparison_coverage_status": "complete",
                "entry_deltas": [{
                    "entry_scope": entry_scope,
                    "base_content_sha256": "old-class",
                    "current_content_sha256": "new-class",
                    "class_change_category": "implementation_changed",
                    "observed_delta_identity": entry_observed,
                    "member_deltas": [{
                        "member_scope": dict(member_scope),
                        "member_change_kind": "implementation_changed",
                        "base_member_fingerprint": "old-member",
                        "current_member_fingerprint": "new-member",
                        "observed_delta_identity": member_observed,
                    }],
                }],
            })

        bundle = self.build(
            diffs,
            self.runtime(providers=(provider,), definitions=(definition,)),
        )

        decisions = (
            *bundle.authoritative_decisions,
            *bundle.excluded_decisions,
        )
        self.assertEqual(len(decisions), 2)
        self.assertEqual(
            {row["evidence"]["upstream_artifact_observed_delta_identity"] for row in decisions},
            set(upstream),
        )
        self.assertEqual(len({
            row["disposition_obligation_identity"] for row in decisions
        }), 2)


class BinaryDecisionEngineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        home = jdk_home()
        if not shutil.which("javac") or not home or not (home / "jmods").is_dir():
            raise unittest.SkipTest("full target JDK required")
        try:
            cls.asm_jar = binary_asm_helper.resolve_asm_jar()
            cls.platform = JdkPlatformImage(home, asm_jar=cls.asm_jar)
        except Exception as error:
            raise unittest.SkipTest(str(error)) from error

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def compile_jar(self, side, return_value):
        source = self.root / side / "src" / "demo" / "Api.java"
        source.parent.mkdir(parents=True)
        source.write_text(
            f"package demo; public class Api {{ public int value(){{ return {return_value}; }} }}",
            encoding="utf-8",
        )
        classes = self.root / side / "classes"
        classes.mkdir()
        completed = subprocess.run(
            ["javac", "-g", "-d", str(classes), str(source)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        artifact = self.root / side / "api.jar"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.write(classes / "demo" / "Api.class", "demo/Api.class")
        return artifact

    def profile(self, sha):
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
            "ordered_runtime_path_entry_descriptors": [{
                "logical_location": "lib/api.jar",
                "content_sha256": sha,
                "path_kind": "classpath",
                "slot": 0,
                "loader_realm": "application-loader",
            }],
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
            "runtime_code_source_origin_mapping_identity": "deployment-origins-1",
            "runtime_security_and_package_sealing_policy_identity": "standard-unsealed-unsigned-v1",
            "active_profile_identities": ["default"],
            "external_config_snapshot_identities": [],
            "agent_transformer_plugin_profile_identities": [],
            "business_entrypoint_profile": {"classes": ["demo/Api"]},
            "runtime_class_closure_coverage_status": "complete",
            "resource_selection_coverage_status": "complete",
            "field_coverage": {key: "known" for key in required},
        })

    def instance(self, artifact, profile):
        sha = binary_artifact_diff._sha256_file(artifact)
        return ArtifactInstance(
            outer_artifact_sha256=sha,
            container_entry="<artifact>",
            content_sha256=sha,
            runtime_profile_identity=profile.identity,
            path_owner_loader_realm_identity="application-loader",
            runtime_path_kind="classpath",
            runtime_classpath_index=0,
            container_loader_policy_version="flat-parent-first-v1",
            runtime_code_source_origin_identity="deployment-api-jar",
            coord="com.acme:api:1",
        )

    def context(self, base_profile, current_profile):
        comparison = RuntimeComparison(
            base_profile,
            current_profile,
            "same_deployment_profile",
            "v1",
            ("target_jvm", "loader_topology"),
            ("dependency-artifacts",),
            (),
        )
        required = AnalysisScope.REQUIRED_FIELDS
        scope = AnalysisScope({
            "analysis_observability_scope": "binary-static-v1",
            "artifact_diff_support_manifest_identity": "artifact-v1",
            "runtime_loader_support_manifest_identity": "loader-v1",
            "class_definition_support_manifest_identity": "definition-v1",
            "runtime_fact_semantic_capability_identity": "semantic-v1",
            "runtime_fact_dynamic_capability_identity": "dynamic-v1",
            "runtime_fact_transformer_capability_identity": "transformer-none",
            "environment_equivalence_capability_identity": "equivalence-v1",
            "field_coverage": {key: "known" for key in required},
        })
        return comparison, AnalysisContext(comparison, scope)

    def snapshot_and_store(self, artifact, instance):
        snapshot = binary_artifact_diff.snapshot_archive(
            artifact,
            artifact_instance_identity=instance.identity,
            expected_sha256=instance.content_sha256,
            asm_jar=self.asm_jar,
        )
        store = BinaryFactStore()
        store.add_artifact_snapshot(instance, snapshot)
        return snapshot, store

    def test_effective_method_body_change_becomes_one_confirmed_targetable_fact(self):
        base_artifact = self.compile_jar("base", 1)
        current_artifact = self.compile_jar("current", 2)
        base_profile = self.profile(binary_artifact_diff._sha256_file(base_artifact))
        current_profile = self.profile(binary_artifact_diff._sha256_file(current_artifact))
        comparison, context = self.context(base_profile, current_profile)
        base_instance = self.instance(base_artifact, base_profile)
        current_instance = self.instance(current_artifact, current_profile)
        base_snapshot, base_store = self.snapshot_and_store(base_artifact, base_instance)
        current_snapshot, current_store = self.snapshot_and_store(current_artifact, current_instance)
        try:
            artifact_diff = binary_artifact_diff.compare_artifact_snapshots(
                base_snapshot,
                current_snapshot,
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
            bundle = BinaryDecisionEngine(
                analysis_context_identity=context.identity,
                runtime_comparison_identity=comparison.identity,
                base_store=base_store,
                current_store=current_store,
                base_reconciliation=base_runtime,
                current_reconciliation=current_runtime,
                artifact_local_diffs=(artifact_diff,),
            ).build()
        finally:
            base_store.close()
            current_store.close()

        method_facts = [
            item for item in bundle.authoritative_decisions
            if item["fact_kind"] == "method"
            and item["fact_scope"]["member_name"] == "value"
        ]
        self.assertEqual(len(method_facts), 1)
        self.assertEqual(method_facts[0]["change_fact_status"], "confirmed")
        self.assertEqual(method_facts[0]["fact_scope"]["member_change_kind"], "implementation_changed")
        self.assertEqual(bundle.diagnostic_decisions, ())
        assessment = next(
            item for item in bundle.projection_assessments
            if item["decision_identity"] == method_facts[0]["decision_identity"]
        )
        self.assertEqual(assessment["analysis_projection_status"], "targetable")
        self.assertEqual(assessment["projection_coverage_status"], "complete")
        self.assertEqual(len(bundle.active_snapshots), 4)
        self.assertFalse(any(
            item["fact_kind"] == "provider_topology"
            for item in bundle.authoritative_decisions
        ))

    def test_unknown_resource_is_candidate_and_never_formal_projection(self):
        base = self.root / "base-resource.jar"
        current = self.root / "current-resource.jar"
        with zipfile.ZipFile(base, "w") as archive:
            archive.writestr("config/custom.bin", b"old")
        with zipfile.ZipFile(current, "w") as archive:
            archive.writestr("config/custom.bin", b"new")
        base_profile = self.profile(binary_artifact_diff._sha256_file(base))
        current_profile = self.profile(binary_artifact_diff._sha256_file(current))
        comparison, context = self.context(base_profile, current_profile)
        base_instance = self.instance(base, base_profile)
        current_instance = self.instance(current, current_profile)
        base_snapshot, base_store = self.snapshot_and_store(base, base_instance)
        current_snapshot, current_store = self.snapshot_and_store(current, current_instance)
        try:
            artifact_diff = binary_artifact_diff.compare_artifact_snapshots(
                base_snapshot, current_snapshot,
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
            bundle = BinaryDecisionEngine(
                analysis_context_identity=context.identity,
                runtime_comparison_identity=comparison.identity,
                base_store=base_store,
                current_store=current_store,
                base_reconciliation=base_runtime,
                current_reconciliation=current_runtime,
                artifact_local_diffs=(artifact_diff,),
            ).build()
        finally:
            base_store.close()
            current_store.close()

        self.assertEqual(len(bundle.diagnostic_decisions), 1)
        self.assertEqual(bundle.diagnostic_decisions[0]["fact_kind"], "resource")
        self.assertFalse(bundle.formal_projections)
        self.assertEqual(bundle.candidate_projection_plans[0]["planning_status"], "unbound")

    def test_semantic_member_edges_keep_only_selected_caller_with_its_lineage(self):
        artifact = self.compile_jar("duplicate-callsite", 1)
        sha = binary_artifact_diff._sha256_file(artifact)
        profile_payload = dict(self.profile(sha).payload)
        profile_payload["ordered_runtime_path_entry_descriptors"] = [
            {
                "logical_location": f"lib/dependency-{suffix}.jar",
                "content_sha256": sha,
                "path_kind": "classpath",
                "slot": index,
                "loader_realm": "application-loader",
            }
            for index, suffix in enumerate(("a", "b"))
        ]
        profile_payload["runtime_code_source_origin_mapping_identity"] = (
            "two-dependency-origins"
        )
        profile = RuntimeProfile(profile_payload)
        instances = []
        store = BinaryFactStore()
        try:
            for index, suffix in enumerate(("a", "b")):
                instance = ArtifactInstance(
                    outer_artifact_sha256=sha,
                    container_entry="<artifact>",
                    content_sha256=sha,
                    runtime_profile_identity=profile.identity,
                    path_owner_loader_realm_identity="application-loader",
                    runtime_path_kind="classpath",
                    runtime_classpath_index=index,
                    container_loader_policy_version="flat-parent-first-v1",
                    runtime_code_source_origin_identity=f"dependency-{suffix}",
                    coord=f"com.acme:dependency-{suffix}:1",
                )
                instances.append(instance)
                snapshot = binary_artifact_diff.snapshot_archive(
                    artifact,
                    artifact_instance_identity=instance.identity,
                    expected_sha256=sha,
                    asm_jar=self.asm_jar,
                )
                store.add_artifact_snapshot(instance, snapshot)
            runtime = RuntimeReconciler(
                store,
                profile,
                self.platform,
                analysis_context_identity="analysis-context",
            ).reconcile()

            edges = BinaryDecisionEngine._semantic_member_edges(
                store,
                runtime,
                {
                    instances[0].identity: "com.acme:dependency-a",
                    instances[1].identity: "com.acme:dependency-b",
                },
            )
        finally:
            store.close()

        constructor_edges = [
            key for key in edges
            if key[2:5] == ("demo/Api", "<init>", "()V")
        ]
        self.assertEqual(len(constructor_edges), 1, tuple(edges))
        self.assertEqual(constructor_edges[0][0], "com.acme:dependency-a")
        self.assertEqual(constructor_edges[0][11], "application-loader")


if __name__ == "__main__":
    unittest.main()
