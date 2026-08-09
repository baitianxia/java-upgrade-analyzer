import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import zipfile


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_artifact_diff  # noqa: E402
from binary_decision_engine import BinaryDecisionEngine  # noqa: E402
from binary_fact_store import BinaryFactStore  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
