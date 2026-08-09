import os
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
from binary_fact_store import BinaryFactStore  # noqa: E402
from binary_first_model import ArtifactInstance, RuntimeProfile  # noqa: E402
from binary_platform_image import JdkPlatformImage  # noqa: E402
from binary_runtime_reconciler import RuntimeReconciler  # noqa: E402


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
            "demo/Api.java": "package demo; public interface Api { String value(); }",
            "demo/Impl.java": "package demo; public class Impl implements Api { public String value(){ return \"ok\"; } }",
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
                  public Runnable dynamic(Api api) { return api::value; }
                  public Init create() { return new Init(); }
                  public int staticCall() { return Init.value(); }
                  public int staticField() { return Init.VALUE; }
                  public Class<?> literal() { return Init.class; }
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

    def test_provider_definition_member_resolution_and_dispatch_are_physical(self):
        with self.build_store() as store:
            result = RuntimeReconciler(
                store,
                self.profile,
                self.platform,
                analysis_context_identity="analysis-context-1",
            ).reconcile()
            stored = store.counts()["reconciliation_records"]
            init_member = next(
                item for item in store.rows("members")
                if item["class_name"] == "demo/Init"
                and item["member_name"] == "<clinit>"
            )

        providers = {
            (item["initiating_loader_realm_identity"], item["class_name"]): item
            for item in result.provider_bindings
        }
        self.assertEqual(result.coverage_status, "complete")
        self.assertEqual(
            providers[("application-loader", "demo/Caller")]["selected_artifact_instance_identity"],
            self.instance.identity,
        )
        self.assertTrue(
            providers[("application-loader", "java/lang/String")][
                "selected_artifact_instance_identity"
            ].startswith("platform-image:")
        )
        caller_definition = next(
            item for item in result.class_definitions
            if item["initiating_loader_realm_identity"] == "application-loader"
            and item["class_name"] == "demo/Caller"
        )
        self.assertEqual(caller_definition["class_definition_status"], "definition_ready")
        self.assertTrue(result.member_resolutions)
        self.assertTrue(all(
            item["member_resolution_status"] == "resolved"
            for item in result.member_resolutions
        ))
        interface_dispatch = [
            item for item in result.dispatch_resolutions
            if item["dispatch_status"] == "possible"
        ]
        self.assertTrue(interface_dispatch)
        self.assertTrue(any(item["implementation_target_identities"] for item in interface_dispatch))
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
        self.assertEqual(
            sum(
                item["class_initialization_status"] == "resolved"
                for item in result.class_initialization_resolutions
            ),
            3,
            "new/invokestatic/getstatic initialize; class literal must not",
        )

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


if __name__ == "__main__":
    unittest.main()
