import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from binary_runtime_materializer import (  # noqa: E402
    BinaryRuntimeMaterializationError,
    materialize_binary_pipeline_config,
)


class BinaryRuntimeMaterializerTest(unittest.TestCase):
    @staticmethod
    def write_artifact(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return hashlib.sha256(content).hexdigest()

    def fixture(self, root):
        report = root / ".upgrade-report"
        dependencies = report / "evidence" / "dependencies"
        dependencies.mkdir(parents=True)
        items = []
        business = []
        provenance = []
        for side, version in (("base", "1"), ("current", "2")):
            outer = root / f"{side}-outer.jar"
            outer_sha = self.write_artifact(outer, f"outer-{side}".encode())
            business_path = root / f"{side}-business.jar"
            business_sha = self.write_artifact(
                business_path, f"business-{side}".encode()
            )
            dependency = root / f"{side}-dependency.jar"
            dependency_sha = self.write_artifact(
                dependency, f"dependency-{side}".encode()
            )
            business.append({
                "side": side,
                "retained_path": str(business_path),
                "sha256": business_sha,
                "outer_artifact_path": str(outer),
                "outer_artifact_sha256": outer_sha,
                "container_and_launcher_kind": "spring-boot-executable-jar",
            })
            items.append({
                "side": side,
                "coord": "com.acme:library",
                "version": version,
                "lib_entry": f"BOOT-INF/lib/library-{version}.jar",
                "retained_path": str(dependency),
                "nested_jar_sha256": dependency_sha,
                "outer_artifact_sha256": outer_sha,
                "runtime_classpath_index": 0,
                "purposes": ["binary_runtime"],
            })
            jdk = root / f"{side}-jdk"
            jdk.mkdir()
            provenance.append({
                "side": side,
                "target_module": "app",
                "jdk_home": str(jdk),
                "artifact_sha256": outer_sha,
            })
        (dependencies / "dependency_jars.json").write_text(
            json.dumps({
                "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
                "items": items,
                "business_artifacts": business,
                "runtime_closure": {
                    side: {
                        "coverage_status": "complete",
                        "coverage_gaps": [],
                    }
                    for side in ("base", "current")
                },
            }),
            encoding="utf-8",
        )
        (dependencies / "build_provenance.json").write_text(
            json.dumps({"sides": provenance}), encoding="utf-8"
        )
        return report

    def test_materializes_two_complete_ordered_runtime_sides(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            config = materialize_binary_pipeline_config(report)

        self.assertEqual(
            config["runtime_comparison"]["comparison_intent"],
            "release_snapshot",
        )
        for side in ("base", "current"):
            artifacts = config[side]["artifacts"]
            self.assertEqual([item["slot"] for item in artifacts], [0, 1])
            self.assertEqual(artifacts[0]["path_kind"], "business_classes")
            self.assertEqual(artifacts[1]["lineage"], "com.acme:library")
            self.assertTrue(
                artifacts[1]["coord"].startswith("com.acme:library:")
            )
            self.assertEqual(
                config[side]["runtime_profile"][
                    "runtime_class_closure_coverage_status"
                ],
                "complete",
            )

    def test_missing_one_side_business_artifact_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = (
                report / "evidence" / "dependencies" / "dependency_jars.json"
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["business_artifacts"] = [
                item for item in manifest["business_artifacts"]
                if item["side"] != "base"
            ]
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_BUSINESS_ARTIFACT_CARDINALITY",
            ):
                materialize_binary_pipeline_config(report)

    def test_changed_artifact_only_v2_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = report / "evidence" / "dependencies" / "dependency_jars.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["schema"] = "java-upgrade-analyzer.step1-dependency-jars.v2"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(
                BinaryRuntimeMaterializationError,
                "BINARY_RUNTIME_MANIFEST_SCHEMA_INVALID",
            ):
                materialize_binary_pipeline_config(report)

    def test_packaged_properties_materialize_profiles_and_condition_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.fixture(Path(tmp))
            manifest_path = report / "evidence" / "dependencies" / "dependency_jars.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for business in manifest["business_artifacts"]:
                path = Path(business["retained_path"])
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(
                        "application.properties",
                        "spring.profiles.active=prod\nfeature.scheduler=true\n",
                    )
                    archive.writestr(
                        "application-prod.properties",
                        "feature.mode=live\n",
                    )
                business["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            config = materialize_binary_pipeline_config(report)

        for side in ("base", "current"):
            profile = config[side]["runtime_profile"]
            self.assertEqual(profile["active_profile_identities"], ["prod"])
            self.assertEqual(
                profile["resolved_configuration_properties"]["feature.mode"],
                "live",
            )
            self.assertEqual(profile["resource_selection_coverage_status"], "complete")


if __name__ == "__main__":
    unittest.main()
