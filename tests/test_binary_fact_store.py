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
from binary_fact_store import BinaryFactStore, BinaryFactStoreError  # noqa: E402
from binary_first_model import ArtifactInstance  # noqa: E402


class BinaryFactStoreTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("java") or not shutil.which("javac"):
            raise unittest.SkipTest("JDK required")
        try:
            cls.asm_jar = binary_asm_helper.resolve_asm_jar()
        except binary_asm_helper.BinaryAsmError as error:
            raise unittest.SkipTest(str(error)) from error

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        source = self.root / "src" / "demo" / "Caller.java"
        source.parent.mkdir(parents=True)
        source.write_text(
            """
            package demo;
            public class Caller {
              private String field = "value";
              public String call() { return field.trim(); }
              public Runnable dynamic() { return this::call; }
            }
            """,
            encoding="utf-8",
        )
        classes = self.root / "classes"
        classes.mkdir()
        completed = subprocess.run(
            ["javac", "-g", "-d", str(classes), str(source)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.class_bytes = (classes / "demo" / "Caller.class").read_bytes()

    def tearDown(self):
        self.temp.cleanup()

    def make_jar(self, name="caller.jar"):
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("demo/Caller.class", self.class_bytes)
            archive.writestr("META-INF/services/demo.Service", "demo.Caller\n")
        return path

    def instance(self, artifact, slot, *, coord="com.acme:caller:1"):
        sha = binary_artifact_diff._sha256_file(artifact)
        return ArtifactInstance(
            outer_artifact_sha256=sha,
            container_entry="<artifact>",
            content_sha256=sha,
            runtime_profile_identity="runtime-1",
            path_owner_loader_realm_identity="application-loader",
            runtime_path_kind="classpath",
            runtime_classpath_index=slot,
            container_loader_policy_version="flat-parent-first-v1",
            runtime_code_source_origin_identity=f"origin-{slot}",
            coord=coord,
        )

    def snapshot(self, artifact, instance):
        return binary_artifact_diff.snapshot_archive(
            artifact,
            artifact_instance_identity=instance.identity,
            expected_sha256=instance.content_sha256,
            asm_jar=self.asm_jar,
        )

    def test_ingests_members_edges_bci_resources_and_stable_content_identity(self):
        artifact = self.make_jar()
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)

        with BinaryFactStore() as store:
            counts = store.add_artifact_snapshot(instance, snapshot)
            identity = store.content_identity()
            methods = store.rows("members", where="member_kind='method'")
            edges = store.rows("direct_edges")

        self.assertEqual(counts["classes"], 1)
        self.assertGreaterEqual(counts["members"], 4)
        self.assertGreater(counts["edges"], 0)
        self.assertEqual(counts["resources"], 1)
        self.assertEqual(len(identity), 64)
        self.assertIn("call", {item["member_name"] for item in methods})
        self.assertTrue(all(item["bytecode_offset"] >= 0 for item in edges))
        self.assertIn("invokedynamic_bootstrap", {item["edge_kind"] for item in edges})
        self.assertTrue(any(item["edge_kind"].startswith("invokedynamic_handle_") for item in edges))
        self.assertIn("field", {item["edge_kind"] for item in edges})
        self.assertIn("method", {item["edge_kind"] for item in edges})

    def test_same_coordinate_different_physical_instances_are_not_conflicts(self):
        first_artifact = self.make_jar("first.jar")
        second_artifact = self.make_jar("second.jar")
        first = self.instance(first_artifact, 0)
        second = self.instance(second_artifact, 1)
        first_snapshot = self.snapshot(first_artifact, first)
        second_snapshot = self.snapshot(second_artifact, second)

        with BinaryFactStore() as store:
            store.add_artifact_snapshot(first, first_snapshot)
            store.add_artifact_snapshot(second, second_snapshot)
            instances = store.rows(
                "artifact_instances", where="coord=?", parameters=(first.coord,)
            )

        self.assertEqual(len(instances), 2)
        self.assertNotEqual(instances[0]["artifact_instance_identity"], instances[1]["artifact_instance_identity"])

    def test_reingesting_same_physical_identity_fails_closed(self):
        artifact = self.make_jar()
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)

        with BinaryFactStore() as store:
            store.add_artifact_snapshot(instance, snapshot)
            with self.assertRaises(BinaryFactStoreError) as error:
                store.add_artifact_snapshot(instance, snapshot)

        self.assertEqual(error.exception.reason_code, "FACT_STORE_IDENTITY_CONFLICT")


if __name__ == "__main__":
    unittest.main()
