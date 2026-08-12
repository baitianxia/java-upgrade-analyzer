import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import zipfile
import json


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
              public Class<?>[] arrayLiterals() { return new Class<?>[]{String[].class, int[].class}; }
              public Object matrix() { return new String[1][1]; }
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

    def test_unknown_resource_does_not_taint_successful_class_fact_coverage(self):
        artifact = self.make_jar("class-and-unknown-resource.jar")
        with zipfile.ZipFile(artifact, "a") as archive:
            archive.writestr("config/custom.bin", b"opaque")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)

        self.assertEqual(snapshot.comparison_coverage_status, "partial")
        self.assertEqual(snapshot.class_fact_coverage_status, "complete")
        with BinaryFactStore() as store:
            store.add_artifact_snapshot(instance, snapshot)
            row = store.rows("artifact_instances")[0]

        self.assertEqual(row["coverage_status"], "complete")

    def test_array_class_literals_and_multianewarray_keep_jvm_descriptors(self):
        artifact = self.make_jar("array-types.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)

        with BinaryFactStore() as store:
            store.add_artifact_snapshot(instance, snapshot)
            edges = store.rows("direct_edges", where="edge_kind='type'")

        observed = {
            (row["symbolic_owner"], row["symbolic_descriptor"])
            for row in edges
        }
        self.assertIn(("[Ljava/lang/String;", "[Ljava/lang/String;"), observed)
        self.assertIn(("[I", "[I"), observed)
        self.assertIn(("[[Ljava/lang/String;", "[[Ljava/lang/String;"), observed)

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

    def test_reconciliation_payloads_are_streamed_and_compressed(self):
        database = self.root / "compressed.sqlite"
        records = (
            {
                "analysis_context_identity": "context",
                "record_kind": "member_resolution",
                "status": "resolved",
                "subject_identity": f"subject-{index}",
                "payload": {
                    "direct_edge_identity": f"edge-{index}",
                    "member_resolution_status": "resolved",
                    "repeated_evidence": "x" * 5_000,
                },
            }
            for index in range(100)
        )
        with BinaryFactStore(database) as store:
            identities = store.add_reconciliation_records(
                records, collect_identities=False
            )
            count = store.counts()["reconciliation_records"]
            compressed_bytes = store.connection.execute(
                "SELECT SUM(length(payload_zlib)) FROM reconciliation_records"
            ).fetchone()[0]
            identity_bytes = store.connection.execute(
                "SELECT length(chunk_identity) FROM reconciliation_records LIMIT 1"
            ).fetchone()[0]
            chunk_count = store.connection.execute(
                "SELECT COUNT(*) FROM reconciliation_records"
            ).fetchone()[0]
            columns = {
                row[1] for row in store.connection.execute(
                    "PRAGMA table_info(reconciliation_records)"
                )
            }
            restored = store.rows("reconciliation_records")

        self.assertEqual(identities, [])
        self.assertEqual(count, 100)
        self.assertIn("payload_zlib", columns)
        self.assertNotIn("payload_json", columns)
        self.assertNotIn("analysis_context_identity", columns)
        self.assertNotIn("subject_identity", columns)
        self.assertNotIn("status", columns)
        self.assertEqual(identity_bytes, 32)
        self.assertEqual(chunk_count, 1)
        self.assertLess(compressed_bytes, 50_000)
        self.assertEqual(len(restored), 100)
        self.assertTrue(all(row["analysis_context_identity"] == "context" for row in restored))
        self.assertTrue(all(row["record_kind"] == "member_resolution" for row in restored))
        self.assertTrue(all(len(row["record_identity"]) == 64 for row in restored))

    def test_reconciliation_chunks_preserve_counts_across_kind_boundaries(self):
        records = [
            {
                "analysis_context_identity": "context",
                "record_kind": "member_resolution" if index < 2_501 else "dispatch_resolution",
                "status": "resolved",
                "subject_identity": f"subject-{index}",
                "payload": {"index": index, "value": "shared" * 20},
            }
            for index in range(4_100)
        ]
        with BinaryFactStore() as store:
            store.add_reconciliation_records(records, collect_identities=False)
            logical_count = store.counts()["reconciliation_records"]
            physical_chunks = store.connection.execute(
                "SELECT COUNT(*) FROM reconciliation_records"
            ).fetchone()[0]
            restored = store.rows("reconciliation_records")
            member_payloads = list(
                store.reconciliation_payloads("member_resolution")
            )
            dispatch_payloads = list(
                store.reconciliation_payloads("dispatch_resolution")
            )

        self.assertEqual(logical_count, 4_100)
        self.assertEqual(physical_chunks, 3)
        self.assertEqual(len(restored), 4_100)
        self.assertEqual(
            {row["record_kind"] for row in restored},
            {"member_resolution", "dispatch_resolution"},
        )
        self.assertEqual(
            {row["index"] for row in member_payloads}, set(range(2_501))
        )
        self.assertEqual(
            {row["index"] for row in dispatch_payloads}, set(range(2_501, 4_100))
        )

    def test_secondary_indexes_can_be_deferred_until_bulk_load_finishes(self):
        artifact = self.make_jar("deferred-indexes.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)
        expected_indexes = {
            "artifact_instances_coord",
            "artifact_instances_runtime_slot",
            "archive_entries_class",
            "classes_runtime_lookup",
            "members_symbolic_lookup",
            "direct_edges_symbolic_target",
            "reconciliation_records_kind",
        }

        with BinaryFactStore(defer_secondary_indexes=True) as store:
            before = {
                row[0] for row in store.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                )
            }
            store.add_artifact_snapshot(instance, snapshot)
            store.ensure_secondary_indexes()
            after = {
                row[0] for row in store.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                )
            }
            class_count = store.connection.execute(
                "SELECT COUNT(*) FROM classes"
            ).fetchone()[0]

        self.assertTrue(expected_indexes.isdisjoint(before))
        self.assertTrue(expected_indexes.issubset(after))
        self.assertEqual(class_count, 1)

    def test_mid_archive_batch_flush_preserves_exact_fact_identity(self):
        artifact = self.make_jar("batch-flush.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)

        with BinaryFactStore() as regular:
            regular_counts = regular.add_artifact_snapshot(instance, snapshot)
            regular_identity = regular.content_identity()
        with BinaryFactStore() as batched:
            batched.FACT_INSERT_CHUNK_SIZE = 1
            batched_counts = batched.add_artifact_snapshot(instance, snapshot)
            batched_identity = batched.content_identity()

        self.assertEqual(batched_counts, regular_counts)
        self.assertEqual(batched_identity, regular_identity)

    def test_class_bytes_and_full_facts_are_transparently_compressed(self):
        artifact = self.make_jar("compressed-class.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)

        with BinaryFactStore() as store:
            store.add_artifact_snapshot(instance, snapshot)
            columns = {
                row[1] for row in store.connection.execute("PRAGMA table_info(classes)")
            }
            stored_lengths = store.connection.execute(
                "SELECT length(class_bytes_zlib), length(fact_zlib) FROM classes"
            ).fetchone()
            row = store.rows("classes")[0]
            metadata_only = store.rows(
                "classes",
                include_class_bytes=False,
                include_class_facts=False,
            )[0]
            lazy_class_bytes = store.class_bytes(
                metadata_only["class_variant_identity"]
            )

        self.assertIn("class_bytes_zlib", columns)
        self.assertIn("fact_zlib", columns)
        self.assertNotIn("class_bytes", columns)
        self.assertNotIn("fact_json", columns)
        self.assertEqual(row["class_bytes"], self.class_bytes)
        self.assertEqual(lazy_class_bytes, self.class_bytes)
        self.assertNotIn("class_bytes", metadata_only)
        self.assertNotIn("class_bytes_zlib", metadata_only)
        self.assertNotIn("fact_json", metadata_only)
        self.assertNotIn("fact_zlib", metadata_only)
        fact = json.loads(row["fact_json"])
        self.assertEqual(fact["class_name"], "demo/Caller")
        self.assertLess(stored_lengths[0], len(self.class_bytes))
        self.assertLess(stored_lengths[1], len(row["fact_json"].encode("utf-8")))

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
