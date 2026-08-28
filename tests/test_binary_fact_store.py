import base64
from contextlib import closing
import hashlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zlib
from dataclasses import replace
from pathlib import Path
import zipfile
import json
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_artifact_diff  # noqa: E402
import binary_validation_oracle  # noqa: E402
from binary_fact_store import (  # noqa: E402
    BinaryFactStore,
    BinaryFactStoreError,
    _json_and_transport_jvm_value,
)
from binary_first_contract import (  # noqa: E402
    canonical_identity_native_json,
    restore_jvm_text,
    transport_jvm_text,
)
from binary_first_model import ArtifactInstance  # noqa: E402


CUSTOM_INVOKEDYNAMIC_CLASS = base64.b64decode(
    "yv66vgAAAD0AGgEAClRhZ0ZpeHR1cmUHAAEBABBqYXZhL2xhbmcvT2JqZWN0BwAD"
    "AQADcnVuAQADKClWAQAGVGFyZ2V0BwAHAQAFVkFMVUUBAAFJDAAJAAoJAAgACw8C"
    "AAwBAAlCb290c3RyYXAHAA4BAANic20BAJIoTGphdmEvbGFuZy9pbnZva2UvTWV0"
    "aG9kSGFuZGxlcyRMb29rdXA7TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9p"
    "bnZva2UvTWV0aG9kVHlwZTtMamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGU7"
    "KUxqYXZhL2xhbmcvaW52b2tlL0NhbGxTaXRlOwwAEAARCgAPABIPBgATAQAEY2Fs"
    "bAwAFQAGEgAAABYBAARDb2RlAQAQQm9vdHN0cmFwTWV0aG9kcwAhAAIABAAAAAAA"
    "AQAJAAUABgABABgAAAASAAAAAAAAAAa6ABcAALEAAAAAAAEAGQAAAAgAAQAUAAEA"
    "DQ=="
)

METHOD_TYPE_CORPUS_CLASS = base64.b64decode(
    "yv66vgAAAD0AEAEAFmF1ZGl0L01ldGhvZFR5cGVDb3JwdXMHAAEBABBqYXZhL2xhbmcvT2JqZWN0"
    "BwADAQANcHJpbWl0aXZlT25seQEAAygpVgEAByhJSltEKVoQAAcBAA9vYmplY3RBbmRBcnJheXMB"
    "AEMoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL3V0aWwvTGlzdDtbW0xhdWRpdC9UaGluZzspTGph"
    "dmEvdXRpbC9NYXA7EAAKAQAJZHVwbGljYXRlAQA5KExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9s"
    "YW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7EAANAQAEQ29kZQAhAAIABAAAAAAAAwAJAAUA"
    "BgABAA8AAAAQAAEAAAAAAAQSCFexAAAAAAAJAAkABgABAA8AAAAQAAEAAAAAAAQSC1exAAAAAAAJ"
    "AAwABgABAA8AAAAQAAEAAAAAAAQSDlexAAAAAAAA"
)


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

    def test_content_identity_never_expands_compressed_fact_tables(self):
        artifact = self.make_jar("streamed-content-identity.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)

        with BinaryFactStore() as store:
            store.add_artifact_snapshot(instance, snapshot)
            with patch.object(
                store,
                "rows",
                side_effect=AssertionError("whole-table rows are forbidden"),
            ), patch(
                "binary_fact_store.zlib.decompress",
                side_effect=AssertionError("blob decompression is forbidden"),
            ):
                identity = store.content_identity()

        self.assertEqual(len(identity), 64)

    def test_cached_template_rebind_is_row_exact_without_recompression(self):
        artifact = self.make_jar("exact-template-rebind.jar")
        source_instance = self.instance(artifact, 0)
        target_instance = ArtifactInstance(
            outer_artifact_sha256=source_instance.outer_artifact_sha256,
            container_entry=source_instance.container_entry,
            content_sha256=source_instance.content_sha256,
            runtime_profile_identity="runtime-2",
            path_owner_loader_realm_identity=(
                source_instance.path_owner_loader_realm_identity
            ),
            runtime_path_kind=source_instance.runtime_path_kind,
            runtime_classpath_index=source_instance.runtime_classpath_index,
            container_loader_policy_version=(
                source_instance.container_loader_policy_version
            ),
            runtime_code_source_origin_identity="target-origin",
            coord=source_instance.coord,
        )
        template_identity = "a" * 64
        source_snapshot = replace(
            self.snapshot(artifact, source_instance),
            rebind_template_identity=template_identity,
        )
        target_snapshot = replace(
            self.snapshot(artifact, target_instance),
            rebind_template_identity=template_identity,
        )
        tables = (
            "artifact_instances",
            "archive_entries",
            "classes",
            "members",
            "direct_edges",
            "resources",
        )

        with BinaryFactStore() as source, BinaryFactStore() as rebound, (
            BinaryFactStore()
        ) as regular:
            source_counts = source.add_artifact_snapshot(
                source_instance, source_snapshot
            )
            with patch(
                "binary_fact_store._json_and_transport_jvm_value",
                side_effect=AssertionError("rebound facts were reserialized"),
            ), patch.object(
                BinaryFactStore,
                "_instruction_edges",
                side_effect=AssertionError("rebound instructions were replayed"),
            ), patch(
                "binary_fact_store.zlib.compress",
                side_effect=AssertionError("rebound facts were recompressed"),
            ), patch(
                "binary_fact_store.zlib.decompress",
                side_effect=AssertionError("rebound facts were decompressed"),
            ):
                rebound_counts = rebound.add_rebound_artifact_snapshot(
                    target_instance,
                    target_snapshot,
                    source_store=source,
                    source_instance=source_instance,
                    source_snapshot=source_snapshot,
                    expected_source_counts=source_counts,
                )
            regular_counts = regular.add_artifact_snapshot(
                target_instance, target_snapshot
            )
            rebound_rows = {
                table: [
                    tuple(row)
                    for row in rebound.connection.execute(
                        f"SELECT * FROM {table} ORDER BY 1"
                    )
                ]
                for table in tables
            }
            regular_rows = {
                table: [
                    tuple(row)
                    for row in regular.connection.execute(
                        f"SELECT * FROM {table} ORDER BY 1"
                    )
                ]
                for table in tables
            }
            rebound_summary = rebound.runtime_trigger_summary()
            regular_summary = regular.runtime_trigger_summary()
            rebound_identity = rebound.content_identity()
            regular_identity = regular.content_identity()

        self.assertEqual(rebound_counts, source_counts)
        self.assertEqual(rebound_counts, regular_counts)
        self.assertEqual(rebound_rows, regular_rows)
        self.assertEqual(rebound_summary, regular_summary)
        self.assertEqual(rebound_identity, regular_identity)

    def test_cached_template_rebind_fails_closed_on_proof_or_count_mismatch(self):
        artifact = self.make_jar("rebind-fail-closed.jar")
        source_instance = self.instance(artifact, 0)
        target_instance = self.instance(
            artifact, 1, coord="com.acme:caller:2"
        )
        source_snapshot = replace(
            self.snapshot(artifact, source_instance),
            rebind_template_identity="b" * 64,
        )
        target_snapshot = replace(
            self.snapshot(artifact, target_instance),
            rebind_template_identity="b" * 64,
        )

        with BinaryFactStore() as source, BinaryFactStore() as target:
            counts = source.add_artifact_snapshot(
                source_instance, source_snapshot
            )
            with self.assertRaises(BinaryFactStoreError) as bad_proof:
                target.add_rebound_artifact_snapshot(
                    target_instance,
                    replace(
                        target_snapshot,
                        rebind_template_identity="c" * 64,
                    ),
                    source_store=source,
                    source_instance=source_instance,
                    source_snapshot=source_snapshot,
                    expected_source_counts=counts,
                )
            with self.assertRaises(BinaryFactStoreError) as bad_counts:
                target.add_rebound_artifact_snapshot(
                    target_instance,
                    target_snapshot,
                    source_store=source,
                    source_instance=source_instance,
                    source_snapshot=source_snapshot,
                    expected_source_counts={**counts, "edges": counts["edges"] + 1},
                )
            target_counts = target.counts()

        self.assertEqual(
            bad_proof.exception.reason_code,
            "FACT_STORE_REBIND_TEMPLATE_IDENTITY_MISMATCH",
        )
        self.assertEqual(
            bad_counts.exception.reason_code,
            "FACT_STORE_REBIND_SOURCE_COUNTS_MISMATCH",
        )
        self.assertTrue(all(value == 0 for value in target_counts.values()))

    def test_cached_template_rebind_fails_closed_at_every_proof_boundary(self):
        artifact = self.make_jar("rebind-proof-boundaries.jar")
        source_instance = self.instance(artifact, 0)
        target_instance = ArtifactInstance(
            outer_artifact_sha256=source_instance.outer_artifact_sha256,
            container_entry=source_instance.container_entry,
            content_sha256=source_instance.content_sha256,
            runtime_profile_identity="runtime-2",
            path_owner_loader_realm_identity=(
                source_instance.path_owner_loader_realm_identity
            ),
            runtime_path_kind=source_instance.runtime_path_kind,
            runtime_classpath_index=source_instance.runtime_classpath_index,
            container_loader_policy_version=(
                source_instance.container_loader_policy_version
            ),
            runtime_code_source_origin_identity="target-origin",
            coord=source_instance.coord,
        )
        template_identity = "d" * 64
        source_snapshot = replace(
            self.snapshot(artifact, source_instance),
            rebind_template_identity=template_identity,
        )
        target_snapshot = replace(
            self.snapshot(artifact, target_instance),
            rebind_template_identity=template_identity,
        )

        with BinaryFactStore() as source:
            counts = source.add_artifact_snapshot(
                source_instance, source_snapshot
            )

            def expect_failure(
                reason_code,
                *,
                instance=target_instance,
                snapshot=target_snapshot,
                source_store=source,
                source_instance_value=source_instance,
                source_snapshot_value=source_snapshot,
                expected_counts=counts,
            ):
                with self.subTest(reason_code=reason_code), BinaryFactStore() as target:
                    with self.assertRaises(BinaryFactStoreError) as caught:
                        target.add_rebound_artifact_snapshot(
                            instance,
                            snapshot,
                            source_store=source_store,
                            source_instance=source_instance_value,
                            source_snapshot=source_snapshot_value,
                            expected_source_counts=expected_counts,
                        )
                    self.assertEqual(caught.exception.reason_code, reason_code)

            expect_failure(
                "FACT_STORE_REBIND_SOURCE_INVALID", source_store=object()
            )
            with self.assertRaises(BinaryFactStoreError) as same_source:
                source.add_rebound_artifact_snapshot(
                    target_instance,
                    target_snapshot,
                    source_store=source,
                    source_instance=source_instance,
                    source_snapshot=source_snapshot,
                    expected_source_counts=counts,
                )
            self.assertEqual(
                same_source.exception.reason_code,
                "FACT_STORE_REBIND_SOURCE_INVALID",
            )

            for invalid_counts in (
                None,
                {},
                {**counts, "edges": True},
                {**counts, "edges": -1},
            ):
                expect_failure(
                    "FACT_STORE_REBIND_SOURCE_COUNTS_INVALID",
                    expected_counts=invalid_counts,
                )

            for side, changed in (
                ("source", replace(
                    source_snapshot, artifact_instance_identity="wrong"
                )),
                ("target", replace(
                    target_snapshot, artifact_instance_identity="wrong"
                )),
            ):
                expect_failure(
                    "FACT_STORE_REBIND_ARTIFACT_IDENTITY_MISMATCH",
                    source_snapshot_value=(
                        changed if side == "source" else source_snapshot
                    ),
                    snapshot=changed if side == "target" else target_snapshot,
                )
            for side, changed in (
                ("source", replace(
                    source_snapshot, artifact_content_sha256="wrong"
                )),
                ("target", replace(
                    target_snapshot, artifact_content_sha256="wrong"
                )),
            ):
                expect_failure(
                    "FACT_STORE_REBIND_ARTIFACT_CONTENT_MISMATCH",
                    source_snapshot_value=(
                        changed if side == "source" else source_snapshot
                    ),
                    snapshot=changed if side == "target" else target_snapshot,
                )

            for changed_source, changed_target in (
                (source_snapshot, replace(
                    target_snapshot, rebind_template_identity=""
                )),
                (source_snapshot, replace(
                    target_snapshot, rebind_template_identity="D" * 64
                )),
                (replace(
                    source_snapshot, rebind_template_identity="e" * 64
                ), target_snapshot),
            ):
                expect_failure(
                    "FACT_STORE_REBIND_TEMPLATE_IDENTITY_MISMATCH",
                    source_snapshot_value=changed_source,
                    snapshot=changed_target,
                )

            expect_failure(
                "FACT_STORE_REBIND_SNAPSHOT_SEMANTICS_MISMATCH",
                snapshot=replace(
                    target_snapshot,
                    runtime_semantics_diagnostic_codes=("changed",),
                ),
            )

            source_entries = source_snapshot.entries
            target_entries = target_snapshot.entries
            for changed_source, changed_target in (
                (replace(
                    source_snapshot,
                    entries=source_entries + (source_entries[0],),
                ), target_snapshot),
                (source_snapshot, replace(
                    target_snapshot,
                    entries=target_entries + (target_entries[0],),
                )),
                (source_snapshot, replace(
                    target_snapshot,
                    entries=(
                        replace(target_entries[0], name="other/Caller.class"),
                        *target_entries[1:],
                    ),
                )),
                (source_snapshot, replace(
                    target_snapshot,
                    entries=(
                        replace(
                            target_entries[0],
                            byte_length=target_entries[0].byte_length + 1,
                        ),
                        *target_entries[1:],
                    ),
                )),
            ):
                expect_failure(
                    "FACT_STORE_REBIND_ARCHIVE_INVENTORY_MISMATCH",
                    source_snapshot_value=changed_source,
                    snapshot=changed_target,
                )

            source_records = source_snapshot.class_records
            target_records = target_snapshot.class_records
            for changed_source, changed_target in (
                (replace(
                    source_snapshot,
                    class_records=source_records + (source_records[0],),
                ), target_snapshot),
                (source_snapshot, replace(
                    target_snapshot,
                    class_records=target_records + (target_records[0],),
                )),
                (source_snapshot, replace(
                    target_snapshot,
                    class_records=({
                        **target_records[0], "class_entry": "different",
                    },),
                )),
            ):
                expect_failure(
                    "FACT_STORE_REBIND_CLASS_INVENTORY_MISMATCH",
                    source_snapshot_value=changed_source,
                    snapshot=changed_target,
                )

            blank_source = replace(
                source_snapshot,
                class_records=({**source_records[0], "class_entry": None},),
            )
            blank_target = replace(
                target_snapshot,
                class_records=({**target_records[0], "class_entry": None},),
            )
            expect_failure(
                "FACT_STORE_REBIND_CLASS_ENTRY_UNBOUND",
                source_snapshot_value=blank_source,
                snapshot=blank_target,
            )

            class EntryWithSpoofedAlignment:
                def __init__(self, entry):
                    self.__dict__.update(vars(entry))
                    self.name = "different/Caller.class"
                    self.alignment_key = entry.alignment_key

            spoofed_target = replace(
                target_snapshot,
                entries=(
                    EntryWithSpoofedAlignment(target_entries[0]),
                    *target_entries[1:],
                ),
            )
            with patch.object(
                BinaryFactStore,
                "_archive_entry_rebind_fingerprint",
                return_value=("equal",),
            ):
                expect_failure(
                    "FACT_STORE_REBIND_CLASS_ENTRY_UNBOUND",
                    snapshot=spoofed_target,
                )

            missing_source_instance = replace(
                source_instance,
                runtime_profile_identity="missing-runtime",
            )
            expect_failure(
                "FACT_STORE_REBIND_SOURCE_ARTIFACT_MISMATCH",
                source_instance_value=missing_source_instance,
                source_snapshot_value=replace(
                    source_snapshot,
                    artifact_instance_identity=missing_source_instance.identity,
                ),
            )

            source.connection.execute("SAVEPOINT bad_artifact_row")
            source.connection.execute(
                "UPDATE artifact_instances SET inventory_digest='wrong' "
                "WHERE artifact_instance_identity=?",
                (source_instance.identity,),
            )
            try:
                expect_failure("FACT_STORE_REBIND_SOURCE_ARTIFACT_MISMATCH")
            finally:
                source.connection.execute("ROLLBACK TO bad_artifact_row")
                source.connection.execute("RELEASE bad_artifact_row")

            class ConnectionProjection:
                def __init__(self, connection, marker, transform):
                    self.connection = connection
                    self.marker = " ".join(marker.split())
                    self.transform = transform

                def execute(self, query, parameters=()):
                    result = self.connection.execute(query, parameters)
                    if self.marker in " ".join(str(query).split()):
                        return self.transform([dict(row) for row in result])
                    return result

                def __getattr__(self, name):
                    return getattr(self.connection, name)

            def projected_failure(marker, transform, reason_code, **expect_kwargs):
                original = source.connection
                source.connection = ConnectionProjection(
                    original, marker, transform
                )
                try:
                    expect_failure(reason_code, **expect_kwargs)
                finally:
                    source.connection = original

            class_marker = (
                "SELECT * FROM classes WHERE artifact_instance_identity=?"
            )
            projected_failure(
                class_marker, lambda _rows: [],
                "FACT_STORE_REBIND_SOURCE_CLASS_COUNT_MISMATCH",
            )
            projected_failure(
                class_marker,
                lambda rows: [{
                    **row, "physical_entry_label": "different",
                } for row in rows],
                "FACT_STORE_REBIND_SOURCE_CLASS_LABEL_MISMATCH",
            )
            for field, value, reason_code in (
                ("artifact_instance_identity", "wrong",
                 "FACT_STORE_REBIND_SOURCE_CLASS_MISMATCH"),
                ("physical_entry_identity", "wrong",
                 "FACT_STORE_REBIND_SOURCE_CLASS_MISMATCH"),
                ("class_bytes_sha256", "wrong",
                 "FACT_STORE_REBIND_SOURCE_CLASS_MISMATCH"),
                ("class_contract_digest", "wrong",
                 "FACT_STORE_REBIND_SOURCE_CLASS_MISMATCH"),
                ("parse_status", "wrong",
                 "FACT_STORE_REBIND_SOURCE_CLASS_MISMATCH"),
                ("fact_zlib_sha256", "0" * 64,
                 "FACT_STORE_REBIND_SOURCE_FACT_DIGEST_MISMATCH"),
            ):
                projected_failure(
                    class_marker,
                    lambda rows, field=field, value=value: [
                        {**row, field: value} for row in rows
                    ],
                    reason_code,
                )

            for field in ("class_bytes_sha256", "class_contract_digest"):
                changed_source_record = {**source_records[0], field: None}
                changed_target_record = {**target_records[0], field: None}
                projected_failure(
                    class_marker,
                    lambda rows, field=field: [{
                        **row,
                        field: "",
                        "fact_zlib_sha256": "0" * 64,
                    } for row in rows],
                    "FACT_STORE_REBIND_SOURCE_FACT_DIGEST_MISMATCH",
                    source_snapshot_value=replace(
                        source_snapshot,
                        class_records=(changed_source_record,),
                    ),
                    snapshot=replace(
                        target_snapshot,
                        class_records=(changed_target_record,),
                    ),
                )

            for field in (
                "class_bytes_sha256", "class_contract_digest", "frame_type",
            ):
                changed_target_record = {
                    **target_records[0], field: "changed"
                }
                expect_failure(
                    "FACT_STORE_REBIND_SOURCE_CLASS_MISMATCH",
                    snapshot=replace(
                        target_snapshot,
                        class_records=(changed_target_record,),
                    ),
                )
            failed_source_record = {
                **source_records[0], "frame_type": "class_error"
            }
            failed_target_record = {
                **target_records[0], "frame_type": "class_error"
            }
            expect_failure(
                "FACT_STORE_REBIND_SOURCE_CLASS_MISMATCH",
                source_snapshot_value=replace(
                    source_snapshot, class_records=(failed_source_record,)
                ),
                snapshot=replace(
                    target_snapshot, class_records=(failed_target_record,)
                ),
            )

            member_marker = (
                "SELECT * FROM members WHERE class_variant_identity IN"
            )
            projected_failure(
                member_marker,
                lambda rows: [{
                    **row, "class_variant_identity": "missing",
                } for row in rows],
                "FACT_STORE_REBIND_SOURCE_MEMBER_MISMATCH",
            )
            projected_failure(
                member_marker,
                lambda rows: [{
                    **row, "artifact_instance_identity": "wrong",
                } for row in rows],
                "FACT_STORE_REBIND_SOURCE_MEMBER_MISMATCH",
            )

            edge_marker = (
                "SELECT * FROM direct_edges ORDER BY rowid DESC LIMIT ?"
            )
            for field in (
                "caller_member_identity",
                "caller_class_variant_identity",
                "caller_artifact_instance_identity",
            ):
                projected_failure(
                    edge_marker,
                    lambda rows, field=field: [
                        {**row, field: "missing"} for row in rows
                    ],
                    "FACT_STORE_REBIND_SOURCE_EDGE_MISMATCH",
                )

            reference_marker = (
                "SELECT reference_kind,class_name FROM runtime_class_references"
            )
            projected_failure(
                reference_marker,
                lambda rows: [{
                    **row, "reference_kind": "invalid",
                } for row in rows],
                "FACT_STORE_REBIND_RUNTIME_REFERENCE_INVALID",
            )
            projected_failure(
                reference_marker,
                lambda rows: [{**row, "class_name": ""} for row in rows],
                "FACT_STORE_REBIND_RUNTIME_REFERENCE_INVALID",
            )

            with patch.object(
                source,
                "_runtime_trigger_data_version",
                side_effect=[1, 2],
            ):
                expect_failure("FACT_STORE_REBIND_SOURCE_CHANGED")

            class ChangingTotalChanges(ConnectionProjection):
                def __init__(self, connection):
                    super().__init__(connection, "never-match", lambda rows: rows)
                    self.reads = 0

                @property
                def total_changes(self):
                    self.reads += 1
                    return self.connection.total_changes + self.reads

            original = source.connection
            source.connection = ChangingTotalChanges(original)
            try:
                expect_failure("FACT_STORE_REBIND_SOURCE_CHANGED")
            finally:
                source.connection = original

    def test_cached_template_rebind_zero_edge_and_transaction_failure_matrix(self):
        empty_artifact = self.root / "empty-rebind.jar"
        with zipfile.ZipFile(empty_artifact, "w"):
            pass
        source_instance = self.instance(empty_artifact, 0)
        target_instance = replace(
            source_instance,
            runtime_profile_identity="runtime-empty-target",
            runtime_code_source_origin_identity="empty-target-origin",
        )
        template_identity = "f" * 64
        source_snapshot = replace(
            self.snapshot(empty_artifact, source_instance),
            rebind_template_identity=template_identity,
        )
        target_snapshot = replace(
            self.snapshot(empty_artifact, target_instance),
            rebind_template_identity=template_identity,
        )
        with BinaryFactStore() as source:
            counts = source.add_artifact_snapshot(source_instance, source_snapshot)
            self.assertEqual(counts["edges"], 0)
            with BinaryFactStore(bulk_load_transaction=True) as target:
                self.assertEqual(
                    target.add_rebound_artifact_snapshot(
                        target_instance,
                        target_snapshot,
                        source_store=source,
                        source_instance=source_instance,
                        source_snapshot=source_snapshot,
                        expected_source_counts=counts,
                    ),
                    counts,
                )

        artifact = self.make_jar("rebind-transaction-boundaries.jar")
        source_instance = self.instance(artifact, 0)
        target_instance = replace(
            source_instance,
            runtime_profile_identity="runtime-transaction-target",
            runtime_code_source_origin_identity="transaction-target-origin",
        )
        source_snapshot = replace(
            self.snapshot(artifact, source_instance),
            rebind_template_identity=template_identity,
        )
        target_snapshot = replace(
            self.snapshot(artifact, target_instance),
            rebind_template_identity=template_identity,
        )
        with BinaryFactStore() as source:
            counts = source.add_artifact_snapshot(source_instance, source_snapshot)
            fallback_source = replace(
                source_snapshot,
                entries=tuple(
                    replace(entry, logical_resource_entry="")
                    if entry.kind == "resource" else entry
                    for entry in source_snapshot.entries
                ),
            )
            fallback_target = replace(
                target_snapshot,
                entries=tuple(
                    replace(entry, logical_resource_entry="")
                    if entry.kind == "resource" else entry
                    for entry in target_snapshot.entries
                ),
            )
            with BinaryFactStore() as target:
                self.assertEqual(
                    target.add_rebound_artifact_snapshot(
                        target_instance,
                        fallback_target,
                        source_store=source,
                        source_instance=source_instance,
                        source_snapshot=fallback_source,
                        expected_source_counts=counts,
                    ),
                    counts,
                )
            for bulk in (False, True):
                with self.subTest(integrity_bulk=bulk), BinaryFactStore(
                    bulk_load_transaction=bulk
                ) as target:
                    target.add_artifact_snapshot(target_instance, target_snapshot)
                    with self.assertRaises(BinaryFactStoreError) as caught:
                        target.add_rebound_artifact_snapshot(
                            target_instance,
                            target_snapshot,
                            source_store=source,
                            source_instance=source_instance,
                            source_snapshot=source_snapshot,
                            expected_source_counts=counts,
                        )
                    self.assertEqual(
                        caught.exception.reason_code,
                        "FACT_STORE_IDENTITY_CONFLICT",
                    )

            bad_value = object()
            source_entries = tuple(
                replace(
                    entry,
                    logical_resource_entry="",
                    resource_semantic_facts=(bad_value,),
                )
                if entry.kind == "resource" else entry
                for entry in source_snapshot.entries
            )
            target_entries = tuple(
                replace(
                    entry,
                    logical_resource_entry="",
                    resource_semantic_facts=(bad_value,),
                )
                if entry.kind == "resource" else entry
                for entry in target_snapshot.entries
            )
            bad_source = replace(source_snapshot, entries=source_entries)
            bad_target = replace(target_snapshot, entries=target_entries)
            for bulk in (False, True):
                with self.subTest(base_exception_bulk=bulk), BinaryFactStore(
                    bulk_load_transaction=bulk
                ) as target:
                    with self.assertRaises(TypeError):
                        target.add_rebound_artifact_snapshot(
                            target_instance,
                            bad_target,
                            source_store=source,
                            source_instance=source_instance,
                            source_snapshot=bad_source,
                            expected_source_counts=counts,
                        )

    def test_fact_store_preserves_unpaired_surrogate_jvm_text(self):
        from tests.test_final_artifact_edge_oracle import (
            _minimal_static_edge_class,
        )

        raw_member = json.loads('"\\ud800"')
        artifact = self.root / "surrogate.jar"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr(
                "SurrogateFactStoreFixture.class",
                _minimal_static_edge_class(
                    "SurrogateFactStoreFixture", raw_member
                ),
            )
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)
        self.assertEqual(
            snapshot.class_records[0]["methods"][0]["contract"]["name"],
            raw_member,
        )

        with BinaryFactStore() as store:
            counts = store.add_artifact_snapshot(instance, snapshot)
            members = store.rows("members", where="member_kind='method'")

        transported = transport_jvm_text(raw_member)
        self.assertEqual(counts["classes"], 1)
        self.assertIn(transported, {row["member_name"] for row in members})
        self.assertEqual(restore_jvm_text(transported), raw_member)

    def test_fact_json_fast_path_preserves_ordinary_and_transport_text(self):
        ordinary = {"nested": ["运行时😀", 7, None], "flag": True}
        record, encoded = _json_and_transport_jvm_value(ordinary)
        self.assertIs(record, ordinary)
        self.assertEqual(
            encoded,
            json.dumps(
                ordinary,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ),
        )

        for raw in (json.loads('"\\ud800"'), "~jua-utf16-v1~literal"):
            with self.subTest(raw=repr(raw)):
                source = {"value": raw}
                transported_record, transported_json = (
                    _json_and_transport_jvm_value(source)
                )
                stored = json.loads(transported_json)["value"]
                self.assertIsNot(transported_record, source)
                self.assertEqual(stored, transport_jvm_text(raw))
                self.assertEqual(restore_jvm_text(stored), raw)

    def test_direct_edge_fast_identity_is_exact_for_canonical_payloads(self):
        from binary_fact_store import _direct_edge_identity_from_json

        transported_surrogate = transport_jvm_text(json.loads('"\\ud800"'))
        payloads = (
            {},
            {"opcode": "invokevirtual", "interface": False},
            {
                "bootstrap": [None, True, -1, "运行时😀"],
                "transported": transported_surrogate,
            },
        )
        for payload in payloads:
            values = {
                "caller_member_identity": "a" * 64,
                "bytecode_offset": 37,
                "instruction_index": 11,
                "edge_kind": "invoke/运行时",
                "symbolic_owner": "fixture.运行时",
                "symbolic_name": transported_surrogate,
                "symbolic_descriptor": "(Ljava/lang/String;)V",
                "edge_payload": payload,
            }
            with self.subTest(payload=payload):
                self.assertEqual(
                    _direct_edge_identity_from_json(
                        values["caller_member_identity"],
                        values["bytecode_offset"],
                        values["instruction_index"],
                        values["edge_kind"],
                        values["symbolic_owner"],
                        values["symbolic_name"],
                        values["symbolic_descriptor"],
                        json.dumps(
                            payload,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                            allow_nan=False,
                        ),
                    ),
                    canonical_identity_native_json(
                        "binary_direct_edge_identity", values,
                        schema_version="1",
                    ),
                )

    def test_constructor_failure_closes_partially_initialized_connection(self):
        connections = []
        real_connect = sqlite3.connect

        def tracked_connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            connections.append(connection)
            return connection

        with patch(
            "binary_fact_store.sqlite3.connect", side_effect=tracked_connect
        ), patch.object(
            BinaryFactStore,
            "_create_schema",
            side_effect=RuntimeError("synthetic schema failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic schema failure"):
                BinaryFactStore(self.root / "constructor-failure.sqlite")

        self.assertEqual(len(connections), 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            connections[0].execute("SELECT 1")

    def test_fact_store_persists_only_runtime_effective_logical_resources(self):
        artifact = self.root / "mr-resources.jar"
        selected_content = b"<beans><bean id='selected'/></beans>"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr(
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
            )
            archive.writestr(
                "config/runtime.xml", b"<beans><bean id='base'/></beans>"
            )
            archive.writestr(
                "META-INF/versions/9/config/runtime.xml", selected_content
            )
            archive.writestr(
                "META-INF/services/demo.Service", b"demo.Base\n"
            )
            archive.writestr(
                "META-INF/versions/9/META-INF/services/demo.Service",
                b"demo.Versioned\n",
            )
        instance = self.instance(artifact, 0)
        snapshot = binary_artifact_diff.snapshot_archive(
            artifact,
            artifact_instance_identity=instance.identity,
            expected_sha256=instance.content_sha256,
            asm_jar=self.asm_jar,
            target_jvm_major=21,
        )

        with BinaryFactStore() as store:
            counts = store.add_artifact_snapshot(instance, snapshot)
            resources = store.rows("resources")
            archive_entries = store.rows("archive_entries")
            schema = store.rows(
                "metadata", where="key='schema_version'"
            )[0]["value"]

        by_name = {row["resource_name"]: row for row in resources}
        self.assertEqual(schema, "binary-fact-sqlite-v11")
        self.assertEqual(counts["resources"], 3)
        self.assertEqual(
            by_name["config/runtime.xml"]["content_sha256"],
            hashlib.sha256(selected_content).hexdigest(),
        )
        self.assertEqual(
            by_name["META-INF/services/demo.Service"]["content_sha256"],
            hashlib.sha256(b"demo.Base\n").hexdigest(),
        )
        self.assertNotIn(
            "META-INF/versions/9/config/runtime.xml", by_name
        )
        physical = {
            row["name"]: row for row in archive_entries
        }
        self.assertEqual(
            physical["META-INF/versions/9/config/runtime.xml"][
                "logical_resource_entry"
            ],
            "config/runtime.xml",
        )
        self.assertIn(
            "META-INF/versions/9/META-INF/services/demo.Service", physical
        )

    def test_v3_fact_store_is_not_silently_relabelled_as_v4(self):
        database = self.root / "legacy-v3.sqlite"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO metadata VALUES('schema_version',"
                "'binary-fact-sqlite-v3')"
            )
            connection.commit()

        with self.assertRaises(BinaryFactStoreError) as raised:
            BinaryFactStore(database)

        self.assertEqual(
            raised.exception.reason_code,
            "FACT_STORE_SCHEMA_VERSION_MISMATCH",
        )
        with closing(sqlite3.connect(database)) as connection:
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
        self.assertEqual(version, "binary-fact-sqlite-v3")

    def test_v4_fact_store_is_not_silently_relabelled_as_v5(self):
        database = self.root / "legacy-v4.sqlite"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO metadata VALUES('schema_version',"
                "'binary-fact-sqlite-v4')"
            )
            connection.commit()

        with self.assertRaises(BinaryFactStoreError) as raised:
            BinaryFactStore(database)

        self.assertEqual(
            raised.exception.reason_code,
            "FACT_STORE_SCHEMA_VERSION_MISMATCH",
        )
        with closing(sqlite3.connect(database)) as connection:
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]

        self.assertEqual(version, "binary-fact-sqlite-v4")

    def test_v5_fact_store_identity_is_stable_after_reopen(self):
        artifact = self.make_jar("reopen.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)
        database = self.root / "facts.sqlite"

        with BinaryFactStore(database) as store:
            store.add_artifact_snapshot(instance, snapshot)
            before = store.content_identity()

        with BinaryFactStore(database) as store:
            after = store.content_identity()
            version = store.rows(
                "metadata", where="key='schema_version'"
            )[0]["value"]

        self.assertEqual(version, "binary-fact-sqlite-v11")
        self.assertEqual(after, before)

    def test_custom_invokedynamic_bootstrap_tag_validates_from_nested_payload(self):
        artifact = self.root / "custom-invokedynamic.jar"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr("TagFixture.class", CUSTOM_INVOKEDYNAMIC_CLASS)
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)

        with BinaryFactStore() as store:
            store.add_artifact_snapshot(instance, snapshot)
            bootstrap = store.connection.execute(
                "SELECT edge_json FROM direct_edges "
                "WHERE edge_kind='invokedynamic_bootstrap'"
            ).fetchone()
            self.assertIsNotNone(bootstrap)
            payload = json.loads(bootstrap["edge_json"])
            self.assertEqual(payload["bootstrap"]["tag"], 6)
            self.assertIs(payload["bootstrap"]["interface"], False)

            issues, truth = binary_validation_oracle._validate_direct_edges(
                store.connection,
                [{
                    "path": str(artifact),
                    "sha256": instance.content_sha256,
                    "loader_realm": (
                        instance.path_owner_loader_realm_identity
                    ),
                    "slot": instance.runtime_classpath_index,
                }],
                javap=str(shutil.which("javap")),
            )

        self.assertEqual(issues, [])
        self.assertEqual(len(truth["dynamic_handle_edges"]), 2)

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

    def test_method_type_descriptor_expands_reference_owners_once(self):
        descriptor = (
            "(Ljava/lang/String;[Ljava/util/List;[[Laudit/Thing;"
            "Ljava/lang/String;)Ljava/util/Map;"
        )
        edges = BinaryFactStore._instruction_edges([
            "ldc", 7, {"kind": "method_type", "descriptor": descriptor},
        ])

        self.assertEqual(
            [edge["symbolic_owner"] for edge in edges],
            [
                "java/lang/String", "java/util/List", "audit/Thing",
                "java/util/Map",
            ],
        )
        self.assertTrue(all(
            edge["edge_kind"] == "type"
            and edge["bytecode_offset"] == 7
            and edge["payload"]["type_use_kind"]
            == "method_type_descriptor"
            and edge["symbolic_descriptor"]
            == edge["payload"]["referenced_type_descriptor"]
            == f'L{edge["symbolic_owner"]};'
            and edge["payload"]["descriptor"] == descriptor
            for edge in edges
        ))

    def test_primitive_only_method_type_descriptor_has_no_type_owner(self):
        self.assertEqual(
            BinaryFactStore._instruction_edges([
                "ldc", 0,
                {"kind": "method_type", "descriptor": "(IJ[D)Z"},
            ]),
            [],
        )

    def test_invalid_method_type_descriptor_fails_closed(self):
        for descriptor in (
            "", "Ljava/lang/String;", "()", "(V)V", "([V)V",
            "(Ljava/lang/String)V", "(L;)V", "(Lbad//Name;)V",
            "(Ljava.lang.String;)V", "()Vextra",
        ):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(BinaryFactStoreError) as raised:
                    BinaryFactStore._instruction_edges([
                        "ldc", 0,
                        {"kind": "method_type", "descriptor": descriptor},
                    ])
                self.assertEqual(
                    raised.exception.reason_code,
                    "FACT_STORE_METHOD_TYPE_DESCRIPTOR_INVALID",
                )

    def test_method_type_descriptor_enforces_jvm_shape_limits(self):
        valid = (
            "(" + "I" * 255 + ")V",
            "(" + "J" * 127 + "I)V",
            "([" + "[" * 254 + "Ljava/lang/String;)V",
            "(Lraw/)name;)V",
        )
        for descriptor in valid:
            with self.subTest(valid=descriptor[:40]):
                BinaryFactStore._method_descriptor_reference_owners(descriptor)

        invalid = (
            "(" + "I" * 256 + ")V",
            "(" + "J" * 128 + ")V",
            "([" + "[" * 255 + "Ljava/lang/String;)V",
        )
        for descriptor in invalid:
            with self.subTest(invalid=descriptor[:40]):
                with self.assertRaises(BinaryFactStoreError) as raised:
                    BinaryFactStore._method_descriptor_reference_owners(
                        descriptor
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "FACT_STORE_METHOD_TYPE_DESCRIPTOR_INVALID",
                )

    def test_field_descriptor_reference_owner_is_strict_and_array_aware(self):
        self.assertEqual(
            BinaryFactStore._field_descriptor_reference_owner(
                "Ljava/util/Locale;"
            ),
            "java/util/Locale",
        )
        self.assertEqual(
            BinaryFactStore._field_descriptor_reference_owner(
                "[[Ljava/util/Locale;"
            ),
            "java/util/Locale",
        )
        for descriptor in ("I", "[J", "[[Z"):
            with self.subTest(primitive=descriptor):
                self.assertEqual(
                    BinaryFactStore._field_descriptor_reference_owner(
                        descriptor
                    ),
                    "",
                )
        for descriptor in (
            "", "V", "[V", "Ljava/util/Locale", "Ljava.lang.Locale;",
            "Lbad//Name;", "[", "Ljava/util/Locale;extra",
        ):
            with self.subTest(invalid=descriptor):
                with self.assertRaises(BinaryFactStoreError) as raised:
                    BinaryFactStore._field_descriptor_reference_owner(
                        descriptor
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "FACT_STORE_FIELD_TYPE_DESCRIPTOR_INVALID",
                )

    def test_dynamic_resolution_descriptors_expand_without_changing_linkage_edges(self):
        bootstrap = {
            "kind": "handle", "tag": 6, "owner": "audit/Bootstrap",
            "name": "link", "descriptor": "(Lboot/In;)Lboot/Out;",
            "interface": False,
        }
        repeated_handle = {
            "kind": "handle", "tag": 6, "owner": "audit/Target",
            "name": "run", "descriptor": "(Lshared/Type;)Lshared/Type;",
            "interface": False,
        }
        field_handle = {
            "kind": "handle", "tag": 2, "owner": "audit/Target",
            "name": "VALUE", "descriptor": "Lhandle/FieldType;",
            "interface": False,
        }
        nested = {
            "kind": "constant_dynamic", "name": "nested",
            "descriptor": "Lnested/Nominal;",
            "bootstrap": {
                "kind": "handle", "tag": 6,
                "owner": "audit/NestedBootstrap", "name": "link",
                "descriptor": "(Lnested/BootIn;)Lnested/BootOut;",
                "interface": False,
            },
            "arguments": [
                {"kind": "method_type", "descriptor": "(Lnested/Arg;)V"},
                repeated_handle,
            ],
        }
        edges = BinaryFactStore._instruction_edges([
            "invokedynamic", 9, "call",
            "(Lcall/In;Lcall/In;)Lcall/Out;", bootstrap,
            [
                {"kind": "method_type", "descriptor": "(Larg/Method;)V"},
                {"kind": "type", "descriptor": "Larg/Class;"},
                field_handle, repeated_handle, nested,
            ],
        ])

        linkage = [
            edge for edge in edges
            if edge["edge_kind"] not in {"type", "member_descriptor_type"}
        ]
        self.assertEqual(
            [
                (
                    edge["edge_kind"], edge["symbolic_owner"],
                    edge["symbolic_name"], edge["symbolic_descriptor"],
                )
                for edge in linkage
            ],
            [
                (
                    "invokedynamic_bootstrap", "audit/Bootstrap", "link",
                    "(Lboot/In;)Lboot/Out;",
                ),
                (
                    "invokedynamic_handle_0", "audit/Target", "VALUE",
                    "Lhandle/FieldType;",
                ),
                (
                    "invokedynamic_handle_1", "audit/Target", "run",
                    "(Lshared/Type;)Lshared/Type;",
                ),
                (
                    "invokedynamic_handle_2", "audit/NestedBootstrap",
                    "link", "(Lnested/BootIn;)Lnested/BootOut;",
                ),
                (
                    "invokedynamic_handle_3", "audit/Target", "run",
                    "(Lshared/Type;)Lshared/Type;",
                ),
            ],
        )
        observed = {
            (
                edge["symbolic_owner"],
                edge["payload"]["type_use_kind"],
            )
            for edge in edges if edge["edge_kind"] == "type"
        }
        self.assertEqual(observed, {
            ("call/In", "invokedynamic_callsite_descriptor"),
            ("call/Out", "invokedynamic_callsite_descriptor"),
            ("boot/In", "method_handle_descriptor"),
            ("boot/Out", "method_handle_descriptor"),
            ("handle/FieldType", "method_handle_descriptor"),
            ("shared/Type", "method_handle_descriptor"),
            ("nested/BootIn", "method_handle_descriptor"),
            ("nested/BootOut", "method_handle_descriptor"),
            ("arg/Method", "method_type_descriptor"),
            ("arg/Class", "bootstrap_class_constant"),
            ("nested/Nominal", "constant_dynamic_descriptor"),
            ("nested/Arg", "method_type_descriptor"),
        })
        self.assertEqual(
            sum(
                edge["symbolic_owner"] == "shared/Type"
                and edge["payload"].get("type_use_kind")
                == "method_handle_descriptor"
                for edge in edges if edge["edge_kind"] == "type"
            ),
            1,
        )

    def test_invalid_method_handle_descriptor_fails_closed(self):
        cases = (
            ({"kind": "handle", "tag": 0, "descriptor": "()V"},),
            ({"kind": "handle", "tag": 2, "descriptor": "()V"},),
            ({"kind": "handle", "tag": 6, "descriptor": "Ljava/lang/String;"},),
        )
        for (constant,) in cases:
            with self.subTest(constant=constant):
                with self.assertRaises(BinaryFactStoreError) as raised:
                    BinaryFactStore._instruction_edges(["ldc", 0, constant])
                self.assertEqual(
                    raised.exception.reason_code,
                    "FACT_STORE_METHOD_HANDLE_DESCRIPTOR_INVALID",
                )

    def test_deep_bootstrap_arguments_are_complete_without_python_recursion(self):
        type_value = {"kind": "type", "descriptor": "Ldeep/Type;"}
        handle_value = {
            "kind": "handle",
            "tag": 6,
            "owner": "deep/Target",
            "name": "run",
            "descriptor": "()V",
            "interface": False,
        }
        nested_types = type_value
        nested_handles = handle_value
        for _ in range(2_000):
            nested_types = [nested_types]
            nested_handles = [nested_handles]

        type_edges = BinaryFactStore._bootstrap_argument_type_edges(
            nested_types, 7
        )
        handles = []
        BinaryFactStore._collect_handles(nested_handles, handles)

        self.assertEqual(
            [edge["symbolic_owner"] for edge in type_edges], ["deep/Type"]
        )
        self.assertEqual(handles, [handle_value])

    def test_all_method_handle_reference_kinds_materialize_constraints(self):
        expected_reference_kinds = {
            1: "REF_getField",
            2: "REF_getStatic",
            3: "REF_putField",
            4: "REF_putStatic",
            5: "REF_invokeVirtual",
            6: "REF_invokeStatic",
            7: "REF_invokeSpecial",
            8: "REF_newInvokeSpecial",
            9: "REF_invokeInterface",
        }
        for tag, reference_kind in expected_reference_kinds.items():
            field_reference = tag <= 4
            descriptor = (
                "[[Ltypes/Field;" if field_reference
                else "(Ltypes/Argument;[Ltypes/Argument;)Ltypes/Return;"
            )
            handle = {
                "kind": "handle",
                "tag": tag,
                "owner": "audit/HandleOwner",
                "name": "VALUE" if field_reference else "invoke",
                "descriptor": descriptor,
                # Tag 9 must carry interface resolution semantics even if a
                # malformed/legacy producer omitted ASM's redundant flag.
                "interface": False,
            }
            with self.subTest(tag=tag, reference_kind=reference_kind):
                edges = BinaryFactStore._instruction_edges([
                    "ldc", 23, handle,
                ])
                handles = [
                    edge for edge in edges
                    if edge["edge_kind"] == "ldc_handle"
                ]
                self.assertEqual(len(handles), 1)
                self.assertEqual(
                    handles[0]["payload"].get(
                        "loading_constraint_type_owners", []
                    ),
                    ["types/Field"] if field_reference else [
                        "types/Argument", "types/Return",
                    ],
                )
                compact = handles[0]
                self.assertEqual(compact["opcode"], 18)
                self.assertEqual(compact["bytecode_offset"], 23)
                self.assertEqual(compact["symbolic_owner"], "audit/HandleOwner")
                self.assertEqual(
                    compact["symbolic_name"],
                    "VALUE" if field_reference else "invoke",
                )
                self.assertEqual(compact["symbolic_descriptor"], descriptor)
                self.assertEqual(compact["payload"]["tag"], tag)
                self.assertEqual(
                    expected_reference_kinds[tag], reference_kind
                )
                self.assertFalse(any(
                    edge["edge_kind"] == "member_descriptor_type"
                    for edge in edges
                ))

    def test_member_reference_descriptors_attach_compact_constraint_owners(self):
        method_edges = BinaryFactStore._instruction_edges([
            "method", 12, 185, "audit/Api", "call",
            "(Ltypes/A;[Ltypes/B;Ltypes/A;I)[[Ltypes/C;", True,
        ])
        self.assertEqual(
            (
                method_edges[0]["edge_kind"],
                method_edges[0]["symbolic_owner"],
                method_edges[0]["symbolic_name"],
                method_edges[0]["symbolic_descriptor"],
            ),
            (
                "method", "audit/Api", "call",
                "(Ltypes/A;[Ltypes/B;Ltypes/A;I)[[Ltypes/C;",
            ),
        )
        self.assertEqual(len(method_edges), 1)
        self.assertEqual(
            method_edges[0]["payload"]["loading_constraint_type_owners"],
            ["types/A", "types/B", "types/C"],
        )
        self.assertIs(method_edges[0]["payload"]["interface"], True)

        field_edges = BinaryFactStore._instruction_edges([
            "field", 4, 180, "audit/Owner", "value", "[[Ltypes/Field;",
        ])
        self.assertEqual([edge["edge_kind"] for edge in field_edges], ["field"])
        self.assertEqual(
            field_edges[0]["payload"]["loading_constraint_type_owners"],
            ["types/Field"],
        )
        self.assertEqual(
            BinaryFactStore._instruction_edges([
                "field", 4, 180, "audit/Owner", "count", "I",
            ])[0]["edge_kind"],
            "field",
        )
        self.assertEqual(
            len(BinaryFactStore._instruction_edges([
                "field", 4, 180, "audit/Owner", "count", "I",
            ])),
            1,
        )
        self.assertNotIn(
            "loading_constraint_type_owners",
            BinaryFactStore._instruction_edges([
                "field", 4, 180, "audit/Owner", "count", "I",
            ])[0]["payload"],
        )

    def test_invalid_member_reference_descriptors_fail_closed(self):
        cases = (
            ["method", 0, 184, "audit/Owner", "call", "(Lbad)V", False],
            ["field", 0, 180, "audit/Owner", "value", "V"],
        )
        for instruction in cases:
            with self.subTest(instruction=instruction):
                with self.assertRaises(BinaryFactStoreError) as raised:
                    BinaryFactStore._instruction_edges(instruction)
                self.assertEqual(
                    raised.exception.reason_code,
                    "FACT_STORE_MEMBER_REFERENCE_DESCRIPTOR_INVALID",
                )

    def test_real_method_type_constants_expand_through_helper_and_store(self):
        artifact = self.root / "method-types.jar"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr(
                "audit/MethodTypeCorpus.class", METHOD_TYPE_CORPUS_CLASS
            )
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)

        helper_constants = {
            method["contract"]["name"]: instruction[2]
            for record in snapshot.class_records
            for method in record.get("methods") or ()
            for instruction in method.get("instructions") or ()
            if instruction[0] == "ldc"
        }
        with BinaryFactStore() as store:
            store.add_artifact_snapshot(instance, snapshot)
            rows = store.connection.execute(
                """
                SELECT m.member_name,e.symbolic_owner,e.symbolic_descriptor,
                       e.edge_json
                FROM direct_edges AS e
                JOIN members AS m
                  ON m.member_identity=e.caller_member_identity
                WHERE e.edge_kind='type'
                ORDER BY m.member_name,e.symbolic_owner
                """
            ).fetchall()
            grouped = store.connection.execute(
                """
                SELECT m.member_name,e.bytecode_offset,e.edge_kind,COUNT(*) AS n
                FROM direct_edges AS e
                JOIN members AS m
                  ON m.member_identity=e.caller_member_identity
                WHERE m.member_name='objectAndArrays' AND e.edge_kind='type'
                GROUP BY m.member_name,e.bytecode_offset,e.edge_kind
                """
            ).fetchone()
            duplicate = tuple(store.connection.execute(
                "SELECT * FROM direct_edges LIMIT 1"
            ).fetchone())
            with self.assertRaises(sqlite3.IntegrityError):
                store.connection.execute(
                    "INSERT INTO direct_edges VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    duplicate,
                )

        self.assertTrue(all(
            constant["kind"] == "method_type"
            for constant in helper_constants.values()
        ))
        by_method = {}
        for row in rows:
            by_method.setdefault(row["member_name"], []).append(
                row["symbolic_owner"]
            )
            self.assertEqual(
                json.loads(row["edge_json"])["type_use_kind"],
                "method_type_descriptor",
            )
        self.assertNotIn("primitiveOnly", by_method)
        self.assertEqual(grouped["n"], 4)
        self.assertEqual(by_method["duplicate"], ["java/lang/String"])
        self.assertEqual(by_method["objectAndArrays"], [
            "audit/Thing", "java/lang/String", "java/util/List",
            "java/util/Map",
        ])

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

    def test_reconciliation_v11_columnar_payload_is_exact_and_canonical(self):
        records = [
            {
                "analysis_context_identity": "context",
                "record_kind": "member_resolution",
                "status": "resolved",
                "subject_identity": f"subject-{index}",
                "payload": (
                    {"z": index, "a": None}
                    if index == 0 else {"a": False, "z": index}
                ),
            }
            for index in range(2)
        ]
        with BinaryFactStore() as store:
            expected_identities = store.add_reconciliation_records(records)
            row = store.connection.execute(
                "SELECT payload_zlib,metadata_zlib FROM reconciliation_records"
            ).fetchone()
            payload = json.loads(zlib.decompress(row[0]).decode("utf-8"))
            metadata = json.loads(zlib.decompress(row[1]).decode("utf-8"))
            restored = store.rows("reconciliation_records")

        self.assertEqual(
            payload,
            {
                "format": "binary-reconciliation-columnar-payload-v1",
                "records": [[0, None, 0], [0, False, 1]],
                "shapes": [["a", "z"]],
            },
        )
        self.assertEqual(
            metadata,
            {
                "format": "binary-reconciliation-metadata-array-v1",
                "records": [
                    ["resolved", "subject-0"],
                    ["resolved", "subject-1"],
                ],
            },
        )
        self.assertEqual(
            [row["record_identity"] for row in restored], expected_identities
        )
        self.assertEqual(
            [json.loads(row["payload_json"]) for row in restored],
            [record["payload"] for record in records],
        )

    def test_reconciliation_v11_derived_metadata_round_trips_exactly(self):
        payload = {
            "direct_edge_identity": "edge",
            "member_resolution_status": "resolved",
            "member_resolution_identity": "member",
            "optional": None,
        }
        with BinaryFactStore() as store:
            identities = store.add_reconciliation_payloads(
                analysis_context_identity="context",
                record_kind="member_resolution",
                records=[("resolved", "member", payload)],
                derive_metadata_from_payload=True,
            )
            metadata_zlib = store.connection.execute(
                "SELECT metadata_zlib FROM reconciliation_records"
            ).fetchone()[0]
            restored = store.rows("reconciliation_records")

        self.assertEqual(
            json.loads(zlib.decompress(metadata_zlib).decode("utf-8")),
            {
                "format": (
                    "binary-reconciliation-payload-field-metadata-v1"
                ),
                "status_field": "member_resolution_status",
                "subject_field": "member_resolution_identity",
            },
        )
        self.assertEqual(restored[0]["record_identity"], identities[0])
        self.assertEqual(json.loads(restored[0]["payload_json"]), payload)
        self.assertEqual(restored[0]["status"], "resolved")
        self.assertEqual(restored[0]["subject_identity"], "member")

    def test_reconciliation_v11_invalid_column_shape_fails_closed(self):
        with BinaryFactStore() as store:
            store.add_reconciliation_records([{
                "analysis_context_identity": "context",
                "record_kind": "member_resolution",
                "status": "resolved",
                "subject_identity": "subject",
                "payload": {"a": 1},
            }])
            invalid = {
                "format": "binary-reconciliation-columnar-payload-v1",
                "records": [[0, 1]],
                "shapes": [["a", "a"]],
            }
            store.connection.execute(
                "UPDATE reconciliation_records SET payload_zlib=?",
                (zlib.compress(json.dumps(invalid).encode("utf-8")),),
            )
            store.connection.commit()
            with self.assertRaises(BinaryFactStoreError) as caught:
                store.rows("reconciliation_records")

        self.assertEqual(
            caught.exception.reason_code,
            "FACT_STORE_RECONCILIATION_CHUNK_INVALID",
        )

    def test_reconciliation_v9_and_v10_chunks_remain_readable(self):
        fixtures = (
            (
                {
                    "format": "binary-reconciliation-payload-array-v1",
                    "records": [{"value": "v10"}],
                },
                {
                    "format": "binary-reconciliation-metadata-array-v1",
                    "records": [["resolved-v10", "subject-v10"]],
                },
                "v10",
                "resolved-v10",
                "subject-v10",
            ),
            (
                [{
                    "record_identity": "a" * 64,
                    "status": "resolved-v9",
                    "subject_identity": "subject-v9",
                    "payload": {"value": "v9"},
                }],
                {},
                "v9",
                "resolved-v9",
                "subject-v9",
            ),
        )
        for ordinal, (
            payload, metadata, value, status, subject,
        ) in enumerate(fixtures):
            with self.subTest(value=value), BinaryFactStore() as store:
                store.connection.execute(
                    "INSERT INTO metadata(key,value) VALUES(?,?)",
                    ("reconciliation_analysis_context_identity", "context"),
                )
                chunk_identity = bytes([ordinal + 1]) * 32
                store.connection.execute(
                    "INSERT INTO reconciliation_records VALUES(?,?,?,?,?)",
                    (
                        chunk_identity,
                        3,
                        1,
                        zlib.compress(json.dumps(payload).encode("utf-8")),
                        zlib.compress(json.dumps(metadata).encode("utf-8")),
                    ),
                )
                store.connection.execute(
                    "INSERT INTO reconciliation_chunk_order VALUES(?,?,?)",
                    (3, 0, chunk_identity),
                )
                store.connection.commit()
                restored = store.rows("reconciliation_records")
                hydrated = list(
                    store.reconciliation_payloads("member_resolution")
                )

            self.assertEqual(len(restored), 1)
            self.assertEqual(json.loads(restored[0]["payload_json"]), {
                "value": value,
            })
            self.assertEqual(restored[0]["status"], status)
            self.assertEqual(restored[0]["subject_identity"], subject)
            self.assertEqual(hydrated, [{"value": value}])

    def test_specialized_reconciliation_writer_is_byte_identical(self):
        ordinary_path = self.root / "ordinary.sqlite"
        specialized_path = self.root / "specialized.sqlite"
        records = [
            {
                "analysis_context_identity": "context-汉字",
                "record_kind": "member_resolution",
                "status": f"resolved-{index % 3}\n",
                "subject_identity": f"subject-{index:04d}",
                "payload": {
                    "index": index,
                    "nested": [True, None, -0.0, 'é\n"'],
                    "value": "共享" * 10,
                },
            }
            for index in range(2_005)
        ]
        with BinaryFactStore(ordinary_path) as ordinary:
            ordinary_identities = ordinary.add_reconciliation_records(records)
        with BinaryFactStore(specialized_path) as specialized:
            specialized_identities = specialized.add_reconciliation_payloads(
                analysis_context_identity="context-汉字",
                record_kind="member_resolution",
                records=(
                    (row["status"], row["subject_identity"], row["payload"])
                    for row in records
                ),
            )

        self.assertEqual(specialized_identities, ordinary_identities)
        self.assertEqual(specialized_path.read_bytes(), ordinary_path.read_bytes())

    def test_specialized_reconciliation_writer_can_join_outer_transaction(self):
        with BinaryFactStore() as store:
            store.connection.execute("BEGIN")
            store.add_reconciliation_payloads(
                analysis_context_identity="context",
                record_kind="member_resolution",
                records=[(
                    "resolved",
                    "subject",
                    {
                        "direct_edge_identity": "edge",
                        "member_resolution_status": "resolved",
                    },
                )],
                manage_transaction=False,
            )
            self.assertTrue(store.connection.in_transaction)
            self.assertEqual(store.counts()["reconciliation_records"], 1)
            store.connection.rollback()
            self.assertEqual(store.counts()["reconciliation_records"], 0)
            context = store.connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                ("reconciliation_analysis_context_identity",),
            ).fetchone()

        self.assertIsNone(context)

    def test_specialized_writer_rejects_unowned_bulk_transaction(self):
        with BinaryFactStore() as store:
            with self.assertRaises(BinaryFactStoreError) as caught:
                store.add_reconciliation_payloads(
                    analysis_context_identity="context",
                    record_kind="member_resolution",
                    records=[("resolved", "subject", {"value": 1})],
                    manage_transaction=False,
                )

        self.assertEqual(
            caught.exception.reason_code,
            "FACT_STORE_RECONCILIATION_TRANSACTION_MISSING",
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

    def test_single_large_class_bounds_member_and_edge_insert_batches(self):
        artifact = self.make_jar("single-large-class.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)
        record = dict(snapshot.class_records[0])
        record["fields"] = [
            {"name": f"field{index}", "descriptor": "I", "access": 1}
            for index in range(8)
        ]
        record["methods"] = [
            {
                "contract": {
                    "name": f"method{index}",
                    "descriptor": "()V",
                    "access": 1,
                },
                "implementation_digest": f"implementation-{index}",
                "instructions": [],
            }
            for index in range(8)
        ] + [
            {
                "contract": {
                    "name": "edgeHeavyMethod",
                    "descriptor": "()V",
                    "access": 1,
                },
                "implementation_digest": "edge-heavy-implementation",
                "instructions": [
                    [
                        "method",
                        index,
                        182,
                        "java/lang/String",
                        "trim",
                        "()Ljava/lang/String;",
                        False,
                    ]
                    for index in range(11)
                ],
            }
        ]
        large_snapshot = replace(snapshot, class_records=(record,))

        class RecordingConnection:
            def __init__(self, connection):
                self.connection = connection
                self.fact_batch_sizes = {
                    "classes": [],
                    "members": [],
                    "direct_edges": [],
                }

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def __enter__(self):
                self.connection.__enter__()
                return self

            def __exit__(self, exc_type, exc, traceback):
                return self.connection.__exit__(exc_type, exc, traceback)

            def executemany(self, sql, rows):
                for table in self.fact_batch_sizes:
                    if f"INSERT INTO {table} " in sql:
                        self.fact_batch_sizes[table].append(len(rows))
                        break
                return self.connection.executemany(sql, rows)

        with BinaryFactStore() as regular:
            regular_counts = regular.add_artifact_snapshot(instance, large_snapshot)
            regular_identity = regular.content_identity()
        with BinaryFactStore() as bounded:
            bounded.FACT_INSERT_CHUNK_SIZE = 3
            recording = RecordingConnection(bounded.connection)
            bounded.connection = recording
            bounded_counts = bounded.add_artifact_snapshot(instance, large_snapshot)
            bounded_identity = bounded.content_identity()
            batch_sizes = recording.fact_batch_sizes

        self.assertEqual(bounded_counts, regular_counts)
        self.assertEqual(bounded_identity, regular_identity)
        self.assertGreater(len(batch_sizes["members"]), 1)
        self.assertGreater(len(batch_sizes["direct_edges"]), 1)
        self.assertTrue(
            all(
                0 < batch_size <= 3
                for sizes in batch_sizes.values()
                for batch_size in sizes
            )
        )

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
            stored_fact = store.connection.execute(
                "SELECT artifact_instance_identity,fact_zlib,fact_zlib_sha256 "
                "FROM classes"
            ).fetchone()
            stored_header = dict(store.connection.execute(
                """
                SELECT class_access,super_name,interfaces_json,
                       nest_host,nest_members_json,has_runtime_annotations
                FROM classes
                """
            ).fetchone())
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
        self.assertIn("fact_zlib_sha256", columns)
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
        self.assertEqual(
            fact["artifact_instance_identity"], instance.identity
        )
        normalized_fact = zlib.decompress(stored_fact["fact_zlib"])
        self.assertNotIn(instance.identity.encode("ascii"), normalized_fact)
        self.assertIn(
            b"@binary-fact-store-row-artifact-instance-v1@",
            normalized_fact,
        )
        self.assertEqual(
            hashlib.sha256(stored_fact["fact_zlib"]).hexdigest(),
            stored_fact["fact_zlib_sha256"],
        )
        self.assertEqual(stored_header["class_access"], fact["class_access"])
        self.assertEqual(stored_header["super_name"], fact.get("super_name"))
        self.assertEqual(
            json.loads(stored_header["interfaces_json"]),
            fact.get("interfaces") or [],
        )
        self.assertEqual(stored_header["nest_host"], fact.get("nest_host"))
        self.assertEqual(
            json.loads(stored_header["nest_members_json"]),
            fact.get("nest_members") or [],
        )
        self.assertEqual(
            bool(stored_header["has_runtime_annotations"]),
            bool(fact.get("annotations"))
            or any(
                (field or {}).get("annotations")
                for field in fact.get("fields") or ()
            )
            or any(
                ((method or {}).get("contract") or {}).get("annotations")
                for method in fact.get("methods") or ()
            ),
        )
        self.assertLess(stored_lengths[0], len(self.class_bytes))
        self.assertLess(stored_lengths[1], len(row["fact_json"].encode("utf-8")))

    def test_normalized_class_fact_digest_tampering_fails_closed(self):
        artifact = self.make_jar("tampered-normalized-fact.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)

        with BinaryFactStore() as store:
            store.add_artifact_snapshot(instance, snapshot)
            store.connection.execute(
                "UPDATE classes SET fact_zlib_sha256=?",
                ("0" * 64,),
            )
            with self.assertRaises(BinaryFactStoreError) as raised:
                store.rows("classes")

        self.assertEqual(
            raised.exception.reason_code,
            "FACT_STORE_CLASS_FACT_DIGEST_MISMATCH",
        )

    def test_runtime_trigger_summary_is_incremental_complete_and_reopen_exact(self):
        first_artifact = self.make_jar("annotated-first.jar")
        first_instance = self.instance(first_artifact, 0)
        first_snapshot = self.snapshot(first_artifact, first_instance)
        first_record = dict(first_snapshot.class_records[0])
        first_record["super_name"] = "trigger/AnnotatedBase"
        first_record["interfaces"] = ["trigger/AnnotatedInterface"]
        first_record["annotations"] = [{"descriptor": "Ltrigger/Marker;"}]
        first_record["methods"] = list(first_record.get("methods") or ()) + [
            {
                "contract": {
                    "name": "main",
                    "descriptor": "([Ljava/lang/String;)V",
                    "access": 9,
                },
                "implementation_digest": "main-implementation",
                "instructions": [],
            }
        ]
        first_snapshot = replace(
            first_snapshot,
            class_records=(first_record,),
        )

        second_artifact = self.make_jar("later-hierarchy.jar")
        second_instance = self.instance(second_artifact, 1)
        second_snapshot = self.snapshot(second_artifact, second_instance)
        second_record = dict(second_snapshot.class_records[0])
        second_record["super_name"] = "trigger/LaterBase"
        second_record["interfaces"] = ["trigger/LaterInterface"]
        second_record["annotations"] = []
        second_snapshot = replace(
            second_snapshot,
            class_records=(second_record,),
        )
        database = self.root / "runtime-trigger-summary.sqlite"

        with BinaryFactStore(database) as store:
            store.add_artifact_snapshot(first_instance, first_snapshot)
            with patch(
                "binary_fact_store.zlib.decompress",
                side_effect=AssertionError("fresh summary decompressed facts"),
            ):
                first_summary = store.runtime_trigger_summary()
            self.assertEqual(
                first_summary,
                {
                    "has_runtime_annotations": True,
                    "hierarchy_types": frozenset({
                        "trigger/AnnotatedBase",
                        "trigger/AnnotatedInterface",
                    }),
                    "has_main_method": True,
                },
            )

            store.add_artifact_snapshot(second_instance, second_snapshot)
            with patch(
                "binary_fact_store.zlib.decompress",
                side_effect=AssertionError("merged summary decompressed facts"),
            ):
                incremental_summary = store.runtime_trigger_summary()

        with BinaryFactStore(database) as reopened, patch(
            "binary_fact_store.zlib.decompress",
            side_effect=AssertionError("reopened summary decompressed facts"),
        ):
            reopened_summary = reopened.runtime_trigger_summary()

        self.assertEqual(reopened_summary, incremental_summary)
        self.assertTrue(reopened_summary["has_runtime_annotations"])
        self.assertTrue(reopened_summary["has_main_method"])
        self.assertEqual(
            reopened_summary["hierarchy_types"],
            frozenset({
                "trigger/AnnotatedBase",
                "trigger/AnnotatedInterface",
                "trigger/LaterBase",
                "trigger/LaterInterface",
            }),
        )

    def test_runtime_trigger_summary_rejects_continuously_changing_snapshot(self):
        with BinaryFactStore() as store, patch.object(
            store,
            "_runtime_trigger_data_version",
            side_effect=range(7),
        ):
            with self.assertRaises(BinaryFactStoreError) as raised:
                store.runtime_trigger_summary()

        self.assertEqual(
            raised.exception.reason_code,
            "FACT_STORE_RUNTIME_TRIGGER_SUMMARY_UNSTABLE",
        )
        self.assertIn("observed_data_versions", str(raised.exception))

    def test_exact_backup_adopts_runtime_trigger_summary_defensively(self):
        artifact = self.make_jar("summary-backup.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)
        record = dict(snapshot.class_records[0])
        record["super_name"] = "trigger/BackupBase"
        record["interfaces"] = ["trigger/BackupInterface"]
        record["annotations"] = [{"descriptor": "Ltrigger/Marker;"}]
        record["methods"] = list(record.get("methods") or ()) + [{
            "contract": {
                "name": "main",
                "descriptor": "([Ljava/lang/String;)V",
                "access": 9,
            },
            "implementation_digest": "backup-main",
            "instructions": [],
        }]
        snapshot = replace(snapshot, class_records=(record,))

        with BinaryFactStore(
            self.root / "summary-backup-source.sqlite"
        ) as source, BinaryFactStore(
            self.root / "summary-backup-destination.sqlite"
        ) as destination:
            source.add_artifact_snapshot(instance, snapshot)
            source_view = source.runtime_trigger_summary()
            source_view["has_runtime_annotations"] = False
            source_view["hierarchy_types"] = frozenset()
            source_view["has_main_method"] = False
            self.assertEqual(
                destination.runtime_trigger_summary(),
                BinaryFactStore._empty_runtime_trigger_summary(),
            )
            source.connection.backup(destination.connection)
            destination.connection.commit()
            # SQLite backup mutates through the destination connection, so
            # data_version alone cannot observe this replacement.
            self.assertEqual(
                destination.runtime_trigger_summary(),
                BinaryFactStore._empty_runtime_trigger_summary(),
            )
            with patch(
                "binary_fact_store.zlib.decompress",
                side_effect=AssertionError("backup adoption rescanned facts"),
            ):
                adopted = (
                    destination
                    .adopt_runtime_trigger_summary_from_exact_backup(source)
                )
                cached = destination.runtime_trigger_summary()

            expected = {
                "has_runtime_annotations": True,
                "hierarchy_types": frozenset({
                    "trigger/BackupBase",
                    "trigger/BackupInterface",
                }),
                "has_main_method": True,
            }
            self.assertEqual(adopted, expected)
            self.assertEqual(cached, expected)
            adopted["has_runtime_annotations"] = False
            adopted["hierarchy_types"] = frozenset()
            adopted["has_main_method"] = False
            self.assertEqual(
                destination.runtime_trigger_summary(), expected
            )

    def test_runtime_trigger_summary_detects_other_connection_commit(self):
        artifact = self.make_jar("summary-concurrent.sqlite.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)
        record = dict(snapshot.class_records[0])
        record["super_name"] = "trigger/ConcurrentBase"
        record["interfaces"] = ["trigger/ConcurrentInterface"]
        record["annotations"] = [{"descriptor": "Ltrigger/Marker;"}]
        snapshot = replace(snapshot, class_records=(record,))
        database = self.root / "summary-concurrent.sqlite"

        with BinaryFactStore(database) as reader, BinaryFactStore(
            database
        ) as writer:
            self.assertFalse(
                reader.runtime_trigger_summary()[
                    "has_runtime_annotations"
                ]
            )
            version_before = reader.connection.execute(
                "PRAGMA data_version"
            ).fetchone()[0]
            writer.add_artifact_snapshot(instance, snapshot)
            version_after = reader.connection.execute(
                "PRAGMA data_version"
            ).fetchone()[0]
            observed = reader.runtime_trigger_summary()

        self.assertNotEqual(version_before, version_after)
        self.assertTrue(observed["has_runtime_annotations"])
        self.assertEqual(
            observed["hierarchy_types"],
            frozenset({
                "trigger/ConcurrentBase",
                "trigger/ConcurrentInterface",
            }),
        )

    def test_runtime_trigger_backup_adoption_rejects_mismatch_and_bad_source(self):
        artifact = self.make_jar("summary-mismatch.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)

        with BinaryFactStore() as source, BinaryFactStore() as destination:
            source.add_artifact_snapshot(instance, snapshot)
            with self.assertRaises(BinaryFactStoreError) as mismatch:
                destination.adopt_runtime_trigger_summary_from_exact_backup(
                    source
                )
            with self.assertRaises(BinaryFactStoreError) as invalid_source:
                destination.adopt_runtime_trigger_summary_from_exact_backup(
                    object()
                )

        self.assertEqual(
            mismatch.exception.reason_code,
            "FACT_STORE_RUNTIME_TRIGGER_BACKUP_MISMATCH",
        )
        self.assertEqual(
            invalid_source.exception.reason_code,
            "FACT_STORE_RUNTIME_TRIGGER_BACKUP_SOURCE_INVALID",
        )

        with BinaryFactStore() as source, BinaryFactStore() as destination:
            adopted_empty = (
                destination
                .adopt_runtime_trigger_summary_from_exact_backup(source)
            )
        self.assertEqual(
            adopted_empty, BinaryFactStore._empty_runtime_trigger_summary()
        )

    def test_runtime_trigger_backup_adoption_rejects_invalid_summary_shape(self):
        with BinaryFactStore() as source, BinaryFactStore() as destination:
            with patch.object(
                source,
                "runtime_trigger_summary",
                return_value={
                    "has_runtime_annotations": 0,
                    "hierarchy_types": [],
                    "has_main_method": False,
                },
            ):
                with self.assertRaises(BinaryFactStoreError) as raised:
                    destination.adopt_runtime_trigger_summary_from_exact_backup(
                        source
                    )

        self.assertEqual(
            raised.exception.reason_code,
            "FACT_STORE_RUNTIME_TRIGGER_SUMMARY_INVALID",
        )

    def test_field_and_method_annotations_each_set_runtime_trigger_summary(self):
        artifact = self.make_jar("summary-member-annotations.jar")
        for annotation_location in ("field", "method"):
            with self.subTest(annotation_location=annotation_location):
                instance = self.instance(artifact, 0)
                snapshot = self.snapshot(artifact, instance)
                record = dict(snapshot.class_records[0])
                record["annotations"] = []
                if annotation_location == "field":
                    fields = [
                        dict(field)
                        for field in record.get("fields") or ()
                    ]
                    fields[0]["annotations"] = [{
                        "descriptor": "Ltrigger/FieldMarker;"
                    }]
                    record["fields"] = fields
                else:
                    methods = []
                    for index, method in enumerate(
                        record.get("methods") or ()
                    ):
                        method = dict(method)
                        contract = dict(method.get("contract") or {})
                        if index == 0:
                            contract["annotations"] = [{
                                "descriptor": "Ltrigger/MethodMarker;"
                            }]
                        method["contract"] = contract
                        methods.append(method)
                    record["methods"] = methods
                snapshot = replace(snapshot, class_records=(record,))
                with BinaryFactStore() as store:
                    store.add_artifact_snapshot(instance, snapshot)
                    summary = store.runtime_trigger_summary()
                self.assertTrue(summary["has_runtime_annotations"])

    def test_bulk_integrity_rollback_invalidates_incremental_summary(self):
        artifact = self.make_jar("summary-bulk-rollback.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)
        record = dict(snapshot.class_records[0])
        record["annotations"] = [{"descriptor": "Ltrigger/Marker;"}]
        snapshot = replace(snapshot, class_records=(record,))

        with BinaryFactStore(bulk_load_transaction=True) as store:
            store.add_artifact_snapshot(instance, snapshot)
            self.assertTrue(
                store.runtime_trigger_summary()[
                    "has_runtime_annotations"
                ]
            )
            with self.assertRaises(BinaryFactStoreError):
                store.add_artifact_snapshot(instance, snapshot)
            after_rollback = store.runtime_trigger_summary()
            class_count = store.connection.execute(
                "SELECT COUNT(*) FROM classes"
            ).fetchone()[0]

        self.assertEqual(class_count, 0)
        self.assertEqual(
            after_rollback, BinaryFactStore._empty_runtime_trigger_summary()
        )

    def test_failed_snapshot_does_not_pollute_runtime_trigger_summary(self):
        artifact = self.make_jar("summary-base.jar")
        instance = self.instance(artifact, 0)
        snapshot = self.snapshot(artifact, instance)
        failing_artifact = self.make_jar("summary-failing.jar")
        failing_instance = self.instance(failing_artifact, 1)
        failing_snapshot = self.snapshot(failing_artifact, failing_instance)
        failing_record = dict(failing_snapshot.class_records[0])
        failing_record["super_name"] = "poison/FailedBase"
        failing_record["interfaces"] = ["poison/FailedInterface"]
        failing_record["annotations"] = [{"descriptor": "Lpoison/Marker;"}]
        failing_record["methods"] = list(
            failing_record.get("methods") or ()
        ) + [{
            "contract": {
                "name": "main",
                "descriptor": "([Ljava/lang/String;)V",
                "access": 9,
            },
            "implementation_digest": "poison-main",
            "instructions": [],
        }]
        failing_snapshot = replace(
            failing_snapshot,
            class_records=(failing_record,),
        )

        class FailingClassInsertConnection:
            def __init__(self, connection):
                self.connection = connection

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def __enter__(self):
                self.connection.__enter__()
                return self

            def __exit__(self, exc_type, exc, traceback):
                return self.connection.__exit__(exc_type, exc, traceback)

            def executemany(self, sql, rows):
                if "INSERT INTO classes " in sql:
                    raise sqlite3.IntegrityError("synthetic class conflict")
                return self.connection.executemany(sql, rows)

        with BinaryFactStore() as store:
            store.add_artifact_snapshot(instance, snapshot)
            expected = store.runtime_trigger_summary()
            store.connection = FailingClassInsertConnection(store.connection)
            with self.assertRaises(BinaryFactStoreError) as raised:
                store.add_artifact_snapshot(
                    failing_instance,
                    failing_snapshot,
                )
            with patch(
                "binary_fact_store.zlib.decompress",
                side_effect=AssertionError("failed add invalidated cache"),
            ):
                after_failure = store.runtime_trigger_summary()
            artifact_count = store.connection.execute(
                "SELECT COUNT(*) FROM artifact_instances"
            ).fetchone()[0]

        self.assertEqual(
            raised.exception.reason_code,
            "FACT_STORE_IDENTITY_CONFLICT",
        )
        self.assertEqual(after_failure, expected)
        self.assertEqual(artifact_count, 1)
        self.assertNotIn(
            "poison/FailedBase",
            after_failure["hierarchy_types"],
        )

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
