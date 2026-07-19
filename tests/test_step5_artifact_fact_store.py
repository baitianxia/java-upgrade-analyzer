import csv
import hashlib
import json
import sys
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from real_project_regression import (  # noqa: E402
    cold_run_metrics,
    step5_result_contract,
)
from step5_artifact_fact_store import FactOutcome, Step5ArtifactFactStore  # noqa: E402
from business_bytecode_graph import collect_business_bytecode_batch  # noqa: E402
from s5_call_chain_engine_integrated import (  # noqa: E402
    EVIDENCE_FAILURE_OCCURRENCE_FIELDS,
    _serialize_ingestion_failure,
    _write_step5_timing_csv,
)
from step5_evidence_model import EvidenceFailure, EvidenceFailureOccurrence  # noqa: E402


class Step5ColdRunContractTest(unittest.TestCase):
    def test_stream_reader_does_not_spool_archive_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "artifact.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("demo/One.class", b"one")
            entry = {
                "coord": "g:a", "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})

            with patch(
                "step5_artifact_fact_store.tempfile.TemporaryFile",
                side_effect=AssertionError("disk spool must not be used"),
            ):
                self.assertEqual(1, len(list(store.iter_class_bytes("g:a"))))

    def test_inventory_rejects_exact_duplicate_class_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "artifact.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("demo/Duplicate.class", b"first")
                archive.writestr("demo/Duplicate.class", b"second")
            entry = {
                "coord": "g:a", "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})

            with self.assertRaisesRegex(ValueError, "artifact_duplicate_entries"):
                store.verified_inventory("g:a")

    def test_physical_class_stream_checks_identity_when_closed_early(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "artifact.jar"
            replacement = Path(tmp) / "replacement.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("demo/Original.class", b"original")
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr("demo/Replaced.class", b"replacement")
            entry = {
                "coord": "g:a", "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})
            stream = store.iter_physical_class_bytes("g:a")
            next(stream)
            replacement.replace(jar)

            with self.assertRaisesRegex(ValueError, "artifact_changed_after_inventory"):
                stream.close()

    def test_verified_artifact_checks_identity_when_body_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "artifact.jar"
            replacement = Path(tmp) / "replacement.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("demo/Original.class", b"original")
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr("demo/Replaced.class", b"replacement")
            entry = {
                "coord": "g:a", "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})

            with self.assertRaisesRegex(ValueError, "artifact_changed_after_inventory"):
                with store.open_verified_artifact("g:a"):
                    replacement.replace(jar)
                    raise RuntimeError("parse")

    def test_stream_reader_bounds_prefetch_cache_and_rereads_evicted_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "artifact.jar"
            with zipfile.ZipFile(jar, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for index in range(16):
                    archive.writestr(
                        f"demo/Class{index:02d}.class", b"x" * (1024 * 1024),
                    )
            entry = {
                "coord": "g:a", "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})
            locations = store.verified_inventory("g:a").classes
            stream = store.iter_class_bytes_with_reader("g:a")
            first_location, _first_content, reader = next(stream)

            import tracemalloc
            tracemalloc.start()
            for location in locations[1:]:
                reader(location)
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            reads_before = store.metrics()["class_bytes_reads"]
            reader(first_location)
            reads_after = store.metrics()["class_bytes_reads"]
            stream.close()

        self.assertLess(peak, 8 * 1024 * 1024)
        self.assertLessEqual(store.metrics()["stream_cache_peak_bytes"], 4 * 1024 * 1024)
        self.assertGreater(store.metrics()["stream_cache_evictions"], 0)
        self.assertEqual(reads_before + 1, reads_after)

    def test_ingestion_failure_serialization_uses_compact_occurrence_rows(self):
        occurrence = EvidenceFailureOccurrence(
            caller_symbol="com.acme.App.run()",
            caller_qualified_key="com.acme.App.run()",
            artifact="/app.jar",
            artifact_entry="com/acme/App.class",
            class_name="com.acme.App",
            line=12,
            instruction_offset=4,
            detail="lookup detail",
        )
        payload = _serialize_ingestion_failure(
            "business_bytecode",
            EvidenceFailure(
                stage="evidence-ingestion",
                reason_code="BYTECODE_CALLER_UNRESOLVED",
                blocking=True,
                api_identity="com.vendor.Legacy.call()",
                occurrences=(occurrence,),
            ),
        )

        self.assertEqual(
            EVIDENCE_FAILURE_OCCURRENCE_FIELDS,
            (
                "caller_symbol", "caller_qualified_key", "artifact",
                "artifact_entry", "class_name", "line",
                "instruction_offset", "detail",
            ),
        )
        self.assertEqual(len(payload["occurrences"]), 1)
        self.assertIsInstance(payload["occurrences"][0], tuple)
        self.assertEqual(payload["occurrences"][0][0], "com.acme.App.run()")
    def test_step5_timing_exposes_shared_artifact_fact_cost_and_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_step5_timing_csv(tmp, {"step5_perf": {
                "artifact_facts": {
                    "inventory_elapsed_sec": 1.25,
                    "inventory_builds": 2,
                    "inventory_hits": 7,
                    "fact_hits": 5,
                },
            }})
            with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

        values = {(row["section"], row["metric"]): row["value"] for row in rows}
        self.assertEqual("1.25", values[("artifact_facts", "inventory_elapsed_sec")])
        self.assertEqual("7", values[("artifact_facts", "inventory_hits")])

    def _write_report(
        self, root, *, status="reachable", path_text="A -> B",
        evidence_ingestion=None,
    ):
        root = Path(root)
        call_chain = root / "evidence" / "call_chain"
        call_chain.mkdir(parents=True)
        (call_chain / "summary.json").write_text(
            json.dumps({
                "generated_at": "volatile",
                "reachable": int(status == "reachable"),
                "meta": {"graph_stats": {
                    "step5_perf": {"trace": {"elapsed_sec": 1.0}},
                    **({"evidence_ingestion": evidence_ingestion}
                       if evidence_ingestion is not None else {}),
                }},
            }),
            encoding="utf-8",
        )
        with (call_chain / "alerts.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "api_id", "api_status", "path_text", "evidence_files",
            ])
            writer.writeheader()
            writer.writerow({
                "api_id": "API-1",
                "api_status": status,
                "path_text": path_text,
                "evidence_files": str(root / "current.jar!/example/A.class"),
            })

    def test_contract_ignores_report_root_and_runtime_telemetry(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            self._write_report(first)
            self._write_report(second)

            self.assertEqual(
                step5_result_contract(Path(first)),
                step5_result_contract(Path(second)),
            )

    def test_contract_changes_when_path_changes(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            self._write_report(first, path_text="A -> B")
            self._write_report(second, path_text="A -> C -> B")

            self.assertNotEqual(
                step5_result_contract(Path(first)),
                step5_result_contract(Path(second)),
            )

    def test_contract_treats_query_reverse_edge_bucket_as_unordered(self):
        edges = [
            {"caller_symbol_id": "B", "callee_key": "target()", "line": 2},
            {"caller_symbol_id": "A", "callee_key": "target()", "line": 1},
        ]
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for root, bucket in ((Path(first), edges), (Path(second), list(reversed(edges)))):
                self._write_report(root)
                index = root / ".runtime" / "indexes" / "s5_query_index.json"
                index.parent.mkdir(parents=True)
                index.write_text(json.dumps({
                    "methods_by_id": {},
                    "reverse_edges": {"target()": bucket},
                }), encoding="utf-8")

            self.assertEqual(
                step5_result_contract(Path(first)),
                step5_result_contract(Path(second)),
            )

    def test_contract_preserves_grouped_ingestion_failure_occurrences(self):
        failure = {
            "reason_code": "BYTECODE_CALLER_UNRESOLVED",
            "blocking": True,
            "api_identity": "com.vendor.Legacy.call()",
            "class_name": "com.acme.First",
            "detail": "first caller",
            "occurrences": [{
                "caller_symbol": "com.acme.First.run()",
                "caller_qualified_key": "com.acme.First.run()",
                "artifact": "/app.jar",
                "artifact_entry": "com/acme/First.class",
                "class_name": "com.acme.First",
                "line": 12,
                "instruction_offset": 4,
                "detail": "first caller",
            }],
        }
        with (
            tempfile.TemporaryDirectory() as first,
            tempfile.TemporaryDirectory() as second,
            tempfile.TemporaryDirectory() as changed,
        ):
            self._write_report(first, evidence_ingestion={
                "rejected_edges": 2,
                "failure_count": 1,
                "failures": [{**failure, "occurrences": [
                    *failure["occurrences"],
                    {
                        **failure["occurrences"][0],
                        "caller_symbol": "com.acme.Second.run()",
                        "caller_qualified_key": "com.acme.Second.run()",
                        "artifact_entry": "com/acme/Second.class",
                        "class_name": "com.acme.Second",
                        "line": 24,
                    },
                ]}],
                "reason_codes": ["BYTECODE_CALLER_UNRESOLVED"],
            })
            self._write_report(second, evidence_ingestion={
                "rejected_edges": 2,
                "failure_count": 1,
                "failures": [failure],
                "reason_codes": ["BYTECODE_CALLER_UNRESOLVED"],
            })

            self.assertNotEqual(
                step5_result_contract(Path(first)),
                step5_result_contract(Path(second)),
            )
            self._write_report(changed, evidence_ingestion={
                "rejected_edges": 1,
                "failure_count": 1,
                "failures": [{**failure, "api_identity": "com.vendor.Other.call()"}],
                "reason_codes": ["BYTECODE_CALLER_UNRESOLVED"],
            })
            self.assertNotEqual(
                step5_result_contract(Path(first)),
                step5_result_contract(Path(changed)),
            )

    def test_contract_rejects_missing_step5_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                step5_result_contract(Path(tmp))

    def test_cold_run_metrics_reads_utf8_bom_timing_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            timing = Path(tmp) / ".runtime" / "observability" / "step5_timing.csv"
            timing.parent.mkdir(parents=True)
            timing.write_text(
                "\ufeffsection,metric,value\nartifact_facts,inventory_builds,2\n",
                encoding="utf-8",
            )

            self.assertEqual(
                cold_run_metrics(Path(tmp)),
                {"artifact_facts.inventory_builds": "2"},
            )


class ArtifactInventoryTest(unittest.TestCase):
    def _catalog(self, jar_path, *, target_jdk="17", sha256=None):
        digest = sha256 or hashlib.sha256(Path(jar_path).read_bytes()).hexdigest()
        entry = {
            "coord": "com.example:fixture",
            "jar_path": str(jar_path),
            "sha256": digest,
            "artifact_entry": "BOOT-INF/lib/fixture.jar",
        }
        return {
            "target_jdk": target_jdk,
            "by_coord": {entry["coord"]: entry},
            "entries": [entry],
        }

    def _write_jar(self, path, *, multi_release=True):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", (
                "Manifest-Version: 1.0\n"
                + ("Multi-Release: true\n" if multi_release else "")
            ))
            archive.writestr("com/example/A.class", b"base")
            archive.writestr("com/example/B.class", b"base-b")
            archive.writestr("META-INF/versions/11/com/example/A.class", b"v11")
            archive.writestr("META-INF/versions/17/com/example/A.class", b"v17")
            archive.writestr("META-INF/services/com.example.Service", b"impl")

    def test_selects_effective_multi_release_class_for_target_jdk(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            self._write_jar(jar_path)

            inventory = Step5ArtifactFactStore.from_catalog(
                self._catalog(jar_path, target_jdk="11")
            ).inventory("com.example:fixture")

        self.assertEqual(inventory.failure, "")
        self.assertEqual(
            [(item.logical_name, item.physical_entry, item.multi_release_version)
             for item in inventory.classes],
            [
                ("com/example/A.class", "META-INF/versions/11/com/example/A.class", 11),
                ("com/example/B.class", "com/example/B.class", "base"),
            ],
        )
        self.assertEqual(
            inventory.resources,
            ("META-INF/MANIFEST.MF", "META-INF/services/com.example.Service"),
        )

    def test_without_multi_release_manifest_ignores_versioned_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            self._write_jar(jar_path, multi_release=False)

            inventory = Step5ArtifactFactStore.from_catalog(
                self._catalog(jar_path, target_jdk="17")
            ).inventory("com.example:fixture")

        self.assertEqual(
            [item.physical_entry for item in inventory.classes],
            ["com/example/A.class", "com/example/B.class"],
        )

    def test_inventory_is_singleton_per_artifact_and_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            self._write_jar(jar_path)
            store = Step5ArtifactFactStore.from_catalog(self._catalog(jar_path))

            first = store.inventory("com.example:fixture")
            second = store.inventory("com.example:fixture")

        self.assertIs(first, second)
        with self.assertRaises(Exception):
            first.failure = "changed"

    def test_sha_mismatch_is_explicit_failure_not_empty_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            self._write_jar(jar_path)
            store = Step5ArtifactFactStore.from_catalog(
                self._catalog(jar_path, sha256="0" * 64)
            )

            inventory = store.inventory("com.example:fixture")

        self.assertIn("sha256_mismatch", inventory.failure)
        self.assertEqual(inventory.classes, ())

    def test_corrupt_archive_is_explicit_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "broken.jar"
            jar_path.write_bytes(b"not-a-zip")
            store = Step5ArtifactFactStore.from_catalog(self._catalog(jar_path))

            inventory = store.inventory("com.example:fixture")

        self.assertIn("BadZipFile", inventory.failure)
        self.assertEqual(inventory.classes, ())

    def test_inventory_hashes_and_reads_the_same_descriptor_when_symlink_retargets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.jar"
            replacement = root / "replacement.jar"
            link = root / "runtime.jar"
            with zipfile.ZipFile(original, "w") as archive:
                archive.writestr("com/example/Original.class", b"original")
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr("com/example/Replacement.class", b"replacement")
            link.symlink_to(original)
            store = Step5ArtifactFactStore.from_catalog(
                self._catalog(
                    link, sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
                )
            )
            real_zip_file = zipfile.ZipFile

            def retarget_while_opening(source, *args, **kwargs):
                link.unlink()
                link.symlink_to(replacement)
                opened = real_zip_file(source, *args, **kwargs)
                link.unlink()
                link.symlink_to(original)
                return opened

            with patch(
                "step5_artifact_fact_store.zipfile.ZipFile",
                side_effect=retarget_while_opening,
            ):
                inventory = store.inventory("com.example:fixture")

        self.assertEqual("", inventory.failure)
        self.assertEqual(
            [item.binary_name for item in inventory.classes],
            ["com.example.Original"],
        )


class ResourceFactTest(unittest.TestCase):
    def _store_with_resource(self, tmp):
        jar = Path(tmp) / "runtime.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            archive.writestr("META-INF/spring.factories", b"original-resource")
            archive.writestr("example/Impl.class", b"original-class")
        digest = hashlib.sha256(jar.read_bytes()).hexdigest()
        store = Step5ArtifactFactStore.from_catalog({
            "entries": [{"coord": "g:a", "jar_path": str(jar), "sha256": digest}],
        })
        location = store.inventory("g:a").classes[0]
        return jar, store, location

    def _atomically_replace_jar(self, jar):
        replacement = jar.with_name("replacement.jar")
        with zipfile.ZipFile(replacement, "w") as archive:
            archive.writestr("META-INF/spring.factories", b"replacement-resource")
            archive.writestr("example/Impl.class", b"replacement-class")
        replacement.replace(jar)

    def test_class_bytes_rejects_artifact_replaced_after_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar, store, location = self._store_with_resource(tmp)
            self._atomically_replace_jar(jar)

            outcome = store.class_bytes("g:a", location)

        self.assertEqual("failed", outcome.status)
        self.assertIn("artifact_changed_after_inventory", outcome.reason)

    def test_resource_bytes_rejects_artifact_replaced_after_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar, store, _location = self._store_with_resource(tmp)
            self._atomically_replace_jar(jar)

            outcome = store.resource_bytes("g:a", "META-INF/spring.factories")

        self.assertEqual("failed", outcome.status)
        self.assertIn("artifact_changed_after_inventory", outcome.reason)

    def test_javap_rejects_artifact_replaced_after_inventory_without_running_producer(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar, store, location = self._store_with_resource(tmp)
            self._atomically_replace_jar(jar)
            calls = []

            outcome = store.javap_fact(
                "g:a", location, "verbose",
                lambda *_args: calls.append(1) or ("replacement", "", 0),
                retain=False,
            )

        self.assertEqual("failed", outcome.status)
        self.assertIn("artifact_changed_after_inventory", outcome.reason)
        self.assertEqual([], calls)

    def test_cached_resource_is_not_reused_after_artifact_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar, store, _location = self._store_with_resource(tmp)
            first = store.resource_bytes("g:a", "META-INF/spring.factories")
            self.assertEqual("complete", first.status)
            self._atomically_replace_jar(jar)

            second = store.resource_bytes("g:a", "META-INF/spring.factories")

        self.assertEqual("failed", second.status)
        self.assertIn("artifact_changed_after_inventory", second.reason)

    def test_cached_javap_is_not_reused_after_artifact_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar, store, location = self._store_with_resource(tmp)
            first = store.javap_fact(
                "g:a", location, "verbose", lambda *_args: ("original", "", 0),
            )
            self.assertEqual("complete", first.status)
            self._atomically_replace_jar(jar)

            second = store.javap_fact(
                "g:a", location, "verbose",
                lambda *_args: self.fail("replaced artifact must not run producer"),
            )

        self.assertEqual("failed", second.status)
        self.assertIn("artifact_changed_after_inventory", second.reason)

    def test_javap_uses_verified_class_bytes_when_symlink_retargets_and_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.jar"
            replacement = root / "replacement.jar"
            link = root / "runtime.jar"
            with zipfile.ZipFile(original, "w") as archive:
                archive.writestr("example/Impl.class", b"original-class")
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr("example/Impl.class", b"replacement-class")
            link.symlink_to(original)
            digest = hashlib.sha256(original.read_bytes()).hexdigest()
            store = Step5ArtifactFactStore.from_catalog({
                "entries": [{"coord": "g:a", "jar_path": str(link), "sha256": digest}],
            })
            location = store.inventory("g:a").classes[0]

            def producer(identity, bound_location, _profile):
                link.unlink()
                link.symlink_to(replacement)
                try:
                    class_path = (
                        Path(identity.path)
                        / (bound_location.binary_name.replace(".", "/") + ".class")
                    )
                    return class_path.read_bytes()
                finally:
                    link.unlink()
                    link.symlink_to(original)

            outcome = store.javap_fact(
                "g:a", location, "verbose", producer, retain=False,
            )

        self.assertEqual("complete", outcome.status)
        self.assertEqual(b"original-class", outcome.value)

    def test_resource_bytes_are_sha_bound_and_shared_without_reopening_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "runtime.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("META-INF/spring.factories", "example.Factory=example.Impl\n")
                archive.writestr("example/Impl.class", b"class-bytes")
            digest = hashlib.sha256(jar.read_bytes()).hexdigest()
            store = Step5ArtifactFactStore.from_catalog({
                "entries": [{"coord": "g:a", "jar_path": str(jar), "sha256": digest}],
            })

            first = store.resource_bytes("g:a", "META-INF/spring.factories")
            second = store.resource_bytes("g:a", "META-INF/spring.factories")

            self.assertEqual("complete", first.status)
            self.assertEqual(b"example.Factory=example.Impl\n", first.value)
            self.assertEqual(first, second)
            self.assertEqual(1, store.metrics()["resource_bytes_reads"])
            self.assertGreaterEqual(store.metrics()["fact_hits"], 1)

    def test_resource_bytes_reports_missing_resource_instead_of_empty_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "runtime.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("example/Impl.class", b"class-bytes")
            digest = hashlib.sha256(jar.read_bytes()).hexdigest()
            store = Step5ArtifactFactStore.from_catalog({
                "entries": [{"coord": "g:a", "jar_path": str(jar), "sha256": digest}],
            })

            outcome = store.resource_bytes("g:a", "META-INF/spring.factories")

            self.assertEqual("failed", outcome.status)
            self.assertIn("resource_not_in_inventory", outcome.reason)


class SingleFlightFactTest(unittest.TestCase):
    def test_class_fact_from_bytes_reuses_the_same_sha_bound_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "fixture.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/example/A.class", b"class-data")
            digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
            store = Step5ArtifactFactStore.from_catalog({"entries": [{
                "coord": "g:a", "jar_path": str(jar_path), "sha256": digest,
            }]})
            location = store.inventory("g:a").classes[0]
            calls = []

            first = store.class_fact_from_bytes(
                "g:a", location, "constant-pool-summary-v1", b"class-data",
                lambda data: calls.append(data) or ("summary", len(data)),
            )
            second = store.class_fact_from_bytes(
                "g:a", location, "constant-pool-summary-v1", b"class-data",
                lambda _data: self.fail("cached fact producer must not run twice"),
            )

            self.assertEqual(first, second)
            self.assertEqual([b"class-data"], calls)
            self.assertEqual(0, store.metrics()["class_bytes_reads"])

    def _store_and_location(self, tmp):
        jar_path = Path(tmp) / "fixture.jar"
        with zipfile.ZipFile(jar_path, "w") as archive:
            archive.writestr("com/example/A.class", b"class-bytes")
        digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
        entry = {
            "coord": "com.example:fixture",
            "jar_path": str(jar_path),
            "sha256": digest,
            "artifact_entry": "BOOT-INF/lib/fixture.jar",
        }
        store = Step5ArtifactFactStore.from_catalog({
            "target_jdk": "17", "entries": [entry],
        })
        location = store.inventory(entry["coord"]).classes[0]
        return store, entry["coord"], location

    def test_concurrent_class_fact_runs_producer_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, coord, location = self._store_and_location(tmp)
            calls = 0
            calls_lock = threading.Lock()

            def producer(content):
                nonlocal calls
                with calls_lock:
                    calls += 1
                time.sleep(0.02)
                return (content.decode("ascii"),)

            results = []
            threads = [threading.Thread(
                target=lambda: results.append(
                    store.class_fact(coord, location, "header-v1", producer)
                )
            ) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(calls, 1)
        self.assertEqual(len(results), 8)
        self.assertTrue(all(item is results[0] for item in results))
        self.assertEqual(results[0], FactOutcome("complete", ("class-bytes",), "", "classfile"))

    def test_failure_is_shared_and_never_becomes_empty_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, coord, location = self._store_and_location(tmp)
            calls = 0

            def producer(_content):
                nonlocal calls
                calls += 1
                raise ValueError("broken class")

            first = store.class_fact(coord, location, "header-v1", producer)
            second = store.class_fact(coord, location, "header-v1", producer)

        self.assertEqual(calls, 1)
        self.assertIs(first, second)
        self.assertEqual(first.status, "failed")
        self.assertIn("ValueError: broken class", first.reason)
        self.assertIsNone(first.value)

    def test_namespaces_and_javap_profiles_do_not_collide(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, coord, location = self._store_and_location(tmp)
            calls = []

            first = store.class_fact(
                coord, location, "header-v1",
                lambda _content: calls.append("header") or ("header",),
            )
            second = store.class_fact(
                coord, location, "constant-pool-v1",
                lambda _content: calls.append("constant-pool") or ("cp",),
            )
            verbose = store.javap_fact(
                coord, location, "verbose-code-v1",
                lambda _identity, _location, profile: calls.append(profile) or "verbose",
            )
            header = store.javap_fact(
                coord, location, "header-v1",
                lambda _identity, _location, profile: calls.append(profile) or "header",
            )

        self.assertEqual(first.value, ("header",))
        self.assertEqual(second.value, ("cp",))
        self.assertEqual(verbose.value, "verbose")
        self.assertEqual(header.value, "header")
        self.assertEqual(calls, ["header", "constant-pool", "verbose-code-v1", "header-v1"])

    def test_non_retained_javap_fact_does_not_accumulate_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, coord, location = self._store_and_location(tmp)
            starts = []

            def produce(*_args):
                starts.append(1)
                return ("large javap output", "", 0)

            first = store.javap_fact(
                coord, location, "business", produce, retain=False,
            )
            second = store.javap_fact(
                coord, location, "business", produce, retain=False,
            )

        self.assertEqual(first.value, second.value)
        self.assertEqual(len(starts), 2)
        self.assertEqual(store.metrics()["retained_facts"], 0)

    def test_class_bytes_are_not_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, coord, location = self._store_and_location(tmp)

            first = store.class_bytes(coord, location)
            second = store.class_bytes(coord, location)

        self.assertEqual(first.value, b"class-bytes")
        self.assertEqual(second.value, b"class-bytes")
        self.assertIsNot(first, second)
        self.assertEqual(store.metrics()["class_bytes_reads"], 2)


class BusinessBytecodeFactParityTest(unittest.TestCase):
    def _compiled_business_catalog(self, tmp):
        if not shutil.which("javac"):
            self.skipTest("javac is required")
        root = Path(tmp)
        source = root / "src" / "com" / "example" / "Business.java"
        classes = root / "classes"
        source.parent.mkdir(parents=True)
        classes.mkdir()
        source.write_text(
            """
            package com.example;
            import java.util.function.Supplier;
            public class Business {
                public String call(String value) {
                    Supplier<String> supplier = value::trim;
                    return supplier.get();
                }
                public Class<?> reflective(String name) throws Exception {
                    return Class.forName(name);
                }
                public int switched(int value) {
                    switch (value) { case 1: return call(" a ").length(); default: return 0; }
                }
            }
            """,
            encoding="utf-8",
        )
        completed = subprocess.run(
            ["javac", "-d", str(classes), str(source)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        jar_path = root / "business.jar"
        with zipfile.ZipFile(jar_path, "w") as archive:
            for class_file in sorted(classes.rglob("*.class")):
                archive.write(class_file, class_file.relative_to(classes).as_posix())
        digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
        entry = {
            "coord": "__business__", "jar_path": str(jar_path),
            "sha256": digest, "artifact_entry": "<business-classes>",
        }
        return {"target_jdk": "17", "entries": [entry], "by_coord": {"__business__": entry}}

    def test_shared_business_collector_is_exactly_equal_to_legacy(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog = self._compiled_business_catalog(tmp)
            legacy = collect_business_bytecode_batch(
                [], catalog, str(Path(tmp) / "legacy.jsonl"),
            )
            shared = collect_business_bytecode_batch(
                [], catalog, str(Path(tmp) / "shared.jsonl"),
                fact_store=Step5ArtifactFactStore.from_catalog(catalog),
            )

        self.assertEqual(shared, legacy)

    def test_shared_business_collector_preserves_malformed_class_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "business.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/example/Broken.class", b"broken")
            digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
            entry = {
                "coord": "__business__", "jar_path": str(jar_path),
                "sha256": digest, "artifact_entry": "<business-classes>",
            }
            catalog = {"target_jdk": "17", "entries": [entry], "by_coord": {"__business__": entry}}

            legacy = collect_business_bytecode_batch([], catalog, None)
            shared = collect_business_bytecode_batch(
                [], catalog, None,
                fact_store=Step5ArtifactFactStore.from_catalog(catalog),
            )

        self.assertEqual(shared, legacy)
        self.assertTrue(shared.failures)

    def test_shared_business_collector_reports_invalid_catalog_sha_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "business.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/example/Broken.class", b"broken")
            entry = {
                "coord": "__business__", "jar_path": str(jar_path),
                "sha256": "invalid", "artifact_entry": "<business-classes>",
            }
            catalog = {
                "target_jdk": "17", "entries": [entry],
                "by_coord": {"__business__": entry},
            }

            batch = collect_business_bytecode_batch(
                [], catalog, None,
                fact_store=Step5ArtifactFactStore.from_catalog(catalog),
            )

        self.assertEqual(batch.edges, ())
        self.assertEqual(
            [failure.reason_code for failure in batch.failures],
            ["CURRENT_FINAL_ARTIFACT_SHA_INVALID"],
        )

    def test_shared_business_collector_reports_replacement_during_iteration(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "business.jar"
            replacement = Path(tmp) / "replacement.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/example/Original.class", b"original")
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr("com/example/Replacement.class", b"replacement")
            digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
            entry = {
                "coord": "__business__", "jar_path": str(jar_path),
                "sha256": digest, "artifact_entry": "<business-classes>",
            }
            catalog = {
                "target_jdk": "17", "entries": [entry],
                "by_coord": {"__business__": entry},
            }
            store = Step5ArtifactFactStore.from_catalog(catalog)
            original_iterator = __import__(
                "business_bytecode_graph"
            )._iter_business_class_bytes

            def replacing_iterator(*args, **kwargs):
                replacement.replace(jar_path)
                yield from original_iterator(*args, **kwargs)

            with patch(
                "business_bytecode_graph._iter_business_class_bytes",
                side_effect=replacing_iterator,
            ):
                batch = collect_business_bytecode_batch(
                    [], catalog, None, fact_store=store,
                )

        self.assertEqual(batch.edges, ())
        self.assertEqual(
            [failure.reason_code for failure in batch.failures],
            ["CURRENT_FINAL_ARTIFACT_CHANGED_DURING_SCAN"],
        )

    def test_nested_fat_jar_javap_fallback_queue_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "business.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                for index in range(24):
                    archive.writestr(
                        f"BOOT-INF/classes/com/example/Broken{index}.class",
                        f"broken-{index}".encode("ascii"),
                    )
            digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
            entry = {
                "coord": "__business__", "jar_path": str(jar_path),
                "sha256": digest, "artifact_entry": "<business-classes>",
            }
            catalog = {
                "target_jdk": "17", "entries": [entry],
                "by_coord": {"__business__": entry},
            }

            with (
                patch.dict("os.environ", {"JUA_STEP5_BYTECODE_JAVAP_WORKERS": "2"}),
                patch("business_bytecode_graph.run_cmd", return_value=("", "", 0)),
            ):
                batch = collect_business_bytecode_batch([], catalog, None)

        metrics = dict(batch.metrics)
        self.assertLessEqual(metrics["javap_peak_pending_tasks"], 4)
        self.assertEqual(metrics["javap_pending_limit"], 4)

    def test_business_batch_automatically_uses_artifact_fact_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar_path = Path(tmp) / "business.jar"
            with zipfile.ZipFile(jar_path, "w") as archive:
                archive.writestr("com/example/App.class", b"class")
            digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
            entry = {
                "coord": "__business__", "jar_path": str(jar_path),
                "sha256": digest, "artifact_entry": "<business-classes>",
            }
            catalog = {
                "target_jdk": "17", "entries": [entry],
                "by_coord": {"__business__": entry},
            }
            observed = []

            def no_classes(_path, fact_store):
                observed.append(fact_store)
                return iter(())

            with patch(
                "business_bytecode_graph._iter_business_class_bytes",
                side_effect=no_classes,
            ):
                collect_business_bytecode_batch([], catalog, None)

        self.assertEqual(1, len(observed))
        self.assertIsInstance(observed[0], Step5ArtifactFactStore)

if __name__ == "__main__":
    unittest.main()
