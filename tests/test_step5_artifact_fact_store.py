import csv
import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from real_project_regression import (  # noqa: E402
    cold_run_metrics,
    step5_result_contract,
)
from step5_artifact_fact_store import Step5ArtifactFactStore  # noqa: E402


class Step5ColdRunContractTest(unittest.TestCase):
    def _write_report(self, root, *, status="reachable", path_text="A -> B"):
        root = Path(root)
        call_chain = root / "evidence" / "call_chain"
        call_chain.mkdir(parents=True)
        (call_chain / "summary.json").write_text(
            json.dumps({
                "generated_at": "volatile",
                "reachable": int(status == "reachable"),
                "meta": {"graph_stats": {"step5_perf": {"trace": {"elapsed_sec": 1.0}}}},
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
                ("com/example/A.class", "META-INF/versions/11/com/example/A.class", "11"),
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

if __name__ == "__main__":
    unittest.main()
