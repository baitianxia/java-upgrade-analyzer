import csv
import hashlib
import io
import json
import sys
import tempfile
import time
import tracemalloc
import unittest
import warnings
import zipfile
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import artifact_safety  # noqa: E402
import confidence_weighted_tracer as tracer  # noqa: E402
import s5_call_chain_engine_integrated as step5  # noqa: E402


def _archive_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=compression) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return payload.getvalue()


class ArtifactSafetyTest(unittest.TestCase):
    def test_safe_archive_reports_bounded_metadata(self):
        result = artifact_safety.inspect_archive_bytes(_archive_bytes([
            ("com/acme/App.class", b"class"),
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        ]))

        self.assertTrue(result.safe)
        self.assertEqual(result.entry_count, 2)
        self.assertEqual(result.reason_codes, ())

    def test_rejects_traversal_duplicate_and_high_expansion_entries(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            duplicate = _archive_bytes([
                ("com/acme/App.class", b"one"),
                ("com/acme/App.class", b"two"),
            ])
        cases = {
            "traversal": _archive_bytes([("../escape.class", b"x")]),
            "duplicate": duplicate,
            "expansion": _archive_bytes([("large.bin", b"0" * 200_000)]),
        }

        expected = {
            "traversal": "ARCHIVE_ENTRY_PATH_UNSAFE",
            "duplicate": "ARCHIVE_DUPLICATE_ENTRY",
            "expansion": "ARCHIVE_EXPANSION_RATIO_EXCEEDED",
        }
        for name, payload in cases.items():
            with self.subTest(name=name):
                result = artifact_safety.inspect_archive_bytes(
                    payload, max_expansion_ratio=10
                )
                self.assertFalse(result.safe)
                self.assertIn(expected[name], result.reason_codes)

    def test_rejects_nested_archive_depth_and_entry_budget(self):
        nested = _archive_bytes([("Leaf.class", b"x")])
        for depth in range(4):
            nested = _archive_bytes([(f"level-{depth}.jar", nested)])

        depth_result = artifact_safety.inspect_archive_bytes(nested, max_nested_depth=2)
        count_result = artifact_safety.inspect_archive_bytes(
            _archive_bytes([(f"c/{index}.class", b"x") for index in range(12)]),
            max_entries=10,
        )

        self.assertIn("ARCHIVE_NESTED_DEPTH_EXCEEDED", depth_result.reason_codes)
        self.assertIn("ARCHIVE_ENTRY_COUNT_EXCEEDED", count_result.reason_codes)

    def test_runtime_catalog_fails_closed_before_reading_unsafe_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            artifact = report / "application.jar"
            artifact.write_bytes(_archive_bytes([
                ("../escape.class", b"x"),
                ("BOOT-INF/classes/com/acme/Application.class", b"app"),
            ]))
            dependencies = report / "evidence/dependencies"
            dependencies.mkdir(parents=True)
            with (dependencies / "deps_current_resolved.csv").open(
                "w", newline="", encoding="utf-8"
            ) as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=["coord", "version", "scope", "lib_entry"]
                )
                writer.writeheader()
            (dependencies / "build_provenance.json").write_text(json.dumps({
                "sides": [{
                    "side": "current",
                    "artifact_path": str(artifact),
                    "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }]
            }), encoding="utf-8")

            catalog = step5.build_runtime_dependency_catalog(str(report))

        self.assertEqual(catalog["status"], "insufficient")
        self.assertIn("artifact_safety_violation", catalog["reason_codes"])
        self.assertNotIn("__business__", catalog["by_coord"])

    def test_large_archive_metadata_scan_stays_within_time_and_memory_budget(self):
        payload = _archive_bytes([
            (f"com/acme/generated/C{index}.class", b"class")
            for index in range(5_000)
        ], compression=zipfile.ZIP_STORED)

        tracemalloc.start()
        started = time.monotonic()
        result = artifact_safety.inspect_archive_bytes(payload)
        elapsed = time.monotonic() - started
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertTrue(result.safe, result.reason_codes)
        self.assertEqual(result.entry_count, 5_000)
        self.assertLess(elapsed, 5.0)
        self.assertLess(peak, 32 * 1024 * 1024)

    def test_final_artifact_provenance_rejects_unsafe_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            artifact = report / "unsafe.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("../escaped.class", b"class")
            dependencies = report / "evidence/dependencies"
            dependencies.mkdir(parents=True)
            (dependencies / "build_provenance.json").write_text(json.dumps({
                "sides": [{
                    "side": "current",
                    "artifact_path": str(artifact),
                    "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }]
            }), encoding="utf-8")
            graph = type("Graph", (), {"report_dir": str(report)})()

            result = tracer._verified_final_artifact_provenance(graph)

        self.assertFalse(result["complete"])
        self.assertTrue(any(
            "ARCHIVE_ENTRY_PATH_UNSAFE" in failure
            for failure in result["failures"]
        ), result["failures"])


if __name__ == "__main__":
    unittest.main()
