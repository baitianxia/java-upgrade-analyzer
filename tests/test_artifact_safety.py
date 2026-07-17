import csv
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import tracemalloc
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import artifact_safety  # noqa: E402
import confidence_weighted_tracer as tracer  # noqa: E402
import data_contract_analysis  # noqa: E402
import s4_jar_compare  # noqa: E402
import s5_call_chain_engine_integrated as step5  # noqa: E402


def _archive_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=compression) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return payload.getvalue()


class ArtifactSafetyTest(unittest.TestCase):
    def setUp(self):
        artifact_safety.clear_archive_safety_cache()

    def tearDown(self):
        artifact_safety.clear_archive_safety_cache()

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

    def test_step4_class_hash_scan_rejects_unsafe_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "unsafe.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("../Escaped.class", b"class")

            with self.assertRaisesRegex(ValueError, "ARCHIVE_ENTRY_PATH_UNSAFE"):
                s4_jar_compare._jar_class_hash_map(str(artifact))

    def test_data_contract_scan_rejects_unsafe_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            unsafe = Path(tmp) / "unsafe.jar"
            safe = Path(tmp) / "safe.jar"
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("../Escaped.class", b"class")
            with zipfile.ZipFile(safe, "w"):
                pass

            with self.assertRaisesRegex(ValueError, "ARCHIVE_ENTRY_PATH_UNSAFE"):
                data_contract_analysis.compare_jar_data_contracts(
                    unsafe,
                    safe,
                    coord="sample:api",
                    old_version="1",
                    new_version="2",
                )

    def test_step4_class_hash_scan_rejects_crc_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "corrupt.jar"
            payload = b"unique-class-payload"
            with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("sample/Broken.class", payload)
            content = bytearray(artifact.read_bytes())
            offset = content.index(payload)
            content[offset] ^= 0x01
            artifact.write_bytes(content)

            with self.assertRaisesRegex(ValueError, "ARCHIVE_ENTRY_READ_FAILED"):
                s4_jar_compare._jar_class_hash_map(str(artifact))

    def test_archive_safety_result_is_cached_for_unchanged_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "safe.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("sample/Ok.class", b"class")

            with patch.object(
                artifact_safety,
                "_inspect_archive_source",
                wraps=artifact_safety._inspect_archive_source,
            ) as inspect_mock:
                artifact_safety.require_safe_archive(artifact)
                artifact_safety.require_safe_archive(artifact)

            self.assertEqual(inspect_mock.call_count, 1)

    def test_archive_safety_coalesces_concurrent_first_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "concurrent.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("sample/Ok.class", b"class")

            original = artifact_safety._inspect_archive_source

            def slow_scan(*args, **kwargs):
                time.sleep(0.05)
                return original(*args, **kwargs)

            with patch.object(
                artifact_safety, "_inspect_archive_source", side_effect=slow_scan,
            ) as inspect_mock, ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(
                    lambda _index: artifact_safety.require_safe_archive(artifact),
                    range(8),
                ))

            self.assertTrue(all(result.safe for result in results))
            self.assertEqual(inspect_mock.call_count, 1)

    def test_cache_clear_during_scan_prevents_stale_writeback(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "in-flight.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("sample/Ok.class", b"class")
            started = threading.Event()
            release = threading.Event()
            original = artifact_safety._inspect_archive_source

            def blocked_scan(*args, **kwargs):
                started.set()
                self.assertTrue(release.wait(timeout=2))
                return original(*args, **kwargs)

            with patch.object(
                artifact_safety, "_inspect_archive_source", side_effect=blocked_scan,
            ) as inspect_mock, ThreadPoolExecutor(max_workers=1) as pool:
                first = pool.submit(artifact_safety.require_safe_archive, artifact)
                self.assertTrue(started.wait(timeout=2))
                artifact_safety.clear_archive_safety_cache()
                release.set()
                self.assertTrue(first.result(timeout=2).safe)
                self.assertTrue(artifact_safety.require_safe_archive(artifact).safe)

            self.assertEqual(inspect_mock.call_count, 2)

    def test_archive_safety_cache_invalidates_after_same_size_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "mutable.jar"
            payload = b"mutable-class-payload"
            with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("sample/Mutable.class", payload)
            artifact_safety.require_safe_archive(artifact)
            original_stat = artifact.stat()
            content = bytearray(artifact.read_bytes())
            content[content.index(payload)] ^= 0x01
            artifact.write_bytes(content)
            os.utime(
                artifact,
                ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
            )

            with self.assertRaisesRegex(ValueError, "ARCHIVE_ENTRY_READ_FAILED"):
                artifact_safety.require_safe_archive(artifact)

    def test_high_expansion_ratio_entry_is_not_decompressed_after_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "ratio.jar"
            with zipfile.ZipFile(
                artifact, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                archive.writestr("sample/Large.class", b"0" * 1024 * 1024)

            with patch.object(
                zipfile.ZipFile,
                "open",
                side_effect=AssertionError("unsafe entry must not be decompressed"),
            ) as open_mock:
                result = artifact_safety.inspect_archive(artifact)

            self.assertFalse(result.safe)
            self.assertIn("ARCHIVE_EXPANSION_RATIO_EXCEEDED", result.reason_codes)
            open_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
