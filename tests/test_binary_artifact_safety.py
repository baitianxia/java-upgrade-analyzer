import io
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import artifact_safety  # noqa: E402
import binary_artifact_diff  # noqa: E402


def archive_bytes(entries, *, compression=zipfile.ZIP_DEFLATED):
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=compression) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return payload.getvalue()


class BinaryArtifactSafetyTest(unittest.TestCase):
    def test_spring_xml_uses_xml_semantics_before_line_registration_semantics(self):
        malformed = b"<beans><bean id='broken'"

        facts = binary_artifact_diff._resource_semantic_facts(
            "META-INF/spring/context.xml", "runtime_topology", malformed
        )

        self.assertEqual(facts, (("xml_parse_gap", "malformed_xml"),))

    def test_safe_archive_reports_bounded_metadata(self):
        result = artifact_safety.inspect_archive_bytes(
            archive_bytes((("demo/A.class", b"bytecode"),))
        )
        self.assertTrue(result.safe)
        self.assertEqual(result.entry_count, 1)
        self.assertEqual(result.total_uncompressed_bytes, 8)

    def test_missing_artifact_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = artifact_safety.inspect_archive(Path(tmp) / "missing.jar")
        self.assertFalse(result.safe)
        self.assertIn("ARCHIVE_READ_FAILED", result.reason_codes)

    def test_path_traversal_duplicate_and_expansion_are_rejected(self):
        payload = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("../escape.class", b"x")
                archive.writestr("demo/A.class", b"x")
                archive.writestr("demo/A.class", b"x")
                archive.writestr("huge.txt", b"0" * 100_000)
        result = artifact_safety.inspect_archive_bytes(
            payload.getvalue(), max_expansion_ratio=2
        )
        self.assertFalse(result.safe)
        self.assertIn("ARCHIVE_ENTRY_PATH_UNSAFE", result.reason_codes)
        self.assertIn("ARCHIVE_DUPLICATE_ENTRY", result.reason_codes)
        self.assertIn("ARCHIVE_EXPANSION_RATIO_EXCEEDED", result.reason_codes)

    def test_nested_depth_is_bounded(self):
        inner = archive_bytes((("demo/A.class", b"x"),))
        middle = archive_bytes((("lib/inner.jar", inner),))
        outer = archive_bytes((("lib/middle.jar", middle),))
        result = artifact_safety.inspect_archive_bytes(
            outer, max_nested_depth=1
        )
        self.assertFalse(result.safe)
        self.assertIn("ARCHIVE_NESTED_DEPTH_EXCEEDED", result.reason_codes)

    def test_archive_crc_scan_stops_cooperatively_on_cancellation(self):
        payload = archive_bytes((
            (f"payload/{index}.bin", b"x" * (2 * 1024 * 1024))
            for index in range(3)
        ))
        checks = 0

        def cancel_after_first_read_chunk():
            nonlocal checks
            checks += 1
            return checks >= 4

        result = artifact_safety.inspect_archive_bytes(
            payload, cancellation_check=cancel_after_first_read_chunk,
        )

        self.assertFalse(result.safe)
        self.assertIn("ARCHIVE_INSPECTION_CANCELLED", result.reason_codes)
        self.assertLess(result.total_uncompressed_bytes, 6 * 1024 * 1024)

    def test_snapshot_blocks_duplicate_class_entries_but_allows_maven_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            duplicate_class = root / "duplicate-class.jar"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate_class, "w") as archive:
                    archive.writestr("demo/A.class", b"one")
                    archive.writestr("demo/A.class", b"two")
            digest = artifact_safety._sha256_file(duplicate_class)
            with self.assertRaises(binary_artifact_diff.BinaryArtifactDiffError) as raised:
                binary_artifact_diff.snapshot_archive(
                    duplicate_class,
                    artifact_instance_identity="duplicate-class",
                    expected_sha256=digest,
                )
            allowed = root / "duplicate-maven.jar"
            metadata = "META-INF/maven/example/demo/pom.properties"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(allowed, "w") as archive:
                    archive.writestr(metadata, b"version=1")
                    archive.writestr(metadata, b"version=1")
            allowed_result = artifact_safety.inspect_archive(
                allowed, allow_duplicate_maven_metadata=True
            )

        self.assertEqual(raised.exception.reason_code, "ARTIFACT_SAFETY_POLICY_BLOCKED")
        self.assertTrue(allowed_result.safe, allowed_result)


class ArtifactSafetyBoundaryTest(unittest.TestCase):
    def setUp(self):
        artifact_safety.clear_archive_safety_cache()
        with artifact_safety._ARCHIVE_CACHE_CONDITION:
            artifact_safety._ARCHIVE_CACHE_IN_FLIGHT.clear()

    def tearDown(self):
        artifact_safety.clear_archive_safety_cache()
        with artifact_safety._ARCHIVE_CACHE_CONDITION:
            artifact_safety._ARCHIVE_CACHE_IN_FLIGHT.clear()

    def test_entry_name_policy_covers_every_platform_form(self):
        unsafe_names = (
            None,
            "",
            "\x00name.class",
            "/absolute.class",
            "\\absolute.class",
            "C:/absolute.class",
            "C:\\absolute.class",
            "dir\\member.class",
            "dir/../member.class",
        )
        for name in unsafe_names:
            with self.subTest(name=name):
                self.assertTrue(artifact_safety._unsafe_entry_name(name))
        self.assertFalse(artifact_safety._unsafe_entry_name("dir/member.class"))
        self.assertFalse(
            artifact_safety.is_allowed_duplicate_archive_entry(
                None, allow_duplicate_maven_metadata=True
            )
        )
        self.assertFalse(
            artifact_safety.is_allowed_duplicate_archive_entry(
                "META-INF/maven/g/a/pom.xml",
                allow_duplicate_maven_metadata=False,
            )
        )

    def test_expansion_ratio_rejects_inconsistent_metadata_boundaries(self):
        cases = (
            (
                SimpleNamespace(
                    file_size=2,
                    compress_size=1,
                    compress_type=zipfile.ZIP_STORED,
                ),
                (None, "ARCHIVE_SIZE_METADATA_INVALID"),
            ),
            (
                SimpleNamespace(
                    file_size=0,
                    compress_size=0,
                    compress_type=zipfile.ZIP_DEFLATED,
                ),
                (1.0, None),
            ),
            (
                SimpleNamespace(
                    file_size=1,
                    compress_size=0,
                    compress_type=zipfile.ZIP_DEFLATED,
                ),
                (None, "ARCHIVE_SIZE_METADATA_INVALID"),
            ),
            (
                SimpleNamespace(
                    file_size=-1,
                    compress_size=-1,
                    compress_type=zipfile.ZIP_STORED,
                ),
                (1.0, None),
            ),
        )
        for info, expected in cases:
            with self.subTest(info=info):
                self.assertEqual(
                    artifact_safety._archive_entry_expansion_ratio(info),
                    expected,
                )

    def test_limits_cover_entry_count_total_size_ratio_directory_and_nested_size(self):
        nested = archive_bytes((("inside.txt", b"x"),))
        payload = archive_bytes(
            (("folder/", b""), ("payload.txt", b"abc"), ("lib/a.jar", nested)),
            compression=zipfile.ZIP_STORED,
        )
        result = artifact_safety.inspect_archive_bytes(
            payload,
            max_entries=0,
            max_total_uncompressed_bytes=0,
            max_expansion_ratio=2,
        )
        nested_size_result = artifact_safety.inspect_archive_bytes(
            payload,
            max_entries=0,
            max_expansion_ratio=2,
            max_nested_archive_bytes=0,
        )

        self.assertFalse(result.safe)
        self.assertIn("ARCHIVE_ENTRY_COUNT_EXCEEDED", result.reason_codes)
        self.assertIn("ARCHIVE_UNCOMPRESSED_SIZE_EXCEEDED", result.reason_codes)
        self.assertIn(
            "ARCHIVE_NESTED_SIZE_EXCEEDED", nested_size_result.reason_codes
        )
        self.assertNotIn("ARCHIVE_EXPANSION_RATIO_EXCEEDED", result.reason_codes)

    def test_nested_inspection_can_be_disabled_without_losing_count(self):
        payload = archive_bytes((("lib/not-really-a.jar", b"not a zip"),))
        result = artifact_safety.inspect_archive_bytes(
            payload, inspect_nested_archives=False
        )

        self.assertTrue(result.safe, result)
        self.assertEqual(result.nested_archives, 1)
        self.assertEqual(result.max_observed_depth, 0)

    def test_zero_nested_depth_rejects_first_nested_archive(self):
        nested = archive_bytes((("inside.txt", b"x"),))
        result = artifact_safety.inspect_archive_bytes(
            archive_bytes((("lib/a.jar", nested),)), max_nested_depth=0
        )

        self.assertIn("ARCHIVE_NESTED_DEPTH_EXCEEDED", result.reason_codes)
        self.assertEqual(result.max_observed_depth, 0)

    def test_invalid_root_and_nested_formats_are_distinguished(self):
        invalid_root = artifact_safety.inspect_archive_bytes(b"not a zip")
        invalid_nested = artifact_safety.inspect_archive_bytes(
            archive_bytes((("lib/broken.jar", b"not a zip"),))
        )
        with patch.object(
            artifact_safety.zipfile,
            "ZipFile",
            side_effect=OSError("cannot read"),
        ):
            path_failure = artifact_safety._inspect_archive_source("virtual.jar")
            bytes_failure = artifact_safety._inspect_archive_source(b"payload")

        self.assertEqual(
            invalid_root.reason_codes, ("ARCHIVE_FORMAT_INVALID",)
        )
        self.assertIn("ARCHIVE_FORMAT_INVALID", invalid_nested.reason_codes)
        self.assertEqual(path_failure.reason_codes, ("ARCHIVE_READ_FAILED",))
        self.assertEqual(bytes_failure.reason_codes, ("ARCHIVE_FORMAT_INVALID",))

    def test_entry_read_failures_distinguish_regular_and_nested_members(self):
        def info(name):
            return SimpleNamespace(
                filename=name,
                file_size=1,
                compress_size=1,
                compress_type=zipfile.ZIP_STORED,
                is_dir=lambda: False,
            )

        class BrokenArchive:
            def __init__(self, member):
                self.member = member

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def infolist(self):
                return [self.member]

            def open(self, _member):
                raise OSError("read failed")

        for name, reason in (
            ("payload.bin", "ARCHIVE_ENTRY_READ_FAILED"),
            ("lib/a.jar", "ARCHIVE_NESTED_READ_FAILED"),
        ):
            with self.subTest(name=name), patch.object(
                artifact_safety.zipfile,
                "ZipFile",
                return_value=BrokenArchive(info(name)),
            ):
                result = artifact_safety.inspect_archive_bytes(b"ignored")
            self.assertEqual(result.reason_codes, (reason,))
            self.assertEqual(result.details, (f"{reason}:{name}",))

    def test_cancellation_hook_failure_and_immediate_cancellation_fail_closed(self):
        payload = archive_bytes((("payload.bin", b"x"),))

        def broken_hook():
            raise RuntimeError("hook failed")

        for hook in (broken_hook, lambda: True):
            with self.subTest(hook=hook):
                result = artifact_safety.inspect_archive_bytes(
                    payload, cancellation_check=hook
                )
            self.assertEqual(
                result.reason_codes, ("ARCHIVE_INSPECTION_CANCELLED",)
            )
            self.assertEqual(result.entry_count, 0)

    def test_seekable_stream_is_rewound_before_inspection(self):
        class RecordingStream(io.BytesIO):
            def __init__(self, content):
                super().__init__(content)
                self.seek_calls = []

            def seek(self, offset, whence=0):
                self.seek_calls.append((offset, whence))
                return super().seek(offset, whence)

        stream = RecordingStream(archive_bytes((("payload.bin", b"x"),)))
        stream.seek(len(stream.getvalue()))
        stream.seek_calls.clear()

        result = artifact_safety.inspect_archive_stream(stream)

        self.assertTrue(result.safe)
        self.assertEqual(stream.seek_calls[0], (0, 0))

    def test_bytes_like_payload_with_read_but_without_seek_uses_bytes_adapter(self):
        class ReadableBytes(bytes):
            def read(self, *_args):
                return bytes(self)

        payload = ReadableBytes(archive_bytes((("payload.bin", b"x"),)))

        result = artifact_safety._inspect_archive_source(payload)

        self.assertTrue(result.safe, result)

    def test_metadata_error_and_cancellation_boundaries_are_reported_in_context(self):
        invalid_info = SimpleNamespace(
            filename="payload.bin",
            file_size=1,
            compress_size=0,
            compress_type=zipfile.ZIP_DEFLATED,
            is_dir=lambda: False,
        )

        class MetadataArchive:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def infolist(self):
                return [invalid_info]

        with patch.object(
            artifact_safety.zipfile, "ZipFile", return_value=MetadataArchive()
        ):
            invalid = artifact_safety.inspect_archive_bytes(b"ignored")
        self.assertEqual(
            invalid.reason_codes, ("ARCHIVE_SIZE_METADATA_INVALID",)
        )
        self.assertEqual(
            invalid.details,
            ("ARCHIVE_SIZE_METADATA_INVALID:<root>!/payload.bin",),
        )

        payload = archive_bytes((("payload.bin", b"x"),))
        checks = 0

        def cancel_before_first_member():
            nonlocal checks
            checks += 1
            return checks == 2

        cancelled = artifact_safety.inspect_archive_bytes(
            payload, cancellation_check=cancel_before_first_member
        )
        self.assertEqual(
            cancelled.reason_codes, ("ARCHIVE_INSPECTION_CANCELLED",)
        )

        nested = archive_bytes((("inside.txt", b"x"),))
        checks = 0

        def cancel_after_nested_member_read():
            nonlocal checks
            checks += 1
            return checks == 5

        cancelled_nested = artifact_safety.inspect_archive_bytes(
            archive_bytes((("lib/a.jar", nested),)),
            cancellation_check=cancel_after_nested_member_read,
        )
        self.assertEqual(
            cancelled_nested.reason_codes,
            ("ARCHIVE_INSPECTION_CANCELLED",),
        )
        self.assertEqual(cancelled_nested.max_observed_depth, 0)

    def test_nested_os_error_is_classified_as_format_failure(self):
        nested_info = SimpleNamespace(
            filename="lib/a.jar",
            file_size=1,
            compress_size=1,
            compress_type=zipfile.ZIP_STORED,
            is_dir=lambda: False,
        )

        class OuterArchive:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def infolist(self):
                return [nested_info]

            def open(self, _member):
                return io.BytesIO(b"x")

        calls = 0

        def open_archive(_source):
            nonlocal calls
            calls += 1
            if calls == 1:
                return OuterArchive()
            raise OSError("nested source vanished")

        with patch.object(
            artifact_safety.zipfile, "ZipFile", side_effect=open_archive
        ):
            result = artifact_safety.inspect_archive_bytes(b"outer")

        self.assertEqual(result.reason_codes, ("ARCHIVE_FORMAT_INVALID",))
        self.assertEqual(
            result.details, ("ARCHIVE_FORMAT_INVALID:lib/a.jar",)
        )

    def test_cache_hit_wait_generation_and_eviction_paths(self):
        safe = artifact_safety.ArchiveSafetyResult(True, (), 1, 1, 0, 0)
        path = "/virtual/archive.jar"
        key = (path, "digest", ())
        artifact_safety._ARCHIVE_SAFETY_CACHE[key] = safe
        with patch.object(artifact_safety, "_inspect_archive_source") as scanner:
            self.assertIs(
                artifact_safety._cached_archive_inspection(path, "digest", ()),
                safe,
            )
        scanner.assert_not_called()

        artifact_safety.clear_archive_safety_cache()
        generation_before = artifact_safety._ARCHIVE_CACHE_GENERATION

        def scan_after_cache_clear(*_args, **_kwargs):
            artifact_safety.clear_archive_safety_cache()
            return safe

        with patch.object(
            artifact_safety, "_inspect_archive_source", side_effect=scan_after_cache_clear
        ), patch.object(artifact_safety, "_sha256_file", return_value="digest"):
            self.assertIs(
                artifact_safety._cached_archive_inspection(path, "digest", ()),
                safe,
            )
        self.assertGreater(
            artifact_safety._ARCHIVE_CACHE_GENERATION, generation_before
        )
        self.assertNotIn(key, artifact_safety._ARCHIVE_SAFETY_CACHE)

        artifact_safety._ARCHIVE_SAFETY_CACHE[("old", "digest", ())] = safe
        with patch.object(
            artifact_safety, "_ARCHIVE_CACHE_MAX_SIZE", 1
        ), patch.object(
            artifact_safety, "_inspect_archive_source", return_value=safe
        ), patch.object(artifact_safety, "_sha256_file", return_value="digest"):
            artifact_safety._cached_archive_inspection(path, "digest", ())
        self.assertEqual(list(artifact_safety._ARCHIVE_SAFETY_CACHE), [key])

    def test_cache_waits_for_owner_and_cleans_up_after_base_exception(self):
        safe = artifact_safety.ArchiveSafetyResult(True, (), 1, 1, 0, 0)
        path = "/virtual/archive.jar"
        key = (path, "digest", ())
        artifact_safety._ARCHIVE_CACHE_IN_FLIGHT.add(key)
        real_condition = artifact_safety._ARCHIVE_CACHE_CONDITION

        class ReleasingCondition:
            waits = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def wait(self):
                self.waits += 1
                artifact_safety._ARCHIVE_CACHE_IN_FLIGHT.discard(key)

            def notify_all(self):
                return None

        condition = ReleasingCondition()
        with patch.object(
            artifact_safety, "_ARCHIVE_CACHE_CONDITION", condition
        ), patch.object(
            artifact_safety, "_inspect_archive_source", return_value=safe
        ), patch.object(artifact_safety, "_sha256_file", return_value="digest"):
            result = artifact_safety._cached_archive_inspection(path, "digest", ())
        self.assertIs(result, safe)
        self.assertEqual(condition.waits, 1)

        artifact_safety._ARCHIVE_CACHE_CONDITION = real_condition
        with patch.object(
            artifact_safety, "_inspect_archive_source", side_effect=KeyboardInterrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                artifact_safety._cached_archive_inspection(path, "other", ())
        self.assertNotIn((path, "other", ()), artifact_safety._ARCHIVE_CACHE_IN_FLIGHT)

    def test_require_safe_archive_uses_cancellation_and_detail_evidence(self):
        safe = artifact_safety.ArchiveSafetyResult(True, (), 1, 1, 0, 0)
        unsafe = artifact_safety.ArchiveSafetyResult(
            False,
            ("ARCHIVE_ENTRY_PATH_UNSAFE",),
            1,
            1,
            0,
            0,
            ("ARCHIVE_ENTRY_PATH_UNSAFE:../bad",),
        )
        cancellation = lambda: False
        with patch.object(
            artifact_safety, "inspect_archive", return_value=safe
        ) as inspector:
            result = artifact_safety.require_safe_archive(
                "/virtual/archive.jar", cancellation_check=cancellation
            )
        self.assertIs(result, safe)
        inspector.assert_called_once_with(
            Path("/virtual/archive.jar"), cancellation_check=cancellation
        )

        with patch.object(
            artifact_safety, "inspect_archive", return_value=unsafe
        ):
            with self.assertRaisesRegex(
                ValueError, "ARCHIVE_ENTRY_PATH_UNSAFE:\\.\\./bad"
            ):
                artifact_safety.require_safe_archive(
                    "/virtual/archive.jar", cancellation_check=cancellation
                )


if __name__ == "__main__":
    unittest.main()
