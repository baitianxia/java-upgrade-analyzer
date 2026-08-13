import io
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
