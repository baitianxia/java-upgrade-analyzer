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


def archive_bytes(entries, *, compression=zipfile.ZIP_DEFLATED):
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=compression) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return payload.getvalue()


class BinaryArtifactSafetyTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
