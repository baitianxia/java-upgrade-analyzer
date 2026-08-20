import errno
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import streaming_json  # noqa: E402
from streaming_json import (  # noqa: E402
    files_equal,
    fsync_directory,
    write_json_streaming,
    write_json_streaming_atomic,
)


class StreamingJsonTest(unittest.TestCase):
    def test_large_result_is_written_incrementally_with_canonical_bytes(self):
        payload = {
            "issues": [
                {"reason_code": "ISSUE", "index": index, "text": "问题" * 8}
                for index in range(20_000)
            ],
            "status": "failed",
        }
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "validation.json"
            write_json_streaming(destination, payload)
            encoded = destination.read_bytes()

        expected = (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        self.assertEqual(encoded, expected)

    def test_atomic_writer_reuses_identical_file_and_rejects_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / "result.json"
            write_json_streaming_atomic(destination, {"value": 1})
            identical = root / "identical.json"
            write_json_streaming(identical, {"value": 1})
            self.assertTrue(files_equal(destination, identical))
            write_json_streaming_atomic(destination, {"value": 1})
            with self.assertRaisesRegex(RuntimeError, "collision"):
                write_json_streaming_atomic(
                    destination,
                    {"value": 2},
                    collision_error=RuntimeError("collision"),
                )

    def test_atomic_writer_synchronizes_parent_after_replace_and_equal_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "result.json"
            with patch.object(
                streaming_json,
                "fsync_directory",
                wraps=streaming_json.fsync_directory,
            ) as synchronize:
                write_json_streaming_atomic(destination, {"value": 1})
                self.assertEqual(
                    synchronize.call_args_list[-1].args,
                    (destination.parent,),
                )
                synchronize.reset_mock()
                write_json_streaming_atomic(destination, {"value": 1})
                synchronize.assert_called_once_with(destination.parent)

    @unittest.skipIf(os.name == "nt", "POSIX directory fsync semantics")
    def test_directory_fsync_distinguishes_unsupported_from_real_io_failure(self):
        unsupported = getattr(errno, "ENOTSUP", errno.EOPNOTSUPP)
        with patch.object(
            streaming_json.os,
            "open",
            side_effect=OSError(unsupported, "unsupported"),
        ):
            self.assertFalse(fsync_directory("/not-opened"))

        with patch.object(
            streaming_json.os,
            "open",
            side_effect=OSError(errno.EIO, "media failure"),
        ), self.assertRaisesRegex(OSError, "media failure"):
            fsync_directory("/not-opened")

    def test_directory_fsync_explicitly_reports_windows_non_support(self):
        open_directory = Mock()
        with patch.object(streaming_json.os, "name", "nt"), patch.object(
            streaming_json.os, "open", open_directory
        ):
            self.assertFalse(fsync_directory("C:/synthetic"))
        open_directory.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX directory fsync semantics")
    def test_directory_fsync_closes_descriptor_without_masking_io_failure(self):
        close = Mock()
        with patch.object(streaming_json.os, "open", return_value=73), patch.object(
            streaming_json.os,
            "fsync",
            side_effect=OSError(errno.EIO, "fsync primary"),
        ), patch.object(streaming_json.os, "close", close):
            with self.assertRaisesRegex(OSError, "fsync primary"):
                fsync_directory("/synthetic-directory")
        close.assert_called_once_with(73)

    def test_atomic_cleanup_preserves_primary_and_python310_note_fallback(self):
        class LegacyPrimary(RuntimeError):
            add_note = None

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "result.json"
            primary = LegacyPrimary("replace primary")
            with patch.object(
                streaming_json.os, "replace", side_effect=primary
            ), patch.object(
                streaming_json.Path,
                "unlink",
                side_effect=OSError("unlink cleanup"),
            ):
                with self.assertRaises(LegacyPrimary) as caught:
                    write_json_streaming_atomic(destination, {"value": 1})

        self.assertIs(caught.exception, primary)
        self.assertTrue(
            any("unlink cleanup" in note for note in primary.__notes__)
        )

    def test_atomic_cleanup_failure_remains_fatal_without_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "result.json"
            with patch.object(
                streaming_json.Path,
                "unlink",
                side_effect=OSError("cleanup only"),
            ):
                with self.assertRaisesRegex(OSError, "cleanup only"):
                    write_json_streaming_atomic(destination, {"value": 1})
            self.assertTrue(destination.is_file())


if __name__ == "__main__":
    unittest.main()
