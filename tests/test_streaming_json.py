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
    StreamingJsonReadError,
    files_equal,
    fsync_directory,
    iter_canonical_json_object_array,
    load_canonical_json_top_level_value,
    prime_canonical_json_fields,
    write_json_streaming,
    write_json_streaming_atomic,
)


class StreamingJsonTest(unittest.TestCase):
    def test_field_priming_with_no_keys_does_not_touch_the_path(self):
        prime_canonical_json_fields("/path/does/not/exist.json", ())

    def test_field_priming_normalizes_filesystem_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            with self.assertRaises(StreamingJsonReadError):
                prime_canonical_json_fields(missing, ("rows",))

    def test_field_priming_indexes_multiple_values_with_one_scan(self):
        payload = {
            "coverage_gaps": ["gap"],
            "records": [{"identity": "one"}],
            "status": "complete",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "multi.json"
            write_json_streaming(path, payload)
            prime_canonical_json_fields(
                path, ("coverage_gaps", "records", "status")
            )
            with patch.object(
                streaming_json,
                "prime_canonical_json_fields",
                side_effect=AssertionError("cached offsets must be reused"),
            ):
                self.assertEqual(
                    list(iter_canonical_json_object_array(path, "records")),
                    payload["records"],
                )
                self.assertEqual(
                    load_canonical_json_top_level_value(
                        path, "coverage_gaps"
                    ),
                    ["gap"],
                )
                self.assertEqual(
                    load_canonical_json_top_level_value(path, "status"),
                    "complete",
                )

    def test_canonical_object_array_reader_handles_nested_delimiters(self):
        payload = {
            "coverage_gaps": ["one"],
            "rows": [
                {
                    "index": 1,
                    "nested": [{"value": "literal },{ and }] text"}],
                },
                {"index": 2, "nested": []},
            ],
            "schema": "fixture.v1",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large.json"
            write_json_streaming(path, payload)
            rows = list(iter_canonical_json_object_array(path, "rows"))
            gaps = load_canonical_json_top_level_value(
                path, "coverage_gaps"
            )

        self.assertEqual(rows, payload["rows"])
        self.assertEqual(gaps, ["one"])

    def test_canonical_readers_reject_nested_or_string_embedded_field_names(self):
        payload = {
            "message": 'literal \\"rows\\":[{\"wrong\":true}]',
            "nested": {"rows": [{"wrong": True}]},
            "schema": "fixture.v1",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested.json"
            write_json_streaming(path, payload)
            with self.assertRaises(StreamingJsonReadError):
                list(iter_canonical_json_object_array(path, "rows"))
            with self.assertRaises(StreamingJsonReadError):
                load_canonical_json_top_level_value(path, "rows")

    def test_canonical_reader_rejects_non_object_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "array.json"
            path.write_text('[{"rows":[{"wrong":true}]}]\n', encoding="utf-8")
            with self.assertRaises(StreamingJsonReadError):
                list(iter_canonical_json_object_array(path, "rows"))

    def test_structure_cursor_preserves_escape_state_across_chunks(self):
        # End the first 64 KiB chunk on a backslash. The quote at the start of
        # the next chunk is escaped data, not the end of the message string.
        prefix = b'{"message":"'
        filler = b"x" * (64 * 1024 - len(prefix) - 1)
        payload = prefix + filler + b'\\"{[still text]}","rows":[]}'
        rows_offset = payload.index(b'"rows"')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "boundary.json"
            path.write_bytes(payload)
            with path.open("rb") as handle:
                import mmap

                with mmap.mmap(
                    handle.fileno(), 0, access=mmap.ACCESS_READ
                ) as mapped:
                    state = [0, False, False]
                    streaming_json._advance_json_structure(
                        mapped, 0, rows_offset, state, chunk_bytes=64 * 1024
                    )
        self.assertEqual(state, [1, False, False])

    def test_canonical_object_array_reader_handles_empty_and_rejects_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = root / "empty.json"
            write_json_streaming(empty, {"rows": [], "schema": "fixture"})
            self.assertEqual(
                list(iter_canonical_json_object_array(empty, "rows")), []
            )

            partial = root / "partial.json"
            partial.write_bytes(b'{"rows":[{"value":1}')
            with self.assertRaises(StreamingJsonReadError):
                list(iter_canonical_json_object_array(partial, "rows"))

    def test_canonical_object_array_reader_reports_incremental_progress(self):
        payload = {"rows": [{"index": index} for index in range(2_000)]}
        progress = []
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.json"
            write_json_streaming(path, payload)
            rows = list(iter_canonical_json_object_array(
                path,
                "rows",
                progress_callback=lambda current, total: progress.append(
                    (current, total)
                ),
                progress_interval_bytes=1_024,
            ))

        self.assertEqual(rows, payload["rows"])
        self.assertGreater(len(progress), 1)
        self.assertLessEqual(progress[-1][0], progress[-1][1])
        self.assertLessEqual(progress[-1][1] - progress[-1][0], 2)

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
