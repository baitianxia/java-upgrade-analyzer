import errno
import hashlib
import io
import json
import mmap
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import streaming_json  # noqa: E402
from binary_first_contract import surrogate_safe_json_dumps  # noqa: E402
from streaming_json import (  # noqa: E402
    StreamingJsonArray,
    StreamingJsonReadError,
    files_equal,
    fsync_directory,
    iter_canonical_json_object_array,
    json_file_digest_if_matches,
    load_canonical_json_top_level_value,
    prime_canonical_json_fields,
    write_json_streaming,
    write_json_streaming_atomic,
)


class StreamingJsonTest(unittest.TestCase):
    def test_lazy_array_is_repeatable_and_enforces_per_item_limit(self):
        calls = []
        rows = [{"index": 1}, {"index": 2}]
        lazy = StreamingJsonArray(
            lambda: (calls.append("iter") or iter(rows)),
            len(rows),
        )
        payload = {"issues": lazy, "status": "failed"}

        expected = b'{"issues":[{"index":1},{"index":2}],"status":"failed"}\n'
        self.assertEqual(b"".join(streaming_json.iter_json_bytes(payload)), expected)
        self.assertEqual(b"".join(streaming_json.iter_json_bytes(payload)), expected)
        self.assertEqual(calls, ["iter", "iter"])
        self.assertEqual(len(lazy), 2)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oversized-item.json"
            write_json_streaming(path, {"rows": [{"text": "x" * 100}]})
            with self.assertRaisesRegex(
                StreamingJsonReadError, "exceeds 32 bytes"
            ):
                list(iter_canonical_json_object_array(
                    path, "rows", maximum_item_bytes=32,
                ))

    def test_streamed_bytes_match_frozen_surrogate_safe_json_encoding(self):
        payload = {
            "literal": r"\ud800",
            "raw": json.loads('"\\ud800"'),
            "unicode": "问题😀",
        }
        expected = (
            surrogate_safe_json_dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        self.assertEqual(
            b"".join(streaming_json.iter_json_bytes(payload)), expected
        )

    def test_structure_cursor_covers_reconnected_plain_string_and_negative_depth(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "structure.bin"
            path.write_bytes(b'continued"}')
            with path.open("rb") as handle, mmap.mmap(
                handle.fileno(),
                0,
                access=mmap.ACCESS_READ,
            ) as mapped:
                state = [1, True, False]
                streaming_json._advance_json_structure(
                    mapped,
                    0,
                    len(mapped),
                    state,
                )
            self.assertEqual(state, [0, False, False])

            path.write_bytes(b"}")
            with path.open("rb") as handle, mmap.mmap(
                handle.fileno(),
                0,
                access=mmap.ACCESS_READ,
            ) as mapped, self.assertRaisesRegex(
                StreamingJsonReadError,
                "invalid JSON nesting",
            ):
                streaming_json._advance_json_structure(
                    mapped,
                    0,
                    len(mapped),
                    [0, False, False],
                )

    def test_field_priming_with_no_keys_does_not_touch_the_path(self):
        prime_canonical_json_fields("/path/does/not/exist.json", ())

    def test_field_priming_normalizes_filesystem_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            with self.assertRaises(StreamingJsonReadError):
                prime_canonical_json_fields(missing, ("rows",))

    def test_field_priming_covers_empty_whitespace_cached_and_cache_eviction(self):
        streaming_json._CANONICAL_VALUE_START_CACHE.clear()
        self.addCleanup(streaming_json._CANONICAL_VALUE_START_CACHE.clear)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = root / "empty.json"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(StreamingJsonReadError, "empty JSON"):
                prime_canonical_json_fields(empty, ("rows",))

            whitespace = root / "whitespace.json"
            whitespace.write_bytes(b"  \n\t")
            with self.assertRaisesRegex(StreamingJsonReadError, "root is not an object"):
                prime_canonical_json_fields(whitespace, ("rows",))

            valid = root / "valid.json"
            write_json_streaming(valid, {"rows": [], "status": "ok"})
            prime_canonical_json_fields(valid, ("rows",))
            cached_snapshot = dict(streaming_json._CANONICAL_VALUE_START_CACHE)
            prime_canonical_json_fields(valid, ("rows", "rows"))
            self.assertEqual(
                streaming_json._CANONICAL_VALUE_START_CACHE,
                cached_snapshot,
            )

            for index in range(513):
                streaming_json._CANONICAL_VALUE_START_CACHE[
                    (f"old-{index}", index, index, "key")
                ] = ()
            prime_canonical_json_fields(valid, ("status",))
            self.assertFalse(any(
                key[0].startswith("old-")
                for key in streaming_json._CANONICAL_VALUE_START_CACHE
            ))

    def test_non_array_field_is_not_accepted_as_object_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "object.json"
            write_json_streaming(path, {"rows": {"not": "an array"}})
            with self.assertRaisesRegex(
                StreamingJsonReadError,
                "found 0",
            ):
                list(iter_canonical_json_object_array(path, "rows"))

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

    def test_canonical_object_array_reader_ignores_terminator_before_separator_in_string(self):
        payload = {
            "rows": [{"text": "first }] then },{ still text"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "delimiter-order.json"
            write_json_streaming(path, payload)
            self.assertEqual(
                list(iter_canonical_json_object_array(path, "rows")),
                payload["rows"],
            )

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

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "quoted-key.json"
            write_json_streaming(
                path,
                {"message": 'literal "rows":[] text', "schema": "fixture.v1"},
            )
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

            missing_terminator = root / "missing-terminator.json"
            missing_terminator.write_bytes(b'{"rows":[{},{')
            with self.assertRaises(StreamingJsonReadError):
                list(iter_canonical_json_object_array(
                    missing_terminator,
                    "rows",
                ))

    def test_canonical_object_array_reader_rejects_empty_and_non_object_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = root / "empty-file.json"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(StreamingJsonReadError, "empty JSON"):
                list(iter_canonical_json_object_array(empty, "rows"))

            scalar = root / "scalar.json"
            scalar.write_bytes(b'{"rows":[1]}')
            with self.assertRaisesRegex(StreamingJsonReadError, "non-object item"):
                list(iter_canonical_json_object_array(scalar, "rows"))

            empty_array = root / "empty-array.json"
            write_json_streaming(empty_array, {"rows": []})
            progress = []
            self.assertEqual(
                list(iter_canonical_json_object_array(
                    empty_array,
                    "rows",
                    progress_callback=lambda current, total: progress.append(
                        (current, total)
                    ),
                )),
                [],
            )
            self.assertEqual(len(progress), 1)

            small = root / "small.json"
            write_json_streaming(small, {"rows": [{"one": 1}]})
            progress.clear()
            self.assertEqual(
                list(iter_canonical_json_object_array(
                    small,
                    "rows",
                    progress_callback=lambda current, total: progress.append(
                        (current, total)
                    ),
                    progress_interval_bytes=10_000,
                )),
                [{"one": 1}],
            )
            self.assertEqual(len(progress), 1)

    def test_top_level_value_reader_covers_growth_eof_limit_and_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "values.json"
            expected = "x" * 500
            write_json_streaming(path, {"value": expected})
            self.assertEqual(
                load_canonical_json_top_level_value(
                    path,
                    "value",
                    initial_bytes=64,
                    maximum_bytes=1024,
                ),
                expected,
            )
            with self.assertRaisesRegex(StreamingJsonReadError, "exceeds 64 bytes"):
                load_canonical_json_top_level_value(
                    path,
                    "value",
                    initial_bytes=64,
                    maximum_bytes=64,
                )

            malformed = root / "malformed.json"
            malformed.write_bytes(b'{"value":')
            with self.assertRaisesRegex(StreamingJsonReadError, "invalid"):
                load_canonical_json_top_level_value(
                    malformed,
                    "value",
                    initial_bytes=64,
                    maximum_bytes=128,
                )

            empty = root / "empty.json"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(StreamingJsonReadError, "empty JSON"):
                load_canonical_json_top_level_value(empty, "value")

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

    def test_streamed_json_file_match_hashes_without_whole_document_bytes(self):
        raw_surrogate = json.loads('"\\ud800"')
        payload = {
            "issues": [
                {
                    "domain": "provider",
                    "index": index,
                    "text": raw_surrogate if index == 0 else "问题" * 8,
                }
                for index in range(20_000)
            ],
            "status": "failed",
        }
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "validation.json"
            write_json_streaming(destination, payload)
            expected_digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            with patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("whole-file read is forbidden"),
            ):
                self.assertEqual(
                    json_file_digest_if_matches(destination, payload),
                    expected_digest,
                )
            with destination.open("ab") as handle:
                handle.write(b"x")
            self.assertIsNone(
                json_file_digest_if_matches(destination, payload)
            )

    def test_stream_encoder_covers_indented_output_without_terminal_newline(self):
        handle = io.StringIO()
        streaming_json.stream_json(
            {"value": "问题"},
            handle,
            ensure_ascii=True,
            sort_keys=False,
            indent=2,
            newline=False,
        )
        self.assertFalse(handle.getvalue().endswith("\n"))
        self.assertIn("\\u95ee", handle.getvalue())

    def test_file_equality_covers_size_content_eof_and_io_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first"
            second = root / "second"
            first.write_bytes(b"same")
            second.write_bytes(b"same")
            self.assertTrue(files_equal(first, second))
            second.write_bytes(b"longer")
            self.assertFalse(files_equal(first, second))
            second.write_bytes(b"diff")
            self.assertFalse(files_equal(first, second))
            self.assertFalse(files_equal(first, root / "missing"))

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

            write_json_streaming_atomic(destination, {"value": 3})
            self.assertEqual(json.loads(destination.read_text()), {"value": 3})

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
    def test_directory_fsync_covers_unsupported_fsync_and_cleanup_failures(self):
        unsupported = getattr(errno, "ENOTSUP", errno.EOPNOTSUPP)
        with patch.object(
            streaming_json.os,
            "O_DIRECTORY",
            0,
            create=True,
        ), patch.object(streaming_json.os, "open", return_value=71) as opened, patch.object(
            streaming_json.os,
            "fsync",
            side_effect=OSError(unsupported, "unsupported"),
        ), patch.object(streaming_json.os, "close"):
            self.assertFalse(fsync_directory("/synthetic-directory"))
        opened.assert_called_once_with(Path("/synthetic-directory"), os.O_RDONLY)

        with patch.object(streaming_json.os, "open", return_value=72), patch.object(
            streaming_json.os,
            "fsync",
        ), patch.object(
            streaming_json.os,
            "close",
            side_effect=OSError("close only"),
        ), self.assertRaisesRegex(OSError, "close only") as raised:
            fsync_directory("/synthetic-directory")
        self.assertTrue(any(
            "close directory descriptor" in note
            for note in raised.exception.__notes__
        ))

        primary = OSError(errno.EIO, "fsync primary")
        with patch.object(streaming_json.os, "open", return_value=73), patch.object(
            streaming_json.os,
            "fsync",
            side_effect=primary,
        ), patch.object(
            streaming_json.os,
            "close",
            side_effect=OSError("close secondary"),
        ), self.assertRaises(OSError) as raised:
            fsync_directory("/synthetic-directory")
        self.assertIs(raised.exception, primary)
        self.assertTrue(any("close secondary" in note for note in primary.__notes__))

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

    def test_cleanup_helpers_cover_existing_notes_and_multiple_failures(self):
        class BrokenAddNote(RuntimeError):
            def add_note(self, _note):
                raise RuntimeError("disabled")

        primary = BrokenAddNote("primary")
        primary.__notes__ = ["existing"]
        streaming_json._add_cleanup_note(primary, "new")
        self.assertEqual(primary.__notes__, ["existing", "new"])
        self.assertIsNone(streaming_json._finish_cleanups(None, []))

        first = OSError("first")
        with self.assertRaises(OSError) as raised:
            streaming_json._finish_cleanups(
                None,
                [("first", first), ("second", OSError("second"))],
            )
        self.assertIs(raised.exception, first)
        self.assertTrue(any("second" in note for note in first.__notes__))


if __name__ == "__main__":
    unittest.main()
