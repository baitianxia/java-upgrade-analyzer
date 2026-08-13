import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from streaming_json import (  # noqa: E402
    files_equal,
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


if __name__ == "__main__":
    unittest.main()
