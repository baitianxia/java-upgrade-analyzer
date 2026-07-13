import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import enhanced_source_analyzer as analyzer  # noqa: E402


class SourceDecodingTest(unittest.TestCase):
    def test_decodes_gbk_java_source_without_replacement_characters(self):
        raw = "package com.acme; class 中文服务 { void 调用() {} }".encode("gb18030")

        text = analyzer.decode_java_source_bytes(raw)

        self.assertIn("中文服务", text)
        self.assertIn("调用", text)
        self.assertNotIn("\ufffd", text)

    def test_oversized_java_file_is_marked_incomplete_instead_of_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "Huge.java"
            source.write_text("class Huge {}\n" * 3, encoding="utf-8")
            previous = analyzer.MAX_TREE_SITTER_SOURCE_LINES
            analyzer.MAX_TREE_SITTER_SOURCE_LINES = 2
            try:
                methods, info = analyzer.analyze_file(
                    str(source), str(source.parent), return_diagnostics=True
                )
            finally:
                analyzer.MAX_TREE_SITTER_SOURCE_LINES = previous

        self.assertEqual(methods, [])
        self.assertEqual(info["actual_parser"], "skipped")
        self.assertEqual(info["fallback_reason"], "source_file_line_limit_exceeded")


if __name__ == "__main__":
    unittest.main()
