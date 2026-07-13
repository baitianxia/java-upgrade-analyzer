import sys
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


if __name__ == "__main__":
    unittest.main()
