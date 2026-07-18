import ast
import contextlib
import io
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import compat  # noqa: E402


class SubprocessEncodingTest(unittest.TestCase):
    def test_run_cmd_forces_utf8_for_inline_python_child(self):
        for stream_output in (False, True):
            with self.subTest(stream_output=stream_output), patch.dict(
                os.environ,
                {"PYTHONIOENCODING": "gbk", "PYTHONUTF8": "0"},
                clear=False,
            ):
                stdout, stderr, rc = compat.run_cmd(
                    [
                        sys.executable,
                        "-c",
                        "import sys; print(f'utf8_mode={sys.flags.utf8_mode}'); print('状态：⚠')",
                    ],
                    env={"PYTHONIOENCODING": "gbk", "PYTHONUTF8": "0"},
                    stream_output=stream_output,
                    stream_stdout=False,
                )

            self.assertEqual(rc, 0, stderr)
            self.assertEqual(stdout.splitlines(), ["utf8_mode=0", "状态：⚠"])

    def test_run_cmd_streams_unicode_stdout_and_stderr(self):
        relayed = io.StringIO()
        command = [
            sys.executable,
            "-c",
            (
                "import sys;"
                "print('标准输出：⚠', flush=True);"
                "print('错误输出：⚠', file=sys.stderr, flush=True)"
            ),
        ]

        with patch.dict(
            os.environ,
            {"PYTHONIOENCODING": "gbk", "PYTHONUTF8": "0"},
            clear=False,
        ), contextlib.redirect_stderr(relayed):
            stdout, stderr, rc = compat.run_cmd(command, stream_output=True)

        self.assertEqual(rc, 0, stderr)
        self.assertEqual(stdout.strip(), "标准输出：⚠")
        self.assertEqual(stderr.strip(), "错误输出：⚠")
        self.assertIn("标准输出：⚠", relayed.getvalue())
        self.assertIn("错误输出：⚠", relayed.getvalue())

    def test_text_mode_subprocess_calls_explicitly_decode_with_replacement(self):
        violations = []
        for path in (ROOT_DIR / "scripts").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                    and node.func.attr in {"run", "Popen"}
                ):
                    continue
                keywords = {item.arg for item in node.keywords if item.arg}
                if "text" in keywords and not {"encoding", "errors"} <= keywords:
                    violations.append(f"{path.name}:{node.lineno}")

        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
