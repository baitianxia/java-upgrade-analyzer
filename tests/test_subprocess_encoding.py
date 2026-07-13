import ast
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


class SubprocessEncodingTest(unittest.TestCase):
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
