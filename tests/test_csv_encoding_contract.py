import ast
import csv
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import csv_io  # noqa: E402
import gate  # noqa: E402
import run_step  # noqa: E402
import s2_context_from_deps as step2  # noqa: E402
from step1_observability import Step1Observer  # noqa: E402


def _call_name(call):
    function = call.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return ""


def _is_csv_writer(node):
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "csv"
        and node.func.attr in {"writer", "DictWriter"}
    )


def _authorized_writer_lines(tree):
    authorized = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.With):
            continue
        handles = {
            item.optional_vars.id
            for item in node.items
            if isinstance(item.context_expr, ast.Call)
            and _call_name(item.context_expr) in {"open_csv_write", "open_csv_append"}
            and isinstance(item.optional_vars, ast.Name)
        }
        for statement in node.body:
            for child in ast.walk(statement):
                if (
                    _is_csv_writer(child)
                    and child.args
                    and isinstance(child.args[0], ast.Name)
                    and child.args[0].id in handles
                ):
                    authorized.add(child.lineno)
    return authorized


class CsvEncodingContractTest(unittest.TestCase):
    def assert_single_bom(self, path):
        payload = Path(path).read_bytes()
        self.assertTrue(payload.startswith(csv_io.UTF8_BOM), path)
        self.assertEqual(payload.count(csv_io.UTF8_BOM), 1, path)

    def test_core_csv_readers_strip_bom_from_first_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dep_changes.csv"
            fields = ("coord", "old_version", "new_version", "结论")
            with csv_io.open_csv_write(path) as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow({
                    "coord": "g:a", "old_version": "1", "new_version": "2",
                    "结论": "正式变化",
                })
            self.assertEqual(step2.load_dep_changes(str(path))["g:a"]["结论"], "正式变化")
            self.assertEqual(gate.read_csv_dicts(path, fields)[0]["coord"], "g:a")

    def test_every_script_csv_writer_uses_shared_encoding_boundary(self):
        offenders = []
        for path in sorted((ROOT / "scripts").glob("*.py")):
            if path.name == "csv_io.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            authorized = _authorized_writer_lines(tree)
            for node in ast.walk(tree):
                if _is_csv_writer(node) and node.lineno not in authorized:
                    offenders.append(f"{path.name}:{node.lineno}")
        self.assertEqual(offenders, [])

    def test_orchestration_and_observability_csvs_have_one_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            orchestration = run_step.write_csv_rows(
                root / "step4_timing.csv",
                [{"phase": "binary_trace", "elapsed_seconds": 0.1}],
                ("phase", "elapsed_seconds"),
            )
            observer = Step1Observer(root / "evidence/dependencies/dep_changes.csv")
            token = observer.start_phase("resolve", side="current", message="开始解析")
            observer.finish_phase(token, status="completed", message="解析完成")
            self.assert_single_bom(orchestration)
            self.assert_single_bom(observer.timing_path)

    def test_user_docs_declare_excel_compatible_encoding(self):
        for relative in ("SKILL.md", "RUNBOOK.md", "docs/user/outputs.md"):
            self.assertIn("UTF-8 BOM", (ROOT / relative).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
