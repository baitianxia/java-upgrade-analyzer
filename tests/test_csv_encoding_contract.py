import ast
import csv
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import csv_io  # noqa: E402
import enhanced_output_formatter as output_formatter  # noqa: E402
import gate  # noqa: E402
import run_step  # noqa: E402
import s2_context_from_deps as step2  # noqa: E402
import s3_scan as step3  # noqa: E402
import s4_jar_compare as step4  # noqa: E402
import s6_report as step6  # noqa: E402
from step1_observability import Step1Observer  # noqa: E402


def _call_name(call):
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _is_csv_writer_call(node):
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
            and _call_name(item.context_expr)
            in {"open_csv_write", "open_csv_append"}
            and isinstance(item.optional_vars, ast.Name)
        }
        for statement in node.body:
            for child in ast.walk(statement):
                if (
                    _is_csv_writer_call(child)
                    and child.args
                    and isinstance(child.args[0], ast.Name)
                    and child.args[0].id in handles
                ):
                    authorized.add(child.lineno)
    return authorized


class CsvEncodingContractTest(unittest.TestCase):
    def assert_single_leading_bom(self, path):
        payload = Path(path).read_bytes()
        self.assertTrue(payload.startswith(csv_io.UTF8_BOM), path)
        self.assertEqual(payload.count(csv_io.UTF8_BOM), 1, path)

    def test_core_csv_readers_do_not_expose_bom_in_first_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dep_changes.csv"
            fields = [
                "coord",
                "old_version",
                "new_version",
                "change_type",
                "resolution_status",
                "结论",
            ]
            with csv_io.open_csv_write(path) as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "g:a",
                        "old_version": "1",
                        "new_version": "2",
                        "change_type": "升级",
                        "resolution_status": "resolved",
                        "结论": "已确认",
                    }
                )

            self.assertEqual(step2.load_dep_changes(str(path))["g:a"]["结论"], "已确认")
            gate_rows = gate.read_csv_dicts(path, ["coord", "old_version", "new_version"])
            self.assertEqual(gate_rows[0]["coord"], "g:a")

    def test_all_script_csv_writers_use_csv_io_boundary(self):
        offenders = []
        for path in sorted((ROOT_DIR / "scripts").glob("*.py")):
            if path.name == "csv_io.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            authorized = _authorized_writer_lines(tree)
            for node in ast.walk(tree):
                if _is_csv_writer_call(node) and node.lineno not in authorized:
                    offenders.append(f"{path.name}:{node.lineno}")
        self.assertEqual(offenders, [])

    def test_representative_pipeline_outputs_have_one_leading_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outputs = [
                root / "step3.csv",
                root / "step4.csv",
                root / "run_step.csv",
                root / "alerts.csv",
                root / "step6_part.csv",
            ]
            step3.write_csv_results([{"结论": "已确认"}], ["结论"], outputs[0])
            step4._write_contract_csv(outputs[1], [])
            run_step.write_csv_rows(outputs[2], [{"结论": "已确认"}], ["结论"])
            output_formatter._write_alert_rows_csv(outputs[3], [])
            step6._write_changed_api_part(
                outputs[4], ["依赖坐标", "结论"],
                [{"依赖坐标": "示例:依赖:1.0", "结论": "已确认影响"}],
            )

            observer = Step1Observer(root / "evidence" / "dependencies" / "dep_changes.csv")
            token = observer.start_phase("resolve", side="current", message="开始解析")
            observer.finish_phase(token, status="completed", message="解析完成")
            outputs.append(observer.timing_path)

            for path in outputs:
                self.assert_single_leading_bom(path)


if __name__ == "__main__":
    unittest.main()
