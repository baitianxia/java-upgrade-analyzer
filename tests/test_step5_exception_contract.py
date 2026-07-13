import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
class Step5ExceptionContractTest(unittest.TestCase):
    def test_runtime_bytecode_failures_are_recorded_in_coverage_ledger(self):
        source = (ROOT / "scripts" / "confidence_weighted_tracer.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        functions = {
            node.name: node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        }

        scan_source = ast.get_source_segment(source, functions["_build_packaged_runtime_dependency_scan_cache"])
        expand_source = ast.get_source_segment(source, functions["_ensure_runtime_dependency_callers_for_key"])

        self.assertIn("scan_failures.append", scan_source)
        self.assertIn("BYTECODE_WORKER_FAILED", scan_source)
        self.assertIn("expansion_failures.append", expand_source)
        self.assertIn("BYTECODE_EXPANSION_INCOMPLETE", expand_source)
