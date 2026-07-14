import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class Step5ExceptionBoundaryTest(unittest.TestCase):
    def test_core_evidence_functions_do_not_catch_all_exceptions(self):
        path = ROOT / "scripts/s5_call_chain_engine_integrated.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        protected = {
            "load_orchestrated_step5_input",
            "build_runtime_dependency_catalog",
            "_analyze_source_file_entry",
            "collect_initializer_edges",
            "build_enhanced_source_graph",
            "check_if_needs_bridge_sources",
            "check_apis_that_need_bridge",
        }
        violations = []
        for function in (
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in protected
        ):
            for node in ast.walk(function):
                if (
                    isinstance(node, ast.ExceptHandler)
                    and isinstance(node.type, ast.Name)
                    and node.type.id == "Exception"
                ):
                    violations.append(f"{function.name}:{node.lineno}")

        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
