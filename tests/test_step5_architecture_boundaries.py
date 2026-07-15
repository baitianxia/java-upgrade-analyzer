import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class Step5ArchitectureBoundaryTest(unittest.TestCase):
    def test_step5_engine_initializes_single_ingestion_boundary(self):
        path = ROOT / "scripts/s5_call_chain_engine_integrated.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and ast.unparse(node.func) == "ingest_collector_batches"
        ]

        self.assertEqual(len(calls), 1)

    def test_post_source_graph_mutations_are_known_migration_debt(self):
        files = {
            "scripts/framework_adapters.py",
            "scripts/indirect_usage_analyzer.py",
            "scripts/business_bytecode_graph.py",
        }
        observed = set()
        for relative in files:
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            parents = {}
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    parents[child] = node
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                call = ast.unparse(node.func)
                if not call.endswith("reverse_edges.setdefault"):
                    continue
                owner = node
                while owner and not isinstance(owner, ast.FunctionDef):
                    owner = parents.get(owner)
                observed.add((relative, owner.name if owner else "<module>"))

        self.assertEqual(observed, {
            ("scripts/framework_adapters.py", "attach_framework_edges_to_graph"),
            ("scripts/indirect_usage_analyzer.py", "analyze_and_merge_indirect_usages"),
            ("scripts/business_bytecode_graph.py", "merge_business_bytecode_edges"),
        })


if __name__ == "__main__":
    unittest.main()
