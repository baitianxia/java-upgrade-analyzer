import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


_MUTATING_METHODS = {
    "__delitem__",
    "__setitem__",
    "append",
    "clear",
    "extend",
    "insert",
    "pop",
    "popitem",
    "remove",
    "setdefault",
    "update",
}


def _mentions_reverse_edges(node, aliases=()):
    return any(
        (
            isinstance(item, ast.Attribute)
            and item.attr == "reverse_edges"
        )
        or (
            isinstance(item, ast.Name)
            and item.id in aliases
        )
        or (
            isinstance(item, ast.Constant)
            and item.value == "reverse_edges"
        )
        for item in ast.walk(node)
    )


def _assigned_names(node):
    if isinstance(node, ast.Name):
        return {node.id}
    return {
        item.id for item in ast.walk(node)
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store)
    }


def _reverse_edge_mutations(tree):
    """Return function names containing any direct reverse-edge mutation shape."""
    observed = set()
    owners = [tree, *(
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )]
    nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
    for owner in owners:
        body_nodes = []
        pending = list(ast.iter_child_nodes(owner))
        while pending:
            node = pending.pop()
            if isinstance(node, nested):
                continue
            body_nodes.append(node)
            pending.extend(ast.iter_child_nodes(node))
        aliases = set()
        changed = True
        while changed:
            changed = False
            for node in body_nodes:
                if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    continue
                value = getattr(node, "value", None)
                if value is None or not _mentions_reverse_edges(value, aliases):
                    continue
                targets = (
                    node.targets if isinstance(node, ast.Assign)
                    else [node.target]
                )
                for target in targets:
                    for name in _assigned_names(target):
                        if name not in aliases:
                            aliases.add(name)
                            changed = True

        for node in body_nodes:
            target = None
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                target = getattr(node, "target", None)
                if isinstance(node, ast.Assign):
                    targets = node.targets
                else:
                    targets = [target]
                if any(
                    candidate is not None
                    and _mentions_reverse_edges(candidate, aliases)
                    and not isinstance(candidate, ast.Name)
                    for candidate in targets
                ):
                    observed.add(getattr(owner, "name", "<module>"))
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if isinstance(function, ast.Attribute):
                if (
                    function.attr in _MUTATING_METHODS
                    and _mentions_reverse_edges(function.value, aliases)
                ):
                    observed.add(getattr(owner, "name", "<module>"))
            elif (
                isinstance(function, ast.Name)
                and function.id in {"setattr", "delattr"}
                and any(_mentions_reverse_edges(argument, aliases) for argument in node.args)
            ):
                observed.add(getattr(owner, "name", "<module>"))
    return observed


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

    def test_post_source_collectors_do_not_mutate_graphs_directly(self):
        files = {
            "scripts/framework_adapters.py",
            "scripts/indirect_usage_analyzer.py",
            "scripts/business_bytecode_graph.py",
        }
        observed = set()
        for relative in files:
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            observed.update(
                (relative, owner) for owner in _reverse_edge_mutations(tree)
            )

        self.assertEqual(observed, set())

    def test_reverse_edge_guard_detects_assignment_alias_and_method_mutations(self):
        tree = ast.parse("""
def assign(graph):
    graph.reverse_edges = {}

def subscript(graph, edge):
    graph.reverse_edges[edge.key] = [edge]

def augment(graph, edge):
    graph.reverse_edges[edge.key] += [edge]

def method(graph, edge):
    graph.reverse_edges.setdefault(edge.key, []).append(edge)

def alias(graph, edge):
    reverse = graph.reverse_edges
    bucket = reverse.setdefault(edge.key, [])
    bucket.extend([edge])

def mapping_protocol(graph, edge):
    graph.reverse_edges.__setitem__(edge.key, [edge])
""")

        self.assertEqual(
            _reverse_edge_mutations(tree),
            {"assign", "subscript", "augment", "method", "alias", "mapping_protocol"},
        )

    def test_engine_uses_typed_collectors_not_legacy_mergers(self):
        source = (ROOT / "scripts/s5_call_chain_engine_integrated.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("collect_business_bytecode_batch", source)
        self.assertIn("collect_indirect_usage_batch", source)
        self.assertIn("serialize_framework_batches", source)
        self.assertNotIn("merge_business_bytecode_edges", source)
        self.assertNotIn("analyze_and_merge_indirect_usages", source)
        self.assertNotIn("attach_framework_edges_to_graph", source)


if __name__ == "__main__":
    unittest.main()
