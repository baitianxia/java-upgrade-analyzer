import ast
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import confidence_weighted_tracer as tracer  # noqa: E402
import step5_trace_policy as policy  # noqa: E402
from step5_graph import SourceGraph  # noqa: E402


class Step5TracePolicyTest(unittest.TestCase):
    def test_step5_module_dependencies_form_one_way_boundaries(self):
        selected = {
            "enhanced_source_analyzer",
            "signature_utils",
            "step5_graph",
            "step5_trace_policy",
            "step5_evidence_model",
            "enhanced_output_formatter",
            "tool_execution",
            "confidence_weighted_tracer",
            "s5_call_chain_engine_integrated",
        }
        dependencies = {}
        for module_name in selected:
            tree = ast.parse(
                (ROOT / "scripts" / f"{module_name}.py").read_text(encoding="utf-8")
            )
            dependencies[module_name] = {
                node.module.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.split(".", 1)[0] in selected
            } | {
                alias.name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
                if alias.name.split(".", 1)[0] in selected
            }

        self.assertEqual(dependencies["signature_utils"], set())
        self.assertEqual(dependencies["step5_graph"], set())
        self.assertEqual(dependencies["step5_trace_policy"], set())
        self.assertEqual(dependencies["step5_evidence_model"], set())
        self.assertEqual(
            dependencies["enhanced_source_analyzer"], {"signature_utils"}
        )
        self.assertFalse(
            dependencies["enhanced_output_formatter"]
            & {"confidence_weighted_tracer", "s5_call_chain_engine_integrated"}
        )
        self.assertFalse(
            dependencies["confidence_weighted_tracer"]
            & {"enhanced_output_formatter", "s5_call_chain_engine_integrated"}
        )
        self.assertIn(
            "confidence_weighted_tracer",
            dependencies["s5_call_chain_engine_integrated"],
        )
        self.assertIn("step5_graph", dependencies["s5_call_chain_engine_integrated"])

        visiting = set()
        visited = set()

        def visit(module_name):
            if module_name in visiting:
                self.fail(f"Step5 module dependency cycle detected at {module_name}")
            if module_name in visited:
                return
            visiting.add(module_name)
            for dependency in dependencies[module_name]:
                visit(dependency)
            visiting.remove(module_name)
            visited.add(module_name)

        for module_name in sorted(selected):
            visit(module_name)

        graph = SourceGraph({}, {}, {}, {}, 0, {}, {})
        self.assertEqual(graph.reverse_edge_count, 0)

    def test_policy_module_is_pure_and_tracer_only_reexports_its_stable_interface(self):
        source = (ROOT / "scripts/step5_trace_policy.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]

        self.assertEqual(imports, [])
        for name in (
            "calculate_depth_cost",
            "calculate_confidence_decay",
            "update_path_frontier",
            "should_stop_tracing",
            "adaptive_exact_high_confidence_cost_limit",
        ):
            with self.subTest(name=name):
                self.assertIs(getattr(tracer, name), getattr(policy, name))

    def test_cost_and_decay_tables_are_total_for_unknown_confidence(self):
        self.assertEqual(
            [policy.calculate_depth_cost(item) for item in ("high", "medium", "low", "")],
            [1, 2, 5, 5],
        )
        self.assertEqual(
            [policy.calculate_confidence_decay(1.0, item) for item in ("high", "medium", "low", "")],
            [0.95, 0.8, 0.5, 0.5],
        )

    def test_frontier_dominance_keeps_orthogonal_cost_confidence_states(self):
        dominated, frontier = policy.update_path_frontier(
            [(2, 0.7)], cost=3, confidence=0.6
        )
        self.assertTrue(dominated)
        self.assertEqual(frontier, [(2, 0.7)])

        dominated, frontier = policy.update_path_frontier(
            frontier, cost=1, confidence=0.5
        )
        self.assertFalse(dominated)
        self.assertEqual(frontier, [(1, 0.5), (2, 0.7)])

    def test_adaptive_budget_only_expands_exact_high_confidence_paths(self):
        graph = SimpleNamespace(reverse_edge_count=12, reverse_edges={})
        high_path = [SimpleNamespace(confidence="high") for _ in range(3)]
        medium_path = [SimpleNamespace(confidence="medium")]

        self.assertEqual(
            policy.adaptive_exact_high_confidence_cost_limit(graph, 5, high_path, "exact"),
            13,
        )
        self.assertEqual(
            policy.adaptive_exact_high_confidence_cost_limit(graph, 5, medium_path, "exact"),
            5,
        )
        self.assertEqual(
            policy.adaptive_exact_high_confidence_cost_limit(graph, 5, high_path, "fallback"),
            5,
        )

    def test_stop_reasons_are_deterministic_and_fail_closed(self):
        cases = (
            ((5, 5, 1.0, None, ""), (True, "DEPTH_LIMIT_REACHED")),
            ((5, 5, 1.0, None, "low"), (True, "LOW_CONFIDENCE_EDGE")),
            ((1, 5, 0.2, None, ""), (True, "CONFIDENCE_DECAYED")),
            ((1, 5, 1.0, {"type": "system_code_touched"}, ""), (True, "SYSTEM_CODE_REACHED")),
            ((1, 5, 1.0, {"type": "framework_boundary"}, ""), (True, "FRAMEWORK_BOUNDARY")),
            ((1, 5, 1.0, None, ""), (False, None)),
        )
        for arguments, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(policy.should_stop_tracing(*arguments), expected)


if __name__ == "__main__":
    unittest.main()
