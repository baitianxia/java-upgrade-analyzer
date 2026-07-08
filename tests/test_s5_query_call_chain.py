import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from enhanced_source_analyzer import CallEdge
from s5_query_call_chain import (
    build_query_index,
    query_call_chains,
    render_call_chains,
    write_query_index,
    load_query_index,
)


def method(symbol_id, qualified_key, owner_type="dependency", owner_coord="com.example:dep", module="dep"):
    class_fqcn, method_name = qualified_key.rsplit(".", 1)
    return SimpleNamespace(
        symbol_id=symbol_id,
        qualified_key=qualified_key,
        simple_key=f"method:{method_name}",
        class_fqcn=class_fqcn,
        method_name=method_name,
        owner_type=owner_type,
        owner_coord=owner_coord,
        module=module,
        file=f"/repo/{module}/src/main/java/{class_fqcn.replace('.', '/')}.java",
        line=1,
        is_test=False,
    )


def edge(caller, callee, owner_type="dependency", owner_coord="com.example:dep", module="dep"):
    return CallEdge(
        caller_symbol_id=caller.symbol_id,
        caller_qualified_key=caller.qualified_key,
        callee_key=callee,
        callee_simple_key=f"method:{callee.rsplit('.', 1)[-1]}",
        evidence_type="ast_method_invocation",
        confidence="high",
        file=caller.file,
        line=caller.line,
        content="",
        owner_type=owner_type,
        owner_coord=owner_coord,
        module=module,
        is_test=False,
    )


class S5QueryCallChainTest(unittest.TestCase):
    def test_query_returns_complete_business_to_dependency_chain(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        dep_a = method("a", "com.depa.FacadeA.entry", owner_coord="com.example:dep-a", module="dep-a")
        dep_b = method("b", "com.depb.BridgeB.use", owner_coord="com.example:dep-b", module="dep-b")
        target = "com.vendor.Target.removed(String)"
        graph = SimpleNamespace(
            methods_by_id={item.symbol_id: item for item in [app, dep_a, dep_b]},
            lookup_keys_by_symbol={
                "app": ["com.app.App.run", "method:run"],
                "a": ["com.depa.FacadeA.entry", "method:entry"],
                "b": ["com.depb.BridgeB.use", "method:use"],
            },
            reverse_edges={
                target: [edge(dep_b, target, owner_coord="com.example:dep-b", module="dep-b")],
                "com.depb.BridgeB.use": [edge(dep_a, "com.depb.BridgeB.use", owner_coord="com.example:dep-a", module="dep-a")],
                "com.depa.FacadeA.entry": [edge(app, "com.depa.FacadeA.entry", owner_type="business", owner_coord="BUSINESS", module="app")],
            },
        )

        index = build_query_index(graph)
        chains = query_call_chains(index, "com.vendor.Target.removed(String)")

        self.assertEqual(
            chains,
            [
                "com.app.App.run → com.example:dep-a:com.depa.FacadeA.entry → "
                "com.example:dep-b:com.depb.BridgeB.use → com.vendor.Target.removed(String)"
            ],
        )

    def test_query_uses_signature_to_select_overload(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        graph = SimpleNamespace(
            methods_by_id={"app": app},
            lookup_keys_by_symbol={"app": ["com.app.App.run", "method:run"]},
            reverse_edges={
                "com.vendor.Target.removed(String)": [edge(app, "com.vendor.Target.removed(String)", owner_type="business", owner_coord="BUSINESS", module="app")],
                "com.vendor.Target.removed(int)": [edge(app, "com.vendor.Target.removed(int)", owner_type="business", owner_coord="BUSINESS", module="app")],
            },
        )

        chains = query_call_chains(build_query_index(graph), "com.vendor.Target.removed(String)")

        self.assertEqual(chains, ["com.app.App.run → com.vendor.Target.removed(String)"])

    def test_query_returns_empty_when_target_is_missing(self):
        graph = SimpleNamespace(methods_by_id={}, lookup_keys_by_symbol={}, reverse_edges={})

        self.assertEqual(query_call_chains(build_query_index(graph), "com.vendor.Missing.call()"), [])
        self.assertEqual(render_call_chains([]), "未找到调用链。")

    def test_query_index_can_be_loaded_from_report_dir_and_rendered(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        target = "com.vendor.Target.removed()"
        graph = SimpleNamespace(
            methods_by_id={"app": app},
            lookup_keys_by_symbol={"app": ["com.app.App.run", "method:run"]},
            reverse_edges={
                target: [edge(app, target, owner_type="business", owner_coord="BUSINESS", module="app")],
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            index_path = report_dir / ".runtime" / "indexes" / "s5_query_index.json"
            write_query_index(graph, index_path)
            index, path = load_query_index(report_dir)

        self.assertEqual(path.name, "s5_query_index.json")
        text = render_call_chains(query_call_chains(index, target))
        self.assertIn("找到 1 条调用链", text)
        self.assertIn("com.app.App.run → com.vendor.Target.removed()", text)

    def test_query_works_even_when_pipeline_is_awaiting_user_input(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        target = "com.vendor.Target.removed()"
        graph = SimpleNamespace(
            methods_by_id={"app": app},
            lookup_keys_by_symbol={"app": ["com.app.App.run", "method:run"]},
            reverse_edges={
                target: [edge(app, target, owner_type="business", owner_coord="BUSINESS", module="app")],
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            index_path = report_dir / ".runtime" / "indexes" / "s5_query_index.json"
            write_query_index(graph, index_path)
            state_path = report_dir / ".runtime" / "state" / "main_state.json"
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps(
                    {
                        "state": {
                            "status": "awaiting_user_input",
                            "current_step": "step6",
                            "completed_step": "step5",
                        }
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (report_dir / ".runtime" / "state" / "interaction.json").write_text(
                json.dumps({"step_id": "step5", "question": "是否继续？"}, ensure_ascii=False),
                encoding="utf-8",
            )

            index, _path = load_query_index(report_dir)
            chains = query_call_chains(index, target)

        self.assertEqual(chains, ["com.app.App.run → com.vendor.Target.removed()"])


if __name__ == "__main__":
    unittest.main()
