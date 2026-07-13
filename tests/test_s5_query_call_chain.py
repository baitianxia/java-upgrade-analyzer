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
    build_target_keys,
    _is_precise_lookup_key,
    query_alert_chains,
    query_call_chains,
    query_call_chain_result,
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

    def test_default_target_keys_do_not_include_simple_name_fallbacks(self):
        self.assertEqual(
            build_target_keys("io.seata.common.util.CollectionUtils.isEmpty(java.util.Collection)"),
            [
                "io.seata.common.util.CollectionUtils.isEmpty(java.util.Collection)",
                "io.seata.common.util.CollectionUtils.isEmpty(Collection)",
            ],
        )
        self.assertEqual(
            build_target_keys("net.sf.json.JSONArray"),
            ["net.sf.json.JSONArray", "class:net.sf.json.JSONArray"],
        )
        self.assertIn(
            "method:isEmpty",
            build_target_keys(
                "io.seata.common.util.CollectionUtils.isEmpty(java.util.Collection)",
                fuzzy=True,
            ),
        )

    def test_signed_query_does_not_fall_back_to_unsigned_overload_key(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        wrong_edge = edge(
            app,
            "org.slf4j.Logger.info(java.lang.String,java.lang.Object)",
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
        )
        graph = SimpleNamespace(
            methods_by_id={"app": app},
            lookup_keys_by_symbol={"app": ["com.app.App.run", "method:run"]},
            reverse_edges={
                "org.slf4j.Logger.info": [wrong_edge],
                "org.slf4j.Logger.info(java.lang.String,java.lang.Object)": [wrong_edge],
            },
        )

        chains = query_call_chains(
            build_query_index(graph),
            "org.slf4j.Logger.info(java.lang.String,java.lang.Object[])",
        )

        self.assertEqual(chains, [])

    def test_query_does_not_fall_back_to_unrelated_simple_method_key(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        unrelated_target = "java.util.List.isEmpty()"
        graph = SimpleNamespace(
            methods_by_id={"app": app},
            lookup_keys_by_symbol={"app": ["com.app.App.run", "method:run"]},
            reverse_edges={
                "method:isEmpty": [
                    edge(app, unrelated_target, owner_type="business", owner_coord="BUSINESS", module="app"),
                ],
            },
        )

        chains = query_call_chains(
            build_query_index(graph),
            "io.seata.common.util.CollectionUtils.isEmpty(java.util.Collection)",
        )

        self.assertEqual(chains, [])

    def test_query_does_not_fall_back_to_unrelated_simple_class_key(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        graph = SimpleNamespace(
            methods_by_id={"app": app},
            lookup_keys_by_symbol={"app": ["com.app.App.run", "method:run"]},
            reverse_edges={
                "class:JSONArray": [
                    edge(
                        app,
                        "jsonSwitch.JSONArray",
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                    ),
                ],
            },
        )

        chains = query_call_chains(build_query_index(graph), "net.sf.json.JSONArray")

        self.assertEqual(chains, [])

    def test_query_rejects_chain_that_does_not_contain_exact_target(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        graph = SimpleNamespace(
            methods_by_id={"app": app},
            lookup_keys_by_symbol={"app": ["com.app.App.run", "method:run"]},
            reverse_edges={
                "com.vendor.Target.removed": [
                    edge(
                        app,
                        "com.other.Target.removed",
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                    ),
                ],
            },
        )

        chains = query_call_chains(build_query_index(graph), "com.vendor.Target.removed")

        self.assertEqual(chains, [])

    def test_upstream_expansion_does_not_follow_simple_lookup_keys_by_default(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        unrelated_app = method("other", "com.other.Other.run", owner_type="business", owner_coord="BUSINESS", module="app")
        dep = method("dep", "com.dep.Bridge.use", owner_coord="com.example:dep", module="dep")
        target = "com.vendor.Target.removed()"
        graph = SimpleNamespace(
            methods_by_id={"app": app, "other": unrelated_app, "dep": dep},
            lookup_keys_by_symbol={
                "app": ["com.app.App.run", "method:run"],
                "other": ["com.other.Other.run", "method:run"],
                "dep": ["com.dep.Bridge.use", "method:use"],
            },
            reverse_edges={
                target: [edge(dep, target, owner_coord="com.example:dep", module="dep")],
                # Only the simple key has an incoming business caller.  Default
                # exact query must not use it, otherwise com.other.Other.run is
                # incorrectly stitched onto com.dep.Bridge.use.
                "method:use": [
                    edge(
                        unrelated_app,
                        "com.other.Unrelated.use()",
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                    )
                ],
            },
        )

        chains = query_call_chains(build_query_index(graph), target)

        self.assertEqual(chains, [])

    def test_upstream_expansion_follows_precise_lookup_keys(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        dep = method("dep", "com.dep.Bridge.use", owner_coord="com.example:dep", module="dep")
        target = "com.vendor.Target.removed()"
        graph = SimpleNamespace(
            methods_by_id={"app": app, "dep": dep},
            lookup_keys_by_symbol={
                "app": ["com.app.App.run", "method:run"],
                "dep": ["com.dep.Bridge.use", "method:use"],
            },
            reverse_edges={
                target: [edge(dep, target, owner_coord="com.example:dep", module="dep")],
                "com.dep.Bridge.use": [
                    edge(app, "com.dep.Bridge.use", owner_type="business", owner_coord="BUSINESS", module="app")
                ],
            },
        )

        chains = query_call_chains(build_query_index(graph), target)

        self.assertEqual(
            chains,
            ["com.app.App.run → com.example:dep:com.dep.Bridge.use → com.vendor.Target.removed()"],
        )

    def test_precise_lookup_key_classifier_blocks_simple_keys(self):
        self.assertFalse(_is_precise_lookup_key("method:isEmpty"))
        self.assertFalse(_is_precise_lookup_key("method:isEmpty(String)"))
        self.assertFalse(_is_precise_lookup_key("class:JSONArray"))
        self.assertTrue(_is_precise_lookup_key("class:net.sf.json.JSONArray"))
        self.assertTrue(_is_precise_lookup_key("net.sf.json.JSONArray.fromObject(Object)"))

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

    def test_query_falls_back_to_alerts_for_packaged_dependency_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            alerts = report_dir / "evidence" / "call_chain" / "alerts.csv"
            alerts.parent.mkdir(parents=True)
            alerts.write_text(
                "changed_symbol,api_signature,path_status,path_text\n"
                "com.vendor.LegacyApi.removed,(String),reachable,"
                "com.app.App.run -> com.example:dep-a:com.depa.FacadeA.entry(String) -> "
                "com.example:dep-b:com.depb.BridgeB.call(String) -> "
                "com.vendor.LegacyApi.removed(String)\n",
                encoding="utf-8",
            )

            chains = query_alert_chains(report_dir, "com.vendor.LegacyApi.removed(String)")

        self.assertEqual(
            chains,
            [
                "com.app.App.run → com.example:dep-a:com.depa.FacadeA.entry(String) → "
                "com.example:dep-b:com.depb.BridgeB.call(String) → "
                "com.vendor.LegacyApi.removed(String)"
            ],
        )

    def test_query_falls_back_to_alerts_when_changed_symbol_includes_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            alerts = report_dir / "evidence" / "call_chain" / "alerts.csv"
            alerts.parent.mkdir(parents=True)
            alerts.write_text(
                "changed_symbol,api_signature,path_status,path_text\n"
                "com.vendor.LegacyApi.removed(String),(String),reachable,"
                "com.app.App.run -> com.vendor.LegacyApi.removed(String)\n",
                encoding="utf-8",
            )

            chains = query_alert_chains(report_dir, "com.vendor.LegacyApi.removed(String)")

        self.assertEqual(
            chains,
            ["com.app.App.run → com.vendor.LegacyApi.removed(String)"],
        )

    def test_alert_fallback_rejects_exact_symbol_with_wrong_path_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            alerts = report_dir / "evidence" / "call_chain" / "alerts.csv"
            alerts.parent.mkdir(parents=True)
            alerts.write_text(
                "changed_symbol,api_signature,path_status,path_text\n"
                "net.sf.json.JSONArray,,reachable,"
                "com.app.App.run -> jsonSwitch.JSONArray -> com.alibaba.fastjson.JSONArray\n",
                encoding="utf-8",
            )

            chains = query_alert_chains(report_dir, "net.sf.json.JSONArray")

        self.assertEqual(chains, [])

    def test_query_result_reports_exact_not_found_without_silent_fuzzy_match(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        graph = SimpleNamespace(
            methods_by_id={"app": app},
            lookup_keys_by_symbol={"app": ["com.app.App.run", "method:run"]},
            reverse_edges={
                "method:isEmpty": [
                    edge(
                        app,
                        "java.util.List.isEmpty()",
                        owner_type="business",
                        owner_coord="BUSINESS",
                        module="app",
                    ),
                ],
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            write_query_index(graph, report_dir / ".runtime" / "indexes" / "s5_query_index.json")

            result = query_call_chain_result(
                report_dir,
                "io.seata.common.util.CollectionUtils.isEmpty(java.util.Collection)",
            )

        self.assertEqual(result["chains"], [])
        self.assertFalse(result["exact_match"])
        self.assertEqual(result["match_mode"], "not_found")
        self.assertIn("未找到精确匹配的调用链。", result["warnings"])

    def test_query_respects_limit_on_many_business_callers(self):
        target = "com.vendor.Target.removed()"
        methods = {}
        lookup_keys = {}
        edges = []
        for idx in range(200):
            app = method(
                f"app{idx}",
                f"com.app.App{idx}.run",
                owner_type="business",
                owner_coord="BUSINESS",
                module="app",
            )
            methods[app.symbol_id] = app
            lookup_keys[app.symbol_id] = [app.qualified_key, "method:run"]
            edges.append(edge(app, target, owner_type="business", owner_coord="BUSINESS", module="app"))
        graph = SimpleNamespace(
            methods_by_id=methods,
            lookup_keys_by_symbol=lookup_keys,
            reverse_edges={target: edges},
        )

        chains = query_call_chains(build_query_index(graph), target, limit=3)

        self.assertEqual(len(chains), 3)

    def test_query_avoids_cycles_while_finding_business_chain(self):
        app = method("app", "com.app.App.run", owner_type="business", owner_coord="BUSINESS", module="app")
        dep = method("dep", "com.dep.Looper.loop", owner_coord="com.example:dep", module="dep")
        target = "com.vendor.Target.removed()"
        graph = SimpleNamespace(
            methods_by_id={"app": app, "dep": dep},
            lookup_keys_by_symbol={
                "app": ["com.app.App.run", "method:run"],
                "dep": ["com.dep.Looper.loop", "method:loop"],
            },
            reverse_edges={
                target: [edge(dep, target, owner_coord="com.example:dep", module="dep")],
                "com.dep.Looper.loop": [
                    edge(dep, "com.dep.Looper.loop", owner_coord="com.example:dep", module="dep"),
                    edge(app, "com.dep.Looper.loop", owner_type="business", owner_coord="BUSINESS", module="app"),
                ],
            },
        )

        chains = query_call_chains(build_query_index(graph), target, limit=5, max_visits=20)

        self.assertEqual(
            chains,
            ["com.app.App.run → com.example:dep:com.dep.Looper.loop → com.vendor.Target.removed()"],
        )


if __name__ == "__main__":
    unittest.main()
