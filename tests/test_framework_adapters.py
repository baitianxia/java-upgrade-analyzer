import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from framework_adapters import run_framework_adapters, attach_framework_edges_to_graph


class FrameworkAdaptersTest(unittest.TestCase):
    def test_spi_spring_and_mybatis_emit_independent_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            resources = module / "src/main/resources"
            java.mkdir(parents=True)
            (resources / "META-INF/services").mkdir(parents=True)
            (resources / "mappers").mkdir(parents=True)
            (java / "Listener.java").write_text(
                "package com.acme; import org.springframework.context.event.EventListener; "
                "class Listener { @EventListener public void handle(Object event) {} }",
                encoding="utf-8",
            )
            (java / "PluginOne.java").write_text(
                "package com.acme; import org.springframework.stereotype.Service; "
                "@Service class PluginOne implements Plugin {}",
                encoding="utf-8",
            )
            (resources / "META-INF/services/com.acme.Plugin").write_text(
                "com.acme.PluginOne\ncom.acme.PluginTwo\n", encoding="utf-8",
            )
            (resources / "mappers/Demo.xml").write_text(
                '<mapper namespace="com.acme.DemoMapper">'
                '<select id="find" resultType="com.acme.Dto">select 1</select></mapper>',
                encoding="utf-8",
            )

            payload = run_framework_adapters([{'root': str(module / 'src/main/java')}])

        adapters = {item['adapter']: item for item in payload['adapters']}
        self.assertEqual(adapters['java_spi']['status'], 'partial')
        self.assertEqual(len(adapters['java_spi']['edges']), 2)
        self.assertEqual(adapters['spring_basic']['edges'][0]['edge_kind'], 'spring_event_listener')
        self.assertTrue(any(edge['edge_kind'] == 'spring_bean_dispatch' for edge in adapters['spring_basic']['edges']))
        self.assertEqual(adapters['mybatis']['edges'][0]['target'], 'com.acme.DemoMapper.find')
        self.assertEqual(adapters['mybatis']['findings'][0]['value'], 'com.acme.Dto')

    def test_absent_framework_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'src/main/java'
            root.mkdir(parents=True)
            payload = run_framework_adapters([{'root': str(root)}])
        self.assertTrue(all(item['status'] == 'not_applicable' for item in payload['adapters']))

    def test_spring_callback_edges_are_attached_to_matching_graph_methods(self):
        method = SimpleNamespace(symbol_id="m1", qualified_key="com.acme.Listener.handle(java.lang.Object)")
        graph = SimpleNamespace(methods_by_id={"m1": method})
        payload = {"adapters": [{
            "adapter": "spring_basic", "version": "1",
            "edges": [{
                "source": "framework:spring-event-dispatch",
                "target": "com.acme.Listener.handle",
                "edge_kind": "spring_event_listener",
                "confidence": "high",
            }],
        }]}

        stats = attach_framework_edges_to_graph(graph, payload)

        self.assertEqual(stats["matched_callback_edges"], 1)
        self.assertEqual(graph.framework_entry_symbols["m1"][0]["adapter"], "spring_basic")

    def test_spring_runner_emits_framework_callback_edge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Startup.java").write_text(
                "package com.acme; import org.springframework.stereotype.Component; "
                "import org.springframework.boot.ApplicationRunner; "
                "@Component class Startup implements ApplicationRunner { public void run(Object args) {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertTrue(any(edge["edge_kind"] == "spring_framework_callback" for edge in spring["edges"]))

    def test_spring_autoconfiguration_resource_registrations_are_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java"
            spring_meta = module / "src/main/resources/META-INF/spring"
            java.mkdir(parents=True)
            spring_meta.mkdir(parents=True)
            (spring_meta / "org.springframework.boot.autoconfigure.AutoConfiguration.imports").write_text(
                "com.acme.NewAutoConfiguration\n", encoding="utf-8",
            )
            (module / "src/main/resources/META-INF/spring.factories").write_text(
                "org.springframework.boot.autoconfigure.EnableAutoConfiguration=\\\n"
                "com.acme.LegacyAutoConfiguration\n",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(java)}])

        spi = next(item for item in payload["adapters"] if item["adapter"] == "java_spi")
        kinds = {edge["edge_kind"] for edge in spi["edges"]}
        self.assertIn("spring_autoconfiguration_registration", kinds)
        self.assertIn("spring_factories_registration", kinds)

    def test_edges_have_stable_schema_and_ambiguous_spring_dispatch_is_not_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            for name in ("One", "Two"):
                (root / f"{name}.java").write_text(
                    f"package com.acme; import org.springframework.stereotype.Service; "
                    f"@Service class {name} implements Plugin {{}}", encoding="utf-8"
                )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])
        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertFalse(any(edge["edge_kind"] == "spring_bean_dispatch" for edge in spring["edges"]))
        self.assertTrue(any(item["reason_code"] == "AMBIGUOUS_FRAMEWORK_DISPATCH" for item in spring["findings"]))
        spi = next(item for item in payload["adapters"] if item["adapter"] == "java_spi")
        for edge in spi["edges"]:
            self.assertTrue({"adapter", "adapter_version", "evidence", "activation_conditions", "candidate_count", "ambiguity_reason"} <= set(edge))


if __name__ == '__main__':
    unittest.main()
