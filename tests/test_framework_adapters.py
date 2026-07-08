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

    def test_spring_scheduled_method_emits_runtime_active_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "CleanupJob.java").write_text(
                "package com.acme; import org.springframework.scheduling.annotation.Scheduled; "
                "class CleanupJob { @Scheduled(fixedDelay = 1000) public void cleanup() {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertTrue(any(
            edge["edge_kind"] == "spring_runtime_active_entry"
            and edge["target"] == "com.acme.CleanupJob.cleanup"
            for edge in spring["edges"]
        ))

    def test_spring_post_construct_method_emits_runtime_active_entry_without_spring_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Warmup.java").write_text(
                "package com.acme; import jakarta.annotation.PostConstruct; "
                "class Warmup { @PostConstruct public void init() {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertTrue(any(
            edge["edge_kind"] == "spring_runtime_active_entry"
            and edge["target"] == "com.acme.Warmup.init"
            for edge in spring["edges"]
        ))

    def test_spring_xml_scheduled_task_emits_runtime_active_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            resources = module / "src/main/resources"
            java.mkdir(parents=True)
            resources.mkdir(parents=True)
            (java / "CleanupJob.java").write_text(
                "package com.acme; class CleanupJob { public void cleanup() {} }",
                encoding="utf-8",
            )
            (resources / "spring-jobs.xml").write_text(
                """<beans xmlns:task="http://www.springframework.org/schema/task">
  <bean id="cleanupJob" class="com.acme.CleanupJob"/>
  <task:scheduled-tasks>
    <task:scheduled ref="cleanupJob" method="cleanup" fixed-delay="1000"/>
  </task:scheduled-tasks>
</beans>""",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(module / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertTrue(any(
            edge["edge_kind"] == "spring_runtime_active_entry"
            and edge["target"] == "com.acme.CleanupJob.cleanup"
            and edge["evidence"].get("xml_kind") == "spring_xml_scheduled_task"
            for edge in spring["edges"]
        ))

    def test_spring_xml_quartz_method_invoking_job_emits_runtime_active_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            resources = module / "src/main/resources"
            java.mkdir(parents=True)
            resources.mkdir(parents=True)
            (java / "CleanupJob.java").write_text(
                "package com.acme; class CleanupJob { public void cleanup() {} }",
                encoding="utf-8",
            )
            (resources / "quartz.xml").write_text(
                """<beans>
  <bean id="cleanupJob" class="com.acme.CleanupJob"/>
  <bean id="jobDetail" class="org.springframework.scheduling.quartz.MethodInvokingJobDetailFactoryBean">
    <property name="targetObject" ref="cleanupJob"/>
    <property name="targetMethod" value="cleanup"/>
  </bean>
</beans>""",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(module / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertTrue(any(
            edge["edge_kind"] == "spring_runtime_active_entry"
            and edge["target"] == "com.acme.CleanupJob.cleanup"
            and edge["evidence"].get("xml_kind") == "spring_xml_quartz_method_invoking_job"
            for edge in spring["edges"]
        ))

    def test_spring_xml_runtime_active_entry_is_attached_to_graph_method(self):
        method = SimpleNamespace(symbol_id="m1", qualified_key="com.acme.CleanupJob.cleanup")
        graph = SimpleNamespace(methods_by_id={"m1": method})
        payload = {"adapters": [{
            "adapter": "spring_basic",
            "version": "1",
            "edges": [{
                "source": "framework:spring_xml_scheduled_task",
                "target": "com.acme.CleanupJob.cleanup",
                "edge_kind": "spring_runtime_active_entry",
                "confidence": "high",
            }],
        }]}

        stats = attach_framework_edges_to_graph(graph, payload)

        self.assertEqual(stats["matched_callback_edges"], 1)
        self.assertEqual(graph.framework_entry_symbols["m1"][0]["edge_kind"], "spring_runtime_active_entry")

    def test_spring_bean_method_binds_return_type_to_created_implementation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Config.java").write_text(
                "package com.acme; import org.springframework.context.annotation.Bean; "
                "import org.springframework.context.annotation.Configuration; "
                "@Configuration class Config { @Bean PaymentService paymentService() { "
                "return new PaymentServiceImpl(); } "
                "static class PaymentServiceImpl implements PaymentService {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        bean_edge = next(edge for edge in spring["edges"] if edge["edge_kind"] == "spring_bean_dispatch")
        self.assertEqual(bean_edge["source"], "com.acme.PaymentService")
        self.assertEqual(bean_edge["target"], "com.acme.PaymentServiceImpl")
        self.assertNotEqual(bean_edge["target"], "com.acme.Config")

    def test_unresolved_spring_bean_factory_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Config.java").write_text(
                "package com.acme; import org.springframework.context.annotation.Bean; "
                "class Config { @Bean PaymentService paymentService() { return createService(); } }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertEqual(spring["status"], "partial")
        self.assertTrue(any(
            item["reason_code"] == "spring_bean_method_unresolved" for item in spring["findings"]
        ))

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

    def test_dynamic_proxy_adapter_emits_callback_edge_and_registration_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Handler.java").write_text(
                "package com.acme; "
                "import java.lang.reflect.InvocationHandler; "
                "import java.lang.reflect.Method; "
                "class Handler implements InvocationHandler { "
                "public Object invoke(Object proxy, Method method, Object[] args) { return null; } }",
                encoding="utf-8",
            )
            (root / "Factory.java").write_text(
                "package com.acme; "
                "import java.lang.reflect.Proxy; "
                "class Factory { Object build(Handler handler) { return Proxy.newProxyInstance("
                "Factory.class.getClassLoader(), new Class[]{Plugin.class}, handler); } }",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        adapter = next(item for item in payload["adapters"] if item["adapter"] == "dynamic_proxy_basic")
        self.assertEqual(adapter["status"], "complete")
        self.assertTrue(any(edge["edge_kind"] == "dynamic_proxy_callback" for edge in adapter["edges"]))
        self.assertTrue(any(item["reason_code"] == "dynamic_proxy_registration" for item in adapter["findings"]))

        graph = SimpleNamespace(
            methods_by_id={"m1": SimpleNamespace(symbol_id="m1", qualified_key="com.acme.Handler.invoke")}
        )
        attach_framework_edges_to_graph(graph, payload)
        self.assertEqual(graph.framework_entry_symbols, {})

    def test_unregistered_dynamic_proxy_handler_is_not_a_framework_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "DeadHandler.java").write_text(
                "package com.acme; import java.lang.reflect.*; "
                "class DeadHandler implements InvocationHandler { "
                "public Object invoke(Object proxy, Method method, Object[] args) { return null; } }",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        adapter = next(item for item in payload["adapters"] if item["adapter"] == "dynamic_proxy_basic")
        self.assertEqual(adapter["status"], "not_applicable")
        self.assertEqual(adapter["edges"], [])

    def test_declarative_http_client_adapter_emits_outbound_edge_for_feign_get_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "RemoteApi.java").write_text(
                "package com.acme; "
                "import org.springframework.cloud.openfeign.FeignClient; "
                "import org.springframework.web.bind.annotation.GetMapping; "
                "@FeignClient(name = \"demo\") "
                "interface RemoteApi { @GetMapping(\"/orders\") Order fetch(); }",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        adapter = next(item for item in payload["adapters"] if item["adapter"] == "declarative_http_client_basic")
        self.assertEqual(adapter["status"], "complete")
        self.assertTrue(any(edge["edge_kind"] == "declarative_http_client_outbound" for edge in adapter["edges"]))
        self.assertEqual(adapter["edges"][0]["source"], "com.acme.RemoteApi.fetch")
        self.assertTrue(any(item["reason_code"] == "declarative_http_client_registration" for item in adapter["findings"]))

        graph = SimpleNamespace(
            methods_by_id={"m1": SimpleNamespace(symbol_id="m1", qualified_key="com.acme.RemoteApi.fetch")}
        )
        attach_framework_edges_to_graph(graph, payload)
        self.assertEqual(graph.framework_entry_symbols, {})


if __name__ == '__main__':
    unittest.main()
