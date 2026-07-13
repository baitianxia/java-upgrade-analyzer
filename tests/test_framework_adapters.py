import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from framework_adapters import run_framework_adapters, attach_framework_edges_to_graph


class FrameworkAdaptersTest(unittest.TestCase):
    def test_dynamic_proxy_text_inside_string_does_not_create_registration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Documentation.java").write_text(
                'package com.acme; class Documentation { String sample = '
                '"Proxy.newProxyInstance(loader, new Class[]{Api.class}, handler)"; }\n',
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        proxy = next(item for item in payload["adapters"] if item["adapter"] == "dynamic_proxy_basic")
        self.assertEqual(proxy["status"], "not_applicable")
        self.assertEqual(proxy["edges"], [])

    def test_multiline_mybatis_annotation_is_bound_by_ast(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "DemoMapper.java").write_text(
                "package com.acme; interface DemoMapper {\n"
                "  @org.apache.ibatis.annotations.Select(\n"
                "    {\"select 1\"}\n"
                "  )\n"
                "  int find();\n"
                "}\n",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        mybatis = next(item for item in payload["adapters"] if item["adapter"] == "mybatis")
        self.assertTrue(any(
            edge.get("target") == "com.acme.DemoMapper.find"
            and (edge.get("provenance") or {}).get("parser") == "tree_sitter"
            for edge in mybatis["edges"]
        ))

    def test_commented_spring_annotations_do_not_create_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Disabled.java").write_text(
                "package com.acme; class Disabled { /* @EventListener public void ghost(Object e) {} */ "
                "// @Scheduled(fixedDelay=1) public void task() {}\n"
                "public void live() {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertFalse(any("ghost" in str(edge) or "task" in str(edge) for edge in spring["edges"]))

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

    def test_packaged_spring_listener_is_runtime_entry_when_business_starts_spring_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            java.mkdir(parents=True)
            (java / "Application.java").write_text(
                "package com.acme; import org.springframework.boot.SpringApplication; "
                "class Application { public static void main(String[] args) { "
                "SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            runtime_jar = module / "runtime.jar"
            with zipfile.ZipFile(runtime_jar, "w") as jar:
                jar.writestr(
                    "META-INF/spring.factories",
                    "org.springframework.context.ApplicationListener=\\\n"
                    "com.vendor.RuntimeListener\n"
                    "org.springframework.boot.autoconfigure.EnableAutoConfiguration=\\\n"
                    "com.vendor.OptionalAutoConfiguration\n",
                )
            payload = run_framework_adapters(
                [{"root": str(module / "src/main/java")}],
                artifact_catalog={"entries": [{
                    "coord": "com.vendor:runtime",
                    "jar_path": str(runtime_jar),
                }]},
            )

        runtime = next(item for item in payload["adapters"] if item["adapter"] == "spring_runtime_artifact")
        callback = next(edge for edge in runtime["edges"] if edge["edge_kind"] == "spring_runtime_registered_callback")
        autoconfig = next(edge for edge in runtime["edges"] if edge["edge_kind"] == "spring_runtime_autoconfiguration_registration")
        self.assertEqual(callback["target"], "com.vendor.RuntimeListener.onApplicationEvent")
        self.assertEqual(callback["runtime_activation"], "active")
        self.assertEqual(autoconfig["runtime_activation"], "conditional")

        graph = SimpleNamespace(methods_by_id={})
        stats = attach_framework_edges_to_graph(graph, payload)
        self.assertEqual(stats["runtime_framework_entry_methods"], 1)
        self.assertIn("com.vendor.RuntimeListener.onApplicationEvent", graph.framework_runtime_entry_methods)

    def test_dependency_test_source_does_not_activate_spring_boot_runtime_callbacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            business = module / "app/src/main/java/com/acme"
            dependency_tests = module / "dep/src/test/java/com/vendor"
            business.mkdir(parents=True)
            dependency_tests.mkdir(parents=True)
            (business / "PlainApp.java").write_text(
                "package com.acme; class PlainApp { public static void main(String[] args) {} }",
                encoding="utf-8",
            )
            (dependency_tests / "DependencyTestApplication.java").write_text(
                "package com.vendor; import org.springframework.boot.SpringApplication; "
                "class DependencyTestApplication { public static void main(String[] args) { "
                "SpringApplication.run(DependencyTestApplication.class, args); } }",
                encoding="utf-8",
            )
            runtime_jar = module / "runtime.jar"
            with zipfile.ZipFile(runtime_jar, "w") as jar:
                jar.writestr(
                    "META-INF/spring.factories",
                    "org.springframework.context.ApplicationListener=com.vendor.RuntimeListener\n",
                )

            payload = run_framework_adapters(
                [
                    {"root": str(module / "app/src/main/java"), "owner_type": "business"},
                    {"root": str(module / "dep"), "owner_type": "dependency"},
                ],
                artifact_catalog={"entries": [{
                    "coord": "com.vendor:runtime",
                    "jar_path": str(runtime_jar),
                }]},
            )

        runtime = next(item for item in payload["adapters"] if item["adapter"] == "spring_runtime_artifact")
        callback = next(edge for edge in runtime["edges"] if edge["edge_kind"] == "spring_runtime_registered_callback")
        self.assertEqual(callback["runtime_activation"], "unproven")
        self.assertEqual(callback["provenance"]["business_activation"], [])

    def test_source_framework_adapters_exclude_dependency_test_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp) / "dependency"
            main = module / "src/main/java/com/vendor"
            tests = module / "src/test/java/com/vendor"
            main.mkdir(parents=True)
            tests.mkdir(parents=True)
            (main / "CleanupJob.java").write_text(
                "package com.vendor; import org.springframework.scheduling.annotation.Scheduled; "
                "class CleanupJob { @Scheduled(fixedDelay=1000) public void cleanup() {} }",
                encoding="utf-8",
            )
            (tests / "DependencyTestJob.java").write_text(
                "package com.vendor; import org.springframework.scheduling.annotation.Scheduled; "
                "class DependencyTestJob { @Scheduled(fixedDelay=1000) public void testOnly() {} "
                "void proxy() { java.lang.reflect.Proxy.newProxyInstance(null, null, null); } }",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{
                "root": str(module),
                "owner_type": "dependency",
                "coord": "com.vendor:dependency",
            }])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        proxy = next(item for item in payload["adapters"] if item["adapter"] == "dynamic_proxy_basic")
        self.assertTrue(any(edge["target"] == "com.vendor.CleanupJob.cleanup" for edge in spring["edges"]))
        self.assertFalse(any("DependencyTestJob" in edge.get("target", "") for edge in spring["edges"]))
        self.assertFalse(any("src/test" in item.get("file", "") for item in proxy["findings"]))
        self.assertEqual(proxy["metrics"]["source_files_scanned"], 1)

    def test_active_runtime_registration_is_added_to_reverse_call_graph(self):
        app = SimpleNamespace(
            symbol_id="app", qualified_key="com.acme.Application.main",
            declared_qualified_key="com.acme.Application.main(String[])",
            declared_signature="(String[])", owner_type="business",
            owner_coord="BUSINESS", module="app", is_test=False,
        )
        listener = SimpleNamespace(
            symbol_id="listener", qualified_key="com.vendor.RuntimeListener.onApplicationEvent",
            declared_qualified_key="com.vendor.RuntimeListener.onApplicationEvent(Object)",
            declared_signature="(Object)", owner_type="dependency",
            owner_coord="com.vendor:runtime", module="runtime", is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"app": app, "listener": listener},
            reverse_edges={},
        )
        payload = {"adapters": [{
            "adapter": "spring_runtime_artifact",
            "version": "1",
            "edges": [{
                "source": "framework:spring-factories:org.springframework.context.ApplicationListener",
                "target": "com.vendor.RuntimeListener.onApplicationEvent",
                "edge_kind": "spring_runtime_registered_callback",
                "confidence": "high",
                "runtime_activation": "active",
                "conditions": [],
                "ambiguity": False,
                "provenance": {
                    "jar": "/runtime/runtime.jar",
                    "line": 1,
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main",
                        "file": "/app/Application.java",
                        "spring_application_run": True,
                    }],
                },
            }],
        }]}

        stats = attach_framework_edges_to_graph(graph, payload)

        self.assertEqual(stats["framework_activation_linked_methods"], 1)
        self.assertIn("listener", graph.framework_activation_linked_symbols)
        linked = graph.reverse_edges["com.vendor.RuntimeListener.onApplicationEvent(Object)"]
        self.assertEqual(linked[0].caller_symbol_id, "app")
        self.assertEqual(linked[0].evidence_type, "spring_runtime_registered_callback")

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
