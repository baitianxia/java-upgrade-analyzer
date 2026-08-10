import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import binary_asm_helper  # noqa: E402
from binary_pipeline import run_pipeline  # noqa: E402
from binary_fact_store import BinaryFactStore  # noqa: E402
from binary_regression_topology import (  # noqa: E402
    expected_changed_reachability,
    generate_topology,
    java_sources,
    topology_matrix,
)


def jdk_home():
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, check=False,
    )
    for line in completed.stderr.splitlines():
        if "java.home" in line and "=" in line:
            return Path(line.split("=", 1)[1].strip())
    return None


class BinaryGeneratedRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = jdk_home()
        if not shutil.which("javac") or not cls.home or not (cls.home / "jmods").is_dir():
            raise unittest.SkipTest("full target JDK required")
        cls.asm_jar = binary_asm_helper.resolve_asm_jar()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def compile_jar(self, label, sources, *, resources=None, classpath=()):
        source_root = self.root / label / "src"
        paths = []
        for relative, content in sources.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            paths.append(path)
        classes = self.root / label / "classes"
        classes.mkdir(parents=True)
        command = ["javac", "-g:none", "-d", str(classes)]
        if classpath:
            command.extend(["-classpath", ":".join(map(str, classpath))])
        completed = subprocess.run(
            [*command, *map(str, paths)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        jar = self.root / label / f"{label}.jar"
        completed = subprocess.run(
            ["jar", "--create", "--file", str(jar), "-C", str(classes), "."],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        if resources:
            resource_root = self.root / label / "resources"
            for relative, content in resources.items():
                path = resource_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            completed = subprocess.run(
                ["jar", "--update", "--file", str(jar), "-C", str(resource_root), "."],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        return jar

    def side(self, jar, version):
        return {
            "jdk_home": str(self.home),
            "artifacts": [{
                "path": str(jar), "logical_location": "lib/generated.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 0, "coord": f"generated:topology:{version}",
                "lineage": "generated:topology",
                "runtime_code_source_origin_identity": "generated-topology",
            }],
            "runtime_profile": {
                "container_and_launcher_kind": "java-classpath",
                "loader_topology": {
                    "coverage_status": "complete",
                    "entrypoint_realms": ["application-loader"],
                    "realms": [{
                        "identity": "platform-loader", "kind": "platform",
                        "delegation": "parent_first", "module_mode": "named-platform",
                    }, {
                        "identity": "application-loader", "kind": "application",
                        "parent": "platform-loader", "delegation": "parent_first",
                        "module_mode": "unnamed",
                    }],
                },
                "runtime_security_and_package_sealing_policy_identity": (
                    "standard-unsealed-unsigned-v1"
                ),
                "active_profile_identities": [],
                "external_config_snapshot_identities": [],
                "agent_transformer_plugin_profile_identities": [],
                "business_entrypoint_profile": {
                    "coverage_status": "complete", "methods": [{
                        "initiating_loader_realm_identity": "application-loader",
                        "class_name": "generated/N000", "member_name": "call",
                        "descriptor": "()I",
                    }],
                },
                "runtime_class_closure_coverage_status": "complete",
                "resource_selection_coverage_status": "complete",
            },
        }

    def run_topology(self, topology, label, *, include_unrelated=False):
        base = self.compile_jar(
            f"{label}-base",
            java_sources(topology, current=False, include_unrelated=include_unrelated),
        )
        current = self.compile_jar(
            f"{label}-current",
            java_sources(topology, current=True, include_unrelated=include_unrelated),
        )
        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": self.side(base, "1"), "current": self.side(current, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(config, output_root=self.root / f"{label}-report")
        payload = json.loads(
            (Path(result["generation_directory"]) / "binary_formal_results.json")
            .read_text(encoding="utf-8")
        )
        return {
            row["display_owner"]: row["reachability_status"]
            for row in payload["by_api"]
            if row["display_owner"] in expected_changed_reachability(topology)
            and row["display_member"] == "call"
        }

    def test_generated_seed_matrix_has_positive_and_negative_oracles(self):
        for topology in topology_matrix((7, 19, 43, 101)):
            with self.subTest(seed=topology.seed):
                expected = expected_changed_reachability(topology)
                self.assertIn("reachable", expected.values())
                self.assertIn("not_found_in_static_analysis", expected.values())
                self.assertEqual(topology, generate_topology(topology.seed))

    def test_generated_binary_graph_matches_independent_reachability_oracle(self):
        topology = generate_topology(43, node_count=18)
        self.assertEqual(
            self.run_topology(topology, "generated"),
            expected_changed_reachability(topology),
        )

    def test_unrelated_binary_addition_is_metamorphically_invariant(self):
        topology = generate_topology(19, node_count=14)
        baseline = self.run_topology(topology, "metamorphic-clean")
        transformed = self.run_topology(
            topology, "metamorphic-unrelated", include_unrelated=True
        )
        self.assertEqual(baseline, transformed)
        self.assertEqual(baseline, expected_changed_reachability(topology))

    def test_dependency_only_scheduled_auto_configuration_is_exact_and_reachable(self):
        application = self.compile_jar("scheduled-app", {
            "business/Main.java": (
                "package business; public class Main { "
                "public static void main(String[] args){} }"
            ),
        })

        def dependency(label, value):
            return self.compile_jar(label, {
                "org/springframework/boot/autoconfigure/AutoConfiguration.java": (
                    "package org.springframework.boot.autoconfigure; "
                    "import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                    "public @interface AutoConfiguration {}"
                ),
                "org/springframework/scheduling/annotation/Scheduled.java": (
                    "package org.springframework.scheduling.annotation; "
                    "import java.lang.annotation.*; "
                    "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) "
                    "public @interface Scheduled {}"
                ),
                "vendor/ScheduledConfig.java": (
                    "package vendor; "
                    "@org.springframework.boot.autoconfigure.AutoConfiguration "
                    "public class ScheduledConfig { "
                    "@org.springframework.scheduling.annotation.Scheduled "
                    f"public void tick() {{ System.setProperty(\"scheduled.version\", \"{value}\"); }} "
                    "}"
                ),
                "vendor/ConfigKey.java": (
                    "package vendor; public record ConfigKey(String value) { "
                    "public Class<?>[] types() { return new Class<?>[]{String[].class, int[].class}; } "
                    "public Object matrix() { return new String[1][1]; } }"
                ),
            }, resources={
                "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports": (
                    "vendor.ScheduledConfig\n"
                ),
            })

        base_dependency = dependency("scheduled-dependency-base", "base")
        current_dependency = dependency("scheduled-dependency-current", "current")

        def side(dependency_jar, version):
            payload = self.side(dependency_jar, version)
            payload["artifacts"] = [{
                "path": str(application),
                "logical_location": "application/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "generated:scheduled-app:1",
                "lineage": "generated:scheduled-app",
                "runtime_code_source_origin_identity": "generated-scheduled-app",
            }, {
                "path": str(dependency_jar),
                "logical_location": "dependencies/scheduler.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"generated:scheduler:{version}",
                "lineage": "generated:scheduler",
                "runtime_code_source_origin_identity": "generated-scheduler",
            }]
            payload["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "activated_frameworks": ["spring_boot"],
                "main_class": "business/Main",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "business/Main", "member_name": "main",
                    "descriptor": "([Ljava/lang/String;)V",
                }],
            }
            payload["runtime_profile"]["active_profile_identities"] = ["default"]
            payload["runtime_profile"]["resolved_configuration_properties"] = {}
            payload["runtime_profile"]["runtime_configuration_coverage_status"] = "complete"
            return payload

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_dependency, "1"),
            "current": side(current_dependency, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(config, output_root=self.root / "scheduled-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        entrypoints = json.loads(
            (generation / "binary_entrypoints.json").read_text(encoding="utf-8")
        )
        changed = [
            row for row in formal["by_api"]
            if row["display_owner"] == "vendor/ScheduledConfig"
            and row["display_member"] == "tick"
        ]
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["reachability_status"], "reachable")
        scheduled = [
            row for row in entrypoints["records"]
            if row["class_name"] == "vendor/ScheduledConfig"
            and row["member_name"] == "tick"
            and row["entry_kind"] == "spring_scheduled"
        ]
        self.assertEqual(len(scheduled), 1)
        self.assertEqual(scheduled[0]["path_certainty"], "exact")
        self.assertEqual(
            scheduled[0]["activation_reason"],
            "spring_boot_auto_configuration_import",
        )
        self.assertEqual(scheduled[0]["dependency_coord"], "generated:scheduler:2")
        self.assertEqual(scheduled[0]["runtime_path_kind"], "classpath")
        with BinaryFactStore(generation / "current_binary_facts.sqlite") as store:
            type_edges = {
                row["direct_edge_identity"]: row
                for row in store.rows("direct_edges", where="edge_kind='type'")
            }
            type_resolutions = [
                json.loads(row["payload_json"])
                for row in store.rows("reconciliation_records")
                if row["record_kind"] == "type_resolution"
            ]
        array_resolutions = {
            type_edges[row["direct_edge_identity"]]["symbolic_owner"]: row
            for row in type_resolutions
            if row["direct_edge_identity"] in type_edges
            and str(type_edges[row["direct_edge_identity"]]["symbolic_owner"]).startswith("[")
        }
        self.assertEqual(
            array_resolutions["[I"]["type_resolution_status"],
            "primitive_or_array_type",
        )
        for descriptor in ("[Ljava/lang/String;", "[[Ljava/lang/String;"):
            self.assertEqual(array_resolutions[descriptor]["type_resolution_status"], "resolved")
            self.assertEqual(
                array_resolutions[descriptor]["resolved_provider_owner"],
                "java/lang/String",
            )

    def test_message_listener_adapter_string_callback_is_exact_and_reachable(self):
        def target(label, value):
            return self.compile_jar(label, {
                "target/Api.java": (
                    "package target; public class Api { "
                    f"public int value() {{ return {value}; }} }}"
                ),
            })

        base_target = target("amqp-target-base", 1)
        current_target = target("amqp-target-current", 2)
        application = self.compile_jar("amqp-application", {
            "org/springframework/context/annotation/Configuration.java": (
                "package org.springframework.context.annotation; "
                "import java.lang.annotation.*; "
                "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) "
                "public @interface Configuration {}"
            ),
            "org/springframework/context/annotation/Bean.java": (
                "package org.springframework.context.annotation; "
                "import java.lang.annotation.*; "
                "@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) "
                "public @interface Bean {}"
            ),
            "org/springframework/amqp/rabbit/listener/adapter/MessageListenerAdapter.java": (
                "package org.springframework.amqp.rabbit.listener.adapter; "
                "public class MessageListenerAdapter { "
                "public MessageListenerAdapter(Object receiver, String method) {} }"
            ),
            "business/Receiver.java": (
                "package business; public class Receiver { "
                "public int receiveMessage(String body) { "
                "return new target.Api().value(); } }"
            ),
            "business/Config.java": (
                "package business; "
                "@org.springframework.context.annotation.Configuration "
                "public class Config { "
                "@org.springframework.context.annotation.Bean "
                "public org.springframework.amqp.rabbit.listener.adapter.MessageListenerAdapter "
                "listenerAdapter(Receiver receiver) { "
                "return new org.springframework.amqp.rabbit.listener.adapter.MessageListenerAdapter("
                "receiver, \"receiveMessage\"); } }"
            ),
            "business/Main.java": (
                "package business; public class Main { "
                "public static void main(String[] args) {} }"
            ),
        }, classpath=(base_target,))

        def side(target_jar, version):
            payload = self.side(target_jar, version)
            payload["artifacts"] = [{
                "path": str(application),
                "logical_location": "application/business.jar",
                "loader_realm": "application-loader",
                "path_kind": "business_classes", "slot": 0,
                "coord": "generated:amqp-app:1",
                "lineage": "generated:amqp-app",
                "runtime_code_source_origin_identity": "generated-amqp-app",
            }, {
                "path": str(target_jar),
                "logical_location": "dependencies/target.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath", "slot": 1,
                "coord": f"generated:amqp-target:{version}",
                "lineage": "generated:amqp-target",
                "runtime_code_source_origin_identity": "generated-amqp-target",
            }]
            payload["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "activated_frameworks": ["spring_boot"],
                "main_class": "business/Main",
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "business/Main", "member_name": "main",
                    "descriptor": "([Ljava/lang/String;)V",
                }],
            }
            return payload

        result = run_pipeline({
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_target, "1"),
            "current": side(current_target, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }, output_root=self.root / "amqp-report")
        generation = Path(result["generation_directory"])
        entrypoints = json.loads(
            (generation / "binary_entrypoints.json").read_text(encoding="utf-8")
        )
        callbacks = [
            row for row in entrypoints["records"]
            if row["class_name"] == "business/Receiver"
            and row["member_name"] == "receiveMessage"
            and row["descriptor"] == "(Ljava/lang/String;)I"
            and row["entry_kind"] == "spring_message_listener"
        ]
        self.assertEqual(len(callbacks), 1, entrypoints["records"])
        self.assertEqual(callbacks[0]["path_certainty"], "exact")
        self.assertEqual(
            callbacks[0]["activation_reason"],
            "spring_message_listener_adapter_registration",
        )
        self.assertEqual(callbacks[0]["dependency_coord"], "generated:amqp-app:1")

        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        changed = [
            row for row in formal["by_api"]
            if row["display_owner"] == "target/Api"
            and row["display_member"] == "value"
            and row["display_descriptor"] == "()I"
        ]
        self.assertEqual(len(changed), 1, formal["by_api"])
        self.assertEqual(changed[0]["reachability_status"], "reachable")
        self.assertEqual(
            changed[0]["current_dependency_coords"],
            ["generated:amqp-target:2"],
        )

    def test_mybatis_xml_extensions_are_registered_runtime_callbacks(self):
        application = self.compile_jar("mybatis-extension-app", {
            "business/Main.java": (
                "package business; public class Main { "
                "public static void main(String[] args) {} }"
            ),
        })

        def extension(label, value):
            return self.compile_jar(label, {
                "org/apache/ibatis/plugin/Interceptor.java": (
                    "package org.apache.ibatis.plugin; public interface Interceptor { "
                    "Object intercept(Object invocation); }"
                ),
                "org/apache/ibatis/type/TypeHandler.java": (
                    "package org.apache.ibatis.type; public interface TypeHandler { "
                    "void setParameter(Object value); Object getResult(Object value); }"
                ),
                "vendor/AuditPlugin.java": (
                    "package vendor; public class AuditPlugin implements "
                    "org.apache.ibatis.plugin.Interceptor { "
                    f"public Object intercept(Object invocation) {{ return {value}; }} }}"
                ),
                "vendor/CodeHandler.java": (
                    "package vendor; public class CodeHandler implements "
                    "org.apache.ibatis.type.TypeHandler { "
                    f"public void setParameter(Object value) {{ System.setProperty("
                    f"\"handler.version\", \"{value}\"); }} "
                    f"public Object getResult(Object value) {{ return {value}; }} }}"
                ),
            }, resources={
                "mybatis-config.xml": (
                    '<!DOCTYPE configuration PUBLIC "-//mybatis.org//DTD Config 3.0//EN" '
                    '"https://mybatis.org/dtd/mybatis-3-config.dtd">'
                    '<configuration><plugins><plugin interceptor="vendor.AuditPlugin"/>'
                    '</plugins><typeHandlers><typeHandler javaType="java.lang.String" '
                    'handler="vendor.CodeHandler"/></typeHandlers></configuration>'
                ),
            })

        base_extension = extension("mybatis-extension-base", 1)
        current_extension = extension("mybatis-extension-current", 2)

        def side(extension_jar, version):
            payload = self.side(extension_jar, version)
            payload["artifacts"] = [{
                "path": str(application),
                "logical_location": "application/business.jar",
                "loader_realm": "application-loader",
                "path_kind": "business_classes", "slot": 0,
                "coord": "generated:mybatis-app:1",
                "lineage": "generated:mybatis-app",
                "runtime_code_source_origin_identity": "generated-mybatis-app",
            }, {
                "path": str(extension_jar),
                "logical_location": "dependencies/mybatis-extension.jar",
                "loader_realm": "application-loader", "path_kind": "classpath",
                "slot": 1, "coord": f"generated:mybatis-extension:{version}",
                "lineage": "generated:mybatis-extension",
                "runtime_code_source_origin_identity": "generated-mybatis-extension",
            }]
            payload["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete",
                "activated_frameworks": ["mybatis"],
                "activated_resource_names": ["classpath:mybatis-config.xml"],
                "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "business/Main", "member_name": "main",
                    "descriptor": "([Ljava/lang/String;)V",
                }],
            }
            return payload

        result = run_pipeline({
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {
                "decision": "skip_source", "decision_source": "explicit_config",
            },
            "asm_jar": str(self.asm_jar),
            "base": side(base_extension, "1"),
            "current": side(current_extension, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }, output_root=self.root / "mybatis-extension-report")
        generation = Path(result["generation_directory"])
        entries = json.loads(
            (generation / "binary_entrypoints.json").read_text(encoding="utf-8")
        )["records"]
        extension_entries = [
            row for row in entries
            if row["entry_kind"] in {
                "mybatis_plugin_callback", "mybatis_type_handler_callback",
            }
        ]
        self.assertEqual(
            {
                (row["class_name"], row["member_name"], row["path_certainty"])
                for row in extension_entries
            },
            {
                ("vendor/AuditPlugin", "intercept", "exact"),
                ("vendor/CodeHandler", "setParameter", "exact"),
                ("vendor/CodeHandler", "getResult", "exact"),
            },
        )
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )["by_api"]
        changed_callbacks = [
            row for row in formal
            if row["display_owner"] in {
                "vendor/AuditPlugin", "vendor/CodeHandler",
            }
            and row["display_member"] in {
                "intercept", "setParameter", "getResult",
            }
        ]
        self.assertEqual(len(changed_callbacks), 3, changed_callbacks)
        self.assertTrue(all(
            row["reachability_status"] == "reachable"
            for row in changed_callbacks
        ))

    def test_business_to_cross_dependency_multihop_preserves_dispatch_topologies(self):
        def targets(label, value):
            return self.compile_jar(label, {
                "target/Service.java": (
                    "package target; public interface Service { int value(); }"
                ),
                "target/ServiceImpl.java": (
                    "package target; public class ServiceImpl implements Service { "
                    f"public int value() {{ return {value}; }} }}"
                ),
                "target/VirtualTarget.java": (
                    "package target; public class VirtualTarget { "
                    f"public int value() {{ return {value + 10}; }} }}"
                ),
                "target/StaticTarget.java": (
                    "package target; public class StaticTarget { "
                    f"public static int value() {{ return {value + 20}; }} }}"
                ),
                "target/OverloadedTarget.java": (
                    "package target; public class OverloadedTarget { "
                    f"public int value(int input) {{ return input + {value}; }} "
                    "public int value(String input) { return input.length(); } }"
                ),
                "target/ConstructorTarget.java": (
                    "package target; public class ConstructorTarget { "
                    f"public ConstructorTarget() {{ System.setProperty(\"target.version\", \"{value}\"); }} }}"
                ),
                "target/FieldTarget.java": (
                    "package target; public class FieldTarget { "
                    f"public static int VALUE = {value}; }}"
                ),
            })

        base_target = targets("multihop-target-base", 1)
        current_target = targets("multihop-target-current", 2)

        def bridge(label, target_jar):
            return self.compile_jar(label, {
                "bridge/Bridge.java": (
                    "package bridge; public class Bridge { public int run() { "
                    "target.Service service = new target.ServiceImpl(); "
                    "new target.ConstructorTarget(); "
                    "return service.value() + new target.VirtualTarget().value() "
                    "+ target.StaticTarget.value() "
                    "+ target.FieldTarget.VALUE "
                    "+ new target.OverloadedTarget().value(1); } }"
                ),
            }, classpath=(target_jar,))

        base_bridge = bridge("multihop-bridge-base", base_target)
        current_bridge = bridge("multihop-bridge-current", current_target)

        def application(label, bridge_jar, target_jar):
            return self.compile_jar(label, {
                "business/Main.java": (
                    "package business; public class Main { "
                    "public int run() { return new bridge.Bridge().run(); } }"
                ),
            }, classpath=(bridge_jar, target_jar))

        base_application = application(
            "multihop-app-base", base_bridge, base_target
        )
        current_application = application(
            "multihop-app-current", current_bridge, current_target
        )

        def side(application_jar, bridge_jar, target_jar, version):
            payload = self.side(target_jar, version)
            payload["artifacts"] = [
                {
                    "path": str(application_jar),
                    "logical_location": "application/business.jar",
                    "loader_realm": "application-loader", "path_kind": "business_classes",
                    "slot": 0, "coord": "generated:multihop-app:1",
                    "lineage": "generated:multihop-app",
                    "runtime_code_source_origin_identity": "generated-multihop-app",
                }, {
                    "path": str(bridge_jar),
                    "logical_location": "dependencies/bridge.jar",
                    "loader_realm": "application-loader", "path_kind": "classpath",
                    # Deliberately share the project coordinate with the
                    # business module: physical runtime slot and lineage, not
                    # Maven coordinate alone, must keep both modules distinct.
                    "slot": 1, "coord": "generated:multihop-app:1",
                    "lineage": "generated:multihop-bridge",
                    "runtime_code_source_origin_identity": "generated-multihop-bridge",
                }, {
                    "path": str(target_jar),
                    "logical_location": "dependencies/target.jar",
                    "loader_realm": "application-loader", "path_kind": "classpath",
                    "slot": 2, "coord": f"generated:multihop-target:{version}",
                    "lineage": "generated:multihop-target",
                    "runtime_code_source_origin_identity": "generated-multihop-target",
                },
            ]
            payload["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "business/Main", "member_name": "run",
                    "descriptor": "()I",
                }],
            }
            return payload

        config = {
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(base_application, base_bridge, base_target, "1"),
            "current": side(current_application, current_bridge, current_target, "2"),
            "runtime_comparison": {
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }
        result = run_pipeline(config, output_root=self.root / "multihop-report")
        formal = json.loads(
            (Path(result["generation_directory"]) / "binary_formal_results.json")
            .read_text(encoding="utf-8")
        )
        observed = {
            (row["display_owner"], row["display_member"], row["display_descriptor"]): row
            for row in formal["by_api"]
        }
        expected = {
            ("target/ServiceImpl", "value", "()I"),
            ("target/VirtualTarget", "value", "()I"),
            ("target/StaticTarget", "value", "()I"),
            ("target/OverloadedTarget", "value", "(I)I"),
            ("target/ConstructorTarget", "<init>", "()V"),
            ("target/FieldTarget", "<clinit>", "()V"),
        }
        self.assertTrue(expected.issubset(observed), sorted(observed))
        for key in expected:
            self.assertEqual(observed[key]["reachability_status"], "reachable", key)
            self.assertIn(
                "generated:multihop-target:2",
                observed[key]["current_dependency_coords"],
                key,
            )
        unchanged_overload = (
            "target/OverloadedTarget", "value", "(Ljava/lang/String;)I"
        )
        self.assertNotIn(unchanged_overload, observed)

    def test_removed_dependency_is_reported_with_base_ownership_and_explicit_limit(self):
        removed = self.compile_jar("removed-dependency", {
            "removed/Api.java": (
                "package removed; public class Api { public int value() { return 1; } }"
            ),
        })
        application = self.compile_jar("removed-dependency-app", {
            "business/Main.java": (
                "package business; public class Main { "
                "public int run() { return new removed.Api().value(); } }"
            ),
        }, classpath=(removed,))

        def side(include_dependency):
            payload = self.side(application, "1")
            payload["artifacts"] = [{
                "path": str(application),
                "logical_location": "application/business.jar",
                "loader_realm": "application-loader", "path_kind": "business_classes",
                "slot": 0, "coord": "generated:removed-app:1",
                "lineage": "generated:removed-app",
                "runtime_code_source_origin_identity": "generated-removed-app",
            }]
            if include_dependency:
                payload["artifacts"].append({
                    "path": str(removed),
                    "logical_location": "dependencies/removed.jar",
                    "loader_realm": "application-loader", "path_kind": "classpath",
                    "slot": 1, "coord": "generated:removed-library:1",
                    "lineage": "generated:removed-library",
                    "runtime_code_source_origin_identity": "generated-removed-library",
                })
            payload["runtime_profile"]["business_entrypoint_profile"] = {
                "coverage_status": "complete", "methods": [{
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "business/Main", "member_name": "run",
                    "descriptor": "()I",
                }],
            }
            return payload

        result = run_pipeline({
            "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            "source_usage": {"decision": "skip_source", "decision_source": "explicit_config"},
            "asm_jar": str(self.asm_jar),
            "base": side(True), "current": side(False),
            "runtime_comparison": {
                "comparison_intent": "release_snapshot",
                "controlled_profile_fields": ["loader_topology"],
                "declared_upgrade_payload_scope": ["artifact-bytes"],
            },
        }, output_root=self.root / "removed-report")
        generation = Path(result["generation_directory"])
        formal = json.loads(
            (generation / "binary_formal_results.json").read_text(encoding="utf-8")
        )
        pairings = json.loads(
            (generation / "binary_pairings.json").read_text(encoding="utf-8")
        )
        rows = [
            row for row in formal["by_api"]
            if row["display_owner"] == "removed/Api"
            and row["display_member"] == "value"
            and row["display_descriptor"] == "()I"
        ]
        self.assertEqual(
            len(rows), 1,
            [
                (row["display_owner"], row["display_member"], row["display_descriptor"])
                for row in formal["by_api"]
                if str(row["display_owner"]).startswith("removed/")
            ],
        )
        self.assertEqual(rows[0]["base_dependency_coords"], ["generated:removed-library:1"])
        self.assertEqual(rows[0]["current_dependency_coords"], [])
        self.assertEqual(rows[0]["impact_conclusion"], "inconclusive")
        self.assertEqual(rows[0]["reachability_status"], "uncertain")
        removed_pairing = [
            row for row in pairings["pairings"]
            if row["logical_dependency_lineage"] == "generated:removed-library"
        ]
        self.assertEqual(len(removed_pairing), 1)
        self.assertEqual(removed_pairing[0]["status"], "base_only")


if __name__ == "__main__":
    unittest.main()
