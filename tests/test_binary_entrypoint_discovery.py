import json
import sys
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from binary_entrypoint_discovery import discover_binary_entrypoints  # noqa: E402


def annotation(descriptor, *, values=()):
    return {
        "descriptor": descriptor,
        "visible": True,
        "values": list(values),
    }


class FakeStore:
    def __init__(self, tables):
        self.tables = tables

    def rows(self, table, **_kwargs):
        return [dict(item) for item in self.tables.get(table, ())]


class FakeReconciliation:
    def __init__(self, providers, resources=()):
        self.provider_bindings = tuple(providers)
        self.resource_selections = tuple(resources)
        self.coverage_status = "complete"
        self.coverage_gaps = ()


class FakeProfile:
    identity = "profile-1"

    def __init__(self, entrypoints=None):
        self.payload = {
            "business_entrypoint_profile": entrypoints or {
                "discovery_mode": "binary_auto",
                "coverage_status": "complete",
                "methods": [],
            },
        }


class BinaryEntrypointDiscoveryTest(unittest.TestCase):
    def fixture(
        self,
        *,
        path_kind="classpath",
        class_annotations=(),
        method_annotations=(),
        interfaces=(),
        resources=(),
        method_name="tick",
        descriptor="()V",
        access_flags=1,
    ):
        class_name = "vendor/ScheduledConfig"
        variant = "variant-1"
        member = "member-1"
        store = FakeStore({
            "artifact_instances": [{
                "artifact_instance_identity": "artifact-1",
                "coord": "com.acme:scheduler:1.0",
                "runtime_path_kind": path_kind,
                "loader_realm_identity": "application-loader",
            }],
            "classes": [{
                "class_variant_identity": variant,
                "artifact_instance_identity": "artifact-1",
                "class_name": class_name,
                "fact_json": json.dumps({
                    "class_name": class_name,
                    "annotations": list(class_annotations),
                    "interfaces": list(interfaces),
                    "super_name": "java/lang/Object",
                }),
            }],
            "members": [{
                "member_identity": member,
                "class_variant_identity": variant,
                "artifact_instance_identity": "artifact-1",
                "class_name": class_name,
                "member_kind": "method",
                "member_name": method_name,
                "descriptor": descriptor,
                "access_flags": access_flags,
                "contract_json": json.dumps({
                    "name": method_name,
                    "descriptor": descriptor,
                    "access": access_flags,
                    "annotations": list(method_annotations),
                }),
            }],
        })
        runtime = FakeReconciliation(
            [{
                "initiating_loader_realm_identity": "application-loader",
                "class_name": class_name,
                "class_provider_status": "resolved",
                "selected_class_variant_identity": variant,
            }],
            resources,
        )
        return store, runtime, member

    def test_dependency_scheduled_method_is_exact_when_boot_import_activates_class(self):
        store, runtime, member = self.fixture(
            class_annotations=[annotation(
                "Lorg/springframework/boot/autoconfigure/AutoConfiguration;"
            )],
            method_annotations=[annotation(
                "Lorg/springframework/scheduling/annotation/Scheduled;"
            )],
            resources=[{
                "initiating_loader_realm_identity": "application-loader",
                "resource_name": (
                    "META-INF/spring/"
                    "org.springframework.boot.autoconfigure.AutoConfiguration.imports"
                ),
                "resource_selection_status": "resolved",
                "coverage_status": "complete",
                "selected_resources": [{
                    "resource_semantic_facts": [[
                        "ordered_entry", "vendor.ScheduledConfig"
                    ]],
                }],
            }],
        )

        result = discover_binary_entrypoints(store, FakeProfile({
            "discovery_mode": "binary_auto",
            "coverage_status": "complete",
            "methods": [],
            "activated_frameworks": ["spring_boot"],
        }), runtime)

        self.assertEqual(result.exact_member_identities, (member,))
        self.assertEqual(result.possible_member_identities, ())
        self.assertEqual(result.records[0]["entry_kind"], "spring_scheduled")
        self.assertEqual(
            result.records[0]["activation_reason"],
            "spring_boot_auto_configuration_import",
        )

    def test_boot_registration_without_business_boot_activation_is_only_possible(self):
        store, runtime, member = self.fixture(
            method_annotations=[annotation(
                "Lorg/springframework/scheduling/annotation/Scheduled;"
            )],
            resources=[{
                "initiating_loader_realm_identity": "application-loader",
                "resource_name": (
                    "META-INF/spring/"
                    "org.springframework.boot.autoconfigure.AutoConfiguration.imports"
                ),
                "resource_selection_status": "resolved",
                "coverage_status": "complete",
                "selected_resources": [{
                    "resource_semantic_facts": [[
                        "ordered_entry", "vendor.ScheduledConfig"
                    ]],
                }],
            }],
        )

        result = discover_binary_entrypoints(store, FakeProfile(), runtime)

        self.assertEqual(result.exact_member_identities, ())
        self.assertEqual(result.possible_member_identities, (member,))
        self.assertEqual(
            result.records[0]["activation_reason"],
            "dependency_framework_activation_unproven",
        )

    def test_dependency_spring_factories_listener_is_exact_when_boot_is_active(self):
        store, runtime, member = self.fixture(
            method_name="onApplicationEvent",
            interfaces=["org/springframework/context/ApplicationListener"],
            resources=[{
                "initiating_loader_realm_identity": "application-loader",
                "resource_name": "META-INF/spring.factories",
                "resource_selection_status": "resolved",
                "coverage_status": "complete",
                "selected_resources": [{
                    "resource_semantic_facts": [[
                        "property_entry:org.springframework.context.ApplicationListener",
                        "vendor.ScheduledConfig",
                    ]],
                }],
            }],
        )
        profile = FakeProfile({
            "discovery_mode": "binary_auto",
            "coverage_status": "complete",
            "methods": [],
            "activated_frameworks": ["spring_boot"],
        })

        result = discover_binary_entrypoints(store, profile, runtime)

        self.assertEqual(result.exact_member_identities, (member,))
        self.assertEqual(result.records[0]["entry_kind"], "spring_application_listener")
        self.assertEqual(
            result.records[0]["activation_reason"],
            "spring_factories_runtime_registration",
        )

    def test_dependency_scheduled_method_is_only_possible_without_activation_proof(self):
        store, runtime, member = self.fixture(
            method_annotations=[annotation(
                "Lorg/springframework/scheduling/annotation/Scheduled;"
            )],
        )

        result = discover_binary_entrypoints(store, FakeProfile(), runtime)

        self.assertEqual(result.exact_member_identities, ())
        self.assertEqual(result.possible_member_identities, (member,))
        self.assertEqual(
            result.records[0]["activation_reason"],
            "dependency_framework_activation_unproven",
        )

    def test_conditional_dependency_auto_configuration_is_not_promoted_to_exact(self):
        store, runtime, member = self.fixture(
            class_annotations=[
                annotation("Lorg/springframework/boot/autoconfigure/AutoConfiguration;"),
                annotation(
                    "Lorg/springframework/boot/autoconfigure/condition/ConditionalOnProperty;"
                ),
            ],
            method_annotations=[annotation(
                "Lorg/springframework/scheduling/annotation/Scheduled;"
            )],
            resources=[{
                "initiating_loader_realm_identity": "application-loader",
                "resource_name": (
                    "META-INF/spring/"
                    "org.springframework.boot.autoconfigure.AutoConfiguration.imports"
                ),
                "resource_selection_status": "resolved",
                "coverage_status": "complete",
                "selected_resources": [{
                    "resource_semantic_facts": [[
                        "ordered_entry", "vendor.ScheduledConfig"
                    ]],
                }],
            }],
        )

        result = discover_binary_entrypoints(store, FakeProfile(), runtime)

        self.assertEqual(result.exact_member_identities, ())
        self.assertEqual(result.possible_member_identities, (member,))
        self.assertEqual(
            result.records[0]["activation_reason"],
            "framework_condition_not_evaluated",
        )

    def test_runtime_annotation_entrypoint_matrix_is_discovered_from_bytecode(self):
        cases = {
            "Lorg/springframework/scheduling/annotation/Scheduled;": "spring_scheduled",
            "Lorg/springframework/context/event/EventListener;": "spring_event_listener",
            "Lorg/springframework/kafka/annotation/KafkaListener;": "spring_message_listener",
            "Lorg/springframework/amqp/rabbit/annotation/RabbitListener;": "spring_message_listener",
            "Lorg/springframework/jms/annotation/JmsListener;": "spring_message_listener",
            "Ljavax/annotation/PostConstruct;": "lifecycle_callback",
            "Lorg/springframework/web/bind/annotation/GetMapping;": "spring_web_endpoint",
        }
        for descriptor, expected_kind in cases.items():
            with self.subTest(descriptor=descriptor):
                store, runtime, member = self.fixture(
                    path_kind="business_classes",
                    method_annotations=[annotation(descriptor)],
                )

                result = discover_binary_entrypoints(store, FakeProfile(), runtime)

                self.assertEqual(result.exact_member_identities, (member,))
                self.assertEqual(
                    {item["entry_kind"] for item in result.records},
                    {expected_kind},
                )

    def test_jpa_lifecycle_annotation_remains_possible_without_entity_use_proof(self):
        store, runtime, member = self.fixture(
            path_kind="business_classes",
            method_annotations=[annotation("Ljakarta/persistence/PostLoad;")],
        )

        result = discover_binary_entrypoints(store, FakeProfile(), runtime)

        self.assertEqual(result.exact_member_identities, ())
        self.assertEqual(result.possible_member_identities, (member,))
        self.assertEqual(result.records[0]["entry_kind"], "jpa_lifecycle_callback")
        self.assertEqual(
            result.records[0]["activation_reason"],
            "entity_lifecycle_activation_unproven",
        )

    def test_business_main_requires_launcher_or_profile_activation_for_exact_root(self):
        store, runtime, member = self.fixture(
            path_kind="business_classes",
            method_name="main",
            descriptor="([Ljava/lang/String;)V",
            access_flags=9,
        )

        unproved = discover_binary_entrypoints(store, FakeProfile(), runtime)
        exact = discover_binary_entrypoints(store, FakeProfile({
            "discovery_mode": "binary_auto",
            "coverage_status": "complete",
            "main_class": "vendor.ScheduledConfig",
            "methods": [],
        }), runtime)

        self.assertEqual(unproved.possible_member_identities, (member,))
        self.assertEqual(
            unproved.records[0]["activation_reason"],
            "business_main_activation_unproven",
        )
        self.assertEqual(exact.exact_member_identities, (member,))

    def test_interface_callback_matrix_follows_inherited_interfaces(self):
        cases = {
            ("org/springframework/boot/ApplicationRunner", "run"): "spring_application_runner",
            ("org/springframework/boot/CommandLineRunner", "run"): "spring_command_line_runner",
            ("org/springframework/context/ApplicationListener", "onApplicationEvent"): "spring_application_listener",
            ("org/springframework/context/SmartLifecycle", "start"): "spring_lifecycle_callback",
            ("org/springframework/beans/factory/InitializingBean", "afterPropertiesSet"): "spring_lifecycle_callback",
            ("org/springframework/web/servlet/HandlerInterceptor", "preHandle"): "spring_web_interceptor",
            ("org/springframework/core/convert/converter/Converter", "convert"): "spring_conversion_callback",
            ("jakarta/servlet/Servlet", "service"): "servlet_endpoint",
            ("jakarta/servlet/Filter", "doFilter"): "servlet_filter",
            ("org/quartz/Job", "execute"): "quartz_job",
        }
        for (framework_interface, method_name), expected_kind in cases.items():
            with self.subTest(framework_interface=framework_interface):
                store, runtime, member = self.fixture(
                    path_kind="business_classes",
                    interfaces=["business/CustomCallback"],
                    method_name=method_name,
                )
                store.tables["classes"].append({
                    "class_variant_identity": "callback-interface-variant",
                    "artifact_instance_identity": "artifact-1",
                    "class_name": "business/CustomCallback",
                    "fact_json": json.dumps({
                        "class_name": "business/CustomCallback",
                        "annotations": [],
                        "interfaces": [framework_interface],
                        "super_name": "java/lang/Object",
                    }),
                })
                runtime.provider_bindings += ({
                    "initiating_loader_realm_identity": "application-loader",
                    "class_name": "business/CustomCallback",
                    "class_provider_status": "resolved",
                    "selected_class_variant_identity": "callback-interface-variant",
                },)

                result = discover_binary_entrypoints(store, FakeProfile(), runtime)

                self.assertEqual(result.exact_member_identities, (member,))
                self.assertEqual(result.records[0]["entry_kind"], expected_kind)

    def test_composed_runtime_annotation_is_resolved_from_annotation_class(self):
        store, runtime, member = self.fixture(
            path_kind="business_classes",
            method_annotations=[annotation("Lbusiness/EveryMinute;")],
        )
        store.tables["classes"].append({
            "class_variant_identity": "composed-annotation-variant",
            "artifact_instance_identity": "artifact-1",
            "class_name": "business/EveryMinute",
            "fact_json": json.dumps({
                "class_name": "business/EveryMinute",
                "annotations": [annotation(
                    "Lorg/springframework/scheduling/annotation/Scheduled;"
                )],
                "interfaces": ["java/lang/annotation/Annotation"],
                "super_name": "java/lang/Object",
            }),
        })
        runtime.provider_bindings += ({
            "initiating_loader_realm_identity": "application-loader",
            "class_name": "business/EveryMinute",
            "class_provider_status": "resolved",
            "selected_class_variant_identity": "composed-annotation-variant",
        },)

        result = discover_binary_entrypoints(store, FakeProfile(), runtime)

        self.assertEqual(result.exact_member_identities, (member,))
        self.assertEqual(result.records[0]["entry_kind"], "spring_scheduled")

    def test_declared_entrypoint_is_merged_with_automatic_discovery(self):
        store, runtime, member = self.fixture()
        profile = FakeProfile({
            "discovery_mode": "binary_auto",
            "coverage_status": "complete",
            "methods": [{
                "initiating_loader_realm_identity": "application-loader",
                "class_name": "vendor/ScheduledConfig",
                "member_name": "tick",
                "descriptor": "()V",
            }],
        })

        result = discover_binary_entrypoints(store, profile, runtime)

        self.assertEqual(result.exact_member_identities, (member,))
        self.assertEqual(result.records[0]["entry_kind"], "declared_runtime_entry")

    def test_same_entrypoint_keeps_evidence_for_each_loader_realm(self):
        store, runtime, member = self.fixture(
            path_kind="business_classes",
            method_annotations=[annotation(
                "Lorg/springframework/scheduling/annotation/Scheduled;"
            )],
        )
        runtime.provider_bindings += ({
            "initiating_loader_realm_identity": "plugin-loader",
            "class_name": "vendor/ScheduledConfig",
            "class_provider_status": "resolved",
            "selected_class_variant_identity": "variant-1",
        },)

        result = discover_binary_entrypoints(store, FakeProfile(), runtime)

        self.assertEqual(result.exact_member_identities, (member,))
        self.assertEqual(
            {
                item["initiating_loader_realm_identity"]
                for item in result.records
            },
            {"application-loader", "plugin-loader"},
        )


if __name__ == "__main__":
    unittest.main()
