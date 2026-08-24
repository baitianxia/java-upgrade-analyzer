import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import binary_entrypoint_discovery as entrypoints  # noqa: E402


def annotation(descriptor, values=(), *, visible=True):
    return {
        "descriptor": descriptor,
        "visible": visible,
        "values": list(values),
    }


def profile(**payload):
    base = {
        "active_profile_identities": [],
        "resolved_configuration_properties": {},
        "runtime_configuration_coverage_status": "complete",
        "business_entrypoint_profile": {
            "coverage_status": "complete",
            "methods": [],
        },
    }
    base.update(payload)
    return SimpleNamespace(identity="profile-boundary", payload=base)


class RowStore:
    def __init__(self, **tables):
        self.tables = tables

    def rows(self, table, **_kwargs):
        return [dict(row) for row in self.tables.get(table, ())]


class Reconciliation:
    def __init__(self, providers=(), resources=(), *, identity="reconciliation"):
        self.provider_bindings = tuple(providers)
        self.resource_selections = tuple(resources)
        self.identity = identity
        self.definition_statuses = {}
        self.class_load_statuses = {}

    @property
    def class_definitions(self):
        result = []
        for provider in self.provider_bindings:
            realm = provider.get("initiating_loader_realm_identity", "")
            name = provider.get("class_name", "")
            key = (realm, name)
            definition = self.definition_statuses.get(key, "definition_ready")
            result.append({
                "initiating_loader_realm_identity": realm,
                "class_name": name,
                "class_definition_status": definition,
                "class_load_status": self.class_load_statuses.get(
                    key, "ready" if definition == "definition_ready" else "failed",
                ),
            })
        return tuple(result)


class SummaryCursor:
    def __init__(self, present):
        self.present = present

    def fetchone(self):
        return (1,) if self.present else None


class SummaryConnection:
    def __init__(self, adapter_present=False):
        self.adapter_present = adapter_present

    def execute(self, _sql):
        return SummaryCursor(self.adapter_present)


class SummaryStore(RowStore):
    def __init__(self, summary, *, adapter_present=False, **tables):
        super().__init__(**tables)
        self.summary = summary
        self.connection = SummaryConnection(adapter_present)

    def runtime_trigger_summary(self):
        return dict(self.summary)


def class_row(variant, artifact, class_name, fact):
    return {
        "class_variant_identity": variant,
        "artifact_instance_identity": artifact,
        "class_name": class_name,
        "fact_json": json.dumps({"class_name": class_name, **fact}),
    }


def member_row(
    identity, variant, artifact, class_name, name, descriptor="()V",
    *, annotations=(), access=1,
):
    return {
        "member_identity": identity,
        "class_variant_identity": variant,
        "artifact_instance_identity": artifact,
        "class_name": class_name,
        "member_kind": "method",
        "member_name": name,
        "descriptor": descriptor,
        "access_flags": access,
        "contract_json": json.dumps({
            "name": name,
            "descriptor": descriptor,
            "access": access,
            "annotations": list(annotations),
        }),
    }


def provider(realm, class_name, variant, *, status="resolved"):
    return {
        "initiating_loader_realm_identity": realm,
        "class_name": class_name,
        "class_provider_status": status,
        "selected_class_variant_identity": variant,
    }


class BinaryEntrypointDiscoveryBoundaryTest(unittest.TestCase):
    def test_pure_payload_descriptor_annotation_and_boolean_matrix(self):
        self.assertEqual(entrypoints._loads(""), {})
        self.assertEqual(entrypoints._loads('{"value": 3}'), {"value": 3})

        payload = {
            "annotations": [
                "invalid",
                annotation("Lhidden;", visible=False),
                annotation(""),
                annotation("Lvisible;"),
                {"descriptor": "Limplicit;"},
            ]
        }
        self.assertEqual(
            entrypoints._annotation_descriptors(payload),
            {"Lvisible;", "Limplicit;"},
        )
        self.assertEqual(entrypoints._annotations({}), ())

        self.assertEqual(entrypoints._descriptor_class_name(None), "")
        self.assertEqual(entrypoints._descriptor_class_name("I"), "")
        self.assertEqual(entrypoints._descriptor_class_name("Ldemo/Type"), "")
        self.assertEqual(
            entrypoints._descriptor_class_name("Ldemo/Type;"), "demo/Type",
        )
        for descriptor in (None, "I", "(", "([", "(Ldemo/Type"):
            self.assertIsNone(entrypoints._descriptor_parameters(descriptor))
        self.assertEqual(entrypoints._descriptor_parameters("()V"), ())
        self.assertEqual(
            entrypoints._descriptor_parameters(
                "([I[[Ljava/lang/String;Z)Ldemo/Return;"
            ),
            ("[I", "[[Ljava/lang/String;", "Z"),
        )

        nested = {
            "direct": {"kind": "type", "descriptor": "Ldemo/A;"},
            "empty": {"kind": "type", "descriptor": ""},
            "wrong": {"kind": "text", "descriptor": "Ldemo/Wrong;"},
            "items": [
                {"nested": {"kind": "type", "descriptor": "Ldemo/B;"}},
                7,
            ],
        }
        self.assertEqual(
            entrypoints._type_descriptors(nested), {"Ldemo/A;", "Ldemo/B;"},
        )
        self.assertEqual(entrypoints._type_descriptors("scalar"), set())
        self.assertEqual(
            entrypoints._string_values({"a": ["one", ("two", 3)]}),
            {"one", "two"},
        )
        self.assertEqual(entrypoints._string_values(3), set())

        decoded = entrypoints._annotation_attributes({
            "values": [
                "invalid", ("short",), ("", "ignored"),
                ("names", "array", ["a", "b"]),
                ("mode", "enum", "LMode;", "ON"),
                ("value", "literal"),
                ("value", "second"),
                ("short_array", "array"),
                ("short_enum", "enum", "LMode;"),
            ],
        })
        self.assertEqual(decoded["names"], ("a", "b"))
        self.assertEqual(decoded["mode"], ("ON",))
        self.assertEqual(decoded["value"], ("literal", "second"))
        self.assertEqual(decoded["short_array"], ("array",))
        self.assertEqual(decoded["short_enum"], ("enum",))

        checks = (
            (True, False, True), (False, True, False),
            (1, False, True), (0, True, False),
            (" YES ", False, True), ("off", True, False),
            ("unknown", True, True), (None, True, False),
        )
        for value, default, expected in checks:
            self.assertIs(entrypoints._as_bool(value, default), expected)

    def test_condition_status_complete_boundary_matrix(self):
        realm = "realm"
        selected = {
            (realm, "demo/Present"): ({}, {}),
        }

        def status(item, **overrides):
            return entrypoints._condition_status(
                realm, (item,), profile(**overrides), selected,
            )[0]

        profile_annotation = lambda *values: annotation(
            "Lorg/springframework/context/annotation/Profile;",
            (("value", "array", list(values)),),
        )
        self.assertEqual(status(profile_annotation()), "active")
        self.assertEqual(
            status(
                profile_annotation("dev", ""),
                active_profile_identities=["", " dev "],
            ),
            "active",
        )
        self.assertEqual(status(profile_annotation("prod")), "inactive")

        on_class = "Lx/ConditionalOnClass;"
        self.assertEqual(status(annotation(on_class)), "unproven")
        self.assertEqual(status(annotation(on_class, (
            ("value", "type", {"kind": "type", "descriptor": "Ldemo/Present;"}),
        ))), "active")
        self.assertEqual(status(annotation(on_class, (
            ("name", "demo.Missing"),
        ))), "inactive")
        self.assertEqual(status(annotation(on_class, (
            ("value", "type", {"kind": "type", "descriptor": "I"}),
        ))), "unproven")

        on_missing = "Lx/ConditionalOnMissingClass;"
        self.assertEqual(status(annotation(on_missing)), "unproven")
        self.assertEqual(status(annotation(on_missing, (
            ("name", "PresentWithoutPackage"),
        ))), "unproven")
        self.assertEqual(status(annotation(on_missing, (
            ("name", "demo.Missing"),
        ))), "active")
        self.assertEqual(status(annotation(on_missing, (
            ("name", "demo.Present"),
        ))), "inactive")

        on_property = "Lx/ConditionalOnProperty;"
        self.assertEqual(status(annotation(on_property)), "unproven")
        property_annotation = annotation(on_property, (
            ("prefix", " feature "),
            ("name", "array", ["enabled", "", "mode"]),
            ("havingValue", "on"),
        ))
        self.assertEqual(status(
            property_annotation,
            resolved_configuration_properties={
                "feature.enabled": "on", "feature.mode": "off",
            },
        ), "inactive")
        self.assertEqual(status(
            property_annotation,
            resolved_configuration_properties={"feature.enabled": "on"},
        ), "inactive")
        self.assertEqual(status(
            property_annotation,
            resolved_configuration_properties={"feature.enabled": "on"},
            runtime_configuration_coverage_status="partial",
        ), "unproven")
        match_missing = annotation(on_property, (
            ("prefix", "feature."), ("value", "enabled"),
            ("matchIfMissing", True),
        ))
        self.assertEqual(status(match_missing), "active")
        no_having = annotation(on_property, (("name", "enabled"),))
        self.assertEqual(status(
            no_having,
            resolved_configuration_properties={"enabled": "false"},
        ), "inactive")
        self.assertEqual(status(
            no_having,
            resolved_configuration_properties={"enabled": " yes "},
        ), "active")
        self.assertEqual(status(annotation(
            "Lorg/springframework/context/annotation/Conditional;"
        )), "unproven")
        self.assertEqual(status(annotation("Ldemo/Unrelated;")), "active")
        self.assertEqual(status({}), "active")

        combined, evidence = entrypoints._condition_status(
            realm,
            (profile_annotation("prod"), annotation(on_class)),
            profile(),
            selected,
        )
        self.assertEqual(combined, "inactive")
        self.assertEqual(len(evidence), 1)

    def test_annotation_hierarchy_resource_and_result_boundaries(self):
        realm = "realm"
        selected = {
            (realm, "meta/One"): ({}, {
                "annotations": [annotation("Lmeta/Two;")],
            }),
            (realm, "meta/Two"): ({}, {
                "annotations": [
                    annotation("Lmeta/One;"), annotation("Ltarget/Marker;"),
                ],
            }),
            (realm, "demo/Child"): ({}, {
                "super_name": "demo/Base", "interfaces": ["demo/Api", ""],
            }),
            (realm, "demo/Base"): ({}, {
                "super_name": "java/lang/Object", "interfaces": ["demo/Api"],
            }),
            (realm, "demo/Api"): ({}, {
                "super_name": "java/lang/Object", "interfaces": ["demo/Child"],
            }),
            (realm, "meta/Imported"): ({}, {
                "annotations": [annotation(
                    "Lorg/springframework/context/annotation/Import;",
                    (("value", "type", {
                        "kind": "type", "descriptor": "Ldemo/Config;",
                    }),),
                )],
            }),
        }
        closure = entrypoints._annotation_closure(
            realm, {"Lmeta/One;", "Lmissing/Annotation;"}, selected,
        )
        self.assertEqual(
            closure,
            {"Lmeta/One;", "Lmeta/Two;", "Ltarget/Marker;", "Lmissing/Annotation;"},
        )
        self.assertTrue(entrypoints._is_conditional({
            "Lorg/springframework/context/annotation/Conditional;"
        }))
        self.assertFalse(entrypoints._is_conditional({"Ldemo/Other;"}))
        self.assertEqual(
            entrypoints._hierarchy_types(realm, "demo/Child", selected),
            {"demo/Base", "demo/Api", "demo/Child"},
        )
        self.assertEqual(
            entrypoints._hierarchy_types(realm, "demo/Missing", selected), set(),
        )

        imported = entrypoints._annotation_imports(
            realm,
            (
                annotation(""), annotation("Lmissing/Meta;"),
                annotation("Lmeta/Imported;"),
                annotation("Lmeta/Imported;"),
                annotation(
                    "Lorg/springframework/context/annotation/Import;"
                ),
                annotation(
                    "Lorg/springframework/context/annotation/Import;",
                    (("value", "array", [
                        {"kind": "type", "descriptor": "I"},
                        {"kind": "type", "descriptor": "Ldemo/Direct;"},
                    ]),),
                ),
            ),
            selected,
        )
        self.assertEqual(imported, {"demo/Config", "demo/Direct"})

        self.assertTrue(entrypoints._is_business_artifact({
            "runtime_path_kind": "BUSINESS_CLASSES",
        }))
        self.assertTrue(entrypoints._is_business_artifact({
            "coord": " Business:Application ",
        }))
        self.assertFalse(entrypoints._is_business_artifact({
            "runtime_path_kind": "classpath", "coord": "vendor:lib:1",
        }))

        resources = [
            {"resource_selection_status": "missing"},
            {
                "resource_selection_status": "resolved",
                "resource_name": "empty",
            },
            {
                "resource_selection_status": "resolved",
                "resource_name": next(iter(entrypoints.AUTO_CONFIGURATION_RESOURCES)),
                "selected_resources": [{
                    "resource_semantic_facts": [("other", "demo.Ignored")],
                }],
            },
            {
                "resource_selection_status": "resolved",
                "resource_name": "ignored",
                "selected_resources": [{"resource_semantic_facts": [
                    ("", "demo.EmptyKey"),
                    ("ordered_entry", "demo.Wrong"),
                    ("property_entry:other", "demo.Wrong"),
                    ("property_entry:org.springframework.boot.autoconfigure.EnableAutoConfiguration", ""),
                    ("property_entry:org.springframework.boot.autoconfigure.EnableAutoConfiguration", "demo.Legacy"),
                ]}],
            },
            {
                "resource_selection_status": "resolved",
                "resource_name": next(iter(entrypoints.AUTO_CONFIGURATION_RESOURCES)),
                "selected_resources": [{"resource_semantic_facts": [
                    ("ordered_entry", "demo.Modern"),
                ]}],
            },
            {
                "resource_selection_status": "resolved",
                "resource_name": "META-INF/spring.factories",
                "selected_resources": [{"resource_semantic_facts": [
                    ("", "demo.EmptyKey"),
                    ("ordered_entry", "ignored"),
                    ("property_entry:unknown.Callback", "demo.Unknown"),
                    ("property_entry:org.springframework.context.ApplicationListener", ""),
                    ("property_entry:org.springframework.context.ApplicationListener", "demo.Listener"),
                ]}],
            },
            {
                "resource_selection_status": "resolved",
                "resource_name": "META-INF/spring.factories",
            },
            {
                "resource_selection_status": "resolved",
                "resource_name": "META-INF/spring.factories",
                "selected_resources": [{}],
            },
        ]
        reconciliation = SimpleNamespace(resource_selections=resources)
        self.assertEqual(
            entrypoints._selected_auto_configuration_classes(reconciliation),
            {"demo/Legacy", "demo/Modern"},
        )
        self.assertEqual(
            entrypoints._selected_spring_factories_callbacks(reconciliation),
            {"demo/Listener": {(
                "onApplicationEvent", "spring_application_listener",
            )}},
        )

        result = entrypoints.BinaryEntrypointDiscoveryResult(
            exact_member_identities=("exact",),
            possible_member_identities=("possible",),
            records=({"entry_kind": "test"},),
            coverage_status="partial",
            coverage_gaps=("gap",),
            identity="identity",
        )
        payload = result.as_payload()
        self.assertEqual(payload["exact_entrypoint_count"], 1)
        self.assertEqual(payload["possible_entrypoint_count"], 1)
        self.assertEqual(payload["records"], [{"entry_kind": "test"}])

    def test_spring_boot_activation_call_and_profile_matrix(self):
        artifacts = {
            "business": {"runtime_path_kind": "business"},
            "library": {"runtime_path_kind": "classpath"},
        }
        self.assertEqual(entrypoints._spring_boot_activation_status(
            RowStore(),
            profile(business_entrypoint_profile={
                "activated_frameworks": ["", "SPRING_BOOT"],
            }), artifacts, set(), set(),
        )[0], "exact")
        self.assertEqual(entrypoints._spring_boot_activation_status(
            RowStore(), profile(container_and_launcher_kind="Spring-Boot"),
            artifacts, set(), set(),
        )[0], "exact")

        members = [
            {
                "member_identity": "missing-artifact", "class_variant_identity": "v",
                "artifact_instance_identity": "missing", "class_name": "biz/Missing",
                "member_name": "run", "descriptor": "()V",
            },
            {
                "member_identity": "library", "class_variant_identity": "v",
                "artifact_instance_identity": "library", "class_name": "lib/Entry",
                "member_name": "run", "descriptor": "()V",
            },
            {
                "member_identity": "other", "class_variant_identity": "v",
                "artifact_instance_identity": "business", "class_name": "biz/Other",
                "member_name": "run", "descriptor": "()V",
            },
            {
                "member_identity": "declared", "class_variant_identity": "v",
                "artifact_instance_identity": "business", "class_name": "biz/Declared",
                "member_name": "boot", "descriptor": "()V",
            },
            {
                "member_identity": "main", "class_variant_identity": "v",
                "artifact_instance_identity": "business", "class_name": "biz/Main",
                "member_name": "main", "descriptor": "([Ljava/lang/String;)V",
            },
            {
                "member_identity": "blank", "class_variant_identity": "v",
                "artifact_instance_identity": "business",
            },
        ]
        edges = [
            {"edge_kind": "field"},
            {"edge_kind": "method", "symbolic_owner": "other"},
            {
                "edge_kind": "method",
                "symbolic_owner": "org/springframework/boot/SpringApplication",
                "symbolic_name": "other",
            },
            *({
                "edge_kind": "method",
                "symbolic_owner": "org/springframework/boot/SpringApplication",
                "symbolic_name": "run",
                "caller_member_identity": member_id,
                "direct_edge_identity": "edge-" + member_id,
            } for member_id in (
                "unknown", "missing-artifact", "library", "other", "declared", "main", "blank",
            )),
        ]
        edges[-1].pop("direct_edge_identity")
        store = RowStore(members=members, direct_edges=edges)
        runtime = profile(business_entrypoint_profile={
            "methods": [
                "invalid",
                {
                    "class_name": "biz.Declared", "member_name": "boot",
                    "descriptor": "()V",
                },
                {},
            ],
        })
        status, evidence = entrypoints._spring_boot_activation_status(
            store, runtime, artifacts, {"v"}, {"biz/Main"},
        )
        self.assertEqual(status, "exact")
        self.assertEqual(
            {item["caller_member_name"] for item in evidence}, {"", "boot", "main"},
        )
        empty_status, empty_evidence = entrypoints._spring_boot_activation_status(
            RowStore(members=members, direct_edges=edges),
            profile(), artifacts, set(), set(),
        )
        self.assertEqual((empty_status, empty_evidence), ("unproven", ()))

    def test_runtime_summary_fast_path_signal_matrix(self):
        empty_summary = {
            "has_runtime_annotations": False,
            "has_main_method": False,
            "hierarchy_types": [],
        }

        def discover(
            *, summary=None, business=None, resources=(), launcher="",
            adapter=False, declared_gaps=None,
        ):
            payload = {
                "business_entrypoint_profile": business if business is not None else {
                    "coverage_status": "complete", "methods": [],
                },
                "container_and_launcher_kind": launcher,
            }
            if declared_gaps is not None:
                payload["entrypoint_discovery_coverage_gaps"] = declared_gaps
            return entrypoints.discover_binary_entrypoints(
                SummaryStore(
                    dict(empty_summary if summary is None else summary),
                    adapter_present=adapter,
                ),
                SimpleNamespace(identity="fast-profile", payload=payload),
                Reconciliation(resources=resources, identity=""),
            )

        fast = discover()
        self.assertEqual(fast.coverage_status, "complete")
        self.assertEqual(fast.records, ())
        truthy_identity = entrypoints.discover_binary_entrypoints(
            SummaryStore(empty_summary),
            SimpleNamespace(identity="fast-profile", payload={
                "business_entrypoint_profile": {
                    "coverage_status": "complete", "methods": [],
                },
            }),
            Reconciliation(identity="fast-reconciliation"),
        )
        self.assertEqual(truthy_identity.records, ())
        signals = [
            {"summary": {**empty_summary, "has_runtime_annotations": True}},
            {"summary": {**empty_summary, "has_main_method": True}},
            {"summary": {
                **empty_summary,
                "hierarchy_types": ["org/springframework/boot/ApplicationRunner"],
            }},
            {"business": {"coverage_status": "complete", "methods": [{}]}},
            {"resources": ({"resource_name": "config/runtime.xml"},)},
            {"resources": ({"resource_name": "META-INF/spring.factories"},)},
            {"resources": ({}, {"resource_name": "ordinary.txt"})},
            {"launcher": "java-jar"},
            {"adapter": True},
            {"declared_gaps": ["keeps-full-discovery"]},
            {"declared_gaps": "invalid"},
        ]
        for kwargs in signals:
            result = discover(**kwargs)
            self.assertIsInstance(
                result, entrypoints.BinaryEntrypointDiscoveryResult,
            )
        missing_profile = entrypoints.discover_binary_entrypoints(
            SummaryStore(empty_summary),
            SimpleNamespace(identity="missing-profile", payload={}),
            SimpleNamespace(resource_selections=()),
        )
        self.assertEqual(missing_profile.records, ())

    def test_full_discovery_adversarial_activation_adapter_and_xml_matrix(self):
        realm = "application-loader"
        second_realm = "child-loader"
        business_artifact = {
            "artifact_instance_identity": "business-artifact",
            "coord": "business:application",
            "runtime_path_kind": "business_classes",
        }
        library_artifact = {
            "artifact_instance_identity": "library-artifact",
            "coord": "vendor:framework:1",
            "runtime_path_kind": "classpath",
        }
        classes = []
        members = [{
            "member_identity": "ignored-field",
            "class_variant_identity": "v-main",
            "member_kind": "field",
        }]
        providers = [
            provider(realm, "ignored/Unresolved", "v-unresolved", status="missing"),
            provider(realm, "ignored/MissingVariant", "v-does-not-exist"),
            provider(realm, "ignored/FailedDefinition", "v-failed"),
            provider("", "", ""),
            provider(realm, "ignored/BlankVariant", None),
            provider(realm, "ignored/NoFact", "v-no-fact"),
        ]
        classes.extend((
            {
                "class_variant_identity": "",
                "artifact_instance_identity": "missing-artifact",
                "class_name": "",
                "fact_json": "{}",
            },
            {
                "class_variant_identity": "v-no-fact",
                "artifact_instance_identity": "missing-artifact",
                "class_name": "ignored/NoFact",
            },
        ))

        def add_class(
            variant, class_name, *, artifact="library-artifact",
            annotations=(), interfaces=(), super_name="java/lang/Object",
            class_access=0, methods=(), realm_id=realm,
        ):
            classes.append(class_row(variant, artifact, class_name, {
                "annotations": list(annotations),
                "interfaces": list(interfaces),
                "super_name": super_name,
                "class_access": class_access,
                "methods": list(methods),
            }))
            providers.append(provider(realm_id, class_name, variant))

        scheduled = annotation(
            "Lorg/springframework/scheduling/annotation/Scheduled;"
        )
        post_load = annotation("Ljakarta/persistence/PostLoad;")
        component = annotation("Lorg/springframework/stereotype/Component;")
        adapter_owner = (
            "org/springframework/amqp/rabbit/listener/adapter/"
            "MessageListenerAdapter"
        )

        adapter_methods = []
        adapter_members = (
            ("factory", "(Lbiz/Receiver;)Ljava/lang/Object;", "receiveMessage"),
            ("duplicateFactory", "(Lbiz/Receiver;)V", "receiveMessage"),
            ("zeroFactory", "()V", "receiveMessage"),
            ("ambiguousFactory", "(Lbiz/AmbiguousReceiver;)V", "receiveMessage"),
            ("missingReceiverFactory", "(Lbiz/MissingReceiver;)V", "receiveMessage"),
            ("noCallbackFactory", "(Lbiz/NoCallback;)V", "missing"),
        )
        for index, (name, descriptor, callback) in enumerate(adapter_members):
            instructions = [
                None,
                ("method",),
                ("method", 0, 0, "other/Owner", "<init>", "()V", 0),
                ("method", 0, 0, adapter_owner, "other", "()V", 0),
                ("method", 0, 0, adapter_owner, "<init>", "()V", 0),
                ("ldc", 0, 7),
                ("ldc", 0, callback),
                (
                    "method", 0, 0, adapter_owner, "<init>",
                    "(Ljava/lang/Object;Ljava/lang/String;)V", 0,
                ),
            ]
            adapter_methods.append({
                "contract": {"name": name, "descriptor": descriptor},
                "instructions": instructions,
            })
            members.append(member_row(
                "factory-" + str(index), "v-main", "business-artifact",
                "biz/Main", name, descriptor,
            ))
        adapter_methods.extend((
            {"contract": {}, "instructions": []},
            {
                "contract": {"name": "literalFree", "descriptor": "(I)V"},
                "instructions": [(
                    "method", 0, 0, adapter_owner, "<init>",
                    "(Ljava/lang/Object;Ljava/lang/String;)V", 0,
                )],
            },
        ))
        members.append(member_row(
            "literal-free", "v-main", "business-artifact", "biz/Main",
            "literalFree", "(I)V",
        ))
        add_class(
            "v-main", "biz/Main", artifact="business-artifact",
            annotations=(
                {},
                annotation(
                    "Lorg/springframework/context/annotation/ComponentScan;",
                    (("value", "array", ["vendor", "ignored.class", ""]),),
                ),
                annotation(
                    "Lorg/springframework/context/annotation/ComponentScan;"
                ),
                annotation(
                    "Lorg/springframework/context/annotation/ImportResource;",
                    (("value", "array", [
                        "classpath:config/runtime.xml", "ignored.txt",
                    ]),),
                ),
                annotation(
                    "Lorg/springframework/context/annotation/ImportResource;"
                ),
                annotation(
                    "Lorg/springframework/context/annotation/Import;",
                    (("value", "type", {
                        "kind": "type", "descriptor": "Limported/Config;",
                    }),),
                ),
                annotation("Ljakarta/persistence/Entity;"),
            ),
            methods=adapter_methods,
        )
        members.extend((
            member_row(
                "main", "v-main", "business-artifact", "biz/Main", "main",
                "([Ljava/lang/String;)V", access=entrypoints.ACC_PUBLIC | entrypoints.ACC_STATIC,
            ),
            member_row(
                "business-scheduled", "v-main", "business-artifact", "biz/Main",
                "tick", annotations=(scheduled,),
            ),
            member_row(
                "main-wrong-descriptor", "v-main", "business-artifact",
                "biz/Main", "main", "()V",
            ),
            member_row(
                "main-private", "v-main", "business-artifact", "biz/Main",
                "main", "([Ljava/lang/String;)V", access=0,
            ),
            member_row(
                "main-public-not-static", "v-main", "business-artifact",
                "biz/Main", "main", "([Ljava/lang/String;)V",
                access=entrypoints.ACC_PUBLIC,
            ),
        ))

        add_class("v-receiver", "biz/Receiver", artifact="business-artifact")
        members.append(member_row(
            "receiver", "v-receiver", "business-artifact", "biz/Receiver",
            "receiveMessage",
        ))
        add_class(
            "v-ambiguous", "biz/AmbiguousReceiver",
            artifact="business-artifact",
        )
        members.extend((
            member_row(
                "ambiguous-one", "v-ambiguous", "business-artifact",
                "biz/AmbiguousReceiver", "receiveMessage", "()V",
            ),
            member_row(
                "ambiguous-two", "v-ambiguous", "business-artifact",
                "biz/AmbiguousReceiver", "receiveMessage", "(Ljava/lang/String;)V",
            ),
        ))
        add_class("v-no-callback", "biz/NoCallback", artifact="business-artifact")
        members.append(member_row(
            "ordinary", "v-no-callback", "business-artifact", "biz/NoCallback",
            "ordinary",
        ))
        inactive_factory_instructions = [
            ("ldc", 0, "receiveMessage"),
            (
                "method", 0, 0, adapter_owner, "<init>",
                "(Ljava/lang/Object;Ljava/lang/String;)V", 0,
            ),
        ]
        add_class(
            "v-inactive-factory", "outside/InactiveFactory",
            methods=({
                "contract": {
                    "name": "factory", "descriptor": "(Lbiz/Receiver;)V",
                },
                "instructions": inactive_factory_instructions,
            },),
        )
        members.append(member_row(
            "inactive-factory", "v-inactive-factory", "library-artifact",
            "outside/InactiveFactory", "factory", "(Lbiz/Receiver;)V",
        ))

        def scheduled_class(
            suffix, class_name, *, annotations=(), method_annotations=(scheduled,),
            class_access=0, access=1, interfaces=(), artifact="library-artifact",
        ):
            variant = "v-" + suffix
            add_class(
                variant, class_name, artifact=artifact,
                annotations=annotations, class_access=class_access,
                interfaces=interfaces,
            )
            members.append(member_row(
                "m-" + suffix, variant, artifact, class_name, "tick",
                annotations=method_annotations, access=access,
            ))

        scheduled_class("component", "vendor/Component", annotations=(component,))
        scheduled_class("component-exact-prefix", "vendor", annotations=(component,))
        scheduled_class(
            "component-outside", "outside/Component", annotations=(component,),
        )
        scheduled_class("imported", "imported/Config")
        scheduled_class("auto", "auto/Configuration")
        scheduled_class("declared", "vendor/Declared")
        scheduled_class("unactivated", "outside/Unactivated")
        scheduled_class(
            "conditional", "vendor/Conditional",
            annotations=(annotation(
                "Lorg/springframework/context/annotation/Conditional;"
            ),),
        )
        scheduled_class(
            "inactive", "vendor/Inactive",
            annotations=(annotation(
                "Lorg/springframework/context/annotation/Profile;",
                (("value", "prod"),),
            ),),
        )
        scheduled_class(
            "abstract", "vendor/Abstract", class_access=entrypoints.ACC_ABSTRACT,
        )
        scheduled_class(
            "abstract-member", "vendor/AbstractMember",
            access=entrypoints.ACC_ABSTRACT,
        )
        scheduled_class(
            "minimal", "vendor/Minimal", artifact="missing-artifact",
        )
        members.extend((
            {
                "member_identity": "",
                "class_variant_identity": "v-minimal",
                "artifact_instance_identity": "",
                "member_kind": "method",
                "member_name": "emptyIdentity",
                "descriptor": "",
                "access_flags": 1,
                "contract_json": json.dumps({
                    "annotations": [scheduled],
                }),
            },
            {
                "member_identity": "minimal-fields",
                "class_variant_identity": "v-minimal",
                "member_kind": "method",
                "access_flags": 1,
                "contract_json": json.dumps({
                    "annotations": [scheduled],
                }),
            },
        ))

        add_class(
            "v-trigger", "vendor/Triggered",
            annotations=(annotation(
                "Lorg/apache/rocketmq/spring/annotation/RocketMQMessageListener;"
            ),),
        )
        members.extend((
            member_row(
                "trigger-match", "v-trigger", "library-artifact",
                "vendor/Triggered", "onMessage",
            ),
            member_row(
                "trigger-other", "v-trigger", "library-artifact",
                "vendor/Triggered", "other",
            ),
        ))
        add_class(
            "v-runner", "vendor/Runner",
            interfaces=("org/springframework/boot/ApplicationRunner",),
        )
        members.extend((
            member_row(
                "runner", "v-runner", "library-artifact", "vendor/Runner", "run",
            ),
            member_row(
                "runner-other", "v-runner", "library-artifact",
                "vendor/Runner", "other",
            ),
            {
                "member_identity": "runner-no-contract",
                "class_variant_identity": "v-runner",
                "artifact_instance_identity": "library-artifact",
                "class_name": "vendor/Runner",
                "member_kind": "method",
                "member_name": "run",
            },
        ))
        add_class("v-listener", "factory/Listener")
        members.extend((
            member_row(
                "listener", "v-listener", "library-artifact",
                "factory/Listener", "onApplicationEvent",
            ),
            member_row(
                "listener-other", "v-listener", "library-artifact",
                "factory/Listener", "other",
            ),
        ))

        add_class(
            "v-entity", "vendor/Entity",
            annotations=(annotation("Ljakarta/persistence/Entity;"),),
        )
        members.append(member_row(
            "entity-load", "v-entity", "library-artifact", "vendor/Entity",
            "afterLoad", annotations=(post_load,),
        ))
        add_class("v-entity-resource", "vendor/ResourceEntity")
        members.append(member_row(
            "resource-load", "v-entity-resource", "library-artifact",
            "vendor/ResourceEntity", "afterLoad", annotations=(post_load,),
        ))

        for variant, class_name, method_names in (
            ("v-plugin", "vendor/Plugin", ("intercept",)),
            ("v-handler", "vendor/Handler", ("setParameter", "getResult")),
            ("v-no-plugin", "vendor/NoPlugin", ("ordinary",)),
            ("v-xml", "vendor/XmlTarget", ("run", "run", "init")),
            ("v-other-xml", "vendor/OtherXml", ("run",)),
        ):
            add_class(variant, class_name)
            for index, method_name in enumerate(method_names):
                members.append(member_row(
                    f"{variant}-{method_name}-{index}", variant,
                    "library-artifact", class_name, method_name,
                    "()V" if index == 0 else "(I)V",
                ))

        add_class("v-failed", "ignored/FailedDefinition")
        add_class("v-library-main", "outside/LibraryMain")
        members.extend((
            member_row(
                "library-main-private", "v-library-main", "library-artifact",
                "outside/LibraryMain", "main", "([Ljava/lang/String;)V",
                access=0,
            ),
            member_row(
                "library-main-public", "v-library-main", "library-artifact",
                "outside/LibraryMain", "main", "([Ljava/lang/String;)V",
                access=entrypoints.ACC_PUBLIC | entrypoints.ACC_STATIC,
            ),
        ))
        providers.append(provider(
            second_realm, "vendor/XmlTarget", "v-xml",
        ))
        providers.append(provider(
            second_realm, "vendor/Component", "v-component",
        ))

        auto_resource = next(iter(entrypoints.AUTO_CONFIGURATION_RESOURCES))
        xml_facts = [
            ("xml_parse_gap", "blocked-doctype"),
            ("mybatis_plugin_registration", "alias|missing.Provider"),
            ("mybatis_plugin_registration", "alias|vendor.NoPlugin"),
            ("mybatis_plugin_registration", "alias|vendor.Plugin"),
            ("mybatis_type_handler_registration", "vendor.Handler"),
            ("mybatis_statement_type_handler", "vendor.Handler"),
            ("unknown_fact", "ignored"),
            ("spring_init_method", "invalid"),
            ("spring_init_method", "bean||run"),
            ("spring_init_method", "bean|vendor.XmlTarget|"),
            ("spring_init_method", "bean|missing.Xml|run"),
            ("spring_init_method", "bean|vendor.NoPlugin|run"),
            ("spring_scheduled_method", "bean|vendor.XmlTarget|run"),
            ("spring_init_method", "bean|vendor.XmlTarget|init"),
        ]
        resources = [
            {},
            {"resource_selection_status": "missing", "resource_name": "missing.xml"},
            {
                "resource_selection_status": "resolved",
                "resource_name": auto_resource,
                "selected_resources": [{"resource_semantic_facts": [
                    ("ordered_entry", "auto.Configuration"),
                ]}],
            },
            {
                "resource_selection_status": "resolved",
                "resource_name": "META-INF/spring.factories",
                "selected_resources": [{"resource_semantic_facts": [
                    (
                        "property_entry:org.springframework.context.ApplicationListener",
                        "factory.Listener",
                    ),
                ]}],
            },
            {
                "resource_selection_status": "resolved",
                "resource_name": "META-INF/jpa.index",
                "selected_resources": [{"resource_semantic_facts": [
                    ("jpa_managed_class", ""),
                    ("jpa_managed_class", "vendor.ResourceEntity"),
                ]}],
            },
            {
                "resource_selection_status": "resolved",
                "resource_name": "empty.xml",
            },
            {
                "resource_selection_status": "resolved",
                "resource_name": "empty-facts.xml",
                "selected_resources": [{}],
            },
            {
                "initiating_loader_realm_identity": realm,
                "resource_selection_status": "resolved",
                "resource_name": "config/runtime.xml",
                "resource_selection_identity": "xml-exact",
                "selected_resources": [{"resource_semantic_facts": xml_facts}],
            },
            {
                "initiating_loader_realm_identity": second_realm,
                "resource_selection_status": "resolved",
                "resource_name": "config/other.xml",
                "resource_selection_identity": "xml-possible",
                "selected_resources": [{"resource_semantic_facts": [
                    ("spring_quartz_method", "bean|vendor.XmlTarget|init"),
                ]}],
            },
            {
                "initiating_loader_realm_identity": realm,
                "resource_selection_status": "resolved",
                "resource_name": "config/other.xml",
                "resource_selection_identity": "xml-other",
                "selected_resources": [{"resource_semantic_facts": [
                    ("mybatis_plugin_registration", "alias|vendor.Plugin"),
                    ("mybatis_plugin_registration", None),
                    ("spring_init_method", None),
                    (None, "ignored"),
                    ("spring_quartz_method", "bean|vendor.OtherXml|run"),
                ]}],
            },
        ]

        store = RowStore(
            artifact_instances=(business_artifact, library_artifact),
            classes=classes,
            members=members,
            resources=(
                {},
                {"resource_name": "ignored", "artifact_instance_identity": "business-artifact"},
                {"resource_name": "META-INF/MANIFEST.MF", "artifact_instance_identity": "library-artifact", "resource_semantic_json": "[]"},
                {"resource_name": "META-INF/MANIFEST.MF", "artifact_instance_identity": "missing", "resource_semantic_json": "[]"},
                {
                    "resource_name": "META-INF/MANIFEST.MF",
                    "artifact_instance_identity": "business-artifact",
                },
                {
                    "resource_name": "META-INF/MANIFEST.MF",
                    "artifact_instance_identity": "business-artifact",
                    "resource_semantic_json": json.dumps([
                        ["Other", "ignored"], ["Main-Class", "biz.Main"],
                        ["Start-Class", "biz.Start"],
                    ]),
                },
            ),
            direct_edges=(),
        )
        reconciliation = Reconciliation(providers, resources)
        reconciliation.definition_statuses[(realm, "ignored/FailedDefinition")] = "failed"
        runtime = SimpleNamespace(identity="full-profile", payload={
            "container_and_launcher_kind": "java-jar",
            "active_profile_identities": ["dev"],
            "resolved_configuration_properties": {},
            "runtime_configuration_coverage_status": "complete",
            "entrypoint_discovery_coverage_gaps": ["", "global-gap"],
            "business_entrypoint_profile": {
                "coverage_status": "partial",
                "coverage_gaps": ["", "profile-gap"],
                "activated_frameworks": ["spring_boot"],
                "main_class": "biz.Main",
                "activated_classes": ["", "vendor.Declared"],
                "activated_entity_classes": ["", "vendor.Entity"],
                "activated_resource_names": ["", "classpath:config/runtime.xml"],
                "methods": [
                    "invalid",
                    {
                        "initiating_loader_realm_identity": realm,
                        "class_name": "missing.Provider", "member_name": "run",
                        "descriptor": "()V",
                    },
                    {
                        "initiating_loader_realm_identity": realm,
                        "class_name": "vendor.XmlTarget", "member_name": "run",
                        "descriptor": "()V",
                    },
                    {
                        "initiating_loader_realm_identity": realm,
                        "class_name": "vendor.Declared", "member_name": "missing",
                        "descriptor": "()V",
                    },
                    {
                        "initiating_loader_realm_identity": realm,
                        "class_name": "vendor.Declared", "member_name": "tick",
                        "descriptor": "()V",
                    },
                ],
            },
        })

        result = entrypoints.discover_binary_entrypoints(
            store, runtime, reconciliation,
        )

        self.assertEqual(result.coverage_status, "partial")
        self.assertIn("global-gap", result.coverage_gaps)
        self.assertIn("profile-gap", result.coverage_gaps)
        self.assertIn("entrypoint_record_invalid", result.coverage_gaps)
        self.assertTrue(any(
            gap.startswith("xml_entrypoint_overload_ambiguous:")
            for gap in result.coverage_gaps
        ))
        reasons = {row["activation_reason"] for row in result.records}
        self.assertTrue({
            "business_final_artifact_runtime_trigger",
            "spring_boot_auto_configuration_import",
            "spring_factories_runtime_registration",
            "spring_import_from_active_configuration",
            "runtime_profile_activation_declaration",
            "dependency_framework_activation_unproven",
            "framework_condition_not_evaluated",
            "jpa_entity_registration_proved",
            "spring_message_listener_adapter_registration",
            "spring_message_listener_adapter_activation_unproven",
            "mybatis_resource_registration",
            "spring_import_resource_activation",
            "spring_xml_activation_unproven",
        }.issubset(reasons), reasons)
        kinds = {row["entry_kind"] for row in result.records}
        self.assertTrue({
            "java_main", "spring_scheduled", "spring_application_runner",
            "spring_application_listener", "spring_message_listener",
            "jpa_lifecycle_callback", "mybatis_plugin_callback",
            "mybatis_type_handler_callback", "spring_xml_init_method",
            "spring_xml_scheduled", "spring_xml_quartz",
        }.issubset(kinds), kinds)
        self.assertIn("main", result.exact_member_identities)
        self.assertNotIn("m-inactive", result.exact_member_identities)


if __name__ == "__main__":
    unittest.main()
