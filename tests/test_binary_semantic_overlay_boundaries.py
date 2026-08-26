from __future__ import annotations

from collections import defaultdict
import json
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import binary_semantic_overlay as semantic


PROFILE_ANNOTATION = "Lorg/springframework/context/annotation/Profile;"
CONDITIONAL_ON_CLASS = (
    "Lorg/springframework/boot/autoconfigure/condition/ConditionalOnClass;"
)
CONDITIONAL_ON_MISSING_CLASS = (
    "Lorg/springframework/boot/autoconfigure/condition/ConditionalOnMissingClass;"
)
CONDITIONAL_ON_PROPERTY = (
    "Lorg/springframework/boot/autoconfigure/condition/ConditionalOnProperty;"
)


def annotation(descriptor, values=(), *, visible=True):
    return {
        "descriptor": descriptor,
        "visible": visible,
        "values": list(values or ()),
    }


def member(
    identity,
    class_name="demo/Owner",
    name="run",
    descriptor="()V",
    *,
    artifact="business",
    variant="variant",
    kind="method",
    annotations=(),
):
    return {
        "member_identity": identity,
        "class_variant_identity": variant,
        "artifact_instance_identity": artifact,
        "class_name": class_name,
        "member_kind": kind,
        "member_name": name,
        "descriptor": descriptor,
        "access_flags": 0,
        "contract_json": json.dumps({"annotations": list(annotations)}),
    }


def bare_builder(*, spring=False):
    builder = object.__new__(semantic._Builder)
    builder.store = None
    builder.profile = SimpleNamespace(
        identity="profile",
        payload={
            "active_profile_identities": [],
            "resolved_configuration_properties": {},
            "runtime_configuration_coverage_status": "complete",
            "business_entrypoint_profile": {
                "activated_frameworks": ["spring_boot"] if spring else [],
                "activated_resource_names": [],
                "activated_component_scan_packages": [],
                "main_class": "",
            },
            "container_and_launcher_kind": "",
        },
    )
    builder.runtime = SimpleNamespace(identity="runtime", resource_selections=())
    builder.decisions = None
    builder.artifacts = {
        "business": {
            "artifact_instance_identity": "business",
            "runtime_path_kind": "business_classes",
            "coord": "demo:business:1",
        },
        "library": {
            "artifact_instance_identity": "library",
            "runtime_path_kind": "dependency",
            "coord": "demo:library:1",
        },
    }
    builder.classes = {}
    builder.members = {}
    builder.members_by_variant = defaultdict(list)
    builder.direct_edges = []
    builder.selected = {}
    builder.realms = []
    builder.rows = []
    builder.seen = set()
    builder.gaps = set()
    builder.resource_facts = []
    return builder


def install_class(
    builder,
    realm,
    class_name,
    *,
    variant=None,
    artifact="business",
    access=0,
    super_name="",
    interfaces=(),
    annotations=(),
    members=(),
    method_facts=None,
):
    variant = variant or f"variant:{realm}:{class_name}"
    class_row = {
        "class_variant_identity": variant,
        "artifact_instance_identity": artifact,
    }
    if method_facts is None:
        method_facts = [
            {
                "contract": {
                    "name": item["member_name"],
                    "descriptor": item["descriptor"],
                },
                "instructions": [],
            }
            for item in members
            if item.get("member_kind") == "method"
        ]
    fact = {
        "class_access": access,
        "super_name": super_name,
        "interfaces": list(interfaces),
        "annotations": list(annotations),
        "methods": list(method_facts),
    }
    builder.selected[(realm, class_name)] = (class_row, fact)
    builder.realms = sorted({*builder.realms, realm})
    builder.members_by_variant[variant].extend(members)
    for item in members:
        builder.members[item["member_identity"]] = item
    return class_row, fact


class BinarySemanticOverlayBoundaryTest(unittest.TestCase):
    def test_boolean_descriptor_and_overlay_build_contract_matrix(self):
        for value in (True, 1, -1, 0.5, "TRUE", " yes ", "on"):
            self.assertTrue(semantic._as_bool(value))
        for value in (False, 0, 0.0, None, "", "false", "off", object()):
            self.assertFalse(semantic._as_bool(value))
        self.assertEqual(semantic._annotation_descriptors({
            "annotations": [{"descriptor": None}, {"descriptor": "Ldemo/A;"}],
        }), {"Ldemo/A;"})
        self.assertIsNone(semantic._descriptor_parameters("(I"))

        builder = bare_builder()
        calls = []
        names = (
            "reflection_and_method_handles", "dynamic_proxy", "mybatis",
            "spring_transaction", "spring_data_and_bean_wiring",
            "spring_aop_and_security", "declarative_clients", "dubbo_spi",
            "implicit_data_contracts",
        )
        patches = [
            patch.object(builder, name, side_effect=lambda name=name: calls.append(name))
            for name in names
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8]:
            complete = builder.build()
        self.assertEqual(calls, list(names))
        self.assertEqual(complete.coverage_status, "complete")
        self.assertEqual(complete.rows, ())

        builder.rows = [
            {"semantic_edge_identity": "z"},
            {"semantic_edge_identity": "a"},
        ]
        builder.gaps = {"gap-b", "gap-a"}
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8]:
            partial = builder.build()
        self.assertEqual(
            [row["semantic_edge_identity"] for row in partial.rows], ["a", "z"],
        )
        self.assertEqual(partial.coverage_status, "partial")
        self.assertEqual(partial.coverage_gaps, ("gap-a", "gap-b"))
        self.assertEqual(partial.as_payload()["edge_count"], 2)

    def test_runtime_selection_preflight_and_build_override_matrix(self):
        self.assertTrue(
            semantic.semantic_overlay_requires_runtime_selection(SimpleNamespace())
        )

        def store_for(*, annotations=False, hierarchy=(), resource=False, edge=False):
            connection = MagicMock()
            connection.execute.side_effect = [
                SimpleNamespace(fetchone=lambda: (1,) if resource else None),
                SimpleNamespace(fetchone=lambda: (1,) if edge else None),
            ]
            return SimpleNamespace(
                runtime_trigger_summary=lambda: {
                    "has_runtime_annotations": annotations,
                    "hierarchy_types": hierarchy,
                },
                connection=connection,
            )

        empty = store_for(hierarchy=(None, ""))
        self.assertFalse(semantic.semantic_overlay_requires_runtime_selection(empty))
        decision = SimpleNamespace(
            authoritative_decisions=({"fact_scope": None},),
            diagnostic_decisions=({"fact_scope": {"member_kind": "field"}},),
        )
        self.assertTrue(
            semantic.semantic_overlay_requires_runtime_selection(
                store_for(), decision,
            )
        )
        non_field = SimpleNamespace(
            authoritative_decisions=({"fact_scope": {"member_kind": "method"}},),
            diagnostic_decisions=(),
        )
        self.assertFalse(
            semantic.semantic_overlay_requires_runtime_selection(
                store_for(), non_field,
            )
        )
        for kwargs in (
            {"annotations": True},
            {"resource": True},
            {"hierarchy": ("org/springframework/data/repository/Repository",)},
            {"hierarchy": ("org/springframework/data/jpa/repository/JpaRepository",)},
            {"edge": True},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertTrue(
                    semantic.semantic_overlay_requires_runtime_selection(
                        store_for(**kwargs)
                    )
                )

        store = MagicMock()
        profile = SimpleNamespace(identity="profile")
        runtime = SimpleNamespace(identity="runtime")
        with self.assertRaises(semantic.BinaryFirstContractError):
            semantic.build_binary_semantic_overlay(
                store, profile, runtime, runtime_selection_required=1,
            )
        for required in (False, None):
            with self.subTest(required=required), patch.object(
                semantic, "semantic_overlay_requires_runtime_selection",
                return_value=False,
            ) as preflight:
                result = semantic.build_binary_semantic_overlay(
                    store, profile, runtime,
                    runtime_selection_required=required,
                )
            self.assertEqual(result.rows, ())
            if required is None:
                preflight.assert_called_once_with(store, None)
            else:
                preflight.assert_not_called()

        hydrated = SimpleNamespace(identity="hydrated")
        expected = object()
        with patch.object(
            semantic, "hydrate_runtime_reconciliation", return_value=hydrated,
        ) as hydrate, patch.object(semantic, "_Builder") as builder_class:
            builder_class.return_value.build.return_value = expected
            self.assertIs(
                semantic.build_binary_semantic_overlay(
                    store, profile, runtime, runtime_selection_required=True,
                ),
                expected,
            )
        hydrate.assert_called_once_with(
            store, runtime, ("provider_binding", "class_definition"),
        )
        builder_class.assert_called_once_with(store, profile, hydrated, None)

    def test_pure_annotation_descriptor_and_pointcut_matrix(self):
        self.assertIsNone(semantic._spring_aop_pointcut_constraints(None))
        self.assertIsNone(semantic._spring_aop_pointcut_constraints("within(demo.Type)"))
        complete = semantic._spring_aop_pointcut_constraints(
            "execution(* demo.Service.run(..)) && "
            "@within(demo.Component) && @annotation(demo.Allowed) && "
            "!@annotation(demo.Blocked)"
        )
        self.assertTrue(complete["complete"])
        self.assertEqual(complete["executions"], (("demo.Service", "run"),))
        self.assertEqual(complete["class_annotations"], {"Ldemo/Component;"})
        self.assertEqual(complete["method_annotations"], {"Ldemo/Allowed;"})
        self.assertEqual(
            complete["excluded_method_annotations"], {"Ldemo/Blocked;"},
        )
        for suffix in (
            " || execution(* demo.Other.run(..))",
            " && within(demo..*)",
            " && @target(demo.Component)",
            " && !@within(demo.Component)",
        ):
            with self.subTest(suffix=suffix):
                parsed = semantic._spring_aop_pointcut_constraints(
                    "execution(* demo.Service.run(..))" + suffix
                )
                self.assertFalse(parsed["complete"])

        self.assertEqual(semantic._loads(None), {})
        self.assertEqual(semantic._loads("not-json"), {})
        self.assertEqual(semantic._loads('{"value":1}'), {"value": 1})
        payload = {
            "annotations": [
                "not-a-mapping",
                {"descriptor": "Linvisible;", "visible": False},
                {"descriptor": "Ldefault;"},
                {"descriptor": "", "visible": True},
            ]
        }
        self.assertEqual(
            semantic._annotations(payload),
            ({"descriptor": "Ldefault;"}, {"descriptor": "", "visible": True}),
        )
        self.assertEqual(semantic._annotations({}), ())
        self.assertEqual(semantic._annotation_descriptors(payload), {"Ldefault;"})
        self.assertEqual(semantic._annotation_descriptors({}), set())

    def test_nested_values_annotation_attributes_and_descriptor_matrix(self):
        nested = {
            "plain": "alpha",
            "mapping": {"inner": "beta"},
            "sequence": ["gamma", ("delta",)],
            "ignored": 7,
        }
        self.assertEqual(
            semantic._nested_strings(nested), {"alpha", "beta", "gamma", "delta"},
        )
        self.assertEqual(semantic._nested_strings([]), set())
        self.assertEqual(semantic._nested_strings(7), set())

        typed = {
            "direct": {"kind": "type", "descriptor": "Ldemo/Direct;"},
            "invalid_start": {"kind": "type", "descriptor": "demo/Invalid;"},
            "invalid_end": {"kind": "type", "descriptor": "Ldemo/Invalid"},
            "empty": {"kind": "type", "descriptor": None},
            "nested": [{"kind": "type", "descriptor": "Ldemo/Nested;"}],
        }
        self.assertEqual(
            semantic._nested_type_names(typed), {"demo/Direct", "demo/Nested"},
        )
        self.assertEqual(semantic._nested_type_names("value"), set())
        self.assertEqual(semantic._nested_type_names([]), set())

        attributes = semantic._annotation_attributes({
            "values": [
                "bad",
                ["short"],
                [None, "value"],
                ["empty-array", "array"],
                ["array", "array", ["a", "b"]],
                ["none-array", "array", None],
                ["short-enum", "enum", "Ldemo/Mode;"],
                ["enum", "enum", "Ldemo/Mode;", "ACTIVE"],
                ["plain", "value"],
                ["plain", "second"],
            ]
        })
        self.assertEqual(attributes["empty-array"], ("array",))
        self.assertEqual(attributes["array"], ("a", "b"))
        self.assertEqual(attributes["none-array"], ())
        self.assertEqual(attributes["short-enum"], ("enum",))
        self.assertEqual(attributes["enum"], ("ACTIVE",))
        self.assertEqual(attributes["plain"], ("value", "second"))
        self.assertEqual(semantic._annotation_attributes({}), {})

        parameter_cases = {
            None: None,
            "not-a-method": None,
            "(": None,
            "([": None,
            "(Ldemo/Type": None,
            "()V": (),
            "(I[Z[[Ljava/lang/String;)Ljava/lang/Object;": (
                "I", "[Z", "[[Ljava/lang/String;",
            ),
        }
        for descriptor, expected in parameter_cases.items():
            with self.subTest(descriptor=descriptor):
                self.assertEqual(semantic._descriptor_parameters(descriptor), expected)
        self.assertEqual(semantic._descriptor_return(None), "")
        self.assertEqual(semantic._descriptor_return("broken"), "")
        self.assertEqual(semantic._descriptor_return("(I)Ljava/lang/String;"), "Ljava/lang/String;")
        for descriptor, expected in (
            (None, ""), ("", ""), ("Ldemo/Type", ""),
            ("demo/Type;", ""), ("Ldemo/Type;", "demo/Type"),
        ):
            self.assertEqual(semantic._descriptor_class(descriptor), expected)

    def test_builder_init_selection_resource_and_index_boundaries(self):
        artifact_rows = [
            {"artifact_instance_identity": "business", "runtime_path_kind": "business"},
        ]
        class_rows = [
            {
                "class_variant_identity": "v-good",
                "artifact_instance_identity": "business",
                "fact_json": '{"class_access":0,"methods":[]}',
            },
            {
                "class_variant_identity": "v-invalid",
                "artifact_instance_identity": "business",
                "fact_json": "invalid",
            },
            {
                "class_variant_identity": "v-empty",
                "artifact_instance_identity": "business",
                "fact_json": None,
            },
        ]
        member_rows = [member("m", variant="v-good")]
        connection = MagicMock()
        connection.execute.return_value = member_rows
        store = MagicMock(connection=connection)
        store.rows.side_effect = lambda table, **_kwargs: (
            artifact_rows if table == "artifact_instances" else class_rows
        )
        reconciliation = SimpleNamespace(
            class_definitions=(
                {"initiating_loader_realm_identity": None, "class_name": None, "ready": False},
                {"initiating_loader_realm_identity": "app", "class_name": "demo/Good"},
                {"initiating_loader_realm_identity": "app", "class_name": "demo/GoodAlias"},
                {"initiating_loader_realm_identity": "app", "class_name": "demo/Invalid"},
                {"initiating_loader_realm_identity": "app", "class_name": "demo/MissingVariant"},
                {"initiating_loader_realm_identity": None, "class_name": "demo/BlankRealm"},
                {"initiating_loader_realm_identity": "app", "class_name": None},
                {"initiating_loader_realm_identity": "app", "class_name": "demo/Empty"},
            ),
            provider_bindings=(
                {"class_provider_status": "missing"},
                {
                    "class_provider_status": "resolved",
                    "initiating_loader_realm_identity": "not-ready",
                    "class_name": "demo/Skipped",
                    "selected_class_variant_identity": "v-good",
                },
                {
                    "class_provider_status": "resolved",
                    "initiating_loader_realm_identity": "app",
                    "class_name": "demo/MissingVariant",
                    "selected_class_variant_identity": "missing",
                },
                {
                    "class_provider_status": "resolved",
                    "initiating_loader_realm_identity": "app",
                    "class_name": "demo/Good",
                    "selected_class_variant_identity": "v-good",
                },
                {
                    "class_provider_status": "resolved",
                    "initiating_loader_realm_identity": "app",
                    "class_name": "demo/GoodAlias",
                    "selected_class_variant_identity": "v-good",
                },
                {
                    "class_provider_status": "resolved",
                    "initiating_loader_realm_identity": "app",
                    "class_name": "demo/Invalid",
                    "selected_class_variant_identity": "v-invalid",
                },
                {
                    "class_provider_status": "resolved",
                    "initiating_loader_realm_identity": None,
                    "class_name": "demo/BlankRealm",
                    "selected_class_variant_identity": None,
                },
                {
                    "class_provider_status": "resolved",
                    "initiating_loader_realm_identity": "app",
                    "class_name": None,
                    "selected_class_variant_identity": None,
                },
                {
                    "class_provider_status": "resolved",
                    "initiating_loader_realm_identity": "app",
                    "class_name": "demo/Empty",
                    "selected_class_variant_identity": "v-empty",
                },
            ),
            resource_selections=(
                {"resource_selection_status": "missing"},
                {"resource_selection_status": "resolved", "selected_resources": None},
                {
                    "resource_selection_status": "resolved",
                    "initiating_loader_realm_identity": None,
                    "resource_name": None,
                    "resource_selection_identity": None,
                    "selected_resources": [
                        {"resource_semantic_facts": None},
                        {"resource_semantic_facts": [["kind", "value"]]},
                    ],
                },
            ),
        )
        with patch.object(
            semantic, "class_load_is_ready",
            side_effect=lambda item: item.get("ready", True),
        ):
            builder = semantic._Builder(
                store, SimpleNamespace(payload={}, identity="profile"), reconciliation,
            )
        self.assertEqual(set(builder.selected), {
            ("app", "demo/Good"), ("app", "demo/GoodAlias"),
            ("app", "demo/Invalid"), ("app", "demo/Empty"),
        })
        self.assertNotIn("fact_json", class_rows[0])
        self.assertEqual(builder.realms, ["app"])
        self.assertEqual(len(builder.resource_facts), 2)
        self.assertNotIsInstance(builder.direct_edges, list)
        self.assertEqual(connection.execute.call_count, 1)
        self.assertNotIn(
            "FROM direct_edges", connection.execute.call_args.args[0]
        )

        empty_connection = MagicMock()
        empty_connection.execute.return_value = []
        empty_store = MagicMock(connection=empty_connection)
        empty_store.rows.return_value = []
        empty_builder = semantic._Builder(
            empty_store,
            SimpleNamespace(payload={}, identity="empty-profile"),
            SimpleNamespace(),
        )
        self.assertEqual(empty_builder.selected, {})
        self.assertEqual(empty_builder.resource_facts, [])

        empty_builder.runtime = SimpleNamespace(resource_selections=(
            {
                "resource_selection_status": "resolved",
                "initiating_loader_realm_identity": "app",
                "resource_name": "META-INF/services/demo.Service",
                "resource_selection_identity": "selection",
                "selected_resources": [{
                    "resource_semantic_facts": [["ordered_entry", "demo.Provider"]],
                }],
            },
        ))
        self.assertEqual(empty_builder._selected_resource_facts(), [{
            "realm": "app",
            "name": "META-INF/services/demo.Service",
            "facts": (("ordered_entry", "demo.Provider"),),
            "selection_identity": "selection",
        }])

    def test_builder_lookup_hierarchy_business_spring_and_member_rows(self):
        builder = bare_builder()
        self.assertFalse(builder._business("missing"))
        self.assertFalse(builder._business("library"))
        builder.artifacts["upper"] = {"runtime_path_kind": "APPLICATION"}
        self.assertTrue(builder._business("upper"))

        run = member("run", "demo/Child", "run", variant="child")
        field = member("field", "demo/Child", "value", variant="child", kind="field")
        install_class(
            builder, "app", "demo/Parent", variant="parent",
            super_name="demo/Root",
        )
        install_class(
            builder, "app", "demo/Child", variant="child",
            super_name="demo/Parent", interfaces=("demo/Interface",),
            members=(run, field),
            method_facts=(
                {"contract": None, "instructions": []},
                {"contract": {"name": "missing", "descriptor": "()V"}},
                {"contract": {"name": "run", "descriptor": "()V"}},
            ),
        )
        install_class(
            builder, "app", "demo/Root", variant="root",
            super_name="demo/Child",
        )
        self.assertEqual(builder._members_for("app", "missing"), [])
        self.assertEqual(builder._members_for("app", "demo/Child"), [run])
        self.assertEqual(builder._members_for("app", "demo/Child", "missing"), [])
        self.assertEqual(builder._members_for("app", "demo/Child", "run"), [run])
        rows = list(builder._member_fact_rows())
        self.assertEqual([item[4]["member_identity"] for item in rows], ["run"])
        self.assertEqual(
            builder._hierarchy("app", "demo/Child"),
            {"demo/Parent", "demo/Root", "demo/Child", "demo/Interface"},
        )
        self.assertEqual(builder._hierarchy("app", "missing"), set())
        self.assertFalse(builder._spring_active())
        builder.profile.payload["business_entrypoint_profile"] = {
            "activated_frameworks": [None, "SPRING_BOOT"],
        }
        self.assertTrue(builder._spring_active())
        builder.profile.payload["business_entrypoint_profile"] = None
        builder.profile.payload["container_and_launcher_kind"] = "SPRING-BOOT"
        self.assertTrue(builder._spring_active())

    def test_condition_certainty_complete_activation_matrix(self):
        builder = bare_builder()

        def evaluate(descriptor, values=(), *, profiles=(), properties=None,
                     coverage="complete", selected=()):
            builder.profile.payload.update({
                "active_profile_identities": list(profiles),
                "resolved_configuration_properties": properties or {},
                "runtime_configuration_coverage_status": coverage,
            })
            builder.selected = {("app", name): ({}, {}) for name in selected}
            return builder._condition_certainty(
                "app", {"annotations": [annotation(descriptor, values)]},
            )

        self.assertEqual(builder._condition_certainty("app", {}), "exact")
        self.assertEqual(evaluate(PROFILE_ANNOTATION, [["value", "array", []]]), "exact")
        self.assertEqual(
            evaluate(PROFILE_ANNOTATION, [["value", "array", ["dev"]]], profiles=["dev"]),
            "exact",
        )
        self.assertEqual(
            evaluate(PROFILE_ANNOTATION, [["value", "array", ["dev"]]], profiles=[None]),
            "inactive",
        )
        class_value = [["value", "array", [{"kind": "type", "descriptor": "Ldemo/Present;"}]]]
        self.assertEqual(
            evaluate(CONDITIONAL_ON_CLASS, class_value, selected=["demo/Present"]), "exact",
        )
        self.assertEqual(evaluate(CONDITIONAL_ON_CLASS, class_value), "inactive")
        self.assertEqual(evaluate(CONDITIONAL_ON_CLASS), "possible")
        missing_value = [["value", "array", ["demo.Absent"]]]
        self.assertEqual(evaluate(CONDITIONAL_ON_MISSING_CLASS, missing_value), "exact")
        self.assertEqual(
            evaluate(CONDITIONAL_ON_MISSING_CLASS, missing_value, selected=["demo/Absent"]),
            "inactive",
        )
        self.assertEqual(
            evaluate(
                CONDITIONAL_ON_MISSING_CLASS,
                [["value", "array", ["NoDot", "demo.Absent"]]],
            ),
            "exact",
        )
        self.assertEqual(evaluate(CONDITIONAL_ON_MISSING_CLASS), "possible")

        self.assertEqual(evaluate(CONDITIONAL_ON_PROPERTY), "possible")
        name = [["prefix", "feature"], ["name", "enabled"]]
        dotted = [["prefix", "feature."], ["value", "enabled"]]
        self.assertEqual(
            evaluate(CONDITIONAL_ON_PROPERTY, name, coverage="partial"), "possible",
        )
        self.assertEqual(evaluate(CONDITIONAL_ON_PROPERTY, name), "inactive")
        self.assertEqual(
            evaluate(
                CONDITIONAL_ON_PROPERTY,
                [*name, ["matchIfMissing", True]],
            ),
            "exact",
        )
        self.assertEqual(
            evaluate(CONDITIONAL_ON_PROPERTY, dotted, properties={"feature.enabled": "true"}),
            "exact",
        )
        self.assertEqual(
            evaluate(CONDITIONAL_ON_PROPERTY, dotted, properties={"feature.enabled": "false"}),
            "inactive",
        )
        having = [*dotted, ["havingValue", "yes"]]
        self.assertEqual(
            evaluate(CONDITIONAL_ON_PROPERTY, having, properties={"feature.enabled": "yes"}),
            "exact",
        )
        self.assertEqual(
            evaluate(CONDITIONAL_ON_PROPERTY, having, properties={"feature.enabled": "no"}),
            "inactive",
        )
        self.assertEqual(
            evaluate(
                "Lorg/springframework/boot/autoconfigure/condition/ConditionalOnBean;"
            ),
            "possible",
        )
        self.assertEqual(
            evaluate("Lorg/springframework/context/annotation/Conditional;"),
            "possible",
        )
        builder.profile.payload = {}
        builder.selected = {}
        self.assertEqual(
            builder._condition_certainty(
                "app", {"annotations": [{"descriptor": None, "values": None}]},
            ),
            "exact",
        )
        self.assertEqual(
            evaluate(
                PROFILE_ANNOTATION,
                [["value", "array", ["value", "array"]]],
            ),
            "exact",
        )
        self.assertEqual(
            evaluate(
                CONDITIONAL_ON_CLASS,
                [["value", "array", ["NoDot", "demo.Present"]]],
                selected=["demo/Present"],
            ),
            "exact",
        )
        self.assertEqual(
            evaluate(
                CONDITIONAL_ON_PROPERTY,
                [["name", "array", ["", "enabled"]]],
                properties={"enabled": "true"},
            ),
            "exact",
        )

    def test_add_unique_targets_and_payload_boundaries(self):
        builder = bare_builder()
        target = member("target", "demo/Target", "run", artifact="library", variant="target")
        caller = member("caller", "demo/Caller", "call", descriptor="(I)V")
        builder.add({}, target, kind="kind", certainty="exact", evidence={})
        builder.add(caller, {}, kind="kind", certainty="exact", evidence={})
        self.assertEqual(builder.rows, [])
        builder.add(caller, target, kind="kind", certainty="exact", evidence={"x": 1})
        builder.add(caller, target, kind="kind", certainty="exact", evidence={"x": 2})
        self.assertEqual(len(builder.rows), 1)
        self.assertEqual(builder.rows[0]["caller_dependency_coord"], "demo:business:1")
        self.assertEqual(builder.rows[0]["target_dependency_coord"], "demo:library:1")

        sparse_caller = {"member_identity": "sparse-caller"}
        sparse_target = {"member_identity": "sparse-target"}
        builder.add(
            sparse_caller, sparse_target, kind="sparse", certainty="possible",
            evidence={},
        )
        sparse = builder.rows[-1]
        for key in (
            "caller_class_name", "caller_member_name", "caller_descriptor",
            "target_class_name", "target_member_name", "target_descriptor",
            "caller_dependency_coord", "target_dependency_coord",
        ):
            self.assertEqual(sparse[key], "")

        good = member(
            "overload", "demo/Service", "invoke", "(I)V", variant="service",
        )
        invalid = member(
            "invalid", "demo/Service", "invoke", "broken", variant="service",
        )
        zero = member(
            "zero", "demo/Service", "invoke", "()V", variant="service",
        )
        duplicate = dict(good)
        install_class(
            builder, "app", "demo/Service", variant="service",
            members=(good, invalid, zero, duplicate),
        )
        install_class(
            builder, "other", "demo/Service", variant="other-service",
            members=(dict(good, class_variant_identity="other-service"),),
        )
        self.assertEqual(
            [item[1]["member_identity"] for item in builder._unique_targets(
                "demo/Service", "invoke",
            )],
            ["overload", "invalid", "zero"],
        )
        self.assertEqual(
            [item[1]["member_identity"] for item in builder._unique_targets(
                "demo/Service", "invoke", parameter_count=1,
            )],
            ["overload"],
        )

    def test_reflection_and_method_handle_literal_resolution_matrix(self):
        builder = bare_builder()
        callers = [
            member("reflect-overloaded", "demo/Caller", "overloaded", variant="callers"),
            member("reflect-exact", "demo/Caller", "exact", variant="callers"),
            member("reflect-constructor", "demo/Caller", "constructor", variant="callers"),
            member("reflect-field", "demo/Caller", "field", variant="callers"),
            member("reflect-unresolved", "demo/Caller", "unresolved", variant="callers"),
            member("reflect-no-terminal", "demo/Caller", "noTerminal", variant="callers"),
            member("reflect-no-prior", "demo/Caller", "noPrior", variant="callers"),
            member("reflect-owner-only", "demo/Caller", "ownerOnly", variant="callers"),
            member("reflect-terminal-before", "demo/Caller", "terminalBefore", variant="callers"),
            member("reflect-no-invocation", "demo/Caller", "noInvocation", variant="callers"),
            member("reflect-late-type", "demo/Caller", "lateType", variant="callers"),
        ]
        method_facts = (
            {
                "contract": {"name": "overloaded", "descriptor": "()V"},
                "instructions": [
                    ("ldc", 0, "demo.Overloaded"),
                    ("method", 1, 184, "java/lang/Class", "forName", "()V"),
                    ("ldc", 2, "run"),
                    ("method", 3, 182, "java/lang/Class", "getMethod", "()V"),
                    ("method", 4, 182, "java/lang/reflect/Method", "invoke", "()V"),
                ],
            },
            {
                "contract": {"name": "exact", "descriptor": "()V"},
                "instructions": [
                    ("ldc", 0, {"kind": "type", "descriptor": "Ldemo/Exact;"}),
                    ("ldc", 1, "work"),
                    ("method", 2, 182, "java/lang/invoke/MethodHandles$Lookup", "findVirtual", "()V"),
                    ("method", 3, 182, "java/lang/invoke/MethodHandle", "invokeExact", "()V"),
                ],
            },
            {
                "contract": {"name": "constructor", "descriptor": "()V"},
                "instructions": [
                    ("ldc", 0, {"kind": "type", "descriptor": "Ldemo/Ctor;"}),
                    ("method", 1, 182, "java/lang/Class", "getConstructor", "()V"),
                    ("method", 2, 182, "java/lang/reflect/Constructor", "newInstance", "()V"),
                ],
            },
            {
                "contract": {"name": "field", "descriptor": "()V"},
                "instructions": [
                    ("ldc", 0, {"kind": "type", "descriptor": "Ldemo/Fields;"}),
                    ("ldc", 1, "value"),
                    ("method", 2, 182, "java/lang/Class", "getField", "()V"),
                    ("method", 3, 182, "java/lang/reflect/Field", "get", "()V"),
                ],
            },
            {
                "contract": {"name": "unresolved", "descriptor": "()V"},
                "instructions": [
                    (), ("other",), ("method", 0, 182, "java/lang/Class", "getMethod", "()V"),
                    ("method", 1, 182, "java/lang/reflect/Method", "invoke", "()V"),
                ],
            },
            {
                "contract": {"name": "noTerminal", "descriptor": "()V"},
                "instructions": [
                    ("method", 0, 182, "java/lang/Class", "getDeclaredMethod", "()V"),
                    ("method", 99, 182, "java/lang/reflect/Method", "invoke", "()V"),
                    ("not-method", 1, 2, 3, 4, 5),
                ],
            },
            {
                "contract": {"name": "noPrior", "descriptor": "()V"},
                "instructions": [
                    ("ldc", 0, {"kind": "type", "descriptor": "Ldemo/Exact;"}),
                    ("method", 1, 184, "java/lang/Class", "forName", "()V"),
                    ("ldc", 2, "work"),
                    ("method", 3, 182, "java/lang/Class", "getMethod", "()V"),
                    ("method", 4, 182, "java/lang/reflect/Method", "invoke", "()V"),
                ],
            },
            {
                "contract": {"name": "ownerOnly", "descriptor": "()V"},
                "instructions": [
                    ("ldc", 0, {"kind": "type", "descriptor": "Ldemo/Exact;"}),
                    ("method", 1, 182, "java/lang/Class", "getMethod", "()V"),
                    ("method", 2, 182, "java/lang/reflect/Method", "invoke", "()V"),
                ],
            },
            {
                "contract": {"name": "terminalBefore", "descriptor": "()V"},
                "instructions": [
                    ("method", 0, 182, "java/lang/reflect/Method", "invoke", "()V"),
                    ("method", 1, 182, "java/lang/Class", "getMethod", "()V"),
                ],
            },
            {
                "contract": {"name": "noInvocation", "descriptor": "()V"},
                "instructions": [
                    ("method", 0, 182, "java/lang/Class", "getMethod", "()V"),
                ],
            },
            {
                "contract": {"name": "lateType", "descriptor": "()V"},
                "instructions": [
                    ("ldc", 0, "work"),
                    ("ldc", 1, {"kind": "type", "descriptor": "Ldemo/Exact;"}),
                    ("method", 2, 182, "java/lang/Class", "getMethod", "()V"),
                    ("method", 3, 182, "java/lang/reflect/Method", "invoke", "()V"),
                ],
            },
        )
        install_class(
            builder, "app", "demo/Caller", variant="callers",
            members=callers, method_facts=method_facts,
        )
        install_class(
            builder, "app", "demo/Overloaded", variant="overloaded",
            members=(
                member("run-int", "demo/Overloaded", "run", "(I)V", variant="overloaded"),
                member("run-string", "demo/Overloaded", "run", "(Ljava/lang/String;)V", variant="overloaded"),
            ),
        )
        install_class(
            builder, "app", "demo/Exact", variant="exact",
            members=(member("work", "demo/Exact", "work", variant="exact"),),
        )
        install_class(
            builder, "app", "demo/Ctor", variant="ctor",
            members=(member("ctor", "demo/Ctor", "<init>", variant="ctor"),),
        )
        install_class(
            builder, "app", "demo/Fields", variant="fields",
            members=(
                member("field-value", "demo/Fields", "value", variant="fields", kind="field"),
                member("field-method", "demo/Fields", "value", variant="fields"),
                member("field-other", "demo/Fields", "other", variant="fields", kind="field"),
            ),
        )
        builder.realms.append("missing-realm")

        builder.reflection_and_method_handles()

        kinds = [row["semantic_edge_kind"] for row in builder.rows]
        self.assertEqual(kinds.count("reflection_method_invocation"), 4)
        self.assertIn("method_handle_invocation", kinds)
        self.assertIn("reflection_constructor_invocation", kinds)
        self.assertIn("reflection_field_access", kinds)
        self.assertIn(
            "semantic_reflection_overload_ambiguous:demo/Overloaded:run",
            builder.gaps,
        )
        self.assertIn(
            "semantic_reflection_target_unresolved:demo/Caller:unresolved",
            builder.gaps,
        )
        self.assertIn(
            "semantic_reflection_target_unresolved:demo/Caller:ownerOnly",
            builder.gaps,
        )

    def test_dynamic_proxy_exact_possible_and_unresolved_handlers(self):
        builder = bare_builder()
        callers = [
            member("proxy-exact", "demo/ProxyCaller", "exact", variant="proxy-callers"),
            member("proxy-possible", "demo/ProxyCaller", "possible", variant="proxy-callers"),
            member("proxy-missing", "demo/ProxyCaller", "missing", variant="proxy-callers"),
        ]
        registration = ("method", 10, 184, "java/lang/reflect/Proxy", "newProxyInstance", "()V")
        exact_instructions = [
            (),
            ("ldc", 0, {"kind": "type", "descriptor": "Ldemo/Api;"}),
            ("type", 1, 187, "demo/Handler"),
            ("type", 2, 189, "demo/NotConstructed"),
            registration,
            ("method", 11, 185, "demo/Api", "run", "()V"),
        ]
        possible_instructions = [
            ("type", 0, 187, "demo/Handler"), registration,
        ]
        missing_instructions = [
            ("type",), ("type", 0, 187, "demo/Other"), registration,
        ]
        install_class(
            builder, "app", "demo/ProxyCaller", variant="proxy-callers",
            members=callers,
            method_facts=(
                {"contract": {"name": "exact", "descriptor": "()V"}, "instructions": exact_instructions},
                {"contract": {"name": "possible", "descriptor": "()V"}, "instructions": possible_instructions},
                {"contract": {"name": "missing", "descriptor": "()V"}, "instructions": missing_instructions},
            ),
        )
        install_class(
            builder, "app", "demo/Handler", variant="handler",
            interfaces=("java/lang/reflect/InvocationHandler",),
            members=(member("handler-invoke", "demo/Handler", "invoke", variant="handler"),),
        )
        install_class(builder, "app", "demo/Other", variant="other")

        builder.dynamic_proxy()

        self.assertEqual(len(builder.rows), 2)
        self.assertEqual(
            {row["path_certainty"] for row in builder.rows}, {"exact", "possible"},
        )
        self.assertIn("dynamic_proxy_handler_unresolved:proxy-missing", builder.gaps)

        malformed = member(
            "proxy-malformed", "demo/MalformedProxyCaller", "run",
            variant="malformed-proxy",
        )
        install_class(
            builder, "app", "demo/MalformedProxyCaller", variant="malformed-proxy",
            members=(malformed,), method_facts=({
                "contract": {"name": "run", "descriptor": "()V"},
                "instructions": [
                    ("method", 0, 184, "java/lang/reflect/Proxy", "wrong", "()V"),
                    ("other", 1, 2, 3, 4, 5),
                    ("other", 2, {"kind": "type", "descriptor": "Ldemo/NotLiteral;"}),
                    ("method", 2, 184, "wrong/Proxy", "newProxyInstance", "()V"),
                    ("ldc", 3, {"kind": "type", "descriptor": "Ldemo/Api;"}),
                    ("type", 4, 187, "demo/Handler"),
                    registration,
                    ("method",),
                    ("method", 12, 182, "demo/Api", "run", "()V"),
                ],
            },),
        )
        builder.dynamic_proxy()

    def test_mybatis_annotation_xml_registration_and_runtime_targets(self):
        builder = bare_builder()
        mapper_runtime = member("mapper-proxy", "org/apache/ibatis/binding/MapperProxy", "invoke")
        builder.resource_facts = [
            {"realm": "app", "facts": (("ignored", "x"),)},
            {"realm": "app", "facts": (("mybatis_mapper_namespace", "demo.XmlMapper"),)},
        ]
        annotated_method = member("annotated-select", "demo/AnnotatedMapper", "find", variant="annotated")
        xml_method = member("xml-select", "demo/XmlMapper", "find", variant="xml")
        install_class(builder, "app", "demo/Plain", variant="plain", access=semantic.ACC_INTERFACE)
        install_class(
            builder, "app", "demo/AnnotatedConcrete", variant="annotated-concrete",
            annotations=(annotation(next(iter(semantic.MAPPER_ANNOTATIONS))),),
        )
        install_class(
            builder, "app", "demo/UninvokedMapper", variant="uninvoked",
            access=semantic.ACC_INTERFACE,
            annotations=(annotation(next(iter(semantic.MAPPER_ANNOTATIONS))),),
        )
        install_class(
            builder, "app", "demo/AnnotatedMapper", variant="annotated",
            access=semantic.ACC_INTERFACE,
            annotations=(annotation(next(iter(semantic.MAPPER_ANNOTATIONS))),),
            members=(annotated_method,),
        )
        install_class(
            builder, "app", "demo/XmlMapper", variant="xml",
            access=semantic.ACC_INTERFACE, members=(xml_method,),
        )
        builder.direct_edges = [
            {"edge_kind": "field", "symbolic_owner": "demo/AnnotatedMapper"},
            {"edge_kind": "method", "symbolic_owner": "demo/AnnotatedMapper"},
            {"edge_kind": "method", "symbolic_owner": "demo/XmlMapper"},
        ]

        def targets(owner, _name, *, parameter_count=None):
            self.assertIsNotNone(parameter_count)
            if owner.endswith("MapperProxy"):
                return [("app", mapper_runtime)]
            return []

        with patch.object(builder, "_unique_targets", side_effect=targets):
            builder.mybatis()

        self.assertEqual(len(builder.rows), 2)
        self.assertEqual(
            {row["path_certainty"] for row in builder.rows}, {"exact", "possible"},
        )
        self.assertIn(
            "mybatis_runtime_target_unresolved:org/apache/ibatis/binding/MapperMethod:execute",
            builder.gaps,
        )
        self.assertIn("mybatis_xml_activation_unproven:demo/XmlMapper", builder.gaps)

        empty = bare_builder()
        empty.direct_edges = [{"edge_kind": "method", "symbolic_owner": None}]
        with patch.object(empty, "_unique_targets", return_value=[]):
            empty.mybatis()

    def test_spring_transaction_business_annotation_and_activation_matrix(self):
        runtime_targets = [member(f"tx-{index}") for index in range(3)]

        def execute(spring, target_count):
            builder = bare_builder(spring=spring)
            no_annotation = member("plain", "demo/Service", "plain", variant="service")
            no_annotation["contract_json"] = None
            method_tx = member(
                "method-tx", "demo/Service", "methodTx", variant="service",
                annotations=(annotation(semantic.TRANSACTIONAL),),
            )
            class_tx = member("class-tx", "demo/ClassTx", "run", variant="class-tx")
            library_tx = member(
                "library-tx", "demo/Library", "run", artifact="library", variant="library-tx",
                annotations=(annotation(semantic.TRANSACTIONAL),),
            )
            install_class(
                builder, "app", "demo/Service", variant="service",
                members=(no_annotation, method_tx),
            )
            install_class(
                builder, "app", "demo/ClassTx", variant="class-tx",
                annotations=(annotation(semantic.TRANSACTIONAL),), members=(class_tx,),
            )
            install_class(
                builder, "app", "demo/Library", variant="library-tx",
                artifact="library", members=(library_tx,),
            )
            counter = iter(runtime_targets[:target_count] + [None] * (3 - target_count))

            def unique(*_args, **_kwargs):
                value = next(counter)
                return [] if value is None else [("app", value)]

            with patch.object(builder, "_unique_targets", side_effect=unique):
                builder.spring_transaction()
            return builder

        exact = execute(True, 3)
        self.assertEqual(len(exact.rows), 6)
        self.assertEqual({row["path_certainty"] for row in exact.rows}, {"exact"})
        possible = execute(False, 1)
        self.assertEqual(len(possible.rows), 2)
        self.assertEqual({row["path_certainty"] for row in possible.rows}, {"possible"})
        self.assertEqual(len(possible.gaps), 2)
        active_incomplete = execute(True, 1)
        self.assertEqual(
            {row["path_certainty"] for row in active_incomplete.rows}, {"possible"},
        )
        inactive_complete = execute(False, 3)
        self.assertEqual(
            {row["path_certainty"] for row in inactive_complete.rows}, {"possible"},
        )

    def test_spring_bean_resources_components_primary_and_wiring_matrix(self):
        builder = bare_builder(spring=True)
        builder.profile.payload["business_entrypoint_profile"].update({
            "activated_resource_names": [None, "classpath:beans.xml"],
            "activated_component_scan_packages": [None, "", "demo.scanned"],
            "main_class": "demo.app.Main",
        })
        builder.resource_facts = [
            {
                "realm": "app", "name": "ignored.xml",
                "facts": (
                    ("spring_bean_class", "invalid"),
                    ("spring_bean_primary", "invalid"),
                    ("spring_component_scan", " , demo.resource ,"),
                    ("ignored", "value"),
                ),
            },
            {
                "realm": "app", "name": "beans.xml",
                "facts": (
                    ("spring_bean_class", "bean|demo.PrimaryImpl"),
                    ("spring_bean_primary", "bean|demo.PrimaryImpl"),
                ),
            },
            {
                "realm": "app", "name": "inactive.xml",
                "facts": (("spring_bean_class", "bean|demo.ResourceImpl"),),
            },
        ]
        api = member("api", "demo/Api", "run", variant="api")
        install_class(
            builder, "app", "demo/Api", variant="api",
            access=semantic.ACC_INTERFACE, members=(api,),
        )
        primary = member("primary-run", "demo/PrimaryImpl", "run", variant="primary")
        primary_wrong = member(
            "primary-run-wrong", "demo/PrimaryImpl", "run", "(I)V", variant="primary",
        )
        install_class(
            builder, "app", "demo/PrimaryImpl", variant="primary", artifact="library",
            interfaces=("demo/Api",), members=(primary, primary_wrong),
        )
        resource_impl = member("resource-run", "demo/ResourceImpl", "run", variant="resource")
        install_class(
            builder, "app", "demo/ResourceImpl", variant="resource", artifact="library",
            interfaces=("demo/Api",), members=(resource_impl,),
        )
        component = annotation(next(iter(semantic.COMPONENT_ANNOTATIONS)))
        scanned = member("scanned-run", "demo/scanned/Impl", "run", variant="scanned")
        install_class(
            builder, "app", "demo/scanned/Impl", variant="scanned", artifact="library",
            interfaces=("demo/Api",), annotations=(component,), members=(scanned,),
        )
        exact_prefix = member(
            "exact-prefix-run", "demo/scanned", "run", variant="exact-prefix",
        )
        install_class(
            builder, "app", "demo/scanned", variant="exact-prefix", artifact="library",
            interfaces=("demo/Api",), annotations=(component,),
            members=(exact_prefix,),
        )
        possible = member("possible-run", "outside/Impl", "run", variant="possible")
        install_class(
            builder, "app", "outside/Impl", variant="possible", artifact="library",
            interfaces=("demo/Api",), annotations=(component,), members=(possible,),
        )
        inactive = member("inactive-run", "demo/Inactive", "run", variant="inactive")
        install_class(
            builder, "app", "demo/Inactive", variant="inactive",
            interfaces=("demo/Api",),
            annotations=(
                component,
                annotation(PROFILE_ANNOTATION, [["value", "array", ["disabled"]]]),
            ),
            members=(inactive,),
        )
        config = member("config", "demo/Config", "config", variant="config")
        install_class(
            builder, "app", "demo/Config", variant="config",
            annotations=(
                annotation(
                    "Lorg/springframework/context/annotation/ComponentScan;",
                    [["value", "array", ["", "demo.extra", "Ignored.class"]]],
                ),
                annotation(
                    "Lorg/springframework/context/annotation/ComponentScan;"
                ),
                annotation("Ldemo/Irrelevant;"),
            ),
            members=(config,),
        )
        caller = member("wiring-caller", "demo/Caller", "call")
        builder.members[caller["member_identity"]] = caller
        builder.direct_edges = [
            {"edge_kind": "field"},
            {"edge_kind": "method", "symbolic_owner": "demo/Concrete"},
            {
                "edge_kind": "method", "symbolic_owner": "demo/Api",
                "symbolic_name": "run", "symbolic_descriptor": "()V",
                "caller_member_identity": "missing",
            },
            {
                "edge_kind": "method", "symbolic_owner": "demo/Api",
                "symbolic_name": "run", "symbolic_descriptor": "()V",
                "caller_member_identity": caller["member_identity"],
            },
        ]

        builder.spring_data_and_bean_wiring()

        wiring = [
            row for row in builder.rows
            if row["semantic_edge_kind"] == "spring_bean_wiring_dispatch"
        ]
        self.assertEqual(len(wiring), 1)
        self.assertEqual(wiring[0]["target_member_identity"], "primary-run")
        self.assertEqual(wiring[0]["path_certainty"], "exact")
        self.assertTrue(wiring[0]["evidence"]["selected_by_primary"])

    def test_spring_bean_factory_resolution_and_unresolved_interface_matrix(self):
        builder = bare_builder(spring=True)
        bean = "Lorg/springframework/context/annotation/Bean;"
        product_interface = member("product-api", "demo/Product", "use", variant="product")
        install_class(
            builder, "app", "demo/Product", variant="product",
            access=semantic.ACC_INTERFACE, members=(product_interface,),
        )
        implementation = member("product-use", "demo/ProductImpl", "use", variant="product-impl")
        install_class(
            builder, "app", "demo/ProductImpl", variant="product-impl",
            interfaces=("demo/Product",), members=(implementation,),
        )
        install_class(
            builder, "app", "demo/UnknownProduct", variant="unknown-product",
            access=semantic.ACC_INTERFACE,
        )
        install_class(builder, "app", "demo/Concrete", variant="concrete")
        install_class(builder, "other", "demo/OtherRealm", variant="other-realm")
        factories = (
            member(
                "factory-product", "demo/Factory", "product", "()Ldemo/Product;",
                variant="factory", annotations=(annotation(bean), annotation(semantic.PRIMARY)),
            ),
            member(
                "factory-unresolved", "demo/Factory", "unresolved", "()Ldemo/UnknownProduct;",
                variant="factory", annotations=(annotation(bean),),
            ),
            member(
                "factory-concrete", "demo/Factory", "concrete", "()Ldemo/Concrete;",
                variant="factory", annotations=(annotation(bean),),
            ),
            member(
                "factory-primitive", "demo/Factory", "primitive", "()I",
                variant="factory", annotations=(annotation(bean),),
            ),
            member("factory-ordinary", "demo/Factory", "ordinary", variant="factory"),
        )
        install_class(
            builder, "app", "demo/Factory", variant="factory", members=factories,
            method_facts=(
                {
                    "contract": {"name": "product", "descriptor": "()Ldemo/Product;"},
                    "instructions": [
                        (), ("other", 0, 187, "demo/No"),
                        ("type", 1, 189, "demo/No"),
                        ("type", 2, 187, "demo/ProductImpl"),
                    ],
                },
                {"contract": {"name": "unresolved", "descriptor": "()Ldemo/UnknownProduct;"}, "instructions": []},
                {"contract": {"name": "concrete", "descriptor": "()Ldemo/Concrete;"}, "instructions": []},
                {"contract": {"name": "primitive", "descriptor": "()I"}, "instructions": []},
                {"contract": {"name": "ordinary", "descriptor": "()V"}, "instructions": []},
            ),
        )
        caller = member("factory-caller")
        builder.members[caller["member_identity"]] = caller
        builder.direct_edges = [{
            "edge_kind": "method", "symbolic_owner": "demo/Product",
            "symbolic_name": "use", "symbolic_descriptor": "()V",
            "caller_member_identity": caller["member_identity"],
        }]

        builder.spring_data_and_bean_wiring()

        self.assertIn(
            "spring_bean_factory_implementation_unresolved:factory-unresolved",
            builder.gaps,
        )
        wiring = [
            row for row in builder.rows
            if row["semantic_edge_kind"] == "spring_bean_wiring_dispatch"
        ]
        self.assertEqual([row["target_member_identity"] for row in wiring], ["product-use"])

    def test_spring_data_repository_default_and_custom_factory_paths(self):
        def execute(custom, *, spring=True):
            builder = bare_builder(spring=spring)
            repository = member("repository", "demo/Repo", "save", variant="repository")
            install_class(
                builder, "app", "demo/Repo", variant="repository",
                access=semantic.ACC_INTERFACE,
                interfaces=("org/springframework/data/repository/Repository",),
                members=(repository,),
            )
            target = member(
                "simple-save",
                "org/springframework/data/jpa/repository/support/SimpleJpaRepository",
                "save", "(Ljava/lang/Object;)Ljava/lang/Object;", variant="simple-repo",
            )
            install_class(
                builder, "app",
                "org/springframework/data/jpa/repository/support/SimpleJpaRepository",
                variant="simple-repo", artifact="library", members=(target,),
            )
            caller = member("repo-caller")
            builder.members[caller["member_identity"]] = caller
            builder.direct_edges = [
                {"edge_kind": "field", "symbolic_owner": "demo/Repo"},
                {
                    "edge_kind": "method", "symbolic_owner": "demo/Repo",
                    "symbolic_name": None, "symbolic_descriptor": None,
                    "caller_member_identity": caller["member_identity"],
                },
                {
                    "edge_kind": "method", "symbolic_owner": "demo/Repo",
                    "symbolic_name": "save",
                    "symbolic_descriptor": "(Ljava/lang/Object;)Ljava/lang/Object;",
                    "caller_member_identity": "missing",
                },
                {
                    "edge_kind": "method", "symbolic_owner": "demo/Repo",
                    "symbolic_name": "save",
                    "symbolic_descriptor": "(Ljava/lang/Object;)Ljava/lang/Object;",
                    "caller_member_identity": caller["member_identity"],
                },
            ]
            if custom:
                config = member("repo-config", "demo/RepoConfig", "config", variant="repo-config")
                install_class(
                    builder, "app", "demo/RepoConfig", variant="repo-config",
                    annotations=(annotation(
                        "Lorg/springframework/data/jpa/repository/config/EnableJpaRepositories;",
                        [["repositoryBaseClass", "demo.Custom"]],
                    ),),
                    members=(config,),
                )
            builder.spring_data_and_bean_wiring()
            return builder

        default = execute(False)
        repository_rows = [
            row for row in default.rows
            if row["semantic_edge_kind"] == "spring_data_repository_proxy_dispatch"
        ]
        self.assertEqual(len(repository_rows), 1)
        self.assertEqual(repository_rows[0]["path_certainty"], "exact")
        custom = execute(True)
        self.assertIn("spring_data_custom_repository_factory", custom.gaps)
        self.assertFalse(any(
            row["semantic_edge_kind"] == "spring_data_repository_proxy_dispatch"
            for row in custom.rows
        ))
        inactive = execute(False, spring=False)
        repository_rows = [
            row for row in inactive.rows
            if row["semantic_edge_kind"] == "spring_data_repository_proxy_dispatch"
        ]
        self.assertEqual(repository_rows[0]["path_certainty"], "possible")

    def test_remaining_spring_bean_activation_and_candidate_cross_products(self):
        for spring, main_class in ((True, "Main"), (False, "demo.app.Main")):
            builder = bare_builder(spring=spring)
            builder.profile.payload["business_entrypoint_profile"] = {
                "activated_frameworks": ["spring_boot"] if spring else [],
                "activated_resource_names": None,
                "activated_component_scan_packages": None,
                "main_class": main_class,
            }
            builder.spring_data_and_bean_wiring()

        builder = bare_builder(spring=True)
        builder.profile.payload["business_entrypoint_profile"] = None
        builder.spring_data_and_bean_wiring()

        component = annotation(next(iter(semantic.COMPONENT_ANNOTATIONS)))
        business_run = member(
            "business-run", "demo/BusinessImpl", "run", variant="business-impl",
        )
        install_class(
            builder, "app", "demo/BusinessImpl", variant="business-impl",
            interfaces=("demo/SingleApi",),
            annotations=(component, annotation(semantic.PRIMARY)),
            members=(business_run,),
        )
        conditional_run = member(
            "conditional-run", "demo/ConditionalImpl", "run", variant="conditional-impl",
        )
        install_class(
            builder, "app", "demo/ConditionalImpl", variant="conditional-impl",
            interfaces=("demo/ConditionalApi",),
            annotations=(
                component,
                annotation(
                    "Lorg/springframework/boot/autoconfigure/condition/ConditionalOnBean;"
                ),
            ),
            members=(conditional_run,),
        )
        install_class(
            builder, "app", "demo/SingleApi", variant="single-api",
            access=semantic.ACC_INTERFACE,
        )
        install_class(
            builder, "app", "demo/ConditionalApi", variant="conditional-api",
            access=semantic.ACC_INTERFACE,
        )
        config = member("empty-repo-config", "demo/EmptyRepoConfig", "config", variant="empty-repo-config")
        install_class(
            builder, "app", "demo/EmptyRepoConfig", variant="empty-repo-config",
            annotations=(annotation(
                "Lorg/springframework/data/jpa/repository/config/EnableJpaRepositories;"
            ),),
            members=(config,),
        )
        no_contract_factory = dict(
            member("no-contract-factory", "demo/Factories", "none", variant="factories"),
            contract_json=None,
        )
        direct_factory = member(
            "direct-factory", "demo/Factories", "direct", "()Ldemo/Direct;",
            variant="factories", annotations=(annotation(
                "Lorg/springframework/context/annotation/Bean;"
            ),),
        )
        library_factory = member(
            "library-factory", "demo/Factories", "library", "()Ldemo/LibraryConcrete;",
            artifact="library", variant="factories", annotations=(annotation(
                "Lorg/springframework/context/annotation/Bean;"
            ),),
        )
        install_class(builder, "app", "demo/Direct", variant="direct")
        install_class(builder, "app", "demo/LibraryConcrete", variant="library-concrete")
        install_class(
            builder, "app", "demo/Factories", variant="factories",
            members=(no_contract_factory, direct_factory, library_factory),
            method_facts=(
                {"contract": {"name": "none", "descriptor": "()V"}, "instructions": []},
                {
                    "contract": {"name": "direct", "descriptor": "()Ldemo/Direct;"},
                    "instructions": [("type", 0, 187, "demo/Direct")],
                },
                {
                    "contract": {"name": "library", "descriptor": "()Ldemo/LibraryConcrete;"},
                    "instructions": [],
                },
            ),
        )
        caller = member("cross-caller")
        builder.members[caller["member_identity"]] = caller
        builder.direct_edges = [
            {"edge_kind": "method", "symbolic_owner": None},
            {
                "edge_kind": "method", "symbolic_owner": "demo/SingleApi",
                "symbolic_name": None, "symbolic_descriptor": "()V",
                "caller_member_identity": caller["member_identity"],
            },
            {
                "edge_kind": "method", "symbolic_owner": "demo/SingleApi",
                "symbolic_name": "run", "symbolic_descriptor": "()V",
                "caller_member_identity": caller["member_identity"],
            },
            {
                "edge_kind": "method", "symbolic_owner": "demo/ConditionalApi",
                "symbolic_name": "run", "symbolic_descriptor": "()V",
                "caller_member_identity": caller["member_identity"],
            },
        ]
        builder.spring_data_and_bean_wiring()
        rows = [
            row for row in builder.rows
            if row["semantic_edge_kind"] == "spring_bean_wiring_dispatch"
        ]
        self.assertIn("business-run", {
            row["target_member_identity"] for row in rows
        })
        self.assertIn("conditional-run", {
            row["target_member_identity"] for row in rows
        })
        conditional = next(
            row for row in rows
            if row["target_member_identity"] == "conditional-run"
        )
        self.assertEqual(conditional["path_certainty"], "possible")

        def wiring_for(*, spring, primary_count):
            matrix = bare_builder(spring=spring)
            install_class(
                matrix, "app", "demo/MatrixApi", variant="matrix-api",
                access=semantic.ACC_INTERFACE,
            )
            for index in range(2):
                annotations = [component]
                if index < primary_count:
                    annotations.append(annotation(semantic.PRIMARY))
                target = member(
                    f"matrix-{index}", f"demo/Matrix{index}", "run",
                    variant=f"matrix-{index}",
                )
                install_class(
                    matrix, "app", f"demo/Matrix{index}", variant=f"matrix-{index}",
                    interfaces=("demo/MatrixApi",), annotations=tuple(annotations),
                    members=(target,),
                )
            matrix_caller = member("matrix-caller")
            matrix.members[matrix_caller["member_identity"]] = matrix_caller
            matrix.direct_edges = [{
                "edge_kind": "method", "symbolic_owner": "demo/MatrixApi",
                "symbolic_name": "run", "symbolic_descriptor": "()V",
                "caller_member_identity": matrix_caller["member_identity"],
            }]
            matrix.spring_data_and_bean_wiring()
            return matrix

        ambiguous = wiring_for(spring=True, primary_count=0)
        self.assertEqual(len(ambiguous.rows), 2)
        self.assertEqual({row["path_certainty"] for row in ambiguous.rows}, {"possible"})
        double_primary = wiring_for(spring=True, primary_count=2)
        self.assertEqual(len(double_primary.rows), 2)
        self.assertTrue(all(
            not row["evidence"]["selected_by_primary"]
            for row in double_primary.rows
        ))

        active_possible = bare_builder(spring=True)
        install_class(
            active_possible, "app", "demo/PossibleApi", variant="possible-api",
            access=semantic.ACC_INTERFACE,
        )
        possible_target = member(
            "active-possible-target", "outside/PossibleImpl", "run",
            artifact="library", variant="active-possible",
        )
        install_class(
            active_possible, "app", "outside/PossibleImpl",
            variant="active-possible", artifact="library",
            interfaces=("demo/PossibleApi",), annotations=(component,),
            members=(possible_target,),
        )
        possible_caller = member("active-possible-caller")
        active_possible.members[possible_caller["member_identity"]] = possible_caller
        active_possible.direct_edges = [{
            "edge_kind": "method", "symbolic_owner": "demo/PossibleApi",
            "symbolic_name": "run", "symbolic_descriptor": "()V",
            "caller_member_identity": possible_caller["member_identity"],
        }]
        active_possible.spring_data_and_bean_wiring()
        self.assertEqual(active_possible.rows[0]["path_certainty"], "possible")

    def test_spring_aop_pointcut_filters_exact_possible_and_unsupported_matrix(self):
        builder = bare_builder(spring=True)
        before = next(iter(semantic.ADVICE_ANNOTATIONS))
        aspect_members = (
            member("ordinary-advice", "demo/Aspect", "ordinary", variant="aspect"),
            dict(
                member("no-contract-advice", "demo/Aspect", "noContract", variant="aspect"),
                contract_json=None,
            ),
            member(
                "other-annotation-advice", "demo/Aspect", "otherAnnotation",
                variant="aspect", annotations=(annotation("Ldemo/Other;"),),
            ),
            member(
                "empty-advice", "demo/Aspect", "empty", variant="aspect",
                annotations=(annotation(before, None),),
            ),
            member(
                "unsupported-advice", "demo/Aspect", "unsupported", variant="aspect",
                annotations=(annotation(before, [["value", "not-a-pointcut"]]),),
            ),
            member(
                "exact-advice", "demo/Aspect", "exact", variant="aspect",
                annotations=(annotation(before, [[
                    "value",
                    "execution(* demo.Target.run(..)) && "
                    "@within(demo.RequiredClass) && "
                    "@annotation(demo.RequiredMethod) && "
                    "!@annotation(demo.Excluded)",
                ]]),),
            ),
            member(
                "possible-advice", "demo/Aspect", "possible", variant="aspect",
                annotations=(annotation(before, [[
                    "value",
                    "execution(* demo.Target.run(..)) || "
                    "execution(* demo.Other.run(..))",
                ]]),),
            ),
        )
        install_class(
            builder, "app", "demo/Aspect", variant="aspect",
            annotations=(annotation(semantic.ASPECT_ANNOTATION),),
            members=aspect_members,
        )
        required_class = annotation("Ldemo/RequiredClass;")
        required_method = annotation("Ldemo/RequiredMethod;")
        excluded_method = annotation("Ldemo/Excluded;")
        valid = member(
            "target-valid", "demo/Target", "run", variant="target",
            annotations=(required_method,),
        )
        excluded = member(
            "target-excluded", "demo/Target", "run", "(I)V", variant="target",
            annotations=(required_method, excluded_method),
        )
        missing_method = member(
            "target-no-method-annotation", "demo/Target", "run", "(J)V", variant="target",
        )
        constructor = member("target-constructor", "demo/Target", "<init>", variant="target")
        wrong_name = member("target-wrong-name", "demo/Target", "other", variant="target")
        empty_name = member("target-empty-name", "demo/Target", None, "(B)V", variant="target")
        no_contract = dict(
            member("target-no-contract", "demo/Target", "run", "(S)V", variant="target"),
            contract_json=None,
        )
        install_class(
            builder, "app", "demo/Target", variant="target",
            annotations=(required_class,),
            members=(
                valid, excluded, missing_method, constructor, wrong_name,
                empty_name, no_contract,
            ),
        )
        wrong_class = member(
            "wrong-class", "demo/WrongClass", "run", variant="wrong-class",
            annotations=(required_method,),
        )
        install_class(
            builder, "app", "demo/WrongClass", variant="wrong-class",
            members=(wrong_class,),
        )
        other_realm = member(
            "other-realm-target", "demo/Target", "run", variant="other-target",
            annotations=(required_method,),
        )
        install_class(
            builder, "other", "demo/Target", variant="other-target",
            annotations=(required_class,), members=(other_realm,),
        )

        builder.spring_aop_and_security()

        aop_rows = [
            row for row in builder.rows
            if row["semantic_edge_kind"] == "spring_aop_dispatch"
        ]
        self.assertIn(
            ("target-valid", "exact-advice", "exact"),
            {
                (
                    row["caller_member_identity"], row["target_member_identity"],
                    row["path_certainty"],
                )
                for row in aop_rows
            },
        )
        self.assertTrue(any(
            row["target_member_identity"] == "possible-advice"
            and row["path_certainty"] == "possible"
            for row in aop_rows
        ))
        self.assertFalse(any(
            row["caller_member_identity"] in {
                "target-excluded", "target-no-method-annotation",
                "target-constructor", "target-wrong-name", "wrong-class",
                "other-realm-target",
            }
            and row["target_member_identity"] == "exact-advice"
            for row in aop_rows
        ))
        self.assertIn("spring_aop_pointcut_unsupported:unsupported-advice", builder.gaps)
        self.assertIn("spring_aop_pointcut_unsupported:empty-advice", builder.gaps)
        self.assertIn("spring_aop_pointcut_unsupported:possible-advice", builder.gaps)

        inactive = bare_builder()
        inactive_advice = member(
            "inactive-advice", "demo/InactiveAspect", "before", variant="inactive-aspect",
            annotations=(annotation(before, [["value", "execution(* demo.Target.run(..))"]]),),
        )
        install_class(
            inactive, "app", "demo/InactiveAspect", variant="inactive-aspect",
            annotations=(annotation(semantic.ASPECT_ANNOTATION),), members=(inactive_advice,),
        )
        inactive_target = member("inactive-target", "demo/Target", "run", variant="inactive-target")
        install_class(
            inactive, "app", "demo/Target", variant="inactive-target",
            members=(inactive_target,),
        )
        inactive.spring_aop_and_security()
        self.assertEqual(inactive.rows[0]["path_certainty"], "possible")

        library_aspect = bare_builder(spring=True)
        library_advice = member(
            "library-advice", "demo/LibraryAspect", "before",
            artifact="library", variant="library-aspect",
            annotations=(annotation(before, [["value", "execution(* demo.Target.run(..))"]]),),
        )
        install_class(
            library_aspect, "app", "demo/LibraryAspect", variant="library-aspect",
            artifact="library", annotations=(annotation(semantic.ASPECT_ANNOTATION),),
            members=(library_advice,),
        )
        library_target = member(
            "library-aspect-target", "demo/Target", "run", variant="library-target",
        )
        install_class(
            library_aspect, "app", "demo/Target", variant="library-target",
            members=(library_target,),
        )
        library_aspect.spring_aop_and_security()
        self.assertEqual(library_aspect.rows[0]["path_certainty"], "possible")

        missing_class_annotation = bare_builder(spring=True)
        guarded_advice = member(
            "guarded-advice", "demo/GuardedAspect", "before",
            variant="guarded-aspect", annotations=(annotation(before, [[
                "value",
                "execution(* demo.Target.run(..)) && @within(demo.RequiredClass)",
            ]]),),
        )
        install_class(
            missing_class_annotation, "app", "demo/GuardedAspect",
            variant="guarded-aspect",
            annotations=(annotation(semantic.ASPECT_ANNOTATION),),
            members=(guarded_advice,),
        )
        unguarded_target = member(
            "unguarded-target", "demo/Target", "run", variant="unguarded-target",
        )
        install_class(
            missing_class_annotation, "app", "demo/Target",
            variant="unguarded-target", members=(unguarded_target,),
        )
        missing_class_annotation.spring_aop_and_security()
        self.assertEqual(missing_class_annotation.rows, [])

    def test_spring_security_filter_factory_registration_matrix(self):
        def execute(*, spring, artifact):
            builder = bare_builder(spring=spring)
            bean = "Lorg/springframework/context/annotation/Bean;"
            factories = (
                dict(
                    member("security-ordinary", "demo/Security", "ordinary", variant="security"),
                    contract_json=None,
                ),
                member(
                    "security-wrong-return", "demo/Security", "wrong",
                    "()Ljava/lang/String;", variant="security",
                    annotations=(annotation(bean),),
                ),
                member(
                    "security-no-registration", "demo/Security", "empty",
                    "()Lorg/springframework/security/web/SecurityFilterChain;",
                    variant="security", annotations=(annotation(bean),),
                ),
                member(
                    "security-chain", "demo/Security", "chain",
                    "()Lorg/springframework/security/web/SecurityFilterChain;",
                    variant="security", annotations=(annotation(bean),),
                ),
            )
            install_class(
                builder, "app", "demo/Security", variant="security",
                artifact=artifact, members=factories,
                method_facts=(
                    {"contract": {"name": "ordinary", "descriptor": "()V"}, "instructions": []},
                    {"contract": {"name": "wrong", "descriptor": "()Ljava/lang/String;"}, "instructions": []},
                    {"contract": {"name": "empty", "descriptor": "()Lorg/springframework/security/web/SecurityFilterChain;"}, "instructions": []},
                    {
                        "contract": {"name": "chain", "descriptor": "()Lorg/springframework/security/web/SecurityFilterChain;"},
                        "instructions": [
                            (), ("type",), ("type", 0, 189, "demo/NotNew"),
                            ("type", 1, 187, "demo/NotFilter"),
                            ("type", 2, 187, "demo/Filter"),
                            ("type", 3, 187, "demo/NoCallbackFilter"),
                            ("method", 4, 182, "security/Builder", "ignored", "()V"),
                            ("method", 5, 182, "security/Builder", "addFilterBefore", "()V"),
                        ],
                    },
                ),
            )
            install_class(builder, "app", "demo/NotFilter", variant="not-filter")
            callback = member("filter-callback", "demo/Filter", "doFilter", variant="filter")
            install_class(
                builder, "app", "demo/Filter", variant="filter",
                interfaces=("jakarta/servlet/Filter",), members=(callback,),
            )
            install_class(
                builder, "app", "demo/NoCallbackFilter", variant="no-callback-filter",
                interfaces=("javax/servlet/Filter",),
            )
            builder.spring_aop_and_security()
            return builder

        exact = execute(spring=True, artifact="business")
        security = [
            row for row in exact.rows
            if row["semantic_edge_kind"] == "spring_security_filter_dispatch"
        ]
        self.assertEqual(len(security), 1)
        self.assertEqual(security[0]["path_certainty"], "exact")
        possible = execute(spring=False, artifact="library")
        security = [
            row for row in possible.rows
            if row["semantic_edge_kind"] == "spring_security_filter_dispatch"
        ]
        self.assertEqual(security[0]["path_certainty"], "possible")
        active_library = execute(spring=True, artifact="library")
        security = [
            row for row in active_library.rows
            if row["semantic_edge_kind"] == "spring_security_filter_dispatch"
        ]
        self.assertEqual(security[0]["path_certainty"], "possible")

    def test_declarative_clients_support_class_and_method_annotations(self):
        target = member("feign-runtime", "feign/SynchronousMethodHandler", "invoke")
        builder = bare_builder(spring=True)
        class_method = member("class-client", "demo/ClassClient", "call", variant="class-client")
        method_method = member(
            "method-client", "demo/MethodClient", "call", variant="method-client",
            annotations=(annotation("Lfeign/RequestLine;"),),
        )
        ignored_method = member("ignored-client", "demo/IgnoredClient", "call", variant="ignored-client")
        install_class(
            builder, "app", "demo/ClassClient", variant="class-client",
            annotations=(annotation("Lorg/springframework/cloud/openfeign/FeignClient;"),),
            members=(class_method,),
        )
        install_class(
            builder, "app", "demo/MethodClient", variant="method-client",
            members=(method_method,),
        )
        install_class(
            builder, "app", "demo/IgnoredClient", variant="ignored-client",
            members=(ignored_method,),
        )
        with patch.object(
            builder, "_unique_targets",
            side_effect=lambda owner, _name: (
                [("app", target)] if owner == "feign/SynchronousMethodHandler" else []
            ),
        ):
            builder.declarative_clients()
        self.assertEqual(
            {row["caller_member_identity"] for row in builder.rows},
            {"class-client", "method-client"},
        )
        self.assertEqual({row["path_certainty"] for row in builder.rows}, {"exact"})

        inactive = bare_builder()
        install_class(
            inactive, "app", "demo/MethodClient", variant="method-client",
            members=(method_method,),
        )
        with patch.object(inactive, "_unique_targets", return_value=[]):
            inactive.declarative_clients()
        self.assertEqual(inactive.rows, [])
        no_runtime = bare_builder(spring=True)
        no_contract = dict(method_method, member_identity="no-contract", contract_json=None)
        install_class(
            no_runtime, "app", "demo/ClassClient", variant="no-runtime-client",
            annotations=(annotation("Lorg/springframework/cloud/openfeign/FeignClient;"),),
            members=(dict(no_contract, class_variant_identity="no-runtime-client"),),
        )
        with patch.object(no_runtime, "_unique_targets", return_value=[]):
            no_runtime.declarative_clients()
        self.assertEqual(no_runtime.rows, [])

    def test_dubbo_spi_resource_edge_and_provider_cardinality_matrix(self):
        builder = bare_builder()
        caller = member("dubbo-caller")
        callback = member("dubbo-callback", "demo/Provider", "execute", variant="provider")
        constructor = member("dubbo-constructor", "demo/Provider", "<init>", variant="provider")
        install_class(
            builder, "app", "demo/Provider", variant="provider",
            members=(callback, constructor),
        )
        builder.members[caller["member_identity"]] = caller
        builder.resource_facts = [
            {"realm": "app", "name": "META-INF/services/demo.Service", "facts": (("ordered_entry", "demo.Provider"),)},
            {"realm": "app", "name": "META-INF/dubbo/demo.Service", "facts": (("ignored", "x"),)},
            {"realm": "app", "name": "META-INF/dubbo/demo.Service", "facts": (("ordered_entry", "named=demo.Provider"),)},
            {"realm": "app", "name": "META-INF/dubbo/internal/demo.Other", "facts": (("ordered_entry", ""),)},
        ]
        builder.direct_edges = [
            {"edge_kind": "field"},
            {"edge_kind": "method", "symbolic_owner": "other", "symbolic_name": "getExtension"},
            {
                "edge_kind": "method",
                "symbolic_owner": "org/apache/dubbo/common/extension/ExtensionLoader",
                "symbolic_name": "unknown",
            },
            {
                "direct_edge_identity": "missing-caller",
                "edge_kind": "method",
                "symbolic_owner": "org/apache/dubbo/common/extension/ExtensionLoader",
                "symbolic_name": "getExtension",
                "caller_member_identity": "missing",
            },
            {
                "direct_edge_identity": "dubbo-edge",
                "edge_kind": "method",
                "symbolic_owner": "org/apache/dubbo/common/extension/ExtensionLoader",
                "symbolic_name": "getAdaptiveExtension",
                "caller_member_identity": caller["member_identity"],
            },
        ]
        builder.dubbo_spi()
        self.assertEqual(len(builder.rows), 1)
        self.assertEqual(builder.rows[0]["semantic_edge_kind"], "dubbo_spi_dispatch")
        self.assertEqual(builder.rows[0]["path_certainty"], "exact")

        builder.rows.clear()
        builder.seen.clear()
        builder.resource_facts.append({
            "realm": "other", "name": "META-INF/dubbo/demo.Second",
            "facts": (("ordered_entry", "demo.Provider"),),
        })
        builder.dubbo_spi()
        self.assertEqual(builder.rows[0]["path_certainty"], "possible")

    def test_implicit_data_contract_existing_symbolic_and_direct_boundaries(self):
        none_builder = bare_builder()
        none_builder.implicit_data_contracts()
        self.assertEqual(none_builder.rows, [])

        builder = bare_builder()
        endpoint = member(
            "endpoint", "demo/Controller", "post",
            "(Ldemo/Dto;I)Ldemo/Response;", variant="controller",
            annotations=(annotation("Lorg/springframework/web/bind/annotation/PostMapping;"),),
        )
        ordinary = member("ordinary", "demo/Controller", "ordinary", variant="controller")
        install_class(
            builder, "app", "demo/Controller", variant="controller",
            members=(endpoint, ordinary),
        )
        dto_field = member(
            "dto-field", "demo/Dto", "removed", "Ljava/lang/String;",
            variant="dto", kind="field",
        )
        install_class(
            builder, "app", "demo/Dto", variant="dto", members=(dto_field,),
        )
        direct = member("jackson-caller", "demo/Json", "read", variant="json")
        builder.members[direct["member_identity"]] = direct
        builder.direct_edges = [
            {"edge_kind": "field"},
            {"edge_kind": "method", "symbolic_owner": "other", "symbolic_name": "readValue"},
            {
                "edge_kind": "method",
                "symbolic_owner": "com/fasterxml/jackson/databind/ObjectMapper",
                "symbolic_name": "readValue",
                "caller_member_identity": "missing",
            },
            {
                "edge_kind": "method",
                "symbolic_owner": "com/fasterxml/jackson/databind/ObjectMapper",
                "symbolic_name": "writeValueAsString",
                "caller_member_identity": direct["member_identity"],
            },
        ]
        builder.decisions = SimpleNamespace(
            authoritative_decisions=(
                {"fact_scope": None},
                {"fact_scope": {"member_kind": "method"}},
                {"fact_scope": {"member_kind": "field", "class_name": "demo/Dto", "member_name": "removed", "descriptor": "Ljava/lang/String;"}},
            ),
            diagnostic_decisions=(
                {"fact_scope": {"member_kind": "field", "class_name": "demo/Missing", "member_name": None, "descriptor": None}},
            ),
        )

        builder.implicit_data_contracts()

        pairs = {
            (row["caller_member_identity"], row["target_member_identity"])
            for row in builder.rows
        }
        self.assertIn(("endpoint", "dto-field"), pairs)
        self.assertNotIn(("jackson-caller", "dto-field"), pairs)
        symbolic = [
            row for row in builder.rows
            if row["target_class_name"] == "demo/Missing"
        ]
        self.assertEqual(symbolic, [])

        missing_endpoint = member(
            "missing-endpoint", "demo/MissingController", "post",
            "(Ldemo/Missing;)V", variant="missing-controller",
            annotations=(annotation("Lorg/springframework/web/bind/annotation/PostMapping;"),),
        )
        broken_endpoint = member(
            "broken-endpoint", "demo/MissingController", "broken", "broken",
            variant="missing-controller",
            annotations=(annotation("Lorg/springframework/web/bind/annotation/PostMapping;"),),
        )
        no_contract_endpoint = dict(
            broken_endpoint, member_identity="no-contract-endpoint",
            member_name="noContract", contract_json=None,
        )
        install_class(
            builder, "app", "demo/MissingController", variant="missing-controller",
            members=(missing_endpoint, broken_endpoint, no_contract_endpoint),
        )
        builder.selected[("app", "demo/Dto")][0]
        builder.members_by_variant["dto"].extend((
            member("dto-method", "demo/Dto", "removed", variant="dto"),
            member("dto-other-field", "demo/Dto", "other", variant="dto", kind="field"),
        ))
        builder.decisions = SimpleNamespace(
            authoritative_decisions=(
                {
                    "fact_scope": {
                        "member_kind": "field", "class_name": "demo/Missing",
                        "member_name": "unknown", "descriptor": "I",
                    },
                },
                {
                    "fact_scope": {
                        "member_kind": "field", "class_name": "demo/Dto",
                        "member_name": "removed", "descriptor": "Ljava/lang/String;",
                    },
                },
                {
                    "fact_scope": {
                        "member_kind": "field", "class_name": None,
                        "member_name": None, "descriptor": None,
                    },
                },
            ),
            diagnostic_decisions=(),
        )
        builder.rows.clear()
        builder.seen.clear()
        builder.implicit_data_contracts()
        symbolic = [
            row for row in builder.rows
            if row["target_class_name"] == "demo/Missing"
        ]
        self.assertEqual(
            {row["caller_member_identity"] for row in symbolic},
            {"missing-endpoint"},
        )
        self.assertEqual(
            {row["target_member_name"] for row in symbolic}, {"unknown"},
        )


if __name__ == "__main__":
    unittest.main()
