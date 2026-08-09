#!/usr/bin/env python3
"""Discover runtime entrypoints from selected final-artifact classfile facts.

The tracer must not depend on users enumerating every framework callback.  This
module turns runtime-visible annotations, implemented callback interfaces and
selected Spring Boot registration resources into exact or possible roots.  A
dependency callback is exact only when the current runtime view also proves its
activation; a declaration without activation evidence remains possible.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping

from binary_first_contract import canonical_identity


DISCOVERY_POLICY_VERSION = "binary-entrypoint-discovery-v1"


METHOD_ANNOTATION_KINDS = {
    "Lorg/springframework/scheduling/annotation/Scheduled;": "spring_scheduled",
    "Lorg/springframework/scheduling/annotation/Schedules;": "spring_scheduled",
    "Lorg/springframework/context/event/EventListener;": "spring_event_listener",
    "Lorg/springframework/kafka/annotation/KafkaListener;": "spring_message_listener",
    "Lorg/springframework/amqp/rabbit/annotation/RabbitListener;": "spring_message_listener",
    "Lorg/springframework/amqp/rabbit/annotation/RabbitHandler;": "spring_message_listener",
    "Lorg/springframework/jms/annotation/JmsListener;": "spring_message_listener",
    "Lorg/apache/rocketmq/spring/annotation/RocketMQMessageListener;": "spring_message_listener",
    "Ljavax/annotation/PostConstruct;": "lifecycle_callback",
    "Ljakarta/annotation/PostConstruct;": "lifecycle_callback",
    "Ljavax/persistence/PrePersist;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PostPersist;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PreUpdate;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PostUpdate;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PreRemove;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PostRemove;": "jpa_lifecycle_callback",
    "Ljavax/persistence/PostLoad;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PrePersist;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PostPersist;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PreUpdate;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PostUpdate;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PreRemove;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PostRemove;": "jpa_lifecycle_callback",
    "Ljakarta/persistence/PostLoad;": "jpa_lifecycle_callback",
    "Lorg/springframework/web/bind/annotation/RequestMapping;": "spring_web_endpoint",
    "Lorg/springframework/web/bind/annotation/GetMapping;": "spring_web_endpoint",
    "Lorg/springframework/web/bind/annotation/PostMapping;": "spring_web_endpoint",
    "Lorg/springframework/web/bind/annotation/PutMapping;": "spring_web_endpoint",
    "Lorg/springframework/web/bind/annotation/DeleteMapping;": "spring_web_endpoint",
    "Lorg/springframework/web/bind/annotation/PatchMapping;": "spring_web_endpoint",
    "Lorg/springframework/context/annotation/Bean;": "spring_bean_initialization",
}

CLASS_TRIGGER_ANNOTATION_KINDS = {
    "Lorg/apache/rocketmq/spring/annotation/RocketMQMessageListener;": (
        "spring_message_listener",
        ("onMessage",),
    ),
    "Lorg/springframework/amqp/rabbit/annotation/RabbitListener;": (
        "spring_message_listener",
        ("handleMessage", "onMessage"),
    ),
}

INTERFACE_CALLBACKS = {
    "org/springframework/boot/ApplicationRunner": {
        "run": "spring_application_runner",
    },
    "org/springframework/boot/CommandLineRunner": {
        "run": "spring_command_line_runner",
    },
    "org/springframework/context/ApplicationListener": {
        "onApplicationEvent": "spring_application_listener",
    },
    "org/springframework/context/Lifecycle": {
        "start": "spring_lifecycle_callback",
        "stop": "spring_lifecycle_callback",
    },
    "org/springframework/context/SmartLifecycle": {
        "start": "spring_lifecycle_callback",
        "stop": "spring_lifecycle_callback",
    },
    "org/springframework/beans/factory/InitializingBean": {
        "afterPropertiesSet": "spring_lifecycle_callback",
    },
    "org/springframework/web/servlet/HandlerInterceptor": {
        "preHandle": "spring_web_interceptor",
        "postHandle": "spring_web_interceptor",
        "afterCompletion": "spring_web_interceptor",
    },
    "org/springframework/core/convert/converter/Converter": {
        "convert": "spring_conversion_callback",
    },
    "org/springframework/format/Formatter": {
        "parse": "spring_conversion_callback",
        "print": "spring_conversion_callback",
    },
    "javax/servlet/Servlet": {"service": "servlet_endpoint"},
    "jakarta/servlet/Servlet": {"service": "servlet_endpoint"},
    "javax/servlet/Filter": {"doFilter": "servlet_filter"},
    "jakarta/servlet/Filter": {"doFilter": "servlet_filter"},
    "javax/servlet/ServletContextListener": {
        "contextInitialized": "servlet_lifecycle_callback",
        "contextDestroyed": "servlet_lifecycle_callback",
    },
    "jakarta/servlet/ServletContextListener": {
        "contextInitialized": "servlet_lifecycle_callback",
        "contextDestroyed": "servlet_lifecycle_callback",
    },
    "org/quartz/Job": {
        "execute": "quartz_job",
    },
}

CONDITIONAL_ANNOTATION_PREFIXES = (
    "Lorg/springframework/boot/autoconfigure/condition/Conditional",
    "Lorg/springframework/context/annotation/Conditional;",
)

AUTO_CONFIGURATION_RESOURCES = frozenset({
    "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports",
})

AUTO_CONFIGURATION_FACT_KEYS = frozenset({
    "org.springframework.boot.autoconfigure.EnableAutoConfiguration",
    "org.springframework.boot.autoconfigure.AutoConfiguration",
})

SPRING_FACTORIES_CALLBACKS = {
    "org.springframework.context.ApplicationListener": (
        "onApplicationEvent", "spring_application_listener",
    ),
    "org.springframework.boot.env.EnvironmentPostProcessor": (
        "postProcessEnvironment", "spring_environment_post_processor",
    ),
    "org.springframework.context.ApplicationContextInitializer": (
        "initialize", "spring_application_context_initializer",
    ),
}

BUSINESS_PATH_KINDS = frozenset({
    "application",
    "application_classes",
    "business",
    "business_classes",
})

ACC_PUBLIC = 0x0001
ACC_STATIC = 0x0008


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _loads(value: str) -> Any:
    return json.loads(value or "{}")


def _annotations(payload: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    return tuple(
        dict(item)
        for item in payload.get("annotations") or ()
        if isinstance(item, Mapping) and item.get("visible") is not False
    )


def _annotation_descriptors(payload: Mapping[str, Any]) -> set[str]:
    return {
        str(item.get("descriptor") or "")
        for item in _annotations(payload)
        if str(item.get("descriptor") or "")
    }


def _descriptor_class_name(descriptor: str) -> str:
    descriptor = str(descriptor or "")
    return descriptor[1:-1] if descriptor.startswith("L") and descriptor.endswith(";") else ""


def _type_descriptors(value: Any) -> set[str]:
    result = set()
    if isinstance(value, Mapping):
        if value.get("kind") == "type" and value.get("descriptor"):
            result.add(str(value["descriptor"]))
        for nested in value.values():
            result.update(_type_descriptors(nested))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            result.update(_type_descriptors(nested))
    return result


def _annotation_closure(
    realm: str,
    descriptors: set[str],
    selected_classes: Mapping[
        tuple[str, str], tuple[Mapping[str, Any], Mapping[str, Any]]
    ],
) -> set[str]:
    """Resolve runtime meta-annotations from the selected class universe."""

    result = set(descriptors)
    pending = list(sorted(descriptors))
    while pending:
        descriptor = pending.pop()
        annotation_name = _descriptor_class_name(descriptor)
        selected = selected_classes.get((realm, annotation_name))
        if selected is None:
            continue
        for nested in _annotation_descriptors(selected[1]):
            if nested not in result:
                result.add(nested)
                pending.append(nested)
    return result


def _is_conditional(descriptors: set[str]) -> bool:
    return any(
        descriptor.startswith(CONDITIONAL_ANNOTATION_PREFIXES)
        for descriptor in descriptors
    )


def _hierarchy_types(
    realm: str,
    class_name: str,
    selected_classes: Mapping[
        tuple[str, str], tuple[Mapping[str, Any], Mapping[str, Any]]
    ],
) -> set[str]:
    """Return the selected superclass/interface closure for one class."""

    result: set[str] = set()
    pending = [class_name]
    seen = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        selected = selected_classes.get((realm, current))
        if selected is None:
            continue
        fact = selected[1]
        parents = [
            str(value or "")
            for value in (
                fact.get("super_name"),
                *(fact.get("interfaces") or ()),
            )
            if str(value or "") and str(value or "") != "java/lang/Object"
        ]
        for parent in parents:
            if parent not in result:
                result.add(parent)
                pending.append(parent)
    return result


def _annotation_imports(
    realm: str,
    annotations: tuple[dict[str, Any], ...],
    selected_classes: Mapping[
        tuple[str, str], tuple[Mapping[str, Any], Mapping[str, Any]]
    ],
) -> set[str]:
    """Resolve direct and composed Spring ``@Import`` declarations."""

    imported = set()
    pending = list(annotations)
    visited_annotation_types = set()
    while pending:
        item = pending.pop()
        descriptor = str(item.get("descriptor") or "")
        if descriptor == "Lorg/springframework/context/annotation/Import;":
            for value_descriptor in _type_descriptors(item.get("values") or ()):
                class_name = _descriptor_class_name(value_descriptor)
                if class_name:
                    imported.add(class_name)
            continue
        annotation_name = _descriptor_class_name(descriptor)
        if not annotation_name or annotation_name in visited_annotation_types:
            continue
        visited_annotation_types.add(annotation_name)
        selected = selected_classes.get((realm, annotation_name))
        if selected is not None:
            pending.extend(_annotations(selected[1]))
    return imported


def _is_business_artifact(artifact: Mapping[str, Any]) -> bool:
    if str(artifact.get("runtime_path_kind") or "").lower() in BUSINESS_PATH_KINDS:
        return True
    return str(artifact.get("coord") or "").strip().lower() in {
        "business", "application", "business:application",
    }


def _selected_auto_configuration_classes(reconciliation: Any) -> set[str]:
    result = set()
    for selection in getattr(reconciliation, "resource_selections", ()):
        name = str(selection.get("resource_name") or "")
        if selection.get("resource_selection_status") != "resolved":
            continue
        for selected in selection.get("selected_resources") or ():
            for raw_key, raw_value in selected.get("resource_semantic_facts") or ():
                key = str(raw_key or "")
                value = str(raw_value or "").strip()
                if not value:
                    continue
                if name in AUTO_CONFIGURATION_RESOURCES and key == "ordered_entry":
                    result.add(value.replace(".", "/"))
                elif key.startswith("property_entry:"):
                    property_key = key.removeprefix("property_entry:")
                    if property_key in AUTO_CONFIGURATION_FACT_KEYS:
                        result.add(value.replace(".", "/"))
    return result


def _selected_spring_factories_callbacks(
    reconciliation: Any,
) -> dict[str, set[tuple[str, str]]]:
    result: dict[str, set[tuple[str, str]]] = {}
    for selection in getattr(reconciliation, "resource_selections", ()):
        if (
            selection.get("resource_selection_status") != "resolved"
            or selection.get("resource_name") != "META-INF/spring.factories"
        ):
            continue
        for selected in selection.get("selected_resources") or ():
            for raw_key, raw_value in selected.get("resource_semantic_facts") or ():
                key = str(raw_key or "")
                if not key.startswith("property_entry:"):
                    continue
                registration = key.removeprefix("property_entry:")
                callback = SPRING_FACTORIES_CALLBACKS.get(registration)
                class_name = str(raw_value or "").strip().replace(".", "/")
                if callback and class_name:
                    result.setdefault(class_name, set()).add(callback)
    return result


def _spring_boot_activation_status(
    store: Any,
    runtime_profile: Any,
    artifacts: Mapping[str, Mapping[str, Any]],
    selected_class_variants: set[str],
    exact_main_classes: set[str],
) -> tuple[str, tuple[dict[str, Any], ...]]:
    """Prove Boot startup from the selected business bytecode or explicit profile."""

    profile = runtime_profile.payload.get("business_entrypoint_profile") or {}
    declared = {
        str(value or "").strip().lower()
        for value in profile.get("activated_frameworks") or ()
    }
    if "spring_boot" in declared:
        return "exact", ({"kind": "runtime_profile", "framework": "spring_boot"},)
    launcher = str(
        runtime_profile.payload.get("container_and_launcher_kind") or ""
    ).lower()
    if launcher in {"spring-boot", "spring_boot", "spring-boot-launcher"}:
        return "exact", ({"kind": "launcher", "value": launcher},)

    members = {
        row["member_identity"]: row
        for row in store.rows("members")
        if row.get("class_variant_identity") in selected_class_variants
    }
    declared_methods = {
        (
            str(item.get("class_name") or "").replace(".", "/"),
            str(item.get("member_name") or ""),
            str(item.get("descriptor") or ""),
        )
        for item in profile.get("methods") or ()
        if isinstance(item, Mapping)
    }
    evidence = []
    for edge in store.rows("direct_edges"):
        if (
            edge.get("edge_kind") != "method"
            or edge.get("symbolic_owner") != "org/springframework/boot/SpringApplication"
            or edge.get("symbolic_name") != "run"
        ):
            continue
        caller = members.get(edge.get("caller_member_identity"))
        artifact = artifacts.get((caller or {}).get("artifact_instance_identity")) or {}
        if caller is None or not _is_business_artifact(artifact):
            continue
        caller_key = (
            str(caller.get("class_name") or ""),
            str(caller.get("member_name") or ""),
            str(caller.get("descriptor") or ""),
        )
        selected_launcher_call = (
            caller_key in declared_methods
            or (
                caller_key[0] in exact_main_classes
                and caller_key[1:] == ("main", "([Ljava/lang/String;)V")
            )
        )
        if not selected_launcher_call:
            continue
        evidence.append({
            "kind": "business_bytecode_call",
            "caller_class_name": str(caller.get("class_name") or ""),
            "caller_member_name": str(caller.get("member_name") or ""),
            "caller_descriptor": str(caller.get("descriptor") or ""),
            "direct_edge_identity": str(edge.get("direct_edge_identity") or ""),
        })
    return ("exact", tuple(evidence)) if evidence else ("unproven", ())


@dataclass(frozen=True)
class BinaryEntrypointDiscoveryResult:
    exact_member_identities: tuple[str, ...]
    possible_member_identities: tuple[str, ...]
    records: tuple[dict[str, Any], ...]
    coverage_status: str
    coverage_gaps: tuple[str, ...]
    identity: str

    def as_payload(self) -> dict[str, Any]:
        return {
            "schema": "java-upgrade-analyzer.binary-entrypoint-discovery.v1",
            "discovery_policy_version": DISCOVERY_POLICY_VERSION,
            "entrypoint_discovery_identity": self.identity,
            "coverage_status": self.coverage_status,
            "coverage_gaps": list(self.coverage_gaps),
            "exact_entrypoint_count": len(self.exact_member_identities),
            "possible_entrypoint_count": len(self.possible_member_identities),
            "records": list(self.records),
        }


def discover_binary_entrypoints(
    store: Any,
    runtime_profile: Any,
    reconciliation: Any,
) -> BinaryEntrypointDiscoveryResult:
    """Discover exact and possible callback roots in the selected runtime view."""

    artifacts = {
        row["artifact_instance_identity"]: row
        for row in store.rows("artifact_instances")
    }
    class_rows = {
        row["class_variant_identity"]: row
        for row in store.rows("classes")
    }
    members_by_variant: dict[str, list[dict[str, Any]]] = {}
    for row in store.rows("members"):
        if row.get("member_kind") == "method":
            members_by_variant.setdefault(row["class_variant_identity"], []).append(row)
    providers = {
        (
            str(item.get("initiating_loader_realm_identity") or ""),
            str(item.get("class_name") or ""),
        ): item
        for item in getattr(reconciliation, "provider_bindings", ())
        if item.get("class_provider_status") == "resolved"
    }
    selected_classes: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    for (realm, class_name), provider in providers.items():
        class_row = class_rows.get(provider.get("selected_class_variant_identity"))
        if class_row is None:
            continue
        selected_classes[(realm, class_name)] = (
            class_row,
            _loads(class_row.get("fact_json") or "{}"),
        )
    selected_class_variants = {
        str(row.get("class_variant_identity") or "")
        for row, _fact in selected_classes.values()
    }

    profile = runtime_profile.payload.get("business_entrypoint_profile") or {}
    coverage_gaps = set()
    if not isinstance(profile, Mapping):
        profile = {}
        coverage_gaps.add("entrypoint_profile_invalid")
    if profile.get("coverage_status") not in {None, "complete"}:
        coverage_gaps.add("declared_entrypoint_coverage_incomplete")

    registered_auto_configurations = _selected_auto_configuration_classes(reconciliation)
    spring_factories_callbacks = _selected_spring_factories_callbacks(reconciliation)
    exact_main_classes = {
        str(profile.get("main_class") or "").strip().replace(".", "/")
    } - {""}
    launcher_kind = str(
        runtime_profile.payload.get("container_and_launcher_kind") or ""
    ).lower()
    if launcher_kind in {
        "java-jar", "executable-jar", "spring-boot", "spring_boot",
        "spring-boot-launcher",
    }:
        for resource in store.rows("resources"):
            if str(resource.get("resource_name") or "").upper() != "META-INF/MANIFEST.MF":
                continue
            artifact = artifacts.get(resource.get("artifact_instance_identity")) or {}
            if not _is_business_artifact(artifact):
                continue
            for key, value in _loads(
                resource.get("resource_semantic_json") or "[]"
            ):
                if str(key).lower() in {"main-class", "start-class"}:
                    exact_main_classes.add(str(value).strip().replace(".", "/"))
    spring_boot_status, spring_boot_evidence = _spring_boot_activation_status(
        store, runtime_profile, artifacts, selected_class_variants,
        exact_main_classes,
    )
    resource_activated_classes = (
        set(registered_auto_configurations)
        | set(spring_factories_callbacks)
        if spring_boot_status == "exact"
        else set()
    )
    activated_classes = set(resource_activated_classes)
    declared_activated_classes = {
        str(item or "").replace(".", "/")
        for item in profile.get("activated_classes") or ()
        if str(item or "").strip()
    }
    activated_classes.update(declared_activated_classes)
    imported_activated_classes: set[str] = set()

    # @Import on an already activated configuration is a transitive activation
    # proof.  Resolve it to a fixed point over selected classfile facts.
    changed = True
    while changed:
        changed = False
        for (_realm, class_name), (_row, fact) in selected_classes.items():
            artifact = artifacts.get(_row.get("artifact_instance_identity")) or {}
            if class_name not in activated_classes and not _is_business_artifact(artifact):
                continue
            for imported in _annotation_imports(
                _realm, _annotations(fact), selected_classes
            ):
                if imported and imported not in activated_classes:
                    activated_classes.add(imported)
                    imported_activated_classes.add(imported)
                    changed = True

    records: list[dict[str, Any]] = []
    recorded: set[tuple[str, str, str]] = set()

    def add_record(
        member: Mapping[str, Any],
        *,
        realm: str,
        entry_kind: str,
        certainty: str,
        activation_reason: str,
        evidence: Mapping[str, Any],
    ) -> None:
        member_identity = str(member.get("member_identity") or "")
        # A selected member can be visible through more than one loader realm.
        # Keep the activation evidence realm-scoped even though reachability
        # graph nodes are currently member-scoped.
        key = (realm, member_identity, entry_kind)
        if not member_identity or key in recorded:
            return
        recorded.add(key)
        artifact = artifacts.get(member.get("artifact_instance_identity")) or {}
        payload = {
            "member_identity": member_identity,
            "initiating_loader_realm_identity": realm,
            "class_name": str(member.get("class_name") or ""),
            "member_name": str(member.get("member_name") or ""),
            "descriptor": str(member.get("descriptor") or ""),
            "entry_kind": entry_kind,
            "path_certainty": certainty,
            "activation_reason": activation_reason,
            "artifact_instance_identity": str(
                member.get("artifact_instance_identity") or ""
            ),
            "dependency_coord": str(artifact.get("coord") or ""),
            "runtime_path_kind": str(artifact.get("runtime_path_kind") or ""),
            "evidence": dict(evidence),
            "discovery_policy_version": DISCOVERY_POLICY_VERSION,
        }
        payload["entrypoint_record_identity"] = _identity(
            "binary_entrypoint_record_identity", payload
        )
        records.append(payload)

    # Explicit external/runtime declarations remain valid evidence and are
    # merged with, never used to disable, automatic discovery.
    declared_members = set()
    for item in profile.get("methods") or ():
        if not isinstance(item, Mapping):
            coverage_gaps.add("entrypoint_record_invalid")
            continue
        realm = str(item.get("initiating_loader_realm_identity") or "")
        class_name = str(item.get("class_name") or "").replace(".", "/")
        selected = selected_classes.get((realm, class_name))
        if selected is None:
            coverage_gaps.add(f"entrypoint_provider_unresolved:{realm}:{class_name}")
            continue
        class_row, _fact = selected
        candidates = [
            member
            for member in members_by_variant.get(class_row["class_variant_identity"], ())
            if member.get("member_name") == item.get("member_name")
            and member.get("descriptor") == item.get("descriptor")
        ]
        if len(candidates) != 1:
            coverage_gaps.add(
                "entrypoint_member_unresolved:"
                f"{realm}:{class_name}:{item.get('member_name')}:{item.get('descriptor')}"
            )
            continue
        declared_members.add(candidates[0]["member_identity"])
        add_record(
            candidates[0], realm=realm,
            entry_kind="declared_runtime_entry", certainty="exact",
            activation_reason="runtime_profile_declaration",
            evidence={"runtime_profile_identity": runtime_profile.identity},
        )

    for (realm, class_name), (class_row, class_fact) in sorted(selected_classes.items()):
        artifact = artifacts.get(class_row.get("artifact_instance_identity")) or {}
        business_owned = _is_business_artifact(artifact)
        class_activated = business_owned or class_name in activated_classes
        class_annotations = _annotation_descriptors(class_fact)
        class_annotation_closure = _annotation_closure(
            realm, class_annotations, selected_classes
        )
        class_conditional = _is_conditional(class_annotation_closure)
        hierarchy_types = _hierarchy_types(realm, class_name, selected_classes)
        members = sorted(
            members_by_variant.get(class_row["class_variant_identity"], ()),
            key=lambda item: (
                str(item.get("member_name") or ""),
                str(item.get("descriptor") or ""),
            ),
        )
        for member in members:
            if member.get("member_identity") in declared_members:
                continue
            contract = _loads(member.get("contract_json") or "{}")
            member_annotations = _annotation_descriptors(contract)
            member_annotation_closure = _annotation_closure(
                realm, member_annotations, selected_classes
            )
            candidate_kinds = {
                METHOD_ANNOTATION_KINDS[descriptor]
                for descriptor in member_annotation_closure
                if descriptor in METHOD_ANNOTATION_KINDS
            }
            for descriptor, (kind, names) in CLASS_TRIGGER_ANNOTATION_KINDS.items():
                if (
                    descriptor in class_annotation_closure
                    and member.get("member_name") in names
                ):
                    candidate_kinds.add(kind)
            for interface in hierarchy_types:
                kind = (INTERFACE_CALLBACKS.get(interface) or {}).get(
                    member.get("member_name")
                )
                if kind:
                    candidate_kinds.add(kind)
            for callback_name, kind in spring_factories_callbacks.get(
                class_name, ()
            ):
                if member.get("member_name") == callback_name:
                    candidate_kinds.add(kind)
            access = int(member.get("access_flags") or 0)
            if (
                member.get("member_name") == "main"
                and member.get("descriptor") == "([Ljava/lang/String;)V"
                and access & ACC_PUBLIC
                and access & ACC_STATIC
                and business_owned
            ):
                candidate_kinds.add("java_main")
            for entry_kind in sorted(candidate_kinds):
                conditional = class_conditional or _is_conditional(
                    member_annotation_closure
                )
                if conditional:
                    certainty = "possible"
                    reason = "framework_condition_not_evaluated"
                elif entry_kind == "jpa_lifecycle_callback":
                    certainty = "possible"
                    reason = "entity_lifecycle_activation_unproven"
                elif entry_kind == "java_main" and class_name not in exact_main_classes:
                    certainty = "possible"
                    reason = "business_main_activation_unproven"
                elif class_activated:
                    certainty = "exact"
                    if business_owned:
                        reason = "business_final_artifact_runtime_trigger"
                    elif class_name in resource_activated_classes:
                        reason = (
                            "spring_factories_runtime_registration"
                            if class_name in spring_factories_callbacks
                            else "spring_boot_auto_configuration_import"
                        )
                    elif class_name in imported_activated_classes:
                        reason = "spring_import_from_active_configuration"
                    else:
                        reason = "runtime_profile_activation_declaration"
                else:
                    certainty = "possible"
                    reason = "dependency_framework_activation_unproven"
                add_record(
                    member, realm=realm, entry_kind=entry_kind,
                    certainty=certainty, activation_reason=reason,
                    evidence={
                        "class_annotation_descriptors": sorted(class_annotations),
                        "method_annotation_descriptors": sorted(member_annotations),
                        "resolved_class_annotation_descriptors": sorted(
                            class_annotation_closure
                        ),
                        "resolved_method_annotation_descriptors": sorted(
                            member_annotation_closure
                        ),
                        "implemented_hierarchy_types": sorted(hierarchy_types),
                        "activated_class": class_name in activated_classes,
                        "spring_boot_activation_status": spring_boot_status,
                        "spring_boot_activation_evidence": list(
                            spring_boot_evidence
                        ),
                    },
                )

    records.sort(key=lambda item: (
        0 if item["path_certainty"] == "exact" else 1,
        item["class_name"], item["member_name"], item["descriptor"],
        item["entry_kind"],
    ))
    exact = tuple(sorted({
        item["member_identity"] for item in records
        if item["path_certainty"] == "exact"
    }))
    possible = tuple(sorted({
        item["member_identity"] for item in records
        if item["path_certainty"] == "possible"
        and item["member_identity"] not in exact
    }))
    gaps = tuple(sorted(coverage_gaps))
    payload = {
        "runtime_profile_identity": runtime_profile.identity,
        "runtime_reconciliation_identity": str(
            getattr(reconciliation, "identity", "") or ""
        ),
        "discovery_policy_version": DISCOVERY_POLICY_VERSION,
        "exact_member_identities": list(exact),
        "possible_member_identities": list(possible),
        "record_identities": [item["entrypoint_record_identity"] for item in records],
        "coverage_gaps": list(gaps),
    }
    return BinaryEntrypointDiscoveryResult(
        exact_member_identities=exact,
        possible_member_identities=possible,
        records=tuple(records),
        coverage_status="complete" if not gaps else "partial",
        coverage_gaps=gaps,
        identity=_identity("binary_entrypoint_discovery_identity", payload),
    )


__all__ = [
    "BinaryEntrypointDiscoveryResult",
    "DISCOVERY_POLICY_VERSION",
    "discover_binary_entrypoints",
]
