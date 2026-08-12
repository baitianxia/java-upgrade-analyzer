#!/usr/bin/env python3
"""Typed runtime-semantic edges derived from the selected final binary view.

These edges cover dispatch performed by frameworks or the JDK that is absent
from ordinary invoke instructions.  Binary members and selected resources are
the authority; source is never required and no legacy reachability engine is
invoked.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
import re
from typing import Any, Iterable, Mapping

from binary_first_contract import canonical_identity
from binary_runtime_reconciler import class_load_is_ready


POLICY_VERSION = "binary-runtime-semantic-overlay-v1"
ACC_INTERFACE = 0x0200
BUSINESS_PATH_KINDS = frozenset({
    "application", "application_classes", "business", "business_classes",
})

TRANSACTIONAL = "Lorg/springframework/transaction/annotation/Transactional;"
PRIMARY = "Lorg/springframework/context/annotation/Primary;"
MAPPER_ANNOTATIONS = {
    "Lorg/apache/ibatis/annotations/Mapper;",
    "Lorg/mybatis/spring/annotation/MapperScan;",
}
COMPONENT_ANNOTATIONS = {
    "Lorg/springframework/stereotype/Component;",
    "Lorg/springframework/stereotype/Service;",
    "Lorg/springframework/stereotype/Repository;",
    "Lorg/springframework/stereotype/Controller;",
    "Lorg/springframework/web/bind/annotation/RestController;",
    "Lorg/springframework/context/annotation/Configuration;",
}
ASPECT_ANNOTATION = "Lorg/aspectj/lang/annotation/Aspect;"
ADVICE_ANNOTATIONS = {
    "Lorg/aspectj/lang/annotation/Before;",
    "Lorg/aspectj/lang/annotation/After;",
    "Lorg/aspectj/lang/annotation/Around;",
    "Lorg/aspectj/lang/annotation/AfterReturning;",
    "Lorg/aspectj/lang/annotation/AfterThrowing;",
}
FEIGN_ANNOTATIONS = {
    "Lorg/springframework/cloud/openfeign/FeignClient;",
    "Lfeign/RequestLine;",
}
DATA_BINDING_METHOD_ANNOTATIONS = {
    "Lorg/springframework/web/bind/annotation/RequestMapping;",
    "Lorg/springframework/web/bind/annotation/GetMapping;",
    "Lorg/springframework/web/bind/annotation/PostMapping;",
    "Lorg/springframework/web/bind/annotation/PutMapping;",
    "Lorg/springframework/web/bind/annotation/PatchMapping;",
    "Lorg/springframework/web/bind/annotation/DeleteMapping;",
}


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _spring_aop_pointcut_constraints(expression: str) -> dict[str, Any] | None:
    value = str(expression or "")
    executions = re.findall(
        r"execution\([^)]*?([\w.$*]+)\.([\w$*]+)\s*\(", value
    )
    if not executions:
        return None
    class_annotations = set(re.findall(r"(?<!!)@within\(([\w.$]+)\)", value))
    method_annotations = set(re.findall(r"(?<!!)@annotation\(([\w.$]+)\)", value))
    excluded_method_annotations = set(re.findall(
        r"!\s*@annotation\(([\w.$]+)\)", value
    ))
    unsupported = bool(
        "||" in value
        or re.search(
            r"(?<!@)\b(?:within|this|target|args|bean|call|get|set|cflow)\s*\(",
            value,
        )
        or re.search(r"@(?:target|args|this)\s*\(", value)
        or re.search(r"!\s*@within\s*\(", value)
    )
    return {
        "executions": tuple(executions),
        "class_annotations": frozenset(
            "L" + item.replace(".", "/") + ";" for item in class_annotations
        ),
        "method_annotations": frozenset(
            "L" + item.replace(".", "/") + ";" for item in method_annotations
        ),
        "excluded_method_annotations": frozenset(
            "L" + item.replace(".", "/") + ";"
            for item in excluded_method_annotations
        ),
        "complete": not unsupported,
    }


def _loads(value: str) -> Any:
    try:
        return json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}


def _annotations(payload: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    return tuple(
        dict(item) for item in payload.get("annotations") or ()
        if isinstance(item, Mapping) and item.get("visible") is not False
    )


def _annotation_descriptors(payload: Mapping[str, Any]) -> set[str]:
    return {
        str(item.get("descriptor") or "") for item in _annotations(payload)
        if str(item.get("descriptor") or "")
    }


def _nested_strings(value: Any) -> set[str]:
    result = set()
    if isinstance(value, str):
        result.add(value)
    elif isinstance(value, Mapping):
        for nested in value.values():
            result.update(_nested_strings(nested))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            result.update(_nested_strings(nested))
    return result


def _nested_type_names(value: Any) -> set[str]:
    result = set()
    if isinstance(value, Mapping):
        if value.get("kind") == "type":
            descriptor = str(value.get("descriptor") or "")
            if descriptor.startswith("L") and descriptor.endswith(";"):
                result.add(descriptor[1:-1])
        for nested in value.values():
            result.update(_nested_type_names(nested))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            result.update(_nested_type_names(nested))
    return result


def _annotation_attributes(annotation: Mapping[str, Any]) -> dict[str, tuple[Any, ...]]:
    result: dict[str, list[Any]] = {}
    for raw in annotation.get("values") or ():
        if not isinstance(raw, (list, tuple)) or len(raw) < 2:
            continue
        name = str(raw[0] or "")
        if not name:
            continue
        if raw[1] == "array" and len(raw) >= 3:
            values = list(raw[2] or ())
        elif raw[1] == "enum" and len(raw) >= 4:
            values = [raw[3]]
        else:
            values = [raw[1]]
        result.setdefault(name, []).extend(values)
    return {key: tuple(values) for key, values in result.items()}


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value or "").strip().lower() in {"true", "1", "yes", "on"}


def _descriptor_parameters(descriptor: str) -> tuple[str, ...] | None:
    value = str(descriptor or "")
    if not value.startswith("("):
        return None
    result = []
    index = 1
    while index < len(value) and value[index] != ")":
        start = index
        while index < len(value) and value[index] == "[":
            index += 1
        if index >= len(value):
            return None
        if value[index] == "L":
            end = value.find(";", index)
            if end < 0:
                return None
            index = end + 1
        else:
            index += 1
        result.append(value[start:index])
    return tuple(result) if index < len(value) and value[index] == ")" else None


def _descriptor_return(descriptor: str) -> str:
    value = str(descriptor or "")
    marker = value.find(")")
    return value[marker + 1:] if marker >= 0 else ""


def _descriptor_class(descriptor: str) -> str:
    value = str(descriptor or "")
    return value[1:-1] if value.startswith("L") and value.endswith(";") else ""


@dataclass(frozen=True)
class BinarySemanticOverlay:
    rows: tuple[dict[str, Any], ...]
    coverage_status: str
    coverage_gaps: tuple[str, ...]
    identity: str

    def as_payload(self) -> dict[str, Any]:
        return {
            "schema": "java-upgrade-analyzer.binary-runtime-semantic-overlay.v1",
            "policy_version": POLICY_VERSION,
            "semantic_overlay_identity": self.identity,
            "coverage_status": self.coverage_status,
            "coverage_gaps": list(self.coverage_gaps),
            "edge_count": len(self.rows),
            "rows": list(self.rows),
        }


class _Builder:
    def __init__(self, store: Any, profile: Any, reconciliation: Any, decisions: Any = None):
        self.store = store
        self.profile = profile
        self.runtime = reconciliation
        self.decisions = decisions
        self.artifacts = {
            row["artifact_instance_identity"]: row
            for row in store.rows("artifact_instances")
        }
        self.classes = {
            row["class_variant_identity"]: row
            for row in store.rows("classes", include_class_bytes=False)
        }
        self.members = {
            row["member_identity"]: dict(row)
            for row in store.connection.execute(
                """
                SELECT member_identity,class_variant_identity,
                       artifact_instance_identity,class_name,member_kind,
                       member_name,descriptor,access_flags,contract_json
                FROM members
                """
            )
        }
        self.members_by_variant: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in self.members.values():
            self.members_by_variant[row["class_variant_identity"]].append(row)
        self.direct_edges = [
            dict(row)
            for row in store.connection.execute(
                """
                SELECT direct_edge_identity,caller_member_identity,
                       caller_artifact_instance_identity,instruction_index,
                       bytecode_offset,edge_kind,opcode,symbolic_owner,
                       symbolic_name,symbolic_descriptor,edge_json
                FROM direct_edges
                """
            )
        ]
        class_load_ready = {
            (
                str(item.get("initiating_loader_realm_identity") or ""),
                str(item.get("class_name") or ""),
            )
            for item in getattr(reconciliation, "class_definitions", ())
            if class_load_is_ready(item)
        }
        self.selected: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
        selected_facts: dict[str, dict[str, Any]] = {}
        for binding in getattr(reconciliation, "provider_bindings", ()):
            if binding.get("class_provider_status") != "resolved":
                continue
            selection_key = (
                str(binding.get("initiating_loader_realm_identity") or ""),
                str(binding.get("class_name") or ""),
            )
            if selection_key not in class_load_ready:
                continue
            variant = str(binding.get("selected_class_variant_identity") or "")
            row = self.classes.get(variant)
            if row is not None:
                fact = selected_facts.get(variant)
                if fact is None:
                    fact = _loads(row.get("fact_json") or "{}")
                    selected_facts[variant] = fact
                self.selected[selection_key] = (
                    row, fact
                )
        # ``selected`` owns the rows needed below. Drop shadowed/MR variants
        # and the duplicate serialized fact strings before semantic indexes are
        # built from the parsed documents.
        for row, _fact in self.selected.values():
            row.pop("fact_json", None)
        self.classes.clear()
        self.realms = sorted({realm for realm, _name in self.selected})
        self.rows: list[dict[str, Any]] = []
        self.seen = set()
        self.gaps = set()
        self.resource_facts = self._selected_resource_facts()

    def _selected_resource_facts(self):
        result = []
        for selection in getattr(self.runtime, "resource_selections", ()):
            if selection.get("resource_selection_status") != "resolved":
                continue
            for selected in selection.get("selected_resources") or ():
                result.append({
                    "realm": str(selection.get("initiating_loader_realm_identity") or ""),
                    "name": str(selection.get("resource_name") or ""),
                    "facts": tuple(tuple(item) for item in selected.get("resource_semantic_facts") or ()),
                    "selection_identity": str(selection.get("resource_selection_identity") or ""),
                })
        return result

    def _business(self, artifact_identity: str) -> bool:
        artifact = self.artifacts.get(artifact_identity) or {}
        return str(artifact.get("runtime_path_kind") or "").lower() in BUSINESS_PATH_KINDS

    def _class_annotations(self, row_fact) -> set[str]:
        return _annotation_descriptors(row_fact[1])

    def _members_for(self, realm: str, class_name: str, name: str = ""):
        selected = self.selected.get((realm, class_name))
        if not selected:
            return []
        return [
            row for row in self.members_by_variant[selected[0]["class_variant_identity"]]
            if row.get("member_kind") == "method"
            and (not name or row.get("member_name") == name)
        ]

    def _member_fact_rows(self):
        for (realm, class_name), (class_row, fact) in self.selected.items():
            by_key = {
                (row.get("member_name"), row.get("descriptor")): row
                for row in self.members_by_variant[class_row["class_variant_identity"]]
                if row.get("member_kind") == "method"
            }
            for method in fact.get("methods") or ():
                contract = method.get("contract") or {}
                member = by_key.get((contract.get("name"), contract.get("descriptor")))
                if member:
                    yield realm, class_name, class_row, fact, member, method

    def _hierarchy(self, realm: str, class_name: str) -> set[str]:
        result = set()
        pending = [class_name]
        while pending:
            current = pending.pop()
            selected = self.selected.get((realm, current))
            if not selected:
                continue
            fact = selected[1]
            parents = [fact.get("super_name"), *(fact.get("interfaces") or ())]
            for parent in map(str, filter(None, parents)):
                if parent not in result:
                    result.add(parent)
                    pending.append(parent)
        return result

    def _spring_active(self) -> bool:
        runtime = self.profile.payload
        declared = {
            str(item or "").lower()
            for item in (runtime.get("business_entrypoint_profile") or {}).get(
                "activated_frameworks"
            ) or ()
        }
        launcher = str(runtime.get("container_and_launcher_kind") or "").lower()
        return "spring_boot" in declared or launcher in {
            "spring-boot", "spring_boot", "spring-boot-launcher",
            "spring-boot-executable-jar",
        }

    def _condition_certainty(self, realm: str, fact: Mapping[str, Any]) -> str:
        active_profiles = {
            str(value or "") for value in self.profile.payload.get(
                "active_profile_identities"
            ) or ()
        }
        properties = self.profile.payload.get("resolved_configuration_properties") or {}
        configuration_complete = str(
            self.profile.payload.get("runtime_configuration_coverage_status") or ""
        ) == "complete"
        unresolved = False
        for annotation in _annotations(fact):
            descriptor = str(annotation.get("descriptor") or "")
            attributes = _annotation_attributes(annotation)
            strings = {
                value
                for values in attributes.values()
                for raw in values
                for value in _nested_strings(raw)
            }
            types = _nested_type_names(annotation.get("values") or ())
            if descriptor == "Lorg/springframework/context/annotation/Profile;":
                values = {value for value in strings if value not in {"value", "array"}}
                if values and not values.intersection(active_profiles):
                    return "inactive"
            elif descriptor.endswith("/ConditionalOnClass;"):
                classes = set(types) | {value.replace(".", "/") for value in strings if "." in value}
                if classes and not all((realm, value) in self.selected for value in classes):
                    return "inactive"
                unresolved |= not bool(classes)
            elif descriptor.endswith("/ConditionalOnMissingClass;"):
                classes = {value.replace(".", "/") for value in strings if "." in value}
                if classes and not all((realm, value) not in self.selected for value in classes):
                    return "inactive"
                unresolved |= not bool(classes)
            elif descriptor.endswith("/ConditionalOnProperty;"):
                prefix = str((attributes.get("prefix") or ("",))[0] or "").strip()
                if prefix and not prefix.endswith("."):
                    prefix += "."
                declared = tuple(
                    str(value or "").strip()
                    for value in (
                        attributes.get("name") or attributes.get("value") or ()
                    )
                    if str(value or "").strip()
                )
                names = tuple(prefix + value for value in declared)
                having = str(
                    (attributes.get("havingValue") or ("",))[0] or ""
                )
                match_missing = _as_bool(
                    (attributes.get("matchIfMissing") or (False,))[0]
                )
                if not names:
                    unresolved = True
                    continue
                for name in names:
                    if name not in properties:
                        if not match_missing:
                            if configuration_complete:
                                return "inactive"
                            unresolved = True
                        continue
                    actual = str(properties[name])
                    matched = actual == having if having else actual.lower() != "false"
                    if not matched:
                        return "inactive"
            elif descriptor.startswith(
                "Lorg/springframework/boot/autoconfigure/condition/Conditional"
            ) or descriptor == "Lorg/springframework/context/annotation/Conditional;":
                unresolved = True
        return "possible" if unresolved else "exact"

    def add(self, caller: Mapping[str, Any], target: Mapping[str, Any], *,
            kind: str, certainty: str, evidence: Mapping[str, Any]):
        caller_id = str(caller.get("member_identity") or "")
        target_id = str(target.get("member_identity") or "")
        key = (caller_id, target_id, kind, certainty)
        if not caller_id or not target_id or key in self.seen:
            return
        self.seen.add(key)
        caller_artifact = self.artifacts.get(caller.get("artifact_instance_identity")) or {}
        target_artifact = self.artifacts.get(target.get("artifact_instance_identity")) or {}
        payload = {
            "caller_member_identity": caller_id,
            "target_member_identity": target_id,
            "semantic_edge_kind": kind,
            "path_certainty": certainty,
            "caller_class_name": str(caller.get("class_name") or ""),
            "caller_member_name": str(caller.get("member_name") or ""),
            "caller_descriptor": str(caller.get("descriptor") or ""),
            "target_class_name": str(target.get("class_name") or ""),
            "target_member_name": str(target.get("member_name") or ""),
            "target_descriptor": str(target.get("descriptor") or ""),
            "caller_dependency_coord": str(caller_artifact.get("coord") or ""),
            "target_dependency_coord": str(target_artifact.get("coord") or ""),
            "evidence": dict(evidence),
            "policy_version": POLICY_VERSION,
        }
        payload["semantic_edge_identity"] = _identity(
            "binary_runtime_semantic_edge_identity", payload
        )
        self.rows.append(payload)

    def _unique_targets(self, class_name: str, member_name: str, *, parameter_count=None):
        result = []
        for realm in self.realms:
            for member in self._members_for(realm, class_name, member_name):
                parameters = _descriptor_parameters(member.get("descriptor"))
                if parameter_count is None or (
                    parameters is not None and len(parameters) == parameter_count
                ):
                    result.append((realm, member))
        unique = {item[1]["member_identity"]: item for item in result}
        return list(unique.values())

    def reflection_and_method_handles(self):
        reflection_terminals = {
            ("java/lang/reflect/Method", "invoke"),
            ("java/lang/reflect/Constructor", "newInstance"),
            ("java/lang/reflect/Field", "get"),
            ("java/lang/reflect/Field", "set"),
            ("java/lang/invoke/MethodHandle", "invoke"),
            ("java/lang/invoke/MethodHandle", "invokeExact"),
        }
        lookups = {
            "getMethod": ("method", "reflection_method_invocation"),
            "getDeclaredMethod": ("method", "reflection_method_invocation"),
            "getConstructor": ("constructor", "reflection_constructor_invocation"),
            "getDeclaredConstructor": ("constructor", "reflection_constructor_invocation"),
            "getField": ("field", "reflection_field_access"),
            "getDeclaredField": ("field", "reflection_field_access"),
            "findStatic": ("method", "method_handle_invocation"),
            "findVirtual": ("method", "method_handle_invocation"),
            "findSpecial": ("method", "method_handle_invocation"),
            "findConstructor": ("constructor", "method_handle_invocation"),
            "findGetter": ("field", "method_handle_field_access"),
            "findSetter": ("field", "method_handle_field_access"),
        }
        for _realm, _class, _class_row, _fact, caller, method in self._member_fact_rows():
            instructions = list(method.get("instructions") or ())
            terminal_indexes = [
                index for index, item in enumerate(instructions)
                if len(item) >= 6 and item[0] == "method"
                and (str(item[3]), str(item[4])) in reflection_terminals
            ]
            for index, item in enumerate(instructions):
                if len(item) < 6 or item[0] != "method" or str(item[4]) not in lookups:
                    continue
                if not any(index < terminal <= index + 48 for terminal in terminal_indexes):
                    continue
                lookup_kind, semantic_kind = lookups[str(item[4])]
                window = instructions[max(0, index - 32):index]
                strings = [
                    (offset, str(value[2])) for offset, value in enumerate(window)
                    if len(value) >= 3 and value[0] == "ldc" and isinstance(value[2], str)
                ]
                typed_literals = [
                    (offset, name)
                    for offset, value in enumerate(window)
                    if value and value[0] == "ldc"
                    for name in _nested_type_names(value[2:])
                ]
                for_name_indexes = [
                    offset for offset, value in enumerate(window)
                    if len(value) >= 6 and value[0] == "method"
                    and value[3] == "java/lang/Class" and value[4] == "forName"
                ]
                owner = ""
                if for_name_indexes:
                    prior = [value for offset, value in strings if offset < for_name_indexes[-1]]
                    if prior:
                        owner = prior[-1].replace(".", "/")
                if not owner and strings:
                    before_member = [
                        name for offset, name in typed_literals
                        if offset < strings[-1][0]
                    ]
                    if before_member:
                        owner = before_member[-1]
                if not owner and typed_literals:
                    owner = typed_literals[0][1]
                member_name = "<init>" if lookup_kind == "constructor" else (
                    strings[-1][1] if strings else ""
                )
                if not owner or not member_name:
                    self.gaps.add(
                        f"semantic_reflection_target_unresolved:{caller['class_name']}:{caller['member_name']}"
                    )
                    continue
                target_kind = "field" if lookup_kind == "field" else "method"
                candidates = []
                for realm in self.realms:
                    selected = self.selected.get((realm, owner))
                    if not selected:
                        continue
                    candidates.extend(
                        member for member in self.members_by_variant[
                            selected[0]["class_variant_identity"]
                        ]
                        if member.get("member_kind") == target_kind
                        and member.get("member_name") == member_name
                    )
                certainty = "exact" if len(candidates) == 1 else "possible"
                if len(candidates) > 1:
                    self.gaps.add(f"semantic_reflection_overload_ambiguous:{owner}:{member_name}")
                for target in candidates:
                    self.add(
                        caller, target, kind=semantic_kind, certainty=certainty,
                        evidence={
                            "lookup_owner": str(item[3]),
                            "lookup_name": str(item[4]),
                            "lookup_bytecode_offset": int(item[1]),
                            "terminal_invocation_proved": True,
                            "literal_owner": owner,
                            "literal_member": member_name,
                        },
                    )

    def dynamic_proxy(self):
        for realm, _class, _class_row, _fact, caller, method in self._member_fact_rows():
            instructions = list(method.get("instructions") or ())
            for index, item in enumerate(instructions):
                if not (
                    len(item) >= 6 and item[0] == "method"
                    and item[3] == "java/lang/reflect/Proxy"
                    and item[4] == "newProxyInstance"
                ):
                    continue
                class_literals = {
                    name for value in instructions[max(0, index - 32):index]
                    for name in _nested_type_names(value[2:])
                    if value and value[0] == "ldc"
                }
                proxy_invocations = [
                    value for value in instructions[index + 1:index + 49]
                    if len(value) >= 6 and value[0] == "method"
                    and int(value[2]) == 185 and str(value[3]) in class_literals
                ]
                candidates = []
                for candidate in instructions[max(0, index - 32):index]:
                    if len(candidate) < 4 or candidate[0] != "type" or int(candidate[2]) != 187:
                        continue
                    class_name = str(candidate[3])
                    if "java/lang/reflect/InvocationHandler" not in self._hierarchy(realm, class_name):
                        continue
                    candidates.extend(self._members_for(realm, class_name, "invoke"))
                unique = {row["member_identity"]: row for row in candidates}
                certainty = (
                    "exact" if len(unique) == 1 and proxy_invocations else "possible"
                )
                if not unique:
                    self.gaps.add(f"dynamic_proxy_handler_unresolved:{caller['member_identity']}")
                for target in unique.values():
                    self.add(caller, target, kind="dynamic_proxy_callback", certainty=certainty,
                             evidence={"registration_bytecode_offset": int(item[1]),
                                       "registration_api": "java.lang.reflect.Proxy.newProxyInstance",
                                       "proxied_interface_literals": sorted(class_literals),
                                       "proxied_interface_invocation_proved": bool(proxy_invocations)})

    def mybatis(self):
        namespaces = {
            str(value).replace(".", "/")
            for resource in self.resource_facts
            for key, value in resource["facts"]
            if key == "mybatis_mapper_namespace"
        }
        runtime_targets = []
        for owner, name, count in (
            ("org/apache/ibatis/binding/MapperProxy", "invoke", 3),
            ("org/apache/ibatis/binding/MapperMethod", "execute", 2),
        ):
            matches = self._unique_targets(owner, name, parameter_count=count)
            if len(matches) == 1:
                runtime_targets.append(matches[0][1])
            elif namespaces:
                self.gaps.add(f"mybatis_runtime_target_unresolved:{owner}:{name}")
        invoked_owners = {
            str(edge.get("symbolic_owner") or "") for edge in self.direct_edges
            if edge.get("edge_kind") == "method"
        }
        for realm, class_name in sorted(self.selected):
            selected = self.selected[(realm, class_name)]
            annotations = self._class_annotations(selected)
            registered = bool(annotations & MAPPER_ANNOTATIONS) or class_name in namespaces
            interface = int(selected[1].get("class_access") or 0) & ACC_INTERFACE
            if not registered or not interface or class_name not in invoked_owners:
                continue
            certainty = "exact" if annotations & MAPPER_ANNOTATIONS else "possible"
            if certainty == "possible":
                self.gaps.add(f"mybatis_xml_activation_unproven:{class_name}")
            for mapper_member in self._members_for(realm, class_name):
                for target in runtime_targets:
                    self.add(mapper_member, target, kind="mybatis_mapper_proxy_dispatch",
                             certainty=certainty,
                             evidence={"mapper_class": class_name,
                                       "registration": "annotation" if annotations & MAPPER_ANNOTATIONS else "xml_namespace"})

    def spring_transaction(self):
        spring_active = self._spring_active()
        targets = []
        for owner, name, count in (
            ("org/springframework/transaction/interceptor/TransactionInterceptor", "invoke", 1),
            ("org/springframework/transaction/interceptor/TransactionAspectSupport", "invokeWithinTransaction", 3),
            ("org/springframework/aop/framework/ReflectiveMethodInvocation", "proceed", 0),
        ):
            matches = self._unique_targets(owner, name, parameter_count=count)
            if len(matches) == 1:
                targets.append(matches[0][1])
        for _realm, _class, class_row, class_fact, member, _method in self._member_fact_rows():
            if not self._business(class_row["artifact_instance_identity"]):
                continue
            annotations = _annotation_descriptors(_loads(member.get("contract_json") or "{}"))
            if TRANSACTIONAL not in annotations and TRANSACTIONAL not in _annotation_descriptors(class_fact):
                continue
            certainty = "exact" if spring_active and len(targets) == 3 else "possible"
            if certainty == "possible":
                self.gaps.add(f"spring_transaction_runtime_unproven:{member['member_identity']}")
            for target in targets:
                self.add(member, target, kind="spring_transaction_proxy_dispatch",
                         certainty=certainty,
                         evidence={"annotation": "@Transactional", "spring_activation": spring_active})

    def spring_data_and_bean_wiring(self):
        spring_active = self._spring_active()
        simple_repo = "org/springframework/data/jpa/repository/support/SimpleJpaRepository"
        bean_types: dict[tuple[str, str], str] = {}
        primary_bean_types: set[tuple[str, str]] = set()
        custom_repository_configuration = False
        entry_profile = self.profile.payload.get("business_entrypoint_profile") or {}
        active_resources = {
            str(value or "").removeprefix("classpath:").lstrip("/")
            for value in entry_profile.get("activated_resource_names") or ()
        }
        scan_prefixes = {
            str(value or "").replace(".", "/")
            for value in entry_profile.get("activated_component_scan_packages") or ()
            if str(value or "").strip()
        }
        main_class = str(entry_profile.get("main_class") or "").replace(".", "/")
        if spring_active and "/" in main_class:
            scan_prefixes.add(main_class.rsplit("/", 1)[0])
        for resource in self.resource_facts:
            for key, value in resource["facts"]:
                if key == "spring_bean_class":
                    parts = str(value).split("|", 1)
                    if len(parts) == 2:
                        bean_types[(resource["realm"], parts[1].replace(".", "/"))] = (
                            "exact" if resource["name"] in active_resources else "possible"
                        )
                elif key == "spring_bean_primary":
                    parts = str(value).split("|", 1)
                    if len(parts) == 2:
                        primary_bean_types.add((
                            resource["realm"], parts[1].replace(".", "/")
                        ))
                elif key == "spring_component_scan":
                    scan_prefixes.update(
                        item.strip().replace(".", "/")
                        for item in str(value).split(",") if item.strip()
                    )
        for (_realm, _class_name), selected in self.selected.items():
            if not self._business(selected[0]["artifact_instance_identity"]):
                continue
            for annotation in _annotations(selected[1]):
                if annotation.get("descriptor") == "Lorg/springframework/context/annotation/ComponentScan;":
                    scan_prefixes.update(
                        value.replace(".", "/")
                        for value in _nested_strings(annotation.get("values") or ())
                        if value and not value.lower().endswith(".class")
                    )
                if annotation.get("descriptor") == (
                    "Lorg/springframework/data/jpa/repository/config/"
                    "EnableJpaRepositories;"
                ):
                    attributes = _annotation_attributes(annotation)
                    if {
                        "repositoryBaseClass", "repositoryFactoryBeanClass"
                    }.intersection(attributes):
                        custom_repository_configuration = True
        for realm, class_name in self.selected:
            selected = self.selected[(realm, class_name)]
            annotations = self._class_annotations(selected)
            if annotations & COMPONENT_ANNOTATIONS:
                condition = self._condition_certainty(realm, selected[1])
                if condition == "inactive":
                    continue
                bean_types[(realm, class_name)] = (
                    "exact"
                    if condition == "exact" and (
                        self._business(selected[0]["artifact_instance_identity"])
                        or any(
                        class_name == prefix or class_name.startswith(prefix + "/")
                        for prefix in scan_prefixes
                        )
                    )
                    else "possible"
                )
                if PRIMARY in annotations:
                    primary_bean_types.add((realm, class_name))
        for realm, _class, _class_row, _fact, factory, method in self._member_fact_rows():
            annotations = _annotation_descriptors(_loads(factory.get("contract_json") or "{}"))
            if "Lorg/springframework/context/annotation/Bean;" in annotations:
                returned = _descriptor_class(_descriptor_return(factory.get("descriptor")))
                if returned:
                    registered_type = returned
                    constructed_types = {
                        str(item[3])
                        for item in method.get("instructions") or ()
                        if len(item) >= 4 and item[0] == "type"
                        and int(item[2]) == 187
                        and (
                            str(item[3]) == returned
                            or returned in self._hierarchy(realm, str(item[3]))
                        )
                    }
                    if len(constructed_types) == 1:
                        registered_type = next(iter(constructed_types))
                    elif any(
                        int((self.selected.get((candidate_realm, returned)) or ({}, {}))[1].get(
                            "class_access"
                        ) or 0) & ACC_INTERFACE
                        for candidate_realm in self.realms
                    ):
                        self.gaps.add(
                            f"spring_bean_factory_implementation_unresolved:"
                            f"{factory['member_identity']}"
                        )
                        continue
                    bean_types[(realm, registered_type)] = (
                        "exact" if self._business(factory["artifact_instance_identity"]) else "possible"
                    )
                    if PRIMARY in annotations:
                        primary_bean_types.add((realm, registered_type))

        for edge in self.direct_edges:
            if edge.get("edge_kind") != "method":
                continue
            realm_candidates = self.realms
            interface = str(edge.get("symbolic_owner") or "")
            if not any(
                int((self.selected.get((realm, interface)) or ({}, {}))[1].get("class_access") or 0) & ACC_INTERFACE
                for realm in realm_candidates
            ):
                continue
            implementations = []
            for (realm, class_name), _selected in self.selected.items():
                if (realm, class_name) not in bean_types or interface not in self._hierarchy(realm, class_name):
                    continue
                implementations.extend(
                    (
                        row,
                        bean_types[(realm, class_name)],
                        (realm, class_name) in primary_bean_types,
                    )
                    for row in self._members_for(realm, class_name, str(edge.get("symbolic_name") or ""))
                    if row.get("descriptor") == edge.get("symbolic_descriptor")
                )
            primary_implementations = [
                item for item in implementations if item[2]
            ]
            selected_implementations = (
                primary_implementations
                if len(primary_implementations) == 1
                else implementations
            )
            caller = self.members.get(edge.get("caller_member_identity"))
            if caller:
                for target, activation, primary in selected_implementations:
                    unique = len(selected_implementations) == 1
                    self.add(caller, target, kind="spring_bean_wiring_dispatch",
                             certainty=(
                                 "exact"
                                 if unique and spring_active and activation == "exact"
                                 else "possible"
                             ),
                             evidence={
                                 "interface": interface,
                                 "unique_bean_implementation": unique,
                                 "selected_by_primary": primary and unique,
                                 "candidate_count": len(implementations),
                             })

        repo_interfaces = {
            class_name for realm, class_name in self.selected
            if any(name.startswith("org/springframework/data/repository/") or
                   name == "org/springframework/data/jpa/repository/JpaRepository"
                   for name in self._hierarchy(realm, class_name))
        }
        if custom_repository_configuration:
            self.gaps.add("spring_data_custom_repository_factory")
        for edge in self.direct_edges:
            owner = str(edge.get("symbolic_owner") or "")
            if (
                owner not in repo_interfaces
                or edge.get("edge_kind") != "method"
                or custom_repository_configuration
            ):
                continue
            caller = self.members.get(edge.get("caller_member_identity"))
            targets = self._unique_targets(simple_repo, str(edge.get("symbolic_name") or ""),
                                           parameter_count=len(_descriptor_parameters(edge.get("symbolic_descriptor")) or ()))
            certainty = "exact" if spring_active and len(targets) == 1 else "possible"
            for _realm, target in targets:
                if caller:
                    self.add(caller, target, kind="spring_data_repository_proxy_dispatch",
                             certainty=certainty,
                             evidence={"repository_interface": owner, "spring_activation": spring_active})

    def spring_aop_and_security(self):
        spring_active = self._spring_active()
        for realm, aspect_name in sorted(self.selected):
            selected = self.selected[(realm, aspect_name)]
            if ASPECT_ANNOTATION not in self._class_annotations(selected):
                continue
            for advice in self._members_for(realm, aspect_name):
                contract = _loads(advice.get("contract_json") or "{}")
                annotations = [
                    item for item in _annotations(contract)
                    if item.get("descriptor") in ADVICE_ANNOTATIONS
                ]
                for annotation in annotations:
                    values = _nested_strings(annotation.get("values") or ())
                    pointcuts = [
                        parsed for value in values
                        if (parsed := _spring_aop_pointcut_constraints(value))
                    ]
                    if not pointcuts:
                        self.gaps.add(f"spring_aop_pointcut_unsupported:{advice['member_identity']}")
                    for pointcut in pointcuts:
                        if not pointcut["complete"]:
                            self.gaps.add(
                                f"spring_aop_pointcut_unsupported:{advice['member_identity']}"
                            )
                        for owner_pattern, method_pattern in pointcut["executions"]:
                            owner_re = re.compile("^" + re.escape(owner_pattern.replace(".", "/")).replace(r"\*", ".*") + "$")
                            method_re = re.compile("^" + re.escape(method_pattern).replace(r"\*", ".*") + "$")
                            for (
                                candidate_realm, candidate_class, _class_row,
                                _class_fact, candidate, _method_fact,
                            ) in self._member_fact_rows():
                                if candidate_realm != realm:
                                    continue
                                if candidate.get("member_name") in {
                                    "<init>", "<clinit>"
                                }:
                                    continue
                                if not owner_re.match(candidate_class) or not method_re.match(
                                    str(candidate.get("member_name") or "")
                                ):
                                    continue
                                candidate_selected = self.selected.get(
                                    (candidate_realm, candidate_class)
                                )
                                class_annotations = self._class_annotations(
                                    candidate_selected
                                ) if candidate_selected else set()
                                member_annotations = _annotation_descriptors(
                                    _loads(candidate.get("contract_json") or "{}")
                                )
                                if not pointcut["class_annotations"].issubset(
                                    class_annotations
                                ):
                                    continue
                                if not pointcut["method_annotations"].issubset(
                                    member_annotations
                                ):
                                    continue
                                if pointcut["excluded_method_annotations"].intersection(
                                    member_annotations
                                ):
                                    continue
                                if not pointcut["complete"]:
                                    certainty = "possible"
                                elif spring_active and self._business(
                                    selected[0]["artifact_instance_identity"]
                                ):
                                    certainty = "exact"
                                else:
                                    certainty = "possible"
                                self.add(
                                    candidate, advice, kind="spring_aop_dispatch",
                                    certainty=certainty,
                                    evidence={
                                        "pointcut": sorted(values),
                                        "aspect": aspect_name,
                                        "pointcut_complete": pointcut["complete"],
                                        "required_class_annotations": sorted(
                                            pointcut["class_annotations"]
                                        ),
                                        "required_method_annotations": sorted(
                                            pointcut["method_annotations"]
                                        ),
                                        "excluded_method_annotations": sorted(
                                            pointcut["excluded_method_annotations"]
                                        ),
                                    },
                                )

        for _realm, _class, class_row, _fact, bean, method in self._member_fact_rows():
            contract = _loads(bean.get("contract_json") or "{}")
            if "Lorg/springframework/context/annotation/Bean;" not in _annotation_descriptors(contract):
                continue
            if _descriptor_return(bean.get("descriptor")) not in {
                "Lorg/springframework/security/web/SecurityFilterChain;",
                "Ljavax/servlet/Filter;", "Ljakarta/servlet/Filter;",
            }:
                continue
            candidate_types = {
                str(item[3]) for item in method.get("instructions") or ()
                if len(item) >= 4 and item[0] == "type" and int(item[2]) == 187
            }
            filter_registration_calls = [
                item for item in method.get("instructions") or ()
                if len(item) >= 6 and item[0] == "method"
                and str(item[4]) in {"addFilter", "addFilterBefore", "addFilterAfter", "addFilterAt"}
            ]
            if not filter_registration_calls:
                continue
            for candidate_type in candidate_types:
                hierarchy = self._hierarchy(_realm, candidate_type)
                if not hierarchy.intersection({"javax/servlet/Filter", "jakarta/servlet/Filter"}):
                    continue
                for callback in self._members_for(_realm, candidate_type, "doFilter"):
                    self.add(bean, callback, kind="spring_security_filter_dispatch",
                             certainty="exact" if spring_active and self._business(class_row["artifact_instance_identity"]) else "possible",
                             evidence={"security_filter_chain_factory": bean["member_identity"]})

    def declarative_clients(self):
        spring_active = self._spring_active()
        runtime_targets = []
        for owner in (
            "feign/SynchronousMethodHandler",
            "feign/InvocationHandlerFactory$Default",
        ):
            runtime_targets.extend(item[1] for item in self._unique_targets(owner, "invoke"))
        for realm, class_name in sorted(self.selected):
            selected = self.selected[(realm, class_name)]
            class_annotations = self._class_annotations(selected)
            if not class_annotations.intersection(FEIGN_ANNOTATIONS):
                continue
            for client_method in self._members_for(realm, class_name):
                if not _annotation_descriptors(_loads(client_method.get("contract_json") or "{}")) and not class_annotations:
                    continue
                certainty = "exact" if spring_active and runtime_targets else "possible"
                for target in runtime_targets:
                    self.add(client_method, target, kind="declarative_http_client_dispatch",
                             certainty=certainty,
                             evidence={"client_interface": class_name, "spring_activation": spring_active})

    def dubbo_spi(self):
        providers: dict[tuple[str, str], set[str]] = defaultdict(set)
        for resource in self.resource_facts:
            name = resource["name"]
            prefixes = ("META-INF/dubbo/", "META-INF/dubbo/internal/", "META-INF/dubbo/external/")
            prefix = next((value for value in prefixes if name.startswith(value)), "")
            if not prefix:
                continue
            service = name[len(prefix):].replace(".", "/")
            for key, value in resource["facts"]:
                if key != "ordered_entry":
                    continue
                implementation = str(value).split("=", 1)[-1].strip().replace(".", "/")
                if implementation:
                    providers[(resource["realm"], service)].add(implementation)
        for edge in self.direct_edges:
            if not (
                edge.get("edge_kind") == "method"
                and edge.get("symbolic_owner") == "org/apache/dubbo/common/extension/ExtensionLoader"
                and edge.get("symbolic_name") in {"getExtension", "getAdaptiveExtension", "getActivateExtension"}
            ):
                continue
            caller = self.members.get(edge.get("caller_member_identity"))
            if not caller:
                continue
            candidates = []
            for (realm, service), implementations in providers.items():
                for implementation in implementations:
                    for callback in self._members_for(realm, implementation):
                        if callback.get("member_name") not in {"<init>", "<clinit>"}:
                            candidates.append((service, callback))
            certainty = "exact" if len(providers) == 1 else "possible"
            for service, target in candidates:
                self.add(caller, target, kind="dubbo_spi_dispatch", certainty=certainty,
                         evidence={"service": service, "resource_registration": True,
                                   "extension_loader_call": edge.get("direct_edge_identity")})

    def implicit_data_contracts(self):
        if self.decisions is None:
            return
        binding_callers: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for _realm, class_name, _class_row, _fact, member, _method in self._member_fact_rows():
            contract = _loads(member.get("contract_json") or "{}")
            if _annotation_descriptors(contract).intersection(DATA_BINDING_METHOD_ANNOTATIONS):
                descriptors = list(_descriptor_parameters(member.get("descriptor")) or ())
                descriptors.append(_descriptor_return(member.get("descriptor")))
                for descriptor in descriptors:
                    owner = _descriptor_class(descriptor)
                    if owner:
                        binding_callers[owner].append(member)
        for edge in self.direct_edges:
            if edge.get("edge_kind") != "method":
                continue
            if (str(edge.get("symbolic_owner") or ""), str(edge.get("symbolic_name") or "")) not in {
                ("com/fasterxml/jackson/databind/ObjectMapper", "readValue"),
                ("com/fasterxml/jackson/databind/ObjectMapper", "writeValue"),
                ("com/fasterxml/jackson/databind/ObjectMapper", "writeValueAsString"),
                ("jakarta/persistence/EntityManager", "persist"),
                ("javax/persistence/EntityManager", "persist"),
            }:
                continue
            caller = self.members.get(edge.get("caller_member_identity"))
            if caller:
                for owner in binding_callers:
                    binding_callers[owner].append(caller)
        decisions = [
            *getattr(self.decisions, "authoritative_decisions", ()),
            *getattr(self.decisions, "diagnostic_decisions", ()),
        ]
        for decision in decisions:
            scope = decision.get("fact_scope") or {}
            if scope.get("member_kind") != "field":
                continue
            owner = str(scope.get("class_name") or "")
            target_nodes = []
            for realm in self.realms:
                selected = self.selected.get((realm, owner))
                if selected:
                    target_nodes.extend(
                        row for row in self.members_by_variant[selected[0]["class_variant_identity"]]
                        if row.get("member_kind") == "field"
                        and row.get("member_name") == scope.get("member_name")
                    )
            if not target_nodes:
                descriptor = str(scope.get("descriptor") or "")
                target_nodes.append({
                    "member_identity": _identity("binary_symbolic_trace_target", {
                        "owner": owner,
                        "name": str(scope.get("member_name") or ""),
                        "descriptor": descriptor,
                        "member_kind": "field",
                    }),
                    "artifact_instance_identity": "",
                    "class_name": owner,
                    "member_name": str(scope.get("member_name") or ""),
                    "descriptor": descriptor,
                })
            for caller in binding_callers.get(owner, ()):
                for target in target_nodes:
                    self.add(caller, target, kind="implicit_data_contract_dispatch",
                             certainty="exact",
                             evidence={"data_owner": owner, "binding_boundary": caller["member_identity"]})

    def build(self) -> BinarySemanticOverlay:
        self.reflection_and_method_handles()
        self.dynamic_proxy()
        self.mybatis()
        self.spring_transaction()
        self.spring_data_and_bean_wiring()
        self.spring_aop_and_security()
        self.declarative_clients()
        self.dubbo_spi()
        self.implicit_data_contracts()
        self.rows.sort(key=lambda row: row["semantic_edge_identity"])
        gaps = tuple(sorted(self.gaps))
        payload = {
            "policy_version": POLICY_VERSION,
            "runtime_profile_identity": self.profile.identity,
            "runtime_reconciliation_identity": str(getattr(self.runtime, "identity", "")),
            "edge_identities": [row["semantic_edge_identity"] for row in self.rows],
            "coverage_gaps": list(gaps),
        }
        return BinarySemanticOverlay(
            rows=tuple(self.rows),
            coverage_status="complete" if not gaps else "partial",
            coverage_gaps=gaps,
            identity=_identity("binary_runtime_semantic_overlay_identity", payload),
        )


def build_binary_semantic_overlay(store: Any, runtime_profile: Any,
                                  reconciliation: Any, decisions: Any = None) -> BinarySemanticOverlay:
    summary_reader = getattr(store, "runtime_trigger_summary", None)
    if callable(summary_reader):
        summary = summary_reader()
        has_relevant_decision = any(
            (item.get("fact_scope") or {}).get("member_kind") == "field"
            for item in (
                *getattr(decisions, "authoritative_decisions", ()),
                *getattr(decisions, "diagnostic_decisions", ()),
            )
        ) if decisions is not None else False
        has_relevant_resource = store.connection.execute(
            """
            SELECT 1 FROM resources
            WHERE upper(resource_name)<>'META-INF/MANIFEST.MF'
            LIMIT 1
            """
        ).fetchone() is not None
        has_relevant_direct_edge = store.connection.execute(
            """
            SELECT 1 FROM direct_edges
            WHERE symbolic_owner='java/lang/Class'
               OR symbolic_owner LIKE 'java/lang/reflect/%'
               OR symbolic_owner LIKE 'java/lang/invoke/%'
               OR symbolic_owner LIKE 'org/springframework/%'
               OR symbolic_owner LIKE 'org/apache/ibatis/%'
               OR symbolic_owner LIKE 'org/apache/dubbo/%'
               OR symbolic_owner LIKE 'com/fasterxml/jackson/%'
               OR symbolic_owner LIKE 'jakarta/persistence/%'
               OR symbolic_owner LIKE 'javax/persistence/%'
               OR symbolic_owner LIKE 'feign/%'
            LIMIT 1
            """
        ).fetchone() is not None
        if not (
            summary["has_runtime_annotations"]
            or has_relevant_decision
            or has_relevant_resource
            or has_relevant_direct_edge
        ):
            payload = {
                "policy_version": POLICY_VERSION,
                "runtime_profile_identity": runtime_profile.identity,
                "runtime_reconciliation_identity": str(
                    getattr(reconciliation, "identity", "")
                ),
                "edge_identities": [],
                "coverage_gaps": [],
            }
            return BinarySemanticOverlay(
                rows=(),
                coverage_status="complete",
                coverage_gaps=(),
                identity=_identity(
                    "binary_runtime_semantic_overlay_identity", payload
                ),
            )
    return _Builder(store, runtime_profile, reconciliation, decisions).build()


__all__ = [
    "BinarySemanticOverlay", "POLICY_VERSION", "build_binary_semantic_overlay",
]
