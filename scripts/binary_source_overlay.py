#!/usr/bin/env python3
"""Map source methods onto immutable binary members without changing authority."""

from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from binary_fact_store import BinaryFactStore
from binary_first_contract import BinaryFirstContractError, canonical_identity


ACC_BRIDGE = 0x0040
ACC_SYNTHETIC = 0x1000


class SourceOverlayError(BinaryFirstContractError):
    pass


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _erase_generics(value: str) -> str:
    output = []
    depth = 0
    for char in value:
        if char == "<":
            depth += 1
        elif char == ">":
            depth = max(0, depth - 1)
        elif depth == 0:
            output.append(char)
    return "".join(output)


def _source_type_descriptor(raw: str, method: Any, *, allow_void: bool = False) -> str:
    value = _erase_generics(str(raw or "").strip())
    value = re.sub(r"\s+", "", value).replace("...", "[]")
    value = re.sub(r"^(?:final|volatile|transient)", "", value)
    dimensions = 0
    while value.endswith("[]"):
        dimensions += 1
        value = value[:-2]
    primitives = {
        "boolean": "Z", "byte": "B", "char": "C", "short": "S", "int": "I",
        "long": "J", "float": "F", "double": "D",
    }
    if allow_void and value == "void" and dimensions == 0:
        return "V"
    if value in primitives:
        descriptor = primitives[value]
    else:
        value = value.replace("?extends", "").replace("?super", "").strip("?")
        if not value or re.fullmatch(r"[A-Z]", value):
            return ""
        known = getattr(method, "known_classes_by_simple", {}) or {}
        imports = getattr(method, "imports", {}) or {}
        if value in known:
            value = str(known[value])
        elif value in imports:
            value = str(imports[value])
        elif value in {
            "String", "Object", "Class", "Throwable", "Exception", "RuntimeException",
            "Boolean", "Byte", "Character", "Short", "Integer", "Long", "Float", "Double",
            "Void", "Iterable", "Record", "Enum",
        }:
            value = "java.lang." + value
        elif "." not in value:
            package_name = str(getattr(method, "package_name", "") or "")
            if not package_name:
                return ""
            value = package_name + "." + value
        descriptor = "L" + value.replace(".", "/") + ";"
    return "[" * dimensions + descriptor


def source_method_descriptor(method: Any) -> str:
    parameters = getattr(method, "param_types", {}) or {}
    declared = getattr(method, "param_declared_types", {}) or {}
    ordered_types = []
    for name, value in parameters.items():
        ordered_types.append(value or declared.get(name) or "")
    class_simple = str(getattr(method, "class_name", "") or "").split(".")[-1]
    method_name = str(getattr(method, "method_name", "") or "")
    constructor = method_name in {"<init>", class_simple}
    return_type = "void" if constructor else (
        getattr(method, "return_type", "")
        or getattr(method, "return_declared_type", "")
    )
    params = [_source_type_descriptor(item, method) for item in ordered_types]
    result = _source_type_descriptor(return_type, method, allow_void=True)
    if any(not item for item in params) or not result:
        return ""
    return "(" + "".join(params) + ")" + result


def _normalized_source_owner(method: Any) -> str:
    return str(getattr(method, "class_fqcn", "") or "").replace("$", ".")


def _normalized_binary_owner(value: str) -> str:
    return str(value or "").replace("/", ".").replace("$", ".")


def _source_method_name(method: Any) -> str:
    name = str(getattr(method, "method_name", "") or "")
    class_simple = str(getattr(method, "class_name", "") or "").split(".")[-1]
    return "<init>" if name == class_simple else name


@dataclass(frozen=True)
class SourceOverlayResult:
    source_snapshot_identity: str
    overlay_set_identity: str
    rows: tuple[dict[str, Any], ...]
    mapped_count: int
    ambiguous_count: int
    binary_only_count: int
    conflict_count: int
    coverage_status: str


@dataclass(frozen=True)
class InlineOverlayResult:
    inline_overlay_set_identity: str
    rows: tuple[dict[str, Any], ...]
    proven_count: int
    possible_count: int
    retained_or_unchanged_count: int
    unbound_count: int
    coverage_status: str


def _strip_java_comments_and_literals(value: str) -> str:
    output = []
    index = 0
    state = "code"
    while index < len(value):
        char = value[index]
        following = value[index + 1] if index + 1 < len(value) else ""
        if state == "code":
            if char == "/" and following == "/":
                output.extend("  ")
                index += 2
                state = "line_comment"
                continue
            if char == "/" and following == "*":
                output.extend("  ")
                index += 2
                state = "block_comment"
                continue
            if char in {'"', "'"}:
                output.append(" ")
                state = "string" if char == '"' else "char"
                index += 1
                continue
            output.append(char)
            index += 1
            continue
        if state == "line_comment":
            output.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if char == "*" and following == "/":
                output.extend("  ")
                index += 2
                state = "code"
            else:
                output.append("\n" if char == "\n" else " ")
                index += 1
            continue
        output.append("\n" if char == "\n" else " ")
        if char == "\\":
            if following:
                output.append(" ")
                index += 2
            else:
                index += 1
        elif (state == "string" and char == '"') or (state == "char" and char == "'"):
            state = "code"
            index += 1
        else:
            index += 1
    return "".join(output)


def _exact_field_reference_count(method: Any, owner: str, field_name: str) -> int:
    if str(getattr(method, "language", "") or "").lower() != "java":
        return 0
    body = _strip_java_comments_and_literals(method.get_body_text())
    owner_dotted = owner.replace("/", ".").replace("$", ".")
    simple = owner_dotted.rsplit(".", 1)[-1]
    aliases = {owner_dotted, simple}
    for alias, imported in (getattr(method, "imports", {}) or {}).items():
        if str(imported).replace("$", ".") == owner_dotted:
            aliases.add(str(alias))
    reference_spans = set()
    for alias in aliases:
        reference_spans.update(
            match.span()
            for match in re.finditer(
                rf"(?<![\w$.]){re.escape(alias)}\s*\.\s*{re.escape(field_name)}(?![\w$])",
                body,
            )
        )
    count = len(reference_spans)
    static_import = (getattr(method, "static_imports", {}) or {}).get(field_name)
    if str(static_import or "").replace("$", ".") == f"{owner_dotted}.{field_name}":
        count += len(re.findall(
            rf"(?<![\w$.]){re.escape(field_name)}(?![\w$])", body
        ))
    return count


def _instruction_constants(store: BinaryFactStore, member: Mapping[str, Any]) -> Counter:
    class_rows = store.rows(
        "classes",
        where="class_variant_identity=?",
        parameters=(member["class_variant_identity"],),
    )
    if len(class_rows) != 1:
        return Counter()
    fact = json.loads(class_rows[0]["fact_json"])
    method_fact = next((
        item for item in fact.get("methods") or ()
        if (item.get("contract") or {}).get("name") == member["member_name"]
        and (item.get("contract") or {}).get("descriptor") == member["descriptor"]
    ), None)
    constants: Counter = Counter()
    for instruction in (method_fact or {}).get("instructions") or ():
        if not isinstance(instruction, list) or len(instruction) < 3:
            continue
        kind = instruction[0]
        if kind == "ldc" and not isinstance(instruction[2], dict):
            constants[(type(instruction[2]).__name__, instruction[2])] += 1
        elif kind == "int" and len(instruction) >= 4 and int(instruction[2]) in {16, 17}:
            constants[("int", int(instruction[3]))] += 1
        elif kind == "insn":
            opcode = int(instruction[2])
            small = {
                2: -1, 3: 0, 4: 1, 5: 2, 6: 3, 7: 4, 8: 5,
                9: 0, 10: 1, 11: 0.0, 12: 1.0, 13: 2.0,
                14: 0.0, 15: 1.0,
            }
            if opcode in small:
                value = small[opcode]
                constants[(type(value).__name__, value)] += 1
    return constants


def _constant_key(value: Any) -> tuple[str, Any]:
    return type(value).__name__, value


def build_inline_consumption_overlay(
    base_store: BinaryFactStore,
    current_store: BinaryFactStore,
    source_methods: Iterable[Any],
    source_overlay: SourceOverlayResult,
    artifact_diffs: Iterable[Mapping[str, Any]],
    current_reconciliation: Any,
    *,
    analysis_context_identity: str,
) -> InlineOverlayResult:
    methods_by_symbol = {
        str(getattr(method, "symbol_id", "") or ""): method
        for method in source_methods
    }
    current_members = {
        row["member_identity"]: row for row in current_store.rows("members")
    }
    mapped_methods = []
    for overlay in source_overlay.rows:
        if overlay["mapping_status"] != "mapped":
            continue
        member = current_members.get(overlay["binary_member_identity"])
        method = methods_by_symbol.get(
            str((overlay.get("source_location") or {}).get("source_symbol_id") or "")
        )
        if member and method:
            mapped_methods.append((member, method, overlay))
    selected_variants = {
        item.get("selected_class_variant_identity")
        for item in current_reconciliation.provider_bindings
        if item.get("class_provider_status") == "resolved"
    }
    base_members_by_symbol: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for member in base_store.rows("members"):
        key = (
            member["class_name"], member["member_kind"],
            member["member_name"], member["descriptor"],
        )
        base_members_by_symbol.setdefault(key, []).append(member)
    field_changes = []
    for artifact_diff in artifact_diffs:
        for entry in artifact_diff.get("entry_deltas") or ():
            for delta in entry.get("member_deltas") or ():
                scope = delta.get("member_scope") or {}
                old = delta.get("base_contract") or {}
                new = delta.get("current_contract") or {}
                if (
                    scope.get("member_kind") == "field"
                    and int(new.get("access") or old.get("access") or 0) & 0x0018 == 0x0018
                    and old.get("constant") != new.get("constant")
                    and old.get("constant") is not None
                    and new.get("constant") is not None
                ):
                    field_changes.append((artifact_diff, entry, delta, old, new))
    rows = []
    for artifact_diff, entry, delta, old, new in field_changes:
        scope = delta["member_scope"]
        owner = str(entry["entry_scope"]["entry_name"])
        owner = re.sub(r"^META-INF/versions/\d+/", "", owner).removesuffix(".class")
        current_fields = [
            member for member in current_members.values()
            if member["class_name"] == owner
            and member["member_kind"] == "field"
            and member["member_name"] == scope["member_name"]
            and member["descriptor"] == scope["descriptor"]
            and member["class_variant_identity"] in selected_variants
        ]
        if len(current_fields) != 1:
            continue
        field_member = current_fields[0]
        matched = 0
        for consumer, method, overlay in mapped_methods:
            if consumer["class_variant_identity"] not in selected_variants:
                continue
            ref_count = _exact_field_reference_count(method, owner, scope["member_name"])
            if ref_count == 0:
                continue
            matched += 1
            physical_field_edges = current_store.rows(
                "direct_edges",
                where=(
                    "caller_member_identity=? AND edge_kind='field' "
                    "AND symbolic_owner=? AND symbolic_name=? AND symbolic_descriptor=?"
                ),
                parameters=(
                    consumer["member_identity"], owner,
                    scope["member_name"], scope["descriptor"],
                ),
            )
            base_candidates = base_members_by_symbol.get((
                consumer["class_name"], "method",
                consumer["member_name"], consumer["descriptor"],
            ), [])
            base_consumer = base_candidates[0] if len(base_candidates) == 1 else None
            unchanged = bool(
                base_consumer
                and base_consumer["implementation_digest"] == consumer["implementation_digest"]
            )
            base_constants = _instruction_constants(base_store, base_consumer) if base_consumer else Counter()
            current_constants = _instruction_constants(current_store, consumer)
            old_key = _constant_key(old["constant"])
            new_key = _constant_key(new["constant"])
            transitioned = bool(
                base_consumer
                and base_constants[old_key] > current_constants[old_key]
                and current_constants[new_key] > base_constants[new_key]
            )
            if physical_field_edges:
                state, certainty = "not_inlined_binary_field_access", "not_applicable"
            elif unchanged:
                state, certainty = "retained_base_or_unchanged", "none"
            elif transitioned and ref_count == 1:
                state, certainty = "changed_with_source", "proven"
            else:
                state, certainty = "changed_with_source", "possible"
            coverage = (
                "complete"
                if source_overlay.coverage_status == "complete" and base_consumer
                else "partial"
            )
            payload = {
                "analysis_context_identity": analysis_context_identity,
                "changed_field_member_identity": field_member["member_identity"],
                "consumer_member_identity": consumer["member_identity"],
                "consumption_state": state,
                "binding_certainty": certainty,
                "coverage_status": coverage,
                "field_owner": owner,
                "field_name": scope["member_name"],
                "field_descriptor": scope["descriptor"],
                "base_constant": old["constant"],
                "current_constant": new["constant"],
                "source_overlay_identity": overlay["overlay_identity"],
                "exact_source_reference_count": ref_count,
                "base_consumer_member_identity": (
                    (base_consumer or {}).get("member_identity") or ""
                ),
                "bytecode_constant_transition_proven": transitioned,
                "inline_policy_version": "java-javac-inline-overlay-v1",
            }
            payload["inline_overlay_identity"] = _identity(
                "inline_overlay_identity", payload
            )
            current_store.add_inline_overlay(payload)
            rows.append(payload)
        if matched == 0:
            payload = {
                "analysis_context_identity": analysis_context_identity,
                "changed_field_member_identity": field_member["member_identity"],
                "consumer_member_identity": "",
                "consumption_state": "unbound",
                "binding_certainty": "none",
                "coverage_status": "partial",
                "field_owner": owner,
                "field_name": scope["member_name"],
                "field_descriptor": scope["descriptor"],
                "base_constant": old["constant"],
                "current_constant": new["constant"],
                "reason_code": "NO_EXACT_SOURCE_SYMBOL_REFERENCE_IN_OVERLAY",
                "inline_policy_version": "java-javac-inline-overlay-v1",
            }
            payload["inline_overlay_identity"] = _identity(
                "inline_overlay_identity", payload
            )
            current_store.add_inline_overlay(payload)
            rows.append(payload)
    counts = Counter(row["binding_certainty"] for row in rows)
    retained = sum(
        row["consumption_state"] == "retained_base_or_unchanged" for row in rows
    )
    unbound = sum(row["consumption_state"] == "unbound" for row in rows)
    coverage = "complete" if rows and all(
        row["coverage_status"] == "complete" for row in rows
    ) else ("not_applicable" if not field_changes else "partial")
    identity = _identity("inline_overlay_set_identity", {
        "analysis_context_identity": analysis_context_identity,
        "inline_overlay_identities": sorted(
            row["inline_overlay_identity"] for row in rows
        ),
    })
    return InlineOverlayResult(
        inline_overlay_set_identity=identity,
        rows=tuple(rows),
        proven_count=counts["proven"],
        possible_count=counts["possible"],
        retained_or_unchanged_count=retained,
        unbound_count=unbound,
        coverage_status=coverage,
    )


def build_source_overlay(
    store: BinaryFactStore,
    source_methods: Iterable[Any],
    *,
    analysis_context_identity: str,
    source_snapshot_identity: str,
    source_snapshot_coverage_status: str = "complete",
) -> SourceOverlayResult:
    context = str(analysis_context_identity or "").strip()
    snapshot_id = str(source_snapshot_identity or "").strip()
    if not context or not snapshot_id:
        raise SourceOverlayError(
            "SOURCE_OVERLAY_IDENTITY_MISSING", "analysis context and source snapshot are required"
        )
    methods = tuple(source_methods)
    index: dict[tuple[str, str], list[Any]] = {}
    for method in methods:
        key = (_normalized_source_owner(method), _source_method_name(method))
        index.setdefault(key, []).append(method)
    artifact_coords = {
        str(item["artifact_instance_identity"]): str(item["coord"] or "")
        for item in store.rows("artifact_instances")
    }

    rows = []
    for member in store.rows("members", where="member_kind='method'"):
        owner = _normalized_binary_owner(member["class_name"])
        name = member["member_name"]
        flags = int(member["access_flags"])
        candidates = index.get((owner, name), [])
        exact = [
            method for method in candidates
            if source_method_descriptor(method) == member["descriptor"]
        ]
        location: dict[str, Any] = {}
        conflict: dict[str, Any] = {}
        if len(exact) == 1:
            method = exact[0]
            source_path = Path(str(getattr(method, "file", "") or ""))
            root = Path(str(getattr(method, "source_root", "") or "")).resolve()
            try:
                logical_path = source_path.resolve().relative_to(root).as_posix()
            except (OSError, ValueError):
                status = "source_conflict"
                conflict = {
                    "reason_code": "SOURCE_LOCATION_OUTSIDE_SNAPSHOT_ROOT",
                    "source_file": str(source_path),
                }
            else:
                if not source_path.is_file():
                    status = "source_conflict"
                    conflict = {
                        "reason_code": "SOURCE_FILE_MISSING",
                        "logical_path": logical_path,
                    }
                else:
                    status = "mapped"
                    location = {
                        "source_snapshot_identity": snapshot_id,
                        "logical_path": logical_path,
                        "source_content_sha256": _sha256_file(source_path),
                        "line": int(getattr(method, "line", 0) or 0),
                        "end_line": int(getattr(method, "end_line", 0) or 0),
                        "language": str(getattr(method, "language", "") or ""),
                        "owner_type": str(getattr(method, "owner_type", "") or ""),
                        "owner_coord": str(getattr(method, "owner_coord", "") or ""),
                        "module": str(getattr(method, "module", "") or ""),
                        "source_symbol_id": str(getattr(method, "symbol_id", "") or ""),
                        "jvm_descriptor": member["descriptor"],
                    }
        elif len(exact) > 1:
            status = "ambiguous"
            conflict = {
                "reason_code": "MULTIPLE_EXACT_SOURCE_METHODS",
                "candidate_symbol_ids": sorted(
                    str(getattr(item, "symbol_id", "") or "") for item in exact
                ),
            }
        elif flags & (ACC_BRIDGE | ACC_SYNTHETIC) or name == "<clinit>":
            status = "binary_only"
            conflict = {"reason_code": "COMPILER_GENERATED_MEMBER"}
        elif candidates:
            status = "source_conflict"
            conflict = {
                "reason_code": "SOURCE_BINARY_DESCRIPTOR_MISMATCH",
                "binary_descriptor": member["descriptor"],
                "source_descriptors": sorted({source_method_descriptor(item) or "unknown" for item in candidates}),
            }
        else:
            status = "binary_only"
            conflict = {"reason_code": "SOURCE_METHOD_NOT_AVAILABLE"}
        identity_payload = {
            "analysis_context_identity": context,
            "source_snapshot_identity": snapshot_id,
            "binary_member_identity": member["member_identity"],
            "mapping_status": status,
            "stable_source_location": {
                key: value for key, value in location.items()
                if key != "source_symbol_id"
            },
            "conflict": conflict,
            "overlay_policy_version": "binary-source-overlay-v1",
        }
        overlay_identity = _identity("source_overlay_identity", identity_payload)
        row = {
            **identity_payload,
            "overlay_identity": overlay_identity,
            "binary_member": {
                "class_name": member["class_name"],
                "member_name": member["member_name"],
                "descriptor": member["descriptor"],
                "artifact_coord": artifact_coords.get(
                    str(member["artifact_instance_identity"]), ""
                ),
            },
            "source_location": location,
        }
        store.add_source_overlay(
            overlay_identity=overlay_identity,
            analysis_context_identity=context,
            binary_member_identity=member["member_identity"],
            mapping_status=status,
            source_location=location,
            conflict=conflict,
        )
        rows.append(row)
    counts = {
        status: sum(item["mapping_status"] == status for item in rows)
        for status in ("mapped", "ambiguous", "binary_only", "source_conflict")
    }
    coverage_status = (
        "complete"
        if source_snapshot_coverage_status == "complete"
        and counts["ambiguous"] == 0
        and counts["source_conflict"] == 0
        else "partial"
    )
    overlay_set_identity = _identity(
        "source_overlay_set_identity",
        {
            "analysis_context_identity": context,
            "source_snapshot_identity": snapshot_id,
            "source_snapshot_coverage_status": source_snapshot_coverage_status,
            "overlay_identities": sorted(item["overlay_identity"] for item in rows),
        },
    )
    return SourceOverlayResult(
        source_snapshot_identity=snapshot_id,
        overlay_set_identity=overlay_set_identity,
        rows=tuple(rows),
        mapped_count=counts["mapped"],
        ambiguous_count=counts["ambiguous"],
        binary_only_count=counts["binary_only"],
        conflict_count=counts["source_conflict"],
        coverage_status=coverage_status,
    )


__all__ = [
    "InlineOverlayResult",
    "SourceOverlayError",
    "SourceOverlayResult",
    "build_inline_consumption_overlay",
    "build_source_overlay",
    "source_method_descriptor",
]
