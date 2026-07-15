#!/usr/bin/env python3
"""Compare instance-field data contracts directly from final JAR classfiles."""

from __future__ import annotations

import re
import struct
import zipfile
from pathlib import Path

from business_bytecode_graph import (
    _cp_class_name,
    _cp_utf8,
    _descriptor_type,
    _parse_classfile_constant_pool,
    _skip_attributes,
)


ACC_STATIC = 0x0008
ACC_SYNTHETIC = 0x1000
ACC_PUBLIC = 0x0001
VERSIONED_CLASS_RE = re.compile(r"^META-INF/versions/(?P<version>\d+)/(?P<entry>.+\.class)$")
DATA_CARRIER_NAME_RE = re.compile(
    r"(?:Dto|DTO|VO|ViewObject|Entity|Record|Request|Response|Command|Query|Payload|Data)$"
)
DATA_CARRIER_PACKAGE_SEGMENTS = {
    "dto", "vo", "entity", "entities", "model", "domain", "pojo", "request",
    "response", "command", "query", "payload",
}


def _field_type(descriptor: str) -> str:
    value, end = _descriptor_type(str(descriptor or ""), 0)
    return value if value and end == len(str(descriptor or "")) else str(descriptor or "")


def _parse_classfile_data_shape(data: bytes) -> tuple[str, dict[str, str], set[str]]:
    """Return ``(class_fqcn, {field_name: java_type})`` for one classfile.

    The classfile member table is authoritative for private DTO state. Static
    constants and compiler-generated fields are deliberately excluded because
    they are not per-instance data-contract properties.
    """
    cp, offset = _parse_classfile_constant_pool(data)
    if cp is None or offset + 8 > len(data):
        raise ValueError("invalid classfile constant pool")

    this_class = struct.unpack_from(">H", data, offset + 2)[0]
    owner = _cp_class_name(cp, this_class).replace("/", ".").replace("$", ".")
    offset += 6  # access_flags, this_class, super_class
    interface_count = struct.unpack_from(">H", data, offset)[0]
    interface_indexes = (
        struct.unpack_from(f">{interface_count}H", data, offset + 2)
        if interface_count else ()
    )
    interfaces = {
        _cp_class_name(cp, index).replace("/", ".").replace("$", ".")
        for index in interface_indexes
    }
    offset += 2 + interface_count * 2
    if offset + 2 > len(data):
        raise ValueError("truncated classfile interface table")

    field_count = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    fields: dict[str, str] = {}
    public_fields = set()
    for _ in range(field_count):
        if offset + 8 > len(data):
            raise ValueError("truncated classfile field table")
        access_flags, name_index, descriptor_index, attribute_count = struct.unpack_from(
            ">HHHH", data, offset
        )
        offset += 8
        name = _cp_utf8(cp, name_index)
        descriptor = _cp_utf8(cp, descriptor_index)
        next_offset = _skip_attributes(data, offset, attribute_count)
        if not next_offset:
            raise ValueError("truncated classfile field attributes")
        offset = next_offset
        if access_flags & (ACC_STATIC | ACC_SYNTHETIC):
            continue
        if not name or name.startswith("this$"):
            continue
        fields[name] = _field_type(descriptor)
        if access_flags & ACC_PUBLIC:
            public_fields.add(name)

    if offset + 2 > len(data):
        raise ValueError("truncated classfile method table")
    method_count = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    method_names = set()
    for _ in range(method_count):
        if offset + 8 > len(data):
            raise ValueError("truncated classfile method table")
        _flags, name_index, _descriptor_index, attribute_count = struct.unpack_from(
            ">HHHH", data, offset
        )
        offset += 8
        method_names.add(_cp_utf8(cp, name_index))
        next_offset = _skip_attributes(data, offset, attribute_count)
        if not next_offset:
            raise ValueError("truncated classfile method attributes")
        offset = next_offset

    reasons = set()
    simple_name = owner.rsplit(".", 1)[-1]
    package_segments = {part.lower() for part in owner.rsplit(".", 1)[0].split(".")}
    if DATA_CARRIER_NAME_RE.search(simple_name):
        reasons.add("data_carrier_name")
    if package_segments & DATA_CARRIER_PACKAGE_SEGMENTS:
        reasons.add("data_carrier_package")
    if "java.io.Serializable" in interfaces and fields:
        reasons.add("serializable_state")
    accessor_fields = set(public_fields)
    for field_name, field_type in fields.items():
        capitalized = field_name[:1].upper() + field_name[1:]
        getter_names = {field_name, f"get{capitalized}"}
        if field_type == "boolean":
            getter_names.add(f"is{capitalized}")
        if getter_names & method_names or f"set{capitalized}" in method_names:
            accessor_fields.add(field_name)
    if fields and accessor_fields and len(accessor_fields) * 2 >= len(fields):
        reasons.add("bean_or_record_accessors")
    return owner, fields, reasons


def parse_classfile_instance_fields(data: bytes) -> tuple[str, dict[str, str]]:
    owner, fields, _reasons = _parse_classfile_data_shape(data)
    return owner, fields


def _effective_class_entries(
    archive: zipfile.ZipFile,
    target_java_version: int | None,
) -> dict[str, str]:
    """Resolve Multi-Release JAR entries without mixing class variants."""
    candidates: dict[str, list[tuple[int, str]]] = {}
    for entry in archive.namelist():
        if not entry.endswith(".class") or entry.endswith("module-info.class"):
            continue
        version = 0
        logical_entry = entry
        match = VERSIONED_CLASS_RE.match(entry)
        if match:
            version = int(match.group("version"))
            logical_entry = match.group("entry")
            if target_java_version is None or version > target_java_version:
                continue
        elif entry.startswith("META-INF/"):
            continue
        candidates.setdefault(logical_entry, []).append((version, entry))
    return {
        logical: max(entries, key=lambda item: item[0])[1]
        for logical, entries in candidates.items()
        if entries
    }


def compare_jar_data_contracts(
    old_jar: str | Path,
    new_jar: str | Path,
    *,
    coord: str,
    old_version: str,
    new_version: str,
    target_java_version: int | None = None,
) -> list[dict]:
    """Return instance-field additions, removals, and type changes.

    Rows intentionally describe data-contract facts rather than binary API
    compatibility. Step 5 decides whether the owning type reaches a proven or
    conditional system runtime entry.
    """
    rows: list[dict] = []
    with zipfile.ZipFile(old_jar) as old_archive, zipfile.ZipFile(new_jar) as new_archive:
        old_entries = _effective_class_entries(old_archive, target_java_version)
        new_entries = _effective_class_entries(new_archive, target_java_version)
        changed_field_sets = []
        for logical_entry in sorted(set(old_entries) & set(new_entries)):
            old_bytes = old_archive.read(old_entries[logical_entry])
            new_bytes = new_archive.read(new_entries[logical_entry])
            if old_bytes == new_bytes:
                continue
            old_owner, old_fields, old_reasons = _parse_classfile_data_shape(old_bytes)
            new_owner, new_fields, new_reasons = _parse_classfile_data_shape(new_bytes)
            if not old_owner or old_owner != new_owner:
                continue
            carrier_reasons = sorted(old_reasons | new_reasons)
            if not carrier_reasons:
                continue
            changed_field_sets.append((old_owner, old_fields, new_fields, carrier_reasons))

    for owner, old_fields, new_fields, carrier_reasons in changed_field_sets:
        changes = [
            (name, "DATA_FIELD_REMOVED", old_fields[name], "")
            for name in sorted(set(old_fields) - set(new_fields))
        ]
        changes.extend(
            (name, "DATA_FIELD_ADDED", "", new_fields[name])
            for name in sorted(set(new_fields) - set(old_fields))
        )
        changes.extend(
            (name, "DATA_FIELD_TYPE_CHANGED", old_fields[name], new_fields[name])
            for name in sorted(set(old_fields) & set(new_fields))
            if old_fields[name] != new_fields[name]
        )
        for name, change_type, old_type, new_type in changes:
            rows.append({
                "coord": coord,
                "old_version": old_version,
                "new_version": new_version,
                "change_type": change_type,
                "api_name": f"{owner}.{name}",
                "api_simple": name,
                "symbol_kind": "field",
                "api_signature": "",
                "confirmed": "true",
                "severity": "P2" if change_type == "DATA_FIELD_ADDED" else "P1",
                "source": "classfile_contract",
                "binary_compatible": "unknown",
                "source_compatible": "unknown",
                "compatibility_flags": "DATA_CONTRACT_CHANGE",
                "data_contract_evidence": "|".join(carrier_reasons),
                "reason_code": change_type.lower(),
                "evidence_path": f"{Path(old_jar)}|{Path(new_jar)}",
                "old_value": old_type,
                "new_value": new_type,
            })
    rows.sort(key=lambda row: (row["api_name"], row["change_type"]))
    return rows


__all__ = ["compare_jar_data_contracts", "parse_classfile_instance_fields"]
