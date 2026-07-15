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
VERSIONED_CLASS_RE = re.compile(r"^META-INF/versions/(?P<version>\d+)/(?P<entry>.+\.class)$")


def _field_type(descriptor: str) -> str:
    value, end = _descriptor_type(str(descriptor or ""), 0)
    return value if value and end == len(str(descriptor or "")) else str(descriptor or "")


def parse_classfile_instance_fields(data: bytes) -> tuple[str, dict[str, str]]:
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
    offset += 2 + interface_count * 2
    if offset + 2 > len(data):
        raise ValueError("truncated classfile interface table")

    field_count = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    fields: dict[str, str] = {}
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


def _jar_instance_fields(
    jar_path: str | Path,
    target_java_version: int | None = None,
) -> dict[str, dict[str, str]]:
    inventory: dict[str, dict[str, str]] = {}
    with zipfile.ZipFile(jar_path) as archive:
        for _logical, entry in sorted(
            _effective_class_entries(archive, target_java_version).items()
        ):
            owner, fields = parse_classfile_instance_fields(archive.read(entry))
            if owner:
                inventory[owner] = fields
    return inventory


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
    old_inventory = _jar_instance_fields(old_jar, target_java_version)
    new_inventory = _jar_instance_fields(new_jar, target_java_version)
    rows: list[dict] = []
    for owner in sorted(set(old_inventory) & set(new_inventory)):
        old_fields = old_inventory[owner]
        new_fields = new_inventory[owner]
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
                "reason_code": change_type.lower(),
                "evidence_path": f"{Path(old_jar)}|{Path(new_jar)}",
                "old_value": old_type,
                "new_value": new_type,
            })
    rows.sort(key=lambda row: (row["api_name"], row["change_type"]))
    return rows


__all__ = ["compare_jar_data_contracts", "parse_classfile_instance_fields"]
