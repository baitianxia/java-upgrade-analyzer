#!/usr/bin/env python3
"""Independent compile-time constant and runtime-link evidence."""

from dataclasses import asdict, dataclass
import hashlib
import io
from pathlib import Path
import re
import struct
import subprocess
import zipfile

from artifact_safety import require_safe_archive


@dataclass(frozen=True)
class ConstantImpact:
    compile_impact: str
    runtime_link_impact: str
    old_field_has_constant_value: bool
    source_reference_present: bool
    runtime_field_edge_present: bool
    source_artifact_aligned: bool

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class ConstantFieldEvidence:
    owner: str
    field_name: str
    descriptor: str
    has_constant_value: bool
    constant_value: object
    artifact_sha256: str
    artifact_entry: str
    status: str
    failures: tuple[str, ...] = ()

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class FieldLinkEvidence:
    consumer_owner: str
    consumer_method: str
    consumer_descriptor: str
    target_owner: str
    target_field: str
    target_descriptor: str
    opcode: str
    instruction_offset: int
    artifact_sha256: str
    artifact_entry: str

    def to_dict(self):
        return asdict(self)


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _class_owner(entry):
    value = str(entry or "").replace("\\", "/")
    for prefix in ("BOOT-INF/classes/", "WEB-INF/classes/"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    match = re.match(r"META-INF/versions/\d+/(.+)", value)
    if match:
        value = match.group(1)
    if not value.endswith(".class") or value.endswith("module-info.class"):
        return ""
    return value[:-6].replace("/", ".")


def _iter_zip_classes(payload, prefix="", depth=0):
    if depth > 3:
        return
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for info in sorted(archive.infolist(), key=lambda item: item.filename):
            if info.is_dir():
                continue
            entry = f"{prefix}{info.filename}"
            lower = info.filename.lower()
            if lower.endswith(".class"):
                yield _class_owner(info.filename), entry, archive.read(info)
            elif lower.endswith((".jar", ".war", ".zip")):
                nested = archive.read(info)
                yield from _iter_zip_classes(nested, f"{entry}!/", depth + 1)


def _iter_artifact_classes(path):
    artifact = Path(path)
    if artifact.is_dir():
        for class_file in sorted(artifact.rglob("*.class")):
            relative = class_file.relative_to(artifact).as_posix()
            yield _class_owner(relative), relative, class_file.read_bytes()
        return
    require_safe_archive(artifact)
    yield from _iter_zip_classes(artifact.read_bytes())


def _parse_constant_pool(data):
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("invalid_classfile_magic")
    count = struct.unpack_from(">H", data, 8)[0]
    cp = {}
    offset = 10
    index = 1
    while index < count:
        if offset >= len(data):
            raise ValueError("truncated_constant_pool")
        tag = data[offset]
        offset += 1
        if tag == 1:
            if offset + 2 > len(data):
                raise ValueError("truncated_utf8_length")
            length = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            if offset + length > len(data):
                raise ValueError("truncated_utf8_value")
            cp[index] = {"tag": tag, "value": data[offset:offset + length].decode("utf-8", errors="replace")}
            offset += length
        elif tag == 3:
            cp[index] = {"tag": tag, "value": struct.unpack_from(">i", data, offset)[0]}
            offset += 4
        elif tag == 4:
            cp[index] = {"tag": tag, "value": struct.unpack_from(">f", data, offset)[0]}
            offset += 4
        elif tag == 5:
            cp[index] = {"tag": tag, "value": struct.unpack_from(">q", data, offset)[0]}
            offset += 8
            index += 1
        elif tag == 6:
            cp[index] = {"tag": tag, "value": struct.unpack_from(">d", data, offset)[0]}
            offset += 8
            index += 1
        elif tag in (7, 8, 16, 19, 20):
            cp[index] = {"tag": tag, "index": struct.unpack_from(">H", data, offset)[0]}
            offset += 2
        elif tag in (9, 10, 11, 12, 17, 18):
            cp[index] = {
                "tag": tag,
                "first": struct.unpack_from(">H", data, offset)[0],
                "second": struct.unpack_from(">H", data, offset + 2)[0],
            }
            offset += 4
        elif tag == 15:
            cp[index] = {"tag": tag}
            offset += 3
        else:
            raise ValueError(f"unsupported_constant_pool_tag:{tag}")
        if offset > len(data):
            raise ValueError("truncated_constant_pool_entry")
        index += 1
    return cp, offset


def _cp_utf8(cp, index):
    item = cp.get(index) or {}
    return str(item.get("value") or "") if item.get("tag") == 1 else ""


def _constant_value(cp, index):
    item = cp.get(index) or {}
    if item.get("tag") == 8:
        return _cp_utf8(cp, item.get("index"))
    if item.get("tag") in (3, 4, 5, 6):
        return item.get("value")
    raise ValueError(f"unsupported_constant_value_tag:{item.get('tag')}")


def _skip_attributes(data, offset, count):
    for _ in range(count):
        if offset + 6 > len(data):
            raise ValueError("truncated_attribute")
        length = struct.unpack_from(">I", data, offset + 2)[0]
        offset += 6 + length
        if offset > len(data):
            raise ValueError("truncated_attribute_body")
    return offset


def _class_fields(data):
    cp, offset = _parse_constant_pool(data)
    if offset + 8 > len(data):
        raise ValueError("truncated_class_header")
    this_class_index = struct.unpack_from(">H", data, offset + 2)[0]
    this_class = cp.get(this_class_index) or {}
    if this_class.get("tag") != 7:
        raise ValueError("invalid_this_class")
    internal_owner = _cp_utf8(cp, this_class.get("index")).replace("/", ".")
    if not internal_owner:
        raise ValueError("missing_internal_class_owner")
    offset += 6
    interface_count = struct.unpack_from(">H", data, offset)[0]
    offset += 2 + interface_count * 2
    if offset + 2 > len(data):
        raise ValueError("truncated_field_count")
    field_count = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    fields = []
    for _ in range(field_count):
        if offset + 8 > len(data):
            raise ValueError("truncated_field")
        name = _cp_utf8(cp, struct.unpack_from(">H", data, offset + 2)[0])
        descriptor = _cp_utf8(cp, struct.unpack_from(">H", data, offset + 4)[0])
        attr_count = struct.unpack_from(">H", data, offset + 6)[0]
        offset += 8
        value_marker = False
        value = None
        for _attr in range(attr_count):
            if offset + 6 > len(data):
                raise ValueError("truncated_field_attribute")
            attr_name = _cp_utf8(cp, struct.unpack_from(">H", data, offset)[0])
            attr_length = struct.unpack_from(">I", data, offset + 2)[0]
            body = offset + 6
            end = body + attr_length
            if end > len(data):
                raise ValueError("truncated_field_attribute_body")
            if attr_name == "ConstantValue":
                if attr_length != 2:
                    raise ValueError("invalid_constant_value_attribute")
                value = _constant_value(cp, struct.unpack_from(">H", data, body)[0])
                value_marker = True
            offset = end
        fields.append((name, descriptor, value_marker, value))
    return internal_owner, fields


def extract_constant_field_evidence(jar_path, owner, field_name, descriptor):
    artifact = Path(jar_path)
    artifact_sha = _sha256_file(artifact) if artifact.is_file() else ""
    expected_owner = str(owner or "").replace("/", ".")
    candidates = []
    failures = []
    try:
        for class_owner, entry, content in _iter_artifact_classes(artifact):
            if class_owner != expected_owner:
                continue
            try:
                internal_owner, fields = _class_fields(content)
            except (ValueError, struct.error) as exc:
                failures.append(f"{entry}:{type(exc).__name__}:{exc}")
                continue
            if internal_owner != class_owner:
                failures.append(
                    f"{entry}:class_owner_mismatch:{internal_owner}!={class_owner}"
                )
                continue
            for name, field_descriptor, has_value, value in fields:
                if name == field_name and field_descriptor == descriptor:
                    candidates.append((entry, has_value, value))
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        failures.append(f"{type(exc).__name__}:{exc}")
    if failures and not candidates:
        status = "incomplete"
    elif len(candidates) > 1:
        status = "ambiguous"
        failures.append("multiple_exact_field_definitions")
    elif not candidates:
        status = "field_not_found"
    else:
        status = "complete"
    entry, has_value, value = candidates[0] if len(candidates) == 1 else ("", False, None)
    return ConstantFieldEvidence(
        owner=expected_owner,
        field_name=str(field_name or ""),
        descriptor=str(descriptor or ""),
        has_constant_value=bool(has_value),
        constant_value=value,
        artifact_sha256=artifact_sha,
        artifact_entry=entry,
        status=status,
        failures=tuple(failures),
    )


def scan_consumer_field_links(artifact_paths, owner, field_name, descriptor):
    from business_bytecode_graph import parse_classfile_calls

    expected_owner = str(owner or "").replace("/", ".")
    links = []
    for artifact_path in artifact_paths or ():
        artifact = Path(artifact_path)
        artifact_sha = _sha256_file(artifact) if artifact.is_file() else ""
        for class_owner, entry, content in _iter_artifact_classes(artifact):
            edges = parse_classfile_calls(content, class_owner)
            if edges is None:
                continue
            for edge in edges:
                if edge.get("evidence_type") != "bytecode_field_access":
                    continue
                target_owner = str(edge.get("callee_jvm_owner") or "").replace("/", ".")
                target_field = str(edge.get("callee_key") or "").rsplit(".", 1)[-1]
                if (
                    target_owner != expected_owner
                    or target_field != field_name
                    or str(edge.get("callee_descriptor") or "") != descriptor
                ):
                    continue
                opcode_hex = str(edge.get("content") or "").rsplit("0x", 1)[-1]
                opcode = {
                    "b2": "getstatic", "b3": "putstatic",
                    "b4": "getfield", "b5": "putfield",
                }.get(opcode_hex, f"opcode_{opcode_hex}")
                links.append(FieldLinkEvidence(
                    consumer_owner=class_owner,
                    consumer_method=str(edge.get("caller_name") or ""),
                    consumer_descriptor=str(edge.get("caller_descriptor") or ""),
                    target_owner=expected_owner,
                    target_field=str(field_name or ""),
                    target_descriptor=str(descriptor or ""),
                    opcode=opcode,
                    instruction_offset=int(edge.get("instruction_offset") or 0),
                    artifact_sha256=artifact_sha,
                    artifact_entry=entry,
                ))
    return tuple(sorted(links, key=lambda item: (
        item.artifact_sha256, item.artifact_entry, item.consumer_method,
        item.consumer_descriptor, item.instruction_offset,
    )))


def classify_constant_impact(
    *, change_type, old_field_has_constant_value, source_reference_present,
    runtime_field_edge_present, source_artifact_aligned,
):
    if not source_artifact_aligned:
        compile_impact = "unverified"
    else:
        normalized = str(change_type or "").upper()
        if not source_reference_present:
            compile_impact = "source_reference_absent"
        elif normalized == "CONSTANT_VALUE_CHANGED":
            compile_impact = "recompile_value_change"
        elif normalized in {"REMOVED", "FIELD_REMOVED"}:
            compile_impact = "recompile_break"
        else:
            compile_impact = "recompile_review_required"

    normalized = str(change_type or "").upper()
    if runtime_field_edge_present:
        runtime_impact = "runtime_link_present"
    elif not source_artifact_aligned:
        runtime_impact = "unverified"
    elif old_field_has_constant_value and source_reference_present:
        runtime_impact = (
            "inlined_old_value"
            if normalized == "CONSTANT_VALUE_CHANGED"
            else "inlined_no_link"
        )
    else:
        runtime_impact = "runtime_link_absent"

    return ConstantImpact(
        compile_impact=compile_impact,
        runtime_link_impact=runtime_impact,
        old_field_has_constant_value=bool(old_field_has_constant_value),
        source_reference_present=bool(source_reference_present),
        runtime_field_edge_present=bool(runtime_field_edge_present),
        source_artifact_aligned=bool(source_artifact_aligned),
    )


def _javap(classpath, *args):
    completed = subprocess.run(
        ["javap", "-classpath", str(Path(classpath)), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"javap_failed:{completed.stderr.strip()}")
    return completed.stdout


def javap_field_has_constant_value(classpath, owner, field_name):
    lines = _javap(classpath, "-verbose", "-p", owner).splitlines()
    declaration = re.compile(rf"\b{re.escape(field_name)};$")
    in_field = False
    for line in lines:
        stripped = line.strip()
        if declaration.search(stripped):
            in_field = True
            continue
        if not in_field:
            continue
        if stripped.startswith("ConstantValue:"):
            return True
        if stripped == "}" or (line.startswith("  ") and not line.startswith("    ") and stripped.endswith(";")):
            return False
    return False


def javap_caller_has_field_link(classpath, caller, owner, field_name):
    output = _javap(classpath, "-c", "-p", caller)
    owner_path = str(owner).replace(".", "/")
    return bool(re.search(
        rf"//\s+Field\s+{re.escape(owner_path)}\.{re.escape(field_name)}:",
        output,
    ))
