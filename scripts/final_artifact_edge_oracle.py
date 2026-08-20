#!/usr/bin/env python3
"""Independently enumerate executable JVM edges from a packaged artifact."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from threading import Event, Lock
import time
import zipfile

from artifact_safety import inspect_archive_stream
from compat import (
    managed_popen,
    release_process_tree,
    run_managed_subprocess,
    terminate_process_tree,
)
from edge_truth import EdgeIdentity, canonical_edge_identity
from javap_contract import JAVAP_STABLE_JVM_OPTIONS, javap_command
from path_runtime import short_temporary_directory


INVOKE_OPCODES = {"invokevirtual", "invokeinterface", "invokestatic", "invokespecial", "invokedynamic"}
FIELD_OPCODES = {"getfield", "putfield", "getstatic", "putstatic"}
EDGE_OPCODES = INVOKE_OPCODES | FIELD_OPCODES
LDC_OPCODES = {"ldc", "ldc_w", "ldc2_w"}
NESTED_JAR_PREFIXES = ("BOOT-INF/lib/", "WEB-INF/lib/")
VERSIONED_CLASS_RE = re.compile(
    r"^META-INF/versions/(?P<version>[1-9][0-9]*)/(?P<logical>.+)$",
    re.ASCII,
)
MIN_MULTI_RELEASE_VERSION = 8
ACC_MODULE = 0x8000
CLASS_DECLARATION_RE = re.compile(
    r"^(?:\S+\s+)*(?:class|interface|enum|record)\s+"
    r'("(?:\\.|[^"\\])*"|[^\s<{]+)(?=\s|<|\{|$)'
)
HEADER_LINE_RE = re.compile(r"^ {2}(?! )(?P<header>.+);\s*$")
INSTRUCTION_RE = re.compile(r"^\s*(\d+):\s+([a-z][a-z0-9_]*)\b(.*)$")
METHOD_COMMENT_RE = re.compile(
    r"^(?P<reference_type>InterfaceMethod|Method)\s+"
    r"(?P<target>.+):(?P<descriptor>\(.*)$"
)
FIELD_COMMENT_RE = re.compile(
    r"^Field\s+(?P<target>.+):"
    r"(?P<descriptor>(?:\[*[BCDFIJSZ]|\[*L.+;))$"
)
CONSTANT_POOL_DYNAMIC_RE = re.compile(
    r"^\s*#(?P<constant>\d+)\s+=\s+InvokeDynamic\s+#(?P<bootstrap>\d+):#\d+\s+"
    r"//\s+#\d+:(?P<member>.+):(?P<descriptor>\(.*)$"
)
DYNAMIC_COMMENT_RE = re.compile(
    r"^InvokeDynamic\s+#(?P<bootstrap>\d+):(?P<member>.+):(?P<descriptor>\(.*)$"
)
CONSTANT_POOL_CONSTANT_DYNAMIC_RE = re.compile(
    r"^\s*#(?P<constant>\d+)\s+=\s+Dynamic\s+#(?P<bootstrap>\d+):#\d+\s+"
    r"//\s+#\d+:(?P<member>.+):"
    r"(?P<descriptor>(?:\[*[BCDFIJSZ]|\[*L.+;))$"
)
CONSTANT_DYNAMIC_COMMENT_RE = re.compile(
    r"^Dynamic\s+#(?P<bootstrap>\d+):(?P<member>.+):"
    r"(?P<descriptor>(?:\[*[BCDFIJSZ]|\[*L.+;))$"
)
BOOTSTRAP_REFERENCE_RE = re.compile(
    r"^\s*(?P<index>\d+):\s+#(?P<constant>\d+)\s+"
    r"(?P<reference_kind>REF_\w+)\s+"
    r"(?P<target>.+):"
    r"(?P<descriptor>\(.*|(?:\[*[BCDFIJSZ]|\[*L.+;))$"
)
BOOTSTRAP_HANDLE_RE = re.compile(
    r"(?:#(?P<constant>\d+)\s+)?(?P<reference_kind>REF_\w+)\s+"
    r"(?P<target>.+):"
    r"(?P<descriptor>\(.*|(?:\[*[BCDFIJSZ]|\[*L.+;))$"
)
BOOTSTRAP_CONSTANT_DYNAMIC_ARGUMENT_RE = re.compile(
    r"^\s+#(?P<constant>\d+)\s+#(?P<bootstrap>\d+):(?P<member>.+):"
    r"(?P<descriptor>(?:\[*[BCDFIJSZ]|\[*L.+;))$"
)
LDC_HANDLE_COMMENT_RE = re.compile(
    r"^MethodHandle\s+(?P<reference_kind>REF_\w+)\s+(?P<target>.+):"
    r"(?P<descriptor>\(.*|(?:\[*[BCDFIJSZ]|\[*L.+;))$"
)
CONSTANT_POOL_MEMBER_REFERENCE_KIND_RE = re.compile(
    r"^\s*#(?P<constant>\d+)\s+=\s+"
    r"(?P<kind>Fieldref|Methodref|InterfaceMethodref)\s+"
)
CONSTANT_POOL_METHOD_HANDLE_TARGET_RE = re.compile(
    r"^\s*#(?P<constant>\d+)\s+=\s+MethodHandle\s+\d+:#(?P<target>\d+)\s+"
)
CONSTANT_POOL_CLASS_RE = re.compile(
    r"^\s*#(?P<constant>\d+)\s+=\s+Class\s+#\d+\s+//\s+(?P<value>.+)$"
)
CONSTANT_POOL_METHOD_TYPE_RE = re.compile(
    r"^\s*#(?P<constant>\d+)\s+=\s+MethodType\s+#\d+\s+//\s+"
    r"(?P<value>.+)$"
)
LINKER_BOOTSTRAP_OWNERS = {
    "java.lang.invoke.LambdaMetafactory",
    "java.lang.invoke.StringConcatFactory",
}
METHOD_HANDLE_REFERENCE_KIND_BY_TAG = {
    1: "REF_getField",
    2: "REF_getStatic",
    3: "REF_putField",
    4: "REF_putStatic",
    5: "REF_invokeVirtual",
    6: "REF_invokeStatic",
    7: "REF_invokeSpecial",
    8: "REF_newInvokeSpecial",
    9: "REF_invokeInterface",
}
METHOD_HANDLE_REFERENCE_KINDS = frozenset(
    METHOD_HANDLE_REFERENCE_KIND_BY_TAG.values()
)
PROCEDURE = (
    "javap with stable English/UTF-8 JVM properties -c -p -s "
    "<exact class-file path or staged-JAR entry URL>; add -sysinfo to "
    "non-verbose multi-class batches "
    "for path-bound output segmentation; add -v for classes with BootstrapMethods or "
    "CONSTANT_MethodHandle entries; "
    "bind caller owner/name/descriptor identities from strict-MUTF8 raw "
    "classfile member_info and bind BootstrapMethods arguments to raw "
    "constant-pool tags; retain ordinary Fieldref/Methodref/InterfaceMethodref "
    "constant-pool kind independently from opcode; enumerate executable "
    "final-artifact and dynamic-linkage edges; independently expand direct and "
    "recursive-bootstrap CONSTANT_MethodType/Class providers plus invokedynamic "
    "call-site, ConstantDynamic nominal-type, MethodHandle, and ordinary "
    "field/method/interface-method reference descriptors; "
    "exclude only structurally valid "
    "ACC_MODULE module descriptors and retain malformed ACC_MODULE classfiles "
    "for fail-closed scanning"
)
ORACLE_PROCEDURE_VERSION = "java-upgrade-analyzer.final-artifact-javap.v17"
MAX_JAVAP_WORKERS = 8
# Windows' command-line limit is much smaller than POSIX ARG_MAX. On POSIX,
# larger batches materially reduce target-JVM startup overhead while remaining
# far below the platform argument boundary, even for long extracted paths.
# Python launches javap through CreateProcess rather than cmd.exe, so Windows'
# applicable command-line ceiling is 32,767 UTF-16 code units.  The previous
# fixed batch of 32 left most of that budget unused and multiplied JVM cold
# starts across large dependency sets.  Keep explicit headroom for quoting,
# the executable path and JVM options, and additionally enforce the actual
# rendered command length for every group below.
# The rendered-command budget remains the effective Windows guard for real
# extracted paths.  A higher count ceiling lets short paths use the available
# CreateProcess budget and commonly turns a 250-500 class JAR from 2-4 JVM
# cold starts into one, while POSIX keeps its established output-size bound.
MAX_CLASSES_PER_JAVAP_BATCH = 512 if os.name == "nt" else 256
MAX_JAVAP_COMMAND_CHARS = 24_000 if os.name == "nt" else 0
# Validation scans artifacts concurrently. Retain bytes only for ordinary
# artifacts whose selected class set fits this per-scan bound; larger archives
# keep the established file-backed path. At eight workers this adds at most
# 128 MiB while eliminating small-file churn for the usual dependencies.
MAX_STAGED_JAVAP_CLASS_BYTES = 16 * 1024 * 1024
USE_STAGED_JAVAP_ARCHIVE = os.name == "nt"
JAVAP_VERSION_TIMEOUT_SECONDS = 5.0
_IMMUTABLE_ORACLE_CACHE: dict[tuple[str, str, str, str, str], str] = {}
_JAVAP_VERSION_CACHE: dict[tuple[str, int, int, int], str] = {}
_IMMUTABLE_ORACLE_CACHE_LOCK = Lock()


@dataclass(frozen=True)
class PackagedClass:
    artifact_entry: str
    extracted_path: Path
    content: bytes | None = None
    requires_verbose_javap: bool | None = None
    javap_argument: str = ""


@dataclass(frozen=True)
class ClassfileMember:
    kind: str
    name: str
    descriptor: str
    access_flags: int


@dataclass(frozen=True)
class ClassfileMemberInventory:
    owner: str
    members: tuple[ClassfileMember, ...]
    class_access_flags: int
    major_version: int
    super_class: int
    interface_count: int
    class_attributes: tuple[str, ...]
    class_constants: tuple[tuple[int, str], ...]
    method_type_constants: tuple[tuple[int, str], ...]
    constant_pool_tags: tuple[tuple[int, int], ...]
    javap_reference_text_lossy: bool = False


@dataclass(frozen=True)
class BootstrapReferenceSet:
    bootstrap: tuple[str, str, str, str, bool | None]
    argument_handles: tuple[tuple[str, str, str, str, bool | None], ...]
    constant_dynamic_arguments: tuple[int, ...]
    type_arguments: tuple[tuple[str, str], ...]


def clear_immutable_oracle_cache() -> None:
    """Reset process-local immutable oracle results for isolated tests."""
    with _IMMUTABLE_ORACLE_CACHE_LOCK:
        _IMMUTABLE_ORACLE_CACHE.clear()
        _JAVAP_VERSION_CACHE.clear()


def _decode_modified_utf8(value: bytes) -> str:
    """Decode the JVM's strict modified-UTF8 CONSTANT_Utf8 representation."""
    # CONSTANT_Utf8 is *not* ordinary UTF-8.  In particular, a literal zero
    # byte and four-byte UTF-8 are forbidden, NUL is encoded as C0 80, and a
    # supplementary character is represented by two independently encoded
    # UTF-16 surrogate code units.  Decode code units first so that valid
    # unpaired surrogates remain representable in Python as well.
    code_units: list[int] = []
    index = 0

    def invalid(start: int, end: int, reason: str) -> UnicodeDecodeError:
        return UnicodeDecodeError("modified UTF-8", value, start, end, reason)

    while index < len(value):
        first = value[index]
        if 0x01 <= first <= 0x7F:
            code_units.append(first)
            index += 1
            continue
        if first == 0:
            raise invalid(index, index + 1, "literal NUL byte is forbidden")
        if 0xC0 <= first <= 0xDF:
            if index + 1 >= len(value):
                raise invalid(index, len(value), "truncated two-byte sequence")
            second = value[index + 1]
            if second & 0xC0 != 0x80:
                raise invalid(index + 1, index + 2, "invalid continuation byte")
            code_unit = ((first & 0x1F) << 6) | (second & 0x3F)
            if code_unit == 0:
                if first != 0xC0 or second != 0x80:
                    raise invalid(index, index + 2, "invalid NUL encoding")
            elif code_unit < 0x80:
                raise invalid(index, index + 2, "overlong two-byte sequence")
            code_units.append(code_unit)
            index += 2
            continue
        if 0xE0 <= first <= 0xEF:
            if index + 2 >= len(value):
                raise invalid(index, len(value), "truncated three-byte sequence")
            second, third = value[index + 1:index + 3]
            if second & 0xC0 != 0x80:
                raise invalid(index + 1, index + 2, "invalid continuation byte")
            if third & 0xC0 != 0x80:
                raise invalid(index + 2, index + 3, "invalid continuation byte")
            code_unit = (
                ((first & 0x0F) << 12)
                | ((second & 0x3F) << 6)
                | (third & 0x3F)
            )
            if code_unit < 0x800:
                raise invalid(index, index + 3, "overlong three-byte sequence")
            code_units.append(code_unit)
            index += 3
            continue
        raise invalid(index, index + 1, "invalid modified UTF-8 leading byte")

    utf16 = b"".join(code_unit.to_bytes(2, "big") for code_unit in code_units)
    return utf16.decode("utf-16-be", errors="surrogatepass")


def _contains_unpaired_surrogate(value: str) -> bool:
    # Valid high+low pairs were combined by the MUTF-8 decoder.  Any remaining
    # surrogate code point is isolated and Java's UTF-8 stdout encoder replaces
    # it with '?', so a javap reference comment cannot be authoritative.
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _classfile_member_inventory(content: bytes) -> ClassfileMemberInventory:
    """Read only class/member identities, independently of production ASM.

    The bridge deliberately does not interpret bytecode. Its sole purpose is
    to bind javap Code blocks when javap prints a legal JVM name containing
    source-illegal characters (including a literal quote or newline).
    """
    data = memoryview(content)
    cursor = 0

    def take(size: int) -> bytes:
        nonlocal cursor
        if size < 0 or cursor + size > len(data):
            raise ValueError("truncated classfile")
        result = bytes(data[cursor:cursor + size])
        cursor += size
        return result

    def skip(size: int) -> None:
        nonlocal cursor
        if size < 0 or cursor + size > len(data):
            raise ValueError("truncated classfile")
        cursor += size

    def u1() -> int:
        return int.from_bytes(take(1), "big")

    def u2() -> int:
        return int.from_bytes(take(2), "big")

    def u4() -> int:
        return int.from_bytes(take(4), "big")

    if take(4) != b"\xca\xfe\xba\xbe":
        raise ValueError("invalid classfile magic")
    take(2)  # minor_version
    major_version = u2()
    constant_pool_count = u2()
    if constant_pool_count < 1:
        raise ValueError("invalid constant_pool_count")
    utf8: dict[int, str] = {}
    class_name_indexes: dict[int, int] = {}
    method_type_descriptor_indexes: dict[int, int] = {}
    name_and_type_indexes: dict[int, tuple[int, int]] = {}
    member_reference_indexes: dict[int, tuple[int, int]] = {}
    constant_pool_tags: dict[int, int] = {}
    index = 1
    while index < constant_pool_count:
        tag = u1()
        constant_pool_tags[index] = tag
        if tag == 1:
            utf8[index] = _decode_modified_utf8(take(u2()))
        elif tag in {3, 4}:
            take(4)
        elif tag in {5, 6}:
            take(8)
            index += 1
        elif tag == 7:
            class_name_indexes[index] = u2()
        elif tag in {8, 19, 20}:
            take(2)
        elif tag == 16:
            method_type_descriptor_indexes[index] = u2()
        elif tag in {9, 10, 11}:
            member_reference_indexes[index] = (u2(), u2())
        elif tag == 12:
            name_and_type_indexes[index] = (u2(), u2())
        elif tag in {17, 18}:
            take(4)
        elif tag == 15:
            take(3)
        else:
            raise ValueError(f"unknown constant-pool tag {tag}")
        index += 1

    def utf8_at(index_value: int, role: str) -> str:
        result = utf8.get(index_value)
        if result is None:
            raise ValueError(f"invalid {role} UTF8 index {index_value}")
        return result

    javap_reference_text_lossy = any(
        _contains_unpaired_surrogate(
            utf8_at(name_index, "class reference name")
        )
        for name_index in class_name_indexes.values()
    )
    for class_index, name_and_type_index in member_reference_indexes.values():
        class_name_index = class_name_indexes.get(class_index)
        name_and_type = name_and_type_indexes.get(name_and_type_index)
        if class_name_index is None or name_and_type is None:
            raise ValueError("invalid member reference indexes")
        name_index, descriptor_index = name_and_type
        if any(_contains_unpaired_surrogate(value) for value in (
            utf8_at(class_name_index, "member reference owner"),
            utf8_at(name_index, "member reference name"),
            utf8_at(descriptor_index, "member reference descriptor"),
        )):
            javap_reference_text_lossy = True

    class_constants = tuple(
        (constant_index, utf8_at(name_index, "class constant name"))
        for constant_index, name_index in sorted(class_name_indexes.items())
    )
    method_type_constants = tuple(
        (
            constant_index,
            utf8_at(descriptor_index, "MethodType descriptor"),
        )
        for constant_index, descriptor_index in sorted(
            method_type_descriptor_indexes.items()
        )
    )

    class_access_flags = u2()
    this_class = u2()
    super_class = u2()
    owner_name_index = class_name_indexes.get(this_class)
    if owner_name_index is None:
        raise ValueError(f"invalid this_class index {this_class}")
    owner = utf8_at(owner_name_index, "class name")
    interface_count = u2()
    for _ in range(interface_count):
        take(2)

    def skip_attributes() -> tuple[str, ...]:
        names: list[str] = []
        for _ in range(u2()):
            name_index = u2()
            names.append(utf8_at(name_index, "attribute name"))
            # Do not duplicate an arbitrarily large Code/custom attribute just
            # to advance over it; the caller already owns the class bytes.
            skip(u4())
        return tuple(names)

    def read_members(kind: str) -> list[ClassfileMember]:
        members: list[ClassfileMember] = []
        for _ in range(u2()):
            access_flags = u2()
            name = utf8_at(u2(), f"{kind} name")
            descriptor = utf8_at(u2(), f"{kind} descriptor")
            skip_attributes()
            members.append(ClassfileMember(
                kind=kind,
                name=name,
                descriptor=descriptor,
                access_flags=access_flags,
            ))
        return members

    members = read_members("field")
    members.extend(read_members("method"))
    class_attributes = skip_attributes()
    if cursor != len(data):
        raise ValueError("trailing classfile bytes")
    return ClassfileMemberInventory(
        owner=owner,
        members=tuple(members),
        class_access_flags=class_access_flags,
        major_version=major_version,
        super_class=super_class,
        interface_count=interface_count,
        class_attributes=class_attributes,
        class_constants=class_constants,
        method_type_constants=method_type_constants,
        constant_pool_tags=tuple(sorted(constant_pool_tags.items())),
        javap_reference_text_lossy=javap_reference_text_lossy,
    )


_MODULE_DESCRIPTOR_ATTRIBUTES = frozenset({
    "Module",
    "ModulePackages",
    "ModuleMainClass",
    "InnerClasses",
    "SourceFile",
    "SourceDebugExtension",
    "RuntimeVisibleAnnotations",
    "RuntimeInvisibleAnnotations",
    "RuntimeVisibleTypeAnnotations",
    "RuntimeInvisibleTypeAnnotations",
})


def _classfile_is_valid_module_descriptor(content: bytes) -> bool:
    """Recognize the basic JVMS 4.1 constraints for module descriptors."""
    try:
        inventory = _classfile_member_inventory(content)
    except (UnicodeError, ValueError):
        return False
    return bool(
        inventory.class_access_flags == ACC_MODULE
        and inventory.major_version >= 53
        and inventory.owner == "module-info"
        and inventory.super_class == 0
        and inventory.interface_count == 0
        and not inventory.members
        and inventory.class_attributes.count("Module") == 1
        and set(inventory.class_attributes) <= _MODULE_DESCRIPTOR_ATTRIBUTES
    )


def _entry_member_inventory(
    entry: PackagedClass,
) -> tuple[ClassfileMemberInventory | None, str | None]:
    content = entry.content
    if content is None:
        try:
            content = entry.extracted_path.read_bytes()
        except OSError as error:
            return None, f"classfile member_info read failed: {error}"
    try:
        return _classfile_member_inventory(content), None
    except (UnicodeError, ValueError) as error:
        return None, f"classfile member_info parse failed: {error}"


def _javap_lines(output: str) -> list[str]:
    """Split only on process line endings, not Unicode identifier content.

    ``str.splitlines`` also treats NEL, vertical-tab and Unicode line/paragraph
    separators as boundaries.  Those code points are legal in JVM identifiers
    and javap does not emit them as platform line terminators.
    """
    return output.split("\n")


def _javap_embedded_lines(value: str) -> list[str]:
    """Mirror subprocess universal-newline normalization inside javap text."""
    return value.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def _oracle_cache_key(
    artifact_sha256: str,
    jdk_version: str,
    selected_targets: tuple[tuple[str, str, str], ...],
    excluded_nested_jars: tuple[str, ...] = (),
    include_nested_runtime_jars: bool = True,
    include_structural_facts: bool = False,
) -> tuple[str, str, str, str, str]:
    target_scope = json.dumps(
        {
            "targets": selected_targets,
            "excluded_nested_jars": excluded_nested_jars,
            "include_nested_runtime_jars": include_nested_runtime_jars,
            "include_structural_facts": include_structural_facts,
        },
        separators=(",", ":"),
    )
    return artifact_sha256, ORACLE_PROCEDURE_VERSION, PROCEDURE, jdk_version, target_scope


def _normalize_selected_targets(selected_targets: list[dict] | None) -> tuple[tuple[str, str, str], ...]:
    normalized = set()
    for target in selected_targets or []:
        owner = str((target or {}).get("owner") or "").strip().replace("/", ".")
        member = str((target or {}).get("member") or "").strip()
        descriptor = str((target or {}).get("descriptor") or "").strip()
        if owner and member:
            normalized.add((owner, member, descriptor))
    return tuple(sorted(normalized))


def _entry_might_reference(entry: PackagedClass, targets: set[tuple[str, str, str]]) -> bool:
    content = entry.content
    if content is None:
        try:
            content = entry.extracted_path.read_bytes()
        except OSError:
            return True
    for owner, member, descriptor in targets:
        if owner.replace(".", "/").encode() not in content:
            continue
        if member.encode() not in content:
            continue
        if descriptor and descriptor.encode() not in content:
            continue
        return True
    return False


def _edge_targets(edge: dict, targets: set[tuple[str, str, str]]) -> bool:
    owner = str(edge.get("callee_owner") or "")
    member = str(edge.get("callee_member") or "")
    descriptor = str(edge.get("callee_descriptor") or "")
    return any(
        owner == target_owner
        and member == target_member
        and (not target_descriptor or descriptor == target_descriptor)
        for target_owner, target_member, target_descriptor in targets
    )


def _reverse_target_closure(
    rows: list[dict], targets: set[tuple[str, str, str]]
) -> list[dict]:
    """Keep only physical edges that participate in the selected reverse closure."""
    frontier = set(targets)
    expanded: set[tuple[str, str, str]] = set()
    selected_indexes: set[int] = set()
    while frontier:
        pending = frontier - expanded
        if not pending:
            break
        expanded.update(pending)
        matched_indexes = {
            index for index, edge in enumerate(rows)
            if _edge_targets(edge, pending)
        }
        selected_indexes.update(matched_indexes)
        frontier.update({
            (
                str(rows[index].get("caller_owner") or ""),
                str(rows[index].get("caller_member") or ""),
                str(rows[index].get("caller_descriptor") or ""),
            )
            for index in matched_indexes
        })
    return [row for index, row in enumerate(rows) if index in selected_indexes]


def _is_runtime_class(entry: str) -> bool:
    return (
        entry.endswith(".class")
        and not entry.startswith("META-INF/")
    )


def _is_nested_jar(entry: str) -> bool:
    return entry.endswith(".jar") and entry.startswith(NESTED_JAR_PREFIXES)


def _logical_class_entry(info: zipfile.ZipInfo) -> tuple[str, int] | None:
    versioned_match = VERSIONED_CLASS_RE.match(info.filename)
    if versioned_match:
        version = int(versioned_match.group("version"))
        if version < MIN_MULTI_RELEASE_VERSION:
            return None
        logical = versioned_match.group("logical")
        if any(part in {"", ".", ".."} for part in logical.split("/")):
            return None
        if not _is_runtime_class(logical):
            return None
        return logical, version
    if _is_runtime_class(info.filename):
        return info.filename, 0
    return None


def _select_effective_classes(
    infos: list[zipfile.ZipInfo], target_major: int | None, scope: str, multi_release: bool
) -> tuple[list[zipfile.ZipInfo], list[str]]:
    grouped: dict[str, dict[int, list[zipfile.ZipInfo]]] = {}
    for info in infos:
        logical = _logical_class_entry(info)
        if logical is None:
            continue
        logical_name, version = logical
        grouped.setdefault(logical_name, {}).setdefault(version, []).append(info)

    selected: list[zipfile.ZipInfo] = []
    failures: list[str] = []
    for logical_name in sorted(grouped):
        candidates = grouped[logical_name]
        eligible_versions = [
            version for version in candidates
            if version == 0 or (
                multi_release
                and target_major is not None
                and target_major >= 9
                and version <= target_major
            )
        ]
        if multi_release and target_major is None and any(version > 0 for version in candidates):
            failures.append(f"{scope}!/{logical_name}: cannot resolve versioned class without javap major version")
            continue
        if not eligible_versions:
            continue
        selected_version = max(eligible_versions)
        duplicate_versions = [
            version for version, entries in candidates.items()
            if version == selected_version and len(entries) != 1
        ]
        if duplicate_versions:
            versions = ",".join(str(version) for version in sorted(duplicate_versions))
            failures.append(f"{scope}!/{logical_name}: duplicate logical class entry for version(s) {versions}")
            continue
        selected.append(candidates[selected_version][0])
    return selected, failures


def _is_multi_release_archive(archive: zipfile.ZipFile) -> bool:
    manifests = [
        info for info in archive.infolist()
        if not info.is_dir()
        and info.filename.lower() == "meta-inf/manifest.mf"
    ]
    if len(manifests) != 1:
        return False
    for info in manifests:
        try:
            manifest = archive.read(info).decode("utf-8", errors="replace")
        except (OSError, zipfile.BadZipFile):
            return False
        attributes: dict[str, str] = {}
        continued: dict[str, bool] = {}
        physical_header_valid: dict[str, bool] = {}
        current_key: str | None = None
        # JAR manifests have CR/LF physical lines. ``str.splitlines()`` also
        # treats Unicode NEL/VT/LS/PS as separators and can manufacture a
        # Multi-Release header out of an ordinary attribute value, diverging
        # from java.util.jar and the production archive scanner.
        physical_lines = (
            manifest.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        )
        for line in physical_lines:
            if not line:
                break
            if line.startswith(" "):
                if current_key is not None:
                    attributes[current_key] += line[1:]
                    continued[current_key] = True
                continue
            key, separator, value = line.partition(":")
            if not separator:
                current_key = None
                continue
            current_key = key.strip().lower()
            attributes[current_key] = value.strip()
            continued[current_key] = False
            physical_header_valid[current_key] = bool(
                key.lower() == current_key and value.lower() == " true"
            )
        return bool(
            attributes.get("multi-release", "").strip().lower() == "true"
            and not continued.get("multi-release", False)
            and physical_header_valid.get("multi-release", False)
        )
    return False


def _multi_release_manifest_failures(
    archive: zipfile.ZipFile, scope: str,
) -> list[str]:
    manifests = [
        info for info in archive.infolist()
        if not info.is_dir()
        and info.filename.lower() == "meta-inf/manifest.mf"
    ]
    if len(manifests) <= 1 or not any(
        not info.is_dir()
        and info.filename.startswith("META-INF/versions/")
        for info in archive.infolist()
    ):
        return []
    return [
        f"{scope}: ambiguous case-insensitive MR manifest entries: "
        + ",".join(info.filename for info in manifests)
    ]


def _write_extracted_class(destination: Path, index: int, content: bytes) -> Path:
    class_path = destination / f"class-{index:06d}.class"
    class_path.write_bytes(content)
    return class_path


def _stage_javap_archive(
    destination: Path,
    entries: list[PackagedClass],
) -> list[PackagedClass]:
    """Store exact class bytes in one uncompressed JAR for javap URL input."""

    archive_path = destination / "javap-classes.jar"
    archive_uri = archive_path.resolve().as_uri()
    staged: list[PackagedClass] = []
    with zipfile.ZipFile(
        archive_path, "x", compression=zipfile.ZIP_STORED, allowZip64=True
    ) as archive:
        for index, entry in enumerate(entries):
            if entry.content is None:
                raise ValueError("staged javap entry bytes are missing")
            archive_entry = f"classes/class-{index:06d}.class"
            archive.writestr(
                archive_entry,
                entry.content,
                compress_type=zipfile.ZIP_STORED,
            )
            staged.append(PackagedClass(
                artifact_entry=entry.artifact_entry,
                extracted_path=entry.extracted_path,
                content=entry.content,
                requires_verbose_javap=entry.requires_verbose_javap,
                javap_argument=f"jar:{archive_uri}!/{archive_entry}",
            ))
    return staged


def _classfile_header_facts(content: bytes) -> tuple[bool, int | None]:
    """Return ``(has_method_handle, access_flags)`` from a classfile header.

    Every BootstrapMethods entry references a CONSTANT_MethodHandle, while an
    LDC MethodHandle may have no BootstrapMethods attribute at all.  Parsing
    the pool shape therefore selects verbose javap exactly and avoids false
    positives from an unrelated UTF8/string value named ``BootstrapMethods``.

    The access flags distinguish a real module descriptor (``ACC_MODULE``)
    from a legal ordinary JVM class whose raw internal name or JAR entry is
    ``module-info``. Malformed input takes the conservative verbose path, is
    never silently classified as a module descriptor, and is rejected later
    by javap/raw member parsing.
    """
    data = memoryview(content)
    cursor = 0

    def skip(size: int) -> None:
        nonlocal cursor
        if size < 0 or cursor + size > len(data):
            raise ValueError("truncated classfile")
        cursor += size

    def u1() -> int:
        nonlocal cursor
        skip(1)
        return int(data[cursor - 1])

    def u2() -> int:
        nonlocal cursor
        skip(2)
        return int.from_bytes(data[cursor - 2:cursor], "big")

    try:
        if len(data) < 10 or bytes(data[:4]) != b"\xca\xfe\xba\xbe":
            raise ValueError("invalid classfile header")
        cursor = 8
        constant_pool_count = u2()
        if constant_pool_count < 1:
            raise ValueError("invalid constant_pool_count")
        has_method_handle = False
        index = 1
        while index < constant_pool_count:
            tag = u1()
            if tag == 15:
                has_method_handle = True
                skip(3)
            elif tag == 1:
                skip(u2())
            elif tag in {3, 4, 9, 10, 11, 12, 17, 18}:
                skip(4)
            elif tag in {5, 6}:
                skip(8)
                index += 1
            elif tag in {7, 8, 16, 19, 20}:
                skip(2)
            else:
                raise ValueError(f"unknown constant-pool tag {tag}")
            index += 1
        return has_method_handle, u2()
    except ValueError:
        return True, None


def _classfile_has_method_handle_constant(content: bytes) -> bool:
    return _classfile_header_facts(content)[0]


def _extract_packaged_classes(
    snapshot: bytes | Path | io.BufferedIOBase,
    destination: Path,
    target_major: int | None,
    *,
    defer_writes: bool = False,
    stage_javap_archive: bool = False,
    max_staged_class_bytes: int = MAX_STAGED_JAVAP_CLASS_BYTES,
    excluded_nested_jars: set[str] | None = None,
    include_nested_runtime_jars: bool = True,
) -> tuple[list[PackagedClass], list[str]]:
    entries: list[PackagedClass] = []
    failures: list[str] = []
    staged_class_bytes = 0
    staging_enabled = bool(stage_javap_archive)

    def spill_staged_entries() -> None:
        nonlocal entries, staging_enabled
        materialized: list[PackagedClass] = []
        for entry in entries:
            if entry.content is None:
                materialized.append(entry)
                continue
            try:
                path = _write_extracted_class(
                    destination, len(materialized), entry.content
                )
            except OSError as error:
                failures.append(
                    f"{entry.artifact_entry}: extract failed: {error}"
                )
                continue
            materialized.append(PackagedClass(
                entry.artifact_entry,
                path,
                None,
                entry.requires_verbose_javap,
            ))
        entries = materialized
        staging_enabled = False

    def append_class(
        artifact_entry: str,
        content: bytes,
        requires_verbose: bool,
    ) -> None:
        nonlocal staged_class_bytes, staging_enabled
        if staging_enabled:
            if staged_class_bytes + len(content) <= max_staged_class_bytes:
                path = destination / f"class-{len(entries):06d}.class"
                entries.append(PackagedClass(
                    artifact_entry,
                    path,
                    content,
                    requires_verbose,
                ))
                staged_class_bytes += len(content)
                return
            spill_staged_entries()
        path = destination / f"class-{len(entries):06d}.class"
        if not defer_writes:
            path = _write_extracted_class(destination, len(entries), content)
        entries.append(PackagedClass(
            artifact_entry,
            path,
            content if defer_writes else None,
            requires_verbose,
        ))

    try:
        if isinstance(snapshot, bytes):
            archive_source = io.BytesIO(snapshot)
        elif isinstance(snapshot, (str, Path)):
            archive_source = Path(snapshot)
        else:
            snapshot.seek(0)
            archive_source = snapshot
        with zipfile.ZipFile(archive_source) as outer:
            outer_infos = outer.infolist()
            # A Spring Boot executable archive runs application classes from
            # BOOT-INF/classes. Root-level class files are packaging byproducts,
            # not an additional runtime classpath, so scanning them would invent
            # duplicate executable edges and inflate the independent audit.
            boot_classes_prefix = "BOOT-INF/classes/"
            if any(
                not info.is_dir() and info.filename.startswith(boot_classes_prefix)
                for info in outer_infos
            ):
                direct_candidates = [
                    info for info in outer_infos if info.filename.startswith(boot_classes_prefix)
                ]
            else:
                direct_candidates = outer_infos
            manifest_failures = _multi_release_manifest_failures(
                outer, "final-artifact"
            )
            if manifest_failures:
                direct_infos, direct_failures = [], manifest_failures
            else:
                direct_infos, direct_failures = _select_effective_classes(
                    direct_candidates, target_major, "final-artifact",
                    _is_multi_release_archive(outer),
                )
            failures.extend(direct_failures)
            for info in direct_infos:
                try:
                    content = outer.read(info)
                    requires_verbose, access_flags = _classfile_header_facts(
                        content
                    )
                    if (
                        access_flags is not None
                        and access_flags & ACC_MODULE
                        and _classfile_is_valid_module_descriptor(content)
                    ):
                        continue
                    append_class(info.filename, content, requires_verbose)
                except (OSError, zipfile.BadZipFile) as error:
                    failures.append(f"{info.filename}: extract failed: {error}")

            if include_nested_runtime_jars:
                nested_by_name: dict[str, list[zipfile.ZipInfo]] = {}
                for info in outer_infos:
                    if not info.is_dir() and _is_nested_jar(info.filename):
                        nested_by_name.setdefault(info.filename, []).append(info)
                for nested_name in sorted(nested_by_name):
                    if nested_name in (excluded_nested_jars or set()):
                        continue
                    nested_infos = nested_by_name[nested_name]
                    if len(nested_infos) != 1:
                        failures.append(f"{nested_name}: duplicate nested JAR entry")
                        continue
                    nested_info = nested_infos[0]
                    try:
                        with zipfile.ZipFile(io.BytesIO(outer.read(nested_info))) as nested:
                            manifest_failures = _multi_release_manifest_failures(
                                nested, nested_name
                            )
                            if manifest_failures:
                                class_infos, nested_failures = [], manifest_failures
                            else:
                                class_infos, nested_failures = _select_effective_classes(
                                    nested.infolist(), target_major, nested_name,
                                    _is_multi_release_archive(nested),
                                )
                            failures.extend(nested_failures)
                            for class_info in class_infos:
                                content = nested.read(class_info)
                                requires_verbose, access_flags = (
                                    _classfile_header_facts(content)
                                )
                                if (
                                    access_flags is not None
                                    and access_flags & ACC_MODULE
                                    and _classfile_is_valid_module_descriptor(
                                        content
                                    )
                                ):
                                    continue
                                append_class(
                                    f"{nested_name}!/{class_info.filename}",
                                    content,
                                    requires_verbose,
                                )
                    except (OSError, zipfile.BadZipFile) as error:
                        failures.append(f"{nested_name}: nested JAR read failed: {error}")
    except (OSError, zipfile.BadZipFile) as error:
        failures.append(f"final-artifact: artifact read failed: {error}")
    if staging_enabled and entries:
        try:
            entries = _stage_javap_archive(destination, entries)
        except Exception:
            # This JAR is only a performance transport. Fall back to the
            # established exact class-file path; never weaken or fail an
            # analysis because an internal staging optimization was unusable.
            try:
                (destination / "javap-classes.jar").unlink()
            except OSError:
                pass
            spill_staged_entries()
    return entries, failures


_MEMBER_MODIFIERS = frozenset({
    "public", "protected", "private", "static", "final", "synchronized",
    "native", "abstract", "strictfp", "default", "transient", "volatile",
})
def _unquote_javap_identifier(value: str) -> str | None:
    value = str(value or "").strip()
    if not value:
        return None
    if not value.startswith('"'):
        return value if '"' not in value else None
    if not value.endswith('"'):
        return None
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, str) and decoded else None


def _strip_leading_type_parameters(value: str) -> str:
    value = value.strip()
    if not value.startswith("<"):
        return value
    depth = 0
    for index, character in enumerate(value):
        if character == "<":
            depth += 1
        elif character == ">":
            depth -= 1
            if depth == 0:
                return value[index + 1:].strip()
    return value


def _strip_member_modifiers(prefix: str) -> str:
    remaining = prefix.strip()
    while remaining:
        token = re.match(r"(?P<token>\S+)(?:\s+|$)", remaining)
        if token is None:
            break
        modifier = token.group("token")
        if modifier not in _MEMBER_MODIFIERS:
            break
        remaining = remaining[token.end():].strip()
    return _strip_leading_type_parameters(remaining)


def _member_name_from_declaration(
    declaration: str, caller_owner: str, *, method: bool
) -> str | None:
    remaining = _strip_member_modifiers(declaration)
    if not remaining:
        return None
    if method:
        constructor_name = _unquote_javap_identifier(remaining)
        if constructor_name in {
            caller_owner, caller_owner.rsplit(".", 1)[-1]
        }:
            return "<init>"

    generic_depth = 0
    quoted = False
    escaped = False
    separator = -1
    for index, character in enumerate(remaining):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quoted:
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
            continue
        if quoted:
            continue
        if character == "<":
            generic_depth += 1
        elif character == ">" and generic_depth:
            generic_depth -= 1
        elif character.isspace() and generic_depth == 0:
            separator = index
            break
    if separator < 0:
        return None
    candidate = remaining[separator:].strip()
    return _unquote_javap_identifier(candidate)


def _find_unquoted(value: str, target: str, start: int = 0) -> int:
    quoted = False
    escaped = False
    for index in range(start, len(value)):
        character = value[index]
        if escaped:
            escaped = False
            continue
        if character == "\\" and quoted:
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
            continue
        if character == target and not quoted:
            return index
    return -1


def _find_last_unquoted(value: str, target: str) -> int:
    found = -1
    start = 0
    while True:
        candidate = _find_unquoted(value, target, start)
        if candidate < 0:
            return found
        found = candidate
        start = candidate + 1


def _parse_member_header(line: str, caller_owner: str) -> tuple[str | None, str | None]:
    match = HEADER_LINE_RE.match(line)
    if not match:
        return None, None
    header = match.group("header").strip()
    if header == "static {}":
        return "<clinit>", "method"
    opening = _find_last_unquoted(header, "(")
    if opening < 0:
        assignment = _find_unquoted(header, "=")
        declaration = header[:assignment].strip() if assignment >= 0 else header
        candidate = _member_name_from_declaration(
            declaration, caller_owner, method=False
        )
        return (candidate, "field") if candidate else (None, "invalid")
    closing = _find_last_unquoted(header, ")")
    if closing < 0:
        return None, "invalid"
    before_parameters = header[:opening]
    suffix = header[closing + 1:]
    if suffix and not re.fullmatch(r"\s+throws\s+.+", suffix):
        return None, "invalid"
    candidate = _member_name_from_declaration(
        before_parameters, caller_owner, method=True
    )
    if candidate is None:
        return None, "invalid"
    return candidate, "method"


def _parse_qualified_member(
    target: str, caller_owner: str
) -> tuple[str, str] | None:
    owner_text, separator, member_text = target.rpartition(".")
    if not separator:
        owner_text = caller_owner.replace(".", "/")
        member_text = target
    owner = _unquote_javap_identifier(owner_text)
    member = _unquote_javap_identifier(member_text)
    if owner is None or member is None:
        return None
    return owner.replace("/", "."), member


def _field_descriptor_end(value: str, start: int = 0) -> int | None:
    index = start
    dimensions = 0
    while index < len(value) and value[index] == "[":
        dimensions += 1
        if dimensions > 255:
            return None
        index += 1
    if index >= len(value):
        return None
    if value[index] in "BCDFIJSZ":
        return index + 1
    if value[index] != "L":
        return None
    end = value.find(";", index + 1)
    if end < 0:
        return None
    internal_name = value[index + 1:end]
    if (
        not internal_name
        or "." in internal_name
        or "[" in internal_name
        or any(not segment for segment in internal_name.split("/"))
    ):
        return None
    return end + 1


def _is_field_descriptor(value: str) -> bool:
    return _field_descriptor_end(value) == len(value)


def _is_method_descriptor(value: str) -> bool:
    if not value.startswith("("):
        return False
    index = 1
    while index < len(value) and value[index] != ")":
        end = _field_descriptor_end(value, index)
        if end is None:
            return False
        index = end
    if index >= len(value) or value[index] != ")":
        return False
    index += 1
    if index < len(value) and value[index] == "V":
        return index + 1 == len(value)
    return _field_descriptor_end(value, index) == len(value)


def _method_type_reference_owners(value: str) -> tuple[str, ...] | None:
    """Independently expand object providers in a javap MethodType value."""
    descriptor = str(value or "")
    length = len(descriptor)
    owners: list[str] = []
    seen: set[str] = set()

    def field_type(offset: int) -> tuple[int, int] | None:
        dimensions = 0
        while offset < length and descriptor[offset] == "[":
            dimensions += 1
            if dimensions > 255:
                return None
            offset += 1
        if offset >= length:
            return None
        marker = descriptor[offset]
        if marker in "BCDFIJSZ":
            return offset + 1, (1 if dimensions or marker not in "JD" else 2)
        if marker != "L":
            return None
        end = descriptor.find(";", offset + 1)
        if end < 0:
            return None
        internal_name = descriptor[offset + 1:end]
        if (
            not internal_name
            or "." in internal_name
            or "[" in internal_name
            or any(not segment for segment in internal_name.split("/"))
        ):
            return None
        if internal_name not in seen:
            seen.add(internal_name)
            owners.append(internal_name)
        return end + 1, 1

    if length < 3 or not descriptor.startswith("("):
        return None
    cursor = 1
    parameter_slots = 0
    while cursor < length and descriptor[cursor] != ")":
        parsed = field_type(cursor)
        if parsed is None:
            return None
        cursor, slots = parsed
        parameter_slots += slots
        if parameter_slots > 255:
            return None
    if cursor >= length or descriptor[cursor] != ")":
        return None
    cursor += 1
    if cursor >= length:
        return None
    if descriptor[cursor] == "V":
        cursor += 1
    else:
        parsed = field_type(cursor)
        if parsed is None:
            return None
        cursor = parsed[0]
    return tuple(owners) if cursor == length else None


def _field_type_reference_owners(value: str) -> tuple[str, ...] | None:
    """Independently expand the provider resolved by one field descriptor.

    A primitive (or primitive array) is structurally valid but has no classfile
    provider.  Object arrays resolve the element class, matching the JVM
    descriptor-resolution rule used for MethodType constants.
    """
    descriptor = str(value or "")
    if _field_descriptor_end(descriptor) != len(descriptor):
        return None
    cursor = 0
    while descriptor[cursor] == "[":
        cursor += 1
    if descriptor[cursor] in "BCDFIJSZ":
        return ()
    return (descriptor[cursor + 1:-1],)


def _method_handle_reference_owners(
    handle: tuple[str, str, str, str, bool | None],
) -> tuple[str, ...] | None:
    """Expand descriptor providers for an independently parsed MethodHandle."""
    descriptor = handle[2]
    reference_kind = handle[3]
    if reference_kind in {
        "REF_getField", "REF_getStatic", "REF_putField", "REF_putStatic",
    }:
        return _field_type_reference_owners(descriptor)
    if reference_kind in METHOD_HANDLE_REFERENCE_KINDS:
        return _method_type_reference_owners(descriptor)
    return None


def _bootstrap_class_symbolic_owner(value: str) -> str | None:
    """Normalize a raw CONSTANT_Class bootstrap argument like production."""
    name = str(value or "")
    if name.startswith("["):
        return name if _is_field_descriptor(name) else None
    if (
        not name
        or "." in name
        or "[" in name
        or ";" in name
        or any(not segment for segment in name.split("/"))
    ):
        return None
    return name


def _parse_member_reference(
    comment: str, caller_owner: str,
) -> tuple[str, str, str, str] | None:
    match = METHOD_COMMENT_RE.match(comment)
    if not match or not _is_method_descriptor(match.group("descriptor")):
        return None
    target = _parse_qualified_member(match.group("target"), caller_owner)
    if target is None:
        return None
    owner, member = target
    return (
        owner,
        member,
        match.group("descriptor"),
        (
            "interface_method"
            if match.group("reference_type") == "InterfaceMethod"
            else "method"
        ),
    )


def _parse_field_reference(comment: str, caller_owner: str) -> tuple[str, str, str] | None:
    match = FIELD_COMMENT_RE.match(comment)
    if not match or not _is_field_descriptor(match.group("descriptor")):
        return None
    target = _parse_qualified_member(match.group("target"), caller_owner)
    if target is None:
        return None
    owner, member = target
    return owner, member, match.group("descriptor")


def _dynamic_references(output: str) -> dict[int, tuple[int, str, str]]:
    references: dict[int, tuple[int, str, str]] = {}
    for line in _javap_lines(output):
        match = CONSTANT_POOL_DYNAMIC_RE.match(line)
        if match and _is_method_descriptor(match.group("descriptor")):
            references[int(match.group("constant"))] = (
                int(match.group("bootstrap")),
                match.group("member"),
                match.group("descriptor"),
            )
    return references


def _constant_dynamic_references(
    output: str,
) -> dict[int, tuple[int, str, str]]:
    references: dict[int, tuple[int, str, str]] = {}
    for line in _javap_lines(output):
        match = CONSTANT_POOL_CONSTANT_DYNAMIC_RE.match(line)
        if match and _is_field_descriptor(match.group("descriptor")):
            references[int(match.group("constant"))] = (
                int(match.group("bootstrap")),
                match.group("member"),
                match.group("descriptor"),
            )
    return references


def _method_handle_interfaces(output: str) -> dict[int, bool]:
    """Resolve MethodHandle CP entries to Methodref vs InterfaceMethodref.

    ``REF_invokeStatic`` and ``REF_invokeSpecial`` do not encode this bit in
    javap's BootstrapMethods rendering.  The verbose constant-pool table does,
    so retain it independently instead of trusting the production ASM payload.
    """
    reference_interfaces: dict[int, bool] = {}
    handle_targets: dict[int, int] = {}
    for line in _javap_lines(output):
        reference = CONSTANT_POOL_MEMBER_REFERENCE_KIND_RE.match(line)
        if reference:
            reference_interfaces[int(reference.group("constant"))] = (
                reference.group("kind") == "InterfaceMethodref"
            )
            continue
        handle = CONSTANT_POOL_METHOD_HANDLE_TARGET_RE.match(line)
        if handle:
            handle_targets[int(handle.group("constant"))] = int(
                handle.group("target")
            )
    return {
        handle: reference_interfaces[target]
        for handle, target in handle_targets.items()
        if target in reference_interfaces
    }


def _javap_constant_type_values(
    output: str,
) -> tuple[dict[int, str], dict[int, str]]:
    """Read CONSTANT_Class/MethodType values from verbose javap output."""
    classes: dict[int, str] = {}
    method_types: dict[int, str] = {}
    for line in _javap_lines(output):
        class_match = CONSTANT_POOL_CLASS_RE.match(line)
        if class_match:
            rendered = _unquote_javap_identifier(
                class_match.group("value")
            )
            if rendered is not None:
                classes[int(class_match.group("constant"))] = rendered
            continue
        method_type_match = CONSTANT_POOL_METHOD_TYPE_RE.match(line)
        if method_type_match:
            method_types[int(method_type_match.group("constant"))] = (
                method_type_match.group("value")
            )
    return classes, method_types


def _bootstrap_references(
    output: str,
    constant_dynamic_references: dict[int, tuple[int, str, str]],
    member_inventory: ClassfileMemberInventory | None = None,
) -> dict[int, BootstrapReferenceSet]:
    in_bootstrap_section = False
    current_bootstrap: int | None = None
    handle_interfaces = _method_handle_interfaces(output)
    bootstraps: dict[int, tuple[str, str, str, str, bool | None]] = {}
    argument_handles: dict[
        int, list[tuple[str, str, str, str, bool | None]]
    ] = {}
    constant_dynamic_arguments: dict[int, list[int]] = {}
    type_arguments: dict[int, list[tuple[str, str]]] = {}
    javap_classes, javap_method_types = _javap_constant_type_values(output)
    raw_classes = (
        dict(member_inventory.class_constants)
        if member_inventory is not None else {}
    )
    raw_method_types = (
        dict(member_inventory.method_type_constants)
        if member_inventory is not None else {}
    )
    raw_constant_tags = (
        dict(member_inventory.constant_pool_tags)
        if member_inventory is not None else {}
    )
    class_constants = raw_classes or javap_classes
    method_type_constants = raw_method_types or javap_method_types
    invalid_bootstraps: set[int] = set()
    for line in _javap_lines(output):
        if line.strip() == "BootstrapMethods:":
            in_bootstrap_section = True
            continue
        if not in_bootstrap_section:
            continue
        # javap renders class-level attributes as unindented sections.  Text
        # such as ``REF_X`` in a later InnerClasses/NestMembers attribute is
        # not a bootstrap handle and must not invalidate the completed table.
        if line and not line[0].isspace():
            break
        start = BOOTSTRAP_REFERENCE_RE.match(line)
        if start:
            current_bootstrap = int(start.group("index"))
            argument_handles.setdefault(current_bootstrap, [])
            constant_dynamic_arguments.setdefault(current_bootstrap, [])
            type_arguments.setdefault(current_bootstrap, [])
            match = start
        else:
            match = BOOTSTRAP_HANDLE_RE.search(line)
            if match is not None and raw_constant_tags:
                constant_text = match.group("constant")
                if (
                    constant_text is None
                    or raw_constant_tags.get(int(constant_text)) != 15
                ):
                    # Bootstrap arguments are rendered as arbitrary text by
                    # javap.  A CONSTANT_String recipe such as ``REF_\u0001``
                    # must not be reinterpreted as a MethodHandle merely
                    # because its value resembles the handle rendering.
                    match = None
        if match is not None and current_bootstrap is not None:
            constant_text = match.group("constant")
            if (
                start
                and raw_constant_tags
                and (
                    constant_text is None
                    or raw_constant_tags.get(int(constant_text)) != 15
                )
            ):
                invalid_bootstraps.add(current_bootstrap)
                continue
            reference_kind = match.group("reference_kind")
            if reference_kind not in METHOD_HANDLE_REFERENCE_KINDS:
                invalid_bootstraps.add(current_bootstrap)
                continue
            descriptor = match.group("descriptor")
            descriptor_valid = (
                _is_field_descriptor(descriptor)
                if reference_kind in {
                    "REF_getField", "REF_getStatic",
                    "REF_putField", "REF_putStatic",
                }
                else _is_method_descriptor(descriptor)
            )
            if not descriptor_valid:
                invalid_bootstraps.add(current_bootstrap)
                continue
            member = _parse_qualified_member(match.group("target"), "")
            if member is None:
                invalid_bootstraps.add(current_bootstrap)
                continue
            target = (
                *member,
                descriptor,
                reference_kind,
                handle_interfaces.get(int(match.group("constant")))
                if match.group("constant") is not None else None,
            )
            if start:
                if current_bootstrap in bootstraps:
                    invalid_bootstraps.add(current_bootstrap)
                else:
                    bootstraps[current_bootstrap] = target
            elif target not in argument_handles[current_bootstrap]:
                # Field MethodHandles are linkage-bearing bootstrap arguments
                # too (for example the handles used by record ObjectMethods).
                argument_handles[current_bootstrap].append(target)
            continue

        if current_bootstrap is None:
            continue
        nested = BOOTSTRAP_CONSTANT_DYNAMIC_ARGUMENT_RE.match(line)
        if (
            nested is not None
            and raw_constant_tags
            and raw_constant_tags.get(int(nested.group("constant"))) != 17
        ):
            # A String bootstrap argument may legally look exactly like
            # javap's ConstantDynamic rendering.  The raw CP tag is the only
            # authoritative discriminator.
            nested = None
        if nested:
            constant_index = int(nested.group("constant"))
            expected = constant_dynamic_references.get(constant_index)
            rendered = (
                int(nested.group("bootstrap")),
                nested.group("member"),
                nested.group("descriptor"),
            )
            if expected != rendered:
                invalid_bootstraps.add(current_bootstrap)
            elif constant_index not in constant_dynamic_arguments[current_bootstrap]:
                constant_dynamic_arguments[current_bootstrap].append(
                    constant_index
                )
            continue
        argument_constant = re.match(r"^\s+#(?P<constant>\d+)\b", line)
        if argument_constant is not None:
            constant_index = int(argument_constant.group("constant"))
            if raw_constant_tags.get(constant_index) == 15:
                # A real MethodHandle argument that did not satisfy the strict
                # structural parser above is incomplete Oracle evidence.
                invalid_bootstraps.add(current_bootstrap)
                continue
            rendered_value = line[argument_constant.end():].strip()
            if constant_index in method_type_constants:
                expected = method_type_constants[constant_index]
                if (
                    rendered_value != expected
                    or (
                        constant_index in javap_method_types
                        and javap_method_types[constant_index] != expected
                    )
                    or _method_type_reference_owners(expected) is None
                ):
                    invalid_bootstraps.add(current_bootstrap)
                elif ("method_type", expected) not in type_arguments[
                    current_bootstrap
                ]:
                    type_arguments[current_bootstrap].append(
                        ("method_type", expected)
                    )
                continue
            if constant_index in class_constants:
                expected = class_constants[constant_index]
                rendered = _unquote_javap_identifier(rendered_value)
                if (
                    rendered != expected
                    or (
                        constant_index in javap_classes
                        and javap_classes[constant_index] != expected
                    )
                    or _bootstrap_class_symbolic_owner(expected) is None
                ):
                    invalid_bootstraps.add(current_bootstrap)
                elif ("type", expected) not in type_arguments[
                    current_bootstrap
                ]:
                    type_arguments[current_bootstrap].append(("type", expected))
                continue
        if (
            argument_constant is not None
            and int(argument_constant.group("constant"))
            in constant_dynamic_references
        ):
            # A ConstantDynamic argument affects executable bootstrap handles.
            # If javap rendered it in an unknown form, partial truth is unsafe.
            invalid_bootstraps.add(current_bootstrap)
    return {
        index: BootstrapReferenceSet(
            bootstrap=bootstrap,
            argument_handles=tuple(argument_handles.get(index, ())),
            constant_dynamic_arguments=tuple(
                constant_dynamic_arguments.get(index, ())
            ),
            type_arguments=tuple(type_arguments.get(index, ())),
        )
        for index, bootstrap in bootstraps.items()
        if index not in invalid_bootstraps
    }


def _bootstrap_argument_handles(
    bootstrap_index: int,
    bootstrap_references: dict[int, BootstrapReferenceSet],
    constant_dynamic_references: dict[int, tuple[int, str, str]],
    *,
    active_bootstraps: frozenset[int] = frozenset(),
) -> tuple[
    tuple[tuple[str, str, str, str, bool | None], ...], str | None
]:
    if bootstrap_index in active_bootstraps:
        return (), f"cyclic ConstantDynamic bootstrap {bootstrap_index}"
    reference_set = bootstrap_references.get(bootstrap_index)
    if reference_set is None:
        return (), f"unresolved bootstrap {bootstrap_index}"
    targets = list(reference_set.argument_handles)
    active = active_bootstraps | {bootstrap_index}
    for constant_index in reference_set.constant_dynamic_arguments:
        nested_dynamic = constant_dynamic_references.get(constant_index)
        if nested_dynamic is None:
            return (), f"unresolved ConstantDynamic constant #{constant_index}"
        nested_bootstrap = nested_dynamic[0]
        nested_reference_set = bootstrap_references.get(nested_bootstrap)
        if nested_reference_set is None:
            return (), f"unresolved ConstantDynamic bootstrap {nested_bootstrap}"
        targets.append(nested_reference_set.bootstrap)
        nested_targets, failure = _bootstrap_argument_handles(
            nested_bootstrap,
            bootstrap_references,
            constant_dynamic_references,
            active_bootstraps=active,
        )
        if failure:
            return (), failure
        targets.extend(nested_targets)
    # Production edge comparison is set-based. Preserve first-seen javap order
    # while avoiding duplicate rows for a repeated constant-pool handle.
    return tuple(dict.fromkeys(targets)), None


def _bootstrap_resolution_handles(
    bootstrap_index: int,
    bootstrap_references: dict[int, BootstrapReferenceSet],
    constant_dynamic_references: dict[int, tuple[int, str, str]],
    *,
    active_bootstraps: frozenset[int] = frozenset(),
) -> tuple[
    tuple[tuple[str, str, str, str, bool | None], ...], str | None
]:
    """Return every MethodHandle whose descriptor is resolved at a use site.

    Direct-linkage truth intentionally suppresses standard JDK indy linker
    bootstraps. Descriptor-resolution truth cannot do that: the VM resolves
    the bootstrap handle's method type even when the target is a standard
    linker. Nested ConstantDynamic arguments recursively do the same.
    """
    if bootstrap_index in active_bootstraps:
        return (), f"cyclic ConstantDynamic bootstrap {bootstrap_index}"
    reference_set = bootstrap_references.get(bootstrap_index)
    if reference_set is None:
        return (), f"unresolved bootstrap {bootstrap_index}"
    targets = [reference_set.bootstrap, *reference_set.argument_handles]
    active = active_bootstraps | {bootstrap_index}
    for constant_index in reference_set.constant_dynamic_arguments:
        nested_dynamic = constant_dynamic_references.get(constant_index)
        if nested_dynamic is None:
            return (), f"unresolved ConstantDynamic constant #{constant_index}"
        nested_targets, failure = _bootstrap_resolution_handles(
            nested_dynamic[0],
            bootstrap_references,
            constant_dynamic_references,
            active_bootstraps=active,
        )
        if failure:
            return (), failure
        targets.extend(nested_targets)
    return tuple(dict.fromkeys(targets)), None


def _bootstrap_argument_types(
    bootstrap_index: int,
    bootstrap_references: dict[int, BootstrapReferenceSet],
    constant_dynamic_references: dict[int, tuple[int, str, str]],
    *,
    active_bootstraps: frozenset[int] = frozenset(),
) -> tuple[tuple[tuple[str, str], ...], str | None]:
    """Return Class/MethodType args, including nested ConstantDynamic args."""
    if bootstrap_index in active_bootstraps:
        return (), f"cyclic ConstantDynamic bootstrap {bootstrap_index}"
    reference_set = bootstrap_references.get(bootstrap_index)
    if reference_set is None:
        return (), f"unresolved bootstrap {bootstrap_index}"
    targets = list(reference_set.type_arguments)
    active = active_bootstraps | {bootstrap_index}
    for constant_index in reference_set.constant_dynamic_arguments:
        nested_dynamic = constant_dynamic_references.get(constant_index)
        if nested_dynamic is None:
            return (), f"unresolved ConstantDynamic constant #{constant_index}"
        nested_bootstrap = nested_dynamic[0]
        if bootstrap_references.get(nested_bootstrap) is None:
            return (), f"unresolved ConstantDynamic bootstrap {nested_bootstrap}"
        # The nested constant's nominal field descriptor is resolved before
        # its bootstrap is invoked, independently of its static arguments.
        targets.append(("constant_dynamic", nested_dynamic[2]))
        nested_targets, failure = _bootstrap_argument_types(
            nested_bootstrap,
            bootstrap_references,
            constant_dynamic_references,
            active_bootstraps=active,
        )
        if failure:
            return (), failure
        targets.extend(nested_targets)
    return tuple(dict.fromkeys(targets)), None


def _parse_dynamic_reference(
    rest: str,
    comment: str,
    dynamic_references: dict[int, tuple[int, str, str]],
    bootstrap_references: dict[int, BootstrapReferenceSet],
    constant_dynamic_references: dict[int, tuple[int, str, str]],
) -> tuple[
    tuple[tuple[str, str, str, str, bool | None], ...], str | None
]:
    constant_match = re.search(r"#(\d+)", rest)
    comment_match = DYNAMIC_COMMENT_RE.match(comment)
    dynamic_reference = dynamic_references.get(int(constant_match.group(1))) if constant_match else None
    if (
        dynamic_reference is None
        and comment_match
        and _is_method_descriptor(comment_match.group("descriptor"))
    ):
        dynamic_reference = (
            int(comment_match.group("bootstrap")), comment_match.group("member"), comment_match.group("descriptor")
        )
    if dynamic_reference is None:
        return (), "unresolved invokedynamic bootstrap or constant-pool reference"
    bootstrap_index, _, _ = dynamic_reference
    reference_set = bootstrap_references.get(bootstrap_index)
    if reference_set is None:
        return (), f"unresolved invokedynamic bootstrap {bootstrap_index}"
    argument_handles, failure = _bootstrap_argument_handles(
        bootstrap_index,
        bootstrap_references,
        constant_dynamic_references,
    )
    if failure:
        return (), f"unresolved invokedynamic {failure}"
    targets = list(argument_handles)
    if reference_set.bootstrap[0] not in LINKER_BOOTSTRAP_OWNERS:
        targets.insert(0, reference_set.bootstrap)
    return tuple(dict.fromkeys(targets)), None


def _parse_constant_dynamic_reference(
    rest: str,
    comment: str,
    constant_dynamic_references: dict[int, tuple[int, str, str]],
    bootstrap_references: dict[int, BootstrapReferenceSet],
) -> tuple[
    tuple[str, str, str, str, bool | None] | None,
    tuple[tuple[str, str, str, str, bool | None], ...],
    str | None,
]:
    constant_match = re.search(r"#(\d+)", rest)
    comment_match = CONSTANT_DYNAMIC_COMMENT_RE.match(comment)
    dynamic_reference = (
        constant_dynamic_references.get(int(constant_match.group(1)))
        if constant_match else None
    )
    if (
        dynamic_reference is None
        and comment_match
        and _is_field_descriptor(comment_match.group("descriptor"))
    ):
        dynamic_reference = (
            int(comment_match.group("bootstrap")),
            comment_match.group("member"),
            comment_match.group("descriptor"),
        )
    if dynamic_reference is None:
        return None, (), (
            "unresolved ConstantDynamic bootstrap or constant-pool reference"
        )
    bootstrap_index, _, _ = dynamic_reference
    reference_set = bootstrap_references.get(bootstrap_index)
    if reference_set is None:
        return None, (), f"unresolved ConstantDynamic bootstrap {bootstrap_index}"
    handles, failure = _bootstrap_argument_handles(
        bootstrap_index,
        bootstrap_references,
        constant_dynamic_references,
    )
    if failure:
        return None, (), failure
    return reference_set.bootstrap, handles, None


def _parse_ldc_handle_reference(
    comment: str,
    caller_owner: str,
    is_interface: bool | None,
) -> tuple[str, str, str, str, bool | None] | None:
    match = LDC_HANDLE_COMMENT_RE.match(comment)
    if match is None:
        return None
    reference_kind = match.group("reference_kind")
    if reference_kind not in METHOD_HANDLE_REFERENCE_KINDS:
        return None
    descriptor = match.group("descriptor")
    descriptor_valid = (
        _is_field_descriptor(descriptor)
        if reference_kind in {
            "REF_getField", "REF_getStatic",
            "REF_putField", "REF_putStatic",
        }
        else _is_method_descriptor(descriptor)
    )
    if not descriptor_valid:
        return None
    target = _parse_qualified_member(match.group("target"), caller_owner)
    if target is None:
        return None
    return (*target, descriptor, reference_kind, is_interface)


def _edge_row(
    artifact_sha256: str,
    artifact_entry: str,
    authority_version: str,
    caller_owner: str,
    caller_member: str,
    caller_descriptor: str,
    callee: tuple[str, str, str],
    opcode: str,
    instruction_offset: int,
    reference_kind: str = "",
    reference_interface: bool | None = None,
) -> dict:
    identity = EdgeIdentity(
        artifact_sha256=artifact_sha256,
        caller_owner=caller_owner,
        caller_member=caller_member,
        caller_descriptor=caller_descriptor,
        callee_owner=callee[0],
        callee_member=callee[1],
        callee_descriptor=callee[2],
        opcode_family=opcode,
    )
    return {
        "artifact_sha256": identity.artifact_sha256,
        "artifact_entry": artifact_entry,
        "caller_owner": identity.caller_owner,
        "caller_member": identity.caller_member,
        "caller_descriptor": identity.caller_descriptor,
        "callee_owner": identity.callee_owner,
        "callee_member": identity.callee_member,
        "callee_descriptor": identity.callee_descriptor,
        "opcode_family": identity.opcode_family,
        "instruction_offset": instruction_offset,
        "reference_kind": reference_kind,
        "reference_interface": reference_interface,
        "authority": "jdk-javap",
        "authority_version": authority_version,
        "procedure": PROCEDURE,
    }


def _parse_javap_output(
    output: str,
    artifact_sha256: str,
    artifact_entry: str,
    authority_version: str,
    member_inventory: ClassfileMemberInventory | None = None,
) -> tuple[list[dict], list[str]]:
    caller_owner = (
        member_inventory.owner.replace("/", ".")
        if member_inventory is not None else ""
    )
    caller_member: str | None = None
    caller_descriptor = ""
    declaration_state: str | None = None
    # With raw member_info available, the owner and member table are
    # authoritative even when a legal source-illegal owner makes javap split
    # its declaration across physical lines.
    in_class_body = member_inventory is not None
    in_code_block = False
    member_inventory_index = 0
    member_inventory_closed = False
    raw_binding_failed = False
    descriptor_continuation: list[str] = []
    rows: list[dict] = []
    failures: list[str] = []
    if (
        member_inventory is not None
        and member_inventory.javap_reference_text_lossy
    ):
        return [], [
            f"{artifact_entry}: javap UTF-8 cannot losslessly render an "
            "unpaired-surrogate constant-pool reference"
        ]
    dynamic_references = _dynamic_references(output)
    constant_dynamic_references = _constant_dynamic_references(output)
    method_handle_interfaces = _method_handle_interfaces(output)
    bootstrap_references = _bootstrap_references(
        output, constant_dynamic_references, member_inventory
    )

    for line in _javap_lines(output):
        if descriptor_continuation:
            expected = descriptor_continuation.pop(0)
            if line != expected:
                failures.append(
                    f"{artifact_entry}: javap/classfile member descriptor "
                    f"continuation mismatch at index "
                    f"{member_inventory_index - 1}"
                )
                descriptor_continuation.clear()
                raw_binding_failed = True
                caller_member = None
                caller_descriptor = ""
                declaration_state = "invalid"
                in_code_block = False
            # Embedded newlines are part of the raw descriptor, not javap
            # structure.  Never reinterpret their continuation text.
            continue
        class_match = CLASS_DECLARATION_RE.match(line)
        if class_match:
            rendered_owner = _unquote_javap_identifier(
                class_match.group(1)
            ) or ""
            if member_inventory is not None:
                # A regular source-style name is unambiguous and remains a
                # useful batched-output cross-check.  For source-illegal names
                # (quotes, controls, spaces, etc.) javap rendering itself is
                # not authoritative; retain the raw owner instead.
                if (
                    re.fullmatch(
                        r"[A-Za-z0-9_$]+(?:/[A-Za-z0-9_$]+)*",
                        member_inventory.owner,
                    )
                    and rendered_owner.replace(".", "/")
                    != member_inventory.owner
                ):
                    failures.append(
                        f"{artifact_entry}: javap/classfile owner mismatch"
                    )
            else:
                caller_owner = rendered_owner
                caller_member = None
                caller_descriptor = ""
                declaration_state = None
            if member_inventory is None or line.rstrip().endswith("{"):
                in_class_body = line.rstrip().endswith("{")
            in_code_block = False
            continue
        stripped = line.strip()
        if caller_owner and line == "{":
            in_class_body = True
            in_code_block = False
            continue
        if (
            in_class_body
            and line == "}"
            and (
                member_inventory is None
                or member_inventory_index == len(member_inventory.members)
            )
        ):
            in_class_body = False
            member_inventory_closed = True
            caller_member = None
            caller_descriptor = ""
            declaration_state = None
            in_code_block = False
            continue
        if not in_class_body:
            continue
        # A two-space declaration starts a new member and therefore ends the
        # prior Code block even when its source-illegal name makes the header
        # itself unparseable.
        if member_inventory is not None and re.match(r"^ {2}\S", line):
            in_code_block = False
        if member_inventory is not None and line.startswith("    descriptor:"):
            if raw_binding_failed:
                continue
            if member_inventory_index >= len(member_inventory.members):
                failures.append(
                    f"{artifact_entry}: javap emitted an unexpected member "
                    "descriptor"
                )
                raw_binding_failed = True
                caller_member = None
                caller_descriptor = ""
                declaration_state = "invalid"
                in_code_block = False
                continue
            raw_member = member_inventory.members[member_inventory_index]
            descriptor_lines = _javap_embedded_lines(raw_member.descriptor)
            expected_first = f"    descriptor: {descriptor_lines[0]}"
            if line != expected_first:
                failures.append(
                    f"{artifact_entry}: javap/classfile member descriptor "
                    f"mismatch at index {member_inventory_index}"
                )
                raw_binding_failed = True
                caller_member = None
                caller_descriptor = ""
                declaration_state = "invalid"
                in_code_block = False
                continue
            member_inventory_index += 1
            # javap's source writer reapplies the current four-space member
            # indentation after every embedded CR/LF in a descriptor.
            descriptor_continuation = [
                f"    {part}" for part in descriptor_lines[1:]
            ]
            in_code_block = False
            if raw_member.kind == "field":
                caller_member = None
                caller_descriptor = ""
                declaration_state = "field"
                continue
            caller_member = raw_member.name
            caller_descriptor = raw_member.descriptor
            declaration_state = "method"
            if (
                caller_member == "<init>"
                and not raw_member.descriptor.endswith(")V")
            ):
                failures.append(
                    f"{artifact_entry}: constructor descriptor must return void"
                )
                caller_descriptor = ""
            continue
        parsed_member, parsed_state = (
            _parse_member_header(line, caller_owner)
            if caller_owner and member_inventory is None else (None, None)
        )
        if parsed_state is not None:
            caller_member = parsed_member
            caller_descriptor = ""
            declaration_state = parsed_state
            in_code_block = False
            continue
        if stripped.startswith("descriptor:"):
            parsed_descriptor = stripped.partition(":")[2].strip()
            if declaration_state == "field":
                continue
            if declaration_state != "method" or caller_member is None:
                failures.append(f"{artifact_entry}: descriptor without a valid header")
                caller_descriptor = ""
            else:
                if (
                    caller_member == "<init>"
                    and not parsed_descriptor.endswith(")V")
                ):
                    failures.append(
                        f"{artifact_entry}: constructor descriptor must return void"
                    )
                    caller_descriptor = ""
                else:
                    caller_descriptor = parsed_descriptor
            in_code_block = False
            continue
        if stripped == "Code:":
            if declaration_state != "method" or caller_member is None or not caller_descriptor:
                failures.append(f"{artifact_entry}: Code block without a valid header and descriptor")
                in_code_block = False
            else:
                in_code_block = True
            continue
        if not in_code_block:
            continue
        instruction_match = INSTRUCTION_RE.match(line)
        if not instruction_match:
            continue
        offset, opcode, rest = instruction_match.groups()
        if opcode not in EDGE_OPCODES and opcode not in LDC_OPCODES:
            continue
        if not caller_owner or declaration_state != "method" or caller_member is None or not caller_descriptor:
            failures.append(f"{artifact_entry}: missing caller context for {opcode} at {offset}")
            continue
        _, separator, comment = rest.partition("//")
        comment = comment.strip()
        if opcode in LDC_OPCODES:
            constant_match = re.search(r"#(\d+)", rest)
            known_constant_dynamic = bool(
                constant_match
                and int(constant_match.group(1))
                in constant_dynamic_references
            )
            if not separator:
                if known_constant_dynamic:
                    failures.append(
                        f"{artifact_entry}: missing constant-pool comment for "
                        f"ConstantDynamic at {offset}"
                    )
                continue
            if comment.startswith("Dynamic ") or known_constant_dynamic:
                bootstrap, handles, dynamic_failure = (
                    _parse_constant_dynamic_reference(
                        rest,
                        comment,
                        constant_dynamic_references,
                        bootstrap_references,
                    )
                )
                if dynamic_failure or bootstrap is None:
                    failures.append(
                        f"{artifact_entry}: {dynamic_failure or 'unresolved ConstantDynamic'} "
                        f"at {offset}"
                    )
                    continue
                for callee, edge_kind in (
                    (bootstrap, "ldc_constant_dynamic_bootstrap"),
                    *((handle, "ldc_bootstrap_handle") for handle in handles),
                ):
                    rows.append(_edge_row(
                        artifact_sha256,
                        artifact_entry,
                        authority_version,
                        caller_owner,
                        caller_member,
                        caller_descriptor,
                        callee[:3],
                        edge_kind,
                        int(offset),
                        reference_kind=callee[3],
                        reference_interface=callee[4],
                    ))
                continue
            if comment.startswith("MethodHandle "):
                callee = _parse_ldc_handle_reference(
                    comment,
                    caller_owner,
                    method_handle_interfaces.get(
                        int(constant_match.group(1))
                    ) if constant_match else None,
                )
                if callee is None:
                    failures.append(
                        f"{artifact_entry}: unparseable {opcode} MethodHandle "
                        f"comment at {offset}: {comment}"
                    )
                    continue
                rows.append(_edge_row(
                    artifact_sha256,
                    artifact_entry,
                    authority_version,
                    caller_owner,
                    caller_member,
                    caller_descriptor,
                    callee[:3],
                    "ldc_handle",
                    int(offset),
                    reference_kind=callee[3],
                    reference_interface=callee[4],
                ))
            continue
        if not separator:
            failures.append(f"{artifact_entry}: missing constant-pool comment for {opcode} at {offset}")
            continue
        if opcode == "invokedynamic":
            callees, dynamic_failure = _parse_dynamic_reference(
                rest,
                comment,
                dynamic_references,
                bootstrap_references,
                constant_dynamic_references,
            )
            if dynamic_failure:
                failures.append(f"{artifact_entry}: {dynamic_failure} at {offset}")
                continue
            if not callees:
                continue
        elif opcode in FIELD_OPCODES:
            callee = _parse_field_reference(comment, caller_owner)
            callees = (callee,) if callee is not None else ()
        else:
            callee = _parse_member_reference(comment, caller_owner)
            callees = (callee,) if callee is not None else ()
        if not callees:
            failures.append(f"{artifact_entry}: unparseable {opcode} comment at {offset}: {comment}")
            continue
        for callee in callees:
            dynamic_reference = len(callee) == 5
            ordinary_method_reference = len(callee) == 4
            reference_kind = (
                callee[3]
                if dynamic_reference or ordinary_method_reference else ""
            )
            if opcode in FIELD_OPCODES:
                reference_kind = "field"
            reference_interface = (
                callee[4]
                if dynamic_reference
                else callee[3] == "interface_method"
                if ordinary_method_reference
                else None
            )
            rows.append(_edge_row(
                artifact_sha256,
                artifact_entry,
                authority_version,
                caller_owner,
                caller_member,
                caller_descriptor,
                callee[:3],
                opcode,
                int(offset),
                reference_kind=reference_kind,
                reference_interface=reference_interface,
            ))
    if not caller_owner:
        failures.append(f"{artifact_entry}: javap output had no class declaration")
    if member_inventory is not None:
        if member_inventory_index != len(member_inventory.members):
            failures.append(
                f"{artifact_entry}: javap member inventory ended at "
                f"{member_inventory_index}/{len(member_inventory.members)}"
            )
        if descriptor_continuation:
            failures.append(
                f"{artifact_entry}: javap output ended inside a member descriptor"
            )
        if not member_inventory_closed:
            failures.append(
                f"{artifact_entry}: javap output had no complete class body"
            )
    return rows, failures


def _parse_class_reference(comment: str) -> str | None:
    """Parse a javap ``class`` constant without truncating quoted JVM names."""
    if not comment.startswith("class "):
        return None
    value = comment[len("class "):].strip()
    if not value:
        return None
    if value.startswith('"'):
        quoted = True
        escaped = False
        closing = -1
        for index, character in enumerate(value[1:], start=1):
            if escaped:
                escaped = False
                continue
            if character == "\\":
                escaped = True
                continue
            if character == '"':
                closing = index
                quoted = False
                break
        if quoted or closing < 0 or value[closing + 1:].strip():
            return None
        value = value[:closing + 1]
    elif any(character.isspace() for character in value):
        return None
    return _unquote_javap_identifier(value)


def parse_structural_javap(
    output: str,
    member_inventory: ClassfileMemberInventory | None = None,
) -> dict[str, set]:
    """Extract type/init/semantic facts from the same independent javap text.

    Direct-edge and structural validation intentionally use different parsers,
    but they do not need different target-JVM processes. Keeping this parser
    separate from ``_parse_javap_output`` preserves that independent comparison
    while sharing only the immutable javap observation.
    """
    owner = member_inventory.owner if member_inventory is not None else ""
    member_name = ""
    descriptor = ""
    pending_member: tuple[str, str, int] | None = None
    in_class_body = member_inventory is not None
    in_code_block = False
    member_inventory_index = 0
    member_inventory_closed = False
    raw_binding_failed = False
    descriptor_continuation: list[str] = []
    type_edges = set()
    init_edges = set()
    clinit_classes = set()
    semantic_instructions = set()
    declared_members = set()
    class_names = {owner} if owner else set()
    failures = set()
    if (
        member_inventory is not None
        and member_inventory.javap_reference_text_lossy
    ):
        failures.add(
            "javap UTF-8 cannot losslessly render an unpaired-surrogate "
            "constant-pool reference"
        )
        return {
            "type_edges": type_edges,
            "class_init_edges": init_edges,
            "clinit_classes": clinit_classes,
            "semantic_instructions": semantic_instructions,
            "declared_members": declared_members,
            "class_names": class_names,
            "failures": failures,
        }

    dynamic_references = _dynamic_references(output)
    constant_dynamic_references = _constant_dynamic_references(output)
    bootstrap_references = _bootstrap_references(
        output, constant_dynamic_references, member_inventory
    )
    method_handle_interfaces = _method_handle_interfaces(output)
    method_type_constants = (
        dict(member_inventory.method_type_constants)
        if member_inventory is not None else {}
    )

    def add_descriptor_type_edges(
        value: str,
        bci: int,
        type_use_kind: str,
        source: str,
        *,
        method_descriptor: bool,
        member_reference_source: tuple[str, str, str, str] | None = None,
    ) -> None:
        referenced_owners = (
            _method_type_reference_owners(value)
            if method_descriptor else _field_type_reference_owners(value)
        )
        if referenced_owners is None:
            failures.add(
                f"unparseable {source} descriptor at {bci}: {value}"
            )
            return
        for referenced_owner in referenced_owners:
            edge = (
                owner, member_name, descriptor, bci,
                referenced_owner, type_use_kind,
            )
            if member_reference_source is not None:
                edge = (*edge, *member_reference_source)
            type_edges.add(edge)

    def add_method_handle_type_edges(
        handles: tuple[tuple[str, str, str, str, bool | None], ...],
        bci: int,
        source: str,
    ) -> None:
        for handle in handles:
            referenced_owners = _method_handle_reference_owners(handle)
            if referenced_owners is None:
                failures.add(
                    f"unparseable {source} MethodHandle descriptor at "
                    f"{bci}: {handle[2]}"
                )
                continue
            for referenced_owner in referenced_owners:
                type_edges.add((
                    owner, member_name, descriptor, bci,
                    referenced_owner, "method_handle_descriptor",
                ))
                type_edges.add((
                    owner, member_name, descriptor, bci,
                    referenced_owner, "member_reference_descriptor",
                    handle[0].replace(".", "/"), handle[1], handle[2],
                    handle[3],
                ))

    def add_bootstrap_handle_type_edges(
        bootstrap_index: int, bci: int, source: str,
    ) -> None:
        handles, failure = _bootstrap_resolution_handles(
            bootstrap_index,
            bootstrap_references,
            constant_dynamic_references,
        )
        if failure:
            failures.add(f"{source} {failure} at {bci}")
            return
        add_method_handle_type_edges(handles, bci, source)

    def add_bootstrap_type_edges(
        bootstrap_index: int, bci: int, source: str,
    ) -> None:
        constants, failure = _bootstrap_argument_types(
            bootstrap_index,
            bootstrap_references,
            constant_dynamic_references,
        )
        if failure:
            failures.add(f"{source} {failure} at {bci}")
            return
        for constant_kind, value in constants:
            if constant_kind == "method_type":
                referenced_owners = _method_type_reference_owners(value)
                if referenced_owners is None:
                    failures.add(
                        f"unparseable {source} MethodType at {bci}: {value}"
                    )
                    continue
                for referenced_owner in referenced_owners:
                    type_edges.add((
                        owner, member_name, descriptor, bci,
                        referenced_owner, "method_type_descriptor",
                    ))
            elif constant_kind == "type":
                referenced_owner = _bootstrap_class_symbolic_owner(value)
                if referenced_owner is None:
                    failures.add(
                        f"unparseable {source} class constant at {bci}: {value}"
                    )
                    continue
                type_edges.add((
                    owner, member_name, descriptor, bci,
                    referenced_owner, "bootstrap_class_constant",
                ))
            elif constant_kind == "constant_dynamic":
                add_descriptor_type_edges(
                    value,
                    bci,
                    "constant_dynamic_descriptor",
                    source,
                    method_descriptor=False,
                )
            else:
                failures.add(
                    f"unknown {source} type constant at {bci}: {constant_kind}"
                )

    def access_flags(header: str) -> int:
        tokens = set(header.replace("(", " ").split())
        flags = 0
        for token, value in (
            ("public", 0x0001), ("private", 0x0002),
            ("protected", 0x0004), ("static", 0x0008),
            ("final", 0x0010), ("abstract", 0x0400),
        ):
            if token in tokens:
                flags |= value
        return flags

    for line in _javap_lines(output):
        if descriptor_continuation:
            expected = descriptor_continuation.pop(0)
            if line != expected:
                failures.add(
                    "javap/classfile member descriptor continuation mismatch "
                    f"at index {member_inventory_index - 1}"
                )
                descriptor_continuation.clear()
                raw_binding_failed = True
                member_name = ""
                descriptor = ""
                pending_member = None
                in_code_block = False
            continue
        declaration = CLASS_DECLARATION_RE.match(line)
        if declaration:
            rendered_owner = (
                _unquote_javap_identifier(declaration.group(1)) or ""
            ).replace(".", "/")
            if member_inventory is not None:
                if (
                    re.fullmatch(
                        r"[A-Za-z0-9_$]+(?:/[A-Za-z0-9_$]+)*", owner
                    )
                    and rendered_owner != owner
                ):
                    failures.add("javap/classfile owner mismatch")
            else:
                owner = rendered_owner
            class_names.add(owner)
            if member_inventory is None or line.rstrip().endswith("{"):
                in_class_body = line.rstrip().endswith("{")
            in_code_block = False
            continue
        stripped = line.strip()
        if owner and line == "{":
            in_class_body = True
            in_code_block = False
            continue
        if (
            in_class_body
            and line == "}"
            and (
                member_inventory is None
                or member_inventory_index == len(member_inventory.members)
            )
        ):
            in_class_body = False
            member_inventory_closed = True
            member_name = ""
            descriptor = ""
            pending_member = None
            in_code_block = False
            continue
        if not in_class_body:
            continue
        if member_inventory is not None and re.match(r"^ {2}\S", line):
            in_code_block = False
        if member_inventory is not None and line.startswith("    descriptor:"):
            if raw_binding_failed:
                continue
            if member_inventory_index >= len(member_inventory.members):
                failures.add("javap emitted an unexpected member descriptor")
                raw_binding_failed = True
                member_name = ""
                descriptor = ""
                pending_member = None
                in_code_block = False
                continue
            raw_member = member_inventory.members[member_inventory_index]
            descriptor_lines = _javap_embedded_lines(raw_member.descriptor)
            expected_first = f"    descriptor: {descriptor_lines[0]}"
            if line != expected_first:
                failures.add(
                    "javap/classfile member descriptor mismatch at index "
                    f"{member_inventory_index}"
                )
                raw_binding_failed = True
                member_name = ""
                descriptor = ""
                pending_member = None
                in_code_block = False
                continue
            member_inventory_index += 1
            descriptor_continuation = [
                f"    {part}" for part in descriptor_lines[1:]
            ]
            declared_members.add((
                owner,
                raw_member.kind,
                raw_member.name,
                raw_member.descriptor,
                raw_member.access_flags,
            ))
            pending_member = None
            in_code_block = False
            if raw_member.kind == "method":
                member_name = raw_member.name
                descriptor = raw_member.descriptor
                if member_name == "<clinit>":
                    clinit_classes.add(owner)
            else:
                member_name = ""
                descriptor = ""
            continue
        header = HEADER_LINE_RE.match(line)
        if header and owner:
            value = header.group("header").strip()
            if member_inventory is not None:
                member_name = ""
                descriptor = ""
                pending_member = None
                in_code_block = False
                continue
            parsed_member, parsed_state = _parse_member_header(
                line, owner.replace("/", ".")
            )
            if parsed_member == "<clinit>" and parsed_state == "method":
                member_name = "<clinit>"
                descriptor = "()V"
                clinit_classes.add(owner)
                declared_members.add(
                    (owner, "method", member_name, descriptor, 0x0008)
                )
                pending_member = None
            elif parsed_state == "method" and parsed_member:
                member_name = parsed_member
                descriptor = ""
                pending_member = ("method", member_name, access_flags(value))
            elif parsed_state == "field" and parsed_member:
                member_name = ""
                descriptor = ""
                pending_member = (
                    "field", parsed_member, access_flags(value)
                )
            else:
                member_name = ""
                descriptor = ""
                pending_member = None
            in_code_block = False
            continue
        if stripped.startswith("descriptor:") and pending_member:
            descriptor = stripped.split(":", 1)[1].strip()
            member_kind, member_name, member_flags = pending_member
            declared_members.add(
                (owner, member_kind, member_name, descriptor, member_flags)
            )
            pending_member = None
            in_code_block = False
            continue
        if stripped == "Code:":
            in_code_block = bool(owner and member_name and descriptor)
            if not in_code_block:
                failures.add("Code block without a valid member descriptor")
            continue
        if not in_code_block:
            continue
        instruction = INSTRUCTION_RE.match(line)
        if not instruction or not owner or not member_name or not descriptor:
            continue
        bci = int(instruction.group(1))
        opcode = instruction.group(2)
        rest = instruction.group(3)
        comment = rest.split("//", 1)[1].strip() if "//" in rest else ""
        semantic_instructions.add(
            (owner, member_name, descriptor, bci, opcode, comment)
        )
        member_reference = None
        member_reference_is_method = opcode in {
            "invokevirtual", "invokespecial", "invokestatic",
            "invokeinterface",
        }
        if member_reference_is_method:
            member_reference = _parse_member_reference(comment, owner)
        elif opcode in {"getstatic", "putstatic", "getfield", "putfield"}:
            member_reference = _parse_field_reference(comment, owner)
        if member_reference_is_method or opcode in {
            "getstatic", "putstatic", "getfield", "putfield",
        }:
            if member_reference is None:
                failures.add(
                    f"unparseable {opcode} member reference at {bci}: "
                    f"{comment}"
                )
            else:
                add_descriptor_type_edges(
                    member_reference[2],
                    bci,
                    "member_reference_descriptor",
                    opcode,
                    method_descriptor=member_reference_is_method,
                    member_reference_source=(
                        member_reference[0].replace(".", "/"),
                        member_reference[1],
                        member_reference[2],
                        (
                            member_reference[3]
                            if member_reference_is_method else "field"
                        ),
                    ),
                )
        target = _parse_class_reference(comment) or ""
        if opcode in {
            "new", "anewarray", "checkcast", "instanceof", "multianewarray"
        }:
            if target:
                type_edges.add(
                    (owner, member_name, descriptor, bci, target, opcode)
                )
            else:
                failures.add(
                    f"unparseable {opcode} class reference at {bci}: {comment}"
                )
        elif opcode in LDC_OPCODES:
            constant_match = re.search(r"#(\d+)", rest)
            constant_index = (
                int(constant_match.group(1)) if constant_match else None
            )
            expected_method_type = (
                method_type_constants.get(constant_index)
                if constant_index is not None else None
            )
            if expected_method_type is not None or comment.startswith(
                "MethodType "
            ):
                observed_method_type = (
                    comment[len("MethodType "):]
                    if comment.startswith("MethodType ") else None
                )
                if (
                    observed_method_type is None
                    or (
                        expected_method_type is not None
                        and observed_method_type != expected_method_type
                    )
                ):
                    failures.add(
                        f"lossy or unparseable {opcode} MethodType at {bci}: "
                        f"{comment}"
                    )
                else:
                    referenced_owners = _method_type_reference_owners(
                        observed_method_type
                    )
                    if referenced_owners is None:
                        failures.add(
                            f"unparseable {opcode} MethodType at {bci}: "
                            f"{comment}"
                        )
                    else:
                        for referenced_owner in referenced_owners:
                            type_edges.add((
                                owner, member_name, descriptor, bci,
                                referenced_owner, "method_type_descriptor",
                            ))
            elif comment.startswith("Dynamic ") or (
                constant_index is not None
                and constant_index in constant_dynamic_references
            ):
                dynamic_reference = (
                    constant_dynamic_references.get(constant_index)
                    if constant_index is not None else None
                )
                comment_match = CONSTANT_DYNAMIC_COMMENT_RE.match(comment)
                if dynamic_reference is None and comment_match:
                    dynamic_reference = (
                        int(comment_match.group("bootstrap")),
                        comment_match.group("member"),
                        comment_match.group("descriptor"),
                    )
                if dynamic_reference is None:
                    failures.add(
                        f"unresolved ConstantDynamic type arguments at {bci}"
                    )
                else:
                    add_descriptor_type_edges(
                        dynamic_reference[2],
                        bci,
                        "constant_dynamic_descriptor",
                        "ConstantDynamic",
                        method_descriptor=False,
                    )
                    add_bootstrap_type_edges(
                        dynamic_reference[0], bci, "ConstantDynamic"
                    )
                    add_bootstrap_handle_type_edges(
                        dynamic_reference[0], bci, "ConstantDynamic"
                    )
            elif comment.startswith("MethodHandle "):
                handle = _parse_ldc_handle_reference(
                    comment,
                    owner.replace("/", "."),
                    method_handle_interfaces.get(constant_index)
                    if constant_index is not None else None,
                )
                if handle is None:
                    failures.add(
                        f"unparseable {opcode} MethodHandle at {bci}: "
                        f"{comment}"
                    )
                else:
                    add_method_handle_type_edges(
                        (handle,), bci, f"{opcode}"
                    )
            elif opcode in {"ldc", "ldc_w"} and target:
                type_edges.add(
                    (owner, member_name, descriptor, bci, target, "class_literal")
                )
            elif opcode in {"ldc", "ldc_w"} and comment.startswith("class "):
                failures.add(
                    f"unparseable {opcode} class reference at {bci}: {comment}"
                )
        if opcode == "invokedynamic":
            constant_match = re.search(r"#(\d+)", rest)
            dynamic_reference = (
                dynamic_references.get(int(constant_match.group(1)))
                if constant_match else None
            )
            comment_match = DYNAMIC_COMMENT_RE.match(comment)
            if dynamic_reference is None and comment_match:
                dynamic_reference = (
                    int(comment_match.group("bootstrap")),
                    comment_match.group("member"),
                    comment_match.group("descriptor"),
                )
            if dynamic_reference is None:
                failures.add(
                    f"unresolved invokedynamic type arguments at {bci}"
                )
            else:
                add_descriptor_type_edges(
                    dynamic_reference[2],
                    bci,
                    "invokedynamic_callsite_descriptor",
                    "invokedynamic",
                    method_descriptor=True,
                )
                add_bootstrap_type_edges(
                    dynamic_reference[0], bci, "invokedynamic"
                )
                add_bootstrap_handle_type_edges(
                    dynamic_reference[0], bci, "invokedynamic"
                )
        if opcode in {"invokestatic", "getstatic", "putstatic"}:
            reference = member_reference
            if reference is None:
                failures.add(
                    f"unparseable {opcode} member reference at {bci}: {comment}"
                )
            else:
                target_owner = reference[0].replace(".", "/")
                init_edges.add(
                    (owner, member_name, descriptor, bci, target_owner, opcode)
                )
        elif opcode == "new" and target:
            init_edges.add(
                (owner, member_name, descriptor, bci, target, "new")
            )
    if member_inventory is not None:
        if member_inventory_index != len(member_inventory.members):
            failures.add(
                "javap member inventory ended at "
                f"{member_inventory_index}/{len(member_inventory.members)}"
            )
        if descriptor_continuation:
            failures.add("javap output ended inside a member descriptor")
        if not member_inventory_closed:
            failures.add("javap output had no complete class body")
    return {
        "type_edges": type_edges,
        "class_init_edges": init_edges,
        "clinit_classes": clinit_classes,
        "semantic_instructions": semantic_instructions,
        "declared_members": declared_members,
        "class_names": class_names,
        "failures": failures,
    }


def _javap_command(javap: str, *arguments: str) -> list[str]:
    """Backward-compatible private alias used by existing integrations."""
    return javap_command(javap, *arguments)


def _javap_version(javap: str, *, timeout: float) -> str:
    completed = run_managed_subprocess(
        _javap_command(javap, "-version"),
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", check=False, timeout=timeout,
    )
    return (completed.stdout or completed.stderr).strip()


def _javap_version_cache_key(javap: str) -> tuple[str, int, int, int]:
    resolved = shutil.which(javap) or str(Path(javap).expanduser().resolve())
    try:
        status = Path(resolved).stat()
    except OSError:
        return resolved, 0, 0, 0
    return resolved, int(status.st_size), int(status.st_mtime_ns), int(status.st_ino)


def _javap_major(version: str) -> int | None:
    match = re.search(r"(?:1\.)?(\d+)", version)
    return int(match.group(1)) if match else None


def _cancel_process(process: subprocess.Popen) -> None:
    try:
        terminate_process_tree(process)
    except BaseException:
        # Preserve the triggering failure. Pipes still need to be drained or
        # closed for an already-reaped/concurrently-exiting process.
        pass
    try:
        process.communicate(timeout=5)
    except (OSError, ValueError):
        # Preserve the triggering failure while making cleanup idempotent for
        # already-closed pipes and concurrently reaped processes.
        pass
    except subprocess.TimeoutExpired:
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe is not None:
                try:
                    pipe.close()
                except OSError:
                    pass
    finally:
        release_process_tree(process)


def _materialize_packaged_class(entry: PackagedClass) -> str:
    if (
        entry.javap_argument
        or entry.content is None
        or entry.extracted_path.exists()
    ):
        return ""
    try:
        entry.extracted_path.write_bytes(entry.content)
        return ""
    except OSError as error:
        return str(error)


def _entry_requires_verbose_javap(entry: PackagedClass) -> bool:
    if entry.requires_verbose_javap is not None:
        return entry.requires_verbose_javap
    content = entry.content
    if content is None:
        try:
            content = entry.extracted_path.read_bytes()
        except OSError:
            return True
    return _classfile_has_method_handle_constant(content)


def _javap_path_key(path: str | Path) -> str:
    """Normalize a javap path lexically without restatting every class file."""
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _entry_javap_argument(entry: PackagedClass) -> str:
    return entry.javap_argument or str(entry.extracted_path)


def _entry_javap_section_key(entry: PackagedClass) -> str:
    return _javap_path_key(_entry_javap_argument(entry))


def _parse_entry_with_javap(
    entry: PackagedClass,
    artifact_sha256: str,
    javap: str,
    version: str,
    cancellation_event: Event,
    deadline: float | None,
    *,
    verbose: bool | None = None,
) -> dict:
    materialize_error = _materialize_packaged_class(entry)
    if materialize_error:
        return {
            "rows": [],
            "failures": [
                f"{entry.artifact_entry}: class materialization failed: {materialize_error}"
            ],
            "completed": True,
            "parsed": False,
        }
    per_class_deadline = time.perf_counter() + 30.0
    deadline = min(deadline, per_class_deadline) if deadline is not None else per_class_deadline
    if cancellation_event.is_set() or (deadline is not None and time.perf_counter() >= deadline):
        return {"rows": [], "failures": [], "completed": False, "parsed": False}
    try:
        command = _javap_command(javap)
        if _entry_requires_verbose_javap(entry) if verbose is None else verbose:
            command.append("-v")
        command.extend(("-c", "-p", "-s", _entry_javap_argument(entry)))
        process = managed_popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        return {
            "rows": [],
            "failures": [f"{entry.artifact_entry}: {javap} execution failed: {error}"],
            "completed": True,
            "parsed": False,
        }

    try:
        while True:
            remaining = deadline - time.perf_counter() if deadline is not None else None
            if cancellation_event.is_set() or (remaining is not None and remaining <= 0):
                _cancel_process(process)
                return {"rows": [], "failures": [], "completed": False, "parsed": False}
            wait_seconds = min(0.1, remaining) if remaining is not None else 0.1
            try:
                stdout, stderr = process.communicate(timeout=wait_seconds)
                break
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        # KeyboardInterrupt, decoding failures and unexpected pipe errors used
        # to unwind while leaving javap alive with both PIPE descriptors open.
        _cancel_process(process)
        raise
    release_process_tree(process)

    if process.returncode != 0:
        detail = (stderr or stdout).strip().replace("\n", " ")
        return {
            "rows": [],
            "failures": [f"{entry.artifact_entry}: javap failed: {detail}"],
            "completed": True,
            "parsed": False,
        }
    if not version:
        return {
            "rows": [],
            "failures": [f"{entry.artifact_entry}: javap version was empty"],
            "completed": True,
            "parsed": False,
        }
    member_inventory, inventory_failure = _entry_member_inventory(entry)
    if inventory_failure or member_inventory is None:
        return {
            "rows": [],
            "failures": [
                f"{entry.artifact_entry}: "
                f"{inventory_failure or 'classfile member_info unavailable'}"
            ],
            "completed": True,
            "parsed": False,
        }
    rows, failures = _parse_javap_output(
        stdout,
        artifact_sha256,
        entry.artifact_entry,
        version,
        member_inventory,
    )
    structural_facts = parse_structural_javap(stdout, member_inventory)
    failures.extend(
        f"{entry.artifact_entry}: {failure}"
        for failure in sorted(structural_facts.pop("failures", set()))
    )
    return {
        "rows": rows,
        "structural_facts": structural_facts,
        "failures": failures,
        "completed": True,
        "parsed": True,
    }


def _parse_entry_group_with_javap(
    entries: list[PackagedClass],
    artifact_sha256: str,
    javap: str,
    version: str,
    cancellation_event: Event,
    deadline: float | None,
    *,
    force_verbose: bool | None = None,
) -> list[dict]:
    if force_verbose is None:
        verbose_entries = []
        plain_entries = []
        for entry in entries:
            target = (
                verbose_entries
                if _entry_requires_verbose_javap(entry)
                else plain_entries
            )
            target.append(entry)
        if verbose_entries and plain_entries:
            by_path = {}
            for group, verbose in ((plain_entries, False), (verbose_entries, True)):
                group_results = _parse_entry_group_with_javap(
                    group,
                    artifact_sha256,
                    javap,
                    version,
                    cancellation_event,
                    deadline,
                    force_verbose=verbose,
                )
                by_path.update(
                    (entry.extracted_path, result)
                    for entry, result in zip(group, group_results)
                )
            return [by_path[entry.extracted_path] for entry in entries]
        force_verbose = bool(verbose_entries)
    if len(entries) == 1:
        return [
            _parse_entry_with_javap(
                entries[0], artifact_sha256, javap, version, cancellation_event, deadline,
                verbose=force_verbose,
            )
        ]
    overall_deadline = deadline

    def parse_separately(candidates: list[PackagedClass]) -> list[dict]:
        return [
            _parse_entry_with_javap(
                entry,
                artifact_sha256,
                javap,
                version,
                cancellation_event,
                overall_deadline,
                verbose=force_verbose,
            )
            for entry in candidates
        ]

    def parse_smaller_batches(candidates: list[PackagedClass]) -> list[dict]:
        """Bisect a failed aggregate invocation until its bad class is isolated."""

        if len(candidates) <= 1:
            return parse_separately(candidates)
        midpoint = len(candidates) // 2
        return [
            *_parse_entry_group_with_javap(
                candidates[:midpoint],
                artifact_sha256,
                javap,
                version,
                cancellation_event,
                overall_deadline,
                force_verbose=force_verbose,
            ),
            *_parse_entry_group_with_javap(
                candidates[midpoint:],
                artifact_sha256,
                javap,
                version,
                cancellation_event,
                overall_deadline,
                force_verbose=force_verbose,
            ),
        ]

    materialize_errors = {
        entry.extracted_path: error
        for entry in entries
        if (error := _materialize_packaged_class(entry))
    }
    if materialize_errors:
        return parse_separately(entries)
    group_deadline = time.perf_counter() + 30.0
    deadline = min(deadline, group_deadline) if deadline is not None else group_deadline
    if cancellation_event.is_set() or time.perf_counter() >= deadline:
        return [
            {"rows": [], "failures": [], "completed": False, "parsed": False}
            for _entry in entries
        ]
    try:
        command = _javap_command(javap)
        if force_verbose:
            command.append("-v")
        else:
            # A source declaration is not a class boundary: legal raw JVM
            # names may contain controls, quotes, or a leading ``[`` and javap
            # renders those declarations across multiple physical lines.
            # ``-sysinfo`` provides an exact extracted-file marker without the
            # constant-pool volume of ``-v``, so every valid class stays in the
            # original batched invocation and its raw member_info inventory
            # remains bound to the correct output section.
            command.append("-sysinfo")
        command.extend(("-c", "-p", "-s"))
        command.extend(_entry_javap_argument(entry) for entry in entries)
        process = managed_popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        if len(entries) > 1 and _command_line_too_long(error):
            midpoint = len(entries) // 2
            return [
                *_parse_entry_group_with_javap(
                    entries[:midpoint],
                    artifact_sha256,
                    javap,
                    version,
                    cancellation_event,
                    deadline,
                    force_verbose=force_verbose,
                ),
                *_parse_entry_group_with_javap(
                    entries[midpoint:],
                    artifact_sha256,
                    javap,
                    version,
                    cancellation_event,
                    deadline,
                    force_verbose=force_verbose,
                ),
            ]
        return [
            {
                "rows": [],
                "failures": [f"{entry.artifact_entry}: {javap} execution failed: {error}"],
                "completed": True,
                "parsed": False,
            }
            for entry in entries
        ]

    try:
        while True:
            remaining = deadline - time.perf_counter()
            if cancellation_event.is_set() or remaining <= 0:
                _cancel_process(process)
                if (
                    not cancellation_event.is_set()
                    and (
                        overall_deadline is None
                        or time.perf_counter() < overall_deadline
                    )
                ):
                    return parse_smaller_batches(entries)
                return [
                    {"rows": [], "failures": [], "completed": False, "parsed": False}
                    for _entry in entries
                ]
            try:
                stdout, stderr = process.communicate(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        _cancel_process(process)
        raise
    release_process_tree(process)
    if process.returncode != 0:
        return parse_smaller_batches(entries)

    sections: dict[str, str] = {}
    markers = list(re.finditer(r"(?m)^Classfile (?P<path>.+)\n", stdout))
    for index, marker in enumerate(markers):
        end = markers[index + 1].start() if index + 1 < len(markers) else len(stdout)
        sections[_javap_path_key(marker.group("path").strip())] = (
            stdout[marker.start():end]
        )
    results = []
    for entry in entries:
        section = sections.get(_entry_javap_section_key(entry))
        if section is None:
            results.extend(parse_separately([entry]))
            continue
        member_inventory, inventory_failure = _entry_member_inventory(entry)
        if inventory_failure or member_inventory is None:
            results.append({
                "rows": [],
                "failures": [
                    f"{entry.artifact_entry}: "
                    f"{inventory_failure or 'classfile member_info unavailable'}"
                ],
                "completed": True,
                "parsed": False,
            })
            continue
        rows, failures = _parse_javap_output(
            section,
            artifact_sha256,
            entry.artifact_entry,
            version,
            member_inventory,
        )
        structural_facts = parse_structural_javap(section, member_inventory)
        failures.extend(
            f"{entry.artifact_entry}: {failure}"
            for failure in sorted(structural_facts.pop("failures", set()))
        )
        results.append({
            "rows": rows,
            "structural_facts": structural_facts,
            "failures": failures,
            "completed": True,
            "parsed": True,
        })
    return results


def _parse_entries_with_javap(
    entries: list[PackagedClass], artifact_sha256: str, javap: str, version: str
) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    failures: list[str] = []
    cancellation_event = Event()
    for entry in entries:
        result = _parse_entry_with_javap(
            entry, artifact_sha256, javap, version, cancellation_event, None
        )
        rows.extend(result["rows"])
        failures.extend(result["failures"])
    return rows, failures


def _worker_exception_result(entry: PackagedClass, error: BaseException) -> dict:
    return {
        "rows": [],
        "failures": [
            f"{entry.artifact_entry}: oracle worker failed: {type(error).__name__}: {error}"
        ],
        "completed": True,
        "parsed": False,
    }


def _javap_batch_command_chars(
    javap: str, entries: list[PackagedClass],
) -> int:
    """Return the conservative Windows command-line rendering length."""
    command = _javap_command(javap, "-v", "-sysinfo", "-c", "-p", "-s")
    command.extend(_entry_javap_argument(entry) for entry in entries)
    return len(subprocess.list2cmdline(command))


def _javap_batch_groups(
    entries: list[PackagedClass],
    requested_workers: int,
    javap: str,
) -> list[list[PackagedClass]]:
    """Partition javap work by CPU balance and the real command-line budget."""
    group_size = min(
        MAX_CLASSES_PER_JAVAP_BATCH,
        max(1, (len(entries) + requested_workers - 1) // requested_workers),
    )
    groups: list[list[PackagedClass]] = []
    current: list[PackagedClass] = []
    for entry in entries:
        candidate = [*current, entry]
        command_too_long = bool(
            MAX_JAVAP_COMMAND_CHARS
            and _javap_batch_command_chars(javap, candidate)
            > MAX_JAVAP_COMMAND_CHARS
        )
        if current and (len(current) >= group_size or command_too_long):
            groups.append(current)
            current = [entry]
        else:
            current = candidate
    if current:
        groups.append(current)
    return groups


def _command_line_too_long(error: OSError) -> bool:
    return (
        error.errno == errno.E2BIG
        or getattr(error, "winerror", None) == 206
    )


def _parse_entry_batch(
    entries: list[PackagedClass],
    artifact_sha256: str,
    javap: str,
    version: str,
    cancellation_event: Event,
    deadline: float | None,
    max_workers: int | None,
    *,
    batch_javap: bool = True,
) -> tuple[list[dict | None], int, bool, bool]:
    if not entries:
        return [], 0, False, False
    requested_workers = max_workers if max_workers is not None else min(
        MAX_JAVAP_WORKERS, max(1, os.cpu_count() or 1)
    )
    requested_workers = min(MAX_JAVAP_WORKERS, max(1, int(requested_workers)))
    if batch_javap:
        # JVM startup dominates a full-closure scan. Keep argv within the
        # rendered Windows CreateProcess budget while parsing a group per javap
        # process instead of launching one target JVM for every class.
        groups = _javap_batch_groups(entries, requested_workers, javap)
    else:
        groups = [[entry] for entry in entries]
    worker_count = min(len(groups), requested_workers)
    timed_out = False
    interrupted = False
    executor = ThreadPoolExecutor(
        max_workers=worker_count, thread_name_prefix="final-artifact-javap"
    )
    futures = []
    try:
        # Submission itself can fail after one or more worker threads have
        # started (for example at the process/thread resource limit). Keep it
        # inside the shutdown guard so those workers and child javap processes
        # cannot outlive the failed scan.
        futures = [
            executor.submit(
                _parse_entry_group_with_javap,
                group,
                artifact_sha256,
                javap,
                version,
                cancellation_event,
                deadline,
            )
            for group in groups
        ]
        for future in futures:
            remaining = deadline - time.perf_counter() if deadline is not None else None
            if remaining is not None and remaining <= 0:
                timed_out = True
                cancellation_event.set()
                break
            try:
                future.result(timeout=remaining)
            except FutureTimeoutError:
                timed_out = True
                cancellation_event.set()
                break
            except BaseException:
                continue
    except KeyboardInterrupt:
        interrupted = True
        cancellation_event.set()
    except BaseException:
        cancellation_event.set()
        raise
    finally:
        executor.shutdown(wait=True, cancel_futures=True)

    result_by_path: dict[Path, dict | None] = {}
    for group, future in zip(groups, futures):
        if future.cancelled():
            for entry in group:
                result_by_path[entry.extracted_path] = None
            continue
        try:
            group_results = future.result()
            for entry, result in zip(group, group_results):
                result_by_path[entry.extracted_path] = result
        except KeyboardInterrupt:
            interrupted = True
            cancellation_event.set()
            for entry in group:
                result_by_path[entry.extracted_path] = None
        except BaseException as error:
            for entry in group:
                result_by_path[entry.extracted_path] = _worker_exception_result(entry, error)
    results = [result_by_path.get(entry.extracted_path) for entry in entries]
    return results, worker_count, timed_out, interrupted


def _base_result(artifact_sha256: str, *, elapsed_seconds: float, **values) -> dict:
    class_count = int(values.get("class_count") or 0)
    result = {
        "artifact_sha256": artifact_sha256,
        "class_count": class_count,
        "inventory_class_count": int(values.get("inventory_class_count") or class_count),
        "completed_class_count": int(values.get("completed_class_count") or 0),
        "parsed_class_count": int(values.get("parsed_class_count") or 0),
        "cached_class_count": int(values.get("cached_class_count") or 0),
        "parse_failure_count": int(values.get("parse_failure_count") or 0),
        "parse_seconds": float(values.get("parse_seconds") or 0.0),
        "elapsed_seconds": elapsed_seconds,
        "worker_count": int(values.get("worker_count") or 0),
        "cache_hits": int(values.get("cache_hits") or 0),
        "cache_misses": int(values.get("cache_misses") or 0),
        "timed_out": bool(values.get("timed_out")),
        "interrupted": bool(values.get("interrupted")),
        "edges": list(values.get("edges") or []),
        "failures": list(values.get("failures") or []),
        "complete": bool(values.get("complete")),
    }
    structural = values.get("structural_facts")
    if structural is not None:
        result["structural_facts"] = {
            key: [
                list(value) if isinstance(value, tuple) else value
                for value in sorted(values)
            ]
            for key, values in structural.items()
        }
    return result


class _ArtifactSnapshotDeadlineExceeded(TimeoutError):
    pass


def _copy_artifact_snapshot(
    source: Path, destination, *, deadline: float | None = None,
) -> str:
    """Stream one opened source inode into a private immutable snapshot."""
    digest = hashlib.sha256()
    with source.open("rb") as source_handle:
        while True:
            if deadline is not None and time.perf_counter() >= deadline:
                raise _ArtifactSnapshotDeadlineExceeded
            block = source_handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            destination.write(block)
    destination.flush()
    destination.seek(0)
    return digest.hexdigest()


def scan_final_artifact(
    artifact: Path,
    javap: str = "javap",
    *,
    max_workers: int | None = None,
    time_budget_seconds: float | None = None,
    selected_targets: list[dict] | None = None,
    excluded_nested_jars: set[str] | None = None,
    include_nested_runtime_jars: bool = True,
    include_structural_facts: bool = False,
    cache_result: bool = True,
) -> dict:
    """Return executable edges from one archive and, when requested, nested runtime JARs."""
    artifact = Path(artifact)
    started_at = time.perf_counter()
    budget = float(time_budget_seconds or 0.0)
    deadline = started_at + budget if budget > 0 else None
    # The private directory prevents path replacement after inspection. Copy
    # from one already-open source inode, hashing as bytes are streamed, then
    # authorize and extract from that same file. This closes inspect→read
    # TOCTOU without retaining a potentially GiB-scale archive in memory.
    with short_temporary_directory(
        prefix="s5-edge-snapshot"
    ) as snapshot_directory:
        snapshot_path = Path(snapshot_directory) / "artifact.snapshot"
        try:
            snapshot_handle = snapshot_path.open("x+b")
        except OSError as error:
            return _base_result(
                "",
                elapsed_seconds=time.perf_counter() - started_at,
                failures=[f"{artifact}: artifact snapshot read failed: {error}"],
                complete=False,
            )
        with snapshot_handle:
            try:
                digest = _copy_artifact_snapshot(
                    artifact, snapshot_handle, deadline=deadline,
                )
            except _ArtifactSnapshotDeadlineExceeded:
                return _base_result(
                    "",
                    elapsed_seconds=time.perf_counter() - started_at,
                    failures=[f"oracle_time_budget_exceeded:{budget:.3f}s"],
                    timed_out=True,
                    cache_misses=1,
                    complete=False,
                )
            except OSError as error:
                return _base_result(
                    "",
                    elapsed_seconds=time.perf_counter() - started_at,
                    failures=[f"{artifact}: artifact snapshot read failed: {error}"],
                    complete=False,
                )
            safety = inspect_archive_stream(
                snapshot_handle,
                cancellation_check=(
                    (lambda: time.perf_counter() >= deadline)
                    if deadline is not None else None
                ),
            )
            if "ARCHIVE_INSPECTION_CANCELLED" in safety.reason_codes:
                return _base_result(
                    digest,
                    elapsed_seconds=time.perf_counter() - started_at,
                    failures=[f"oracle_time_budget_exceeded:{budget:.3f}s"],
                    timed_out=True,
                    cache_misses=1,
                    complete=False,
                )
            if not safety.safe:
                return _base_result(
                    "",
                    elapsed_seconds=time.perf_counter() - started_at,
                    failures=[
                        f"artifact_safety:{reason}"
                        for reason in safety.reason_codes
                    ],
                    complete=False,
                )
            return _scan_final_artifact_snapshot(
                snapshot_handle,
                digest,
                javap=javap,
                max_workers=max_workers,
                selected_targets=selected_targets,
                excluded_nested_jars=excluded_nested_jars,
                include_nested_runtime_jars=include_nested_runtime_jars,
                include_structural_facts=include_structural_facts,
                cache_result=cache_result,
                started_at=started_at,
                budget=budget,
                deadline=deadline,
            )


def _scan_final_artifact_snapshot(
    snapshot,
    digest: str,
    *,
    javap: str,
    max_workers: int | None,
    selected_targets: list[dict] | None,
    excluded_nested_jars: set[str] | None,
    include_nested_runtime_jars: bool,
    include_structural_facts: bool,
    cache_result: bool,
    started_at: float,
    budget: float,
    deadline: float | None,
) -> dict:
    version_timeout = JAVAP_VERSION_TIMEOUT_SECONDS
    if deadline is not None:
        version_timeout = deadline - time.perf_counter()
        if version_timeout <= 0:
            return _base_result(
                digest,
                elapsed_seconds=time.perf_counter() - started_at,
                failures=[f"oracle_time_budget_exceeded:{budget:.3f}s"],
                timed_out=True,
                cache_misses=1,
                complete=False,
            )
        version_timeout = min(version_timeout, JAVAP_VERSION_TIMEOUT_SECONDS)
    try:
        version_cache_key = _javap_version_cache_key(javap)
        with _IMMUTABLE_ORACLE_CACHE_LOCK:
            version = _JAVAP_VERSION_CACHE.get(version_cache_key)
        if version is None:
            version = _javap_version(javap, timeout=version_timeout)
            if version:
                with _IMMUTABLE_ORACLE_CACHE_LOCK:
                    version = _JAVAP_VERSION_CACHE.setdefault(
                        version_cache_key, version
                    )
    except subprocess.TimeoutExpired:
        return _base_result(
            digest,
            elapsed_seconds=time.perf_counter() - started_at,
            failures=["oracle_javap_version_timeout"],
            timed_out=True,
            cache_misses=1,
            complete=False,
        )
    except OSError as error:
        return _base_result(
            digest,
            elapsed_seconds=time.perf_counter() - started_at,
            failures=[f"oracle_javap_version_failed:OSError: {error}"],
            cache_misses=1,
            complete=False,
        )
    except KeyboardInterrupt:
        return _base_result(
            digest,
            elapsed_seconds=time.perf_counter() - started_at,
            failures=["oracle_interrupted"],
            interrupted=True,
            cache_misses=1,
            complete=False,
        )
    except Exception as error:
        return _base_result(
            digest,
            elapsed_seconds=time.perf_counter() - started_at,
            failures=[f"oracle_javap_version_failed:{type(error).__name__}: {error}"],
            cache_misses=1,
            complete=False,
        )
    normalized_targets = _normalize_selected_targets(selected_targets)
    normalized_exclusions = tuple(sorted({
        str(item or "").strip() for item in (excluded_nested_jars or set())
        if str(item or "").strip()
    }))
    cache_key = _oracle_cache_key(
        digest,
        version,
        normalized_targets,
        normalized_exclusions,
        include_nested_runtime_jars,
        include_structural_facts,
    )
    with _IMMUTABLE_ORACLE_CACHE_LOCK:
        cached_serialized = (
            _IMMUTABLE_ORACLE_CACHE.get(cache_key) if cache_result else None
        )
    if cached_serialized is not None:
        cached = json.loads(cached_serialized)
        return _base_result(
            digest,
            elapsed_seconds=time.perf_counter() - started_at,
            class_count=cached["class_count"],
            inventory_class_count=cached.get("inventory_class_count", cached["class_count"]),
            completed_class_count=cached["class_count"],
            cached_class_count=cached["class_count"],
            parse_failure_count=cached["parse_failure_count"],
            cache_hits=1,
            edges=cached["edges"],
            structural_facts=cached.get("structural_facts"),
            failures=cached["failures"],
            complete=cached["complete"],
        )
    target_major = _javap_major(version)
    cancellation_event = Event()
    timed_out = False
    interrupted = False
    parse_started_at = time.perf_counter()
    entries: list[PackagedClass] = []
    failures: list[str] = []
    results: list[dict | None] = []
    worker_count = 0
    inventory_class_count = 0
    try:
        with short_temporary_directory(prefix="s5-edge-oracle") as temporary_directory:
            entries, failures = _extract_packaged_classes(
                snapshot,
                Path(temporary_directory),
                target_major,
                defer_writes=False,
                # javap accepts exact ``jar:file:...!/entry`` URLs. For the
                # ordinary bounded artifact, one uncompressed staging JAR
                # avoids a small file per class and keeps member parsing in
                # memory. Oversized artifacts automatically spill to the
                # established file-backed representation.
                stage_javap_archive=USE_STAGED_JAVAP_ARCHIVE,
                excluded_nested_jars=set(normalized_exclusions),
                include_nested_runtime_jars=include_nested_runtime_jars,
            )
            inventory_class_count = len(entries)
            if deadline is not None and time.perf_counter() >= deadline:
                timed_out = True
            if normalized_targets and entries and not timed_out:
                remaining_entries = list(entries)
                selected_entries: list[PackagedClass] = []
                frontier = set(normalized_targets)
                expanded_targets: set[tuple[str, str, str]] = set()
                closure_rows: list[dict] = []
                while frontier and not timed_out and not interrupted:
                    pending_targets = frontier - expanded_targets
                    if not pending_targets:
                        break
                    active_targets: set[tuple[str, str, str]] = set()
                    while pending_targets:
                        active_targets.update(pending_targets)
                        expanded_targets.update(pending_targets)
                        historical_callers = {
                            (
                                str(edge.get("caller_owner") or ""),
                                str(edge.get("caller_member") or ""),
                                str(edge.get("caller_descriptor") or ""),
                            )
                            for edge in closure_rows
                            if _edge_targets(edge, pending_targets)
                        }
                        frontier.update(historical_callers)
                        pending_targets = historical_callers - expanded_targets
                    candidates = [
                        entry for entry in remaining_entries
                        if _entry_might_reference(entry, active_targets)
                    ]
                    if not candidates:
                        continue
                    candidate_paths = {entry.extracted_path for entry in candidates}
                    remaining_entries = [
                        entry for entry in remaining_entries
                        if entry.extracted_path not in candidate_paths
                    ]
                    selected_entries.extend(candidates)
                    batch_results, batch_workers, batch_timed_out, batch_interrupted = (
                        _parse_entry_batch(
                            candidates, digest, javap, version, cancellation_event,
                            deadline, max_workers, batch_javap=True,
                        )
                    )
                    results.extend(batch_results)
                    worker_count = max(worker_count, batch_workers)
                    timed_out = timed_out or batch_timed_out
                    interrupted = interrupted or batch_interrupted
                    batch_rows = [
                        row
                        for result in batch_results if result is not None
                        for row in (result.get("rows") or [])
                    ]
                    closure_rows.extend(batch_rows)
                    if any(
                        result is None or not result.get("completed")
                        for result in batch_results
                    ):
                        if not timed_out and not interrupted:
                            failures.append("oracle_parse_incomplete")
                    if timed_out or interrupted:
                        cancellation_event.set()
                        break
                    frontier.update({
                        (
                            str(edge.get("caller_owner") or ""),
                            str(edge.get("caller_member") or ""),
                            str(edge.get("caller_descriptor") or ""),
                        )
                        for edge in closure_rows
                        if _edge_targets(edge, active_targets)
                    })
                entries = selected_entries
            elif entries and not timed_out:
                results, worker_count, timed_out, interrupted = _parse_entry_batch(
                    entries, digest, javap, version, cancellation_event,
                    deadline, max_workers,
                )
                if any(result is None or not result.get("completed") for result in results):
                    if deadline is not None and time.perf_counter() >= deadline:
                        timed_out = True
                    elif not interrupted:
                        failures.append("oracle_parse_incomplete")
    except KeyboardInterrupt:
        interrupted = True
        cancellation_event.set()

    rows: list[dict] = []
    parse_failures: list[str] = []
    completed_class_count = 0
    parsed_class_count = 0
    structural_facts = {
        "type_edges": set(),
        "class_init_edges": set(),
        "clinit_classes": set(),
        "semantic_instructions": set(),
        "declared_members": set(),
        "class_names": set(),
    }
    for result in results:
        if result is None:
            continue
        rows.extend(result["rows"])
        parse_failures.extend(result["failures"])
        completed_class_count += int(bool(result.get("completed")))
        parsed_class_count += int(bool(result.get("parsed")))
        if include_structural_facts:
            for key, values in (result.get("structural_facts") or {}).items():
                structural_facts[key].update(values)
    failures.extend(parse_failures)
    if timed_out:
        failures.append(f"oracle_time_budget_exceeded:{budget:.3f}s")
    if interrupted:
        failures.append("oracle_interrupted")
    if normalized_targets:
        rows = _reverse_target_closure(rows, set(normalized_targets))
    rows.sort(key=lambda row: (
        canonical_edge_identity(row), row["artifact_entry"], row["instruction_offset"]
    ))
    parse_seconds = time.perf_counter() - parse_started_at
    complete = not failures and completed_class_count == len(entries)
    result = _base_result(
        digest,
        elapsed_seconds=time.perf_counter() - started_at,
        class_count=len(entries),
        inventory_class_count=inventory_class_count,
        completed_class_count=completed_class_count,
        parsed_class_count=parsed_class_count,
        parse_failure_count=len(parse_failures),
        parse_seconds=parse_seconds,
        worker_count=worker_count,
        cache_misses=1,
        timed_out=timed_out,
        interrupted=interrupted,
        edges=rows,
        structural_facts=(structural_facts if include_structural_facts else None),
        failures=failures,
        complete=complete,
    )
    if (
        cache_result
        and complete
        and not timed_out
        and not interrupted
        and completed_class_count == len(entries)
    ):
        serialized = json.dumps(
            {
                "class_count": len(entries),
                "inventory_class_count": inventory_class_count,
                "parse_failure_count": len(parse_failures),
                "edges": rows,
                **(
                    {
                        "structural_facts": {
                            key: sorted(values)
                            for key, values in structural_facts.items()
                        }
                    }
                    if include_structural_facts else {}
                ),
                "failures": failures,
                "complete": complete,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        with _IMMUTABLE_ORACLE_CACHE_LOCK:
            _IMMUTABLE_ORACLE_CACHE.setdefault(cache_key, serialized)
    return result
