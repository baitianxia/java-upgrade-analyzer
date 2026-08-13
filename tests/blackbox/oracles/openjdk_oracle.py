"""Independent Oracle backed only by OpenJDK command-line tools.

This module intentionally imports no production package.  It derives the
fixture's removed API set and direct root reachability with ``javap``, then
executes the compiled client on base/current classpaths to observe the JVM's
actual linkage behavior.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
from typing import Iterable, Mapping
import zipfile


IDENTITY_FIELDS = ("owner", "member", "descriptor", "member_kind")
_METHOD_HEADING = re.compile(
    r"^\s*(?:public|protected|private)\s+.*?([A-Za-z_$][\w$]*)\([^)]*\);\s*$"
)
_FIELD_HEADING = re.compile(
    r"^\s*(?:public|protected|private)\s+.+\s+([A-Za-z_$][\w$]*);\s*$"
)
_DESCRIPTOR = re.compile(r"^\s*descriptor:\s*(\S+)\s*$")
_INVOKE = re.compile(
    r"//\s+(?:InterfaceMethod|Method)\s+([^\s.]+)\.([^:]+):(\S+)"
)
_LOCAL_INVOKE = re.compile(
    r"//\s+(?:InterfaceMethod|Method)\s+([^\s.:]+):(\S+)"
)
_FIELD_ACCESS = re.compile(r"//\s+Field\s+([^\s.]+)\.([^:]+):(\S+)")
_MEMBER_FLAGS = re.compile(
    r"^\s*flags:\s*\(0x[0-9a-fA-F]+\)\s*(.*)$"
)
_INSTRUCTION = re.compile(r"^\s*\d+:\s+(.+?)\s*$")
_CONSTANT_POOL_INDEX = re.compile(r"#\d+")
_SUPER_CLASS = re.compile(r"^\s*super_class:.*?//\s+(\S+)\s*$")
_PRIMITIVES = {
    "B": "byte", "C": "char", "D": "double", "F": "float",
    "I": "int", "J": "long", "S": "short", "Z": "boolean", "V": "void",
}


class OpenJdkOracleError(RuntimeError):
    pass


def _run(command: list[str], *, expected_returncode: int | None = 0) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=60,
    )
    if expected_returncode is not None and completed.returncode != expected_returncode:
        raise OpenJdkOracleError(
            f"command_failed:{completed.returncode}:{' '.join(command)}:"
            f"{completed.stderr[-1000:]}"
        )
    return completed


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _identity(row: Mapping[str, object]) -> tuple[str, str, str, str]:
    return tuple(str(row.get(field) or "") for field in IDENTITY_FIELDS)


def _identity_row(identity: tuple[str, str, str, str]) -> dict[str, str]:
    return dict(zip(IDENTITY_FIELDS, identity))


def _javap(
    javap: str, classpath: Iterable[Path], class_name: str, *options: str,
    allow_missing: bool = False,
) -> str:
    command = [
        javap,
        "-classpath", os.pathsep.join(str(Path(path)) for path in classpath),
        *options,
        class_name,
    ]
    completed = _run(
        command, expected_returncode=None if allow_missing else 0,
    )
    if completed.returncode != 0:
        diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
        if allow_missing and (
            "class not found" in diagnostic or "not found:" in diagnostic
        ):
            return ""
        raise OpenJdkOracleError(
            f"command_failed:{completed.returncode}:{' '.join(command)}:"
            f"{completed.stderr[-1000:]}"
        )
    return completed.stdout


def public_members(
    javap: str, jar: Path, class_name: str, *, allow_missing: bool = False,
) -> set[tuple[str, str, str, str]]:
    """Return the complete public method/field inventory emitted by javap."""
    owner = class_name.replace(".", "/")
    if allow_missing:
        with zipfile.ZipFile(jar) as archive:
            if f"{owner}.class" not in archive.namelist():
                return set()
    simple_class_name = class_name.rsplit(".", 1)[-1]
    pending_member = ""
    pending_kind = ""
    members: set[tuple[str, str, str, str]] = set()
    output = _javap(
        javap, [jar], class_name, "-public", "-s",
        allow_missing=allow_missing,
    )
    if not output:
        return set()
    for line in output.splitlines():
        heading = _METHOD_HEADING.match(line)
        if heading:
            pending_member = heading.group(1)
            pending_kind = "method"
            if pending_member == simple_class_name:
                pending_member = "<init>"
            continue
        field_heading = _FIELD_HEADING.match(line)
        if field_heading:
            pending_member = field_heading.group(1)
            pending_kind = "field"
            continue
        descriptor = _DESCRIPTOR.match(line)
        if descriptor and pending_member:
            members.add((owner, pending_member, descriptor.group(1), pending_kind))
            pending_member = ""
            pending_kind = ""
    if not members:
        raise OpenJdkOracleError(f"javap_public_member_inventory_empty:{class_name}")
    return members


def public_member_contracts(
    javap: str, jar: Path, class_name: str, *, allow_missing: bool = False,
) -> dict[tuple[str, str, str, str], tuple[str, ...]]:
    """Return public member access/dispatch flags from OpenJDK ``javap -v``."""
    owner = class_name.replace(".", "/")
    if allow_missing and not _class_entry_present(jar, class_name):
        return {}
    simple_class_name = class_name.rsplit(".", 1)[-1]
    pending_member = ""
    pending_kind = ""
    pending_identity: tuple[str, str, str, str] | None = None
    contracts: dict[tuple[str, str, str, str], tuple[str, ...]] = {}
    output = _javap(
        javap, [jar], class_name, "-public", "-s", "-v",
        allow_missing=allow_missing,
    )
    if not output:
        return contracts
    for line in output.splitlines():
        heading = _METHOD_HEADING.match(line)
        if heading:
            pending_member = heading.group(1)
            pending_kind = "method"
            pending_identity = None
            if pending_member == simple_class_name:
                pending_member = "<init>"
            continue
        field_heading = _FIELD_HEADING.match(line)
        if field_heading:
            pending_member = field_heading.group(1)
            pending_kind = "field"
            pending_identity = None
            continue
        descriptor = _DESCRIPTOR.match(line)
        if descriptor and pending_member:
            pending_identity = (
                owner, pending_member, descriptor.group(1), pending_kind,
            )
            pending_member = ""
            pending_kind = ""
            continue
        flags = _MEMBER_FLAGS.match(line)
        if flags and pending_identity:
            contracts[pending_identity] = tuple(sorted(
                value.strip()
                for value in flags.group(1).split(",")
                if value.strip()
            ))
            pending_identity = None
    if not contracts:
        raise OpenJdkOracleError(
            f"javap_public_member_contract_inventory_empty:{class_name}"
        )
    return contracts


def public_method_bodies(
    javap: str, jar: Path, class_name: str, *, allow_missing: bool = False,
) -> dict[tuple[str, str, str, str], tuple[str, ...]]:
    """Return normalized public method instructions without product parsers."""
    owner = class_name.replace(".", "/")
    if allow_missing and not _class_entry_present(jar, class_name):
        return {}
    simple_class_name = class_name.rsplit(".", 1)[-1]
    pending_member = ""
    current: tuple[str, str, str, str] | None = None
    in_code = False
    bodies: dict[tuple[str, str, str, str], list[str]] = {}
    output = _javap(
        javap, [jar], class_name, "-public", "-s", "-c",
        allow_missing=allow_missing,
    )
    if not output:
        return {}
    for line in output.splitlines():
        heading = _METHOD_HEADING.match(line)
        if heading:
            pending_member = heading.group(1)
            current = None
            in_code = False
            if pending_member == simple_class_name:
                pending_member = "<init>"
            continue
        descriptor = _DESCRIPTOR.match(line)
        if descriptor and pending_member:
            current = (owner, pending_member, descriptor.group(1), "method")
            bodies.setdefault(current, [])
            pending_member = ""
            in_code = False
            continue
        if current and line.strip() == "Code:":
            in_code = True
            continue
        instruction = _INSTRUCTION.match(line)
        if current and in_code and instruction:
            bodies[current].append(
                _CONSTANT_POOL_INDEX.sub("#", instruction.group(1))
            )
    return {identity: tuple(body) for identity, body in bodies.items()}


def direct_super_class(
    javap: str, jar: Path, class_name: str, *, allow_missing: bool = False,
) -> str:
    """Read the direct superclass from the classfile, not source metadata."""
    if allow_missing and not _class_entry_present(jar, class_name):
        return ""
    output = _javap(
        javap, [jar], class_name, "-v", allow_missing=allow_missing,
    )
    for line in output.splitlines():
        matched = _SUPER_CLASS.match(line)
        if matched:
            return matched.group(1)
    return ""


def resolve_inherited_target(
    identity: tuple[str, str, str, str],
    members: set[tuple[str, str, str, str]],
    super_classes: Mapping[str, str],
) -> tuple[str, str, str, str]:
    """Resolve a symbolic owner through its independently read superclass chain."""
    if identity in members:
        return identity
    owner, member, descriptor, kind = identity
    visited = set()
    candidate_owner = owner
    while candidate_owner and candidate_owner not in visited:
        visited.add(candidate_owner)
        candidate_owner = str(super_classes.get(candidate_owner) or "")
        candidate = (candidate_owner, member, descriptor, kind)
        if candidate in members:
            return candidate
    return identity


def direct_call_graph(
    javap: str, classpath: Iterable[Path], class_name: str,
) -> dict[tuple[str, str, str, str], set[tuple[str, str, str, str]]]:
    """Read exact direct invocation targets from javap bytecode comments."""
    owner = class_name.replace(".", "/")
    simple_class_name = class_name.rsplit(".", 1)[-1]
    pending_member = ""
    current: tuple[str, str, str, str] | None = None
    graph: dict[tuple[str, str, str, str], set[tuple[str, str, str, str]]] = {}
    output = _javap(javap, classpath, class_name, "-p", "-s", "-c")
    for line in output.splitlines():
        heading = _METHOD_HEADING.match(line)
        if heading:
            pending_member = heading.group(1)
            current = None
            if pending_member == simple_class_name:
                pending_member = "<init>"
            continue
        descriptor = _DESCRIPTOR.match(line)
        if descriptor and pending_member:
            current = (owner, pending_member, descriptor.group(1), "method")
            graph.setdefault(current, set())
            pending_member = ""
            continue
        invoked = _INVOKE.search(line)
        if current and invoked:
            graph[current].add((
                invoked.group(1), invoked.group(2).strip('"'),
                invoked.group(3), "method",
            ))
            continue
        local_invoked = _LOCAL_INVOKE.search(line)
        if current and local_invoked:
            graph[current].add((
                owner, local_invoked.group(1).strip('"'),
                local_invoked.group(2), "method",
            ))
            continue
        field_access = _FIELD_ACCESS.search(line)
        if current and field_access:
            graph[current].add((
                field_access.group(1), field_access.group(2).strip('"'),
                field_access.group(3), "field",
            ))
    if not graph:
        raise OpenJdkOracleError(f"javap_call_graph_empty:{class_name}")
    return graph


def _descriptor_type(value: str, offset: int) -> tuple[str, int]:
    dimensions = 0
    while offset < len(value) and value[offset] == "[":
        dimensions += 1
        offset += 1
    if offset >= len(value):
        raise OpenJdkOracleError(f"invalid_descriptor:{value}")
    marker = value[offset]
    if marker in _PRIMITIVES:
        type_name = _PRIMITIVES[marker]
        offset += 1
    elif marker == "L":
        end = value.find(";", offset)
        if end < 0:
            raise OpenJdkOracleError(f"invalid_descriptor:{value}")
        type_name = value[offset + 1:end].replace("/", ".").replace("$", ".")
        offset = end + 1
    else:
        raise OpenJdkOracleError(f"invalid_descriptor:{value}")
    return type_name + "[]" * dimensions, offset


def _member_label(identity: tuple[str, str, str, str]) -> str:
    owner, member, descriptor, kind = identity
    if kind == "field":
        return f"{owner.replace('/', '.')}.{member}"
    if not descriptor.startswith("(") or ")" not in descriptor:
        raise OpenJdkOracleError(f"invalid_method_descriptor:{descriptor}")
    end = descriptor.index(")")
    offset = 1
    parameters = []
    while offset < end:
        parameter, offset = _descriptor_type(descriptor, offset)
        parameters.append(parameter)
    if offset != end:
        raise OpenJdkOracleError(f"invalid_method_descriptor:{descriptor}")
    return f"{owner.replace('/', '.')}.{member}({','.join(parameters)})"


def reachable_paths(
    graph: Mapping[
        tuple[str, str, str, str], set[tuple[str, str, str, str]]
    ],
    roots: Iterable[tuple[str, str, str, str]],
) -> dict[tuple[str, str, str, str], tuple[tuple[str, str, str, str], ...]]:
    """Compute deterministic shortest paths without using product graph code."""
    queue = [(root, (root,)) for root in roots]
    paths: dict[
        tuple[str, str, str, str], tuple[tuple[str, str, str, str], ...]
    ] = {}
    while queue:
        node, path = queue.pop(0)
        if node in paths:
            continue
        paths[node] = path
        for target in sorted(graph.get(node, set())):
            if target not in paths:
                queue.append((target, (*path, target)))
    return paths


def _tool_version(command: str, *arguments: str) -> str:
    completed = _run([command, *arguments], expected_returncode=None)
    text = f"{completed.stdout}\n{completed.stderr}".strip()
    if completed.returncode != 0 or not text:
        raise OpenJdkOracleError(f"tool_version_unavailable:{command}")
    return text.splitlines()[0].strip()


def _class_entry_present(jar: Path, class_name: str) -> bool:
    entry = class_name.replace(".", "/") + ".class"
    with zipfile.ZipFile(jar) as archive:
        return entry in archive.namelist()


def evaluate_fixture(
    *,
    case: Mapping[str, object],
    base_library: Path,
    current_library: Path,
    business_jar: Path,
    oracle_jar: Path,
    java: str,
    javap: str,
) -> dict[str, object]:
    library_classes = [
        str(value) for value in (
            case.get("library_classes") or [case["library_class"]]
        )
    ]
    business_classes = [
        str(value) for value in (
            case.get("business_classes") or [case["business_class"]]
        )
    ]
    base_members = set().union(*(
        public_members(javap, base_library, class_name)
        for class_name in library_classes
    ))
    current_members = set().union(*(
        public_members(
            javap, current_library, class_name, allow_missing=True,
        )
        for class_name in library_classes
    ))
    removed = base_members - current_members
    base_contracts: dict[
        tuple[str, str, str, str], tuple[str, ...]
    ] = {}
    current_contracts: dict[
        tuple[str, str, str, str], tuple[str, ...]
    ] = {}
    base_bodies: dict[
        tuple[str, str, str, str], tuple[str, ...]
    ] = {}
    current_bodies: dict[
        tuple[str, str, str, str], tuple[str, ...]
    ] = {}
    for class_name in library_classes:
        base_contracts.update(public_member_contracts(
            javap, base_library, class_name,
        ))
        current_contracts.update(public_member_contracts(
            javap, current_library, class_name, allow_missing=True,
        ))
        base_bodies.update(public_method_bodies(
            javap, base_library, class_name,
        ))
        current_bodies.update(public_method_bodies(
            javap, current_library, class_name, allow_missing=True,
        ))
    contract_changed = {
        identity for identity in base_contracts.keys() & current_contracts.keys()
        if base_contracts[identity] != current_contracts[identity]
    }
    implementation_changed = {
        identity for identity in base_bodies.keys() & current_bodies.keys()
        if base_contracts.get(identity) == current_contracts.get(identity)
        and base_bodies[identity] != current_bodies[identity]
    }
    oracle_contract = str(case.get("oracle_contract") or "")
    if oracle_contract == "removed_member_linkage_closed_set":
        changed = removed
    elif oracle_contract == "complete_member_change_closed_set":
        changed = (
            (base_members ^ current_members)
            | contract_changed
            | implementation_changed
        )
    elif oracle_contract == "member_contract_linkage_closed_set":
        changed = removed | contract_changed
    elif oracle_contract == "implementation_change_closed_set":
        changed = implementation_changed
    else:
        raise OpenJdkOracleError(
            f"unsupported_oracle_contract:{oracle_contract}"
        )
    graph: dict[
        tuple[str, str, str, str], set[tuple[str, str, str, str]]
    ] = {}
    super_classes = {
        class_name.replace(".", "/"): direct_super_class(
            javap, base_library, class_name,
        )
        for class_name in library_classes
    }
    for class_name in business_classes:
        for caller, targets in direct_call_graph(
            javap, [business_jar, base_library], class_name,
        ).items():
            graph.setdefault(caller, set()).update(targets)
    graph = {
        caller: {
            resolve_inherited_target(target, base_members, super_classes)
            for target in targets
        }
        for caller, targets in graph.items()
    }
    roots = {
        (
            str(row["class_name"]), str(row["member_name"]),
            str(row["descriptor"]), "method",
        )
        for row in case["entrypoints"]
    }
    paths = reachable_paths(graph, roots)
    linkage = {}
    for probe in case.get("linkage_probes") or ():
        identity = (
            str(probe["owner"]), str(probe["member"]),
            str(probe["descriptor"]), str(probe.get("member_kind") or "method"),
        )
        mode = str(probe["mode"])
        base_run = _run([
            java, "-cp", os.pathsep.join((
                str(oracle_jar), str(business_jar), str(base_library),
            )),
            str(case["oracle_main_class"]), mode,
        ], expected_returncode=None)
        current_run = _run([
            java, "-cp", os.pathsep.join((
                str(oracle_jar), str(business_jar), str(current_library),
            )),
            str(case["oracle_main_class"]), mode,
        ], expected_returncode=None)
        current_error = f"{current_run.stdout}\n{current_run.stderr}"
        expected_error = str(probe["linkage_error"])
        expected_symbol = str(probe.get("error_symbol") or probe["member"])
        linkage[identity] = {
            "base_succeeded": base_run.returncode == 0,
            "current_failed_with_expected_linkage_error": (
                current_run.returncode != 0
                and expected_error in current_error
                and expected_symbol in current_error
            ),
            "expected_error": expected_error,
            "expected_symbol": expected_symbol,
        }
    behavior = {}
    for probe in case.get("behavior_probes") or ():
        identity = (
            str(probe["owner"]), str(probe["member"]),
            str(probe["descriptor"]), str(probe.get("member_kind") or "method"),
        )
        mode = str(probe["mode"])
        base_run = _run([
            java, "-cp", os.pathsep.join((
                str(oracle_jar), str(business_jar), str(base_library),
            )),
            str(case["oracle_main_class"]), mode,
        ], expected_returncode=None)
        current_run = _run([
            java, "-cp", os.pathsep.join((
                str(oracle_jar), str(business_jar), str(current_library),
            )),
            str(case["oracle_main_class"]), mode,
        ], expected_returncode=None)
        behavior[identity] = {
            "base_succeeded": base_run.returncode == 0,
            "current_succeeded": current_run.returncode == 0,
            "base_stdout": base_run.stdout.strip(),
            "current_stdout": current_run.stdout.strip(),
            "matches_authored_expectation": (
                base_run.stdout.strip() == str(probe["base_stdout"])
                and current_run.stdout.strip() == str(probe["current_stdout"])
            ),
        }
    runtime_outcomes = []
    for probe in case.get("runtime_outcome_probes") or ():
        kind = str(probe["member_kind"])
        owner = str(probe["owner"])
        identity = (owner, "", "", kind)
        if kind == "provider_topology":
            base_present = _class_entry_present(
                base_library, owner.replace("/", "."),
            )
            current_present = _class_entry_present(
                current_library, owner.replace("/", "."),
            )
            if not base_present or current_present:
                raise OpenJdkOracleError(
                    f"provider_topology_probe_failed:{owner}:"
                    f"base={base_present}:current={current_present}"
                )
        elif kind == "class_definition":
            definition_main = str(case["definition_oracle_main_class"])
            target_class = owner.replace("/", ".")
            base_run = _run([
                java, "-cp", os.pathsep.join((
                    str(oracle_jar), str(business_jar), str(base_library),
                )), definition_main, target_class,
            ], expected_returncode=None)
            current_run = _run([
                java, "-cp", os.pathsep.join((
                    str(oracle_jar), str(business_jar), str(current_library),
                )), definition_main, target_class,
            ], expected_returncode=None)
            current_error = f"{current_run.stdout}\n{current_run.stderr}"
            if (
                base_run.returncode != 0
                or current_run.returncode == 0
                or str(probe["linkage_error"]) not in current_error
                or str(probe["error_symbol"]) not in current_error
            ):
                raise OpenJdkOracleError(
                    f"class_definition_probe_failed:{owner}:"
                    f"base={base_run.returncode}:current={current_run.returncode}:"
                    f"{current_error[-500:]}"
                )
        else:
            raise OpenJdkOracleError(f"unsupported_runtime_outcome_probe:{kind}")
        runtime_outcomes.append(_identity_row(identity))
    changed_paths = {
        identity: paths[identity]
        for identity in changed if identity in paths
    }
    return {
        "schema": "java-upgrade-analyzer.openjdk-blackbox-oracle.v1",
        "producer": "OpenJDK javap + JVM linker",
        "tool_versions": {
            "java": _tool_version(java, "-version"),
            "javap": _tool_version(javap, "-version"),
        },
        "artifact_sha256": {
            "base_library": _sha256(base_library),
            "current_library": _sha256(current_library),
            "business": _sha256(business_jar),
            "oracle_runner": _sha256(oracle_jar),
        },
        "removed_identities": [
            _identity_row(identity) for identity in sorted(removed)
        ],
        "contract_changed_identities": [
            _identity_row(identity) for identity in sorted(contract_changed)
        ],
        "implementation_changed_identities": [
            _identity_row(identity) for identity in sorted(implementation_changed)
        ],
        "changed_identities": [
            _identity_row(identity) for identity in sorted(changed)
        ],
        "base_identities": [
            _identity_row(identity) for identity in sorted(base_members)
        ],
        "current_identities": [
            _identity_row(identity) for identity in sorted(current_members)
        ],
        "super_classes": dict(sorted(super_classes.items())),
        "reachable_removed_identities": [
            _identity_row(identity) for identity in sorted(changed_paths)
        ],
        "reachable_changed_identities": [
            _identity_row(identity) for identity in sorted(changed_paths)
        ],
        "required_paths": {
            "|".join(identity): " → ".join(
                _member_label(node) for node in path
            )
            for identity, path in sorted(changed_paths.items())
        },
        "linkage": {
            "|".join(identity): result
            for identity, result in sorted(linkage.items())
        },
        "behavior": {
            "|".join(identity): result
            for identity, result in sorted(behavior.items())
        },
        "runtime_outcome_identities": sorted(
            runtime_outcomes, key=_identity,
        ),
    }


__all__ = ["OpenJdkOracleError", "evaluate_fixture"]
