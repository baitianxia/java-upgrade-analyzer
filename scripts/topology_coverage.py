#!/usr/bin/env python3
"""Extract and classify stable topologies from verified final artifacts."""

from __future__ import annotations

from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, wait
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import struct
import tempfile
import time
import zipfile

from final_artifact_edge_oracle import (
    INSTRUCTION_RE,
    _parse_member_header,
    scan_final_artifact,
)
from signature_utils import normalize_signature_for_lookup
from third_party_jdk_oracle import _source_signature


STABLE_TOPOLOGY_IDS = frozenset({
    "business_direct", "same_jar_bridge", "cross_jar_bridge",
    "business_to_same_jar_bridge", "business_to_cross_jar_bridge",
    "same_coord_multimodule", "overloaded_method", "constructor",
    "interface_dispatch", "virtual_dispatch", "static_dispatch", "field_access",
    "invokedynamic", "reflection", "spi", "framework_proxy",
    "source_bytecode_agree", "source_bytecode_true_conflict",
})
EDGE_FIELDS = (
    "caller_owner", "caller_member", "caller_descriptor", "callee_owner",
    "callee_member", "callee_descriptor", "opcode_family",
)
INVOKE_OPCODES = {
    "invokevirtual", "invokeinterface", "invokestatic", "invokespecial", "invokedynamic"
}
FIELD_OPCODES = {"getfield", "putfield", "getstatic", "putstatic"}
REFLECTION_REGISTRATION_RESOURCE = "META-INF/jua/authoritative-reflection-registration.json"
FRAMEWORK_PROXY_REGISTRATION_RESOURCE = "META-INF/jua/authoritative-framework-proxy-registration.json"
HIERARCHY_SCAN_TIMEOUT_SEC = 120.0
HIERARCHY_SCAN_MAX_WORKERS = max(1, min(8, os.cpu_count() or 1))


def descriptor_source_signature(descriptor: str) -> str:
    if not str(descriptor or "").startswith("("):
        return ""
    return _source_signature(str(descriptor).split(")", 1)[0] + ")")


def _edge_identity(edge: dict) -> tuple[str, ...]:
    return tuple(str(edge.get(field) or "").strip() for field in EDGE_FIELDS)


def _method_node(edge: dict, side: str) -> tuple[str, str, str]:
    return tuple(str(edge.get(f"{side}_{field}") or "").strip() for field in (
        "owner", "member", "descriptor"
    ))


def _target_identity(item: dict) -> tuple[str, str, str]:
    return tuple(str(item.get(field) or "").strip() for field in ("owner", "member", "descriptor"))


def _entry_metadata(entry: str, layout: dict) -> dict:
    matches = [
        item for item in layout.get("entry_layout") or []
        if entry == item.get("entry")
        or (item.get("prefix") and entry.startswith(str(item["prefix"])))
    ]
    return max(
        matches,
        key=lambda item: len(str(item.get("entry") or item.get("prefix") or "")),
        default={},
    )


def _business_reaches(target, incoming, caller_roles) -> bool:
    pending = deque([target])
    visited = {target}
    while pending:
        for caller in incoming.get(pending.popleft(), set()):
            if "business" in caller_roles.get(caller, set()):
                return True
            if caller not in visited:
                visited.add(caller)
                pending.append(caller)
    return False


def _archive_inventory(artifact: Path) -> dict:
    classes: dict[str, bytes] = {}
    resources: dict[str, bytes] = {}
    containers: set[str] = set()
    with zipfile.ZipFile(artifact) as outer:
        for info in outer.infolist():
            if info.is_dir():
                continue
            data = outer.read(info)
            if info.filename.endswith(".class"):
                classes[info.filename] = data
            elif info.filename.startswith("META-INF/"):
                resources[info.filename] = data
            if info.filename.startswith(("BOOT-INF/lib/", "WEB-INF/lib/")) and info.filename.endswith(".jar"):
                containers.add(info.filename)
                with zipfile.ZipFile(io.BytesIO(data)) as nested:
                    for nested_info in nested.infolist():
                        if nested_info.is_dir():
                            continue
                        key = f"{info.filename}!/{nested_info.filename}"
                        nested_data = nested.read(nested_info)
                        if nested_info.filename.endswith(".class"):
                            classes[key] = nested_data
                        elif nested_info.filename.startswith("META-INF/"):
                            resources[key] = nested_data
    return {"classes": classes, "resources": resources, "containers": containers}


def _class_binary_name(entry: str) -> str:
    logical = entry.split("!/", 1)[-1]
    for prefix in ("BOOT-INF/classes/", "WEB-INF/classes/"):
        if logical.startswith(prefix):
            logical = logical[len(prefix):]
    return logical[:-6].replace("/", ".") if logical.endswith(".class") else ""


def _container(entry: str) -> str:
    return entry.split("!/", 1)[0] if "!/" in entry else ""


def compute_source_tree_sha256(source_root: Path) -> str:
    digest = hashlib.sha256()
    root = Path(source_root)
    for path in sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink()):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def _javap_text(content: bytes, *options: str) -> str:
    with tempfile.TemporaryDirectory(prefix="topology-javap-") as temporary:
        class_path = Path(temporary) / "target.class"
        class_path.write_bytes(content)
        completed = subprocess.run(
            ["javap", *options, str(class_path)], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
            timeout=30,
        )
    return completed.stdout if completed.returncode == 0 else ""


def _classfile_header_parents(content: bytes) -> tuple[tuple[str, ...], str]:
    """Read erased superclass/interfaces without starting a JVM."""
    try:
        if len(content) < 10 or content[:4] != b"\xca\xfe\xba\xbe":
            return (), "not a classfile"
        count = struct.unpack_from(">H", content, 8)[0]
        utf8 = {}
        classes = {}
        index = 10
        slot = 1
        while slot < count:
            if index >= len(content):
                return (), "truncated constant pool"
            tag = content[index]
            index += 1
            if tag == 1:
                length = struct.unpack_from(">H", content, index)[0]
                index += 2
                utf8[slot] = content[index:index + length].decode("utf-8", errors="replace")
                index += length
            elif tag == 7:
                classes[slot] = struct.unpack_from(">H", content, index)[0]
                index += 2
            elif tag in (9, 10, 11, 12, 17, 18):
                index += 4
            elif tag in (3, 4):
                index += 4
            elif tag in (5, 6):
                index += 8
                slot += 1
            elif tag in (8, 16, 19, 20):
                index += 2
            elif tag == 15:
                index += 3
            else:
                return (), f"unsupported constant-pool tag {tag}"
            if index > len(content):
                return (), "truncated constant-pool payload"
            slot += 1
        if index + 8 > len(content):
            return (), "truncated class header"
        _access, _this_class, super_class, interface_count = struct.unpack_from(">HHHH", content, index)
        index += 8
        if index + interface_count * 2 > len(content):
            return (), "truncated interface table"
        interface_indexes = struct.unpack_from(f">{interface_count}H", content, index) if interface_count else ()

        def class_name(class_index):
            return utf8.get(classes.get(class_index), "").replace("/", ".")

        parents = []
        if super_class:
            parents.append(class_name(super_class))
        parents.extend(class_name(item) for item in interface_indexes)
        if any(not item for item in parents):
            return (), "unresolved class name in header"
        return tuple(parents), ""
    except (IndexError, struct.error, ValueError) as exc:
        return (), f"classfile header parse failed: {type(exc).__name__}: {exc}"


def _class_header_parents(content: bytes, timeout_sec: float) -> tuple[tuple[str, ...], str]:
    direct, direct_error = _classfile_header_parents(content)
    if not direct_error:
        return direct, ""
    if timeout_sec <= 0:
        return (), f"hierarchy scan deadline exceeded before javap started; {direct_error}"
    try:
        with tempfile.TemporaryDirectory(prefix="topology-javap-") as temporary:
            class_path = Path(temporary) / "target.class"
            class_path.write_bytes(content)
            completed = subprocess.run(
                ["javap", "-p", str(class_path)], capture_output=True, text=True, encoding="utf-8", errors="replace",
                check=False, timeout=timeout_sec,
            )
    except subprocess.TimeoutExpired:
        return (), "javap timed out before the hierarchy scan deadline"
    except OSError as error:
        return (), f"direct parse failed ({direct_error}); javap unavailable: {error}"
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
        return (), f"javap exited {completed.returncode}: {detail}"
    declaration = next(
        (line.strip() for line in completed.stdout.splitlines() if re.search(r"\b(class|interface)\b", line)),
        "",
    )
    return _class_header_relation_types(declaration), ""


def _class_header_relation_types(declaration: str) -> tuple[str, ...]:
    class_name = re.search(r"\b(?:class|interface)\s+[\w.$]+", declaration)
    if not class_name:
        return ()
    remainder = declaration[class_name.end():].lstrip()
    if remainder.startswith("<"):
        remainder = _strip_leading_generic_arguments(remainder)

    parents = []
    extends = re.search(r"\bextends\s+(.+?)(?=\s+implements\b|\s*\{|$)", remainder)
    implements = re.search(r"\bimplements\s+(.+?)(?=\s*\{|$)", remainder)
    if extends:
        parents.extend(_header_type_names(extends.group(1)))
    if implements:
        parents.extend(_header_type_names(implements.group(1)))
    return tuple(parents)


def _strip_leading_generic_arguments(value: str) -> str:
    depth = 0
    for index, character in enumerate(value):
        if character == "<":
            depth += 1
        elif character == ">":
            depth -= 1
            if depth == 0:
                return value[index + 1:].lstrip()
    return value


def _header_type_names(value: str) -> list[str]:
    names = []
    depth = 0
    start = 0
    for index, character in enumerate(value):
        if character == "<":
            depth += 1
        elif character == ">":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            names.append(value[start:index])
            start = index + 1
    names.append(value[start:])
    return [name.split("<", 1)[0].strip() for name in names if name.split("<", 1)[0].strip()]


def _class_header_before_deadline(
    content: bytes, deadline: float,
) -> tuple[tuple[str, ...], str]:
    return _class_header_parents(content, deadline - time.perf_counter())


def _scan_class_hierarchy(
    inventory: dict,
    *,
    timeout_sec: float = HIERARCHY_SCAN_TIMEOUT_SEC,
    max_workers: int = HIERARCHY_SCAN_MAX_WORKERS,
) -> dict:
    started_at = time.perf_counter()
    timeout_sec = max(0.0, float(timeout_sec))
    workers = max(1, min(HIERARCHY_SCAN_MAX_WORKERS, int(max_workers)))
    deadline = started_at + timeout_sec
    class_entries = sorted((inventory.get("classes") or {}).items())
    entries_by_sha: dict[str, list[str]] = defaultdict(list)
    content_by_sha: dict[str, bytes] = {}
    for entry, content in class_entries:
        fingerprint = hashlib.sha256(content).hexdigest()
        entries_by_sha[fingerprint].append(entry)
        content_by_sha.setdefault(fingerprint, content)

    futures = {}
    pending_fingerprints = set()
    interrupted_fingerprints = set()
    interruption_error = ""
    completed = set()
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="topology-javap")
    try:
        for fingerprint in sorted(content_by_sha):
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                pending_fingerprints.add(fingerprint)
                continue
            futures[executor.submit(
                _class_header_before_deadline, content_by_sha[fingerprint], deadline,
            )] = fingerprint
        if futures:
            completed, pending = wait(futures, timeout=max(0.0, deadline - time.perf_counter()))
            pending_fingerprints.update(futures[future] for future in pending)
    except BaseException as exc:  # KeyboardInterrupt/SystemExit must fail closed.
        interruption_error = f"hierarchy scan interrupted: {type(exc).__name__}: {exc}"
        interrupted_fingerprints.update(content_by_sha)
    finally:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)

    futures_by_fingerprint = {fingerprint: future for future, fingerprint in futures.items()}
    parents_by_sha: dict[str, tuple[str, ...]] = {}
    errors_by_sha: dict[str, str] = {}
    for future in completed:
        fingerprint = futures[future]
        try:
            parents, error = future.result()
        except BaseException as exc:  # KeyboardInterrupt/SystemExit must fail closed.
            parents, error = (), f"header worker failed: {type(exc).__name__}: {exc}"
        if error:
            errors_by_sha[fingerprint] = str(error)
        else:
            parents_by_sha[fingerprint] = tuple(parents)
    for fingerprint in pending_fingerprints:
        future = futures_by_fingerprint[fingerprint]
        if future.cancelled():
            error = "header worker cancelled before the hierarchy scan deadline"
        else:
            try:
                _, error = future.result()
            except BaseException as exc:  # KeyboardInterrupt/SystemExit must fail closed.
                error = f"header worker failed: {type(exc).__name__}: {exc}"
        detail = f"; {error}" if error else ""
        errors_by_sha[fingerprint] = f"hierarchy scan deadline exceeded{detail}"
    for fingerprint in interrupted_fingerprints:
        future = futures_by_fingerprint.get(fingerprint)
        detail = ""
        if future is not None and not future.cancelled():
            try:
                _, error = future.result()
            except BaseException as exc:  # KeyboardInterrupt/SystemExit must fail closed.
                error = f"header worker failed: {type(exc).__name__}: {exc}"
            if error:
                detail = f"; {error}"
        errors_by_sha[fingerprint] = f"{interruption_error}{detail}"

    errors = []
    for fingerprint in sorted(errors_by_sha):
        for entry in sorted(entries_by_sha[fingerprint]):
            errors.append(
                f"hierarchy header unavailable entry={entry} sha256={fingerprint}: "
                f"{errors_by_sha[fingerprint]}"
            )

    relations = set()
    owner_entries = defaultdict(set)
    for entry in inventory["classes"]:
        owner_entries[_class_binary_name(entry)].add(entry)
    for entry, content in class_entries:
        child = _class_binary_name(entry)
        parents = parents_by_sha.get(hashlib.sha256(content).hexdigest(), ())
        for parent in parents:
            same_scope = [
                parent_entry for parent_entry in owner_entries.get(parent, set())
                if _entry_scope(parent_entry) == _entry_scope(entry)
            ]
            for parent_entry in same_scope:
                if child and parent and child != parent:
                    relations.add((entry, child, parent_entry, parent))
    elapsed_sec = time.perf_counter() - started_at
    metrics = {
        "elapsed_sec": round(elapsed_sec, 3),
        "deadline_sec": timeout_sec,
        "max_workers": workers,
        "class_entries": len(class_entries),
        "unique_class_headers": len(content_by_sha),
        "cache_hits": len(class_entries) - len(content_by_sha),
        "completed_unique_headers": len(completed),
        "failed_class_entries": len(errors),
        "timed_out_class_entries": sum(
            len(entries_by_sha[fingerprint]) for fingerprint in pending_fingerprints
        ),
    }
    return {
        "complete": not errors,
        "relations": [
        {
            "child_entry": child_entry, "child": child,
            "parent_entry": parent_entry, "parent": parent,
            "authority": "javap_class_header",
        }
        for child_entry, child, parent_entry, parent in sorted(relations)
        ],
        "errors": errors,
        "metrics": metrics,
    }


def _class_hierarchy(inventory: dict) -> list[dict]:
    return _scan_class_hierarchy(inventory)["relations"]


def _entry_scope(entry: str) -> str:
    return _container(entry) or "<root>"


def _is_assignable(
    child: str, child_entry: str, parent: str, parent_entry: str, hierarchy: list[dict]
) -> bool:
    parents = defaultdict(set)
    for item in hierarchy:
        if item.get("authority") == "javap_class_header":
            parents[(str(item.get("child") or ""), str(item.get("child_entry") or ""))].add(
                (str(item.get("parent") or ""), str(item.get("parent_entry") or ""))
            )
    pending = deque([(child, child_entry)])
    visited = {(child, child_entry)}
    while pending:
        node = pending.popleft()
        if node == (parent, parent_entry):
            return True
        for candidate in parents.get(node, set()):
            if candidate not in visited:
                visited.add(candidate)
                pending.append(candidate)
    return False


def _selected_target_identities(rows: list[dict], edges: list[dict]) -> tuple[list[dict], list[str]]:
    targets: dict[tuple[str, str, str], dict] = {}
    unresolved: list[str] = []
    for row in rows:
        api_name = str(row.get("api_name") or "").strip()
        owner, separator, member = api_name.rpartition(".")
        signature = normalize_signature_for_lookup(str(row.get("api_signature") or ""))
        kind = str(row.get("symbol_kind") or "method").strip()
        matches = []
        for edge in edges:
            if edge.get("callee_owner") != owner or edge.get("callee_member") != member:
                continue
            descriptor = str(edge.get("callee_descriptor") or "")
            if kind != "field" and normalize_signature_for_lookup(descriptor_source_signature(descriptor)) != signature:
                continue
            matches.append(edge)
        identities = {_method_node(edge, "callee") for edge in matches}
        if not separator or not identities:
            unresolved.append(f"{api_name}{row.get('api_signature') or ''}")
            continue
        for identity in identities:
            targets[identity] = {
                "owner": identity[0], "member": identity[1], "descriptor": identity[2],
                "coordinate": str(row.get("coord") or ""),
            }
    return sorted(targets.values(), key=_target_identity), sorted(unresolved)


def _target_reachable_from_provider(
    provider: str, provider_entry: str, targets: set[tuple[str, str, str]],
    target_entries: set[str], edges: list[dict],
) -> bool:
    outgoing = defaultdict(set)
    starts = set()
    for edge in edges:
        caller = (str(edge.get("artifact_entry") or ""), *_method_node(edge, "caller"))
        if caller[0] == provider_entry and caller[1] == provider:
            starts.add(caller)
        if edge.get("opcode_family") in INVOKE_OPCODES:
            outgoing[caller].add(_method_node(edge, "callee"))
    pending = deque(starts)
    visited = set(starts)
    while pending:
        node = pending.popleft()
        if len(node) == 3 and node in targets:
            return any(_entry_scope(item) == _entry_scope(provider_entry) for item in target_entries)
        for callee in outgoing.get(node, set()):
            if callee not in visited:
                visited.add(callee)
                pending.append(callee)
    return False


def _target_from_text(value: str, targets: set[tuple[str, str, str]]) -> tuple[str, str, str] | None:
    compact = str(value or "").strip().replace("/", ".")
    for target in targets:
        rendered = f"{target[0]}.{target[1]}{target[2]}"
        if compact == rendered:
            return target
    return None


def _authoritative_runtime_registration(
    item: dict, kind: str, resource: str, targets: set[tuple[str, str, str]]
) -> bool:
    target = tuple(item.get("target") or [])
    runtime = item.get("runtime_registration") or {}
    return bool(
        item.get("kind") == kind
        and item.get("evidence_authority") in {
            "parsed_reflection_registration", "parsed_framework_resource",
        }
        and item.get("resource", "").split("!/", 1)[-1] == resource
        and item.get("authority")
        and "analyzer" not in str(item.get("authority")).lower()
        and item.get("authority_version")
        and item.get("procedure")
        and target in targets
        and runtime.get("validated") is True
        and _target_from_text(str(runtime.get("target") or ""), targets) == target
    )


def _resource_evidence(
    inventory: dict, targets: set[tuple[str, str, str]], target_entries: set[str],
    edges: list[dict], hierarchy: list[dict]
) -> list[dict]:
    owner_entries = defaultdict(set)
    for entry in inventory["classes"]:
        owner_entries[_class_binary_name(entry)].add(entry)
    evidence = []
    for resource, data in inventory["resources"].items():
        logical = resource.split("!/", 1)[-1]
        if logical.startswith("META-INF/services/"):
            contract = logical[len("META-INF/services/"):]
            for provider in data.decode("utf-8", errors="replace").splitlines():
                provider = provider.split("#", 1)[0].strip()
                for provider_entry in owner_entries.get(provider, set()):
                    for contract_entry in owner_entries.get(contract, set()):
                        if (
                            _is_assignable(provider, provider_entry, contract, contract_entry, hierarchy)
                            and _target_reachable_from_provider(
                                provider, provider_entry, targets, target_entries, edges
                            )
                        ):
                            evidence.append({
                                "kind": "spi", "resource": resource, "contract": contract,
                                "contract_entry": contract_entry, "provider": provider,
                                "provider_entry": provider_entry,
                                "target_entries": sorted(target_entries),
                                "evidence_authority": "parsed_service_resource",
                            })
        elif logical == REFLECTION_REGISTRATION_RESOURCE:
            try:
                payload = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            target = _target_from_text(payload.get("target"), targets)
            runtime = payload.get("runtime_registration") or {}
            runtime_target = _target_from_text(runtime.get("target"), targets)
            if (
                target and runtime_target == target
                and payload.get("authority")
                and payload.get("authority_version")
                and payload.get("procedure")
                and runtime.get("validated") is True
            ):
                evidence.append({
                    "kind": "reflection", "resource": resource, "target": list(target),
                    "authority": payload["authority"],
                    "authority_version": payload["authority_version"],
                    "procedure": payload["procedure"],
                    "runtime_registration": runtime,
                    "evidence_authority": "parsed_reflection_registration",
                })
        elif logical == FRAMEWORK_PROXY_REGISTRATION_RESOURCE:
            try:
                payload = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            target = _target_from_text(payload.get("target"), targets)
            contract = str(payload.get("contract") or "")
            runtime = payload.get("runtime_registration") or {}
            runtime_target = _target_from_text(runtime.get("target"), targets)
            if (
                target and runtime_target == target and owner_entries.get(contract)
                and payload.get("authority") and payload.get("authority_version")
                and payload.get("procedure") and runtime.get("validated") is True
            ):
                evidence.append({
                    "kind": "framework_proxy", "resource": resource, "contract": contract,
                    "target": list(target), "authority": payload["authority"],
                    "authority_version": payload["authority_version"],
                    "procedure": payload["procedure"], "runtime_registration": runtime,
                    "evidence_authority": "parsed_framework_resource",
                })
    return evidence


def _reflection_evidence(inventory: dict, targets: set[tuple[str, str, str]], edges: list[dict]) -> list[dict]:
    results = []
    oracle_callers = {_method_node(edge, "caller") for edge in edges}
    for entry, content in inventory["classes"].items():
        owner = _class_binary_name(entry)
        output = _javap_text(content, "-c", "-p", "-s")
        member = None
        descriptor = ""
        instructions = []

        def inspect_method():
            caller = (owner, member or "", descriptor)
            if caller not in oracle_callers:
                return
            stack = []
            locals_map = {}

            def pop(default=("unknown",)):
                return stack.pop() if stack else default

            for line in instructions[:256]:
                match = INSTRUCTION_RE.match(line)
                if not match or len(stack) > 64:
                    continue
                _offset, opcode, rest = match.groups()
                comment = rest.partition("//")[2].strip()
                local_match = re.match(r"(?:a|i)load_(\d+)", opcode) or (
                    re.match(r"(?:a|i)load", opcode) and re.search(r"\b(\d+)\b", rest)
                )
                store_match = re.match(r"(?:a|i)store_(\d+)", opcode) or (
                    re.match(r"(?:a|i)store", opcode) and re.search(r"\b(\d+)\b", rest)
                )
                if opcode in {"ldc", "ldc_w"} and comment.startswith("String "):
                    stack.append(("string", comment[len("String "):]))
                elif local_match:
                    stack.append(locals_map.get(int(local_match.group(1)), ("unknown",)))
                elif store_match:
                    locals_map[int(store_match.group(1))] = pop()
                elif opcode.startswith("iconst") or opcode in {"bipush", "sipush", "aconst_null"}:
                    stack.append(("unknown",))
                elif opcode == "anewarray":
                    pop()
                    stack.append(("array",))
                elif opcode == "aastore":
                    pop(); pop(); pop()
                elif "java/lang/Class.forName:" in comment:
                    value = pop()
                    stack.append(("class", value[1]) if value[0] == "string" else ("unknown",))
                elif "java/lang/Class.getMethod:" in comment:
                    pop()
                    method_name = pop()
                    class_value = pop()
                    if class_value[0] == "class" and method_name[0] == "string":
                        stack.append(("method", class_value[1], method_name[1]))
                    else:
                        stack.append(("unknown",))
                elif "java/lang/reflect/Method.invoke:" in comment:
                    pop(); pop()
                    method_value = pop()
                    if method_value[0] == "method":
                        candidates = [
                            target for target in targets if method_value[1:] == target[:2]
                        ]
                        # Parameter types are not modeled for getMethod. Fail closed on overloads.
                        if len(candidates) == 1:
                            results.append({
                                "caller": list(caller), "target": list(candidates[0]),
                                "artifact_entry": entry,
                                "evidence_authority": "bounded_jvm_instruction_dataflow",
                            })
                    stack.append(("unknown",))
                elif opcode in {"pop", "areturn", "return"}:
                    pop()

        declaration_state = None
        for line in output.splitlines():
            parsed_member, parsed_state = _parse_member_header(line, owner)
            if parsed_state is not None:
                inspect_method()
                member, declaration_state, descriptor, instructions = parsed_member, parsed_state, "", []
                continue
            stripped = line.strip()
            if stripped.startswith("descriptor:") and declaration_state == "method":
                descriptor = stripped.partition(":")[2].strip()
            elif INSTRUCTION_RE.match(line):
                instructions.append(line)
        inspect_method()
    return results


def _bootstrap_links(inventory: dict, targets: set[tuple[str, str, str]], edges: list[dict]) -> list[dict]:
    links = []
    dynamic_edges = {
        (_method_node(edge, "caller"), int(edge.get("instruction_offset") or -1))
        for edge in edges if edge.get("opcode_family") == "invokedynamic"
    }
    for entry, content in inventory["classes"].items():
        owner = _class_binary_name(entry)
        if not any(caller[0] == owner for caller, _offset in dynamic_edges):
            continue
        with tempfile.TemporaryDirectory(prefix="topology-bootstrap-") as temporary:
            class_path = Path(temporary) / "target.class"
            class_path.write_bytes(content)
            completed = subprocess.run(
                ["javap", "-v", "-c", "-p", "-s", str(class_path)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=30,
            )
        if completed.returncode != 0:
            continue
        output = completed.stdout
        dynamic_constants = {
            int(constant): int(bootstrap)
            for constant, bootstrap in re.findall(
                r"^\s*#(\d+)\s+=\s+InvokeDynamic\s+#(\d+):", output, re.MULTILINE
            )
        }
        bootstrap_targets: dict[int, set[tuple[str, str, str]]] = defaultdict(set)
        current_bootstrap = None
        in_bootstraps = False
        for line in output.splitlines():
            if line.strip() == "BootstrapMethods:":
                in_bootstraps = True
                continue
            if not in_bootstraps:
                continue
            header = re.match(r"^\s+(\d+):\s+", line)
            if header:
                current_bootstrap = int(header.group(1))
                continue
            handle = re.search(
                r"REF_\w+\s+([\w/$]+)\.\"?([^\":]+)\"?:(\([^\s]+)", line
            )
            if handle and current_bootstrap is not None:
                target = (
                    handle.group(1).replace("/", "."), handle.group(2), handle.group(3)
                )
                if target in targets:
                    bootstrap_targets[current_bootstrap].add(target)

        caller_member = None
        caller_descriptor = ""
        declaration_state = None
        for line in output.splitlines():
            parsed_member, parsed_state = _parse_member_header(line, owner)
            if parsed_state is not None:
                caller_member = parsed_member
                caller_descriptor = ""
                declaration_state = parsed_state
                continue
            stripped = line.strip()
            if stripped.startswith("descriptor:") and declaration_state == "method":
                caller_descriptor = stripped.partition(":")[2].strip()
                continue
            instruction = INSTRUCTION_RE.match(line)
            if not instruction or instruction.group(2) != "invokedynamic":
                continue
            constant = re.search(r"#(\d+)", instruction.group(3))
            if not constant or not caller_member or not caller_descriptor:
                continue
            caller = (owner, caller_member, caller_descriptor)
            offset = int(instruction.group(1))
            if (caller, offset) not in dynamic_edges:
                continue
            bootstrap = dynamic_constants.get(int(constant.group(1)))
            for target in bootstrap_targets.get(bootstrap, set()):
                links.append({
                    "caller": list(caller), "target": list(target),
                    "bootstrap_index": bootstrap,
                    "evidence_authority": "javap_bootstrap_method_handle",
                })
    return links


def _java_type_descriptor(type_name: str, package: str, imports: dict[str, str]) -> str:
    primitives = {"void": "V", "boolean": "Z", "byte": "B", "char": "C", "short": "S", "int": "I", "long": "J", "float": "F", "double": "D"}
    value = re.sub(r"<.*>", "", type_name.strip()).replace("...", "[]")
    dimensions = 0
    while value.endswith("[]"):
        dimensions += 1
        value = value[:-2]
    if value in primitives:
        descriptor = primitives[value]
    else:
        fqcn = value if "." in value else imports.get(value) or (f"java.lang.{value}" if value in {"String", "Object", "Class"} else f"{package}.{value}")
        descriptor = f"L{fqcn.replace('.', '/')};"
    return "[" * dimensions + descriptor


def _source_attestation_evidence(
    source_root: Path | None, source_attestation: Path | None, artifact_sha256: str
) -> tuple[list[dict], list[dict], dict]:
    if source_root is None or source_attestation is None:
        return [], [], {}
    try:
        attestation_path = Path(source_attestation)
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
        evidence_path = Path(str(attestation.get("evidence_path") or ""))
        if not evidence_path.is_absolute():
            evidence_path = attestation_path.parent / evidence_path
        evidence_bytes = evidence_path.read_bytes()
        evidence_sha = hashlib.sha256(evidence_bytes).hexdigest()
        evidence = json.loads(evidence_bytes.decode("utf-8"))
        revision = str(attestation.get("git_revision") or "")
        tree = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", f"{revision}^{{tree}}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=30,
        )
        source_path = Path(source_root) / str(attestation.get("source_path") or ".")
        source_root_resolved = Path(source_root).resolve()
        source_path_resolved = source_path.resolve()
        source_path_text = str(attestation.get("source_path") or "")
        tracked = subprocess.run(
            ["git", "-C", str(source_root), "ls-tree", "-d", revision, "--", source_path_text],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=30,
        )
        git_entries = subprocess.run(
            ["git", "-C", str(source_root), "ls-tree", "-r", "-z", revision, "--", source_path_text],
            capture_output=True, check=False, timeout=30,
        )
        revision_digest = hashlib.sha256()
        for record in git_entries.stdout.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            fields = metadata.split()
            if not separator or len(fields) < 3 or fields[1] != b"blob":
                raise ValueError("invalid Git source tree entry")
            relative_path = raw_path.decode("utf-8").removeprefix(source_path_text.rstrip("/") + "/")
            if not relative_path or relative_path == raw_path.decode("utf-8"):
                raise ValueError("Git source tree entry escapes declared source path")
            blob = subprocess.run(
                ["git", "-C", str(source_root), "cat-file", "blob", fields[2].decode("ascii")],
                capture_output=True, check=False, timeout=30,
            )
            if blob.returncode != 0:
                raise ValueError("Git source tree blob unreadable")
            revision_digest.update(relative_path.encode() + b"\0" + blob.stdout)
        worktree_diff = subprocess.run(
            ["git", "-C", str(source_root), "diff", "--quiet", revision, "--", source_path_text],
            capture_output=True, check=False, timeout=30,
        )
        index_diff = subprocess.run(
            ["git", "-C", str(source_root), "diff", "--cached", "--quiet", revision, "--", source_path_text],
            capture_output=True, check=False, timeout=30,
        )
        status = subprocess.run(
            ["git", "-C", str(source_root), "status", "--porcelain", "--untracked-files=all", "--", source_path_text],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=30,
        )
        live_digest = compute_source_tree_sha256(source_path_resolved)
        valid = bool(
            attestation.get("authority")
            and "analyzer" not in str(attestation.get("authority")).lower()
            and attestation.get("authority_version")
            and attestation.get("procedure")
            and re.fullmatch(r"[0-9a-f]{40}", revision)
            and tree.returncode == 0
            and tree.stdout.strip() == attestation.get("git_tree")
            and source_path_text not in {"", "."}
            and ".." not in Path(source_path_text).parts
            and source_path_resolved.is_relative_to(source_root_resolved)
            and tracked.returncode == 0 and bool(tracked.stdout.strip())
            and source_path_resolved.is_dir()
            and git_entries.returncode == 0
            and revision_digest.hexdigest() == attestation.get("source_tree_sha256")
            and live_digest == revision_digest.hexdigest()
            and worktree_diff.returncode == 0
            and index_diff.returncode == 0
            and status.returncode == 0 and not status.stdout.strip()
            and attestation.get("artifact_sha256") == artifact_sha256
            and attestation.get("evidence_sha256") == evidence_sha
        )
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return [], [], {"valid": False, "authority": "external_source_attestation"}
    return (
        list(evidence.get("source_edges") or []) if valid else [],
        list(evidence.get("source_conflicts") or []) if valid else [],
        {
            **attestation,
            "computed_evidence_sha256": evidence_sha,
            "computed_git_source_tree_sha256": revision_digest.hexdigest(),
            "computed_live_source_tree_sha256": live_digest,
            "valid": valid,
        },
    )


def extract_artifact_topology_evidence(
    artifact: Path,
    changed_api_rows: list[dict],
    coordinate_entries: dict[str, list[str]],
    *,
    source_root: Path | None = None,
    source_attestation: Path | None = None,
    target_owner_entries: dict[str, list[str]] | None = None,
    hierarchy_scan_timeout_sec: float = HIERARCHY_SCAN_TIMEOUT_SEC,
    hierarchy_scan_max_workers: int = HIERARCHY_SCAN_MAX_WORKERS,
) -> dict:
    artifact = Path(artifact)
    errors = []
    try:
        scan = scan_final_artifact(artifact)
        inventory = _archive_inventory(artifact)
    except (OSError, zipfile.BadZipFile, ValueError) as error:
        scan = {"edges": [], "complete": False, "artifact_sha256": "", "failures": [str(error)]}
        inventory = {"classes": {}, "resources": {}, "containers": set()}
    errors.extend(str(item) for item in scan.get("failures") or [])
    targets, unresolved = _selected_target_identities(changed_api_rows, scan.get("edges") or [])
    errors.extend(f"unresolved exact changed API identity: {item}" for item in unresolved)
    target_set = {_target_identity(item) for item in targets}

    owner_entries: dict[str, set[str]] = defaultdict(set)
    for entry in inventory["classes"]:
        owner_entries[_class_binary_name(entry)].add(entry)
    target_containers = set()
    target_class_entries = set()
    exact_owner_entries = target_owner_entries or {}
    for target in targets:
        coordinate = str(target.get("coordinate") or "")
        allowed = set(coordinate_entries.get(coordinate, []))
        candidates = owner_entries.get(str(target.get("owner") or ""), set())
        nested = {_container(entry) for entry in candidates if _container(entry)}
        explicit = set(exact_owner_entries.get(str(target.get("owner") or ""), []))
        if not candidates:
            errors.append(f"target class absent from final artifact: {target.get('owner')}")
        elif explicit:
            if not explicit.issubset(candidates):
                errors.append(f"exact target owner entry mismatch: {target.get('owner')} expected={sorted(explicit)}")
            else:
                target_class_entries.update(explicit)
                target_containers.update(_container(entry) for entry in explicit if _container(entry))
        elif allowed:
            chosen = nested & allowed
            if not chosen:
                errors.append(
                    f"exact target artifact entry mismatch: {coordinate} expected={sorted(allowed)}"
                )
            target_containers.update(chosen)
            target_class_entries.update(
                entry for entry in candidates if _container(entry) in chosen
            )
        else:
            errors.append(
                f"ambiguous target artifact entries without exact owner mapping: "
                f"{target.get('owner')} entries={sorted(candidates)}"
            )
    for owner, entries in exact_owner_entries.items():
        candidates = owner_entries.get(owner, set())
        explicit = set(entries)
        if explicit.issubset(candidates):
            target_class_entries.update(explicit)
    entry_layout = []
    for container in sorted(inventory["containers"]):
        coordinate = next((coord for coord, entries in coordinate_entries.items() if container in entries), "")
        role = "target" if container in target_containers else "dependency"
        entry_layout.append({
            "prefix": f"{container}!/", "role": role,
            "coordinate": coordinate, "module": Path(container).stem,
        })
    for entry in sorted(inventory["classes"]):
        if not _container(entry):
            root_role = "target" if entry in target_class_entries else "business"
            root_coordinate = next((str(item.get("coordinate") or "") for item in targets if str(item.get("owner") or "") == _class_binary_name(entry)), "") if root_role == "target" else "__business__"
            entry_layout.append({"entry": entry, "role": root_role, "coordinate": root_coordinate})

    hierarchy_scan = _scan_class_hierarchy(
        inventory,
        timeout_sec=hierarchy_scan_timeout_sec,
        max_workers=hierarchy_scan_max_workers,
    )
    hierarchy = hierarchy_scan["relations"]
    errors.extend(hierarchy_scan["errors"])
    registrations = _resource_evidence(
        inventory, target_set, target_class_entries,
        scan.get("edges") or [], hierarchy,
    )
    reflection = _reflection_evidence(inventory, target_set, scan.get("edges") or [])
    bootstrap = _bootstrap_links(inventory, target_set, scan.get("edges") or [])
    source_edges, source_conflicts, verified_source_provenance = _source_attestation_evidence(
        source_root, source_attestation, str(scan.get("artifact_sha256") or ""),
    )
    layout = {
        "authority": "final_artifact_edge_oracle",
        "complete": bool(scan.get("complete") and not errors),
        "artifact_sha256": scan.get("artifact_sha256") or "",
        "entry_layout": entry_layout,
        "target_apis": targets,
        "registrations": registrations,
        "reflection_target_links": reflection,
        "bootstrap_target_links": bootstrap,
        "hierarchy_evidence": hierarchy,
        "hierarchy_scan": hierarchy_scan["metrics"],
        "source_edges": source_edges,
        "source_conflicts": source_conflicts,
        "source_provenance": verified_source_provenance,
        "errors": errors,
    }
    return {"complete": layout["complete"], "errors": errors, "edges": scan.get("edges") or [], "artifact_layout": layout}


def classify_topologies(edges: list[dict], artifact_layout: dict) -> set[str]:
    if artifact_layout.get("authority") != "final_artifact_edge_oracle" or artifact_layout.get("complete") is not True:
        return set()
    observed: set[str] = set()
    edge_identities = {_edge_identity(edge) for edge in edges}
    targets = {_target_identity(item) for item in artifact_layout.get("target_apis") or []}
    target_edges = [edge for edge in edges if _method_node(edge, "callee") in targets]
    target_coordinates = {
        str(item.get("coordinate") or "") for item in artifact_layout.get("entry_layout") or []
        if item.get("role") == "target"
    }
    incoming = defaultdict(set)
    caller_roles = defaultdict(set)
    for edge in edges:
        caller = _method_node(edge, "caller")
        caller_roles[caller].add(str(_entry_metadata(str(edge.get("artifact_entry") or ""), artifact_layout).get("role") or ""))
        if edge.get("opcode_family") in INVOKE_OPCODES:
            incoming[_method_node(edge, "callee")].add(caller)
    same_coord, same_jar, cross_jar = [], [], []
    for edge in target_edges:
        metadata = _entry_metadata(str(edge.get("artifact_entry") or ""), artifact_layout)
        role = metadata.get("role")
        coordinate = str(metadata.get("coordinate") or "")
        if role == "business":
            observed.add("business_direct")
        elif role == "target":
            same_jar.append(edge)
            observed.add("same_jar_bridge")
        elif role == "dependency" and coordinate and coordinate in target_coordinates:
            same_coord.append(edge)
            observed.add("same_coord_multimodule")
        elif role == "dependency":
            cross_jar.append(edge)
            observed.add("cross_jar_bridge")
    if any(_business_reaches(_method_node(edge, "caller"), incoming, caller_roles) for edge in same_jar + same_coord):
        observed.add("business_to_same_jar_bridge")
    if any(_business_reaches(_method_node(edge, "caller"), incoming, caller_roles) for edge in cross_jar):
        observed.add("business_to_cross_jar_bridge")
    overloads = defaultdict(set)
    for owner, member, descriptor in targets:
        overloads[(owner, member)].add(descriptor)
    if any(len(overloads[_method_node(edge, "callee")[:2]]) > 1 for edge in target_edges):
        observed.add("overloaded_method")
    if any(edge.get("callee_member") == "<init>" and edge.get("opcode_family") == "invokespecial" for edge in target_edges):
        observed.add("constructor")
    if any(edge.get("opcode_family") == "invokeinterface" for edge in target_edges):
        observed.add("interface_dispatch")
    hierarchy = artifact_layout.get("hierarchy_evidence") or []
    if any(
        edge.get("opcode_family") == "invokevirtual"
        and any(
            item.get("authority") == "javap_class_header"
            and item.get("parent") == edge.get("callee_owner")
            and item.get("child") != item.get("parent")
            and _entry_metadata(str(item.get("parent_entry") or ""), artifact_layout).get("role") == "target"
            and _entry_scope(str(item.get("child_entry") or "")) == _entry_scope(str(item.get("parent_entry") or ""))
            for item in hierarchy
        )
        for edge in target_edges
    ):
        observed.add("virtual_dispatch")
    if any(edge.get("opcode_family") == "invokestatic" for edge in target_edges):
        observed.add("static_dispatch")
    if any(edge.get("opcode_family") in FIELD_OPCODES for edge in target_edges):
        observed.add("field_access")
    dynamic_callers = {_method_node(edge, "caller") for edge in edges if edge.get("opcode_family") == "invokedynamic"}
    if any(
        tuple(item.get("caller") or []) in dynamic_callers
        and tuple(item.get("target") or []) in targets
        and item.get("evidence_authority") == "javap_bootstrap_method_handle"
        for item in artifact_layout.get("bootstrap_target_links") or []
    ):
        observed.add("invokedynamic")
    reflection_registrations = {
        tuple(item.get("target") or []) for item in artifact_layout.get("registrations") or []
        if _authoritative_runtime_registration(
            item, "reflection", REFLECTION_REGISTRATION_RESOURCE, targets
        )
    }
    unambiguous_reflection_targets = {
        target for target in reflection_registrations
        if sum(1 for candidate in targets if candidate[:2] == target[:2]) == 1
    }
    if any(
        item.get("evidence_authority") == "bounded_jvm_instruction_dataflow"
        and tuple(item.get("target") or []) in unambiguous_reflection_targets
        for item in artifact_layout.get("reflection_target_links") or []
    ):
        observed.add("reflection")
    for item in artifact_layout.get("registrations") or []:
        if item.get("kind") == "spi" and item.get("evidence_authority") == "parsed_service_resource":
            observed.add("spi")
        if _authoritative_runtime_registration(
            item, "framework_proxy", FRAMEWORK_PROXY_REGISTRATION_RESOURCE, targets
        ):
            observed.add("framework_proxy")
    provenance = artifact_layout.get("source_provenance") or {}
    source_valid = bool(
        provenance.get("authority")
        and "analyzer" not in str(provenance.get("authority")).lower()
        and provenance.get("valid") is True
        and re.fullmatch(r"[0-9a-f]{40}", str(provenance.get("git_revision") or ""))
        and provenance.get("artifact_sha256") == artifact_layout.get("artifact_sha256")
        and provenance.get("evidence_sha256") == provenance.get("computed_evidence_sha256")
    )
    if source_valid:
        source_edges = {_edge_identity(item) for item in artifact_layout.get("source_edges") or []}
        if source_edges & edge_identities:
            observed.add("source_bytecode_agree")
        if any(
            item.get("evidence_authority")
            and "analyzer" not in str(item.get("evidence_authority")).lower()
            and item.get("normalization_checked") is True
            and _edge_identity(item.get("bytecode_edge") or {}) in edge_identities
            and _edge_identity(item.get("source_edge") or {}) not in edge_identities
            for item in artifact_layout.get("source_conflicts") or []
        ):
            observed.add("source_bytecode_true_conflict")
    return observed & STABLE_TOPOLOGY_IDS


def compute_topology_coverage(
    required: tuple[str, ...],
    observed: set[str],
    *,
    prior_covered: set[str] | None = None,
    case_mode: str = "guard",
    evidence_complete: bool = True,
) -> dict:
    required_set = set(required)
    observed_set = set(observed)
    prior_set = set(prior_covered or set())
    missing = sorted(required_set - observed_set)
    newly_observed = sorted(observed_set - prior_set)
    eligible_mode = case_mode in {"discovery", "convergence"}
    return {
        "required": sorted(required_set), "observed": sorted(observed_set),
        "missing": missing, "complete": bool(evidence_complete and not missing),
        "evidence_complete": bool(evidence_complete),
        "prior_covered": sorted(prior_set), "newly_observed": newly_observed,
        "discovery_target_eligible": bool(eligible_mode and newly_observed),
        "rotation_required": bool(eligible_mode and not newly_observed),
    }
