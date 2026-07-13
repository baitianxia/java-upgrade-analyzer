#!/usr/bin/env python3
"""Generate positive third-party oracle records from JDK javap bytecode output."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
import subprocess
from pathlib import Path


CALL_RE = re.compile(
    r"//\s+(?:InterfaceMethod|Method)\s+([\w/$]+)\.\"?([^\":]+)\"?:(\([^)]*\)).*"
)
PRIMITIVES = {
    "boolean": "Z", "byte": "B", "char": "C", "short": "S",
    "int": "I", "long": "J", "float": "F", "double": "D",
}
JAVA_LANG = {
    "Boolean", "Byte", "Character", "Short", "Integer", "Long", "Float",
    "Double", "String", "Object", "Class", "Throwable", "Exception",
}
DESCRIPTOR_PRIMITIVES = {value: key for key, value in PRIMITIVES.items()}


def _descriptor_type(descriptor: str, offset: int) -> tuple[str, int]:
    dimensions = 0
    while descriptor[offset] == "[":
        dimensions += 1
        offset += 1
    code = descriptor[offset]
    if code in DESCRIPTOR_PRIMITIVES:
        value = DESCRIPTOR_PRIMITIVES[code]
        offset += 1
    elif code == "L":
        end = descriptor.index(";", offset)
        value = descriptor[offset + 1:end].replace("/", ".")
        offset = end + 1
    else:
        raise ValueError(f"unsupported JVM descriptor: {descriptor}")
    return value + "[]" * dimensions, offset


def _source_signature(parameter_descriptor: str) -> str:
    offset = 1
    parameters = []
    while parameter_descriptor[offset] != ")":
        value, offset = _descriptor_type(parameter_descriptor, offset)
        parameters.append(value)
    return "(" + ",".join(parameters) + ")"


def discover_calls(
    class_files: list[Path],
    owner_prefixes: tuple[str, ...],
    coord: str,
    evidence_dir: Path,
) -> list[dict]:
    """Enumerate every distinct dependency method called by production bytecode."""
    if not class_files:
        raise ValueError("no production class files available for bytecode discovery")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / "jdk_javap_discovered_calls.txt"
    discovered: dict[tuple[str, str, str], dict] = {}
    with evidence_path.open("w", encoding="utf-8") as evidence:
        for class_file in class_files:
            completed = subprocess.run(
                ["javap", "-c", "-s", "-p", str(class_file)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            evidence.write(f"===== {class_file} =====\n")
            evidence.write(completed.stdout)
            if completed.stderr:
                evidence.write(completed.stderr)
            if completed.returncode != 0:
                raise RuntimeError(f"javap failed for {class_file}: {completed.stderr.strip()}")
            caller_match = re.search(r"(?:class|interface|enum)\s+([\w.$]+)", completed.stdout)
            caller = caller_match.group(1) if caller_match else class_file.stem
            for owner, member, descriptor in CALL_RE.findall(completed.stdout):
                if not owner.startswith(owner_prefixes):
                    continue
                key = owner, member, descriptor
                discovered.setdefault(key, {
                    "coord": coord,
                    "api_name": f"{owner.replace('/', '.')}.{member}",
                    "api_signature": _source_signature(descriptor),
                    "symbol_kind": "constructor" if member == "<init>" else "method",
                    "oracle_conclusion": "reachable",
                    "caller_class": caller,
                })

    digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    version = subprocess.run(
        ["javap", "-version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
    ).stdout.strip()
    generated_at = datetime.now(timezone.utc).isoformat()
    for row in discovered.values():
        row.update({
            "authority": "jdk-javap",
            "authority_version": version,
            "procedure": "javap -c -s -p <class-file>; enumerate exact dependency calls",
            "evidence_path": str(evidence_path),
            "evidence_sha256": digest,
            "generated_at": generated_at,
            "evidence_mode": "bytecode",
        })
    return sorted(discovered.values(), key=lambda row: (
        row["api_name"], row["symbol_kind"], row["api_signature"]
    ))


def _split_parameters(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in text:
        if char == "<":
            depth += 1
        elif char == ">":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return [part for part in parts if part]


def _erase_generics(text: str) -> str:
    output: list[str] = []
    depth = 0
    for char in text:
        if char == "<":
            depth += 1
        elif char == ">":
            depth = max(0, depth - 1)
        elif depth == 0:
            output.append(char)
    return "".join(output)


def _type_descriptor(type_name: str, owner_package: str) -> str | None:
    value = _erase_generics(type_name.strip()).replace("? extends ", "").replace("? super ", "")
    dimensions = 0
    if value.endswith("..."):
        dimensions += 1
        value = value[:-3]
    while value.endswith("[]"):
        dimensions += 1
        value = value[:-2]
    value = value.strip()
    if value in PRIMITIVES:
        descriptor = PRIMITIVES[value]
    elif value in JAVA_LANG:
        descriptor = f"Ljava/lang/{value};"
    elif "." in value:
        descriptor = f"L{value.replace('.', '/')};"
    elif re.fullmatch(r"[A-Z]", value) or value in {"?", ""}:
        return None
    else:
        descriptor = f"L{owner_package.replace('.', '/')}/{value};"
    return "[" * dimensions + descriptor


def parameter_descriptor(row: dict) -> str | None:
    signature = str(row.get("api_signature") or "").strip()
    if not signature.startswith("(") or ")" not in signature:
        return None
    api_name = str(row.get("api_name") or row.get("api") or "")
    owner = api_name.rsplit(".", 1)[0]
    owner_package = owner.rsplit(".", 1)[0] if "." in owner else ""
    descriptors = []
    for parameter in _split_parameters(signature[1:signature.rfind(")")]):
        descriptor = _type_descriptor(parameter, owner_package)
        if descriptor is None:
            return None
        descriptors.append(descriptor)
    return "(" + "".join(descriptors) + ")"


def _target_key(row: dict) -> tuple[str, str, str] | None:
    api_name = str(row.get("api_name") or row.get("api") or "")
    if "." not in api_name:
        return None
    owner, member = api_name.rsplit(".", 1)
    if str(row.get("symbol_kind") or "") == "constructor":
        member = "<init>"
        owner = owner.rsplit(".", 1)[0] if owner.rsplit(".", 1)[-1] == api_name.rsplit(".", 1)[-1] else owner
    descriptor = parameter_descriptor(row)
    if descriptor is None:
        return None
    return owner.replace(".", "/"), member, descriptor


def scan_class_files(changed_rows: list[dict], class_files: list[Path], evidence_dir: Path) -> list[dict]:
    targets: dict[tuple[str, str, str], list[dict]] = {}
    for row in changed_rows:
        if str(row.get("symbol_kind") or "") not in {"method", "constructor"}:
            continue
        key = _target_key(row)
        if key is not None:
            targets.setdefault(key, []).append(row)

    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / "jdk_javap_calls.txt"
    matched: dict[tuple[str, str, str], dict] = {}
    with evidence_path.open("w", encoding="utf-8") as evidence:
        for offset in range(0, len(class_files), 100):
            batch = class_files[offset:offset + 100]
            completed = subprocess.run(
                ["javap", "-c", "-s", "-p", *(str(path) for path in batch)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
            )
            evidence.write(f"===== batch {offset // 100 + 1}: {len(batch)} class files =====\n")
            evidence.write(completed.stdout)
            if completed.stderr:
                evidence.write(completed.stderr)
            for owner, member, descriptor in CALL_RE.findall(completed.stdout):
                key = (owner, member, descriptor)
                if key in targets:
                    matched[key] = targets[key][0]

    digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    version = subprocess.run(
        ["javap", "-version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
    ).stdout.strip()
    generated_at = datetime.now(timezone.utc).isoformat()
    records = []
    for row in matched.values():
        records.append({
            **{key: str(row.get(key) or "") for key in ("coord", "api_name", "api_signature", "symbol_kind")},
            "oracle_conclusion": "reachable",
            "authority": "jdk-javap",
            "authority_version": version,
            "procedure": "javap -c -s -p <class-file>; exact owner/member/JVM parameter descriptor",
            "evidence_path": str(evidence_path),
            "evidence_sha256": digest,
            "generated_at": generated_at,
            "evidence_mode": "bytecode",
        })
    return sorted(records, key=lambda row: (
        row["api_name"], row["symbol_kind"], row["api_signature"]
    ))
