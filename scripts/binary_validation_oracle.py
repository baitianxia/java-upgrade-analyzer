#!/usr/bin/env python3
"""Independent validation of a completed binary generation.

The validator consumes raw artifacts, target-JDK observations and immutable
generation sidecars.  It does not call the production ASM parser, provider
resolver, member resolver, dispatch resolver, decision engine or tracer.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, urlparse
import zipfile

from binary_first_contract import BinaryFirstContractError, canonical_identity
from path_runtime import short_temporary_directory
from final_artifact_edge_oracle import scan_final_artifact


ORACLE_SOURCE = Path(__file__).with_name("java") / "RuntimeOutcomeOracle.java"
SUPPORT_MANIFEST = Path(__file__).with_name("binary_first_support_manifest.json")
POLICY_VERSION = "binary-independent-validation-v1"


_ORACLE_METHOD_ENTRY_KINDS = {
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

_ORACLE_INTERFACE_CALLBACKS = {
    "org/springframework/boot/ApplicationRunner": {"run": "spring_application_runner"},
    "org/springframework/boot/CommandLineRunner": {"run": "spring_command_line_runner"},
    "org/springframework/context/ApplicationListener": {
        "onApplicationEvent": "spring_application_listener"
    },
    "org/springframework/context/Lifecycle": {
        "start": "spring_lifecycle_callback", "stop": "spring_lifecycle_callback",
    },
    "org/springframework/context/SmartLifecycle": {
        "start": "spring_lifecycle_callback", "stop": "spring_lifecycle_callback",
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
        "parse": "spring_conversion_callback", "print": "spring_conversion_callback",
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
    "org/quartz/Job": {"execute": "quartz_job"},
}

_ORACLE_CLASS_TRIGGER_KINDS = {
    "Lorg/apache/rocketmq/spring/annotation/RocketMQMessageListener;": (
        "spring_message_listener", {"onMessage"},
    ),
    "Lorg/springframework/amqp/rabbit/annotation/RabbitListener;": (
        "spring_message_listener", {"handleMessage", "onMessage"},
    ),
}

_ORACLE_SPRING_FACTORIES_CALLBACKS = {
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


class BinaryValidationError(BinaryFirstContractError):
    pass


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryValidationError("BINARY_VALIDATION_JSON_INVALID", str(error)) from error
    if not isinstance(value, dict):
        raise BinaryValidationError("BINARY_VALIDATION_JSON_INVALID", str(path))
    return value


def _release_major(jdk_home: Path) -> int:
    release = {}
    try:
        for line in (jdk_home / "release").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                release[key] = value.strip().strip('"')
    except OSError as error:
        raise BinaryValidationError("BINARY_ORACLE_JDK_RELEASE_MISSING", str(error)) from error
    version = release.get("JAVA_VERSION", "")
    match = re.match(r"(?:1\.)?(\d+)", version)
    if not match:
        raise BinaryValidationError("BINARY_ORACLE_JDK_VERSION_INVALID", version)
    return int(match.group(1))


def _manifest_multi_release(archive: zipfile.ZipFile) -> bool:
    matches = [
        info for info in archive.infolist()
        if not info.is_dir() and info.filename.upper() == "META-INF/MANIFEST.MF"
    ]
    if len(matches) != 1:
        return False
    text = archive.read(matches[0]).decode("utf-8", errors="replace")
    unfolded = []
    for line in text.splitlines():
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    return any(
        key.strip().lower() == "multi-release" and value.strip().lower() == "true"
        for line in unfolded
        for key, separator, value in [line.partition(":")]
        if separator
    )


def _archive_inventory(path: Path, target_major: int) -> dict[str, Any]:
    classes: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
    resources: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with zipfile.ZipFile(path) as archive:
        mr = _manifest_multi_release(archive)
        for ordinal, info in enumerate(archive.infolist()):
            if info.is_dir():
                continue
            content = archive.read(info)
            match = re.match(r"META-INF/versions/(\d+)/(.+\.class)$", info.filename)
            if match:
                version, logical = int(match.group(1)), match.group(2)
                classes[logical.removesuffix(".class")][version].append(info.filename)
            elif info.filename.endswith(".class") and not info.filename.startswith("META-INF/"):
                classes[info.filename.removesuffix(".class")][0].append(info.filename)
            else:
                resources[info.filename].append({
                    "ordinal": ordinal,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "semantic_digest": _independent_resource_digest(info.filename, content),
                    "semantic_facts": _independent_resource_facts(info.filename, content),
                })
        selected = {}
        failures = []
        for name, versions in classes.items():
            eligible = [
                version for version in versions
                if version == 0 or (mr and version <= target_major)
            ]
            if not eligible:
                continue
            version = max(eligible)
            if len(versions[version]) != 1:
                failures.append(f"duplicate_class:{name}:{version}")
                continue
            selected[name] = versions[version][0]
    return {
        "classes": selected,
        "resources": dict(resources),
        "failures": failures,
        "multi_release": mr,
    }


def _independent_resource_category(name: str) -> str:
    upper = name.upper()
    if name.startswith("META-INF/services/") or name == "META-INF/spring.factories" or (
        name.startswith("META-INF/spring/") and name.endswith(".imports")
    ):
        return "runtime_topology"
    if re.fullmatch(r"META-INF/[^/]+\.(?:SF|RSA|DSA|EC)", upper):
        return "operational_security"
    if upper == "META-INF/MANIFEST.MF":
        return "distribution_metadata"
    if re.fullmatch(r"META-INF/maven/[^/]+/[^/]+/pom\.(?:properties|xml)", name):
        return "build_metadata"
    if name.lower().endswith((".so", ".dll", ".dylib", ".jnilib")):
        return "runtime_native"
    return "unknown"


def _independent_resource_digest(name: str, content: bytes) -> str:
    category = _independent_resource_category(name)
    if category != "runtime_topology":
        return hashlib.sha256(content).hexdigest()
    lines = []
    for raw in content.decode("utf-8", errors="replace").splitlines():
        value = raw.split("#", 1)[0].strip()
        if value:
            lines.append(value)
    return hashlib.sha256(
        json.dumps(lines, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _independent_resource_facts(name: str, content: bytes) -> list[list[str]]:
    if name.upper() == "META-INF/MANIFEST.MF":
        text = content.decode("utf-8", errors="replace").replace(
            "\r\n", "\n"
        ).replace("\r", "\n")
        unfolded = []
        for line in text.split("\n"):
            if line.startswith(" ") and unfolded:
                unfolded[-1] += line[1:]
            else:
                unfolded.append(line)
        return [
            [key.strip().lower(), value.strip()]
            for line in unfolded
            for key, separator, value in [line.partition(":")]
            if separator
        ]
    if name == "META-INF/spring.factories":
        text = content.decode("iso-8859-1").replace("\r\n", "\n").replace("\r", "\n")
        logical = []
        pending = ""
        for physical in text.split("\n"):
            combined = pending + (physical.lstrip() if pending else physical)
            trailing = len(combined) - len(combined.rstrip("\\"))
            if trailing % 2:
                pending = combined[:-1]
            else:
                logical.append(combined)
                pending = ""
        if pending:
            logical.append(pending)
        facts = []
        for raw in logical:
            stripped = raw.strip()
            if not stripped or stripped.startswith(("#", "!")):
                continue
            separator = next(
                (index for index, item in enumerate(stripped) if item in "=:"),
                -1,
            )
            if separator < 0:
                continue
            key = stripped[:separator].strip()
            for entry in stripped[separator + 1:].split(","):
                if entry.strip():
                    facts.append([f"property_entry:{key}", entry.strip()])
        return facts
    if not (
        name.startswith("META-INF/services/")
        or (name.startswith("META-INF/spring/") and name.endswith(".imports"))
    ):
        return []
    return [
        ["ordered_entry", value]
        for raw in content.decode("utf-8", errors="replace").splitlines()
        for value in [raw.split("#", 1)[0].strip()]
        if value
    ]


def _artifact_configs(side: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = []
    seen_slots = set()
    for raw in side.get("artifacts") or ():
        item = dict(raw)
        path = Path(str(item.get("path") or "")).expanduser().resolve()
        if not path.is_file():
            raise BinaryValidationError("BINARY_ORACLE_ARTIFACT_MISSING", str(path))
        key = (str(item.get("loader_realm") or ""), int(item.get("slot")))
        if key in seen_slots:
            raise BinaryValidationError("BINARY_ORACLE_RUNTIME_SLOT_DUPLICATE", str(key))
        seen_slots.add(key)
        item["path"] = str(path)
        item["sha256"] = _sha256_file(path)
        result.append(item)
    return sorted(result, key=lambda item: (str(item.get("loader_realm")), int(item.get("slot"))))


def _compile_oracle(jdk_home: Path, destination: Path) -> str:
    destination.mkdir(parents=True, exist_ok=True)
    javac = jdk_home / "bin" / ("javac.exe" if (jdk_home / "bin" / "javac.exe").exists() else "javac")
    completed = subprocess.run(
        [str(javac), "-encoding", "UTF-8", "-source", "8", "-target", "8", "-d", str(destination), str(ORACLE_SOURCE)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise BinaryValidationError(
            "BINARY_ORACLE_COMPILE_FAILED", (completed.stderr or completed.stdout).strip()
        )
    return _identity("runtime_outcome_oracle_helper_identity", {
        "source_sha256": _sha256_file(ORACLE_SOURCE),
        "target_jdk_release_sha256": _sha256_file(jdk_home / "release"),
        "policy_version": POLICY_VERSION,
    })


def _observe_classes(
    jdk_home: Path,
    artifacts: list[dict[str, Any]],
    initial_classes: Iterable[str],
) -> tuple[dict[str, dict[str, Any]], str]:
    with short_temporary_directory(prefix="runtime-oracle") as temp_text:
        temp = Path(temp_text)
        helper_identity = _compile_oracle(jdk_home, temp / "helper")
        classpath_file = temp / "classpath.txt"
        classpath_file.write_text(
            "\n".join(item["path"] for item in artifacts) + "\n", encoding="utf-8"
        )
        observations: dict[str, dict[str, Any]] = {}
        pending = {str(item).replace("/", ".") for item in initial_classes if item}
        java = jdk_home / "bin" / ("java.exe" if (jdk_home / "bin" / "java.exe").exists() else "java")
        rounds = 0
        while pending:
            rounds += 1
            if rounds > 64:
                raise BinaryValidationError("BINARY_ORACLE_FIXED_POINT_LIMIT", str(len(pending)))
            batch = sorted(pending)
            pending.clear()
            classes_file = temp / f"classes-{rounds}.txt"
            classes_file.write_text("\n".join(batch) + "\n", encoding="utf-8")
            completed = subprocess.run(
                [
                    str(java), "-Xverify:all", "-cp", str(temp / "helper"),
                    "RuntimeOutcomeOracle", str(classpath_file), str(classes_file),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=300,
            )
            if completed.returncode != 0:
                raise BinaryValidationError(
                    "BINARY_ORACLE_EXECUTION_FAILED", (completed.stderr or completed.stdout).strip()
                )
            for line in completed.stdout.splitlines():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    raise BinaryValidationError("BINARY_ORACLE_OUTPUT_INVALID", line[:200]) from error
                name = str(row.get("class_name") or "")
                observations[name] = row
                if row.get("status") == "definition_ready":
                    for dependency in [row.get("super_name"), *(row.get("interfaces") or ())]:
                        if dependency and dependency not in observations:
                            pending.add(str(dependency).replace("/", "."))
        return observations, helper_identity


def _file_url_path(value: str) -> Path | None:
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.scheme != "file":
        return None
    return Path(unquote(parsed.path)).resolve()


def _opcode_name(value: int) -> str:
    return {
        178: "getstatic", 179: "putstatic", 180: "getfield", 181: "putfield",
        182: "invokevirtual", 183: "invokespecial", 184: "invokestatic",
        185: "invokeinterface",
    }.get(int(value), f"opcode-{value}")


_ORACLE_CLASS_DECLARATION = re.compile(
    r"^(?:[\w$]+\s+)*(?:class|interface|enum|record)\s+([\w.$]+)"
)
_ORACLE_MEMBER_HEADER = re.compile(r"^ {2}(?! )(.+);\s*$")
_ORACLE_INSTRUCTION = re.compile(r"^\s*(\d+):\s+([a-z][a-z0-9_]*)\b(.*)$")


def _parse_javap_structural(output: str) -> dict[str, Any]:
    owner = ""
    member_name = ""
    descriptor = ""
    pending_member = ""
    type_edges = set()
    init_edges = set()
    clinit_classes = set()
    for line in output.splitlines():
        declaration = _ORACLE_CLASS_DECLARATION.match(line)
        if declaration:
            owner = declaration.group(1).replace(".", "/")
            continue
        header = _ORACLE_MEMBER_HEADER.match(line)
        if header and owner:
            value = header.group(1).strip()
            if value == "static {}":
                member_name = "<clinit>"
                descriptor = "()V"
                clinit_classes.add(owner)
                pending_member = ""
            elif "(" in value:
                before = value.split("(", 1)[0].split()[-1].strip('"')
                simple = owner.rsplit("/", 1)[-1]
                member_name = "<init>" if before in {simple, owner.replace("/", ".")} else before
                descriptor = ""
                pending_member = member_name
            else:
                pending_member = ""
            continue
        stripped = line.strip()
        if stripped.startswith("descriptor:") and pending_member:
            descriptor = stripped.split(":", 1)[1].strip()
            member_name = pending_member
            pending_member = ""
            continue
        instruction = _ORACLE_INSTRUCTION.match(line)
        if not instruction or not owner or not member_name or not descriptor:
            continue
        bci = int(instruction.group(1))
        opcode = instruction.group(2)
        rest = instruction.group(3)
        comment = rest.split("//", 1)[1].strip() if "//" in rest else ""
        target = ""
        class_match = re.match(r"class\s+\"?([^\"\s]+)\"?", comment)
        if class_match:
            target = class_match.group(1)
            while target.startswith("["):
                target = target[1:]
            if target.startswith("L") and target.endswith(";"):
                target = target[1:-1]
        if opcode in {"new", "anewarray", "checkcast", "instanceof", "multianewarray"}:
            if target:
                type_edges.add((owner, member_name, descriptor, bci, target, opcode))
        elif opcode in {"ldc", "ldc_w"} and target:
            type_edges.add((owner, member_name, descriptor, bci, target, "class_literal"))
        if opcode in {"invokestatic", "getstatic", "putstatic"}:
            reference = re.match(
                r"(?:InterfaceMethod|Method|Field)\s+(?:(?P<owner>[\w/$]+)\.)?",
                comment,
            )
            target_owner = (reference.group("owner") if reference else None) or owner
            init_edges.add((owner, member_name, descriptor, bci, target_owner, opcode))
        elif opcode == "new" and target:
            init_edges.add((owner, member_name, descriptor, bci, target, "new"))
    return {
        "type_edges": type_edges,
        "class_init_edges": init_edges,
        "clinit_classes": clinit_classes,
    }


def _scan_structural_edges(
    artifact: Path, inventory: Mapping[str, Any], javap: str
) -> dict[str, Any]:
    combined = {"type_edges": set(), "class_init_edges": set(), "clinit_classes": set()}
    failures = []
    with short_temporary_directory(prefix="structural-oracle") as temp_text:
        temp = Path(temp_text)
        try:
            archive = zipfile.ZipFile(artifact)
        except (OSError, zipfile.BadZipFile) as error:
            return {**combined, "failures": [str(error)]}
        with archive:
            for index, (class_name, entry) in enumerate(sorted(inventory["classes"].items())):
                class_path = temp / f"class-{index:06d}.class"
                class_path.write_bytes(archive.read(entry))
                completed = subprocess.run(
                    [javap, "-c", "-p", "-s", str(class_path)],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                    timeout=30,
                )
                if completed.returncode != 0:
                    failures.append(
                        f"{entry}:{(completed.stderr or completed.stdout).strip()}"
                    )
                    continue
                parsed = _parse_javap_structural(completed.stdout)
                for key in combined:
                    combined[key].update(parsed[key])
    return {**combined, "failures": failures}


def _validate_structural_edges(
    connection: sqlite3.Connection,
    artifacts: list[dict[str, Any]],
    inventories: list[dict[str, Any]],
    *,
    javap: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues = []
    artifact_instances = _rows(connection, "artifact_instances")
    instance_by_sha_slot = {
        (row["content_sha256"], int(row["runtime_classpath_index"])): row
        for row in artifact_instances
    }
    members = {row["member_identity"]: row for row in _rows(connection, "members")}
    production_type = defaultdict(set)
    production_init = defaultdict(set)
    for edge in _rows(connection, "direct_edges"):
        caller = members[edge["caller_member_identity"]]
        common = (
            caller["class_name"], caller["member_name"], caller["descriptor"],
            int(edge["bytecode_offset"]), edge["symbolic_owner"],
        )
        payload = json.loads(edge["edge_json"])
        if edge["edge_kind"] == "type":
            production_type[edge["caller_artifact_instance_identity"]].add(
                (*common, str(payload.get("type_use_kind") or "type_instruction"))
            )
        elif edge["edge_kind"] == "class_init":
            production_init[edge["caller_artifact_instance_identity"]].add(
                (*common, str(payload.get("trigger_kind") or ""))
            )
    truth_type = []
    truth_init = []
    clinit_classes = set()
    opcode_to_type_use = {
        "new": "new", "anewarray": "anewarray", "checkcast": "checkcast",
        "instanceof": "instanceof", "multianewarray": "multianewarray",
        "class_literal": "class_literal",
    }
    for artifact, inventory in zip(artifacts, inventories):
        instance = instance_by_sha_slot.get((artifact["sha256"], int(artifact["slot"])))
        if not instance:
            continue
        scanned = _scan_structural_edges(Path(artifact["path"]), inventory, javap)
        if scanned["failures"]:
            issues.append(_validation_issue(
                "type_class_init", "ORACLE_STRUCTURAL_SCAN_INCOMPLETE",
                artifact=artifact["path"], failures=scanned["failures"],
            ))
            continue
        truth_t = {
            (*item[:5], opcode_to_type_use[item[5]]) for item in scanned["type_edges"]
        }
        truth_i = set(scanned["class_init_edges"])
        # Production names the trigger, not the opcode mnemonic, identically for
        # the supported active-use opcodes.
        actual_t = production_type.get(instance["artifact_instance_identity"], set())
        actual_i = production_init.get(instance["artifact_instance_identity"], set())
        for missing in sorted(truth_t - actual_t):
            issues.append(_validation_issue("type_class_init", "ORACLE_TYPE_EDGE_MISSING", edge=missing))
        for extra in sorted(actual_t - truth_t):
            issues.append(_validation_issue("type_class_init", "ORACLE_TYPE_EDGE_EXTRA", edge=extra))
        for missing in sorted(truth_i - actual_i):
            issues.append(_validation_issue("type_class_init", "ORACLE_CLASS_INIT_EDGE_MISSING", edge=missing))
        for extra in sorted(actual_i - truth_i):
            issues.append(_validation_issue("type_class_init", "ORACLE_CLASS_INIT_EDGE_EXTRA", edge=extra))
        truth_type.extend(sorted(truth_t))
        truth_init.extend(sorted(truth_i))
        clinit_classes.update(scanned["clinit_classes"])
    return issues, {
        "type_edges": truth_type,
        "class_init_edges": truth_init,
        "clinit_classes": sorted(clinit_classes),
    }


def _rows(connection: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(f"SELECT * FROM {table}")]


def _reconciliation(connection: sqlite3.Connection, kind: str) -> list[dict[str, Any]]:
    return [
        json.loads(row["payload_json"])
        for row in _rows(connection, "reconciliation_records")
        if row["record_kind"] == kind
    ]


def _member_tuple(value: str) -> tuple[str, str, str, int]:
    kind, name, descriptor, flags = value.split("|", 3)
    return kind, name, descriptor, int(flags)


def _declared_members(observation: Mapping[str, Any]) -> list[tuple[str, str, str, int]]:
    return [_member_tuple(value) for value in observation.get("members") or ()]


def _resolve_member(
    observations: Mapping[str, Mapping[str, Any]],
    owner: str,
    kind: str,
    name: str,
    descriptor: str,
    visited: frozenset[str] = frozenset(),
) -> tuple[str, tuple[str, str, str, int]] | None:
    if owner in visited:
        return None
    observation = observations.get(owner)
    if not observation or observation.get("status") != "definition_ready":
        return None
    for member in _declared_members(observation):
        if member[:3] == (kind, name, descriptor):
            return owner, member
    if name == "<init>":
        return None
    parents = (
        [*(observation.get("interfaces") or ()), observation.get("super_name")]
        if kind == "field"
        else [observation.get("super_name"), *(observation.get("interfaces") or ())]
    )
    for parent in parents:
        if not parent:
            continue
        result = _resolve_member(
            observations, str(parent), kind, name, descriptor, visited | {owner}
        )
        if result:
            return result
    return None


def _is_subtype(
    observations: Mapping[str, Mapping[str, Any]], child: str, parent: str,
    visited: frozenset[str] = frozenset(),
) -> bool:
    if child == parent:
        return True
    if child in visited:
        return False
    row = observations.get(child) or {}
    return any(
        _is_subtype(observations, str(candidate), parent, visited | {child})
        for candidate in [row.get("super_name"), *(row.get("interfaces") or ())]
        if candidate
    )


def _oracle_annotation_closure(
    observations: Mapping[str, Mapping[str, Any]], descriptors: Iterable[str],
) -> set[str]:
    result = {str(value) for value in descriptors if str(value)}
    pending = list(result)
    while pending:
        descriptor = pending.pop()
        if not descriptor.startswith("L") or not descriptor.endswith(";"):
            continue
        annotation_type = descriptor[1:-1]
        for nested in (observations.get(annotation_type) or {}).get(
            "class_annotations"
        ) or ():
            if nested not in result:
                result.add(str(nested))
                pending.append(str(nested))
    return result


def _oracle_member_annotations(
    observation: Mapping[str, Any],
) -> dict[tuple[str, str], set[str]]:
    result: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in observation.get("member_annotations") or ():
        name, descriptor, annotation = str(row).split("|", 2)
        result[(name, descriptor)].add(annotation)
    return result


def _oracle_selected_auto_configurations(
    resource_truth: Iterable[Mapping[str, Any]],
) -> tuple[set[str], dict[str, set[tuple[str, str]]]]:
    result = set()
    callbacks: dict[str, set[tuple[str, str]]] = defaultdict(set)
    boot_imports = (
        "META-INF/spring/"
        "org.springframework.boot.autoconfigure.AutoConfiguration.imports"
    )
    factory_keys = {
        "org.springframework.boot.autoconfigure.EnableAutoConfiguration",
        "org.springframework.boot.autoconfigure.AutoConfiguration",
    }
    for selection in resource_truth:
        name = str(selection.get("name") or "")
        for selected in selection.get("selected") or ():
            for key, value in selected.get("semantic_facts") or ():
                if name == boot_imports and key == "ordered_entry":
                    result.add(str(value).replace(".", "/"))
                elif str(key).startswith("property_entry:") and str(key).split(
                    ":", 1
                )[1] in factory_keys:
                    result.add(str(value).replace(".", "/"))
                elif str(key).startswith("property_entry:"):
                    registration = str(key).split(":", 1)[1]
                    callback = _ORACLE_SPRING_FACTORIES_CALLBACKS.get(registration)
                    if callback:
                        callbacks[str(value).replace(".", "/")].add(callback)
    return result, dict(callbacks)


def _validate_entrypoint_discovery(
    generation: Path,
    current_side: Mapping[str, Any],
    current_artifacts: list[dict[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
    resource_truth: Iterable[Mapping[str, Any]],
    direct_edge_truth: Iterable[Iterable[Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Independently reconstruct automatic callback roots using target-JVM reflection."""

    issues = []
    sidecar = _load_json(generation / "binary_entrypoints.json")
    profile = (current_side.get("runtime_profile") or {}).get(
        "business_entrypoint_profile"
    ) or {}
    topology = (current_side.get("runtime_profile") or {}).get("loader_topology") or {}
    non_platform_realms = sorted({
        str(item.get("identity") or "")
        for item in topology.get("realms") or ()
        if item.get("kind") != "platform" and item.get("identity")
    })
    realms = tuple(topology.get("entrypoint_realms") or non_platform_realms)
    path_kinds_by_path = {
        Path(str(item["path"])).resolve(): str(item.get("path_kind") or "").lower()
        for item in current_artifacts
    }
    business_path_kinds = {
        "application", "application_classes", "business", "business_classes",
    }

    def artifact_path(observation: Mapping[str, Any]) -> Path | None:
        return _file_url_path(str(observation.get("provider_url") or ""))

    def business_owned(observation: Mapping[str, Any]) -> bool:
        path = artifact_path(observation)
        return path is not None and path_kinds_by_path.get(path) in business_path_kinds

    exact_main_classes = {
        str(profile.get("main_class") or "").strip().replace(".", "/")
    } - {""}
    launcher_kind = str(
        (current_side.get("runtime_profile") or {}).get(
            "container_and_launcher_kind"
        ) or ""
    ).lower()
    if launcher_kind in {
        "java-jar", "executable-jar", "spring-boot", "spring_boot",
        "spring-boot-launcher",
    }:
        for artifact in current_artifacts:
            artifact_path_value = Path(str(artifact["path"])).resolve()
            if path_kinds_by_path.get(artifact_path_value) not in business_path_kinds:
                continue
            with zipfile.ZipFile(artifact_path_value) as archive:
                manifests = [
                    info for info in archive.infolist()
                    if not info.is_dir()
                    and info.filename.upper() == "META-INF/MANIFEST.MF"
                ]
                for manifest in manifests:
                    for key, value in _independent_resource_facts(
                        manifest.filename, archive.read(manifest)
                    ):
                        if str(key).lower() in {"main-class", "start-class"}:
                            exact_main_classes.add(
                                str(value).strip().replace(".", "/")
                            )

    registered_auto_configurations, spring_factories_callbacks = (
        _oracle_selected_auto_configurations(resource_truth)
    )
    explicitly_activated_frameworks = {
        str(value or "").strip().lower()
        for value in profile.get("activated_frameworks") or ()
    }
    launcher = str(
        (current_side.get("runtime_profile") or {}).get(
            "container_and_launcher_kind"
        ) or ""
    ).lower()
    declared_method_keys = {
        (
            str(item.get("class_name") or "").replace("/", "."),
            str(item.get("member_name") or ""),
            str(item.get("descriptor") or ""),
        )
        for item in profile.get("methods") or ()
        if isinstance(item, Mapping)
    }
    spring_boot_active = (
        "spring_boot" in explicitly_activated_frameworks
        or launcher in {"spring-boot", "spring_boot", "spring-boot-launcher"}
        or any(
            str(edge[3]).replace("/", ".")
            == "org.springframework.boot.SpringApplication"
            and str(edge[4]) == "run"
            and business_owned(observations.get(str(edge[0]).replace(".", "/")) or {})
            and (
                (str(edge[0]), str(edge[1]), str(edge[2]))
                in declared_method_keys
                or (
                    str(edge[0]).replace(".", "/") in exact_main_classes
                    and str(edge[1]) == "main"
                    and str(edge[2]) == "([Ljava/lang/String;)V"
                )
            )
            for edge in direct_edge_truth
        )
    )
    resource_activated = (
        set(registered_auto_configurations) | set(spring_factories_callbacks)
        if spring_boot_active else set()
    )
    activated = set(resource_activated)
    activated.update(
        str(value).replace(".", "/")
        for value in profile.get("activated_classes") or ()
        if str(value).strip()
    )
    imported_activated = set()
    changed = True
    while changed:
        changed = False
        for class_name, observation in observations.items():
            if class_name not in activated and not business_owned(observation):
                continue
            annotations = _oracle_annotation_closure(
                observations, observation.get("class_annotations") or ()
            )
            annotated_types = [class_name]
            annotated_types.extend(
                descriptor[1:-1]
                for descriptor in annotations
                if descriptor.startswith("L") and descriptor.endswith(";")
            )
            for annotated_type in annotated_types:
                for imported in (observations.get(annotated_type) or {}).get(
                    "class_annotation_imports"
                ) or ():
                    if str(imported).startswith("<unresolved:"):
                        issues.append(_validation_issue(
                            "entrypoint_discovery",
                            "ORACLE_ENTRYPOINT_IMPORT_UNRESOLVED",
                            class_name=class_name, detail=imported,
                        ))
                    elif imported not in activated:
                        activated.add(str(imported))
                        imported_activated.add(str(imported))
                        changed = True

    declared = {
        (
            str(item.get("class_name") or "").replace(".", "/"),
            str(item.get("member_name") or ""),
            str(item.get("descriptor") or ""),
        )
        for item in profile.get("methods") or ()
        if isinstance(item, Mapping)
    }
    expected = set()
    for realm in realms:
        for class_name, observation in observations.items():
            if observation.get("status") != "definition_ready":
                continue
            owned = business_owned(observation)
            active = owned or class_name in activated
            class_annotations = _oracle_annotation_closure(
                observations, observation.get("class_annotations") or ()
            )
            conditional_class = any(
                value.startswith(
                    "Lorg/springframework/boot/autoconfigure/condition/Conditional"
                ) or value == "Lorg/springframework/context/annotation/Conditional;"
                for value in class_annotations
            )
            annotation_by_member = _oracle_member_annotations(observation)
            for kind, member_name, descriptor, flags in _declared_members(observation):
                if kind != "method":
                    continue
                member_key = (class_name, member_name, descriptor)
                if member_key in declared:
                    expected.add((
                        realm, class_name, member_name, descriptor,
                        "declared_runtime_entry", "exact",
                        "runtime_profile_declaration",
                    ))
                    continue
                annotations = _oracle_annotation_closure(
                    observations,
                    annotation_by_member.get((member_name, descriptor), ()),
                )
                candidate_kinds = {
                    _ORACLE_METHOD_ENTRY_KINDS[value]
                    for value in annotations
                    if value in _ORACLE_METHOD_ENTRY_KINDS
                }
                for annotation, (entry_kind, names) in _ORACLE_CLASS_TRIGGER_KINDS.items():
                    if annotation in class_annotations and member_name in names:
                        candidate_kinds.add(entry_kind)
                for interface, callbacks in _ORACLE_INTERFACE_CALLBACKS.items():
                    if _is_subtype(observations, class_name, interface):
                        entry_kind = callbacks.get(member_name)
                        if entry_kind:
                            candidate_kinds.add(entry_kind)
                for callback_name, entry_kind in spring_factories_callbacks.get(
                    class_name, ()
                ):
                    if member_name == callback_name:
                        candidate_kinds.add(entry_kind)
                if (
                    member_name == "main"
                    and descriptor == "([Ljava/lang/String;)V"
                    and flags & 0x0001 and flags & 0x0008 and owned
                ):
                    candidate_kinds.add("java_main")
                for entry_kind in candidate_kinds:
                    conditional = conditional_class or any(
                        value.startswith(
                            "Lorg/springframework/boot/autoconfigure/condition/Conditional"
                        ) or value == "Lorg/springframework/context/annotation/Conditional;"
                        for value in annotations
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
                    elif active:
                        certainty = "exact"
                        if owned:
                            reason = "business_final_artifact_runtime_trigger"
                        elif class_name in resource_activated:
                            reason = (
                                "spring_factories_runtime_registration"
                                if class_name in spring_factories_callbacks
                                else "spring_boot_auto_configuration_import"
                            )
                        elif class_name in imported_activated:
                            reason = "spring_import_from_active_configuration"
                        else:
                            reason = "runtime_profile_activation_declaration"
                    else:
                        certainty = "possible"
                        reason = "dependency_framework_activation_unproven"
                    expected.add((
                        realm, class_name, member_name, descriptor,
                        entry_kind, certainty, reason,
                    ))

    actual = {
        (
            str(item.get("initiating_loader_realm_identity") or ""),
            str(item.get("class_name") or ""),
            str(item.get("member_name") or ""),
            str(item.get("descriptor") or ""),
            str(item.get("entry_kind") or ""),
            str(item.get("path_certainty") or ""),
            str(item.get("activation_reason") or ""),
        )
        for item in sidecar.get("records") or ()
    }
    if actual != expected:
        issues.append(_validation_issue(
            "entrypoint_discovery", "ORACLE_ENTRYPOINT_SET_MISMATCH",
            missing=sorted(expected - actual), extra=sorted(actual - expected),
        ))
    return issues, {
        "entrypoints": [list(item) for item in sorted(expected)],
        "entrypoint_count": len(expected),
    }


def _oracle_runtime_contexts(
    observations: Mapping[str, Mapping[str, Any]],
    initial_classes: Iterable[str],
    entrypoint_realms: Iterable[str],
    platform_realm: str,
) -> tuple[tuple[str, str], ...]:
    """Mirror JVM initiating-to-defining-loader hierarchy traversal.

    Initial application classes and symbolic targets are requested through an
    entrypoint realm.  Their superclasses and interfaces are then requested by
    the selected class's defining loader.  Applying every transitive platform
    type back to every application realm invents provider obligations that do
    not exist in the production reconciliation universe.
    """
    contexts = set()
    pending = [
        (str(realm), str(name).replace(".", "/"))
        for realm in entrypoint_realms
        for name in initial_classes
        if str(realm) and str(name)
    ]
    while pending:
        realm, name = pending.pop()
        if (realm, name) in contexts:
            continue
        contexts.add((realm, name))
        observation = observations.get(name) or {}
        if observation.get("status") != "definition_ready":
            continue
        defining_realm = (
            platform_realm
            if _file_url_path(str(observation.get("provider_url") or "")) is None
            else realm
        )
        for dependency in [
            observation.get("super_name"), *(observation.get("interfaces") or ())
        ]:
            normalized = str(dependency or "").replace(".", "/")
            if normalized and (defining_realm, normalized) not in contexts:
                pending.append((defining_realm, normalized))
    return tuple(sorted(contexts))


def _validation_issue(domain: str, code: str, **evidence: Any) -> dict[str, Any]:
    return {"domain": domain, "reason_code": code, "evidence": evidence}


def _validate_direct_edges(
    connection: sqlite3.Connection,
    artifacts: list[dict[str, Any]],
    *,
    javap: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues = []
    truth_rows = []
    dynamic_rows = []
    discovery_classes = set()
    artifact_instances = _rows(connection, "artifact_instances")
    instance_by_sha_slot = {
        (row["content_sha256"], int(row["runtime_classpath_index"])): row
        for row in artifact_instances
    }
    members = {row["member_identity"]: row for row in _rows(connection, "members")}
    production_edges = _rows(connection, "direct_edges")
    production_by_artifact: dict[str, set[tuple[Any, ...]]] = defaultdict(set)
    production_dynamic_by_artifact: dict[str, set[tuple[Any, ...]]] = defaultdict(set)
    for edge in production_edges:
        if edge["edge_kind"].startswith("invokedynamic_handle_"):
            caller = members[edge["caller_member_identity"]]
            if str(edge["symbolic_descriptor"]).startswith("("):
                production_dynamic_by_artifact[
                    edge["caller_artifact_instance_identity"]
                ].add((
                    caller["class_name"].replace("/", "."),
                    caller["member_name"], caller["descriptor"],
                    edge["symbolic_owner"].replace("/", "."),
                    edge["symbolic_name"], edge["symbolic_descriptor"],
                    int(edge["bytecode_offset"]),
                ))
            continue
        if edge["edge_kind"] not in {"method", "field"}:
            continue
        caller = members[edge["caller_member_identity"]]
        production_by_artifact[edge["caller_artifact_instance_identity"]].add((
            caller["class_name"].replace("/", "."), caller["member_name"],
            caller["descriptor"], edge["symbolic_owner"].replace("/", "."),
            edge["symbolic_name"], edge["symbolic_descriptor"],
            _opcode_name(edge["opcode"]), int(edge["bytecode_offset"]),
        ))
    for artifact in artifacts:
        instance = instance_by_sha_slot.get((artifact["sha256"], int(artifact["slot"])))
        if not instance:
            issues.append(_validation_issue(
                "direct_edge", "ORACLE_ARTIFACT_INSTANCE_UNBOUND",
                path=artifact["path"], slot=artifact["slot"],
            ))
            continue
        result = scan_final_artifact(Path(artifact["path"]), javap=javap)
        if not result.get("complete"):
            issues.append(_validation_issue(
                "direct_edge", "ORACLE_JAVAP_INVENTORY_INCOMPLETE",
                artifact=artifact["path"], failures=result.get("failures") or (),
            ))
            continue
        truth = {
            (
                row["caller_owner"], row["caller_member"], row["caller_descriptor"],
                row["callee_owner"], row["callee_member"], row["callee_descriptor"],
                row["opcode_family"], int(row["instruction_offset"]),
            )
            for row in result.get("edges") or ()
            if row.get("opcode_family") != "invokedynamic"
        }
        dynamic_truth = {
            (
                row["caller_owner"], row["caller_member"], row["caller_descriptor"],
                row["callee_owner"], row["callee_member"], row["callee_descriptor"],
                int(row["instruction_offset"]),
            )
            for row in result.get("edges") or ()
            if row.get("opcode_family") == "invokedynamic"
        }
        discovery_classes.update(
            str(row.get("callee_owner") or "").replace(".", "/")
            for row in result.get("edges") or ()
            if row.get("callee_owner")
        )
        actual = production_by_artifact.get(instance["artifact_instance_identity"], set())
        actual_dynamic = production_dynamic_by_artifact.get(
            instance["artifact_instance_identity"], set()
        )
        for missing in sorted(truth - actual):
            issues.append(_validation_issue("direct_edge", "ORACLE_DIRECT_EDGE_MISSING", edge=missing))
        for extra in sorted(actual - truth):
            issues.append(_validation_issue("direct_edge", "ORACLE_DIRECT_EDGE_EXTRA", edge=extra))
        for missing in sorted(dynamic_truth - actual_dynamic):
            issues.append(_validation_issue(
                "dynamic_bootstrap", "ORACLE_DYNAMIC_HANDLE_MISSING", edge=missing
            ))
        for extra in sorted(actual_dynamic - dynamic_truth):
            issues.append(_validation_issue(
                "dynamic_bootstrap", "ORACLE_DYNAMIC_HANDLE_EXTRA", edge=extra
            ))
        truth_rows.extend(sorted(truth))
        dynamic_rows.extend(sorted(dynamic_truth))
    return issues, {
        "direct_edges": truth_rows,
        "dynamic_handle_edges": dynamic_rows,
        "discovery_classes": sorted(discovery_classes),
    }


def _validate_runtime_outcomes(
    connection: sqlite3.Connection,
    artifacts: list[dict[str, Any]],
    inventories: list[dict[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
    entrypoint_realms: Iterable[str],
    initial_classes: Iterable[str],
    platform_realm: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues = []
    artifact_rows = {row["artifact_instance_identity"]: row for row in _rows(connection, "artifact_instances")}
    artifacts_by_path = {Path(item["path"]).resolve(): item for item in artifacts}
    providers = _reconciliation(connection, "provider_binding")
    definitions = {
        (row["initiating_loader_realm_identity"], row["class_name"]): row
        for row in _reconciliation(connection, "class_definition")
    }
    provider_by_key = {
        (row["initiating_loader_realm_identity"], row["class_name"]): row
        for row in providers
    }
    oracle_contexts = _oracle_runtime_contexts(
        observations, initial_classes, entrypoint_realms, platform_realm
    )
    for realm, name in oracle_contexts:
        oracle = observations.get(name) or {}
        provider = provider_by_key.get((realm, name))
        if not provider:
            issues.append(_validation_issue(
                "provider", "ORACLE_PROVIDER_BINDING_MISSING", realm=realm, class_name=name,
            ))
            continue
        actual_status = provider["class_provider_status"]
        if not oracle or oracle.get("status") != "definition_ready":
            if actual_status == "resolved":
                issues.append(_validation_issue(
                    "provider", "ORACLE_PROVIDER_FALSE_RESOLUTION", realm=realm, class_name=name,
                ))
            continue
        provider_path = _file_url_path(str(oracle.get("provider_url") or ""))
        if provider_path is None:
            expected_kind = "platform"
        else:
            expected_kind = "artifact"
        if actual_status != "resolved":
            issues.append(_validation_issue(
                "provider", "ORACLE_PROVIDER_MISSED", realm=realm, class_name=name,
                oracle_provider_url=oracle.get("provider_url"),
            ))
            continue
        selected = provider.get("selected_artifact_instance_identity")
        if expected_kind == "platform":
            if not str(selected).startswith("platform-image:"):
                issues.append(_validation_issue(
                    "provider", "ORACLE_PLATFORM_PROVIDER_MISMATCH",
                    realm=realm, class_name=name, selected=selected,
                ))
        else:
            selected_row = artifact_rows.get(str(selected))
            expected_artifact = artifacts_by_path.get(provider_path)
            if (
                not selected_row or not expected_artifact
                or selected_row["content_sha256"] != expected_artifact["sha256"]
            ):
                issues.append(_validation_issue(
                    "provider", "ORACLE_ARTIFACT_PROVIDER_MISMATCH",
                    realm=realm, class_name=name, oracle_provider_url=oracle.get("provider_url"),
                    selected=selected,
                ))
        definition = definitions.get((realm, name))
        if not definition or definition.get("class_definition_status") != "definition_ready":
            issues.append(_validation_issue(
                "class_definition", "ORACLE_DEFINITION_READY_MISMATCH",
                realm=realm, class_name=name,
                production_status=(definition or {}).get("class_definition_status"),
            ))

    member_rows = {row["member_identity"]: row for row in _rows(connection, "members")}
    direct_edges = {row["direct_edge_identity"]: row for row in _rows(connection, "direct_edges")}
    member_resolutions = _reconciliation(connection, "member_resolution")
    for resolution in member_resolutions:
        edge = direct_edges.get(resolution["direct_edge_identity"])
        if not edge or edge["edge_kind"] not in {"method", "field"}:
            continue
        kind = "field" if edge["edge_kind"] == "field" else "method"
        oracle_member = _resolve_member(
            observations, edge["symbolic_owner"], kind,
            edge["symbolic_name"], edge["symbolic_descriptor"],
        )
        status = resolution["member_resolution_status"]
        if oracle_member is None:
            if status == "resolved":
                issues.append(_validation_issue(
                    "member_resolution", "ORACLE_MEMBER_FALSE_RESOLUTION",
                    direct_edge_identity=edge["direct_edge_identity"],
                ))
            continue
        declaring, _member = oracle_member
        if status != "resolved":
            issues.append(_validation_issue(
                "member_resolution", "ORACLE_MEMBER_MISSED",
                direct_edge_identity=edge["direct_edge_identity"], declaring_owner=declaring,
            ))
            continue
        selected_member = member_rows.get(str(resolution.get("resolved_member_identity") or ""))
        if selected_member and selected_member["class_name"] != declaring:
            issues.append(_validation_issue(
                "member_resolution", "ORACLE_MEMBER_OWNER_MISMATCH",
                direct_edge_identity=edge["direct_edge_identity"],
                expected_owner=declaring, actual_owner=selected_member["class_name"],
            ))

    dispatches = {
        row["direct_edge_identity"]: row
        for row in _reconciliation(connection, "dispatch_resolution")
    }
    for edge_id, edge in direct_edges.items():
        if edge["edge_kind"] != "method" or int(edge["opcode"] or 0) not in {182, 185}:
            continue
        oracle_targets = set()
        for class_name, observation in observations.items():
            if observation.get("status") != "definition_ready":
                continue
            modifiers = int(observation.get("modifiers") or 0)
            if modifiers & (0x0200 | 0x0400):
                continue
            if not _is_subtype(observations, class_name, edge["symbolic_owner"]):
                continue
            target = _resolve_member(
                observations, class_name, "method",
                edge["symbolic_name"], edge["symbolic_descriptor"],
            )
            if target:
                oracle_targets.add((target[0], target[1][1], target[1][2]))
        production = dispatches.get(edge_id) or {}
        target_symbols = set()
        for target_id in production.get("implementation_target_identities") or ():
            row = member_rows.get(target_id)
            if row:
                target_symbols.add((row["class_name"], row["member_name"], row["descriptor"]))
        application_oracle_targets = {
            item for item in oracle_targets
            if any(item[0] in inventory["classes"] for inventory in inventories)
        }
        if target_symbols != application_oracle_targets:
            issues.append(_validation_issue(
                "dispatch", "ORACLE_DISPATCH_TARGET_MISMATCH",
                direct_edge_identity=edge_id,
                expected=sorted(application_oracle_targets), actual=sorted(target_symbols),
            ))
        if application_oracle_targets and production.get("dispatch_status") not in {
            "possible", "partial_possible_set", "proven_receiver", "exact"
        }:
            issues.append(_validation_issue(
                "dispatch", "ORACLE_DISPATCH_STATUS_MISMATCH",
                direct_edge_identity=edge_id, status=production.get("dispatch_status"),
            ))

    return issues, {
        "runtime_observations": observations,
        "provider_count": len(providers),
        "member_resolution_count": len(member_resolutions),
        "dispatch_count": len(dispatches),
    }


def _validate_resource_selections(
    connection: sqlite3.Connection,
    artifacts: list[dict[str, Any]],
    inventories: list[dict[str, Any]],
    entrypoint_realms: Iterable[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues = []
    production = {
        (row["initiating_loader_realm_identity"], row["resource_name"], row["resource_mechanism"]): row
        for row in _reconciliation(connection, "resource_selection")
    }
    truth = {}
    all_names = sorted({name for inventory in inventories for name in inventory["resources"]})
    for realm in entrypoint_realms:
        for name in all_names:
            category = _independent_resource_category(name)
            mechanism = "ordered_all" if category == "runtime_topology" else "classloader_first"
            candidates = []
            for artifact, inventory in zip(artifacts, inventories):
                if str(artifact.get("loader_realm") or "") != realm:
                    continue
                for item in inventory["resources"].get(name, ()):
                    candidates.append({
                        "slot": int(artifact["slot"]),
                        "origin": str(artifact.get("runtime_code_source_origin_identity") or ""),
                        "digest": item["semantic_digest"] if category == "runtime_topology" else item["sha256"],
                        "semantic_facts": item["semantic_facts"],
                    })
            candidates.sort(key=lambda item: (item["slot"], item["origin"], item["digest"]))
            selected = candidates if mechanism == "ordered_all" else candidates[:1]
            key = (realm, name, mechanism)
            truth[key] = selected
            actual_record = production.get(key)
            actual = []
            for item in (actual_record or {}).get("selected_resources") or ():
                actual.append({
                    "slot": int(item["runtime_classpath_index"]),
                    "origin": item["runtime_code_source_origin_identity"],
                    "digest": (
                        item["normalized_resource_digest"]
                        if category == "runtime_topology" else item["content_sha256"]
                    ),
                    "semantic_facts": item.get("resource_semantic_facts") or [],
                })
            def comparable(item):
                semantic = item.get("semantic_facts") or []
                return {
                    "slot": item["slot"], "origin": item["origin"],
                    "value": semantic if semantic else item["digest"],
                }
            expected_comparable = [comparable(item) for item in selected]
            actual_comparable = [comparable(item) for item in actual]
            if actual_comparable != expected_comparable:
                issues.append(_validation_issue(
                    "resource_selection", "ORACLE_RESOURCE_SELECTION_MISMATCH",
                    realm=realm, resource_name=name,
                    expected=expected_comparable, actual=actual_comparable,
                ))
    return issues, {
        "resource_selections": [
            {"realm": key[0], "name": key[1], "mechanism": key[2], "selected": value}
            for key, value in sorted(truth.items())
        ]
    }


def _validate_pairings(
    generation: Path, base_artifacts: list[dict[str, Any]], current_artifacts: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    payload = _load_json(generation / "binary_pairings.json")
    actual = {
        row["logical_dependency_lineage"]: row["status"]
        for row in payload.get("pairings") or ()
    }
    base = defaultdict(int)
    current = defaultdict(int)
    for item in base_artifacts:
        base[str(item.get("lineage") or item.get("coord") or item.get("logical_location"))] += 1
    for item in current_artifacts:
        current[str(item.get("lineage") or item.get("coord") or item.get("logical_location"))] += 1
    expected = {}
    issues = []
    for lineage in sorted(set(base) | set(current)):
        if base[lineage] > 1 or current[lineage] > 1:
            status = "ambiguous"
        elif base[lineage] and current[lineage]:
            status = "exact"
        elif base[lineage]:
            status = "base_only"
        else:
            status = "current_only"
        expected[lineage] = status
        if actual.get(lineage) != status:
            issues.append(_validation_issue(
                "pairing", "ORACLE_PAIRING_MISMATCH", lineage=lineage,
                expected=status, actual=actual.get(lineage),
            ))
    return issues, {"pairings": expected}


def _validate_cross_version_semantics(
    generation: Path,
    config: Mapping[str, Any],
    truth_parts: Mapping[str, Any],
    observations_by_side: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    issues = []
    base_edges = {tuple(item) for item in truth_parts["base"]["direct_edges"]}
    current_edges = {tuple(item) for item in truth_parts["current"]["direct_edges"]}
    expected_resolution_changes = set()
    for edge in sorted(base_edges.intersection(current_edges)):
        (
            caller_owner, caller_name, caller_descriptor,
            target_owner, target_name, target_descriptor,
            opcode, bytecode_offset,
        ) = edge
        if not str(opcode).startswith("invoke"):
            continue
        base_target = _resolve_member(
            observations_by_side["base"], str(target_owner).replace(".", "/"),
            "method", target_name, target_descriptor,
        )
        current_target = _resolve_member(
            observations_by_side["current"], str(target_owner).replace(".", "/"),
            "method", target_name, target_descriptor,
        )
        if not base_target or not current_target or base_target[0] == current_target[0]:
            continue
        expected_resolution_changes.add((
            str(caller_owner), str(caller_name), str(caller_descriptor),
            int(bytecode_offset), str(target_owner), str(target_name),
            str(target_descriptor), base_target[0].replace("/", "."),
            current_target[0].replace("/", "."),
        ))

    decisions = _load_json(generation / "binary_decisions.json")
    actual_resolution_changes = set()
    for decision in decisions.get("authoritative_change_facts") or ():
        if decision.get("reason_code") != "RUNTIME_MEMBER_RESOLUTION_CHANGED":
            continue
        scope = decision.get("fact_scope") or {}
        evidence = decision.get("evidence") or {}
        caller = evidence.get("semantic_caller_edge") or {}
        actual_resolution_changes.add((
            str(caller.get("caller_class") or "").replace("/", "."),
            str(caller.get("caller_member") or ""),
            str(caller.get("caller_descriptor") or ""),
            int(caller.get("bytecode_offset") or 0),
            str(scope.get("class_name") or "").replace("/", "."),
            str(scope.get("member_name") or ""),
            str(scope.get("descriptor") or ""),
            str((evidence.get("base_resolution") or {}).get("resolved_owner") or "").replace("/", "."),
            str((evidence.get("current_resolution") or {}).get("resolved_owner") or "").replace("/", "."),
        ))
    for missing in sorted(expected_resolution_changes - actual_resolution_changes):
        issues.append(_validation_issue(
            "cross_version_member_resolution",
            "ORACLE_MEMBER_RESOLUTION_CHANGE_MISSING",
            change=missing,
        ))
    for extra in sorted(actual_resolution_changes - expected_resolution_changes):
        issues.append(_validation_issue(
            "cross_version_member_resolution",
            "ORACLE_MEMBER_RESOLUTION_CHANGE_EXTRA",
            change=extra,
        ))

    current_graph = defaultdict(set)
    for edge in current_edges:
        caller = (str(edge[0]), str(edge[1]), str(edge[2]))
        if not str(edge[6]).startswith("("):
            continue
        target = _resolve_member(
            observations_by_side["current"], str(edge[3]).replace(".", "/"),
            "method", edge[4], edge[5],
        )
        if target:
            current_graph[caller].add((
                target[0].replace("/", "."), str(target[1][1]), str(target[1][2])
            ))
    entrypoints = {
        (
            str(item.get("class_name") or "").replace("/", "."),
            str(item.get("member_name") or ""),
            str(item.get("descriptor") or ""),
        )
        for item in (
            ((config.get("current") or {}).get("runtime_profile") or {})
            .get("business_entrypoint_profile", {}).get("methods") or ()
        )
    }
    reached = set(entrypoints)
    pending = list(entrypoints)
    while pending:
        caller = pending.pop()
        for target in current_graph.get(caller, ()):
            if target not in reached:
                reached.add(target)
                pending.append(target)

    base_resources = {
        (item["realm"], item["name"], item["mechanism"]): item["selected"]
        for item in truth_parts["base"]["resource_selections"]
    }
    current_resources = {
        (item["realm"], item["name"], item["mechanism"]): item["selected"]
        for item in truth_parts["current"]["resource_selections"]
    }
    current_type_edges = {
        tuple(item) for item in truth_parts["current"]["type_edges"]
    }
    expected_resource_status = {}
    for key in sorted(set(base_resources).intersection(current_resources)):
        realm, name, _mechanism = key
        if not name.startswith("META-INF/services/"):
            continue
        if base_resources[key] == current_resources[key]:
            continue
        service = name.removeprefix("META-INF/services/")
        load_callers = {
            (str(edge[0]), str(edge[1]), str(edge[2])): int(edge[7])
            for edge in current_edges
            if str(edge[3]) == "java.util.ServiceLoader"
            and str(edge[4]) == "load"
            and str(edge[5]).startswith("(Ljava/lang/Class;")
        }
        activated = False
        for literal in current_type_edges:
            caller = (
                str(literal[0]).replace("/", "."),
                str(literal[1]), str(literal[2]),
            )
            literal_owner = str(literal[4]).replace("/", ".")
            if (
                literal_owner == service
                and literal[5] == "class_literal"
                and caller in load_callers
                and 0 <= load_callers[caller] - int(literal[3]) <= 4
                and caller in reached
            ):
                activated = True
                break
        expected_resource_status[name] = (
            "reachable" if activated else "not_found_in_static_analysis"
        )
    formal = _load_json(generation / "binary_formal_results.json")
    actual_resource_status = {
        str(item.get("resource_name") or ""): str(item.get("activation_status") or "")
        for item in formal.get("resource_activation_results") or ()
    }
    if actual_resource_status != expected_resource_status:
        issues.append(_validation_issue(
            "resource_activation",
            "ORACLE_RESOURCE_ACTIVATION_MISMATCH",
            expected=expected_resource_status,
            actual=actual_resource_status,
        ))
    return issues, {
        "member_resolution_changes": sorted(expected_resolution_changes),
        "resource_activation_status": dict(sorted(expected_resource_status.items())),
    }


def validate_generation(
    config: Mapping[str, Any], generation_directory: str | Path,
) -> dict[str, Any]:
    generation = Path(generation_directory).resolve()
    manifest = _load_json(generation / "result_generation.json")
    integrity_issues = []
    for name, expected in (manifest.get("sidecar_content_identities") or {}).items():
        sidecar = generation / str(name)
        actual = _sha256_file(sidecar) if sidecar.is_file() else "MISSING"
        if actual != expected:
            integrity_issues.append(_validation_issue(
                "generation_integrity", "ORACLE_GENERATION_SIDECAR_TAMPERED",
                sidecar=name, expected_sha256=expected, actual_sha256=actual,
            ))
    base_side = dict(config.get("base") or {})
    current_side = dict(config.get("current") or {})
    base_artifacts = _artifact_configs(base_side)
    current_artifacts = _artifact_configs(current_side)
    base_jdk = Path(str(base_side.get("jdk_home") or "")).expanduser().resolve()
    current_jdk = Path(str(current_side.get("jdk_home") or "")).expanduser().resolve()
    base_inventories = [
        _archive_inventory(Path(item["path"]), _release_major(base_jdk))
        for item in base_artifacts
    ]
    current_inventories = [
        _archive_inventory(Path(item["path"]), _release_major(current_jdk))
        for item in current_artifacts
    ]
    issues = list(integrity_issues)
    for side, inventories in (("base", base_inventories), ("current", current_inventories)):
        for inventory in inventories:
            for failure in inventory["failures"]:
                issues.append(_validation_issue("artifact_inventory", "ORACLE_INVENTORY_FAILURE", side=side, failure=failure))
    truth_parts = {
        "generation_integrity": [
            issue["evidence"] for issue in integrity_issues
        ] or [{"status": "intact"}],
    }
    pairing_issues, pairing_truth = _validate_pairings(
        generation, base_artifacts, current_artifacts
    )
    issues.extend(pairing_issues)
    truth_parts.update(pairing_truth)

    helper_identities = {}
    observations_by_side = {}
    for side_name, side, artifacts, inventories, db_name, jdk_home in (
        ("base", base_side, base_artifacts, base_inventories, "base_binary_facts.sqlite", base_jdk),
        ("current", current_side, current_artifacts, current_inventories, "current_binary_facts.sqlite", current_jdk),
    ):
        db_path = generation / db_name
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            javap = str(jdk_home / "bin" / ("javap.exe" if (jdk_home / "bin" / "javap.exe").exists() else "javap"))
            edge_issues, edge_truth = _validate_direct_edges(
                connection, artifacts, javap=javap
            )
            structural_issues, structural_truth = _validate_structural_edges(
                connection, artifacts, inventories, javap=javap
            )
            issues.extend(edge_issues)
            issues.extend(structural_issues)
            independent_classes = {
                name for inventory in inventories for name in inventory["classes"]
            }
            independent_classes.update(edge_truth["discovery_classes"])
            observations, helper_identity = _observe_classes(
                jdk_home, artifacts, independent_classes
            )
            helper_identities[side_name] = helper_identity
            observations_by_side[side_name] = observations
            topology = (side.get("runtime_profile") or {}).get("loader_topology") or {}
            realms = {
                str(item.get("identity")) for item in topology.get("realms") or ()
                if item.get("kind") != "platform"
            }
            entrypoint_realms = tuple(topology.get("entrypoint_realms") or sorted(realms))
            platform_realms = [
                str(item.get("identity")) for item in topology.get("realms") or ()
                if item.get("kind") == "platform"
            ]
            platform_realm = (
                platform_realms[0] if len(platform_realms) == 1 else "platform-loader"
            )
            runtime_issues, runtime_truth = _validate_runtime_outcomes(
                connection,
                artifacts,
                inventories,
                observations,
                entrypoint_realms,
                independent_classes,
                platform_realm,
            )
            resource_issues, resource_truth = _validate_resource_selections(
                connection, artifacts, inventories, entrypoint_realms
            )
            issues.extend(runtime_issues)
            issues.extend(resource_issues)
            truth_parts[side_name] = {
                **edge_truth, **structural_truth, **runtime_truth, **resource_truth,
            }
        finally:
            connection.close()

    cross_issues, cross_truth = _validate_cross_version_semantics(
        generation, config, truth_parts, observations_by_side
    )
    issues.extend(cross_issues)
    truth_parts["cross_version_semantics"] = cross_truth
    entrypoint_issues, entrypoint_truth = _validate_entrypoint_discovery(
        generation,
        current_side,
        current_artifacts,
        observations_by_side.get("current") or {},
        (truth_parts.get("current") or {}).get("resource_selections") or (),
        (truth_parts.get("current") or {}).get("direct_edges") or (),
    )
    issues.extend(entrypoint_issues)
    truth_parts["entrypoint_discovery"] = entrypoint_truth

    truth_set_identity = _identity("binary_oracle_truth_set_identity", truth_parts)
    support = _load_json(SUPPORT_MANIFEST)
    oracle_manifest_identity = _identity(
        "oracle_support_manifest_identity", support["oracle_support_manifest"]
    )
    validation_run_identity = _identity("binary_validation_run_identity", {
        "result_generation_identity": manifest["result_generation_identity"],
        "active_snapshot_identities": manifest["active_snapshot_identities"],
        "oracle_support_manifest_identity": oracle_manifest_identity,
        "truth_set_identity": truth_set_identity,
        "validation_policy_version": POLICY_VERSION,
        "helper_identities": helper_identities,
    })
    domain_counts = defaultdict(lambda: {"issues": 0})
    for issue in issues:
        domain_counts[issue["domain"]]["issues"] += 1
    result = {
        "schema": "java-upgrade-analyzer.binary-validation-result.v1",
        "validation_run_identity": validation_run_identity,
        "result_generation_identity": manifest["result_generation_identity"],
        "oracle_support_manifest_identity": oracle_manifest_identity,
        "truth_set_identity": truth_set_identity,
        "validation_policy_version": POLICY_VERSION,
        "status": "passed" if not issues else "failed",
        "issue_count": len(issues),
        "issues": issues,
        "domain_summary": dict(domain_counts),
        "helper_identities": helper_identities,
        "production_identity_influence": "none_validation_attachment_only",
    }
    validation_dir = generation / "validation"
    validation_dir.mkdir(exist_ok=True)
    destination = validation_dir / f"{validation_run_identity}.json"
    encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    if destination.exists() and destination.read_text(encoding="utf-8") != encoded:
        raise BinaryValidationError("BINARY_VALIDATION_IDENTITY_COLLISION", str(destination))
    destination.write_text(encoded, encoding="utf-8")
    return {**result, "validation_result_path": str(destination)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Validate a binary generation independently")
    parser.add_argument("--config", required=True)
    parser.add_argument("--generation-directory", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args(argv)
    result = validate_generation(_load_json(args.config), args.generation_directory)
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
