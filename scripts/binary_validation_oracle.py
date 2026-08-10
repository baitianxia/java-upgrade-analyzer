#!/usr/bin/env python3
"""Independent validation of a completed binary generation.

The validator consumes raw artifacts, target-JDK observations and immutable
generation sidecars.  It does not call the production ASM parser, provider
resolver, member resolver, dispatch resolver, decision engine or tracer.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, urlparse
import xml.etree.ElementTree as ET
import zipfile
import zlib

from binary_first_contract import BinaryFirstContractError, canonical_identity
from binary_tool_execution import execute_binary_tool
from path_runtime import short_temporary_directory
from final_artifact_edge_oracle import LINKER_BOOTSTRAP_OWNERS, scan_final_artifact


ORACLE_SOURCE = Path(__file__).with_name("java") / "RuntimeOutcomeOracle.java"
SUPPORT_MANIFEST = Path(__file__).with_name("binary_first_support_manifest.json")
POLICY_VERSION = "binary-independent-validation-v1"
_ORACLE_RECONCILIATION_KIND_CODES = {
    "provider_binding": 1,
    "class_definition": 2,
    "member_resolution": 3,
    "dispatch_resolution": 4,
    "type_resolution": 5,
    "class_initialization_resolution": 6,
    "linkage_resolution": 7,
    "resource_selection": 8,
}
_ORACLE_SOURCE_FILE_LANGUAGES = {
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin_script",
    ".scala": "scala", ".groovy": "groovy",
}
_ORACLE_XML_DOCTYPE = re.compile(
    br"<!DOCTYPE\s+[^>]+>", re.IGNORECASE | re.DOTALL
)
_ORACLE_ALLOWED_MYBATIS_DTDS = (
    b"mybatis.org/dtd/mybatis-3-mapper.dtd",
    b"mybatis.org/dtd/mybatis-3-config.dtd",
)


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
    if name.lower().endswith(".xml"):
        return "runtime_topology"
    if name.startswith("META-INF/dubbo/"):
        return "runtime_topology"
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
    if name.lower().endswith(".xml"):
        normalized = content.decode("utf-8", errors="surrogateescape").replace(
            "\r\n", "\n"
        ).replace("\r", "\n")
        return hashlib.sha256(
            normalized.encode("utf-8", errors="surrogateescape")
        ).hexdigest()
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
    if name.lower().endswith(".xml"):
        return _independent_xml_facts(content)
    if not (
        name.startswith("META-INF/services/")
        or name.startswith("META-INF/dubbo/")
        or (name.startswith("META-INF/spring/") and name.endswith(".imports"))
    ):
        return []
    return [
        ["ordered_entry", value]
        for raw in content.decode("utf-8", errors="replace").splitlines()
        for value in [raw.split("#", 1)[0].strip()]
        if value
    ]


def _independent_xml_facts(content: bytes) -> list[list[str]]:
    """Oracle-side XML registration inventory built directly from archive bytes."""
    if len(content) > 4 * 1024 * 1024:
        return [["xml_parse_gap", "resource_too_large"]]
    doctype = _ORACLE_XML_DOCTYPE.search(content)
    if b"<!ENTITY" in content.upper() or (
        doctype and b"[" in doctype.group(0)
    ):
        return [["xml_parse_gap", "doctype_or_entity_rejected"]]
    if doctype:
        declaration = doctype.group(0).lower()
        if not any(
            marker in declaration for marker in _ORACLE_ALLOWED_MYBATIS_DTDS
        ):
            return [["xml_parse_gap", "doctype_or_entity_rejected"]]
        content = content[:doctype.start()] + content[doctype.end():]
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return [["xml_parse_gap", "malformed_xml"]]

    def local(tag: Any) -> str:
        return str(tag or "").split("}")[-1].split(":")[-1]

    def nested_attribute(node: Any, child_tag: str, *names: str) -> str:
        for name in names:
            value = str(node.attrib.get(name) or "").strip()
            if value:
                return value
        for child in node:
            if local(child.tag) != child_tag:
                continue
            for name in names:
                value = str(child.attrib.get(name) or "").strip()
                if value:
                    return value
            value = str(child.text or "").strip()
            if value:
                return value
        return ""

    result = [["xml_root", local(root.tag)]]
    bean_types: dict[str, str] = {}
    bean_nodes: dict[str, Any] = {}
    for node in root.iter():
        if local(node.tag) != "bean":
            continue
        identity = str(node.attrib.get("id") or node.attrib.get("name") or "").strip()
        class_name = str(node.attrib.get("class") or "").strip()
        if identity and class_name:
            bean_types[identity] = class_name
            bean_nodes[identity] = node
            result.append(["spring_bean_class", f"{identity}|{class_name}"])
            if str(node.attrib.get("primary") or "").strip().lower() == "true":
                result.append(["spring_bean_primary", f"{identity}|{class_name}"])
            init_method = str(node.attrib.get("init-method") or "").strip()
            if init_method:
                result.append([
                    "spring_init_method",
                    f"{identity}|{class_name}|{init_method}",
                ])

    for node in root.iter():
        tag = local(node.tag)
        if tag == "class" and local(root.tag) == "persistence":
            managed_class = str(node.text or "").strip()
            if managed_class:
                result.append(["jpa_managed_class", managed_class])
        if tag == "component-scan":
            base_package = str(node.attrib.get("base-package") or "").strip()
            if base_package:
                result.append(["spring_component_scan", base_package])
        if tag == "scan":
            base_package = str(node.attrib.get("base-package") or "").strip()
            if base_package:
                result.append(["mybatis_mapper_scan", base_package])
        if tag == "plugin":
            interceptor = str(node.attrib.get("interceptor") or "").strip()
            if interceptor:
                result.append(["mybatis_plugin_registration", interceptor])
        if tag == "typeHandler":
            handler = str(node.attrib.get("handler") or "").strip()
            java_type = str(node.attrib.get("javaType") or "").strip()
            if handler:
                result.append([
                    "mybatis_type_handler_registration",
                    f"{java_type}|{handler}",
                ])
        if tag == "scheduled":
            reference = str(node.attrib.get("ref") or "").strip()
            method = str(node.attrib.get("method") or "").strip()
            target = str(node.attrib.get("target") or "").strip()
            if not reference and target:
                if "." in target and not target.startswith("&"):
                    reference, target_method = target.rsplit(".", 1)
                    method = method or target_method
                else:
                    reference = target
            if reference and method:
                result.append([
                    "spring_scheduled_method",
                    f"{reference}|{bean_types.get(reference, '')}|{method}",
                ])
        if tag == "mapper":
            namespace = str(node.attrib.get("namespace") or "").strip()
            if namespace:
                result.append(["mybatis_mapper_namespace", namespace])
        if tag in {"mapper", "select", "insert", "update", "delete"}:
            statement = str(node.attrib.get("id") or "").strip()
            if statement:
                result.append(["mybatis_statement", statement])
                statement_handler = str(
                    node.attrib.get("typeHandler") or ""
                ).strip()
                if statement_handler:
                    result.append([
                        "mybatis_statement_type_handler",
                        f"{statement}|{statement_handler}",
                    ])
    for identity, node in bean_nodes.items():
        for child in node:
            if local(child.tag) != "property":
                continue
            property_name = str(child.attrib.get("name") or "").strip()
            property_ref = nested_attribute(
                child, "ref", "ref", "bean", "local"
            )
            if property_name and property_ref:
                result.append([
                    "spring_bean_property_ref",
                    "|".join((
                        identity,
                        bean_types.get(identity, ""),
                        property_name,
                        property_ref,
                        bean_types.get(property_ref, ""),
                    )),
                ])

    quartz_factories = {
        "org.springframework.scheduling.quartz.MethodInvokingJobDetailFactoryBean",
        "org.springframework.scheduling.quartz.JobDetailFactoryBean",
    }
    for identity, node in bean_nodes.items():
        if bean_types.get(identity) not in quartz_factories:
            continue
        reference = ""
        method = ""
        for property_node in node:
            if local(property_node.tag) != "property":
                continue
            if property_node.attrib.get("name") == "targetObject":
                reference = nested_attribute(
                    property_node, "ref", "ref", "bean", "local"
                )
            elif property_node.attrib.get("name") == "targetMethod":
                method = nested_attribute(property_node, "value", "value")
        if reference and method:
            result.append([
                "spring_quartz_method",
                f"{reference}|{bean_types.get(reference, '')}|{method}",
            ])
    return result


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
    completed = execute_binary_tool(
        [str(javac), "-encoding", "UTF-8", "-source", "8", "-target", "8", "-d", str(destination), str(ORACLE_SOURCE)],
        stage="binary_oracle.compile",
        reason_prefix="BINARY_ORACLE_COMPILE",
        timeout_seconds=60,
    )
    if not completed.succeeded:
        raise BinaryValidationError(
            "BINARY_ORACLE_COMPILE_FAILED",
            json.dumps(completed.failure.to_mapping(), ensure_ascii=False),
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
            completed = execute_binary_tool(
                [
                    str(java), "-Xverify:all", "-cp", str(temp / "helper"),
                    "RuntimeOutcomeOracle", str(classpath_file), str(classes_file),
                ],
                stage="binary_oracle.runtime_observation",
                reason_prefix="BINARY_ORACLE_EXECUTION",
                timeout_seconds=300,
                require_stdout=True,
            )
            if not completed.succeeded:
                raise BinaryValidationError(
                    "BINARY_ORACLE_EXECUTION_FAILED",
                    json.dumps(completed.failure.to_mapping(), ensure_ascii=False),
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


def _provider_resource_path(value: str) -> Path | None:
    resource = str(value or "")
    if resource.startswith("jar:"):
        resource = resource[4:].split("!/", 1)[0]
    return _file_url_path(resource)


def _oracle_provider_location(observation: Mapping[str, Any]) -> str:
    """Return independent provider evidence for classpath and named modules.

    ``ClassLoader.getResource`` is not authoritative for every resolved JDK
    module.  In particular, classes owned by ``jdk.jdi`` and ``jdk.attach``
    can load successfully while a child URLClassLoader cannot obtain their
    class resource.  Their protection-domain code source still identifies the
    exact ``jrt:`` module.  Prefer the resource URL because it identifies an
    archive entry, then use the code-source location as the JVM-supported
    fallback instead of declaring a valid platform resolution false.
    """
    resource = str(observation.get("provider_resource_url") or "")
    if resource and not resource.startswith("<resource-error:"):
        return resource
    code_source = str(observation.get("provider_url") or "")
    if code_source and not code_source.startswith("<"):
        return code_source
    return ""


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
    pending_member: tuple[str, str, int] | None = None
    type_edges = set()
    init_edges = set()
    clinit_classes = set()
    semantic_instructions = set()
    declared_members = set()

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
                declared_members.add((owner, "method", member_name, descriptor, 0x0008))
                pending_member = None
            elif "(" in value:
                before = value.split("(", 1)[0].split()[-1].strip('"')
                simple = owner.rsplit("/", 1)[-1]
                member_name = "<init>" if before in {simple, owner.replace("/", ".")} else before
                descriptor = ""
                pending_member = ("method", member_name, access_flags(value))
            else:
                field_name = value.split("=", 1)[0].split()[-1].strip('"')
                pending_member = ("field", field_name, access_flags(value))
            continue
        stripped = line.strip()
        if stripped.startswith("descriptor:") and pending_member:
            descriptor = stripped.split(":", 1)[1].strip()
            member_kind, member_name, member_flags = pending_member
            declared_members.add(
                (owner, member_kind, member_name, descriptor, member_flags)
            )
            pending_member = None
            continue
        instruction = _ORACLE_INSTRUCTION.match(line)
        if not instruction or not owner or not member_name or not descriptor:
            continue
        bci = int(instruction.group(1))
        opcode = instruction.group(2)
        rest = instruction.group(3)
        comment = rest.split("//", 1)[1].strip() if "//" in rest else ""
        semantic_instructions.add((
            owner, member_name, descriptor, bci, opcode, comment,
        ))
        target = ""
        class_match = re.match(r"class\s+\"?([^\"\s]+)\"?", comment)
        if class_match:
            target = class_match.group(1)
            # Keep the constant-pool class name exactly as javap renders it.
            # CHECKCAST and MULTIANEWARRAY may target an array descriptor (for
            # example ``[Ljava/lang/String;``). ASM exposes that same value to
            # the production extractor, so reducing it to the element type
            # would make this independent oracle validate the wrong JVM fact.
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
        "semantic_instructions": semantic_instructions,
        "declared_members": declared_members,
    }


def _scan_structural_edges(
    artifact: Path, inventory: Mapping[str, Any], javap: str
) -> dict[str, Any]:
    combined = {
        "type_edges": set(), "class_init_edges": set(),
        "clinit_classes": set(), "semantic_instructions": set(),
        "declared_members": set(),
    }
    failures = []
    with short_temporary_directory(prefix="structural-oracle") as temp_text:
        temp = Path(temp_text)
        try:
            archive = zipfile.ZipFile(artifact)
        except (OSError, zipfile.BadZipFile) as error:
            return {**combined, "failures": [str(error)]}
        with archive:
            pending = []
            for index, (class_name, entry) in enumerate(sorted(inventory["classes"].items())):
                class_path = temp / f"class-{index:06d}.class"
                class_path.write_bytes(archive.read(entry))
                pending.append((entry, class_path))
            for offset in range(0, len(pending), 256):
                batch = pending[offset:offset + 256]
                completed = execute_binary_tool(
                    [
                        javap, "-c", "-p", "-s",
                        *[str(class_path) for _entry, class_path in batch],
                    ],
                    stage="binary_oracle.structural_javap",
                    reason_prefix="BINARY_ORACLE_JAVAP",
                    timeout_seconds=120,
                    require_stdout=True,
                )
                if not completed.succeeded:
                    failures.append(
                        f"{batch[0][0]}..{batch[-1][0]}:"
                        f"{json.dumps(completed.failure.to_mapping(), ensure_ascii=False)}"
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
    semantic_instructions = []
    clinit_classes = set()
    declared_members = set()
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
        semantic_instructions.extend(sorted(scanned["semantic_instructions"]))
        declared_members.update(scanned["declared_members"])
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
        "semantic_instructions": sorted(semantic_instructions),
        "declared_members": sorted(declared_members),
    }


def _rows(connection: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(f"SELECT * FROM {table}")]


def _reconciliation(connection: sqlite3.Connection, kind: str) -> list[dict[str, Any]]:
    result = []
    for row in connection.execute(
        "SELECT record_count,payload_zlib FROM reconciliation_records WHERE record_kind=?",
        (_ORACLE_RECONCILIATION_KIND_CODES[kind],),
    ):
        records = json.loads(zlib.decompress(row["payload_zlib"]).decode("utf-8"))
        if len(records) != int(row["record_count"]):
            raise BinaryValidationError(
                "BINARY_ORACLE_RECONCILIATION_CHUNK_COUNT_INVALID", kind
            )
        result.extend(item["payload"] for item in records)
    return result


def _member_tuple(value: str) -> tuple[str, str, str, int]:
    kind, name, descriptor, flags = value.split("|", 3)
    return kind, name, descriptor, int(flags)


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


def _descriptor_return_class(descriptor: str) -> str:
    value = str(descriptor or "")
    marker = value.find(")")
    returned = value[marker + 1:] if marker >= 0 else ""
    return returned[1:-1] if returned.startswith("L") and returned.endswith(";") else ""


def _oracle_type_provider_owner(symbolic_owner: str) -> str:
    """Independently map an array class to the classfile its JVM type needs."""
    value = str(symbolic_owner or "")
    if not value.startswith("["):
        return value
    while value.startswith("["):
        value = value[1:]
    if value.startswith("L") and value.endswith(";"):
        return value[1:-1]
    return ""


def _declared_members(observation: Mapping[str, Any]) -> list[tuple[str, str, str, int]]:
    # Reflection is authoritative when it could enumerate the declaration.
    # javap is only a fallback for classes whose unrelated optional member
    # types prevented exhaustive reflection.  Access-flag renderings can
    # legitimately differ (for example reflection retains ACC_VARARGS while
    # the compact javap parser only records ``public``).  Treating those two
    # rows as distinct creates duplicate logical methods and incorrectly turns
    # a unique framework callback/bean implementation into a possible set.
    result: dict[tuple[str, str, str], tuple[str, str, str, int]] = {}
    for source in ("members", "javap_declared_members"):
        for value in observation.get(source) or ():
            member = _member_tuple(value)
            result.setdefault(member[:3], member)
    return list(result.values())


def _oracle_class_load_ready(observation: Mapping[str, Any] | None) -> bool:
    if not observation:
        return False
    return bool(
        observation.get("status") == "definition_ready"
        or (
            observation.get("status") == "definition_failed"
            and observation.get("failure_phase") == "member_linkage"
        )
    )


def _oracle_aop_pointcut_constraints(expression: str) -> dict[str, Any] | None:
    value = str(expression or "")
    executions = re.findall(
        r"execution\([^)]*?([\w.$*]+)\.([\w$*]+)\s*\(", value
    )
    if not executions:
        return None
    unsupported = bool(
        "||" in value
        or re.search(
            r"(?<!@)\b(?:within|this|target|args|bean|call|get|set|cflow)\s*\(",
            value,
        )
        or re.search(r"@(?:target|args|this)\s*\(", value)
        or re.search(r"!\s*@within\s*\(", value)
    )
    descriptor_set = lambda items: frozenset(
        "L" + item.replace(".", "/") + ";" for item in items
    )
    return {
        "executions": tuple(executions),
        "class_annotations": descriptor_set(
            re.findall(r"(?<!!)@within\(([\w.$]+)\)", value)
        ),
        "method_annotations": descriptor_set(
            re.findall(r"(?<!!)@annotation\(([\w.$]+)\)", value)
        ),
        "excluded_method_annotations": descriptor_set(
            re.findall(r"!\s*@annotation\(([\w.$]+)\)", value)
        ),
        "complete": not unsupported,
    }


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
    if not _oracle_class_load_ready(observation):
        return None
    for member in _declared_members(observation):
        if member[:3] == (kind, name, descriptor):
            return owner, member
    if name == "<init>":
        return None
    if kind == "method" and int(observation.get("modifiers") or 0) & 0x0200:
        # JVM interface method resolution may select a matching public
        # instance method declared by Object before searching superinterfaces.
        object_member = _resolve_member(
            observations, "java/lang/Object", kind, name, descriptor,
            visited | {owner},
        )
        if object_member:
            flags = int(object_member[1][3])
            if flags & 0x0001 and not flags & 0x0008:
                return object_member
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


def _oracle_annotation_values(
    rows: Iterable[str], *, member_rows: bool = False,
) -> dict[Any, dict[str, set[str]]]:
    result: dict[Any, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for raw in rows or ():
        parts = str(raw).split("|", 4 if member_rows else 2)
        if member_rows:
            if len(parts) != 5:
                continue
            name, member_descriptor, annotation, attribute, value = parts
            key = (name, member_descriptor, annotation)
        else:
            if len(parts) != 3:
                continue
            annotation, attribute, value = parts
            key = annotation
        result[key][attribute].add(value)
    return result


def _oracle_condition_status(
    descriptors: Iterable[str],
    values: Mapping[str, Mapping[str, set[str]]],
    *,
    active_profiles: set[str],
    resolved_properties: Mapping[str, str],
    configuration_complete: bool,
    observations: Mapping[str, Mapping[str, Any]],
) -> str:
    unresolved = False
    for descriptor in descriptors:
        attributes = values.get(str(descriptor)) or {}
        flattened = {
            value for items in attributes.values() for value in items
            if value and not value.startswith("<unresolved:")
        }
        if descriptor == "Lorg/springframework/context/annotation/Profile;":
            if flattened and not flattened.intersection(active_profiles):
                return "inactive"
        elif str(descriptor).endswith("/ConditionalOnClass;"):
            classes = {
                value.replace(".", "/") for value in flattened if "." in value or "/" in value
            }
            if classes and not all(name in observations for name in classes):
                return "inactive"
            if not classes:
                unresolved = True
        elif str(descriptor).endswith("/ConditionalOnMissingClass;"):
            classes = {
                value.replace(".", "/") for value in flattened if "." in value or "/" in value
            }
            if classes and not all(name not in observations for name in classes):
                return "inactive"
            if not classes:
                unresolved = True
        elif str(descriptor).endswith("/ConditionalOnProperty;"):
            prefix = str(next(iter(attributes.get("prefix") or ("",)), "") or "").strip()
            if prefix and not prefix.endswith("."):
                prefix += "."
            declared_names = (
                set(attributes.get("name") or ())
                or set(attributes.get("value") or ())
            )
            names = {prefix + str(value) for value in declared_names if str(value)}
            having = str(
                next(iter(attributes.get("havingValue") or ("",)), "") or ""
            )
            match_missing = str(
                next(iter(attributes.get("matchIfMissing") or ("false",)), "false")
            ).lower() == "true"
            if not names:
                unresolved = True
                continue
            for name in names:
                if name not in resolved_properties:
                    if not match_missing:
                        if configuration_complete:
                            return "inactive"
                        unresolved = True
                    continue
                actual = str(resolved_properties[name])
                if not (actual == having if having else actual.lower() != "false"):
                    return "inactive"
        elif str(descriptor).startswith(
            "Lorg/springframework/boot/autoconfigure/condition/Conditional"
        ) or descriptor == "Lorg/springframework/context/annotation/Conditional;":
            unresolved = True
    return "unproven" if unresolved else "active"


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
    semantic_instructions: Iterable[Iterable[Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Independently reconstruct automatic callback roots using target-JVM reflection."""

    issues = []
    candidate_activation_gaps = set()
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
        "spring-boot-launcher", "spring-boot-executable-jar",
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
        or launcher in {
            "spring-boot", "spring_boot", "spring-boot-launcher",
            "spring-boot-executable-jar",
        }
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
    jpa_entity_annotations = {
        "Ljavax/persistence/Entity;", "Ljakarta/persistence/Entity;",
        "Ljavax/persistence/MappedSuperclass;",
        "Ljakarta/persistence/MappedSuperclass;",
    }
    activated_entity_classes = {
        str(value or "").replace(".", "/")
        for value in profile.get("activated_entity_classes") or ()
        if str(value or "").strip()
    }
    for selection in resource_truth:
        for selected in selection.get("selected") or ():
            for key, value in selected.get("semantic_facts") or ():
                if key == "jpa_managed_class" and str(value or "").strip():
                    activated_entity_classes.add(str(value).replace(".", "/"))
    if spring_boot_active:
        for class_name, observation in observations.items():
            if (
                business_owned(observation)
                and set(observation.get("class_annotations") or ()).intersection(
                    jpa_entity_annotations
                )
            ):
                activated_entity_classes.add(class_name)
    active_profiles = {
        str(value or "").strip()
        for value in (current_side.get("runtime_profile") or {}).get(
            "active_profile_identities"
        ) or ()
    }
    resolved_properties = {
        str(key): str(value) for key, value in (
            (current_side.get("runtime_profile") or {}).get(
                "resolved_configuration_properties"
            ) or {}
        ).items()
    }
    configuration_complete = str(
        (current_side.get("runtime_profile") or {}).get(
            "runtime_configuration_coverage_status"
        ) or ""
    ) == "complete"
    component_scan_prefixes = {
        class_name.rsplit("/", 1)[0]
        for class_name in exact_main_classes
        if "/" in class_name and spring_boot_active
    }
    for class_name, observation in observations.items():
        if not business_owned(observation):
            continue
        annotation_values = _oracle_annotation_values(
            observation.get("class_annotation_values") or ()
        )
        component_values = annotation_values.get(
            "Lorg/springframework/context/annotation/ComponentScan;"
        ) or {}
        component_scan_prefixes.update(
            value.replace(".", "/")
            for items in component_values.values() for value in items
            if value and not value.lower().endswith(".class")
        )
    component_annotations = {
        "Lorg/springframework/stereotype/Component;",
        "Lorg/springframework/stereotype/Service;",
        "Lorg/springframework/stereotype/Repository;",
        "Lorg/springframework/stereotype/Controller;",
        "Lorg/springframework/web/bind/annotation/RestController;",
        "Lorg/springframework/context/annotation/Configuration;",
    }
    for class_name, observation in observations.items():
        if (
            set(observation.get("class_annotations") or ()).intersection(
                component_annotations
            )
            and any(
                class_name == prefix or class_name.startswith(prefix + "/")
                for prefix in component_scan_prefixes
            )
        ):
            activated.add(class_name)
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
                        candidate_activation_gaps.add(
                            f"annotation_import:{class_name}:{imported}"
                        )
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
            if not _oracle_class_load_ready(observation):
                continue
            if int(observation.get("modifiers") or 0) & (0x0200 | 0x0400):
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
            class_annotation_values = _oracle_annotation_values(
                observation.get("class_annotation_values") or ()
            )
            member_annotation_values = _oracle_annotation_values(
                observation.get("member_annotation_values") or (),
                member_rows=True,
            )
            class_condition_status = _oracle_condition_status(
                observation.get("class_annotations") or (),
                class_annotation_values,
                active_profiles=active_profiles,
                resolved_properties=resolved_properties,
                configuration_complete=configuration_complete,
                observations=observations,
            )
            for kind, member_name, descriptor, flags in _declared_members(observation):
                if kind != "method":
                    continue
                if flags & 0x0400:
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
                    values_for_member = {
                        annotation: attributes
                        for (value_name, value_descriptor, annotation), attributes
                        in member_annotation_values.items()
                        if value_name == member_name and value_descriptor == descriptor
                    }
                    member_condition_status = _oracle_condition_status(
                        annotation_by_member.get((member_name, descriptor), ()),
                        values_for_member,
                        active_profiles=active_profiles,
                        resolved_properties=resolved_properties,
                        configuration_complete=configuration_complete,
                        observations=observations,
                    )
                    if "inactive" in {
                        class_condition_status, member_condition_status
                    }:
                        continue
                    if conditional and "unproven" in {
                        class_condition_status, member_condition_status
                    }:
                        certainty = "possible"
                        reason = "framework_condition_not_evaluated"
                    elif (
                        entry_kind == "jpa_lifecycle_callback"
                        and class_name not in activated_entity_classes
                    ):
                        certainty = "possible"
                        reason = "entity_lifecycle_activation_unproven"
                    elif entry_kind == "jpa_lifecycle_callback":
                        certainty = "exact"
                        reason = "jpa_entity_registration_proved"
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

    # Reconstruct Spring AMQP's string-named MessageListenerAdapter callback
    # directly from javap output. This intentionally does not consume the ASM
    # instruction facts used by production discovery.
    adapter_owner = (
        "org/springframework/amqp/rabbit/listener/adapter/MessageListenerAdapter"
    )
    instructions_by_member: dict[
        tuple[str, str, str], list[tuple[int, str, str]]
    ] = defaultdict(list)
    for owner, member_name, descriptor, bci, opcode, comment in semantic_instructions:
        instructions_by_member[(
            str(owner), str(member_name), str(descriptor)
        )].append((int(bci), str(opcode), str(comment)))
    for factory_key, instructions in instructions_by_member.items():
        factory_class, factory_member, factory_descriptor = factory_key
        factory_observation = observations.get(factory_class) or {}
        if not _oracle_class_load_ready(factory_observation):
            continue
        instructions.sort()
        callback_names = set()
        for constructor_index, (_bci, opcode, comment) in enumerate(instructions):
            referenced_owner, referenced_name, referenced_descriptor = (
                _javap_reference(comment)
            )
            if not (
                opcode == "invokespecial"
                and referenced_owner == adapter_owner
                and referenced_name == "<init>"
                and "Ljava/lang/String;" in referenced_descriptor
            ):
                continue
            preceding_literals = [
                value.removeprefix("String ")
                for _offset, literal_opcode, value in instructions[
                    max(0, constructor_index - 16):constructor_index
                ]
                if literal_opcode in {"ldc", "ldc_w"}
                and value.startswith("String ")
            ]
            if preceding_literals:
                callback_names.add(preceding_literals[-1])
        if not callback_names:
            continue
        receiver_owners = {
            parameter[1:-1]
            for parameter in (_descriptor_parameters(factory_descriptor) or ())
            if parameter.startswith("L") and parameter.endswith(";")
        }
        factory_active = spring_boot_active and (
            business_owned(factory_observation) or factory_class in activated
        )
        for realm in realms:
            for receiver_owner in receiver_owners:
                callback_candidates = [
                    (name, descriptor)
                    for kind, name, descriptor, _flags in _declared_members(
                        observations.get(receiver_owner) or {}
                    )
                    if kind == "method" and name in callback_names
                ]
                certainty = (
                    "exact"
                    if factory_active and len(callback_candidates) == 1
                    else "possible"
                )
                reason = (
                    "spring_message_listener_adapter_registration"
                    if certainty == "exact"
                    else "spring_message_listener_adapter_activation_unproven"
                )
                for callback_name, callback_descriptor in callback_candidates:
                    expected.add((
                        realm, receiver_owner, callback_name,
                        callback_descriptor, "spring_message_listener",
                        certainty, reason,
                    ))

    activated_resource_names = {
        str(value or "").removeprefix("classpath:").lstrip("/")
        for value in profile.get("activated_resource_names") or ()
        if str(value or "").strip()
    }
    for observation in observations.values():
        if not business_owned(observation):
            continue
        for value in observation.get("class_annotation_resources") or ():
            value = str(value or "")
            if value.startswith("<unresolved:"):
                candidate_activation_gaps.add(f"resource_import:{value}")
            elif value.lower().endswith(".xml"):
                activated_resource_names.add(
                    value.removeprefix("classpath:").lstrip("/")
                )

    for selection in resource_truth:
        resource_name = str(selection.get("name") or "")
        if not resource_name.lower().endswith(".xml"):
            continue
        realm = str(selection.get("realm") or "")
        resource_exact = resource_name in activated_resource_names
        for selected in selection.get("selected") or ():
            for fact_key, raw_value in selected.get("semantic_facts") or ():
                mybatis_callback = {
                    "mybatis_plugin_registration": (
                        "mybatis_plugin_callback", ("intercept",)
                    ),
                    "mybatis_type_handler_registration": (
                        "mybatis_type_handler_callback",
                        ("setParameter", "getResult"),
                    ),
                    "mybatis_statement_type_handler": (
                        "mybatis_type_handler_callback",
                        ("setParameter", "getResult"),
                    ),
                }.get(str(fact_key or ""))
                if mybatis_callback:
                    entry_kind, callback_names = mybatis_callback
                    class_name = str(raw_value or "").rsplit("|", 1)[-1].replace(
                        ".", "/"
                    )
                    candidates = [
                        (name, descriptor)
                        for kind, name, descriptor, _flags in _declared_members(
                            observations.get(class_name) or {}
                        )
                        if kind == "method" and name in callback_names
                    ]
                    certainty = "exact" if resource_exact else "possible"
                    reason = (
                        "mybatis_resource_registration"
                        if resource_exact
                        else "mybatis_resource_activation_unproven"
                    )
                    for name, descriptor in candidates:
                        expected.add((
                            realm, class_name, name, descriptor, entry_kind,
                            certainty, reason,
                        ))
                    continue
                entry_kind = {
                    "spring_init_method": "spring_xml_init_method",
                    "spring_scheduled_method": "spring_xml_scheduled",
                    "spring_quartz_method": "spring_xml_quartz",
                }.get(str(fact_key or ""))
                if not entry_kind:
                    continue
                parts = str(raw_value or "").split("|", 2)
                if len(parts) != 3 or not parts[1] or not parts[2]:
                    continue
                class_name = parts[1].replace(".", "/")
                method_name = parts[2]
                candidates = [
                    (name, descriptor)
                    for kind, name, descriptor, _flags in _declared_members(
                        observations.get(class_name) or {}
                    )
                    if kind == "method" and name == method_name
                ]
                certainty = "exact" if resource_exact and len(candidates) == 1 else "possible"
                reason = (
                    "spring_import_resource_activation"
                    if resource_exact else "spring_xml_activation_unproven"
                )
                for name, descriptor in candidates:
                    expected.add((
                        realm, class_name, name, descriptor,
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
    # Candidate roots intentionally retain incomplete activation evidence and
    # therefore need not be reconstructed as an identical set by an
    # independent mechanism. Only exact roots can create authoritative
    # reachability; those must match byte-for-byte. Candidate consistency is
    # checked later by the closed-world uncertainty reconstruction.
    actual_exact = {item for item in actual if item[5] == "exact"}
    expected_exact = {item for item in expected if item[5] == "exact"}
    if actual_exact != expected_exact:
        issues.append(_validation_issue(
            "entrypoint_discovery", "ORACLE_ENTRYPOINT_SET_MISMATCH",
            missing=sorted(expected_exact - actual_exact),
            extra=sorted(actual_exact - expected_exact),
        ))
    return issues, {
        "exact_entrypoints": [list(item) for item in sorted(expected_exact)],
        "exact_entrypoint_count": len(expected_exact),
        "oracle_candidate_entrypoint_count": len(expected - expected_exact),
        "production_candidate_entrypoint_count": len(actual - actual_exact),
        "candidate_activation_gaps": sorted(candidate_activation_gaps),
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
        (str(realm), provider_owner)
        for realm in entrypoint_realms
        for name in initial_classes
        for provider_owner in (
            _oracle_type_provider_owner(str(name).replace(".", "/")),
        )
        if str(realm) and provider_owner
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
            normalized = _oracle_type_provider_owner(
                str(dependency or "").replace(".", "/")
            )
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
        edge_kind = str(edge["edge_kind"] or "")
        dynamic_bootstrap = (
            edge_kind == "invokedynamic_bootstrap"
            and str(edge["symbolic_owner"] or "").replace("/", ".")
            not in LINKER_BOOTSTRAP_OWNERS
        )
        if edge_kind.startswith("invokedynamic_handle_") or dynamic_bootstrap:
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
        if edge_kind not in {"method", "field"}:
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
    member_resolution_cache: dict[
        tuple[str, str, str, str],
        tuple[str, tuple[str, str, str, int]] | None,
    ] = {}

    def resolve_member_cached(
        owner: str, kind: str, name: str, descriptor: str,
    ) -> tuple[str, tuple[str, str, str, int]] | None:
        key = (owner, kind, name, descriptor)
        if key not in member_resolution_cache:
            member_resolution_cache[key] = _resolve_member(
                observations, owner, kind, name, descriptor,
            )
        return member_resolution_cache[key]

    def dispatch_symbol(
        target: tuple[str, tuple[str, str, str, int]],
    ) -> tuple[str, str, str]:
        declaring, member = target
        _kind, member_name, descriptor, flags = member
        if (
            int(flags) & 0x1000
            and member_name in {
                "begin", "commit", "end", "isEnabled", "shouldCommit",
            }
            and _is_subtype(
                observations, declaring, "jdk/jfr/Event"
            )
        ):
            # The target JVM injects these synthetic methods into Event
            # subclasses at definition time. Their behavior is platform-owned,
            # so dependency impact normalizes them to the JFR base API rather
            # than publishing a nonexistent dependency classfile member.
            return "jdk/jfr/Event", member_name, descriptor
        return declaring, member_name, descriptor

    # Build the full transitive subtype relation once.  The former Oracle
    # repeated a recursive hierarchy walk for every virtual call edge and
    # every runtime class, which made a complete real-project closure
    # quadratic without adding any independent evidence.
    ancestor_cache: dict[str, frozenset[str]] = {}

    def ancestors(class_name: str, visiting: frozenset[str] = frozenset()) -> frozenset[str]:
        cached = ancestor_cache.get(class_name)
        if cached is not None:
            return cached
        if class_name in visiting:
            return frozenset()
        row = observations.get(class_name) or {}
        direct = {
            str(value) for value in [
                row.get("super_name"), *(row.get("interfaces") or ())
            ] if value
        }
        closure = set(direct)
        for parent in direct:
            closure.update(ancestors(parent, visiting | {class_name}))
        result = frozenset(closure)
        ancestor_cache[class_name] = result
        return result

    concrete_subtypes: dict[str, list[str]] = defaultdict(list)
    for class_name, observation in observations.items():
        if not _oracle_class_load_ready(observation):
            continue
        modifiers = int(observation.get("modifiers") or 0)
        if modifiers & (0x0200 | 0x0400):
            continue
        concrete_subtypes[class_name].append(class_name)
        for parent in ancestors(class_name):
            concrete_subtypes[parent].append(class_name)
    for values in concrete_subtypes.values():
        values.sort()
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
        provider_location = _oracle_provider_location(oracle)
        if not provider_location:
            if actual_status == "resolved":
                issues.append(_validation_issue(
                    "provider", "ORACLE_PROVIDER_FALSE_RESOLUTION", realm=realm, class_name=name,
                ))
            continue
        provider_path = _provider_resource_path(provider_location)
        if provider_path is None:
            expected_kind = "platform"
        else:
            expected_kind = "artifact"
        if actual_status != "resolved":
            issues.append(_validation_issue(
                "provider", "ORACLE_PROVIDER_MISSED", realm=realm, class_name=name,
                oracle_provider_url=provider_location,
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
                    realm=realm, class_name=name, oracle_provider_url=provider_location,
                    selected=selected,
                ))
        definition = definitions.get((realm, name))
        production_definition_status = (definition or {}).get(
            "class_definition_status"
        )
        production_class_load_ready = (definition or {}).get(
            "class_load_status"
        ) == "ready"
        oracle_definition_ready = oracle.get("status") == "definition_ready"
        if (
            not definition
            or oracle_definition_ready
            != (production_definition_status == "definition_ready")
        ):
            issues.append(_validation_issue(
                "class_definition", "ORACLE_DEFINITION_READY_MISMATCH",
                realm=realm, class_name=name,
                oracle_status=oracle.get("status"),
                production_status=production_definition_status,
            ))
        if definition and production_class_load_ready != _oracle_class_load_ready(oracle):
            issues.append(_validation_issue(
                "class_definition", "ORACLE_CLASS_LOAD_READY_MISMATCH",
                realm=realm, class_name=name,
                oracle_status=oracle.get("status"),
                oracle_failure_phase=oracle.get("failure_phase"),
                production_class_load_status=definition.get("class_load_status"),
            ))

    member_rows = {row["member_identity"]: row for row in _rows(connection, "members")}
    direct_edges = {row["direct_edge_identity"]: row for row in _rows(connection, "direct_edges")}
    member_resolutions = _reconciliation(connection, "member_resolution")
    for resolution in member_resolutions:
        edge = direct_edges.get(resolution["direct_edge_identity"])
        if not edge or edge["edge_kind"] not in {"method", "field"}:
            continue
        kind = "field" if edge["edge_kind"] == "field" else "method"
        oracle_member = resolve_member_cached(
            edge["symbolic_owner"], kind,
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
    dispatch_target_cache: dict[
        tuple[str, str, str], set[tuple[str, str, str]]
    ] = {}
    for edge_id, edge in direct_edges.items():
        if edge["edge_kind"] != "method" or int(edge["opcode"] or 0) not in {182, 185}:
            continue
        dispatch_key = (
            edge["symbolic_owner"], edge["symbolic_name"],
            edge["symbolic_descriptor"],
        )
        oracle_targets = dispatch_target_cache.get(dispatch_key)
        if oracle_targets is None:
            oracle_targets = set()
            declaration = resolve_member_cached(
                edge["symbolic_owner"], "method", edge["symbolic_name"],
                edge["symbolic_descriptor"],
            )
            declaration_fixed = bool(
                declaration
                and (
                    int(declaration[1][3]) & 0x0010
                    or int(
                        (observations.get(declaration[0]) or {}).get(
                            "modifiers"
                        ) or 0
                    ) & 0x0010
                )
            )
            if not declaration:
                oracle_targets = set()
            elif declaration_fixed:
                oracle_targets.add(dispatch_symbol(declaration))
            else:
                for class_name in concrete_subtypes.get(edge["symbolic_owner"], ()):
                    target = resolve_member_cached(
                        class_name, "method", edge["symbolic_name"],
                        edge["symbolic_descriptor"],
                    )
                    if target:
                        oracle_targets.add(dispatch_symbol(target))
            dispatch_target_cache[dispatch_key] = oracle_targets
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


def _javap_reference(comment: str) -> tuple[str, str, str]:
    match = re.match(
        r"(?:InterfaceMethod|Method)\s+(?:(?P<owner>[\w/$]+)\.)?"
        r'"?(?P<name>[^":]+)"?:(?P<descriptor>\(.*)$',
        str(comment or ""),
    )
    if not match:
        return "", "", ""
    return (
        str(match.group("owner") or ""),
        str(match.group("name") or ""),
        str(match.group("descriptor") or ""),
    )


def _oracle_runtime_semantic_rows(
    observations: Mapping[str, Mapping[str, Any]],
    instructions: Iterable[Iterable[Any]],
) -> set[tuple[str, str, str, str, str, str, str, str]]:
    """Rebuild literal reflection and JDK proxy edges from javap output."""
    grouped: dict[tuple[str, str, str], list[tuple[int, str, str]]] = defaultdict(list)
    for owner, member, descriptor, bci, opcode, comment in instructions:
        grouped[(str(owner), str(member), str(descriptor))].append(
            (int(bci), str(opcode), str(comment))
        )
    result = set()
    reflection_terminals = {
        ("java/lang/reflect/Method", "invoke"),
        ("java/lang/reflect/Constructor", "newInstance"),
        ("java/lang/reflect/Field", "get"),
        ("java/lang/reflect/Field", "set"),
        ("java/lang/invoke/MethodHandle", "invoke"),
        ("java/lang/invoke/MethodHandle", "invokeExact"),
    }
    lookup_kinds = {
        "getMethod": ("method", "reflection_method_invocation"),
        "getDeclaredMethod": ("method", "reflection_method_invocation"),
        "getConstructor": ("method", "reflection_constructor_invocation"),
        "getDeclaredConstructor": ("method", "reflection_constructor_invocation"),
        "getField": ("field", "reflection_field_access"),
        "getDeclaredField": ("field", "reflection_field_access"),
        "findStatic": ("method", "method_handle_invocation"),
        "findVirtual": ("method", "method_handle_invocation"),
        "findSpecial": ("method", "method_handle_invocation"),
        "findConstructor": ("method", "method_handle_invocation"),
        "findGetter": ("field", "method_handle_field_access"),
        "findSetter": ("field", "method_handle_field_access"),
    }
    for caller, rows in grouped.items():
        rows.sort()
        calls = [(*_javap_reference(comment), index) for index, (_bci, _op, comment) in enumerate(rows)]
        terminal_indexes = {
            index for ref_owner, ref_name, _descriptor, index in calls
            if (ref_owner, ref_name) in reflection_terminals
        }
        for ref_owner, ref_name, _ref_descriptor, index in calls:
            if ref_name not in lookup_kinds or not any(
                index < terminal <= index + 48 for terminal in terminal_indexes
            ):
                continue
            member_kind, semantic_kind = lookup_kinds[ref_name]
            window = rows[max(0, index - 32):index]
            strings = [
                (offset, comment.removeprefix("String "))
                for offset, (_bci, opcode, comment) in enumerate(window)
                if opcode in {"ldc", "ldc_w"} and comment.startswith("String ")
            ]
            type_literals = [
                (offset, comment.removeprefix("class ").strip('"'))
                for offset, (_bci, opcode, comment) in enumerate(window)
                if opcode in {"ldc", "ldc_w"} and comment.startswith("class ")
            ]
            for_name_indexes = [
                offset for offset, (_bci, _opcode, comment) in enumerate(window)
                if _javap_reference(comment)[:2] == ("java/lang/Class", "forName")
            ]
            target_owner = ""
            if for_name_indexes:
                preceding = [value for offset, value in strings if offset < for_name_indexes[-1]]
                if preceding:
                    target_owner = preceding[-1].replace(".", "/")
            if not target_owner and strings:
                preceding_types = [
                    value for offset, value in type_literals if offset < strings[-1][0]
                ]
                if preceding_types:
                    target_owner = preceding_types[-1]
            if not target_owner and type_literals:
                target_owner = type_literals[0][1]
            target_name = "<init>" if "Constructor" in ref_name else (
                strings[-1][1] if strings else ""
            )
            candidates = [
                (name, descriptor)
                for kind, name, descriptor, _flags in _declared_members(
                    observations.get(target_owner) or {}
                )
                if kind == member_kind and name == target_name
            ]
            certainty = "exact" if len(candidates) == 1 else "possible"
            for name, descriptor in candidates:
                result.add((semantic_kind, *caller, target_owner, name, descriptor, certainty))

        proxy_calls = [
            index for ref_owner, ref_name, _descriptor, index in calls
            if (ref_owner, ref_name) == ("java/lang/reflect/Proxy", "newProxyInstance")
        ]
        for proxy_index in proxy_calls:
            before = rows[max(0, proxy_index - 32):proxy_index]
            after = rows[proxy_index + 1:proxy_index + 49]
            handler_classes = {
                comment.removeprefix("class ").strip('"')
                for _bci, opcode, comment in before
                if opcode == "new" and comment.startswith("class ")
                and _is_subtype(
                    observations,
                    comment.removeprefix("class ").strip('"'),
                    "java/lang/reflect/InvocationHandler",
                )
            }
            interface_literals = {
                comment.removeprefix("class ").strip('"')
                for _bci, opcode, comment in before
                if opcode in {"ldc", "ldc_w"} and comment.startswith("class ")
            }
            invoked_interfaces = {
                _javap_reference(comment)[0]
                for _bci, opcode, comment in after if opcode == "invokeinterface"
            }
            exact_invocation = bool(interface_literals.intersection(invoked_interfaces))
            candidates = [
                (handler, name, descriptor)
                for handler in handler_classes
                for kind, name, descriptor, _flags in _declared_members(
                    observations.get(handler) or {}
                )
                if kind == "method" and name == "invoke"
            ]
            certainty = "exact" if len(candidates) == 1 and exact_invocation else "possible"
            for handler, name, descriptor in candidates:
                result.add(("dynamic_proxy_callback", *caller, handler, name, descriptor, certainty))
    return result


def _validate_runtime_semantic_overlay(
    generation: Path,
    current_side: Mapping[str, Any],
    current_artifacts: Iterable[Mapping[str, Any]],
    base_observations: Mapping[str, Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
    semantic_instructions: Iterable[Iterable[Any]],
    direct_edges: Iterable[Iterable[Any]],
    resource_truth: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    semantic_instructions = tuple(tuple(item) for item in semantic_instructions)
    payload = _load_json(generation / "binary_runtime_semantic_overlay.json")
    supported_kinds = {
        "reflection_method_invocation", "reflection_constructor_invocation",
        "reflection_field_access", "method_handle_invocation",
        "method_handle_field_access", "dynamic_proxy_callback",
        "mybatis_mapper_proxy_dispatch",
        "spring_transaction_proxy_dispatch",
        "spring_bean_wiring_dispatch", "spring_data_repository_proxy_dispatch",
        "spring_aop_dispatch", "spring_security_filter_dispatch",
        "declarative_http_client_dispatch", "dubbo_spi_dispatch",
        "implicit_data_contract_dispatch",
    }
    actual = {
        (
            str(row.get("semantic_edge_kind") or ""),
            str(row.get("caller_class_name") or ""),
            str(row.get("caller_member_name") or ""),
            str(row.get("caller_descriptor") or ""),
            str(row.get("target_class_name") or ""),
            str(row.get("target_member_name") or ""),
            str(row.get("target_descriptor") or ""),
            str(row.get("path_certainty") or ""),
        )
        for row in payload.get("rows") or ()
        if row.get("semantic_edge_kind") in supported_kinds
    }
    artifact_paths = {
        Path(str(item.get("path") or "")).resolve()
        for item in current_artifacts
        if item.get("path")
    }
    expected = {
        row for row in _oracle_runtime_semantic_rows(
            observations, semantic_instructions
        )
        if _file_url_path(
            str((observations.get(row[4]) or {}).get("provider_url") or "")
        ) in artifact_paths
    }
    namespaces = {
        str(value).replace(".", "/")
        for selection in resource_truth
        for selected in selection.get("selected") or ()
        for key, value in selected.get("semantic_facts") or ()
        if key == "mybatis_mapper_namespace"
    }
    invoked_owners = {
        str(edge[3]).replace(".", "/") for edge in direct_edges
        if len(edge) >= 6 and str(edge[5]).startswith("(")
    }
    runtime_targets = []
    for owner, name, count in (
        ("org/apache/ibatis/binding/MapperProxy", "invoke", 3),
        ("org/apache/ibatis/binding/MapperMethod", "execute", 2),
    ):
        candidates = [
            (member_name, descriptor)
            for kind, member_name, descriptor, _flags in _declared_members(
                observations.get(owner) or {}
            )
            if kind == "method" and member_name == name
            and len(_descriptor_parameters(descriptor) or ()) == count
        ]
        if len(candidates) == 1:
            runtime_targets.append((owner, *candidates[0]))
    mapper_annotation = "Lorg/apache/ibatis/annotations/Mapper;"
    for class_name, observation in observations.items():
        annotated = mapper_annotation in set(observation.get("class_annotations") or ())
        if (
            not (annotated or class_name in namespaces)
            or class_name not in invoked_owners
            or not (int(observation.get("modifiers") or 0) & 0x0200)
        ):
            continue
        certainty = "exact" if annotated else "possible"
        for kind, mapper_name, mapper_descriptor, _flags in _declared_members(observation):
            if kind != "method":
                continue
            for target_owner, target_name, target_descriptor in runtime_targets:
                expected.add((
                    "mybatis_mapper_proxy_dispatch",
                    class_name, mapper_name, mapper_descriptor,
                    target_owner, target_name, target_descriptor, certainty,
                ))

    path_kinds = {
        Path(str(item.get("path") or "")).resolve(): str(item.get("path_kind") or "").lower()
        for item in current_artifacts
    }

    def business_owned(observation):
        path = _file_url_path(str(observation.get("provider_url") or ""))
        return path is not None and path_kinds.get(path) in {
            "application", "application_classes", "business", "business_classes",
        }

    runtime_profile = current_side.get("runtime_profile") or {}
    activated_frameworks = {
        str(value or "").lower()
        for value in (runtime_profile.get("business_entrypoint_profile") or {}).get(
            "activated_frameworks"
        ) or ()
    }
    launcher = str(runtime_profile.get("container_and_launcher_kind") or "").lower()
    spring_active = "spring_boot" in activated_frameworks or launcher in {
        "spring-boot", "spring_boot", "spring-boot-launcher",
        "spring-boot-executable-jar",
    }
    active_profiles = {
        str(value or "") for value in runtime_profile.get("active_profile_identities") or ()
    }
    resolved_properties = {
        str(key): str(value)
        for key, value in (runtime_profile.get("resolved_configuration_properties") or {}).items()
    }
    configuration_complete = str(
        runtime_profile.get("runtime_configuration_coverage_status") or ""
    ) == "complete"
    entry_profile = runtime_profile.get("business_entrypoint_profile") or {}
    scan_prefixes = {
        str(value or "").replace(".", "/")
        for value in entry_profile.get("activated_component_scan_packages") or ()
    }
    main_class = str(entry_profile.get("main_class") or "").replace(".", "/")
    if spring_active and "/" in main_class:
        scan_prefixes.add(main_class.rsplit("/", 1)[0])
    component_scan = "Lorg/springframework/context/annotation/ComponentScan;"
    for class_name, observation in observations.items():
        if not business_owned(observation):
            continue
        values = _oracle_annotation_values(
            observation.get("class_annotation_values") or ()
        ).get(component_scan) or {}
        scan_prefixes.update(
            value.replace(".", "/")
            for items in values.values() for value in items
            if value and not value.lower().endswith(".class")
        )
    active_resources = {
        str(value or "").removeprefix("classpath:").lstrip("/")
        for value in entry_profile.get("activated_resource_names") or ()
    }
    bean_types: dict[str, str] = {}
    primary_bean_types: set[str] = set()
    custom_repository_configuration = False
    for selection in resource_truth:
        resource_name = str(selection.get("name") or "")
        for selected in selection.get("selected") or ():
            for key, value in selected.get("semantic_facts") or ():
                if key == "spring_bean_class":
                    parts = str(value).split("|", 1)
                    if len(parts) == 2:
                        bean_types[parts[1].replace(".", "/")] = (
                            "exact" if resource_name in active_resources else "possible"
                        )
                elif key == "spring_bean_primary":
                    parts = str(value).split("|", 1)
                    if len(parts) == 2:
                        primary_bean_types.add(parts[1].replace(".", "/"))
    component_annotations = {
        "Lorg/springframework/stereotype/Component;",
        "Lorg/springframework/stereotype/Service;",
        "Lorg/springframework/stereotype/Repository;",
        "Lorg/springframework/stereotype/Controller;",
        "Lorg/springframework/web/bind/annotation/RestController;",
        "Lorg/springframework/context/annotation/Configuration;",
    }
    for class_name, observation in observations.items():
        descriptors = set(observation.get("class_annotations") or ())
        repository_attributes = _oracle_annotation_values(
            observation.get("class_annotation_values") or ()
        ).get(
            "Lorg/springframework/data/jpa/repository/config/EnableJpaRepositories;"
        ) or {}
        if {"repositoryBaseClass", "repositoryFactoryBeanClass"}.intersection(
            repository_attributes
        ):
            custom_repository_configuration = True
        if not descriptors.intersection(component_annotations):
            continue
        condition = _oracle_condition_status(
            descriptors,
            _oracle_annotation_values(observation.get("class_annotation_values") or ()),
            active_profiles=active_profiles,
            resolved_properties=resolved_properties,
            configuration_complete=configuration_complete,
            observations=observations,
        )
        if condition == "inactive":
            continue
        discovered = business_owned(observation) or any(
            class_name == prefix or class_name.startswith(prefix + "/")
            for prefix in scan_prefixes
        )
        bean_types[class_name] = (
            "exact" if condition == "active" and discovered else "possible"
        )
        if "Lorg/springframework/context/annotation/Primary;" in descriptors:
            primary_bean_types.add(class_name)
    bean_annotation = "Lorg/springframework/context/annotation/Bean;"
    new_types_by_factory: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for owner, member_name, descriptor, _bci, opcode, comment in semantic_instructions:
        if str(opcode) != "new" or not str(comment).startswith("class "):
            continue
        new_types_by_factory[(
            str(owner), str(member_name), str(descriptor)
        )].add(str(comment).removeprefix("class ").strip('"'))
    for class_name, observation in observations.items():
        member_annotations = _oracle_member_annotations(observation)
        for kind, member_name, descriptor, _flags in _declared_members(observation):
            annotations = set(member_annotations.get((member_name, descriptor), ()))
            if kind != "method" or bean_annotation not in annotations:
                continue
            returned = _descriptor_return_class(descriptor)
            if returned:
                compatible_constructions = {
                    candidate
                    for candidate in new_types_by_factory.get(
                        (class_name, member_name, descriptor), ()
                    )
                    if candidate == returned
                    or _is_subtype(observations, candidate, returned)
                }
                registered_type = (
                    next(iter(compatible_constructions))
                    if len(compatible_constructions) == 1 else returned
                )
                if (
                    len(compatible_constructions) != 1
                    and int((observations.get(returned) or {}).get("modifiers") or 0)
                    & 0x0200
                ):
                    continue
                bean_types[registered_type] = (
                    "exact" if business_owned(observation) else "possible"
                )
                if "Lorg/springframework/context/annotation/Primary;" in annotations:
                    primary_bean_types.add(registered_type)

    bean_wiring_candidate_evidence: dict[tuple[str, ...], dict[str, Any]] = {}
    for edge in direct_edges:
        if len(edge) < 8 or not str(edge[5]).startswith("("):
            continue
        caller_class = str(edge[0]).replace(".", "/")
        caller_name, caller_descriptor = str(edge[1]), str(edge[2])
        target_interface = str(edge[3]).replace(".", "/")
        target_name, target_descriptor = str(edge[4]), str(edge[5])
        interface_observation = observations.get(target_interface) or {}
        if int(interface_observation.get("modifiers") or 0) & 0x0200:
            implementations = []
            for implementation, activation in bean_types.items():
                if not _is_subtype(observations, implementation, target_interface):
                    continue
                candidates = [
                    (name, descriptor)
                    for kind, name, descriptor, _flags in _declared_members(
                        observations.get(implementation) or {}
                    )
                    if kind == "method" and name == target_name
                    and descriptor == target_descriptor
                ]
                implementations.extend(
                    (
                        implementation, name, descriptor, activation,
                        implementation in primary_bean_types,
                    )
                    for name, descriptor in candidates
                )
            primary_implementations = [
                item for item in implementations if item[4]
            ]
            selected_implementations = (
                primary_implementations
                if len(primary_implementations) == 1 else implementations
            )
            for implementation, name, descriptor, activation, _primary in (
                selected_implementations
            ):
                expected_row = (
                    "spring_bean_wiring_dispatch",
                    caller_class, caller_name, caller_descriptor,
                    implementation, name, descriptor,
                    (
                        "exact"
                        if len(selected_implementations) == 1
                        and spring_active and activation == "exact"
                        else "possible"
                    ),
                )
                expected.add(expected_row)
                bean_wiring_candidate_evidence[expected_row[:7]] = {
                    "interface": target_interface,
                    "spring_active": spring_active,
                    "candidates": [
                        {
                            "implementation": candidate[0],
                            "member_name": candidate[1],
                            "descriptor": candidate[2],
                            "activation": candidate[3],
                            "primary": candidate[4],
                        }
                        for candidate in implementations
                    ],
                    "selected_candidate_count": len(selected_implementations),
                }

        if _is_subtype(
            observations, target_interface,
            "org/springframework/data/repository/Repository",
        ) and not custom_repository_configuration:
            parameter_count = len(_descriptor_parameters(target_descriptor) or ())
            candidates = [
                (name, descriptor)
                for kind, name, descriptor, _flags in _declared_members(
                    observations.get(
                        "org/springframework/data/jpa/repository/support/SimpleJpaRepository"
                    ) or {}
                )
                if kind == "method" and name == target_name
                and len(_descriptor_parameters(descriptor) or ()) == parameter_count
            ]
            for name, descriptor in candidates:
                expected.add((
                    "spring_data_repository_proxy_dispatch",
                    caller_class, caller_name, caller_descriptor,
                    "org/springframework/data/jpa/repository/support/SimpleJpaRepository",
                    name, descriptor,
                    "exact" if spring_active and len(candidates) == 1 else "possible",
                ))

    aspect_annotation = "Lorg/aspectj/lang/annotation/Aspect;"
    advice_annotations = {
        "Lorg/aspectj/lang/annotation/Before;",
        "Lorg/aspectj/lang/annotation/After;",
        "Lorg/aspectj/lang/annotation/Around;",
        "Lorg/aspectj/lang/annotation/AfterReturning;",
        "Lorg/aspectj/lang/annotation/AfterThrowing;",
    }
    for aspect_name, observation in observations.items():
        if aspect_annotation not in set(observation.get("class_annotations") or ()):
            continue
        annotation_values = _oracle_annotation_values(
            observation.get("member_annotation_values") or (), member_rows=True
        )
        for kind, advice_name, advice_descriptor, _flags in _declared_members(observation):
            if kind != "method":
                continue
            values = {
                value
                for (name, descriptor, annotation), attributes in annotation_values.items()
                if name == advice_name and descriptor == advice_descriptor
                and annotation in advice_annotations
                for items in attributes.values() for value in items
            }
            pointcuts = [
                parsed for value in values
                if (parsed := _oracle_aop_pointcut_constraints(value))
            ]
            for pointcut in pointcuts:
                for owner_pattern, method_pattern in pointcut["executions"]:
                    owner_re = re.compile(
                        "^" + re.escape(owner_pattern.replace(".", "/")).replace(r"\*", ".*") + "$"
                    )
                    method_re = re.compile(
                        "^" + re.escape(method_pattern).replace(r"\*", ".*") + "$"
                    )
                    for join_owner, join_observation in observations.items():
                        if not owner_re.match(join_owner):
                            continue
                        class_annotations = set(
                            join_observation.get("class_annotations") or ()
                        )
                        if not pointcut["class_annotations"].issubset(
                            class_annotations
                        ):
                            continue
                        annotations_by_member = _oracle_member_annotations(
                            join_observation
                        )
                        for join_kind, join_name, join_descriptor, _join_flags in _declared_members(
                            join_observation
                        ):
                            member_annotations = set(
                                annotations_by_member.get(
                                    (join_name, join_descriptor), ()
                                )
                            )
                            if (
                                join_kind != "method"
                                or join_name in {"<init>", "<clinit>"}
                                or not method_re.match(join_name)
                                or not pointcut["method_annotations"].issubset(
                                    member_annotations
                                )
                                or pointcut["excluded_method_annotations"].intersection(
                                    member_annotations
                                )
                            ):
                                continue
                            expected.add((
                                "spring_aop_dispatch",
                                join_owner, join_name, join_descriptor,
                                aspect_name, advice_name, advice_descriptor,
                                (
                                    "exact"
                                    if pointcut["complete"] and spring_active
                                    and business_owned(observation)
                                    else "possible"
                                ),
                            ))

    semantic_by_caller: dict[tuple[str, str, str], list[tuple[int, str, str]]] = defaultdict(list)
    for owner, member, descriptor, bci, opcode, comment in semantic_instructions:
        semantic_by_caller[(str(owner), str(member), str(descriptor))].append(
            (int(bci), str(opcode), str(comment))
        )
    bean_methods = {
        (class_name, member_name, descriptor)
        for class_name, observation in observations.items()
        for (member_name, descriptor), annotations in _oracle_member_annotations(observation).items()
        if bean_annotation in annotations
        and _descriptor_return_class(descriptor) in {
            "org/springframework/security/web/SecurityFilterChain",
            "javax/servlet/Filter", "jakarta/servlet/Filter",
        }
    }
    for bean_method in bean_methods:
        instructions_for_method = semantic_by_caller.get(bean_method) or ()
        has_registration = any(
            _javap_reference(comment)[1] in {
                "addFilter", "addFilterBefore", "addFilterAfter", "addFilterAt",
            }
            for _bci, _opcode, comment in instructions_for_method
        )
        if not has_registration:
            continue
        filter_types = {
            comment.removeprefix("class ").strip('"')
            for _bci, opcode, comment in instructions_for_method
            if opcode == "new" and comment.startswith("class ")
            and (
                _is_subtype(
                    observations, comment.removeprefix("class ").strip('"'),
                    "javax/servlet/Filter",
                )
                or _is_subtype(
                    observations, comment.removeprefix("class ").strip('"'),
                    "jakarta/servlet/Filter",
                )
            )
        }
        bean_observation = observations.get(bean_method[0]) or {}
        for filter_type in filter_types:
            for kind, callback_name, callback_descriptor, _flags in _declared_members(
                observations.get(filter_type) or {}
            ):
                if kind == "method" and callback_name == "doFilter":
                    expected.add((
                        "spring_security_filter_dispatch",
                        *bean_method,
                        filter_type, callback_name, callback_descriptor,
                        "exact" if spring_active and business_owned(bean_observation) else "possible",
                    ))

    feign_annotations = {
        "Lorg/springframework/cloud/openfeign/FeignClient;",
        "Lfeign/RequestLine;",
    }
    feign_targets = []
    for owner in (
        "feign/SynchronousMethodHandler",
        "feign/InvocationHandlerFactory$Default",
    ):
        feign_targets.extend(
            (owner, name, descriptor)
            for kind, name, descriptor, _flags in _declared_members(
                observations.get(owner) or {}
            )
            if kind == "method" and name == "invoke"
        )
    for client_name, observation in observations.items():
        if not feign_annotations.intersection(
            set(observation.get("class_annotations") or ())
        ):
            continue
        certainty = "exact" if spring_active and feign_targets else "possible"
        for kind, client_method, client_descriptor, _flags in _declared_members(
            observation
        ):
            if kind != "method":
                continue
            for target_owner, target_name, target_descriptor in feign_targets:
                expected.add((
                    "declarative_http_client_dispatch",
                    client_name, client_method, client_descriptor,
                    target_owner, target_name, target_descriptor, certainty,
                ))

    dubbo_providers: dict[tuple[str, str], set[str]] = defaultdict(set)
    dubbo_prefixes = (
        "META-INF/dubbo/internal/",
        "META-INF/dubbo/external/",
        "META-INF/dubbo/",
    )
    for selection in resource_truth:
        resource_name = str(selection.get("name") or "")
        prefix = next(
            (value for value in dubbo_prefixes if resource_name.startswith(value)),
            "",
        )
        if not prefix:
            continue
        service = resource_name[len(prefix):].replace(".", "/")
        realm = str(selection.get("realm") or "")
        for selected in selection.get("selected") or ():
            for key, value in selected.get("semantic_facts") or ():
                if key != "ordered_entry":
                    continue
                implementation = str(value).split("=", 1)[-1].strip().replace(
                    ".", "/"
                )
                if implementation:
                    dubbo_providers[(realm, service)].add(implementation)
    extension_loader_calls = {
        (
            str(edge[0]).replace(".", "/"), str(edge[1]), str(edge[2])
        )
        for edge in direct_edges
        if len(edge) >= 6
        and str(edge[3]).replace(".", "/")
        == "org/apache/dubbo/common/extension/ExtensionLoader"
        and str(edge[4]) in {
            "getExtension", "getAdaptiveExtension", "getActivateExtension",
        }
        and str(edge[5]).startswith("(")
    }
    dubbo_certainty = "exact" if len(dubbo_providers) == 1 else "possible"
    for caller in extension_loader_calls:
        for (_realm, _service), implementations in dubbo_providers.items():
            for implementation in implementations:
                for kind, target_name, target_descriptor, _flags in _declared_members(
                    observations.get(implementation) or {}
                ):
                    if kind == "method" and target_name not in {"<init>", "<clinit>"}:
                        expected.add((
                            "dubbo_spi_dispatch", *caller,
                            implementation, target_name, target_descriptor,
                            dubbo_certainty,
                        ))

    data_binding_annotations = {
        "Lorg/springframework/web/bind/annotation/RequestMapping;",
        "Lorg/springframework/web/bind/annotation/GetMapping;",
        "Lorg/springframework/web/bind/annotation/PostMapping;",
        "Lorg/springframework/web/bind/annotation/PutMapping;",
        "Lorg/springframework/web/bind/annotation/PatchMapping;",
        "Lorg/springframework/web/bind/annotation/DeleteMapping;",
    }

    def descriptor_owner(descriptor: str) -> str:
        value = str(descriptor or "")
        return value[1:-1] if value.startswith("L") and value.endswith(";") else ""

    binding_callers: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    for class_name, observation in observations.items():
        member_annotations = _oracle_member_annotations(observation)
        for kind, member_name, member_descriptor, _flags in _declared_members(
            observation
        ):
            if kind != "method" or not data_binding_annotations.intersection(
                member_annotations.get((member_name, member_descriptor), ())
            ):
                continue
            descriptors = list(_descriptor_parameters(member_descriptor) or ())
            marker = member_descriptor.find(")")
            if marker >= 0:
                descriptors.append(member_descriptor[marker + 1:])
            for descriptor in descriptors:
                owner = descriptor_owner(descriptor)
                if owner:
                    binding_callers[owner].add(
                        (class_name, member_name, member_descriptor)
                    )

    decisions_payload = _load_json(generation / "binary_decisions.json")
    decisions = [
        *(decisions_payload.get("authoritative_change_facts") or ()),
        *(decisions_payload.get("diagnostic_candidate_facts") or ()),
    ]
    for decision in decisions:
        scope = decision.get("fact_scope") or {}
        if scope.get("member_kind") != "field":
            continue
        owner = str(scope.get("class_name") or "").replace(".", "/")
        target_name = str(scope.get("member_name") or "")
        target_descriptor = str(scope.get("descriptor") or "")
        if not owner or not target_name:
            continue
        current_targets = [
            (name, descriptor)
            for kind, name, descriptor, _flags in _declared_members(
                observations.get(owner) or {}
            )
            if kind == "field" and name == target_name
        ]
        if not current_targets:
            base_targets = [
                (name, descriptor)
                for kind, name, descriptor, _flags in _declared_members(
                    base_observations.get(owner) or {}
                )
                if kind == "field" and name == target_name
            ]
            current_targets = base_targets or [(target_name, target_descriptor)]
        for caller in binding_callers.get(owner, ()):
            for name, descriptor in current_targets:
                expected.add((
                    "implicit_data_contract_dispatch", *caller,
                    owner, name, descriptor, "exact",
                ))

    transaction_targets = []
    for owner, name, count in (
        ("org/springframework/transaction/interceptor/TransactionInterceptor", "invoke", 1),
        ("org/springframework/transaction/interceptor/TransactionAspectSupport", "invokeWithinTransaction", 3),
        ("org/springframework/aop/framework/ReflectiveMethodInvocation", "proceed", 0),
    ):
        candidates = [
            (member_name, descriptor)
            for kind, member_name, descriptor, _flags in _declared_members(
                observations.get(owner) or {}
            )
            if kind == "method" and member_name == name
            and len(_descriptor_parameters(descriptor) or ()) == count
        ]
        if len(candidates) == 1:
            transaction_targets.append((owner, *candidates[0]))
    transactional = "Lorg/springframework/transaction/annotation/Transactional;"
    for class_name, observation in observations.items():
        if not business_owned(observation):
            continue
        class_tx = transactional in set(observation.get("class_annotations") or ())
        member_annotations = _oracle_member_annotations(observation)
        for kind, member_name, member_descriptor, _flags in _declared_members(observation):
            if kind != "method" or not (
                class_tx or transactional in member_annotations.get(
                    (member_name, member_descriptor), ()
            )):
                continue
            certainty = (
                "exact" if spring_active and len(transaction_targets) == 3 else "possible"
            )
            for target_owner, target_name, target_descriptor in transaction_targets:
                expected.add((
                    "spring_transaction_proxy_dispatch",
                    class_name, member_name, member_descriptor,
                    target_owner, target_name, target_descriptor, certainty,
                ))
    issues = []
    actual_exact = {item for item in actual if item[7] == "exact"}
    expected_exact = {item for item in expected if item[7] == "exact"}
    if actual_exact != expected_exact:
        expected_by_edge = {item[:7]: item[7] for item in expected}
        actual_by_edge = {item[:7]: item[7] for item in actual}
        certainty_conflicts = [
            {
                "edge": list(edge),
                "oracle_certainty": expected_by_edge[edge],
                "production_certainty": actual_by_edge[edge],
                "oracle_candidate_evidence": bean_wiring_candidate_evidence.get(edge),
            }
            for edge in sorted(set(expected_by_edge).intersection(actual_by_edge))
            if expected_by_edge[edge] != actual_by_edge[edge]
        ]
        issues.append(_validation_issue(
            "runtime_semantic_overlay",
            "ORACLE_RUNTIME_SEMANTIC_EDGE_SET_MISMATCH",
            missing=sorted(expected_exact - actual_exact),
            extra=sorted(actual_exact - expected_exact),
            certainty_conflicts=certainty_conflicts,
        ))
    return issues, {
        "validated_kinds": sorted(supported_kinds),
        "validated_exact_edges": [list(item) for item in sorted(expected_exact)],
        "observed_production_exact_edges": [
            list(item) for item in sorted(actual_exact)
        ],
        "oracle_candidate_edge_count": len(expected - expected_exact),
        "production_candidate_edge_count": len(actual - actual_exact),
        "exact_edge_set_matches": actual_exact == expected_exact,
    }


def _validate_closed_world_results(
    generation: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Rebuild formal reachability from already independently validated facts.

    Direct/reconciliation records are admitted here only after their preceding
    Oracle validators have compared them with raw artifacts and target-JVM
    observations. Semantic edges and entrypoints have likewise already been
    independently rebuilt. This final pass closes those domains over the
    formal result, API projection, CSV and summary surfaces.
    """
    issues: list[dict[str, Any]] = []
    database = generation / "current_binary_facts.sqlite"
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        members = {row["member_identity"]: row for row in _rows(connection, "members")}
        edges = {row["direct_edge_identity"]: row for row in _rows(connection, "direct_edges")}
        resolutions = {
            row["direct_edge_identity"]: row
            for row in _reconciliation(connection, "member_resolution")
        }
        dispatches = {
            row["direct_edge_identity"]: row
            for row in _reconciliation(connection, "dispatch_resolution")
        }
        type_resolutions = {
            row["direct_edge_identity"]: row
            for row in _reconciliation(connection, "type_resolution")
        }
        initializations = {
            row["direct_edge_identity"]: row
            for row in _reconciliation(connection, "class_initialization_resolution")
        }
        linkages = {
            row["direct_edge_identity"]: row
            for row in _reconciliation(connection, "linkage_resolution")
        }
    finally:
        connection.close()

    # caller -> (target, certainty, evidence identity)
    transitions: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    relation_by_evidence: dict[str, list[tuple[str, str, str]]] = defaultdict(list)

    def admit(caller: str, target: str, certainty: str, evidence: str) -> None:
        if not caller or not target or certainty not in {"exact", "possible"}:
            return
        record = (target, certainty, evidence)
        transitions[caller].append(record)
        relation_by_evidence[evidence].append((caller, target, certainty))

    for edge_id, resolution in resolutions.items():
        edge = edges.get(edge_id)
        if edge is None:
            continue
        edge_kind = str(edge["edge_kind"] or "")
        executable_linkage = edge_kind in {
            "invokedynamic_bootstrap", "ldc_constant_dynamic_bootstrap",
        }
        if edge_kind not in {"method", "field"} and not executable_linkage:
            continue
        dispatch = dispatches.get(edge_id) or {}
        targets = list(dispatch.get("implementation_target_identities") or ())
        if (
            not targets
            and resolution.get("member_resolution_status") == "resolved"
            and resolution.get("resolved_member_identity")
        ):
            targets = [resolution["resolved_member_identity"]]
        certainty = (
            "possible"
            if dispatch.get("dispatch_status") in {"possible", "partial_possible_set"}
            or executable_linkage
            else "exact"
        )
        for target in targets:
            admit(str(edge["caller_member_identity"]), str(target), certainty, edge_id)
        if resolution.get("member_resolution_status") != "resolved":
            symbolic = _identity("binary_symbolic_trace_target", {
                "owner": edge["symbolic_owner"],
                "name": edge["symbolic_name"],
                "descriptor": edge["symbolic_descriptor"],
                "member_kind": "field" if edge_kind == "field" else "method",
            })
            admit(
                str(edge["caller_member_identity"]), symbolic,
                "exact"
                if resolution.get("member_resolution_status") == "no_such_member"
                else "possible",
                edge_id,
            )

    for edge_id, resolution in type_resolutions.items():
        if resolution.get("type_resolution_status") not in {
            "resolved", "primitive_or_array_type",
        }:
            continue
        edge = edges.get(edge_id)
        if edge is None:
            continue
        symbolic = _identity("binary_symbolic_trace_target", {
            "owner": edge["symbolic_owner"], "name": "<class>",
            "descriptor": edge["symbolic_descriptor"], "member_kind": "class",
        })
        admit(str(edge["caller_member_identity"]), symbolic, "exact", edge_id)

    for edge_id, resolution in initializations.items():
        if resolution.get("class_initialization_status") != "resolved":
            continue
        edge = edges.get(edge_id)
        if edge is None:
            continue
        for target in resolution.get("initializer_target_identities") or ():
            admit(str(edge["caller_member_identity"]), str(target), "exact", edge_id)

    semantic_payload = _load_json(generation / "binary_runtime_semantic_overlay.json")
    for row in semantic_payload.get("rows") or ():
        admit(
            str(row.get("caller_member_identity") or ""),
            str(row.get("target_member_identity") or ""),
            "exact" if row.get("path_certainty") == "exact" else "possible",
            str(row.get("semantic_edge_identity") or ""),
        )
    inline_path = generation / "binary_inline_overlay.json"
    if inline_path.is_file():
        for row in _load_json(inline_path).get("rows") or ():
            if row.get("consumption_state") != "changed_with_source" or row.get(
                "binding_certainty"
            ) not in {"proven", "possible"}:
                continue
            admit(
                str(row.get("consumer_member_identity") or ""),
                str(row.get("changed_field_member_identity") or ""),
                "exact" if row.get("binding_certainty") == "proven" else "possible",
                str(row.get("inline_overlay_identity") or ""),
            )

    entrypoint_payload = _load_json(generation / "binary_entrypoints.json")
    exact_entrypoints = {
        str(row.get("member_identity") or "")
        for row in entrypoint_payload.get("records") or ()
        if row.get("path_certainty") == "exact"
    }
    possible_entrypoints = {
        str(row.get("member_identity") or "")
        for row in entrypoint_payload.get("records") or ()
        if row.get("path_certainty") == "possible"
    } - exact_entrypoints

    def closure(roots: set[str], *, include_possible: bool) -> set[str]:
        reached = set(roots)
        pending = list(sorted(roots))
        while pending:
            caller = pending.pop()
            for target, certainty, _evidence in transitions.get(caller, ()):
                if certainty == "possible" and not include_possible:
                    continue
                if target not in reached:
                    reached.add(target)
                    pending.append(target)
        return reached

    exact_reached = closure(exact_entrypoints, include_possible=False)
    possible_reached = closure(
        exact_entrypoints | possible_entrypoints, include_possible=True
    )

    decisions_payload = _load_json(generation / "binary_decisions.json")
    decisions = {
        str(row.get("decision_identity") or ""): row
        for row in decisions_payload.get("authoritative_change_facts") or ()
    }
    decisions_by_change = {
        str(row.get("change_fact_identity") or ""): row
        for row in decisions.values()
    }
    projections_payload = _load_json(generation / "binary_projections.json")
    assessments = {
        str(row.get("projection_assessment_identity") or ""): row
        for row in projections_payload.get("authoritative_projection_assessments") or ()
    }
    projections = {
        str(row.get("projection_identity") or ""): row
        for row in projections_payload.get("formal_projections") or ()
    }
    coverage = _load_json(generation / "binary_coverage.json")
    # Semantic-adapter gaps are global diagnostics; they must not turn an
    # unrelated, otherwise complete target into not_analyzed. Per-result trace
    # construction intentionally applies only entrypoint/runtime/decision and
    # target-specific enumeration gaps.
    all_decision_rows = [
        *(decisions_payload.get("authoritative_change_facts") or ()),
        *(decisions_payload.get("diagnostic_candidate_facts") or ()),
    ]
    decision_gap_union = {
        str(gap)
        for row in all_decision_rows
        for gap in row.get("coverage_gaps") or ()
    }
    global_trace_gaps = (
        set(coverage.get("trace_coverage_gaps") or ())
        - set(semantic_payload.get("coverage_gaps") or ())
        - decision_gap_union
        - {
            "trace_path_enumeration_limit_exceeded",
            "trace_node_limit_exceeded",
        }
    )
    formal_payload = _load_json(generation / "binary_formal_results.json")
    formal_results = list(formal_payload.get("results") or ())
    result_by_projection = {
        str(row.get("projection_identity") or ""): row for row in formal_results
    }
    if set(result_by_projection) != set(projections):
        issues.append(_validation_issue(
            "closed_world_results", "ORACLE_FORMAL_PROJECTION_RESULT_SET_MISMATCH",
            missing=sorted(set(projections) - set(result_by_projection)),
            extra=sorted(set(result_by_projection) - set(projections)),
        ))

    for result in formal_results:
        projection_id = str(result.get("projection_identity") or "")
        projection = projections.get(projection_id) or {}
        assessment_id = str(projection.get("projection_assessment_identity") or "")
        assessment = assessments.get(assessment_id) or {}
        decision = decisions.get(str(assessment.get("decision_identity") or ""))
        if decision is None or result.get("change_fact_identity") != decision.get(
            "change_fact_identity"
        ):
            issues.append(_validation_issue(
                "closed_world_results", "ORACLE_FORMAL_RESULT_DECISION_BINDING_MISMATCH",
                projection_identity=projection_id,
            ))
            continue
        targets = {str(value) for value in result.get("target_nodes") or () if value}
        exact = bool(targets.intersection(exact_reached))
        possible = bool(targets.intersection(possible_reached))
        complete = not global_trace_gaps and not set(
            decision.get("coverage_gaps") or ()
        )
        expected_status = (
            "reachable" if exact else
            "uncertain" if possible else
            "not_found_in_static_analysis" if complete else
            "not_analyzed"
        )
        expected_state = {
            "reachability_status": expected_status,
            "analysis_status": expected_status,
            "is_reachable": exact,
            "impact_conclusion": "probable_impact" if exact else "inconclusive",
            "decision_bucket": "probable_impact" if exact else "inconclusive",
            "runtime_verification_status": (
                "required_not_executed" if exact else "undetermined"
            ),
            "runtime_verification_executed_by_system": False,
            "exact_path_exists": exact,
        }
        mismatches = {
            key: {"expected": value, "actual": result.get(key)}
            for key, value in expected_state.items()
            if result.get(key) != value
        }

        path_resolution_statuses = set()
        path_linkage_statuses = set()
        for path in result.get("paths") or ():
            entrypoint = str(path.get("entrypoint_member_identity") or "")
            current_nodes = {entrypoint}
            path_certainty = (
                "possible" if entrypoint in possible_entrypoints else "exact"
            )
            for path_edge in path.get("edges") or ():
                evidence = str(path_edge.get("direct_edge_identity") or "")
                next_nodes = set()
                for caller, target, certainty in relation_by_evidence.get(evidence, ()):
                    if caller in current_nodes:
                        next_nodes.add(target)
                        if certainty == "possible":
                            path_certainty = "possible"
                current_nodes = next_nodes
                if evidence in resolutions:
                    path_resolution_statuses.add(
                        str(resolutions[evidence].get("member_resolution_status") or "")
                    )
                if evidence in linkages:
                    path_linkage_statuses.add(
                        str(linkages[evidence].get("linkage_status") or "")
                    )
            if not current_nodes.intersection(targets):
                issues.append(_validation_issue(
                    "closed_world_results", "ORACLE_TRACE_PATH_CONTINUITY_MISMATCH",
                    projection_identity=projection_id,
                    path_identity=path.get("path_identity"),
                ))
            if path.get("path_certainty") != path_certainty:
                issues.append(_validation_issue(
                    "closed_world_results", "ORACLE_TRACE_PATH_CERTAINTY_MISMATCH",
                    projection_identity=projection_id,
                    path_identity=path.get("path_identity"),
                    expected=path_certainty, actual=path.get("path_certainty"),
                ))
            expected_path_identity = _identity("binary_trace_path_identity", {
                "entrypoint_member_identity": entrypoint,
                "entrypoint_record_identities": [
                    row.get("entrypoint_record_identity")
                    for row in path.get("entrypoint_records") or ()
                ],
                "target_nodes": list(result.get("target_nodes") or ()),
                "edge_identities": [
                    row.get("direct_edge_identity")
                    for row in path.get("edges") or ()
                ],
                "path_certainty": path.get("path_certainty"),
            })
            if path.get("path_identity") != expected_path_identity:
                issues.append(_validation_issue(
                    "closed_world_results", "ORACLE_TRACE_PATH_IDENTITY_MISMATCH",
                    projection_identity=projection_id,
                    path_identity=path.get("path_identity"),
                ))
        path_resolution_statuses.discard("")
        path_linkage_statuses.discard("")
        if sorted(path_resolution_statuses) != list(
            result.get("member_resolution_statuses") or ()
        ):
            mismatches["member_resolution_statuses"] = {
                "expected": sorted(path_resolution_statuses),
                "actual": result.get("member_resolution_statuses"),
            }
        if sorted(path_linkage_statuses) != list(
            result.get("linkage_resolution_statuses") or ()
        ):
            mismatches["linkage_resolution_statuses"] = {
                "expected": sorted(path_linkage_statuses),
                "actual": result.get("linkage_resolution_statuses"),
            }
        if mismatches:
            issues.append(_validation_issue(
                "closed_world_results", "ORACLE_FORMAL_STATE_MISMATCH",
                projection_identity=projection_id, mismatches=mismatches,
            ))
        expected_result_identity = _identity(
            "binary_trace_result_identity",
            {
                key: value for key, value in result.items()
                if key != "trace_result_identity"
            },
        )
        if result.get("trace_result_identity") != expected_result_identity:
            issues.append(_validation_issue(
                "closed_world_results", "ORACLE_FORMAL_RESULT_IDENTITY_MISMATCH",
                projection_identity=projection_id,
            ))

    priority = {
        "reachable": 3, "uncertain": 2,
        "not_found_in_static_analysis": 1, "not_analyzed": 0,
    }
    grouped: dict[tuple[Any, Any, Any, Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for result in formal_results:
        decision = decisions_by_change.get(str(result.get("change_fact_identity") or ""))
        if decision is None:
            continue
        scope = decision.get("fact_scope") or {}
        key = (
            scope.get("initiating_loader_realm_identity"),
            scope.get("class_name"),
            scope.get("member_kind") or decision.get("fact_kind"),
            scope.get("member_name"),
            scope.get("descriptor"),
        )
        grouped[key].append(result)
    expected_api: dict[str, dict[str, Any]] = {}
    analysis_context = str(decisions_payload.get("analysis_context_identity") or "")
    runtime_profile_identity = (
        formal_results[0].get("runtime_profile_identity")
        if formal_results else
        (_load_json(generation / "binary_summary.json")).get(
            "current_runtime_profile_identity"
        )
    )
    for key, results in grouped.items():
        realm, owner, kind, name, descriptor = key
        identity = _identity("reported_api_identity", {
            "analysis_context_identity": analysis_context,
            "current_runtime_profile_identity": runtime_profile_identity,
            "initiating_loader_realm_identity": realm,
            "class_name": owner,
            "member_kind": kind,
            "member_name": name,
            "descriptor": descriptor,
            "grouping_rule_version": "binary-reported-api-v1",
        })
        status = max(
            (str(row.get("reachability_status") or "") for row in results),
            key=lambda value: priority.get(value, -1),
        )
        contributing = [
            decisions_by_change[str(row.get("change_fact_identity") or "")]
            for row in results
        ]
        expected_api[identity] = {
            "reported_api_identity": identity,
            "display_owner": owner,
            "display_member": name,
            "display_descriptor": descriptor,
            "display_member_kind": kind,
            "reachability_status": status,
            "is_reachable": any(bool(row.get("is_reachable")) for row in results),
            "impact_conclusion": (
                "probable_impact"
                if any(row.get("impact_conclusion") == "probable_impact" for row in results)
                else "inconclusive"
            ),
            "runtime_verification_status": "required_not_executed",
            "runtime_verification_executed_by_system": False,
            "path_set_complete": all(bool(row.get("path_set_complete")) for row in results),
            "exact_path_exists": any(bool(row.get("exact_path_exists")) for row in results),
            "possible_path_exists": any(bool(row.get("possible_path_exists")) for row in results),
            "contributing_projection_ids": sorted(
                str(row.get("projection_identity") or "") for row in results
            ),
            "contributing_change_fact_ids": sorted(
                str(row.get("change_fact_identity") or "") for row in results
            ),
            "base_dependency_coords": sorted({
                str(artifact.get("coord") or "")
                for decision in contributing
                for artifact in decision.get("dependency_artifacts") or ()
                if artifact.get("side") == "base" and artifact.get("coord")
            }),
            "current_dependency_coords": sorted({
                str(artifact.get("coord") or "")
                for decision in contributing
                for artifact in decision.get("dependency_artifacts") or ()
                if artifact.get("side") == "current" and artifact.get("coord")
            }),
        }
    actual_api = {
        str(row.get("reported_api_identity") or ""): row
        for row in formal_payload.get("by_api") or ()
    }
    api_mismatches = []
    if set(actual_api) != set(expected_api):
        api_mismatches.append({
            "field": "identity_set",
            "missing": sorted(set(expected_api) - set(actual_api)),
            "extra": sorted(set(actual_api) - set(expected_api)),
        })
    for identity in sorted(set(actual_api).intersection(expected_api)):
        for field, expected in expected_api[identity].items():
            if actual_api[identity].get(field) != expected:
                api_mismatches.append({
                    "reported_api_identity": identity, "field": field,
                    "expected": expected, "actual": actual_api[identity].get(field),
                })
    if api_mismatches:
        issues.append(_validation_issue(
            "closed_world_results", "ORACLE_API_AGGREGATION_MISMATCH",
            mismatches=api_mismatches[:100],
        ))

    csv_path = generation / "binary_formal_results.csv"
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        csv_rows = list(csv.DictReader(handle))
    csv_by_identity = {
        str(row.get("reported_api_identity") or ""): row for row in csv_rows
    }
    csv_fields = {
        "display_owner", "display_member", "display_descriptor",
        "reachability_status", "impact_conclusion", "runtime_verification_status",
    }
    csv_mismatch = set(csv_by_identity) != set(actual_api)
    if not csv_mismatch:
        for identity, row in actual_api.items():
            for field in csv_fields:
                if str(csv_by_identity[identity].get(field) or "") != str(
                    row.get(field) or ""
                ):
                    csv_mismatch = True
                    break
            if csv_mismatch:
                break
    if csv_mismatch:
        issues.append(_validation_issue(
            "closed_world_results", "ORACLE_FORMAL_CSV_PROJECTION_MISMATCH",
        ))

    summary = _load_json(generation / "binary_summary.json")
    summary_expected = {
        "authoritative_change_fact_count": len(decisions),
        "formal_projection_count": len(projections),
        "formal_trace_result_count": len(formal_results),
        "unique_reported_api_total": len(expected_api),
        "reachable_total": sum(
            row["reachability_status"] == "reachable" for row in expected_api.values()
        ),
        "uncertain_total": sum(
            row["reachability_status"] == "uncertain" for row in expected_api.values()
        ),
        "not_found_in_static_analysis_total": sum(
            row["reachability_status"] == "not_found_in_static_analysis"
            for row in expected_api.values()
        ),
        "not_analyzed_total": sum(
            row["reachability_status"] == "not_analyzed" for row in expected_api.values()
        ),
        "probable_impact_total": sum(
            row["impact_conclusion"] == "probable_impact"
            for row in expected_api.values()
        ),
    }
    summary_mismatches = {
        key: {"expected": value, "actual": summary.get(key)}
        for key, value in summary_expected.items()
        if summary.get(key) != value
    }
    if summary_mismatches:
        issues.append(_validation_issue(
            "closed_world_results", "ORACLE_SUMMARY_AGGREGATION_MISMATCH",
            mismatches=summary_mismatches,
        ))
    return issues, {
        "exact_reachable_node_count": len(exact_reached),
        "possible_reachable_node_count": len(possible_reached),
        "formal_result_count": len(formal_results),
        "reported_api_count": len(expected_api),
        "formal_identity_set_closed": not issues,
    }


def _validate_source_attestation(
    generation: Path, config: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Re-hash every user-authorized source file without using the source parser."""
    usage = dict(config.get("source_usage") or {})
    decision = str(usage.get("decision") or "")
    overlay = dict(config.get("source_overlay") or {})
    path = generation / "binary_source_attestation.json"
    if decision == "skip_source":
        issues = []
        if path.exists() or overlay:
            issues.append(_validation_issue(
                "source_attestation", "ORACLE_UNAUTHORIZED_SOURCE_OVERLAY_PRESENT",
                attestation_present=path.exists(), config_overlay_present=bool(overlay),
            ))
        return issues, {"decision": decision, "source_file_count": 0}
    if decision != "use_source" or not path.is_file():
        return [_validation_issue(
            "source_attestation", "ORACLE_SOURCE_ATTESTATION_MISSING",
            decision=decision, attestation_present=path.is_file(),
        )], {"decision": decision, "source_file_count": 0}

    payload = _load_json(path)
    actual_files = []
    actual_sets = []
    expected_coverage_gaps = []
    language_file_counts: dict[str, int] = defaultdict(int)
    issues = []
    for raw_set in overlay.get("source_sets") or ():
        source_set = dict(raw_set or {})
        roots = [
            Path(str(item)).expanduser().resolve()
            for item in source_set.get("source_dirs") or ()
        ]
        common_value = source_set.get("source_root") or (
            roots[0] if len(roots) == 1 else None
        )
        if common_value is None:
            issues.append(_validation_issue(
                "source_attestation", "ORACLE_SOURCE_COMMON_ROOT_MISSING",
                owner_coord=str(source_set.get("owner_coord") or ""),
            ))
            continue
        common = Path(str(common_value)).expanduser().resolve()
        set_files = []
        for root in roots:
            if not root.is_dir():
                issues.append(_validation_issue(
                    "source_attestation", "ORACLE_SOURCE_ROOT_MISSING",
                    source_root=str(root),
                ))
                continue
            source_files = sorted(
                file_path for file_path in root.rglob("*")
                if file_path.is_file()
                and file_path.suffix.lower() in _ORACLE_SOURCE_FILE_LANGUAGES
            )
            for file_path in source_files:
                try:
                    logical = file_path.relative_to(common).as_posix()
                except ValueError:
                    issues.append(_validation_issue(
                        "source_attestation", "ORACLE_SOURCE_FILE_OUTSIDE_SNAPSHOT",
                        source_file=str(file_path), source_root=str(common),
                    ))
                    continue
                row = {
                    "owner_type": str(source_set.get("owner_type") or ""),
                    "owner_coord": str(source_set.get("owner_coord") or ""),
                    "module": str(source_set.get("module") or "root"),
                    "logical_path": logical,
                    "sha256": _sha256_file(file_path),
                }
                actual_files.append(row)
                set_files.append(row)
                language = _ORACLE_SOURCE_FILE_LANGUAGES[
                    file_path.suffix.lower()
                ]
                language_file_counts[language] += 1
                if language != "java":
                    expected_coverage_gaps.append({
                        "reason_code": "BINARY_SOURCE_LANGUAGE_NOT_MAPPED",
                        "language": language,
                        "owner_coord": row["owner_coord"],
                        "module": row["module"],
                        "logical_path": logical,
                    })
        actual_sets.append({
            "owner_type": str(source_set.get("owner_type") or ""),
            "owner_coord": str(source_set.get("owner_coord") or ""),
            "module": str(source_set.get("module") or "root"),
            "snapshot_revision": str(
                source_set.get("snapshot_revision") or "content-addressed-only"
            ),
            "file_count": len(set_files),
        })

    attested_core = [{
        key: row.get(key) for key in (
            "owner_type", "owner_coord", "module", "logical_path", "sha256"
        )
    } for row in payload.get("files") or ()]
    if attested_core != actual_files:
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_FILE_MANIFEST_MISMATCH",
            expected=actual_files, actual=attested_core,
        ))
    attested_sets = [{
        key: row.get(key) for key in (
            "owner_type", "owner_coord", "module", "snapshot_revision", "file_count"
        )
    } for row in payload.get("source_sets") or ()]
    if attested_sets != actual_sets:
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_SET_ATTESTATION_MISMATCH",
            expected=actual_sets, actual=attested_sets,
        ))
    snapshot_identity = _identity(
        "source_snapshot_identity", {"files": list(payload.get("files") or ())}
    )
    if payload.get("source_snapshot_identity") != snapshot_identity:
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_SNAPSHOT_IDENTITY_MISMATCH",
            expected=snapshot_identity,
            actual=payload.get("source_snapshot_identity"),
        ))
    if payload.get("file_count") != len(actual_files):
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_FILE_COUNT_MISMATCH",
            expected=len(actual_files), actual=payload.get("file_count"),
        ))
    if payload.get("language_file_counts") != dict(sorted(language_file_counts.items())):
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_LANGUAGE_COUNTS_MISMATCH",
            expected=dict(sorted(language_file_counts.items())),
            actual=payload.get("language_file_counts"),
        ))
    attested_gaps = list(payload.get("coverage_gaps") or ())
    actual_source_keys = {
        (row["owner_coord"], row["module"], row["logical_path"])
        for row in actual_files
    }
    seen_gap_identities = set()
    for gap in attested_gaps:
        identity = (
            str(gap.get("reason_code") or ""),
            str(gap.get("owner_coord") or ""),
            str(gap.get("module") or ""),
            str(gap.get("logical_path") or ""),
        )
        valid_reason = identity[0] in {
            "BINARY_SOURCE_LANGUAGE_NOT_MAPPED",
            "BINARY_SOURCE_PARSE_PARTIAL",
        }
        if (
            identity in seen_gap_identities
            or not valid_reason
            or identity[1:] not in actual_source_keys
        ):
            issues.append(_validation_issue(
                "source_attestation", "ORACLE_SOURCE_COVERAGE_GAP_INVALID",
                gap=gap,
            ))
        seen_gap_identities.add(identity)
    missing_language_gaps = [
        gap for gap in expected_coverage_gaps if gap not in attested_gaps
    ]
    if missing_language_gaps:
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_COVERAGE_GAPS_MISMATCH",
            missing=missing_language_gaps,
            actual=attested_gaps,
        ))
    expected_coverage_status = "partial" if attested_gaps else "complete"
    if payload.get("coverage_status") != expected_coverage_status:
        issues.append(_validation_issue(
            "source_attestation", "ORACLE_SOURCE_COVERAGE_STATUS_MISMATCH",
            expected=expected_coverage_status,
            actual=payload.get("coverage_status"),
        ))
    return issues, {
        "decision": decision,
        "source_file_count": len(actual_files),
        "source_snapshot_identity": snapshot_identity,
        "source_coverage_status": expected_coverage_status,
        "source_coverage_gap_count": len(expected_coverage_gaps),
        "source_manifest_exact": not issues,
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
    source_issues, source_truth = _validate_source_attestation(generation, config)
    issues.extend(source_issues)
    truth_parts["source_attestation"] = source_truth

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
                if name != "module-info"
            }
            independent_classes.update(
                name for name in edge_truth["discovery_classes"]
                if name != "module-info"
            )
            observations, helper_identity = _observe_classes(
                jdk_home, artifacts, independent_classes
            )
            javap_members: dict[str, list[str]] = defaultdict(list)
            for owner, kind, member_name, descriptor, flags in (
                structural_truth.get("declared_members") or ()
            ):
                javap_members[str(owner)].append(
                    f"{kind}|{member_name}|{descriptor}|{int(flags)}"
                )
            for class_name, values in javap_members.items():
                observation = observations.get(class_name)
                if observation is not None:
                    observation["javap_declared_members"] = sorted(set(values))
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
        (truth_parts.get("current") or {}).get("semantic_instructions") or (),
    )
    issues.extend(entrypoint_issues)
    truth_parts["entrypoint_discovery"] = entrypoint_truth
    semantic_issues, semantic_truth = _validate_runtime_semantic_overlay(
        generation,
        current_side,
        current_artifacts,
        observations_by_side.get("base") or {},
        observations_by_side.get("current") or {},
        (truth_parts.get("current") or {}).get("semantic_instructions") or (),
        (truth_parts.get("current") or {}).get("direct_edges") or (),
        (truth_parts.get("current") or {}).get("resource_selections") or (),
    )
    issues.extend(semantic_issues)
    truth_parts["runtime_semantic_overlay"] = semantic_truth
    closed_issues, closed_truth = _validate_closed_world_results(generation)
    issues.extend(closed_issues)
    truth_parts["closed_world_results"] = closed_truth

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
