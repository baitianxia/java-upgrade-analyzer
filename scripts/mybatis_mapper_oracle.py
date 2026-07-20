#!/usr/bin/env python3
"""Independent final-artifact evidence for MyBatis mapper proxy dispatch."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
import re
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile

from final_artifact_edge_oracle import scan_final_artifact


MAPPER_ANNOTATION = b"Lorg/apache/ibatis/annotations/Mapper;"
SQL_ANNOTATION_PREFIX = "org.apache.ibatis.annotations."
SQL_ANNOTATIONS = {
    "Delete", "DeleteProvider", "Insert", "InsertProvider", "Select",
    "SelectProvider", "Update", "UpdateProvider",
}
STATEMENT_TAGS = {"delete", "insert", "select", "update"}
MYBATIS_JAR_RE = re.compile(r"^BOOT-INF/lib/mybatis-\d[^/]*\.jar$")
CLASS_DECLARATION_RE = re.compile(
    r"^(?:public\s+)?(?:abstract\s+)?(?:class|interface)\s+(?P<owner>[\w.$]+)"
)
METHOD_HEADER_RE = re.compile(
    r"^\s{2}(?:public|protected|private)\s+(?:abstract\s+)?(?:static\s+)?"
    r".+\s+(?P<member>[\w$<>]+)\([^;]*\);\s*$"
)
DESCRIPTOR_RE = re.compile(r"^\s+descriptor:\s+(?P<descriptor>\S+)\s*$")
ANNOTATION_RE = re.compile(r"^\s+(org\.apache\.ibatis\.annotations\.(?P<name>\w+))\s*\(?$")
DOCTYPE_RE = re.compile(br"<!DOCTYPE\s+[^>]+>", re.IGNORECASE | re.DOTALL)
FRAMEWORK_TARGETS = (
    {
        "owner": "org.apache.ibatis.binding.MapperMethod",
        "member": "execute",
        "descriptor": (
            "(Lorg/apache/ibatis/session/SqlSession;[Ljava/lang/Object;)"
            "Ljava/lang/Object;"
        ),
    },
    {
        "owner": "org.apache.ibatis.session.SqlSession",
        "member": "selectOne",
        "descriptor": "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;",
    },
)
PROXY_ENTRY_TARGET = {
    "owner": "org.apache.ibatis.binding.MapperProxy$MapperMethodInvoker",
    "member": "invoke",
    "descriptor": (
        "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;"
        "Lorg/apache/ibatis/session/SqlSession;)Ljava/lang/Object;"
    ),
}


def _local_name(tag: str) -> str:
    return str(tag or "").rsplit("}", 1)[-1]


def _safe_mybatis_xml_root(content: bytes):
    raw = bytes(content)
    upper = raw.upper()
    if b"<!ENTITY" in upper or b"[" in (DOCTYPE_RE.search(raw).group(0) if DOCTYPE_RE.search(raw) else b""):
        raise ET.ParseError("XML entities and internal DTD subsets are not allowed")
    doctype = DOCTYPE_RE.search(raw)
    if doctype:
        declaration = doctype.group(0).lower()
        allowed = (
            b"mybatis.org/dtd/mybatis-3-mapper.dtd" in declaration
            or b"mybatis.org/dtd/mybatis-3-config.dtd" in declaration
        )
        if not allowed:
            raise ET.ParseError("unrecognized external DTD")
        raw = raw[:doctype.start()] + raw[doctype.end():]
    return ET.fromstring(raw)


def parse_mapper_xml(content: bytes, artifact_entry: str) -> dict:
    """Parse one mapper XML resource without resolving its external DTD."""
    root = _safe_mybatis_xml_root(content)
    if _local_name(root.tag) != "mapper":
        raise ET.ParseError("root element is not mapper")
    namespace = str(root.attrib.get("namespace") or "").strip()
    statements = sorted({
        str(child.attrib.get("id") or "").strip()
        for child in root
        if _local_name(child.tag) in STATEMENT_TAGS
        and str(child.attrib.get("id") or "").strip()
    })
    return {
        "namespace": namespace,
        "statements": statements,
        "artifact_entry": artifact_entry,
    }


def _config_mapper_resources(content: bytes) -> list[str]:
    root = _safe_mybatis_xml_root(content)
    if _local_name(root.tag) != "configuration":
        return []
    return sorted({
        str(element.attrib.get("resource") or "").strip()
        for element in root.iter()
        if _local_name(element.tag) == "mapper"
        and str(element.attrib.get("resource") or "").strip()
    })


def parse_mapper_javap(output: str, artifact_entry: str) -> dict:
    """Read exact mapper method descriptors and annotations from `javap -v`."""
    lines = output.splitlines()
    owner = ""
    for line in lines:
        match = CLASS_DECLARATION_RE.match(line.strip())
        if match:
            owner = match.group("owner")
            break

    mapper_registered = any(
        line.strip().startswith("org.apache.ibatis.annotations.Mapper")
        for line in lines
    )
    methods: list[dict] = []
    index = 0
    while index < len(lines):
        header = METHOD_HEADER_RE.match(lines[index])
        if not header:
            index += 1
            continue
        member = header.group("member")
        descriptor = ""
        annotations: set[str] = set()
        cursor = index + 1
        while cursor < len(lines):
            if METHOD_HEADER_RE.match(lines[cursor]) or lines[cursor].strip() == "}":
                break
            descriptor_match = DESCRIPTOR_RE.match(lines[cursor])
            if descriptor_match:
                descriptor = descriptor_match.group("descriptor")
            annotation_match = ANNOTATION_RE.match(lines[cursor])
            if annotation_match and annotation_match.group("name") in SQL_ANNOTATIONS:
                annotations.add(annotation_match.group(1))
            cursor += 1
        if owner and descriptor and member not in {"<init>", "<clinit>"}:
            methods.append({
                "owner": owner,
                "member": member,
                "descriptor": descriptor,
                "annotation_bindings": sorted(annotations),
                "artifact_entry": artifact_entry,
            })
        index = max(cursor, index + 1)
    return {
        "owner": owner,
        "mapper_registered": mapper_registered,
        "methods": methods,
        "artifact_entry": artifact_entry,
    }


def _run_javap(content: bytes, artifact_entry: str, timeout_seconds: float) -> str:
    with tempfile.TemporaryDirectory(prefix="mybatis-oracle-javap-") as temporary:
        class_path = Path(temporary) / "target.class"
        class_path.write_bytes(content)
        completed = subprocess.run(
            ["javap", "-v", "-p", "-s", str(class_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(0.1, timeout_seconds),
            check=False,
        )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "javap failed").strip()
        raise RuntimeError(f"{artifact_entry}: {detail}")
    return completed.stdout


def verify_runtime_activation(
    artifact: Path, required_output: list[str], timeout_seconds: float = 30.0
) -> dict:
    """Run one pinned executable Jar and verify its reviewed observable outputs."""
    started = time.perf_counter()
    if not required_output:
        return {
            "active": False,
            "failures": ["MYBATIS_RUNTIME_EXPECTATION_MISSING"],
            "output_sha256": "",
            "elapsed_seconds": time.perf_counter() - started,
        }
    command = ["java", "-jar", str(Path(artifact))]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "active": False,
            "failures": ["MYBATIS_RUNTIME_TIMEOUT"],
            "output_sha256": "",
            "elapsed_seconds": time.perf_counter() - started,
        }
    except OSError as error:
        return {
            "active": False,
            "failures": [f"MYBATIS_RUNTIME_FAILED:{type(error).__name__}:{error}"],
            "output_sha256": "",
            "elapsed_seconds": time.perf_counter() - started,
        }
    output = f"{completed.stdout or ''}\n{completed.stderr or ''}"
    failures = []
    if completed.returncode != 0:
        failures.append(f"MYBATIS_RUNTIME_EXIT:{completed.returncode}")
    failures.extend(
        f"MYBATIS_RUNTIME_OUTPUT_MISSING:{expected}"
        for expected in required_output
        if expected not in output
    )
    return {
        "active": not failures,
        "failures": failures,
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "elapsed_seconds": time.perf_counter() - started,
    }


def mybatis_physical_targets() -> list[dict]:
    """Targets needed to prove the complete packaged mapper dispatch chain."""
    return [dict(target) for target in FRAMEWORK_TARGETS] + [dict(PROXY_ENTRY_TARGET)]


def _edge_target(edge: dict) -> tuple[str, str, str]:
    return (
        str(edge.get("callee_owner") or ""),
        str(edge.get("callee_member") or ""),
        str(edge.get("callee_descriptor") or ""),
    )


def _contract_target(contract: dict) -> tuple[str, str, str]:
    return contract["owner"], contract["member"], contract["descriptor"]


def inspect_mybatis_artifact(
    path: Path,
    timeout_seconds: float = 120.0,
    *,
    physical_scan: dict | None = None,
) -> dict:
    """Inventory mapper contracts and proxy evidence from one executable Jar."""
    artifact = Path(path)
    started = time.perf_counter()
    failures: list[str] = []
    try:
        snapshot = artifact.read_bytes()
        artifact_sha256 = hashlib.sha256(snapshot).hexdigest()
        outer = zipfile.ZipFile(io.BytesIO(snapshot))
    except (OSError, zipfile.BadZipFile) as error:
        return {
            "artifact_sha256": "",
            "mapper_contracts": [],
            "statement_bindings": [],
            "physical_edges": [],
            "proxy_dispatch_links": [],
            "failures": [f"ARTIFACT_READ_FAILED:{type(error).__name__}:{error}"],
            "metrics": {"elapsed_seconds": time.perf_counter() - started},
            "complete": False,
        }

    with outer:
        infos = [info for info in outer.infolist() if not info.is_dir()]
        names = {info.filename for info in infos}
        mapper_documents: dict[str, dict] = {}
        configured_resources: set[str] = set()
        mapper_resource_count = 0
        for info in infos:
            if not info.filename.startswith("BOOT-INF/classes/") or not info.filename.endswith(".xml"):
                continue
            try:
                content = outer.read(info)
                if info.filename.endswith("mybatis-config.xml"):
                    configured_resources.update(_config_mapper_resources(content))
                    continue
                root = _safe_mybatis_xml_root(content)
                if _local_name(root.tag) != "mapper":
                    continue
                parsed = parse_mapper_xml(content, info.filename)
                mapper_resource_count += 1
                namespace = parsed["namespace"]
                if not namespace:
                    failures.append(f"MAPPER_NAMESPACE_MISSING:{info.filename}")
                    continue
                if namespace in mapper_documents:
                    failures.append(f"MAPPER_NAMESPACE_DUPLICATE:{namespace}")
                    continue
                mapper_documents[namespace] = parsed
            except (ET.ParseError, UnicodeError) as error:
                failures.append(f"MAPPER_XML_PARSE_FAILED:{info.filename}:{error}")

        for resource in configured_resources:
            entry = f"BOOT-INF/classes/{resource.lstrip('/')}"
            if entry not in names:
                failures.append(f"MAPPER_RESOURCE_MISSING:{resource}")

        namespace_owners = set(mapper_documents)
        mapper_classes: list[dict] = []
        for info in infos:
            if not info.filename.startswith("BOOT-INF/classes/") or not info.filename.endswith(".class"):
                continue
            content = outer.read(info)
            owner = info.filename[len("BOOT-INF/classes/"):-len(".class")].replace("/", ".")
            if MAPPER_ANNOTATION not in content and owner not in namespace_owners:
                continue
            try:
                output = _run_javap(
                    content,
                    info.filename,
                    timeout_seconds=max(0.1, timeout_seconds - (time.perf_counter() - started)),
                )
                parsed = parse_mapper_javap(output, info.filename)
                if not parsed["owner"]:
                    failures.append(f"MAPPER_CLASS_OWNER_UNRESOLVED:{info.filename}")
                    continue
                mapper_classes.append(parsed)
            except subprocess.TimeoutExpired:
                failures.append(f"ORACLE_TIMEOUT:{info.filename}")
            except (OSError, RuntimeError) as error:
                failures.append(f"MAPPER_JAVAP_FAILED:{info.filename}:{error}")

        if not any(MYBATIS_JAR_RE.match(name) for name in names):
            failures.append("MYBATIS_RUNTIME_JAR_MISSING")

    candidate_methods = [
        method
        for mapper_class in mapper_classes
        for method in mapper_class["methods"]
    ]
    selected_targets = [
        {"owner": method["owner"], "member": method["member"], "descriptor": method["descriptor"]}
        for method in candidate_methods
    ] + [dict(target) for target in FRAMEWORK_TARGETS] + [dict(PROXY_ENTRY_TARGET)]
    elapsed = time.perf_counter() - started
    scan_budget = max(0.1, timeout_seconds - elapsed)
    scan = physical_scan if physical_scan is not None else scan_final_artifact(
        artifact,
        time_budget_seconds=scan_budget,
        selected_targets=selected_targets,
    )
    for failure in scan.get("failures") or []:
        failures.append(f"PHYSICAL_ORACLE_FAILED:{failure}")
    if not scan.get("complete"):
        failures.append("PHYSICAL_ORACLE_INCOMPLETE")
    edges = list(scan.get("edges") or [])
    invoked_targets = {_edge_target(edge) for edge in edges}

    mapper_by_owner = {item["owner"]: item for item in mapper_classes}
    contracts: list[dict] = []
    statement_bindings: list[dict] = []
    for method in candidate_methods:
        target = _contract_target(method)
        if target not in invoked_targets:
            continue
        mapper_class = mapper_by_owner[method["owner"]]
        if not mapper_class["mapper_registered"]:
            failures.append(f"MAPPER_REGISTRATION_MISSING:{method['owner']}")
            continue
        binding = ""
        binding_entry = ""
        if method["annotation_bindings"]:
            binding = "mapper_annotation"
            binding_entry = method["artifact_entry"]
        else:
            document = mapper_documents.get(method["owner"])
            if document and method["member"] in document["statements"]:
                binding = "mapper_xml"
                binding_entry = document["artifact_entry"]
        if not binding:
            wrong_namespaces = sorted(
                namespace for namespace, document in mapper_documents.items()
                if namespace != method["owner"]
                and method["member"] in document["statements"]
            )
            if len(wrong_namespaces) == 1:
                failures.append(
                    f"MAPPER_NAMESPACE_MISMATCH:{method['owner']}:{wrong_namespaces[0]}"
                )
            else:
                failures.append(
                    f"MAPPER_STATEMENT_UNRESOLVED:{method['owner']}.{method['member']}"
                )
            continue
        contract = {
            "owner": method["owner"],
            "member": method["member"],
            "descriptor": method["descriptor"],
            "registration": "mapper_annotation",
            "binding": binding,
            "artifact_entry": method["artifact_entry"],
            "binding_entry": binding_entry,
            "artifact_sha256": artifact_sha256,
        }
        contracts.append(contract)
        statement_bindings.append({
            "owner": method["owner"],
            "member": method["member"],
            "binding": binding,
            "artifact_entry": binding_entry,
            "artifact_sha256": artifact_sha256,
        })

    mapper_execute = (
        "org.apache.ibatis.binding.MapperMethod",
        "execute",
        FRAMEWORK_TARGETS[0]["descriptor"],
    )
    proxy_invoker = (
        PROXY_ENTRY_TARGET["owner"],
        PROXY_ENTRY_TARGET["member"],
        PROXY_ENTRY_TARGET["descriptor"],
    )
    proxy_entry_edges = [edge for edge in edges if _edge_target(edge) == proxy_invoker]
    dispatch_edges = [edge for edge in edges if _edge_target(edge) == mapper_execute]
    select_one = (
        FRAMEWORK_TARGETS[1]["owner"],
        FRAMEWORK_TARGETS[1]["member"],
        FRAMEWORK_TARGETS[1]["descriptor"],
    )
    select_one_edges = [edge for edge in edges if _edge_target(edge) == select_one]
    proxy_dispatch_links: list[dict] = []
    if contracts and not proxy_entry_edges:
        failures.append("MYBATIS_PROXY_ENTRY_DISPATCH_MISSING")
    if contracts and not dispatch_edges:
        failures.append("MYBATIS_PROXY_DISPATCH_MISSING")
    if contracts and not select_one_edges:
        failures.append("MYBATIS_SELECT_ONE_DISPATCH_MISSING")
    framework_api_evidence = {
        "org.apache.ibatis.binding.MapperProxy.invoke": proxy_entry_edges,
        "org.apache.ibatis.binding.MapperMethod.execute": dispatch_edges,
        "org.apache.ibatis.session.SqlSession.selectOne": select_one_edges,
    }
    for contract in contracts:
        if not proxy_entry_edges or not dispatch_edges or not select_one_edges:
            break
        proxy_dispatch_links.append({
            "target": {
                "owner": contract["owner"],
                "member": contract["member"],
                "descriptor": contract["descriptor"],
            },
            "framework_target": dict(FRAMEWORK_TARGETS[0]),
            "artifact_sha256": artifact_sha256,
            "registration_entry": contract["artifact_entry"],
            "binding_entry": contract["binding_entry"],
            "physical_dispatch_edges": [
                proxy_entry_edges[0], dispatch_edges[0], select_one_edges[0]
            ],
            "evidence_authority": "final-artifact-javap-plus-mapper-registration",
        })

    scan_metrics = dict(scan.get("metrics") or {})
    metrics = {
        "elapsed_seconds": time.perf_counter() - started,
        "mapper_classes": len(mapper_classes),
        "mapper_resources": mapper_resource_count,
        "javap_tasks": int(
            scan_metrics.get("javap_tasks")
            or scan.get("parsed_class_count")
            or scan.get("class_count")
            or 0
        ),
        "visited_classes": int(
            scan_metrics.get("visited_classes")
            or scan.get("inventory_class_count")
            or scan.get("class_count")
            or 0
        ),
        "duplicate_artifact_scans": 0,
    }
    return {
        "artifact_sha256": artifact_sha256,
        "mapper_contracts": sorted(
            contracts, key=lambda item: (item["owner"], item["member"], item["descriptor"])
        ),
        "statement_bindings": sorted(
            statement_bindings, key=lambda item: (item["owner"], item["member"])
        ),
        "physical_edges": edges,
        "proxy_dispatch_links": proxy_dispatch_links,
        "framework_api_evidence": framework_api_evidence,
        "physical_scan": scan,
        "failures": sorted(set(failures)),
        "metrics": metrics,
        "complete": not failures and bool(scan.get("complete")),
    }


__all__ = [
    "inspect_mybatis_artifact",
    "parse_mapper_javap",
    "parse_mapper_xml",
    "mybatis_physical_targets",
    "verify_runtime_activation",
]
