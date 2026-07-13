#!/usr/bin/env python3
"""Shared project-scope, provenance, and evidence-coverage contracts."""

from __future__ import annotations

import hashlib
import csv
import json
import subprocess
import re
import safe_xml as ET
from datetime import datetime, timezone
from pathlib import Path

from pipeline_constants import STEP5_ARTIFACT_BYTECODE_CATALOG_FILE


COVERAGE_STATUSES = ("complete", "partial", "insufficient", "not_applicable")
_STATUS_RANK = {"complete": 0, "not_applicable": 0, "partial": 1, "insufficient": 2}


def _text(element, name):
    if element is None:
        return ""
    child = element.find(f"{{*}}{name}")
    return (child.text or "").strip() if child is not None else ""


def _pom_model(pom_path, inherited_group="", inherited_version="", inherited_properties=None):
    root = ET.parse(str(pom_path)).getroot()
    parent = root.find("{*}parent")
    group_id = _text(root, "groupId") or _text(parent, "groupId") or inherited_group
    artifact_id = _text(root, "artifactId")
    version = _text(root, "version") or _text(parent, "version") or inherited_version
    packaging = _text(root, "packaging") or "jar"
    module_paths = [
        (item.text or "").strip()
        for item in root.findall("{*}modules/{*}module")
        if (item.text or "").strip()
    ]
    dependencies = []
    for dep in root.findall("{*}dependencies/{*}dependency"):
        dep_group = _text(dep, "groupId")
        dep_artifact = _text(dep, "artifactId")
        if dep_artifact:
            dependencies.append(f"{dep_group}:{dep_artifact}" if dep_group else dep_artifact)
    plugins = {
        _text(plugin, "artifactId")
        for plugin in root.findall(".//{*}plugins/{*}plugin")
        if _text(plugin, "artifactId")
    }
    properties = dict(inherited_properties or {})
    properties.update({
        str(child.tag).rsplit('}', 1)[-1]: (child.text or '').strip()
        for child in root.findall('{*}properties/*')
        if (child.text or '').strip()
    })
    build = root.find('{*}build')
    source_paths = []
    resource_paths = []
    if build is not None:
        source_dir = _text(build, 'sourceDirectory')
        if source_dir:
            source_paths.append(source_dir)
        for resource in build.findall('{*}resources/{*}resource'):
            directory = _text(resource, 'directory')
            if directory:
                resource_paths.append(directory)
    for plugin in root.findall('.//{*}plugins/{*}plugin'):
        if _text(plugin, 'artifactId') != 'build-helper-maven-plugin':
            continue
        for execution in plugin.findall('{*}executions/{*}execution'):
            goals = {_text(goal, '') or (goal.text or '').strip() for goal in execution.findall('{*}goals/{*}goal')}
            configuration = execution.find('{*}configuration')
            if configuration is None:
                continue
            target = resource_paths if 'add-resource' in goals else source_paths
            if not ({'add-source', 'add-resource'} & goals):
                continue
            for node in configuration.findall('.//{*}source') + configuration.findall('.//{*}resource/{*}directory'):
                value = (node.text or '').strip()
                if value:
                    target.append(value)
    return {
        "group_id": group_id,
        "artifact_id": artifact_id,
        "version": version,
        "packaging": packaging,
        "module_paths": module_paths,
        "dependencies": dependencies,
        "plugins": sorted(plugins),
        "properties": properties,
        "source_paths": source_paths,
        "resource_paths": resource_paths,
    }


def discover_maven_modules(project_dir):
    """Discover the reactor without executing Maven or scanning unrelated repositories."""
    root = Path(project_dir).resolve()
    root_pom = root / "pom.xml"
    if not root_pom.is_file():
        return {"status": "insufficient", "reason_codes": ["maven_root_pom_missing"], "modules": []}

    modules = []
    problems = []
    visited = set()

    def visit(module_dir, inherited_group="", inherited_version="", inherited_properties=None):
        module_dir = module_dir.resolve()
        if module_dir in visited:
            return
        visited.add(module_dir)
        pom_path = module_dir / "pom.xml"
        if not pom_path.is_file():
            problems.append(f"module_pom_missing:{module_dir.relative_to(root)}")
            return
        try:
            model = _pom_model(pom_path, inherited_group, inherited_version, inherited_properties)
        except (ET.ParseError, OSError) as exc:
            problems.append(f"module_pom_unreadable:{module_dir.relative_to(root)}:{type(exc).__name__}")
            return
        rel = "." if module_dir == root else module_dir.relative_to(root).as_posix()
        coord = ":".join(part for part in (model["group_id"], model["artifact_id"]) if part)
        deploy_hints = []
        if model["packaging"] == "war":
            deploy_hints.append("war_packaging")
        for plugin_id in ("spring-boot-maven-plugin", "maven-shade-plugin", "maven-assembly-plugin"):
            if plugin_id in model["plugins"]:
                deploy_hints.append(plugin_id)
        modules.append(
            {
                "module": rel,
                "module_dir": str(module_dir),
                "coord": coord,
                "group_id": model["group_id"],
                "artifact_id": model["artifact_id"],
                "version": model["version"],
                "packaging": model["packaging"],
                "dependencies": model["dependencies"],
                "deploy_hints": deploy_hints,
                "properties": model["properties"],
                "declared_source_paths": model["source_paths"],
                "declared_resource_paths": model["resource_paths"],
            }
        )
        for child in model["module_paths"]:
            visit(module_dir / child, model["group_id"], model["version"], model["properties"])

    visit(root)
    modules.sort(key=lambda item: (item["module"] != ".", item["module"]))
    return {
        "status": "partial" if problems else "complete",
        "reason_codes": problems,
        "modules": modules,
    }


def _resolve_target(modules, target_module):
    selector = str(target_module or "").strip().replace("\\", "/").rstrip("/")
    if selector in ("", "root", "__root__", "./"):
        selector = "."
    matches = []
    for item in modules:
        aliases = {
            item.get("module", ""),
            item.get("artifact_id", ""),
            item.get("coord", ""),
            Path(item.get("module_dir", "")).name,
        }
        if selector in aliases:
            matches.append(item)
    return matches[0] if len(matches) == 1 else None


def build_project_scope(project_dir, target_module):
    """Build one canonical source/resource scope from the confirmed target module."""
    root = Path(project_dir).resolve()
    discovery = discover_maven_modules(root)
    modules = discovery["modules"]
    target = _resolve_target(modules, target_module)
    if not target:
        return {
            "schema": "java-upgrade-analyzer.project-scope.v1",
            "status": "insufficient",
            "reason_codes": ["target_module_unresolved"],
            "target_module": str(target_module or ""),
            "candidate_modules": [item.get("module") for item in modules],
            "included_modules": [],
            "source_roots": [],
            "resource_roots": [],
        }

    by_coord = {item["coord"]: item for item in modules if item.get("coord")}
    by_artifact = {}
    for item in modules:
        by_artifact.setdefault(item.get("artifact_id"), []).append(item)

    included = []
    seen = set()

    def include(item):
        key = item["module"]
        if key in seen:
            return
        seen.add(key)
        included.append(item)
        for dep in item.get("dependencies") or []:
            dep_item = by_coord.get(dep)
            if not dep_item and ":" not in dep:
                candidates = by_artifact.get(dep) or []
                dep_item = candidates[0] if len(candidates) == 1 else None
            if dep_item:
                include(dep_item)

    include(target)
    source_roots = []
    resource_roots = []
    missing_declared_roots = []

    def resolve_declared(module_dir, value, properties):
        replacements = {
            'basedir': str(module_dir),
            'project.basedir': str(module_dir),
            'pom.basedir': str(module_dir),
            **{str(key): str(val) for key, val in (properties or {}).items()},
        }
        text = str(value or '').strip()
        for _ in range(5):
            updated = re.sub(
                r'\$\{([^}]+)\}',
                lambda match: replacements.get(match.group(1), match.group(0)),
                text,
            )
            if updated == text:
                break
            text = updated
        candidate = Path(text)
        return candidate.resolve() if candidate.is_absolute() else (module_dir / candidate).resolve()

    for item in included:
        module_dir = Path(item["module_dir"])
        declared_sources = list(item.get('declared_source_paths') or [])
        source_candidates = [module_dir / relative for relative in ('src/main/java', 'src/main/kotlin', 'src/main/groovy')]
        source_candidates.extend(
            resolve_declared(module_dir, value, item.get('properties')) for value in declared_sources
        )
        declared_source_candidates = set(source_candidates[-len(declared_sources):]) if declared_sources else set()
        for candidate in source_candidates:
            if candidate.is_dir():
                source_roots.append(str(candidate.resolve()))
            elif candidate in declared_source_candidates:
                missing_declared_roots.append(str(candidate))
        resource_candidates = [module_dir / 'src/main/resources']
        resource_candidates.extend(
            resolve_declared(module_dir, value, item.get('properties'))
            for value in (item.get('declared_resource_paths') or [])
        )
        for resources in resource_candidates:
            if resources.is_dir():
                resource_roots.append(str(resources.resolve()))

    reason_codes = list(discovery.get("reason_codes") or [])
    if not source_roots:
        reason_codes.append("system_source_roots_missing")
    if missing_declared_roots:
        reason_codes.append('declared_source_roots_missing')
    status = "insufficient" if not source_roots else ("partial" if reason_codes else "complete")
    payload = {
        "schema": "java-upgrade-analyzer.project-scope.v1",
        "status": status,
        "reason_codes": reason_codes,
        "system_source": str(root),
        "target_module": target["module"],
        "target_coord": target.get("coord", ""),
        "included_modules": [item["module"] for item in included],
        "included_module_coords": sorted({item.get("coord", "") for item in included if item.get("coord")}),
        "source_roots": sorted(set(source_roots)),
        "resource_roots": sorted(set(resource_roots)),
        "excluded_modules": sorted(item["module"] for item in modules if item["module"] not in seen),
        "candidate_modules": [item["module"] for item in modules],
        "missing_declared_roots": sorted(set(missing_declared_roots)),
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    payload["scope_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload


def aggregate_coverage_status(statuses):
    normalized = [item for item in statuses if item in COVERAGE_STATUSES]
    if not normalized or all(item == "not_applicable" for item in normalized):
        return "not_applicable"
    return max(normalized, key=lambda item: _STATUS_RANK[item])


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_revision(project_dir, ref="HEAD"):
    result = subprocess.run(
        ["git", "rev-parse", str(ref)], cwd=str(project_dir), text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def build_provenance(project_dir, side, ref, module, build_command, artifact_path="", jdk_home=""):
    artifact = Path(artifact_path).resolve() if artifact_path else None
    return {
        "schema": "java-upgrade-analyzer.build-provenance.v1",
        "side": side,
        "ref": str(ref or ""),
        "revision": git_revision(project_dir, ref or "HEAD"),
        "target_module": str(module or ""),
        "jdk_home": str(jdk_home or ""),
        "build_command": str(build_command or ""),
        "artifact_path": str(artifact) if artifact else "",
        "artifact_sha256": sha256_file(artifact) if artifact and artifact.is_file() else "",
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }


def _csv_rows(path):
    if not Path(path).is_file():
        return []
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def derive_coverage_report(report_dir, project_scope=None):
    """Derive coverage from evidence artifacts; never act as an additional truth source."""
    report = Path(report_dir)
    components = []

    scope = dict(project_scope or {})
    components.append({
        "id": "project_scope",
        "status": scope.get("status") or "insufficient",
        "reason_codes": list(scope.get("reason_codes") or ["project_scope_missing"]),
        "evidence": [".runtime/state/main_state.json#project_scope"],
    })

    dep_path = report / "evidence" / "dependencies" / "dep_changes.csv"
    dep_rows = _csv_rows(dep_path)
    if dep_path.is_file():
        ambiguous = [row for row in dep_rows if row.get("pairing_reason_code")]
        unresolved = [row for row in dep_rows if row.get("resolution_status") == "unresolved"]
        status = "partial" if unresolved else "complete"
        reasons = []
        if ambiguous:
            reasons.append("dependency_pairing_ambiguous")
        if unresolved and not ambiguous:
            reasons.append("dependency_coordinates_unresolved")
    else:
        status, reasons = "not_applicable", ["step1_not_executed"]
    components.append({
        "id": "dependency_diff", "status": status, "reason_codes": reasons,
        "evidence": ["evidence/dependencies/dep_changes.csv"] if dep_path.is_file() else [],
        "metrics": {"rows": len(dep_rows)},
    })

    provenance_path = report / "evidence" / "dependencies" / "build_provenance.json"
    if provenance_path.is_file():
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        both_ok = bool(provenance.get("both_builds_succeeded"))
        complete_hashes = all(item.get("artifact_sha256") for item in provenance.get("sides") or [])
        provenance_status = "complete" if both_ok and complete_hashes else ("partial" if both_ok else "insufficient")
        provenance_reasons = [] if provenance_status == "complete" else [
            "artifact_hash_missing" if both_ok else "base_or_current_build_not_succeeded"
        ]
    else:
        provenance_status, provenance_reasons = "not_applicable", ["step1_not_executed"]
    components.append({
        "id": "build_provenance", "status": provenance_status,
        "reason_codes": provenance_reasons,
        "evidence": ["evidence/dependencies/build_provenance.json"] if provenance_path.is_file() else [],
    })

    static_scan_dir = report / "evidence" / "static_scan"
    step3_coverage_path = report / ".runtime" / "coverage" / "s3_coverage.json"
    if step3_coverage_path.is_file():
        try:
            step3_coverage = json.loads(step3_coverage_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            step3_coverage = {'status': 'insufficient', 'reason_codes': ['step3_coverage_invalid']}
    else:
        step3_coverage = {
            'status': 'not_applicable' if not any(static_scan_dir.glob('s3_*')) else 'partial',
            'reason_codes': ['step3_not_executed'] if not any(static_scan_dir.glob('s3_*')) else ['step3_coverage_missing'],
        }
    components.append({
        'id': 'static_scan',
        'status': step3_coverage.get('status') or 'insufficient',
        'reason_codes': list(step3_coverage.get('reason_codes') or []),
        'evidence': ['.runtime/coverage/s3_coverage.json'] if step3_coverage_path.is_file() else [],
        'metrics': step3_coverage.get('metrics') or {},
    })

    api_changes_dir = report / "evidence" / "api_changes"
    api_path = api_changes_dir / "all_changed_apis.csv"
    api_rows = _csv_rows(api_path)
    step4_coverage_path = report / ".runtime" / "coverage" / "s4_coverage.json"
    step4_coverage = {}
    if step4_coverage_path.is_file():
        try:
            step4_coverage = json.loads(step4_coverage_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            step4_coverage = {}
    binary_component = dict(step4_coverage.get('binary_api_diff') or {})
    if api_path.is_file():
        binary_status = binary_component.get('status') or "partial"
        binary_reasons = list(binary_component.get('reason_codes') or (
            [] if binary_status == 'complete' else ['step4_coverage_missing']
        ))
    else:
        binary_status, binary_reasons = "not_applicable", ["step4_not_executed"]
    components.append({
        "id": "binary_api_diff", "status": binary_status, "reason_codes": binary_reasons,
        "evidence": ["evidence/api_changes/all_changed_apis.csv"] if api_path.is_file() else [],
        "metrics": {"changed_apis": len(api_rows), **(binary_component.get('metrics') or {})},
    })

    behavior_files = sorted(api_changes_dir.glob("*_gitdiff_api_changes.txt"))
    behavior_component = dict(step4_coverage.get('behavior_diff') or {})
    if behavior_component:
        behavior_status = behavior_component.get('status') or 'insufficient'
        behavior_reasons = list(behavior_component.get('reason_codes') or [])
    elif not dep_path.is_file():
        behavior_status, behavior_reasons = "not_applicable", ["step1_not_executed"]
    elif not dep_rows:
        behavior_status, behavior_reasons = "not_applicable", ["no_dependency_changes"]
    elif behavior_files:
        behavior_status, behavior_reasons = "complete", []
    else:
        behavior_status, behavior_reasons = "partial", ["dependency_source_diff_not_available"]
    components.append({
        "id": "behavior_diff", "status": behavior_status, "reason_codes": behavior_reasons,
        "evidence": [str(path.relative_to(report)) for path in behavior_files],
        "metrics": behavior_component.get('metrics') or {},
    })

    call_chain_dir = report / "evidence" / "call_chain"
    step5_summary = call_chain_dir / "summary.json"
    graph_stats = {}
    if step5_summary.is_file():
        try:
            step5_payload = json.loads(step5_summary.read_text(encoding="utf-8"))
            graph_stats = (
                step5_payload.get('graph_stats')
                or (step5_payload.get('meta') or {}).get('graph_stats')
                or {}
            )
        except (OSError, json.JSONDecodeError):
            step5_payload, graph_stats = {}, {}
    else:
        step5_payload = {}
    bytecode = dict(graph_stats.get("business_bytecode") or {})
    components.append({
        "id": "business_bytecode_graph",
        "status": bytecode.get("status") or ("partial" if step5_summary.is_file() else "not_applicable"),
        "reason_codes": (
            [] if bytecode.get("status") == "complete"
            else (["compiled_business_classes_not_available"] if step5_summary.is_file() else ["step5_not_executed"])
        ),
        "evidence": ["evidence/call_chain/summary.json"] if step5_summary.is_file() else [],
        "metrics": bytecode,
    })

    if step5_summary.is_file():
        total = int(step5_payload.get('total_apis') or 0)
        completed = sum(int(step5_payload.get(key) or 0) for key in (
            'reachable', 'uncertain', 'not_analyzed', 'not_found_in_static_analysis'
        ))
        reachability_status = 'complete' if total == completed and not int(step5_payload.get('not_analyzed') or 0) else (
            'partial' if completed else ('not_applicable' if total == 0 else 'insufficient')
        )
        reachability_reasons = []
        if total != completed:
            reachability_reasons.append('step5_target_count_mismatch')
        if int(step5_payload.get('not_analyzed') or 0):
            reachability_reasons.append('step5_not_analyzed_targets')
    else:
        total = completed = 0
        reachability_status, reachability_reasons = 'not_applicable', ['step5_not_executed']
    components.append({
        'id': 'business_reachability',
        'status': reachability_status,
        'reason_codes': reachability_reasons,
        'evidence': ['evidence/call_chain/summary.json'] if step5_summary.is_file() else [],
        'metrics': {
            'target_apis': total,
            'completed_results': completed,
            'reachable': int(step5_payload.get('reachable') or 0),
            'uncertain': int(step5_payload.get('uncertain') or 0),
            'not_analyzed': int(step5_payload.get('not_analyzed') or 0),
            'not_found_in_static_analysis': int(step5_payload.get('not_found_in_static_analysis') or 0),
        },
    })

    alignment_path = call_chain_dir / 'source_artifact_alignment.json'
    if alignment_path.is_file():
        try:
            alignment = json.loads(alignment_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            alignment = {'status': 'unverified', 'reason_codes': ['source_alignment_invalid']}
        alignment_state = alignment.get('status')
        alignment_status = 'complete' if alignment_state == 'aligned' else 'partial'
        alignment_reasons = list(alignment.get('reason_codes') or [])
    else:
        alignment, alignment_status, alignment_reasons = {}, 'not_applicable', ['step5_not_executed']
    components.append({
        'id': 'source_artifact_alignment',
        'status': alignment_status,
        'reason_codes': alignment_reasons,
        'evidence': ['evidence/call_chain/source_artifact_alignment.json'] if alignment_path.is_file() else [],
        'metrics': alignment,
    })

    artifact_bytecode = dict(graph_stats.get("artifact_bytecode") or {})
    artifact_status = artifact_bytecode.get("status") or (
        "partial" if step5_summary.is_file() else "not_applicable"
    )
    components.append({
        "id": "artifact_bytecode_dependencies",
        "status": artifact_status,
        "reason_codes": list(artifact_bytecode.get("reason_codes") or (
            [] if artifact_status == "complete"
            else (["s5_artifact_bytecode_catalog_missing"] if step5_summary.is_file() else ["step5_not_executed"])
        )),
        "evidence": [
            item for item in (
                f".runtime/cache/{STEP5_ARTIFACT_BYTECODE_CATALOG_FILE}",
                "evidence/call_chain/summary.json",
            )
            if (report / item).is_file()
        ],
        "metrics": artifact_bytecode,
    })

    indirect_usage = dict(graph_stats.get("indirect_usage") or {})
    indirect_status = indirect_usage.get("status") or (
        "partial" if step5_summary.is_file() else "not_applicable"
    )
    components.append({
        "id": "indirect_usage_matrix",
        "status": indirect_status,
        "reason_codes": list(indirect_usage.get("reason_codes") or (
            [] if indirect_status in {"complete", "not_applicable"}
            else (["indirect_usage_coverage_missing"] if step5_summary.is_file() else ["step5_not_executed"])
        )),
        "evidence": ["evidence/call_chain/summary.json"] if step5_summary.is_file() else [],
        "metrics": {
            "analyzers": indirect_usage.get("analyzers") or {},
            "matrix": indirect_usage.get("matrix") or {},
            "source_methods_scanned": int(indirect_usage.get("source_methods_scanned") or 0),
            "resource_files_scanned": int(indirect_usage.get("resource_files_scanned") or 0),
            "merged_edges": int(indirect_usage.get("merged_edges") or 0),
        },
    })

    adapter_path = call_chain_dir / "framework_adapters.json"
    if adapter_path.is_file():
        try:
            adapters = json.loads(adapter_path.read_text(encoding="utf-8")).get("adapters") or []
        except (OSError, json.JSONDecodeError):
            adapters = []
        for adapter in adapters:
            components.append({
                "id": f"framework_adapter:{adapter.get('adapter')}",
                "status": adapter.get("status") or "insufficient",
                "reason_codes": ["adapter_execution_errors"] if adapter.get("errors") else [],
                "evidence": ["evidence/call_chain/framework_adapters.json"],
                "metrics": adapter.get("metrics") or {},
            })

    overall = aggregate_coverage_status(item["status"] for item in components)
    critical_ids = {
        'project_scope', 'dependency_diff', 'build_provenance', 'binary_api_diff',
        'artifact_bytecode_dependencies', 'source_artifact_alignment',
        'indirect_usage_matrix',
    }
    critical_incomplete = [
        item['id'] for item in components
        if item['id'] in critical_ids and item['status'] not in {'complete', 'not_applicable'}
    ]
    return {
        "schema": "java-upgrade-analyzer.coverage.v1",
        "derived": True,
        "overall_status": overall,
        "critical_incomplete": critical_incomplete,
        "components": components,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def write_coverage_report(report_dir, project_scope=None):
    payload = derive_coverage_report(report_dir, project_scope=project_scope)
    # Direct/legacy script invocations do not carry the confirmed project scope.
    # Keep their coverage visible but advisory; orchestrated runs pass the scope
    # and receive enforceable standard-mode gates.
    payload['enforcement'] = (
        'required' if project_scope and project_scope.get('status') in {'complete', 'partial'}
        else 'advisory'
    )
    path = Path(report_dir) / ".runtime" / "coverage" / "coverage.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload
