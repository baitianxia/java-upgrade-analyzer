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

from compat import git_cmd
from csv_io import open_csv_read
from diagnostic_contract import (
    diagnostic_contract_metadata,
    normalize_component_reason_codes,
)
from pipeline_constants import STEP5_ARTIFACT_BYTECODE_CATALOG_FILE


COVERAGE_STATUSES = ("complete", "partial", "insufficient", "not_applicable")
_STATUS_RANK = {"complete": 0, "not_applicable": 0, "partial": 1, "insufficient": 2}


def _text(element, name):
    if element is None:
        return ""
    child = element.find(f"{{*}}{name}")
    return (child.text or "").strip() if child is not None else ""


def _pom_model(
    pom_path, inherited_group="", inherited_version="",
    inherited_properties=None, active_profiles=None, *,
    inherited_artifact="", inherited_dependencies=None,
    inherited_plugins=None, inherited_source_paths=None,
    inherited_resource_paths=None,
):
    root = ET.parse(str(pom_path)).getroot()
    parent = root.find("{*}parent")

    def resolve_inherited(value):
        result = str(value or "").strip()
        replacements = {
            **{
                str(key): str(val)
                for key, val in (inherited_properties or {}).items()
            },
            "project.groupId": inherited_group,
            "pom.groupId": inherited_group,
            "project.version": inherited_version,
            "pom.version": inherited_version,
        }
        for _ in range(8):
            updated = re.sub(
                r'\$\{([^}]+)\}',
                lambda match: replacements.get(match.group(1), match.group(0)),
                result,
            )
            if updated == result:
                break
            result = updated
        return result

    inherits_reactor_parent = bool(
        parent is not None
        and inherited_artifact
        and _text(parent, "artifactId") == inherited_artifact
        and (
            not _text(parent, "groupId")
            or resolve_inherited(_text(parent, "groupId")) == inherited_group
        )
        and (
            not _text(parent, "version")
            or resolve_inherited(_text(parent, "version")) == inherited_version
        )
    )
    group_id = _text(root, "groupId") or _text(parent, "groupId") or inherited_group
    artifact_id = _text(root, "artifactId")
    version = _text(root, "version") or _text(parent, "version") or inherited_version
    packaging = _text(root, "packaging") or "jar"
    selected_profiles = {
        str(profile).strip() for profile in (active_profiles or set())
        if str(profile).strip()
    }
    profile_nodes = root.findall("{*}profiles/{*}profile")
    explicitly_active = [
        profile for profile in profile_nodes
        if _text(profile, "id") in selected_profiles
    ]
    default_active = [
        profile for profile in profile_nodes
        if _text(profile.find("{*}activation"), "activeByDefault").lower()
        == "true"
    ]
    active_profile_nodes = explicitly_active or default_active
    properties = dict(inherited_properties or {}) if inherits_reactor_parent else {}
    properties.update({
        str(child.tag).rsplit('}', 1)[-1]: (child.text or '').strip()
        for child in root.findall('{*}properties/*')
        if (child.text or '').strip()
    })
    for profile in active_profile_nodes:
        properties.update({
            str(child.tag).rsplit('}', 1)[-1]: (child.text or '').strip()
            for child in profile.findall('{*}properties/*')
            if (child.text or '').strip()
        })
    builtin_properties = {
        "project.groupId": group_id,
        "pom.groupId": group_id,
        "project.artifactId": artifact_id,
        "pom.artifactId": artifact_id,
        "project.version": version,
        "pom.version": version,
    }

    def resolve_value(value):
        result = str(value or "").strip()
        replacements = {**properties, **builtin_properties}
        for _ in range(8):
            updated = re.sub(
                r'\$\{([^}]+)\}',
                lambda match: replacements.get(match.group(1), match.group(0)),
                result,
            )
            if updated == result:
                break
            result = updated
        return result

    group_id = resolve_value(group_id)
    artifact_id = resolve_value(artifact_id)
    version = resolve_value(version)
    builtin_properties.update({
        "project.groupId": group_id,
        "pom.groupId": group_id,
        "project.artifactId": artifact_id,
        "pom.artifactId": artifact_id,
        "project.version": version,
        "pom.version": version,
    })

    module_nodes = list(root.findall("{*}modules/{*}module"))
    for profile in active_profile_nodes:
        module_nodes.extend(profile.findall("{*}modules/{*}module"))
    module_paths = list(dict.fromkeys(
        (item.text or "").strip()
        for item in module_nodes
        if (item.text or "").strip()
    ))
    dependency_nodes = list(root.findall("{*}dependencies/{*}dependency"))
    for profile in active_profile_nodes:
        dependency_nodes.extend(
            profile.findall("{*}dependencies/{*}dependency")
        )
    dependency_edges = [
        dict(item) for item in (inherited_dependencies or [])
    ] if inherits_reactor_parent else []
    for dep in dependency_nodes:
        scope = resolve_value(_text(dep, "scope") or "compile").lower()
        optional = resolve_value(_text(dep, "optional")).lower() == "true"
        if scope not in {"compile", "runtime"}:
            continue
        dep_group = resolve_value(_text(dep, "groupId"))
        dep_artifact = resolve_value(_text(dep, "artifactId"))
        if dep_artifact:
            dependency_edges.append({
                "coord": (
                    f"{dep_group}:{dep_artifact}" if dep_group else dep_artifact
                ),
                "optional": optional,
                "scope": scope,
            })
    plugin_nodes = list(root.findall("{*}build/{*}plugins/{*}plugin"))
    for profile in active_profile_nodes:
        plugin_nodes.extend(profile.findall("{*}build/{*}plugins/{*}plugin"))
    plugins = set(inherited_plugins or []) if inherits_reactor_parent else set()
    plugins.update({
        _text(plugin, "artifactId")
        for plugin in plugin_nodes
        if _text(plugin, "artifactId")
    })
    build_nodes = [node for node in [root.find('{*}build')] if node is not None]
    build_nodes.extend(
        node for node in (profile.find('{*}build') for profile in active_profile_nodes)
        if node is not None
    )
    source_paths = list(inherited_source_paths or []) if inherits_reactor_parent else []
    resource_paths = list(inherited_resource_paths or []) if inherits_reactor_parent else []
    for build in build_nodes:
        source_dir = _text(build, 'sourceDirectory')
        if source_dir:
            source_paths.append(source_dir)
        for resource in build.findall('{*}resources/{*}resource'):
            directory = _text(resource, 'directory')
            if directory:
                resource_paths.append(directory)
    for plugin in plugin_nodes:
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
        "dependencies": [item["coord"] for item in dependency_edges],
        "dependency_edges": dependency_edges,
        "plugins": sorted(plugins),
        "properties": properties,
        "source_paths": source_paths,
        "resource_paths": resource_paths,
        "pom_sha256": sha256_file(pom_path),
    }


def discover_maven_modules(project_dir, *, active_profiles=None):
    """Discover the reactor without executing Maven or scanning unrelated repositories."""
    root = Path(project_dir).resolve()
    root_pom = root / "pom.xml"
    if not root_pom.is_file():
        return {"status": "insufficient", "reason_codes": ["maven_root_pom_missing"], "modules": []}

    modules = []
    problems = []
    visited = set()

    def visit(
        module_dir, inherited_group="", inherited_version="",
        inherited_properties=None, inherited_artifact="",
        inherited_dependencies=None, inherited_plugins=None,
        inherited_source_paths=None, inherited_resource_paths=None,
    ):
        module_dir = module_dir.resolve()
        if module_dir in visited:
            return
        visited.add(module_dir)
        pom_path = module_dir / "pom.xml"
        if not pom_path.is_file():
            problems.append(f"module_pom_missing:{module_dir.relative_to(root)}")
            return
        try:
            model = _pom_model(
                pom_path, inherited_group, inherited_version,
                inherited_properties, active_profiles,
                inherited_artifact=inherited_artifact,
                inherited_dependencies=inherited_dependencies,
                inherited_plugins=inherited_plugins,
                inherited_source_paths=inherited_source_paths,
                inherited_resource_paths=inherited_resource_paths,
            )
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
                "dependency_edges": model["dependency_edges"],
                "deploy_hints": deploy_hints,
                "properties": model["properties"],
                "declared_source_paths": model["source_paths"],
                "declared_resource_paths": model["resource_paths"],
                "pom_sha256": model["pom_sha256"],
            }
        )
        for child in model["module_paths"]:
            visit(
                module_dir / child,
                model["group_id"],
                model["version"],
                model["properties"],
                model["artifact_id"],
                model["dependency_edges"],
                model["plugins"],
                model["source_paths"],
                model["resource_paths"],
            )

    visit(root)
    modules.sort(key=lambda item: (item["module"] != ".", item["module"]))
    active_profile_ids = sorted({
        str(profile).strip() for profile in (active_profiles or set())
        if str(profile).strip()
    })
    model_payload = {
        "active_maven_profiles": active_profile_ids,
        "modules": [{
            "module": item["module"],
            "coord": item["coord"],
            "version": item["version"],
            "packaging": item["packaging"],
            "dependency_edges": item["dependency_edges"],
            "deploy_hints": item["deploy_hints"],
            "properties": item["properties"],
            "declared_source_paths": item["declared_source_paths"],
            "declared_resource_paths": item["declared_resource_paths"],
            "pom_sha256": item["pom_sha256"],
        } for item in modules],
    }
    model_canonical = json.dumps(
        model_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return {
        "status": "partial" if problems else "complete",
        "reason_codes": problems,
        "modules": modules,
        "maven_model_hash": hashlib.sha256(
            model_canonical.encode("utf-8")
        ).hexdigest(),
    }


_GRADLE_BUILD_FILES = ("build.gradle", "build.gradle.kts")
_GRADLE_SETTINGS_FILES = ("settings.gradle", "settings.gradle.kts")


def _read_gradle_text(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _strip_gradle_comments(text):
    """Remove comments while preserving quoted strings used by the static model."""
    result = []
    index = 0
    quote = ""
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if quote:
            result.append(char)
            if char == "\\" and index + 1 < len(text):
                index += 1
                result.append(text[index])
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            result.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        if char == "/" and next_char == "*":
            index += 2
            while index + 1 < len(text) and text[index:index + 2] != "*/":
                index += 1
            index += 2
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _gradle_quoted_values(text):
    return [match[1] for match in re.findall(r"(['\"])(.*?)\1", str(text or ""), re.DOTALL)]


def _gradle_assignment(text, names):
    joined = "|".join(re.escape(name) for name in names)
    match = re.search(
        rf"(?m)^\s*(?:{joined})\s*(?:=|\.set\s*\()\s*(['\"])(.*?)\1",
        text,
    )
    return match.group(2).strip() if match else ""


def _gradle_settings_model(root):
    settings_path = next(
        (root / name for name in _GRADLE_SETTINGS_FILES if (root / name).is_file()),
        None,
    )
    text = _strip_gradle_comments(_read_gradle_text(settings_path)) if settings_path else ""
    module_paths = []
    for match in re.finditer(r"(?m)^\s*include\b\s*(?:\((.*?)\)|([^\r\n]+))", text):
        payload = match.group(1) if match.group(1) is not None else match.group(2)
        for value in _gradle_quoted_values(payload):
            normalized = value.strip().strip(":").replace(":", "/")
            if normalized and normalized not in module_paths:
                module_paths.append(normalized)

    project_dirs = {}
    for match in re.finditer(
        r"project\s*\(\s*(['\"])(:[^'\"]+)\1\s*\)\s*\.projectDir\s*=\s*"
        r"(?:file\s*\(|new\s+File\s*\(\s*settingsDir\s*,\s*)?(['\"])(.*?)\3",
        text,
    ):
        gradle_path = match.group(2)
        project_dirs[gradle_path] = match.group(4).strip().replace("\\", "/")

    project_names = {}
    for match in re.finditer(
        r"project\s*\(\s*(['\"])(:[^'\"]+)\1\s*\)\s*\.name\s*=\s*(['\"])(.*?)\3",
        text,
    ):
        project_names[match.group(2)] = match.group(4).strip()

    return {
        "path": str(settings_path or ""),
        "text": text,
        "root_name": _gradle_assignment(text, ("rootProject.name",)),
        "module_paths": module_paths,
        "project_dirs": project_dirs,
        "project_names": project_names,
        "sha256": sha256_file(settings_path) if settings_path else "",
    }


def _gradle_main_source_block(text):
    patterns = (
        r"\bmain\s*\{",
        r"\bnamed\s*\(\s*['\"]main['\"]\s*\)\s*\{",
        r"\bgetByName\s*\(\s*['\"]main['\"]\s*\)\s*\{",
    )
    source_sets = re.search(r"\bsourceSets\s*\{", text)
    start_at = source_sets.end() if source_sets else 0
    match = next(
        (candidate for pattern in patterns
         if (candidate := re.search(pattern, text[start_at:]))),
        None,
    )
    if not match:
        return ""
    brace = text.find("{", start_at + match.start())
    if brace < 0:
        return ""
    depth = 1
    quote = ""
    index = brace + 1
    while index < len(text) and depth:
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in ("'", '"'):
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        index += 1
    return text[brace + 1:index - 1] if depth == 0 else ""


def _gradle_declared_source_paths(text):
    block = _gradle_main_source_block(text)
    if not block:
        return [], []
    sources = []
    resources = []
    for line in block.splitlines():
        if not re.search(r"(?:srcDir|srcDirs|setSrcDirs)", line):
            continue
        target = resources if "resources" in line else sources
        for value in _gradle_quoted_values(line):
            if value and value not in target:
                target.append(value)
    return sources, resources


def _gradle_project_dependencies(text):
    edges = []
    seen = set()
    runtime_configurations = (
        "api", "implementation", "compile", "compileOnly", "runtimeOnly", "runtime",
    )
    configurations = "|".join(runtime_configurations)
    for match in re.finditer(
        rf"(?m)^\s*(?:{configurations})\s*(?:\(|\s+)\s*"
        r"project\s*\(?(?:\s*path\s*:\s*)?\s*(['\"])(:[^'\"]+)\1",
        text,
    ):
        gradle_path = match.group(2)
        if gradle_path in seen:
            continue
        seen.add(gradle_path)
        edges.append({
            "coord": "",
            "module": gradle_path.strip(":").replace(":", "/") or ".",
            "optional": False,
            "scope": "runtime",
        })
    return edges


def _gradle_build_model(build_path, *, inherited_group="", inherited_version="", artifact_id=""):
    text = _strip_gradle_comments(_read_gradle_text(build_path))
    group_id = _gradle_assignment(text, ("group",)) or inherited_group
    version = _gradle_assignment(text, ("version",)) or inherited_version
    archive_name = _gradle_assignment(
        text,
        ("archivesBaseName", "archivesName", "base.archivesName"),
    )
    artifact_id = archive_name or artifact_id or build_path.parent.name
    plugin_tokens = set(re.findall(
        r"(?:id|apply\s+plugin\s*:)\s*\(?\s*['\"]([^'\"]+)['\"]",
        text,
    ))
    packaging = "war" if "war" in plugin_tokens else "jar"
    deploy_hints = []
    if packaging == "war":
        deploy_hints.append("war_plugin")
    if "org.springframework.boot" in plugin_tokens:
        deploy_hints.append("org.springframework.boot")
    if "com.github.johnrengelman.shadow" in plugin_tokens or "com.gradleup.shadow" in plugin_tokens:
        deploy_hints.append("shadow_plugin")
    source_paths, resource_paths = _gradle_declared_source_paths(text)
    dependency_edges = _gradle_project_dependencies(text)
    return {
        "group_id": group_id,
        "artifact_id": artifact_id,
        "version": version,
        "packaging": packaging,
        "dependencies": [],
        "dependency_edges": dependency_edges,
        "deploy_hints": deploy_hints,
        "properties": {},
        "source_paths": source_paths,
        "resource_paths": resource_paths,
        "build_sha256": sha256_file(build_path),
    }


def _gradle_root_config_hash(root, settings_model):
    paths = []
    for name in (*_GRADLE_SETTINGS_FILES, *_GRADLE_BUILD_FILES, "gradle.properties"):
        candidate = root / name
        if candidate.is_file():
            paths.append(candidate)
    catalog = root / "gradle" / "libs.versions.toml"
    if catalog.is_file():
        paths.append(catalog)
    build_src = root / "buildSrc"
    if build_src.is_dir():
        paths.extend(sorted(
            path for path in build_src.rglob("*")
            if path.is_file() and not any(part in {"build", ".gradle"} for part in path.parts)
        ))
    digest = hashlib.sha256()
    for path in sorted(set(paths), key=lambda item: str(item)):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest() if paths else settings_model.get("sha256", "")


def discover_gradle_modules(project_dir):
    """Build a deterministic Gradle module inventory without executing build logic."""
    root = Path(project_dir).resolve()
    settings = _gradle_settings_model(root)
    root_build = next(
        (root / name for name in _GRADLE_BUILD_FILES if (root / name).is_file()),
        None,
    )
    if not root_build and not settings.get("path"):
        return {"status": "insufficient", "reason_codes": ["gradle_root_build_missing"], "modules": []}

    root_text = _strip_gradle_comments(_read_gradle_text(root_build)) if root_build else ""
    inherited_group = _gradle_assignment(root_text, ("group",))
    inherited_version = _gradle_assignment(root_text, ("version",))
    specs = [(".", ":", root)]
    for module in settings.get("module_paths") or []:
        gradle_path = ":" + module.replace("/", ":")
        relative = settings.get("project_dirs", {}).get(gradle_path, module)
        specs.append((module, gradle_path, (root / relative).resolve()))

    modules = []
    problems = []
    for module, gradle_path, module_dir in specs:
        build_path = next(
            (module_dir / name for name in _GRADLE_BUILD_FILES if (module_dir / name).is_file()),
            None,
        )
        default_artifact = (
            settings.get("root_name") or root.name
            if module == "."
            else settings.get("project_names", {}).get(gradle_path) or module_dir.name
        )
        if build_path:
            model = _gradle_build_model(
                build_path,
                inherited_group=inherited_group,
                inherited_version=inherited_version,
                artifact_id=default_artifact,
            )
        elif module != ".":
            # A Gradle project may be configured entirely from the root's
            # subprojects/allprojects blocks and legitimately have no local script.
            model = {
                "group_id": inherited_group,
                "artifact_id": default_artifact,
                "version": inherited_version,
                "packaging": "jar",
                "dependencies": [],
                "dependency_edges": [],
                "deploy_hints": [],
                "properties": {},
                "source_paths": [],
                "resource_paths": [],
                "build_sha256": "",
            }
        else:
            continue
        coord = ":".join(
            part for part in (model["group_id"], model["artifact_id"]) if part
        )
        modules.append({
            "module": module,
            "gradle_path": gradle_path,
            "module_dir": str(module_dir),
            "coord": coord,
            "group_id": model["group_id"],
            "artifact_id": model["artifact_id"],
            "version": model["version"],
            "packaging": model["packaging"],
            "dependencies": model["dependencies"],
            "dependency_edges": model["dependency_edges"],
            "deploy_hints": model["deploy_hints"],
            "properties": model["properties"],
            "declared_source_paths": model["source_paths"],
            "declared_resource_paths": model["resource_paths"],
            "build_sha256": model["build_sha256"],
        })
    modules.sort(key=lambda item: (item["module"] != ".", item["module"]))
    model_payload = {
        "root_config_hash": _gradle_root_config_hash(root, settings),
        "modules": [{
            "module": item["module"],
            "gradle_path": item["gradle_path"],
            "coord": item["coord"],
            "version": item["version"],
            "packaging": item["packaging"],
            "dependency_edges": item["dependency_edges"],
            "deploy_hints": item["deploy_hints"],
            "declared_source_paths": item["declared_source_paths"],
            "declared_resource_paths": item["declared_resource_paths"],
            "build_sha256": item["build_sha256"],
        } for item in modules],
    }
    canonical = json.dumps(model_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "status": "partial" if problems else "complete",
        "reason_codes": problems,
        "modules": modules,
        "gradle_model_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "root_config_hash": model_payload["root_config_hash"],
    }


def detect_project_build_tool(project_dir):
    root = Path(project_dir).resolve()
    if (root / "pom.xml").is_file():
        return "maven"
    if any((root / name).is_file() for name in (*_GRADLE_BUILD_FILES, *_GRADLE_SETTINGS_FILES, "gradlew", "gradlew.bat")):
        return "gradle"
    return "maven"


def discover_project_modules(project_dir, *, build_tool="", active_profiles=None):
    tool = str(build_tool or "").strip().lower() or detect_project_build_tool(project_dir)
    if tool == "gradle":
        return discover_gradle_modules(project_dir)
    return discover_maven_modules(project_dir, active_profiles=active_profiles)


def _resolve_target(modules, target_module):
    selector = str(target_module or "").strip().replace("\\", "/").rstrip("/")
    if selector in ("", "root", "__root__", "./"):
        selector = "."
    matches = []
    for item in modules:
        aliases = {
            item.get("module", ""),
            item.get("gradle_path", ""),
            item.get("artifact_id", ""),
            item.get("coord", ""),
            Path(item.get("module_dir", "")).name,
        }
        if selector in aliases:
            matches.append(item)
    return matches[0] if len(matches) == 1 else None


def build_project_scope(project_dir, target_module, *, active_profiles=None, build_tool=""):
    """Build one canonical source/resource scope from the confirmed target module."""
    root = Path(project_dir).resolve()
    tool = str(build_tool or "").strip().lower() or detect_project_build_tool(root)
    discovery = discover_project_modules(
        root, build_tool=tool, active_profiles=active_profiles
    )
    modules = discovery["modules"]
    target = _resolve_target(modules, target_module)
    if not target:
        return {
            "schema": "java-upgrade-analyzer.project-scope.v1",
            "build_tool": tool,
            "status": "insufficient",
            "reason_codes": ["target_module_unresolved"],
            "target_module": str(target_module or ""),
            "candidate_modules": [item.get("module") for item in modules],
            "included_modules": [],
            "source_roots": [],
            "resource_roots": [],
            "active_maven_profiles": sorted({
                str(profile).strip() for profile in (active_profiles or set())
                if tool == "maven" and str(profile).strip()
            }),
        }

    by_coord = {item["coord"]: item for item in modules if item.get("coord")}
    by_artifact = {}
    for item in modules:
        by_artifact.setdefault(item.get("artifact_id"), []).append(item)

    included = []
    seen = set()
    by_module = {item.get("module"): item for item in modules}

    def include(item):
        key = item["module"]
        if key in seen:
            return
        seen.add(key)
        included.append(item)
        dependency_edges = item.get("dependency_edges") or [
            {"coord": dep, "optional": False}
            for dep in (item.get("dependencies") or [])
        ]
        for edge in dependency_edges:
            if edge.get("optional") and item["module"] != target["module"]:
                continue
            dep = str(edge.get("coord") or "")
            dep_item = by_module.get(str(edge.get("module") or ""))
            dep_item = dep_item or by_coord.get(dep)
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
    active_profile_ids = sorted({
        str(profile).strip() for profile in (active_profiles or set())
        if tool == "maven" and str(profile).strip()
    })
    source_revision = git_revision(root)
    reactor_root = next(
        (item for item in modules if item.get("module") == "."), {}
    )
    effective_model_payload = {
        "build_tool": tool,
        "active_maven_profiles": active_profile_ids,
        "target_module": target["module"],
        "reactor_root_pom_sha256": reactor_root.get("pom_sha256", ""),
        "gradle_root_config_hash": discovery.get("root_config_hash", ""),
        "included_modules": [{
            "module": item["module"],
            "coord": item["coord"],
            "version": item["version"],
            "packaging": item["packaging"],
            "dependency_edges": item["dependency_edges"],
            "deploy_hints": item["deploy_hints"],
            "properties": item["properties"],
            "declared_source_paths": item["declared_source_paths"],
            "declared_resource_paths": item["declared_resource_paths"],
            "pom_sha256": item.get("pom_sha256", ""),
            "build_sha256": item.get("build_sha256", ""),
        } for item in included],
    }
    build_model_hash = hashlib.sha256(json.dumps(
        effective_model_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    source_state_payload = {
        "source_revision": source_revision,
        "build_model_hash": build_model_hash,
        "active_maven_profiles": active_profile_ids,
        "target_module": target["module"],
    }
    source_state_hash = hashlib.sha256(json.dumps(
        source_state_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    payload = {
        "schema": "java-upgrade-analyzer.project-scope.v1",
        "build_tool": tool,
        "status": status,
        "reason_codes": reason_codes,
        "system_source": str(root),
        "source_revision": source_revision,
        "build_model_hash": build_model_hash,
        "maven_model_hash": build_model_hash if tool == "maven" else "",
        "gradle_model_hash": build_model_hash if tool == "gradle" else "",
        "source_state_hash": source_state_hash,
        "target_module": target["module"],
        "target_coord": target.get("coord", ""),
        "included_modules": [item["module"] for item in included],
        "included_module_coords": sorted({item.get("coord", "") for item in included if item.get("coord")}),
        "source_roots": sorted(set(source_roots)),
        "resource_roots": sorted(set(resource_roots)),
        "excluded_modules": sorted(item["module"] for item in modules if item["module"] not in seen),
        "candidate_modules": [item["module"] for item in modules],
        "missing_declared_roots": sorted(set(missing_declared_roots)),
        "active_maven_profiles": active_profile_ids,
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
        git_cmd() + ["rev-parse", str(ref)], cwd=str(project_dir), text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def project_scope_provenance_fields(project_scope):
    scope = dict(project_scope or {})
    return {
        "project_scope_hash": str(scope.get("scope_hash") or ""),
        "source_state_hash": str(scope.get("source_state_hash") or ""),
        "build_tool": str(scope.get("build_tool") or "maven"),
        "build_model_hash": str(
            scope.get("build_model_hash")
            or scope.get("maven_model_hash")
            or scope.get("gradle_model_hash")
            or ""
        ),
        "maven_model_hash": str(scope.get("maven_model_hash") or ""),
        "gradle_model_hash": str(scope.get("gradle_model_hash") or ""),
        "active_maven_profiles": sorted({
            str(profile).strip()
            for profile in (scope.get("active_maven_profiles") or [])
            if str(profile).strip()
        }),
    }


def project_scope_provenance_errors(project_scope, provenance_side):
    expected = project_scope_provenance_fields(project_scope)
    actual = project_scope_provenance_fields({
        "scope_hash": (provenance_side or {}).get("project_scope_hash"),
        "source_state_hash": (provenance_side or {}).get("source_state_hash"),
        "build_tool": (
            (provenance_side or {}).get("build_tool")
            or (project_scope or {}).get("build_tool")
            or "maven"
        ),
        "build_model_hash": (
            (provenance_side or {}).get("build_model_hash")
            or (provenance_side or {}).get("maven_model_hash")
            or (provenance_side or {}).get("gradle_model_hash")
        ),
        "maven_model_hash": (provenance_side or {}).get("maven_model_hash"),
        "gradle_model_hash": (provenance_side or {}).get("gradle_model_hash"),
        "active_maven_profiles": (
            (provenance_side or {}).get("active_maven_profiles") or []
        ),
    })
    errors = []
    for key, reason in (
        ("project_scope_hash", "build_project_scope_mismatch"),
        ("source_state_hash", "build_source_state_mismatch"),
        ("build_model_hash", "build_model_mismatch"),
    ):
        if not expected[key]:
            errors.append(f"project_{key}_missing")
        elif not actual[key]:
            errors.append(f"build_{key}_missing")
        elif expected[key] != actual[key]:
            errors.append(reason)
    if expected.get("build_tool") != actual.get("build_tool"):
        errors.append("build_tool_mismatch")
    if expected.get("build_tool") == "maven" and "active_maven_profiles" not in (project_scope or {}):
        errors.append("project_active_profiles_missing")
    elif expected.get("build_tool") == "maven" and "active_maven_profiles" not in (provenance_side or {}):
        errors.append("build_active_profiles_missing")
    elif expected.get("build_tool") == "maven" and expected["active_maven_profiles"] != actual["active_maven_profiles"]:
        errors.append("build_active_profiles_mismatch")
    return errors


def build_provenance(
    project_dir, side, ref, module, build_command, artifact_path="", jdk_home="",
    *, project_scope=None, active_profiles=None,
):
    artifact = Path(artifact_path).resolve() if artifact_path else None
    scope = project_scope
    if scope is None and module:
        scope = build_project_scope(
            project_dir, module, active_profiles=set(active_profiles or [])
        )
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
        **project_scope_provenance_fields(scope),
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }


def _csv_rows(path):
    if not Path(path).is_file():
        return []
    with open_csv_read(path) as handle:
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
        current_side = next((
            item for item in (provenance.get("sides") or [])
            if str(item.get("side") or "") == "current"
        ), {})
        binding_errors = project_scope_provenance_errors(scope, current_side)
        if not both_ok:
            provenance_status = "insufficient"
            provenance_reasons = ["base_or_current_build_not_succeeded"]
        elif not complete_hashes:
            provenance_status = "partial"
            provenance_reasons = ["artifact_hash_missing"]
        elif binding_errors:
            provenance_status = "insufficient"
            provenance_reasons = binding_errors
        else:
            provenance_status = "complete"
            provenance_reasons = []
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
    dependency_status_csv = api_changes_dir / "dependency_analysis_status.csv"
    dependency_status_json = api_changes_dir / "dependency_analysis_status.json"
    dependency_status_md = api_changes_dir / "dependency_analysis_status.md"
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
        "evidence": [
            value
            for path, value in (
                (api_path, "evidence/api_changes/all_changed_apis.csv"),
                (
                    dependency_status_csv,
                    "evidence/api_changes/dependency_analysis_status.csv",
                ),
                (
                    dependency_status_json,
                    "evidence/api_changes/dependency_analysis_status.json",
                ),
                (
                    dependency_status_md,
                    "evidence/api_changes/dependency_analysis_status.md",
                ),
            )
            if path.is_file()
        ],
        "metrics": {"changed_apis": len(api_rows), **(binary_component.get('metrics') or {})},
    })

    behavior_files = sorted(api_changes_dir.glob("*_gitdiff_api_changes.txt"))
    behavior_bytecode_files = sorted(api_changes_dir.glob("*_bytecode_behavior.json"))
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
        "evidence": [
            str(path.relative_to(report))
            for path in [*behavior_files, *behavior_bytecode_files]
        ],
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

    components = [
        normalize_component_reason_codes(component)
        for component in components
    ]
    overall = aggregate_coverage_status(item["status"] for item in components)
    critical_ids = {
        'project_scope', 'dependency_diff', 'build_provenance', 'binary_api_diff',
        'behavior_diff',
        'artifact_bytecode_dependencies', 'source_artifact_alignment',
        'indirect_usage_matrix',
    }
    critical_incomplete = [
        item['id'] for item in components
        if item['id'] in critical_ids and item['status'] not in {'complete', 'not_applicable'}
    ]
    return {
        "schema": "java-upgrade-analyzer.coverage.v1",
        "diagnostic_contract": diagnostic_contract_metadata(),
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
