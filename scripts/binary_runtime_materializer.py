#!/usr/bin/env python3
"""Materialize a binary-first runtime config from retained Step1 artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping
import zipfile


class BinaryRuntimeMaterializationError(RuntimeError):
    def __init__(self, reason_code: str, detail: str):
        self.reason_code = str(reason_code)
        self.detail = str(detail)
        super().__init__(f"{self.reason_code}: {self.detail}")


def _load_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_EVIDENCE_INVALID", f"{path}: {error}"
        ) from error
    if not isinstance(payload, dict):
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_EVIDENCE_INVALID", f"{path}: root_not_object"
        )
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _existing_sha(path_value: Any, expected: Any, *, label: str) -> Path:
    path = Path(str(path_value or "")).expanduser().resolve()
    if not path.is_file():
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_ARTIFACT_MISSING", f"{label}: {path}"
        )
    actual = _sha256(path)
    if expected and actual != str(expected).lower():
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_ARTIFACT_DIGEST_MISMATCH",
            f"{label}: expected={expected}; actual={actual}",
        )
    return path


def _coord_with_version(item: Mapping[str, Any]) -> tuple[str, str]:
    coord = str(item.get("coord") or "").strip()
    version = str(item.get("version") or "").strip()
    if not coord or not version:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_COORDINATE_MISSING", str(item.get("lib_entry") or "")
        )
    parts = coord.split(":")
    if len(parts) not in {2, 3}:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_COORDINATE_INVALID", coord
        )
    lineage = coord
    return f"{coord}:{version}", lineage


def _properties(content: bytes) -> dict[str, str]:
    result = {}
    pending = ""
    text_value = content.decode("iso-8859-1").replace("\r\n", "\n").replace("\r", "\n")
    for physical in text_value.split("\n"):
        line = pending + (physical.lstrip() if pending else physical)
        if (len(line) - len(line.rstrip("\\"))) % 2:
            pending = line[:-1]
            continue
        pending = ""
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        separator = next((index for index, value in enumerate(stripped) if value in "=:"), -1)
        if separator < 0:
            parts = stripped.split(None, 1)
            key, value = parts[0], parts[1] if len(parts) == 2 else ""
        else:
            key, value = stripped[:separator], stripped[separator + 1:]
        result[key.strip()] = value.strip()
    return result


def _packaged_runtime_configuration(path: Path) -> tuple[dict[str, str], list[str]]:
    """Read only unambiguous packaged Properties inputs; YAML remains explicit gap."""
    properties: dict[str, str] = {}
    gaps = []
    try:
        with zipfile.ZipFile(path) as archive:
            names = {
                info.filename for info in archive.infolist() if not info.is_dir()
            }
            property_names = sorted(
                name for name in names
                if name in {"application.properties", "config/application.properties"}
            )
            yaml_names = sorted(
                name for name in names
                if name in {
                    "application.yml", "application.yaml",
                    "config/application.yml", "config/application.yaml",
                }
            )
            if len(property_names) > 1:
                gaps.append("packaged_default_properties_precedence_ambiguous")
            elif property_names:
                properties.update(_properties(archive.read(property_names[0])))
            if yaml_names:
                gaps.append("packaged_yaml_condition_inputs_not_materialized")
            profiles = [
                value.strip() for value in properties.get("spring.profiles.active", "").split(",")
                if value.strip()
            ]
            for profile in profiles:
                variants = sorted(
                    name for name in names
                    if name in {
                        f"application-{profile}.properties",
                        f"config/application-{profile}.properties",
                    }
                )
                if len(variants) == 1:
                    properties.update(_properties(archive.read(variants[0])))
                elif len(variants) > 1:
                    gaps.append(f"packaged_profile_properties_precedence_ambiguous:{profile}")
    except (OSError, zipfile.BadZipFile, UnicodeError) as error:
        gaps.append(f"packaged_configuration_unreadable:{type(error).__name__}")
    return properties, sorted(set(gaps))


def _side_config(
    side: str,
    manifest: Mapping[str, Any],
    provenance: Mapping[str, Any],
    runtime_overrides: Mapping[str, Any],
) -> dict[str, Any]:
    business_rows = [
        dict(item)
        for item in manifest.get("business_artifacts") or ()
        if str(item.get("side") or "") == side
    ]
    if len(business_rows) != 1:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_BUSINESS_ARTIFACT_CARDINALITY",
            f"{side}: expected=1; actual={len(business_rows)}",
        )
    business = business_rows[0]
    business_path = _existing_sha(
        business.get("retained_path"), business.get("sha256"),
        label=f"{side}:business",
    )
    outer_path = _existing_sha(
        business.get("outer_artifact_path"),
        business.get("outer_artifact_sha256"),
        label=f"{side}:outer",
    )
    provenance_rows = [
        dict(item)
        for item in provenance.get("sides") or ()
        if str(item.get("side") or "") == side
    ]
    if len(provenance_rows) != 1:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_PROVENANCE_CARDINALITY", side
        )
    side_provenance = provenance_rows[0]
    jdk_home = str(
        runtime_overrides.get(f"{side}_jdk_home")
        or side_provenance.get("jdk_home")
        or ""
    ).strip()
    if not jdk_home:
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_JDK_HOME_MISSING", side
        )

    module = str(side_provenance.get("target_module") or "application").strip()
    artifacts = [{
        "path": str(business_path),
        "outer_artifact_path": str(outer_path),
        "container_entry": "BOOT-INF/classes/"
        if business.get("container_and_launcher_kind")
        == "spring-boot-executable-jar"
        else (
            "WEB-INF/classes/"
            if business.get("container_and_launcher_kind") == "servlet-war"
            else "<artifact>"
        ),
        "logical_location": "application/business-classes.jar",
        "loader_realm": "application-loader",
        "path_kind": "business_classes",
        "slot": 0,
        "coord": f"application:{module}:{side}",
        "lineage": "application:business",
        "runtime_code_source_origin_identity": (
            f"sha256:{business.get('outer_artifact_sha256')}#business-classes"
        ),
    }]
    dependency_rows = sorted(
        (
            dict(item)
            for item in manifest.get("items") or ()
            if str(item.get("side") or "") == side
            and "binary_runtime" in set(item.get("purposes") or ())
        ),
        key=lambda item: (
            int(item.get("runtime_classpath_index") or 0),
            str(item.get("lib_entry") or ""),
        ),
    )
    for slot, item in enumerate(dependency_rows, start=1):
        path = _existing_sha(
            item.get("retained_path"), item.get("nested_jar_sha256"),
            label=f"{side}:{item.get('lib_entry')}",
        )
        coord, lineage = _coord_with_version(item)
        artifacts.append({
            "path": str(path),
            "outer_artifact_path": str(outer_path),
            "container_entry": str(item.get("lib_entry") or ""),
            "logical_location": f"dependencies/{slot:05d}-{path.name}",
            "loader_realm": "application-loader",
            "path_kind": "classpath",
            "slot": slot,
            "coord": coord,
            "lineage": lineage,
            "runtime_code_source_origin_identity": (
                f"sha256:{item.get('outer_artifact_sha256')}#"
                f"{item.get('lib_entry')}"
            ),
        })

    side_coverage = dict((manifest.get("runtime_closure") or {}).get(side) or {})
    closure_status = str(side_coverage.get("coverage_status") or "complete")
    packaged_properties, configuration_gaps = _packaged_runtime_configuration(
        business_path
    )
    supplied_properties = dict(
        runtime_overrides.get(f"{side}_resolved_configuration_properties")
        or runtime_overrides.get("resolved_configuration_properties")
        or {}
    )
    resolved_properties = {
        **packaged_properties,
        **{str(key): str(value) for key, value in supplied_properties.items()},
    }
    active_profiles = list(
        runtime_overrides.get("active_profile_identities")
        or tuple(
            item.strip()
            for item in resolved_properties.get("spring.profiles.active", "").split(",")
            if item.strip()
        )
        or ("default",)
    )
    external_configs = list(
        runtime_overrides.get("external_config_snapshot_identities") or ()
    )
    agent_profiles = list(
        runtime_overrides.get("agent_transformer_plugin_profile_identities") or ()
    )
    runtime_profile = {
        "container_and_launcher_kind": str(
            business.get("container_and_launcher_kind") or "java-classpath"
        ),
        "loader_topology": {
            "coverage_status": "complete",
            "entrypoint_realms": ["application-loader"],
            "realms": [{
                "identity": "platform-loader",
                "kind": "platform",
                "delegation": "parent_first",
                "module_mode": "named-platform",
            }, {
                "identity": "application-loader",
                "kind": "application",
                "parent": "platform-loader",
                "delegation": "parent_first",
                "module_mode": "unnamed",
            }],
        },
        "runtime_security_and_package_sealing_policy_identity": (
            "standard-unsealed-unsigned-v1"
        ),
        "active_profile_identities": active_profiles,
        "resolved_configuration_properties": resolved_properties,
        "runtime_configuration_coverage_status": (
            "complete"
            if not configuration_gaps and (not external_configs or supplied_properties)
            else "partial"
        ),
        "external_config_snapshot_identities": external_configs,
        "agent_transformer_plugin_profile_identities": agent_profiles,
        "business_entrypoint_profile": {
            "discovery_mode": "binary_auto",
            "coverage_status": "complete",
            "methods": [],
        },
        "runtime_class_closure_coverage_status": closure_status,
        "resource_selection_coverage_status": (
            "complete"
            if not configuration_gaps and (not external_configs or supplied_properties)
            else "partial"
        ),
        "runtime_configuration_coverage_gaps": sorted(set(
            configuration_gaps
            + (["external_configuration_snapshot_content_missing"]
               if external_configs and not supplied_properties else [])
        )),
    }
    input_mode = str(
        side_provenance.get("input_mode")
        or side_provenance.get("source_mode")
        or "provided_artifact"
    )
    if input_mode not in {"checkout_build", "provided_artifact"}:
        input_mode = "provided_artifact"
    build_executed = (
        bool(side_provenance.get("build_executed_by_system"))
        if input_mode == "checkout_build"
        else False
    )
    build_status = (
        str(side_provenance.get("build_execution_status") or "succeeded")
        if input_mode == "checkout_build"
        else "not_executed"
    )
    return {
        "jdk_home": str(Path(jdk_home).expanduser().resolve()),
        "artifacts": artifacts,
        "runtime_profile": runtime_profile,
        "build_identity": {
            "artifact_build_provenance": {
                **side_provenance,
                "input_mode": input_mode,
                "build_executed_by_system": build_executed,
                "build_execution_status": build_status,
                "binary_runtime_materialization": {
                    "source_manifest_schema": manifest.get("schema"),
                    "business_artifact_sha256": business.get("sha256"),
                    "dependency_artifact_sha256": [
                        item.get("nested_jar_sha256") for item in dependency_rows
                    ],
                    "runtime_closure_coverage": side_coverage,
                },
            },
        },
    }


def materialize_binary_pipeline_config(
    report_dir: str | Path,
    *,
    runtime_overrides: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    report = Path(report_dir).resolve()
    dependencies = report / "evidence" / "dependencies"
    manifest = _load_object(dependencies / "dependency_jars.json")
    provenance = _load_object(dependencies / "build_provenance.json")
    # v3 is the first Step1 manifest that proves a two-sided, ordered runtime
    # closure.  Treating an older changed-artifact-only manifest as complete
    # would silently drop unchanged dependencies from binary reachability.
    if manifest.get("schema") != "java-upgrade-analyzer.step1-dependency-jars.v3":
        raise BinaryRuntimeMaterializationError(
            "BINARY_RUNTIME_MANIFEST_SCHEMA_INVALID", str(manifest.get("schema"))
        )
    overrides = dict(runtime_overrides or {})
    base = _side_config("base", manifest, provenance, overrides)
    current = _side_config("current", manifest, provenance, overrides)
    return {
        "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
        "base": base,
        "current": current,
        "runtime_comparison": {
            "comparison_intent": "release_snapshot",
            "profile_correspondence_policy_version": "auto-materialized-v1",
            "controlled_profile_fields": [
                "loader_topology",
                "container_and_launcher_kind",
            ],
            "declared_upgrade_payload_scope": ["artifact-bytes"],
            "changed_or_unknown_profile_fields": [],
        },
        "runtime_materialization": {
            "authority": "step1-retained-final-artifact-closure",
            "manifest": str((dependencies / "dependency_jars.json").resolve()),
            "provenance": str((dependencies / "build_provenance.json").resolve()),
        },
    }


__all__ = [
    "BinaryRuntimeMaterializationError",
    "materialize_binary_pipeline_config",
]
