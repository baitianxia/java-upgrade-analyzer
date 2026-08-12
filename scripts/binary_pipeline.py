#!/usr/bin/env python3
"""End-to-end binary-first pipeline with source as an optional overlay."""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Any, Mapping

try:
    import resource
except ImportError:  # pragma: no cover - Windows does not provide resource.
    resource = None

from binary_artifact_diff import ArtifactSnapshot, compare_artifact_snapshots, snapshot_archive
from binary_decision_engine import BinaryDecisionEngine, DEFAULT_RULES
from binary_fact_store import BinaryFactStore
from binary_first_contract import (
    BinaryFirstContractError,
    artifact_content_identity,
    canonical_identity,
)
from binary_first_model import (
    AnalysisContext,
    AnalysisScope,
    ArtifactInstance,
    BuildIdentityBundle,
    CrossVersionArtifactPairing,
    FactBuildInputSlice,
    RuntimeComparison,
    RuntimeProfile,
)
from binary_output import activate_binary_generation, write_binary_generation
from binary_platform_image import JdkPlatformImage
from binary_runtime_reconciler import RuntimeCapabilityPolicy, RuntimeReconciler
from binary_semantic_overlay import build_binary_semantic_overlay
from binary_snapshot_cache import cached_snapshot_archive
from binary_source_overlay import build_inline_consumption_overlay, build_source_overlay
from binary_trace_engine import build_binary_traces
from binary_validation_oracle import validate_generation
from enhanced_source_analyzer import analyze_file, extract_call_edges_enhanced
from path_runtime import short_temporary_directory


SUPPORT_MANIFEST_PATH = Path(__file__).with_name("binary_first_support_manifest.json")
PERFORMANCE_GATE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests" / "fixtures" / "binary_first" / "performance_gate.json"
)


class BinaryPipelineError(BinaryFirstContractError):
    pass


class _PhaseTimingRecorder(list):
    """Persist non-authoritative progress after every completed phase."""

    ORDER = (
        "input_and_runtime_profile",
        "artifact_fact_build_and_local_diff",
        "target_independent_runtime_reconciliation",
        "decision_and_projection_freeze",
        "binary_trace",
        "immutable_generation_write",
        "independent_validation",
        "validated_generation_activation",
    )

    def __init__(self, output_root: Path, started: float):
        super().__init__()
        self.started = started
        self.directory = output_root / "binary_observability"
        self.path = self.directory / "latest_in_progress.json"

    def append(self, item):
        item = dict(item or {})
        item.setdefault("peak_rss_bytes", _peak_rss_bytes())
        super().append(item)
        self.directory.mkdir(parents=True, exist_ok=True)
        completed = str((item or {}).get("phase") or "")
        try:
            index = self.ORDER.index(completed)
        except ValueError:
            next_phase = "unknown"
        else:
            next_phase = self.ORDER[index + 1] if index + 1 < len(self.ORDER) else ""
        payload = json.dumps({
            "schema": "java-upgrade-analyzer.binary-progress.v1",
            "status": "completed" if not next_phase else "running",
            "last_completed_phase": completed,
            "current_phase": next_phase,
            "elapsed_seconds": round(time.perf_counter() - self.started, 6),
            "phases": list(self),
            "non_authoritative_observability": True,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(payload, encoding="utf-8")
        temporary.replace(self.path)


SOURCE_INPUT_PURPOSE_VERSION = "source-input-purpose-v2"
SOURCE_FILE_LANGUAGES = {
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin_script",
    ".scala": "scala",
    ".groovy": "groovy",
}


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _peak_rss_bytes() -> int:
    """Return this analyzer process' peak resident set size."""
    if resource is None:
        return 0
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss or 0)
    return value if sys.platform == "darwin" else value * 1024


def _load_json(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BinaryPipelineError("BINARY_PIPELINE_CONFIG_INVALID", str(error)) from error
    if not isinstance(value, dict):
        raise BinaryPipelineError("BINARY_PIPELINE_CONFIG_INVALID", "root must be an object")
    return value


def _source_inputs_contract(config: Mapping[str, Any]) -> dict[str, Any]:
    source_sets = list((config.get("source_overlay") or {}).get("source_sets") or [])
    has_business = any(
        str((item or {}).get("owner_type") or "") == "business"
        for item in source_sets
    )
    has_dependencies = any(
        str((item or {}).get("owner_type") or "") == "dependency"
        for item in source_sets
    )
    raw = dict(config.get("source_inputs") or {})
    business = dict(raw.get("business") or {})
    dependencies = dict(raw.get("dependencies") or {})
    expected_business_status = "available" if has_business else "not_provided"
    expected_dependency_status = "available" if has_dependencies else "not_provided"
    if business and str(business.get("status") or "") != expected_business_status:
        raise BinaryPipelineError(
            "BINARY_BUSINESS_SOURCE_STATUS_MISMATCH",
            "source_inputs.business.status does not match business source sets",
        )
    if dependencies and str(dependencies.get("status") or "") != expected_dependency_status:
        raise BinaryPipelineError(
            "BINARY_DEPENDENCY_SOURCE_STATUS_MISMATCH",
            "source_inputs.dependencies.status does not match dependency source sets",
        )
    return {
        "purpose_version": SOURCE_INPUT_PURPOSE_VERSION,
        "business": {
            "status": expected_business_status,
            "origin": str(business.get("origin") or (
                "provided" if has_business else "not_provided"
            )),
        },
        "dependencies": {
            "status": expected_dependency_status,
            "origin": str(dependencies.get("origin") or (
                "provided" if has_dependencies else "not_provided"
            )),
        },
    }


def _require_binary_authority_gates(support: Mapping[str, Any]) -> None:
    if support.get("authority") != "binary_first_only_fail_closed":
        raise BinaryPipelineError(
            "BINARY_AUTHORITY_MANIFEST_INVALID", str(support.get("authority") or "")
        )
    oracle = support.get("oracle_support_manifest") or {}
    if not oracle.get("production_binary_authority_switch_allowed"):
        raise BinaryPipelineError("BINARY_ORACLE_AUTHORITY_GATE_BLOCKED", "binary_first")
    performance_contract = support.get("performance_gate") or {}
    try:
        performance = _load_json(PERFORMANCE_GATE_PATH)
    except BinaryPipelineError as error:
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_GATE_UNAVAILABLE", str(error)
        ) from error
    if (
        performance.get("status") != "passed"
        or performance.get("blocks_binary_authority_switch") is not False
        or performance_contract.get("status") != "passed"
        or performance_contract.get("blocks_binary_authority_switch") is not False
        or _sha256_file(PERFORMANCE_GATE_PATH) != performance_contract.get("sha256")
    ):
        raise BinaryPipelineError(
            "BINARY_PERFORMANCE_AUTHORITY_GATE_BLOCKED",
            str(PERFORMANCE_GATE_PATH),
        )


def _artifact_descriptors(
    raw_artifacts: list[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    normalized = []
    path_descriptors = []
    slots = set()
    for raw in raw_artifacts:
        path = Path(str(raw.get("path") or "")).expanduser().resolve()
        if not path.is_file():
            raise BinaryPipelineError("BINARY_PIPELINE_ARTIFACT_MISSING", str(path))
        slot = int(raw.get("slot"))
        loader = str(raw.get("loader_realm") or "").strip()
        logical = str(raw.get("logical_location") or "").strip()
        if slot < 0 or (loader, slot) in slots:
            raise BinaryPipelineError(
                "BINARY_PIPELINE_RUNTIME_SLOT_INVALID", f"duplicate/invalid {loader}:{slot}"
            )
        slots.add((loader, slot))
        sha = _sha256_file(path)
        item = {
            **dict(raw), "path": str(path), "content_sha256": sha,
            "byte_length": path.stat().st_size, "slot": slot,
        }
        normalized.append(item)
        path_descriptors.append({
            "logical_location": logical,
            "content_sha256": sha,
            "path_kind": str(raw.get("path_kind") or "classpath"),
            "slot": slot,
            "loader_realm": loader,
        })
    normalized.sort(key=lambda item: (item["loader_realm"], item["slot"], item["logical_location"]))
    path_descriptors.sort(key=lambda item: (item["loader_realm"], item["slot"], item["logical_location"]))
    return normalized, path_descriptors


def _build_identity_bundle(
    side_config: Mapping[str, Any], artifacts: list[dict[str, Any]]
) -> BuildIdentityBundle:
    raw = dict(side_config.get("build_identity") or {})
    provenance = dict(raw.get("artifact_build_provenance") or {})
    if not provenance:
        provenance = {
            "input_mode": "provided_artifact",
            "build_executed_by_system": False,
            "build_execution_status": "not_executed",
            "clean_output_status": "not_applicable_provided_artifact",
            "determinism_status": "unknown_no_build_reproduction_claim",
            "artifact_content_identities": [
                artifact_content_identity(item["content_sha256"], item["byte_length"])
                for item in artifacts
            ],
        }
    return BuildIdentityBundle(
        dict(raw.get("build_environment") or {}),
        dict(raw.get("build_input_manifest") or {}),
        provenance,
    )


def _runtime_profile(
    side_config: Mapping[str, Any],
    platform: JdkPlatformImage,
    path_descriptors: list[dict[str, Any]],
) -> RuntimeProfile:
    raw = dict(side_config.get("runtime_profile") or {})
    supplied_platform = raw.get("runtime_platform_image_identity")
    if supplied_platform and supplied_platform != platform.identity:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_PLATFORM_IDENTITY_MISMATCH", str(supplied_platform)
        )
    raw["runtime_platform_image_identity"] = platform.identity
    raw["target_jvm"] = raw.get("target_jvm") or {
        "vendor": platform.release.get("IMPLEMENTOR", "unknown"),
        "version": platform.release.get("JAVA_VERSION", "unknown"),
        "major": platform.java_major,
    }
    if int((raw["target_jvm"] or {}).get("major") or 0) != platform.java_major:
        raise BinaryPipelineError(
            "BINARY_PIPELINE_TARGET_JVM_MISMATCH", str(raw["target_jvm"])
        )
    raw["target_os"] = raw.get("target_os") or platform.release.get("OS_NAME", "unknown")
    raw["target_arch"] = raw.get("target_arch") or platform.release.get("OS_ARCH", "unknown")
    raw["ordered_runtime_path_entry_descriptors"] = path_descriptors
    if not raw.get("runtime_code_source_origin_mapping_identity"):
        raw["runtime_code_source_origin_mapping_identity"] = _identity(
            "runtime_code_source_origin_mapping_identity",
            {
                "origins": [
                    {
                        "logical_location": item["logical_location"],
                        "origin_identity": next(
                            str(artifact.get("runtime_code_source_origin_identity") or "")
                            for artifact in side_config.get("artifacts") or ()
                            if str(artifact.get("logical_location") or "") == item["logical_location"]
                        ),
                    }
                    for item in path_descriptors
                ]
            },
        )
    required = RuntimeProfile.REQUIRED_FIELDS
    supplied_coverage = dict(raw.get("field_coverage") or {})
    raw["field_coverage"] = {
        key: supplied_coverage.get(key) or ("known" if key in raw else "unknown")
        for key in required
    }
    return RuntimeProfile(raw)


def _artifact_instances(
    artifacts: list[dict[str, Any]], profile: RuntimeProfile
) -> list[tuple[dict[str, Any], ArtifactInstance]]:
    result = []
    for raw in artifacts:
        outer_path = Path(str(raw.get("outer_artifact_path") or raw["path"]))
        outer_sha = _sha256_file(outer_path)
        instance = ArtifactInstance(
            outer_artifact_sha256=outer_sha,
            container_entry=str(raw.get("container_entry") or "<artifact>"),
            content_sha256=raw["content_sha256"],
            runtime_profile_identity=profile.identity,
            path_owner_loader_realm_identity=str(raw.get("loader_realm") or ""),
            runtime_path_kind=str(raw.get("path_kind") or "classpath"),
            runtime_classpath_index=int(raw["slot"]),
            container_loader_policy_version=str(
                raw.get("container_loader_policy_version") or "flat-parent-first-v1"
            ),
            runtime_code_source_origin_identity=str(
                raw.get("runtime_code_source_origin_identity") or ""
            ),
            coord=str(raw.get("coord") or ""),
        )
        result.append((raw, instance))
    return result


def _absent_snapshot(identity: str, parser_identity: str) -> ArtifactSnapshot:
    return ArtifactSnapshot(
        artifact_instance_identity=identity,
        artifact_content_sha256="0" * 64,
        artifact_byte_length=0,
        archive_comment_sha256=hashlib.sha256(b"").hexdigest(),
        entries=(),
        class_records=(),
        class_payloads=(),
        safety_reason_codes=(),
        parse_failure_count=0,
        unknown_attribute_scopes=(),
        unknown_resource_scopes=(),
        inventory_digest=_identity("absent_artifact_inventory", {"identity": identity}),
        parser_identity=parser_identity,
        comparison_coverage_status="complete",
    )


def _source_methods(source_config: Mapping[str, Any]):
    source_sets = list(source_config.get("source_sets") or ())
    if not source_sets:
        raise BinaryPipelineError(
            "BINARY_SOURCE_SETS_REQUIRED",
            "source_overlay.source_sets must contain at least one user-authorized source set",
        )
    methods = []
    manifest = []
    source_set_records = []
    coverage_complete = True
    coverage_gaps = []
    language_file_counts: dict[str, int] = {}
    for raw_set in source_sets:
        source_set = dict(raw_set or {})
        roots = [
            Path(item).expanduser().resolve()
            for item in source_set.get("source_dirs") or ()
        ]
        common_root_value = source_set.get("source_root") or (
            roots[0] if len(roots) == 1 else None
        )
        if common_root_value is None:
            raise BinaryPipelineError(
                "BINARY_SOURCE_COMMON_ROOT_REQUIRED",
                "each source set with multiple source_dirs requires source_root",
            )
        common_root = Path(str(common_root_value)).expanduser().resolve()
        if not common_root.is_dir():
            raise BinaryPipelineError("BINARY_SOURCE_ROOT_MISSING", str(common_root))
        owner_type = str(source_set.get("owner_type") or "").strip()
        owner_coord = str(source_set.get("owner_coord") or "").strip()
        module = str(source_set.get("module") or "root").strip()
        if owner_type not in {"business", "dependency"} or not owner_coord:
            raise BinaryPipelineError(
                "BINARY_SOURCE_OWNER_REQUIRED",
                "every source set requires owner_type business/dependency and owner_coord",
            )
        set_manifest = []
        for root in roots:
            if not root.is_dir():
                raise BinaryPipelineError("BINARY_SOURCE_ROOT_MISSING", str(root))
            try:
                root.relative_to(common_root)
            except ValueError as error:
                raise BinaryPipelineError(
                    "BINARY_SOURCE_ROOT_OUTSIDE_SNAPSHOT", str(root)
                ) from error
            source_files = sorted(
                path for path in root.rglob("*")
                if path.is_file() and path.suffix.lower() in SOURCE_FILE_LANGUAGES
            )
            for path in source_files:
                sha = _sha256_file(path)
                logical = path.relative_to(common_root).as_posix()
                language = SOURCE_FILE_LANGUAGES[path.suffix.lower()]
                language_file_counts[language] = (
                    language_file_counts.get(language, 0) + 1
                )
                manifest_item = {
                    "owner_type": owner_type,
                    "owner_coord": owner_coord,
                    "module": module,
                    "logical_path": logical,
                    "sha256": sha,
                    "language": language,
                }
                analyzer_root = {
                    "root": str(root),
                    "owner_type": owner_type,
                    "owner_coord": owner_coord,
                    "module": module,
                }
                if language == "java":
                    parsed, diagnostics = analyze_file(
                        str(path), analyzer_root,
                        prefer_tree_sitter=True,
                        return_diagnostics=True,
                    )
                else:
                    parsed = []
                    diagnostics = {
                        "preferred_parser": "none",
                        "actual_parser": "skipped",
                        "fallback_reason": f"unsupported_source_language:{language}",
                        "tree_sitter_available": False,
                        "language": language,
                        "error_nodes": 0,
                    }
                    coverage_gaps.append({
                        "reason_code": "BINARY_SOURCE_LANGUAGE_NOT_MAPPED",
                        "language": language,
                        "owner_coord": owner_coord,
                        "module": module,
                        "logical_path": logical,
                    })
                if diagnostics:
                    # Source is explanatory. Preserve partial coverage but never mutate binary facts.
                    stable_diagnostics = {
                        key: diagnostics.get(key)
                        for key in (
                            "preferred_parser", "actual_parser", "fallback_reason",
                            "tree_sitter_available", "language", "error_nodes",
                        )
                    }
                    manifest_item["diagnostics"] = stable_diagnostics
                    if (
                        stable_diagnostics.get("actual_parser") == "skipped"
                        or int(stable_diagnostics.get("error_nodes") or 0) > 0
                    ):
                        coverage_complete = False
                        if language == "java":
                            coverage_gaps.append({
                                "reason_code": "BINARY_SOURCE_PARSE_PARTIAL",
                                "language": language,
                                "owner_coord": owner_coord,
                                "module": module,
                                "logical_path": logical,
                                "actual_parser": str(
                                    stable_diagnostics.get("actual_parser") or ""
                                ),
                                "error_nodes": int(
                                    stable_diagnostics.get("error_nodes") or 0
                                ),
                            })
                manifest.append(manifest_item)
                set_manifest.append(manifest_item)
                methods.extend(parsed)
        source_set_records.append({
            "owner_type": owner_type,
            "owner_coord": owner_coord,
            "module": module,
            "snapshot_revision": str(
                source_set.get("snapshot_revision") or "content-addressed-only"
            ),
            "file_count": len(set_manifest),
            "source_tree_identity": _identity(
                "source_tree_identity", {"files": set_manifest}
            ),
            "language_file_counts": dict(sorted({
                language: sum(
                    item.get("language") == language for item in set_manifest
                )
                for language in SOURCE_FILE_LANGUAGES.values()
                if any(item.get("language") == language for item in set_manifest)
            }.items())),
        })
    snapshot_identity = _identity("source_snapshot_identity", {"files": manifest})
    return (
        methods,
        snapshot_identity,
        "complete" if coverage_complete else "partial",
        {
            "schema": "java-upgrade-analyzer.binary-source-attestation.v1",
            "source_snapshot_identity": snapshot_identity,
            "coverage_status": "complete" if coverage_complete else "partial",
            "file_count": len(manifest),
            "language_file_counts": dict(sorted(language_file_counts.items())),
            "coverage_gaps": coverage_gaps,
            "source_sets": source_set_records,
            "files": manifest,
        },
    )


def _source_explanations(
    methods: list[Any] | tuple[Any, ...],
    source_overlay: Any,
    *,
    analysis_context_identity: str,
) -> dict[str, Any]:
    mapped_by_symbol = {
        str((row.get("source_location") or {}).get("source_symbol_id") or ""): row
        for row in source_overlay.rows
        if row.get("mapping_status") == "mapped"
        and (row.get("source_location") or {}).get("source_symbol_id")
    }
    declarations = []
    candidates = []
    for method in methods:
        overlay = mapped_by_symbol.get(str(getattr(method, "symbol_id", "") or ""))
        if not overlay:
            continue
        location = dict(overlay.get("source_location") or {})
        member = dict(overlay.get("binary_member") or {})
        declared_signature = str(
            getattr(method, "declared_signature", "") or ""
        ).strip()
        if not declared_signature:
            parameter_types = list(
                (getattr(method, "param_declared_types", {}) or {}).values()
            ) or list((getattr(method, "param_types", {}) or {}).values())
            return_type = str(
                getattr(method, "return_declared_type", "")
                or getattr(method, "return_type", "")
                or ""
            ).strip()
            modifiers = " ".join(
                map(str, getattr(method, "modifiers", ()) or ())
            ).strip()
            declared_signature = " ".join(
                item for item in (
                    modifiers,
                    return_type,
                    f"{getattr(method, 'method_name', '')}({', '.join(map(str, parameter_types))})",
                )
                if item
            )
        declaration = {
            "overlay_identity": overlay.get("overlay_identity"),
            "source_owner_type": location.get("owner_type"),
            "source_owner_coord": location.get("owner_coord"),
            "binary_artifact_coord": member.get("artifact_coord"),
            "binary_class_name": member.get("class_name"),
            "binary_member_name": member.get("member_name"),
            "binary_descriptor": member.get("descriptor"),
            "logical_path": location.get("logical_path"),
            "line": location.get("line"),
            "end_line": location.get("end_line"),
            "declared_signature": declared_signature,
            "annotations": list(getattr(method, "annotations", ()) or ()),
            "modifiers": list(getattr(method, "modifiers", ()) or ()),
            "throws_declared_types": list(
                getattr(method, "throws_declared_types", ()) or ()
            ),
        }
        declarations.append(declaration)
        for edge in extract_call_edges_enhanced(method, include_low_confidence=False):
            candidates.append({
                "overlay_identity": overlay.get("overlay_identity"),
                "source_owner_type": location.get("owner_type"),
                "source_owner_coord": location.get("owner_coord"),
                "binary_artifact_coord": member.get("artifact_coord"),
                "caller_binary_class_name": member.get("class_name"),
                "caller_binary_member_name": member.get("member_name"),
                "caller_binary_descriptor": member.get("descriptor"),
                "caller_logical_path": location.get("logical_path"),
                "source_line": int(getattr(edge, "line", 0) or 0),
                "callee_key": str(getattr(edge, "callee_key", "") or ""),
                "callee_simple_key": str(
                    getattr(edge, "callee_simple_key", "") or ""
                ),
                "evidence_type": str(getattr(edge, "evidence_type", "") or ""),
                "confidence": str(getattr(edge, "confidence", "") or ""),
                "authority": "source_candidate_only_not_executable_edge",
            })
    declarations.sort(key=lambda item: (
        str(item.get("source_owner_coord") or ""),
        str(item.get("binary_artifact_coord") or ""),
        str(item.get("binary_class_name") or ""),
        str(item.get("binary_member_name") or ""),
        str(item.get("binary_descriptor") or ""),
    ))
    candidates.sort(key=lambda item: (
        str(item.get("source_owner_coord") or ""),
        str(item.get("caller_binary_class_name") or ""),
        str(item.get("caller_binary_member_name") or ""),
        int(item.get("source_line") or 0),
        str(item.get("callee_key") or ""),
    ))
    return {
        "schema": "java-upgrade-analyzer.binary-source-explanations.v1",
        "analysis_context_identity": analysis_context_identity,
        "authority": "explanatory_source_overlay_only",
        "declaration_count": len(declarations),
        "candidate_relationship_count": len(candidates),
        "declarations": declarations,
        "candidate_relationships": candidates,
    }


def run_pipeline(config: Mapping[str, Any], *, output_root: str | Path) -> dict[str, Any]:
    pipeline_started = time.perf_counter()
    if config.get("schema") != "java-upgrade-analyzer.binary-pipeline-input.v1":
        raise BinaryPipelineError("BINARY_PIPELINE_CONFIG_SCHEMA_INVALID", str(config.get("schema")))
    source_inputs = _source_inputs_contract(config)
    asm_jar = config.get("asm_jar") or None
    output_root = Path(output_root).resolve()
    phase_timings: list[dict[str, Any]] = _PhaseTimingRecorder(
        output_root, pipeline_started
    )
    cache_root = Path(
        str(config.get("cache_root") or (output_root / "binary_cache"))
    ).expanduser().resolve()
    base_config = dict(config.get("base") or {})
    current_config = dict(config.get("current") or {})
    base_platform = JdkPlatformImage(base_config.get("jdk_home", ""), asm_jar=asm_jar)
    current_platform = JdkPlatformImage(current_config.get("jdk_home", ""), asm_jar=asm_jar)
    if current_platform.identity == base_platform.identity:
        # Platform facts are immutable and content-addressed. Sharing one
        # instance avoids parsing the same target JDK twice for an ordinary
        # dependency upgrade while preserving the same platform identity.
        current_platform = base_platform
    base_artifacts, base_paths = _artifact_descriptors(list(base_config.get("artifacts") or ()))
    current_artifacts, current_paths = _artifact_descriptors(list(current_config.get("artifacts") or ()))
    base_config["artifacts"] = base_artifacts
    current_config["artifacts"] = current_artifacts
    base_profile = _runtime_profile(base_config, base_platform, base_paths)
    current_profile = _runtime_profile(current_config, current_platform, current_paths)
    base_build = _build_identity_bundle(base_config, base_artifacts)
    current_build = _build_identity_bundle(current_config, current_artifacts)
    base_instances = _artifact_instances(base_artifacts, base_profile)
    current_instances = _artifact_instances(current_artifacts, current_profile)
    runtime_sides_identical = (
        base_platform.identity == current_platform.identity
        and base_profile.identity == current_profile.identity
        and [
            (
                str(raw.get("lineage") or raw.get("coord") or raw["logical_location"]),
                instance,
            )
            for raw, instance in base_instances
        ]
        == [
            (
                str(raw.get("lineage") or raw.get("coord") or raw["logical_location"]),
                instance,
            )
            for raw, instance in current_instances
        ]
    )
    comparison_config = dict(config.get("runtime_comparison") or {})
    runtime_comparison = RuntimeComparison(
        base_profile,
        current_profile,
        str(comparison_config.get("comparison_intent") or "same_deployment_profile"),
        str(comparison_config.get("profile_correspondence_policy_version") or "v1"),
        tuple(comparison_config.get("controlled_profile_fields") or ()),
        tuple(comparison_config.get("declared_upgrade_payload_scope") or ("artifact-bytes",)),
        tuple(comparison_config.get("changed_or_unknown_profile_fields") or ()),
    )
    capability = RuntimeCapabilityPolicy(**dict(config.get("runtime_capability_policy") or {}))
    support = json.loads(SUPPORT_MANIFEST_PATH.read_text(encoding="utf-8"))
    _require_binary_authority_gates(support)
    scope_fields = {
        "analysis_observability_scope": str(config.get("analysis_observability_scope") or "binary-static-v1"),
        "artifact_diff_support_manifest_identity": _identity(
            "artifact_diff_support_manifest_identity", support["artifact_diff_support_manifest"]
        ),
        "runtime_loader_support_manifest_identity": _identity(
            "runtime_loader_support_manifest_identity", support["runtime_loader_support_manifest"]
        ),
        "class_definition_support_manifest_identity": _identity(
            "class_definition_support_manifest_identity", support["class_definition_support_manifest"]
        ),
        "runtime_fact_semantic_capability_identity": _identity(
            "runtime_fact_semantic_capability_identity", {
                "resource_policy": support["artifact_diff_support_manifest"]["resource_policy"],
                "entrypoint_discovery": support["entrypoint_discovery_support_manifest"],
            }
        ),
        "runtime_fact_dynamic_capability_identity": _identity(
            "runtime_fact_dynamic_capability_identity", {"asm": support["artifact_diff_support_manifest"]["parser_contract"]}
        ),
        "runtime_fact_transformer_capability_identity": _identity(
            "runtime_fact_transformer_capability_identity",
            {"supported": list(capability.supported_transformer_profile_identities)},
        ),
        "environment_equivalence_capability_identity": _identity(
            "environment_equivalence_capability_identity", {"version": "none-v1"}
        ),
    }
    scope_fields["field_coverage"] = {key: "known" for key in AnalysisScope.REQUIRED_FIELDS}
    analysis_scope = AnalysisScope(scope_fields)
    context = AnalysisContext(runtime_comparison, analysis_scope)
    phase_timings.append({
        "phase": "input_and_runtime_profile",
        "elapsed_seconds": round(time.perf_counter() - pipeline_started, 6),
        "artifact_count": len(base_artifacts) + len(current_artifacts),
    })

    with short_temporary_directory(prefix="binary-pipeline") as temp_text:
        temp = Path(temp_text)
        base_store = BinaryFactStore(
            temp / "base.sqlite",
            defer_secondary_indexes=True,
            bulk_load_transaction=True,
        )
        current_store = BinaryFactStore(
            temp / "current.sqlite",
            defer_secondary_indexes=True,
            bulk_load_transaction=True,
        )
        base_store_open = True
        current_store_open = True
        try:
            artifact_phase_started = time.perf_counter()
            cache_metrics = {
                "artifact_snapshot_hits": 0,
                "artifact_snapshot_misses": 0,
                "artifact_snapshot_corrupt_rebuilt": 0,
                "classfile_parser_invocations": 0,
            }
            base_by_lineage = {}
            current_by_lineage = {}
            for raw, instance in base_instances:
                lineage = str(raw.get("lineage") or raw.get("coord") or raw["logical_location"])
                if lineage in base_by_lineage:
                    raise BinaryPipelineError("BINARY_ARTIFACT_LINEAGE_AMBIGUOUS", lineage)
                base_by_lineage[lineage] = (raw, instance)
            for raw, instance in current_instances:
                lineage = str(raw.get("lineage") or raw.get("coord") or raw["logical_location"])
                if lineage in current_by_lineage:
                    raise BinaryPipelineError("BINARY_ARTIFACT_LINEAGE_AMBIGUOUS", lineage)
                current_by_lineage[lineage] = (raw, instance)

            parser_identities = set()

            def load_snapshot(raw, instance, store, target_jvm_major):
                cache_outcome = cached_snapshot_archive(
                    raw["path"], artifact_instance_identity=instance.identity,
                    expected_sha256=instance.content_sha256, asm_jar=asm_jar,
                    cache_root=cache_root,
                    target_jvm_major=target_jvm_major,
                )
                cache_metrics[
                    "artifact_snapshot_hits"
                    if cache_outcome.cache_status == "hit"
                    else "artifact_snapshot_misses"
                ] += 1
                if cache_outcome.cache_status == "corrupt_rebuilt":
                    cache_metrics["artifact_snapshot_corrupt_rebuilt"] += 1
                cache_metrics["classfile_parser_invocations"] += cache_outcome.parser_invocation_count
                snapshot = cache_outcome.snapshot
                parser_identities.add(snapshot.parser_identity)
                store.add_artifact_snapshot(instance, snapshot)
                return snapshot

            diffs = []
            pairings = []
            for lineage in sorted(set(base_by_lineage) | set(current_by_lineage)):
                base_pair = base_by_lineage.get(lineage)
                current_pair = current_by_lineage.get(lineage)
                if base_pair and current_pair:
                    status = "exact"
                    base_raw, base_instance = base_pair
                    current_raw, current_instance = current_pair
                    base_snapshot = load_snapshot(
                        base_raw, base_instance, base_store,
                        base_platform.java_major,
                    )
                    if runtime_sides_identical:
                        # The ArtifactInstance (including content, slot, realm,
                        # origin and runtime profile) is byte-for-byte equal.
                        # Compare the immutable snapshot with itself and clone
                        # the completed evidence store once after reconciliation
                        # instead of parsing/decompressing and inserting every
                        # unchanged class a second time.
                        current_snapshot = base_snapshot
                    else:
                        current_snapshot = load_snapshot(
                            current_raw, current_instance, current_store,
                            current_platform.java_major,
                        )
                elif base_pair:
                    status = "base_only"
                    base_raw, base_instance = base_pair
                    base_snapshot = load_snapshot(
                        base_raw, base_instance, base_store,
                        base_platform.java_major,
                    )
                    current_instance = None
                    current_snapshot = _absent_snapshot(
                        f"ABSENT:current:{lineage}", base_snapshot.parser_identity
                    )
                else:
                    status = "current_only"
                    current_raw, current_instance = current_pair
                    current_snapshot = load_snapshot(
                        current_raw, current_instance, current_store,
                        current_platform.java_major,
                    )
                    base_instance = None
                    base_snapshot = _absent_snapshot(
                        f"ABSENT:base:{lineage}", current_snapshot.parser_identity
                    )
                pairing = CrossVersionArtifactPairing(
                    status,
                    lineage,
                    base_profile.identity,
                    current_profile.identity,
                    ({"rule": "explicit-lineage-v1", "lineage": lineage},),
                    "explicit-lineage-v1",
                    base_instance.identity if base_instance else "",
                    current_instance.identity if current_instance else "",
                )
                pairings.append(pairing)
                artifact_diff = compare_artifact_snapshots(
                    base_snapshot,
                    current_snapshot,
                    comparison_or_runtime_scope={
                        "runtime_comparison_identity": runtime_comparison.identity,
                        "cross_version_artifact_pairing_identity": pairing.identity,
                    },
                )
                artifact_diff["logical_dependency_lineage"] = lineage
                diffs.append(artifact_diff)
                # A snapshot contains all classfile bytes and full ASM facts for
                # one archive. Pair and persist it immediately so residency is
                # bounded by the largest base/current JAR rather than the full
                # 500-JAR input set.
                del base_snapshot, current_snapshot
            # Secondary lookup trees are not consulted while immutable archive
            # facts are appended. Building each tree once is materially cheaper
            # than maintaining it across hundreds of thousands of inserts, and
            # the same complete indexes exist before any reconciliation query.
            base_store.ensure_secondary_indexes()
            current_store.ensure_secondary_indexes()
            phase_timings.append({
                "phase": "artifact_fact_build_and_local_diff",
                "elapsed_seconds": round(
                    time.perf_counter() - artifact_phase_started, 6
                ),
                "artifact_count": len(base_artifacts) + len(current_artifacts),
                "pairing_count": len(pairings),
            })
            reconciliation_started = time.perf_counter()
            # Reconcile both runtime views over the same symbolic class
            # universe. A type referenced only by one version (for example a
            # newly introduced JDK parameter type) still exists in the other
            # runtime and must not be reported as a provider change merely
            # because it was absent from that side's local discovery seeds.
            common_runtime_classes = set()
            for store in (base_store, current_store):
                common_runtime_classes.update(
                    row[0]
                    for row in store.connection.execute(
                        "SELECT DISTINCT class_name FROM classes"
                    )
                    if row[0]
                )
                common_runtime_classes.update(
                    row[0]
                    for row in store.connection.execute(
                        """
                        SELECT DISTINCT symbolic_owner FROM direct_edges
                        WHERE symbolic_owner<>''
                        """
                    )
                )
            base_retained_kinds = {
                "provider_binding",
                "class_definition",
                "resource_selection",
            }
            if not runtime_sides_identical:
                # Only cross-version member-resolution comparison consumes the
                # base member records. Exact sides prove that pass is empty.
                base_retained_kinds.add("member_resolution")
            current_retained_kinds = {
                "provider_binding",
                "class_definition",
                "member_resolution",
                "resource_selection",
            }
            base_runtime = RuntimeReconciler(
                base_store, base_profile, base_platform,
                analysis_context_identity=context.identity,
                capability_policy=capability,
                additional_initial_classes=common_runtime_classes,
            ).reconcile(retain_record_kinds=base_retained_kinds)
            if runtime_sides_identical:
                # Reconciliation is a deterministic function of the complete
                # runtime side identity. SQLite backup preserves the full
                # independently-validatable evidence without constructing a
                # second million-record Python graph.
                base_store.connection.commit()
                base_store.connection.backup(current_store.connection)
                current_store.connection.commit()
                current_runtime = base_runtime
            else:
                current_runtime = RuntimeReconciler(
                    current_store, current_profile, current_platform,
                    analysis_context_identity=context.identity,
                    capability_policy=capability,
                    additional_initial_classes=common_runtime_classes,
                ).reconcile(retain_record_kinds=current_retained_kinds)
            base_runtime_identity = base_runtime.identity
            current_runtime_identity = current_runtime.identity
            phase_timings.append({
                "phase": "target_independent_runtime_reconciliation",
                "elapsed_seconds": round(
                    time.perf_counter() - reconciliation_started, 6
                ),
            })
            decision_started = time.perf_counter()
            source_overlay = None
            source_methods = ()
            source_explanations = None
            source_attestation = None
            if config.get("source_overlay"):
                methods, source_snapshot, source_coverage, source_attestation = _source_methods(
                    dict(config["source_overlay"])
                )
                source_overlay = build_source_overlay(
                    current_store,
                    methods,
                    analysis_context_identity=context.identity,
                    source_snapshot_identity=source_snapshot,
                    source_snapshot_coverage_status=source_coverage,
                )
                source_methods = tuple(methods)
                source_explanations = _source_explanations(
                    source_methods,
                    source_overlay,
                    analysis_context_identity=context.identity,
                )
                mapping_status_counts: dict[str, int] = {}
                for row in source_overlay.rows:
                    status = str(row.get("mapping_status") or "unknown")
                    mapping_status_counts[status] = mapping_status_counts.get(status, 0) + 1
                source_attestation["mapping_status_counts"] = dict(
                    sorted(mapping_status_counts.items())
                )
                source_attestation["mapped_binary_member_count"] = int(
                    mapping_status_counts.get("mapped", 0)
                )
            decisions = BinaryDecisionEngine(
                analysis_context_identity=context.identity,
                runtime_comparison_identity=runtime_comparison.identity,
                base_store=base_store,
                current_store=current_store,
                base_reconciliation=base_runtime,
                current_reconciliation=current_runtime,
                artifact_local_diffs=diffs,
            ).build()
            inline_overlay = None
            if source_overlay is not None:
                inline_overlay = build_inline_consumption_overlay(
                    base_store,
                    current_store,
                    source_methods,
                    source_overlay,
                    diffs,
                    current_runtime,
                    analysis_context_identity=context.identity,
                )
            # The remaining semantic and trace phases use only the current
            # runtime. Keep the immutable identity, but release the full base
            # provider/definition/edge result graph before building the next
            # large set of indexes.
            del base_runtime
            semantic_overlay = build_binary_semantic_overlay(
                current_store,
                current_profile,
                current_runtime,
                decisions,
            )
            phase_timings.append({
                "phase": "decision_and_projection_freeze",
                "elapsed_seconds": round(time.perf_counter() - decision_started, 6),
                "authoritative_change_fact_count": len(
                    decisions.authoritative_decisions
                ),
                "diagnostic_candidate_fact_count": len(decisions.diagnostic_decisions),
                "runtime_semantic_edge_count": len(semantic_overlay.rows),
            })
            trace_started = time.perf_counter()
            traces = build_binary_traces(
                current_store, current_profile, current_runtime, decisions,
                inline_overlay=inline_overlay,
                semantic_overlay=semantic_overlay,
                max_visited_nodes=int(config.get("max_trace_nodes") or 1_000_000),
                max_paths_per_target=int(config.get("max_paths_per_target") or 20),
            )
            del current_runtime
            phase_timings.append({
                "phase": "binary_trace",
                "elapsed_seconds": round(time.perf_counter() - trace_started, 6),
                "formal_trace_result_count": len(traces.formal_results),
                "candidate_trace_result_count": len(traces.candidate_results),
                "exact_entrypoint_count": sum(
                    item.get("path_certainty") == "exact"
                    for item in traces.entrypoint_records
                ),
                "possible_entrypoint_count": sum(
                    item.get("path_certainty") == "possible"
                    for item in traces.entrypoint_records
                ),
            })
            base_store.connection.commit()
            current_store.connection.commit()
            parser_identities = sorted(parser_identities)
            if len(parser_identities) != 1:
                raise BinaryPipelineError(
                    "BINARY_PIPELINE_PARSER_IDENTITY_SET_INVALID",
                    str(parser_identities),
                )
            parser_identity = parser_identities[0]
            base_input_slice = FactBuildInputSlice(
                base_build.provenance_identity,
                tuple(
                    artifact_content_identity(item["content_sha256"], item["byte_length"])
                    for item in base_artifacts
                ),
                base_profile.identity,
                parser_identity,
            )
            current_input_slice = FactBuildInputSlice(
                current_build.provenance_identity,
                tuple(
                    artifact_content_identity(item["content_sha256"], item["byte_length"])
                    for item in current_artifacts
                ),
                current_profile.identity,
                parser_identity,
            )
            phase_manifest = {
                "schema": "java-upgrade-analyzer.binary-phase-manifest.v1",
                "analysis_context_identity": context.identity,
                "phase_order": [
                    "step4a_artifact_local_diff",
                    "step5a_target_independent_reconciliation",
                    "step4b_decision_projection_freeze",
                    "step5b_trace",
                    "step6_report",
                ],
                "phases": [
                    {
                        "phase": "step4a_artifact_local_diff",
                        "input_identities": [
                            runtime_comparison.identity,
                            base_input_slice.identity,
                            current_input_slice.identity,
                            *[item.identity for item in pairings],
                        ],
                        "output_identity": _identity(
                            "artifact_local_diff_set_identity",
                            [item.get("artifact_local_result_identity") for item in diffs],
                        ),
                    },
                    {
                        "phase": "step5a_target_independent_reconciliation",
                        "input_identities": [
                            base_profile.identity,
                            current_profile.identity,
                            base_platform.identity,
                            current_platform.identity,
                        ],
                        "output_identity": _identity(
                            "runtime_reconciliation_pair_identity",
                            [base_runtime_identity, current_runtime_identity],
                        ),
                    },
                    {
                        "phase": "step4b_decision_projection_freeze",
                        "input_identities": [
                            context.identity,
                            base_runtime_identity,
                            current_runtime_identity,
                        ],
                        "output_identity": decisions.identity,
                        "active_snapshot_identities": {
                            key: value.identity
                            for key, value in decisions.active_snapshots.items()
                        },
                    },
                    {
                        "phase": "step5b_trace",
                        "input_identities": [
                            decisions.identity,
                            current_runtime_identity,
                            traces.entrypoint_discovery_identity,
                        ],
                        "output_identity": traces.identity,
                    },
                    {
                        "phase": "step6_report",
                        "input_identities": [traces.identity, decisions.identity],
                        "output_identity": _identity(
                            "binary_report_projection_contract_identity",
                            {
                                "formatter": "binary-output-v1",
                                "four_dimension_state": "binary-formal-state-v2",
                            },
                        ),
                    },
                ],
                "dependency_direction": "strictly_forward_no_snapshot_rewrite",
            }
            additional = {
                # Fact stores can be hundreds of MiB on real projects. Keep
                # their complete evidence, but stream immutable sidecars into
                # the generation instead of materializing both files in RAM.
                "base_binary_facts.sqlite": temp / "base.sqlite",
                "current_binary_facts.sqlite": temp / "current.sqlite",
                "binary_runtime_semantic_overlay.json": (
                    json.dumps(
                        semantic_overlay.as_payload(),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ) + "\n"
                ).encode("utf-8"),
                "binary_pairings.json": (
                    json.dumps(
                        {
                            "schema": "java-upgrade-analyzer.binary-pairings.v1",
                            "runtime_comparison_identity": runtime_comparison.identity,
                            "pairing_identities": [item.identity for item in pairings],
                            "pairings": [
                                {
                                    "identity": item.identity,
                                    "status": item.status,
                                    "logical_dependency_lineage": item.logical_dependency_lineage,
                                    "base_artifact_instance_identity": item.base_artifact_instance_identity,
                                    "current_artifact_instance_identity": item.current_artifact_instance_identity,
                                }
                                for item in pairings
                            ],
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ) + "\n"
                ).encode("utf-8"),
                "binary_phase_manifest.json": (
                    json.dumps(
                        phase_manifest,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ) + "\n"
                ).encode("utf-8"),
                "binary_build_identities.json": (
                    json.dumps(
                        {
                            "schema": "java-upgrade-analyzer.binary-build-identities.v1",
                            "base": {
                                "build_environment_identity": base_build.environment_identity,
                                "build_input_manifest_identity": base_build.input_identity,
                                "artifact_build_provenance_identity": base_build.provenance_identity,
                                "fact_build_input_slice_identity": base_input_slice.identity,
                            },
                            "current": {
                                "build_environment_identity": current_build.environment_identity,
                                "build_input_manifest_identity": current_build.input_identity,
                                "artifact_build_provenance_identity": current_build.provenance_identity,
                                "fact_build_input_slice_identity": current_input_slice.identity,
                            },
                            "domain_separation": "build_environment_build_input_provenance_runtime_profile_analysis_scope",
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ) + "\n"
                ).encode("utf-8"),
            }
            if inline_overlay is not None:
                additional["binary_inline_overlay.json"] = (
                    json.dumps(
                        {
                            "schema": "java-upgrade-analyzer.binary-inline-overlay.v1",
                            "inline_overlay_set_identity": inline_overlay.inline_overlay_set_identity,
                            "coverage_status": inline_overlay.coverage_status,
                            "proven_count": inline_overlay.proven_count,
                            "possible_count": inline_overlay.possible_count,
                            "retained_or_unchanged_count": inline_overlay.retained_or_unchanged_count,
                            "unbound_count": inline_overlay.unbound_count,
                            "rows": list(inline_overlay.rows),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ) + "\n"
                ).encode("utf-8")
            if source_explanations is not None:
                additional["binary_source_explanations.json"] = (
                    json.dumps(
                        source_explanations,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ) + "\n"
                ).encode("utf-8")
            if source_attestation is not None:
                additional["binary_source_attestation.json"] = (
                    json.dumps(
                        source_attestation,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ) + "\n"
                ).encode("utf-8")
            generation_write_started = time.perf_counter()
            manifest = write_binary_generation(
                output_root,
                decisions,
                traces,
                current_profile,
                policy_identities={
                    "support_manifest": _sha256_file(SUPPORT_MANIFEST_PATH),
                    "runtime_capability": capability.identity,
                    "entrypoint_discovery": _identity(
                        "entrypoint_discovery_support_manifest_identity",
                        support["entrypoint_discovery_support_manifest"],
                    ),
                    "analysis_scope": analysis_scope.identity,
                    "runtime_comparison": runtime_comparison.identity,
                    "projection_registry": _identity(
                        "projection_registry_identity",
                        {key: rule.identity for key, rule in DEFAULT_RULES.items()},
                    ),
                    "base_platform_image": base_platform.identity,
                    "current_platform_image": current_platform.identity,
                    "base_build_environment": base_build.environment_identity,
                    "current_build_environment": current_build.environment_identity,
                    "base_build_input_manifest": base_build.input_identity,
                    "current_build_input_manifest": current_build.input_identity,
                    "base_artifact_build_provenance": base_build.provenance_identity,
                    "current_artifact_build_provenance": current_build.provenance_identity,
                    "base_fact_build_input_slice": base_input_slice.identity,
                    "current_fact_build_input_slice": current_input_slice.identity,
                },
                source_overlay=source_overlay,
                source_inputs=source_inputs,
                additional_sidecars=additional,
            )
            result_summary = {
                "base_runtime_reconciliation_identity": base_runtime_identity,
                "current_runtime_reconciliation_identity": current_runtime_identity,
                "decision_bundle_identity": decisions.identity,
                "trace_bundle_identity": traces.identity,
                "decision_coverage_status": decisions.coverage_status,
                "trace_coverage_status": traces.coverage_status,
                "authoritative_change_fact_count": len(
                    decisions.authoritative_decisions
                ),
                "diagnostic_candidate_fact_count": len(
                    decisions.diagnostic_decisions
                ),
            }
            phase_timings.append({
                "phase": "immutable_generation_write",
                "elapsed_seconds": round(
                    time.perf_counter() - generation_write_started, 6
                ),
            })
            # Independent validation reconstructs its own truth from immutable
            # output. Release production graphs and serialized sidecar buffers
            # first so their complete base/current object graphs do not overlap
            # the Oracle's equally large indexes at the process RSS peak.
            additional.clear()
            del (
                decisions,
                traces,
                semantic_overlay,
                inline_overlay,
                source_overlay,
                source_methods,
                source_explanations,
                diffs,
                pairings,
            )
            base_store.close()
            base_store_open = False
            current_store.close()
            current_store_open = False
            gc.collect()
            validation_started = time.perf_counter()
            validation = validate_generation(config, manifest["generation_directory"])
            phase_timings.append({
                "phase": "independent_validation",
                "elapsed_seconds": round(time.perf_counter() - validation_started, 6),
                "issue_count": len(validation.get("issues") or ()),
            })
            if validation["status"] != "passed":
                raise BinaryPipelineError(
                    "BINARY_INDEPENDENT_VALIDATION_FAILED",
                    json.dumps(validation["issues"][:20], ensure_ascii=False),
                )
            activation_started = time.perf_counter()
            manifest["active_generation_descriptor"] = activate_binary_generation(
                output_root, manifest, validation_result=validation
            )
            phase_timings.append({
                "phase": "validated_generation_activation",
                "elapsed_seconds": round(time.perf_counter() - activation_started, 6),
            })
            observability = output_root / "binary_observability"
            observability.mkdir(parents=True, exist_ok=True)
            cache_metrics_path = observability / "latest_cache_metrics.json"
            cache_metrics_path.write_text(
                json.dumps(
                    {
                        "schema": "java-upgrade-analyzer.binary-cache-metrics.v1",
                        "result_generation_identity": manifest["result_generation_identity"],
                        **cache_metrics,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ) + "\n",
                encoding="utf-8",
            )
            total_elapsed_seconds = round(time.perf_counter() - pipeline_started, 6)
            peak_rss_bytes = _peak_rss_bytes()
            phase_timings_path = observability / "latest_phase_timings.json"
            phase_timings_path.write_text(
                json.dumps(
                    {
                        "schema": "java-upgrade-analyzer.binary-phase-timings.v1",
                        "result_generation_identity": manifest[
                            "result_generation_identity"
                        ],
                        "total_elapsed_seconds": total_elapsed_seconds,
                        "peak_rss_bytes": peak_rss_bytes,
                        "peak_rss_scope": "current_process",
                        "phases": phase_timings,
                        "non_authoritative_observability": True,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ) + "\n",
                encoding="utf-8",
            )
            return {
                "schema": "java-upgrade-analyzer.binary-pipeline-result.v1",
                **manifest,
                "runtime_comparison_identity": runtime_comparison.identity,
                "analysis_scope_identity": analysis_scope.identity,
                "analysis_context_identity": context.identity,
                **result_summary,
                "source_inputs": source_inputs,
                "validation_run_identity": validation["validation_run_identity"],
                "validation_status": validation["status"],
                "validation_result_path": validation["validation_result_path"],
                "cache_metrics": cache_metrics,
                "cache_metrics_path": str(cache_metrics_path),
                "phase_timings": phase_timings,
                "phase_timings_path": str(phase_timings_path),
                "total_elapsed_seconds": total_elapsed_seconds,
                "peak_rss_bytes": peak_rss_bytes,
                "peak_rss_scope": "current_process",
            }
        finally:
            if base_store_open:
                base_store.close()
            if current_store_open:
                current_store.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the binary-first analysis generation")
    parser.add_argument("--config", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--result-json", default="")
    args = parser.parse_args(argv)
    result = run_pipeline(_load_json(args.config), output_root=args.output_root)
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.result_json:
        Path(args.result_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.result_json).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
