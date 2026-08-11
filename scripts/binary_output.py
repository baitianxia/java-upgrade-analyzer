#!/usr/bin/env python3
"""Immutable whole-generation output writer for the binary authority pipeline."""

from __future__ import annotations

import csv
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Mapping

from binary_decision_engine import BinaryDecisionBundle
from binary_first_contract import BinaryFirstContractError, canonical_identity
from binary_first_model import ResultGeneration, RuntimeProfile
from binary_source_overlay import SourceOverlayResult
from binary_trace_engine import BinaryTraceBundle
from csv_io import open_csv_write
from path_runtime import make_short_temp_dir, short_temporary_directory
from signature_utils import jvm_method_parameter_signature


EDGE_KIND_LABELS = {
    "method": "字节码方法调用",
    "field": "字节码字段访问",
    "type": "字节码类型引用",
    "class_initialization": "类初始化",
    "reflection_method_invocation": "反射方法调用",
    "reflection_constructor_invocation": "反射构造调用",
    "reflection_field_access": "反射字段访问",
    "method_handle_invocation": "MethodHandle 调用",
    "method_handle_field_access": "MethodHandle 字段访问",
    "dynamic_proxy_callback": "JDK 动态代理回调",
    "mybatis_mapper_proxy_dispatch": "MyBatis Mapper 代理分派",
    "spring_transaction_proxy_dispatch": "Spring 事务代理分派",
    "spring_bean_wiring_dispatch": "Spring Bean 注入分派",
    "spring_data_repository_proxy_dispatch": "Spring Data 仓库代理分派",
    "spring_aop_dispatch": "Spring AOP 切面分派",
    "spring_security_filter_dispatch": "Spring Security 过滤器链",
    "declarative_http_client_dispatch": "声明式 HTTP 客户端分派",
    "dubbo_spi_dispatch": "Dubbo SPI 扩展分派",
    "implicit_data_contract_dispatch": "序列化/绑定数据契约",
}


ENTRY_KIND_LABELS = {
    "declared_runtime_entry": "用户声明的运行入口",
    "java_main": "Java 主程序入口",
    "spring_scheduled": "Spring 定时任务",
    "spring_xml_scheduled": "Spring XML 定时任务",
    "spring_xml_quartz": "Spring XML Quartz 定时任务",
    "spring_event_listener": "Spring 事件监听",
    "spring_message_listener": "消息监听",
    "lifecycle_callback": "组件初始化回调",
    "jpa_lifecycle_callback": "JPA 生命周期回调",
    "spring_web_endpoint": "HTTP 接口入口",
    "spring_bean_initialization": "Spring Bean 初始化",
    "spring_application_runner": "Spring ApplicationRunner 启动回调",
    "spring_command_line_runner": "Spring CommandLineRunner 启动回调",
    "spring_application_listener": "Spring ApplicationListener 事件回调",
    "spring_environment_post_processor": "Spring 环境后处理回调",
    "spring_application_context_initializer": "Spring 上下文初始化回调",
    "spring_lifecycle_callback": "Spring 生命周期回调",
    "spring_web_interceptor": "Spring Web 拦截器回调",
    "spring_conversion_callback": "Spring 类型转换回调",
    "servlet_endpoint": "Servlet 请求入口",
    "servlet_filter": "Servlet 过滤器入口",
    "servlet_lifecycle_callback": "Servlet 生命周期回调",
    "quartz_job": "Quartz 定时任务",
}


class BinaryOutputError(BinaryFirstContractError):
    pass


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reported_api_identity(
    decision: Mapping[str, Any],
    *,
    runtime_profile_identity: str,
    analysis_context_identity: str,
) -> str:
    scope = decision.get("fact_scope") or {}
    return _identity("reported_api_identity", {
        "analysis_context_identity": analysis_context_identity,
        "current_runtime_profile_identity": runtime_profile_identity,
        "initiating_loader_realm_identity": scope.get("initiating_loader_realm_identity"),
        "class_name": scope.get("class_name"),
        "member_kind": scope.get("member_kind") or decision.get("fact_kind"),
        "member_name": scope.get("member_name"),
        "descriptor": scope.get("descriptor"),
        "grouping_rule_version": "binary-reported-api-v1",
    })


def _aggregate_by_api(
    decisions: BinaryDecisionBundle,
    traces: BinaryTraceBundle,
    profile: RuntimeProfile,
) -> list[dict[str, Any]]:
    decision_by_change = {
        item["change_fact_identity"]: item for item in decisions.authoritative_decisions
    }
    groups: dict[str, list[dict[str, Any]]] = {}
    for result in traces.formal_results:
        decision = decision_by_change.get(result["change_fact_identity"])
        if not decision:
            raise BinaryOutputError(
                "BINARY_OUTPUT_TRACE_DECISION_UNBOUND",
                str(result.get("trace_result_identity")),
            )
        reported = _reported_api_identity(
            decision,
            runtime_profile_identity=profile.identity,
            analysis_context_identity=decisions.analysis_context_identity,
        )
        groups.setdefault(reported, []).append({"result": result, "decision": decision})
    priority = {
        "reachable": 3,
        "uncertain": 2,
        "not_found_in_static_analysis": 1,
        "not_analyzed": 0,
    }
    linkage_priority = {
        "compatible_or_not_applicable": 0,
        "undetermined": 1,
        "incompatible_if_executed": 2,
    }
    output = []
    for reported, items in sorted(groups.items()):
        results = [item["result"] for item in items]
        primary = max(results, key=lambda item: priority[item["reachability_status"]])
        scopes = [item["decision"]["fact_scope"] for item in items]
        target_scope = scopes[0]
        target_owner = str(target_scope.get("class_name") or "").replace("/", ".")
        target_member = str(target_scope.get("member_name") or "")
        target_descriptor = str(target_scope.get("descriptor") or "")
        target_signature = (
            jvm_method_parameter_signature(target_descriptor)
            if target_descriptor.startswith("(") else ""
        )
        target_label = (
            target_owner
            if not target_member or target_member == "<class>"
            else f"{target_owner}.{target_member}{target_signature}"
        )
        path_records = []
        path_identities = set()
        for result in results:
            for path in result.get("paths") or ():
                if path.get("path_identity") in path_identities:
                    continue
                path_identities.add(path.get("path_identity"))
                nodes = []
                for edge in path.get("edges") or ():
                    owner = str(edge.get("caller_class_name") or "").replace("/", ".")
                    member = str(edge.get("caller_member_name") or "")
                    descriptor = str(edge.get("caller_descriptor") or "")
                    signature = (
                        jvm_method_parameter_signature(descriptor)
                        if descriptor.startswith("(") else ""
                    )
                    label = f"{owner}.{member}{signature}" if owner and member else ""
                    if label and (not nodes or nodes[-1] != label):
                        nodes.append(label)
                if target_label and (not nodes or nodes[-1] != target_label):
                    nodes.append(target_label)
                entrypoint_records = list(path.get("entrypoint_records") or ())
                entry_kinds = sorted({
                    str(item.get("entry_kind") or "")
                    for item in entrypoint_records
                    if item.get("entry_kind")
                })
                mechanism_kinds = []
                for edge in path.get("edges") or ():
                    kind = str(edge.get("edge_kind") or "")
                    if kind and kind not in mechanism_kinds:
                        mechanism_kinds.append(kind)
                path_records.append({
                    "path_identity": path.get("path_identity"),
                    "path_certainty": path.get("path_certainty"),
                    "path_text": " → ".join(nodes),
                    "edge_count": len(path.get("edges") or ()),
                    "entry_kinds": entry_kinds,
                    "entry_kind_labels": [
                        ENTRY_KIND_LABELS.get(item, item) for item in entry_kinds
                    ],
                    "entrypoint_dependency_coords": sorted({
                        str(item.get("dependency_coord") or "")
                        for item in entrypoint_records
                        if item.get("dependency_coord")
                    }),
                    "entrypoint_activation_reasons": sorted({
                        str(item.get("activation_reason") or "")
                        for item in entrypoint_records
                        if item.get("activation_reason")
                    }),
                    "mechanism_kinds": mechanism_kinds,
                    "mechanism_labels": [
                        EDGE_KIND_LABELS.get(item, item)
                        for item in mechanism_kinds
                    ],
                })
        dependency_artifacts = []
        dependency_keys = set()
        for item in items:
            for artifact in item["decision"].get("dependency_artifacts") or ():
                key = (
                    str(artifact.get("side") or ""),
                    str(artifact.get("artifact_instance_identity") or ""),
                )
                if key not in dependency_keys:
                    dependency_keys.add(key)
                    dependency_artifacts.append(dict(artifact))
        output.append({
            "reported_api_identity": reported,
            "display_owner": scopes[0].get("class_name"),
            "display_member": scopes[0].get("member_name"),
            "display_descriptor": scopes[0].get("descriptor"),
            "display_member_kind": scopes[0].get("member_kind") or items[0]["decision"].get("fact_kind"),
            "reachability_status": primary["reachability_status"],
            "is_reachable": any(item["is_reachable"] for item in results),
            "impact_conclusion": (
                "probable_impact"
                if any(item["impact_conclusion"] == "probable_impact" for item in results)
                else "inconclusive"
            ),
            "static_linkage_status": max(
                (item.get("static_linkage_status") or "undetermined" for item in results),
                key=lambda value: linkage_priority.get(value, 1),
            ),
            "runtime_verification_status": "required_not_executed",
            "runtime_verification_executed_by_system": False,
            "path_set_complete": all(item["path_set_complete"] for item in results),
            "exact_path_exists": any(item["exact_path_exists"] for item in results),
            "possible_path_exists": any(item["possible_path_exists"] for item in results),
            "paths": sorted(path_records, key=lambda item: (
                str(item.get("path_certainty") or ""),
                str(item.get("path_text") or ""),
                str(item.get("path_identity") or ""),
            )),
            "contributing_projection_ids": sorted(item["projection_identity"] for item in results),
            "contributing_projection_assessment_ids": sorted(
                item["projection_assessment_identity"] for item in results
            ),
            "contributing_change_fact_ids": sorted(item["change_fact_identity"] for item in results),
            "dependency_artifacts": dependency_artifacts,
            "dependency_lineages": sorted({
                str(item.get("logical_dependency_lineage") or "")
                for item in dependency_artifacts
                if item.get("logical_dependency_lineage")
            }),
            "base_dependency_coords": sorted({
                str(item.get("coord") or "")
                for item in dependency_artifacts
                if item.get("side") == "base" and item.get("coord")
            }),
            "current_dependency_coords": sorted({
                str(item.get("coord") or "")
                for item in dependency_artifacts
                if item.get("side") == "current" and item.get("coord")
            }),
            "target_jvm_identities": [profile.identity],
            "primary_projection_id": primary["projection_identity"],
            "primary_projection_selection_reason": "highest_reachability_then_stable_input_order_v1",
            "projection_coverage_statuses": sorted({
                next(
                    assessment["projection_coverage_status"]
                    for assessment in decisions.projection_assessments
                    if assessment["projection_assessment_identity"]
                    == item["projection_assessment_identity"]
                )
                for item in results
            }),
        })
    return output


def build_output_payloads(
    decisions: BinaryDecisionBundle,
    traces: BinaryTraceBundle,
    profile: RuntimeProfile,
    *,
    source_overlay: SourceOverlayResult | None = None,
    source_inputs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source_inputs = dict(source_inputs or {})
    assessments = {
        item["projection_assessment_identity"]: item
        for item in decisions.projection_assessments
    }
    unprojectable = [
        decision
        for decision in decisions.authoritative_decisions
        if any(
            assessment["decision_identity"] == decision["decision_identity"]
            and assessment["analysis_projection_status"] == "unsupported"
            for assessment in decisions.projection_assessments
        )
    ]
    by_api = _aggregate_by_api(decisions, traces, profile)
    exact_entrypoints = {
        str(item.get("member_identity") or "")
        for item in traces.entrypoint_records
        if item.get("path_certainty") == "exact" and item.get("member_identity")
    }
    possible_entrypoints = {
        str(item.get("member_identity") or "")
        for item in traces.entrypoint_records
        if item.get("path_certainty") == "possible"
        and item.get("member_identity") not in exact_entrypoints
    }
    summary = {
        "schema": "java-upgrade-analyzer.binary-summary.v1",
        "analysis_context_identity": decisions.analysis_context_identity,
        "current_runtime_profile_identity": profile.identity,
        "authoritative_change_fact_count": len(decisions.authoritative_decisions),
        "diagnostic_candidate_fact_count": len(decisions.diagnostic_decisions),
        "excluded_decision_count": len(decisions.excluded_decisions),
        "confirmed_unprojectable_fact_count": len(unprojectable),
        "formal_projection_count": len(decisions.formal_projections),
        "candidate_projection_plan_count": len(decisions.candidate_projection_plans),
        "formal_trace_result_count": len(traces.formal_results),
        "candidate_trace_result_count": len(traces.candidate_results),
        "unique_reported_api_total": len(by_api),
        "reachable_total": sum(item["reachability_status"] == "reachable" for item in by_api),
        "uncertain_total": sum(item["reachability_status"] == "uncertain" for item in by_api),
        "not_found_in_static_analysis_total": sum(
            item["reachability_status"] == "not_found_in_static_analysis" for item in by_api
        ),
        "not_analyzed_total": sum(item["reachability_status"] == "not_analyzed" for item in by_api),
        "probable_impact_total": sum(item["impact_conclusion"] == "probable_impact" for item in by_api),
        "runtime_verified_total": 0,
        "resource_activation_reachable_total": sum(
            item.get("activation_status") == "reachable"
            for item in traces.resource_activation_results
        ),
        "resource_activation_result_count": len(traces.resource_activation_results),
        "exact_entrypoint_count": len(exact_entrypoints),
        "possible_entrypoint_count": len(possible_entrypoints),
        "entrypoint_discovery_identity": traces.entrypoint_discovery_identity,
        "formal_path_set_complete": all(item["path_set_complete"] for item in by_api),
        "decision_coverage_status": decisions.coverage_status,
        "trace_coverage_status": traces.coverage_status,
        "source_inputs": source_inputs,
    }
    return {
        "binary_decisions.json": {
            "schema": "java-upgrade-analyzer.binary-decisions.v1",
            "analysis_context_identity": decisions.analysis_context_identity,
            "active_decision_snapshot_identity": decisions.active_snapshots["decision"].identity,
            "authoritative_change_facts": list(decisions.authoritative_decisions),
            "diagnostic_candidate_facts": list(decisions.diagnostic_decisions),
            "excluded_decisions": list(decisions.excluded_decisions),
        },
        "binary_projections.json": {
            "schema": "java-upgrade-analyzer.binary-projections.v1",
            "active_assessment_snapshot_identity": decisions.active_snapshots["assessment"].identity,
            "active_formal_projection_snapshot_identity": decisions.active_snapshots["formal_projection"].identity,
            "active_candidate_projection_snapshot_identity": decisions.active_snapshots["candidate_projection"].identity,
            "authoritative_projection_assessments": list(decisions.projection_assessments),
            "formal_projections": list(decisions.formal_projections),
            "candidate_projection_plans": list(decisions.candidate_projection_plans),
            "confirmed_unprojectable_facts": unprojectable,
        },
        "binary_formal_results.json": {
            "schema": "java-upgrade-analyzer.binary-formal-results.v1",
            "results": list(traces.formal_results),
            "by_api": by_api,
            "resource_activation_results": list(traces.resource_activation_results),
        },
        "binary_candidate_results.json": {
            "schema": "java-upgrade-analyzer.binary-candidate-results.v1",
            "results": list(traces.candidate_results),
        },
        "binary_entrypoints.json": {
            "schema": "java-upgrade-analyzer.binary-entrypoint-discovery.v1",
            "entrypoint_discovery_identity": traces.entrypoint_discovery_identity,
            "exact_entrypoint_count": len(exact_entrypoints),
            "possible_entrypoint_count": len(possible_entrypoints),
            "records": list(traces.entrypoint_records),
        },
        "binary_coverage.json": {
            "schema": "java-upgrade-analyzer.binary-coverage.v1",
            "decision_coverage_status": decisions.coverage_status,
            "decision_coverage_gaps": list(decisions.coverage_gaps),
            "trace_coverage_status": traces.coverage_status,
            "trace_coverage_gaps": list(traces.coverage_gaps),
            "batch_graph_stats": dict(traces.graph_stats or {}),
            "entrypoint_discovery_identity": traces.entrypoint_discovery_identity,
            "source_overlay": asdict(source_overlay) if source_overlay else {
                "coverage_status": "not_provided",
            },
            "source_inputs": source_inputs,
        },
        "binary_summary.json": summary,
    }


def _csv_bytes(rows: list[dict[str, Any]]) -> bytes:
    columns = [
        "reported_api_identity", "display_owner", "display_member", "display_descriptor",
        "reachability_status", "is_reachable", "impact_conclusion", "static_linkage_status",
        "runtime_verification_status", "runtime_verification_executed_by_system",
        "path_set_complete", "exact_path_exists", "possible_path_exists",
        "primary_projection_id",
    ]
    with short_temporary_directory(prefix="binary-output-csv") as temp_text:
        path = Path(temp_text) / "binary_formal_results.csv"
        with open_csv_write(path) as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        return path.read_bytes()


def write_binary_generation(
    output_root: str | Path,
    decisions: BinaryDecisionBundle,
    traces: BinaryTraceBundle,
    profile: RuntimeProfile,
    *,
    policy_identities: Mapping[str, str],
    source_overlay: SourceOverlayResult | None = None,
    source_inputs: Mapping[str, Any] | None = None,
    additional_sidecars: Mapping[str, bytes | Path] | None = None,
) -> dict[str, Any]:
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    payloads = build_output_payloads(
        decisions,
        traces,
        profile,
        source_overlay=source_overlay,
        source_inputs=source_inputs,
    )
    encoded = {name: _json_bytes(payload) for name, payload in payloads.items()}
    encoded["binary_formal_results.csv"] = _csv_bytes(payloads["binary_formal_results.json"]["by_api"])
    sidecar_sources: dict[str, bytes | Path] = dict(encoded)
    for name, content in (additional_sidecars or {}).items():
        safe_name = Path(str(name or "")).name
        if not safe_name or safe_name != str(name) or safe_name in sidecar_sources:
            raise BinaryOutputError(
                "BINARY_OUTPUT_ADDITIONAL_SIDECAR_INVALID", str(name)
            )
        if not isinstance(content, (bytes, Path)) or (
            isinstance(content, Path) and not content.is_file()
        ):
            raise BinaryOutputError(
                "BINARY_OUTPUT_ADDITIONAL_SIDECAR_INVALID",
                f"{name} must be bytes or an existing Path",
            )
        sidecar_sources[safe_name] = content
    sidecar_identities = {
        name: (_sha256(content) if isinstance(content, bytes) else _sha256_file(content))
        for name, content in sidecar_sources.items()
    }
    generation = ResultGeneration(
        decisions.analysis_context_identity,
        decisions.active_snapshots,
        traces.trace_result_set_digest,
        sidecar_identities,
        dict(policy_identities),
    )
    generations = root / "binary_generations"
    generations.mkdir(exist_ok=True)
    destination = generations / generation.identity
    manifest = {
        "schema": "java-upgrade-analyzer.binary-result-generation.v1",
        "result_generation_identity": generation.identity,
        "analysis_context_identity": decisions.analysis_context_identity,
        "authority": "binary_first",
        "active_snapshot_identities": {
            layer: snapshot.identity for layer, snapshot in decisions.active_snapshots.items()
        },
        "trace_result_set_digest": traces.trace_result_set_digest,
        "sidecar_content_identities": sidecar_identities,
        "policy_identities": dict(policy_identities),
        "attachment_policy": "trace-results-bound-by-generation-attachment-v1",
    }
    attachment = {
        "schema": "java-upgrade-analyzer.binary-generation-attachments.v1",
        "result_generation_identity": generation.identity,
        "formal_trace_result_identities": [
            item["trace_result_identity"] for item in traces.formal_results
        ],
        "candidate_trace_result_identities": [
            item["trace_result_identity"] for item in traces.candidate_results
        ],
    }
    if destination.exists():
        existing_manifest = destination / "result_generation.json"
        existing = (
            json.loads(existing_manifest.read_text(encoding="utf-8"))
            if existing_manifest.is_file() else {}
        )
        content_valid = all(
            (destination / name).is_file()
            and _sha256_file(destination / name) == expected
            for name, expected in sidecar_identities.items()
        )
        if (
            existing.get("result_generation_identity") != generation.identity
            or existing.get("sidecar_content_identities") != sidecar_identities
            or not content_valid
        ):
            raise BinaryOutputError(
                "BINARY_GENERATION_IDENTITY_COLLISION", str(destination)
            )
    else:
        temp = make_short_temp_dir(
            prefix="binary-generation",
            preferred_root=generations,
            strict_preferred=True,
        )
        try:
            for name, content in sidecar_sources.items():
                target = temp / name
                if isinstance(content, bytes):
                    target.write_bytes(content)
                else:
                    shutil.copyfile(content, target)
                if _sha256_file(target) != sidecar_identities[name]:
                    raise BinaryOutputError(
                        "BINARY_OUTPUT_SIDECAR_CHANGED_DURING_COPY", str(content)
                    )
            (temp / "result_generation.json").write_bytes(_json_bytes(manifest))
            (temp / "generation_attachments.json").write_bytes(_json_bytes(attachment))
            os.replace(temp, destination)
        finally:
            if temp.exists():
                shutil.rmtree(temp)
    return {
        **manifest,
        "generation_directory": str(destination),
        "active_generation_descriptor": "",
    }


def activate_binary_generation(
    output_root: str | Path,
    manifest: Mapping[str, Any],
    *,
    validation_result: Mapping[str, Any] | None = None,
) -> str:
    root = Path(output_root)
    generation_identity = str(manifest.get("result_generation_identity") or "")
    destination = root / "binary_generations" / generation_identity
    if not generation_identity or not destination.is_dir():
        raise BinaryOutputError(
            "BINARY_GENERATION_ACTIVATION_TARGET_INVALID", str(destination)
        )
    if (
        manifest.get("authority") != "binary_first"
        or not validation_result
        or validation_result.get("status") != "passed"
        or validation_result.get("result_generation_identity") != generation_identity
    ):
        raise BinaryOutputError(
            "BINARY_GENERATION_VALIDATION_REQUIRED", generation_identity
        )
    for name, expected in (manifest.get("sidecar_content_identities") or {}).items():
        path = destination / str(name)
        if not path.is_file() or _sha256_file(path) != expected:
            raise BinaryOutputError(
                "BINARY_GENERATION_ACTIVATION_INTEGRITY_FAILED", str(path)
            )
    active = {
        "schema": "java-upgrade-analyzer.active-binary-generation.v1",
        "result_generation_identity": generation_identity,
        "generation_directory": f"binary_generations/{generation_identity}",
        "validation_run_identity": (
            str((validation_result or {}).get("validation_run_identity") or "")
        ),
    }
    descriptor, temporary_name = tempfile.mkstemp(prefix=".active-generation-", dir=root)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_json_bytes(active))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, root / "active_binary_generation.json")
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return str(root / "active_binary_generation.json")


__all__ = [
    "BinaryOutputError",
    "activate_binary_generation",
    "build_output_payloads",
    "write_binary_generation",
]
