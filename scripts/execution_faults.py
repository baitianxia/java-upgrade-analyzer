#!/usr/bin/env python3
"""Typed execution faults applied only to copied test inputs and processes."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import zipfile

from business_bytecode_graph import collect_business_bytecode_edges
from confidence_weighted_tracer import _load_runtime_member_index_cache
from s1_dep_diff import collect_packaged_deps_from_artifact_path
from s4_jar_compare import parse_japicmp_xml


@dataclass(frozen=True)
class ExecutionFaultSpec:
    id: str
    boundary: str
    expected_reason: str


@dataclass(frozen=True)
class ExecutionFaultResult:
    fault_id: str
    status: str
    reason_code: str
    before_sha256: str
    after_sha256: str
    cleanup_complete: bool


@dataclass(frozen=True)
class ProductionBoundaryFaultResult:
    stage: str
    fault_id: str
    status: str
    reason_code: str
    production_entrypoint: str
    evidence: str


EXECUTION_FAULTS = (
    ExecutionFaultSpec("subprocess_timeout", "subprocess", "EXECUTION_TIMEOUT"),
    ExecutionFaultSpec("subprocess_nonzero_exit", "subprocess", "EXECUTION_NONZERO_EXIT"),
    ExecutionFaultSpec("truncated_output", "parser_output", "EXECUTION_OUTPUT_TRUNCATED"),
    ExecutionFaultSpec("partial_artifact_write", "artifact", "EXECUTION_PARTIAL_WRITE"),
    ExecutionFaultSpec("artifact_replacement", "artifact", "EXECUTION_ARTIFACT_REPLACED"),
    ExecutionFaultSpec("permission_denied", "artifact", "EXECUTION_PERMISSION_DENIED"),
    ExecutionFaultSpec("invalid_encoding", "parser_output", "EXECUTION_ENCODING_INVALID"),
    ExecutionFaultSpec("process_interruption", "orchestrator", "EXECUTION_INTERRUPTED"),
    ExecutionFaultSpec("process_cancellation", "orchestrator", "EXECUTION_CANCELLED"),
    ExecutionFaultSpec("cache_race", "cache", "EXECUTION_CACHE_RACE"),
)


def _digest_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode())
            try:
                content = path.read_bytes()
            except PermissionError:
                content = b"<UNREADABLE>"
            digest.update(content)
            digest.update(str(path.stat().st_mode & 0o777).encode())
    return digest.hexdigest()


def run_execution_fault(spec: ExecutionFaultSpec, workspace: Path) -> ExecutionFaultResult:
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    artifact = workspace / "evidence.json"
    artifact.write_text(json.dumps({"status": "complete", "footer": True}), encoding="utf-8")
    before = _digest_tree(workspace)
    reason = ""
    try:
        if spec.id == "subprocess_timeout":
            try:
                subprocess.run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.01)
            except subprocess.TimeoutExpired:
                reason = "EXECUTION_TIMEOUT"
        elif spec.id == "subprocess_nonzero_exit":
            result = subprocess.run([sys.executable, "-c", "raise SystemExit(7)"])
            if result.returncode != 0:
                reason = "EXECUTION_NONZERO_EXIT"
        elif spec.id == "truncated_output":
            artifact.write_bytes(b'{"status":"complete"')
            try:
                json.loads(artifact.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                reason = "EXECUTION_OUTPUT_TRUNCATED"
        elif spec.id == "partial_artifact_write":
            artifact.write_text(json.dumps({"status": "complete"}), encoding="utf-8")
            if not json.loads(artifact.read_text(encoding="utf-8")).get("footer"):
                reason = "EXECUTION_PARTIAL_WRITE"
        elif spec.id == "artifact_replacement":
            original = hashlib.sha256(artifact.read_bytes()).hexdigest()
            artifact.write_text('{"status":"replacement"}', encoding="utf-8")
            if hashlib.sha256(artifact.read_bytes()).hexdigest() != original:
                reason = "EXECUTION_ARTIFACT_REPLACED"
        elif spec.id == "permission_denied":
            artifact.chmod(0)
            if artifact.stat().st_mode & 0o777 == 0:
                reason = "EXECUTION_PERMISSION_DENIED"
        elif spec.id == "invalid_encoding":
            artifact.write_bytes(b"\xff\xfe\xfa")
            try:
                artifact.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                reason = "EXECUTION_ENCODING_INVALID"
        elif spec.id == "process_interruption":
            try:
                raise KeyboardInterrupt()
            except KeyboardInterrupt:
                reason = "EXECUTION_INTERRUPTED"
        elif spec.id == "process_cancellation":
            process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
            process.terminate()
            process.wait(timeout=2)
            if process.returncode != 0:
                reason = "EXECUTION_CANCELLED"
        elif spec.id == "cache_race":
            first = artifact.read_bytes()
            artifact.write_bytes(first + b"\n")
            if artifact.read_bytes() != first:
                reason = "EXECUTION_CACHE_RACE"
        else:
            reason = "UNREGISTERED_EXECUTION_FAULT"
        after = _digest_tree(workspace)
    finally:
        try:
            artifact.chmod(0o600)
        except OSError:
            pass
        shutil.rmtree(workspace, ignore_errors=True)
    cleanup = not workspace.exists()
    return ExecutionFaultResult(
        spec.id,
        "failed_closed" if reason == spec.expected_reason else "detection_failed",
        reason,
        before,
        after,
        cleanup,
    )


def run_production_stage_boundary_faults(
    workspace: Path,
) -> tuple[ProductionBoundaryFaultResult, ...]:
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    results = []

    corrupt_artifact = workspace / "corrupt-application.jar"
    corrupt_artifact.write_bytes(b"not-a-zip")
    try:
        collect_packaged_deps_from_artifact_path(corrupt_artifact)
    except Exception as exc:
        results.append(ProductionBoundaryFaultResult(
            "step1",
            "corrupt_final_artifact",
            "failed_closed",
            "STEP1_FINAL_ARTIFACT_INVALID",
            "s1_dep_diff.collect_packaged_deps_from_artifact_path",
            f"{type(exc).__name__}:{exc}",
        ))
    else:
        results.append(ProductionBoundaryFaultResult(
            "step1", "corrupt_final_artifact", "detection_failed", "",
            "s1_dep_diff.collect_packaged_deps_from_artifact_path", "accepted",
        ))

    truncated_xml = workspace / "japicmp.xml"
    truncated_xml.write_text("<japicmp><classes>", encoding="utf-8")
    try:
        parse_japicmp_xml(truncated_xml, "contract:demo", "1", "2")
    except Exception as exc:
        results.append(ProductionBoundaryFaultResult(
            "step4",
            "truncated_japicmp_xml",
            "failed_closed",
            "STEP4_JAPICMP_XML_INVALID",
            "s4_jar_compare.parse_japicmp_xml",
            f"{type(exc).__name__}:{exc}",
        ))
    else:
        results.append(ProductionBoundaryFaultResult(
            "step4", "truncated_japicmp_xml", "detection_failed", "",
            "s4_jar_compare.parse_japicmp_xml", "accepted",
        ))

    business_jar = workspace / "business.jar"
    with zipfile.ZipFile(business_jar, "w") as archive:
        archive.writestr("contract/App.class", b"fixture")
    _edges, metrics = collect_business_bytecode_edges(
        [],
        artifact_catalog={"by_coord": {"__business__": {
            "jar_path": str(business_jar),
            "sha256": "0" * 64,
        }}},
    )
    artifact_reason = next(
        (
            reason for reason in metrics.get("failures") or ()
            if reason == "current_final_artifact_sha_mismatch"
        ),
        "",
    )
    results.append(ProductionBoundaryFaultResult(
        "step5",
        "replaced_business_artifact",
        "failed_closed" if artifact_reason else "detection_failed",
        artifact_reason,
        "business_bytecode_graph.collect_business_bytecode_edges",
        json.dumps(metrics, sort_keys=True),
    ))

    corrupt_cache = workspace / "member-index.json"
    corrupt_cache.write_text("{", encoding="utf-8")
    try:
        _load_runtime_member_index_cache(
            corrupt_cache, {"schema": "fixture"}, SimpleNamespace()
        )
    except Exception as exc:
        results.append(ProductionBoundaryFaultResult(
            "step5",
            "corrupt_member_cache",
            "failed_closed",
            "STEP5_MEMBER_CACHE_INVALID",
            "confidence_weighted_tracer._load_runtime_member_index_cache",
            f"{type(exc).__name__}:{exc}",
        ))
    else:
        results.append(ProductionBoundaryFaultResult(
            "step5", "corrupt_member_cache", "detection_failed", "",
            "confidence_weighted_tracer._load_runtime_member_index_cache",
            "accepted",
        ))
    return tuple(results)
