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
